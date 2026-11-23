/**
 * First-class Crawlee integration (`WayboundCrawler` and `WayboundCrawlingContext`).
 *
 * Requires the optional `@crawlee/basic` peer dependency:
 *
 *     npm install @crawlee/basic
 */

import {
  BasicCrawler,
  type BasicCrawlerOptions,
  type BasicCrawlingContext,
  type Configuration,
  type CrawlerRunOptions,
  type EnqueueLinksOptions,
  EnqueueStrategy,
  type FinalStatistics,
  type ProxyConfiguration,
  type RequestsLike,
} from "@crawlee/basic";
import type { CapturedResponsesOptions, Page } from "./client.js";
import { type AcquireOptions, BrowserPool, type BrowserPoolOptions } from "./pool.js";
import type { CapturedResponse } from "./types.js";

/** Result returned by `WayboundCrawlingContext.enqueueLinks()`. */
export type WayboundEnqueueLinksResult = Awaited<ReturnType<BasicCrawlingContext["enqueueLinks"]>>;

/** Options accepted by `WayboundCrawlingContext.enqueueLinks()`. */
export interface WayboundEnqueueLinksOptions extends Omit<EnqueueLinksOptions, "selector"> {
  /** Optional accessibility-tree node cap forwarded to `page.links({ maxNodes })`. */
  readonly maxNodes?: number;
}

/** Crawling context for `WayboundCrawler`, exposing the live `Page` and `BrowserPool`. */
export interface WayboundCrawlingContext
  extends Omit<BasicCrawlingContext, "crawler" | "enqueueLinks"> {
  /** The owning `WayboundCrawler` instance. */
  crawler: WayboundCrawler;
  /** The acquired `Page`, already navigated to `request.url` unless `navigate: false`. */
  page: Page;
  /** The `BrowserPool` managing browser sessions for this crawler. */
  pool: BrowserPool;
  /** Return passively captured HTTP responses from the current page. */
  capturedResponses(options?: CapturedResponsesOptions): Promise<CapturedResponse[]>;
  /**
   * Discover links on the current page via `page.links()`, resolve relative URLs against
   * `baseUrl` (defaulting to `request.loadedUrl ?? request.url`), filter by strategy and
   * optional `globs`/`regexps`/`limit`, and enqueue them into Crawlee's `RequestQueue`.
   */
  enqueueLinks(options?: WayboundEnqueueLinksOptions): Promise<WayboundEnqueueLinksResult>;
}

/** Constructor options for `WayboundCrawler`. */
export interface WayboundCrawlerOptions extends BasicCrawlerOptions<WayboundCrawlingContext> {
  /** Pre-configured `BrowserPool` to reuse (not closed automatically on teardown). */
  readonly pool?: BrowserPool;
  /** Options used to construct an internally-managed `BrowserPool` (closed on teardown). */
  readonly poolOptions?: BrowserPoolOptions;
  /** Optional Crawlee `ProxyConfiguration` whose `proxyInfo.url` is forwarded to `pool.withPage()`. */
  readonly proxyConfiguration?: ProxyConfiguration;
  /** Whether to automatically call `page.goto(request.url)` before `requestHandler`. Default `true`. */
  readonly navigate?: boolean;
}

type BaseEnqueueLinksFn = BasicCrawlingContext["enqueueLinks"];

/** Resolve relative URLs against `baseUrl`, keeping unique valid `http:`/`https:` URLs in order. */
export function resolveHttpLinks(rawUrls: readonly string[], baseUrl: string): string[] {
  const resolved: string[] = [];
  const seen = new Set<string>();
  for (const raw of rawUrls) {
    const trimmed = raw.trim();
    if (trimmed.length === 0) {
      continue;
    }
    let parsed: URL;
    try {
      parsed = new URL(trimmed, baseUrl);
    } catch {
      continue;
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      continue;
    }
    const href = parsed.href;
    if (!seen.has(href)) {
      seen.add(href);
      resolved.push(href);
    }
  }
  return resolved;
}

/**
 * Crawlee `BasicCrawler` backed by a `waybound.BrowserPool` of real OS-driven browsers.
 *
 * Each request checks out a healthy `Page` via `pool.withPage()`, navigates to `request.url`
 * (unless `navigate: false`), forwards `proxyInfo.url` when `proxyConfiguration` is supplied,
 * and recycles the slot automatically if navigation or `requestHandler` throws.
 */
export class WayboundCrawler extends BasicCrawler<WayboundCrawlingContext> {
  readonly #ownsPool: boolean;
  readonly #poolOptions: BrowserPoolOptions | undefined;
  readonly #proxyConfiguration: ProxyConfiguration | undefined;
  readonly #navigate: boolean;
  #pool: BrowserPool;

  constructor(options: WayboundCrawlerOptions = {}, config?: Configuration) {
    const { pool, poolOptions, proxyConfiguration, navigate, ...basicOptions } = options;
    if (pool !== undefined && poolOptions !== undefined) {
      throw new TypeError("Cannot specify both `pool` and `poolOptions` in WayboundCrawlerOptions");
    }

    super(basicOptions, config);

    this.#ownsPool = pool === undefined;
    this.#poolOptions = poolOptions;
    this.#proxyConfiguration = proxyConfiguration;
    this.#navigate = navigate ?? true;
    this.#pool = pool ?? new BrowserPool(poolOptions);
  }

  /** The `BrowserPool` managing browser sessions for this crawler. */
  get pool(): BrowserPool {
    return this.#pool;
  }

  protected override async _runRequestHandler(
    crawlingContext: WayboundCrawlingContext,
  ): Promise<void> {
    if (this.#proxyConfiguration !== undefined && crawlingContext.proxyInfo === undefined) {
      const resolvedProxyInfo = await this.#proxyConfiguration.newProxyInfo(
        crawlingContext.session?.id,
      );
      if (resolvedProxyInfo !== undefined) {
        crawlingContext.proxyInfo = resolvedProxyInfo;
      }
    }

    const baseEnqueueLinks = crawlingContext.enqueueLinks as unknown as BaseEnqueueLinksFn;
    const proxyUrl = crawlingContext.proxyInfo?.url;
    const acquireOptions: AcquireOptions | undefined =
      proxyUrl !== undefined ? { proxy: proxyUrl } : undefined;

    await this.#pool.withPage(async (page) => {
      if (this.#navigate) {
        await page.goto(crawlingContext.request.url);
        if (crawlingContext.request.loadedUrl === undefined) {
          crawlingContext.request.loadedUrl = crawlingContext.request.url;
        }
      }

      crawlingContext.page = page;
      crawlingContext.pool = this.#pool;
      crawlingContext.capturedResponses = (opts?: CapturedResponsesOptions) =>
        page.capturedResponses(opts);
      crawlingContext.enqueueLinks = async (
        opts?: WayboundEnqueueLinksOptions,
      ): Promise<WayboundEnqueueLinksResult> => {
        const { maxNodes, urls: explicitUrls, ...rest } = opts ?? {};
        const baseUrl =
          rest.baseUrl ?? crawlingContext.request.loadedUrl ?? crawlingContext.request.url;

        let rawUrls: readonly string[];
        if (explicitUrls !== undefined) {
          rawUrls = explicitUrls;
        } else {
          const linkNodes = await page.links(maxNodes !== undefined ? { maxNodes } : undefined);
          rawUrls = linkNodes
            .map((node) => node.url)
            .filter((url): url is string => typeof url === "string" && url.length > 0);
        }

        const resolvedUrls = resolveHttpLinks(rawUrls, baseUrl);
        if (resolvedUrls.length === 0) {
          return { processedRequests: [], unprocessedRequests: [] };
        }

        return baseEnqueueLinks({
          ...rest,
          baseUrl,
          strategy: rest.strategy ?? EnqueueStrategy.SameHostname,
          urls: resolvedUrls,
        });
      };

      await super._runRequestHandler(crawlingContext);
    }, acquireOptions);
  }

  override async run(
    requests?: RequestsLike,
    options?: CrawlerRunOptions,
  ): Promise<FinalStatistics> {
    if (this.#ownsPool) {
      if (this.#pool.closed) {
        this.#pool = new BrowserPool(this.#poolOptions);
      }
      await this.#pool.start();
    }
    try {
      return await super.run(requests, options);
    } finally {
      if (this.#ownsPool) {
        await this.#pool.close();
      }
    }
  }

  override async teardown(): Promise<void> {
    try {
      await super.teardown();
    } finally {
      if (this.#ownsPool) {
        await this.#pool.close();
      }
    }
  }
}

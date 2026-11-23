/**
 * Unit and live `waybound-daemon --backend mock` tests for `waybound/crawlee` (`WayboundCrawler`).
 */

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { Configuration, EnqueueStrategy, ProxyConfiguration } from "@crawlee/basic";
import { resolveHttpLinks, WayboundCrawler } from "../src/crawlee.js";
import {
  type AccessibilityNode,
  type AcquireOptions,
  Bounds,
  BrowserPool,
  CapturedResponse,
  type Page,
  Role,
} from "../src/index.js";

const REPO_ROOT = fileURLToPath(new URL("../../../../", import.meta.url));
const DAEMON_BIN =
  process.env.WAYBOUND_DAEMON_BIN ??
  path.join(
    REPO_ROOT,
    "target",
    "debug",
    process.platform === "win32" ? "waybound-daemon.exe" : "waybound-daemon",
  );

const present = existsSync(DAEMON_BIN);
if (!present && process.env.WAYBOUND_REQUIRE_DAEMON === "1") {
  throw new Error(
    `WAYBOUND_REQUIRE_DAEMON=1 but the daemon binary is missing at ${DAEMON_BIN}; run \`cargo build -p waybound-daemon\``,
  );
}
const skip = present
  ? false
  : `waybound-daemon not built at ${DAEMON_BIN} (run cargo build -p waybound-daemon)`;

function withTempConfig<T>(fn: (config: Configuration, dir: string) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(path.join(tmpdir(), "wb-crawlee-ts-"));
  const config = new Configuration({
    persistStorage: false,
    purgeOnStart: true,
    storageClientOptions: { localDataDirectory: dir },
  });
  return fn(config, dir).finally(() => {
    rmSync(dir, { recursive: true, force: true });
  });
}

function makeLinkNode(id: number, name: string, url: string): AccessibilityNode {
  return {
    id: String(id),
    role: Role.LINK,
    name,
    value: null,
    bounds: new Bounds(0, 0, 100, 20),
    focused: false,
    url,
  };
}

interface FakePageState {
  visitedUrls: string[];
  currentUrl: string | null;
}

function createFakePage(options?: {
  linksByUrl?: Record<string, AccessibilityNode[]>;
  responsesByUrl?: Record<string, CapturedResponse[]>;
}): { page: Page; state: FakePageState } {
  const linksByUrl = options?.linksByUrl ?? {};
  const responsesByUrl = options?.responsesByUrl ?? {};
  const state: FakePageState = { visitedUrls: [], currentUrl: null };

  const fakePage = {
    async goto(url: string): Promise<void> {
      state.currentUrl = url;
      state.visitedUrls.push(url);
    },
    async url(): Promise<string | null> {
      return state.currentUrl;
    },
    async links(opts?: { maxNodes?: number }): Promise<AccessibilityNode[]> {
      const nodes = linksByUrl[state.currentUrl ?? ""] ?? [];
      return opts?.maxNodes !== undefined ? nodes.slice(0, opts.maxNodes) : [...nodes];
    },
    async capturedResponses(opts?: { urlContains?: string | null }): Promise<CapturedResponse[]> {
      const all = responsesByUrl[state.currentUrl ?? ""] ?? [];
      if (opts?.urlContains === undefined || opts.urlContains === null) {
        return [...all];
      }
      const needle = opts.urlContains.toLowerCase();
      return all.filter((r) => r.url.toLowerCase().includes(needle));
    },
  } as unknown as Page;

  return { page: fakePage, state };
}

class FakeBrowserPool extends BrowserPool {
  readonly #page: Page;
  readonly acquiredProxies: Array<string | undefined> = [];
  recycleCount = 0;
  closeCalls = 0;

  constructor(page: Page) {
    super({ size: 1 });
    this.#page = page;
  }

  override async withPage<T>(
    fn: (page: Page) => Promise<T> | T,
    options?: AcquireOptions,
  ): Promise<T> {
    this.acquiredProxies.push(options?.proxy);
    try {
      return await fn(this.#page);
    } catch (err) {
      this.recycleCount += 1;
      throw err;
    }
  }

  override async close(): Promise<void> {
    this.closeCalls += 1;
    await super.close();
  }
}

describe("WayboundCrawler unit tests", () => {
  it("resolves relative HTTP(S) links and drops non-HTTP schemes and duplicates", () => {
    const urls = resolveHttpLinks(
      [
        "/articles/1",
        "https://example.com/articles/1",
        "../about",
        "mailto:test@example.com",
        "javascript:void(0)",
        "   ",
        "https://other.org/page",
      ],
      "https://example.com/blog/index.html",
    );
    assert.deepEqual(urls, [
      "https://example.com/articles/1",
      "https://example.com/about",
      "https://other.org/page",
    ]);
  });

  it("rejects passing both pool and poolOptions", () => {
    const pool = new BrowserPool({ size: 1 });
    assert.throws(
      () => new WayboundCrawler({ pool, poolOptions: { size: 2 } }),
      /Cannot specify both `pool` and `poolOptions`/,
    );
  });

  it("discovers links via page.links(), filters by strategy/globs/limit, and pushes to Dataset", async () => {
    await withTempConfig(async (config) => {
      const { page, state } = createFakePage({
        linksByUrl: {
          "https://example.com/": [
            makeLinkNode(1, "Article 1", "/articles/one"),
            makeLinkNode(2, "Article 2", "https://example.com/articles/two"),
            makeLinkNode(3, "Admin", "/admin/secret"),
            makeLinkNode(4, "External", "https://other.org/page"),
            makeLinkNode(5, "Mail", "mailto:hi@example.com"),
          ],
          "https://example.com/articles/one": [],
          "https://example.com/articles/two": [],
        },
        responsesByUrl: {
          "https://example.com/": [
            new CapturedResponse(
              "https://example.com/api/feed",
              200,
              "application/json",
              '{"ok":true}',
            ),
          ],
        },
      });
      const fakePool = new FakeBrowserPool(page);

      const crawler = new WayboundCrawler(
        {
          pool: fakePool,
          useSessionPool: false,
          async requestHandler(ctx) {
            assert.equal(ctx.pool, fakePool);
            const responses = await ctx.capturedResponses({ urlContains: "/api/" });
            await ctx.pushData({
              url: ctx.request.url,
              apiCount: responses.length,
            });
            if (ctx.request.url === "https://example.com/") {
              await ctx.enqueueLinks({
                strategy: EnqueueStrategy.SameHostname,
                globs: ["https://example.com/articles/**"],
                limit: 5,
              });
            }
          },
        },
        config,
      );

      const stats = await crawler.run(["https://example.com/"]);
      assert.equal(stats.requestsFinished, 3);
      assert.equal(stats.requestsFailed, 0);
      assert.deepEqual(
        new Set(state.visitedUrls),
        new Set([
          "https://example.com/",
          "https://example.com/articles/one",
          "https://example.com/articles/two",
        ]),
      );

      const data = await crawler.getData();
      assert.equal(data.items.length, 3);
      const rootItem = data.items.find((item) => item.url === "https://example.com/");
      assert.equal(rootItem?.apiCount, 1);

      // External pool must not be closed automatically.
      assert.equal(fakePool.closeCalls, 0);
      await fakePool.close();
    });
  });

  it("forwards proxyConfiguration proxyInfo.url into pool.withPage() and recycles on error", async () => {
    await withTempConfig(async (config) => {
      const { page } = createFakePage();
      const fakePool = new FakeBrowserPool(page);
      const proxyConfiguration = new ProxyConfiguration({
        proxyUrls: ["http://proxy-1.local:8080", "http://proxy-2.local:8080"],
      });
      const seenProxies: Array<string | undefined> = [];
      let attempts = 0;

      const crawler = new WayboundCrawler(
        {
          pool: fakePool,
          proxyConfiguration,
          maxRequestRetries: 2,
          useSessionPool: false,
          async requestHandler(ctx) {
            seenProxies.push(ctx.proxyInfo?.url);
            attempts += 1;
            if (attempts === 1) {
              throw new Error("transient failure");
            }
            await ctx.pushData({ url: ctx.request.url, attempts });
          },
        },
        config,
      );

      const stats = await crawler.run(["https://example.com/flaky"]);
      assert.equal(attempts, 2);
      assert.equal(fakePool.recycleCount, 1);
      assert.equal(stats.requestsFinished, 1);
      assert.equal(stats.requestsFailed, 0);
      assert.deepEqual(fakePool.acquiredProxies, [
        "http://proxy-1.local:8080",
        "http://proxy-2.local:8080",
      ]);
      assert.deepEqual(seenProxies, fakePool.acquiredProxies);
      await fakePool.close();
    });
  });

  it("skips automatic navigation when navigate is false", async () => {
    await withTempConfig(async (config) => {
      const { page, state } = createFakePage();
      const fakePool = new FakeBrowserPool(page);

      const crawler = new WayboundCrawler(
        {
          pool: fakePool,
          navigate: false,
          useSessionPool: false,
          async requestHandler(ctx) {
            await ctx.pushData({ url: ctx.request.url });
          },
        },
        config,
      );

      await crawler.run(["https://example.com/no-nav"]);
      assert.deepEqual(state.visitedUrls, []);
      await fakePool.close();
    });
  });
});

describe("WayboundCrawler live mock-daemon E2E", { skip }, () => {
  it("crawls URLs against waybound-daemon --backend mock, pushes to Dataset, and closes pool", async () => {
    await withTempConfig(async (config) => {
      const crawler = new WayboundCrawler(
        {
          poolOptions: {
            size: 1,
            launchOptions: { backend: "mock", daemonBinary: DAEMON_BIN },
          },
          useSessionPool: false,
          async requestHandler(ctx) {
            const tree = await ctx.page.snapshotTree();
            const responses = await ctx.capturedResponses();
            await ctx.pushData({
              url: ctx.request.url,
              nodeCount: tree.length,
              capturedCount: responses.length,
            });
          },
        },
        config,
      );

      const stats = await crawler.run(["https://example.com/mock-1", "https://example.com/mock-2"]);
      assert.equal(stats.requestsFinished, 2);
      assert.equal(stats.requestsFailed, 0);

      // Internally-owned pool must be closed after run().
      assert.equal(crawler.pool.closed, true);
      assert.equal(crawler.pool.stats().active, 0);
      assert.equal(crawler.pool.stats().idle, 0);

      const data = await crawler.getData();
      assert.equal(data.items.length, 2);
      for (const item of data.items) {
        assert.equal(typeof item.nodeCount, "number");
        assert.ok((item.nodeCount as number) > 0);
      }
    });
  });
});

/** Opt-in production trace bundle recorder and HAR 1.2 exporter. */

import { appendFile, mkdir, rm, writeFile } from "node:fs/promises";
import { STATUS_CODES } from "node:http";
import path from "node:path";
import { DEFAULT_VERSION } from "./binary.js";
import type { AccessibilityNode, CapturedResponse, HttpHeader } from "./types.js";

/** Common credential and session headers that callers can redact in shared traces. */
export const SENSITIVE_HEADERS = [
  "authorization",
  "cookie",
  "set-cookie",
  "proxy-authorization",
  "x-api-key",
] as const;

export const REDACTED_VALUE = "[REDACTED]";
export const TRACE_MANIFEST_VERSION = 1;

const SDK_VERSION = DEFAULT_VERSION.replace(/^v/, "");
const SLUG_RE = /[^a-z0-9_-]+/g;
const MAX_SLUG_LEN = 64;

export interface HarCreator {
  readonly name: string;
  readonly version: string;
}

export interface HarHeader {
  readonly name: string;
  readonly value: string;
}

export interface HarQueryParam {
  readonly name: string;
  readonly value: string;
}

export interface HarPostData {
  readonly mimeType: string;
  readonly text: string;
}

export interface HarRequest {
  readonly method: string;
  readonly url: string;
  readonly httpVersion: string;
  readonly cookies: readonly never[];
  readonly headers: readonly HarHeader[];
  readonly queryString: readonly HarQueryParam[];
  readonly headersSize: number;
  readonly bodySize: number;
  readonly postData?: HarPostData;
}

export interface HarContent {
  readonly size: number;
  readonly mimeType: string;
  readonly text: string;
}

export interface HarResponse {
  readonly status: number;
  readonly statusText: string;
  readonly httpVersion: string;
  readonly cookies: readonly never[];
  readonly headers: readonly HarHeader[];
  readonly content: HarContent;
  readonly redirectURL: string;
  readonly headersSize: number;
  readonly bodySize: number;
}

export interface HarTimings {
  readonly send: number;
  readonly wait: number;
  readonly receive: number;
}

export interface HarEntry {
  readonly startedDateTime: string;
  readonly time: number;
  readonly request: HarRequest;
  readonly response: HarResponse;
  readonly cache: Readonly<Record<string, never>>;
  readonly timings: HarTimings;
}

export interface HarLog {
  readonly version: "1.2";
  readonly creator: HarCreator;
  readonly entries: readonly HarEntry[];
}

export interface HarDocument {
  readonly log: HarLog;
}

export interface ResponsesToHarOptions {
  /** Header names (case-insensitive) whose values should be replaced with `"[REDACTED]"`. */
  readonly redactHeaders?: readonly string[];
}

function isoUtcFromMs(tsMs: number | null): string {
  const date = tsMs !== null ? new Date(tsMs) : new Date();
  return Number.isNaN(date.getTime()) ? new Date().toISOString() : date.toISOString();
}

function parseQueryString(rawUrl: string): HarQueryParam[] {
  try {
    const parsed = new URL(rawUrl);
    const params: HarQueryParam[] = [];
    for (const [name, value] of parsed.searchParams.entries()) {
      params.push({ name, value });
    }
    return params;
  } catch {
    return [];
  }
}

function formatHeaders(headers: readonly HttpHeader[], redacted: ReadonlySet<string>): HarHeader[] {
  return headers.map((header) => ({
    name: header.name,
    value: redacted.has(header.name.toLowerCase()) ? REDACTED_VALUE : header.value,
  }));
}

function firstHeader(headers: readonly HttpHeader[], name: string): string | null {
  const wanted = name.toLowerCase();
  for (const header of headers) {
    if (header.name.toLowerCase() === wanted) {
      return header.value;
    }
  }
  return null;
}

function utf8ByteLen(text: string | null): number {
  return text !== null ? Buffer.byteLength(text, "utf8") : 0;
}

/**
 * Convert passively captured HTTP responses into a spec-compliant HAR 1.2 document.
 *
 * Pass `{ redactHeaders: SENSITIVE_HEADERS }` (or custom header names) to replace
 * matching request and response header values with `"[REDACTED]"`.
 */
export function responsesToHar(
  responses: readonly CapturedResponse[],
  options: ResponsesToHarOptions = {},
): HarDocument {
  const redacted = new Set((options.redactHeaders ?? []).map((name) => name.toLowerCase()));
  const entries: HarEntry[] = responses.map((resp) => {
    const reqBodySize = utf8ByteLen(resp.requestBody);
    const baseRequest: HarRequest = {
      method: resp.requestMethod || "GET",
      url: resp.url,
      httpVersion: "HTTP/1.1",
      cookies: [],
      headers: formatHeaders(resp.requestHeaders, redacted),
      queryString: parseQueryString(resp.url),
      headersSize: -1,
      bodySize: reqBodySize,
    };
    const request: HarRequest =
      resp.requestBody !== null
        ? {
            ...baseRequest,
            postData: {
              mimeType:
                firstHeader(resp.requestHeaders, "content-type") ?? "application/octet-stream",
              text: resp.requestBody,
            },
          }
        : baseRequest;

    const respBodySize = utf8ByteLen(resp.body);
    const respMime =
      resp.contentType ?? firstHeader(resp.headers, "content-type") ?? "application/octet-stream";

    const response: HarResponse = {
      status: resp.status,
      statusText: STATUS_CODES[resp.status] ?? "",
      httpVersion: "HTTP/1.1",
      cookies: [],
      headers: formatHeaders(resp.headers, redacted),
      content: {
        size: respBodySize,
        mimeType: respMime,
        text: resp.body ?? "",
      },
      redirectURL: "",
      headersSize: -1,
      bodySize: respBodySize,
    };

    return {
      startedDateTime: isoUtcFromMs(resp.capturedAtMs),
      time: 0,
      request,
      response,
      cache: {},
      timings: { send: 0, wait: 0, receive: 0 },
    };
  });

  return {
    log: {
      version: "1.2",
      creator: {
        name: "waybound",
        version: SDK_VERSION,
      },
      entries,
    },
  };
}

/** Structural subset of `Page` required by `TraceRecorder`. */
export interface TracePageLike {
  url(): Promise<string | null>;
  screenshot(filePath?: string | null): Promise<Buffer>;
  snapshotTree(): Promise<AccessibilityNode[]>;
  capturedResponses(): Promise<CapturedResponse[]>;
}

export interface TraceRecorderOptions {
  /** If `true`, delete the trace bundle on clean success and keep it only on failure. */
  readonly onErrorOnly?: boolean;
  /** Capture PNG screenshots on `recordSnapshot()` and failure finalization. Default `true`. */
  readonly captureScreenshots?: boolean;
  /** Capture AX tree JSON snapshots on `recordSnapshot()` and failure finalization. Default `true`. */
  readonly captureTrees?: boolean;
  /** Export `network.har` on `finalize()`. Default `true`. */
  readonly captureHar?: boolean;
  /** Header names (case-insensitive) to redact in `network.har`. */
  readonly redactHeaders?: readonly string[];
}

export interface RecordActionOptions {
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly error?: string | null;
  readonly url?: string | null;
}

export interface RecordSnapshotOptions {
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly error?: string | null;
}

export interface FinalizeOptions {
  readonly failed?: boolean;
  readonly error?: string | null;
}

export interface TraceEvent {
  readonly ts_ms: number;
  readonly seq: number;
  readonly action: string;
  readonly url: string | null;
  readonly metadata: Readonly<Record<string, unknown>>;
  readonly screenshot: string | null;
  readonly tree: string | null;
  readonly error: string | null;
}

export interface TraceManifest {
  readonly version: number;
  readonly failed: boolean;
  readonly event_count: number;
  readonly har_entries: number;
  readonly created_at: string;
}

function slugify(label: string): string {
  const slug = label
    .trim()
    .toLowerCase()
    .replace(SLUG_RE, "_")
    .replace(/^_+|_+$/g, "");
  return slug.length > 0 ? slug.slice(0, MAX_SLUG_LEN) : "snapshot";
}

function formatError(err: unknown): string {
  if (err instanceof Error) {
    return `${err.name}: ${err.message}`;
  }
  return String(err);
}

function joinErrors(base: string | null, extra: readonly string[]): string | null {
  const parts: string[] = [];
  if (base !== null && base.length > 0) {
    parts.push(base);
  }
  parts.push(...extra);
  return parts.length > 0 ? parts.join("; ") : null;
}

function serializeNode(node: AccessibilityNode): Record<string, unknown> {
  return {
    id: node.id,
    role: node.role,
    name: node.name,
    value: node.value,
    bounds: {
      x: node.bounds.x,
      y: node.bounds.y,
      width: node.bounds.width,
      height: node.bounds.height,
    },
    focused: node.focused,
    url: node.url ?? null,
  };
}

/**
 * Opt-in production trace bundle recorder.
 *
 * Writes `manifest.json`, `timeline.jsonl`, `screenshots/*.png`, `trees/*.json`,
 * and `network.har` into `outputDir`. Prefer `withTrace()` for automatic failure
 * capture and `onErrorOnly` cleanup without masking the caller's error.
 */
export class TraceRecorder {
  readonly #page: TracePageLike;
  readonly #outputDir: string;
  readonly #onErrorOnly: boolean;
  readonly #captureScreenshots: boolean;
  readonly #captureTrees: boolean;
  readonly #captureHar: boolean;
  readonly #redactHeaders: readonly string[];
  #seq = 0;
  #eventCount = 0;
  #finalized = false;
  #finalizedPath: string | null = null;

  constructor(page: TracePageLike, outputDir: string, options: TraceRecorderOptions = {}) {
    this.#page = page;
    this.#outputDir = path.resolve(outputDir);
    this.#onErrorOnly = options.onErrorOnly ?? false;
    this.#captureScreenshots = options.captureScreenshots ?? true;
    this.#captureTrees = options.captureTrees ?? true;
    this.#captureHar = options.captureHar ?? true;
    this.#redactHeaders = [...(options.redactHeaders ?? [])];
  }

  /** Resolved directory where the trace bundle is staged and written. */
  get outputDir(): string {
    return this.#outputDir;
  }

  async #ensureDirs(): Promise<void> {
    await mkdir(this.#outputDir, { recursive: true });
    if (this.#captureScreenshots) {
      await mkdir(path.join(this.#outputDir, "screenshots"), { recursive: true });
    }
    if (this.#captureTrees) {
      await mkdir(path.join(this.#outputDir, "trees"), { recursive: true });
    }
  }

  async #appendEvent(event: TraceEvent): Promise<TraceEvent> {
    await mkdir(this.#outputDir, { recursive: true });
    await appendFile(
      path.join(this.#outputDir, "timeline.jsonl"),
      `${JSON.stringify(event)}\n`,
      "utf8",
    );
    this.#eventCount += 1;
    return event;
  }

  /** Append a structured action event to `timeline.jsonl`. */
  async recordAction(name: string, options: RecordActionOptions = {}): Promise<TraceEvent> {
    this.#seq += 1;
    return this.#appendEvent({
      ts_ms: Date.now(),
      seq: this.#seq,
      action: name,
      url: options.url ?? null,
      metadata: options.metadata ? { ...options.metadata } : {},
      screenshot: null,
      tree: null,
      error: options.error ?? null,
    });
  }

  /** Capture URL, PNG screenshot, and AX tree JSON, recording any capture errors best-effort. */
  async recordSnapshot(label: string, options: RecordSnapshotOptions = {}): Promise<TraceEvent> {
    await this.#ensureDirs();
    this.#seq += 1;
    const seq = this.#seq;
    const seqPrefix = String(seq).padStart(3, "0");
    const slug = slugify(label);
    const captureErrors: string[] = [];

    let url: string | null = null;
    try {
      url = await this.#page.url();
    } catch (err) {
      captureErrors.push(`url capture failed: ${formatError(err)}`);
    }

    let screenshotRel: string | null = null;
    if (this.#captureScreenshots) {
      const rel = `screenshots/${seqPrefix}_${slug}.png`;
      try {
        await this.#page.screenshot(path.join(this.#outputDir, rel));
        screenshotRel = rel;
      } catch (err) {
        captureErrors.push(`screenshot capture failed: ${formatError(err)}`);
      }
    }

    let treeRel: string | null = null;
    if (this.#captureTrees) {
      const rel = `trees/${seqPrefix}_${slug}.json`;
      try {
        const nodes = await this.#page.snapshotTree();
        await writeFile(
          path.join(this.#outputDir, rel),
          JSON.stringify(nodes.map(serializeNode)),
          "utf8",
        );
        treeRel = rel;
      } catch (err) {
        captureErrors.push(`tree capture failed: ${formatError(err)}`);
      }
    }

    return this.#appendEvent({
      ts_ms: Date.now(),
      seq,
      action: `snapshot:${label}`,
      url,
      metadata: options.metadata ? { ...options.metadata } : {},
      screenshot: screenshotRel,
      tree: treeRel,
      error: joinErrors(options.error ?? null, captureErrors),
    });
  }

  /** Finalize the trace bundle. Returns the bundle directory path, or `null` when discarded. */
  async finalize(options: FinalizeOptions = {}): Promise<string | null> {
    if (this.#finalized) {
      return this.#finalizedPath;
    }
    this.#finalized = true;
    const failed = options.failed ?? false;

    if (this.#onErrorOnly && !failed) {
      await rm(this.#outputDir, { recursive: true, force: true });
      this.#finalizedPath = null;
      return null;
    }

    await this.#ensureDirs();
    if (failed) {
      const snapshotOpts: RecordSnapshotOptions =
        options.error !== undefined ? { error: options.error } : {};
      await this.recordSnapshot("failure", snapshotOpts);
    }

    let harEntries = 0;
    if (this.#captureHar) {
      let responses: CapturedResponse[] = [];
      try {
        responses = await this.#page.capturedResponses();
      } catch (err) {
        await this.recordAction("capture_har_error", { error: formatError(err) });
      }
      const har = responsesToHar(responses, { redactHeaders: this.#redactHeaders });
      await writeFile(
        path.join(this.#outputDir, "network.har"),
        JSON.stringify(har, null, 2),
        "utf8",
      );
      harEntries = responses.length;
    }

    const manifest: TraceManifest = {
      version: TRACE_MANIFEST_VERSION,
      failed,
      event_count: this.#eventCount,
      har_entries: harEntries,
      created_at: new Date().toISOString(),
    };
    await writeFile(
      path.join(this.#outputDir, "manifest.json"),
      JSON.stringify(manifest, null, 2),
      "utf8",
    );
    this.#finalizedPath = this.#outputDir;
    return this.#outputDir;
  }
}

/**
 * Run `fn` with an active `TraceRecorder`. Automatically finalizes with `failed: true`
 * on thrown errors (never masking the original error) and cleans up when `onErrorOnly` is set.
 */
export async function withTrace<T>(
  page: TracePageLike,
  outputDir: string,
  fn: (trace: TraceRecorder) => Promise<T>,
  options: TraceRecorderOptions = {},
): Promise<T> {
  const trace = new TraceRecorder(page, outputDir, options);
  try {
    const result = await fn(trace);
    await trace.finalize({ failed: false });
    return result;
  } catch (err) {
    try {
      await trace.finalize({ failed: true, error: formatError(err) });
    } catch {
      // Never mask the caller's original exception if trace finalization fails.
    }
    throw err;
  }
}

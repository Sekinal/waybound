/**
 * Browser-to-HTTP handoff client replaying captured BoringSSL + HTTP/2 fingerprints
 * through a lightweight `waybound-daemon --replay` worker over stdio NDJSON.
 */

import { type ChildProcess, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { resolveDaemonBinary } from "./binary.js";
import { WayboundDaemonError } from "./errors.js";
import { DEFAULT_MAX_LINE_BYTES, encodeLine, LineDecoder } from "./framing.js";
import { checkMs, DEFAULT_TIMEOUT_MS, type JsonObject, MAX_TIMER_MS } from "./transport.js";
import {
  type CapturedCookie,
  parseCapturedCookie,
  parseSessionFingerprint,
  type SessionFingerprint,
  serializeSessionFingerprint,
} from "./types.js";

/** Extra client-side slack on top of `timeoutMs` for replay worker RPCs. */
const RPC_TIMEOUT_SLACK_MS = 10_000;
/** How long `close()` waits for an in-flight RPC before aborting it. */
const CLOSE_DRAIN_TIMEOUT_MS = 2_000;
/** How long `close()` waits for graceful exit after sending `shutdown`. */
const SHUTDOWN_EXIT_TIMEOUT_MS = 2_000;
/** How long `close()` waits after `SIGTERM` before escalating to `SIGKILL`. */
const SIGTERM_EXIT_TIMEOUT_MS = 2_000;
/** Grace window after stdout EOF to allow stderr + process exit to flush. */
const EOF_GRACE_MS = 25;
/** Maximum buffered stderr characters retained for diagnostics. */
const MAX_STDERR_BUFFER_CHARS = 4_096;
/** Maximum stderr tail length included in error messages. */
const MAX_STDERR_DETAIL_CHARS = 500;

const HEADER_INJECTION_RE = /[\r\n\0]/;

/** File specification accepted in `HandoffRequestOptions.files`. */
export type MultipartFile =
  | Uint8Array
  | readonly [filename: string, data: Uint8Array]
  | readonly [filename: string, data: Uint8Array, contentType: string];

/** Configuration options for `HandoffHttpClient.create()` and `HandoffHttpClient.fromJson()`. */
export interface HandoffHttpClientOptions {
  /** Optional upstream HTTP/HTTPS/SOCKS5 proxy URL. */
  readonly proxy?: string;
  /** Per-request HTTP timeout in milliseconds. Default 30 000. */
  readonly timeoutMs?: number;
  /** Whether to follow HTTP 3xx redirects automatically. Default `true`. */
  readonly followRedirects?: boolean;
  /** Opt-in HTTP/3 (QUIC) transport with transparent fallback to BoringSSL HTTP/2. Default `false`. */
  readonly http3?: boolean;
  /** Explicit `waybound-daemon` binary path; otherwise resolved via `resolveDaemonBinary()`. */
  readonly daemonBinary?: string;
  /**
   * Optional callback invoked once per `request()` when the response status is in
   * `refreshStatuses`. Its returned `SessionFingerprint` is hot-swapped and the request retried.
   */
  readonly onRefresh?: () => Promise<SessionFingerprint> | SessionFingerprint;
  /** HTTP status codes that trigger `onRefresh`. Default `[403]`. */
  readonly refreshStatuses?: readonly number[];
}

/** Per-request options for `HandoffHttpClient.request()` and HTTP verb helpers. */
export interface HandoffRequestOptions {
  /** Extra HTTP request headers (map or ordered `[name, value]` pairs). */
  readonly headers?: Readonly<Record<string, string>> | readonly (readonly [string, string])[];
  /** Raw UTF-8 string or binary request body. Mutually exclusive with `jsonBody` and `data`/`files`. */
  readonly body?: string | Uint8Array;
  /** Value serialized as JSON with `content-type: application/json`. */
  readonly jsonBody?: unknown;
  /** Form fields serialized as `application/x-www-form-urlencoded` (or multipart when `files` is set). */
  readonly data?: Readonly<Record<string, string>>;
  /** Multipart file uploads serialized as `multipart/form-data`. */
  readonly files?: Readonly<Record<string, MultipartFile>>;
}

/** HTTP response returned by `HandoffHttpClient`. */
export class HandoffResponse {
  readonly url: string;
  readonly status: number;
  readonly headers: readonly (readonly [string, string])[];
  readonly body: string;
  readonly content: Buffer;

  constructor(
    url: string,
    status: number,
    headers: readonly (readonly [string, string])[],
    body: string,
    content?: Buffer | Uint8Array,
  ) {
    this.url = url;
    this.status = status;
    this.headers = headers;
    this.body = body;
    if (content !== undefined) {
      this.content = Buffer.isBuffer(content) ? content : Buffer.from(content);
    } else {
      this.content = Buffer.from(body, "utf8");
    }
  }

  /** Return the response body decoded as UTF-8 text. */
  get text(): string {
    return this.body;
  }

  /** Parse and return the response body as JSON. */
  json<T = unknown>(): T {
    return JSON.parse(this.body) as T;
  }

  /** Return the first response header value matching `name` (case-insensitive). */
  header(name: string): string | undefined {
    const target = name.toLowerCase();
    for (const [k, v] of this.headers) {
      if (k.toLowerCase() === target) {
        return v;
      }
    }
    return undefined;
  }
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function describe(value: unknown): string {
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

const HTTP_METHOD_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

function escapeDispositionParam(value: string): string {
  return value
    .replaceAll("\\", "\\\\")
    .replaceAll('"', '\\"')
    .replace(/[\r\n\0]/g, "");
}

function sanitizeHeaderValue(value: string): string {
  return value.replace(/[\r\n\0]/g, "");
}

function normalizeHeaders(
  headers: Readonly<Record<string, string>> | readonly (readonly [string, string])[] | undefined,
): [string, string][] {
  if (headers === undefined) {
    return [];
  }
  const pairs: [string, string][] = Array.isArray(headers)
    ? headers.map(([k, v]) => [String(k), String(v)])
    : Object.entries(headers).map(([k, v]) => [String(k), String(v)]);
  for (const [name, value] of pairs) {
    if (name.length === 0 || HEADER_INJECTION_RE.test(name)) {
      throw new TypeError(`invalid HTTP header name: ${JSON.stringify(name)}`);
    }
    if (HEADER_INJECTION_RE.test(value)) {
      throw new TypeError(`invalid HTTP header value for ${JSON.stringify(name)}`);
    }
  }
  return pairs;
}

/** @internal Encode `data` and `files` as an RFC 7578 `multipart/form-data` payload. */
export function encodeMultipart(
  data: Readonly<Record<string, string>> | undefined,
  files: Readonly<Record<string, MultipartFile>>,
): { body: Buffer; contentType: string } {
  const boundary = `----WayboundBoundary${randomBytes(16).toString("hex")}`;
  const boundaryBytes = Buffer.from(boundary, "ascii");
  const crlf = Buffer.from("\r\n", "ascii");
  const dashes = Buffer.from("--", "ascii");
  const chunks: Buffer[] = [];

  if (data !== undefined) {
    for (const [fieldName, fieldValue] of Object.entries(data)) {
      const escapedName = escapeDispositionParam(fieldName);
      chunks.push(dashes, boundaryBytes, crlf);
      chunks.push(
        Buffer.from(`Content-Disposition: form-data; name="${escapedName}"\r\n\r\n`, "utf8"),
      );
      chunks.push(Buffer.from(fieldValue, "utf8"), crlf);
    }
  }

  for (const [fieldName, fileSpec] of Object.entries(files)) {
    let filename: string;
    let payload: Uint8Array;
    let contentType: string;

    if (fileSpec instanceof Uint8Array) {
      filename = fieldName;
      payload = fileSpec;
      contentType = "application/octet-stream";
    } else if (Array.isArray(fileSpec) && fileSpec.length === 2) {
      [filename, payload] = fileSpec;
      contentType = "application/octet-stream";
    } else if (Array.isArray(fileSpec) && fileSpec.length === 3) {
      [filename, payload, contentType] = fileSpec;
    } else {
      throw new TypeError(
        `invalid multipart file spec for ${JSON.stringify(fieldName)}: expected Uint8Array or [filename, data, contentType?]`,
      );
    }

    const escapedName = escapeDispositionParam(fieldName);
    const escapedFilename = escapeDispositionParam(filename);
    const cleanContentType = sanitizeHeaderValue(contentType);
    chunks.push(dashes, boundaryBytes, crlf);
    chunks.push(
      Buffer.from(
        `Content-Disposition: form-data; name="${escapedName}"; filename="${escapedFilename}"\r\n`,
        "utf8",
      ),
    );
    chunks.push(Buffer.from(`Content-Type: ${cleanContentType}\r\n\r\n`, "utf8"));
    chunks.push(Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength));
    chunks.push(crlf);
  }

  chunks.push(dashes, boundaryBytes, dashes, crlf);
  return {
    body: Buffer.concat(chunks),
    contentType: `multipart/form-data; boundary=${boundary}`,
  };
}

/** @internal Validate and encode request headers + body payload for the replay RPC. */
export function prepareRequestPayload(options: HandoffRequestOptions): {
  headers: [string, string][];
  body: string | Uint8Array | undefined;
} {
  const encodedHeaders = normalizeHeaders(options.headers);
  const specified =
    (options.body !== undefined ? 1 : 0) +
    (options.jsonBody !== undefined ? 1 : 0) +
    (options.data !== undefined || options.files !== undefined ? 1 : 0);
  if (specified > 1) {
    throw new TypeError("specify at most one of 'body', 'jsonBody', or 'data'/'files'");
  }

  const hasContentType = encodedHeaders.some(([k]) => k.toLowerCase() === "content-type");

  if (options.files !== undefined) {
    const { body, contentType } = encodeMultipart(options.data, options.files);
    if (!hasContentType) {
      encodedHeaders.push(["content-type", contentType]);
    }
    return { headers: encodedHeaders, body };
  }

  if (options.data !== undefined) {
    const formBody = new URLSearchParams(Object.entries(options.data)).toString();
    if (!hasContentType) {
      encodedHeaders.push(["content-type", "application/x-www-form-urlencoded"]);
    }
    return { headers: encodedHeaders, body: formBody };
  }

  if (options.jsonBody !== undefined) {
    const serialized = JSON.stringify(options.jsonBody);
    if (serialized === undefined) {
      throw new TypeError("jsonBody is not JSON-serializable");
    }
    if (!hasContentType) {
      encodedHeaders.push(["content-type", "application/json"]);
    }
    return { headers: encodedHeaders, body: serialized };
  }

  return { headers: encodedHeaders, body: options.body };
}

function parseHandoffResponse(raw: JsonObject): HandoffResponse {
  const url = typeof raw.url === "string" ? raw.url : "";
  const status = typeof raw.status === "number" && Number.isInteger(raw.status) ? raw.status : 0;
  const headers: [string, string][] = [];
  if (Array.isArray(raw.headers)) {
    for (const pair of raw.headers) {
      if (Array.isArray(pair) && pair.length === 2) {
        headers.push([String(pair[0]), String(pair[1])]);
      }
    }
  }
  if (typeof raw.body_base64 === "string") {
    const content = Buffer.from(raw.body_base64, "base64");
    const body = typeof raw.body === "string" ? raw.body : content.toString("utf8");
    return new HandoffResponse(url, status, headers, body, content);
  }
  const body = typeof raw.body === "string" ? raw.body : "";
  return new HandoffResponse(url, status, headers, body, Buffer.from(body, "utf8"));
}

// Track live replay workers so forgotten clients never leave orphan processes behind.
const liveWorkers = new Set<ChildProcess>();
const FORWARDED_SIGNALS: readonly NodeJS.Signals[] =
  process.platform === "win32" ? [] : ["SIGTERM", "SIGHUP", "SIGINT"];
const signalHandlers = new Map<NodeJS.Signals, () => void>();

function hasExited(child: ChildProcess): boolean {
  return child.exitCode !== null || child.signalCode !== null;
}

function killAllWorkersSync(): void {
  for (const child of liveWorkers) {
    if (!hasExited(child)) {
      child.kill("SIGTERM");
    }
  }
  liveWorkers.clear();
}

function removeProcessHooks(): void {
  process.off("exit", killAllWorkersSync);
  for (const [signal, handler] of signalHandlers) {
    process.off(signal, handler);
  }
  signalHandlers.clear();
}

function installProcessHooks(): void {
  if (signalHandlers.size > 0 || process.listeners("exit").includes(killAllWorkersSync)) {
    return;
  }
  process.on("exit", killAllWorkersSync);
  for (const signal of FORWARDED_SIGNALS) {
    const handler = (): void => {
      killAllWorkersSync();
      removeProcessHooks();
      if (process.listenerCount(signal) === 0) {
        process.kill(process.pid, signal);
      }
    };
    signalHandlers.set(signal, handler);
    process.on(signal, handler);
  }
}

function trackWorker(child: ChildProcess): void {
  liveWorkers.add(child);
  installProcessHooks();
}

function untrackWorker(child: ChildProcess): void {
  liveWorkers.delete(child);
  if (liveWorkers.size === 0) {
    removeProcessHooks();
  }
}

/** @internal Number of replay workers currently tracked (for tests). */
export function _liveReplayWorkerCount(): number {
  return liveWorkers.size;
}

function waitForExit(child: ChildProcess, ms: number): Promise<boolean> {
  if (hasExited(child)) {
    return Promise.resolve(true);
  }
  return new Promise<boolean>((resolve) => {
    const onExit = (): void => {
      clearTimeout(timer);
      resolve(true);
    };
    // Never `.unref()` a timer driving an awaited Promise (Node 22 empty-loop trap).
    const timer = setTimeout(() => {
      child.off("exit", onExit);
      resolve(hasExited(child));
    }, ms);
    child.once("exit", onExit);
  });
}

async function stopWorker(child: ChildProcess, shutdownSent: boolean): Promise<void> {
  if (hasExited(child) || child.pid === undefined) {
    return;
  }
  if (shutdownSent && (await waitForExit(child, SHUTDOWN_EXIT_TIMEOUT_MS))) {
    return;
  }
  child.kill("SIGTERM");
  if (await waitForExit(child, SIGTERM_EXIT_TIMEOUT_MS)) {
    return;
  }
  child.kill("SIGKILL");
  await waitForExit(child, 1_000);
}

interface Refable {
  ref?(): unknown;
  unref?(): unknown;
}

function setRef(target: unknown, ref: boolean): void {
  const handle = target as Refable | null | undefined;
  if (ref) {
    handle?.ref?.();
  } else {
    handle?.unref?.();
  }
}

interface PendingRpc {
  readonly resolve: (value: JsonObject) => void;
  readonly reject: (reason: WayboundDaemonError) => void;
  readonly timer: NodeJS.Timeout;
}

/**
 * High-throughput BoringSSL + HTTP/2 client replaying a live browser `SessionFingerprint`.
 *
 * Runs a lightweight `waybound-daemon --replay` worker over stdio JSON-RPC with zero
 * browser process required once the fingerprint has been exported.
 */
export class HandoffHttpClient {
  readonly #child: ChildProcess;
  readonly #decoder = new LineDecoder(DEFAULT_MAX_LINE_BYTES);
  readonly #proxy: string | null;
  readonly #timeoutMs: number;
  readonly #rpcTimeoutMs: number;
  readonly #followRedirects: boolean;
  readonly #http3: boolean;
  readonly #onRefresh: (() => Promise<SessionFingerprint> | SessionFingerprint) | undefined;
  readonly #refreshStatuses: ReadonlySet<number>;

  #fingerprint: SessionFingerprint;
  #fingerprintGeneration = 0;
  #refreshInFlight: Promise<void> | null = null;
  #pending: PendingRpc | null = null;
  #tail: Promise<void> = Promise.resolve();
  #stderrTail = "";
  #eofGraceTimer: NodeJS.Timeout | null = null;
  #spawnError: WayboundDaemonError | null = null;
  #closed = false;
  #closing: Promise<void> | null = null;
  #teardown: Promise<void> | null = null;

  private constructor(
    child: ChildProcess,
    fingerprint: SessionFingerprint,
    options: {
      proxy: string | null;
      timeoutMs: number;
      followRedirects: boolean;
      http3: boolean;
      onRefresh: (() => Promise<SessionFingerprint> | SessionFingerprint) | undefined;
      refreshStatuses: readonly number[];
    },
  ) {
    this.#child = child;
    this.#fingerprint = fingerprint;
    this.#proxy = options.proxy;
    this.#timeoutMs = options.timeoutMs;
    this.#rpcTimeoutMs = Math.min(MAX_TIMER_MS, options.timeoutMs + RPC_TIMEOUT_SLACK_MS);
    this.#followRedirects = options.followRedirects;
    this.#http3 = options.http3;
    this.#onRefresh = options.onRefresh;
    this.#refreshStatuses = new Set(options.refreshStatuses);

    trackWorker(child);

    child.stdin?.on("error", (err: Error) => {
      if (!this.#closed && this.#closing === null) {
        this.#fail(this.#ioError(err));
      }
    });
    child.stdout?.on("data", (chunk: Buffer) => this.#onData(chunk));
    child.stdout?.on("end", () => {
      if (this.#closed || this.#closing !== null) {
        return;
      }
      // Give `child` "close" a brief window so buffered stderr flushes before failing.
      this.#eofGraceTimer ??= setTimeout(() => {
        this.#eofGraceTimer = null;
        if (!this.#closed) {
          this.#fail(this.#eofError());
        }
      }, EOF_GRACE_MS);
    });
    child.stdout?.on("error", (err: Error) => {
      if (!this.#closed && this.#closing === null) {
        this.#fail(this.#ioError(err));
      }
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      this.#stderrTail += chunk.toString("utf8");
      if (this.#stderrTail.length > MAX_STDERR_BUFFER_CHARS) {
        this.#stderrTail = this.#stderrTail.slice(-MAX_STDERR_BUFFER_CHARS);
      }
    });
    child.stderr?.on("error", () => undefined);
    child.on("error", (err: Error) => {
      const wrapped = this.#ioError(err);
      if (this.#pending === null && !this.#closed) {
        this.#spawnError = wrapped;
      }
      this.#fail(wrapped);
    });
    child.on("close", () => {
      this.#clearEofGrace();
      untrackWorker(child);
      if (!this.#closed) {
        this.#fail(this.#eofError());
      }
    });
  }

  /**
   * Spawn a `waybound-daemon --replay` worker and initialize it with `fingerprint`.
   * If initialization fails, the worker is terminated before rethrowing.
   */
  static async create(
    fingerprint: SessionFingerprint,
    options: HandoffHttpClientOptions = {},
  ): Promise<HandoffHttpClient> {
    const timeoutMs = Math.max(1, checkMs(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, "timeoutMs"));
    const binary = resolveDaemonBinary(options.daemonBinary ?? null);
    const child = spawn(binary, ["--replay"], {
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    const client = new HandoffHttpClient(child, fingerprint, {
      proxy: options.proxy ?? null,
      timeoutMs,
      followRedirects: options.followRedirects ?? true,
      http3: options.http3 ?? false,
      onRefresh: options.onRefresh,
      refreshStatuses: options.refreshStatuses ?? [403],
    });
    try {
      await client.#initWorker(fingerprint);
      return client;
    } catch (err) {
      await client.close();
      throw err;
    }
  }

  /** Construct a `HandoffHttpClient` from a JSON-serialized `SessionFingerprint`. */
  static async fromJson(
    rawJson: string,
    options: HandoffHttpClientOptions = {},
  ): Promise<HandoffHttpClient> {
    const decoded: unknown = JSON.parse(rawJson);
    const fingerprint = parseSessionFingerprint(decoded);
    return HandoffHttpClient.create(fingerprint, options);
  }

  /** Active `SessionFingerprint` configured on this client. */
  get fingerprint(): SessionFingerprint {
    return this.#fingerprint;
  }

  /** PID of the underlying replay worker process, if spawned. */
  get pid(): number | undefined {
    return this.#child.pid;
  }

  /** `true` once `close()` has started or the worker connection has failed. */
  get closed(): boolean {
    return this.#closed || this.#closing !== null;
  }

  /** Hot-swap the active TLS/HTTP2 fingerprint and cookie jar without restarting the worker. */
  async updateFingerprint(fingerprint: SessionFingerprint): Promise<void> {
    await this.#initWorker(fingerprint);
    this.#fingerprint = fingerprint;
    this.#fingerprintGeneration += 1;
  }

  /** Coalesce concurrent `onRefresh` invocations so parallel 403s trigger one refresh. */
  async #refreshOnce(expectedGeneration: number): Promise<void> {
    if (this.closed) {
      throw new WayboundDaemonError("closed", "handoff HTTP client is closed");
    }
    if (this.#fingerprintGeneration !== expectedGeneration) {
      return;
    }
    if (this.#refreshInFlight !== null) {
      await this.#refreshInFlight;
      if (this.closed) {
        throw new WayboundDaemonError("closed", "handoff HTTP client is closed");
      }
      return;
    }
    const onRefresh = this.#onRefresh;
    if (onRefresh === undefined) {
      return;
    }
    const run = (async () => {
      const refreshed = await onRefresh();
      if (this.closed) {
        throw new WayboundDaemonError("closed", "handoff HTTP client is closed");
      }
      await this.updateFingerprint(refreshed);
    })();
    this.#refreshInFlight = run;
    try {
      await run;
    } finally {
      if (this.#refreshInFlight === run) {
        this.#refreshInFlight = null;
      }
    }
  }

  /** Send an HTTP request replaying the captured browser fingerprint and cookies. */
  async request(
    method: string,
    url: string,
    options: HandoffRequestOptions = {},
  ): Promise<HandoffResponse> {
    if (!HTTP_METHOD_RE.test(method)) {
      throw new TypeError(`invalid HTTP method: ${JSON.stringify(method)}`);
    }
    const { headers, body } = prepareRequestPayload(options);
    const generationBefore = this.#fingerprintGeneration;
    let result = await this.#executeOnce(method, url, headers, body);
    if (this.#onRefresh !== undefined && this.#refreshStatuses.has(result.status) && !this.closed) {
      await this.#refreshOnce(generationBefore);
      result = await this.#executeOnce(method, url, headers, body);
    }
    return result;
  }

  /** Send an HTTP `GET` request. */
  get(url: string, options: Pick<HandoffRequestOptions, "headers"> = {}): Promise<HandoffResponse> {
    return this.request("GET", url, options);
  }

  /** Send an HTTP `HEAD` request. */
  head(
    url: string,
    options: Pick<HandoffRequestOptions, "headers"> = {},
  ): Promise<HandoffResponse> {
    return this.request("HEAD", url, options);
  }

  /** Send an HTTP `POST` request. */
  post(url: string, options: HandoffRequestOptions = {}): Promise<HandoffResponse> {
    return this.request("POST", url, options);
  }

  /** Send an HTTP `PUT` request. */
  put(url: string, options: HandoffRequestOptions = {}): Promise<HandoffResponse> {
    return this.request("PUT", url, options);
  }

  /** Send an HTTP `PATCH` request. */
  patch(url: string, options: HandoffRequestOptions = {}): Promise<HandoffResponse> {
    return this.request("PATCH", url, options);
  }

  /** Send an HTTP `DELETE` request. */
  delete(url: string, options: HandoffRequestOptions = {}): Promise<HandoffResponse> {
    return this.request("DELETE", url, options);
  }

  /** Return all cookies currently held by the handoff client. */
  async cookies(): Promise<CapturedCookie[]> {
    const resp = await this.#rpc({ method: "cookies" });
    if (resp.status !== "cookies" || !Array.isArray(resp.cookies)) {
      throw new WayboundDaemonError(
        "protocol_error",
        `unexpected replay cookies response: ${describe(resp)}`,
      );
    }
    const out: CapturedCookie[] = [];
    for (const entry of resp.cookies) {
      if (isObject(entry)) {
        out.push(parseCapturedCookie(entry));
      }
    }
    return out;
  }

  /**
   * Gracefully shut down the underlying `waybound-daemon --replay` worker process.
   * Serializes with any in-flight call (boundedly), sends `shutdown` over stdin,
   * and escalates to `SIGTERM` -> `SIGKILL` if needed. Idempotent.
   */
  close(): Promise<void> {
    this.#closing ??= this.#close();
    return this.#closing;
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  async #initWorker(fingerprint: SessionFingerprint): Promise<void> {
    const resp = await this.#rpc({
      method: "init",
      fingerprint: serializeSessionFingerprint(fingerprint),
      options: {
        proxy: this.#proxy,
        timeout_ms: this.#timeoutMs,
        follow_redirects: this.#followRedirects,
        http3: this.#http3,
      },
    });
    if (resp.status !== "ok") {
      throw new WayboundDaemonError(
        "protocol_error",
        `unexpected replay init response: ${describe(resp)}`,
      );
    }
  }

  async #executeOnce(
    method: string,
    url: string,
    headers: [string, string][],
    body: string | Uint8Array | undefined,
  ): Promise<HandoffResponse> {
    const payload: JsonObject = {
      method: "request",
      http_method: method,
      url,
      headers,
    };
    if (body instanceof Uint8Array) {
      payload.body_base64 = Buffer.from(body.buffer, body.byteOffset, body.byteLength).toString(
        "base64",
      );
    } else if (body !== undefined) {
      payload.body = body;
    }
    const resp = await this.#rpc(payload);
    if (resp.status !== "response" || !isObject(resp.response)) {
      throw new WayboundDaemonError(
        "protocol_error",
        `unexpected replay request response: ${describe(resp)}`,
      );
    }
    return parseHandoffResponse(resp.response);
  }

  #rpc(payload: JsonObject): Promise<JsonObject> {
    if (this.#spawnError !== null) {
      const err = this.#spawnError;
      this.#spawnError = null;
      return Promise.reject(err);
    }
    if (this.#closed || this.#closing !== null) {
      return Promise.reject(new WayboundDaemonError("closed", "handoff HTTP client is closed"));
    }
    const run = this.#tail.then(() => this.#send(payload));
    this.#tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  #send(payload: JsonObject): Promise<JsonObject> {
    if (this.#spawnError !== null) {
      const err = this.#spawnError;
      this.#spawnError = null;
      return Promise.reject(err);
    }
    if (this.#closed || this.#closing !== null) {
      return Promise.reject(new WayboundDaemonError("closed", "handoff HTTP client is closed"));
    }
    const stdin = this.#child.stdin;
    if (stdin === null || stdin.destroyed || !stdin.writable) {
      return Promise.reject(new WayboundDaemonError("closed", "handoff HTTP client is closed"));
    }
    let encoded: string;
    try {
      encoded = encodeLine(payload);
    } catch (err) {
      return Promise.reject(err);
    }
    return new Promise<JsonObject>((resolve, reject) => {
      // Never `.unref()` this timer: it drives an awaited Promise.
      const timer = setTimeout(() => {
        this.#fail(
          new WayboundDaemonError(
            "io_error",
            `replay worker request timed out after ${this.#rpcTimeoutMs}ms`,
          ),
        );
      }, this.#rpcTimeoutMs);
      this.#pending = { resolve, reject, timer };
      this.#setChildRef(true);
      stdin.write(encoded, (err) => {
        if (err && !this.#closed) {
          this.#fail(this.#ioError(err));
        }
      });
    });
  }

  #settle(): PendingRpc | null {
    const pending = this.#pending;
    this.#pending = null;
    if (pending !== null) {
      clearTimeout(pending.timer);
    }
    if (!this.#closed && this.#closing === null) {
      this.#setChildRef(false);
    }
    return pending;
  }

  #setChildRef(ref: boolean): void {
    setRef(this.#child, ref);
    setRef(this.#child.stdin, ref);
    setRef(this.#child.stdout, ref);
    setRef(this.#child.stderr, ref);
  }

  #clearEofGrace(): void {
    if (this.#eofGraceTimer !== null) {
      clearTimeout(this.#eofGraceTimer);
      this.#eofGraceTimer = null;
    }
  }

  #stderrDetail(): string {
    return this.#stderrTail.trim().slice(-MAX_STDERR_DETAIL_CHARS);
  }

  #eofError(): WayboundDaemonError {
    const detail = this.#stderrDetail();
    const message = detail
      ? `replay worker closed unexpectedly: ${detail}`
      : "replay worker closed unexpectedly";
    return new WayboundDaemonError("eof", message);
  }

  #ioError(err: Error): WayboundDaemonError {
    const detail = this.#stderrDetail();
    const message = detail ? `${err.message}: ${detail}` : err.message;
    return new WayboundDaemonError("io_error", message, { cause: err });
  }

  #fail(error: WayboundDaemonError): void {
    this.#clearEofGrace();
    const pending = this.#settle();
    if (!this.#closed) {
      this.#closed = true;
      this.#destroyStreams();
      // Ensure a poisoned worker (e.g. timeout or malformed JSON) cannot leak.
      this.#ensureTerminated(false);
    }
    pending?.reject(error);
  }

  #destroyStreams(): void {
    this.#child.stdin?.destroy();
    this.#child.stdout?.destroy();
    this.#child.stderr?.destroy();
  }

  #ensureTerminated(shutdownSent: boolean): Promise<void> {
    this.#teardown ??= stopWorker(this.#child, shutdownSent).finally(() => {
      untrackWorker(this.#child);
    });
    return this.#teardown;
  }

  #onData(chunk: Buffer): void {
    let lines: string[];
    try {
      lines = this.#decoder.push(chunk);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.#fail(new WayboundDaemonError("protocol_error", msg));
      return;
    }
    for (const line of lines) {
      if (this.#closed) {
        return;
      }
      if (line.trim() === "") {
        continue;
      }
      const pending = this.#pending;
      if (pending === null) {
        this.#fail(
          new WayboundDaemonError("protocol_error", "unsolicited reply from replay worker"),
        );
        return;
      }
      let decoded: unknown;
      try {
        decoded = JSON.parse(line);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        this.#fail(new WayboundDaemonError("protocol_error", `invalid JSON: ${msg}`));
        return;
      }
      if (!isObject(decoded)) {
        this.#fail(
          new WayboundDaemonError(
            "protocol_error",
            `expected JSON object from replay worker, got ${Array.isArray(decoded) ? "array" : typeof decoded}`,
          ),
        );
        return;
      }
      this.#settle();
      if (decoded.status === "error") {
        const code = decoded.code === undefined ? "unknown" : String(decoded.code);
        const message = decoded.message === undefined ? "unknown error" : String(decoded.message);
        pending.reject(new WayboundDaemonError(code, message));
      } else {
        pending.resolve(decoded);
      }
    }
  }

  async #drainInFlight(): Promise<void> {
    if (this.#pending === null) {
      return;
    }
    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, CLOSE_DRAIN_TIMEOUT_MS);
      void this.#tail.finally(() => {
        clearTimeout(timer);
        resolve();
      });
    });
  }

  async #close(): Promise<void> {
    this.#setChildRef(true);
    try {
      await this.#drainInFlight();
      this.#clearEofGrace();
      const pending = this.#settle();
      const wasClosed = this.#closed;
      this.#closed = true;
      pending?.reject(new WayboundDaemonError("closed", "handoff HTTP client is closed"));

      let shutdownSent = false;
      if (!wasClosed && !hasExited(this.#child)) {
        const stdin = this.#child.stdin;
        if (stdin !== null && !stdin.destroyed && stdin.writable) {
          try {
            stdin.write('{"method":"shutdown"}\n');
            stdin.end();
            shutdownSent = true;
          } catch {
            // fall through to signal escalation
          }
        }
      }
      await this.#ensureTerminated(shutdownSent);
      this.#destroyStreams();
    } finally {
      untrackWorker(this.#child);
    }
  }
}

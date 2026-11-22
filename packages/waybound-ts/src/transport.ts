/** Line-delimited JSON transport to waybound-daemon over a Unix socket or loopback TCP. */

import net from "node:net";
import { WayboundDaemonError } from "./errors.js";
import { encodeLine, LineDecoder } from "./framing.js";
import {
  type AccessibilityNode,
  Bounds,
  CapturedResponse,
  type KeyModifier,
  type LocatorQuery,
  NAMED_KEYS,
  type NamedKey,
  parseRole,
} from "./types.js";

/** Where the daemon listens: a Unix socket path, or a loopback TCP host/port. */
export type Endpoint =
  | { readonly socketPath: string }
  | { readonly host: string; readonly port: number };

export interface TransportOptions {
  /** Base per-request timeout in milliseconds (also bounds the connect). Default 30 000. */
  readonly timeoutMs?: number;
}

export type JsonObject = Record<string, unknown>;

/** An armed `wait_for_response`; see `Transport.expectResponse()`. */
export interface ResponseWaiter {
  /** Settles with the matching response, or rejects (e.g. code `timeout`). */
  readonly response: Promise<CapturedResponse>;
}

/** Default base per-request timeout, matching the Python SDK's `timeout_s=30.0`. */
export const DEFAULT_TIMEOUT_MS = 30_000;
/** The daemon paces typing at up to ~180 ms per key; allow headroom on top of the base timeout. */
export const FILL_MS_PER_CHAR = 250;
/** Extra client-side slack on top of a daemon-side wait budget. */
const WAIT_SLACK_MS = 5_000;
/** Daemon cap on `wait_for` and `wait_for_response` budgets (`MAX_WAIT_TIMEOUT_MS`). */
export const MAX_WAIT_MS = 120_000;
/** Daemon cap on the `wait_for_network_idle` budget. */
export const MAX_NETWORK_IDLE_TIMEOUT_MS = 60_000;
/** Daemon clamp range for `idle_ms`. */
export const MIN_IDLE_MS = 50;
export const MAX_IDLE_MS = 10_000;
/** Largest delay `setTimeout` honours; anything above it fires after 1 ms. */
export const MAX_TIMER_MS = 2 ** 31 - 1;

const NAMED_KEY_SET: ReadonlySet<string> = new Set(NAMED_KEYS);

interface Pending {
  readonly resolve: (value: JsonObject) => void;
  readonly reject: (reason: WayboundDaemonError) => void;
  readonly timer: NodeJS.Timeout;
}

/** Compute the client-side timeout for a daemon-side wait of `waitMs`. */
export function waitTimeoutMs(baseMs: number, waitMs: number): number {
  return Math.min(MAX_TIMER_MS, Math.max(baseMs, waitMs + WAIT_SLACK_MS));
}

/** Compute the client-side timeout for typing `text`. */
export function fillTimeoutMs(baseMs: number, text: string): number {
  return Math.min(MAX_TIMER_MS, baseMs + FILL_MS_PER_CHAR * [...text].length);
}

/**
 * Validate a millisecond duration supplied by the caller and clamp it to `max`.
 * Throws `TypeError` for anything that is not a finite, non-negative number.
 */
export function checkMs(value: unknown, what: string, max: number = MAX_TIMER_MS): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new TypeError(
      `${what} must be a finite, non-negative number of milliseconds, got ${describe(value)}`,
    );
  }
  return Math.min(max, Math.trunc(value));
}

function describe(value: unknown): string {
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * One connection to waybound-daemon.
 *
 * The protocol carries no request IDs: the daemon answers each line with exactly one line, in
 * order. Requests on one transport are therefore queued and sent one at a time, and a reply is
 * always matched to the single in-flight request. If a request times out on the client or the
 * stream breaks, the reply can no longer be matched, so the connection is closed and every
 * later call fails with code `closed`. A structured daemon error (`status: "error"`) keeps the
 * connection usable.
 */
export class Transport {
  readonly endpoint: Endpoint;
  readonly baseTimeoutMs: number;
  readonly #socket: net.Socket;
  readonly #decoder = new LineDecoder();
  #pending: Pending | null = null;
  #tail: Promise<void> = Promise.resolve();
  #closed = false;

  private constructor(socket: net.Socket, endpoint: Endpoint, baseTimeoutMs: number) {
    this.#socket = socket;
    this.endpoint = endpoint;
    this.baseTimeoutMs = baseTimeoutMs;
    socket.on("data", (chunk: Buffer) => this.#onData(chunk));
    socket.on("error", (err: Error) => {
      this.#fail(new WayboundDaemonError("io_error", err.message, { cause: err }));
    });
    socket.on("close", () => {
      this.#fail(new WayboundDaemonError("eof", "daemon closed connection unexpectedly"));
    });
    // Idle connections must not keep the event loop alive; `#send` refs while a call is out.
    socket.unref();
  }

  /** Connect to the daemon. Rejects with `WayboundDaemonError("io_error")` on failure. */
  static connect(endpoint: Endpoint, options: TransportOptions = {}): Promise<Transport> {
    let baseTimeoutMs: number;
    try {
      baseTimeoutMs = Math.max(1, checkMs(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, "timeoutMs"));
    } catch (err) {
      return Promise.reject(err);
    }
    return new Promise<Transport>((resolve, reject) => {
      const socket =
        "socketPath" in endpoint
          ? net.createConnection({ path: endpoint.socketPath })
          : net.createConnection({ host: endpoint.host, port: endpoint.port, noDelay: true });
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new WayboundDaemonError("io_error", `connect timed out after ${baseTimeoutMs}ms`));
      }, baseTimeoutMs);
      const onError = (err: Error): void => {
        clearTimeout(timer);
        socket.destroy();
        reject(new WayboundDaemonError("io_error", err.message, { cause: err }));
      };
      socket.once("error", onError);
      socket.once("connect", () => {
        clearTimeout(timer);
        socket.off("error", onError);
        resolve(new Transport(socket, endpoint, baseTimeoutMs));
      });
    });
  }

  /** `true` once the connection is closed (explicitly or after a fatal error). */
  get closed(): boolean {
    return this.#closed;
  }

  /** Close the connection. Any in-flight or queued call fails with code `closed`. */
  close(): void {
    this.#fail(new WayboundDaemonError("closed", "transport is closed"));
  }

  /**
   * Send one raw request object and return the daemon's reply object.
   *
   * Rejects with the daemon's structured error when the reply has `status: "error"`.
   * `onWritten` is called once the request line has been handed to the OS.
   */
  request(
    payload: JsonObject,
    timeoutOverrideMs?: number,
    onWritten?: () => void,
  ): Promise<JsonObject> {
    const timeoutMs = Math.min(MAX_TIMER_MS, timeoutOverrideMs ?? this.baseTimeoutMs);
    const run = this.#tail.then(() => this.#send(payload, timeoutMs, onWritten));
    this.#tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  #send(payload: JsonObject, timeoutMs: number, onWritten?: () => void): Promise<JsonObject> {
    if (this.#closed) {
      return Promise.reject(new WayboundDaemonError("closed", "transport is closed"));
    }
    return new Promise<JsonObject>((resolve, reject) => {
      const timer = setTimeout(() => {
        // The reply is still in flight; reusing the connection would hand the next request
        // this request's reply, so the connection is poisoned and closed.
        this.#fail(new WayboundDaemonError("io_error", `request timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      this.#pending = { resolve, reject, timer };
      this.#socket.ref();
      this.#socket.write(encodeLine(payload), (err) => {
        if (err) {
          this.#fail(new WayboundDaemonError("io_error", err.message, { cause: err }));
        } else {
          onWritten?.();
        }
      });
    });
  }

  #settle(): Pending | null {
    const pending = this.#pending;
    this.#pending = null;
    if (pending !== null) {
      clearTimeout(pending.timer);
    }
    if (!this.#closed) {
      this.#socket.unref();
    }
    return pending;
  }

  /** Reject the in-flight call (if any) with `error` and close the connection for good. */
  #fail(error: WayboundDaemonError): void {
    const pending = this.#settle();
    if (!this.#closed) {
      this.#closed = true;
      this.#socket.destroy();
    }
    pending?.reject(error);
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
        this.#fail(new WayboundDaemonError("protocol_error", "unsolicited reply from daemon"));
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
            `expected JSON object from daemon, got ${Array.isArray(decoded) ? "array" : typeof decoded}`,
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

  async #expectOk(payload: JsonObject, op: string, timeoutOverrideMs?: number): Promise<void> {
    const response = await this.request(payload, timeoutOverrideMs);
    if (response.status !== "ok") {
      throw new WayboundDaemonError(
        "protocol_error",
        `unexpected ${op} response: ${describe(response)}`,
      );
    }
  }

  /** Health check; returns the daemon version. */
  async ping(timeoutMs?: number): Promise<string> {
    const response = await this.request(
      { method: "ping" },
      timeoutMs === undefined ? undefined : Math.max(1, checkMs(timeoutMs, "timeoutMs")),
    );
    if (typeof response.version !== "string") {
      throw new WayboundDaemonError(
        "protocol_error",
        `unexpected ping response: ${describe(response)}`,
      );
    }
    return response.version;
  }

  /** Fetch the current accessibility tree. */
  async snapshotTree(): Promise<AccessibilityNode[]> {
    return parseNodes(await this.request({ method: "snapshot_tree" }), "tree");
  }

  /** Return every node matching `query` (`nth` is ignored by the daemon). */
  async locateAll(query: LocatorQuery): Promise<AccessibilityNode[]> {
    const response = await this.request({ method: "locate_all", query: encodeQuery(query) });
    return parseNodes(response, "locate_all");
  }

  /** Return the active tab URL, if known. */
  async currentUrl(): Promise<string | null> {
    const response = await this.request({ method: "current_url" });
    const url = response.url;
    if (url === null || url === undefined) {
      return null;
    }
    if (typeof url === "string") {
      return url;
    }
    throw new WayboundDaemonError(
      "protocol_error",
      `unexpected current_url response: ${describe(response)}`,
    );
  }

  /** Poll on the daemon until `query` matches or `timeoutMs` elapses. */
  async waitFor(query: LocatorQuery, timeoutMs = 10_000): Promise<AccessibilityNode> {
    const clamped = checkMs(timeoutMs, "timeoutMs", MAX_WAIT_MS);
    const response = await this.request(
      { method: "wait_for", query: encodeQuery(query), timeout_ms: clamped },
      waitTimeoutMs(this.baseTimeoutMs, clamped),
    );
    if (!isObject(response.node)) {
      throw new WayboundDaemonError(
        "protocol_error",
        `unexpected wait_for response: ${describe(response)}`,
      );
    }
    return parseNode(response.node);
  }

  /** Ask the daemon to shut down gracefully (optionally with a shorter reply timeout). */
  async shutdown(timeoutMs?: number): Promise<void> {
    await this.#expectOk(
      { method: "shutdown" },
      "shutdown",
      timeoutMs === undefined ? undefined : Math.max(1, checkMs(timeoutMs, "timeoutMs")),
    );
  }

  /**
   * Run one request on a dedicated short-lived connection, so a slow or oversized reply only
   * fails this call and never blocks or poisons the main connection.
   */
  async #oneShot(
    payload: JsonObject,
    timeoutMs: number,
  ): Promise<{ written: Promise<void>; reply: Promise<JsonObject> }> {
    if (this.#closed) {
      throw new WayboundDaemonError("closed", "transport is closed");
    }
    const dedicated = await Transport.connect(this.endpoint, { timeoutMs });
    let markWritten: () => void = () => undefined;
    const written = new Promise<void>((resolve) => {
      markWritten = resolve;
    });
    const reply = dedicated.request(payload, timeoutMs, markWritten).finally(() => {
      dedicated.close();
      markWritten();
    });
    return { written, reply };
  }

  /**
   * Return captured HTTP responses, optionally filtered by URL substring.
   *
   * Uses a dedicated connection: the daemon may hold up to 500 responses of up to 4 MiB each,
   * and a reply over the client's 256 MiB line cap fails only this call.
   */
  async capturedResponses(urlContains?: string | null): Promise<CapturedResponse[]> {
    const { reply } = await this.#oneShot(
      { method: "captured_responses", url_contains: urlContains ?? null },
      this.baseTimeoutMs,
    );
    const response = await reply;
    if (!Array.isArray(response.responses)) {
      throw new WayboundDaemonError(
        "protocol_error",
        `unexpected captured_responses payload: ${describe(response)}`,
      );
    }
    return response.responses.filter(isObject).map(parseHttpResponse);
  }

  /**
   * Arm a wait for the first HTTP response captured *after* the daemon receives this request
   * whose URL contains `urlContains`. Resolves once the request has been sent on a dedicated
   * connection; trigger the navigation or click after that, then await `waiter.response`.
   */
  async expectResponse(urlContains: string, timeoutMs = 10_000): Promise<ResponseWaiter> {
    const clamped = checkMs(timeoutMs, "timeoutMs", MAX_WAIT_MS);
    const { written, reply } = await this.#oneShot(
      { method: "wait_for_response", url_contains: urlContains, timeout_ms: clamped },
      waitTimeoutMs(this.baseTimeoutMs, clamped),
    );
    const response = reply.then((r) => {
      if (!isObject(r.response)) {
        throw new WayboundDaemonError(
          "protocol_error",
          `unexpected wait_for_response payload: ${describe(r)}`,
        );
      }
      return parseHttpResponse(r.response);
    });
    // A waiter the caller never awaits must not surface as an unhandled rejection.
    response.catch(() => undefined);
    await written;
    return { response };
  }

  /**
   * Wait until a captured HTTP response matches `urlContains`.
   *
   * Uses a dedicated short-lived connection so it can run concurrently with other calls on
   * this transport. Only responses captured after the daemon receives the request count; see
   * `expectResponse()` to arm the wait before triggering the request.
   */
  async waitForResponse(urlContains: string, timeoutMs = 10_000): Promise<CapturedResponse> {
    return (await this.expectResponse(urlContains, timeoutMs)).response;
  }

  /** Move the pointer over the element without clicking. */
  async hover(query: LocatorQuery): Promise<void> {
    await this.#expectOk({ method: "hover", query: encodeQuery(query) }, "hover");
  }

  /** Native click on the element. */
  async click(query: LocatorQuery): Promise<void> {
    await this.#expectOk({ method: "click", query: encodeQuery(query) }, "click");
  }

  /** Native double-click on the element. */
  async dblclick(query: LocatorQuery): Promise<void> {
    // serde renames `Request::DblClick` to `dbl_click` (the Python SDK's `dblclick` is rejected).
    await this.#expectOk({ method: "dbl_click", query: encodeQuery(query) }, "dbl_click");
  }

  /** Select an option of a `<select>`/combobox by label or 0-based index. */
  async selectOption(
    query: LocatorQuery,
    options: { readonly label?: string | null; readonly index?: number | null } = {},
  ): Promise<void> {
    const index = options.index ?? null;
    if (index !== null && !(Number.isSafeInteger(index) && index >= 0)) {
      throw new RangeError(`index must be a non-negative integer, got ${index}`);
    }
    await this.#expectOk(
      {
        method: "select_option",
        query: encodeQuery(query),
        label: options.label ?? null,
        index,
      },
      "select_option",
    );
  }

  /** Wait until no HTTP/1.1–2 request is in flight for `idleMs`. */
  async waitForNetworkIdle(idleMs = 500, timeoutMs = 15_000): Promise<void> {
    const clamped = checkMs(timeoutMs, "timeoutMs", MAX_NETWORK_IDLE_TIMEOUT_MS);
    await this.#expectOk(
      {
        method: "wait_for_network_idle",
        idle_ms: Math.max(MIN_IDLE_MS, checkMs(idleMs, "idleMs", MAX_IDLE_MS)),
        timeout_ms: clamped,
      },
      "wait_for_network_idle",
      waitTimeoutMs(this.baseTimeoutMs, clamped),
    );
  }

  /** Focus the element and type `text` with native key events. */
  async fill(query: LocatorQuery, text: string): Promise<void> {
    await this.#expectOk(
      { method: "fill", query: encodeQuery(query), text },
      "fill",
      fillTimeoutMs(this.baseTimeoutMs, text),
    );
  }

  /** Navigate the active tab to `url`. */
  async navigate(url: string): Promise<void> {
    await this.#expectOk({ method: "navigate", url }, "navigate");
  }

  async reload(): Promise<void> {
    await this.#expectOk({ method: "reload" }, "reload");
  }

  async goBack(): Promise<void> {
    await this.#expectOk({ method: "go_back" }, "go_back");
  }

  async goForward(): Promise<void> {
    await this.#expectOk({ method: "go_forward" }, "go_forward");
  }

  async newTab(url?: string | null): Promise<void> {
    await this.#expectOk({ method: "new_tab", url: url ?? null }, "new_tab");
  }

  async closeTab(): Promise<void> {
    await this.#expectOk({ method: "close_tab" }, "close_tab");
  }

  async nextTab(): Promise<void> {
    await this.#expectOk({ method: "next_tab" }, "next_tab");
  }

  async prevTab(): Promise<void> {
    await this.#expectOk({ method: "prev_tab" }, "prev_tab");
  }

  /** Capture a PNG screenshot of the browser window to `path` (on the daemon's host). */
  async screenshot(path: string): Promise<void> {
    await this.#expectOk({ method: "screenshot", path }, "screenshot");
  }

  /** Emit a native scroll event. */
  async scroll(deltaX: number, deltaY: number): Promise<void> {
    if (!Number.isFinite(deltaX) || !Number.isFinite(deltaY)) {
      throw new RangeError("scroll deltas must be finite numbers");
    }
    await this.#expectOk({ method: "scroll", delta_x: deltaX, delta_y: deltaY }, "scroll");
  }

  /** Emit a key press: a named key (`enter`, `arrow_left`, ...) or a single character. */
  async press(
    key: NamedKey | (string & {}),
    modifiers: readonly KeyModifier[] = [],
  ): Promise<void> {
    await this.#expectOk(
      { method: "press", key: encodeKey(key), modifiers: [...modifiers] },
      "press",
    );
  }
}

/** Encode a key for the wire: named keys by snake_case name, anything else as `{char}`. */
export function encodeKey(key: string): string | { char: string } {
  const lower = key.toLowerCase();
  if (NAMED_KEY_SET.has(lower)) {
    return lower;
  }
  if ([...key].length !== 1) {
    throw new RangeError(
      `key must be one of ${[...NAMED_KEYS].sort().join(", ")} or a single character, got ${JSON.stringify(key)}`,
    );
  }
  return { char: key };
}

/** Encode a locator query for the wire. */
export function encodeQuery(query: LocatorQuery): JsonObject {
  const payload: JsonObject = {
    role: query.role,
    name: query.name,
    exact: query.exact,
    nth: Math.max(0, query.nth),
  };
  if (query.within !== null) {
    payload.within = encodeQuery(query.within);
  }
  return payload;
}

function parseNumber(raw: unknown, field: string): number {
  if (typeof raw === "number") {
    return raw;
  }
  throw new WayboundDaemonError(
    "protocol_error",
    `expected numeric bounds.${field}, got ${describe(raw)}`,
  );
}

/** Parse one accessibility node leniently, as the Python SDK does. */
export function parseNode(item: JsonObject): AccessibilityNode {
  const rawBounds = item.bounds;
  const bounds = isObject(rawBounds)
    ? new Bounds(
        parseNumber(rawBounds.x ?? 0, "x"),
        parseNumber(rawBounds.y ?? 0, "y"),
        parseNumber(rawBounds.width ?? 0, "width"),
        parseNumber(rawBounds.height ?? 0, "height"),
      )
    : new Bounds(0, 0, 0, 0);
  return {
    id: item.id === undefined || item.id === null ? "" : String(item.id),
    role: parseRole(item.role),
    name: typeof item.name === "string" ? item.name : null,
    value: typeof item.value === "string" ? item.value : null,
    bounds,
    focused: Boolean(item.focused ?? false),
  };
}

function parseNodes(response: JsonObject, op: string): AccessibilityNode[] {
  if (!Array.isArray(response.nodes)) {
    throw new WayboundDaemonError(
      "protocol_error",
      `unexpected ${op} response: ${describe(response)}`,
    );
  }
  return response.nodes.filter(isObject).map(parseNode);
}

/** Parse one captured HTTP response leniently, as the Python SDK does. */
export function parseHttpResponse(item: JsonObject): CapturedResponse {
  const status = Number.isInteger(item.status) ? (item.status as number) : 0;
  return new CapturedResponse(
    item.url === undefined || item.url === null ? "" : String(item.url),
    status,
    typeof item.content_type === "string" ? item.content_type : null,
    typeof item.body === "string" ? item.body : null,
  );
}

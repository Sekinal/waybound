/** Playwright-style `Page` and lazy, chainable `Locator`. */

import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { WayboundDaemonError } from "./errors.js";
import { HandoffHttpClient, type HandoffHttpClientOptions } from "./handoff.js";
import {
  checkMs,
  type NewWindowOptions,
  type ResponseWaiter,
  type SnapshotTreeOptions,
  type Transport,
} from "./transport.js";
import {
  type AccessibilityNode,
  type CapturedResponse,
  type KeyModifier,
  type LocatorQuery,
  type NamedKey,
  type NetworkStats,
  Role,
  type SessionFingerprint,
  type TreeSnapshot,
  type WindowSummary,
} from "./types.js";

const URL_POLL_INTERVAL_MS = 75;

export interface RoleOptions {
  /** Accessible name to match (case-insensitive substring unless `exact`). */
  readonly name?: string | null;
  /** Require an exact, case-sensitive name match. */
  readonly exact?: boolean;
  /** Fail with `strict_mode_violation` if more than one element matches. */
  readonly strict?: boolean;
}

export interface TextOptions {
  /** Require an exact, case-sensitive match. */
  readonly exact?: boolean;
  /** Fail with `strict_mode_violation` if more than one element matches. */
  readonly strict?: boolean;
}

export interface TimeoutOptions {
  /** Maximum wait in milliseconds. */
  readonly timeoutMs?: number;
}

export interface SelectOptionOptions {
  /** Visible option label. */
  readonly label?: string | null;
  /** 0-based option index. */
  readonly index?: number | null;
}

export interface PressOptions {
  /** Modifier keys held during the press. */
  readonly modifiers?: readonly KeyModifier[];
}

export interface ScrollOptions {
  readonly deltaX?: number;
  readonly deltaY?: number;
}

export interface CapturedResponsesOptions {
  /** Case-insensitive URL substring filter. */
  readonly urlContains?: string | null;
}

export interface NetworkIdleOptions {
  /** Continuous idle duration in milliseconds. Default 500 (minimum 50). */
  readonly idleMs?: number;
  /** Maximum wait in milliseconds. Default 15 000. */
  readonly timeoutMs?: number;
}

export interface PageSnapshotTreeOptions {
  /** Optional maximum number of nodes to return (clamped to `1..=20_000` by the daemon). */
  readonly maxNodes?: number | null;
}

function makeQuery(
  role: Role | null,
  name: string | null,
  exact: boolean,
  within: LocatorQuery | null,
  strict: boolean,
): LocatorQuery {
  return Object.freeze({ role, name, exact, nth: 0, within, strict });
}

/**
 * Lazy handle to a semantic UI element. Creating or chaining a locator sends nothing to the
 * daemon; each action resolves the query afresh.
 */
export class Locator {
  readonly #transport: Transport;
  readonly #windowId: number | undefined;
  /** The query this locator resolves. */
  readonly query: LocatorQuery;

  constructor(transport: Transport, query: LocatorQuery, windowId?: number) {
    this.#transport = transport;
    this.query = query;
    this.#windowId = windowId;
  }

  /** A locator narrowed to the first match (`nth(0)`). */
  get first(): Locator {
    return this.nth(0);
  }

  /** A locator narrowed to the zero-based `index`-th match. */
  nth(index: number): Locator {
    if (!Number.isSafeInteger(index) || index < 0) {
      throw new RangeError(`nth index must be a non-negative integer, got ${index}`);
    }
    return new Locator(
      this.#transport,
      Object.freeze({ ...this.query, nth: index, strict: false }),
      this.#windowId,
    );
  }

  /** A child locator matched by role, spatially scoped inside this element. */
  getByRole(role: Role, options: RoleOptions = {}): Locator {
    return new Locator(
      this.#transport,
      makeQuery(
        role,
        options.name ?? null,
        options.exact ?? false,
        this.query,
        options.strict ?? false,
      ),
      this.#windowId,
    );
  }

  /** A child locator matched by accessible text, spatially scoped inside this element. */
  getByText(text: string, options: TextOptions = {}): Locator {
    return new Locator(
      this.#transport,
      makeQuery(null, text, options.exact ?? false, this.query, options.strict ?? false),
      this.#windowId,
    );
  }

  /** All nodes matching this locator (ignoring `nth`). */
  all(): Promise<AccessibilityNode[]> {
    return this.#windowId === undefined
      ? this.#transport.locateAll(this.query)
      : this.#transport.locateAll(this.query, this.#windowId);
  }

  /** Number of nodes matching this locator. */
  async count(): Promise<number> {
    return (await this.all()).length;
  }

  /** `true` if the `nth` match exists and has positive on-screen bounds. */
  async isVisible(): Promise<boolean> {
    const node = (await this.all())[this.query.nth];
    return node !== undefined && node.bounds.width > 0 && node.bounds.height > 0;
  }

  /** Move the pointer over the element without clicking. */
  hover(): Promise<void> {
    return this.#windowId === undefined
      ? this.#transport.hover(this.query)
      : this.#transport.hover(this.query, this.#windowId);
  }

  /** Wait until this element appears in the accessibility tree. */
  waitFor(options: TimeoutOptions = {}): Promise<AccessibilityNode> {
    const timeoutMs = options.timeoutMs ?? 10_000;
    return this.#windowId === undefined
      ? this.#transport.waitFor(this.query, timeoutMs)
      : this.#transport.waitFor(this.query, timeoutMs, this.#windowId);
  }

  /** Accessible name (or value, if unnamed) of the element. */
  async textContent(options: TimeoutOptions = {}): Promise<string | null> {
    const node = await this.waitFor({ timeoutMs: options.timeoutMs ?? 5_000 });
    return node.name ?? node.value;
  }

  /** Current editable value of a textbox/input element (`""` if none). */
  async inputValue(options: TimeoutOptions = {}): Promise<string> {
    const node = await this.waitFor({ timeoutMs: options.timeoutMs ?? 5_000 });
    return node.value || "";
  }

  /** Native click. */
  click(): Promise<void> {
    return this.#windowId === undefined
      ? this.#transport.click(this.query)
      : this.#transport.click(this.query, this.#windowId);
  }

  /** Native double-click. */
  dblclick(): Promise<void> {
    return this.#windowId === undefined
      ? this.#transport.dblclick(this.query)
      : this.#transport.dblclick(this.query, this.#windowId);
  }

  /** Select an option of a `<select>`/combobox by label or 0-based index. */
  selectOption(options: SelectOptionOptions = {}): Promise<void> {
    return this.#transport.selectOption(
      this.query,
      this.#windowId === undefined ? options : { ...options, windowId: this.#windowId },
    );
  }

  /** Focus the element and type `text` with native key events. */
  fill(text: string): Promise<void> {
    return this.#windowId === undefined
      ? this.#transport.fill(this.query, text)
      : this.#transport.fill(this.query, text, this.#windowId);
  }
}

/** High-level semantic interface to a controlled browser session. */
export class Page {
  readonly #transport: Transport;
  /** Backend window identifier this page is scoped to, or `undefined` for the default window. */
  readonly windowId: number | undefined;
  #lastTreeTruncated = false;

  constructor(transport: Transport, windowId?: number) {
    if (windowId !== undefined && (!Number.isSafeInteger(windowId) || windowId < 0)) {
      throw new RangeError(`windowId must be a non-negative integer, got ${windowId}`);
    }
    this.#transport = transport;
    this.windowId = windowId;
  }

  /** The underlying daemon connection. */
  get transport(): Transport {
    return this.#transport;
  }

  /** Whether the most recent `snapshotTree()` call was truncated at the node cap. */
  get lastTreeTruncated(): boolean {
    return this.#lastTreeTruncated;
  }

  /** Return open browser windows tracked by the active backend. */
  listWindows(): Promise<WindowSummary[]> {
    return this.#transport.listWindows();
  }

  /** Open a new browser window on this transport and return a `Page` scoped to it. */
  async newPage(options: NewWindowOptions = {}): Promise<Page> {
    const win = await this.#transport.newWindow(options);
    return new Page(this.#transport, win.id);
  }

  /** Close the browser window this page is scoped to. Throws if `windowId` is `undefined`. */
  async closeWindow(): Promise<void> {
    if (this.windowId === undefined) {
      throw new Error("cannot closeWindow() on an unscoped Page (windowId is undefined)");
    }
    await this.#transport.closeWindow(this.windowId);
  }

  /** Active tab URL, if available. */
  url(): Promise<string | null> {
    return this.windowId === undefined
      ? this.#transport.currentUrl()
      : this.#transport.currentUrl(this.windowId);
  }

  /** Poll until the active tab URL contains `urlContains` (case-insensitive). */
  async waitForUrl(urlContains: string, options: TimeoutOptions = {}): Promise<string> {
    const timeoutMs = checkMs(options.timeoutMs ?? 10_000, "timeoutMs");
    const needle = urlContains.toLowerCase();
    const deadline = performance.now() + timeoutMs;
    for (;;) {
      const current = await this.url();
      if (typeof current === "string" && current.toLowerCase().includes(needle)) {
        return current;
      }
      if (performance.now() >= deadline) {
        throw new WayboundDaemonError(
          "timeout",
          `timed out after ${timeoutMs}ms waiting for URL containing ${JSON.stringify(urlContains)}`,
        );
      }
      await sleep(URL_POLL_INTERVAL_MS);
    }
  }

  /** Navigate the active tab to `url` via native OS shortcut. */
  goto(url: string): Promise<void> {
    return this.windowId === undefined
      ? this.#transport.navigate(url)
      : this.#transport.navigate(url, this.windowId);
  }

  reload(): Promise<void> {
    return this.windowId === undefined
      ? this.#transport.reload()
      : this.#transport.reload(this.windowId);
  }

  goBack(): Promise<void> {
    return this.windowId === undefined
      ? this.#transport.goBack()
      : this.#transport.goBack(this.windowId);
  }

  goForward(): Promise<void> {
    return this.windowId === undefined
      ? this.#transport.goForward()
      : this.#transport.goForward(this.windowId);
  }

  /** Open a new tab, optionally navigating to `url`. */
  newTab(url?: string | null): Promise<void> {
    return this.windowId === undefined
      ? this.#transport.newTab(url)
      : this.#transport.newTab(url, this.windowId);
  }

  closeTab(): Promise<void> {
    return this.windowId === undefined
      ? this.#transport.closeTab()
      : this.#transport.closeTab(this.windowId);
  }

  nextTab(): Promise<void> {
    return this.windowId === undefined
      ? this.#transport.nextTab()
      : this.#transport.nextTab(this.windowId);
  }

  prevTab(): Promise<void> {
    return this.windowId === undefined
      ? this.#transport.prevTab()
      : this.#transport.prevTab(this.windowId);
  }

  /** Wait until any element with accessible text matching `text` appears. */
  waitForText(
    text: string,
    options: TextOptions & TimeoutOptions = {},
  ): Promise<AccessibilityNode> {
    return this.getByText(text, {
      exact: options.exact ?? false,
      strict: options.strict ?? false,
    }).waitFor({
      timeoutMs: options.timeoutMs ?? 10_000,
    });
  }

  /** Scroll the viewport. Defaults to `deltaY: -300`, like the Python SDK. */
  scroll(options: ScrollOptions = {}): Promise<void> {
    const deltaX = options.deltaX ?? 0;
    const deltaY = options.deltaY ?? -300;
    return this.windowId === undefined
      ? this.#transport.scroll(deltaX, deltaY)
      : this.#transport.scroll(deltaX, deltaY, this.windowId);
  }

  /** Native key press: a named key (`enter`, `arrow_left`, ...) or a single character. */
  press(key: NamedKey | (string & {}), options: PressOptions = {}): Promise<void> {
    const modifiers = options.modifiers ?? [];
    return this.windowId === undefined
      ? this.#transport.press(key, modifiers)
      : this.#transport.press(key, modifiers, this.windowId);
  }

  /** Snapshot of the live accessibility tree. */
  async snapshotTree(options: PageSnapshotTreeOptions = {}): Promise<AccessibilityNode[]> {
    return (await this.snapshotTreeWithMeta(options)).nodes;
  }

  /** All link nodes on the current page that expose a non-empty target URL. */
  async links(options: PageSnapshotTreeOptions = {}): Promise<AccessibilityNode[]> {
    const nodes = await this.snapshotTree(options);
    return nodes.filter(
      (node) => node.role === Role.LINK && typeof node.url === "string" && node.url.length > 0,
    );
  }

  /** Snapshot of the live accessibility tree along with truncation metadata. */
  async snapshotTreeWithMeta(options: PageSnapshotTreeOptions = {}): Promise<TreeSnapshot> {
    const merged: SnapshotTreeOptions =
      this.windowId !== undefined
        ? {
            ...(options.maxNodes !== undefined ? { maxNodes: options.maxNodes } : {}),
            windowId: this.windowId,
          }
        : options.maxNodes !== undefined
          ? { maxNodes: options.maxNodes }
          : {};
    const snap = await this.#transport.snapshotTreeWithMeta(merged);
    this.#lastTreeTruncated = snap.truncated;
    return snap;
  }

  /** Passively captured HTTP responses, optionally filtered by URL substring. */
  capturedResponses(options: CapturedResponsesOptions = {}): Promise<CapturedResponse[]> {
    return this.#transport.capturedResponses(options.urlContains ?? null);
  }

  /**
   * Arm a wait for the next captured HTTP response whose URL contains `urlContains`, before
   * triggering it:
   *
   * ```ts
   * const waiter = await page.expectResponse("/api/search");
   * await page.getByRole(Role.BUTTON, { name: "Search" }).click();
   * const response = await waiter.response;
   * ```
   */
  expectResponse(urlContains: string, options: TimeoutOptions = {}): Promise<ResponseWaiter> {
    return this.#transport.expectResponse(urlContains, options.timeoutMs ?? 10_000);
  }

  /**
   * Wait for a captured HTTP response whose URL contains `urlContains`. Only responses captured
   * after the daemon receives this request count; prefer `expectResponse()` when the response
   * is triggered by an action of your own.
   */
  waitForResponse(urlContains: string, options: TimeoutOptions = {}): Promise<CapturedResponse> {
    return this.#transport.waitForResponse(urlContains, options.timeoutMs ?? 10_000);
  }

  /** Wait until no HTTP/1.1–2 request is in flight for `idleMs`. */
  waitForNetworkIdle(options: NetworkIdleOptions = {}): Promise<void> {
    return this.#transport.waitForNetworkIdle(options.idleMs ?? 500, options.timeoutMs ?? 15_000);
  }

  /** Export the live TLS, HTTP/2, header, and cookie fingerprint captured from the session. */
  exportFingerprint(): Promise<SessionFingerprint> {
    return this.#transport.exportFingerprint();
  }

  /**
   * Export the live browser fingerprint and create a standalone BoringSSL/H2 HTTP client.
   *
   * The returned `HandoffHttpClient` continues working after the browser session closes.
   */
  async handoffHttpClient(options: HandoffHttpClientOptions = {}): Promise<HandoffHttpClient> {
    const fp = await this.exportFingerprint();
    return HandoffHttpClient.create(fp, options);
  }

  /** Return per-session bandwidth and connection counters from the daemon proxy. */
  networkStats(): Promise<NetworkStats> {
    return this.#transport.networkStats();
  }

  /**
   * Capture a native PNG screenshot of the browser window and return its bytes. When `path`
   * is given the file is kept there; otherwise a temporary file is used and removed.
   */
  async screenshot(filePath?: string | null): Promise<Buffer> {
    if (filePath !== undefined && filePath !== null) {
      const out = path.resolve(filePath);
      if (this.windowId === undefined) {
        await this.#transport.screenshot(out);
      } else {
        await this.#transport.screenshot(out, this.windowId);
      }
      return readFile(out);
    }
    const dir = await mkdtemp(path.join(tmpdir(), "wb-shot-"));
    try {
      const out = path.join(dir, "shot.png");
      if (this.windowId === undefined) {
        await this.#transport.screenshot(out);
      } else {
        await this.#transport.screenshot(out, this.windowId);
      }
      return await readFile(out);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }

  /** Locator targeting an element by semantic role. */
  getByRole(role: Role, options: RoleOptions = {}): Locator {
    return new Locator(
      this.#transport,
      makeQuery(role, options.name ?? null, options.exact ?? false, null, options.strict ?? false),
      this.windowId,
    );
  }

  /** Locator targeting an element by accessible text. */
  getByText(text: string, options: TextOptions = {}): Locator {
    return new Locator(
      this.#transport,
      makeQuery(null, text, options.exact ?? false, null, options.strict ?? false),
      this.windowId,
    );
  }
}

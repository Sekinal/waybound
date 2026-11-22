/** Playwright-style `Page` and lazy, chainable `Locator`. */

import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { WayboundDaemonError } from "./errors.js";
import { checkMs, type ResponseWaiter, type Transport } from "./transport.js";
import type {
  AccessibilityNode,
  CapturedResponse,
  KeyModifier,
  LocatorQuery,
  NamedKey,
  Role,
} from "./types.js";

const URL_POLL_INTERVAL_MS = 75;

export interface RoleOptions {
  /** Accessible name to match (case-insensitive substring unless `exact`). */
  readonly name?: string | null;
  /** Require an exact, case-sensitive name match. */
  readonly exact?: boolean;
}

export interface TextOptions {
  /** Require an exact, case-sensitive match. */
  readonly exact?: boolean;
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

function makeQuery(
  role: Role | null,
  name: string | null,
  exact: boolean,
  within: LocatorQuery | null,
): LocatorQuery {
  return Object.freeze({ role, name, exact, nth: 0, within });
}

/**
 * Lazy handle to a semantic UI element. Creating or chaining a locator sends nothing to the
 * daemon; each action resolves the query afresh.
 */
export class Locator {
  readonly #transport: Transport;
  /** The query this locator resolves. */
  readonly query: LocatorQuery;

  constructor(transport: Transport, query: LocatorQuery) {
    this.#transport = transport;
    this.query = query;
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
    return new Locator(this.#transport, Object.freeze({ ...this.query, nth: index }));
  }

  /** A child locator matched by role, spatially scoped inside this element. */
  getByRole(role: Role, options: RoleOptions = {}): Locator {
    return new Locator(
      this.#transport,
      makeQuery(role, options.name ?? null, options.exact ?? false, this.query),
    );
  }

  /** A child locator matched by accessible text, spatially scoped inside this element. */
  getByText(text: string, options: TextOptions = {}): Locator {
    return new Locator(this.#transport, makeQuery(null, text, options.exact ?? false, this.query));
  }

  /** All nodes matching this locator (ignoring `nth`). */
  all(): Promise<AccessibilityNode[]> {
    return this.#transport.locateAll(this.query);
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
    return this.#transport.hover(this.query);
  }

  /** Wait until this element appears in the accessibility tree. */
  waitFor(options: TimeoutOptions = {}): Promise<AccessibilityNode> {
    return this.#transport.waitFor(this.query, options.timeoutMs ?? 10_000);
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
    return this.#transport.click(this.query);
  }

  /** Native double-click. */
  dblclick(): Promise<void> {
    return this.#transport.dblclick(this.query);
  }

  /** Select an option of a `<select>`/combobox by label or 0-based index. */
  selectOption(options: SelectOptionOptions = {}): Promise<void> {
    return this.#transport.selectOption(this.query, options);
  }

  /** Focus the element and type `text` with native key events. */
  fill(text: string): Promise<void> {
    return this.#transport.fill(this.query, text);
  }
}

/** High-level semantic interface to a controlled browser session. */
export class Page {
  readonly #transport: Transport;

  constructor(transport: Transport) {
    this.#transport = transport;
  }

  /** The underlying daemon connection. */
  get transport(): Transport {
    return this.#transport;
  }

  /** Active tab URL, if available. */
  url(): Promise<string | null> {
    return this.#transport.currentUrl();
  }

  /** Poll until the active tab URL contains `urlContains` (case-insensitive). */
  async waitForUrl(urlContains: string, options: TimeoutOptions = {}): Promise<string> {
    const timeoutMs = checkMs(options.timeoutMs ?? 10_000, "timeoutMs");
    const needle = urlContains.toLowerCase();
    const deadline = performance.now() + timeoutMs;
    for (;;) {
      const current = await this.#transport.currentUrl();
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
    return this.#transport.navigate(url);
  }

  reload(): Promise<void> {
    return this.#transport.reload();
  }

  goBack(): Promise<void> {
    return this.#transport.goBack();
  }

  goForward(): Promise<void> {
    return this.#transport.goForward();
  }

  /** Open a new tab, optionally navigating to `url`. */
  newTab(url?: string | null): Promise<void> {
    return this.#transport.newTab(url);
  }

  closeTab(): Promise<void> {
    return this.#transport.closeTab();
  }

  nextTab(): Promise<void> {
    return this.#transport.nextTab();
  }

  prevTab(): Promise<void> {
    return this.#transport.prevTab();
  }

  /** Wait until any element with accessible text matching `text` appears. */
  waitForText(
    text: string,
    options: TextOptions & TimeoutOptions = {},
  ): Promise<AccessibilityNode> {
    return this.getByText(text, { exact: options.exact ?? false }).waitFor({
      timeoutMs: options.timeoutMs ?? 10_000,
    });
  }

  /** Scroll the viewport. Defaults to `deltaY: -300`, like the Python SDK. */
  scroll(options: ScrollOptions = {}): Promise<void> {
    return this.#transport.scroll(options.deltaX ?? 0, options.deltaY ?? -300);
  }

  /** Native key press: a named key (`enter`, `arrow_left`, ...) or a single character. */
  press(key: NamedKey | (string & {}), options: PressOptions = {}): Promise<void> {
    return this.#transport.press(key, options.modifiers ?? []);
  }

  /** Snapshot of the live accessibility tree. */
  snapshotTree(): Promise<AccessibilityNode[]> {
    return this.#transport.snapshotTree();
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

  /**
   * Capture a native PNG screenshot of the browser window and return its bytes. When `path`
   * is given the file is kept there; otherwise a temporary file is used and removed.
   */
  async screenshot(filePath?: string | null): Promise<Buffer> {
    if (filePath !== undefined && filePath !== null) {
      const out = path.resolve(filePath);
      await this.#transport.screenshot(out);
      return readFile(out);
    }
    const dir = await mkdtemp(path.join(tmpdir(), "wb-shot-"));
    try {
      const out = path.join(dir, "shot.png");
      await this.#transport.screenshot(out);
      return await readFile(out);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }

  /** Locator targeting an element by semantic role. */
  getByRole(role: Role, options: RoleOptions = {}): Locator {
    return new Locator(
      this.#transport,
      makeQuery(role, options.name ?? null, options.exact ?? false, null),
    );
  }

  /** Locator targeting an element by accessible text. */
  getByText(text: string, options: TextOptions = {}): Locator {
    return new Locator(this.#transport, makeQuery(null, text, options.exact ?? false, null));
  }
}

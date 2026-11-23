/**
 * Async multi-display Linux & remote-worker browser pool (`BrowserPool`).
 *
 * Mirrors the Python SDK's `BrowserPool` for Crawlee TS and standalone concurrent crawlers:
 * - Lazy-launches up to `size` concurrent browser slots with health checks, crash recycling,
 *   and optional proactive recycling (`maxUsesPerSlot`).
 * - On Linux, `isolatedDisplays: true` allocates a free virtual X11 display (`:N`), spawns
 *   `Xvfb`, `dbus-daemon --session`, `openbox`, and `at-spi-bus-launcher` per slot, and
 *   terminates all child processes cleanly on recycle/close.
 * - Supports scheduling across remote TCP `waybound-daemon --tcp` workers (`remoteWorkers`).
 */

import { type ChildProcess, spawn } from "node:child_process";
import { accessSync, existsSync, constants as fsConstants } from "node:fs";
import path from "node:path";
import { createInterface } from "node:readline";
import { setTimeout as sleep } from "node:timers/promises";
import { Page } from "./client.js";
import { type LaunchOptions, launch, type Session } from "./session.js";
import { checkMs, Transport } from "./transport.js";

const DEFAULT_DISPLAY_WIDTH = 1280;
const DEFAULT_DISPLAY_HEIGHT = 800;
const DEFAULT_DISPLAY_DEPTH = 24;
const DEFAULT_DISPLAY_BASE = 100;
const DEFAULT_ACQUIRE_TIMEOUT_MS = 60_000;
const MAX_PORT = 65_535;
const MAX_DISPLAY_SCAN = 10_000;
const XVFB_READY_TIMEOUT_MS = 3_000;
const DBUS_READY_TIMEOUT_MS = 3_000;
const XVFB_POLL_INTERVAL_MS = 50;
const ATSPI_SETTLE_DELAY_MS = 200;
const CHILD_STOP_TIMEOUT_MS = 2_000;
const CHILD_KILL_TIMEOUT_MS = 1_000;
const HEALTH_PING_TIMEOUT_MS = 2_000;
const ATSPI_LAUNCHER_CANDIDATES: readonly string[] = [
  "/usr/libexec/at-spi-bus-launcher",
  "/usr/lib/at-spi2-core/at-spi-bus-launcher",
];

/** Display backend used by `BrowserPool` on Linux. */
export type DisplayBackend = "xvfb" | "wayland";

const DISPLAY_BACKENDS: ReadonlySet<string> = new Set(["xvfb", "wayland"]);

/** Configuration for `BrowserPool`. */
export interface BrowserPoolOptions {
  /** Maximum concurrent browser slots. Defaults to `remoteWorkers.length` or `1`. */
  readonly size?: number;
  /** Base launch options template applied to each local slot. */
  readonly launchOptions?: LaunchOptions;
  /** Optional round-robin proxies assigned to local slots. */
  readonly proxies?: readonly string[];
  /** Optional remote `host:port` TCP daemon endpoints instead of spawning local daemons. */
  readonly remoteWorkers?: readonly string[];
  /** On Linux, spawn isolated display/D-Bus/AT-SPI2 per slot. */
  readonly isolatedDisplays?: boolean;
  /** Linux display backend: `"xvfb"` (default) or `"wayland"` (pure-Rust headless compositor). */
  readonly displayBackend?: DisplayBackend;
  /** Starting X11 display number when `isolatedDisplays` is enabled with `"xvfb"`. Default `100`. */
  readonly displayBase?: number;
  /** Optional proactive slot recycle threshold (recycle after N checkouts). */
  readonly maxUsesPerSlot?: number;
  /** Default timeout in milliseconds waiting for a free slot in `acquire()`. Default `60_000`. */
  readonly acquireTimeoutMs?: number;
}

/** Point-in-time observability counters for a `BrowserPool`. */
export interface PoolStats {
  readonly size: number;
  readonly active: number;
  readonly idle: number;
  readonly launched: number;
  readonly recycled: number;
  readonly failed: number;
}

/** Options for `BrowserPool.acquire()` and `BrowserPool.withPage()`. */
export interface AcquireOptions {
  /** Optional per-checkout proxy override (local slots). */
  readonly proxy?: string;
  /** Override `acquireTimeoutMs` for this checkout. */
  readonly timeoutMs?: number;
}

/** Options for `PooledPage.release()`. */
export interface ReleaseOptions {
  /** When `true`, destroy this slot instead of returning it to the idle queue. */
  readonly recycle?: boolean;
}

/** Checked-out browser page handle returned by `BrowserPool.acquire()`. */
export interface PooledPage extends AsyncDisposable {
  readonly page: Page;
  release(options?: ReleaseOptions): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

/** Parsed remote TCP worker endpoint. */
export interface RemoteWorkerEndpoint {
  readonly host: string;
  readonly port: number;
}

/** Parse a `host:port` or `[ipv6]:port` remote worker endpoint string. */
export function parseRemoteWorker(endpoint: string): RemoteWorkerEndpoint {
  const raw = endpoint.trim();
  if (raw.length === 0) {
    throw new TypeError("remote worker endpoint must not be empty");
  }

  let host: string;
  let portStr: string;
  if (raw.startsWith("[")) {
    const closing = raw.indexOf("]");
    if (closing === -1 || raw[closing + 1] !== ":") {
      throw new TypeError(`invalid IPv6 remote worker endpoint: ${JSON.stringify(endpoint)}`);
    }
    host = raw.slice(1, closing);
    portStr = raw.slice(closing + 2);
  } else {
    const colon = raw.lastIndexOf(":");
    if (colon <= 0) {
      throw new TypeError(
        `remote worker endpoint must be 'host:port', got ${JSON.stringify(endpoint)}`,
      );
    }
    host = raw.slice(0, colon);
    portStr = raw.slice(colon + 1);
  }

  if (!/^\d+$/.test(portStr)) {
    throw new TypeError(`invalid port in remote worker endpoint ${JSON.stringify(endpoint)}`);
  }
  const port = Number(portStr);
  if (!Number.isInteger(port) || port < 1 || port > MAX_PORT) {
    throw new RangeError(
      `port out of range (1..${MAX_PORT}) in remote worker endpoint ${JSON.stringify(endpoint)}`,
    );
  }
  return { host, port };
}

/** Build the `Xvfb` argv (excluding executable) for a virtual display slot. */
export function buildXvfbArgs(
  displayNum: number,
  options?: { readonly width?: number; readonly height?: number; readonly colorDepth?: number },
): string[] {
  if (!Number.isInteger(displayNum) || displayNum < 0) {
    throw new RangeError(`displayNum must be a non-negative integer, got ${displayNum}`);
  }
  const width = options?.width ?? DEFAULT_DISPLAY_WIDTH;
  const height = options?.height ?? DEFAULT_DISPLAY_HEIGHT;
  const colorDepth = options?.colorDepth ?? DEFAULT_DISPLAY_DEPTH;
  return [
    `:${displayNum}`,
    "-screen",
    "0",
    `${width}x${height}x${colorDepth}`,
    "-nolisten",
    "tcp",
    "-ac",
  ];
}

/** Build the `dbus-daemon` argv (excluding executable) for an isolated session bus. */
export function buildDbusArgs(): string[] {
  return ["--session", "--print-address=1", "--nofork"];
}

/** Build the isolated Linux display + D-Bus/AT-SPI2 environment variables for a slot. */
export function buildSlotEnv(options: {
  readonly display?: string;
  readonly dbusAddress: string;
  readonly atspiAddress?: string;
}): Record<string, string> {
  const env: Record<string, string> = {
    DBUS_SESSION_BUS_ADDRESS: options.dbusAddress,
    ACCESSIBILITY_ENABLED: "1",
    GTK_MODULES: "gail:atk-bridge",
    QT_ACCESSIBILITY: "1",
  };
  if (options.display !== undefined) {
    env.DISPLAY = options.display;
  }
  if (options.atspiAddress !== undefined) {
    env.AT_SPI_BUS_ADDRESS = options.atspiAddress;
  }
  return env;
}

/** Find the lowest X11 display number `>= start` not in `reserved` or locked on disk. */
export function findFreeDisplayNum(
  start: number = DEFAULT_DISPLAY_BASE,
  reserved: ReadonlySet<number> = new Set(),
  lockDir = "/tmp",
): number {
  if (!Number.isInteger(start) || start < 0) {
    throw new RangeError(`displayBase must be a non-negative integer, got ${start}`);
  }
  for (let candidate = start; candidate < start + MAX_DISPLAY_SCAN; candidate += 1) {
    if (reserved.has(candidate)) {
      continue;
    }
    const lockFile = path.join(lockDir, `.X${candidate}-lock`);
    const x11Sock = path.join(lockDir, ".X11-unix", `X${candidate}`);
    if (!existsSync(lockFile) && !existsSync(x11Sock)) {
      return candidate;
    }
  }
  throw new Error(`no free X11 display numbers available starting from :${start}`);
}

function isExecutable(filePath: string): boolean {
  try {
    accessSync(filePath, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function findOnPath(binName: string): string | null {
  const pathEnv = process.env.PATH ?? "";
  for (const dir of pathEnv.split(path.delimiter)) {
    if (dir.length === 0) {
      continue;
    }
    const full = path.join(dir, binName);
    if (isExecutable(full)) {
      return full;
    }
  }
  return null;
}

function findAtspiLauncher(): string | null {
  for (const candidate of ATSPI_LAUNCHER_CANDIDATES) {
    if (isExecutable(candidate)) {
      return candidate;
    }
  }
  return findOnPath("at-spi-bus-launcher");
}

function hasExited(child: ChildProcess): boolean {
  return child.exitCode !== null || child.signalCode !== null;
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
    const timer = setTimeout(() => {
      child.off("exit", onExit);
      resolve(hasExited(child));
    }, ms);
    timer.unref();
    child.once("exit", onExit);
  });
}

async function terminateProcess(child: ChildProcess): Promise<void> {
  if (hasExited(child) || child.pid === undefined) {
    return;
  }
  try {
    child.kill("SIGTERM");
  } catch {
    return;
  }
  if (await waitForExit(child, CHILD_STOP_TIMEOUT_MS)) {
    return;
  }
  try {
    child.kill("SIGKILL");
  } catch {
    return;
  }
  await waitForExit(child, CHILD_KILL_TIMEOUT_MS);
}

class IsolatedDisplayStack {
  readonly displayNum: number | undefined;
  readonly display: string | undefined;
  readonly env: Record<string, string>;
  readonly #children: ChildProcess[];

  private constructor(
    displayNum: number | undefined,
    env: Record<string, string>,
    children: ChildProcess[],
  ) {
    this.displayNum = displayNum;
    this.display = displayNum !== undefined ? `:${displayNum}` : undefined;
    this.env = env;
    this.#children = children;
  }

  static async startWaylandDbus(): Promise<IsolatedDisplayStack | null> {
    if (findOnPath("dbus-daemon") === null) {
      return null;
    }
    const children: ChildProcess[] = [];
    try {
      const dbus = spawn("dbus-daemon", buildDbusArgs(), {
        stdio: ["ignore", "pipe", "ignore"],
      });
      let dbusError: Error | null = null;
      dbus.on("error", (err) => {
        dbusError = err;
      });
      dbus.unref();
      children.push(dbus);
      const dbusAddress = await IsolatedDisplayStack.#readDbusAddress(
        dbus,
        () => dbusError,
        DBUS_READY_TIMEOUT_MS,
      );

      const slotEnv = buildSlotEnv({ dbusAddress });
      const childEnv: NodeJS.ProcessEnv = { ...process.env, ...slotEnv };

      const atspiBin = findAtspiLauncher();
      if (atspiBin !== null) {
        const atspi = spawn(atspiBin, ["--launch-immediately"], {
          stdio: ["ignore", "ignore", "ignore"],
          env: childEnv,
        });
        atspi.on("error", () => undefined);
        atspi.unref();
        children.push(atspi);
        await sleep(ATSPI_SETTLE_DELAY_MS);
      }

      return new IsolatedDisplayStack(undefined, slotEnv, children);
    } catch (err) {
      for (const child of [...children].reverse()) {
        await terminateProcess(child);
      }
      throw err;
    }
  }

  static async start(displayNum: number): Promise<IsolatedDisplayStack> {
    const children: ChildProcess[] = [];
    const display = `:${displayNum}`;
    try {
      const xvfb = spawn("Xvfb", buildXvfbArgs(displayNum), {
        stdio: ["ignore", "ignore", "ignore"],
      });
      let xvfbError: Error | null = null;
      xvfb.on("error", (err) => {
        xvfbError = err;
      });
      xvfb.unref();
      children.push(xvfb);
      await IsolatedDisplayStack.#waitForXvfb(xvfb, displayNum, () => xvfbError);

      const dbus = spawn("dbus-daemon", buildDbusArgs(), {
        stdio: ["ignore", "pipe", "ignore"],
      });
      let dbusError: Error | null = null;
      dbus.on("error", (err) => {
        dbusError = err;
      });
      dbus.unref();
      children.push(dbus);
      const dbusAddress = await IsolatedDisplayStack.#readDbusAddress(
        dbus,
        () => dbusError,
        DBUS_READY_TIMEOUT_MS,
      );

      const slotEnv = buildSlotEnv({ display, dbusAddress });
      const childEnv: NodeJS.ProcessEnv = { ...process.env, ...slotEnv };

      const openboxBin = findOnPath("openbox");
      if (openboxBin !== null) {
        const openbox = spawn(openboxBin, [], {
          stdio: ["ignore", "ignore", "ignore"],
          env: childEnv,
        });
        openbox.on("error", () => undefined);
        openbox.unref();
        children.push(openbox);
      }

      const atspiBin = findAtspiLauncher();
      if (atspiBin !== null) {
        const atspi = spawn(atspiBin, ["--launch-immediately"], {
          stdio: ["ignore", "ignore", "ignore"],
          env: childEnv,
        });
        atspi.on("error", () => undefined);
        atspi.unref();
        children.push(atspi);
        await sleep(ATSPI_SETTLE_DELAY_MS);
      }

      return new IsolatedDisplayStack(displayNum, slotEnv, children);
    } catch (err) {
      for (const child of [...children].reverse()) {
        await terminateProcess(child);
      }
      throw err;
    }
  }

  static async #waitForXvfb(
    proc: ChildProcess,
    displayNum: number,
    spawnError: () => Error | null,
  ): Promise<void> {
    const sockPath = path.join("/tmp", ".X11-unix", `X${displayNum}`);
    const deadline = performance.now() + XVFB_READY_TIMEOUT_MS;
    while (performance.now() < deadline) {
      const err = spawnError();
      if (err !== null) {
        throw new Error(`failed to spawn Xvfb :${displayNum}: ${err.message}`, { cause: err });
      }
      if (hasExited(proc)) {
        throw new Error(
          `Xvfb :${displayNum} exited prematurely (code ${proc.exitCode ?? proc.signalCode})`,
        );
      }
      if (existsSync(sockPath)) {
        return;
      }
      await sleep(XVFB_POLL_INTERVAL_MS);
    }
    const err = spawnError();
    if (err !== null) {
      throw new Error(`failed to spawn Xvfb :${displayNum}: ${err.message}`, { cause: err });
    }
    if (hasExited(proc)) {
      throw new Error(
        `Xvfb :${displayNum} exited prematurely (code ${proc.exitCode ?? proc.signalCode})`,
      );
    }
  }

  static #readDbusAddress(
    proc: ChildProcess,
    spawnError: () => Error | null,
    timeoutMs: number,
  ): Promise<string> {
    const initialErr = spawnError();
    if (initialErr !== null) {
      return Promise.reject(
        new Error(`failed to spawn dbus-daemon: ${initialErr.message}`, { cause: initialErr }),
      );
    }
    const stdout = proc.stdout;
    if (stdout === null) {
      return Promise.reject(new Error("dbus-daemon stdout pipe unavailable"));
    }

    return new Promise<string>((resolve, reject) => {
      const rl = createInterface({ input: stdout });
      let settled = false;

      const finish = (cb: () => void): void => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        proc.off("error", onError);
        proc.off("exit", onExit);
        rl.off("line", onLine);
        rl.off("close", onClose);
        rl.close();
        stdout.destroy();
        cb();
      };

      const onLine = (line: string): void => {
        const trimmed = line.trim();
        if (trimmed.length > 0) {
          finish(() => resolve(trimmed));
        }
      };

      const onError = (err: Error): void => {
        finish(() =>
          reject(new Error(`failed to spawn dbus-daemon: ${err.message}`, { cause: err })),
        );
      };

      const onExit = (): void => {
        finish(() =>
          reject(
            new Error(
              `dbus-daemon failed to emit session bus address (code ${proc.exitCode ?? proc.signalCode})`,
            ),
          ),
        );
      };

      const onClose = (): void => {
        finish(() =>
          reject(
            new Error(
              `dbus-daemon closed stdout before emitting bus address (code ${proc.exitCode ?? proc.signalCode})`,
            ),
          ),
        );
      };

      const timer = setTimeout(() => {
        finish(() =>
          reject(
            createTimeoutError(
              `timed out after ${timeoutMs}ms waiting for dbus-daemon bus address`,
            ),
          ),
        );
      }, timeoutMs);

      proc.once("error", onError);
      proc.once("exit", onExit);
      rl.on("line", onLine);
      rl.once("close", onClose);
    });
  }

  async close(): Promise<void> {
    const list = this.#children.splice(0, this.#children.length);
    for (const child of list.reverse()) {
      await terminateProcess(child);
    }
  }
}

interface PoolSlot {
  readonly page: Page;
  readonly proxy: string | undefined;
  readonly overrideProxy: boolean;
  uses: number;
  remoteWorker: string | undefined;
  displayNum: number | undefined;
  ping(): Promise<string>;
  close(): Promise<void>;
}

function makeLocalSlot(args: {
  session: Session;
  proxy: string | undefined;
  overrideProxy: boolean;
  displayStack: IsolatedDisplayStack | null;
  displayNum: number | undefined;
}): PoolSlot {
  let session: Session | null = args.session;
  let displayStack: IsolatedDisplayStack | null = args.displayStack;
  return {
    page: args.session.page,
    proxy: args.proxy,
    overrideProxy: args.overrideProxy,
    uses: 0,
    remoteWorker: undefined,
    displayNum: args.displayNum,
    async ping(): Promise<string> {
      if (session === null) {
        throw new Error("local slot is closed");
      }
      return session.ping(HEALTH_PING_TIMEOUT_MS);
    },
    async close(): Promise<void> {
      try {
        if (session !== null) {
          const s = session;
          session = null;
          await s.close().catch(() => undefined);
        }
      } finally {
        if (displayStack !== null) {
          const stack = displayStack;
          displayStack = null;
          await stack.close().catch(() => undefined);
        }
      }
    },
  };
}

function makeRemoteSlot(args: { transport: Transport; remoteWorker: string }): PoolSlot {
  let transport: Transport | null = args.transport;
  return {
    page: new Page(args.transport),
    proxy: undefined,
    overrideProxy: false,
    uses: 0,
    remoteWorker: args.remoteWorker,
    displayNum: undefined,
    async ping(): Promise<string> {
      if (transport === null) {
        throw new Error("remote slot is closed");
      }
      return transport.ping(HEALTH_PING_TIMEOUT_MS);
    },
    async close(): Promise<void> {
      // Never send `shutdown` to remote workers; close only our client socket.
      if (transport !== null) {
        transport.close();
        transport = null;
      }
    },
  };
}

interface PermitWaiter {
  resolve: () => void;
  reject: (err: Error) => void;
  timer: NodeJS.Timeout;
}

function createTimeoutError(message: string): Error {
  const err = new Error(message);
  err.name = "TimeoutError";
  return err;
}

/** Async pool of isolated local or remote `waybound` browser sessions. */
export class BrowserPool implements AsyncDisposable {
  readonly #size: number;
  readonly #launchOptions: LaunchOptions;
  readonly #proxies: readonly string[];
  readonly #isolatedDisplays: boolean;
  readonly #displayBackend: DisplayBackend;
  readonly #displayBase: number;
  readonly #remoteEndpoints = new Map<string, RemoteWorkerEndpoint>();
  readonly #availableRemotes: string[] = [];
  readonly #maxUsesPerSlot: number | undefined;
  readonly #acquireTimeoutMs: number;

  #availablePermits: number;
  readonly #waiters: PermitWaiter[] = [];
  readonly #idle: PoolSlot[] = [];
  readonly #activeSlots = new Set<PoolSlot>();
  readonly #reservedDisplays = new Set<number>();
  #proxyCursor = 0;
  #started = false;
  #closed = false;

  #launched = 0;
  #recycled = 0;
  #failed = 0;

  constructor(options: BrowserPoolOptions = {}) {
    const seenNormalized = new Set<string>();
    if (options.remoteWorkers !== undefined) {
      for (const raw of options.remoteWorkers) {
        const parsed = parseRemoteWorker(raw);
        const key = `${parsed.host}:${parsed.port}`;
        if (seenNormalized.has(key)) {
          throw new RangeError(`duplicate remote worker endpoint: ${JSON.stringify(raw)}`);
        }
        seenNormalized.add(key);
        this.#remoteEndpoints.set(raw, parsed);
        this.#availableRemotes.push(raw);
      }
    }

    const resolvedSize =
      options.size ?? (this.#remoteEndpoints.size > 0 ? this.#remoteEndpoints.size : 1);
    if (!Number.isInteger(resolvedSize) || resolvedSize < 1) {
      throw new RangeError(`size must be an integer >= 1, got ${resolvedSize}`);
    }
    if (this.#remoteEndpoints.size > 0 && resolvedSize > this.#remoteEndpoints.size) {
      throw new RangeError(
        `size (${resolvedSize}) cannot exceed number of remoteWorkers (${this.#remoteEndpoints.size})`,
      );
    }

    const resolvedLaunchOptions = options.launchOptions ?? {};
    if (
      this.#remoteEndpoints.size === 0 &&
      resolvedSize > 1 &&
      resolvedLaunchOptions.profileDir !== undefined
    ) {
      throw new RangeError(
        "launchOptions.profileDir cannot be set when size > 1 (multiple Chrome slots cannot share one --user-data-dir)",
      );
    }
    if (
      options.maxUsesPerSlot !== undefined &&
      (!Number.isInteger(options.maxUsesPerSlot) || options.maxUsesPerSlot < 1)
    ) {
      throw new RangeError(`maxUsesPerSlot must be an integer >= 1, got ${options.maxUsesPerSlot}`);
    }
    const acquireTimeoutMs = checkMs(
      options.acquireTimeoutMs ?? DEFAULT_ACQUIRE_TIMEOUT_MS,
      "acquireTimeoutMs",
    );
    if (acquireTimeoutMs <= 0) {
      throw new RangeError(`acquireTimeoutMs must be > 0, got ${acquireTimeoutMs}`);
    }
    const displayBackend = options.displayBackend ?? "xvfb";
    if (!DISPLAY_BACKENDS.has(displayBackend)) {
      throw new RangeError(
        `displayBackend must be 'xvfb' or 'wayland', got ${JSON.stringify(displayBackend)}`,
      );
    }
    const displayBase = options.displayBase ?? DEFAULT_DISPLAY_BASE;
    if (!Number.isInteger(displayBase) || displayBase < 0) {
      throw new RangeError(`displayBase must be a non-negative integer, got ${displayBase}`);
    }

    this.#size = resolvedSize;
    this.#availablePermits = resolvedSize;
    this.#launchOptions = resolvedLaunchOptions;
    this.#proxies = options.proxies !== undefined ? [...options.proxies] : [];
    this.#isolatedDisplays = options.isolatedDisplays ?? false;
    this.#displayBackend = displayBackend;
    this.#displayBase = displayBase;
    this.#maxUsesPerSlot = options.maxUsesPerSlot;
    this.#acquireTimeoutMs = acquireTimeoutMs;
  }

  /** Mark the pool as started (slots are lazily launched on `acquire()`). */
  async start(): Promise<void> {
    if (this.#closed) {
      throw new Error("BrowserPool is already closed");
    }
    this.#started = true;
  }

  /** Return a snapshot of current pool utilization and lifecycle counters. */
  stats(): PoolStats {
    return {
      size: this.#size,
      active: this.#activeSlots.size,
      idle: this.#idle.length,
      launched: this.#launched,
      recycled: this.#recycled,
      failed: this.#failed,
    };
  }

  /** Whether `start()` has been called on this pool. */
  get started(): boolean {
    return this.#started;
  }

  /** Whether `close()` has been called on this pool. */
  get closed(): boolean {
    return this.#closed;
  }

  /** Acquire a healthy `PooledPage`. Always call `release()` (or use `await using` / `withPage`). */
  async acquire(options?: AcquireOptions): Promise<PooledPage> {
    if (this.#closed) {
      throw new Error("BrowserPool is closed");
    }
    const timeoutMs =
      options?.timeoutMs !== undefined
        ? checkMs(options.timeoutMs, "timeoutMs")
        : this.#acquireTimeoutMs;
    if (timeoutMs <= 0) {
      throw new RangeError(`timeoutMs must be > 0, got ${timeoutMs}`);
    }

    await this.#acquirePermit(timeoutMs);

    let slot: PoolSlot;
    try {
      if (this.#closed) {
        throw new Error("BrowserPool is closed");
      }
      const reused = await this.#popHealthyIdle(options?.proxy);
      if (this.#closed) {
        if (reused !== null) {
          await this.#destroySlot(reused);
        }
        throw new Error("BrowserPool is closed");
      }
      if (reused !== null) {
        slot = reused;
      } else {
        try {
          slot = await this.#launchSlot(options?.proxy);
        } catch (err) {
          this.#failed += 1;
          throw err;
        }
        if (this.#closed) {
          await this.#destroySlot(slot);
          throw new Error("BrowserPool is closed");
        }
      }
      this.#activeSlots.add(slot);
      slot.uses += 1;
    } catch (err) {
      this.#releasePermit();
      throw err;
    }

    let released = false;
    const release = async (releaseOpts?: ReleaseOptions): Promise<void> => {
      if (released) {
        return;
      }
      released = true;
      this.#activeSlots.delete(slot);
      try {
        await this.#returnOrRecycle(slot, releaseOpts?.recycle === true);
      } finally {
        this.#releasePermit();
      }
    };

    return {
      page: slot.page,
      release,
      async [Symbol.asyncDispose](): Promise<void> {
        await release();
      },
    };
  }

  /**
   * Acquire a page, run `fn(page)`, and release it automatically.
   * If `fn` throws, the slot is recycled so the next caller gets a fresh browser.
   */
  async withPage<T>(fn: (page: Page) => Promise<T> | T, options?: AcquireOptions): Promise<T> {
    const handle = await this.acquire(options);
    let threw = false;
    try {
      return await fn(handle.page);
    } catch (err) {
      threw = true;
      throw err;
    } finally {
      await handle.release(threw ? { recycle: true } : undefined);
    }
  }

  /** Close all idle and active browser slots and terminate any isolated display stacks. */
  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }
    this.#closed = true;

    const closeErr = new Error("BrowserPool is closed");
    while (this.#waiters.length > 0) {
      const waiter = this.#waiters.shift();
      if (waiter !== undefined) {
        clearTimeout(waiter.timer);
        waiter.reject(closeErr);
      }
    }

    const slots: PoolSlot[] = [...this.#idle, ...this.#activeSlots];
    this.#idle.length = 0;
    this.#activeSlots.clear();

    await Promise.allSettled(slots.map((slot) => this.#destroySlot(slot)));
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  #acquirePermit(timeoutMs: number): Promise<void> {
    if (this.#availablePermits > 0) {
      this.#availablePermits -= 1;
      return Promise.resolve();
    }
    return new Promise<void>((resolve, reject) => {
      const waiter: PermitWaiter = {
        resolve,
        reject,
        timer: setTimeout(() => {
          const idx = this.#waiters.indexOf(waiter);
          if (idx !== -1) {
            this.#waiters.splice(idx, 1);
          }
          reject(createTimeoutError(`timed out after ${timeoutMs}ms waiting for a browser slot`));
        }, timeoutMs),
      };
      this.#waiters.push(waiter);
    });
  }

  #releasePermit(): void {
    const next = this.#waiters.shift();
    if (next !== undefined) {
      clearTimeout(next.timer);
      next.resolve();
      return;
    }
    this.#availablePermits += 1;
  }

  #isOverrideProxy(proxy: string | undefined): boolean {
    if (proxy === undefined) {
      return false;
    }
    if (this.#proxies.length > 0) {
      return !this.#proxies.includes(proxy);
    }
    return proxy !== this.#launchOptions.proxy;
  }

  #nextProxy(override: string | undefined): {
    readonly proxy: string | undefined;
    readonly overrideProxy: boolean;
  } {
    if (override !== undefined) {
      return { proxy: override, overrideProxy: this.#isOverrideProxy(override) };
    }
    if (this.#proxies.length > 0) {
      const proxy = this.#proxies[this.#proxyCursor % this.#proxies.length];
      this.#proxyCursor += 1;
      return { proxy, overrideProxy: false };
    }
    return { proxy: this.#launchOptions.proxy, overrideProxy: false };
  }

  #releaseSlotResources(slot: PoolSlot): void {
    if (slot.displayNum !== undefined) {
      this.#reservedDisplays.delete(slot.displayNum);
      slot.displayNum = undefined;
    }
    if (slot.remoteWorker !== undefined) {
      this.#availableRemotes.push(slot.remoteWorker);
      slot.remoteWorker = undefined;
    }
  }

  async #destroySlot(slot: PoolSlot): Promise<void> {
    try {
      await slot.close();
    } finally {
      this.#releaseSlotResources(slot);
    }
  }

  async #popHealthyIdle(proxy: string | undefined): Promise<PoolSlot | null> {
    while (this.#idle.length > 0) {
      let slot: PoolSlot | undefined;
      if (proxy !== undefined) {
        const idx = this.#idle.findIndex((candidate) => candidate.proxy === proxy);
        if (idx !== -1) {
          slot = this.#idle.splice(idx, 1)[0];
        } else {
          const evicted = this.#idle.shift();
          if (evicted !== undefined) {
            this.#recycled += 1;
            await this.#destroySlot(evicted);
          }
          return null;
        }
      } else {
        slot = this.#idle.shift();
      }

      if (slot === undefined) {
        return null;
      }

      try {
        await slot.ping();
      } catch {
        this.#failed += 1;
        this.#recycled += 1;
        await this.#destroySlot(slot);
        continue;
      }

      if (this.#closed) {
        await this.#destroySlot(slot);
        return null;
      }
      return slot;
    }
    return null;
  }

  async #launchSlot(proxy: string | undefined): Promise<PoolSlot> {
    if (this.#remoteEndpoints.size > 0) {
      return this.#launchRemoteSlot();
    }
    return this.#launchLocalSlot(proxy);
  }

  async #launchRemoteSlot(): Promise<PoolSlot> {
    const rawWorker = this.#availableRemotes.shift();
    if (rawWorker === undefined) {
      throw new Error("no remote workers available");
    }
    const endpoint = this.#remoteEndpoints.get(rawWorker);
    if (endpoint === undefined) {
      throw new Error(`unknown remote worker: ${rawWorker}`);
    }
    const connectOpts =
      this.#launchOptions.timeoutMs !== undefined
        ? { timeoutMs: this.#launchOptions.timeoutMs }
        : undefined;

    let transport: Transport;
    try {
      transport = await Transport.connect(endpoint, connectOpts);
      try {
        await transport.ping(HEALTH_PING_TIMEOUT_MS);
      } catch (err) {
        transport.close();
        throw err;
      }
    } catch (err) {
      this.#availableRemotes.push(rawWorker);
      throw err;
    }

    this.#launched += 1;
    return makeRemoteSlot({ transport, remoteWorker: rawWorker });
  }

  async #launchLocalSlot(proxy: string | undefined): Promise<PoolSlot> {
    const { proxy: effectiveProxy, overrideProxy } = this.#nextProxy(proxy);
    const useWayland = this.#displayBackend === "wayland";
    const useIsolated = this.#isolatedDisplays && process.platform === "linux";

    let displayNum: number | undefined;
    if (useIsolated && !useWayland) {
      displayNum = findFreeDisplayNum(this.#displayBase, this.#reservedDisplays);
      this.#reservedDisplays.add(displayNum);
    }

    let displayStack: IsolatedDisplayStack | null = null;
    try {
      let slotOptions: LaunchOptions =
        effectiveProxy !== undefined
          ? { ...this.#launchOptions, proxy: effectiveProxy }
          : { ...this.#launchOptions };

      if (useWayland) {
        if (useIsolated) {
          displayStack = await IsolatedDisplayStack.startWaylandDbus();
        }
        const { display: _omitDisplay, ...withoutDisplay } = slotOptions;
        slotOptions = {
          ...withoutDisplay,
          headlessXvfb: false,
          headlessWayland: true,
          ...(displayStack !== null
            ? { extraEnv: { ...slotOptions.extraEnv, ...displayStack.env } }
            : {}),
        };
      } else if (displayNum !== undefined) {
        displayStack = await IsolatedDisplayStack.start(displayNum);
        slotOptions = {
          ...slotOptions,
          ...(displayStack.display !== undefined ? { display: displayStack.display } : {}),
          headlessXvfb: false,
          extraEnv: { ...slotOptions.extraEnv, ...displayStack.env },
        };
      }

      const session = await launch(slotOptions);
      this.#launched += 1;
      return makeLocalSlot({
        session,
        proxy: effectiveProxy,
        overrideProxy,
        displayStack,
        displayNum,
      });
    } catch (err) {
      if (displayStack !== null) {
        await displayStack.close().catch(() => undefined);
      }
      if (displayNum !== undefined) {
        this.#reservedDisplays.delete(displayNum);
      }
      throw err;
    }
  }

  async #returnOrRecycle(slot: PoolSlot, forceRecycle: boolean): Promise<void> {
    if (this.#closed) {
      await this.#destroySlot(slot);
      return;
    }

    const reachedMaxUses = this.#maxUsesPerSlot !== undefined && slot.uses >= this.#maxUsesPerSlot;
    if (forceRecycle || reachedMaxUses || slot.overrideProxy) {
      this.#recycled += 1;
      await this.#destroySlot(slot);
      return;
    }

    try {
      await slot.ping();
    } catch {
      this.#failed += 1;
      this.#recycled += 1;
      await this.#destroySlot(slot);
      return;
    }

    if (this.#closed) {
      await this.#destroySlot(slot);
      return;
    }

    this.#idle.push(slot);
  }
}

/** Spawning `waybound-daemon`, connecting to it, and shutting it down (`launch()`). */

import { type ChildProcess, spawn } from "node:child_process";
import { closeSync, existsSync, openSync, rmSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import net from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { resolveDaemonBinary } from "./binary.js";
import { Page } from "./client.js";
import { WayboundDaemonError, WayboundLaunchError } from "./errors.js";
import { checkMs, DEFAULT_TIMEOUT_MS, type Endpoint, Transport } from "./transport.js";
import { BLOCK_PRESETS } from "./types.js";

const BLOCK_PRESET_SET: ReadonlySet<string> = new Set(BLOCK_PRESETS);

export type BackendName = "mock" | "macos" | "linux" | "windows" | "android";

/** Options for `launch()`. Mirrors the Python SDK's `LaunchOptions`. */
export interface LaunchOptions {
  /** Driver backend. Default `"mock"` (as in the Python SDK). */
  readonly backend?: BackendName;
  /** Attach to an already running Chrome by PID. */
  readonly pid?: number;
  /** Android device serial. */
  readonly serial?: string;
  /** X11/Wayland display. */
  readonly display?: string;
  readonly headlessXvfb?: boolean;
  /** Let the daemon launch Chrome. */
  readonly launchChrome?: boolean;
  readonly launchWaydroid?: boolean;
  readonly instanceId?: string;
  readonly adbPort?: number;
  /** Initial URL. */
  readonly url?: string;
  readonly profileDir?: string;
  readonly sslKeylog?: string;
  /** Upstream proxy; passed via `WAYBOUND_PROXY` so credentials stay out of `ps` output. */
  readonly proxy?: string;
  readonly blockHosts?: readonly string[];
  /** Opt-in curated L4 host blocklist presets (`"analytics"`, `"ads"`, `"media"`). */
  readonly blockPresets?: readonly string[];
  readonly timezone?: string;
  readonly locale?: string;
  readonly focus?: boolean;
  readonly noMotion?: boolean;
  /** Use loopback TCP instead of a Unix socket (always on for Windows). */
  readonly useTcp?: boolean;
  /** Explicit daemon path; otherwise see `resolveDaemonBinary()`. */
  readonly daemonBinary?: string;
  /** How long to wait for the daemon to accept connections. Default 5 000 ms. */
  readonly startupTimeoutMs?: number;
  /** Base per-request timeout. Default 30 000 ms; long actions scale on top of it. */
  readonly timeoutMs?: number;
  /** Extra environment variables passed to the spawned `waybound-daemon` child process. */
  readonly extraEnv?: Readonly<Record<string, string>>;
}

/** Build the daemon argv (without the executable) for `options` and `endpoint`. */
export function buildDaemonArgs(options: LaunchOptions, endpoint: Endpoint): string[] {
  const args: string[] =
    "socketPath" in endpoint
      ? ["--socket", endpoint.socketPath]
      : ["--tcp", `${endpoint.host}:${endpoint.port}`];
  args.push("--backend", options.backend ?? "mock");
  const pairs: [string, string | number | undefined][] = [
    ["--pid", options.pid],
    ["--serial", options.serial],
    ["--display", options.display],
    ["--instance-id", options.instanceId],
    ["--adb-port", options.adbPort],
    ["--url", options.url],
    ["--profile-dir", options.profileDir],
    ["--ssl-keylog", options.sslKeylog],
    ["--timezone", options.timezone],
    ["--locale", options.locale],
  ];
  for (const [flag, value] of pairs) {
    if (value !== undefined) {
      args.push(flag, String(value));
    }
  }
  if (options.blockHosts !== undefined && options.blockHosts.length > 0) {
    args.push("--block-hosts", options.blockHosts.join(","));
  }
  if (options.blockPresets !== undefined) {
    for (const raw of options.blockPresets) {
      const normalized = raw.trim().toLowerCase();
      if (!BLOCK_PRESET_SET.has(normalized)) {
        throw new RangeError(
          `unknown block preset ${JSON.stringify(raw)} (expected one of: ${BLOCK_PRESETS.join(", ")})`,
        );
      }
      args.push("--block-preset", normalized);
    }
  }
  const flags: [string, boolean | undefined][] = [
    ["--headless-xvfb", options.headlessXvfb],
    ["--launch-chrome", options.launchChrome],
    ["--launch-waydroid", options.launchWaydroid],
    ["--focus", options.focus],
    ["--no-motion", options.noMotion],
  ];
  for (const [flag, on] of flags) {
    if (on) {
      args.push(flag);
    }
  }
  return args;
}

/** How long `close()` waits for the `shutdown` reply before falling back to signals. */
const SHUTDOWN_REPLY_TIMEOUT_MS = 2_000;
/** How long `launch()` waits for the identifying `ping` reply. */
const PING_TIMEOUT_MS = 2_000;
const VERSION_RE = /^\d+\.\d+\.\d+\S*$/;

// Every spawned daemon is tracked from the moment it is spawned until it has been stopped.
// If the Node process exits (or is terminated by SIGTERM/SIGHUP/SIGINT) while any are live,
// they are sent SIGTERM, which the daemon handles like a `shutdown` request, so a forgotten
// `close()` or a crash never leaves an orphaned daemon behind.
const liveDaemons = new Map<ChildProcess, string>();
const FORWARDED_SIGNALS: readonly NodeJS.Signals[] =
  process.platform === "win32" ? [] : ["SIGTERM", "SIGHUP", "SIGINT"];
const signalHandlers = new Map<NodeJS.Signals, () => void>();

function killAllSync(): void {
  for (const [child, tmpDir] of liveDaemons) {
    if (!hasExited(child)) {
      child.kill("SIGTERM");
    }
    try {
      rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // best effort
    }
  }
  liveDaemons.clear();
}

function removeProcessHooks(): void {
  process.off("exit", killAllSync);
  for (const [signal, handler] of signalHandlers) {
    process.off(signal, handler);
  }
  signalHandlers.clear();
}

function installProcessHooks(): void {
  if (signalHandlers.size > 0 || process.listeners("exit").includes(killAllSync)) {
    return;
  }
  process.on("exit", killAllSync);
  for (const signal of FORWARDED_SIGNALS) {
    const handler = (): void => {
      killAllSync();
      removeProcessHooks();
      // Never swallow the signal: if nobody else handles it, re-raise it so the default
      // action (terminating this process) applies. If the application installed its own
      // handler, that handler received this signal too and decides what happens next.
      if (process.listenerCount(signal) === 0) {
        process.kill(process.pid, signal);
      }
    };
    signalHandlers.set(signal, handler);
    process.on(signal, handler);
  }
}

function trackDaemon(child: ChildProcess, tmpDir: string): void {
  liveDaemons.set(child, tmpDir);
  installProcessHooks();
}

function untrackDaemon(child: ChildProcess): void {
  liveDaemons.delete(child);
  if (liveDaemons.size === 0) {
    removeProcessHooks();
  }
}

/** @internal Number of daemons currently tracked (for tests). */
export function _liveDaemonCount(): number {
  return liveDaemons.size;
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
    child.once("exit", onExit);
  });
}

function reserveLoopbackPort(): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const probe = net.createServer();
    probe.unref();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const address = probe.address();
      probe.close(() => {
        if (address !== null && typeof address === "object") {
          resolve(address.port);
        } else {
          reject(new Error("could not reserve a loopback port"));
        }
      });
    });
  });
}

const RETRYABLE_UNIX_CONNECT = new Set(["ENOENT", "ECONNREFUSED", "EACCES", "EPERM"]);

function causeCode(err: unknown): string | undefined {
  if (err instanceof WayboundDaemonError && err.cause instanceof Error) {
    const code = (err.cause as NodeJS.ErrnoException).code;
    return typeof code === "string" ? code : undefined;
  }
  return undefined;
}

/**
 * A running daemon plus one connection to it. Close it with `await session.close()`, or let
 * `await using session = await launch()` do so.
 */
export class Session {
  /** Page bound to this session's daemon connection. */
  readonly page: Page;
  readonly #child: ChildProcess;
  readonly #transport: Transport;
  readonly #tmpDir: string;
  #closing: Promise<void> | null = null;

  private constructor(child: ChildProcess, transport: Transport, tmpDir: string) {
    this.#child = child;
    this.#transport = transport;
    this.#tmpDir = tmpDir;
    this.page = new Page(transport);
  }

  /** @internal Use `launch()`. */
  static _create(child: ChildProcess, transport: Transport, tmpDir: string): Session {
    return new Session(child, transport, tmpDir);
  }

  /** PID of the daemon process. */
  get pid(): number | undefined {
    return this.#child.pid;
  }

  /** `true` once `close()` has started. */
  get closed(): boolean {
    return this.#closing !== null;
  }

  /** Send a health-check `ping` to the daemon and return its version string. */
  ping(timeoutMs?: number): Promise<string> {
    return this.#transport.ping(timeoutMs);
  }

  /**
   * Gracefully shut down the daemon (so it unwinds its browser and socket guards), then
   * escalate to SIGTERM and SIGKILL if it does not exit, and remove the temporary directory.
   * Idempotent.
   */
  close(): Promise<void> {
    this.#closing ??= this.#close();
    return this.#closing;
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  async #close(): Promise<void> {
    try {
      let shutdownSent = false;
      if (!this.#transport.closed) {
        try {
          // A hung daemon must not delay close() by the full request timeout.
          await this.#transport.shutdown(SHUTDOWN_REPLY_TIMEOUT_MS);
          shutdownSent = true;
        } catch {
          // fall through to signals
        }
      }
      this.#transport.close();
      await stopChild(this.#child, shutdownSent);
    } finally {
      untrackDaemon(this.#child);
      await rm(this.#tmpDir, { recursive: true, force: true }).catch(() => undefined);
    }
  }
}

async function stopChild(child: ChildProcess, shutdownSent: boolean): Promise<void> {
  if (hasExited(child) || child.pid === undefined) {
    return;
  }
  if (shutdownSent && (await waitForExit(child, 2_000))) {
    return;
  }
  child.kill("SIGTERM");
  if (await waitForExit(child, 2_000)) {
    return;
  }
  child.kill("SIGKILL");
  await waitForExit(child, 1_000);
}

/** Start `waybound-daemon`, connect to it, and return a `Session` whose `page` drives it. */
export async function launch(options: LaunchOptions = {}): Promise<Session> {
  const binary = resolveDaemonBinary(options.daemonBinary ?? null);
  const useTcp = options.useTcp === true || process.platform === "win32";
  const startupTimeoutMs = checkMs(options.startupTimeoutMs ?? 5_000, "startupTimeoutMs");
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  // Keep the socket path short: macOS limits AF_UNIX paths to 104 bytes.
  const tmpDir = await mkdtemp(useTcp ? path.join(tmpdir(), "wb-") : "/tmp/wb-");
  let child: ChildProcess | null = null;
  try {
    const endpoint: Endpoint = useTcp
      ? { host: "127.0.0.1", port: await reserveLoopbackPort() }
      : { socketPath: path.join(tmpDir, "w.sock") };
    const stderrLog = path.join(tmpDir, "daemon.stderr.log");
    const env: NodeJS.ProcessEnv = { ...process.env, ...options.extraEnv };
    if (options.proxy !== undefined) {
      env.WAYBOUND_PROXY = options.proxy;
    }

    const stderrFd = openSync(stderrLog, "w");
    let spawnError: Error | null = null;
    try {
      child = spawn(binary, buildDaemonArgs(options, endpoint), {
        stdio: ["ignore", "ignore", stderrFd],
        env,
        windowsHide: true,
      });
    } finally {
      closeSync(stderrFd);
    }
    const proc = child;
    trackDaemon(proc, tmpDir);
    proc.on("error", (err) => {
      spawnError = err;
    });
    // A forgotten session must not keep the event loop alive; the exit hook stops the daemon.
    proc.unref();

    const transport = await connectWithRetry({
      endpoint,
      proc,
      stderrLog,
      binary,
      timeoutMs,
      startupTimeoutMs,
      spawnError: () => spawnError,
    });
    return Session._create(proc, transport, tmpDir);
  } catch (err) {
    if (child !== null) {
      await stopChild(child, false);
      untrackDaemon(child);
    }
    await rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
    throw err;
  }
}

async function connectWithRetry(args: {
  endpoint: Endpoint;
  proc: ChildProcess;
  stderrLog: string;
  binary: string;
  timeoutMs: number;
  startupTimeoutMs: number;
  spawnError: () => Error | null;
}): Promise<Transport> {
  const { endpoint, proc } = args;
  const deadline = performance.now() + args.startupTimeoutMs;
  while (performance.now() < deadline) {
    const spawnError = args.spawnError();
    if (spawnError !== null) {
      throw new WayboundLaunchError(`failed to start ${args.binary}: ${spawnError.message}`, {
        cause: spawnError,
      });
    }
    if (hasExited(proc)) {
      const stderr = await readFile(args.stderrLog, "utf8").catch(() => "");
      throw new WayboundLaunchError(
        `waybound-daemon exited early (code ${proc.exitCode ?? proc.signalCode}): ${stderr.trim()}`,
      );
    }
    if (!("socketPath" in endpoint) || existsSync(endpoint.socketPath)) {
      let transport: Transport | null = null;
      try {
        transport = await Transport.connect(endpoint, { timeoutMs: args.timeoutMs });
      } catch (err) {
        if ("socketPath" in endpoint && !RETRYABLE_UNIX_CONNECT.has(causeCode(err) ?? "")) {
          throw err;
        }
      }
      if (transport !== null) {
        await verifyDaemon(transport, endpoint);
        return transport;
      }
    }
    await sleep(20);
  }
  throw new WayboundLaunchError(
    `timed out waiting for waybound-daemon at ${describeEndpoint(endpoint)}`,
  );
}

/**
 * Confirm the endpoint is our daemon before using it (and before ever sending it `shutdown`):
 * another process could have taken the reserved loopback port.
 */
async function verifyDaemon(transport: Transport, endpoint: Endpoint): Promise<void> {
  let version: string;
  try {
    version = await transport.ping(PING_TIMEOUT_MS);
  } catch (err) {
    transport.close();
    throw new WayboundLaunchError(
      `endpoint ${describeEndpoint(endpoint)} did not answer like waybound-daemon`,
      { cause: err },
    );
  }
  if (!VERSION_RE.test(version)) {
    transport.close();
    throw new WayboundLaunchError(
      `endpoint ${describeEndpoint(endpoint)} reported an unexpected version ${JSON.stringify(version)}`,
    );
  }
}

function describeEndpoint(endpoint: Endpoint): string {
  return "socketPath" in endpoint ? endpoint.socketPath : `${endpoint.host}:${endpoint.port}`;
}

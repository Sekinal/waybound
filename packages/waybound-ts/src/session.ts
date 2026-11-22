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
import { DEFAULT_TIMEOUT_MS, type Endpoint, Transport } from "./transport.js";

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

// Daemons still running when the Node process exits are sent SIGTERM (which the daemon handles
// like a `shutdown` request), so a forgotten `close()` never leaves an orphaned daemon behind.
const liveSessions = new Set<Session>();
let exitHookInstalled = false;

function installExitHook(): void {
  if (exitHookInstalled) {
    return;
  }
  exitHookInstalled = true;
  process.on("exit", () => {
    for (const session of liveSessions) {
      session._killSync();
    }
  });
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

  /** @internal Use `launch()`. */
  constructor(child: ChildProcess, transport: Transport, tmpDir: string) {
    this.#child = child;
    this.#transport = transport;
    this.#tmpDir = tmpDir;
    this.page = new Page(transport);
  }

  /** PID of the daemon process. */
  get pid(): number | undefined {
    return this.#child.pid;
  }

  /** `true` once `close()` has started. */
  get closed(): boolean {
    return this.#closing !== null;
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
          await this.#transport.shutdown();
          shutdownSent = true;
        } catch {
          // fall through to signals
        }
      }
      this.#transport.close();
      await stopChild(this.#child, shutdownSent);
    } finally {
      liveSessions.delete(this);
      await rm(this.#tmpDir, { recursive: true, force: true }).catch(() => undefined);
    }
  }

  /** @internal Synchronous best-effort cleanup used by the process `exit` hook. */
  _killSync(): void {
    if (!hasExited(this.#child)) {
      this.#child.kill("SIGTERM");
    }
    try {
      rmSync(this.#tmpDir, { recursive: true, force: true });
    } catch {
      // best effort
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
  const startupTimeoutMs = options.startupTimeoutMs ?? 5_000;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  // Keep the socket path short: macOS limits AF_UNIX paths to 104 bytes.
  const tmpDir = await mkdtemp(useTcp ? path.join(tmpdir(), "wb-") : "/tmp/wb-");
  let child: ChildProcess | null = null;
  try {
    const endpoint: Endpoint = useTcp
      ? { host: "127.0.0.1", port: await reserveLoopbackPort() }
      : { socketPath: path.join(tmpDir, "w.sock") };
    const stderrLog = path.join(tmpDir, "daemon.stderr.log");
    const env = { ...process.env };
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
    const session = new Session(proc, transport, tmpDir);
    liveSessions.add(session);
    installExitHook();
    return session;
  } catch (err) {
    if (child !== null) {
      await stopChild(child, false);
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
      try {
        return await Transport.connect(endpoint, { timeoutMs: args.timeoutMs });
      } catch (err) {
        if ("socketPath" in endpoint && !RETRYABLE_UNIX_CONNECT.has(causeCode(err) ?? "")) {
          throw err;
        }
      }
    }
    await sleep(20);
  }
  const target =
    "socketPath" in endpoint ? endpoint.socketPath : `${endpoint.host}:${endpoint.port}`;
  throw new WayboundLaunchError(`timed out waiting for waybound-daemon at ${target}`);
}

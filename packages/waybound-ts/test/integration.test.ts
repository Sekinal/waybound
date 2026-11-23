/**
 * End-to-end tests against the real `waybound-daemon --backend mock`.
 *
 * They skip (visibly) when the daemon binary is absent. Set `WAYBOUND_REQUIRE_DAEMON=1`
 * (as CI does) to turn a missing binary into a failure instead.
 */

import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, describe, it } from "node:test";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import {
  KeyModifier,
  launch,
  Role,
  type Session,
  Transport,
  WayboundDaemonError,
  WayboundLaunchError,
} from "../src/index.js";
import { _liveDaemonCount } from "../src/session.js";

const REPO_ROOT = fileURLToPath(new URL("../../../../", import.meta.url));
const DAEMON_BIN =
  process.env.WAYBOUND_DAEMON_BIN ??
  path.join(
    REPO_ROOT,
    "target",
    "debug",
    process.platform === "win32" ? "waybound-daemon.exe" : "waybound-daemon",
  );
const PKG_VERSION = (
  JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as {
    version: string;
  }
).version;

const present = existsSync(DAEMON_BIN);
if (!present && process.env.WAYBOUND_REQUIRE_DAEMON === "1") {
  throw new Error(
    `WAYBOUND_REQUIRE_DAEMON=1 but the daemon binary is missing at ${DAEMON_BIN}; run \`cargo build -p waybound-daemon\``,
  );
}
const skip = present
  ? false
  : `waybound-daemon not built at ${DAEMON_BIN} (run cargo build -p waybound-daemon)`;

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

async function assertGone(pid: number | undefined): Promise<void> {
  assert.ok(pid !== undefined);
  for (let i = 0; i < 100 && isAlive(pid); i += 1) {
    await sleep(20);
  }
  assert.equal(isAlive(pid), false, `daemon pid ${pid} is still running`);
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(
    promise,
    (err: unknown) => err instanceof WayboundDaemonError && err.code === code,
  );
}

async function withSession(
  fn: (session: Session) => Promise<void>,
  opts: { useTcp?: boolean } = {},
): Promise<void> {
  const session = await launch({ backend: "mock", daemonBinary: DAEMON_BIN, ...opts });
  const pid = session.pid;
  try {
    await fn(session);
  } finally {
    await session.close();
  }
  await assertGone(pid);
}

describe("integration: waybound-daemon --backend mock", { skip }, () => {
  it("drives a full workflow over the Unix socket transport", async () => {
    await withSession(async (session) => {
      const { page } = session;
      assert.equal(await page.transport.ping(), PKG_VERSION, "daemon version matches package");

      const nodes = await page.snapshotTree();
      assert.equal(nodes.length, 5);
      assert.equal(nodes[0]?.role, Role.TEXTBOX);
      assert.equal(nodes[0]?.name, "Origin");
      assert.equal(await page.url(), "https://mock.waybound.local/");
      assert.equal(await page.waitForUrl("mock.waybound"), "https://mock.waybound.local/");

      const buttons = page.getByRole(Role.BUTTON);
      assert.equal(await buttons.count(), 1);
      assert.equal(await buttons.isVisible(), true);
      assert.equal(await buttons.nth(1).isVisible(), false);
      assert.equal(await buttons.first.textContent(), "Search Flights");
      const found = await page
        .getByRole(Role.BUTTON, { name: "search" })
        .waitFor({ timeoutMs: 1_000 });
      assert.equal(found.id, "btn-search");
      assert.equal(
        (await page.getByRole(Role.BUTTON, { name: "search", exact: true }).all()).length,
        0,
      );
      assert.equal(await page.getByRole(Role.TEXTBOX, { name: "Origin" }).inputValue(), "");
      assert.equal((await page.waitForText("Flights")).id, "btn-search");

      await page.goto("https://example.com");
      await page.getByRole(Role.TEXTBOX, { name: "Origin" }).fill("NRT 東京");
      await page.getByRole(Role.BUTTON, { name: "Search" }).click();
      await page.getByRole(Role.BUTTON, { name: "Search" }).dblclick();
      await page.getByRole(Role.BUTTON, { name: "Search" }).hover();
      await page.getByRole(Role.TEXTBOX).selectOption({ index: 1 });
      await page.scroll({ deltaY: -200 });
      await page.press("enter");
      await page.press("l", { modifiers: [KeyModifier.META] });
      await page.reload();
      await page.goBack();
      await page.goForward();
      await page.newTab("https://example.org");
      await page.nextTab();
      await page.prevTab();
      await page.closeTab();

      const png = await page.screenshot();
      assert.deepEqual([...png.subarray(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
      const shotDir = mkdtempSync(path.join(tmpdir(), "wb-shot-test-"));
      try {
        const kept = path.join(shotDir, "kept.png");
        await page.screenshot(kept);
        assert.ok(existsSync(kept));
      } finally {
        rmSync(shotDir, { recursive: true, force: true });
      }

      assert.deepEqual(await page.capturedResponses(), []);
      assert.deepEqual(await page.capturedResponses({ urlContains: "api" }), []);
      assert.deepEqual(await page.networkStats(), {
        bytesSent: 0,
        bytesReceived: 0,
        connectionsTotal: 0,
        connectionsBlocked: 0,
      });
      await page.waitForNetworkIdle({ idleMs: 50, timeoutMs: 2_000 });

      // Daemon-side errors map to codes and leave the session usable.
      await expectCode(
        page.getByRole(Role.BUTTON, { name: "Nonexistent" }).waitFor({ timeoutMs: 120 }),
        "timeout",
      );
      await expectCode(page.goto("javascript:alert(1)"), "io_error");
      await expectCode(page.getByRole(Role.LINK).click(), "element_not_found");
      await expectCode(page.waitForResponse("/api", { timeoutMs: 150 }), "timeout");
      assert.equal(await page.url(), "https://mock.waybound.local/");
    });
  });

  it("scopes chained locators inside a container", async () => {
    await withSession(async ({ page }) => {
      // The text box does not contain the button, so the scoped query finds nothing.
      const scoped = page.getByRole(Role.TEXTBOX, { name: "Origin" }).getByRole(Role.BUTTON);
      assert.equal(await scoped.count(), 0);
      assert.equal(await page.getByText("Search").count(), 1);
    });
  });

  it("serialises concurrent calls and runs waitForResponse alongside them", async () => {
    await withSession(async ({ page }) => {
      const results = await Promise.all([
        page.url(),
        page.getByRole(Role.BUTTON).count(),
        page.snapshotTree(),
        page.waitForResponse("nothing", { timeoutMs: 200 }).catch((err: unknown) => err),
        page.getByRole(Role.BUTTON).click(),
      ]);
      assert.equal(results[0], "https://mock.waybound.local/");
      assert.equal(results[1], 1);
      assert.ok(results[3] instanceof WayboundDaemonError);
    });
  });

  it("works over loopback TCP", async () => {
    await withSession(
      async ({ page }) => {
        assert.ok((await page.snapshotTree()).length > 0);
        await page.getByRole(Role.BUTTON).click();
        assert.equal((await page.waitForText("Search")).name, "Search Flights");
      },
      { useTcp: true },
    );
  });

  it("stays connected across the daemon's idle read-timeout wakeups", async () => {
    await withSession(async ({ page }) => {
      assert.equal(await page.url(), "https://mock.waybound.local/");
      await sleep(2_500);
      assert.equal(await page.url(), "https://mock.waybound.local/");
    });
  });

  it("shuts the daemon down on close, removes its socket, and is idempotent", async () => {
    const session = await launch({ backend: "mock", daemonBinary: DAEMON_BIN });
    const endpoint = session.page.transport.endpoint;
    assert.ok("socketPath" in endpoint || process.platform === "win32");
    await Promise.all([session.close(), session.close()]);
    await session.close();
    assert.equal(session.closed, true);
    await assertGone(session.pid);
    if ("socketPath" in endpoint) {
      assert.equal(existsSync(path.dirname(endpoint.socketPath)), false, "temp dir removed");
    }
    await expectCode(session.page.url(), "closed");
    await assert.rejects(Transport.connect(endpoint, { timeoutMs: 500 }));
  });

  it("supports `await using`", async () => {
    let pid: number | undefined;
    {
      await using session = await launch({ backend: "mock", daemonBinary: DAEMON_BIN });
      pid = session.pid;
      assert.ok(await session.page.url());
    }
    await assertGone(pid);
  });

  it("kills the daemon if the transport dies and the session is closed", async () => {
    const session = await launch({ backend: "mock", daemonBinary: DAEMON_BIN });
    session.page.transport.close();
    await session.close();
    await assertGone(session.pid);
  });

  it("reports a daemon that exits during startup, with its stderr", async () => {
    await assert.rejects(
      launch({ backend: "no-such-backend" as "mock", daemonBinary: DAEMON_BIN }),
      (err: unknown) => err instanceof WayboundLaunchError && /exited early/.test(err.message),
    );
  });

  it("reports a missing daemon binary", async () => {
    await assert.rejects(
      launch({ daemonBinary: path.join(tmpdir(), "definitely-not-a-waybound-daemon") }),
      (err: unknown) => err instanceof WayboundLaunchError && /failed to start/.test(err.message),
    );
  });

  it("does not keep the event loop alive and leaves no orphan when close() is forgotten", async () => {
    const indexUrl = new URL("../src/index.js", import.meta.url).href;
    const script = `
      import { launch } from ${JSON.stringify(indexUrl)};
      const session = await launch({ backend: "mock", daemonBinary: ${JSON.stringify(DAEMON_BIN)} });
      await session.page.url();
      process.stdout.write(String(session.pid));
    `;
    const started = performance.now();
    const stdout = await new Promise<string>((resolve, reject) => {
      execFile(
        process.execPath,
        ["--input-type=module", "-e", script],
        { timeout: 15_000 },
        (err, out) => (err ? reject(err) : resolve(out)),
      );
    });
    assert.ok(performance.now() - started < 10_000, "child exited without close()");
    await assertGone(Number(stdout));
  });
  for (const withUserHandler of [false, true]) {
    it(`stops the daemon on SIGTERM ${withUserHandler ? "and leaves a user SIGTERM handler in charge" : "and re-raises the signal"}`, {
      skip: process.platform === "win32",
    }, async () => {
      const indexUrl = new URL("../src/index.js", import.meta.url).href;
      const script = `
          import { launch } from ${JSON.stringify(indexUrl)};
          ${withUserHandler ? 'process.on("SIGTERM", () => process.exit(7));' : ""}
          const session = await launch({ backend: "mock", daemonBinary: ${JSON.stringify(DAEMON_BIN)} });
          await session.page.url();
          process.stdout.write(String(session.pid) + "\\n");
          setInterval(() => {}, 1000);
        `;
      const child = spawn(process.execPath, ["--input-type=module", "-e", script], {
        stdio: ["ignore", "pipe", "inherit"],
      });
      const daemonPid = await new Promise<number>((resolve, reject) => {
        let out = "";
        child.stdout.on("data", (d: Buffer) => {
          out += d.toString();
          if (out.includes("\n")) {
            resolve(Number(out.trim()));
          }
        });
        child.once("exit", () => reject(new Error("child exited before launching")));
      });
      const exited = new Promise<[number | null, NodeJS.Signals | null]>((resolve) =>
        child.once("exit", (code, signal) => resolve([code, signal])),
      );
      child.kill("SIGTERM");
      const [code, signal] = await exited;
      if (withUserHandler) {
        assert.equal(code, 7);
      } else {
        assert.equal(signal, "SIGTERM", "signal was re-raised with its default action");
      }
      await assertGone(daemonPid);
    });
  }

  it("untracks daemons once sessions close", async () => {
    const session = await launch({ backend: "mock", daemonBinary: DAEMON_BIN });
    assert.equal(_liveDaemonCount(), 1);
    assert.ok(process.listeners("SIGTERM").length >= 1);
    await session.close();
    assert.equal(_liveDaemonCount(), 0);
    assert.equal(process.listenerCount("SIGHUP"), 0, "signal handlers removed");
  });
});

/** Write an executable stand-in for the daemon. `mode` picks how it misbehaves. */
function fakeDaemonBinary(
  dir: string,
  mode: "badversion" | "silent" | "hang",
): { bin: string; log: string } {
  const log = path.join(dir, `${mode}.log`);
  const js = path.join(dir, `${mode}.mjs`);
  writeFileSync(
    js,
    `
import net from "node:net";
import fs from "node:fs";
const mode = ${JSON.stringify(mode)};
const log = ${JSON.stringify(log)};
const args = process.argv.slice(2);
process.on("SIGTERM", () => { fs.appendFileSync(log, "SIGTERM\\n"); if (mode !== "hang") process.exit(0); });
const server = net.createServer((sock) => {
  sock.on("error", () => {});
  let buf = "";
  sock.on("data", (d) => {
    buf += d;
    for (let k = buf.indexOf("\\n"); k >= 0; k = buf.indexOf("\\n")) {
      const req = JSON.parse(buf.slice(0, k));
      buf = buf.slice(k + 1);
      fs.appendFileSync(log, req.method + "\\n");
      if (req.method === "ping") {
        if (mode === "silent") continue;
        sock.write(JSON.stringify({ status: "pong", version: mode === "badversion" ? "hello" : "0.4.0" }) + "\\n");
      } else if (req.method === "shutdown") {
        if (mode === "hang") continue;
        sock.write('{"status":"ok"}\\n');
        process.exit(0);
      } else {
        sock.write('{"status":"ok"}\\n');
      }
    }
  });
});
const s = args.indexOf("--socket");
if (s >= 0) server.listen(args[s + 1]);
else { const [h, p] = args[args.indexOf("--tcp") + 1].split(":"); server.listen(Number(p), h); }
`,
  );
  const bin = path.join(dir, `${mode}.sh`);
  writeFileSync(bin, `#!/bin/sh\nexec "${process.execPath}" "${js}" "$@"\n`);
  chmodSync(bin, 0o755);
  return { bin, log };
}

describe("launch() against misbehaving endpoints", { skip: process.platform === "win32" }, () => {
  const dir = mkdtempSync(path.join(tmpdir(), "wb-fake-"));
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("refuses an endpoint whose ping reply is not a daemon version, and never sends shutdown", async () => {
    const { bin, log } = fakeDaemonBinary(dir, "badversion");
    await assert.rejects(
      launch({ daemonBinary: bin, useTcp: true }),
      (err: unknown) =>
        err instanceof WayboundLaunchError && /unexpected version/.test(err.message),
    );
    const methods = readFileSync(log, "utf8").trim().split("\n");
    assert.deepEqual(
      methods.filter((m) => m !== "SIGTERM"),
      ["ping"],
    );
    assert.equal(_liveDaemonCount(), 0);
  });

  it("refuses an endpoint that never answers the ping", async () => {
    const { bin } = fakeDaemonBinary(dir, "silent");
    await assert.rejects(
      launch({ daemonBinary: bin, useTcp: true }),
      (err: unknown) => err instanceof WayboundLaunchError && /did not answer/.test(err.message),
    );
  });

  it("does not wait the full request timeout for a hung daemon on close()", async () => {
    const { bin, log } = fakeDaemonBinary(dir, "hang");
    const session = await launch({ daemonBinary: bin });
    const started = performance.now();
    await session.close();
    const elapsed = performance.now() - started;
    assert.ok(elapsed < 8_000, `close took ${elapsed}ms`);
    await assertGone(session.pid);
    assert.match(readFileSync(log, "utf8"), /shutdown\nSIGTERM/);
  });

  it("kills a daemon spawned by a process that exits before it connects", async () => {
    const pidFile = path.join(dir, "slow.pid");
    const bin = path.join(dir, "slow.sh");
    writeFileSync(bin, `#!/bin/sh\necho $$ > "${pidFile}"\nexec sleep 30\n`);
    chmodSync(bin, 0o755);
    const indexUrl = new URL("../src/index.js", import.meta.url).href;
    const script = `
      import { launch } from ${JSON.stringify(indexUrl)};
      launch({ daemonBinary: ${JSON.stringify(bin)}, startupTimeoutMs: 20000 }).catch(() => {});
      setTimeout(() => process.exit(0), 500);
    `;
    await new Promise<void>((resolve, reject) => {
      execFile(
        process.execPath,
        ["--input-type=module", "-e", script],
        { timeout: 15_000 },
        (err) => (err ? reject(err) : resolve()),
      );
    });
    await assertGone(Number(readFileSync(pidFile, "utf8").trim()));
  });

  it("supports snapshotTree maxNodes, truncation metadata, and strict locator mode", async () => {
    const session = await launch({ backend: "mock", daemonBinary: DAEMON_BIN });
    try {
      const { page } = session;

      const full = await page.snapshotTreeWithMeta({ maxNodes: 20 });
      assert.equal(full.nodes.length, 5);
      assert.equal(full.truncated, false);
      assert.equal(page.lastTreeTruncated, false);

      const capped = await page.snapshotTreeWithMeta({ maxNodes: 2 });
      assert.equal(capped.nodes.length, 2);
      assert.equal(capped.truncated, true);
      assert.equal(page.lastTreeTruncated, true);

      const nodes = await page.snapshotTree({ maxNodes: 3 });
      assert.equal(nodes.length, 3);
      assert.equal(page.lastTreeTruncated, true);

      const single = await page
        .getByRole(Role.BUTTON, { strict: true })
        .waitFor({ timeoutMs: 1_000 });
      assert.equal(single.id, "btn-search");

      await assert.rejects(
        () => page.getByRole(Role.CHECKBOX, { strict: true }).click(),
        (err: unknown) =>
          err instanceof WayboundDaemonError &&
          err.code === "strict_mode_violation" &&
          err.message.includes("2 elements"),
      );

      // `.first` and `.nth(i)` disambiguate a strict locator without raising.
      const strictFirst = await page
        .getByRole(Role.CHECKBOX, { strict: true })
        .first.waitFor({ timeoutMs: 1_000 });
      assert.equal(strictFirst.id, "chk-nonstop");

      const strictSecond = await page
        .getByRole(Role.CHECKBOX, { strict: true })
        .nth(1)
        .waitFor({ timeoutMs: 1_000 });
      assert.equal(strictSecond.id, "chk-insurance");

      // Non-strict mode still resolves the first match.
      const firstCheckbox = await page.getByRole(Role.CHECKBOX).waitFor({ timeoutMs: 1_000 });
      assert.equal(firstCheckbox.id, "chk-nonstop");
    } finally {
      await session.close();
    }
  });
});

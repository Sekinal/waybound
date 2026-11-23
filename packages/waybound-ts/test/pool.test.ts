/**
 * Unit and live `waybound-daemon --backend mock` tests for `BrowserPool`.
 */

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import {
  BrowserPool,
  buildDbusArgs,
  buildSlotEnv,
  buildXvfbArgs,
  type DisplayBackend,
  findFreeDisplayNum,
  parseRemoteWorker,
  Role,
  Transport,
} from "../src/index.js";
import { buildDaemonArgs } from "../src/session.js";

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

function reservePort(): Promise<number> {
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
          reject(new Error("could not reserve loopback port"));
        }
      });
    });
  });
}

describe("BrowserPool pure helpers", () => {
  it("parses valid and rejects invalid remote worker endpoints", () => {
    assert.deepEqual(parseRemoteWorker("127.0.0.1:49222"), { host: "127.0.0.1", port: 49222 });
    assert.deepEqual(parseRemoteWorker("worker-1.internal:9000"), {
      host: "worker-1.internal",
      port: 9000,
    });
    assert.deepEqual(parseRemoteWorker("[::1]:49222"), { host: "::1", port: 49222 });

    for (const bad of ["", "   ", "localhost", ":8080", "host:0", "host:70000", "host:abc"]) {
      assert.throws(() => parseRemoteWorker(bad));
    }
  });

  it("builds Xvfb, D-Bus, and isolated slot environment configs", () => {
    assert.deepEqual(buildXvfbArgs(100), [
      ":100",
      "-screen",
      "0",
      "1280x800x24",
      "-nolisten",
      "tcp",
      "-ac",
    ]);
    assert.deepEqual(buildXvfbArgs(105, { width: 1920, height: 1080, colorDepth: 24 }), [
      ":105",
      "-screen",
      "0",
      "1920x1080x24",
      "-nolisten",
      "tcp",
      "-ac",
    ]);
    assert.throws(() => buildXvfbArgs(-1), RangeError);

    assert.deepEqual(buildDbusArgs(), ["--session", "--print-address=1", "--nofork"]);

    assert.deepEqual(buildSlotEnv({ display: ":100", dbusAddress: "unix:path=/tmp/dbus-100" }), {
      DISPLAY: ":100",
      DBUS_SESSION_BUS_ADDRESS: "unix:path=/tmp/dbus-100",
      ACCESSIBILITY_ENABLED: "1",
      GTK_MODULES: "gail:atk-bridge",
      QT_ACCESSIBILITY: "1",
    });

    assert.equal(
      buildSlotEnv({
        display: ":101",
        dbusAddress: "unix:path=/tmp/dbus-101",
        atspiAddress: "unix:path=/tmp/atspi-101",
      }).AT_SPI_BUS_ADDRESS,
      "unix:path=/tmp/atspi-101",
    );
  });

  it("skips reserved displays and existing lock/socket files in findFreeDisplayNum", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "wb-x11-test-"));
    try {
      writeFileSync(path.join(dir, ".X100-lock"), "1234\n");
      mkdirSync(path.join(dir, ".X11-unix"));
      writeFileSync(path.join(dir, ".X11-unix", "X101"), "");

      const chosen = findFreeDisplayNum(100, new Set([102]), dir);
      assert.equal(chosen, 103);
      assert.throws(() => findFreeDisplayNum(-1, new Set(), dir), RangeError);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("validates BrowserPool constructor options", () => {
    assert.throws(() => new BrowserPool({ size: 0 }), RangeError);
    assert.throws(
      () => new BrowserPool({ size: 2, remoteWorkers: ["127.0.0.1:49222"] }),
      RangeError,
    );
    assert.throws(() => new BrowserPool({ size: 1, maxUsesPerSlot: 0 }), RangeError);
    assert.throws(() => new BrowserPool({ size: 1, acquireTimeoutMs: 0 }), RangeError);
    assert.throws(() => new BrowserPool({ size: 1, displayBase: -1 }), RangeError);
    assert.throws(
      () =>
        new BrowserPool({
          remoteWorkers: ["127.0.0.1:49222", " 127.0.0.1:49222 "],
        }),
      RangeError,
    );
    assert.throws(
      () =>
        new BrowserPool({
          size: 2,
          launchOptions: { backend: "mock", profileDir: "/tmp/shared" },
        }),
      RangeError,
    );
    assert.throws(
      () =>
        new BrowserPool({
          size: 1,
          displayBackend: "invalid" as DisplayBackend,
        }),
      RangeError,
    );
  });

  it("forwards --headless-wayland and rejects combining with --headless-xvfb", () => {
    const waylandArgs = buildDaemonArgs(
      { backend: "linux", headlessWayland: true },
      { host: "127.0.0.1", port: 49222 },
    );
    assert.ok(waylandArgs.includes("--headless-wayland"));
    assert.ok(!waylandArgs.includes("--headless-xvfb"));

    assert.throws(
      () =>
        buildDaemonArgs(
          { backend: "linux", headlessXvfb: true, headlessWayland: true },
          { host: "127.0.0.1", port: 49222 },
        ),
      RangeError,
    );

    const waylandEnv = buildSlotEnv({ dbusAddress: "unix:path=/tmp/dbus-wl" });
    assert.equal(waylandEnv.DISPLAY, undefined);
    assert.equal(waylandEnv.DBUS_SESSION_BUS_ADDRESS, "unix:path=/tmp/dbus-wl");
  });
});

describe("BrowserPool live daemon integration", { skip }, () => {
  it("handles concurrent Promise.all checkouts and queueing up to size=3", async () => {
    await using pool = new BrowserPool({
      size: 3,
      launchOptions: { backend: "mock", daemonBinary: DAEMON_BIN },
    });
    await pool.start();

    let currentActive = 0;
    let maxObserved = 0;

    const results = await Promise.all(
      [0, 1, 2, 3, 4].map((idx) =>
        pool.withPage(async (page) => {
          currentActive += 1;
          maxObserved = Math.max(maxObserved, currentActive);
          const tree = await page.snapshotTree();
          assert.ok(tree.length > 0);
          await sleep(80);
          currentActive -= 1;
          return idx;
        }),
      ),
    );

    assert.deepEqual(results, [0, 1, 2, 3, 4]);
    assert.equal(maxObserved, 3);
    assert.deepEqual(pool.stats(), {
      size: 3,
      active: 0,
      idle: 3,
      launched: 3,
      recycled: 0,
      failed: 0,
    });
  });

  it("recycles a slot when withPage throws and launches a fresh slot on next acquire", async () => {
    await using pool = new BrowserPool({
      size: 1,
      launchOptions: { backend: "mock", daemonBinary: DAEMON_BIN },
    });

    await assert.rejects(
      pool.withPage(async (page) => {
        const tree = await page.snapshotTree();
        assert.ok(tree.length > 0);
        throw new Error("simulated crash");
      }),
      /simulated crash/,
    );

    assert.deepEqual(pool.stats(), {
      size: 1,
      active: 0,
      idle: 0,
      launched: 1,
      recycled: 1,
      failed: 0,
    });

    await using handle = await pool.acquire();
    const count = await handle.page.getByRole(Role.BUTTON).count();
    assert.ok(count >= 1);
    await handle.release();

    assert.deepEqual(pool.stats(), {
      size: 1,
      active: 0,
      idle: 1,
      launched: 2,
      recycled: 1,
      failed: 0,
    });
  });

  it("proactively recycles slots after maxUsesPerSlot checkouts", async () => {
    await using pool = new BrowserPool({
      size: 1,
      launchOptions: { backend: "mock", daemonBinary: DAEMON_BIN },
      maxUsesPerSlot: 2,
    });

    // Use 1 -> returned to idle
    await pool.withPage(async (page) => {
      assert.ok((await page.snapshotTree()).length > 0);
    });
    assert.deepEqual(pool.stats(), {
      size: 1,
      active: 0,
      idle: 1,
      launched: 1,
      recycled: 0,
      failed: 0,
    });

    // Use 2 -> reaches maxUsesPerSlot -> recycled
    await pool.withPage(async (page) => {
      assert.ok((await page.snapshotTree()).length > 0);
    });
    assert.deepEqual(pool.stats(), {
      size: 1,
      active: 0,
      idle: 0,
      launched: 1,
      recycled: 1,
      failed: 0,
    });

    // Use 3 -> launches a fresh slot
    await pool.withPage(async (page) => {
      assert.ok((await page.snapshotTree()).length > 0);
    });
    assert.deepEqual(pool.stats(), {
      size: 1,
      active: 0,
      idle: 1,
      launched: 2,
      recycled: 1,
      failed: 0,
    });
  });

  it("rejects with TimeoutError when all slots are busy past acquireTimeoutMs", async () => {
    await using pool = new BrowserPool({
      size: 1,
      launchOptions: { backend: "mock", daemonBinary: DAEMON_BIN },
      acquireTimeoutMs: 150,
    });

    await using held = await pool.acquire();
    assert.ok((await held.page.snapshotTree()).length > 0);

    await assert.rejects(pool.acquire(), (err: unknown) => {
      return err instanceof Error && err.name === "TimeoutError";
    });
  });

  it("connects to remote TCP workers and leaves them running after pool.close()", async () => {
    const port = await reservePort();
    const addr = `127.0.0.1:${port}`;
    const child = spawn(DAEMON_BIN, ["--tcp", addr, "--backend", "mock"], {
      stdio: ["ignore", "ignore", "ignore"],
    });

    try {
      let ready = false;
      const deadline = performance.now() + 5_000;
      while (performance.now() < deadline) {
        try {
          const probe = await Transport.connect({ host: "127.0.0.1", port }, { timeoutMs: 1_000 });
          await probe.ping(1_000);
          probe.close();
          ready = true;
          break;
        } catch {
          await sleep(30);
        }
      }
      assert.ok(ready, `remote mock daemon failed to start on ${addr}`);

      const pool = new BrowserPool({ remoteWorkers: [addr] });
      await pool.withPage(async (page) => {
        const tree = await page.snapshotTree();
        assert.ok(tree.length > 0);
        const node = await page.waitForText("Search");
        assert.ok(node.name !== null);
      });

      assert.deepEqual(pool.stats(), {
        size: 1,
        active: 0,
        idle: 1,
        launched: 1,
        recycled: 0,
        failed: 0,
      });

      await pool.close();
      await pool.close(); // idempotent

      // Remote daemon must still be alive after pool.close().
      const verify = await Transport.connect({ host: "127.0.0.1", port }, { timeoutMs: 2_000 });
      const version = await verify.ping(2_000);
      assert.ok(version.length > 0);
      verify.close();
    } finally {
      try {
        const closer = await Transport.connect({ host: "127.0.0.1", port }, { timeoutMs: 1_000 });
        await closer.shutdown(1_000).catch(() => undefined);
        closer.close();
      } catch {
        // already stopped
      }
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGTERM");
      }
    }
  });

  it("rejects acquire() after close()", async () => {
    const pool = new BrowserPool({
      size: 1,
      launchOptions: { backend: "mock", daemonBinary: DAEMON_BIN },
    });
    await pool.close();
    await assert.rejects(pool.acquire(), /closed/);
  });

  it("unblocks queued waiters and cleans up active slots when close() is called", async () => {
    const pool = new BrowserPool({
      size: 1,
      launchOptions: { backend: "mock", daemonBinary: DAEMON_BIN },
      acquireTimeoutMs: 30_000,
    });

    const held = await pool.acquire();
    assert.ok((await held.page.snapshotTree()).length > 0);

    const queuedAssert = assert.rejects(pool.acquire(), /closed/);
    await sleep(30);

    await pool.close();
    await queuedAssert;
    await held.release();

    assert.equal(pool.stats().active, 0);
    assert.equal(pool.stats().idle, 0);
  });

  it("recycles per-checkout proxy overrides so they never leak to default acquire()", async () => {
    await using pool = new BrowserPool({
      size: 1,
      launchOptions: { backend: "mock", daemonBinary: DAEMON_BIN },
    });

    await pool.withPage(
      async (page) => {
        assert.ok((await page.snapshotTree()).length > 0);
      },
      { proxy: "http://127.0.0.1:18080" },
    );

    assert.deepEqual(pool.stats(), {
      size: 1,
      active: 0,
      idle: 0,
      launched: 1,
      recycled: 1,
      failed: 0,
    });

    await pool.withPage(async (page) => {
      assert.ok((await page.snapshotTree()).length > 0);
    });

    assert.deepEqual(pool.stats(), {
      size: 1,
      active: 0,
      idle: 1,
      launched: 2,
      recycled: 1,
      failed: 0,
    });
  });

  it("skips Xvfb and forwards --headless-wayland when displayBackend is 'wayland'", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = mkdtempSync(path.join(tmpdir(), "wb-wl-pool-"));
    const argsLog = path.join(dir, "daemon.args");
    const wrapper = path.join(dir, "daemon-wrapper.sh");
    writeFileSync(
      wrapper,
      `#!/bin/sh\nprintf '%s\\n' "$@" > ${JSON.stringify(argsLog)}\nexec ${JSON.stringify(DAEMON_BIN)} "$@"\n`,
    );
    chmodSync(wrapper, 0o755);

    try {
      await using pool = new BrowserPool({
        size: 1,
        isolatedDisplays: true,
        displayBackend: "wayland",
        launchOptions: {
          backend: "mock",
          headlessXvfb: true,
          daemonBinary: wrapper,
        },
      });
      await pool.withPage(async (page) => {
        assert.ok((await page.snapshotTree()).length > 0);
      });

      const recorded = readFileSync(argsLog, "utf8").trim().split("\n");
      assert.ok(recorded.includes("--headless-wayland"), `missing --headless-wayland: ${recorded}`);
      assert.ok(!recorded.includes("--headless-xvfb"), `unexpected --headless-xvfb: ${recorded}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

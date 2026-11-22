/**
 * End-to-end tests against the real `waybound-daemon --backend mock`.
 *
 * They skip (visibly) when the daemon binary is absent. Set `WAYBOUND_REQUIRE_DAEMON=1`
 * (as CI does) to turn a missing binary into a failure instead.
 */

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
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
      assert.equal(nodes.length, 2);
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
});

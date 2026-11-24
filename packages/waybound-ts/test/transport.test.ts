import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { after, afterEach, before, describe, it } from "node:test";
import { setTimeout as sleep } from "node:timers/promises";
import { Page } from "../src/client.js";
import { WayboundDaemonError } from "../src/errors.js";
import { buildDaemonArgs } from "../src/session.js";
import {
  DEFAULT_TIMEOUT_MS,
  type Endpoint,
  encodeKey,
  encodeQuery,
  fillTimeoutMs,
  MAX_TIMER_MS,
  MAX_WAIT_MS,
  parseHttpResponse,
  parseNode,
  Transport,
  waitTimeoutMs,
} from "../src/transport.js";
import { KeyModifier, Role } from "../src/types.js";

type Handler = (request: Record<string, unknown>, socket: net.Socket, conn: number) => void;

interface FakeDaemon {
  readonly endpoint: Endpoint;
  readonly requests: Record<string, unknown>[];
  connections: number;
  close(): Promise<void>;
}

/** A scripted stand-in for the daemon: parses request lines and lets `handler` answer. */
async function fakeDaemon(handler: Handler, socketPath?: string): Promise<FakeDaemon> {
  const sockets = new Set<net.Socket>();
  const state = {
    requests: [] as Record<string, unknown>[],
    connections: 0,
  };
  const server = net.createServer((socket) => {
    state.connections += 1;
    const conn = state.connections;
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => undefined);
    let buf = "";
    socket.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      for (let idx = buf.indexOf("\n"); idx !== -1; idx = buf.indexOf("\n")) {
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 1);
        const request = JSON.parse(line) as Record<string, unknown>;
        state.requests.push(request);
        handler(request, socket, conn);
      }
    });
  });
  await new Promise<void>((resolve) => {
    if (socketPath === undefined) {
      server.listen(0, "127.0.0.1", resolve);
    } else {
      server.listen(socketPath, resolve);
    }
  });
  const address = server.address();
  const endpoint: Endpoint =
    socketPath !== undefined
      ? { socketPath }
      : { host: "127.0.0.1", port: (address as net.AddressInfo).port };
  return {
    endpoint,
    get requests() {
      return state.requests;
    },
    get connections() {
      return state.connections;
    },
    set connections(v: number) {
      state.connections = v;
    },
    close: () =>
      new Promise<void>((resolve) => {
        for (const s of sockets) {
          s.destroy();
        }
        server.close(() => resolve());
      }),
  };
}

function reply(socket: net.Socket, payload: unknown): void {
  socket.write(`${JSON.stringify(payload)}\n`);
}

const unhandled: unknown[] = [];
const onUnhandled = (reason: unknown): void => {
  unhandled.push(reason);
};

async function expectCode(promise: Promise<unknown>, code: string): Promise<WayboundDaemonError> {
  try {
    await promise;
  } catch (err) {
    assert.ok(err instanceof WayboundDaemonError, `expected WayboundDaemonError, got ${err}`);
    assert.equal(err.code, code, err.message);
    return err;
  }
  assert.fail(`expected rejection with code ${code}`);
}

describe("Transport against a scripted daemon", () => {
  let daemon: FakeDaemon | null = null;
  let transport: Transport | null = null;

  before(() => {
    process.on("unhandledRejection", onUnhandled);
  });
  after(() => {
    process.off("unhandledRejection", onUnhandled);
    assert.deepEqual(unhandled, [], "no unhandled promise rejections");
  });
  afterEach(async () => {
    transport?.close();
    transport = null;
    await daemon?.close();
    daemon = null;
  });

  it("matches replies to requests in order, even when calls are issued concurrently", async () => {
    daemon = await fakeDaemon((req, socket) => {
      if (req.method === "ping") {
        // Reply slowly and in fragments to exercise reassembly.
        const bytes = Buffer.from('{"status":"pong","version":"9.9.9"}\n');
        setTimeout(() => socket.write(bytes.subarray(0, 7)), 10);
        setTimeout(() => socket.write(bytes.subarray(7)), 30);
      } else {
        reply(socket, { status: "url", url: "https://example.test/ü" });
      }
    });
    transport = await Transport.connect(daemon.endpoint);
    const [version, url, version2] = await Promise.all([
      transport.ping(),
      transport.currentUrl(),
      transport.ping(),
    ]);
    assert.equal(version, "9.9.9");
    assert.equal(url, "https://example.test/ü");
    assert.equal(version2, "9.9.9");
    assert.deepEqual(
      daemon.requests.map((r) => r.method),
      ["ping", "current_url", "ping"],
    );
  });

  it("maps a daemon error reply to WayboundDaemonError and keeps the connection usable", async () => {
    daemon = await fakeDaemon((req, socket) => {
      if (req.method === "click") {
        reply(socket, {
          status: "error",
          code: "element_not_found",
          message: "element not found for query: x",
        });
      } else {
        reply(socket, { status: "pong", version: "1" });
      }
    });
    transport = await Transport.connect(daemon.endpoint);
    const err = await expectCode(
      transport.click({ role: Role.BUTTON, name: "x", exact: false, nth: 0, within: null }),
      "element_not_found",
    );
    assert.equal(err.detail, "element not found for query: x");
    assert.equal(err.message, "[element_not_found] element not found for query: x");
    assert.equal(await transport.ping(), "1");
  });

  it("closes the connection on invalid JSON and fails later calls with `closed`", async () => {
    daemon = await fakeDaemon((_req, socket) => socket.write("not json\n"));
    transport = await Transport.connect(daemon.endpoint);
    await expectCode(transport.ping(), "protocol_error");
    assert.equal(transport.closed, true);
    await expectCode(transport.ping(), "closed");
  });

  it("rejects non-object replies and unexpected payloads as protocol errors", async () => {
    daemon = await fakeDaemon((req, socket) => {
      if (req.method === "ping") {
        socket.write("[1,2]\n");
      } else {
        reply(socket, { status: "tree" });
      }
    });
    transport = await Transport.connect(daemon.endpoint);
    await expectCode(transport.ping(), "protocol_error");

    await daemon.close();
    daemon = await fakeDaemon((_req, socket) => reply(socket, { status: "tree" }));
    transport = await Transport.connect(daemon.endpoint);
    await expectCode(transport.reload(), "protocol_error");
    // A well-formed but unexpected reply does not poison the stream.
    assert.equal(transport.closed, false);
  });

  it("treats an unsolicited extra reply as a protocol error", async () => {
    daemon = await fakeDaemon((_req, socket) => {
      socket.write('{"status":"ok"}\n{"status":"ok"}\n');
    });
    transport = await Transport.connect(daemon.endpoint);
    await transport.reload();
    await sleep(20);
    assert.equal(transport.closed, true);
    await expectCode(transport.reload(), "closed");
  });

  it("times out a request, poisons the connection, and rejects queued calls", async () => {
    daemon = await fakeDaemon(() => undefined); // never replies
    transport = await Transport.connect(daemon.endpoint, { timeoutMs: 80 });
    const started = performance.now();
    const first = transport.ping();
    const queued = transport.ping();
    const err = await expectCode(first, "io_error");
    assert.match(err.detail, /timed out after 80ms/);
    assert.ok(performance.now() - started >= 70);
    await expectCode(queued, "closed");
    assert.equal(daemon.requests.length, 1, "queued request was never sent");
  });

  it("scales the client timeout for long daemon-side waits", async () => {
    daemon = await fakeDaemon((req, socket) => {
      const node = {
        id: "n",
        role: "button",
        name: "Go",
        value: null,
        bounds: { x: 1, y: 2, width: 3, height: 4 },
        focused: false,
      };
      // Reply after 250ms; the base timeout is only 100ms.
      if (req.method === "wait_for") {
        setTimeout(() => reply(socket, { status: "node", node }), 250);
      } else if (req.method === "fill") {
        setTimeout(() => reply(socket, { status: "ok" }), 250);
      } else {
        setTimeout(() => reply(socket, { status: "ok" }), 250);
      }
    });
    transport = await Transport.connect(daemon.endpoint, { timeoutMs: 100 });
    const query = { role: Role.BUTTON, name: null, exact: false, nth: 0, within: null };
    const node = await transport.waitFor(query, 200);
    assert.equal(node.id, "n");
    assert.deepEqual(node.bounds.center, [2.5, 4]);
    await transport.fill(query, "abc");
    await transport.waitForNetworkIdle(10, 300);
    assert.deepEqual(daemon.requests[0], {
      method: "wait_for",
      query: { role: "button", name: null, exact: false, nth: 0 },
      timeout_ms: 200,
    });
    assert.equal(daemon.requests[2]?.idle_ms, 50, "idle_ms is clamped to >= 50");
    // An unscaled call with the same delay still times out.
    await expectCode(transport.reload(), "io_error");
  });

  it("computes per-call timeouts like the Python SDK", () => {
    assert.equal(waitTimeoutMs(DEFAULT_TIMEOUT_MS, 10_000), 30_000);
    assert.equal(waitTimeoutMs(DEFAULT_TIMEOUT_MS, 60_000), 65_000);
    assert.equal(fillTimeoutMs(30_000, "abcd"), 31_000);
    assert.equal(fillTimeoutMs(30_000, "🚀🚀"), 30_500, "counts code points, not UTF-16 units");
  });

  it("rejects the in-flight call with `eof` when the daemon hangs up", async () => {
    daemon = await fakeDaemon((_req, socket) => socket.destroy());
    transport = await Transport.connect(daemon.endpoint);
    const first = transport.ping();
    const second = transport.ping();
    await expectCode(first, "eof");
    await expectCode(second, "closed");
  });

  it("rejects an in-flight call with `closed` when the client closes", async () => {
    daemon = await fakeDaemon(() => undefined);
    transport = await Transport.connect(daemon.endpoint);
    const pending = transport.ping();
    transport.close();
    await expectCode(pending, "closed");
  });

  it("fails to connect with io_error when nothing listens", async () => {
    const probe = await fakeDaemon(() => undefined);
    const endpoint = probe.endpoint;
    await probe.close();
    await expectCode(Transport.connect(endpoint), "io_error");
  });

  it("runs waitForResponse on a dedicated connection, concurrently with other calls", async () => {
    daemon = await fakeDaemon((req, socket, conn) => {
      if (req.method === "wait_for_response") {
        setTimeout(
          () =>
            reply(socket, {
              status: "http_response",
              response: {
                url: "https://x.test/api",
                status: 200,
                content_type: "application/json",
                body: '{"ok":true}',
              },
            }),
          50,
        );
      } else {
        assert.equal(conn, 1);
        reply(socket, { status: "ok" });
      }
    });
    transport = await Transport.connect(daemon.endpoint);
    const page = new Page(transport);
    const [response] = await Promise.all([
      page.waitForResponse("/api", { timeoutMs: 1_000 }),
      page.getByRole(Role.BUTTON, { name: "Go" }).click(),
    ]);
    assert.equal(response.status, 200);
    assert.equal(response.contentType, "application/json");
    assert.deepEqual(response.json(), { ok: true });
    assert.equal(daemon.connections, 2);
  });

  it("works over a Unix domain socket", { skip: process.platform === "win32" }, async () => {
    const dir = mkdtempSync("/tmp/wb-t-");
    try {
      daemon = await fakeDaemon(
        (_req, socket) => reply(socket, { status: "pong", version: "u" }),
        path.join(dir, "s.sock"),
      );
      transport = await Transport.connect(daemon.endpoint);
      assert.equal(await transport.ping(), "u");
    } finally {
      transport?.close();
      await daemon?.close();
      daemon = null;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("encodes page and locator calls as the protocol expects", async () => {
    daemon = await fakeDaemon((req, socket) => {
      if (req.method === "captured_responses") {
        reply(socket, { status: "http_responses", responses: [] });
      } else {
        reply(socket, { status: "ok" });
      }
    });
    transport = await Transport.connect(daemon.endpoint);
    const page = new Page(transport);
    await page.press("Enter");
    await page.press("l", { modifiers: [KeyModifier.META] });
    await page.scroll({ deltaY: -200 });
    await page.newTab();
    await page.capturedResponses({ urlContains: "api" });
    await page.capturedResponses();
    await page
      .getByRole(Role.DIALOG)
      .nth(1)
      .getByText("Ok", { exact: true })
      .selectOption({ index: 2 });
    assert.deepEqual(daemon.requests, [
      { method: "press", key: "enter", modifiers: [] },
      { method: "press", key: { char: "l" }, modifiers: ["meta"] },
      { method: "scroll", delta_x: 0, delta_y: -200 },
      { method: "new_tab", url: null },
      { method: "captured_responses", url_contains: "api" },
      { method: "captured_responses", url_contains: null },
      {
        method: "select_option",
        query: {
          role: null,
          name: "Ok",
          exact: true,
          nth: 0,
          within: { role: "dialog", name: null, exact: false, nth: 1 },
        },
        label: null,
        index: 2,
      },
    ]);
  });

  it("polls waitForUrl and raises a `timeout` error when it never matches", async () => {
    daemon = await fakeDaemon((_req, socket) =>
      reply(socket, { status: "url", url: "https://a.test/" }),
    );
    transport = await Transport.connect(daemon.endpoint);
    const page = new Page(transport);
    assert.equal(await page.waitForUrl("A.TEST"), "https://a.test/");
    await expectCode(page.waitForUrl("nope", { timeoutMs: 100 }), "timeout");
  });
  it("clamps huge waits to the daemon caps and never arms an overflowing timer", async () => {
    daemon = await fakeDaemon((req, socket) => {
      setTimeout(() => {
        if (req.method === "wait_for") {
          reply(socket, {
            status: "node",
            node: { id: "n", role: "button", bounds: { x: 0, y: 0, width: 1, height: 1 } },
          });
        } else if (req.method === "wait_for_response") {
          reply(socket, { status: "http_response", response: { url: "u", status: 204 } });
        } else {
          reply(socket, { status: "ok" });
        }
      }, 50);
    });
    // 3e9 ms is above setTimeout's 2^31-1 limit; unclamped, the timer would fire after 1 ms.
    transport = await Transport.connect(daemon.endpoint, { timeoutMs: 3_000_000_000 });
    const query = { role: Role.BUTTON, name: null, exact: false, nth: 0, within: null };
    assert.equal((await transport.waitFor(query, 3_000_000_000)).id, "n");
    assert.equal((await transport.waitForResponse("u", 2 ** 60)).status, 204);
    await transport.waitForNetworkIdle(Number.MAX_VALUE, 1e20);
    await transport.reload();
    assert.equal(transport.closed, false);
    const sent = daemon.requests;
    assert.equal(sent[0]?.timeout_ms, MAX_WAIT_MS);
    assert.equal(sent[1]?.timeout_ms, MAX_WAIT_MS);
    assert.equal(sent[2]?.idle_ms, 10_000);
    assert.equal(sent[2]?.timeout_ms, 60_000);
    assert.ok(waitTimeoutMs(MAX_TIMER_MS * 10, 1) <= MAX_TIMER_MS);
    assert.ok(fillTimeoutMs(MAX_TIMER_MS, "x".repeat(10)) <= MAX_TIMER_MS);
  });

  it("rejects negative and non-finite durations with TypeError", async () => {
    daemon = await fakeDaemon((_req, socket) => reply(socket, { status: "ok" }));
    transport = await Transport.connect(daemon.endpoint);
    const query = { role: null, name: "x", exact: false, nth: 0, within: null };
    const page = new Page(transport);
    for (const bad of [-1, Number.NaN, Number.POSITIVE_INFINITY, "5" as unknown as number]) {
      await assert.rejects(transport.waitFor(query, bad), TypeError);
      await assert.rejects(page.waitForResponse("x", { timeoutMs: bad }), TypeError);
      await assert.rejects(page.waitForNetworkIdle({ idleMs: bad }), TypeError);
      await assert.rejects(page.waitForUrl("x", { timeoutMs: bad }), TypeError);
    }
    await assert.rejects(Transport.connect(daemon.endpoint, { timeoutMs: -5 }), TypeError);
    assert.equal(daemon.requests.length, 0, "nothing was sent");
    assert.equal(transport.closed, false);
  });

  it("fetches captured responses on a dedicated connection that cannot poison the session", async () => {
    daemon = await fakeDaemon((req, socket) => {
      if (req.method === "captured_responses") {
        socket.write(
          req.url_contains === "bad"
            ? "{not json\n"
            : '{"status":"http_responses","responses":[{"url":"a","status":200}]}\n',
        );
      } else {
        reply(socket, { status: "pong", version: "1" });
      }
    });
    transport = await Transport.connect(daemon.endpoint);
    const page = new Page(transport);
    assert.equal((await page.capturedResponses())[0]?.url, "a");
    await expectCode(page.capturedResponses({ urlContains: "bad" }), "protocol_error");
    assert.equal(await transport.ping(), "1");
    assert.equal(daemon.connections, 3, "one main + one per captured_responses call");
  });

  it("arms expectResponse before the triggering action is sent", async () => {
    daemon = await fakeDaemon((req, socket) => {
      if (req.method === "wait_for_response") {
        setTimeout(
          () => reply(socket, { status: "http_response", response: { url: "x/api", status: 201 } }),
          30,
        );
      } else {
        reply(socket, { status: "ok" });
      }
    });
    transport = await Transport.connect(daemon.endpoint);
    const page = new Page(transport);
    const waiter = await page.expectResponse("/api");
    // The wait request is on the wire before the click is issued.
    await sleep(10);
    assert.deepEqual(
      daemon.requests.map((r) => r.method),
      ["wait_for_response"],
    );
    await page.getByRole(Role.BUTTON).click();
    assert.equal((await waiter.response).status, 201);
  });

  it("does not raise unhandled rejections for a waiter that is never awaited", async () => {
    daemon = await fakeDaemon((_req, socket) =>
      reply(socket, { status: "error", code: "timeout", message: "nothing" }),
    );
    transport = await Transport.connect(daemon.endpoint);
    await new Page(transport).expectResponse("/never");
    await sleep(30);
  });

  it("bounds the shutdown reply wait when asked", async () => {
    daemon = await fakeDaemon(() => undefined);
    transport = await Transport.connect(daemon.endpoint);
    const started = performance.now();
    await expectCode(transport.shutdown(100), "io_error");
    assert.ok(performance.now() - started < 2_000);
  });
});

describe("wire encoding helpers", () => {
  it("encodes named keys and single characters, rejecting anything else", () => {
    assert.equal(encodeKey("ArrOW_LEFT"), "arrow_left");
    assert.deepEqual(encodeKey("A"), { char: "A" });
    assert.deepEqual(encodeKey("🚀"), { char: "🚀" });
    assert.throws(() => encodeKey("ctrl"), RangeError);
    assert.throws(() => encodeKey(""), RangeError);
  });

  it("omits `within` when absent and nests it when present", () => {
    const parent = { role: Role.LIST, name: null, exact: false, nth: 2, within: null };
    assert.deepEqual(encodeQuery(parent), { role: "list", name: null, exact: false, nth: 2 });
    assert.deepEqual(encodeQuery({ ...parent, role: null, name: "x", within: parent }), {
      role: null,
      name: "x",
      exact: false,
      nth: 2,
      within: { role: "list", name: null, exact: false, nth: 2 },
    });
  });

  it("parses nodes leniently and rejects non-numeric bounds", () => {
    const node = parseNode({ id: 7, role: "brand_new_role", name: 3, focused: 1 });
    assert.equal(node.id, "7");
    assert.equal(node.role, Role.UNKNOWN);
    assert.equal(node.name, null);
    assert.equal(node.focused, true);
    assert.equal(node.url, null);
    assert.deepEqual(node.bounds.center, [0, 0]);
    const link = parseNode({ id: "l1", role: "link", name: "About", url: "https://example.com/a" });
    assert.equal(link.role, Role.LINK);
    assert.equal(link.url, "https://example.com/a");
    const badUrl = parseNode({ id: "l2", role: "link", url: 123 });
    assert.equal(badUrl.url, null);
    assert.throws(
      () => parseNode({ bounds: { x: "1" } }),
      (err: unknown) => err instanceof WayboundDaemonError && err.code === "protocol_error",
    );
  });

  it("filters page.links() to link nodes with non-empty URLs", async () => {
    const d = await fakeDaemon((req, sock) => {
      assert.equal(req.method, "snapshot_tree");
      reply(sock, {
        status: "tree",
        nodes: [
          {
            id: "l1",
            role: "link",
            name: "About",
            value: null,
            bounds: { x: 0, y: 0, width: 80, height: 20 },
            focused: false,
            url: "https://example.com/about",
          },
          {
            id: "l2",
            role: "link",
            name: "No URL",
            value: null,
            bounds: { x: 0, y: 20, width: 80, height: 20 },
            focused: false,
          },
          {
            id: "l3",
            role: "link",
            name: "Empty URL",
            value: null,
            bounds: { x: 0, y: 40, width: 80, height: 20 },
            focused: false,
            url: "",
          },
          {
            id: "b1",
            role: "button",
            name: "Not a link",
            value: null,
            bounds: { x: 0, y: 60, width: 80, height: 20 },
            focused: false,
            url: "https://example.com/ignored",
          },
        ],
      });
    });
    const t = await Transport.connect(d.endpoint);
    try {
      const page = new Page(t);
      const links = await page.links();
      assert.deepEqual(
        links.map((n) => [n.id, n.url]),
        [["l1", "https://example.com/about"]],
      );
    } finally {
      t.close();
      await d.close();
    }
  });

  it("parses captured responses leniently", () => {
    const r = parseHttpResponse({ url: "u", status: true, body: null });
    assert.equal(r.status, 0);
    assert.equal(r.contentType, null);
    assert.throws(() => r.json(), /has no body/);
  });

  it("validates locator indices", () => {
    const page = new Page(null as unknown as Transport);
    assert.throws(() => page.getByRole(Role.BUTTON).nth(-1), RangeError);
    assert.throws(() => page.getByRole(Role.BUTTON).nth(1.5), RangeError);
    assert.equal(page.getByRole(Role.BUTTON).nth(3).first.query.nth, 0);
  });

  it("queries network_stats and maps wire fields to camelCase NetworkStats", async () => {
    const d = await fakeDaemon((req, sock) => {
      assert.equal(req.method, "network_stats");
      reply(sock, {
        status: "network_stats",
        stats: {
          bytes_sent: 1024,
          bytes_received: 4096,
          connections_total: 7,
          connections_blocked: 2,
        },
      });
    });
    const t = await Transport.connect(d.endpoint);
    try {
      const page = new Page(t);
      assert.deepEqual(await page.networkStats(), {
        bytesSent: 1024,
        bytesReceived: 4096,
        connectionsTotal: 7,
        connectionsBlocked: 2,
      });
    } finally {
      t.close();
      await d.close();
    }
  });

  it("emits repeatable --block-preset flags and rejects unknown presets", () => {
    const args = buildDaemonArgs(
      { backend: "mock", blockHosts: ["tracker.test"], blockPresets: ["analytics", " ADS "] },
      { host: "127.0.0.1", port: 9999 },
    );
    const presets: string[] = [];
    for (let i = 0; i < args.length; i += 1) {
      if (args[i] === "--block-preset") {
        presets.push(args[i + 1] ?? "");
      }
    }
    assert.deepEqual(presets, ["analytics", "ads"]);
    assert.throws(
      () =>
        buildDaemonArgs(
          { backend: "mock", blockPresets: ["analytics", "bogus"] },
          { host: "127.0.0.1", port: 9999 },
        ),
      RangeError,
    );
  });

  it("handles list_windows, new_window, close_window, and forwards window_id on scoped Page", async () => {
    const d = await fakeDaemon((req, sock) => {
      switch (req.method) {
        case "list_windows":
          reply(sock, {
            status: "windows",
            windows: [
              {
                id: 1,
                title: "Main",
                app_id: "google-chrome",
                width: 1280,
                height: 800,
                has_buffer: true,
              },
            ],
          });
          break;
        case "new_window":
          reply(sock, {
            status: "window",
            window: {
              id: 6,
              title: "Second",
              app_id: "google-chrome",
              width: 1280,
              height: 800,
              has_buffer: true,
            },
          });
          break;
        case "snapshot_tree":
        case "locate_all":
          reply(sock, { status: "tree", nodes: [], truncated: false });
          break;
        case "current_url":
          reply(sock, { status: "url", url: "https://scoped.example/" });
          break;
        default:
          reply(sock, { status: "ok" });
      }
    });
    const t = await Transport.connect(d.endpoint);
    try {
      const root = new Page(t);
      assert.equal(root.windowId, undefined);
      await assert.rejects(() => root.closeWindow(), /unscoped/);
      assert.throws(() => new Page(t, -1), RangeError);

      await root.goto("https://default.example/");
      await root.getByRole(Role.BUTTON, { name: "Go" }).click();
      assert.equal("window_id" in (d.requests[0] ?? {}), false);
      assert.equal("window_id" in (d.requests[1] ?? {}), false);

      const windows = await root.listWindows();
      assert.deepEqual(windows, [
        {
          id: 1,
          title: "Main",
          appId: "google-chrome",
          width: 1280,
          height: 800,
          hasBuffer: true,
        },
      ]);

      const scoped = await root.newPage({ url: "https://second.example/", incognito: true });
      assert.equal(scoped.windowId, 6);
      assert.deepEqual(d.requests.at(-1), {
        method: "new_window",
        url: "https://second.example/",
        incognito: true,
      });

      const startIdx = d.requests.length;
      await scoped.url();
      await scoped.goto("https://scoped.example/");
      await scoped.reload();
      await scoped.goBack();
      await scoped.goForward();
      await scoped.scroll({ deltaX: 1, deltaY: -2 });
      await scoped.press("enter");
      await scoped.snapshotTree();
      await scoped
        .getByRole(Role.GROUP, { name: "Card" })
        .getByRole(Role.BUTTON, { name: "Buy" })
        .first.click();
      await scoped.getByText("Hello").hover();
      await scoped.getByRole(Role.TEXTBOX, { name: "Q" }).fill("abc");

      const scopedRequests = d.requests.slice(startIdx);
      assert.ok(scopedRequests.length >= 11);
      for (const req of scopedRequests) {
        assert.equal(req.window_id, 6, `missing window_id on ${String(req.method)}`);
      }

      await scoped.closeWindow();
      assert.deepEqual(d.requests.at(-1), { method: "close_window", window_id: 6 });
    } finally {
      t.close();
      await d.close();
    }
  });

  it("reports browserAlive from pingHealth() and preserves ping() string return", async () => {
    const d = await fakeDaemon((_req, sock) => {
      reply(sock, { status: "pong", version: "0.6.0", browser_alive: false });
    });
    const t = await Transport.connect(d.endpoint);
    try {
      assert.deepEqual(await t.pingHealth(), { version: "0.6.0", browserAlive: false });
      assert.equal(await t.ping(), "0.6.0");
    } finally {
      t.close();
      await d.close();
    }
  });

  it("omits trailing undefined windowId args on unscoped Page/Locator and prevents windowId override on snapshotTree", async () => {
    const argLengths: Record<string, number> = {};
    const snapshotOpts: unknown[] = [];
    const stubTransport = {
      currentUrl(...args: unknown[]) {
        argLengths.currentUrl = args.length;
        return Promise.resolve(null);
      },
      navigate(...args: unknown[]) {
        argLengths.navigate = args.length;
        return Promise.resolve();
      },
      click(...args: unknown[]) {
        argLengths.click = args.length;
        return Promise.resolve();
      },
      snapshotTreeWithMeta(opts: unknown) {
        snapshotOpts.push(opts);
        return Promise.resolve({ nodes: [], truncated: false });
      },
    } as unknown as Transport;

    const unscoped = new Page(stubTransport);
    await unscoped.url();
    await unscoped.goto("https://example.com/");
    await unscoped.getByRole(Role.BUTTON, { name: "Go" }).click();
    assert.deepEqual(argLengths, { currentUrl: 0, navigate: 1, click: 1 });

    const scoped = new Page(stubTransport, 7);
    await scoped.snapshotTree({
      maxNodes: 50,
      ...({ windowId: 99 } as Record<string, unknown>),
    });
    assert.deepEqual(snapshotOpts, [{ maxNodes: 50, windowId: 7 }]);
  });

  it("exports SessionFingerprint via Transport.exportFingerprint() and Page.exportFingerprint()", async () => {
    const wireFp = {
      tls: {
        tls_version: 0x0303,
        cipher_suites: [0x1301, 0x1302],
        extensions: [0x0000, 0x0010],
        supported_groups: [0x001d, 0x0017],
        ec_point_formats: [0],
        signature_algorithms: [0x0403, 0x0804],
        alpn_protocols: ["h2", "http/1.1"],
        supported_versions: [0x0304, 0x0303],
        cert_compression_algorithms: [2],
        alps_protocols: ["h2"],
        alps_use_new_codepoint: true,
        psk_key_exchange_modes: [1],
        grease_present: true,
        has_status_request: true,
        has_signed_cert_timestamp: true,
        has_session_ticket: true,
        has_extended_master_secret: true,
        has_renegotiation_info: true,
        has_ech: false,
        ja3_string: "771,4865-4866,0-16,29-23,0",
        ja3_hash: "deadbeef",
        ja4: "t13d1516h2_abc_def",
      },
      http2: {
        settings: [
          { id: 1, value: 65536 },
          { id: 4, value: 6291456 },
        ],
        initial_window_update: 15663105,
        pseudo_header_order: [":method", ":authority", ":scheme", ":path"],
        headers_priority: { dependency_id: 0, weight: 255, exclusive: true },
        akamai_fingerprint: "1:65536;4:6291456|15663105|0|m,a,s,p",
      },
      default_headers: [{ name: "user-agent", value: "Chrome/140.0" }],
      api_headers: [{ name: "sec-fetch-mode", value: "cors" }],
      cookies: [
        {
          name: "sid",
          value: "xyz",
          domain: ".example.test",
          path: "/",
          secure: true,
          http_only: true,
        },
      ],
    };

    const d = await fakeDaemon((req, sock) => {
      assert.equal(req.method, "export_session_fingerprint");
      reply(sock, { status: "session_fingerprint", fingerprint: wireFp });
    });
    const t = await Transport.connect(d.endpoint);
    try {
      const fromTransport = await t.exportFingerprint();
      const fromPage = await new Page(t).exportFingerprint();
      assert.deepEqual(fromPage, fromTransport);
      assert.equal(fromPage.tls?.tlsVersion, 0x0303);
      assert.deepEqual(fromPage.tls?.alpnProtocols, ["h2", "http/1.1"]);
      assert.equal(fromPage.tls?.alpsUseNewCodepoint, true);
      assert.equal(fromPage.http2?.initialWindowUpdate, 15663105);
      assert.deepEqual(fromPage.http2?.headersPriority, {
        dependencyId: 0,
        weight: 255,
        exclusive: true,
      });
      assert.deepEqual(fromPage.defaultHeaders, [{ name: "user-agent", value: "Chrome/140.0" }]);
      assert.deepEqual(fromPage.apiHeaders, [{ name: "sec-fetch-mode", value: "cors" }]);
      assert.deepEqual(fromPage.cookies, [
        {
          name: "sid",
          value: "xyz",
          domain: ".example.test",
          path: "/",
          secure: true,
          httpOnly: true,
        },
      ]);
    } finally {
      t.close();
      await d.close();
    }

    const badDaemon = await fakeDaemon((_req, sock) => {
      reply(sock, { status: "ok" });
    });
    const badTransport = await Transport.connect(badDaemon.endpoint);
    try {
      await expectCode(badTransport.exportFingerprint(), "protocol_error");
    } finally {
      badTransport.close();
      await badDaemon.close();
    }
  });
});

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { after, afterEach, before, describe, it } from "node:test";
import { setTimeout as sleep } from "node:timers/promises";
import { Page } from "../src/client.js";
import { WayboundDaemonError } from "../src/errors.js";
import {
  DEFAULT_TIMEOUT_MS,
  type Endpoint,
  encodeKey,
  encodeQuery,
  fillTimeoutMs,
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
    assert.deepEqual(node.bounds.center, [0, 0]);
    assert.throws(
      () => parseNode({ bounds: { x: "1" } }),
      (err: unknown) => err instanceof WayboundDaemonError && err.code === "protocol_error",
    );
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
});

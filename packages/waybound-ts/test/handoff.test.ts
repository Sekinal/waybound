import assert from "node:assert/strict";
import { execFile, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, describe, it } from "node:test";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { _liveReplayWorkerCount, encodeMultipart, prepareRequestPayload } from "../src/handoff.js";
import {
  HandoffHttpClient,
  HandoffResponse,
  launch,
  Page,
  parseSessionFingerprint,
  type SessionFingerprint,
  serializeSessionFingerprint,
  Transport,
  WayboundDaemonError,
} from "../src/index.js";

const REPO_ROOT = fileURLToPath(new URL("../../../../", import.meta.url));
const BIN_NAME = process.platform === "win32" ? "waybound-daemon.exe" : "waybound-daemon";

function resolveReplayDaemonBinary(): string | null {
  const candidates = [
    process.env.WAYBOUND_DAEMON_BIN,
    path.join(REPO_ROOT, "target", "debug", BIN_NAME),
    path.join(REPO_ROOT, "target", "release", BIN_NAME),
    path.resolve(REPO_ROOT, "..", "waybound", "target", "debug", BIN_NAME),
    path.resolve(REPO_ROOT, "..", "waybound", "target", "release", BIN_NAME),
  ];
  for (const candidate of candidates) {
    if (!candidate || !existsSync(candidate)) {
      continue;
    }
    const probe = spawnSync(candidate, ["--replay"], {
      input: '{"method":"shutdown"}\n',
      encoding: "utf8",
      timeout: 5_000,
    });
    if (probe.status === 0 && probe.stdout.includes('"status":"ok"')) {
      return candidate;
    }
  }
  return null;
}

const REPLAY_DAEMON_BIN = resolveReplayDaemonBinary();

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

async function assertGone(pid: number | undefined): Promise<void> {
  assert.ok(pid !== undefined, "expected child pid");
  for (let i = 0; i < 100 && isAlive(pid); i += 1) {
    await sleep(20);
  }
  assert.equal(isAlive(pid), false, `replay worker pid ${pid} is still running`);
}

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

function emptyFingerprint(): SessionFingerprint {
  return {
    tls: null,
    http2: null,
    defaultHeaders: [],
    apiHeaders: [],
    cookies: [],
  };
}

function fullFingerprint(): SessionFingerprint {
  return {
    tls: {
      tlsVersion: 0x0303,
      cipherSuites: [0x1301, 0x1302, 0x1303, 0xc02b],
      extensions: [0x0000, 0x0010, 0x002b],
      supportedGroups: [0x11ec, 0x001d, 0x0017],
      ecPointFormats: [0],
      signatureAlgorithms: [0x0403, 0x0804, 0x0401],
      alpnProtocols: ["h2", "http/1.1"],
      supportedVersions: [0x0304, 0x0303],
      certCompressionAlgorithms: [2],
      alpsProtocols: ["h2"],
      alpsUseNewCodepoint: true,
      pskKeyExchangeModes: [1],
      greasePresent: true,
      hasStatusRequest: true,
      hasSignedCertTimestamp: true,
      hasSessionTicket: true,
      hasExtendedMasterSecret: true,
      hasRenegotiationInfo: true,
      hasEch: true,
      ja3String: "771,4865-4866,0-16-43,4588-29-23,0",
      ja3Hash: "0123456789abcdef0123456789abcdef",
      ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
    },
    http2: {
      settings: [
        { id: 1, value: 65536 },
        { id: 2, value: 0 },
        { id: 4, value: 6291456 },
        { id: 6, value: 262144 },
      ],
      initialWindowUpdate: 15663105,
      pseudoHeaderOrder: [":method", ":authority", ":scheme", ":path"],
      headersPriority: { dependencyId: 0, weight: 255, exclusive: true },
      akamaiFingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    },
    defaultHeaders: [
      { name: "user-agent", value: "WayboundTest/1.0" },
      { name: "accept-language", value: "en-US,en;q=0.9" },
    ],
    apiHeaders: [
      { name: "sec-fetch-mode", value: "cors" },
      { name: "sec-fetch-dest", value: "empty" },
    ],
    cookies: [
      {
        name: "session",
        value: "abc123",
        domain: ".example.test",
        path: "/",
        secure: true,
        httpOnly: true,
      },
    ],
  };
}

/** Write an executable fake `waybound-daemon --replay` script backed by Node. */
function makeFakeWorker(dir: string, name: string, scriptBody: string): string {
  const jsPath = path.join(dir, `${name}.mjs`);
  writeFileSync(jsPath, scriptBody, "utf8");
  const shPath = path.join(dir, `${name}.sh`);
  writeFileSync(shPath, `#!/bin/sh\nexec "${process.execPath}" "${jsPath}" "$@"\n`, "utf8");
  chmodSync(shPath, 0o755);
  return shPath;
}

describe("SessionFingerprint serialization and HandoffResponse helpers", () => {
  it("round-trips full SessionFingerprint through Rust snake_case wire format", () => {
    const fp = fullFingerprint();
    const wire = serializeSessionFingerprint(fp);

    assert.ok(wire.tls !== null && typeof wire.tls === "object");
    assert.equal((wire.tls as Record<string, unknown>).tls_version, 0x0303);
    assert.equal((wire.tls as Record<string, unknown>).alps_use_new_codepoint, true);
    assert.equal(
      (wire.tls as Record<string, unknown>).ja3_hash,
      "0123456789abcdef0123456789abcdef",
    );

    assert.ok(wire.http2 !== null && typeof wire.http2 === "object");
    assert.equal((wire.http2 as Record<string, unknown>).initial_window_update, 15663105);
    assert.deepEqual((wire.http2 as Record<string, unknown>).headers_priority, {
      dependency_id: 0,
      weight: 255,
      exclusive: true,
    });
    assert.deepEqual(wire.cookies, [
      {
        name: "session",
        value: "abc123",
        domain: ".example.test",
        path: "/",
        secure: true,
        http_only: true,
      },
    ]);

    const reparsed = parseSessionFingerprint(JSON.parse(JSON.stringify(wire)));
    assert.deepEqual(reparsed, fp);

    // Also accepts TS camelCase JSON directly.
    const fromCamel = parseSessionFingerprint(JSON.parse(JSON.stringify(fp)));
    assert.deepEqual(fromCamel, fp);
  });

  it("parses empty / null fingerprints and rejects non-object inputs", () => {
    const parsed = parseSessionFingerprint({
      tls: null,
      http2: null,
      default_headers: [],
      cookies: [],
    });
    assert.deepEqual(parsed, emptyFingerprint());

    for (const bad of [null, undefined, "str", 42, true, []]) {
      assert.throws(() => parseSessionFingerprint(bad), TypeError);
    }
  });

  it("exposes text, json, case-insensitive header lookup, and raw binary content on HandoffResponse", () => {
    const raw = Buffer.from([0x00, 0xfe, 0xff, 0x41]);
    const binResp = new HandoffResponse(
      "https://example.test/bin",
      200,
      [
        ["Content-Type", "application/octet-stream"],
        ["X-Multi", "first"],
        ["x-multi", "second"],
      ],
      "decoded-text",
      raw,
    );
    assert.equal(binResp.text, "decoded-text");
    assert.deepEqual(binResp.content, raw);
    assert.equal(binResp.header("content-type"), "application/octet-stream");
    assert.equal(binResp.header("X-MULTI"), "first");
    assert.equal(binResp.header("x-missing"), undefined);

    const jsonResp = new HandoffResponse(
      "https://example.test/json",
      201,
      [["content-type", "application/json"]],
      '{"ok":true,"n":42}',
    );
    assert.deepEqual(jsonResp.json<{ ok: boolean; n: number }>(), { ok: true, n: 42 });
    assert.deepEqual(jsonResp.content, Buffer.from('{"ok":true,"n":42}', "utf8"));
  });

  it("encodes JSON, urlencoded form, raw body, and multipart payloads and enforces mutual exclusion", () => {
    const jsonPrep = prepareRequestPayload({ jsonBody: { a: 1, b: "two" } });
    assert.equal(jsonPrep.body, '{"a":1,"b":"two"}');
    assert.deepEqual(jsonPrep.headers, [["content-type", "application/json"]]);

    // Caller-supplied Content-Type (any casing) is preserved.
    const customJson = prepareRequestPayload({
      headers: { "Content-Type": "application/vnd.api+json" },
      jsonBody: { x: true },
    });
    assert.deepEqual(customJson.headers, [["Content-Type", "application/vnd.api+json"]]);

    const formPrep = prepareRequestPayload({ data: { q: "hello world", tag: "a&b" } });
    assert.equal(formPrep.body, "q=hello+world&tag=a%26b");
    assert.deepEqual(formPrep.headers, [["content-type", "application/x-www-form-urlencoded"]]);

    const binBytes = new Uint8Array([1, 2, 3, 255]);
    const binPrep = prepareRequestPayload({ body: binBytes });
    assert.equal(binPrep.body, binBytes);
    assert.deepEqual(binPrep.headers, []);

    // Mutual exclusion checks.
    assert.throws(
      () => prepareRequestPayload({ body: "hi", jsonBody: { a: 1 } }),
      /specify at most one/,
    );
    assert.throws(
      () => prepareRequestPayload({ body: "hi", data: { a: "1" } }),
      /specify at most one/,
    );
    assert.throws(
      () => prepareRequestPayload({ body: binBytes, files: { f: binBytes } }),
      /specify at most one/,
    );
    assert.throws(
      () => prepareRequestPayload({ jsonBody: { a: 1 }, data: { a: "1" } }),
      /specify at most one/,
    );
    assert.throws(
      () => prepareRequestPayload({ jsonBody: { a: 1 }, files: { f: binBytes } }),
      /specify at most one/,
    );
    assert.throws(
      () => prepareRequestPayload({ jsonBody: () => undefined }),
      /not JSON-serializable/,
    );
  });

  it("sanitizes CRLF/quotes in multipart fields & filenames and rejects header injection", () => {
    const { body, contentType } = encodeMultipart(
      { 'field"\r\nX-Injected: yes': "val" },
      {
        raw: new Uint8Array([0x01, 0x02]),
        twoTuple: ["two.bin", new Uint8Array([0x03])],
        doc: [
          'evil"\r\n\\name.txt',
          new Uint8Array([0x41, 0x42]),
          "text/plain\r\nX-Evil: injected",
        ],
      },
    );
    assert.match(contentType, /^multipart\/form-data; boundary=----WayboundBoundary[0-9a-f]{32}$/);
    const text = body.toString("latin1");
    assert.ok(text.includes('name="field\\"X-Injected: yes"'));
    assert.ok(
      text.includes('name="raw"; filename="raw"\r\nContent-Type: application/octet-stream'),
    );
    assert.ok(
      text.includes(
        'name="twoTuple"; filename="two.bin"\r\nContent-Type: application/octet-stream',
      ),
    );
    assert.ok(text.includes('filename="evil\\"\\\\name.txt"'));
    assert.ok(text.includes("Content-Type: text/plainX-Evil: injected\r\n\r\n"));
    assert.equal(text.includes("\r\nX-Evil:"), false);
    assert.equal(text.includes("\r\nX-Injected:"), false);

    assert.throws(
      () => prepareRequestPayload({ headers: { "X-Ok": "bad\r\nInjected: 1" } }),
      TypeError,
    );
    assert.throws(() => prepareRequestPayload({ headers: { "X-Bad\nName": "ok" } }), TypeError);
    assert.throws(() => prepareRequestPayload({ headers: [["", "val"]] }), TypeError);
  });
});

describe("HandoffHttpClient against scripted fake replay worker", {
  skip: process.platform === "win32",
}, () => {
  const dir = mkdtempSync(path.join(tmpdir(), "wb-handoff-"));
  after(() => {
    rmSync(dir, { recursive: true, force: true });
    assert.equal(_liveReplayWorkerCount(), 0, "no leaked replay workers");
  });

  it("forwards init options, handles all HTTP verbs, binary bodies, cookies, and updateFingerprint", async () => {
    const logPath = path.join(dir, "echo.log");
    const worker = makeFakeWorker(
      dir,
      "echo-worker",
      `
import fs from "node:fs";
import readline from "node:readline";
const logPath = ${JSON.stringify(logPath)};
let activeFp = null;
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  if (!line.trim()) return;
  const req = JSON.parse(line);
  fs.appendFileSync(logPath, JSON.stringify(req) + "\\n");
  if (req.method === "init") {
    activeFp = req.fingerprint;
    process.stdout.write(JSON.stringify({ status: "ok" }) + "\\n");
  } else if (req.method === "request") {
    const respBytes = req.body_base64
      ? Buffer.from(req.body_base64, "base64")
      : Buffer.from(JSON.stringify({
          http_method: req.http_method,
          url: req.url,
          headers: req.headers,
          body: req.body ?? null,
          ua: activeFp?.default_headers?.[0]?.value ?? null,
        }));
    process.stdout.write(JSON.stringify({
      status: "response",
      response: {
        url: req.url,
        status: 200,
        headers: [["Content-Type", req.body_base64 ? "application/octet-stream" : "application/json"]],
        body_base64: respBytes.toString("base64"),
        body: req.body_base64 ? respBytes.toString("latin1") : respBytes.toString("utf8"),
      },
    }) + "\\n");
  } else if (req.method === "cookies") {
    process.stdout.write(JSON.stringify({
      status: "cookies",
      cookies: [
        { name: "ck1", value: "v1", domain: "example.test", path: "/app", secure: true, http_only: true },
        { name: "ck2", value: "v2", domain: "example.test" },
      ],
    }) + "\\n");
  } else if (req.method === "shutdown") {
    process.stdout.write(JSON.stringify({ status: "ok" }) + "\\n");
    process.exit(0);
  }
});
`,
    );

    const fp1: SessionFingerprint = {
      ...emptyFingerprint(),
      defaultHeaders: [{ name: "user-agent", value: "UA-One" }],
    };

    const client = await HandoffHttpClient.fromJson(
      JSON.stringify(serializeSessionFingerprint(fp1)),
      {
        daemonBinary: worker,
        proxy: "http://proxy.local:8080",
        timeoutMs: 12_345,
        followRedirects: false,
        http3: true,
      },
    );
    const pid = client.pid;
    assert.equal(_liveReplayWorkerCount(), 1);
    assert.deepEqual(client.fingerprint, fp1);

    try {
      const g = await client.get("https://example.test/g", { headers: { "X-A": "1" } });
      assert.equal(g.status, 200);
      assert.deepEqual(g.json(), {
        http_method: "GET",
        url: "https://example.test/g",
        headers: [["X-A", "1"]],
        body: null,
        ua: "UA-One",
      });

      const h = await client.head("https://example.test/h");
      assert.equal((h.json() as Record<string, unknown>).http_method, "HEAD");

      const p = await client.post("https://example.test/p", { jsonBody: { k: "v" } });
      assert.deepEqual(p.json(), {
        http_method: "POST",
        url: "https://example.test/p",
        headers: [["content-type", "application/json"]],
        body: '{"k":"v"}',
        ua: "UA-One",
      });

      const pu = await client.put("https://example.test/pu", { body: "raw-put" });
      assert.equal((pu.json() as Record<string, unknown>).http_method, "PUT");
      assert.equal((pu.json() as Record<string, unknown>).body, "raw-put");

      const pa = await client.patch("https://example.test/pa", { data: { a: "1" } });
      assert.equal((pa.json() as Record<string, unknown>).http_method, "PATCH");
      assert.equal((pa.json() as Record<string, unknown>).body, "a=1");

      const d = await client.delete("https://example.test/d");
      assert.equal((d.json() as Record<string, unknown>).http_method, "DELETE");

      // Binary body_base64 round-trip across all 256 byte values.
      const allBytes = Uint8Array.from({ length: 256 }, (_, i) => i);
      const binResp = await client.post("https://example.test/bin", { body: allBytes });
      assert.equal(binResp.header("content-type"), "application/octet-stream");
      assert.deepEqual(binResp.content, Buffer.from(allBytes));

      const cookies = await client.cookies();
      assert.deepEqual(cookies, [
        {
          name: "ck1",
          value: "v1",
          domain: "example.test",
          path: "/app",
          secure: true,
          httpOnly: true,
        },
        {
          name: "ck2",
          value: "v2",
          domain: "example.test",
          path: "/",
          secure: false,
          httpOnly: false,
        },
      ]);

      // Hot-swap fingerprint without restarting worker.
      const fp2: SessionFingerprint = {
        ...emptyFingerprint(),
        defaultHeaders: [{ name: "user-agent", value: "UA-Two" }],
      };
      await client.updateFingerprint(fp2);
      assert.deepEqual(client.fingerprint, fp2);
      assert.equal(client.pid, pid);

      const afterSwap = await client.get("https://example.test/after");
      assert.equal((afterSwap.json() as Record<string, unknown>).ua, "UA-Two");
    } finally {
      await Promise.all([client.close(), client.close()]);
      await client.close();
    }
    await assertGone(pid);
    assert.equal(client.closed, true);
    await expectCode(client.get("https://example.test/closed"), "closed");

    const logged = readFileSync(logPath, "utf8")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as Record<string, unknown>);
    assert.deepEqual(logged[0]?.options, {
      proxy: "http://proxy.local:8080",
      timeout_ms: 12_345,
      follow_redirects: false,
      http3: true,
    });
    assert.equal(logged.at(-1)?.method, "shutdown");
  });

  it("triggers onRefresh once on configured refreshStatuses and never loops infinitely", async () => {
    const worker = makeFakeWorker(
      dir,
      "refresh-worker",
      `
import readline from "node:readline";
let token = "stale";
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  if (!line.trim()) return;
  const req = JSON.parse(line);
  if (req.method === "init") {
    const ck = req.fingerprint.cookies?.[0];
    token = ck ? ck.value : "none";
    process.stdout.write('{"status":"ok"}\\n');
  } else if (req.method === "request") {
    let status = 200;
    if (req.url.endsWith("/protected") && token !== "fresh") status = 403;
    if (req.url.endsWith("/always-403")) status = 403;
    if (req.url.endsWith("/rate-limited") && token !== "fresh2") status = 429;
    const body = JSON.stringify({ token, status });
    process.stdout.write(JSON.stringify({
      status: "response",
      response: { url: req.url, status, headers: [], body_base64: Buffer.from(body).toString("base64"), body },
    }) + "\\n");
  } else if (req.method === "shutdown") {
    process.stdout.write('{"status":"ok"}\\n');
    process.exit(0);
  }
});
`,
    );

    let refreshCalls = 0;
    const staleFp: SessionFingerprint = {
      ...emptyFingerprint(),
      cookies: [
        {
          name: "token",
          value: "stale",
          domain: "example.test",
          path: "/",
          secure: false,
          httpOnly: false,
        },
      ],
    };

    await using client = await HandoffHttpClient.create(staleFp, {
      daemonBinary: worker,
      refreshStatuses: [403, 429],
      onRefresh: async () => {
        refreshCalls += 1;
        await sleep(5);
        return {
          ...emptyFingerprint(),
          cookies: [
            {
              name: "token",
              value: refreshCalls === 1 ? "fresh" : "fresh2",
              domain: "example.test",
              path: "/",
              secure: false,
              httpOnly: false,
            },
          ],
        };
      },
    });

    // 200 does NOT trigger refresh.
    const ok = await client.get("https://example.test/ok");
    assert.equal(ok.status, 200);
    assert.equal(refreshCalls, 0);

    // 403 triggers refresh ONCE and succeeds on retry.
    const protectedResp = await client.get("https://example.test/protected");
    assert.equal(protectedResp.status, 200);
    assert.equal((protectedResp.json() as Record<string, unknown>).token, "fresh");
    assert.equal(refreshCalls, 1);

    // Custom refresh status (429) triggers refresh ONCE.
    const rlResp = await client.get("https://example.test/rate-limited");
    assert.equal(rlResp.status, 200);
    assert.equal((rlResp.json() as Record<string, unknown>).token, "fresh2");
    assert.equal(refreshCalls, 2);

    // If retry ALSO returns 403, stops after ONE retry (no infinite loop).
    const still403 = await client.get("https://example.test/always-403");
    assert.equal(still403.status, 403);
    assert.equal(refreshCalls, 3);
  });

  it("serializes concurrent requests in FIFO order across fragmented stdout chunks", async () => {
    const worker = makeFakeWorker(
      dir,
      "fifo-worker",
      `
import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  if (!line.trim()) return;
  const req = JSON.parse(line);
  if (req.method === "init") {
    process.stdout.write('{"status":"ok"}\\n');
  } else if (req.method === "request") {
    const reply = JSON.stringify({
      status: "response",
      response: { url: req.url, status: 200, headers: [], body: req.url, body_base64: Buffer.from(req.url).toString("base64") },
    }) + "\\n";
    // Split reply across two chunks with a tiny delay.
    setTimeout(() => process.stdout.write(reply.slice(0, 12)), 5);
    setTimeout(() => process.stdout.write(reply.slice(12)), 15);
  } else if (req.method === "shutdown") {
    process.stdout.write('{"status":"ok"}\\n');
    process.exit(0);
  }
});
`,
    );

    await using client = await HandoffHttpClient.create(emptyFingerprint(), {
      daemonBinary: worker,
    });
    const responses = await Promise.all([
      client.get("https://example.test/1"),
      client.get("https://example.test/2"),
      client.get("https://example.test/3"),
    ]);
    assert.deepEqual(
      responses.map((r) => r.body),
      ["https://example.test/1", "https://example.test/2", "https://example.test/3"],
    );
  });

  it("rejects in-flight and queued calls with stderr detail on worker crash", async () => {
    const worker = makeFakeWorker(
      dir,
      "crash-worker",
      `
import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  if (!line.trim()) return;
  const req = JSON.parse(line);
  if (req.method === "init") {
    process.stdout.write('{"status":"ok"}\\n');
  } else if (req.method === "request") {
    process.stderr.write("fatal: simulated segfault\\n");
    process.exit(2);
  }
});
`,
    );

    const client = await HandoffHttpClient.create(emptyFingerprint(), { daemonBinary: worker });
    const first = client.get("https://example.test/boom");
    const second = client.get("https://example.test/queued");
    const err = await expectCode(first, "eof");
    assert.match(err.detail, /simulated segfault/);
    await expectCode(second, "closed");
    await expectCode(client.cookies(), "closed");
    await client.close();
    await assertGone(client.pid);
  });

  it("rejects malformed JSON with protocol_error and kills the worker", async () => {
    const worker = makeFakeWorker(
      dir,
      "badjson-worker",
      `
import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  if (!line.trim()) return;
  const req = JSON.parse(line);
  if (req.method === "init") {
    process.stdout.write('{"status":"ok"}\\n');
  } else {
    process.stdout.write('{not valid json\\n');
  }
});
`,
    );

    const client = await HandoffHttpClient.create(emptyFingerprint(), { daemonBinary: worker });
    const pid = client.pid;
    await expectCode(client.get("https://example.test/bad"), "protocol_error");
    assert.equal(client.closed, true);
    await expectCode(client.get("https://example.test/after"), "closed");
    await client.close();
    await assertGone(pid);
  });

  it("kills worker cleanly when init fails so zero processes leak", async () => {
    const pidFile = path.join(dir, "init-fail.pid");
    const worker = makeFakeWorker(
      dir,
      "init-fail-worker",
      `
import fs from "node:fs";
import readline from "node:readline";
fs.writeFileSync(${JSON.stringify(pidFile)}, String(process.pid));
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  if (!line.trim()) return;
  const req = JSON.parse(line);
  if (req.method === "init") {
    process.stdout.write(JSON.stringify({ status: "error", code: "init_failed", message: "bad proxy" }) + "\\n");
  } else if (req.method === "shutdown") {
    process.stdout.write('{"status":"ok"}\\n');
    process.exit(0);
  }
});
`,
    );

    const err = await expectCode(
      HandoffHttpClient.create(emptyFingerprint(), { daemonBinary: worker }),
      "init_failed",
    );
    assert.match(err.detail, /bad proxy/);
    const childPid = Number(readFileSync(pidFile, "utf8").trim());
    await assertGone(childPid);
    assert.equal(_liveReplayWorkerCount(), 0);
  });

  it("escalates SIGTERM -> SIGKILL when a hung worker ignores shutdown and SIGTERM", async () => {
    const logPath = path.join(dir, "hang.log");
    const worker = makeFakeWorker(
      dir,
      "hang-worker",
      `
import fs from "node:fs";
import readline from "node:readline";
const logPath = ${JSON.stringify(logPath)};
setInterval(() => {}, 1000);
process.on("SIGTERM", () => {
  fs.appendFileSync(logPath, "SIGTERM\\n");
});
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  if (!line.trim()) return;
  const req = JSON.parse(line);
  fs.appendFileSync(logPath, req.method + "\\n");
  if (req.method === "init") {
    process.stdout.write('{"status":"ok"}\\n');
  }
  // Ignore shutdown and stay alive until SIGKILL.
});
`,
    );

    const client = await HandoffHttpClient.create(emptyFingerprint(), { daemonBinary: worker });
    const pid = client.pid;
    await client.close();
    await assertGone(pid);
    assert.equal(_liveReplayWorkerCount(), 0);
    assert.match(readFileSync(logPath, "utf8"), /shutdown\nSIGTERM/);
  });

  it("does not keep the event loop alive and leaves no orphan when close() is forgotten", async () => {
    const worker = makeFakeWorker(
      dir,
      "orphan-worker",
      `
import readline from "node:readline";
setInterval(() => {}, 1000);
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  if (!line.trim()) return;
  const req = JSON.parse(line);
  if (req.method === "init") {
    process.stdout.write('{"status":"ok"}\\n');
  } else if (req.method === "cookies") {
    process.stdout.write('{"status":"cookies","cookies":[]}\\n');
  }
});
`,
    );
    const indexUrl = new URL("../src/index.js", import.meta.url).href;
    const script = `
      import { HandoffHttpClient } from ${JSON.stringify(indexUrl)};
      const client = await HandoffHttpClient.create(
        { tls: null, http2: null, defaultHeaders: [], apiHeaders: [], cookies: [] },
        { daemonBinary: ${JSON.stringify(worker)} },
      );
      await client.cookies();
      process.stdout.write(String(client.pid));
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
    await assertGone(Number(stdout.trim()));
  });

  it("wires Page.handoffHttpClient() and keeps working after browser transport closes", async () => {
    const worker = makeFakeWorker(
      dir,
      "page-handoff-worker",
      `
import readline from "node:readline";
let ua = "";
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  if (!line.trim()) return;
  const req = JSON.parse(line);
  if (req.method === "init") {
    ua = req.fingerprint.default_headers?.[0]?.value ?? "";
    process.stdout.write('{"status":"ok"}\\n');
  } else if (req.method === "request") {
    const body = JSON.stringify({ ua });
    process.stdout.write(JSON.stringify({
      status: "response",
      response: { url: req.url, status: 200, headers: [], body, body_base64: Buffer.from(body).toString("base64") },
    }) + "\\n");
  } else if (req.method === "shutdown") {
    process.stdout.write('{"status":"ok"}\\n');
    process.exit(0);
  }
});
`,
    );

    const server = net.createServer((socket) => {
      let buf = "";
      socket.on("data", (chunk) => {
        buf += chunk.toString("utf8");
        for (let idx = buf.indexOf("\n"); idx !== -1; idx = buf.indexOf("\n")) {
          const req = JSON.parse(buf.slice(0, idx)) as Record<string, unknown>;
          buf = buf.slice(idx + 1);
          if (req.method === "export_session_fingerprint") {
            socket.write(
              `${JSON.stringify({
                status: "session_fingerprint",
                fingerprint: {
                  tls: null,
                  http2: null,
                  default_headers: [{ name: "user-agent", value: "ExportedFromPage/1.0" }],
                  api_headers: [],
                  cookies: [],
                },
              })}\n`,
            );
          }
        }
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as net.AddressInfo).port;
    const transport = await Transport.connect({ host: "127.0.0.1", port });
    try {
      const page = new Page(transport);
      await using client = await page.handoffHttpClient({ daemonBinary: worker });
      // Close browser transport completely — HandoffHttpClient stays operational!
      transport.close();
      const resp = await client.get("https://example.test/after-close");
      assert.deepEqual(resp.json(), { ua: "ExportedFromPage/1.0" });
    } finally {
      transport.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("coalesces concurrent 403s into a single onRefresh invocation and preserves refreshed cookies", async () => {
    const worker = makeFakeWorker(
      dir,
      "single-flight-refresh-worker",
      `
import readline from "node:readline";
let token = "stale";
let initCount = 0;
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  if (!line.trim()) return;
  const req = JSON.parse(line);
  if (req.method === "init") {
    initCount += 1;
    token = req.fingerprint.cookies?.[0]?.value ?? "stale";
    process.stdout.write('{"status":"ok"}\\n');
  } else if (req.method === "request") {
    const status = token === "fresh" ? 200 : 403;
    const body = JSON.stringify({ token, initCount, url: req.url });
    process.stdout.write(JSON.stringify({
      status: "response",
      response: { url: req.url, status, headers: [], body, body_base64: Buffer.from(body).toString("base64") },
    }) + "\\n");
  } else if (req.method === "shutdown") {
    process.stdout.write('{"status":"ok"}\\n');
    process.exit(0);
  }
});
`,
    );

    let refreshCount = 0;
    const staleFp: SessionFingerprint = {
      tls: null,
      http2: null,
      defaultHeaders: [],
      apiHeaders: [],
      cookies: [
        {
          name: "tok",
          value: "stale",
          domain: "example.test",
          path: "/",
          secure: true,
          httpOnly: true,
        },
      ],
    };
    const client = await HandoffHttpClient.create(staleFp, {
      daemonBinary: worker,
      onRefresh: async () => {
        refreshCount += 1;
        await new Promise((r) => setTimeout(r, 40));
        return {
          ...staleFp,
          cookies: [
            {
              name: "tok",
              value: "fresh",
              domain: "example.test",
              path: "/",
              secure: true,
              httpOnly: true,
            },
          ],
        };
      },
    });
    try {
      const [r1, r2, r3] = await Promise.all([
        client.get("https://example.test/a"),
        client.get("https://example.test/b"),
        client.get("https://example.test/c"),
      ]);
      assert.equal(refreshCount, 1);
      assert.equal(r1.status, 200);
      assert.equal(r2.status, 200);
      assert.equal(r3.status, 200);
      assert.equal(r3.json<{ initCount: number }>().initCount, 2);
    } finally {
      await client.close();
    }
  });

  it("does not leak timer or poison worker when encodeLine throws on unserializable payload", async () => {
    const worker = makeFakeWorker(
      dir,
      "encode-error-worker",
      `
import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  if (!line.trim()) return;
  const req = JSON.parse(line);
  if (req.method === "init") {
    process.stdout.write('{"status":"ok"}\\n');
  } else if (req.method === "cookies") {
    process.stdout.write('{"status":"cookies","cookies":[]}\\n');
  } else if (req.method === "shutdown") {
    process.stdout.write('{"status":"ok"}\\n');
    process.exit(0);
  }
});
`,
    );
    const client = await HandoffHttpClient.create(
      { tls: null, http2: null, defaultHeaders: [], apiHeaders: [], cookies: [] },
      { daemonBinary: worker, timeoutMs: 250 },
    );
    try {
      const badFp = {
        tls: null,
        http2: null,
        defaultHeaders: [{ name: "x", value: 1n as unknown as string }],
        apiHeaders: [],
        cookies: [],
      };
      await assert.rejects(() => client.updateFingerprint(badFp), TypeError);
      // Worker must remain healthy and not be killed by a leaked timer.
      assert.deepEqual(await client.cookies(), []);
      await assert.rejects(() => client.request("GET\r\nEvil", "https://example.test/"), TypeError);
      assert.deepEqual(await client.cookies(), []);
    } finally {
      await client.close();
    }
  });
});

describe("E2E: HandoffHttpClient against real waybound-daemon --replay", {
  skip:
    REPLAY_DAEMON_BIN === null ? "waybound-daemon built with --features replay not found" : false,
}, () => {
  it("replays headers, cookies, JSON, form, binary, multipart, HEAD, and auto-refresh over real waybound-http", async () => {
    const daemonBinary = REPLAY_DAEMON_BIN as string;
    const server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const rawBody = Buffer.concat(chunks);
        const urlPath = req.url ?? "/";

        if (req.method === "HEAD" && urlPath === "/head") {
          res.writeHead(200, { "X-Head-Ok": "yes", "Content-Length": "0" });
          res.end();
          return;
        }

        if (urlPath === "/protected") {
          const cookie = req.headers.cookie ?? "";
          if (!cookie.includes("token=fresh")) {
            const body = JSON.stringify({ error: "expired" });
            res.writeHead(403, { "Content-Type": "application/json" });
            res.end(body);
            return;
          }
        }

        if (urlPath === "/echo" || urlPath === "/protected") {
          const payload = JSON.stringify({
            method: req.method,
            path: urlPath,
            user_agent: req.headers["user-agent"] ?? null,
            cookie: req.headers.cookie ?? null,
            custom: req.headers["x-test-header"] ?? null,
          });
          res.writeHead(200, {
            "Content-Type": "application/json",
            "Set-Cookie": "server_ck=hello; Path=/",
          });
          res.end(payload);
          return;
        }

        if (urlPath === "/json") {
          const payload = JSON.stringify({
            content_type: req.headers["content-type"] ?? null,
            parsed: JSON.parse(rawBody.toString("utf8")),
          });
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(payload);
          return;
        }

        if (urlPath === "/form") {
          const payload = JSON.stringify({
            content_type: req.headers["content-type"] ?? null,
            raw: rawBody.toString("utf8"),
          });
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(payload);
          return;
        }

        if (urlPath === "/binary") {
          res.writeHead(200, {
            "Content-Type": "application/octet-stream",
            "Content-Length": String(rawBody.length),
          });
          res.end(rawBody);
          return;
        }

        if (urlPath === "/multipart") {
          const payload = JSON.stringify({
            content_type: req.headers["content-type"] ?? "",
            body_base64: rawBody.toString("base64"),
          });
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(payload);
          return;
        }

        res.writeHead(404);
        res.end();
      });
    });

    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as net.AddressInfo).port;
    const baseUrl = `http://127.0.0.1:${port}`;

    const staleFp: SessionFingerprint = {
      tls: null,
      http2: null,
      defaultHeaders: [
        { name: "user-agent", value: "WayboundTsE2E/140.0" },
        { name: "accept-language", value: "en-US,en;q=0.9" },
      ],
      apiHeaders: [],
      cookies: [
        {
          name: "token",
          value: "stale",
          domain: "127.0.0.1",
          path: "/",
          secure: false,
          httpOnly: false,
        },
      ],
    };

    let refreshCalls = 0;
    const client = await HandoffHttpClient.fromJson(
      JSON.stringify(serializeSessionFingerprint(staleFp)),
      {
        daemonBinary,
        onRefresh: () => {
          refreshCalls += 1;
          return {
            ...staleFp,
            cookies: [
              {
                name: "token",
                value: "fresh",
                domain: "127.0.0.1",
                path: "/",
                secure: false,
                httpOnly: false,
              },
            ],
          };
        },
        refreshStatuses: [403],
      },
    );
    const workerPid = client.pid;

    try {
      // 1. GET with replayed default headers + cookies + custom header.
      const echo = await client.get(`${baseUrl}/echo`, { headers: { "X-Test-Header": "ok" } });
      assert.equal(echo.status, 200);
      assert.equal(echo.header("content-type"), "application/json");
      const echoJson = echo.json<Record<string, unknown>>();
      assert.equal(echoJson.user_agent, "WayboundTsE2E/140.0");
      assert.equal(echoJson.custom, "ok");
      assert.match(String(echoJson.cookie), /token=stale/);

      // 2. Server Set-Cookie appears in client.cookies().
      const cookies = await client.cookies();
      assert.ok(cookies.some((c) => c.name === "server_ck" && c.value === "hello"));

      // 3. 403 -> auto-refresh -> retry -> 200.
      const prot = await client.get(`${baseUrl}/protected`);
      assert.equal(prot.status, 200);
      assert.equal(refreshCalls, 1);

      // 4. JSON POST.
      const jsonResp = await client.post(`${baseUrl}/json`, {
        jsonBody: { hello: "waybound", count: 3 },
      });
      assert.equal(jsonResp.status, 200);
      assert.deepEqual(jsonResp.json(), {
        content_type: "application/json",
        parsed: { hello: "waybound", count: 3 },
      });

      // 5. URL-encoded form POST.
      const formResp = await client.post(`${baseUrl}/form`, {
        data: { title: "Quarterly Report", tag: "finance" },
      });
      assert.equal(formResp.status, 200);
      assert.deepEqual(formResp.json(), {
        content_type: "application/x-www-form-urlencoded",
        raw: "title=Quarterly+Report&tag=finance",
      });

      // 6. Lossless binary POST & PATCH round-trip (all 256 byte values).
      const payload = Uint8Array.from({ length: 256 }, (_, i) => i);
      const binPost = await client.post(`${baseUrl}/binary`, {
        headers: { "Content-Type": "application/octet-stream" },
        body: payload,
      });
      assert.equal(binPost.status, 200);
      assert.deepEqual(binPost.content, Buffer.from(payload));

      const reversed = Uint8Array.from(payload).reverse();
      const binPatch = await client.patch(`${baseUrl}/binary`, {
        headers: { "Content-Type": "application/octet-stream" },
        body: reversed,
      });
      assert.equal(binPatch.status, 200);
      assert.deepEqual(binPatch.content, Buffer.from(reversed));

      // 7. Multipart form + binary file upload.
      const rawBlob = new Uint8Array([0x00, 0xfe, 0xff, 0x10]);
      const mpResp = await client.post(`${baseUrl}/multipart`, {
        data: { title: "Quarterly Report" },
        files: {
          doc: ["sample.bin", payload, "application/octet-stream"],
          raw: rawBlob,
        },
      });
      assert.equal(mpResp.status, 200);
      const mpJson = mpResp.json<{ content_type: string; body_base64: string }>();
      assert.match(mpJson.content_type, /^multipart\/form-data; boundary=----WayboundBoundary/);
      const mpBytes = Buffer.from(mpJson.body_base64, "base64");
      assert.ok(mpBytes.includes(Buffer.from('name="title"\r\n\r\nQuarterly Report\r\n')));
      assert.ok(mpBytes.includes(Buffer.from('name="doc"; filename="sample.bin"')));
      assert.ok(mpBytes.includes(Buffer.from(payload)));
      assert.ok(mpBytes.includes(Buffer.from('name="raw"; filename="raw"')));
      assert.ok(mpBytes.includes(Buffer.from(rawBlob)));

      // 8. HEAD request.
      const headResp = await client.head(`${baseUrl}/head`);
      assert.equal(headResp.status, 200);
      assert.equal(headResp.header("x-head-ok"), "yes");
      assert.equal(headResp.content.length, 0);
    } finally {
      await client.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    await assertGone(workerPid);
    assert.equal(_liveReplayWorkerCount(), 0);
  });

  it("exports fingerprint from real mock daemon and hands off to standalone HandoffHttpClient", async () => {
    const daemonBinary = REPLAY_DAEMON_BIN as string;
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("still-alive");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as net.AddressInfo).port;

    let handoff: HandoffHttpClient | null = null;
    try {
      const session = await launch({ backend: "mock", daemonBinary });
      try {
        const fp = await session.page.exportFingerprint();
        assert.equal(fp.tls, null);
        assert.equal(fp.http2, null);
        assert.deepEqual(fp.defaultHeaders, []);
        assert.deepEqual(fp.cookies, []);

        handoff = await session.page.handoffHttpClient({ daemonBinary });
      } finally {
        await session.close();
      }
      // Session is closed, HandoffHttpClient still works!
      const resp = await handoff.get(`http://127.0.0.1:${port}/`);
      assert.equal(resp.status, 200);
      assert.equal(resp.text, "still-alive");
    } finally {
      await handoff?.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    assert.equal(_liveReplayWorkerCount(), 0);
  });
});

/** Unit and live daemon E2E tests for HAR 1.2 export and `TraceRecorder`. */

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  CapturedResponse,
  type HarDocument,
  launch,
  REDACTED_VALUE,
  Role,
  responsesToHar,
  SENSITIVE_HEADERS,
  type TraceEvent,
  type TraceManifest,
  type TracePageLike,
  TraceRecorder,
  withTrace,
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

const present = existsSync(DAEMON_BIN);
if (!present && process.env.WAYBOUND_REQUIRE_DAEMON === "1") {
  throw new Error(
    `WAYBOUND_REQUIRE_DAEMON=1 but the daemon binary is missing at ${DAEMON_BIN}; run \`cargo build -p waybound-daemon\``,
  );
}
const skip = present
  ? false
  : `waybound-daemon not built at ${DAEMON_BIN} (run cargo build -p waybound-daemon)`;

const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function withTempDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(path.join(tmpdir(), "wb-trace-test-"));
  return fn(dir).finally(() => {
    rmSync(dir, { recursive: true, force: true });
  });
}

describe("responsesToHar", () => {
  it("produces spec-compliant HAR 1.2 with queryString, postData, and UTF-8 sizes", () => {
    const responses = [
      new CapturedResponse(
        "https://api.example.com/search?q=tokyo&tag=a&tag=b&empty=",
        200,
        "application/json; charset=utf-8",
        '{"ok":true,"city":"東京"}',
        [
          { name: "Content-Type", value: "application/json; charset=utf-8" },
          { name: "X-Trace", value: "abc123" },
        ],
        "GET",
        [{ name: "Accept", value: "application/json" }],
        null,
        1_700_000_000_123,
      ),
      new CapturedResponse(
        "https://api.example.com/submit",
        201,
        null,
        null,
        [],
        "POST",
        [{ name: "Content-Type", value: "application/json" }],
        '{"x":1}',
        1_700_000_001_000,
      ),
      new CapturedResponse(
        "https://api.example.com/raw",
        599,
        null,
        "raw",
        [],
        null,
        [],
        "bytes",
        null,
      ),
    ];

    const har = responsesToHar(responses);
    assert.equal(har.log.version, "1.2");
    assert.equal(har.log.creator.name, "waybound");
    assert.ok(har.log.creator.version.length > 0);
    assert.equal(har.log.entries.length, 3);

    const first = har.log.entries[0];
    assert.ok(first !== undefined);
    assert.equal(first.startedDateTime, "2023-11-14T22:13:20.123Z");
    assert.equal(first.time, 0);
    assert.deepEqual(first.cache, {});
    assert.deepEqual(first.timings, { send: 0, wait: 0, receive: 0 });
    assert.equal(first.request.method, "GET");
    assert.equal(first.request.httpVersion, "HTTP/1.1");
    assert.equal(first.request.headersSize, -1);
    assert.equal(first.request.bodySize, 0);
    assert.equal("postData" in first.request, false);
    assert.deepEqual(first.request.queryString, [
      { name: "q", value: "tokyo" },
      { name: "tag", value: "a" },
      { name: "tag", value: "b" },
      { name: "empty", value: "" },
    ]);

    const expectedBytes = Buffer.byteLength('{"ok":true,"city":"東京"}', "utf8");
    assert.equal(first.response.status, 200);
    assert.equal(first.response.statusText, "OK");
    assert.equal(first.response.redirectURL, "");
    assert.equal(first.response.content.size, expectedBytes);
    assert.equal(first.response.bodySize, expectedBytes);
    assert.equal(first.response.content.mimeType, "application/json; charset=utf-8");
    assert.equal(first.response.content.text, '{"ok":true,"city":"東京"}');

    const second = har.log.entries[1];
    assert.ok(second !== undefined);
    assert.equal(second.request.method, "POST");
    assert.equal(second.request.bodySize, 7);
    assert.deepEqual(second.request.postData, {
      mimeType: "application/json",
      text: '{"x":1}',
    });
    assert.equal(second.response.statusText, "Created");
    assert.equal(second.response.content.text, "");

    const third = har.log.entries[2];
    assert.ok(third !== undefined);
    assert.ok(third.startedDateTime.endsWith("Z"));
    assert.equal(third.request.method, "GET");
    assert.deepEqual(third.request.postData, {
      mimeType: "application/octet-stream",
      text: "bytes",
    });
    assert.equal(third.response.statusText, "");
  });

  it("redacts sensitive headers case-insensitively when opted in", () => {
    const resp = new CapturedResponse(
      "https://secure.example.com/me",
      200,
      "application/json",
      "{}",
      [
        { name: "Set-Cookie", value: "sid=secret-cookie; HttpOnly" },
        { name: "X-Request-Id", value: "req-42" },
      ],
      "GET",
      [
        { name: "Authorization", value: "Bearer super-secret" },
        { name: "Cookie", value: "sid=secret-cookie" },
        { name: "X-API-Key", value: "key-123" },
        { name: "Accept", value: "*/*" },
      ],
    );

    const unredacted = responsesToHar([resp]);
    assert.deepEqual(unredacted.log.entries[0]?.request.headers[0], {
      name: "Authorization",
      value: "Bearer super-secret",
    });

    const redacted = responsesToHar([resp], { redactHeaders: SENSITIVE_HEADERS });
    const entry = redacted.log.entries[0];
    assert.ok(entry !== undefined);
    assert.deepEqual(entry.request.headers, [
      { name: "Authorization", value: REDACTED_VALUE },
      { name: "Cookie", value: REDACTED_VALUE },
      { name: "X-API-Key", value: REDACTED_VALUE },
      { name: "Accept", value: "*/*" },
    ]);
    assert.deepEqual(entry.response.headers, [
      { name: "Set-Cookie", value: REDACTED_VALUE },
      { name: "X-Request-Id", value: "req-42" },
    ]);
  });
});

describe("TraceRecorder crash resilience", () => {
  it("never masks caller error when page capture methods fail during finalization", async () => {
    const crashingPage: TracePageLike = {
      async url() {
        throw new Error("daemon crashed on url");
      },
      async screenshot() {
        throw new Error("daemon crashed on screenshot");
      },
      async snapshotTree() {
        throw new Error("daemon crashed on snapshotTree");
      },
      async capturedResponses() {
        throw new Error("daemon crashed on capturedResponses");
      },
    };

    await withTempDir(async (tmp) => {
      const traceDir = path.join(tmp, "crashed-bundle");
      const original = new TypeError("original workflow failure");

      await assert.rejects(
        () =>
          withTrace(
            crashingPage,
            traceDir,
            async (trace) => {
              await trace.recordAction("click_submit", { metadata: { step: 1 } });
              throw original;
            },
            { onErrorOnly: true },
          ),
        (err: unknown) => err === original,
      );

      assert.equal(existsSync(traceDir), true);
      const manifest = JSON.parse(
        readFileSync(path.join(traceDir, "manifest.json"), "utf8"),
      ) as TraceManifest;
      assert.equal(manifest.failed, true);
      assert.equal(manifest.har_entries, 0);

      const events = readFileSync(path.join(traceDir, "timeline.jsonl"), "utf8")
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as TraceEvent);
      assert.equal(events[0]?.action, "click_submit");
      const failEvent = events.find((e) => e.action === "snapshot:failure");
      assert.ok(failEvent !== undefined);
      assert.ok(failEvent.error?.includes("TypeError: original workflow failure"));
      assert.ok(failEvent.error?.includes("screenshot capture failed"));
      assert.ok(failEvent.error?.includes("tree capture failed"));
      assert.ok(events.some((e) => e.action === "capture_har_error"));
    });
  });
});

describe("TraceRecorder E2E: waybound-daemon --backend mock", { skip }, () => {
  it("writes full trace bundle layout and enforces onErrorOnly cleanup/retention", async () => {
    const session = await launch({ backend: "mock", daemonBinary: DAEMON_BIN });
    try {
      const { page } = session;
      await withTempDir(async (tmp) => {
        // 1. Full bundle on success
        const fullDir = path.join(tmp, "full-bundle");
        const recorder = new TraceRecorder(page, fullDir, {
          redactHeaders: SENSITIVE_HEADERS,
        });
        await recorder.recordAction("navigate", { metadata: { target: "mock" } });
        await page.getByRole(Role.TEXTBOX, { name: "Origin" }).fill("NRT");
        const snapEvent = await recorder.recordSnapshot("after fill", {
          metadata: { field: "Origin" },
        });
        assert.equal(snapEvent.url, "https://mock.waybound.local/");
        assert.equal(snapEvent.screenshot, "screenshots/002_after_fill.png");
        assert.equal(snapEvent.tree, "trees/002_after_fill.json");
        const finalizedPath = await recorder.finalize({ failed: false });
        assert.equal(finalizedPath, path.resolve(fullDir));

        const manifest = JSON.parse(
          readFileSync(path.join(fullDir, "manifest.json"), "utf8"),
        ) as TraceManifest;
        assert.equal(manifest.version, 1);
        assert.equal(manifest.failed, false);
        assert.equal(manifest.event_count, 2);
        assert.equal(manifest.har_entries, 0);
        assert.ok(manifest.created_at.endsWith("Z"));

        const shot = readFileSync(path.join(fullDir, "screenshots", "002_after_fill.png"));
        assert.equal(shot.subarray(0, PNG_MAGIC.length).equals(PNG_MAGIC), true);

        const nodes = JSON.parse(
          readFileSync(path.join(fullDir, "trees", "002_after_fill.json"), "utf8"),
        ) as Array<{ name: string | null }>;
        assert.equal(nodes.length, 5);
        assert.equal(nodes[0]?.name, "Origin");

        const har = JSON.parse(
          readFileSync(path.join(fullDir, "network.har"), "utf8"),
        ) as HarDocument;
        assert.equal(har.log.version, "1.2");
        assert.deepEqual(har.log.entries, []);

        // 2. onErrorOnly: true deletes bundle on clean success
        const okDir = path.join(tmp, "ok-discarded");
        const value = await withTrace(
          page,
          okDir,
          async (trace) => {
            await trace.recordSnapshot("before_ok");
            return 42;
          },
          { onErrorOnly: true },
        );
        assert.equal(value, 42);
        assert.equal(existsSync(okDir), false);

        // 3. onErrorOnly: true retains bundle on thrown error and rethrows untouched
        const failDir = path.join(tmp, "fail-retained");
        const boom = new Error("checkout failed");
        await assert.rejects(
          () =>
            withTrace(
              page,
              failDir,
              async (trace) => {
                await trace.recordAction("submit_order");
                throw boom;
              },
              { onErrorOnly: true },
            ),
          (err: unknown) => err === boom,
        );

        assert.equal(existsSync(failDir), true);
        const failManifest = JSON.parse(
          readFileSync(path.join(failDir, "manifest.json"), "utf8"),
        ) as TraceManifest;
        assert.equal(failManifest.failed, true);
        assert.equal(failManifest.event_count, 2);

        const failEvents = readFileSync(path.join(failDir, "timeline.jsonl"), "utf8")
          .trim()
          .split("\n")
          .map((line) => JSON.parse(line) as TraceEvent);
        const last = failEvents.at(-1);
        assert.equal(last?.action, "snapshot:failure");
        assert.ok(last?.error?.includes("Error: checkout failed"));
        assert.equal(last?.screenshot, "screenshots/002_failure.png");
        const failShot = readFileSync(path.join(failDir, "screenshots", "002_failure.png"));
        assert.equal(failShot.subarray(0, PNG_MAGIC.length).equals(PNG_MAGIC), true);
        assert.equal(existsSync(path.join(failDir, "trees", "002_failure.json")), true);
        assert.equal(existsSync(path.join(failDir, "network.har")), true);
      });
    } finally {
      await session.close();
    }
  });
});

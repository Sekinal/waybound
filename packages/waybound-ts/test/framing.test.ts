import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { encodeLine, LineDecoder } from "../src/framing.js";

describe("LineDecoder", () => {
  it("reassembles a line split across many chunks", () => {
    const decoder = new LineDecoder();
    const bytes = Buffer.from('{"status":"pong","version":"0.4.0"}\n');
    const out: string[] = [];
    for (const byte of bytes) {
      out.push(...decoder.push(Buffer.from([byte])));
    }
    assert.deepEqual(out, ['{"status":"pong","version":"0.4.0"}']);
    assert.equal(decoder.pendingBytes, 0);
  });

  it("returns every line coalesced into one chunk and keeps the remainder", () => {
    const decoder = new LineDecoder();
    assert.deepEqual(decoder.push(Buffer.from('{"a":1}\n{"b":2}\n{"c"')), ['{"a":1}', '{"b":2}']);
    assert.equal(decoder.pendingBytes, 4);
    assert.deepEqual(decoder.push(Buffer.from(":3}\n")), ['{"c":3}']);
  });

  it("decodes multi-byte UTF-8 split at every possible chunk boundary", () => {
    const text = '{"name":"Zürich 東京 🚀 naïve"}';
    const bytes = Buffer.from(`${text}\n`, "utf8");
    for (let cut = 1; cut < bytes.length; cut += 1) {
      const decoder = new LineDecoder();
      const lines = [...decoder.push(bytes.subarray(0, cut)), ...decoder.push(bytes.subarray(cut))];
      assert.deepEqual(lines, [text], `cut at ${cut}`);
    }
  });

  it("strips a trailing carriage return", () => {
    assert.deepEqual(new LineDecoder().push(Buffer.from("x\r\n")), ["x"]);
  });

  it("rejects a line over the size cap", () => {
    const decoder = new LineDecoder(8);
    decoder.push(Buffer.from("12345"));
    assert.throws(() => decoder.push(Buffer.from("6789")), RangeError);
  });

  it("rejects invalid UTF-8", () => {
    assert.throws(() => new LineDecoder().push(Buffer.from([0xff, 0xfe, 0x0a])), TypeError);
  });
});

describe("encodeLine", () => {
  it("produces exactly one newline-terminated JSON line", () => {
    const line = encodeLine({ method: "fill", text: "a\nb" });
    assert.equal(line, '{"method":"fill","text":"a\\nb"}\n');
    assert.equal(line.indexOf("\n"), line.length - 1);
  });
});

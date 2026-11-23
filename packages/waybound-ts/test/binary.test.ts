import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import {
  cachedDaemonPath,
  DEFAULT_VERSION,
  daemonFilename,
  downloadDaemonBinary,
  extractDaemonFromTar,
  type FetchLike,
  findCachedDaemon,
  MAX_REDIRECTS,
  parseChecksumFile,
  platformArtifactName,
  resolveDaemonBinary,
} from "../src/binary.js";
import { WayboundLaunchError } from "../src/errors.js";

const scratch = mkdtempSync(path.join(tmpdir(), "wb-bin-test-"));
after(() => rmSync(scratch, { recursive: true, force: true }));
let counter = 0;
function freshDir(): string {
  counter += 1;
  const dir = path.join(scratch, String(counter));
  mkdirSync(dir, { recursive: true });
  return dir;
}

function tarHeader(name: string, size: number, type: string): Buffer {
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, "utf8");
  header.write("0000755\0", 100, "latin1");
  header.write("0000000\0", 108, "latin1");
  header.write("0000000\0", 116, "latin1");
  header.write(`${size.toString(8).padStart(11, "0")}\0`, 124, "latin1");
  header.write("00000000000\0", 136, "latin1");
  header.write(type, 156, "latin1");
  header.write("ustar\0", 257, "latin1");
  header.write("00", 263, "latin1");
  header.fill(0x20, 148, 156);
  let sum = 0;
  for (const b of header) {
    sum += b;
  }
  header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "latin1");
  return header;
}

/** Build an uncompressed ustar archive. */
function makeTar(entries: { name: string; data: Buffer; type?: string }[]): Buffer {
  const parts: Buffer[] = [];
  for (const entry of entries) {
    parts.push(tarHeader(entry.name, entry.data.length, entry.type ?? "0"));
    parts.push(entry.data);
    const pad = (512 - (entry.data.length % 512)) % 512;
    parts.push(Buffer.alloc(pad));
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

function pax(records: Record<string, string>): Buffer {
  let out = "";
  for (const [k, v] of Object.entries(records)) {
    const body = ` ${k}=${v}\n`;
    let len = body.length + 1;
    while (`${len}${body}`.length !== len) {
      len += 1;
    }
    out += `${len}${body}`;
  }
  return Buffer.from(out, "utf8");
}

const sha256 = (data: Buffer): string => createHash("sha256").update(data).digest("hex");

/** A fetch stand-in serving fixed bodies by URL; records every URL requested. */
function fakeFetch(routes: Record<string, Buffer | number>): FetchLike & { urls: string[] } {
  const urls: string[] = [];
  const impl = async (url: string): Promise<Response> => {
    urls.push(url);
    const body = routes[url];
    if (body === undefined || typeof body === "number") {
      return new Response("nope", { status: typeof body === "number" ? body : 404 });
    }
    return new Response(new Uint8Array(body), { status: 200 });
  };
  return Object.assign(impl, { urls });
}

const HOST = { platform: "linux", arch: "x64" } as const;
const BASE = `https://github.com/Sekinal/waybound/releases/download/${DEFAULT_VERSION}/waybound-daemon-linux-x86_64.tar.gz`;

describe("platformArtifactName", () => {
  it("maps supported hosts to release artefacts", () => {
    assert.equal(
      platformArtifactName({ platform: "darwin", arch: "arm64" }),
      "waybound-daemon-macos-arm64",
    );
    assert.equal(
      platformArtifactName({ platform: "linux", arch: "x64" }),
      "waybound-daemon-linux-x86_64",
    );
    assert.equal(
      platformArtifactName({ platform: "linux", arch: "arm64" }),
      "waybound-daemon-linux-arm64",
    );
    assert.equal(
      platformArtifactName({ platform: "win32", arch: "x64" }),
      "waybound-daemon-windows-x86_64",
    );
  });

  it("rejects hosts without a prebuilt binary", () => {
    assert.throws(() => platformArtifactName({ platform: "darwin", arch: "x64" }), /no prebuilt/);
    assert.throws(() => platformArtifactName({ platform: "freebsd", arch: "x64" }), /no prebuilt/);
  });
});

describe("cachedDaemonPath / findCachedDaemon", () => {
  it("validates the version tag", () => {
    const p = cachedDaemonPath("v0.1.0", { cacheDir: "/c", platform: "linux" });
    assert.equal(p, path.join("/c", "v0.1.0", "waybound-daemon"));
    assert.equal(
      path.basename(cachedDaemonPath("v1", { platform: "win32" })),
      "waybound-daemon.exe",
    );
    assert.throws(() => cachedDaemonPath("../escape"), /invalid version tag/);
    assert.throws(() => cachedDaemonPath(".."), /invalid version tag/);
  });

  it("prefers the default version, else the newest cached binary", () => {
    const cacheDir = freshDir();
    assert.equal(findCachedDaemon({ cacheDir }), null);
    const bin = daemonFilename();
    for (const [version, mtime] of [
      ["v0.1.0", 1_000],
      ["v0.2.0", 3_000],
      ["v0.1.5", 2_000],
    ] as const) {
      mkdirSync(path.join(cacheDir, version));
      writeFileSync(path.join(cacheDir, version, bin), "x");
      utimesSync(path.join(cacheDir, version, bin), mtime, mtime);
    }
    assert.equal(findCachedDaemon({ cacheDir }), path.join(cacheDir, "v0.2.0", bin));
    mkdirSync(path.join(cacheDir, DEFAULT_VERSION));
    writeFileSync(path.join(cacheDir, DEFAULT_VERSION, bin), "x");
    utimesSync(path.join(cacheDir, DEFAULT_VERSION, bin), 10, 10);
    assert.equal(findCachedDaemon({ cacheDir }), path.join(cacheDir, DEFAULT_VERSION, bin));
  });
});

describe("resolveDaemonBinary", () => {
  const bin = daemonFilename();
  const setup = (): { root: string; pathDir: string; cacheDir: string; empty: string } => {
    const root = freshDir();
    const pathDir = path.join(root, "bin");
    const cacheDir = path.join(root, "cache");
    const empty = path.join(root, "empty");
    for (const d of [
      pathDir,
      cacheDir,
      empty,
      path.join(root, "target", "debug"),
      path.join(root, "target", "release"),
    ]) {
      mkdirSync(d, { recursive: true });
    }
    return { root, pathDir, cacheDir, empty };
  };

  it("resolves in order: explicit, env var, PATH, target/{release,debug}, cache", () => {
    const { root, pathDir, cacheDir, empty } = setup();
    const env = (extra: Record<string, string>): NodeJS.ProcessEnv => ({ PATH: empty, ...extra });

    assert.throws(
      () => resolveDaemonBinary(null, { env: env({}), repoRoot: root, cacheDir }),
      WayboundLaunchError,
    );

    const cached = path.join(cacheDir, "v9", bin);
    mkdirSync(path.dirname(cached));
    writeFileSync(cached, "");
    assert.equal(resolveDaemonBinary(null, { env: env({}), repoRoot: root, cacheDir }), cached);

    const debug = path.join(root, "target", "debug", bin);
    writeFileSync(debug, "");
    assert.equal(resolveDaemonBinary(null, { env: env({}), repoRoot: root, cacheDir }), debug);

    const release = path.join(root, "target", "release", bin);
    writeFileSync(release, "");
    assert.equal(resolveDaemonBinary(null, { env: env({}), repoRoot: root, cacheDir }), release);

    const onPath = path.join(pathDir, bin);
    writeFileSync(onPath, "");
    chmodSync(onPath, 0o755);
    const withPath = { PATH: [empty, pathDir].join(path.delimiter) };
    assert.equal(resolveDaemonBinary(null, { env: withPath, repoRoot: root, cacheDir }), onPath);

    assert.equal(
      resolveDaemonBinary(null, {
        env: { ...withPath, WAYBOUND_DAEMON_BIN: "/from/env" },
        repoRoot: root,
        cacheDir,
      }),
      "/from/env",
    );
    assert.equal(
      resolveDaemonBinary("/explicit", {
        env: { ...withPath, WAYBOUND_DAEMON_BIN: "/from/env" },
        repoRoot: root,
        cacheDir,
      }),
      "/explicit",
    );
  });

  it("skips non-executable files on PATH", { skip: process.platform === "win32" }, () => {
    const { root, pathDir, cacheDir } = setup();
    const onPath = path.join(pathDir, bin);
    writeFileSync(onPath, "");
    chmodSync(onPath, 0o644);
    assert.throws(
      () => resolveDaemonBinary(null, { env: { PATH: pathDir }, repoRoot: root, cacheDir }),
      WayboundLaunchError,
    );
  });
});

describe("extractDaemonFromTar", () => {
  const payload = Buffer.from("#!/bin/sh\necho daemon\n");

  it("finds the daemon by plain or ./-prefixed name, skipping other entries", () => {
    const tar = makeTar([
      { name: "README", data: Buffer.from("hi") },
      { name: "./waybound-daemon", data: payload },
    ]);
    assert.deepEqual(extractDaemonFromTar(tar, "waybound-daemon"), payload);
    assert.deepEqual(
      extractDaemonFromTar(
        makeTar([{ name: "waybound-daemon.exe", data: payload }]),
        "waybound-daemon.exe",
      ),
      payload,
    );
  });

  it("honours pax `path` overrides and GNU long names", () => {
    const viaPax = makeTar([
      { name: "PaxHeader/x", data: pax({ path: "waybound-daemon", mtime: "1" }), type: "x" },
      { name: "something-else", data: payload },
    ]);
    assert.deepEqual(extractDaemonFromTar(viaPax, "waybound-daemon"), payload);
    const viaLong = makeTar([
      { name: "././@LongLink", data: Buffer.from("waybound-daemon\0"), type: "L" },
      { name: "truncated", data: payload },
    ]);
    assert.deepEqual(extractDaemonFromTar(viaLong, "waybound-daemon"), payload);
  });

  it("rejects archives without a regular daemon file", () => {
    assert.throws(
      () => extractDaemonFromTar(makeTar([{ name: "other", data: payload }]), "waybound-daemon"),
      /archive missing regular file/,
    );
    assert.throws(
      () =>
        extractDaemonFromTar(
          makeTar([{ name: "waybound-daemon", data: Buffer.alloc(0), type: "2" }]),
          "waybound-daemon",
        ),
      /archive missing regular file/,
    );
    const tar = makeTar([{ name: "waybound-daemon", data: payload }]);
    assert.throws(() => extractDaemonFromTar(tar.subarray(0, 520), "waybound-daemon"), /truncated/);
  });

  it("reads archives produced by the system tar", { skip: process.platform === "win32" }, () => {
    const dir = freshDir();
    writeFileSync(path.join(dir, "waybound-daemon"), payload, { mode: 0o755 });
    const out = path.join(dir, "a.tar");
    try {
      // Same shape as the release workflow: `tar -C <dir> -czf ... waybound-daemon`.
      execFileSync("tar", ["-C", dir, "-cf", out, "waybound-daemon"], { stdio: "ignore" });
    } catch {
      return; // no system tar available
    }
    assert.deepEqual(extractDaemonFromTar(readFileSync(out), "waybound-daemon"), payload);
  });
});

describe("parseChecksumFile", () => {
  it("accepts sha256sum output and rejects junk", () => {
    const digest = "a".repeat(64);
    assert.equal(parseChecksumFile(`${digest.toUpperCase()}  x.tar.gz\n`, "x"), digest);
    assert.throws(() => parseChecksumFile("", "x"), /invalid SHA-256 checksum file/);
    assert.throws(() => parseChecksumFile("abc x.tar.gz", "x"), /invalid SHA-256 checksum file/);
  });
});

describe("downloadDaemonBinary (no network)", () => {
  const binary = Buffer.from("\x7fELF fake daemon");
  const tarball = gzipSync(makeTar([{ name: "waybound-daemon", data: binary }]));

  it("downloads, verifies the SHA-256 and installs the binary atomically", async () => {
    const cacheDir = freshDir();
    const fetch = fakeFetch({
      [BASE]: tarball,
      [`${BASE}.sha256`]: Buffer.from(`${sha256(tarball)}  waybound-daemon-linux-x86_64.tar.gz\n`),
    });
    const dest = await downloadDaemonBinary({ ...HOST, cacheDir, fetch });
    assert.equal(dest, path.join(cacheDir, DEFAULT_VERSION, "waybound-daemon"));
    assert.deepEqual(readFileSync(dest), binary);
    if (process.platform !== "win32") {
      assert.equal(statSync(dest).mode & 0o777, 0o755);
    }
    assert.deepEqual(readdirSync(path.dirname(dest)), ["waybound-daemon"], "no staged leftovers");
    assert.deepEqual(fetch.urls, [BASE, `${BASE}.sha256`]);

    // Cached: no further requests unless forced.
    await downloadDaemonBinary({ ...HOST, cacheDir, fetch });
    assert.equal(fetch.urls.length, 2);
    await downloadDaemonBinary({ ...HOST, cacheDir, fetch, force: true });
    assert.equal(fetch.urls.length, 4);
  });

  it("refuses a tarball whose SHA-256 does not match and installs nothing", async () => {
    const cacheDir = freshDir();
    const fetch = fakeFetch({
      [BASE]: tarball,
      [`${BASE}.sha256`]: Buffer.from(`${"0".repeat(64)}  x\n`),
    });
    await assert.rejects(downloadDaemonBinary({ ...HOST, cacheDir, fetch }), /SHA-256 mismatch/);
    assert.equal(existsSync(path.join(cacheDir, DEFAULT_VERSION, "waybound-daemon")), false);
  });

  it("refuses an invalid checksum file and HTTP errors", async () => {
    const cacheDir = freshDir();
    await assert.rejects(
      downloadDaemonBinary({
        ...HOST,
        cacheDir,
        fetch: fakeFetch({ [BASE]: tarball, [`${BASE}.sha256`]: Buffer.from("garbage") }),
      }),
      /invalid SHA-256 checksum file/,
    );
    await assert.rejects(
      downloadDaemonBinary({ ...HOST, cacheDir, fetch: fakeFetch({ [BASE]: 404 }) }),
      /HTTP 404/,
    );
  });

  it("refuses a checksum file over the size cap", async () => {
    const cacheDir = freshDir();
    const fetch = fakeFetch({ [BASE]: tarball, [`${BASE}.sha256`]: Buffer.alloc(5000, 0x61) });
    await assert.rejects(
      downloadDaemonBinary({ ...HOST, cacheDir, fetch }),
      /maximum allowed size/,
    );
  });

  /** A fetch stand-in that answers each URL with a redirect or a final body. */
  function redirectingFetch(
    routes: Record<string, string | Buffer>,
  ): FetchLike & { urls: string[]; inits: { redirect: string }[] } {
    const urls: string[] = [];
    const inits: { redirect: string }[] = [];
    const impl: FetchLike = async (url, init) => {
      urls.push(url);
      inits.push({ redirect: init.redirect });
      const route = routes[url];
      if (typeof route === "string") {
        return new Response(null, { status: 302, headers: { location: route } });
      }
      if (route === undefined) {
        return new Response("nope", { status: 404 });
      }
      return new Response(new Uint8Array(route), { status: 200 });
    };
    return Object.assign(impl, { urls, inits });
  }

  it("follows HTTPS redirects by hand, including relative ones", async () => {
    const cacheDir = freshDir();
    const fetch = redirectingFetch({
      [BASE]: "https://objects.example.test/a/tarball",
      "https://objects.example.test/a/tarball": "../b/tarball",
      "https://objects.example.test/b/tarball": tarball,
      [`${BASE}.sha256`]: "https://objects.example.test/sha",
      "https://objects.example.test/sha": Buffer.from(`${sha256(tarball)}  x\n`),
    });
    const dest = await downloadDaemonBinary({ ...HOST, cacheDir, fetch });
    assert.deepEqual(readFileSync(dest), binary);
    assert.ok(fetch.inits.every((i) => i.redirect === "manual"));
    assert.equal(fetch.urls.length, 5);
  });

  it("refuses a redirect to plain HTTP on any hop", async () => {
    const cacheDir = freshDir();
    const fetch = redirectingFetch({
      [BASE]: "https://objects.example.test/a",
      "https://objects.example.test/a": "http://objects.example.test/b",
      "http://objects.example.test/b": tarball,
    });
    await assert.rejects(downloadDaemonBinary({ ...HOST, cacheDir, fetch }), /non-HTTPS/);
    assert.equal(fetch.urls.includes("http://objects.example.test/b"), false, "never requested");
  });

  it("caps the number of redirects and requires a Location header", async () => {
    const cacheDir = freshDir();
    const loop = redirectingFetch({
      [BASE]: "https://r.test/1",
      "https://r.test/1": "https://r.test/2",
      "https://r.test/2": "https://r.test/1",
    });
    await assert.rejects(
      downloadDaemonBinary({ ...HOST, cacheDir, fetch: loop }),
      /too many redirects/,
    );
    assert.equal(loop.urls.length, MAX_REDIRECTS + 1);
    const noLocation: FetchLike = async () => new Response(null, { status: 301 });
    await assert.rejects(
      downloadDaemonBinary({ ...HOST, cacheDir, fetch: noLocation }),
      /without a Location header/,
    );
  });

  it("aborts a download that stops making progress", async () => {
    const cacheDir = freshDir();
    const stalled: FetchLike = async (_url, init) => {
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new Uint8Array([1, 2, 3]));
          init.signal.addEventListener("abort", () => controller.error(init.signal.reason));
        },
      });
      return new Response(body, { status: 200 });
    };
    const started = performance.now();
    await assert.rejects(
      downloadDaemonBinary({ ...HOST, cacheDir, fetch: stalled, inactivityTimeoutMs: 100 }),
      /download stalled for 100ms/,
    );
    assert.ok(performance.now() - started < 5_000);
  });

  it("validates the repository slug and version before any request", async () => {
    const fetch = fakeFetch({});
    await assert.rejects(
      downloadDaemonBinary({ repo: "not-a-slug", fetch }),
      /invalid GitHub repository slug/,
    );
    await assert.rejects(
      downloadDaemonBinary({ repo: "../..", fetch }),
      /invalid GitHub repository slug/,
    );
    await assert.rejects(downloadDaemonBinary({ version: "../x", fetch }), /invalid version tag/);
    assert.deepEqual(fetch.urls, []);
  });
});

describe("packaging", () => {
  it("never downloads at install time (no install lifecycle scripts)", () => {
    const pkg = JSON.parse(
      readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
    ) as { scripts?: Record<string, string>; dependencies?: Record<string, string> };
    for (const hook of ["preinstall", "install", "postinstall", "prepare"]) {
      assert.equal(pkg.scripts?.[hook], undefined, `${hook} script must not exist`);
    }
    assert.equal(pkg.dependencies, undefined, "zero runtime dependencies");
    assert.equal(pkg.scripts?.prepublishOnly, "npm run build");
  });

  const pkgDir = fileURLToPath(new URL("../../", import.meta.url));
  const built = existsSync(path.join(pkgDir, "dist", "index.js"));

  it("can be imported and required through its exports map", {
    skip: !built && "dist/ not built",
  }, () => {
    for (const code of [
      'const m = require("waybound"); process.stdout.write(typeof m.launch);',
      'import("waybound").then((m) => process.stdout.write(typeof m.launch));',
    ]) {
      const out = execFileSync(process.execPath, ["-e", code], { cwd: pkgDir, encoding: "utf8" });
      assert.equal(out, "function", code);
    }
  });

  it("keeps internals out of the published declarations", {
    skip: !built && "dist/ not built",
  }, () => {
    const dts = readFileSync(path.join(pkgDir, "dist", "session.d.ts"), "utf8");
    assert.doesNotMatch(dts, /_create|_killSync|_liveDaemonCount/);
    assert.match(dts, /private constructor/);
  });

  it("ships both licence texts", () => {
    const pkg = JSON.parse(readFileSync(path.join(pkgDir, "package.json"), "utf8")) as {
      files: string[];
      license: string;
    };
    assert.equal(pkg.license, "MIT OR Apache-2.0");
    for (const file of ["LICENSE-MIT", "LICENSE-APACHE"]) {
      assert.ok(pkg.files.includes(file));
      assert.ok(readFileSync(path.join(pkgDir, file), "utf8").length > 500);
    }
  });
});

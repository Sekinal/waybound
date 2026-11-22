/**
 * Locating `waybound-daemon`, and the SHA-256 verified downloader for prebuilt release
 * artefacts. Nothing here runs at install time: downloading only happens when
 * `downloadDaemonBinary()` is called explicitly.
 */

import { createHash, randomUUID } from "node:crypto";
import { accessSync, constants, readdirSync, statSync } from "node:fs";
import { chmod, mkdir, rename, unlink, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import { WayboundLaunchError } from "./errors.js";

export const DEFAULT_REPO = "Sekinal/waybound";
/** Release tag downloaded by default: the release matching this package's version. */
export const DEFAULT_VERSION = "v0.4.0";

const SAFE_VERSION_RE = /^[A-Za-z0-9._-]+$/;
const SAFE_REPO_RE = /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const DOWNLOAD_TIMEOUT_MS = 60_000;
export const MAX_TARBALL_BYTES = 100 * 1024 * 1024;
export const MAX_BINARY_BYTES = 100 * 1024 * 1024;
const MAX_SHA_BYTES = 4096;
const TAR_BLOCK = 512;

/** Host description used to pick a release artefact; defaults to the running process. */
export interface HostInfo {
  readonly platform?: NodeJS.Platform;
  readonly arch?: string;
}

/** File name of the daemon executable on `platform`. */
export function daemonFilename(platform: NodeJS.Platform = process.platform): string {
  return platform === "win32" ? "waybound-daemon.exe" : "waybound-daemon";
}

/** GitHub Release artefact base name for the host OS/arch. Throws if there is none. */
export function platformArtifactName(host: HostInfo = {}): string {
  const platform = host.platform ?? process.platform;
  const arch = (host.arch ?? process.arch).toLowerCase();
  const isArm64 = arch === "arm64" || arch === "aarch64";
  const isX64 = arch === "x64" || arch === "x86_64" || arch === "amd64";
  if (platform === "darwin" && isArm64) {
    return "waybound-daemon-macos-arm64";
  }
  if (platform === "linux" && isX64) {
    return "waybound-daemon-linux-x86_64";
  }
  if (platform === "linux" && isArm64) {
    return "waybound-daemon-linux-arm64";
  }
  if (platform === "win32" && isX64) {
    return "waybound-daemon-windows-x86_64";
  }
  throw new Error(
    `no prebuilt waybound-daemon binary for ${platform}/${arch}; build with \`cargo build --release\``,
  );
}

/** Default download cache shared with the Python SDK: `~/.cache/waybound`. */
export function defaultCacheDir(): string {
  return path.join(homedir(), ".cache", "waybound");
}

function validateVersion(version: string): void {
  if (!SAFE_VERSION_RE.test(version) || version === "." || version === "..") {
    throw new Error(`invalid version tag: ${JSON.stringify(version)}`);
  }
}

/** Cache path for a downloaded daemon of `version`. */
export function cachedDaemonPath(
  version: string = DEFAULT_VERSION,
  options: { readonly cacheDir?: string; readonly platform?: NodeJS.Platform } = {},
): string {
  validateVersion(version);
  return path.join(
    options.cacheDir ?? defaultCacheDir(),
    version,
    daemonFilename(options.platform),
  );
}

function isFile(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

/** The default-version cached daemon, else the most recently modified cached one, else null. */
export function findCachedDaemon(options: { readonly cacheDir?: string } = {}): string | null {
  const cacheDir = options.cacheDir ?? defaultCacheDir();
  const defaultPath = cachedDaemonPath(DEFAULT_VERSION, { cacheDir });
  if (isFile(defaultPath)) {
    return defaultPath;
  }
  let entries: string[];
  try {
    entries = readdirSync(cacheDir);
  } catch {
    return null;
  }
  const binName = daemonFilename();
  let best: { path: string; mtimeMs: number } | null = null;
  for (const entry of entries) {
    const candidate = path.join(cacheDir, entry, binName);
    try {
      const st = statSync(candidate);
      if (st.isFile() && (best === null || st.mtimeMs > best.mtimeMs)) {
        best = { path: candidate, mtimeMs: st.mtimeMs };
      }
    } catch {
      // not a cached release directory
    }
  }
  return best?.path ?? null;
}

function findOnPath(binName: string, pathEnv: string | undefined): string | null {
  if (!pathEnv) {
    return null;
  }
  for (const dir of pathEnv.split(path.delimiter)) {
    if (dir === "") {
      continue;
    }
    const candidate = path.join(dir, binName);
    try {
      if (statSync(candidate).isFile()) {
        accessSync(candidate, constants.X_OK);
        return candidate;
      }
    } catch {
      // not here, or not executable
    }
  }
  return null;
}

/** Repository root when running from a checkout (`packages/waybound-ts/<dist>/binary.js`). */
function defaultRepoRoot(): string {
  return fileURLToPath(new URL("../../../", import.meta.url));
}

export interface ResolveOptions {
  /** Environment to read `WAYBOUND_DAEMON_BIN` and `PATH` from. Default `process.env`. */
  readonly env?: NodeJS.ProcessEnv;
  /** Directory whose `target/{release,debug}` is searched. Default: this checkout's root. */
  readonly repoRoot?: string;
  /** Download cache directory. Default `~/.cache/waybound`. */
  readonly cacheDir?: string;
}

/**
 * Resolve the daemon executable, in the same order as the Python SDK:
 * explicit path, `$WAYBOUND_DAEMON_BIN`, `PATH`, `<repo>/target/{release,debug}`, then the
 * download cache. Never downloads; call `downloadDaemonBinary()` for that.
 */
export function resolveDaemonBinary(
  explicit?: string | null,
  options: ResolveOptions = {},
): string {
  if (explicit !== undefined && explicit !== null) {
    return explicit;
  }
  const env = options.env ?? process.env;
  const envBin = env.WAYBOUND_DAEMON_BIN;
  if (envBin) {
    return envBin;
  }
  const binName = daemonFilename();
  const onPath = findOnPath(binName, env.PATH ?? env.Path);
  if (onPath !== null) {
    return onPath;
  }
  const repoRoot = options.repoRoot ?? defaultRepoRoot();
  for (const profile of ["release", "debug"]) {
    const candidate = path.join(repoRoot, "target", profile, binName);
    if (isFile(candidate)) {
      return candidate;
    }
  }
  const cached = findCachedDaemon(
    options.cacheDir === undefined ? {} : { cacheDir: options.cacheDir },
  );
  if (cached !== null) {
    return cached;
  }
  throw new WayboundLaunchError(
    `${binName} binary not found on PATH, in target/{release,debug}, or in ~/.cache/waybound ` +
      "(set WAYBOUND_DAEMON_BIN, build with `cargo build -p waybound-daemon`, or call downloadDaemonBinary())",
  );
}

/** Minimal `fetch` signature used by the downloader (injectable for tests). */
export type FetchLike = (url: string, init: { signal: AbortSignal }) => Promise<Response>;

async function downloadBounded(
  url: string,
  maxBytes: number,
  fetchImpl: FetchLike,
): Promise<{ data: Buffer; sha256: string }> {
  if (!url.startsWith("https://")) {
    throw new Error(`refusing non-HTTPS download URL: ${JSON.stringify(url)}`);
  }
  const response = await fetchImpl(url, { signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS) });
  if (response.url !== "" && !response.url.startsWith("https://")) {
    throw new Error(`refusing download redirected to non-HTTPS URL: ${response.url}`);
  }
  if (!response.ok) {
    throw new Error(`download failed with HTTP ${response.status}: ${url}`);
  }
  if (response.body === null) {
    throw new Error(`download returned no body: ${url}`);
  }
  const hash = createHash("sha256");
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = response.body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      total += value.byteLength;
      if (total > maxBytes) {
        throw new Error(`download exceeded maximum allowed size (${maxBytes} bytes): ${url}`);
      }
      hash.update(value);
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  return { data: Buffer.concat(chunks), sha256: hash.digest("hex") };
}

function readCString(block: Buffer, start: number, length: number): string {
  const field = block.subarray(start, start + length);
  const nul = field.indexOf(0);
  return field.subarray(0, nul === -1 ? field.length : nul).toString("utf8");
}

function readTarSize(block: Buffer): number {
  const field = block.subarray(124, 136);
  const first = field[0] ?? 0;
  if (first & 0x80) {
    // GNU base-256 encoding.
    let size = 0;
    for (let i = 1; i < field.length; i += 1) {
      size = size * 256 + (field[i] ?? 0);
    }
    return size;
  }
  const text = readCString(block, 124, 12).trim();
  const size = text === "" ? 0 : Number.parseInt(text, 8);
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new Error("corrupt tar header size");
  }
  return size;
}

function parsePaxPath(data: Buffer): string | null {
  let found: string | null = null;
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space === -1) {
      break;
    }
    const len = Number.parseInt(data.subarray(offset, space).toString("utf8"), 10);
    if (!Number.isSafeInteger(len) || len <= 0 || offset + len > data.length) {
      break;
    }
    const record = data.subarray(space + 1, offset + len - 1).toString("utf8");
    const eq = record.indexOf("=");
    if (eq !== -1 && record.slice(0, eq) === "path") {
      found = record.slice(eq + 1);
    }
    offset += len;
  }
  return found;
}

/**
 * Return the bytes of the regular file `waybound-daemon[.exe]` (or `./waybound-daemon[.exe]`)
 * from an uncompressed tar archive. Handles ustar prefixes, pax `path` overrides and GNU long
 * names; every other entry is skipped.
 */
export function extractDaemonFromTar(tar: Buffer, binName: string = daemonFilename()): Buffer {
  const validNames = new Set([binName, `./${binName}`]);
  let offset = 0;
  let nextName: string | null = null;
  while (offset + TAR_BLOCK <= tar.length) {
    const header = tar.subarray(offset, offset + TAR_BLOCK);
    if (header.every((b) => b === 0)) {
      break;
    }
    const size = readTarSize(header);
    const type = String.fromCharCode(header[156] ?? 0);
    const dataStart = offset + TAR_BLOCK;
    const dataEnd = dataStart + size;
    if (dataEnd > tar.length) {
      throw new Error("truncated tar archive");
    }
    const data = tar.subarray(dataStart, dataEnd);
    offset = dataStart + Math.ceil(size / TAR_BLOCK) * TAR_BLOCK;

    if (type === "x") {
      nextName = parsePaxPath(data) ?? nextName;
      continue;
    }
    if (type === "L") {
      nextName = readCString(data, 0, data.length);
      continue;
    }
    if (type === "g") {
      continue;
    }
    let name = readCString(header, 0, 100);
    if (header.subarray(257, 262).toString("latin1") === "ustar") {
      const prefix = readCString(header, 345, 155);
      if (prefix !== "") {
        name = `${prefix}/${name}`;
      }
    }
    if (nextName !== null) {
      name = nextName;
      nextName = null;
    }
    if (!validNames.has(name)) {
      continue;
    }
    if (type !== "0" && type !== "\0") {
      throw new Error("archive missing regular file waybound-daemon");
    }
    if (size > MAX_BINARY_BYTES) {
      throw new Error(`extracted binary exceeds size cap (${MAX_BINARY_BYTES} bytes)`);
    }
    return Buffer.from(data);
  }
  throw new Error("archive missing regular file waybound-daemon");
}

/** Parse a `sha256sum`-style checksum file and return the lowercase hex digest. */
export function parseChecksumFile(text: string, artifact: string): string {
  const expected = (text.trim().split(/\s+/)[0] ?? "").toLowerCase();
  if (!SHA256_RE.test(expected)) {
    throw new Error(`invalid SHA-256 checksum file for ${artifact}.tar.gz`);
  }
  return expected;
}

export interface DownloadOptions extends HostInfo {
  /** Release tag. Default `DEFAULT_VERSION`. */
  readonly version?: string;
  /** GitHub `owner/repo`. Default `Sekinal/waybound`. */
  readonly repo?: string;
  /** Re-download even if the cached binary exists. */
  readonly force?: boolean;
  /** Cache directory. Default `~/.cache/waybound`. */
  readonly cacheDir?: string;
  /** `fetch` implementation. Default `globalThis.fetch`. */
  readonly fetch?: FetchLike;
}

/**
 * Download the prebuilt daemon for this host from GitHub Releases, verify the tarball against
 * the published `.sha256` file, and atomically install it into the cache. Returns its path.
 */
export async function downloadDaemonBinary(options: DownloadOptions = {}): Promise<string> {
  const repo = options.repo ?? DEFAULT_REPO;
  const version = options.version ?? DEFAULT_VERSION;
  if (!SAFE_REPO_RE.test(repo)) {
    throw new Error(`invalid GitHub repository slug: ${JSON.stringify(repo)}`);
  }
  const [owner = "", repoName = ""] = repo.split("/", 2);
  if ([".", ".."].includes(owner) || [".", ".."].includes(repoName)) {
    throw new Error(`invalid GitHub repository slug: ${JSON.stringify(repo)}`);
  }
  const platform = options.platform ?? process.platform;
  const dest = cachedDaemonPath(version, {
    platform,
    ...(options.cacheDir === undefined ? {} : { cacheDir: options.cacheDir }),
  });
  if (isFile(dest) && !options.force) {
    return dest;
  }

  const artifact = platformArtifactName({
    platform,
    ...(options.arch === undefined ? {} : { arch: options.arch }),
  });
  const baseUrl = `https://github.com/${repo}/releases/download/${version}`;
  const tarUrl = `${baseUrl}/${artifact}.tar.gz`;
  const shaUrl = `${baseUrl}/${artifact}.tar.gz.sha256`;
  const fetchImpl: FetchLike = options.fetch ?? ((url, init) => fetch(url, init));

  const tarball = await downloadBounded(tarUrl, MAX_TARBALL_BYTES, fetchImpl);
  const shaFile = await downloadBounded(shaUrl, MAX_SHA_BYTES, fetchImpl);
  const expected = parseChecksumFile(shaFile.data.toString("utf8"), artifact);
  if (tarball.sha256 !== expected) {
    throw new Error(
      `SHA-256 mismatch for ${artifact}.tar.gz: expected ${expected}, got ${tarball.sha256}`,
    );
  }

  let tar: Buffer;
  try {
    // Generous room for tar headers around a binary of at most MAX_BINARY_BYTES.
    tar = gunzipSync(tarball.data, { maxOutputLength: MAX_BINARY_BYTES + 16 * 1024 * 1024 });
  } catch (err) {
    throw new Error(`could not decompress ${artifact}.tar.gz`, { cause: err });
  }
  const binary = extractDaemonFromTar(tar, daemonFilename(platform));

  const destDir = path.dirname(dest);
  await mkdir(destDir, { recursive: true });
  const staged = path.join(destDir, `.waybound-daemon-${randomUUID()}`);
  try {
    await writeFile(staged, binary, { mode: 0o755, flag: "wx" });
    await chmod(staged, 0o755);
    await rename(staged, dest);
  } catch (err) {
    await unlink(staged).catch(() => undefined);
    throw err;
  }
  return dest;
}

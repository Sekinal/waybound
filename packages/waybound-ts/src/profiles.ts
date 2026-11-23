/**
 * Fast copy-on-write Chrome profile store and snapshot archiving (`ProfileStore`).
 *
 * Mirrors the Python SDK's `ProfileStore` with zero runtime dependencies:
 * - Excludes ephemeral Chrome lock, socket, crash, and cache artifacts when cloning or archiving.
 * - Uses OS copy-on-write (`cp -c -R` on macOS APFS, `cp -a --reflink=auto` on Linux) with a
 *   portable recursive fallback.
 * - Streams `.tar.gz` snapshots using `node:zlib` with strict path-traversal, symlink/hardlink,
 *   and decompressed size-cap enforcement.
 */

import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { createReadStream, createWriteStream, type Dirent } from "node:fs";
import {
  chmod,
  copyFile,
  type FileHandle,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  rename,
  rm,
  unlink,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { createGunzip, createGzip } from "node:zlib";

export const DEFAULT_MAX_SNAPSHOT_BYTES = 512 * 1024 * 1024;
const MAX_PROFILE_NAME_LEN = 255;
const TAR_BLOCK_SIZE = 512;
const MAX_METADATA_BLOCK_BYTES = 1024 * 1024;
const MAX_OCTAL_SIZE = 0o77777777777;
const SAFE_PROFILE_NAME_RE = /^[A-Za-z0-9._-]+$/;
const WINDOWS_DRIVE_RE = /^[A-Za-z]:/;

/** Chrome ephemeral lock, crash, and cache names excluded from clones and snapshots. */
export const EXCLUDED_PROFILE_NAMES: ReadonlySet<string> = new Set([
  "SingletonLock",
  "SingletonCookie",
  "SingletonSocket",
  "LOCK",
  "lockfile",
  "Crashpad",
  "BrowserMetrics",
  "ShaderCache",
  "GrShaderCache",
  "GraphiteDawnCache",
  "Code Cache",
  "GPUCache",
  "DawnCache",
  "Cache",
  "Cache_Data",
]);

/** Options for `ProfileStore.clone()`. */
export interface CloneProfileOptions {
  /** Destination directory. When omitted, a new temporary directory is created. */
  readonly destDir?: string;
  /** Prefer OS copy-on-write cloning (`cp -c -R` / `cp -a --reflink=auto`). Default `true`. */
  readonly preferCow?: boolean;
}

/** Options for `ProfileStore.importSnapshot()`. */
export interface ImportSnapshotOptions {
  /** Replace an existing profile with the same name. Default `false`. */
  readonly overwrite?: boolean;
  /** Maximum total extracted bytes allowed. Default `DEFAULT_MAX_SNAPSHOT_BYTES` (512 MiB). */
  readonly maxBytes?: number;
}

/** Validate that `name` is a safe single-segment profile identifier. */
export function validateProfileName(name: string): string {
  if (
    name.length === 0 ||
    name.length > MAX_PROFILE_NAME_LEN ||
    name.startsWith(".") ||
    name.includes("..") ||
    !SAFE_PROFILE_NAME_RE.test(name)
  ) {
    throw new Error(`invalid profile name: ${JSON.stringify(name)}`);
  }
  return name;
}

function isExcludedName(name: string): boolean {
  return EXCLUDED_PROFILE_NAMES.has(name);
}

async function lstatKind(target: string): Promise<"file" | "dir" | "other" | null> {
  try {
    const st = await lstat(target);
    if (st.isFile()) {
      return "file";
    }
    if (st.isDirectory()) {
      return "dir";
    }
    return "other";
  } catch {
    return null;
  }
}

async function runCowCp(sources: readonly string[], destDir: string): Promise<boolean> {
  if (sources.length === 0) {
    return true;
  }
  let args: string[];
  if (process.platform === "darwin") {
    args = ["-c", "-R", "--", ...sources, destDir];
  } else if (process.platform === "linux") {
    args = ["-a", "--reflink=auto", "--", ...sources, destDir];
  } else {
    return false;
  }

  return await new Promise<boolean>((resolve) => {
    const child = spawn("cp", args, { stdio: "ignore" });
    child.on("error", () => resolve(false));
    child.on("close", (code) => resolve(code === 0));
  });
}

async function copyDirCow(src: string, dst: string, depth: number = 0): Promise<boolean> {
  await mkdir(dst, { recursive: true });
  const entries = await readdir(src);
  const batch: string[] = [];
  const subdirsToRecurse: Array<{ readonly src: string; readonly dst: string }> = [];

  for (const name of entries) {
    if (isExcludedName(name)) {
      continue;
    }
    const entryPath = path.join(src, name);
    const kind = await lstatKind(entryPath);
    if (kind === null || kind === "other") {
      continue;
    }
    if (kind === "dir" && depth === 0) {
      // Recurse into top-level profile subdirs (e.g. `Default/`, `Profile 1/`) so large
      // nested caches like `Default/Cache` are skipped before invoking `cp`.
      subdirsToRecurse.push({ src: entryPath, dst: path.join(dst, name) });
    } else {
      batch.push(entryPath);
    }
  }

  if (batch.length > 0 && !(await runCowCp(batch, dst))) {
    return false;
  }

  for (const child of subdirsToRecurse) {
    if (!(await copyDirCow(child.src, child.dst, depth + 1))) {
      return false;
    }
  }
  return true;
}

async function stripExcludedEntries(root: string): Promise<void> {
  const entries = await readdir(root);
  for (const name of entries) {
    const entryPath = path.join(root, name);
    const kind = await lstatKind(entryPath);
    if (kind === null) {
      continue;
    }
    if (isExcludedName(name) || kind === "other") {
      await rm(entryPath, { recursive: true, force: true });
      continue;
    }
    if (kind === "dir") {
      await stripExcludedEntries(entryPath);
    }
  }
}

async function clearDirectory(directory: string): Promise<void> {
  const entries = await readdir(directory);
  for (const name of entries) {
    await rm(path.join(directory, name), { recursive: true, force: true });
  }
}

async function copyDirFallback(src: string, dst: string): Promise<void> {
  await mkdir(dst, { recursive: true });
  const entries = await readdir(src);
  for (const name of entries) {
    if (isExcludedName(name)) {
      continue;
    }
    const srcEntry = path.join(src, name);
    const dstEntry = path.join(dst, name);
    const kind = await lstatKind(srcEntry);
    if (kind === "dir") {
      await copyDirFallback(srcEntry, dstEntry);
    } else if (kind === "file") {
      await copyFile(srcEntry, dstEntry);
    }
  }
}

// ---------------------------------------------------------------------------
// Minimal zero-dependency USTAR/PAX tar writer and streaming reader
// ---------------------------------------------------------------------------

function writeOctal(buf: Buffer, offset: number, length: number, value: number): void {
  const digits = length - 1;
  const octal = Math.max(0, Math.floor(value)).toString(8).padStart(digits, "0");
  buf.write(octal.slice(-digits), offset, digits, "ascii");
  buf[offset + digits] = 0;
}

function finalizeTarHeader(header: Buffer): Buffer {
  header.fill(0x20, 148, 156);
  let sum = 0;
  for (const byte of header) {
    sum += byte;
  }
  const chk = sum.toString(8).padStart(6, "0");
  header.write(chk, 148, 6, "ascii");
  header[154] = 0;
  header[155] = 0x20;
  return header;
}

function encodePaxRecord(key: string, value: string): Buffer {
  const suffix = ` ${key}=${value}\n`;
  const suffixLen = Buffer.byteLength(suffix, "utf8");
  let total = suffixLen + 1;
  for (;;) {
    const digits = String(total).length;
    const next = digits + suffixLen;
    if (next === total) {
      break;
    }
    total = next;
  }
  return Buffer.from(`${total}${suffix}`, "utf8");
}

function createUstarHeader(
  posixName: string,
  size: number,
  mode: number,
  mtimeSec: number,
  typeFlag: "0" | "5" | "x",
): Buffer {
  const header = Buffer.alloc(TAR_BLOCK_SIZE);
  const nameBytes = Buffer.from(posixName, "utf8");
  nameBytes.copy(header, 0, 0, Math.min(nameBytes.length, 100));
  writeOctal(header, 100, 8, mode & 0o7777);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, size <= MAX_OCTAL_SIZE ? size : 0);
  writeOctal(header, 136, 12, mtimeSec);
  header[156] = typeFlag.charCodeAt(0);
  header.write("ustar\0", 257, 6, "ascii");
  header.write("00", 263, 2, "ascii");
  return finalizeTarHeader(header);
}

function isPureAscii(text: string): boolean {
  for (let i = 0; i < text.length; i += 1) {
    if (text.charCodeAt(i) > 0x7f) {
      return false;
    }
  }
  return true;
}

async function writeToStream(stream: NodeJS.WritableStream, chunk: Buffer): Promise<void> {
  if (stream.write(chunk)) {
    return;
  }
  await new Promise<void>((resolve, reject) => {
    const onDrain = (): void => {
      cleanup();
      resolve();
    };
    const onError = (err: Error): void => {
      cleanup();
      reject(err);
    };
    const cleanup = (): void => {
      stream.off("drain", onDrain);
      stream.off("error", onError);
    };
    stream.once("drain", onDrain);
    stream.once("error", onError);
  });
}

async function writeTarEntryHeader(
  out: NodeJS.WritableStream,
  posixName: string,
  size: number,
  mode: number,
  mtimeSec: number,
  typeFlag: "0" | "5",
): Promise<void> {
  const needsPax =
    Buffer.byteLength(posixName, "utf8") > 100 || !isPureAscii(posixName) || size > MAX_OCTAL_SIZE;
  if (needsPax) {
    const records: Buffer[] = [encodePaxRecord("path", posixName)];
    if (size > MAX_OCTAL_SIZE) {
      records.push(encodePaxRecord("size", String(size)));
    }
    const paxData = Buffer.concat(records);
    const paxHeader = createUstarHeader("PaxHeader", paxData.length, 0o644, mtimeSec, "x");
    await writeToStream(out, paxHeader);
    await writeToStream(out, paxData);
    const pad = (TAR_BLOCK_SIZE - (paxData.length % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;
    if (pad > 0) {
      await writeToStream(out, Buffer.alloc(pad));
    }
  }
  const fallbackName = posixName.slice(0, 100);
  const header = createUstarHeader(fallbackName, size, mode, mtimeSec, typeFlag);
  await writeToStream(out, header);
}

async function writeDirectoryToTar(
  out: NodeJS.WritableStream,
  rootDir: string,
  currentDir: string,
): Promise<void> {
  const entries = (await readdir(currentDir)).sort();
  for (const name of entries) {
    if (isExcludedName(name)) {
      continue;
    }
    const fullPath = path.join(currentDir, name);
    let st: Awaited<ReturnType<typeof lstat>>;
    try {
      st = await lstat(fullPath);
    } catch {
      continue;
    }
    if (!st.isDirectory() && !st.isFile()) {
      continue;
    }
    const relPosix = path.relative(rootDir, fullPath).split(path.sep).join("/");
    const mtimeSec = Math.floor(st.mtimeMs / 1000);
    if (st.isDirectory()) {
      await writeTarEntryHeader(out, `${relPosix}/`, 0, st.mode & 0o777, mtimeSec, "5");
      await writeDirectoryToTar(out, rootDir, fullPath);
    } else {
      await writeTarEntryHeader(out, relPosix, st.size, st.mode & 0o777, mtimeSec, "0");
      let written = 0;
      for await (const rawChunk of createReadStream(fullPath)) {
        const buf = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
        written += buf.length;
        await writeToStream(out, buf);
      }
      if (written !== st.size) {
        throw new Error(`file size changed while archiving: ${fullPath}`);
      }
      const pad = (TAR_BLOCK_SIZE - (st.size % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;
      if (pad > 0) {
        await writeToStream(out, Buffer.alloc(pad));
      }
    }
  }
}

function readCString(block: Buffer, start: number, length: number): string {
  const field = block.subarray(start, start + length);
  const nul = field.indexOf(0);
  return field.subarray(0, nul === -1 ? field.length : nul).toString("utf8");
}

function readTarOctal(block: Buffer, start: number, length: number): number {
  const text = readCString(block, start, length).trim();
  if (text === "") {
    return 0;
  }
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("corrupt tar header octal field");
  }
  return value;
}

function readTarSize(block: Buffer): number {
  const field = block.subarray(124, 136);
  const first = field[0] ?? 0;
  if (first & 0x80) {
    let size = 0;
    for (let i = 1; i < field.length; i += 1) {
      size = size * 256 + (field[i] ?? 0);
    }
    if (!Number.isSafeInteger(size) || size < 0) {
      throw new Error("corrupt tar header base-256 size");
    }
    return size;
  }
  return readTarOctal(block, 124, 12);
}

function verifyTarChecksum(header: Buffer): void {
  const expected = readTarOctal(header, 148, 8);
  let unsignedSum = 0;
  for (let i = 0; i < TAR_BLOCK_SIZE; i += 1) {
    unsignedSum += i >= 148 && i < 156 ? 0x20 : (header[i] ?? 0);
  }
  if (unsignedSum !== expected) {
    throw new Error("corrupt tar header checksum");
  }
}

function parsePaxRecords(data: Buffer): { path?: string; size?: number } {
  const result: { path?: string; size?: number } = {};
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
    if (eq !== -1) {
      const key = record.slice(0, eq);
      const val = record.slice(eq + 1);
      if (key === "path") {
        result.path = val;
      } else if (key === "size") {
        const parsedSize = Number.parseInt(val, 10);
        if (!Number.isSafeInteger(parsedSize) || parsedSize < 0) {
          throw new Error("corrupt PAX size record");
        }
        result.size = parsedSize;
      }
    }
    offset += len;
  }
  return result;
}

function validateArchiveMemberPath(rawName: string): readonly string[] | null {
  if (rawName.includes("\0")) {
    throw new Error(`archive member contains NUL byte: ${JSON.stringify(rawName)}`);
  }
  if (rawName.startsWith("/") || rawName.startsWith("\\") || WINDOWS_DRIVE_RE.test(rawName)) {
    throw new Error(`archive member uses absolute path: ${JSON.stringify(rawName)}`);
  }
  let normalized = rawName.replaceAll("\\", "/");
  while (normalized.startsWith("./")) {
    normalized = normalized.slice(2);
  }
  while (normalized.endsWith("/")) {
    normalized = normalized.slice(0, -1);
  }
  if (normalized === "" || normalized === ".") {
    return null;
  }
  const parts = normalized.split("/");
  for (const part of parts) {
    if (part === "" || part === "." || part === "..") {
      throw new Error(`archive member contains path traversal: ${JSON.stringify(rawName)}`);
    }
  }
  return parts;
}

interface TarExtractState {
  phase: "header" | "file" | "meta" | "pad" | "done";
  headerBuf: Buffer;
  headerFilled: number;
  remainingData: number;
  remainingPad: number;
  metaType: "x" | "L" | "g" | null;
  metaChunks: Buffer[];
  nextPaxPath: string | null;
  nextPaxSize: number | null;
  activeHandle: FileHandle | null;
  activeFilePath: string | null;
  activeFileMode: number;
  totalBytes: number;
  zeroBlocks: number;
}

async function extractTarGzToStaging(
  archivePath: string,
  stagingDir: string,
  maxBytes: number,
): Promise<void> {
  const stagingResolved = path.resolve(stagingDir);
  const stagingPrefix = `${stagingResolved}${path.sep}`;
  const state: TarExtractState = {
    phase: "header",
    headerBuf: Buffer.alloc(TAR_BLOCK_SIZE),
    headerFilled: 0,
    remainingData: 0,
    remainingPad: 0,
    metaType: null,
    metaChunks: [],
    nextPaxPath: null,
    nextPaxSize: null,
    activeHandle: null,
    activeFilePath: null,
    activeFileMode: 0o644,
    totalBytes: 0,
    zeroBlocks: 0,
  };

  const closeActiveFile = async (): Promise<void> => {
    if (state.activeHandle !== null) {
      const fh = state.activeHandle;
      const fp = state.activeFilePath;
      const mode = state.activeFileMode;
      state.activeHandle = null;
      state.activeFilePath = null;
      await fh.close();
      if (fp !== null) {
        await chmod(fp, (mode & 0o755) | 0o600);
      }
    }
  };

  const processHeader = async (header: Buffer): Promise<void> => {
    if (header.every((b) => b === 0)) {
      state.zeroBlocks += 1;
      if (state.zeroBlocks >= 2) {
        state.phase = "done";
      }
      return;
    }
    state.zeroBlocks = 0;
    verifyTarChecksum(header);

    const type = String.fromCharCode(header[156] ?? 0);
    let size = readTarSize(header);
    const mode = readTarOctal(header, 100, 8);
    const pad = (TAR_BLOCK_SIZE - (size % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;

    if (type === "x" || type === "L" || type === "g") {
      if (size > MAX_METADATA_BLOCK_BYTES) {
        throw new Error("tar metadata header exceeds size limit");
      }
      state.metaType = type;
      state.metaChunks = [];
      state.remainingData = size;
      state.remainingPad = pad;
      state.phase = size > 0 ? "meta" : pad > 0 ? "pad" : "header";
      return;
    }

    if (type !== "0" && type !== "\0" && type !== "5") {
      throw new Error(`archive member has disallowed type (${JSON.stringify(type)})`);
    }

    let name = readCString(header, 0, 100);
    if (header.subarray(257, 262).toString("latin1") === "ustar") {
      const prefix = readCString(header, 345, 155);
      if (prefix !== "") {
        name = `${prefix}/${name}`;
      }
    }
    if (state.nextPaxPath !== null) {
      name = state.nextPaxPath;
      state.nextPaxPath = null;
    }
    if (state.nextPaxSize !== null) {
      size = state.nextPaxSize;
      state.nextPaxSize = null;
    }

    const parts = validateArchiveMemberPath(name);
    const skip = parts === null || parts.some((p) => isExcludedName(p));

    if (type === "5") {
      if (size > 0) {
        throw new Error(`archive directory member has non-zero size: ${JSON.stringify(name)}`);
      }
      if (!skip && parts !== null) {
        const destPath = path.resolve(stagingResolved, ...parts);
        if (!destPath.startsWith(stagingPrefix)) {
          throw new Error(`archive member escapes staging directory: ${JSON.stringify(name)}`);
        }
        await mkdir(destPath, { recursive: true });
      }
      state.remainingPad = 0;
      state.remainingData = 0;
      state.phase = "header";
      return;
    }

    if (state.totalBytes + size > maxBytes) {
      throw new Error(`snapshot exceeds maxBytes limit (${maxBytes} bytes)`);
    }

    const filePad = (TAR_BLOCK_SIZE - (size % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;
    state.remainingData = size;
    state.remainingPad = filePad;

    if (!skip && parts !== null) {
      const destPath = path.resolve(stagingResolved, ...parts);
      if (!destPath.startsWith(stagingPrefix)) {
        throw new Error(`archive member escapes staging directory: ${JSON.stringify(name)}`);
      }
      await mkdir(path.dirname(destPath), { recursive: true });
      state.activeHandle = await open(destPath, "w");
      state.activeFilePath = destPath;
      state.activeFileMode = mode;
      if (size === 0) {
        await closeActiveFile();
      }
    }
    state.phase = size > 0 ? "file" : filePad > 0 ? "pad" : "header";
  };

  const fileStream = createReadStream(archivePath);
  const gunzip = createGunzip();
  fileStream.on("error", (err) => {
    gunzip.destroy(err);
  });
  fileStream.pipe(gunzip);

  try {
    for await (const rawChunk of gunzip) {
      const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
      let pos = 0;

      while (pos < chunk.length && state.phase !== "done") {
        if (state.phase === "header") {
          const take = Math.min(TAR_BLOCK_SIZE - state.headerFilled, chunk.length - pos);
          chunk.copy(state.headerBuf, state.headerFilled, pos, pos + take);
          state.headerFilled += take;
          pos += take;
          if (state.headerFilled === TAR_BLOCK_SIZE) {
            state.headerFilled = 0;
            await processHeader(state.headerBuf);
          }
        } else if (state.phase === "meta") {
          const take = Math.min(state.remainingData, chunk.length - pos);
          state.metaChunks.push(Buffer.from(chunk.subarray(pos, pos + take)));
          state.remainingData -= take;
          pos += take;
          if (state.remainingData === 0) {
            const metaBuf = Buffer.concat(state.metaChunks);
            if (state.metaType === "x") {
              const parsed = parsePaxRecords(metaBuf);
              if (parsed.path !== undefined) {
                state.nextPaxPath = parsed.path;
              }
              if (parsed.size !== undefined) {
                state.nextPaxSize = parsed.size;
              }
            } else if (state.metaType === "L") {
              state.nextPaxPath = readCString(metaBuf, 0, metaBuf.length);
            }
            state.metaChunks = [];
            state.metaType = null;
            state.phase = state.remainingPad > 0 ? "pad" : "header";
          }
        } else if (state.phase === "file") {
          const take = Math.min(state.remainingData, chunk.length - pos);
          const slice = chunk.subarray(pos, pos + take);
          state.totalBytes += take;
          if (state.totalBytes > maxBytes) {
            throw new Error(`snapshot exceeds maxBytes limit (${maxBytes} bytes)`);
          }
          if (state.activeHandle !== null) {
            await state.activeHandle.write(slice);
          }
          state.remainingData -= take;
          pos += take;
          if (state.remainingData === 0) {
            await closeActiveFile();
            state.phase = state.remainingPad > 0 ? "pad" : "header";
          }
        } else if (state.phase === "pad") {
          const take = Math.min(state.remainingPad, chunk.length - pos);
          state.remainingPad -= take;
          pos += take;
          if (state.remainingPad === 0) {
            state.phase = "header";
          }
        }
      }
      if (state.phase === "done") {
        break;
      }
    }

    if (state.phase === "file" || state.phase === "meta" || state.headerFilled > 0) {
      throw new Error("truncated tar archive");
    }
  } finally {
    fileStream.destroy();
    gunzip.destroy();
    if (state.activeHandle !== null) {
      await state.activeHandle.close().catch(() => undefined);
    }
  }
}

/**
 * Manage named Chrome `--user-data-dir` profiles with fast CoW cloning and `.tar.gz` snapshots.
 */
export class ProfileStore {
  readonly rootDir: string;

  constructor(rootDir: string) {
    this.rootDir = rootDir;
  }

  /** Return the validated filesystem path for a named profile. */
  profilePath(name: string): string {
    return path.join(this.rootDir, validateProfileName(name));
  }

  /** Return sorted names of stored profiles. */
  async listProfiles(): Promise<string[]> {
    let entries: Dirent[];
    try {
      entries = await readdir(this.rootDir, { withFileTypes: true });
    } catch {
      return [];
    }
    const names: string[] = [];
    for (const entry of entries) {
      if (entry.name.startsWith(".") || !entry.isDirectory() || entry.isSymbolicLink()) {
        continue;
      }
      try {
        validateProfileName(entry.name);
      } catch {
        continue;
      }
      names.push(entry.name);
    }
    return names.sort();
  }

  /** Return `true` if a stored profile with `name` exists as a real directory. */
  async exists(name: string): Promise<boolean> {
    const target = this.profilePath(name);
    return (await lstatKind(target)) === "dir";
  }

  /** Delete a stored profile if it exists (idempotent; validates `name`). */
  async delete(name: string): Promise<void> {
    const target = this.profilePath(name);
    await rm(target, { recursive: true, force: true });
  }

  private async resolveSource(source: string): Promise<string> {
    const isPath = source.includes("/") || source.includes("\\") || path.isAbsolute(source);
    const resolved = isPath ? source : this.profilePath(source);
    let st: Awaited<ReturnType<typeof lstat>>;
    try {
      st = await lstat(resolved);
    } catch {
      throw new Error(`profile source directory not found: ${resolved}`);
    }
    if (!st.isDirectory()) {
      throw new Error(`profile source directory not found: ${resolved}`);
    }
    return resolved;
  }

  /**
   * Clone a named profile or explicit source directory, excluding ephemeral Chrome locks,
   * sockets, crash dumps, and caches.
   */
  async clone(source: string, options: CloneProfileOptions = {}): Promise<string> {
    const src = await this.resolveSource(source);
    const preferCow = options.preferCow ?? true;
    const createdTemp = options.destDir === undefined;
    const dest =
      options.destDir === undefined
        ? await mkdtemp(path.join(tmpdir(), "waybound-profile-"))
        : options.destDir;

    try {
      await mkdir(dest, { recursive: true });
      const srcResolved = path.resolve(src);
      const destResolved = path.resolve(dest);
      if (destResolved === srcResolved || destResolved.startsWith(`${srcResolved}${path.sep}`)) {
        throw new Error(`cannot clone profile into itself or a subdirectory: ${dest}`);
      }

      let copiedWithCow = false;
      if (preferCow && process.platform !== "win32") {
        copiedWithCow = await copyDirCow(src, dest);
        if (copiedWithCow) {
          await stripExcludedEntries(dest);
        } else {
          await clearDirectory(dest);
        }
      }

      if (!copiedWithCow) {
        await copyDirFallback(src, dest);
      }
    } catch (err) {
      if (createdTemp) {
        await rm(dest, { recursive: true, force: true }).catch(() => undefined);
      }
      throw err;
    }

    return dest;
  }

  /**
   * Clone `source` into a temporary directory, invoke `fn(clonedDir)`, and remove the clone
   * when `fn` resolves or rejects.
   */
  async withEphemeralClone<T>(
    source: string,
    fn: (profileDir: string) => Promise<T> | T,
    options: { readonly preferCow?: boolean } = {},
  ): Promise<T> {
    const cloned = await this.clone(source, {
      ...(options.preferCow === undefined ? {} : { preferCow: options.preferCow }),
    });
    try {
      return await fn(cloned);
    } finally {
      await rm(cloned, { recursive: true, force: true }).catch(() => undefined);
    }
  }

  /** Atomically export a profile directory to a `.tar.gz` snapshot archive. */
  async exportSnapshot(source: string, archivePath: string): Promise<string> {
    const src = await this.resolveSource(source);
    const parentDir = path.dirname(archivePath);
    await mkdir(parentDir, { recursive: true });
    const tmpPath = path.join(parentDir, `.waybound-snapshot-${randomUUID()}.tar.gz.tmp`);

    const gzip = createGzip();
    const fileOut = createWriteStream(tmpPath, { flags: "wx" });
    const finished = new Promise<void>((resolve, reject) => {
      fileOut.once("finish", resolve);
      fileOut.once("error", reject);
      gzip.once("error", reject);
    });
    finished.catch(() => undefined);
    gzip.pipe(fileOut);

    try {
      await writeDirectoryToTar(gzip, src, src);
      // Two 512-byte zero blocks terminate a POSIX tar archive.
      await writeToStream(gzip, Buffer.alloc(TAR_BLOCK_SIZE * 2));
      gzip.end();
      await finished;
      await rename(tmpPath, archivePath);
    } catch (err) {
      gzip.destroy();
      if (!fileOut.closed) {
        const closed = new Promise<void>((resolve) => {
          fileOut.once("close", resolve);
          fileOut.once("error", () => resolve());
        });
        fileOut.destroy();
        await closed;
      }
      await unlink(tmpPath).catch(() => undefined);
      throw err;
    }

    return archivePath;
  }

  /** Safely extract a `.tar.gz` snapshot archive into a named profile. */
  async importSnapshot(
    archivePath: string,
    name: string,
    options: ImportSnapshotOptions = {},
  ): Promise<string> {
    const validName = validateProfileName(name);
    const overwrite = options.overwrite ?? false;
    const maxBytes = options.maxBytes ?? DEFAULT_MAX_SNAPSHOT_BYTES;
    if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
      throw new Error(`maxBytes must be a positive integer, got ${maxBytes}`);
    }

    const archiveKind = await lstatKind(archivePath);
    if (archiveKind !== "file") {
      throw new Error(`snapshot archive not found: ${archivePath}`);
    }

    const target = path.join(this.rootDir, validName);
    const existingKind = await lstatKind(target);
    if (existingKind !== null && !overwrite) {
      throw new Error(`profile already exists: ${validName}`);
    }

    await mkdir(this.rootDir, { recursive: true });
    const staging = await mkdtemp(path.join(this.rootDir, `.${validName}-staging-`));
    try {
      await extractTarGzToStaging(archivePath, staging, maxBytes);
      await this.commitStagedProfile(staging, target, validName, overwrite);
    } catch (err) {
      await rm(staging, { recursive: true, force: true }).catch(() => undefined);
      throw err;
    }

    return target;
  }

  private async commitStagedProfile(
    staging: string,
    target: string,
    validName: string,
    overwrite: boolean,
  ): Promise<void> {
    const existingKind = await lstatKind(target);
    if (existingKind !== null) {
      if (!overwrite) {
        throw new Error(`profile already exists: ${validName}`);
      }
      const backup = path.join(this.rootDir, `.${validName}-old-${randomUUID()}`);
      await rename(target, backup);
      try {
        await rename(staging, target);
      } catch (err) {
        await rename(backup, target).catch(() => undefined);
        throw err;
      }
      await rm(backup, { recursive: true, force: true }).catch(() => undefined);
    } else {
      await rename(staging, target);
    }
  }
}

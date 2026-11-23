import assert from "node:assert/strict";
import { lstat, mkdir, mkdtemp, readdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { gzipSync } from "node:zlib";
import { EXCLUDED_PROFILE_NAMES, ProfileStore, validateProfileName } from "../src/index.js";

async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(path.join(tmpdir(), "waybound-ts-profiles-test-"));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function pathExists(p: string): Promise<boolean> {
  try {
    await lstat(p);
    return true;
  } catch {
    return false;
  }
}

async function populateMockChromeProfile(profileDir: string): Promise<void> {
  await mkdir(path.join(profileDir, "Default", "Local Storage", "leveldb"), { recursive: true });
  await mkdir(path.join(profileDir, "Default", "Cache"), { recursive: true });
  await mkdir(path.join(profileDir, "Default", "Cache_Data"), { recursive: true });
  await mkdir(path.join(profileDir, "Default", "Code Cache"), { recursive: true });
  await mkdir(path.join(profileDir, "Default", "GPUCache"), { recursive: true });
  await mkdir(path.join(profileDir, "Default", "DawnCache"), { recursive: true });
  await mkdir(path.join(profileDir, "Crashpad"), { recursive: true });
  await mkdir(path.join(profileDir, "ShaderCache"), { recursive: true });
  await mkdir(path.join(profileDir, "GrShaderCache"), { recursive: true });
  await mkdir(path.join(profileDir, "GraphiteDawnCache"), { recursive: true });
  await mkdir(path.join(profileDir, "BrowserMetrics"), { recursive: true });

  // Valuable session files that must survive clone / snapshot round-trips.
  await writeFile(path.join(profileDir, "Local State"), '{"os_crypt":{}}', "utf8");
  await writeFile(
    path.join(profileDir, "Default", "Preferences"),
    '{"profile":{"name":"Work"}}',
    "utf8",
  );
  await writeFile(
    path.join(profileDir, "Default", "Cookies"),
    Buffer.from("SQLite format 3\0cookie-data"),
  );
  await writeFile(
    path.join(profileDir, "Default", "Local Storage", "leveldb", "000003.log"),
    Buffer.from("leveldb-records"),
  );

  // Ephemeral lock / cache / crash artifacts that must be excluded.
  await symlink("mockhost-99999", path.join(profileDir, "SingletonLock"));
  await writeFile(path.join(profileDir, "SingletonCookie"), "cookie-lock", "utf8");
  await writeFile(path.join(profileDir, "SingletonSocket"), "socket-lock", "utf8");
  await writeFile(path.join(profileDir, "Crashpad", "dump.dmp"), Buffer.from("crash-dump"));
  await writeFile(path.join(profileDir, "ShaderCache", "shader.bin"), Buffer.from("shader-bytes"));
  await writeFile(path.join(profileDir, "GrShaderCache", "gr.bin"), Buffer.from("gr-bytes"));
  await writeFile(
    path.join(profileDir, "GraphiteDawnCache", "dawn.bin"),
    Buffer.from("graphite-bytes"),
  );
  await writeFile(path.join(profileDir, "BrowserMetrics", "metrics.pma"), Buffer.from("metrics"));
  await writeFile(path.join(profileDir, "Default", "LOCK"), "", "utf8");
  await writeFile(path.join(profileDir, "Default", "lockfile"), "", "utf8");
  await writeFile(path.join(profileDir, "Default", "Local Storage", "leveldb", "LOCK"), "", "utf8");
  await writeFile(path.join(profileDir, "Default", "Cache", "f_000001"), Buffer.alloc(4096, 0x78));
  await writeFile(
    path.join(profileDir, "Default", "Cache_Data", "data_0"),
    Buffer.alloc(4096, 0x79),
  );
  await writeFile(
    path.join(profileDir, "Default", "Code Cache", "js.bin"),
    Buffer.alloc(4096, 0x7a),
  );
  await writeFile(
    path.join(profileDir, "Default", "GPUCache", "gpu.bin"),
    Buffer.alloc(1024, 0x67),
  );
  await writeFile(
    path.join(profileDir, "Default", "DawnCache", "dawn.bin"),
    Buffer.alloc(1024, 0x64),
  );
}

async function assertCleanProfileCopy(dest: string): Promise<void> {
  assert.equal(await readFile(path.join(dest, "Local State"), "utf8"), '{"os_crypt":{}}');
  assert.equal(
    await readFile(path.join(dest, "Default", "Preferences"), "utf8"),
    '{"profile":{"name":"Work"}}',
  );
  assert.deepEqual(
    await readFile(path.join(dest, "Default", "Cookies")),
    Buffer.from("SQLite format 3\0cookie-data"),
  );
  assert.deepEqual(
    await readFile(path.join(dest, "Default", "Local Storage", "leveldb", "000003.log")),
    Buffer.from("leveldb-records"),
  );

  for (const excluded of EXCLUDED_PROFILE_NAMES) {
    assert.equal(await pathExists(path.join(dest, excluded)), false, `root ${excluded}`);
    assert.equal(
      await pathExists(path.join(dest, "Default", excluded)),
      false,
      `Default/${excluded}`,
    );
  }
  assert.equal(
    await pathExists(path.join(dest, "Default", "Local Storage", "leveldb", "LOCK")),
    false,
  );
}

function buildRawTarGz(
  entries: ReadonlyArray<{
    readonly name: string;
    readonly typeFlag?: string;
    readonly content?: Buffer;
    readonly linkname?: string;
  }>,
): Buffer {
  const chunks: Buffer[] = [];
  for (const entry of entries) {
    const content = entry.content ?? Buffer.alloc(0);
    const header = Buffer.alloc(512);
    header.write(entry.name, 0, Math.min(Buffer.byteLength(entry.name), 100), "utf8");
    header.write("0000644\0", 100, 8, "ascii");
    header.write("0000000\0", 108, 8, "ascii");
    header.write("0000000\0", 116, 8, "ascii");
    header.write(`${content.length.toString(8).padStart(11, "0")}\0`, 124, 12, "ascii");
    header.write("00000000000\0", 136, 12, "ascii");
    header.fill(0x20, 148, 156);
    header[156] = (entry.typeFlag ?? "0").charCodeAt(0);
    if (entry.linkname !== undefined) {
      header.write(entry.linkname, 157, Math.min(Buffer.byteLength(entry.linkname), 100), "utf8");
    }
    header.write("ustar\0", 257, 6, "ascii");
    header.write("00", 263, 2, "ascii");
    let sum = 0;
    for (const b of header) {
      sum += b;
    }
    header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
    chunks.push(header);
    if (content.length > 0) {
      chunks.push(content);
      const pad = (512 - (content.length % 512)) % 512;
      if (pad > 0) {
        chunks.push(Buffer.alloc(pad));
      }
    }
  }
  chunks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(chunks));
}

describe("ProfileStore", () => {
  it("validates profile names strictly", async () => {
    for (const valid of ["default", "work_1", "prod-us.west", "A0", "_lead", "-dash"]) {
      assert.equal(validateProfileName(valid), valid);
    }

    await withTempDir(async (dir) => {
      const store = new ProfileStore(dir);
      const invalidNames = [
        "",
        ".",
        "..",
        ".hidden",
        "a/b",
        "a\\b",
        "foo..bar",
        "../escape",
        "has space",
        "bad\0name",
        "a".repeat(256),
      ];
      for (const bad of invalidNames) {
        assert.throws(() => validateProfileName(bad), /invalid profile name/);
        assert.throws(() => store.profilePath(bad), /invalid profile name/);
        await assert.rejects(() => store.exists(bad), /invalid profile name/);
        await assert.rejects(() => store.delete(bad), /invalid profile name/);
      }
    });
  });

  it("lists, checks existence, and deletes profiles", async () => {
    await withTempDir(async (dir) => {
      const store = new ProfileStore(path.join(dir, "profiles"));
      assert.deepEqual(await store.listProfiles(), []);
      assert.equal(await store.exists("alpha"), false);

      await mkdir(store.profilePath("beta"), { recursive: true });
      await mkdir(store.profilePath("alpha"), { recursive: true });
      await mkdir(path.join(store.rootDir, ".staging-tmp"), { recursive: true });
      await writeFile(path.join(store.rootDir, "not-a-dir"), "file", "utf8");

      assert.deepEqual(await store.listProfiles(), ["alpha", "beta"]);
      assert.equal(await store.exists("alpha"), true);
      assert.equal(await store.exists("beta"), true);

      await store.delete("alpha");
      assert.equal(await store.exists("alpha"), false);
      assert.deepEqual(await store.listProfiles(), ["beta"]);
      // Idempotent delete on missing profile.
      await store.delete("alpha");
    });
  });

  for (const preferCow of [true, false]) {
    it(`clones profiles excluding ephemeral files (preferCow=${preferCow})`, async () => {
      await withTempDir(async (dir) => {
        const store = new ProfileStore(path.join(dir, "store"));
        const src = store.profilePath("chrome-main");
        await populateMockChromeProfile(src);

        const dest = path.join(dir, `cloned-${preferCow}`);
        const out = await store.clone("chrome-main", { destDir: dest, preferCow });
        assert.equal(out, dest);
        await assertCleanProfileCopy(dest);

        // Also clone from an explicit directory path into an auto-created temp dir.
        const tempClone = await store.clone(src, { preferCow });
        try {
          await assertCleanProfileCopy(tempClone);
        } finally {
          await rm(tempClone, { recursive: true, force: true });
        }
      });
    });
  }

  it("rejects cloning missing sources or into self/subdirectory", async () => {
    await withTempDir(async (dir) => {
      const store = new ProfileStore(path.join(dir, "store"));
      await assert.rejects(() => store.clone("missing"), /not found/);

      const src = store.profilePath("main");
      await mkdir(src, { recursive: true });
      await assert.rejects(
        () => store.clone("main", { destDir: src }),
        /cannot clone profile into itself/,
      );
      await assert.rejects(
        () => store.clone("main", { destDir: path.join(src, "nested") }),
        /cannot clone profile into itself/,
      );
    });
  });

  it("withEphemeralClone cleans up on return and on error", async () => {
    await withTempDir(async (dir) => {
      const store = new ProfileStore(path.join(dir, "store"));
      await populateMockChromeProfile(store.profilePath("main"));

      let capturedPath = "";
      const result = await store.withEphemeralClone("main", async (cloned) => {
        capturedPath = cloned;
        await assertCleanProfileCopy(cloned);
        return "ok";
      });
      assert.equal(result, "ok");
      assert.equal(await pathExists(capturedPath), false);

      let errPath = "";
      await assert.rejects(
        () =>
          store.withEphemeralClone("main", async (cloned) => {
            errPath = cloned;
            assert.equal(await pathExists(cloned), true);
            throw new Error("boom");
          }),
        /boom/,
      );
      assert.equal(await pathExists(errPath), false);
    });
  });

  it("round-trips exportSnapshot and importSnapshot including long PAX paths", async () => {
    await withTempDir(async (dir) => {
      const store = new ProfileStore(path.join(dir, "store"));
      const src = store.profilePath("source");
      await populateMockChromeProfile(src);

      // Add a path > 100 bytes to exercise PAX extended header writing & reading.
      const longRel = path.join(
        "Default",
        "Extensions",
        "a".repeat(40),
        "b".repeat(40),
        "manifest-very-long-filename.json",
      );
      await mkdir(path.dirname(path.join(src, longRel)), { recursive: true });
      await writeFile(path.join(src, longRel), '{"manifest_version":3}', "utf8");

      const archive = path.join(dir, "snapshots", "source.tar.gz");
      const exported = await store.exportSnapshot("source", archive);
      assert.equal(exported, archive);
      assert.deepEqual(await readdir(path.dirname(archive)), ["source.tar.gz"]);

      const restored = await store.importSnapshot(archive, "restored");
      assert.equal(restored, store.profilePath("restored"));
      assert.equal(await store.exists("restored"), true);
      await assertCleanProfileCopy(restored);
      assert.equal(await readFile(path.join(restored, longRel), "utf8"), '{"manifest_version":3}');
    });
  });

  it("enforces overwrite=false vs overwrite=true on importSnapshot", async () => {
    await withTempDir(async (dir) => {
      const store = new ProfileStore(path.join(dir, "store"));
      const v1 = store.profilePath("v1");
      await mkdir(v1, { recursive: true });
      await writeFile(path.join(v1, "marker.txt"), "version-1", "utf8");
      const snap1 = path.join(dir, "v1.tar.gz");
      await store.exportSnapshot("v1", snap1);

      const v2 = store.profilePath("v2");
      await mkdir(v2, { recursive: true });
      await writeFile(path.join(v2, "marker.txt"), "version-2", "utf8");
      const snap2 = path.join(dir, "v2.tar.gz");
      await store.exportSnapshot("v2", snap2);

      await store.importSnapshot(snap1, "active");
      assert.equal(
        await readFile(path.join(store.profilePath("active"), "marker.txt"), "utf8"),
        "version-1",
      );

      await assert.rejects(
        () => store.importSnapshot(snap2, "active", { overwrite: false }),
        /already exists/,
      );
      assert.equal(
        await readFile(path.join(store.profilePath("active"), "marker.txt"), "utf8"),
        "version-1",
      );

      await store.importSnapshot(snap2, "active", { overwrite: true });
      assert.equal(
        await readFile(path.join(store.profilePath("active"), "marker.txt"), "utf8"),
        "version-2",
      );
    });
  });

  it("rejects path traversal and absolute paths in tar archives", async () => {
    await withTempDir(async (dir) => {
      const store = new ProfileStore(path.join(dir, "store"));
      const evilNames = [
        "../evil.txt",
        "Default/../../escape.txt",
        "/etc/passwd",
        "\\Windows\\System32\\evil.dll",
        "C:/evil.txt",
      ];

      for (const evil of evilNames) {
        const archive = path.join(dir, "evil.tar.gz");
        await writeFile(archive, buildRawTarGz([{ name: evil, content: Buffer.from("pwned") }]));
        await assert.rejects(
          () => store.importSnapshot(archive, "victim"),
          /path traversal|absolute path/,
        );
        assert.equal(await store.exists("victim"), false);
        assert.equal(await pathExists(path.join(dir, "evil.txt")), false);
      }
    });
  });

  it("rejects symlinks, hardlinks, and special device entries in tar archives", async () => {
    await withTempDir(async (dir) => {
      const store = new ProfileStore(path.join(dir, "store"));

      const symArchive = path.join(dir, "sym.tar.gz");
      await writeFile(
        symArchive,
        buildRawTarGz([{ name: "link", typeFlag: "2", linkname: "/etc/passwd" }]),
      );
      await assert.rejects(() => store.importSnapshot(symArchive, "sym-victim"), /disallowed type/);

      const hardArchive = path.join(dir, "hard.tar.gz");
      await writeFile(
        hardArchive,
        buildRawTarGz([{ name: "hard", typeFlag: "1", linkname: "target" }]),
      );
      await assert.rejects(
        () => store.importSnapshot(hardArchive, "hard-victim"),
        /disallowed type/,
      );

      const fifoArchive = path.join(dir, "fifo.tar.gz");
      await writeFile(fifoArchive, buildRawTarGz([{ name: "pipe", typeFlag: "6" }]));
      await assert.rejects(
        () => store.importSnapshot(fifoArchive, "fifo-victim"),
        /disallowed type/,
      );
    });
  });

  it("enforces maxBytes cap and cleans up staging directory on failure", async () => {
    await withTempDir(async (dir) => {
      const store = new ProfileStore(path.join(dir, "store"));
      const archive = path.join(dir, "large.tar.gz");
      await writeFile(
        archive,
        buildRawTarGz([
          { name: "chunk_0.bin", content: Buffer.alloc(512, 0x61) },
          { name: "chunk_1.bin", content: Buffer.alloc(512, 0x62) },
          { name: "chunk_2.bin", content: Buffer.alloc(512, 0x63) },
        ]),
      );

      await assert.rejects(
        () => store.importSnapshot(archive, "too-big", { maxBytes: 1024 }),
        /exceeds maxBytes/,
      );
      assert.equal(await store.exists("too-big"), false);
      assert.deepEqual(await readdir(store.rootDir), []);

      await assert.rejects(
        () => store.importSnapshot(archive, "bad-cap", { maxBytes: 0 }),
        /maxBytes must be a positive integer/,
      );

      const restored = await store.importSnapshot(archive, "fits", { maxBytes: 2048 });
      assert.deepEqual(await readFile(path.join(restored, "chunk_2.bin")), Buffer.alloc(512, 0x63));
    });
  });

  it("counts excluded entries toward maxBytes and rejects non-zero directory entries", async () => {
    await withTempDir(async (dir) => {
      const store = new ProfileStore(path.join(dir, "store"));
      const excludedArchive = path.join(dir, "excluded-bomb.tar.gz");
      await writeFile(
        excludedArchive,
        buildRawTarGz([
          { name: "Default/Cache/huge_0.bin", content: Buffer.alloc(512, 0x7a) },
          { name: "Default/Cache/huge_1.bin", content: Buffer.alloc(512, 0x7a) },
          { name: "Default/Cache/huge_2.bin", content: Buffer.alloc(512, 0x7a) },
        ]),
      );

      await assert.rejects(
        () => store.importSnapshot(excludedArchive, "excluded-too-big", { maxBytes: 1024 }),
        /exceeds maxBytes/,
      );
      assert.equal(await store.exists("excluded-too-big"), false);
      assert.deepEqual(await readdir(store.rootDir), []);

      const dirPayloadArchive = path.join(dir, "dir-payload.tar.gz");
      await writeFile(
        dirPayloadArchive,
        buildRawTarGz([{ name: "Default/", typeFlag: "5", content: Buffer.alloc(64, 0x41) }]),
      );
      await assert.rejects(
        () => store.importSnapshot(dirPayloadArchive, "bad-dir"),
        /non-zero size/,
      );
      assert.equal(await store.exists("bad-dir"), false);
    });
  });
});

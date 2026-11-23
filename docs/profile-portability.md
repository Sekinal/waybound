# Portable Sessions: Exporting and Importing a Chrome Profile

`waybound` launches stock Chrome with a `--user-data-dir` (`LaunchOptions(profile_dir=...)`).
Everything a logged-in website needs lives in that directory, so "log in once, reuse the
session elsewhere" means "copy the right part of that directory to the other machine".
`waybound profile export` / `import` do this with no CDP, no extension, and no network
access. Cookie values are never decrypted, read or printed.

> **The bundle holds live session cookies.** Anyone with the file can use your logged-in
> sessions. `waybound` writes it with mode `0600`. Do not commit it, bake it into an image,
> attach it to CI logs or artifacts, or leave it on shared storage. Delete it when done.

## The short version

| Where you logged in | Where you restore | Expected result |
| --- | --- | --- |
| Any machine | **The same machine and OS user** | Expected to work (not verified with a real Chrome) |
| Linux, `password_store="basic"` (including any container) | Any Linux Chrome, including Podman/Docker containers | **Expected to work** (not verified with a real Chrome) |
| Linux desktop with GNOME Keyring / KWallet (Chrome's default there) | Another machine or container, or Chromium instead of Chrome on the same machine | No: cookies are encrypted with a key held in that desktop's keyring |
| macOS | Another Mac, Linux, a container, Windows | No: the key is in the source user's login Keychain |
| Windows | Anything else (and usually even another Windows user) | No: DPAPI and App-Bound Encryption tie the key to the user and machine |

If you work on macOS or Windows and want a session inside a Linux container, the session has
to be created by a Linux Chrome that uses the `basic` store: log in from inside the container
(or a Linux VM/desktop) with `LaunchOptions(password_store="basic")`, export there, and reuse
that bundle in later container runs.

Every "expected" above comes from reading Chromium's synchronous `os_crypt` code at one pinned
commit (see the end of this page). Newer Chrome versions route encryption through
`os_crypt_async`, whose Linux behaviour was not checked. Nobody has yet run a real logged-in
profile through this round trip as part of this project's tests.

## Workflow

### 1. Log in with a Linux "basic" profile

On a Linux desktop:

```python
import waybound

opts = waybound.LaunchOptions(
    backend="linux",
    launch_chrome=True,
    profile_dir="/home/me/wb-profiles/airline",
    password_store="basic",  # cookies use Chrome's fixed Linux key -> portable
    url="https://example.com/login",
)
with waybound.launch(opts) as page:
    input("Log in in the Chrome window, then press Enter here...")
```

Or inside the repository's container (no desktop needed; the login itself is scripted with
`waybound`, or done once in any Linux environment you can see):

```bash
podman build -f Containerfile -t waybound:latest .
mkdir -p ./profiles/airline
podman run --rm --shm-size=2g --security-opt seccomp=unconfined \
  -v "$PWD/profiles:/profiles:Z" \
  waybound:latest python3 login_airline.py   # uses profile_dir="/profiles/airline", password_store="basic"
```

`password_store` maps to Chrome's `--password-store` switch. It defaults to `None` (no flag,
Chrome picks a store itself, exactly as before this option existed) and Chrome ignores it on
macOS and Windows. In a container without a desktop session Chrome already falls back to the
basic store, but setting it explicitly removes the guesswork.

### 2. Close the session, wait, then export

Leave the `with waybound.launch(...)` block (or call `Session.close()`) and let it return
before exporting. On Linux and macOS the daemon stops Chrome with `SIGTERM` and waits up to
5 seconds before resorting to `SIGKILL`; Chromium handles `SIGTERM` with its normal shutdown,
which is expected to write batched cookie changes to disk (Chrome delays them by up to about
30 seconds) and remove `SingletonLock`. A hard kill, a crashed container or pulling the plug
can lose a login made just before the end and leave the lock behind.

Chrome must not be running against the profile: its SQLite databases may have unflushed
journals and the leveldb stores are locked. `export` refuses while `SingletonLock` (or
Windows `lockfile`) is present, with two exceptions:

- the lock names this host and its pid is gone (a stale lock): exported with a warning;
- the lock names **another** host, typically a container that has since exited: refused
  unless you pass `--ignore-lock` (`ignore_lock=True`). Only use it when you know that Chrome
  is gone. It never overrides a lock held by a Chrome running on this machine.

```bash
waybound profile export /home/me/wb-profiles/airline ./airline.session.tar.gz
```

```text
# example output
Wrote airline.session.tar.gz
  source: linux/x86_64, chrome 131.0.6778.85, cookie key store basic
  files: 214 (5839312 bytes uncompressed), saved passwords/autofill excluded
  restore on linux: expected to work (not verified against a real Chrome)
  restore on macos: cookies will not decrypt
  restore on windows: cookies will not decrypt
SECURITY: this bundle contains live session cookies ...
```

`waybound profile inspect <bundle>` prints the same summary plus the verdict for the current
machine, without extracting anything.

### 3. Import where you need it

```bash
waybound profile import ./airline.session.tar.gz ./profiles/airline-run-42
```

Then point `LaunchOptions(profile_dir=...)` at the restored directory. In a container:

```bash
podman run --rm --shm-size=2g --security-opt seccomp=unconfined \
  -v "$PWD/secrets/airline.session.tar.gz:/run/secrets/session.tar.gz:ro,Z" \
  waybound:latest sh -c '
    waybound profile import /run/secrets/session.tar.gz "$HOME/profile" &&
    python3 search.py   # LaunchOptions(backend="linux", headless_xvfb=True,
                        #   launch_chrome=True, profile_dir=os.path.expanduser("~/profile"),
                        #   password_store="basic")
  '
```

With Compose, mount the bundle the same way (a `volumes:` entry or a Compose `secrets:`
entry, read-only) and run the same two commands. Importing per run into a fresh directory
keeps workers independent: two Chrome processes must never share one profile directory.

From Python:

```python
from waybound import export_profile, import_profile

result = export_profile("/home/me/wb-profiles/airline", "airline.session.tar.gz")
restored = import_profile("airline.session.tar.gz", "/tmp/airline-profile")
print(restored.compatibility.level, restored.warnings)
```

## What goes into a bundle

The policy is an **allowlist**: anything not listed stays behind.

| Kept | Why |
| --- | --- |
| `Local State`, `Last Version`, `First Run` (top level) | Browser-wide state (profile list), the Chrome version, and the "skip first-run UI" marker |
| `<profile>/Cookies` and `<profile>/Network/Cookies` (+ `-journal`, `-wal`) | The session cookies. `Network/Cookies` is the newer location used on Windows |
| `<profile>/Preferences`, `<profile>/Secure Preferences` | Profile settings |
| `<profile>/Local Storage/**`, `Session Storage/**`, `IndexedDB/**`, `WebStorage/**` | Tokens many single-page apps keep outside cookies |
| `<profile>/Service Worker/Database/**`, `Service Worker/ScriptCache/**` | Service worker registrations and their scripts |

`<profile>` is `Default` or `Profile N`.

**Opt-in only** (`--include-credentials` / `include_credentials=True`): `Login Data`,
`Login Data For Account`, `Web Data`, `Account Web Data` (saved passwords, autofill, payment
metadata, and the Chrome account's own sign-in tokens). They are not needed to stay logged in
to websites, they are the most sensitive files in a profile, and they are encrypted with the
same OS key as cookies, so they carry the same portability limits.

**Always dropped**, among others: `Cache`, `Code Cache`, `GPUCache`, `GrShaderCache`,
`ShaderCache`, `GraphiteDawnCache`, `DawnWebGPUCache`, `Service Worker/CacheStorage`,
`Crashpad`, `BrowserMetrics*`, component and update data (`Safe Browsing`, `WidevineCdm`,
`OptimizationHints`, `CertificateRevocation`, `component_crx_cache`, ...), `Extensions`,
`History`, `Favicons`, `Top Sites`, `Sessions` (open tabs), `Device Bound Sessions`,
`File System`, `SingletonLock`, `SingletonCookie`, `SingletonSocket`, Windows `lockfile`,
leveldb `LOCK`, `LOG` and `LOG.old` files, SQLite `-shm` files, and every symlink, socket or
other non-regular file (reported as skipped, never followed).

## Bundle format

A gzip-compressed POSIX tar. The first member is `waybound-profile.json`; every other member
is `profile/<path relative to the user-data-dir>`. tar.gz was chosen over zip because it is
read strictly sequentially (the importer never seeks or trusts a central directory), it
compresses the many small leveldb files of a profile together, and it is what `podman cp`,
`docker cp` and every Linux box already handle. Members are written with mode `0600`, uid 0
and mtime 0.

The manifest records:

```json
{
  "kind": "waybound-profile-bundle",
  "format_version": 1,
  "waybound_version": "0.4.0",
  "created_at": "2026-11-22T10:00:00+00:00",
  "source": {"os": "linux", "arch": "x86_64"},
  "chrome_version": "131.0.6778.85",
  "password_store": "basic",
  "cookie_encryption_prefixes": ["v10"],
  "include_credentials": false,
  "files": [{"path": "Default/Cookies", "size": 20480, "sha256": "..."}]
}
```

The manifest is written as compact JSON; it is shown indented here. `chrome_version` comes
from the profile's `Last Version` file. `password_store` is inferred from the version prefix
of the encrypted cookie values: on Linux `v10` means the basic store and `v11` a keyring; on
macOS it is the Keychain; on Windows `v20` means App-Bound Encryption, otherwise DPAPI. To
see rows that are still only in the SQLite write-ahead log, the cookie database and its
`-wal`/`-journal` files are copied into a private temporary directory and opened there; the
source files are never opened for writing, and only the first three bytes of each value are
read. `cookie_encryption_prefixes` is `[]` when there are no encrypted cookies and `null`
when the database could not be read.

`--password-store` is only recorded when nothing can be detected. If it contradicts the
prefixes, the detected store is recorded and a warning is printed, so an override cannot make
a non-portable bundle look portable. On import the prefixes win over the recorded store for
the same reason.

Export also skips (and reports) files whose names the importer would refuse, such as names
containing `:` or reserved Windows device names, and refuses to write the bundle inside the
profile directory. It is limited to 200 000 files.

## Import safety

Bundles are read with a small, strict tar reader rather than Python's `tarfile`, because
`tarfile` loads a whole extended (PAX/GNU) header into memory before any check can run, so a
1 MB bundle can ask for gigabytes. The reader counts every decompressed byte against a budget
derived from the manifest, caps PAX headers at 64 KiB, and refuses GNU long-name/long-link and
global headers. `inspect` uses the same reader and honours `--max-bytes`.

Before anything in the target is touched, `import`:

- reads the manifest and checks its schema, format version, sizes and SHA-256 digests;
- rejects absolute paths, `..`, `.`, backslashes, NUL bytes, characters or names Windows
  cannot store (`<>:"|?*`, control characters, trailing dots or spaces, `CON`, `NUL`, `COM1`
  and the like, with or without an extension), path components over 255 bytes, and any path
  the include policy would not have exported (a bundle cannot plant `Extensions/` or
  `NativeMessagingHosts/`);
- rejects two entries that would land on the same file on a case-insensitive or
  Unicode-normalizing file system (APFS, NTFS), including a file and a directory that differ
  only in case or NFC/NFD form;
- rejects symlinks, hard links, devices, FIFOs and directories as archive members, members
  not in the manifest, repeated members, and missing ones;
- enforces a size cap (`--max-bytes`, default 2 GiB uncompressed, must be positive) and at
  most 200 000 files;
- refuses a non-empty target unless `--force`; with `--force`, refuses anything that does not
  look like a Chrome user-data-dir (`Local State` or `Default/` present) or a previous import
  (which carries a `.waybound-import.json` marker);
- refuses a target that is a symlink, a filesystem root, a mount point, your home directory
  or any of its ancestors, and a target where Chrome appears to be running (`--ignore-lock`
  accepts a lock from another host, as for export);
- refuses a bundle whose cookies cannot decrypt on this OS (see below) unless
  `--allow-incompatible`, and prints a loud warning when they only decrypt on the original
  machine or the key store is unknown. A bundle without any encrypted cookies is not refused
  across OSes, since there is no cookie session to lose; its other storage is expected to
  carry over.

Files are extracted with `O_EXCL | O_NOFOLLOW` into a new private (`0700`) staging directory
**next to** the target (`.<name>.waybound-import-*`, same file system), every digest is
verified, and permissions are set to `0700` for directories and `0600` for files without
following symlinks. Only then is the target replaced, by renames: the existing target is
renamed to `.<name>.waybound-backup-*`, the staging directory is renamed to the target, and
the backup is deleted last. If the second rename fails (or is interrupted), the backup is
renamed back. A verified staging directory is never deleted after a late failure: the error
says where it is. If the old profile cannot be fully deleted, the import still succeeds and a
warning says where the rest of it is. Deleting the backup never follows symlinks.

## Why portability depends on the OS (and what was checked)

Chrome encrypts each cookie value (`encrypted_value`) and, likewise, saved passwords with a
key from the operating system. Copying the files is easy; the key is the hard part.

- **Linux.** Chrome picks a key store from `--password-store` or the desktop environment:
  KWallet on KDE, libsecret (GNOME Keyring) on GNOME, Cinnamon, Deepin, Pantheon, UKUI, XFCE
  and Unity, and the **basic** store for `--password-store=basic`, for KDE3, LXQt and
  unrecognised desktops (no `XDG_CURRENT_DESKTOP`, as in this repo's container), or when the
  requested store is not available. Basic-store values are prefixed `v10` and encrypted with a key derived from a
  constant compiled into Chrome (`"peanuts"`, PBKDF2 with salt `"saltysalt"`, 1 iteration,
  AES-128). Keyring-backed values are prefixed `v11`, and Chrome does not fall back to the
  `v10` key for them. So `v10` profiles are expected to move between Linux machines; `v11`
  ones do not, not even between Chrome and Chromium on one machine, because the two use
  different keyring entries. This is the synchronous `os_crypt` implementation; newer
  Chrome's `os_crypt_async` key providers were not checked. Sources: Chromium `components/os_crypt/sync/key_storage_util_linux.cc` (`SelectBackend`)
  and `os_crypt_linux.cc` at commit `913eaefa55be`; `docs/linux/password_storage.md`.
- **macOS.** The key is derived (PBKDF2, salt `"saltysalt"`, 1003 iterations) from a random
  password stored in the user's login Keychain under the service "Chrome Safe Storage",
  account "Chrome" ("Chromium Safe Storage" for Chromium). Another Mac or user has a different
  item, so the copied cookies fail to decrypt and Chrome discards them. Sources:
  `os_crypt_mac.mm` and `keychain_password_mac.mm` at the same commit.
- **Windows.** A random AES-256-GCM key sits in `Local State` (`os_crypt.encrypted_key`),
  wrapped with DPAPI, which ties it to the Windows user account. Since Chrome 127, cookies
  additionally use App-Bound Encryption (`v20`), verified by a SYSTEM service and tied to the
  machine; Google notes it does not work for profiles that roam between machines. Sources:
  `os_crypt_win.cc` at the same commit; Google Security Blog, "Improving the security of
  Chrome cookies on Windows" (2024-07-30).

`waybound` deliberately does **not** read keys out of the Keychain or DPAPI, re-encrypt
cookies, or export cookies as plaintext JSON. Doing so would mean extracting the user's master
secret (Keychain prompts, DPAPI as the user, App-Bound Encryption's SYSTEM service), which is
exactly what infostealer malware does and what these protections exist to stop. It would also
put every cookie in plaintext in a file. The portable path is to create the session where the
key is portable.

### Not verified / caveats

- Chromium's `SIGTERM` handling was read in `chrome/browser/chrome_browser_main_posix.cc` at
  the same pinned commit (on Linux it calls `chrome::SessionEnding()`). That it flushes the
  cookie database before exiting was not verified.

- These behaviours were checked against Chromium source at one commit and public docs, and the
  feature was tested with synthetic profiles. A round trip of a real logged-in Chrome profile
  between two Linux containers has not been run as part of the test suite.
- The `arm64` image uses Debian Chromium rather than Google Chrome. Chromium uses the same
  `v10` basic-store key, so a basic-store bundle is expected to work across the two, but that
  combination was not tested.
- Importing a `v10` bundle into a Linux desktop Chrome that uses a keyring is expected to work
  (Chrome selects the key by prefix), but was not tested. New cookies will then be written
  with the keyring key.
- Opening a profile last written by a newer Chrome in an older one is not supported by Chrome
  (it may refuse or misbehave; not tested here). Restore into the same or a newer Chrome; the
  manifest records `chrome_version` so you can check.
- `Secure Preferences` is protected by a MAC that includes a machine identifier; on another
  machine Chrome may reset some protected settings. This does not affect cookies.
- Sites using Device Bound Session Credentials, or that bind sessions to IP address or device
  fingerprint, may still log you out after a move. No file copy can fix that.
- Session-only cookies (no expiry) travel only if Chrome wrote them to the `Cookies`
  database before exiting, which depends on its "continue where you left off" setting (not
  verified here).

## Relation to `ProfileStore` (issue #69)

Issue #69 proposes a copy-on-write `ProfileStore` that clones pre-warmed profiles for worker
pools, keeping HTTP and V8 caches, and can archive them across container restarts. This module
does something different: a minimal, verified, security-reviewed bundle for moving a *login*
between machines, with caches deliberately left out. The names do not overlap (`waybound.profile`,
`export_profile`, `import_profile`, `waybound profile ...`). A future `ProfileStore` could reuse
the safe import path (staging, hash checks, atomic swap) and the lock checks here, but it
would need a wider include policy for warm caches.


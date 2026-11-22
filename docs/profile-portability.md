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

| Where you logged in | Where you restore | Works? |
| --- | --- | --- |
| Any machine | **The same machine and OS user** | Yes |
| Linux, `password_store="basic"` (including any container) | Any Linux Chrome, including Podman/Docker containers | **Yes** |
| Linux desktop with GNOME Keyring / KWallet (Chrome's default there) | Another machine or container | No: cookies are encrypted with a key held in that desktop's keyring |
| macOS | Another Mac, Linux, a container, Windows | No: the key is in the source user's login Keychain |
| Windows | Anything else (and usually even another Windows user) | No: DPAPI and App-Bound Encryption tie the key to the user and machine |

If you work on macOS or Windows and want a session inside a Linux container, the session has
to be created by a Linux Chrome that uses the `basic` store: log in from inside the container
(or a Linux VM/desktop) with `LaunchOptions(password_store="basic")`, export there, and reuse
that bundle in later container runs.

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

### 2. Close Chrome and export

Chrome must not be running against the profile: its SQLite databases may have unflushed
journals and the leveldb stores are locked. `export` refuses while `SingletonLock` (or
Windows `lockfile`) is present, unless it can prove the lock is stale (same hostname, pid
gone).

```bash
waybound profile export /home/me/wb-profiles/airline ./airline.session.tar.gz
```

```text
# example output
Wrote airline.session.tar.gz
  source: linux/x86_64, chrome 131.0.6778.85, cookie key store basic
  files: 214 (5839312 bytes uncompressed), saved passwords/autofill excluded
  restore on linux: portable
  restore on macos: incompatible
  restore on windows: incompatible
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

`chrome_version` comes from the profile's `Last Version` file. `password_store` is inferred
from the version prefix of the encrypted cookie values (only the first three bytes are read,
through a read-only SQLite connection): on Linux `v10` means the basic store and `v11` a
keyring; on macOS it is the Keychain; on Windows `v20` means App-Bound Encryption, otherwise
DPAPI. Override it with `--password-store` when you know better.

## Import safety

Before anything in the target is touched, `import`:

- reads the manifest and checks its schema, format version, sizes and SHA-256 digests;
- rejects absolute paths, `..`, `.`, backslashes, drive letters, NUL bytes, paths that differ
  only in case, and any path the include policy would not have exported (a bundle cannot
  plant `Extensions/` or `NativeMessagingHosts/`);
- rejects symlinks, hard links, devices, FIFOs and directories as archive members, members
  not in the manifest, repeated members, and missing ones;
- enforces a size cap (`--max-bytes`, default 2 GiB uncompressed, 200 000 files);
- refuses a non-empty target unless `--force`, a target that is a symlink, `/` or your home
  directory, and a target where Chrome appears to be running;
- refuses a bundle whose cookies cannot decrypt on this OS (see below) unless
  `--allow-incompatible`, and prints a loud warning when they only decrypt on the original
  machine or the key store is unknown.

Files are extracted with `O_EXCL | O_NOFOLLOW` into a private staging directory **inside**
the target, every digest is verified, and only then are the target's old contents removed
(with `--force`) and the staged files moved into place. Nothing outside the target directory
is ever deleted. Restored directories are `0700`, files `0600`.

## Why portability depends on the OS (and what was checked)

Chrome encrypts each cookie value (`encrypted_value`) and, likewise, saved passwords with a
key from the operating system. Copying the files is easy; the key is the hard part.

- **Linux.** Chrome picks a key store from `--password-store` or the desktop environment:
  KWallet on KDE, libsecret (GNOME Keyring) on GNOME, Cinnamon, XFCE, Unity and similar, and
  the **basic** store for `--password-store=basic`, for unrecognised desktops (no
  `XDG_CURRENT_DESKTOP`, as in this repo's container), or when the requested store is not
  available. Basic-store values are prefixed `v10` and encrypted with a key derived from a
  constant compiled into Chrome (`"peanuts"`, PBKDF2 with salt `"saltysalt"`, 1 iteration,
  AES-128). Keyring-backed values are prefixed `v11`, and Chrome does not fall back to the
  `v10` key for them. So `v10` profiles move between Linux machines; `v11` ones do not.
  Sources: Chromium `components/os_crypt/sync/key_storage_util_linux.cc` (`SelectBackend`)
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

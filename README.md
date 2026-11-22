# waybound

[![CI](https://github.com/Sekinal/waybound/actions/workflows/ci.yml/badge.svg)](https://github.com/Sekinal/waybound/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/waybound.svg)](https://pypi.org/project/waybound/)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/Sekinal/waybound#license)

**Zero-fork, zero-CDP, out-of-band OS-level browser automation** built in Rust with a typed sync/`async` Python SDK and stdio MCP server.

Instead of forking Chromium/Firefox, patching C++ getters, and fighting CDP/Juggler leaks every 4 weeks, `waybound` drives **unmodified, official Google Chrome** (Chromium where Chrome is not installed on Linux) through the OS accessibility tree, the native OS input pipeline, and passive `SSLKEYLOGFILE` decryption of the browser's own TLS traffic. Backends exist for **macOS, Linux, Windows, and Android (ADB / Waydroid)**; see [Platform support](#platform-support) for how mature each one is.

---

## Install

```bash
pip install waybound
waybound fetch v0.4.0   # Downloads that release's prebuilt waybound-daemon
waybound doctor         # Reports whether the daemon, Chrome, tshark, and adb/waydroid can be found
```

The wheel is pure Python and does not contain the daemon. `waybound fetch <version>` downloads it from the GitHub release tagged `<version>` (with the `v` prefix, e.g. `v0.4.0`) into `~/.cache/waybound/<version>/` (prebuilt for macOS arm64, Linux x86_64/arm64, and Windows x86_64) and checks it against the `.sha256` file published in the same release. Without an argument it fetches the release pinned in `waybound/binary.py`, which can lag behind the installed package, so pass the version explicitly to match your SDK. Elsewhere, build it with `cargo build --release -p waybound-daemon` and put it on `PATH` or set `WAYBOUND_DAEMON_BIN`.

`waybound doctor` only checks that files and commands exist. For Chrome it looks only at `/Applications/Google Chrome.app` and `/Applications/Google Chrome Canary.app` on macOS, and at `/usr/bin/google-chrome`, `/usr/bin/google-chrome-stable` and `/usr/bin/chromium` everywhere else (including Windows, where it therefore reports Chrome as missing); it does not read `WAYBOUND_CHROME_BIN` or check `/usr/bin/chromium-browser`, both of which the daemon uses. It does not check macOS Accessibility or Screen Recording permissions, packet-capture (BPF) permissions, or the Linux AT-SPI2/X11 tools.

### MCP Server (Antigravity, Claude Code, Cursor, Codex)

```bash
WAYBOUND_BACKEND=macos uvx --from waybound waybound-mcp
```

The daemon still has to be installed (`waybound fetch`). `WAYBOUND_BACKEND` accepts `macos` (launches Chrome), `android` (with `WAYBOUND_SERIAL`), or `mock`; any other value falls back to `macos`.

### Headless Linux Container (Podman & Docker)

```bash
podman run --rm --shm-size=2g --security-opt seccomp=unconfined ghcr.io/sekinal/waybound:latest
# or with Docker:
docker run --rm --shm-size=2g --security-opt seccomp=unconfined ghcr.io/sekinal/waybound:latest
```

See [docs/containers.md](docs/containers.md) for headless Linux scripting and passive capture inside containers.

---

## Why `waybound` vs. Forked Browsers?

| Capability | `waybound` | Camoufox | CloakBrowser | Patchright |
|---|---|---|---|---|
| **Browser Binary** | Official unmodified Chrome (updates with Chrome itself) | Forked Firefox | Forked Chromium | Stock Chromium |
| **Automation Protocol** | **None (Zero CDP / Zero Juggler)** | Patched Juggler | Patched CDP | Patched CDP |
| **Fingerprint** | Whatever the stock browser reports on that host; nothing is spoofed (see [Limitations](#limitations)) | C++ spoofed + noise | C++ spoofed + noise | Host OS |
| **JSON API Capture** | **Passive `SSLKEYLOGFILE` (Zero MITM, Zero CDP)** | Via Juggler/Playwright | Via CDP | Via CDP |
| **Auth Proxy (`http`/`socks5`)** | Built-in Rust loopback forwarder (zero extensions) | Built-in | Built-in | Workarounds |
| **Headless Server** | Headless **Podman/Docker Xvfb**; Waydroid launch is experimental | Xvfb Firefox | Xvfb Chromium | Headless/Xvfb |
| **AI Agent MCP Server** | Built-in (`waybound-mcp`) | External | Built-in | External |

### Diagnostic Benchmarks

[`benchmarks/run_benchmarks.py`](benchmarks/run_benchmarks.py) launches Chrome through `waybound` and reads three public pages from the accessibility tree: the JA4 string from `tls.peet.ws/api/clean`, the WebDriver / Chrome / `HeadlessChrome` rows from `bot.sannysoft.com`, and the headless and stealth percentages from CreepJS. A reported run on macOS with Chrome 158:

- **CreepJS:** `0% headless`, `0% stealth`.
- **bot.sannysoft.com:** `WebDriver: missing`, `Chrome: present`, no `HeadlessChrome`.
- **tls.peet.ws:** Chrome 158 TLS 1.3 JA4 `t13d1517h2_8daaf6152771_cb7bf5808d99`.

These pages test the browser, not the automation: any unmodified Chrome passes them, with or without `waybound`. What they show is that `waybound` adds no CDP, WebDriver flag, or headless marker. They do not measure the signals `waybound` itself produces (pointer paths, click and key timing, scroll events), and the suite is not run in CI.

---

## Quickstart

```python
import asyncio
from pathlib import Path
from waybound import LaunchOptions, Role, launch_async


async def main() -> None:
    async with launch_async(
        LaunchOptions(
            backend="macos",  # or "linux", "windows", "android"
            launch_chrome=True,
            url="https://en.wikipedia.org/wiki/Main_Page",
            profile_dir=Path("/tmp/my-chrome-profile"),
            ssl_keylog=Path("/tmp/my-chrome-profile/sslkeys.log"),
            proxy="socks5://user:pass@proxy.example.com:1080",
            timezone="America/New_York",
            locale="en_US.UTF-8",  # sets LANG/LC_ALL only; see Limitations
        )
    ) as page:
        search = page.get_by_role(Role.TEXTBOX, name="Search Wikipedia")
        await search.wait_for()

        # True parallel: passively decrypt compressed HTTP/2 JSON while typing (zero CDP, zero MITM)
        resp, _ = await asyncio.gather(
            page.wait_for_response("search/title"),
            search.fill("Rust programming"),
        )
        print(resp.status, resp.json())
        png_bytes = await page.screenshot()


asyncio.run(main())
```

> **Proxy credentials and local users.** The upstream proxy URL reaches the daemon via its
> environment, not argv, and is stripped from every process the daemon spawns (Chrome
> included). Chrome talks to a loopback forwarder that adds the credentials. On Linux the
> forwarder only accepts connections from processes running as the same user; on macOS and
> Windows it cannot check, so any local user can relay traffic through your upstream proxy
> while a session runs. See [ARCHITECTURE.md](ARCHITECTURE.md#upstream-proxy-forwarder).

---

## Platform Support

| Backend | Accessibility tree | Input | Screenshot | Status |
|---|---|---|---|---|
| `macos` | `AXUIElement`, scoped to `AXWebArea` | `CGEvent` posted to the HID event tap; Chrome is brought to the front before clicks and key presses | Browser window (`screencapture`) | Main development platform; unit tests only in CI |
| `linux` | AT-SPI2 over D-Bus (`zbus`), falling back to a `python3` `gi.repository.Atspi` helper (PyGObject + `gir1.2-atspi-2.0`) | X11 `XTEST` (`x11rb`), falling back to `xdotool`; `ydotool` on Wayland | Whole display (X11 `GetImage`, `import`/`scrot`, or `grim` on Wayland) | Used by the container image; unit tests only in CI |
| `windows` | UI Automation, queried through a PowerShell helper | Win32 `SendInput` | Primary screen (PowerShell `System.Drawing`) | Live smoke test against real Chrome in CI |
| `android` | `uiautomator dump` over ADB | `adb shell input` (key modifiers are dropped) | `screencap` | Works against an existing device via `serial=`; `launch_waydroid` is experimental (see [docs/waydroid-linux.md](docs/waydroid-linux.md)) |

The SDK talks to the daemon over a Unix socket, or loopback TCP on Windows (`use_tcp=True` elsewhere).

## Limitations

- **One visible desktop session at a time on macOS and Windows.** Input moves the real cursor and goes to the foreground window. On macOS the driver activates Chrome first; on Windows it does not, so Chrome must already be in front. On Linux, `headless_xvfb=True` gives each session its own Xvfb, but always on display `:99`, so run one such session per host or container (or start your own Xvfb and pass `display=`).
- **What a session owns.** Each `launch()` starts its own daemon and its own store of captured responses. With `launch_chrome=True` it also starts its own Chrome process, with a fresh temporary profile unless `profile_dir` is set. It gets its own loopback proxy forwarder only when one is needed: `ssl_keylog`, `block_hosts`, or a `proxy` with credentials. Connections to the same daemon share all of these.
- **Locators are Playwright-style in API, not in strictness.** Names match as a case-insensitive substring, or with `exact=True` as a case-sensitive exact string; whitespace is not normalised. When several elements match, the `nth` one (default the first) is used silently; there is no strict-mode error. `hover`, `click`, `fill`, `dblclick` (broken on 0.4.0: the SDK sends `dblclick` but the daemon expects `dbl_click`; fixed in #46) and `select_option` wait up to 5 s for the element to appear in the accessibility tree and scroll it into view when the viewport is known, but do not wait for it to be visible, enabled, or stable. A locator chained from another (`page.get_by_role(...).get_by_role(...)`) is scoped by screen position (the child's centre must lie inside the parent's bounds), not by tree ancestry.
- **Accessibility snapshots are capped** at 2,000 nodes on macOS and Android and 4,000 on Linux and Windows; on macOS traversal also stops at depth 40 or after visiting 10,000 nodes. Larger pages are truncated without an error.
- **Passive capture** has two paths:
  - With `launch_chrome=True` and `ssl_keylog=...`, Chrome is pointed at the built-in loopback forwarder, which decrypts the HTTPS (`CONNECT`) tunnels it relays, in-process. Plain `http://` requests are not captured. It handles TLS 1.3 (AES-GCM and ChaCha20-Poly1305), HTTP/1.1 and HTTP/2, and `gzip`/`deflate`/`br` bodies. It does not see QUIC/HTTP/3, TLS 1.2, or `zstd` bodies, and it does not work when chaining through an upstream `http://` proxy (direct and `socks5://` upstreams work). `wait_for_network_idle` only counts requests on this path.
  - Whenever the daemon did not launch Chrome itself and `ssl_keylog=...` is set (for example when attaching with `pid=...`), it runs `tshark` instead. The running Chrome must have been started with `SSLKEYLOGFILE` pointing at that same file. The tap captures TCP/UDP port 443 on `en0` (macOS) or `any` (Linux); override with `WAYBOUND_NET_IFACE`. It needs packet-capture permissions and `tshark` in `/opt/homebrew/bin`, `/usr/local/bin`, or `/usr/bin`. HTTP/3 support depends on tshark's QUIC dissector and is not tested.
  - Nothing sets up a key log inside Android, so passive capture does not apply to the `android` backend.
- **Fingerprint.** `waybound` reports whatever the stock browser reports. On a macOS or Windows desktop that is the real OS, GPU and fonts; in the Linux container it is Chrome on Xvfb with no GPU; on Waydroid it is whatever the Android container image reports, which is not the same as a physical phone.
- **`timezone=` and `locale=`** set `TZ`, and `LANG`/`LC_ALL`, in Chrome's environment (on Waydroid, `timezone=` sets `persist.sys.timezone`). Nothing passes `--lang` or changes `Accept-Language`. Whether `navigator.language` follows `LANG` depends on the platform and has not been verified on macOS.
- **Behavioural signals** (minimum-jerk pointer paths, click and key timing, scroll bursts) are generated but not benchmarked against any detector; the Android backend skips pointer motion.

---

## Architecture

- **`crates/waybound-core`** (`unsafe_code = "forbid"`) — Platform-agnostic `Driver` trait, semantic `LocatorQuery`/`Role` (including chained `within` scopes), Flash & Hogan minimum-jerk behavioral motion planner (`motion.rs`), and JSON-lines wire protocol.
- **`crates/waybound-driver-macos`** — Official macOS Chrome via `AXUIElement` (`AXWebArea`-scoped), `CGEvent` posted to the HID event tap with Carbon keycodes, and browser-window screenshots (`CGWindowListCopyWindowInfo` + `screencapture`).
- **`crates/waybound-driver-linux`** (`#![forbid(unsafe_code)]`) — Linux desktop Chrome/Chromium via AT-SPI2 (`zbus`, with a `python3` `gi.repository.Atspi` helper (PyGObject + `gir1.2-atspi-2.0`) as fallback), X11 `XTEST` via `x11rb` (with `xdotool` fallback) / Wayland (`ydotool`), X11 `GetImage` / `import` / `scrot` / `grim` screenshots, and RAII headless `Xvfb` (`--headless-xvfb`).
- **`crates/waybound-driver-windows`** — Windows Chrome via `UIAutomation` (PowerShell helper), audited Win32 `SendInput`, and `System.Drawing` PNG screenshots.
- **`crates/waybound-driver-android`** (`unsafe_code = "forbid"`) — Pure-Rust ADB + `uiautomator` XML parser + experimental headless **Waydroid** launcher (see [docs/waydroid-linux.md](docs/waydroid-linux.md)).
- **`crates/waybound-net`** (`#![forbid(unsafe_code)]`) — Pure-Rust passive TLS 1.3 record decryptor, `SSLKEYLOGFILE` reader, HTTP/1.1 and HTTP/2 (HPACK) response correlator with `gzip`/`deflate`/`br` decompression, and L4 hostname blocker.
- **`crates/waybound-daemon`** — Concurrent `AF_UNIX` / loopback TCP JSON-lines server, Chrome launcher, embedded HTTP/SOCKS5 authenticated proxy forwarder that feeds `waybound-net`, and a `tshark`-based tap for browsers it did not launch.
- **`python/`** — Strictly typed sync + `async` SDK (`mypy --strict`, `ruff`), `waybound` CLI, and zero-dependency `waybound-mcp` stdio server.

---

## Development

```bash
make setup   # Install Python dev deps + pre-commit hooks
make fix     # Auto-format and auto-fix Rust & Python
make check   # Run fmt, clippy (-D warnings), ruff, mypy --strict, build, and all tests
```

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/Sekinal/waybound/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/Sekinal/waybound/blob/main/LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

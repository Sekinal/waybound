# waybound

[![CI](https://github.com/Sekinal/waybound/actions/workflows/ci.yml/badge.svg)](https://github.com/Sekinal/waybound/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/waybound.svg)](https://pypi.org/project/waybound/)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/Sekinal/waybound#license)

**Zero-fork, zero-CDP, two-tier browser automation and scraping engine** built in Rust, with typed Python (`sync`/`async`) and TypeScript SDKs, first-class **Crawlee** and **Scrapy** integrations, and a stdio MCP server.

Instead of forking Chromium/Firefox, patching C++ getters, and chasing CDP/Juggler leaks every 4 weeks, `waybound` combines two tiers:

1. **Tier 1 — Isolated OS-level `BrowserPool`:** Drives **unmodified, official Google Chrome** (or Chromium on Linux) through native OS accessibility trees (`AXUIElement`, AT-SPI2, UI Automation), native input (`CGEvent`, X11 `XTEST` / pure-Rust Wayland `wl_seat`, Win32 `SendInput`), and passive `SSLKEYLOGFILE` decryption of the browser's own TLS traffic — with zero CDP, zero WebDriver, and zero MITM CA certificates. On Linux, `BrowserPool` scales horizontally via either isolated `Xvfb` displays or our pure-Rust `#![forbid(unsafe_code)]` headless Wayland compositor (`waybound-compositor`).
2. **Tier 2 — Fingerprint-Matched HTTP Handoff (`HandoffHttpClient`):** Passively captures a live `SessionFingerprint` (TLS 1.3 parameters, HTTP/2 `SETTINGS`/pseudo-header order, ordered headers, and cookies) from Tier 1 and hands off bulk requests to a compiled Rust client (`waybound-http`) with BoringSSL TLS session resumption, warm HTTP/2 pooling, lossless binary/multipart bodies, and opt-in pure-Rust HTTP/3 (QUIC) with transparent H2 fallback.

```text
                       ┌─────────────────────────────────────────────┐
                       │  Python / TypeScript SDK  ·  Crawlee/Scrapy │
                       └──────────────────────┬──────────────────────┘
                                              │
                 ┌────────────────────────────┴────────────────────────────┐
                 ▼                                                         ▼
┌───────────────────────────────────────────┐   ┌──────────────────────────────────────────┐
│  Tier 1: BrowserPool (unmodified Chrome)  │   │  Tier 2: HandoffHttpClient (waybound-http)│
│  • OS AX tree (AXUIElement/AT-SPI2/UIA)   │   │  • Replays live SessionFingerprint       │
│  • Native input + waybound-compositor     │──▶│  • BoringSSL H2 + TLS session resumption │
│  • Passive SSLKEYLOGFILE TLS 1.3 tap      │   │  • Opt-in pure-Rust HTTP/3 (QUIC)        │
│  • ProfileStore (CoW) + TraceRecorder     │   │  • Lossless binary & multipart bodies    │
└───────────────────────────────────────────┘   └──────────────────────────────────────────┘
```

---

## Install

### Python

```bash
pip install waybound                 # Core sync/async SDK + CLI + MCP server (zero runtime deps)
pip install "waybound[crawlee]"      # + WayboundCrawler for Crawlee Python
pip install "waybound[scrapy]"       # + WayboundDownloadHandler for Scrapy

waybound fetch v0.6.0                # Downloads prebuilt waybound-daemon (macOS/Linux/Windows)
waybound doctor                      # Verifies daemon, Chrome, tshark, and adb/waydroid
```

### TypeScript / Node.js (>= 22.12)

```bash
npm install waybound                 # Typed async SDK + BrowserPool + ProfileStore + TraceRecorder
npm install @crawlee/basic           # Optional peerDep for `waybound/crawlee` (WayboundCrawler)
```

The Python wheel and npm package do not bundle the Rust daemon binary. `waybound fetch <version>` (or `downloadDaemonBinary()` in TypeScript) downloads `waybound-daemon` from GitHub Releases into `~/.cache/waybound/<version>/` (prebuilt for macOS arm64, Linux x86_64/arm64, and Windows x86_64 with `--features replay`) and verifies its `.sha256` checksum. Elsewhere, build from source with `cargo build --release -p waybound-daemon --features replay` and place it on `PATH` or set `WAYBOUND_DAEMON_BIN`.

### MCP Server (Antigravity, Claude Code, Cursor, Codex)

```bash
WAYBOUND_BACKEND=macos uvx --from waybound waybound-mcp
```

### Headless Linux Container (Podman & Docker)

```bash
podman run --rm --shm-size=2g --security-opt seccomp=unconfined ghcr.io/sekinal/waybound:latest
# or with Docker:
docker run --rm --shm-size=2g --security-opt seccomp=unconfined ghcr.io/sekinal/waybound:latest
```

See [docs/containers.md](docs/containers.md) for headless Linux scripting and passive capture inside containers.

---

## Why `waybound`? (Honest Comparison)

`waybound` is **not** a drop-in Playwright replacement for every single-page app — see [Trade-offs & Limitations](#trade-offs--limitations) below. It is built for teams that want unmodified stock Chrome with zero CDP/Juggler surface, pluggable into Crawlee/Scrapy, with an optional Rust HTTP handoff tier.

| Capability | `waybound` | Playwright / Patchright | Camoufox | CloakBrowser |
|---|---|---|---|---|
| **Browser Binary** | Official unmodified Chrome (updates with Chrome) | Stock Chromium (Patched CDP in Patchright) | Forked Firefox | Forked Chromium |
| **Automation Protocol** | **None (Zero CDP / Zero Juggler)** | CDP / Patched CDP | Patched Juggler | Patched CDP |
| **JSON API Capture** | **Passive `SSLKEYLOGFILE` (Zero MITM, Zero CDP)** | Via CDP | Via Juggler | Via CDP |
| **HTTP Handoff Tier** | Built-in Rust (`BoringSSL` H2 + opt-in HTTP/3) | External | External | External |
| **Linux Headless Scaling** | `BrowserPool` (`Xvfb` or pure-Rust `waybound-compositor` Wayland) | Headless / Xvfb | Xvfb Firefox | Xvfb Chromium |
| **Crawlee / Scrapy** | Built-in `WayboundCrawler` (Py/TS) & `WayboundDownloadHandler` | Native Crawlee | Via Playwright | Via Playwright |
| **Auth Proxy (`http`/`socks5`)** | Built-in Rust loopback forwarder + `network_stats` + block presets | Built-in / Workarounds | Built-in | Built-in |
| **Complex SPA DOM/Shadow DOM** | Accessibility tree only (no arbitrary JS eval) | Full DOM + JS eval | Full DOM + JS eval | Full DOM + JS eval |

---

## Quickstart

### 1. Single Session + Passive JSON Capture

```python
import asyncio
from pathlib import Path
from waybound import LaunchOptions, Role, launch_async


async def main() -> None:
    async with launch_async(
        LaunchOptions(
            backend="linux",  # or "macos", "windows", "android"
            headless_wayland=True,  # pure-Rust Wayland compositor (zero Xvfb)
            launch_chrome=True,
            url="https://en.wikipedia.org/wiki/Main_Page",
            profile_dir=Path("/tmp/my-chrome-profile"),
            ssl_keylog=Path("/tmp/my-chrome-profile/sslkeys.log"),
            proxy="socks5://user:pass@proxy.example.com:1080",
            block_presets=("analytics", "ads"),
        )
    ) as page:
        search = page.get_by_role(Role.TEXTBOX, name="Search Wikipedia")
        await search.wait_for()

        # Passively decrypt compressed HTTP/2 JSON while typing (zero CDP, zero MITM)
        resp, _ = await asyncio.gather(
            page.wait_for_response("search/title"),
            search.fill("Rust programming"),
        )
        print(resp.status, resp.json())
        print(await page.network_stats())
        print(await page.links())


asyncio.run(main())
```

### 2. Concurrent `BrowserPool` + Crawlee (`WayboundCrawler`)

```python
import asyncio
from waybound import BrowserPool, LaunchOptions
from waybound.crawlee import WayboundCrawler


async def main() -> None:
    async with BrowserPool(
        size=4,
        launch_options=LaunchOptions(backend="linux", launch_chrome=True),
        display_backend="wayland",
    ) as pool:
        crawler = WayboundCrawler(pool=pool, max_requests_per_crawl=50)

        @crawler.router.default_handler
        async def handle(ctx) -> None:
            await ctx.enqueue_links(strategy="same-domain")
            await ctx.push_data({"url": ctx.request.url, "links": len(await ctx.page.links())})

        await crawler.run(["https://example.com"])


asyncio.run(main())
```

In TypeScript:

```ts
import { BrowserPool } from "waybound";
import { WayboundCrawler } from "waybound/crawlee";

const pool = new BrowserPool({
  size: 4,
  launchOptions: { backend: "linux", launchChrome: true },
  displayBackend: "wayland",
});
const crawler = new WayboundCrawler({
  pool,
  async requestHandler({ page, enqueueLinks, pushData, request }) {
    await enqueueLinks({ strategy: "same-domain" });
    await pushData({ url: request.url, links: (await page.links()).length });
  },
});
await crawler.run(["https://example.com"]);
await pool.close();
```

### 3. Scrapy (`WayboundDownloadHandler`) + Tier 2 HTTP Handoff

```python
# settings.py
from waybound import LaunchOptions

DOWNLOAD_HANDLERS = {
    "http": "waybound.scrapy.WayboundDownloadHandler",
    "https": "waybound.scrapy.WayboundDownloadHandler",
}
WAYBOUND_POOL_SIZE = 2
WAYBOUND_LAUNCH_OPTIONS = LaunchOptions(
    backend="linux",
    launch_chrome=True,
    headless_wayland=True,
)

# Inside a Spider:
# yield scrapy.Request(url, meta={"waybound": True})           # Tier 1: BrowserPool
# yield scrapy.Request(api_url, meta={"waybound_http": True})  # Tier 2: HandoffHttpClient
```

Standalone Tier 2 handoff from a live page (BoringSSL H2 + opt-in HTTP/3 QUIC):

```python
async with await page.handoff_http_client(http3=True) as http:
    res = await http.get("https://api.example.com/v1/items")
    print(res.status, res.json())
```

### 4. Production Ergonomics (`ProfileStore` & `TraceRecorder`)

- **`ProfileStore`** (Python & TS): Fast copy-on-write Chrome profile cloning (APFS `clonefile` on macOS, `cp --reflink=auto` on Linux) plus security-hardened `.tar.gz` profile snapshots.
- **`TraceRecorder`** (Python & TS): Captures `manifest.json`, `timeline.jsonl`, screenshots, accessibility snapshots, and HAR 1.2 bundles with `on_error_only=True` retention for production debugging.

---

## Passive Capture & HTTP/3 Proxy Behavior

Understanding how `waybound` captures network traffic without MITM or CDP is important:

1. **Managed Chrome + Local Proxy Forwarder (`launch_chrome=True` with `ssl_keylog=...`):**
   - `waybound-daemon` points Chrome at its built-in Rust HTTP/1.1 `CONNECT` loopback proxy forwarder and decrypts the TLS 1.3 stream in-process using Chrome's `SSLKEYLOGFILE`.
   - **Why HTTP/3/QUIC is not silently missed:** Because Chrome tunnels proxied HTTPS requests through an HTTP/1.1 `CONNECT` tunnel over TCP, Chrome automatically negotiates **TCP + TLS 1.3 + HTTP/2 (or HTTP/1.1)** for every proxied origin rather than UDP/QUIC. As a result, API responses are captured reliably without silent QUIC bypass.
   - Supports TLS 1.2 and TLS 1.3 (AES-GCM and ChaCha20-Poly1305), HTTP/1.1 and HTTP/2 (HPACK), WebSocket frames, and `gzip`/`deflate`/`br` decompression. Does not decrypt plain `http://` or `zstd` bodies, and does not passively tap when chaining through an upstream `http://` proxy (`socks5://` and direct upstreams work).
2. **Attached Chrome (`pid=...` with `ssl_keylog=...`, no proxy forwarder):**
   - Falls back to `tshark` packet capture on `en0` (macOS) or `any` (Linux; override with `WAYBOUND_NET_IFACE`).
   - Because Chrome is not forced through the HTTP/1.1 `CONNECT` proxy in this mode, origins advertising `Alt-Svc: h3` may upgrade to **UDP/QUIC (HTTP/3)**, which depends on `tshark`'s QUIC dissector and is not guaranteed.
3. **Proxy credentials and local users:**
   - The upstream proxy URL is passed via `WAYBOUND_PROXY` (never argv) and stripped from child processes. On Linux the loopback forwarder enforces same-UID peer verification via `/proc/net/tcp`; on macOS and Windows any local user can relay through the loopback port while a session runs. See [ARCHITECTURE.md](ARCHITECTURE.md#upstream-proxy-forwarder).

---

## Platform Support

| Backend | Accessibility tree | Input | Screenshot | CI Coverage |
|---|---|---|---|---|
| `linux` (Wayland) | AT-SPI2 over D-Bus (`zbus`) | Pure-Rust `waybound-compositor` (`wl_seat` pointer + xkb keyboard) | Direct per-surface `wl_buffer` PNG | **Live stock Chrome CI (`--ozone-platform=wayland`, zero Xvfb)** |
| `linux` (X11/Xvfb) | AT-SPI2 over D-Bus (`zbus`, `pyatspi` fallback) | X11 `XTEST` (`x11rb`, `xdotool` fallback) | X11 `GetImage` (`import`/`scrot` fallback) | **Live stock Chrome CI (`Xvfb` + `openbox`)** |
| `windows` | UI Automation | Win32 `SendInput` | Primary screen (`System.Drawing`) | **Live stock Chrome CI** |
| `macos` | `AXUIElement` (`AXWebArea`-scoped) | `CGEvent` HID tap | Browser window (`screencapture`) | Unit + workspace tests in CI (main dev platform) |
| `android` | `uiautomator dump` over ADB | `adb shell input` | `screencap` | Unit tests in CI; Waydroid launch experimental ([docs/waydroid-linux.md](docs/waydroid-linux.md)) |

---

## Trade-offs & Limitations

- **Accessibility tree vs. full DOM:** Because `waybound` never attaches CDP or injects JavaScript, it only sees what the browser exposes to the OS accessibility tree (plus links via `page.links()` and decrypted network responses via `wait_for_response()`). Canvas-only UIs, unlabelled `<div>` click targets without ARIA roles, or arbitrary JS evaluation are better served by Playwright/CDP.
- **Locator strictness & truncation:** `strict=True` raises `WayboundDaemonError` (`code="strict_mode_violation"`) when multiple elements match; otherwise `nth` (default `0`) selects the first match. Accessibility snapshots support `max_nodes` and return `truncated: bool` (default caps: 2,000 nodes on macOS/Android, 4,000 on Linux/Windows).
- **Desktop focus on macOS & Windows:** Input moves the real cursor and targets the foreground window (one desktop session at a time on macOS/Windows). Use Linux `BrowserPool` (`display_backend="wayland"` or `"xvfb"`) for concurrent headless scraping.
- **Fingerprint honesty:** `waybound` reports whatever the unmodified browser reports on that host — nothing is spoofed.
- **`BrowserPool` isolation:** `size > 1` is refused where slots would share one pointer and keyboard: local `macos`/`windows`, local `android` (one device), and `linux` unless slots get their own input via `display_backend="wayland"` (one in-process compositor per daemon) or `isolated_displays=True` with Xvfb (one Xvfb, D-Bus session and AT-SPI2 bus per slot; the pool picks free display numbers from `:100`, and a display another process already owns is never used). The same applies to `WayboundCrawler(pool_size=...)`. A standalone `headless_xvfb=True` session uses display `:99` unless `display=":N"` picks another.
- **Session and slot lifetime (Linux, macOS):** each daemon runs in its own process group and exits with the Python process that started it, however that process died (`SIGINT`, `SIGTERM`, `SIGHUP`, `SIGKILL`); a signal to your script's group therefore reaches only Python. `close()` (also on leaving the `with` block, and via an `atexit` hook for sessions still open at exit) shuts the daemon down gracefully, then kills anything left in its group and removes temp dirs a killed daemon left behind. A pool slot's own helpers (Xvfb, D-Bus, openbox, AT-SPI2) run in one process group that `close()` stops; if the slot's daemon stops for any other reason (a signal, the Python process dying, a fatal error) the daemon stops that group itself. Only a `SIGKILL`ed daemon followed by a `SIGKILL`ed Python process leaves them running. In a child created with `os.fork()`, closing an inherited session never shuts down the parent's daemon. `close()` normally takes well under a second, but can take up to about 46 s when an abandoned page call still holds the connection. On Windows the daemon is not detached and does not watch its parent.

---

## Architecture

- **`crates/waybound-core`** (`#![forbid(unsafe_code)]`) — Platform-agnostic `Driver` trait, semantic `LocatorQuery`/`Role`, minimum-jerk motion planner, and JSON-lines wire protocol.
- **`crates/waybound-compositor`** (`#![forbid(unsafe_code)]`) — Pure-Rust headless Wayland compositor (`wayland-server` + `xdg_shell` + `wl_shm` + `wl_seat`) for zero-Xvfb Linux Chrome concurrency.
- **`crates/waybound-driver-linux`** (`#![forbid(unsafe_code)]`) — AT-SPI2 (`zbus`), `HeadlessCompositor` Wayland integration, X11 `XTEST`/`GetImage` (`x11rb`), and RAII `Xvfb`.
- **`crates/waybound-driver-macos`** — `AXUIElement` (`AXWebArea`-scoped), `CGEvent` HID input, and `screencapture`.
- **`crates/waybound-driver-windows`** — UI Automation, audited Win32 `SendInput`, and PNG screenshots.
- **`crates/waybound-driver-android`** (`#![forbid(unsafe_code)]`) — Pure-Rust ADB + `uiautomator` XML parser + experimental Waydroid launcher.
- **`crates/waybound-net`** (`#![forbid(unsafe_code)]`) — Passive TLS 1.3 decryptor, `SSLKEYLOGFILE` reader, HTTP/1.1 & HTTP/2 (HPACK) + WebSocket correlator, `SessionFingerprint` recorder, host blocker presets, and bandwidth accounting.
- **`crates/waybound-http`** (`#![forbid(unsafe_code)]`) — Tier 2 replay client (`BoringSSL` via `wreq` with TLS session resumption & warm H2 pooling, lossless binary/multipart bodies, and opt-in pure-Rust HTTP/3 via `quinn` + `h3`).
- **`crates/waybound-daemon`** — Concurrent `AF_UNIX`/TCP JSON-lines server, Chrome launcher, loopback proxy forwarder, and `--replay` subprocess worker.
- **`python/`** — Strictly typed sync + `async` SDK (`waybound`, `waybound[crawlee]`, `waybound[scrapy]`), `waybound` CLI, and `waybound-mcp` stdio server.
- **`packages/waybound-ts/`** — Typed Node.js SDK (`waybound`, `waybound/crawlee`) with zero runtime dependencies.

---

## Development

```bash
make setup   # Install Python dev deps + pre-commit hooks
make check   # Run Rust fmt/clippy/test, Python ruff/mypy/pytest, and TS build/test/lint
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

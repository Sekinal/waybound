# waybound

[![CI](https://github.com/Sekinal/waybound/actions/workflows/ci.yml/badge.svg)](https://github.com/Sekinal/waybound/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/waybound.svg)](https://pypi.org/project/waybound/)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](Cargo.toml)

**Zero-fork, zero-CDP, out-of-band OS-level browser automation** built in Rust with a typed sync/`async` Python SDK and stdio MCP server.

Instead of forking Chromium/Firefox, patching C++ getters, and fighting CDP/Juggler leaks every 4 weeks, `waybound` drives **100% unmodified, official Google Chrome** from the OS accessibility tree, native OS input pipeline, and passive wire-level `SSLKEYLOGFILE` decryption across **macOS, Linux, Windows, and Android/Waydroid**.

---

## Install (30 seconds)

```bash
pip install waybound
waybound fetch       # Downloads SHA-256 verified prebuilt waybound-daemon
waybound doctor      # Verifies daemon, Chrome, tshark, and platform tools
```

### Zero-Install MCP Server (Antigravity, Claude Code, Cursor, Codex)

```bash
WAYBOUND_BACKEND=macos uvx --from waybound waybound-mcp
```

### Headless Linux Container (Podman & Docker)

```bash
podman run --rm --shm-size=2g --security-opt seccomp=unconfined ghcr.io/sekinal/waybound:latest
# or with Docker:
docker run --rm --shm-size=2g --security-opt seccomp=unconfined ghcr.io/sekinal/waybound:latest
```

See [docs/containers.md](docs/containers.md) for headless Linux scripting and passive `tshark` capture inside containers.

---

## Why `waybound` vs. Forked Browsers?

| Capability | `waybound` | Camoufox | CloakBrowser | Patchright |
|---|---|---|---|---|
| **Browser Binary** | Official unmodified Chrome (0-day updates) | Forked Firefox | Forked Chromium | Stock Chromium |
| **Automation Protocol** | **None (Zero CDP / Zero Juggler)** | Patched Juggler | Patched CDP | Patched CDP |
| **Fingerprint Integrity** | 100% genuine OS/GPU/TLS/Fonts | C++ spoofed + noise | C++ spoofed + noise | Host OS |
| **JSON API Capture** | **Passive `SSLKEYLOGFILE` (Zero MITM, Zero CDP)** | Via Juggler/Playwright | Via CDP | Via CDP |
| **Auth Proxy (`http`/`socks5`)** | Built-in Rust loopback forwarder (zero extensions) | Built-in | Built-in | Workarounds |
| **Headless Server Scale** | Headless **Podman/Docker Xvfb** + **Waydroid (Android)** | Xvfb Firefox | Xvfb Chromium | Headless/Xvfb |
| **AI Agent MCP Server** | Built-in (`waybound-mcp`) | External | Built-in | External |

### Live Diagnostic Benchmarks (macOS Official Chrome 158)
- **CreepJS:** `0% headless`, `0% stealth` (zero prototype/Canvas/WebGL lie detections), real Apple Metal GPU + WebGPU.
- **bot.sannysoft.com:** 100% green (`WebDriver: missing`, `Chrome: present`, `Plugins: 5`, zero `HeadlessChrome`).
- **tls.peet.ws:** Exact Chrome 158 TLS 1.3 JA4 (`t13d1517h2_8daaf6152771_cb7bf5808d99`) + canonical Akamai HTTP/2 fingerprint.

Reproduce on your own machine with [`benchmarks/run_benchmarks.py`](benchmarks/run_benchmarks.py).

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
            locale="en_US.UTF-8",
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
> forwarder only accepts connections from processes running as the same user, with two
> caveats: if it cannot read its own socket in `/proc/net/tcp` at startup it warns and
> accepts everyone, and when the daemon runs as root (or as the unmapped UID 65534) the
> check does not separate users, which it also warns about. On macOS and Windows it cannot
> check, so any local user can relay traffic through your upstream proxy while a session
> runs. See [ARCHITECTURE.md](ARCHITECTURE.md#upstream-proxy-forwarder).

---

## Architecture

- **`crates/waybound-core`** (`#![forbid(unsafe_code)]`) — Platform-agnostic `Driver` trait, semantic `LocatorQuery`/`Role` (including chained `within` scopes), Flash & Hogan minimum-jerk behavioral motion planner (`motion.rs`), and JSON-lines wire protocol.
- **`crates/waybound-driver-macos`** — Official macOS Chrome via `AXUIElement` (`AXWebArea`-scoped), PID-targeted `CGEvent` + Carbon keycodes, and native window screenshots (`screencapture`).
- **`crates/waybound-driver-linux`** (`#![forbid(unsafe_code)]`) — Linux desktop Chrome/Chromium via `AT-SPI2`, X11 (`xdotool`) / Wayland (`ydotool`), `grim`/`scrot` screenshots, and RAII headless `Xvfb` (`--headless-xvfb`).
- **`crates/waybound-driver-windows`** — Native Windows Chrome via `UIAutomation`, audited Win32 `SendInput`, and `System.Drawing` PNG screenshots.
- **`crates/waybound-driver-android`** (`#![forbid(unsafe_code)]`) — Pure-Rust ADB + `uiautomator` XML parser + multi-instance headless **Waydroid** Linux orchestrator (see [docs/waydroid-linux.md](docs/waydroid-linux.md)).
- **`crates/waybound-daemon`** — Concurrent `AF_UNIX` / loopback TCP JSON-RPC server, passive `SSLKEYLOGFILE` HTTP/1.1–2–3 tap with gzip/deflate/brotli decompression, and embedded HTTP/SOCKS5 authenticated proxy forwarder.
- **`python/`** — Strictly typed sync + `async` SDK (`mypy --strict`, `ruff`), `waybound` CLI, and zero-dependency `waybound-mcp` stdio server.

---

## Development

```bash
make setup   # Install Python dev deps + pre-commit hooks
make fix     # Auto-format and auto-fix Rust & Python
make check   # Run fmt, clippy (-D warnings), ruff, mypy --strict, build, and all tests
```

# waybound

**Zero-fork, zero-CDP, out-of-band OS-level browser automation** built in Rust with a typed sync/`async` Python SDK and stdio MCP server.

Instead of forking Chromium/Firefox, patching C++ getters, and fighting CDP/Juggler leaks every 4 weeks, `waybound` drives **100% unmodified, official Google Chrome** from the OS accessibility tree, native OS input pipeline, and passive wire-level `SSLKEYLOGFILE` decryption.

---

## Why `waybound` vs. Forked Browsers?

| Capability | `waybound` | Camoufox | CloakBrowser | Patchright |
|---|---|---|---|---|
| **Browser Binary** | Official unmodified Chrome (0-day updates) | Forked Firefox | Forked Chromium | Stock Chromium |
| **Automation Protocol** | **None (Zero CDP / Zero Juggler)** | Patched Juggler | Patched CDP | Patched CDP |
| **Fingerprint Integrity** | 100% genuine OS/GPU/TLS/Fonts | C++ spoofed + noise | C++ spoofed + noise | Host OS |
| **JSON API Capture** | **Passive `SSLKEYLOGFILE` (Zero MITM, Zero CDP)** | Via Juggler/Playwright | Via CDP | Via CDP |
| **Auth Proxy (`http`/`socks5`)** | Built-in Rust loopback forwarder (zero extensions) | Built-in | Built-in | Workarounds |
| **Linux Server Scale** | Headless multi-instance **Waydroid (Android)** | Xvfb Firefox | Xvfb Chromium | Headless/Xvfb |
| **AI Agent MCP Server** | Built-in (`waybound-mcp`) | External | Built-in | External |

### Live Diagnostic Benchmarks (macOS Official Chrome 158)
- **CreepJS:** `0% headless`, `0% stealth` (zero prototype/Canvas/WebGL lie detections), real Apple Metal GPU + WebGPU.
- **bot.sannysoft.com:** 100% green (`WebDriver: missing`, `Chrome: present`, `Plugins: 5`, zero `HeadlessChrome`).
- **tls.peet.ws:** Exact Chrome 158 TLS 1.3 JA4 (`t13d1517h2_8daaf6152771_cb7bf5808d99`) + canonical Akamai HTTP/2 fingerprint.

---

## Quickstart

### Sync / Async Python SDK

```python
import asyncio
from pathlib import Path
from waybound import LaunchOptions, Role, launch_async

async def main() -> None:
    async with launch_async(
        LaunchOptions(
            backend="macos",
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

### MCP Server for AI Agents (Antigravity, Claude Code, Cursor, Codex)

```bash
WAYBOUND_BACKEND=macos waybound-mcp
```

### Environment Check & Prebuilt Binary Fetch

```bash
waybound doctor   # Checks daemon, official Chrome, tshark/BPF, and ADB/Waydroid
waybound fetch    # Downloads SHA-256 verified prebuilt waybound-daemon from GitHub Releases
```

---

## Architecture

- **`crates/waybound-core`** (`#![forbid(unsafe_code)]`) — Platform-agnostic `Driver` trait, semantic `LocatorQuery`/`Role`, Flash & Hogan minimum-jerk behavioral motion planner (`motion.rs`), and wire protocol.
- **`crates/waybound-driver-macos`** — Official macOS Chrome via `AXUIElement` (`AXWebArea`-scoped), `CGEvent`, and native window screenshots (`CGWindowListCopyWindowInfo` + `screencapture`).
- **`crates/waybound-driver-android`** (`#![forbid(unsafe_code)]`) — Pure-Rust ADB + `uiautomator` XML parser + multi-instance headless **Waydroid** Linux orchestrator (see [docs/waydroid-linux.md](docs/waydroid-linux.md)).
- **`crates/waybound-daemon`** — Concurrent `AF_UNIX` JSON-RPC server, passive `SSLKEYLOGFILE` HTTP/1.1–2–3 tap with gzip/deflate/brotli decompression, and embedded HTTP/SOCKS5 authenticated proxy forwarder.
- **`python/`** — Strictly typed sync + `async` SDK (`mypy --strict`, `ruff`), `waybound` CLI, and zero-dependency `waybound-mcp` stdio server.

---

## Development

```bash
make setup   # Install Python dev deps + pre-commit hooks
make check   # Run cargo fmt, clippy (-D warnings), ruff, mypy --strict, and all 39+ tests
make fix     # Auto-format and auto-fix Rust & Python
```

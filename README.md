# waybound

Ergonomic, out-of-band OS-level browser automation built in Rust with a typed Python SDK.

## Architecture

`waybound` separates browser automation into three clean layers so the browser binary itself stays unmodified:

1. **`crates/waybound-core`** (`#![forbid(unsafe_code)]`) — Platform-agnostic domain types and traits (`Driver`, `AccessibilityNode`, `LocatorQuery`, `InputEvent`, `SessionConfig`).
2. **`crates/waybound-daemon`** — Control daemon orchestrating OS backends (macOS `AXUIElement`, Windows `UIAutomation`, Linux Wayland + `AT-SPI2`, and containerized Android / Waydroid) and exposing semantic locators over local IPC.
3. **`python/`** — Strictly typed Playwright-style Python SDK (`Page`, `Locator`, `Role`, `Transport`).

## Guardrails & Code Quality

This repository is configured to make it hard to introduce sloppy code:

- **Rust**: Workspace-wide `unsafe_code = "forbid"` (isolate future OS FFI into dedicated driver crates), `clippy::all` + `clippy::pedantic` + `unwrap_used`/`expect_used`/`panic`/`print_stdout` denied, `rustfmt`, and `deny.toml` for `cargo-deny`.
- **Python**: Managed with `uv`, strict `mypy` (`strict = true`, `disallow_any_explicit = true`), aggressive `ruff` lint + format rules, and `pytest`.
- **Git & CI**: `.pre-commit-config.yaml` and `.github/workflows/ci.yml` run the full suite automatically.

## Quickstart

```bash
make setup   # Install Python dev deps + pre-commit hooks
make check   # Run formatting, clippy, ruff, mypy, and all tests
make fix     # Auto-format and auto-fix Rust & Python
```

# Agent & Contributor Guide (`AGENTS.md`)

Read this file before modifying code in `waybound`.

## Core Invariants (Non-Negotiable)

1. **Zero Browser Forking & Zero CDP:** `waybound` drives unmodified, official browser binaries out-of-band via OS accessibility trees and native OS input APIs. Never add CDP/DevTools/WebDriver dependencies or JS injection to core or drivers.
2. **Strict `unsafe` Isolation:**
   - `waybound-core` and `waybound-daemon` forbid `unsafe_code`.
   - Platform FFI (`unsafe`) is permitted **only** inside dedicated `crates/waybound-driver-*` crates, wrapped in safe RAII abstractions with explicit `// SAFETY:` comments on every `unsafe` block.
3. **Zero Panics in Production Paths:** `unwrap()`, `expect()`, `panic!()`, `print!()` are denied by workspace Clippy lints. Return typed `WayboundError` values and log via `tracing`.
4. **Strict Python Typing:** All Python code must pass `mypy --strict` with `disallow_any_explicit = true` and `ruff check`. Never add `Any` or blanket `# type: ignore` comments.
5. **macOS `AF_UNIX` Path Limit:** Keep Unix domain socket paths under 100 bytes (macOS `sun_path` max is 104 bytes).

## Verification Workflow

Always run before finishing any change:

```bash
make check
```

This runs:
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo build --workspace && cargo test --workspace --all-features`
- `uv run ruff format --check .`
- `uv run ruff check .`
- `uv run mypy src tests`
- `uv run pytest` (with `-W error`, including live Rust ↔ Python IPC E2E tests)

To auto-format and apply safe lint fixes:

```bash
make fix
```

## Commit Conventions

Use Conventional Commits:
- `feat(scope): ...` — new capability
- `fix(scope): ...` — bug fix
- `refactor(scope): ...` — internal restructure without behavior change
- `test(scope): ...` — test additions/updates
- `chore(scope): ...` — build, CI, lint, docs

Examples:
- `feat(driver-macos): add AXUIElement tree traversal`
- `fix(daemon): release stale unix socket on shutdown`

## Crate Boundaries

- `crates/waybound-core` — Pure domain types, `Driver` trait, IPC `Request`/`Response` schema. No OS dependencies, no `unsafe`.
- `crates/waybound-driver-*` — OS/container implementations of `waybound_core::Driver`. Minimal, audited FFI wrapped in RAII types.
- `crates/waybound-daemon` — CLI, Unix-socket JSON-RPC server, driver lifecycle.
- `python/` — Typed Playwright-style SDK (`Page`, `Locator`, `UnixSocketTransport`).

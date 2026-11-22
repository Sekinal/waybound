# Architecture

## System Overview

```text
+------------------------------------------------------------+
|  Python SDK (python/src/waybound)                          |
|  Page / Locator -> UnixSocketTransport                     |
|  (JSON-lines over AF_UNIX, or loopback TCP on Windows)     |
+-----------------------------┬------------------------------+
                              │
+-----------------------------▼------------------------------+
|  waybound-daemon (crates/waybound-daemon)                  |
|  JSON-lines server + backend selection (--backend, ...)    |
|  Chrome launcher, proxy forwarder + waybound-net tap,      |
|  tshark tap for browsers it did not launch                 |
+-----------------------------┬------------------------------+
                              │ trait waybound_core::Driver
     ┌─────────────┬──────────┼──────────────┬───────────────┐
     ▼             ▼          ▼              ▼               ▼
 MockDriver     macos       linux         windows         android
 (hermetic   AXUIElement  AT-SPI2 +     UIAutomation +   ADB uiautomator
  tests)     + CGEvent    XTEST/ydotool  SendInput       + input (Waydroid
                                                         launch experimental)
```

## Wire Protocol (JSON-lines over `AF_UNIX` or loopback TCP)

Each request and response is a single newline-delimited JSON object defined in `crates/waybound-core/src/protocol.rs`. Requests are tagged by `method`, responses by `status`. A `query` is a `LocatorQuery`: `{"role": ..., "name": ..., "exact": false, "nth": 0, "within": {...}}`.

| Request (`method`) | Fields | Response (`status`) |
|---|---|---|
| `ping` | | `pong` (`version`) |
| `snapshot_tree` | | `tree` (`nodes`) |
| `locate_all` | `query` (`nth` ignored) | `tree` (`nodes`) |
| `current_url` | | `url` (`url`, may be `null`) |
| `wait_for` | `query`, `timeout_ms` (capped at 120 s) | `node` (`node`) |
| `hover` | `query` | `ok` |
| `click` | `query` | `ok` |
| `dbl_click` | `query` | `ok` |
| `select_option` | `query`, `label?`, `index?` | `ok` |
| `fill` | `query`, `text` | `ok` |
| `navigate` | `url` (`http://` or `https://`) | `ok` |
| `reload` / `go_back` / `go_forward` | | `ok` |
| `new_tab` | `url?` | `ok` |
| `close_tab` / `next_tab` / `prev_tab` | | `ok` |
| `scroll` | `delta_x`, `delta_y` | `ok` |
| `press` | `key`, `modifiers` | `ok` |
| `captured_responses` | `url_contains?` | `http_responses` (`responses`) |
| `wait_for_response` | `url_contains`, `timeout_ms` (capped at 120 s) | `http_response` (`response`) |
| `wait_for_network_idle` | `idle_ms`, `timeout_ms` | `ok` |
| `screenshot` | `path` | `ok` |
| `shutdown` | | `ok` |
| *(any error)* | | `error` (`code`, `message`) |

Error codes: `element_not_found`, `backend_unavailable`, `timeout`, `io_error`, `invalid_request` (unparseable request or non-finite scroll deltas), and `frame_too_large`.

`hover`, `click`, `dbl_click`, `select_option` and `fill` wait up to 5 s for the element to appear before acting.

## Ownership & Safety Rules

- All OS handles (`CFTypeRef`, `AXUIElementRef`, `CGEventRef`) inside `waybound-driver-macos` must be wrapped in RAII structs implementing `Drop` so no CoreFoundation/CoreGraphics objects can leak on early `?` returns.
- `unsafe` is allowed only in `waybound-driver-macos` and `waybound-driver-windows`; every other crate forbids it.
- Every `unsafe` block must carry a `// SAFETY:` comment explaining the preconditions upheld.

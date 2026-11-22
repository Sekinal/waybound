# Architecture

## System Overview

```text
+------------------------------------------------------------+
|  Python SDK (python/src/waybound)                          |
|  Page / Locator -> UnixSocketTransport (AF_UNIX JSON-lines)|
+-----------------------------┬------------------------------+
                              │
+-----------------------------▼------------------------------+
|  waybound-daemon (crates/waybound-daemon)                  |
|  JSON-RPC server + backend selection (--backend, --socket) |
+-----------------------------┬------------------------------+
                              │ trait waybound_core::Driver
       ┌──────────────────────┼──────────────────────┐
       ▼                      ▼                      ▼
  MockDriver        waybound-driver-macos    (Future Backends)
  (hermetic tests)  AXUIElement + CGEvent    Linux Wayland / Windows /
                                             Android Waydroid
```

## Wire Protocol (JSON-lines over `AF_UNIX`)

Each request and response is a single newline-delimited JSON object defined in `crates/waybound-core/src/protocol.rs`.

| Request (`method`) | Response (`status`) |
|---|---|
| `{"method": "ping"}` | `{"status": "pong", "version": "0.1.0"}` |
| `{"method": "snapshot_tree"}` | `{"status": "tree", "nodes": [...]}` |
| `{"method": "click", "query": {...}}` | `{"status": "ok"}` |
| `{"method": "fill", "query": {...}, "text": "..."}` | `{"status": "ok"}` |
| *(any error)* | `{"status": "error", "code": "...", "message": "..."}` |

## Ownership & Safety Rules

- All OS handles (`CFTypeRef`, `AXUIElementRef`, `CGEventRef`) inside `waybound-driver-macos` must be wrapped in RAII structs implementing `Drop` so no CoreFoundation/CoreGraphics objects can leak on early `?` returns.
- Every `unsafe` block must carry a `// SAFETY:` comment explaining the preconditions upheld.

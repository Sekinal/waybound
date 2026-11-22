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

## Upstream Proxy Forwarder

Chrome's `--proxy-server` cannot carry `user:pass` credentials, so when an authenticated
upstream proxy (or host blocking / the passive TLS tap) is requested, the daemon runs an
unauthenticated HTTP/CONNECT forwarder on `127.0.0.1:<random port>`
(`crates/waybound-daemon/src/proxy.rs`), points Chrome at it, and injects the upstream
credentials itself.

**Credential handling.** The Python SDK passes the upstream URL to the daemon in the
`WAYBOUND_PROXY` environment variable (readable only by the same user and root), never in
argv (world-readable through `ps`). An inherited `WAYBOUND_PROXY` is passed through unless
the `proxy` option overrides it. The daemon itself also accepts `--proxy <url>` on its
command line; that puts the URL in its world-readable argv, so when the value contains
credentials the daemon logs a one-line warning (without the value) recommending
`WAYBOUND_PROXY` instead.

Every child process in the workspace (Chrome, `osascript`, `tshark`, `Xvfb`, `xdotool`,
`ydotool`, `xclip`, `grim`, `import`, `scrot`, the `python3` AT-SPI helper, `adb`,
`waydroid`, `weston`, `screencapture`, PowerShell) is created through
`waybound_core::process::command`, which removes `WAYBOUND_PROXY` from the child's
environment. `clippy.toml` disallows `std::process::Command::new` everywhere else
(including tests and build scripts), and a source-scanning test backs that up. The
daemon's own initial environment (`/proc/<daemon pid>/environ` on Linux) still holds the
variable and is readable by the same user and root.

**Who can use the forwarder.** Each accepted connection is verified before anything is read
from it (`crates/waybound-daemon/src/peer.rs`). Refused clients get `403 Forbidden`, no
upstream connection is made, and a warning without credentials is logged: the first
refusal at `warn`, then at most one `warn` per minute carrying a count of the refusals
logged only at `debug` in between.

| OS | Policy | Residual exposure |
|---|---|---|
| Linux | The client socket is found by four-tuple in `/proc/net/tcp` / `tcp6` and its owning UID must equal the daemon's effective UID. Rows with inode 0 (orphaned sockets whose owner already closed them, which report UID 0) count as not found. A miss is re-read once after 5 ms, because the kernel serves the table in chunks and can skip a row; a second miss is refused. If the daemon cannot see its own listener in `/proc/net/tcp` at startup, it warns and runs **unrestricted** (fail open) rather than refusing Chrome. | Any process of the same user can use the forwarder (it could equally read the daemon's environment or ptrace it). If the daemon runs as root (UID 0), every root process passes; as the overflow UID 65534 (unmapped in a user namespace), every other unmapped user passes. The check stays on, but a startup warning says it is effectively unrestricted for those users. Restricting to the Chrome process tree is not done: mapping sockets to PIDs needs `/proc/<pid>/fd`, which is unreadable for Chrome's non-dumpable sandboxed processes. |
| macOS | Unrestricted. | Any local process, under any user, can relay through the upstream proxy while a session runs. Socket ownership needs `libproc` FFI (not allowed in the daemon) or a per-connection `lsof`, which is too slow. |
| Windows | Unrestricted. | Same as macOS; `GetExtendedTcpTable` would need FFI. |

## Ownership & Safety Rules

- All OS handles (`CFTypeRef`, `AXUIElementRef`, `CGEventRef`) inside `waybound-driver-macos` must be wrapped in RAII structs implementing `Drop` so no CoreFoundation/CoreGraphics objects can leak on early `?` returns.
- Every `unsafe` block must carry a `// SAFETY:` comment explaining the preconditions upheld.

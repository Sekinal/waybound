/** Error types raised by the waybound TypeScript SDK. */

/**
 * Structured error returned by waybound-daemon over IPC, or raised by the client for
 * transport failures.
 *
 * Daemon codes: `element_not_found`, `backend_unavailable`, `timeout`, `io_error`,
 * `invalid_request`, `frame_too_large`. Client codes: `io_error` (socket failure or
 * client-side request timeout), `eof` (daemon closed the connection), `closed` (transport
 * already closed), `protocol_error` (malformed or unexpected reply), `timeout` (client-side
 * polling such as `page.waitForUrl()` gave up).
 */
export class WayboundDaemonError extends Error {
  override readonly name = "WayboundDaemonError";
  /** Machine-readable error code. */
  readonly code: string;
  /** Human-readable message without the `[code]` prefix. */
  readonly detail: string;

  constructor(code: string, detail: string, options?: ErrorOptions) {
    super(`[${code}] ${detail}`, options);
    this.code = code;
    this.detail = detail;
  }
}

/** Raised when the daemon binary cannot be found, fails to start, or never becomes reachable. */
export class WayboundLaunchError extends Error {
  override readonly name = "WayboundLaunchError";
}

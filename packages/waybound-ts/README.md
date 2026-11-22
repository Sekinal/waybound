# waybound (TypeScript / Node.js)

Typed, async Node.js client for `waybound-daemon`, which drives stock Chrome through OS
accessibility APIs and native input (no CDP, no browser patches). It mirrors the Python SDK
(`python/src/waybound`) with camelCase names. Zero runtime dependencies; Node.js 22.12 or newer.

The package is ESM-first (`import { launch } from "waybound"`), with type declarations.
`require("waybound")` also works on Node.js 22.12+, which can `require()` ES modules.

## Usage

```ts
import { launch, Role } from "waybound";

const session = await launch({ backend: "macos", launchChrome: true, url: "https://example.com" });
try {
  const { page } = session;
  await page.getByRole(Role.TEXTBOX, { name: "Search" }).fill("waybound");

  // Arm the wait first, then trigger the request, then await the response.
  const waiter = await page.expectResponse("/api/search", { timeoutMs: 10_000 });
  await page.getByRole(Role.BUTTON, { name: "Go" }).click();
  const response = await waiter.response;
  console.log(response.status, response.json());

  await page.waitForNetworkIdle();
  const results = page.getByRole(Role.LIST, { name: "Results" }).getByRole(Role.LINK);
  console.log(await results.count(), await results.first.textContent());
} finally {
  await session.close(); // or: `await using session = await launch(...)`
}
```

`launch()` defaults to `backend: "mock"`, the in-memory test backend, as the Python SDK does.

Locators are lazy and chainable (`getByRole`, `getByText`, `nth`, `first`); each action resolves
them afresh on the daemon. Daemon errors reject with `WayboundDaemonError` (`err.code` is
`timeout`, `element_not_found`, `io_error`, and so on); startup failures reject with
`WayboundLaunchError`.

### Waiting for network responses

The daemon only matches responses captured _after_ it receives a `wait_for_response` request.
`page.waitForResponse()` opens its own connection before sending that request, so in
`Promise.all([page.waitForResponse(url), locator.click()])` the click is usually sent first,
and a response that arrives very quickly can be missed. Use `page.expectResponse()` as in the
example above: it resolves once the wait has been sent to the daemon, and `waiter.response`
settles with the match (or rejects with code `timeout`).

Wait budgets are capped by the daemon: `waitFor()` and `waitForResponse()` at 120 s,
`waitForNetworkIdle()` at 60 s (with `idleMs` between 50 ms and 10 s). Larger values are
clamped; negative or non-finite values throw `TypeError`.

### Captured responses

`page.capturedResponses()` returns what the daemon has captured so far: up to the 500 most
recent responses, with bodies of up to 4 MiB each. The SDK refuses a single reply line larger
than 256 MiB; the request runs on its own short-lived connection, so if that happens only this
call fails (pass `urlContains` to narrow the result) and the session stays usable.

## Finding the daemon

`launch()` looks for `waybound-daemon` in this order: the `daemonBinary` option,
`$WAYBOUND_DAEMON_BIN`, `PATH`, `target/{release,debug}` of a repository checkout, then the
cache shared with the Python SDK (`~/.cache/waybound/<version>/`). It never downloads anything,
and installing the package runs no scripts. To fetch the prebuilt release binary for this
platform (verified against the release's SHA-256 file):

```ts
import { downloadDaemonBinary } from "waybound";
const daemonPath = await downloadDaemonBinary(); // or { version: "v0.4.0" }
```

## Development

```bash
cargo build -p waybound-daemon   # from the repository root; needed by the integration tests
cd packages/waybound-ts
npm ci
npm run lint && npm run typecheck && npm run build && npm test
```

Integration tests run against `target/debug/waybound-daemon --backend mock` (or
`$WAYBOUND_DAEMON_BIN`) and are skipped when it is missing; set `WAYBOUND_REQUIRE_DAEMON=1` to
make a missing daemon fail the run instead.

# waybound (TypeScript / Node.js)

Typed, async Node.js client for `waybound-daemon`, which drives stock Chrome through OS
accessibility APIs and native input (no CDP, no browser patches). It mirrors the Python SDK
(`python/src/waybound`) with camelCase names. Zero runtime dependencies; ESM with type
declarations; Node.js 22.12 or newer.

## Usage

```ts
import { launch, Role } from "waybound";

const session = await launch({ backend: "macos", launchChrome: true, url: "https://example.com" });
try {
  const { page } = session;
  await page.getByRole(Role.TEXTBOX, { name: "Search" }).fill("waybound");

  // Start waiting for the API reply before the click that triggers it.
  const [response] = await Promise.all([
    page.waitForResponse("/api/search", { timeoutMs: 10_000 }),
    page.getByRole(Role.BUTTON, { name: "Go" }).click(),
  ]);
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

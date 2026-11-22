/** waybound: typed async Node.js client for `waybound-daemon`. */

export {
  cachedDaemonPath,
  DEFAULT_REPO,
  DEFAULT_VERSION,
  type DownloadOptions,
  daemonFilename,
  downloadDaemonBinary,
  type FetchLike,
  findCachedDaemon,
  type HostInfo,
  platformArtifactName,
  type ResolveOptions,
  resolveDaemonBinary,
} from "./binary.js";
export {
  type CapturedResponsesOptions,
  Locator,
  type NetworkIdleOptions,
  Page,
  type PressOptions,
  type RoleOptions,
  type ScrollOptions,
  type SelectOptionOptions,
  type TextOptions,
  type TimeoutOptions,
} from "./client.js";
export { WayboundDaemonError, WayboundLaunchError } from "./errors.js";
export { type BackendName, type LaunchOptions, launch, Session } from "./session.js";
export {
  DEFAULT_TIMEOUT_MS,
  type Endpoint,
  Transport,
  type TransportOptions,
} from "./transport.js";
export {
  type AccessibilityNode,
  BackendKind,
  Bounds,
  CapturedResponse,
  KeyModifier,
  type LocatorQuery,
  NAMED_KEYS,
  type NamedKey,
  Role,
} from "./types.js";

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
export {
  type AcquireOptions,
  BrowserPool,
  type BrowserPoolOptions,
  buildDbusArgs,
  buildSlotEnv,
  buildXvfbArgs,
  findFreeDisplayNum,
  type PooledPage,
  type PoolStats,
  parseRemoteWorker,
  type ReleaseOptions,
  type RemoteWorkerEndpoint,
} from "./pool.js";
export { type BackendName, type LaunchOptions, launch, Session } from "./session.js";
export {
  DEFAULT_TIMEOUT_MS,
  type Endpoint,
  type ResponseWaiter,
  type SnapshotTreeOptions,
  Transport,
  type TransportOptions,
} from "./transport.js";
export {
  type AccessibilityNode,
  BackendKind,
  BLOCK_PRESETS,
  type BlockPreset,
  Bounds,
  CapturedResponse,
  KeyModifier,
  type LocatorQuery,
  NAMED_KEYS,
  type NamedKey,
  type NetworkStats,
  Role,
  type TreeSnapshot,
} from "./types.js";

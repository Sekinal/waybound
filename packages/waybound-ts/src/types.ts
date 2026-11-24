/** Typed value objects shared by the waybound TypeScript SDK and the daemon wire protocol. */

/** Supported execution backends reported by the daemon. */
export const BackendKind = {
  MACOS_NATIVE: "mac_os_native",
  WINDOWS_NATIVE: "windows_native",
  LINUX_WAYLAND: "linux_wayland",
  ANDROID_WAYDROID: "android_waydroid",
} as const;
export type BackendKind = (typeof BackendKind)[keyof typeof BackendKind];

/** Normalized semantic accessibility roles (wire values from `waybound_core::Role`). */
export const Role = {
  BUTTON: "button",
  LINK: "link",
  TEXTBOX: "text_box",
  SEARCHBOX: "search_box",
  CHECKBOX: "check_box",
  RADIO: "radio",
  SWITCH: "switch",
  COMBOBOX: "combo_box",
  LISTBOX: "list_box",
  OPTION: "option",
  LIST: "list",
  LISTITEM: "list_item",
  TAB: "tab",
  DIALOG: "dialog",
  REGION: "region",
  GROUP: "group",
  IMG: "img",
  MENUITEM: "menu_item",
  DOCUMENT: "document",
  HEADING: "heading",
  STATIC_TEXT: "static_text",
  UNKNOWN: "unknown",
} as const;
export type Role = (typeof Role)[keyof typeof Role];

const ROLE_VALUES: ReadonlySet<string> = new Set(Object.values(Role));

/** Return `raw` as a `Role`, or `Role.UNKNOWN` for unmapped values. */
export function parseRole(raw: unknown): Role {
  return typeof raw === "string" && ROLE_VALUES.has(raw) ? (raw as Role) : Role.UNKNOWN;
}

/** Modifier keys held during a key press. */
export const KeyModifier = {
  META: "meta",
  CONTROL: "control",
  ALT: "alt",
  SHIFT: "shift",
} as const;
export type KeyModifier = (typeof KeyModifier)[keyof typeof KeyModifier];

/** Named keys accepted by `page.press()`; any other single character is sent as-is. */
export const NAMED_KEYS = [
  "enter",
  "tab",
  "escape",
  "backspace",
  "arrow_left",
  "arrow_right",
  "arrow_up",
  "arrow_down",
  "space",
  "delete",
  "home",
  "end",
  "page_up",
  "page_down",
] as const;
export type NamedKey = (typeof NAMED_KEYS)[number];

/** Logical screen-space bounding rectangle. */
export class Bounds {
  constructor(
    readonly x: number,
    readonly y: number,
    readonly width: number,
    readonly height: number,
  ) {}

  /** Midpoint `[x, y]` of this rectangle. */
  get center(): [number, number] {
    return [this.x + this.width / 2, this.y + this.height / 2];
  }
}

/** Single node captured from the OS accessibility tree. */
export interface AccessibilityNode {
  readonly id: string;
  readonly role: Role;
  readonly name: string | null;
  readonly value: string | null;
  readonly bounds: Bounds;
  readonly focused: boolean;
  readonly url?: string | null;
}

/** Single HTTP header field as seen on the wire (repeated names are kept separately). */
export interface HttpHeader {
  readonly name: string;
  readonly value: string;
}

/** Passively decrypted HTTP/1.1, HTTP/2, or HTTP/3 response. */
export class CapturedResponse {
  constructor(
    readonly url: string,
    readonly status: number,
    readonly contentType: string | null,
    readonly body: string | null,
    readonly headers: readonly HttpHeader[] = [],
    readonly requestMethod: string | null = null,
    readonly requestHeaders: readonly HttpHeader[] = [],
    readonly requestBody: string | null = null,
    readonly capturedAtMs: number | null = null,
  ) {}

  /** Parse and return the captured response body as JSON. */
  json(): unknown {
    if (this.body === null) {
      throw new Error(`captured response for ${JSON.stringify(this.url)} has no body`);
    }
    return JSON.parse(this.body) as unknown;
  }
}

/** Curated opt-in L4 host blocklist preset names accepted by `LaunchOptions.blockPresets`. */
export const BLOCK_PRESETS = ["analytics", "ads", "media"] as const;
export type BlockPreset = (typeof BLOCK_PRESETS)[number];

/** Per-session bandwidth and connection counters tracked by the daemon proxy. */
export interface NetworkStats {
  readonly bytesSent: number;
  readonly bytesReceived: number;
  readonly connectionsTotal: number;
  readonly connectionsBlocked: number;
}

/** Accessibility tree snapshot along with truncation metadata. */
export interface TreeSnapshot {
  readonly nodes: AccessibilityNode[];
  readonly truncated: boolean;
}

/** Metadata describing an open browser window tracked by the backend. */
export interface WindowSummary {
  readonly id: number;
  readonly title: string;
  readonly appId: string;
  readonly width: number;
  readonly height: number;
  readonly hasBuffer: boolean;
}

/** Semantic query resolved by the daemon. */
export interface LocatorQuery {
  readonly role: Role | null;
  readonly name: string | null;
  readonly exact: boolean;
  readonly nth: number;
  readonly within: LocatorQuery | null;
  readonly strict?: boolean;
}

/** Exact TLS `ClientHello` fingerprint observed on the wire from the live browser. */
export interface TlsFingerprint {
  readonly tlsVersion: number;
  readonly cipherSuites: readonly number[];
  readonly extensions: readonly number[];
  readonly supportedGroups: readonly number[];
  readonly ecPointFormats: readonly number[];
  readonly signatureAlgorithms: readonly number[];
  readonly alpnProtocols: readonly string[];
  readonly supportedVersions: readonly number[];
  readonly certCompressionAlgorithms: readonly number[];
  readonly alpsProtocols: readonly string[];
  readonly alpsUseNewCodepoint: boolean;
  readonly pskKeyExchangeModes: readonly number[];
  readonly greasePresent: boolean;
  readonly hasStatusRequest: boolean;
  readonly hasSignedCertTimestamp: boolean;
  readonly hasSessionTicket: boolean;
  readonly hasExtendedMasterSecret: boolean;
  readonly hasRenegotiationInfo: boolean;
  readonly hasEch: boolean;
  readonly ja3String: string;
  readonly ja3Hash: string;
  readonly ja4: string;
}

/** Single HTTP/2 `SETTINGS` frame parameter in wire order. */
export interface Http2Setting {
  readonly id: number;
  readonly value: number;
}

/** HTTP/2 `HEADERS` frame stream dependency / priority fields (RFC 9113). */
export interface Http2StreamDependency {
  readonly dependencyId: number;
  readonly weight: number;
  readonly exclusive: boolean;
}

/** Exact HTTP/2 connection & header framing fingerprint observed from the live browser. */
export interface Http2Fingerprint {
  readonly settings: readonly Http2Setting[];
  readonly initialWindowUpdate: number | null;
  readonly pseudoHeaderOrder: readonly string[];
  readonly headersPriority?: Http2StreamDependency | null;
  readonly akamaiFingerprint: string;
}

/** Ordered HTTP header `(name, value)` pair preserving exact wire order. */
export interface HeaderEntry {
  readonly name: string;
  readonly value: string;
}

/** Cookie captured passively from live browser `Cookie` / `Set-Cookie` headers. */
export interface CapturedCookie {
  readonly name: string;
  readonly value: string;
  readonly domain: string;
  readonly path: string;
  readonly secure: boolean;
  readonly httpOnly: boolean;
}

/** Complete live wire fingerprint + cookie jar snapshot of a running browser session. */
export interface SessionFingerprint {
  readonly tls: TlsFingerprint | null;
  readonly http2: Http2Fingerprint | null;
  readonly defaultHeaders: readonly HeaderEntry[];
  readonly apiHeaders?: readonly HeaderEntry[];
  readonly cookies: readonly CapturedCookie[];
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseIntOr(raw: unknown, fallback = 0): number {
  return typeof raw === "number" && Number.isInteger(raw) ? raw : fallback;
}

function parseOptionalInt(raw: unknown): number | null {
  return typeof raw === "number" && Number.isInteger(raw) ? raw : null;
}

function parseIntArray(raw: unknown): number[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  const out: number[] = [];
  for (const item of raw) {
    if (typeof item === "number" && Number.isInteger(item)) {
      out.push(item);
    }
  }
  return out;
}

function parseStringArray(raw: unknown): string[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  const out: string[] = [];
  for (const item of raw) {
    if (typeof item === "string") {
      out.push(item);
    }
  }
  return out;
}

function parseStringOr(raw: unknown, fallback = ""): string {
  return typeof raw === "string" ? raw : fallback;
}

function parseHeaderEntries(raw: unknown): HeaderEntry[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  const out: HeaderEntry[] = [];
  for (const entry of raw) {
    if (isPlainObject(entry)) {
      out.push({
        name: entry.name === undefined || entry.name === null ? "" : String(entry.name),
        value: entry.value === undefined || entry.value === null ? "" : String(entry.value),
      });
    }
  }
  return out;
}

/** @internal Parse one `CapturedCookie` from wire JSON (snake_case or camelCase). */
export function parseCapturedCookie(entry: Record<string, unknown>): CapturedCookie {
  return {
    name: entry.name === undefined || entry.name === null ? "" : String(entry.name),
    value: entry.value === undefined || entry.value === null ? "" : String(entry.value),
    domain: entry.domain === undefined || entry.domain === null ? "" : String(entry.domain),
    path: entry.path === undefined || entry.path === null ? "/" : String(entry.path),
    secure: entry.secure === true,
    httpOnly: (entry.http_only ?? entry.httpOnly) === true,
  };
}

function parseTlsFingerprint(raw: Record<string, unknown>): TlsFingerprint {
  return {
    tlsVersion: parseIntOr(raw.tls_version ?? raw.tlsVersion),
    cipherSuites: parseIntArray(raw.cipher_suites ?? raw.cipherSuites),
    extensions: parseIntArray(raw.extensions),
    supportedGroups: parseIntArray(raw.supported_groups ?? raw.supportedGroups),
    ecPointFormats: parseIntArray(raw.ec_point_formats ?? raw.ecPointFormats),
    signatureAlgorithms: parseIntArray(raw.signature_algorithms ?? raw.signatureAlgorithms),
    alpnProtocols: parseStringArray(raw.alpn_protocols ?? raw.alpnProtocols),
    supportedVersions: parseIntArray(raw.supported_versions ?? raw.supportedVersions),
    certCompressionAlgorithms: parseIntArray(
      raw.cert_compression_algorithms ?? raw.certCompressionAlgorithms,
    ),
    alpsProtocols: parseStringArray(raw.alps_protocols ?? raw.alpsProtocols),
    alpsUseNewCodepoint: (raw.alps_use_new_codepoint ?? raw.alpsUseNewCodepoint) === true,
    pskKeyExchangeModes: parseIntArray(raw.psk_key_exchange_modes ?? raw.pskKeyExchangeModes),
    greasePresent: (raw.grease_present ?? raw.greasePresent) === true,
    hasStatusRequest: (raw.has_status_request ?? raw.hasStatusRequest) === true,
    hasSignedCertTimestamp: (raw.has_signed_cert_timestamp ?? raw.hasSignedCertTimestamp) === true,
    hasSessionTicket: (raw.has_session_ticket ?? raw.hasSessionTicket) === true,
    hasExtendedMasterSecret:
      (raw.has_extended_master_secret ?? raw.hasExtendedMasterSecret) === true,
    hasRenegotiationInfo: (raw.has_renegotiation_info ?? raw.hasRenegotiationInfo) === true,
    hasEch: (raw.has_ech ?? raw.hasEch) === true,
    ja3String: parseStringOr(raw.ja3_string ?? raw.ja3String),
    ja3Hash: parseStringOr(raw.ja3_hash ?? raw.ja3Hash),
    ja4: parseStringOr(raw.ja4),
  };
}

function parseHttp2Fingerprint(raw: Record<string, unknown>): Http2Fingerprint {
  const settings: Http2Setting[] = [];
  if (Array.isArray(raw.settings)) {
    for (const entry of raw.settings) {
      if (isPlainObject(entry)) {
        settings.push({
          id: parseIntOr(entry.id),
          value: parseIntOr(entry.value),
        });
      }
    }
  }
  const rawPriority = raw.headers_priority ?? raw.headersPriority;
  let headersPriority: Http2StreamDependency | null = null;
  if (isPlainObject(rawPriority)) {
    headersPriority = {
      dependencyId: parseIntOr(rawPriority.dependency_id ?? rawPriority.dependencyId),
      weight: parseIntOr(rawPriority.weight),
      exclusive: rawPriority.exclusive === true,
    };
  }
  return {
    settings,
    initialWindowUpdate: parseOptionalInt(raw.initial_window_update ?? raw.initialWindowUpdate),
    pseudoHeaderOrder: parseStringArray(raw.pseudo_header_order ?? raw.pseudoHeaderOrder),
    headersPriority,
    akamaiFingerprint: parseStringOr(raw.akamai_fingerprint ?? raw.akamaiFingerprint),
  };
}

/**
 * Parse a JSON object matching `waybound_core::SessionFingerprint` (snake_case wire format,
 * or TypeScript camelCase) into a typed `SessionFingerprint`.
 */
export function parseSessionFingerprint(raw: unknown): SessionFingerprint {
  if (!isPlainObject(raw)) {
    throw new TypeError("expected JSON object for SessionFingerprint");
  }
  const tls = isPlainObject(raw.tls) ? parseTlsFingerprint(raw.tls) : null;
  const http2 = isPlainObject(raw.http2) ? parseHttp2Fingerprint(raw.http2) : null;
  const defaultHeaders = parseHeaderEntries(raw.default_headers ?? raw.defaultHeaders);
  const apiHeaders = parseHeaderEntries(raw.api_headers ?? raw.apiHeaders);
  const cookies: CapturedCookie[] = [];
  if (Array.isArray(raw.cookies)) {
    for (const entry of raw.cookies) {
      if (isPlainObject(entry)) {
        cookies.push(parseCapturedCookie(entry));
      }
    }
  }
  return {
    tls,
    http2,
    defaultHeaders,
    apiHeaders,
    cookies,
  };
}

/**
 * Serialize a `SessionFingerprint` to the snake_case JSON object expected by
 * `waybound_core::SessionFingerprint` and `waybound-daemon --replay`.
 */
export function serializeSessionFingerprint(fp: SessionFingerprint): Record<string, unknown> {
  return {
    tls:
      fp.tls === null
        ? null
        : {
            tls_version: fp.tls.tlsVersion,
            cipher_suites: [...fp.tls.cipherSuites],
            extensions: [...fp.tls.extensions],
            supported_groups: [...fp.tls.supportedGroups],
            ec_point_formats: [...fp.tls.ecPointFormats],
            signature_algorithms: [...fp.tls.signatureAlgorithms],
            alpn_protocols: [...fp.tls.alpnProtocols],
            supported_versions: [...fp.tls.supportedVersions],
            cert_compression_algorithms: [...fp.tls.certCompressionAlgorithms],
            alps_protocols: [...fp.tls.alpsProtocols],
            alps_use_new_codepoint: fp.tls.alpsUseNewCodepoint,
            psk_key_exchange_modes: [...fp.tls.pskKeyExchangeModes],
            grease_present: fp.tls.greasePresent,
            has_status_request: fp.tls.hasStatusRequest,
            has_signed_cert_timestamp: fp.tls.hasSignedCertTimestamp,
            has_session_ticket: fp.tls.hasSessionTicket,
            has_extended_master_secret: fp.tls.hasExtendedMasterSecret,
            has_renegotiation_info: fp.tls.hasRenegotiationInfo,
            has_ech: fp.tls.hasEch,
            ja3_string: fp.tls.ja3String,
            ja3_hash: fp.tls.ja3Hash,
            ja4: fp.tls.ja4,
          },
    http2:
      fp.http2 === null
        ? null
        : {
            settings: fp.http2.settings.map((s) => ({ id: s.id, value: s.value })),
            initial_window_update: fp.http2.initialWindowUpdate,
            pseudo_header_order: [...fp.http2.pseudoHeaderOrder],
            headers_priority:
              fp.http2.headersPriority === undefined || fp.http2.headersPriority === null
                ? null
                : {
                    dependency_id: fp.http2.headersPriority.dependencyId,
                    weight: fp.http2.headersPriority.weight,
                    exclusive: fp.http2.headersPriority.exclusive,
                  },
            akamai_fingerprint: fp.http2.akamaiFingerprint,
          },
    default_headers: fp.defaultHeaders.map((h) => ({ name: h.name, value: h.value })),
    api_headers: (fp.apiHeaders ?? []).map((h) => ({ name: h.name, value: h.value })),
    cookies: fp.cookies.map((c) => ({
      name: c.name,
      value: c.value,
      domain: c.domain,
      path: c.path,
      secure: c.secure,
      http_only: c.httpOnly,
    })),
  };
}

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

/** Semantic query resolved by the daemon. */
export interface LocatorQuery {
  readonly role: Role | null;
  readonly name: string | null;
  readonly exact: boolean;
  readonly nth: number;
  readonly within: LocatorQuery | null;
  readonly strict?: boolean;
}

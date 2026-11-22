//! Pure-Rust native X11 input injection (`XTEST`) and screenshot capture (`GetImage` + `png`).
//!
//! Replaces per-event `xdotool` and `scrot` subprocesses with a single persistent
//! `x11rb::rust_connection::RustConnection`, reducing input latency from ~20 ms per
//! event to sub-millisecond and screenshot capture to in-memory PNG encoding.

use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use std::thread;
use std::time::Duration;

use tracing::debug;
use waybound_core::{InputEvent, KeyCode, KeyModifier, MouseButton, Result, WayboundError};
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{
    BUTTON_PRESS_EVENT, BUTTON_RELEASE_EVENT, ConnectionExt, ImageFormat, KEY_PRESS_EVENT,
    KEY_RELEASE_EVENT, MOTION_NOTIFY_EVENT, Window,
};
use x11rb::protocol::xtest::ConnectionExt as XTestConnectionExt;
use x11rb::rust_connection::RustConnection;

use crate::input::try_paste_unicode_x11;
use crate::process::BACKEND_NAME;

// Standard X11 keysym constants (from <X11/keysymdef.h>).
const XK_BACKSPACE: u32 = 0xFF08;
const XK_TAB: u32 = 0xFF09;
const XK_RETURN: u32 = 0xFF0D;
const XK_ESCAPE: u32 = 0xFF1B;
const XK_HOME: u32 = 0xFF50;
const XK_LEFT: u32 = 0xFF51;
const XK_UP: u32 = 0xFF52;
const XK_RIGHT: u32 = 0xFF53;
const XK_DOWN: u32 = 0xFF54;
const XK_PAGE_UP: u32 = 0xFF55;
const XK_PAGE_DOWN: u32 = 0xFF56;
const XK_END: u32 = 0xFF57;
const XK_DELETE: u32 = 0xFFFF;
const XK_SPACE: u32 = 0x0020;

const XK_SHIFT_L: u32 = 0xFFE1;
const XK_CONTROL_L: u32 = 0xFFE3;
const XK_ALT_L: u32 = 0xFFE9;
const XK_SUPER_L: u32 = 0xFFEB;

/// Persistent pure-Rust X11 connection for sub-millisecond `XTEST` input and `GetImage` capture.
pub struct X11Client {
    conn: RustConnection,
    root: Window,
    width: u16,
    height: u16,
    display: Option<String>,
    /// Map from X11 keysym -> `(keycode, needs_shift)`.
    keymap: HashMap<u32, (u8, bool)>,
    shift_keycode: Option<u8>,
}

impl std::fmt::Debug for X11Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X11Client")
            .field("root", &self.root)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("display", &self.display)
            .field("keymap_entries", &self.keymap.len())
            .finish_non_exhaustive()
    }
}

impl X11Client {
    /// Connects to the X11 server (using `display` or `$DISPLAY`), verifies `XTEST` is
    /// available, and caches the server's keyboard mapping.
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] if connecting to X11 fails or
    /// the `XTEST` extension is unavailable.
    pub fn connect(display: Option<&str>) -> Result<Self> {
        let (conn, screen_num) =
            RustConnection::connect(display).map_err(|err| WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!("failed to connect to X11 display {display:?}: {err}"),
            })?;

        // Verify XTEST extension is present on the server.
        let _ = conn
            .xtest_get_version(2, 1)
            .map_err(|err| WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!("XTEST query failed: {err}"),
            })?
            .reply()
            .map_err(|err| WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!("XTEST extension unavailable: {err}"),
            })?;

        let screen = conn.setup().roots.get(screen_num).ok_or_else(|| {
            WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!("invalid X11 screen index {screen_num}"),
            }
        })?;
        let root = screen.root;
        let width = screen.width_in_pixels;
        let height = screen.height_in_pixels;

        let min_kc = conn.setup().min_keycode;
        let max_kc = conn.setup().max_keycode;
        let count = max_kc.saturating_sub(min_kc).saturating_add(1);
        let mapping = conn
            .get_keyboard_mapping(min_kc, count)
            .map_err(|err| WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!("failed to query X11 keyboard mapping: {err}"),
            })?
            .reply()
            .map_err(|err| WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!("failed to read X11 keyboard mapping reply: {err}"),
            })?;

        let keymap = build_keymap(min_kc, mapping.keysyms_per_keycode, &mapping.keysyms);
        let shift_keycode = keymap.get(&XK_SHIFT_L).map(|&(kc, _)| kc);

        debug!(
            root,
            width,
            height,
            keysyms = keymap.len(),
            "connected native pure-Rust X11Client"
        );

        Ok(Self {
            conn,
            root,
            width,
            height,
            display: display.map(str::to_owned),
            keymap,
            shift_keycode,
        })
    }

    /// Dispatches an [`InputEvent`] directly over X11 `XTEST` with zero subprocess forks.
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] if the X11 connection fails or a
    /// key cannot be mapped.
    pub fn dispatch_input(&self, event: &InputEvent) -> Result<()> {
        match event {
            InputEvent::PointerMove { to } => {
                let x = clamp_i16(to.x);
                let y = clamp_i16(to.y);
                self.fake_input(MOTION_NOTIFY_EVENT, 0, x, y)?;
                self.flush()
            }
            InputEvent::MouseClick { button, hold_ms } => {
                let detail = match button {
                    MouseButton::Left => 1,
                    MouseButton::Middle => 2,
                    MouseButton::Right => 3,
                };
                self.fake_input(BUTTON_PRESS_EVENT, detail, 0, 0)?;
                self.flush()?;
                if *hold_ms > 0 {
                    thread::sleep(Duration::from_millis((*hold_ms).min(1_000)));
                }
                self.fake_input(BUTTON_RELEASE_EVENT, detail, 0, 0)?;
                self.flush()
            }
            InputEvent::Scroll { delta_x, delta_y } => self.dispatch_scroll(*delta_x, *delta_y),
            InputEvent::KeyPress {
                key,
                modifiers,
                hold_ms,
            } => self.dispatch_key(key, modifiers, *hold_ms),
        }
    }

    fn dispatch_scroll(&self, delta_x: f64, delta_y: f64) -> Result<()> {
        let y_steps = scroll_steps(delta_y);
        if y_steps > 0 {
            let btn = if delta_y < 0.0 { 5 } else { 4 };
            for _ in 0..y_steps {
                self.fake_input(BUTTON_PRESS_EVENT, btn, 0, 0)?;
                self.fake_input(BUTTON_RELEASE_EVENT, btn, 0, 0)?;
                self.flush()?;
                thread::sleep(Duration::from_millis(8));
            }
        }
        let x_steps = scroll_steps(delta_x);
        if x_steps > 0 {
            let btn = if delta_x < 0.0 { 6 } else { 7 };
            for _ in 0..x_steps {
                self.fake_input(BUTTON_PRESS_EVENT, btn, 0, 0)?;
                self.fake_input(BUTTON_RELEASE_EVENT, btn, 0, 0)?;
                self.flush()?;
                thread::sleep(Duration::from_millis(8));
            }
        }
        Ok(())
    }

    fn dispatch_key(&self, key: &KeyCode, modifiers: &[KeyModifier], hold_ms: u64) -> Result<()> {
        // Non-ASCII characters (accented Latin, CJK, emoji) are pasted via X11 clipboard + Ctrl+v.
        if modifiers.is_empty()
            && let KeyCode::Char(ch) = key
            && !ch.is_ascii()
            && !ch.is_control()
        {
            if try_paste_unicode_x11(*ch, self.display.as_deref())? {
                return Ok(());
            }
            return Err(WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!("xclip unavailable for non-ASCII character {ch:?}"),
            });
        }

        let keysym = keycode_to_keysym(key).ok_or_else(|| WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!("no X11 keysym for key {key:?}"),
        })?;

        let (kc, needs_shift) =
            self.keymap
                .get(&keysym)
                .copied()
                .ok_or_else(|| WayboundError::BackendUnavailable {
                    backend: BACKEND_NAME.to_owned(),
                    reason: format!("keysym 0x{keysym:04X} not present in X11 keyboard map"),
                })?;

        let mut mod_kcs: Vec<u8> = Vec::with_capacity(modifiers.len() + 1);
        for m in modifiers {
            if let Some(&(mkc, _)) = self.keymap.get(&modifier_keysym(*m))
                && !mod_kcs.contains(&mkc)
            {
                mod_kcs.push(mkc);
            }
        }
        if needs_shift
            && let Some(shift_kc) = self.shift_keycode
            && !mod_kcs.contains(&shift_kc)
        {
            mod_kcs.push(shift_kc);
        }

        for &mkc in &mod_kcs {
            self.fake_input(KEY_PRESS_EVENT, mkc, 0, 0)?;
        }
        self.fake_input(KEY_PRESS_EVENT, kc, 0, 0)?;
        self.flush()?;

        if hold_ms > 0 {
            thread::sleep(Duration::from_millis(hold_ms.min(1_000)));
        }

        self.fake_input(KEY_RELEASE_EVENT, kc, 0, 0)?;
        for &mkc in mod_kcs.iter().rev() {
            self.fake_input(KEY_RELEASE_EVENT, mkc, 0, 0)?;
        }
        self.flush()
    }

    /// Captures the full root window directly over X11 `GetImage` and writes a PNG to `output_path`.
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] if `GetImage` or PNG encoding fails,
    /// or [`WayboundError::Io`] if creating `output_path` fails.
    pub fn capture_png(&self, output_path: &Path) -> Result<()> {
        let reply = self
            .conn
            .get_image(
                ImageFormat::Z_PIXMAP,
                self.root,
                0,
                0,
                self.width,
                self.height,
                u32::MAX,
            )
            .map_err(|err| WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!("X11 GetImage request failed: {err}"),
            })?
            .reply()
            .map_err(|err| WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!("X11 GetImage reply failed: {err}"),
            })?;

        let rgb = bgrx_to_rgb(
            &reply.data,
            usize::from(self.width),
            usize::from(self.height),
        )
        .ok_or_else(|| WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!(
                "unexpected X11 GetImage byte length {} for {}x{} (depth {})",
                reply.data.len(),
                self.width,
                self.height,
                reply.depth
            ),
        })?;

        let file = File::create(output_path)?;
        let writer = BufWriter::new(file);
        let mut encoder = png::Encoder::new(writer, u32::from(self.width), u32::from(self.height));
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut png_writer =
            encoder
                .write_header()
                .map_err(|err| WayboundError::BackendUnavailable {
                    backend: BACKEND_NAME.to_owned(),
                    reason: format!("failed to write PNG header: {err}"),
                })?;
        png_writer
            .write_image_data(&rgb)
            .map_err(|err| WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!("failed to encode PNG pixels: {err}"),
            })?;
        Ok(())
    }

    fn fake_input(&self, event_type: u8, detail: u8, root_x: i16, root_y: i16) -> Result<()> {
        let _ = self
            .conn
            .xtest_fake_input(event_type, detail, 0, self.root, root_x, root_y, 0)
            .map_err(|err| WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!("XTEST fake_input failed: {err}"),
            })?;
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        self.conn
            .flush()
            .map_err(|err| WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!("X11 flush failed: {err}"),
            })
    }
}

/// Builds a lookup table from X11 keysym -> `(keycode, needs_shift)` from `GetKeyboardMapping`.
#[must_use]
pub fn build_keymap(
    min_keycode: u8,
    keysyms_per_keycode: u8,
    keysyms: &[u32],
) -> HashMap<u32, (u8, bool)> {
    let mut map = HashMap::new();
    let stride = usize::from(keysyms_per_keycode);
    if stride == 0 {
        return map;
    }

    for (idx, chunk) in keysyms.chunks_exact(stride).enumerate() {
        let Ok(offset) = u8::try_from(idx) else {
            break;
        };
        let Some(kc) = min_keycode.checked_add(offset) else {
            break;
        };
        // Column 0: unshifted keysym (preferred if keysym appears in both columns).
        if let Some(&sym0) = chunk.first()
            && sym0 != 0
        {
            let _ = map.entry(sym0).or_insert((kc, false));
        }
        // Column 1: shifted keysym.
        if let Some(&sym1) = chunk.get(1)
            && sym1 != 0
        {
            let _ = map.entry(sym1).or_insert((kc, true));
        }
    }
    map
}

/// Converts X11 32-bit `BGRX` / `BGRA` little-endian pixels to packed 24-bit `RGB`.
#[must_use]
pub fn bgrx_to_rgb(data: &[u8], width: usize, height: usize) -> Option<Vec<u8>> {
    let pixels = width.checked_mul(height)?;
    let expected = pixels.checked_mul(4)?;
    if data.len() < expected {
        return None;
    }
    let mut rgb = Vec::with_capacity(pixels.checked_mul(3)?);
    for px in data[..expected].chunks_exact(4) {
        rgb.push(px[2]); // R
        rgb.push(px[1]); // G
        rgb.push(px[0]); // B
    }
    Some(rgb)
}

const fn modifier_keysym(modifier: KeyModifier) -> u32 {
    match modifier {
        KeyModifier::Shift => XK_SHIFT_L,
        KeyModifier::Control => XK_CONTROL_L,
        KeyModifier::Alt => XK_ALT_L,
        KeyModifier::Meta => XK_SUPER_L,
    }
}

/// Maps a [`KeyCode`] to its X11 keysym (ASCII characters map 1:1 to their Unicode scalar).
#[must_use]
pub const fn keycode_to_keysym(key: &KeyCode) -> Option<u32> {
    match key {
        KeyCode::Enter => Some(XK_RETURN),
        KeyCode::Tab => Some(XK_TAB),
        KeyCode::Escape => Some(XK_ESCAPE),
        KeyCode::Backspace => Some(XK_BACKSPACE),
        KeyCode::ArrowLeft => Some(XK_LEFT),
        KeyCode::ArrowRight => Some(XK_RIGHT),
        KeyCode::ArrowUp => Some(XK_UP),
        KeyCode::ArrowDown => Some(XK_DOWN),
        KeyCode::Space => Some(XK_SPACE),
        KeyCode::Delete => Some(XK_DELETE),
        KeyCode::Home => Some(XK_HOME),
        KeyCode::End => Some(XK_END),
        KeyCode::PageUp => Some(XK_PAGE_UP),
        KeyCode::PageDown => Some(XK_PAGE_DOWN),
        KeyCode::Char(ch) if ch.is_ascii() && !ch.is_ascii_control() => Some(*ch as u32),
        KeyCode::Char(_) => None,
    }
}

fn clamp_i16(value: f64) -> i16 {
    if !value.is_finite() {
        return 0;
    }
    let clamped = value
        .round()
        .clamp(f64::from(i16::MIN), f64::from(i16::MAX));
    #[allow(clippy::cast_possible_truncation)]
    {
        clamped as i16
    }
}

fn scroll_steps(delta: f64) -> u32 {
    if !delta.is_finite() || delta == 0.0 {
        return 0;
    }
    let mag = delta.abs().round().clamp(1.0, 50.0);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    {
        mag as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_special_and_ascii_keys_to_x11_keysyms() {
        assert_eq!(keycode_to_keysym(&KeyCode::Enter), Some(XK_RETURN));
        assert_eq!(keycode_to_keysym(&KeyCode::ArrowDown), Some(XK_DOWN));
        assert_eq!(
            keycode_to_keysym(&KeyCode::Char('a')),
            Some(u32::from(b'a'))
        );
        assert_eq!(
            keycode_to_keysym(&KeyCode::Char('@')),
            Some(u32::from(b'@'))
        );
        assert_eq!(keycode_to_keysym(&KeyCode::Char('東')), None);
    }

    #[test]
    fn builds_keymap_with_unshifted_and_shifted_columns() {
        // Keycode 38 -> ('a', 'A'), Keycode 50 -> (Shift_L, 0)
        let syms = vec![u32::from(b'a'), u32::from(b'A'), XK_SHIFT_L, 0];
        let map = build_keymap(38, 2, &syms);
        assert_eq!(map.get(&u32::from(b'a')), Some(&(38, false)));
        assert_eq!(map.get(&u32::from(b'A')), Some(&(38, true)));
        assert_eq!(map.get(&XK_SHIFT_L), Some(&(39, false)));
    }

    #[test]
    fn converts_bgrx_pixels_to_rgb() {
        let bgrx = [10u8, 20, 30, 255, 40, 50, 60, 0];
        assert_eq!(bgrx_to_rgb(&bgrx, 2, 1), Some(vec![30, 20, 10, 60, 50, 40]));
        assert_eq!(bgrx_to_rgb(&bgrx[..4], 2, 1), None);
    }
}

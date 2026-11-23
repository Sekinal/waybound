//! Embedded US-QWERTY XKB keymap and Linux `evdev` keycode mapping.

use waybound_core::{KeyCode, KeyModifier};

/// XKB modifier mask bit for Shift (`ShiftMask`).
pub const XKB_MOD_SHIFT: u32 = 1 << 0;
/// XKB modifier mask bit for Control (`ControlMask`).
pub const XKB_MOD_CTRL: u32 = 1 << 2;
/// XKB modifier mask bit for Alt (`Mod1Mask`).
pub const XKB_MOD_ALT: u32 = 1 << 3;
/// XKB modifier mask bit for Meta/Super (`Mod4Mask`).
pub const XKB_MOD_META: u32 = 1 << 6;

/// Linux `evdev` keycode for Left Control (`KEY_LEFTCTRL`).
pub const EVDEV_LEFTCTRL: u32 = 29;
/// Linux `evdev` keycode for Left Shift (`KEY_LEFTSHIFT`).
pub const EVDEV_LEFTSHIFT: u32 = 42;
/// Linux `evdev` keycode for Left Alt (`KEY_LEFTALT`).
pub const EVDEV_LEFTALT: u32 = 56;
/// Linux `evdev` keycode for Left Meta/Super (`KEY_LEFTMETA`).
pub const EVDEV_LEFTMETA: u32 = 125;

/// Self-contained minimal valid US-QWERTY `xkb_keymap` text for `wl_keyboard::keymap`.
///
/// Keycodes follow the standard Linux `evdev` + 8 offset expected by `libxkbcommon`.
pub const XKB_US_KEYMAP: &str = r#"xkb_keymap {
xkb_keycodes "evdev" {
    minimum = 8;
    maximum = 255;
    <ESC>  = 9;
    <AE01> = 10;
    <AE02> = 11;
    <AE03> = 12;
    <AE04> = 13;
    <AE05> = 14;
    <AE06> = 15;
    <AE07> = 16;
    <AE08> = 17;
    <AE09> = 18;
    <AE10> = 19;
    <AE11> = 20;
    <AE12> = 21;
    <BKSP> = 22;
    <TAB>  = 23;
    <AD01> = 24;
    <AD02> = 25;
    <AD03> = 26;
    <AD04> = 27;
    <AD05> = 28;
    <AD06> = 29;
    <AD07> = 30;
    <AD08> = 31;
    <AD09> = 32;
    <AD10> = 33;
    <AD11> = 34;
    <AD12> = 35;
    <RTRN> = 36;
    <LCTL> = 37;
    <AC01> = 38;
    <AC02> = 39;
    <AC03> = 40;
    <AC04> = 41;
    <AC05> = 42;
    <AC06> = 43;
    <AC07> = 44;
    <AC08> = 45;
    <AC09> = 46;
    <AC10> = 47;
    <AC11> = 48;
    <TLDE> = 49;
    <LFSH> = 50;
    <BKSL> = 51;
    <AB01> = 52;
    <AB02> = 53;
    <AB03> = 54;
    <AB04> = 55;
    <AB05> = 56;
    <AB06> = 57;
    <AB07> = 58;
    <AB08> = 59;
    <AB09> = 60;
    <AB10> = 61;
    <RTSH> = 62;
    <LALT> = 64;
    <SPCE> = 65;
    <CAPS> = 66;
    <RCTL> = 105;
    <RALT> = 108;
    <HOME> = 110;
    <UP>   = 111;
    <PGUP> = 112;
    <LEFT> = 113;
    <RGHT> = 114;
    <END>  = 115;
    <DOWN> = 116;
    <PGDN> = 117;
    <DELE> = 119;
    <LWIN> = 133;
    <RWIN> = 134;
};

xkb_types "complete" {
    virtual_modifiers NumLock,Alt,LevelThree,LAlt,RAlt,RControl,LControl,ScrollLock,LevelFive,AltGr,Meta,Super,Hyper;

    type "ONE_LEVEL" {
        modifiers= none;
        level_name[Level1]= "Any";
    };
    type "TWO_LEVEL" {
        modifiers= Shift;
        map[Shift]= Level2;
        level_name[Level1]= "Base";
        level_name[Level2]= "Shift";
    };
    type "ALPHABETIC" {
        modifiers= Shift+Lock;
        map[Shift]= Level2;
        map[Lock]= Level2;
        level_name[Level1]= "Base";
        level_name[Level2]= "Caps";
    };
};

xkb_compatibility "complete" {
    virtual_modifiers NumLock,Alt,LevelThree,LAlt,RAlt,RControl,LControl,ScrollLock,LevelFive,AltGr,Meta,Super,Hyper;

    interpret.useModMapMods= AnyLevel;
    interpret.repeat= False;
    interpret Caps_Lock+AnyOfOrNone(all) {
        action= LockMods(modifiers=Lock);
    };
    interpret Any+AnyOf(all) {
        action= SetMods(modifiers=modMapMods,clearLocks);
    };
};

xkb_symbols "pc_us" {
    name[group1]="English (US)";

    key <ESC>  { [ Escape ] };
    key <AE01> { [ 1, exclam ] };
    key <AE02> { [ 2, at ] };
    key <AE03> { [ 3, numbersign ] };
    key <AE04> { [ 4, dollar ] };
    key <AE05> { [ 5, percent ] };
    key <AE06> { [ 6, asciicircum ] };
    key <AE07> { [ 7, ampersand ] };
    key <AE08> { [ 8, asterisk ] };
    key <AE09> { [ 9, parenleft ] };
    key <AE10> { [ 0, parenright ] };
    key <AE11> { [ minus, underscore ] };
    key <AE12> { [ equal, plus ] };
    key <BKSP> { [ BackSpace ] };
    key <TAB>  { [ Tab, ISO_Left_Tab ] };
    key <AD01> { [ q, Q ] };
    key <AD02> { [ w, W ] };
    key <AD03> { [ e, E ] };
    key <AD04> { [ r, R ] };
    key <AD05> { [ t, T ] };
    key <AD06> { [ y, Y ] };
    key <AD07> { [ u, U ] };
    key <AD08> { [ i, I ] };
    key <AD09> { [ o, O ] };
    key <AD10> { [ p, P ] };
    key <AD11> { [ bracketleft, braceleft ] };
    key <AD12> { [ bracketright, braceright ] };
    key <RTRN> { [ Return ] };
    key <LCTL> { [ Control_L ] };
    key <AC01> { [ a, A ] };
    key <AC02> { [ s, S ] };
    key <AC03> { [ d, D ] };
    key <AC04> { [ f, F ] };
    key <AC05> { [ g, G ] };
    key <AC06> { [ h, H ] };
    key <AC07> { [ j, J ] };
    key <AC08> { [ k, K ] };
    key <AC09> { [ l, L ] };
    key <AC10> { [ semicolon, colon ] };
    key <AC11> { [ apostrophe, quotedbl ] };
    key <TLDE> { [ grave, asciitilde ] };
    key <LFSH> { [ Shift_L ] };
    key <BKSL> { [ backslash, bar ] };
    key <AB01> { [ z, Z ] };
    key <AB02> { [ x, X ] };
    key <AB03> { [ c, C ] };
    key <AB04> { [ v, V ] };
    key <AB05> { [ b, B ] };
    key <AB06> { [ n, N ] };
    key <AB07> { [ m, M ] };
    key <AB08> { [ comma, less ] };
    key <AB09> { [ period, greater ] };
    key <AB10> { [ slash, question ] };
    key <RTSH> { [ Shift_R ] };
    key <LALT> { [ Alt_L ] };
    key <SPCE> { [ space ] };
    key <CAPS> { [ Caps_Lock ] };
    key <RCTL> { [ Control_R ] };
    key <RALT> { [ Alt_R ] };
    key <HOME> { [ Home ] };
    key <UP>   { [ Up ] };
    key <PGUP> { [ Prior ] };
    key <LEFT> { [ Left ] };
    key <RGHT> { [ Right ] };
    key <END>  { [ End ] };
    key <DOWN> { [ Down ] };
    key <PGDN> { [ Next ] };
    key <DELE> { [ Delete ] };
    key <LWIN> { [ Super_L ] };
    key <RWIN> { [ Super_R ] };

    modifier_map Shift   { <LFSH>, <RTSH> };
    modifier_map Lock    { <CAPS> };
    modifier_map Control { <LCTL>, <RCTL> };
    modifier_map Mod1    { <LALT>, <RALT> };
    modifier_map Mod4    { <LWIN>, <RWIN> };
};
};
"#;

/// Maps a [`KeyCode`] to its Linux `evdev` keycode and whether Shift must be held.
///
/// Returns `None` for characters that cannot be expressed on a US-QWERTY keyboard.
#[must_use]
pub const fn keycode_to_evdev(key: &KeyCode) -> Option<(u32, bool)> {
    match key {
        KeyCode::Escape => Some((1, false)),
        KeyCode::Backspace => Some((14, false)),
        KeyCode::Tab => Some((15, false)),
        KeyCode::Enter => Some((28, false)),
        KeyCode::Space => Some((57, false)),
        KeyCode::Home => Some((102, false)),
        KeyCode::ArrowUp => Some((103, false)),
        KeyCode::PageUp => Some((104, false)),
        KeyCode::ArrowLeft => Some((105, false)),
        KeyCode::ArrowRight => Some((106, false)),
        KeyCode::End => Some((107, false)),
        KeyCode::ArrowDown => Some((108, false)),
        KeyCode::PageDown => Some((109, false)),
        KeyCode::Delete => Some((111, false)),
        KeyCode::Char(ch) => char_to_evdev(*ch),
    }
}

const fn char_to_evdev(ch: char) -> Option<(u32, bool)> {
    match ch {
        '1' => Some((2, false)),
        '!' => Some((2, true)),
        '2' => Some((3, false)),
        '@' => Some((3, true)),
        '3' => Some((4, false)),
        '#' => Some((4, true)),
        '4' => Some((5, false)),
        '$' => Some((5, true)),
        '5' => Some((6, false)),
        '%' => Some((6, true)),
        '6' => Some((7, false)),
        '^' => Some((7, true)),
        '7' => Some((8, false)),
        '&' => Some((8, true)),
        '8' => Some((9, false)),
        '*' => Some((9, true)),
        '9' => Some((10, false)),
        '(' => Some((10, true)),
        '0' => Some((11, false)),
        ')' => Some((11, true)),
        '-' => Some((12, false)),
        '_' => Some((12, true)),
        '=' => Some((13, false)),
        '+' => Some((13, true)),
        '\t' => Some((15, false)),
        'q' => Some((16, false)),
        'Q' => Some((16, true)),
        'w' => Some((17, false)),
        'W' => Some((17, true)),
        'e' => Some((18, false)),
        'E' => Some((18, true)),
        'r' => Some((19, false)),
        'R' => Some((19, true)),
        't' => Some((20, false)),
        'T' => Some((20, true)),
        'y' => Some((21, false)),
        'Y' => Some((21, true)),
        'u' => Some((22, false)),
        'U' => Some((22, true)),
        'i' => Some((23, false)),
        'I' => Some((23, true)),
        'o' => Some((24, false)),
        'O' => Some((24, true)),
        'p' => Some((25, false)),
        'P' => Some((25, true)),
        '[' => Some((26, false)),
        '{' => Some((26, true)),
        ']' => Some((27, false)),
        '}' => Some((27, true)),
        '\n' | '\r' => Some((28, false)),
        'a' => Some((30, false)),
        'A' => Some((30, true)),
        's' => Some((31, false)),
        'S' => Some((31, true)),
        'd' => Some((32, false)),
        'D' => Some((32, true)),
        'f' => Some((33, false)),
        'F' => Some((33, true)),
        'g' => Some((34, false)),
        'G' => Some((34, true)),
        'h' => Some((35, false)),
        'H' => Some((35, true)),
        'j' => Some((36, false)),
        'J' => Some((36, true)),
        'k' => Some((37, false)),
        'K' => Some((37, true)),
        'l' => Some((38, false)),
        'L' => Some((38, true)),
        ';' => Some((39, false)),
        ':' => Some((39, true)),
        '\'' => Some((40, false)),
        '"' => Some((40, true)),
        '`' => Some((41, false)),
        '~' => Some((41, true)),
        '\\' => Some((43, false)),
        '|' => Some((43, true)),
        'z' => Some((44, false)),
        'Z' => Some((44, true)),
        'x' => Some((45, false)),
        'X' => Some((45, true)),
        'c' => Some((46, false)),
        'C' => Some((46, true)),
        'v' => Some((47, false)),
        'V' => Some((47, true)),
        'b' => Some((48, false)),
        'B' => Some((48, true)),
        'n' => Some((49, false)),
        'N' => Some((49, true)),
        'm' => Some((50, false)),
        'M' => Some((50, true)),
        ',' => Some((51, false)),
        '<' => Some((51, true)),
        '.' => Some((52, false)),
        '>' => Some((52, true)),
        '/' => Some((53, false)),
        '?' => Some((53, true)),
        ' ' => Some((57, false)),
        _ => None,
    }
}

/// Maps a [`KeyModifier`] to its corresponding Linux `evdev` left-side keycode.
#[must_use]
pub const fn modifier_to_evdev(modifier: KeyModifier) -> u32 {
    match modifier {
        KeyModifier::Shift => EVDEV_LEFTSHIFT,
        KeyModifier::Control => EVDEV_LEFTCTRL,
        KeyModifier::Alt => EVDEV_LEFTALT,
        KeyModifier::Meta => EVDEV_LEFTMETA,
    }
}

/// Computes the XKB depressed modifier bitmask for the given modifiers and implicit Shift state.
#[must_use]
pub fn modifier_xkb_mask(modifiers: &[KeyModifier], needs_shift: bool) -> u32 {
    let mut mask = if needs_shift { XKB_MOD_SHIFT } else { 0 };
    for modifier in modifiers {
        mask |= match modifier {
            KeyModifier::Shift => XKB_MOD_SHIFT,
            KeyModifier::Control => XKB_MOD_CTRL,
            KeyModifier::Alt => XKB_MOD_ALT,
            KeyModifier::Meta => XKB_MOD_META,
        };
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keymap_contains_required_xkb_sections() {
        assert!(XKB_US_KEYMAP.contains("xkb_keymap {"));
        assert!(XKB_US_KEYMAP.contains("xkb_keycodes"));
        assert!(XKB_US_KEYMAP.contains("xkb_types"));
        assert!(XKB_US_KEYMAP.contains("xkb_compatibility"));
        assert!(XKB_US_KEYMAP.contains("xkb_symbols"));
        assert!(XKB_US_KEYMAP.contains("<AC01> = 38;"));
        assert!(XKB_US_KEYMAP.contains("<RTRN> = 36;"));
        assert!(XKB_US_KEYMAP.contains("<LWIN> = 133;"));
    }

    #[test]
    fn maps_ascii_letters_digits_and_punctuation() {
        assert_eq!(keycode_to_evdev(&KeyCode::Char('a')), Some((30, false)));
        assert_eq!(keycode_to_evdev(&KeyCode::Char('A')), Some((30, true)));
        assert_eq!(keycode_to_evdev(&KeyCode::Char('1')), Some((2, false)));
        assert_eq!(keycode_to_evdev(&KeyCode::Char('!')), Some((2, true)));
        assert_eq!(keycode_to_evdev(&KeyCode::Char(' ')), Some((57, false)));
        assert_eq!(keycode_to_evdev(&KeyCode::Char('/')), Some((53, false)));
        assert_eq!(keycode_to_evdev(&KeyCode::Char('?')), Some((53, true)));
        assert_eq!(keycode_to_evdev(&KeyCode::Char('é')), None);
    }

    #[test]
    fn maps_special_keys_and_modifiers() {
        assert_eq!(keycode_to_evdev(&KeyCode::Escape), Some((1, false)));
        assert_eq!(keycode_to_evdev(&KeyCode::Enter), Some((28, false)));
        assert_eq!(keycode_to_evdev(&KeyCode::Backspace), Some((14, false)));
        assert_eq!(keycode_to_evdev(&KeyCode::Tab), Some((15, false)));
        assert_eq!(keycode_to_evdev(&KeyCode::ArrowUp), Some((103, false)));
        assert_eq!(keycode_to_evdev(&KeyCode::ArrowDown), Some((108, false)));
        assert_eq!(keycode_to_evdev(&KeyCode::ArrowLeft), Some((105, false)));
        assert_eq!(keycode_to_evdev(&KeyCode::ArrowRight), Some((106, false)));
        assert_eq!(keycode_to_evdev(&KeyCode::Delete), Some((111, false)));

        assert_eq!(modifier_to_evdev(KeyModifier::Shift), 42);
        assert_eq!(modifier_to_evdev(KeyModifier::Control), 29);
        assert_eq!(modifier_to_evdev(KeyModifier::Alt), 56);
        assert_eq!(modifier_to_evdev(KeyModifier::Meta), 125);
    }

    #[test]
    fn computes_xkb_modifier_mask() {
        assert_eq!(modifier_xkb_mask(&[], false), 0);
        assert_eq!(modifier_xkb_mask(&[], true), XKB_MOD_SHIFT);
        assert_eq!(
            modifier_xkb_mask(&[KeyModifier::Control, KeyModifier::Alt], false),
            XKB_MOD_CTRL | XKB_MOD_ALT
        );
        assert_eq!(
            modifier_xkb_mask(&[KeyModifier::Meta, KeyModifier::Shift], true),
            XKB_MOD_META | XKB_MOD_SHIFT
        );
    }
}

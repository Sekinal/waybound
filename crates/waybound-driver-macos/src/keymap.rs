//! US ANSI virtual keycode table for printable ASCII (`kVK_ANSI_*` in Carbon `Events.h`).
//!
//! Kept free of FFI so it is compiled and tested on every host.

/// Returns the US ANSI virtual keycode that produces `ch`, and whether Shift must be held.
///
/// Returns `None` for characters that are not printable ASCII (they have no key on an
/// ANSI keyboard and must be delivered as a Unicode string instead).
#[must_use]
pub const fn ansi_keycode(ch: char) -> Option<(u16, bool)> {
    let (base, shifted) = match ch {
        'A'..='Z' => (ch.to_ascii_lowercase(), true),
        '!' => ('1', true),
        '@' => ('2', true),
        '#' => ('3', true),
        '$' => ('4', true),
        '%' => ('5', true),
        '^' => ('6', true),
        '&' => ('7', true),
        '*' => ('8', true),
        '(' => ('9', true),
        ')' => ('0', true),
        '_' => ('-', true),
        '+' => ('=', true),
        '{' => ('[', true),
        '}' => (']', true),
        '|' => ('\\', true),
        ':' => (';', true),
        '"' => ('\'', true),
        '<' => (',', true),
        '>' => ('.', true),
        '?' => ('/', true),
        '~' => ('`', true),
        other => (other, false),
    };
    let keycode = match base {
        'a' => 0x00,
        's' => 0x01,
        'd' => 0x02,
        'f' => 0x03,
        'h' => 0x04,
        'g' => 0x05,
        'z' => 0x06,
        'x' => 0x07,
        'c' => 0x08,
        'v' => 0x09,
        'b' => 0x0B,
        'q' => 0x0C,
        'w' => 0x0D,
        'e' => 0x0E,
        'r' => 0x0F,
        'y' => 0x10,
        't' => 0x11,
        '1' => 0x12,
        '2' => 0x13,
        '3' => 0x14,
        '4' => 0x15,
        '6' => 0x16,
        '5' => 0x17,
        '=' => 0x18,
        '9' => 0x19,
        '7' => 0x1A,
        '-' => 0x1B,
        '8' => 0x1C,
        '0' => 0x1D,
        ']' => 0x1E,
        'o' => 0x1F,
        'u' => 0x20,
        '[' => 0x21,
        'i' => 0x22,
        'p' => 0x23,
        'l' => 0x25,
        'j' => 0x26,
        '\'' => 0x27,
        'k' => 0x28,
        ';' => 0x29,
        '\\' => 0x2A,
        ',' => 0x2B,
        '/' => 0x2C,
        'n' => 0x2D,
        'm' => 0x2E,
        '.' => 0x2F,
        ' ' => 0x31,
        '`' => 0x32,
        _ => return None,
    };
    Some((keycode, shifted))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn every_printable_ascii_character_has_a_key() {
        for byte in 0x20u8..0x7F {
            assert!(
                ansi_keycode(char::from(byte)).is_some(),
                "no key for {byte:#x}"
            );
        }
        assert_eq!(ansi_keycode('\n'), None);
        assert_eq!(ansi_keycode('é'), None);
    }

    #[test]
    fn letters_are_distinct_keys_and_only_uppercase_needs_shift() {
        let mut seen = HashSet::new();
        for ch in 'a'..='z' {
            let lower = ansi_keycode(ch);
            let upper = ansi_keycode(ch.to_ascii_uppercase());
            assert!(matches!(lower, Some((_, false))), "{ch}");
            assert_eq!(upper.map(|(vk, _)| vk), lower.map(|(vk, _)| vk));
            assert!(matches!(upper, Some((_, true))), "{ch}");
            assert!(
                lower.is_some_and(|(vk, _)| seen.insert(vk)),
                "duplicate key for {ch}"
            );
        }
        assert_eq!(seen.len(), 26);
    }

    #[test]
    fn known_keycodes_match_carbon_constants() {
        assert_eq!(ansi_keycode('a'), Some((0x00, false)));
        assert_eq!(ansi_keycode('z'), Some((0x06, false)));
        assert_eq!(ansi_keycode('f'), Some((0x03, false)));
        assert_eq!(ansi_keycode('l'), Some((0x25, false)));
        assert_eq!(ansi_keycode('1'), Some((0x12, false)));
        assert_eq!(ansi_keycode('!'), Some((0x12, true)));
        assert_eq!(ansi_keycode('?'), Some((0x2C, true)));
        assert_eq!(ansi_keycode(' '), Some((0x31, false)));
    }
}

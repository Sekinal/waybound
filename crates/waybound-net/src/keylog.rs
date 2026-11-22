//! Live incremental parser for NSS `SSLKEYLOGFILE` files.
//!
//! Understands the TLS 1.3 `CLIENT_TRAFFIC_SECRET_0` / `SERVER_TRAFFIC_SECRET_0` labels and
//! the TLS 1.2 `CLIENT_RANDOM` label (which carries the 48-byte master secret).

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// TLS secrets associated with a single `client_random`.
#[derive(Debug, Clone, Default)]
pub struct TrafficSecrets {
    /// `CLIENT_TRAFFIC_SECRET_0` (client -> server application data).
    pub client_traffic_secret_0: Option<Vec<u8>>,
    /// `SERVER_TRAFFIC_SECRET_0` (server -> client application data).
    pub server_traffic_secret_0: Option<Vec<u8>>,
    /// `CLIENT_RANDOM` (TLS 1.2 master secret).
    pub master_secret: Option<Vec<u8>>,
}

#[derive(Debug)]
struct KeyLogInner {
    path: PathBuf,
    offset: u64,
    secrets: HashMap<[u8; 32], TrafficSecrets>,
}

/// Thread-safe, incrementally-polled store of `SSLKEYLOGFILE` secrets.
#[derive(Debug, Clone)]
pub struct KeyLogStore {
    inner: Arc<Mutex<KeyLogInner>>,
}

impl KeyLogStore {
    /// Creates a new [`KeyLogStore`] backed by `path` (the file need not exist yet).
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(KeyLogInner {
                path: path.as_ref().to_path_buf(),
                offset: 0,
                secrets: HashMap::new(),
            })),
        }
    }

    /// Reads any newly appended lines from the keylog file and looks up `client_random`.
    #[must_use]
    pub fn lookup(&self, client_random: &[u8; 32]) -> Option<TrafficSecrets> {
        let mut guard = self.inner.lock().ok()?;
        let _ = refresh_locked(&mut guard);
        guard.secrets.get(client_random).cloned()
    }

    /// Inserts a secret directly (useful in unit tests).
    pub fn insert_for_test(
        &self,
        client_random: [u8; 32],
        client_secret: Vec<u8>,
        server_secret: Vec<u8>,
    ) {
        if let Ok(mut guard) = self.inner.lock() {
            let entry = guard.secrets.entry(client_random).or_default();
            entry.client_traffic_secret_0 = Some(client_secret);
            entry.server_traffic_secret_0 = Some(server_secret);
        }
    }

    /// Inserts a TLS 1.2 master secret directly (useful in unit tests).
    pub fn insert_master_secret_for_test(&self, client_random: [u8; 32], master_secret: Vec<u8>) {
        if let Ok(mut guard) = self.inner.lock() {
            guard
                .secrets
                .entry(client_random)
                .or_default()
                .master_secret = Some(master_secret);
        }
    }
}

fn refresh_locked(inner: &mut KeyLogInner) -> std::io::Result<()> {
    let Ok(mut file) = File::open(&inner.path) else {
        return Ok(());
    };
    let len = file.metadata()?.len();
    if len < inner.offset {
        // File was truncated/rotated; re-read from start.
        inner.offset = 0;
    }
    if len == inner.offset {
        return Ok(());
    }
    let _ = file.seek(SeekFrom::Start(inner.offset))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        // Only advance offset for complete newline-terminated lines so we never split a partial write.
        if !line.ends_with('\n') {
            break;
        }
        inner.offset = inner.offset.saturating_add(n as u64);
        parse_keylog_line(&line, &mut inner.secrets);
    }
    Ok(())
}

/// Parses a single NSS `SSLKEYLOGFILE` line into `secrets`.
pub fn parse_keylog_line<S: std::hash::BuildHasher>(
    line: &str,
    secrets: &mut HashMap<[u8; 32], TrafficSecrets, S>,
) {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return;
    }
    let mut parts = trimmed.split_whitespace();
    let Some(label) = parts.next() else {
        return;
    };
    let Some(random_hex) = parts.next() else {
        return;
    };
    let Some(secret_hex) = parts.next() else {
        return;
    };
    let Some(random_bytes) = decode_hex(random_hex) else {
        return;
    };
    let Ok(client_random) = <[u8; 32]>::try_from(random_bytes) else {
        return;
    };
    let Some(secret_bytes) = decode_hex(secret_hex) else {
        return;
    };

    let entry = secrets.entry(client_random).or_default();
    match label {
        "CLIENT_TRAFFIC_SECRET_0" => entry.client_traffic_secret_0 = Some(secret_bytes),
        "SERVER_TRAFFIC_SECRET_0" => entry.server_traffic_secret_0 = Some(secret_bytes),
        "CLIENT_RANDOM" => entry.master_secret = Some(secret_bytes),
        _ => {}
    }
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for pair in bytes.as_chunks::<2>().0 {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tls13_traffic_secret_lines() {
        let mut map = HashMap::new();
        let random_hex = "01".repeat(32);
        let c_hex = "aa".repeat(32);
        let s_hex = "bb".repeat(48);
        parse_keylog_line(
            &format!("CLIENT_TRAFFIC_SECRET_0 {random_hex} {c_hex}\n"),
            &mut map,
        );
        parse_keylog_line(
            &format!("SERVER_TRAFFIC_SECRET_0 {random_hex} {s_hex}\n"),
            &mut map,
        );
        parse_keylog_line("# comment line\n", &mut map);

        let key = [0x01u8; 32];
        let found = map.get(&key);
        assert!(found.is_some());
        if let Some(sec) = found {
            assert_eq!(sec.client_traffic_secret_0, Some(vec![0xAA; 32]));
            assert_eq!(sec.server_traffic_secret_0, Some(vec![0xBB; 48]));
            assert_eq!(sec.master_secret, None);
        }
    }

    #[test]
    fn parses_tls12_client_random_lines() {
        let mut map = HashMap::new();
        let random_hex = "0f".repeat(32);
        let ms_hex = "Cd".repeat(48);
        parse_keylog_line(&format!("CLIENT_RANDOM {random_hex} {ms_hex}\n"), &mut map);
        // Malformed lines (short random, odd hex) are ignored.
        parse_keylog_line(&format!("CLIENT_RANDOM 0f0f {ms_hex}\n"), &mut map);
        parse_keylog_line(&format!("CLIENT_RANDOM {random_hex} abc\n"), &mut map);

        assert_eq!(map.len(), 1);
        let found = map.get(&[0x0Fu8; 32]);
        assert!(found.is_some());
        if let Some(sec) = found {
            assert_eq!(sec.master_secret, Some(vec![0xCD; 48]));
            assert_eq!(sec.client_traffic_secret_0, None);
        }
    }
}

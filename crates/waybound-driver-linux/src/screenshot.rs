//! Linux screenshot capture via `grim` (Wayland) or `import`/`scrot` (X11/Xvfb).

use std::io::Read;
use std::path::Path;

use tracing::debug;
use waybound_core::{Result, WayboundError};

use crate::input::DisplayServer;
use crate::process::{BACKEND_NAME, DEFAULT_TIMEOUT, run_with_timeout, truncate_for_log};

/// Standard 8-byte PNG file signature (`\x89PNG\r\n\x1a\n`).
pub const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

/// Validates that `bytes` begins with the 8-byte PNG magic header.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if `bytes` is shorter than 8 bytes
/// or does not start with [`PNG_MAGIC`].
pub fn validate_png_bytes(bytes: &[u8]) -> Result<()> {
    if bytes.len() < PNG_MAGIC.len() || bytes[..PNG_MAGIC.len()] != PNG_MAGIC {
        return Err(WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!(
                "screenshot output is not a valid PNG (got {} bytes)",
                bytes.len()
            ),
        });
    }
    Ok(())
}

/// Validates that the file at `path` exists and begins with the PNG magic header.
///
/// # Errors
///
/// Returns [`WayboundError::Io`] if the file cannot be opened or read, or
/// [`WayboundError::BackendUnavailable`] if the header is not a valid PNG signature.
pub fn validate_png_file(path: &Path) -> Result<()> {
    let mut file = std::fs::File::open(path)?;
    let mut header = [0u8; 8];
    let mut filled = 0usize;
    while filled < header.len() {
        let n = file.read(&mut header[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    validate_png_bytes(&header[..filled])
}

/// Returns the ordered `(program, args)` candidate commands for capturing a screenshot
/// to `output_path` under `server`.
#[must_use]
pub fn build_screenshot_candidates(
    output_path: &Path,
    server: DisplayServer,
) -> Vec<(String, Vec<String>)> {
    let path_str = output_path.to_string_lossy().into_owned();
    match server {
        DisplayServer::Wayland => vec![("grim".to_owned(), vec![path_str])],
        DisplayServer::X11 => vec![
            (
                "import".to_owned(),
                vec!["-window".to_owned(), "root".to_owned(), path_str.clone()],
            ),
            ("scrot".to_owned(), vec!["--overwrite".to_owned(), path_str]),
        ],
    }
}

/// Captures a PNG screenshot of the active Linux display to `output_path` and
/// validates the resulting PNG magic header.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if no screenshot tool succeeds or
/// the output file is not a valid PNG, [`WayboundError::Timeout`] if capture exceeds
/// 10 seconds, or [`WayboundError::Io`] if reading the captured file fails.
pub fn capture_screenshot(
    output_path: &Path,
    server: DisplayServer,
    display: Option<&str>,
) -> Result<()> {
    let candidates = build_screenshot_candidates(output_path, server);
    let mut envs: Vec<(&str, &str)> = Vec::new();
    if server == DisplayServer::X11
        && let Some(disp) = display
    {
        envs.push(("DISPLAY", disp));
    }

    let mut last_err: Option<String> = None;
    for (program, args) in &candidates {
        debug!(program, ?args, ?server, "capturing Linux screenshot");
        match run_with_timeout(program, args, &envs, DEFAULT_TIMEOUT, "Linux screenshot") {
            Ok(output) if output.status.success() => {
                validate_png_file(output_path)?;
                return Ok(());
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                last_err = Some(format!(
                    "`{program}` exited with {}: {}",
                    output.status,
                    truncate_for_log(&stderr)
                ));
            }
            Err(WayboundError::Timeout {
                timeout_ms,
                context,
            }) => {
                return Err(WayboundError::Timeout {
                    timeout_ms,
                    context,
                });
            }
            Err(err) => {
                last_err = Some(err.to_string());
            }
        }
    }

    Err(WayboundError::BackendUnavailable {
        backend: BACKEND_NAME.to_owned(),
        reason: last_err.unwrap_or_else(|| "no Linux screenshot backend succeeded".to_owned()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_png_magic_header_and_rejects_corrupt_bytes() {
        let mut valid = PNG_MAGIC.to_vec();
        valid.extend_from_slice(&[0x00, 0x00, 0x00, 0x0D]);
        assert!(validate_png_bytes(&valid).is_ok());

        assert!(validate_png_bytes(&[]).is_err());
        assert!(validate_png_bytes(b"not-a-png-file").is_err());
        assert!(validate_png_bytes(&PNG_MAGIC[..4]).is_err());
    }

    #[test]
    fn builds_expected_screenshot_commands_for_wayland_and_x11() {
        let path = Path::new("/tmp/shot.png");

        let wayland = build_screenshot_candidates(path, DisplayServer::Wayland);
        assert_eq!(wayland.len(), 1);
        assert_eq!(wayland[0].0, "grim");
        assert_eq!(wayland[0].1, vec!["/tmp/shot.png"]);

        let x11 = build_screenshot_candidates(path, DisplayServer::X11);
        assert_eq!(x11.len(), 2);
        assert_eq!(x11[0].0, "import");
        assert_eq!(x11[0].1, vec!["-window", "root", "/tmp/shot.png"]);
        assert_eq!(x11[1].0, "scrot");
        assert_eq!(x11[1].1, vec!["--overwrite", "/tmp/shot.png"]);
    }

    #[test]
    fn validates_png_file_on_disk() -> Result<()> {
        let temp_dir = std::env::temp_dir();
        let pid = std::process::id();
        let valid_path = temp_dir.join(format!("waybound-linux-valid-{pid}.png"));
        let invalid_path = temp_dir.join(format!("waybound-linux-invalid-{pid}.png"));

        std::fs::write(&valid_path, PNG_MAGIC)?;
        std::fs::write(&invalid_path, b"JUNK_DATA")?;

        let valid_res = validate_png_file(&valid_path);
        let invalid_res = validate_png_file(&invalid_path);

        let _ = std::fs::remove_file(&valid_path);
        let _ = std::fs::remove_file(&invalid_path);

        assert!(valid_res.is_ok());
        assert!(invalid_res.is_err());
        Ok(())
    }
}

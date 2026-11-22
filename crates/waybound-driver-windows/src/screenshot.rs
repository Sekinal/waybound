//! Native Windows screenshot capture and PNG header validation.

#[cfg(target_os = "windows")]
use std::path::Path;

use waybound_core::{Result, WayboundError};

/// Standard 8-byte PNG file signature.
const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

/// Validates that `bytes` begins with the standard 8-byte PNG magic signature.
///
/// # Errors
///
/// Returns [`WayboundError::Io`] with [`std::io::ErrorKind::InvalidData`] if `bytes` is shorter
/// than 8 bytes or does not begin with the PNG magic header.
pub fn validate_png_bytes(bytes: &[u8]) -> Result<()> {
    if bytes.len() < PNG_SIGNATURE.len() || !bytes.starts_with(&PNG_SIGNATURE) {
        return Err(WayboundError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "captured screenshot does not have a valid PNG header",
        )));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
const SCREENSHOT_TIMEOUT_MS: u64 = 10_000;

#[cfg(target_os = "windows")]
const SCREENSHOT_POWERSHELL_SCRIPT: &str = r"
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$outPath = $env:WAYBOUND_SCREENSHOT_PATH
if (-not $outPath -or $outPath.Trim() -eq '') {
    throw 'WAYBOUND_SCREENSHOT_PATH environment variable is empty'
}

$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bitmap = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height)
try {
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
    } finally {
        $graphics.Dispose()
    }
    $bitmap.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
} finally {
    $bitmap.Dispose()
}
";

/// Captures a PNG screenshot of the primary Windows desktop to `output_path` using
/// `powershell.exe` and `System.Drawing.Bitmap::CopyFromScreen`, then validates the PNG header.
///
/// # Errors
///
/// Returns [`WayboundError::Timeout`] if capture exceeds 10 seconds,
/// [`WayboundError::BackendUnavailable`] if PowerShell exits with an error, or
/// [`WayboundError::Io`] if writing, reading, or validating the PNG fails.
#[cfg(target_os = "windows")]
pub fn capture_screenshot(output_path: &Path) -> Result<()> {
    use std::io::Read;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    tracing::debug!(path = %output_path.display(), "capturing Windows screenshot");

    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let mut cmd = waybound_core::process::command("powershell.exe");
    let _ = cmd
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(SCREENSHOT_POWERSHELL_SCRIPT)
        .env("WAYBOUND_SCREENSHOT_PATH", output_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn()?;
    let stderr_pipe = child.stderr.take();
    let stderr_handle = std::thread::spawn(move || -> std::io::Result<String> {
        let mut buf = String::new();
        if let Some(mut pipe) = stderr_pipe {
            let _ = pipe.read_to_string(&mut buf)?;
        }
        Ok(buf)
    });

    let deadline = Instant::now() + Duration::from_millis(SCREENSHOT_TIMEOUT_MS);
    let status = loop {
        if let Some(exit_status) = child.try_wait()? {
            break exit_status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(WayboundError::Timeout {
                timeout_ms: SCREENSHOT_TIMEOUT_MS,
                context: "Windows screenshot capture".to_owned(),
            });
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    let stderr = stderr_handle
        .join()
        .map_err(|_| WayboundError::BackendUnavailable {
            backend: "windows".to_owned(),
            reason: "screenshot stderr reader thread panicked".to_owned(),
        })??;

    if !status.success() {
        return Err(WayboundError::BackendUnavailable {
            backend: "windows".to_owned(),
            reason: format!(
                "screenshot PowerShell exited with {status}: {}",
                stderr.trim()
            ),
        });
    }

    let bytes = std::fs::read(output_path)?;
    validate_png_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_png_signature() {
        let valid = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00];
        assert!(validate_png_bytes(&valid).is_ok());
    }

    #[test]
    fn rejects_empty_or_non_png_bytes() {
        assert!(validate_png_bytes(&[]).is_err());
        assert!(validate_png_bytes(&[0x89, b'P', b'N', b'G']).is_err());
        assert!(validate_png_bytes(b"JFIF_NOT_A_PNG").is_err());
    }
}

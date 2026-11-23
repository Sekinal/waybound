//! Live smoke test driving unmodified stock Chrome/Chromium directly against
//! `waybound-compositor` (`--ozone-platform=wayland`, zero Xvfb, zero X11, zero CDP).

#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitCode, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use waybound_compositor::{CompositorConfig, HeadlessCompositor};

const HTML_BODY: &str = r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Waybound Wayland Smoke</title></head>
<body style="margin:0;background:#2266cc;color:#ffffff;font-family:sans-serif">
  <h1 style="padding:40px">Hello Wayland</h1>
  <script>
    const params = new URLSearchParams({
      w: String(window.screen.width),
      h: String(window.screen.height),
      vis: String(document.visibilityState),
      ext: String(Boolean(window.screen.isExtended)),
    });
    fetch('/report?' + params.toString());
  </script>
</body>
</html>
"#;

#[derive(Debug)]
struct PageReport {
    width: String,
    height: String,
    visibility: String,
    is_extended: String,
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn log_line(msg: &str) {
    let _ = writeln!(std::io::stdout(), "{msg}");
}

fn find_chrome_binary() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("WAYBOUND_CHROME_BIN")
        && !explicit.is_empty()
    {
        return Some(PathBuf::from(explicit));
    }
    let candidates = [
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
    ];
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        for name in candidates {
            let full = dir.join(name);
            if full.is_file() {
                return Some(full);
            }
        }
    }
    None
}

fn parse_report_query(path: &str) -> Option<PageReport> {
    let query = path.strip_prefix("/report?")?;
    let mut width = String::new();
    let mut height = String::new();
    let mut visibility = String::new();
    let mut is_extended = String::new();

    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            match k {
                "w" => v.clone_into(&mut width),
                "h" => v.clone_into(&mut height),
                "vis" => v.clone_into(&mut visibility),
                "ext" => v.clone_into(&mut is_extended),
                _ => {}
            }
        }
    }

    Some(PageReport {
        width,
        height,
        visibility,
        is_extended,
    })
}

fn spawn_http_server(report_tx: mpsc::Sender<PageReport>) -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind http: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?
        .port();

    let _handle = thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(&stream);
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() {
                continue;
            }
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("/")
                .to_owned();

            // Drain remaining request headers.
            let mut header_line = String::new();
            loop {
                header_line.clear();
                match reader.read_line(&mut header_line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) if header_line == "\r\n" || header_line == "\n" => break,
                    Ok(_) => {}
                }
            }

            let mut writer = &stream;
            if let Some(report) = parse_report_query(&path) {
                let _ = report_tx.send(report);
                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = writer.write_all(resp.as_bytes());
            } else {
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{HTML_BODY}",
                    HTML_BODY.len()
                );
                let _ = writer.write_all(resp.as_bytes());
            }
        }
    });

    Ok(port)
}

fn verify_png_non_blank(png_bytes: &[u8]) -> Result<(u32, u32, usize), String> {
    if !png_bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Err("captured bytes do not start with PNG magic header".to_owned());
    }
    let decoder = png::Decoder::new(std::io::Cursor::new(png_bytes));
    let mut reader = decoder
        .read_info()
        .map_err(|e| format!("PNG decode header failed: {e}"))?;
    let width = reader.info().width;
    let height = reader.info().height;
    let mut pixels = vec![0_u8; reader.output_buffer_size()];
    let _frame_info = reader
        .next_frame(&mut pixels)
        .map_err(|e| format!("PNG decode frame failed: {e}"))?;

    let (chunks, _) = pixels.as_chunks::<4>();
    let non_black = chunks
        .iter()
        .filter(|&&[r, g, b, a]| a > 0 && (r > 0 || g > 0 || b > 0))
        .count();
    if non_black == 0 {
        return Err(format!(
            "decoded {width}x{height} PNG has zero non-black pixels"
        ));
    }
    Ok((width, height, non_black))
}

#[allow(clippy::too_many_lines)]
fn run_smoke(work_dir: &Path) -> Result<(), String> {
    let runtime_dir = work_dir.join("xdg");
    let profile_dir = work_dir.join("chrome-profile");
    std::fs::create_dir_all(&runtime_dir).map_err(|e| format!("mkdir xdg: {e}"))?;
    std::fs::create_dir_all(&profile_dir).map_err(|e| format!("mkdir profile: {e}"))?;

    let chrome_bin = find_chrome_binary()
        .ok_or_else(|| "no google-chrome or chromium binary found in PATH".to_owned())?;
    log_line(&format!("Using Chrome binary: {}", chrome_bin.display()));

    let compositor = HeadlessCompositor::start(CompositorConfig {
        width: 1920,
        height: 1080,
        runtime_dir: Some(runtime_dir),
        socket_name: Some("wb-smoke-0".to_owned()),
        ..CompositorConfig::default()
    })
    .map_err(|e| format!("failed to start HeadlessCompositor: {e}"))?;

    log_line(&format!(
        "Compositor listening on WAYLAND_DISPLAY={} in {}",
        compositor.socket_name(),
        compositor.runtime_dir().display()
    ));

    let (report_tx, report_rx) = mpsc::channel();
    let port = spawn_http_server(report_tx)?;
    let url = format!("http://127.0.0.1:{port}/");

    let child = waybound_core::process::command(&chrome_bin)
        .arg("--ozone-platform=wayland")
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--disable-gpu")
        .arg("--disable-dev-shm-usage")
        .arg("--no-sandbox")
        .arg(format!("--user-data-dir={}", profile_dir.display()))
        .arg(&url)
        .env("WAYLAND_DISPLAY", compositor.socket_name())
        .env("XDG_RUNTIME_DIR", compositor.runtime_dir())
        .env_remove("DISPLAY")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("failed to spawn Chrome: {e}"))?;
    let mut child_guard = ChildGuard(child);

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut received_report: Option<PageReport> = None;
    let mut captured_png: Option<Vec<u8>> = None;

    while Instant::now() < deadline {
        if let Ok(Some(status)) = child_guard.0.try_wait() {
            return Err(format!(
                "Chrome exited early with {status} (windows={:?})",
                compositor.windows()
            ));
        }
        if received_report.is_none()
            && let Ok(report) = report_rx.try_recv()
        {
            log_line(&format!("Received page report: {report:?}"));
            received_report = Some(report);
        }

        if captured_png.is_none()
            && let Ok(windows) = compositor.windows()
            && let Some(win) = windows.iter().find(|w| w.has_buffer)
            && let Ok(png_bytes) = compositor.screenshot_png(Some(win.id))
            && verify_png_non_blank(&png_bytes).is_ok()
        {
            log_line(&format!(
                "Captured committed wl_buffer from window {} ({}x{}, title={:?})",
                win.id, win.width, win.height, win.title
            ));
            captured_png = Some(png_bytes);
        }

        if received_report.is_some() && captured_png.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    let report = received_report
        .ok_or_else(|| "timed out waiting for /report callback from Chrome".to_owned())?;
    if report.width != "1920" || report.height != "1080" {
        return Err(format!(
            "unexpected screen dimensions: {}x{} (expected 1920x1080)",
            report.width, report.height
        ));
    }
    if report.visibility != "visible" {
        return Err(format!(
            "unexpected visibilityState: {:?} (expected \"visible\")",
            report.visibility
        ));
    }
    if report.is_extended != "false" {
        return Err(format!(
            "unexpected screen.isExtended: {:?} (expected \"false\")",
            report.is_extended
        ));
    }

    let png_bytes = captured_png.ok_or_else(|| {
        "timed out waiting for non-blank committed wl_buffer from Chrome".to_owned()
    })?;
    let (w, h, non_black) = verify_png_non_blank(&png_bytes)?;
    log_line(&format!(
        "PASS: Chrome rendered {w}x{h} PNG ({} bytes, {non_black} non-black pixels) on pure-Rust Wayland compositor",
        png_bytes.len()
    ));

    Ok(())
}

fn main() -> ExitCode {
    let work_dir = std::env::temp_dir().join(format!("wb-wl-smoke-{}", std::process::id()));
    let result = run_smoke(&work_dir);
    let _ = std::fs::remove_dir_all(&work_dir);

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "FAIL: {err}");
            ExitCode::FAILURE
        }
    }
}

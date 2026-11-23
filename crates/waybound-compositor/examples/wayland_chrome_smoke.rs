//! Live stacked multi-window smoke test driving unmodified stock Chrome/Chromium directly
//! against `waybound-compositor` (`--ozone-platform=wayland`, zero Xvfb, zero X11, zero CDP).
//!
//! Opens TWO stacked `1920x1080` windows inside ONE Chrome process (via `--new-window`
//! sharing the same `--user-data-dir`), verifies simultaneous non-occluded per-window PNG
//! capture (blue vs. green), verifies targeted `wl_seat` input delivery to Window 2, and
//! verifies `close_window(win2_id)` closes only Window 2 while Window 1 stays alive.

#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitCode, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use waybound_compositor::{CompositorConfig, HeadlessCompositor};
use waybound_core::{InputEvent, KeyCode, MouseButton, Point};

const HTML_PAGE_1: &str = r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Waybound Window 1</title></head>
<body style="margin:0;padding:0;background:#2266cc;color:#ffffff;font-family:sans-serif">
  <h1 style="padding:40px">Waybound Window 1 (Blue)</h1>
  <script>
    const params = new URLSearchParams({
      win: '1',
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

const HTML_PAGE_2: &str = r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Waybound Window 2</title></head>
<body style="margin:0;padding:0;background:#22aa44;color:#ffffff;font-family:sans-serif">
  <button id="btn" style="width:300px;height:120px" onclick="fetch('/clicked')">Click Me</button>
  <h1 style="padding:40px">Waybound Window 2 (Green)</h1>
  <script>
    window.addEventListener('pointerdown', () => {
      fetch('/input?kind=click');
    });
    document.addEventListener('keydown', () => {
      fetch('/input?kind=key');
    });
    const params = new URLSearchParams({
      win: '2',
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

#[derive(Debug, PartialEq, Eq)]
struct PageReport {
    win: String,
    width: String,
    height: String,
    visibility: String,
    is_extended: String,
}

#[derive(Debug, PartialEq, Eq)]
enum PageEvent {
    Report(PageReport),
    InputClick,
    InputKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DominantColor {
    Blue,
    Green,
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
    let mut win = String::new();
    let mut width = String::new();
    let mut height = String::new();
    let mut visibility = String::new();
    let mut is_extended = String::new();

    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            match k {
                "win" => v.clone_into(&mut win),
                "w" => v.clone_into(&mut width),
                "h" => v.clone_into(&mut height),
                "vis" => v.clone_into(&mut visibility),
                "ext" => v.clone_into(&mut is_extended),
                _ => {}
            }
        }
    }

    Some(PageReport {
        win,
        width,
        height,
        visibility,
        is_extended,
    })
}

fn spawn_http_server(event_tx: mpsc::Sender<PageEvent>) -> Result<u16, String> {
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
                let _ = event_tx.send(PageEvent::Report(report));
                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = writer.write_all(resp.as_bytes());
            } else if path == "/input?kind=click" || path == "/clicked" {
                let _ = event_tx.send(PageEvent::InputClick);
                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = writer.write_all(resp.as_bytes());
            } else if path == "/input?kind=key" {
                let _ = event_tx.send(PageEvent::InputKey);
                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = writer.write_all(resp.as_bytes());
            } else if path == "/page2" {
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{HTML_PAGE_2}",
                    HTML_PAGE_2.len()
                );
                let _ = writer.write_all(resp.as_bytes());
            } else {
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{HTML_PAGE_1}",
                    HTML_PAGE_1.len()
                );
                let _ = writer.write_all(resp.as_bytes());
            }
        }
    });

    Ok(port)
}

fn verify_report(label: &str, report: &PageReport) -> Result<(), String> {
    if report.width != "1920" || report.height != "1080" {
        return Err(format!(
            "{label}: unexpected screen dimensions {}x{} (expected 1920x1080)",
            report.width, report.height
        ));
    }
    if report.visibility != "visible" {
        return Err(format!(
            "{label}: unexpected visibilityState {:?} (expected \"visible\")",
            report.visibility
        ));
    }
    if report.is_extended != "false" {
        return Err(format!(
            "{label}: unexpected screen.isExtended {:?} (expected \"false\")",
            report.is_extended
        ));
    }
    Ok(())
}

fn verify_png_color(
    png_bytes: &[u8],
    expected: DominantColor,
) -> Result<(u32, u32, usize, usize), String> {
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
    let mut non_black: usize = 0;
    let mut blue_pixels: usize = 0;
    let mut green_pixels: usize = 0;

    for &[r, g, b, a] in chunks {
        if a == 0 {
            continue;
        }
        if r > 0 || g > 0 || b > 0 {
            non_black += 1;
        }
        let r16 = u16::from(r);
        let g16 = u16::from(g);
        let b16 = u16::from(b);
        if b16 > r16 + 40 && b16 > g16 + 20 {
            blue_pixels += 1;
        }
        if g16 > r16 + 40 && g16 > b16 + 20 {
            green_pixels += 1;
        }
    }

    if non_black == 0 {
        return Err(format!(
            "decoded {width}x{height} PNG has zero non-black pixels"
        ));
    }

    match expected {
        DominantColor::Blue => {
            if blue_pixels < 1_000 || blue_pixels <= green_pixels {
                return Err(format!(
                    "expected dominant blue pixels in {width}x{height} PNG (blue={blue_pixels}, green={green_pixels}, non_black={non_black})"
                ));
            }
            Ok((width, height, non_black, blue_pixels))
        }
        DominantColor::Green => {
            if green_pixels < 1_000 || green_pixels <= blue_pixels {
                return Err(format!(
                    "expected dominant green pixels in {width}x{height} PNG (green={green_pixels}, blue={blue_pixels}, non_black={non_black})"
                ));
            }
            Ok((width, height, non_black, green_pixels))
        }
    }
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

    let (event_tx, event_rx) = mpsc::channel();
    let port = spawn_http_server(event_tx)?;
    let url1 = format!("http://127.0.0.1:{port}/page1");
    let url2 = format!("http://127.0.0.1:{port}/page2");

    // 1. Launch primary Chrome process opening Window 1 (/page1, blue).
    let child = waybound_core::process::command(&chrome_bin)
        .arg("--ozone-platform=wayland")
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--disable-gpu")
        .arg("--disable-gpu-compositing")
        .arg("--disable-dev-shm-usage")
        .arg("--no-sandbox")
        .arg(format!("--user-data-dir={}", profile_dir.display()))
        .arg(&url1)
        .env("WAYLAND_DISPLAY", compositor.socket_name())
        .env("XDG_RUNTIME_DIR", compositor.runtime_dir())
        .env_remove("DISPLAY")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("failed to spawn Chrome: {e}"))?;
    let mut child_guard = ChildGuard(child);

    let deadline1 = Instant::now() + Duration::from_secs(30);
    let mut report1: Option<PageReport> = None;
    let mut win1_id: Option<u64> = None;

    while Instant::now() < deadline1 {
        if let Ok(Some(status)) = child_guard.0.try_wait() {
            return Err(format!(
                "Chrome exited early with {status} (windows={:?})",
                compositor.windows()
            ));
        }
        while let Ok(evt) = event_rx.try_recv() {
            if let PageEvent::Report(report) = evt {
                log_line(&format!("Received page report: {report:?}"));
                if report.win == "1" {
                    report1 = Some(report);
                }
            }
        }
        if win1_id.is_none()
            && let Ok(windows) = compositor.windows()
            && let Some(win) = windows.iter().find(|w| w.has_buffer)
            && let Ok(png_bytes) = compositor.screenshot_png(Some(win.id))
            && let Ok((w, h, non_black, blue)) = verify_png_color(&png_bytes, DominantColor::Blue)
        {
            log_line(&format!(
                "Window 1 ready: id={}, {}x{}, title={:?} ({non_black} non-black, {blue} blue px)",
                win.id, w, h, win.title
            ));
            win1_id = Some(win.id);
        }
        if report1.is_some() && win1_id.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    let report1 =
        report1.ok_or_else(|| "timed out waiting for Window 1 /report callback".to_owned())?;
    verify_report("Window 1", &report1)?;
    let win1_id = win1_id.ok_or_else(|| {
        format!(
            "timed out waiting for Window 1 blue wl_buffer (windows={:?})",
            compositor.windows()
        )
    })?;

    // 2. Open Window 2 (/page2, green) inside the SAME Chrome process via --new-window.
    log_line("Spawning secondary --new-window Chrome handoff for Window 2...");
    let helper_child = waybound_core::process::command(&chrome_bin)
        .arg("--ozone-platform=wayland")
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--disable-gpu")
        .arg("--disable-gpu-compositing")
        .arg("--disable-dev-shm-usage")
        .arg("--no-sandbox")
        .arg(format!("--user-data-dir={}", profile_dir.display()))
        .arg("--new-window")
        .arg(&url2)
        .env("WAYLAND_DISPLAY", compositor.socket_name())
        .env("XDG_RUNTIME_DIR", compositor.runtime_dir())
        .env_remove("DISPLAY")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("failed to spawn secondary Chrome --new-window: {e}"))?;
    let mut helper_guard = ChildGuard(helper_child);

    let deadline2 = Instant::now() + Duration::from_secs(30);
    let mut report2: Option<PageReport> = None;
    let mut win2_id: Option<u64> = None;
    let mut saw_click = false;
    let mut saw_key = false;

    while Instant::now() < deadline2 {
        let _ = helper_guard.0.try_wait();
        if let Ok(Some(status)) = child_guard.0.try_wait() {
            return Err(format!(
                "primary Chrome exited early with {status} while opening Window 2 (windows={:?})",
                compositor.windows()
            ));
        }
        while let Ok(evt) = event_rx.try_recv() {
            match evt {
                PageEvent::Report(report) => {
                    log_line(&format!("Received page report: {report:?}"));
                    if report.win == "2" {
                        report2 = Some(report);
                    }
                }
                PageEvent::InputClick => saw_click = true,
                PageEvent::InputKey => saw_key = true,
            }
        }

        if win2_id.is_none()
            && let Ok(windows) = compositor.windows()
            && let Some(win) = windows.iter().find(|w| w.id != win1_id && w.has_buffer)
            && let Ok(png_bytes) = compositor.screenshot_png(Some(win.id))
            && let Ok((w, h, non_black, green)) = verify_png_color(&png_bytes, DominantColor::Green)
        {
            log_line(&format!(
                "Window 2 ready: id={}, {}x{}, title={:?} ({non_black} non-black, {green} green px)",
                win.id, w, h, win.title
            ));
            win2_id = Some(win.id);
        }

        if report2.is_some() && win2_id.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let _ = helper_guard.0.try_wait();

    let report2 =
        report2.ok_or_else(|| "timed out waiting for Window 2 /report callback".to_owned())?;
    verify_report("Window 2", &report2)?;
    let win2_id = win2_id.ok_or_else(|| {
        format!(
            "timed out waiting for Window 2 green wl_buffer (windows={:?})",
            compositor.windows()
        )
    })?;

    // 3. Verify BOTH windows exist simultaneously and yield distinct non-occluded PNGs.
    let simultaneous_windows = compositor
        .windows()
        .map_err(|e| format!("failed to list windows: {e}"))?;
    if !simultaneous_windows.iter().any(|w| w.id == win1_id)
        || !simultaneous_windows.iter().any(|w| w.id == win2_id)
    {
        return Err(format!(
            "expected both win1={win1_id} and win2={win2_id} open simultaneously; got {simultaneous_windows:?}"
        ));
    }

    let png1 = compositor
        .screenshot_png(Some(win1_id))
        .map_err(|e| format!("simultaneous screenshot of Window 1 failed: {e}"))?;
    let (w1, h1, _, blue_px) = verify_png_color(&png1, DominantColor::Blue)
        .map_err(|e| format!("Window 1 simultaneous capture failed: {e}"))?;

    let png2 = compositor
        .screenshot_png(Some(win2_id))
        .map_err(|e| format!("simultaneous screenshot of Window 2 failed: {e}"))?;
    let (w2, h2, _, green_px) = verify_png_color(&png2, DominantColor::Green)
        .map_err(|e| format!("Window 2 simultaneous capture failed: {e}"))?;

    log_line(&format!(
        "Verified simultaneous zero-occlusion capture: win1={win1_id} ({w1}x{h1}, {blue_px} blue px) + win2={win2_id} ({w2}x{h2}, {green_px} green px)"
    ));

    // 4. Dispatch synthetic pointer click + keyboard press specifically to Window 2.
    compositor
        .dispatch_input(
            Some(win2_id),
            &InputEvent::PointerMove {
                to: Point { x: 400.0, y: 400.0 },
            },
        )
        .map_err(|e| format!("dispatch PointerMove to Window 2 failed: {e}"))?;
    compositor
        .dispatch_input(
            Some(win2_id),
            &InputEvent::MouseClick {
                button: MouseButton::Left,
                hold_ms: 20,
            },
        )
        .map_err(|e| format!("dispatch MouseClick to Window 2 failed: {e}"))?;
    thread::sleep(Duration::from_millis(100));
    compositor
        .dispatch_input(
            Some(win2_id),
            &InputEvent::KeyPress {
                key: KeyCode::Char('a'),
                modifiers: Vec::new(),
                hold_ms: 20,
            },
        )
        .map_err(|e| format!("dispatch KeyPress to Window 2 failed: {e}"))?;

    let input_deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < input_deadline && !(saw_click && saw_key) {
        while let Ok(evt) = event_rx.try_recv() {
            match evt {
                PageEvent::InputClick => {
                    log_line("Received synthetic pointer click callback from Window 2");
                    saw_click = true;
                }
                PageEvent::InputKey => {
                    log_line("Received synthetic keyboard press callback from Window 2");
                    saw_key = true;
                }
                PageEvent::Report(_) => {}
            }
        }
        if saw_click && saw_key {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    if !saw_click {
        return Err(
            "timed out waiting for synthetic pointerdown callback from Window 2".to_owned(),
        );
    }
    if !saw_key {
        return Err("timed out waiting for synthetic keydown callback from Window 2".to_owned());
    }

    // 5. Close ONLY Window 2 and verify Window 1 remains alive.
    compositor
        .close_window(win2_id)
        .map_err(|e| format!("close_window({win2_id}) failed: {e}"))?;

    let close_deadline = Instant::now() + Duration::from_secs(10);
    let mut win2_closed = false;
    while Instant::now() < close_deadline {
        let current = compositor
            .windows()
            .map_err(|e| format!("windows() during close poll failed: {e}"))?;
        let has_win1 = current.iter().any(|w| w.id == win1_id);
        let has_win2 = current.iter().any(|w| w.id == win2_id);
        if !has_win1 {
            return Err(format!(
                "Window 1 ({win1_id}) disappeared after closing Window 2 ({win2_id}): {current:?}"
            ));
        }
        if !has_win2 {
            win2_closed = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    if !win2_closed {
        return Err(format!(
            "timed out waiting for Window 2 ({win2_id}) to close (windows={:?})",
            compositor.windows()
        ));
    }
    if let Ok(Some(status)) = child_guard.0.try_wait() {
        return Err(format!(
            "primary Chrome exited ({status}) after closing only Window 2"
        ));
    }

    log_line(&format!(
        "PASS: Stacked 1920x1080 multi-window Wayland Chrome verified (win1={win1_id} blue {w1}x{h1}, win2={win2_id} green {w2}x{h2}, targeted input delivered to win2, close_window closed only win2)"
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

//! Bounded-timeout subprocess helper shared across Linux backend modules.

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use waybound_core::{Result, WayboundError};

pub const BACKEND_NAME: &str = "linux_wayland";
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Runs `program` with `args` and optional `envs` under a strict wall-clock `timeout`.
///
/// Drains `stdout` and `stderr` concurrently on background threads so large outputs
/// (such as full AT-SPI2 JSON snapshots) cannot deadlock on OS pipe buffers.
pub fn run_with_timeout(
    program: &str,
    args: &[String],
    envs: &[(&str, &str)],
    timeout: Duration,
    context: &str,
) -> Result<Output> {
    let mut cmd = Command::new(program);
    let _ = cmd
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for &(key, value) in envs {
        let _ = cmd.env(key, value);
    }

    let mut child = cmd
        .spawn()
        .map_err(|err| WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!("failed to spawn `{program}` for {context}: {err}"),
        })?;

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let stdout_handle = thread::spawn(move || -> Vec<u8> {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stdout_pipe {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    });

    let stderr_handle = thread::spawn(move || -> Vec<u8> {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stderr_pipe {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(exit_status) = child.try_wait()? {
            break exit_status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_handle.join();
            let _ = stderr_handle.join();
            return Err(WayboundError::Timeout {
                timeout_ms: u64::try_from(timeout.as_millis()).unwrap_or(10_000),
                context: format!("`{program}` timed out during {context}"),
            });
        }
        thread::sleep(POLL_INTERVAL);
    };

    let stdout = stdout_handle.join().unwrap_or_default();
    let stderr = stderr_handle.join().unwrap_or_default();

    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

/// Truncates a diagnostic string to at most 240 characters for error messages.
#[must_use]
pub fn truncate_for_log(input: &str) -> String {
    const LIMIT: usize = 240;
    let trimmed = input.trim();
    if trimmed.chars().count() <= LIMIT {
        return trimmed.to_owned();
    }
    let mut out: String = trimmed.chars().take(LIMIT).collect();
    out.push_str("...");
    out
}

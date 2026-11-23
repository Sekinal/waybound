//! Child-process construction with secret-bearing environment variables scrubbed.
//!
//! The daemon receives the upstream proxy URL (including `user:pass` credentials) through
//! the `WAYBOUND_PROXY` environment variable so it never shows up in the world-readable
//! process argument list. Environment variables are inherited by every child process, so
//! without scrubbing, Chrome, `tshark`, `osascript`, `xdotool`, `adb`, `PowerShell` and every
//! other helper would carry the credentials too (readable through `/proc/<pid>/environ`,
//! crash reports, or the helper's own children).
//!
//! The daemon cannot remove the variable from its own environment (`std::env::remove_var`
//! is `unsafe` in edition 2024, and `unsafe` is forbidden here), so every child process in
//! the workspace is created through [`command`], which strips [`SCRUBBED_ENV_VARS`].
//! `clippy.toml` disallows `std::process::Command::new` everywhere else (the lint resolves
//! paths, so `use ... as` aliases are caught too), and a source-scanning test backs that up.

use std::ffi::OsStr;
use std::process::Command;

/// Environment variables that carry secrets and must never reach a child process.
///
/// `WAYBOUND_EXIT_WITH_PARENT` and `WAYBOUND_REAP_PGID` are not secrets, but they are addressed
/// to the daemon alone: a browser or helper inheriting them must not act on them.
pub const SCRUBBED_ENV_VARS: &[&str] = &[
    "WAYBOUND_PROXY",
    "WAYBOUND_EXIT_WITH_PARENT",
    "WAYBOUND_REAP_PGID",
];

/// Creates a [`Command`] for `program` that does not inherit [`SCRUBBED_ENV_VARS`].
///
/// Use this instead of `Command::new` for every child process the daemon or a driver spawns.
#[must_use]
#[allow(clippy::disallowed_methods)] // The one sanctioned constructor.
pub fn command(program: impl AsRef<OsStr>) -> Command {
    let mut cmd = Command::new(program);
    for var in SCRUBBED_ENV_VARS {
        let _ = cmd.env_remove(var);
    }
    cmd
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::*;

    #[test]
    fn command_removes_scrubbed_vars() {
        let cmd = command("true");
        for var in SCRUBBED_ENV_VARS {
            let removed = cmd
                .get_envs()
                .any(|(key, value)| key == OsStr::new(var) && value.is_none());
            assert!(removed, "{var} is not removed from child environments");
        }
    }

    fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                rust_sources(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    /// Fails if any crate spawns a process without going through [`command`].
    #[test]
    fn no_crate_bypasses_scrubbed_command() {
        let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let this_file = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("process.rs");
        let mut files = Vec::new();
        rust_sources(&crates_dir, &mut files);
        assert!(
            files.len() > 10,
            "source scan found too few files under {}",
            crates_dir.display()
        );

        // Assembled at runtime so this file does not match its own pattern.
        let needle = format!("{}::new(", "Command");
        let mut offenders = Vec::new();
        for file in files {
            if fs::canonicalize(&file).ok() == fs::canonicalize(&this_file).ok() {
                continue;
            }
            let Ok(text) = fs::read_to_string(&file) else {
                continue;
            };
            for (idx, line) in text.lines().enumerate() {
                if line.contains(&needle) {
                    offenders.push(format!("{}:{}: {}", file.display(), idx + 1, line.trim()));
                }
            }
        }
        assert_eq!(
            offenders,
            Vec::<String>::new(),
            "spawn child processes with waybound_core::process::command so secrets are \
             scrubbed from their environment:\n{}",
            offenders.join("\n")
        );
    }
}

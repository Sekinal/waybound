//! Daemon lifetime tied to the SDK process that started it.
//!
//! * `WAYBOUND_EXIT_WITH_PARENT=<pid>` (or `--exit-with-parent`): a watchdog requests the
//!   normal graceful shutdown (the `SIGTERM` path: held buttons released, Chrome and Xvfb
//!   stopped) once the watched process is gone, however it died (`SIGKILL` included).
//! * `WAYBOUND_REAP_PGID=<pgid>`: a process group the SDK started for this daemon's helpers (a
//!   pool slot's Xvfb, D-Bus and AT-SPI2). It is honoured only together with an SDK-set parent
//!   pid, and it is stopped only as a fallback when that parent is gone at shutdown; while
//!   the parent lives, the SDK stops its own helpers.
//!
//! Signals and probes go through `rustix` (no `unsafe`, no external `kill` utility). Unix
//! only; elsewhere both variables are ignored with a warning.

/// Which process the watchdog follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentWatch {
    /// Not requested.
    Off,
    /// The parent seen at startup (`--exit-with-parent`, or a non-pid value such as `1`).
    Current,
    /// This pid, as passed by the SDK (its own pid).
    Pid(u32),
}

/// Parses the `WAYBOUND_EXIT_WITH_PARENT` value.
pub fn parse_parent_watch(raw: Option<&str>) -> ParentWatch {
    match raw.map(str::trim) {
        None | Some("" | "0") => ParentWatch::Off,
        Some(value) => match value.parse::<u32>() {
            Ok(pid) if pid > 1 => ParentWatch::Pid(pid),
            _ => ParentWatch::Current,
        },
    }
}

/// Parses the syntax of `WAYBOUND_REAP_PGID`: a group id greater than 1.
pub fn parse_pgid(raw: Option<&str>) -> Option<i32> {
    raw?.trim().parse::<i32>().ok().filter(|pgid| *pgid > 1)
}

#[cfg(unix)]
pub use unix::Lifetime;

#[cfg(not(unix))]
pub use other::Lifetime;

#[cfg(unix)]
mod unix {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    use rustix::io::Errno;
    use rustix::process::{
        Pid, Signal, getpgid, getpgrp, kill_process_group, test_kill_process,
        test_kill_process_group,
    };

    use super::ParentWatch;

    /// How often the watchdog checks the watched process and the helper group.
    const POLL_INTERVAL: Duration = Duration::from_millis(250);
    /// Grace period between `SIGTERM` and `SIGKILL` when reaping the helper group.
    const REAP_GRACE: Duration = Duration::from_secs(2);

    /// The helper process group named by `WAYBOUND_REAP_PGID`, once validated.
    struct HelperGroup {
        pgid: Pid,
        /// Set once the group was seen empty: its id may then be reused by unrelated
        /// processes, so it is never signalled afterwards.
        seen_empty: AtomicBool,
    }

    impl HelperGroup {
        fn exists(&self) -> bool {
            // ESRCH: no process left in the group. EPERM still means members exist.
            !matches!(test_kill_process_group(self.pgid), Err(Errno::SRCH))
        }

        fn observe(&self) {
            if !self.exists() {
                self.seen_empty.store(true, Ordering::Release);
            }
        }
    }

    /// Watched pid plus how to tell that it is gone.
    #[derive(Clone, Copy)]
    struct Watched {
        pid: Pid,
        /// Whether we were its direct child at startup (then reparenting also counts as gone,
        /// which notices a dead parent even while it is an unreaped zombie).
        direct: bool,
    }

    impl Watched {
        /// Liveness probe: `kill(pid, 0)`. With a wrapper script between the SDK and the
        /// daemon, the SDK is not our parent, so the pid itself is probed rather than
        /// compared with our parent. Limits: a dead SDK process counts as alive while it is
        /// an unreaped zombie of its own parent, and if its pid is reused by an unrelated
        /// process within one poll interval the watchdog keeps waiting for that process.
        fn gone(self) -> bool {
            if self.direct && std::os::unix::process::parent_id() != pid_u32(self.pid) {
                return true;
            }
            matches!(test_kill_process(self.pid), Err(Errno::SRCH))
        }
    }

    fn pid_u32(pid: Pid) -> u32 {
        u32::try_from(pid.as_raw_nonzero().get()).unwrap_or(0)
    }

    fn to_pid(raw: u32) -> Option<Pid> {
        i32::try_from(raw).ok().and_then(Pid::from_raw)
    }

    /// Watchdog and fallback reaper for one daemon run.
    pub struct Lifetime {
        watched: Option<Watched>,
        parent_gone: Arc<AtomicBool>,
        group: Option<Arc<HelperGroup>>,
    }

    impl Lifetime {
        /// Starts the watchdog (if requested) and validates the helper group.
        pub fn start(
            shutdown: &Arc<AtomicBool>,
            watch: ParentWatch,
            reap_pgid: Option<i32>,
        ) -> Self {
            let parent = std::os::unix::process::parent_id();
            let watched = match watch {
                ParentWatch::Off => None,
                ParentWatch::Current => to_pid(parent),
                ParentWatch::Pid(raw) => to_pid(raw),
            }
            .map(|pid| Watched {
                pid,
                direct: pid_u32(pid) == parent,
            });
            let group = reap_pgid
                .and_then(|raw| validate_group(raw, watch, watched, parent))
                .map(|pgid| {
                    Arc::new(HelperGroup {
                        pgid,
                        seen_empty: AtomicBool::new(false),
                    })
                });
            let parent_gone = Arc::new(AtomicBool::new(false));
            if let Some(watched) = watched {
                spawn_watchdog(
                    Arc::clone(shutdown),
                    watched,
                    Arc::clone(&parent_gone),
                    group.clone(),
                );
            }
            Self {
                watched,
                parent_gone,
                group,
            }
        }

        /// Called after the graceful shutdown: if the SDK process is gone (so nobody else
        /// will stop the helpers), stop the helper group. While the SDK lives it stops its
        /// own helpers, so this returns at once.
        pub fn finish(self) {
            let Some(group) = self.group else {
                return;
            };
            let parent_gone =
                self.parent_gone.load(Ordering::Acquire) || self.watched.is_some_and(Watched::gone);
            if !parent_gone {
                return;
            }
            group.observe();
            if group.seen_empty.load(Ordering::Acquire) {
                return;
            }
            reap(&group);
        }
    }

    /// Accepts `pgid` only when the SDK asked for parent watching with an explicit pid, the
    /// group currently exists, and it is none of: our own group, the watched process's group,
    /// our parent's group.
    fn validate_group(
        raw: i32,
        watch: ParentWatch,
        watched: Option<Watched>,
        parent: u32,
    ) -> Option<Pid> {
        let reject = |why: &str| {
            tracing::warn!(pgid = raw, reason = why, "ignoring WAYBOUND_REAP_PGID");
            None
        };
        if !matches!(watch, ParentWatch::Pid(_)) {
            return reject("only honoured together with WAYBOUND_EXIT_WITH_PARENT=<pid>");
        }
        let pgid = Pid::from_raw(raw)?;
        if pgid == getpgrp() {
            return reject("it is the daemon's own process group");
        }
        let group_of = |pid: Option<Pid>| pid.and_then(|p| getpgid(Some(p)).ok());
        if watched.and_then(|w| group_of(Some(w.pid))) == Some(pgid) {
            return reject("it is the watched SDK process's group");
        }
        if group_of(to_pid(parent)) == Some(pgid) {
            return reject("it is the daemon's parent's group");
        }
        if matches!(test_kill_process_group(pgid), Err(Errno::SRCH)) {
            return reject("no such process group");
        }
        Some(pgid)
    }

    fn spawn_watchdog(
        shutdown: Arc<AtomicBool>,
        watched: Watched,
        parent_gone: Arc<AtomicBool>,
        group: Option<Arc<HelperGroup>>,
    ) {
        let spawned = thread::Builder::new()
            .name("waybound-parent-watch".to_owned())
            .spawn(move || {
                while !shutdown.load(Ordering::Acquire) {
                    if let Some(group) = &group {
                        group.observe();
                    }
                    if watched.gone() {
                        tracing::info!(
                            pid = pid_u32(watched.pid),
                            "watched SDK process exited; shutting down"
                        );
                        parent_gone.store(true, Ordering::Release);
                        shutdown.store(true, Ordering::Release);
                        break;
                    }
                    thread::sleep(POLL_INTERVAL);
                }
            });
        if let Err(err) = spawned {
            tracing::warn!(error = %err, "failed to start the parent watchdog");
        }
    }

    /// `SIGTERM` the group (Xvfb then removes its lock file), wait briefly, then `SIGKILL`
    /// what is left. Helpers whose parent (the SDK) is gone are reparented and reaped by
    /// init, so the probe stops matching them as soon as they exit.
    fn reap(group: &HelperGroup) {
        if kill_process_group(group.pgid, Signal::TERM).is_err() {
            return;
        }
        let deadline = Instant::now() + REAP_GRACE;
        while Instant::now() < deadline {
            if !group.exists() {
                tracing::info!(pgid = group.pgid.as_raw_nonzero().get(), "stopped helpers");
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        tracing::warn!(
            pgid = group.pgid.as_raw_nonzero().get(),
            "helper group ignored SIGTERM; killing it"
        );
        let _ = kill_process_group(group.pgid, Signal::KILL);
    }

    #[cfg(test)]
    mod tests {
        use std::os::unix::process::CommandExt;

        use super::*;

        fn spawn_group() -> Option<std::process::Child> {
            waybound_core::process::command("sh")
                .args(["-c", "sleep 30 & sleep 30"])
                .process_group(0)
                .spawn()
                .ok()
        }

        #[test]
        fn group_is_rejected_without_an_sdk_pid_or_when_it_is_ours() {
            let own = getpgrp().as_raw_nonzero().get();
            let parent = std::os::unix::process::parent_id();
            assert!(validate_group(own, ParentWatch::Current, None, parent).is_none());
            let me = to_pid(std::process::id()).map(|pid| Watched { pid, direct: false });
            let pid_watch = ParentWatch::Pid(std::process::id());
            assert!(validate_group(own, pid_watch, me, parent).is_none());
            // A group that does not exist is refused too.
            assert!(validate_group(i32::MAX - 7, pid_watch, me, parent).is_none());
        }

        #[test]
        fn reap_only_when_the_parent_is_gone_and_stops_every_member() {
            let Some(mut leader) = spawn_group() else {
                return;
            };
            let raw = i32::try_from(leader.id()).unwrap_or(0);
            thread::sleep(Duration::from_millis(200));
            let me = to_pid(std::process::id()).map(|pid| Watched { pid, direct: false });
            let pid_watch = ParentWatch::Pid(std::process::id());
            let parent = std::os::unix::process::parent_id();
            let pgid = validate_group(raw, pid_watch, me, parent);
            assert!(pgid.is_some());

            // Parent (this test process) alive: finish() must not touch the group.
            let alive = Lifetime {
                watched: me,
                parent_gone: Arc::new(AtomicBool::new(false)),
                group: pgid.map(|pgid| {
                    Arc::new(HelperGroup {
                        pgid,
                        seen_empty: AtomicBool::new(false),
                    })
                }),
            };
            let started = Instant::now();
            alive.finish();
            assert!(started.elapsed() < Duration::from_millis(100));
            assert!(matches!(leader.try_wait(), Ok(None)));

            // Parent gone: the whole group is stopped.
            let gone = Lifetime {
                watched: None,
                parent_gone: Arc::new(AtomicBool::new(true)),
                group: pgid.map(|pgid| {
                    Arc::new(HelperGroup {
                        pgid,
                        seen_empty: AtomicBool::new(false),
                    })
                }),
            };
            gone.finish();
            let _ = leader.wait();
            if let Some(pgid) = pgid {
                assert!(matches!(test_kill_process_group(pgid), Err(Errno::SRCH)));
            }
        }

        #[test]
        fn a_group_seen_empty_is_never_signalled_again() {
            let Some(mut leader) = spawn_group() else {
                return;
            };
            let raw = i32::try_from(leader.id()).unwrap_or(0);
            let Some(pgid) = Pid::from_raw(raw) else {
                return;
            };
            let group = HelperGroup {
                pgid,
                seen_empty: AtomicBool::new(false),
            };
            let _ = kill_process_group(pgid, Signal::KILL);
            let _ = leader.wait();
            let deadline = Instant::now() + Duration::from_secs(5);
            while group.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
            group.observe();
            assert!(group.seen_empty.load(Ordering::Acquire));
        }
    }
}

#[cfg(not(unix))]
mod other {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    use super::ParentWatch;

    /// No-op counterpart: there is no reparenting or process-group signalling to use here.
    pub struct Lifetime;

    impl Lifetime {
        /// Warns that the lifetime variables are ignored on this platform.
        pub fn start(_shutdown: &Arc<AtomicBool>, watch: ParentWatch, pgid: Option<i32>) -> Self {
            if watch != ParentWatch::Off || pgid.is_some() {
                tracing::warn!(
                    "WAYBOUND_EXIT_WITH_PARENT / WAYBOUND_REAP_PGID are not supported on this \
                     platform; ignoring them"
                );
            }
            Self
        }

        /// Nothing to do on this platform.
        #[allow(clippy::unused_self)] // Same signature as the Unix implementation.
        pub const fn finish(self) {}
    }
}

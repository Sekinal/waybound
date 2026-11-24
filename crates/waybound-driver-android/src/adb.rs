//! Pure-Rust ADB (`adb [-s <serial>] ...`) command runner for Android / Waydroid.

use std::io::Read;
use std::path::Path;
use std::process::{Output, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use tracing::debug;
use waybound_core::{InputEvent, KeyCode, KeyModifier, MouseButton, Point, Result, WayboundError};

const BACKEND_NAME: &str = "android_waydroid";
const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
const ADB_TIMEOUT: Duration = Duration::from_secs(15);
const ADB_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// How long a single snapshot retries transient `uiautomator dump` failures.
///
/// Afterwards it reports [`WayboundError::Transient`] to the caller, whose own wait loop
/// may poll again. Capped further by the caller's remaining wait; see
/// [`snapshot_retry_budget`].
pub const SNAPSHOT_RETRY_BUDGET: Duration = Duration::from_secs(3);
/// Pause between snapshot retries.
pub const SNAPSHOT_RETRY_INTERVAL: Duration = Duration::from_millis(250);

/// First Android API level whose `input keycombination` actually holds modifiers
/// (Android 13).
///
/// `keycombination` exists from API 31, but on Android 12 / 12L (API 31, 32) AOSP
/// `InputShellCommand.sendKeyCombination` builds every `KeyEvent` with `metaState` 0, so
/// Ctrl+A arrives as a plain `a`. Accumulating the modifier meta state was added in
/// android13-release.
pub const KEYCOMBINATION_MIN_SDK: u32 = 33;

/// Android `KeyEvent` keycodes for modifier keys (left-hand variants).
const KEYCODE_CTRL_LEFT: u32 = 113;
const KEYCODE_ALT_LEFT: u32 = 57;
const KEYCODE_SHIFT_LEFT: u32 = 59;
const KEYCODE_META_LEFT: u32 = 117;

/// Default swipe origin used when scrolling before any `PointerMove` has been dispatched.
const DEFAULT_SCROLL_ORIGIN: Point = Point { x: 540.0, y: 960.0 };
const SCROLL_SWIPE_DURATION_MS: u64 = 250;
/// Shortest touch drag gesture; `input swipe` with a tiny duration reads as a fling.
const MIN_DRAG_DURATION_MS: u64 = 300;
/// Longest touch drag gesture, bounded well below [`ADB_TIMEOUT`].
const MAX_DRAG_DURATION_MS: u64 = 10_000;
/// First Android API level whose `input` tool has `draganddrop` (Android 8.0 / Oreo; absent
/// from the Nougat sources).
pub const DRAG_AND_DROP_MIN_SDK: u32 = 26;

/// Android `KeyEvent` keycodes for non-character keys.
const KEYCODE_ENTER: u32 = 66;
const KEYCODE_TAB: u32 = 61;
const KEYCODE_ESCAPE: u32 = 111;
const KEYCODE_BACKSPACE: u32 = 67;

/// Whether a failed `adb` call is worth retrying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// Will not heal by waiting: `adb` missing, device offline / unauthorized / unknown,
    /// several devices without `-s`, or `uiautomator` absent on the device.
    Fatal,
    /// A known, self-healing hiccup: the UI never went idle, the accessibility root was
    /// null, another `UiAutomation` client was connected, or the adb transport reset.
    Transient,
    /// Nothing recognised. Each call site picks a policy (the dump treats it as transient,
    /// bounded by its deadline, and reports the text).
    Unrecognized,
}

/// Substrings (lower-case) of `adb` / device output that mean retrying cannot help.
const FATAL_MARKERS: &[&str] = &[
    "no devices/emulators found",
    "device offline",
    "unauthorized",
    "insufficient permissions",
    "more than one device",
    "device not found",
    "cannot connect to daemon",
    "failed to start daemon",
    "uiautomator: not found",
    "uiautomator: inaccessible or not found",
];

/// Substrings (lower-case) of `adb` / `uiautomator` output that are known to heal.
const TRANSIENT_MARKERS: &[&str] = &[
    "could not get idle state",
    "null root node",
    "already registered",
    "error: closed",
    "protocol fault",
    "connection reset",
];

/// Classifies the combined stdout/stderr text of a failed `adb` invocation.
///
/// Fatal markers win over transient ones, so a message such as
/// `error: device offline` never turns into a retry loop.
#[must_use]
pub fn classify_adb_failure(text: &str) -> FailureClass {
    let lower = text.to_ascii_lowercase();
    let is_missing_device =
        lower.contains("device '") && lower.contains("not found") && !lower.contains("uiautomator");
    if is_missing_device || FATAL_MARKERS.iter().any(|m| lower.contains(m)) {
        return FailureClass::Fatal;
    }
    if TRANSIENT_MARKERS.iter().any(|m| lower.contains(m)) {
        return FailureClass::Transient;
    }
    FailureClass::Unrecognized
}

/// Validates the output of `adb exec-out uiautomator dump <target>` and returns the XML.
///
/// A dump is accepted only when it contains a complete `<hierarchy>` element (closing tag
/// or self-closing). Output that starts an XML document but does not finish it is a
/// truncated dump and always [`WayboundError::Transient`]: its text is page content (which
/// may say "Unauthorized" or "device offline"), so it is never searched for adb markers.
/// Otherwise the non-XML output is classified with [`classify_adb_failure`]: fatal markers
/// become [`WayboundError::BackendUnavailable`], everything else (known transient,
/// unrecognised, empty) becomes [`WayboundError::Transient`].
///
/// # Errors
///
/// Returns the classified error when the output is not a complete hierarchy.
pub fn validate_dump_output(target: &str, success: bool, stdout: &str, stderr: &str) -> Result<()> {
    if has_complete_hierarchy(stdout) {
        return Ok(());
    }
    let status = if success { "exit 0" } else { "non-zero exit" };

    if starts_xml(stdout) {
        return Err(WayboundError::Transient {
            backend: BACKEND_NAME.to_owned(),
            reason: format!(
                "adb uiautomator dump {target} failed ({status}): truncated hierarchy \
                 ({} bytes, no closing </hierarchy>)",
                stdout.len()
            ),
        });
    }

    let combined = format!("{} {}", stdout.trim(), stderr.trim());
    let detail = if combined.trim().is_empty() {
        "empty output".to_owned()
    } else {
        format!(
            "no hierarchy in output: {}",
            truncate_for_log(combined.trim())
        )
    };
    let reason = format!("adb uiautomator dump {target} failed ({status}): {detail}");

    match classify_adb_failure(&combined) {
        FailureClass::Fatal => Err(WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason,
        }),
        FailureClass::Transient | FailureClass::Unrecognized => Err(WayboundError::Transient {
            backend: BACKEND_NAME.to_owned(),
            reason,
        }),
    }
}

/// Whether the dump output contains the start of the XML document.
fn starts_xml(stdout: &str) -> bool {
    stdout.contains("<?xml") || stdout.contains("<hierarchy")
}

/// Whether a failed `/dev/stdout` dump is worth repeating against `/dev/tty`.
///
/// Only empty or unrecognised output suggests the device cannot write the dump to
/// `/dev/stdout`. A known transient failure (UI not idle, null root) would fail the same
/// way on `/dev/tty` after another ~10 s idle wait, a truncated dump means the target
/// works, and a fatal marker cannot heal.
#[must_use]
pub fn should_try_tty_fallback(stdout: &str, stderr: &str) -> bool {
    if starts_xml(stdout) {
        return false;
    }
    let combined = format!("{} {}", stdout.trim(), stderr.trim());
    classify_adb_failure(&combined) == FailureClass::Unrecognized
}

fn has_complete_hierarchy(xml: &str) -> bool {
    let Some(start) = xml.find("<hierarchy") else {
        return false;
    };
    if xml
        .get(start..)
        .is_some_and(|rest| rest.contains("</hierarchy>"))
    {
        return true;
    }
    // `<hierarchy rotation="0"/>`: an empty but complete dump.
    xml.get(start..)
        .and_then(|rest| rest.find('>').and_then(|end| rest.get(..end)))
        .is_some_and(|open_tag| open_tag.ends_with('/'))
}

/// Captures the current Android UI accessibility hierarchy XML.
///
/// Runs `adb [-s <serial>] exec-out uiautomator dump /dev/stdout`, repeating against
/// `/dev/tty` only when [`should_try_tty_fallback`] says the first target produced empty or
/// unrecognised output.
///
/// Makes one attempt (one adb command, or two with the fallback); see [`retry_dump`] for
/// the retrying form.
///
/// # Errors
///
/// Returns [`WayboundError::Transient`] for failures expected to heal (UI not idle, null
/// root node, truncated or empty XML, adb command timeout) and
/// [`WayboundError::BackendUnavailable`] for fatal ones (`adb` missing, device offline,
/// unauthorized or not found).
pub fn dump_ui_xml(serial: Option<&str>) -> Result<String> {
    let mut last_err = None;
    for target in ["/dev/stdout", "/dev/tty"] {
        let args = build_adb_args(serial, &["exec-out", "uiautomator", "dump", target]);
        let output = match run_adb(&args) {
            Ok(output) => output,
            // A hung dump already cost ADB_TIMEOUT; do not spend it again on `/dev/tty`.
            Err(WayboundError::Timeout { context, .. }) => {
                return Err(WayboundError::Transient {
                    backend: BACKEND_NAME.to_owned(),
                    reason: context,
                });
            }
            Err(err) => return Err(err),
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        match validate_dump_output(target, output.status.success(), &stdout, &stderr) {
            Ok(()) => return Ok(stdout.into_owned()),
            Err(err) if err.is_transient() && should_try_tty_fallback(&stdout, &stderr) => {
                debug!(target, error = %err, "uiautomator dump gave no usable output; trying next target");
                last_err = Some(err);
            }
            Err(err) => return Err(err),
        }
    }

    Err(last_err.unwrap_or_else(|| WayboundError::Transient {
        backend: BACKEND_NAME.to_owned(),
        reason: "adb uiautomator dump failed".to_owned(),
    }))
}

/// Retry budget for one snapshot.
///
/// [`SNAPSHOT_RETRY_BUDGET`], capped at the caller's remaining wait when it has one, so a
/// nested retry cannot outlast the caller's deadline by more than the attempt in flight.
#[must_use]
pub fn snapshot_retry_budget(caller_remaining: Option<Duration>) -> Duration {
    caller_remaining.map_or(SNAPSHOT_RETRY_BUDGET, |remaining| {
        remaining.min(SNAPSHOT_RETRY_BUDGET)
    })
}

/// Consecutive `already registered` dump failures one retry loop tolerates.
///
/// Our own dumps are serialised per driver, so a persistent
/// `UiAutomationService ... already registered` means another `UiAutomation` client
/// (a test runner, another tool) holds the device.
pub const MAX_ALREADY_REGISTERED: u32 = 3;

/// Retries `attempt` (one [`dump_ui_xml`]) on transient failures.
///
/// Stops when it succeeds, fails fatally, or `budget` elapses; see [`poll_transient`].
/// Always makes at least one attempt.
///
/// `attempt` should take any per-device lock itself, so other callers can interleave
/// between attempts instead of queueing behind the whole loop.
///
/// # Errors
///
/// Fatal errors are returned at once. After [`MAX_ALREADY_REGISTERED`] consecutive
/// "already registered" failures, returns [`WayboundError::BackendUnavailable`] naming
/// the conflicting client. When the budget runs out, returns
/// [`WayboundError::Transient`] carrying the attempt count and the last failure.
pub fn retry_dump(
    clock: &dyn Clock,
    budget: Duration,
    mut attempt: impl FnMut() -> Result<String>,
) -> Result<String> {
    let mut already_registered: u32 = 0;
    let op = || match attempt() {
        Err(err) if err.is_transient() && error_reason(&err).contains("already registered") => {
            already_registered += 1;
            if already_registered >= MAX_ALREADY_REGISTERED {
                return Err(WayboundError::BackendUnavailable {
                    backend: BACKEND_NAME.to_owned(),
                    reason: format!(
                        "another UiAutomation client is attached to the device \
                         ({already_registered} dumps in a row): {}",
                        error_reason(&err)
                    ),
                });
            }
            Err(err)
        }
        other => {
            already_registered = 0;
            other
        }
    };
    poll_transient(clock, budget, SNAPSHOT_RETRY_INTERVAL, op).map_err(|err| match err {
        PollError::Fatal(err) => err,
        PollError::Exhausted { attempts, last } => WayboundError::Transient {
            backend: BACKEND_NAME.to_owned(),
            reason: format!(
                "uiautomator dump still failing after {attempts} attempts; last error: {}",
                error_reason(&last)
            ),
        },
    })
}

/// Time source for retry loops, injectable so tests need neither a device nor real sleeps.
pub trait Clock {
    /// Current instant.
    fn now(&self) -> Instant;
    /// Blocks for `duration`.
    fn sleep(&self, duration: Duration);
}

/// [`Clock`] backed by [`Instant::now`] and [`thread::sleep`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, duration: Duration) {
        thread::sleep(duration);
    }
}

/// Why [`poll_transient`] gave up.
#[derive(Debug)]
pub enum PollError {
    /// A non-transient error; returned on the attempt that produced it.
    Fatal(WayboundError),
    /// Every attempt until the deadline failed transiently.
    Exhausted {
        /// Number of attempts made.
        attempts: u32,
        /// The last transient error.
        last: WayboundError,
    },
}

/// Calls `op` until it succeeds, fails with a non-transient error, or `budget` elapses.
///
/// Always makes at least one attempt. Errors for which [`WayboundError::is_transient`]
/// is true are retried every `interval`; any other error stops the loop immediately.
///
/// # Errors
///
/// [`PollError::Fatal`] for a non-transient error, [`PollError::Exhausted`] (carrying the
/// last transient error) when the deadline passes.
pub fn poll_transient<T>(
    clock: &dyn Clock,
    budget: Duration,
    interval: Duration,
    mut op: impl FnMut() -> Result<T>,
) -> std::result::Result<T, PollError> {
    let deadline = clock.now() + budget;
    let mut attempts: u32 = 0;
    loop {
        attempts = attempts.saturating_add(1);
        match op() {
            Ok(value) => return Ok(value),
            Err(err) if err.is_transient() => {
                let now = clock.now();
                if now >= deadline {
                    return Err(PollError::Exhausted {
                        attempts,
                        last: err,
                    });
                }
                debug!(attempts, error = %err, "transient adb failure; retrying");
                clock.sleep(interval.min(deadline - now));
            }
            Err(err) => return Err(PollError::Fatal(err)),
        }
    }
}

/// Returns the inner `reason`/`context` of an error without the variant prefix.
#[must_use]
pub fn error_reason(err: &WayboundError) -> String {
    match err {
        WayboundError::Transient { reason, .. }
        | WayboundError::BackendUnavailable { reason, .. }
        | WayboundError::UnsupportedInput { reason, .. } => reason.clone(),
        WayboundError::Timeout { context, .. } => context.clone(),
        other => other.to_string(),
    }
}

/// How the connected device can deliver modifier chords through `adb shell input`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChordSupport {
    /// API 33+ (Android 13+): `input keycombination` presses every key together with the
    /// modifiers' meta state applied.
    KeyCombination,
    /// API 32 and below: `input` cannot hold a modifier (API 31-32 have `keycombination`
    /// but send it without meta state). Only Shift on a letter can be
    /// expressed (by typing the upper-case letter); everything else is unsupported.
    ShiftLettersOnly {
        /// The device's `ro.build.version.sdk`.
        sdk: u32,
    },
}

impl ChordSupport {
    /// Picks the chord strategy for an Android API level.
    #[must_use]
    pub const fn from_sdk(sdk: u32) -> Self {
        if sdk >= KEYCOMBINATION_MIN_SDK {
            Self::KeyCombination
        } else {
            Self::ShiftLettersOnly { sdk }
        }
    }
}

/// Parses `adb shell getprop ro.build.version.sdk` output (for example `"33\r\n"`).
#[must_use]
pub fn parse_sdk_level(raw: &str) -> Option<u32> {
    raw.trim().parse::<u32>().ok().filter(|&sdk| sdk > 0)
}

/// Per-driver cache of the device's [`ChordSupport`], probed at most once successfully.
///
/// A failed probe is not cached, so a later chord retries it.
#[derive(Debug, Default)]
pub struct ChordSupportCache(OnceLock<ChordSupport>);

impl ChordSupportCache {
    /// Creates an empty cache.
    #[must_use]
    pub const fn new() -> Self {
        Self(OnceLock::new())
    }

    /// Returns the cached value, or runs `probe` and caches its success.
    ///
    /// # Errors
    ///
    /// Returns the probe's error, uncached.
    pub fn get_or_probe(
        &self,
        probe: impl FnOnce() -> Result<ChordSupport>,
    ) -> Result<ChordSupport> {
        if let Some(support) = self.0.get() {
            return Ok(*support);
        }
        let support = probe()?;
        Ok(*self.0.get_or_init(|| support))
    }
}

/// Reads the device API level with `adb shell getprop ro.build.version.sdk`.
///
/// # Errors
///
/// [`WayboundError::BackendUnavailable`] if `adb` is missing or the output matches a fatal
/// marker (device offline, unauthorized, ...); [`WayboundError::Transient`] for a command
/// timeout or any other failure, so callers such as `fill` can degrade instead of failing.
pub fn probe_chord_support(serial: Option<&str>) -> Result<ChordSupport> {
    let args = build_adb_args(serial, &["shell", "getprop", "ro.build.version.sdk"]);
    let output = match run_adb(&args) {
        Ok(output) => output,
        Err(WayboundError::Timeout { context, .. }) => {
            return Err(WayboundError::Transient {
                backend: BACKEND_NAME.to_owned(),
                reason: context,
            });
        }
        Err(err) => return Err(err),
    };
    let support = parse_probe_output(
        output.status.success(),
        &String::from_utf8_lossy(&output.stdout),
        &String::from_utf8_lossy(&output.stderr),
    )?;
    debug!(?support, "detected Android key chord support");
    Ok(support)
}

/// Turns `getprop ro.build.version.sdk` output into a [`ChordSupport`].
///
/// # Errors
///
/// [`WayboundError::BackendUnavailable`] when the output matches a fatal marker
/// (see [`classify_adb_failure`]), [`WayboundError::Transient`] for any other failure.
pub fn parse_probe_output(success: bool, stdout: &str, stderr: &str) -> Result<ChordSupport> {
    if success && let Some(sdk) = parse_sdk_level(stdout) {
        return Ok(ChordSupport::from_sdk(sdk));
    }
    let combined = format!("{} {}", stdout.trim(), stderr.trim());
    let reason = format!(
        "could not read Android API level from getprop: {}",
        truncate_for_log(combined.trim())
    );
    if classify_adb_failure(&combined) == FailureClass::Fatal {
        return Err(WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason,
        });
    }
    Err(WayboundError::Transient {
        backend: BACKEND_NAME.to_owned(),
        reason,
    })
}

/// A touch drag that has been pressed but not yet released.
///
/// `adb shell input` cannot hold a finger down across separate commands, so a
/// [`InputEvent::MouseDown`] only records where and when the gesture started; the
/// matching [`InputEvent::MouseUp`] then emits the whole drag as one `input draganddrop`
/// (or `input swipe` on old devices) from that point to the last
/// [`InputEvent::PointerDrag`] position.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PendingDrag {
    /// Where the finger went down.
    pub from: Point,
    /// When the press was recorded.
    pub pressed_at: Instant,
}

/// State of the buffered touch drag between press and release.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum DragGesture {
    /// No drag in progress.
    #[default]
    Idle,
    /// Pressed and waiting for the release that sends the gesture.
    Pressed(PendingDrag),
    /// The last release's gesture command failed. `adb` can report failure after the
    /// device already ran the gesture, so the drag is never replayed; a follow-up release
    /// reports this failure again instead of claiming success.
    ReleaseFailed(String),
}

/// Dispatches a platform-agnostic [`InputEvent`] to an Android device via `adb shell input`.
///
/// Tracks `last_cursor` across [`InputEvent::PointerMove`], [`InputEvent::MouseClick`],
/// and [`InputEvent::Scroll`] events, buffers press / drag / release sequences in
/// `gesture` (see [`PendingDrag`]), and sends modifier key chords via `input keycombination`
/// where available (cached in `chords`). `sdk_level` is only called when a drag is released,
/// to choose between `draganddrop` and `swipe`.
///
/// # Errors
///
/// Returns [`WayboundError::UnsupportedInput`] for input `adb shell input` cannot
/// express (non-left mouse buttons, modifier chords on old Android), or
/// [`WayboundError::BackendUnavailable`] if `adb` fails to execute or exits non-zero.
pub fn dispatch_input(
    serial: Option<&str>,
    event: &InputEvent,
    last_cursor: &mut Point,
    chords: &ChordSupportCache,
    gesture: &mut DragGesture,
    sdk_level: impl FnOnce() -> Option<u32>,
) -> Result<()> {
    if let Some(reason) = unsupported_input_reason(event) {
        return Err(unsupported(reason));
    }

    if let InputEvent::KeyPress { key, modifiers, .. } = event
        && !modifiers.is_empty()
    {
        let support = chords.get_or_probe(|| probe_chord_support(serial))?;
        let shell_args = build_key_chord_args(key, modifiers, support)?;
        let arg_refs: Vec<&str> = shell_args.iter().map(String::as_str).collect();
        let args = build_adb_args(serial, &arg_refs);
        let output = run_adb(&args)?;
        return ensure_success(&output, "input dispatch");
    }

    dispatch_input_with(event, last_cursor, gesture, sdk_level, |shell_args| {
        let arg_refs: Vec<&str> = shell_args.iter().map(String::as_str).collect();
        let args = build_adb_args(serial, &arg_refs);
        let output = run_adb(&args)?;
        ensure_success(&output, "input dispatch")
    })
}

/// [`dispatch_input`] with the `adb shell` runner injected, so gesture buffering and error
/// handling can be tested without a device.
///
/// A release consumes the buffered drag before running its gesture, so the gesture is
/// sent at most once. If it fails, the error is returned and remembered: a retried
/// release returns it again (and sends nothing) rather than reporting success.
///
/// # Errors
///
/// Returns whatever `run` returns for the command it is given, or the remembered error of
/// a failed release.
pub fn dispatch_input_with(
    event: &InputEvent,
    last_cursor: &mut Point,
    gesture: &mut DragGesture,
    sdk_level: impl FnOnce() -> Option<u32>,
    mut run: impl FnMut(&[String]) -> Result<()>,
) -> Result<()> {
    match event {
        InputEvent::MouseDown { .. } => {
            *gesture = DragGesture::Pressed(PendingDrag {
                from: *last_cursor,
                pressed_at: Instant::now(),
            });
            Ok(())
        }
        InputEvent::MouseUp { .. } => match std::mem::take(gesture) {
            DragGesture::Idle => {
                // No finger is down on the device, so there is nothing to lift.
                debug!("ignoring adb release without a pending press");
                Ok(())
            }
            DragGesture::ReleaseFailed(reason) => Err(WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!(
                    "drag release failed and is not replayed (the device may already have \
                     performed it): {reason}"
                ),
            }),
            DragGesture::Pressed(drag) => {
                let held_ms =
                    u64::try_from(drag.pressed_at.elapsed().as_millis()).unwrap_or(u64::MAX);
                let args = build_drag_args(
                    drag.from,
                    *last_cursor,
                    held_ms,
                    supports_drag_and_drop(sdk_level()),
                );
                run(&args).inspect_err(|err| {
                    *gesture = DragGesture::ReleaseFailed(err.to_string());
                })
            }
        },
        other => build_input_shell_args(other, last_cursor).map_or(Ok(()), |args| run(&args)),
    }
}

/// Reads the device API level (`ro.build.version.sdk`), or `None` if it cannot be read.
#[must_use]
pub fn probe_sdk_level(serial: Option<&str>) -> Option<u32> {
    let args = build_adb_args(serial, &["shell", "getprop", "ro.build.version.sdk"]);
    let output = run_adb(&args).ok()?;
    if !output.status.success() {
        return None;
    }
    parse_sdk_level(&String::from_utf8_lossy(&output.stdout))
}

/// Whether a device at API level `sdk` has `input draganddrop` (unknown levels do not).
#[must_use]
pub const fn supports_drag_and_drop(sdk: Option<u32>) -> bool {
    matches!(sdk, Some(level) if level >= DRAG_AND_DROP_MIN_SDK)
}

/// Returns why `event` cannot be delivered through `adb shell input`, if it cannot.
///
/// Modifier chords are checked separately by [`build_key_chord_args`], because the
/// answer depends on the device API level.
#[must_use]
pub fn unsupported_input_reason(event: &InputEvent) -> Option<String> {
    match event {
        InputEvent::MouseClick {
            button: button @ (MouseButton::Right | MouseButton::Middle),
            ..
        } => Some(format!(
            "{button:?} mouse button: `adb shell input` only taps or long-presses (left click)"
        )),
        InputEvent::KeyDown { .. } | InputEvent::KeyUp { .. } => {
            Some("split key_down/key_up is not supported by adb input".to_owned())
        }
        _ => None,
    }
}

fn unsupported(reason: String) -> WayboundError {
    WayboundError::UnsupportedInput {
        backend: BACKEND_NAME.to_owned(),
        reason,
    }
}

/// Builds the `adb shell input ...` arguments for a key press held with `modifiers`.
///
/// * [`ChordSupport::KeyCombination`]: `input keycombination <modifier codes...> <key code>`,
///   modifiers deduplicated in the fixed order Control, Alt, Shift, Meta. An upper-case
///   letter adds Shift.
/// * [`ChordSupport::ShiftLettersOnly`]: Shift on a letter becomes `input text <UPPER>`;
///   anything else is unsupported.
///
/// # Errors
///
/// Returns [`WayboundError::UnsupportedInput`] when the chord cannot be expressed, rather
/// than sending the bare key.
pub fn build_key_chord_args(
    key: &KeyCode,
    modifiers: &[KeyModifier],
    support: ChordSupport,
) -> Result<Vec<String>> {
    if modifiers.is_empty() {
        return Ok(build_key_shell_args(key));
    }
    let chord = describe_chord(key, modifiers);

    match support {
        ChordSupport::KeyCombination => {
            let (keycode, implied_shift) = chord_keycode(key).ok_or_else(|| {
                unsupported(format!(
                    "{chord}: no Android keycode for {key:?} to combine with modifiers"
                ))
            })?;
            let mut args = vec![
                "shell".to_owned(),
                "input".to_owned(),
                "keycombination".to_owned(),
            ];
            for (modifier, code) in [
                (KeyModifier::Control, KEYCODE_CTRL_LEFT),
                (KeyModifier::Alt, KEYCODE_ALT_LEFT),
                (KeyModifier::Shift, KEYCODE_SHIFT_LEFT),
                (KeyModifier::Meta, KEYCODE_META_LEFT),
            ] {
                let implied = implied_shift && modifier == KeyModifier::Shift;
                if implied || modifiers.contains(&modifier) {
                    args.push(code.to_string());
                }
            }
            args.push(keycode.to_string());
            Ok(args)
        }
        ChordSupport::ShiftLettersOnly { sdk } => {
            let only_shift = modifiers.iter().all(|m| *m == KeyModifier::Shift);
            match key {
                KeyCode::Char(ch) if only_shift && ch.is_ascii_alphabetic() => Ok(
                    build_key_shell_args(&KeyCode::Char(ch.to_ascii_uppercase())),
                ),
                _ => Err(unsupported(format!(
                    "{chord}: Android API {sdk} cannot hold modifiers through `adb shell \
                     input` (`input keycombination` applies modifier meta state only from API \
                     {KEYCOMBINATION_MIN_SDK} / Android 13; API 31-32 send the bare key and \
                     older versions lack it); `input keyevent` cannot hold modifiers and \
                     `sendevent` needs root plus device-specific evdev codes"
                ))),
            }
        }
    }
}

fn describe_chord(key: &KeyCode, modifiers: &[KeyModifier]) -> String {
    let mut parts: Vec<String> = modifiers.iter().map(|m| format!("{m:?}")).collect();
    parts.push(match key {
        KeyCode::Char(ch) => ch.to_string(),
        other => format!("{other:?}"),
    });
    parts.join("+")
}

/// Resolves a [`KeyCode`] to an Android keycode (`Ok`) or to a character that has to be
/// typed as text (`Err`). `\n`, `\r` and `\t` resolve to Enter and Tab.
const fn key_target(key: &KeyCode) -> std::result::Result<u32, char> {
    Ok(match key {
        KeyCode::Enter | KeyCode::Char('\n' | '\r') => KEYCODE_ENTER,
        KeyCode::Tab | KeyCode::Char('\t') => KEYCODE_TAB,
        KeyCode::Escape => KEYCODE_ESCAPE,
        KeyCode::Backspace => KEYCODE_BACKSPACE,
        KeyCode::ArrowLeft => 21,
        KeyCode::ArrowRight => 22,
        KeyCode::ArrowUp => 19,
        KeyCode::ArrowDown => 20,
        KeyCode::Space => 62,
        KeyCode::Delete => 112,
        KeyCode::Home => 122,
        KeyCode::End => 123,
        KeyCode::PageUp => 92,
        KeyCode::PageDown => 93,
        KeyCode::Char(ch) => return Err(*ch),
    })
}

/// Android keycode for a key inside a chord, plus whether it needs an implied Shift
/// (upper-case letters).
fn chord_keycode(key: &KeyCode) -> Option<(u32, bool)> {
    let ch = match key_target(key) {
        Ok(code) => return Some((code, false)),
        Err(ch) => ch,
    };
    if ch.is_ascii_lowercase() {
        return Some((29 + u32::from(ch) - u32::from('a'), false));
    }
    if ch.is_ascii_uppercase() {
        return Some((29 + u32::from(ch) - u32::from('A'), true));
    }
    if ch.is_ascii_digit() {
        return Some((7 + u32::from(ch) - u32::from('0'), false));
    }
    let code = match ch {
        ' ' => 62,
        '*' => 17,
        '#' => 18,
        ',' => 55,
        '.' => 56,
        '`' => 68,
        '-' => 69,
        '=' => 70,
        '[' => 71,
        ']' => 72,
        '\\' => 73,
        ';' => 74,
        '\'' => 75,
        '/' => 76,
        '@' => 77,
        '+' => 81,
        _ => return None,
    };
    Some((code, false))
}

/// Captures a PNG screenshot of the Android display to `output_path` via
/// `adb [-s <serial>] exec-out screencap -p`.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if `adb` fails or does not return
/// valid non-empty PNG bytes, or [`WayboundError::Io`] if writing `output_path` fails.
pub fn capture_png(serial: Option<&str>, output_path: &Path) -> Result<()> {
    let args = build_adb_args(serial, &["exec-out", "screencap", "-p"]);
    let output = run_adb(&args)?;
    ensure_success(&output, "screencap")?;

    validate_png_bytes(&output.stdout)?;
    std::fs::write(output_path, &output.stdout)?;
    Ok(())
}

/// Opens an `http://` or `https://` URL in Android Chrome via
/// `adb [-s <serial>] shell am start -a android.intent.action.VIEW -d <url> com.android.chrome`.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if `url` is not a valid `http`/`https` URL
/// or if `adb` fails to launch the intent.
pub fn open_chrome_url(serial: Option<&str>, url: &str) -> Result<()> {
    validate_http_url(url)?;
    let escaped_url = shell_single_quote(url);
    let args = build_adb_args(
        serial,
        &[
            "shell",
            "am",
            "start",
            "-a",
            "android.intent.action.VIEW",
            "-d",
            &escaped_url,
            "com.android.chrome",
        ],
    );
    let output = run_adb(&args)?;
    ensure_success(&output, "am start chrome")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    am_start_error(&stdout, &stderr).map_or(Ok(()), |error| {
        Err(WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!("am start chrome failed: {}", truncate_for_log(&error)),
        })
    })
}

/// Extracts the `Error...` lines from `am start` output.
///
/// `am start` exits 0 even when the activity did not start (for example
/// `Error: Activity not started, unable to resolve Intent` when Chrome is missing), so
/// the exit status alone cannot be trusted. `Warning:` lines (such as "intent has been
/// delivered to currently running top-most instance") are not errors.
#[must_use]
pub fn am_start_error(stdout: &str, stderr: &str) -> Option<String> {
    let errors: Vec<&str> = stdout
        .lines()
        .chain(stderr.lines())
        .map(str::trim)
        .filter(|line| line.starts_with("Error"))
        .collect();
    (!errors.is_empty()).then(|| errors.join("; "))
}

/// Builds the full argument vector for `adb`, prepending `["-s", serial]` when present.
#[must_use]
pub fn build_adb_args(serial: Option<&str>, subcommand: &[&str]) -> Vec<String> {
    let extra = if serial.is_some() { 2 } else { 0 };
    let mut args = Vec::with_capacity(extra + subcommand.len());
    if let Some(id) = serial {
        args.push("-s".to_owned());
        args.push(id.to_owned());
    }
    for &part in subcommand {
        args.push(part.to_owned());
    }
    args
}

/// Builds the `adb shell input` arguments for a touch drag from `from` to `to` lasting
/// `duration_ms` (clamped to a range Chrome reads as a drag, not a fling).
///
/// With `drag_and_drop`, uses `input draganddrop`, which holds for the system long-press
/// timeout before moving, so HTML5 and touch-sortable drags start instead of the page
/// scrolling. Otherwise (Android < 8.0) falls back to a plain `input swipe`.
#[must_use]
pub fn build_drag_args(
    from: Point,
    to: Point,
    duration_ms: u64,
    drag_and_drop: bool,
) -> Vec<String> {
    vec![
        "shell".to_owned(),
        "input".to_owned(),
        if drag_and_drop {
            "draganddrop"
        } else {
            "swipe"
        }
        .to_owned(),
        coord_to_i32(from.x).to_string(),
        coord_to_i32(from.y).to_string(),
        coord_to_i32(to.x).to_string(),
        coord_to_i32(to.y).to_string(),
        duration_ms
            .clamp(MIN_DRAG_DURATION_MS, MAX_DRAG_DURATION_MS)
            .to_string(),
    ]
}

/// Builds the `adb shell input ...` arguments for an [`InputEvent`], updating `last_cursor`.
///
/// Returns `None` for events that only update local pointer state (such as `PointerMove`
/// and `PointerDrag`), for [`InputEvent::MouseDown`] / [`InputEvent::MouseUp`] (handled
/// by [`dispatch_input`]), and for events this function cannot express on its own:
/// a `KeyPress` with modifiers (see [`build_key_chord_args`]) and a non-left `MouseClick`
/// (see [`unsupported_input_reason`]). It never sends a different key or button instead.
#[must_use]
pub fn build_input_shell_args(event: &InputEvent, last_cursor: &mut Point) -> Option<Vec<String>> {
    match event {
        InputEvent::PointerMove { to } | InputEvent::PointerDrag { to, .. } => {
            *last_cursor = *to;
            None
        }
        InputEvent::MouseDown { .. }
        | InputEvent::MouseUp { .. }
        | InputEvent::KeyDown { .. }
        | InputEvent::KeyUp { .. } => None,
        InputEvent::MouseClick { button, .. } if *button != MouseButton::Left => None,
        InputEvent::MouseClick { button: _, hold_ms } => {
            let x = coord_to_i32(last_cursor.x);
            let y = coord_to_i32(last_cursor.y);
            if *hold_ms > 0 {
                Some(vec![
                    "shell".to_owned(),
                    "input".to_owned(),
                    "swipe".to_owned(),
                    x.to_string(),
                    y.to_string(),
                    x.to_string(),
                    y.to_string(),
                    hold_ms.to_string(),
                ])
            } else {
                Some(vec![
                    "shell".to_owned(),
                    "input".to_owned(),
                    "tap".to_owned(),
                    x.to_string(),
                    y.to_string(),
                ])
            }
        }
        InputEvent::Scroll { delta_x, delta_y } => {
            let origin = if last_cursor.x == 0.0 && last_cursor.y == 0.0 {
                DEFAULT_SCROLL_ORIGIN
            } else {
                *last_cursor
            };
            let x1 = coord_to_i32(origin.x);
            let y1 = coord_to_i32(origin.y);
            // Negative delta_y scrolls down (revealing content below), which on touchscreens
            // requires swiping the finger upward (y2 < y1).
            let x2 = coord_to_i32(origin.x + *delta_x);
            let y2 = coord_to_i32(origin.y + *delta_y);
            Some(vec![
                "shell".to_owned(),
                "input".to_owned(),
                "swipe".to_owned(),
                x1.to_string(),
                y1.to_string(),
                x2.to_string(),
                y2.to_string(),
                SCROLL_SWIPE_DURATION_MS.to_string(),
            ])
        }
        InputEvent::KeyPress { key, modifiers, .. } => {
            modifiers.is_empty().then(|| build_key_shell_args(key))
        }
    }
}

fn build_key_shell_args(key: &KeyCode) -> Vec<String> {
    match key_target(key) {
        Ok(keycode) => keyevent_args(keycode),
        Err(ch) => {
            let mut buf = [0u8; 4];
            let s = ch.encode_utf8(&mut buf);
            vec![
                "shell".to_owned(),
                "input".to_owned(),
                "text".to_owned(),
                escape_android_input_text(s),
            ]
        }
    }
}

fn keyevent_args(keycode: u32) -> Vec<String> {
    vec![
        "shell".to_owned(),
        "input".to_owned(),
        "keyevent".to_owned(),
        keycode.to_string(),
    ]
}

/// Safely escapes text for Android's `adb shell input text <arg>`.
///
/// Encodes ASCII spaces as `%s` (as required by Android's `input text` tool) and
/// wraps the result in POSIX single quotes so `/system/bin/sh` never interprets
/// shell metacharacters.
#[must_use]
pub fn escape_android_input_text(text: &str) -> String {
    let with_spaces = text.replace(' ', "%s");
    shell_single_quote(&with_spaces)
}

/// Wraps `raw` in POSIX single quotes for safe passing through `/system/bin/sh`.
#[must_use]
pub fn shell_single_quote(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('\'');
    for ch in raw.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Validates that `url` uses an `http://` or `https://` scheme and contains no
/// whitespace or ASCII control characters.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if validation fails.
pub fn validate_http_url(url: &str) -> Result<()> {
    if url.is_empty() || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!("invalid URL (empty or contains whitespace/control chars): {url}"),
        });
    }

    let lower = url.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"));

    let Some(after_scheme) = rest else {
        return Err(WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!("unsupported URL scheme (expected http:// or https://): {url}"),
        });
    };

    if after_scheme.is_empty() || after_scheme.starts_with('/') {
        return Err(WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!("URL is missing host: {url}"),
        });
    }

    Ok(())
}

/// Verifies that `bytes` is non-empty and begins with the 8-byte PNG signature.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if `bytes` is empty or lacks the PNG header.
pub fn validate_png_bytes(bytes: &[u8]) -> Result<()> {
    if bytes.len() < PNG_MAGIC.len() || !bytes.starts_with(&PNG_MAGIC) {
        return Err(WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!(
                "adb screencap did not return valid PNG data ({} bytes)",
                bytes.len()
            ),
        });
    }
    Ok(())
}

#[allow(clippy::cast_possible_truncation)]
fn coord_to_i32(value: f64) -> i32 {
    if !value.is_finite() {
        return 0;
    }
    value.round().clamp(0.0, f64::from(i32::MAX)) as i32
}

pub(crate) fn run_adb(args: &[String]) -> Result<Output> {
    debug!(?args, "executing adb command");
    let mut cmd = waybound_core::process::command("adb");
    let _ = cmd
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|err| WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!("failed to execute adb: {err}"),
        })?;

    let stdout_handle = child.stdout.take().map(|mut pipe| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    });
    let stderr_handle = child.stderr.take().map(|mut pipe| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    });

    let deadline = Instant::now() + ADB_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(WayboundError::Timeout {
                        timeout_ms: u64::try_from(ADB_TIMEOUT.as_millis()).unwrap_or(15_000),
                        context: format!("adb command timed out: {args:?}"),
                    });
                }
                thread::sleep(ADB_POLL_INTERVAL);
            }
            Err(err) => return Err(WayboundError::Io(err)),
        }
    };

    let stdout = stdout_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();
    let stderr = stderr_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();

    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

pub(crate) fn ensure_success(output: &Output, context: &str) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    // `am` and other device tools print their errors on stdout.
    Err(WayboundError::BackendUnavailable {
        backend: BACKEND_NAME.to_owned(),
        reason: format!(
            "adb {context} failed with status {}: stderr: {}; stdout: {}",
            output.status,
            truncate_for_log(stderr.trim()),
            truncate_for_log(stdout.trim())
        ),
    })
}

pub(crate) fn truncate_for_log(s: &str) -> String {
    const MAX_LEN: usize = 200;
    let mut out: String = s.chars().take(MAX_LEN).collect();
    if s.chars().count() > MAX_LEN {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
mod tests {
    use waybound_core::MouseButton;

    use super::*;

    #[test]
    fn build_adb_args_with_and_without_serial() {
        assert_eq!(
            build_adb_args(None, &["exec-out", "screencap", "-p"]),
            vec!["exec-out", "screencap", "-p"]
        );
        assert_eq!(
            build_adb_args(Some("emulator-5554"), &["exec-out", "screencap", "-p"]),
            vec!["-s", "emulator-5554", "exec-out", "screencap", "-p"]
        );
    }

    #[test]
    fn shell_single_quote_escapes_metacharacters_and_quotes() {
        assert_eq!(shell_single_quote("plain"), "'plain'");
        assert_eq!(shell_single_quote("it's"), "'it'\\''s'");
        assert_eq!(
            shell_single_quote("https://example.com/?a=1&b=$(id);rm"),
            "'https://example.com/?a=1&b=$(id);rm'"
        );
    }

    #[test]
    fn escape_android_input_text_encodes_spaces_and_shell_chars() {
        assert_eq!(escape_android_input_text(" "), "'%s'");
        assert_eq!(escape_android_input_text("hello world"), "'hello%sworld'");
        assert_eq!(escape_android_input_text("a;b&c$d"), "'a;b&c$d'");
        assert_eq!(escape_android_input_text("'"), "''\\'''");
    }

    #[test]
    fn build_input_shell_args_handles_pointer_tap_hold_and_scroll() {
        let mut cursor = Point { x: 0.0, y: 0.0 };

        // PointerMove updates cursor without invoking adb.
        let move_args = build_input_shell_args(
            &InputEvent::PointerMove {
                to: Point { x: 320.4, y: 640.6 },
            },
            &mut cursor,
        );
        assert!(move_args.is_none());
        assert_eq!(cursor, Point { x: 320.4, y: 640.6 });

        // Instant click -> input tap
        let tap_args = build_input_shell_args(
            &InputEvent::MouseClick {
                button: MouseButton::Left,
                hold_ms: 0,
            },
            &mut cursor,
        );
        assert_eq!(
            tap_args,
            Some(vec![
                "shell".to_owned(),
                "input".to_owned(),
                "tap".to_owned(),
                "320".to_owned(),
                "641".to_owned(),
            ])
        );

        // Long press (hold_ms > 0) -> input swipe at same coordinates
        let hold_args = build_input_shell_args(
            &InputEvent::MouseClick {
                button: MouseButton::Left,
                hold_ms: 120,
            },
            &mut cursor,
        );
        assert_eq!(
            hold_args,
            Some(vec![
                "shell".to_owned(),
                "input".to_owned(),
                "swipe".to_owned(),
                "320".to_owned(),
                "641".to_owned(),
                "320".to_owned(),
                "641".to_owned(),
                "120".to_owned(),
            ])
        );

        // Negative delta_y scrolls down by swiping upward from cursor (641 -> 441).
        let scroll_args = build_input_shell_args(
            &InputEvent::Scroll {
                delta_x: 0.0,
                delta_y: -200.0,
            },
            &mut cursor,
        );
        assert_eq!(
            scroll_args,
            Some(vec![
                "shell".to_owned(),
                "input".to_owned(),
                "swipe".to_owned(),
                "320".to_owned(),
                "641".to_owned(),
                "320".to_owned(),
                "441".to_owned(),
                "250".to_owned(),
            ])
        );
    }

    #[test]
    fn build_drag_args_picks_gesture_and_clamps_duration() {
        let from = Point { x: 100.4, y: 200.6 };
        let to = Point { x: 300.0, y: 50.0 };
        assert_eq!(
            build_drag_args(from, to, 850, false),
            vec!["shell", "input", "swipe", "100", "201", "300", "50", "850"]
        );
        assert_eq!(
            build_drag_args(from, to, 850, true),
            vec![
                "shell",
                "input",
                "draganddrop",
                "100",
                "201",
                "300",
                "50",
                "850"
            ]
        );
        assert_eq!(build_drag_args(from, to, 5, true)[7], "300");
        assert_eq!(build_drag_args(from, to, u64::MAX, false)[7], "10000");
    }

    #[test]
    fn parses_sdk_level_and_gates_drag_and_drop() {
        assert_eq!(parse_sdk_level("33\r\n"), Some(33));
        assert_eq!(parse_sdk_level(""), None);
        assert_eq!(parse_sdk_level("error: no devices"), None);
        assert!(supports_drag_and_drop(Some(26)));
        assert!(supports_drag_and_drop(Some(34)));
        assert!(!supports_drag_and_drop(Some(25)));
        assert!(!supports_drag_and_drop(None));
    }

    fn failing_adb(_: &[String]) -> Result<()> {
        Err(WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: "injected adb failure".to_owned(),
        })
    }

    #[test]
    fn failed_drag_release_is_reported_and_never_replayed() {
        let mut cursor = Point { x: 10.0, y: 20.0 };
        let mut gesture = DragGesture::Idle;
        let left = MouseButton::Left;
        let sent: std::cell::RefCell<Vec<Vec<String>>> = std::cell::RefCell::new(Vec::new());
        let record = |args: &[String]| {
            sent.borrow_mut().push(args.to_vec());
            Ok(())
        };
        let fail = |args: &[String]| {
            sent.borrow_mut().push(args.to_vec());
            failing_adb(args)
        };

        let down = InputEvent::MouseDown { button: left };
        let drag = InputEvent::PointerDrag {
            to: Point { x: 90.0, y: 40.0 },
            button: left,
        };
        let up = InputEvent::MouseUp { button: left };
        assert!(dispatch_input_with(&down, &mut cursor, &mut gesture, || Some(30), record).is_ok());
        assert!(dispatch_input_with(&drag, &mut cursor, &mut gesture, || Some(30), record).is_ok());
        assert!(sent.borrow().is_empty());

        // The gesture fails: the error surfaces after exactly one adb command.
        let failed = dispatch_input_with(&up, &mut cursor, &mut gesture, || Some(30), fail);
        assert!(failed.is_err());
        assert_eq!(sent.borrow().len(), 1);
        assert_eq!(
            sent.borrow()[0][..7],
            ["shell", "input", "draganddrop", "10", "20", "90", "40"]
        );

        // A retried release sends nothing and still reports the failure.
        let retried = dispatch_input_with(&up, &mut cursor, &mut gesture, || Some(30), record);
        assert!(retried.is_err());
        assert_eq!(sent.borrow().len(), 1);
        assert_eq!(gesture, DragGesture::Idle);

        // Old devices fall back to a swipe.
        assert!(dispatch_input_with(&down, &mut cursor, &mut gesture, || Some(25), record).is_ok());
        assert!(dispatch_input_with(&up, &mut cursor, &mut gesture, || Some(25), record).is_ok());
        assert_eq!(sent.borrow().len(), 2);
        assert_eq!(sent.borrow()[1][2], "swipe");
        assert_eq!(gesture, DragGesture::Idle);
    }

    #[test]
    fn press_drag_and_release_buffer_without_invoking_adb() {
        let mut cursor = Point { x: 10.0, y: 20.0 };
        let mut gesture = DragGesture::Idle;
        let left = MouseButton::Left;
        let no_sdk_probe = || -> Option<u32> { None };

        // A release with nothing pressed has nothing to send (`failing_adb` would error).
        let up = InputEvent::MouseUp { button: left };
        assert!(
            dispatch_input_with(&up, &mut cursor, &mut gesture, no_sdk_probe, failing_adb).is_ok()
        );

        let down = InputEvent::MouseDown { button: left };
        assert!(
            dispatch_input_with(&down, &mut cursor, &mut gesture, no_sdk_probe, failing_adb)
                .is_ok()
        );
        assert!(matches!(
            gesture,
            DragGesture::Pressed(PendingDrag {
                from: Point { x: 10.0, y: 20.0 },
                ..
            })
        ));

        let drag = InputEvent::PointerDrag {
            to: Point { x: 90.0, y: 40.0 },
            button: left,
        };
        assert!(
            dispatch_input_with(&drag, &mut cursor, &mut gesture, no_sdk_probe, failing_adb)
                .is_ok()
        );
        assert_eq!(cursor, Point { x: 90.0, y: 40.0 });
        assert!(matches!(gesture, DragGesture::Pressed(_)));
    }

    #[test]
    fn build_input_shell_args_handles_key_events() {
        let mut cursor = Point { x: 0.0, y: 0.0 };

        assert_eq!(
            build_input_shell_args(
                &InputEvent::KeyPress {
                    key: KeyCode::Enter,
                    modifiers: vec![],
                    hold_ms: 0,
                },
                &mut cursor,
            ),
            Some(vec![
                "shell".to_owned(),
                "input".to_owned(),
                "keyevent".to_owned(),
                "66".to_owned(),
            ])
        );
        assert_eq!(
            build_input_shell_args(
                &InputEvent::KeyPress {
                    key: KeyCode::Tab,
                    modifiers: vec![],
                    hold_ms: 0,
                },
                &mut cursor,
            ),
            Some(vec![
                "shell".to_owned(),
                "input".to_owned(),
                "keyevent".to_owned(),
                "61".to_owned(),
            ])
        );
        assert_eq!(
            build_input_shell_args(
                &InputEvent::KeyPress {
                    key: KeyCode::Escape,
                    modifiers: vec![],
                    hold_ms: 0,
                },
                &mut cursor,
            ),
            Some(vec![
                "shell".to_owned(),
                "input".to_owned(),
                "keyevent".to_owned(),
                "111".to_owned(),
            ])
        );
        assert_eq!(
            build_input_shell_args(
                &InputEvent::KeyPress {
                    key: KeyCode::Backspace,
                    modifiers: vec![],
                    hold_ms: 0,
                },
                &mut cursor,
            ),
            Some(vec![
                "shell".to_owned(),
                "input".to_owned(),
                "keyevent".to_owned(),
                "67".to_owned(),
            ])
        );
        assert_eq!(
            build_input_shell_args(
                &InputEvent::KeyPress {
                    key: KeyCode::Char(';'),
                    modifiers: vec![],
                    hold_ms: 0,
                },
                &mut cursor,
            ),
            Some(vec![
                "shell".to_owned(),
                "input".to_owned(),
                "text".to_owned(),
                "';'".to_owned(),
            ])
        );
    }

    #[test]
    fn validate_http_url_accepts_http_https_and_rejects_others() {
        assert!(validate_http_url("https://example.com/path?a=1&b=2").is_ok());
        assert!(validate_http_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_http_url("HTTPS://EXAMPLE.COM").is_ok());

        assert!(validate_http_url("").is_err());
        assert!(validate_http_url("javascript:alert(1)").is_err());
        assert!(validate_http_url("file:///etc/passwd").is_err());
        assert!(validate_http_url("https://example.com/has space").is_err());
        assert!(validate_http_url("https://").is_err());
    }

    #[test]
    fn validate_png_bytes_checks_magic_header() {
        let mut valid = PNG_MAGIC.to_vec();
        valid.extend_from_slice(&[0x00, 0x00, 0x00, 0x0D]);
        assert!(validate_png_bytes(&valid).is_ok());

        assert!(validate_png_bytes(&[]).is_err());
        assert!(validate_png_bytes(b"not a png").is_err());
    }

    // ----- transient vs fatal classification -----

    const IDLE_STATE: &str = "ERROR: could not get idle state.\n";
    const NULL_ROOT: &str = "ERROR: null root node returned by UiTestAutomationBridge.\n";
    const ALREADY_REGISTERED: &str = "java.lang.IllegalStateException: UiAutomationService \
        android.accessibilityservice.IAccessibilityServiceClient$Stub$Proxy@6a1f6e1 already registered!\n";
    const COMPLETE_DUMP: &str = "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\
        <hierarchy rotation=\"0\"><node index=\"0\" text=\"\" class=\"android.widget.FrameLayout\" \
        bounds=\"[0,0][1080,2400]\" /></hierarchy>UI hierchary dumped to: /dev/stdout\n";

    #[test]
    fn classifies_real_adb_failure_messages() {
        let fatal = [
            "error: device offline",
            "adb: device offline",
            "error: device unauthorized.\nThis adb server's $ADB_VENDOR_KEYS is not set\n\
             Try 'adb kill-server' if that seems wrong.\nOtherwise check for a confirmation dialog on your device.",
            "error: device 'emulator-5556' not found",
            "adb: device '127.0.0.1:5555' not found",
            "error: no devices/emulators found",
            "adb: more than one device/emulator",
            "error: insufficient permissions for device: user in plugdev group; are your udev rules wrong?",
            "* daemon not running; starting now at tcp:5037\nADB server didn't ACK\n* failed to start daemon\n\
             adb: cannot connect to daemon",
            "/system/bin/sh: uiautomator: inaccessible or not found",
        ];
        for text in fatal {
            assert_eq!(classify_adb_failure(text), FailureClass::Fatal, "{text}");
        }

        let transient = [
            IDLE_STATE,
            NULL_ROOT,
            ALREADY_REGISTERED,
            "error: closed",
            "error: protocol fault (couldn't read status): Connection reset by peer",
        ];
        for text in transient {
            assert_eq!(
                classify_adb_failure(text),
                FailureClass::Transient,
                "{text}"
            );
        }

        assert_eq!(classify_adb_failure("Killed"), FailureClass::Unrecognized);
        assert_eq!(classify_adb_failure(""), FailureClass::Unrecognized);
    }

    #[test]
    fn validate_dump_output_accepts_only_complete_hierarchies() {
        assert!(validate_dump_output("/dev/stdout", true, COMPLETE_DUMP, "").is_ok());
        assert!(
            validate_dump_output(
                "/dev/tty",
                true,
                "<?xml version='1.0' ?><hierarchy rotation=\"1\"/>",
                ""
            )
            .is_ok()
        );

        let truncated = COMPLETE_DUMP
            .get(..COMPLETE_DUMP.len() / 2)
            .unwrap_or_default();
        let transient_cases: [(bool, &str, &str); 6] = [
            (true, IDLE_STATE, ""),
            (false, "", NULL_ROOT),
            (true, truncated, ""),
            (true, "", ""),
            (true, "UI hierchary dumped to: /dev/stdout\n", ""),
            (false, "Killed\n", ""),
        ];
        for (success, stdout, stderr) in transient_cases {
            let result = validate_dump_output("/dev/stdout", success, stdout, stderr);
            assert!(
                matches!(&result, Err(WayboundError::Transient { .. })),
                "{stdout:?} {stderr:?} -> {result:?}"
            );
        }
        let truncated_reason = validate_dump_output("/dev/stdout", true, truncated, "");
        assert!(matches!(
            truncated_reason,
            Err(WayboundError::Transient { ref reason, .. }) if reason.contains("truncated")
        ));

        for stderr in [
            "error: device offline",
            "error: device 'emulator-5556' not found",
        ] {
            let result = validate_dump_output("/dev/stdout", false, "", stderr);
            assert!(
                matches!(&result, Err(WayboundError::BackendUnavailable { reason, .. }) if reason.contains(stderr)),
                "{result:?}"
            );
        }
    }

    #[test]
    fn am_start_error_detects_failures_that_exit_zero() {
        let missing_chrome = "Starting: Intent { act=android.intent.action.VIEW dat=https://example.com/... pkg=com.android.chrome }\n\
            Error: Activity not started, unable to resolve Intent { act=android.intent.action.VIEW dat=https://example.com/... flg=0x10000000 pkg=com.android.chrome }\n";
        assert!(
            am_start_error(missing_chrome, "")
                .is_some_and(|e| e.contains("unable to resolve Intent"))
        );

        let delivered = "Starting: Intent { act=android.intent.action.VIEW dat=https://example.com/... pkg=com.android.chrome }\n\
            Warning: Activity not started, intent has been delivered to currently running top-most instance.\n";
        assert_eq!(am_start_error(delivered, ""), None);
        assert_eq!(am_start_error("Starting: Intent { ... }\n", ""), None);
    }

    // ----- retry loop with an injected clock -----

    /// Clock that advances only when slept on, so tests are instant and deterministic.
    struct FakeClock {
        start: Instant,
        elapsed: std::cell::Cell<Duration>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                start: Instant::now(),
                elapsed: std::cell::Cell::new(Duration::ZERO),
            }
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            self.start + self.elapsed.get()
        }

        fn sleep(&self, duration: Duration) {
            self.elapsed.set(self.elapsed.get() + duration);
        }
    }

    fn transient(reason: &str) -> WayboundError {
        WayboundError::Transient {
            backend: BACKEND_NAME.to_owned(),
            reason: reason.to_owned(),
        }
    }

    #[test]
    fn poll_transient_succeeds_after_n_transient_failures() {
        let clock = FakeClock::new();
        let mut calls = 0;
        let result = poll_transient(
            &clock,
            Duration::from_secs(3),
            Duration::from_millis(250),
            || {
                calls += 1;
                if calls <= 4 {
                    Err(transient(IDLE_STATE))
                } else {
                    Ok("<hierarchy/>")
                }
            },
        );
        assert!(matches!(result, Ok("<hierarchy/>")));
        assert_eq!(calls, 5);
        assert_eq!(clock.elapsed.get(), Duration::from_secs(1));
    }

    #[test]
    fn poll_transient_times_out_carrying_the_last_error() {
        let clock = FakeClock::new();
        let mut calls = 0;
        let result: std::result::Result<(), PollError> = poll_transient(
            &clock,
            Duration::from_secs(1),
            Duration::from_millis(300),
            || {
                calls += 1;
                Err(transient(&format!("attempt {calls}: {NULL_ROOT}")))
            },
        );
        // Attempts at t=0, 300, 600, 900, then a final one at the 1000 ms deadline.
        assert_eq!(calls, 5);
        assert!(
            matches!(
                &result,
                Err(PollError::Exhausted { attempts: 5, last: WayboundError::Transient { reason, .. } })
                    if reason.starts_with("attempt 5:") && reason.contains("null root node")
            ),
            "{result:?}"
        );
        assert_eq!(clock.elapsed.get(), Duration::from_secs(1));
    }

    #[test]
    fn poll_transient_stops_at_the_first_fatal_error() {
        let clock = FakeClock::new();
        let mut calls = 0;
        let result: std::result::Result<(), PollError> = poll_transient(
            &clock,
            Duration::from_secs(30),
            Duration::from_millis(250),
            || {
                calls += 1;
                if calls == 1 {
                    return Err(transient(IDLE_STATE));
                }
                Err(WayboundError::BackendUnavailable {
                    backend: BACKEND_NAME.to_owned(),
                    reason: "error: device unauthorized.".to_owned(),
                })
            },
        );
        assert_eq!(calls, 2);
        assert!(matches!(
            result,
            Err(PollError::Fatal(WayboundError::BackendUnavailable { .. }))
        ));
    }

    // ----- modifier chords -----

    fn shell_input(rest: &[&str]) -> Vec<String> {
        ["shell", "input"]
            .iter()
            .chain(rest)
            .map(|s| (*s).to_owned())
            .collect()
    }

    #[test]
    fn keycombination_args_for_modifier_sets() {
        let api33 = ChordSupport::from_sdk(33);
        assert_eq!(api33, ChordSupport::KeyCombination);

        // Ctrl+A (select all)
        let ctrl_a = build_key_chord_args(&KeyCode::Char('a'), &[KeyModifier::Control], api33);
        assert_eq!(
            ctrl_a.ok(),
            Some(shell_input(&["keycombination", "113", "29"]))
        );

        // Shift+Tab
        let shift_tab = build_key_chord_args(&KeyCode::Tab, &[KeyModifier::Shift], api33);
        assert_eq!(
            shift_tab.ok(),
            Some(shell_input(&["keycombination", "59", "61"]))
        );

        // Ctrl+Shift+Tab, modifiers given out of order and duplicated
        let prev_tab = build_key_chord_args(
            &KeyCode::Tab,
            &[KeyModifier::Shift, KeyModifier::Control, KeyModifier::Shift],
            api33,
        );
        assert_eq!(
            prev_tab.ok(),
            Some(shell_input(&["keycombination", "113", "59", "61"]))
        );

        // Alt+ArrowLeft (Chrome back)
        let back = build_key_chord_args(&KeyCode::ArrowLeft, &[KeyModifier::Alt], api33);
        assert_eq!(
            back.ok(),
            Some(shell_input(&["keycombination", "57", "21"]))
        );

        // Ctrl+Alt+Shift+Meta+5
        let all = build_key_chord_args(
            &KeyCode::Char('5'),
            &[
                KeyModifier::Meta,
                KeyModifier::Alt,
                KeyModifier::Shift,
                KeyModifier::Control,
            ],
            ChordSupport::from_sdk(KEYCOMBINATION_MIN_SDK),
        );
        assert_eq!(
            all.ok(),
            Some(shell_input(&[
                "keycombination",
                "113",
                "57",
                "59",
                "117",
                "12"
            ]))
        );

        // Ctrl+T: an upper-case letter implies Shift
        let ctrl_shift_t =
            build_key_chord_args(&KeyCode::Char('T'), &[KeyModifier::Control], api33);
        assert_eq!(
            ctrl_shift_t.ok(),
            Some(shell_input(&["keycombination", "113", "59", "48"]))
        );

        // No modifiers: same as a plain key press.
        let plain = build_key_chord_args(&KeyCode::Enter, &[], api33);
        assert_eq!(plain.ok(), Some(shell_input(&["keyevent", "66"])));
    }

    #[test]
    fn chords_without_working_keycombination_are_unsupported_not_bare_keys() {
        // API 31/32 (Android 12/12L) have `input keycombination` but send it with metaState
        // 0, so they must take the same path as devices without it.
        assert_eq!(KEYCOMBINATION_MIN_SDK, 33);
        for sdk in [30, 31, 32] {
            let support = ChordSupport::from_sdk(sdk);
            assert_eq!(support, ChordSupport::ShiftLettersOnly { sdk });

            for (key, modifiers) in [
                (KeyCode::Char('a'), vec![KeyModifier::Control]),
                (KeyCode::Tab, vec![KeyModifier::Shift]),
                (KeyCode::ArrowLeft, vec![KeyModifier::Alt]),
                (KeyCode::Char('1'), vec![KeyModifier::Shift]),
            ] {
                let result = build_key_chord_args(&key, &modifiers, support);
                let api = format!("API {sdk}");
                assert!(
                    matches!(&result, Err(WayboundError::UnsupportedInput { reason, .. })
                        if reason.contains(&api) && reason.contains("Android 13")),
                    "{key:?} {modifiers:?} -> {result:?}"
                );
            }

            // Shift on a letter is still expressible: type the upper-case letter.
            let shift_a = build_key_chord_args(&KeyCode::Char('a'), &[KeyModifier::Shift], support);
            assert_eq!(shift_a.ok(), Some(shell_input(&["text", "'A'"])));
        }

        // With keycombination available, a character without an Android keycode is still
        // unsupported.
        let ctrl_bang = build_key_chord_args(
            &KeyCode::Char('!'),
            &[KeyModifier::Control],
            ChordSupport::KeyCombination,
        );
        assert!(matches!(
            ctrl_bang,
            Err(WayboundError::UnsupportedInput { .. })
        ));
    }

    #[test]
    fn build_input_shell_args_never_sends_a_bare_key_for_a_chord() {
        let mut cursor = Point { x: 0.0, y: 0.0 };
        let chord = InputEvent::KeyPress {
            key: KeyCode::Char('a'),
            modifiers: vec![KeyModifier::Control],
            hold_ms: 0,
        };
        assert_eq!(build_input_shell_args(&chord, &mut cursor), None);

        let right_click = InputEvent::MouseClick {
            button: MouseButton::Right,
            hold_ms: 0,
        };
        assert_eq!(build_input_shell_args(&right_click, &mut cursor), None);
        assert!(unsupported_input_reason(&right_click).is_some_and(|r| r.contains("Right")));
        assert!(
            unsupported_input_reason(&InputEvent::MouseClick {
                button: MouseButton::Left,
                hold_ms: 0
            })
            .is_none()
        );
    }

    #[test]
    fn dispatch_rejects_unsupported_input_before_running_adb() {
        // `adb` is never spawned: the cache is pre-filled and both events are rejected first.
        let cache = ChordSupportCache::new();
        assert!(
            cache
                .get_or_probe(|| Ok(ChordSupport::from_sdk(30)))
                .is_ok()
        );
        let mut cursor = Point { x: 0.0, y: 0.0 };

        let chord = InputEvent::KeyPress {
            key: KeyCode::Char('a'),
            modifiers: vec![KeyModifier::Control],
            hold_ms: 0,
        };
        let mut gesture = DragGesture::Idle;
        assert!(matches!(
            dispatch_input(None, &chord, &mut cursor, &cache, &mut gesture, || None),
            Err(WayboundError::UnsupportedInput { .. })
        ));

        let middle = InputEvent::MouseClick {
            button: MouseButton::Middle,
            hold_ms: 0,
        };
        assert!(matches!(
            dispatch_input(None, &middle, &mut cursor, &cache, &mut gesture, || None),
            Err(WayboundError::UnsupportedInput { .. })
        ));

        let key_down = InputEvent::KeyDown {
            key: KeyCode::Char('a'),
            modifiers: Vec::new(),
        };
        let key_up = InputEvent::KeyUp {
            key: KeyCode::Char('a'),
            modifiers: Vec::new(),
        };
        assert!(matches!(
            dispatch_input(None, &key_down, &mut cursor, &cache, &mut gesture, || None),
            Err(WayboundError::UnsupportedInput { .. })
        ));
        assert!(matches!(
            dispatch_input(None, &key_up, &mut cursor, &cache, &mut gesture, || None),
            Err(WayboundError::UnsupportedInput { .. })
        ));
    }

    #[test]
    fn chord_support_is_probed_once_and_failures_are_not_cached() {
        assert_eq!(parse_sdk_level("33\r\n"), Some(33));
        assert_eq!(parse_sdk_level("30\n"), Some(30));
        assert_eq!(parse_sdk_level(""), None);
        assert_eq!(parse_sdk_level("error: device offline"), None);

        let cache = ChordSupportCache::new();
        let mut probes = 0;

        let failed = cache.get_or_probe(|| {
            probes += 1;
            Err(transient("getprop timed out"))
        });
        assert!(failed.is_err());

        for _ in 0..3 {
            let support = cache.get_or_probe(|| {
                probes += 1;
                Ok(ChordSupport::from_sdk(34))
            });
            assert_eq!(support.ok(), Some(ChordSupport::KeyCombination));
        }
        assert_eq!(probes, 2);
    }

    // ----- review follow-ups: truncated page text, fallback, budgets, probe -----

    #[test]
    fn truncated_dump_with_alarming_page_text_stays_transient() {
        let page_text = [
            "Unauthorized",
            "device offline",
            "more than one device/emulator",
            "error: device 'x' not found",
        ];
        for text in page_text {
            let partial = format!(
                "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?><hierarchy rotation=\"0\">\
                 <node index=\"0\" text=\"{text}\" class=\"android.widget.TextView\" bounds=\"[0,0][10"
            );
            let result = validate_dump_output("/dev/stdout", true, &partial, "");
            assert!(
                matches!(&result, Err(WayboundError::Transient { reason, .. }) if reason.contains("truncated")),
                "{text}: {result:?}"
            );
            // Cut even before `<hierarchy`: still a truncated document, not adb output.
            let header_only = format!("<?xml version='1.0' ?><!-- {text} -->");
            assert!(matches!(
                validate_dump_output("/dev/stdout", true, &header_only, ""),
                Err(WayboundError::Transient { .. })
            ));
            assert!(!should_try_tty_fallback(&partial, ""));
        }
    }

    #[test]
    fn tty_fallback_only_for_empty_or_unrecognised_output() {
        assert!(should_try_tty_fallback("", ""));
        assert!(should_try_tty_fallback(
            "UI hierchary dumped to: /dev/stdout\n",
            ""
        ));
        assert!(should_try_tty_fallback("Killed\n", ""));
        // A known transient failure would just wait for idle again on /dev/tty.
        assert!(!should_try_tty_fallback(IDLE_STATE, ""));
        assert!(!should_try_tty_fallback("", NULL_ROOT));
        // Fatal failures cannot heal.
        assert!(!should_try_tty_fallback("", "error: device offline"));
    }

    #[test]
    fn snapshot_budget_is_capped_by_the_callers_remaining_wait() {
        assert_eq!(snapshot_retry_budget(None), SNAPSHOT_RETRY_BUDGET);
        assert_eq!(
            snapshot_retry_budget(Some(Duration::from_secs(60))),
            SNAPSHOT_RETRY_BUDGET
        );
        assert_eq!(
            snapshot_retry_budget(Some(Duration::from_millis(1_500))),
            Duration::from_millis(1_500)
        );
        assert_eq!(snapshot_retry_budget(Some(Duration::ZERO)), Duration::ZERO);
    }

    #[test]
    fn retry_dump_overshoots_the_callers_deadline_by_at_most_one_attempt() {
        // Each dump attempt costs 1 s of (fake) time, like a slow uiautomator dump.
        let attempt_cost = Duration::from_secs(1);
        for remaining in [
            Duration::ZERO,
            Duration::from_millis(1_500),
            Duration::from_secs(60),
        ] {
            let clock = FakeClock::new();
            let mut calls = 0;
            let result = retry_dump(&clock, snapshot_retry_budget(Some(remaining)), || {
                calls += 1;
                clock.sleep(attempt_cost);
                Err(transient(IDLE_STATE))
            });
            assert!(
                matches!(&result, Err(WayboundError::Transient { reason, .. })
                    if reason.contains(&format!("after {calls} attempts")) && reason.contains("idle state")),
                "{result:?}"
            );
            let cap = remaining.min(SNAPSHOT_RETRY_BUDGET);
            assert!(
                clock.elapsed.get() <= cap + attempt_cost,
                "{remaining:?}: {:?}",
                clock.elapsed.get()
            );
            assert!(calls >= 1);
        }

        // No caller deadline: bounded by SNAPSHOT_RETRY_BUDGET (3 s) plus one attempt.
        let clock = FakeClock::new();
        let result = retry_dump(&clock, snapshot_retry_budget(None), || {
            clock.sleep(attempt_cost);
            Err(transient(IDLE_STATE))
        });
        assert!(result.is_err());
        assert!(clock.elapsed.get() <= SNAPSHOT_RETRY_BUDGET + attempt_cost);

        // Success after two transient failures.
        let clock = FakeClock::new();
        let mut calls = 0;
        let ok = retry_dump(&clock, SNAPSHOT_RETRY_BUDGET, || {
            calls += 1;
            if calls < 3 {
                Err(transient(NULL_ROOT))
            } else {
                Ok(COMPLETE_DUMP.to_owned())
            }
        });
        assert_eq!(ok.ok().as_deref(), Some(COMPLETE_DUMP));
    }

    #[test]
    fn persistent_already_registered_becomes_a_clear_fatal_error() {
        let clock = FakeClock::new();
        let mut calls = 0;
        let result = retry_dump(&clock, Duration::from_secs(60), || {
            calls += 1;
            Err(transient(ALREADY_REGISTERED))
        });
        assert_eq!(calls, MAX_ALREADY_REGISTERED);
        assert!(
            matches!(&result, Err(WayboundError::BackendUnavailable { reason, .. })
                if reason.contains("another UiAutomation client")),
            "{result:?}"
        );

        // Interleaved with other transient failures the counter resets, so it keeps retrying.
        let clock = FakeClock::new();
        let mut calls = 0;
        let ok = retry_dump(&clock, Duration::from_secs(60), || {
            calls += 1;
            match calls {
                1 | 2 | 4 | 5 => Err(transient(ALREADY_REGISTERED)),
                3 => Err(transient(IDLE_STATE)),
                _ => Ok(COMPLETE_DUMP.to_owned()),
            }
        });
        assert!(ok.is_ok(), "{ok:?}");
        assert_eq!(calls, 6);
    }

    #[test]
    fn probe_output_failures_are_transient_unless_fatal() {
        assert_eq!(
            parse_probe_output(true, "33\n", "").ok(),
            Some(ChordSupport::KeyCombination)
        );
        assert_eq!(
            parse_probe_output(true, "32\n", "").ok(),
            Some(ChordSupport::ShiftLettersOnly { sdk: 32 })
        );
        assert!(matches!(
            parse_probe_output(true, "", ""),
            Err(WayboundError::Transient { .. })
        ));
        assert!(matches!(
            parse_probe_output(false, "", "error: closed"),
            Err(WayboundError::Transient { .. })
        ));
        assert!(matches!(
            parse_probe_output(false, "", "error: device offline"),
            Err(WayboundError::BackendUnavailable { .. })
        ));
    }
}

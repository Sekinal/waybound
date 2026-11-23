//! In-process COM `IUIAutomation` backend (Windows only).
//!
//! # Threading and timeouts
//!
//! All COM objects live on one dedicated worker thread that joins the multithreaded apartment
//! (`CoInitializeEx(COINIT_MULTITHREADED)`). UIA client objects need no message pump in the MTA,
//! and keeping them on one thread means no interface pointer ever crosses threads and the
//! process only ever has one `CUIAutomation` object. Callers send a [`Job`] over a channel and
//! wait at most [`UIA_QUERY_TIMEOUT_MS`] for the reply, so the daemon never blocks longer than
//! the PowerShell backend did.
//!
//! Three layers bound a hung provider:
//! 1. `IUIAutomation2::SetConnectionTimeout` / `SetTransactionTimeout` make each cross-process
//!    call fail with `UIA_E_TIMEOUT` instead of blocking. The transaction timeout is re-armed
//!    before each call to `min(5 s, time left - 300 ms)`.
//! 2. Every job carries the caller's deadline. The worker skips jobs whose caller has already
//!    given up, and the level-by-level fallback walk stops at the deadline.
//! 3. The caller's channel wait. When it expires the caller returns
//!    [`WayboundError::Timeout`] (error code `timeout`, as before) and abandons the worker: the
//!    next request starts a fresh one, and the abandoned thread exits once its current call
//!    returns (it skips any queued job whose deadline has passed). At most
//!    [`MAX_ABANDONED_WORKERS`] abandoned workers may be outstanding.
//!
//! Starting a worker never holds the slot lock: the slot goes to `Starting`, and concurrent
//! callers wait on a condition variable bounded by their own deadline.
//!
//! # Snapshot cost
//!
//! With a target pid, a snapshot is three cross-process calls regardless of tree size:
//! `FindFirst` (top-level window of the pid), one `FindAllBuildCache` for the window's
//! `Edit`/`Document` descendants (address bar and web root), and one `BuildUpdatedCache` with
//! `TreeScope_Subtree` over the control view of the web root. Without a pid, the first call is
//! a `FindAllBuildCache` over top-level windows plus one `OpenProcess` /
//! `QueryFullProcessImageNameW` per top-level window. Everything else reads the local cache.
//! `current_url` / `viewport_bounds` stop after the second call.
//!
//! UIA cannot cap a subtree cache request, so `max_nodes` is applied while walking the cache.
//! If the subtree call fails for any reason other than a stale element (a page too large for
//! the transaction timeout, or `E_FAIL` mid-navigation), the snapshot falls back to a
//! level-by-level walk (`TreeScope_Element | TreeScope_Children`, one call per visited node,
//! at most `max_nodes` calls) that stops at the caller's deadline and reports `truncated`,
//! like the PowerShell walker did. It is not started with less than a second left, and it
//! does not fetch children of nodes whose children could no longer be queued.
//! `WAYBOUND_WINDOWS_UIA_FORCE_LEVEL_WALK=1` (test-only) forces it, so CI exercises it.
//!
//! # Walk root and page transitions
//!
//! The walk root is chosen like the PowerShell walker's: the control-view `Document` with the
//! largest area, else the browser window. Walking the window is only right for a window that
//! has no web document at all, though: right after launch, and after a new tab, a cross-site
//! navigation or a reload, Chrome's new `Document` exists in the raw view before it joins
//! the control view, and the window walk would return the browser's own UI (tabs, omnibox,
//! caption buttons). So when the control view has no `Document`, one raw-view search decides:
//! with any raw-view `Document` the snapshot is `transient` ("web document not in the control
//! view yet"); with none, the window is walked as before. A failed Edit/Document search is
//! `transient` (or `timeout`), never "no document". Callers re-send `transient` queries for up
//! to 2 s from their own thread (see [`run_job`]), so the worker is never parked.

use std::fmt::Write as _;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use waybound_core::{Result, WayboundError};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::System::Ole::{
    SafeArrayGetDim, SafeArrayGetElement, SafeArrayGetElemsize, SafeArrayGetLBound,
    SafeArrayGetUBound,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::Win32::System::Variant::{VARIANT, VT_ARRAY, VT_BOOL, VT_BSTR, VT_I4};
use windows::Win32::UI::Accessibility::{
    AutomationElementMode_None, CUIAutomation, CUIAutomation8, IUIAutomation, IUIAutomation2,
    IUIAutomationCacheRequest, IUIAutomationCondition, IUIAutomationElement,
    IUIAutomationElementArray, TreeScope, TreeScope_Children, TreeScope_Descendants,
    TreeScope_Element, TreeScope_Subtree, UIA_BoundingRectanglePropertyId,
    UIA_ControlTypePropertyId, UIA_DocumentControlTypeId, UIA_EditControlTypeId,
    UIA_ExpandCollapseExpandCollapseStatePropertyId, UIA_HasKeyboardFocusPropertyId,
    UIA_IsControlElementPropertyId, UIA_IsEnabledPropertyId,
    UIA_IsExpandCollapsePatternAvailablePropertyId, UIA_IsOffscreenPropertyId,
    UIA_IsSelectionItemPatternAvailablePropertyId, UIA_IsTogglePatternAvailablePropertyId,
    UIA_IsValuePatternAvailablePropertyId, UIA_LocalizedControlTypePropertyId, UIA_NamePropertyId,
    UIA_PROPERTY_ID, UIA_ProcessIdPropertyId, UIA_RuntimeIdPropertyId,
    UIA_SelectionItemIsSelectedPropertyId, UIA_ToggleToggleStatePropertyId,
    UIA_ValueValuePropertyId, UIA_WindowControlTypeId,
};
use windows::core::{Interface, Owned, PWSTR};

use crate::uia::{RawBounds, RawUiaNode, RawUiaSnapshot, UIA_QUERY_TIMEOUT_MS};
use crate::uia_model::{
    self, HresultClass, Visit, WindowCandidate, bfs_limited, control_type,
    control_type_programmatic_name, is_address_bar_candidate, pick_browser_window,
    probes_expand_state, probes_selection_state, probes_toggle_state, process_name_from_image_path,
    rect_to_xywh, runtime_id_to_string, select_web_root, worker_life,
};

/// UIA connection timeout: how long UIA waits for a provider to accept a call.
const UIA_CONNECTION_TIMEOUT_MS: u32 = 2_000;
/// UIA transaction timeout: how long one cross-process call may run. Kept well below
/// [`UIA_QUERY_TIMEOUT_MS`] so a too-large subtree call still leaves time for the bounded
/// level-by-level fallback before the caller gives up.
const UIA_TRANSACTION_TIMEOUT_MS: u32 = 5_000;
/// How many abandoned (hung) workers may exist before requests fail fast.
const MAX_ABANDONED_WORKERS: usize = 4;
/// Attempts at creating the automation object, conditions and cache requests on a new worker.
const SESSION_INIT_ATTEMPTS: u32 = 3;
/// How long a caller re-sends a query that came back `transient` (page between documents,
/// stale element), and the pause between attempts. The worker stays free in between.
const TRANSIENT_RETRY_BUDGET: Duration = Duration::from_secs(2);
const TRANSIENT_RETRY_PAUSE: Duration = Duration::from_millis(150);
/// Kept back from the deadline when arming the per-call transaction timeout.
const TRANSACTION_MARGIN: Duration = Duration::from_millis(300);
/// The level-by-level walk is not started with less time than this left.
const MIN_LEVEL_WALK: Duration = Duration::from_secs(1);
/// Test-only switch that forces the level-by-level walk (see `UiaSession::force_level_walk`).
pub const FORCE_LEVEL_WALK_ENV: &str = "WAYBOUND_WINDOWS_UIA_FORCE_LEVEL_WALK";
/// Time kept back from the caller's deadline when walking level by level.
const WALK_DEADLINE_MARGIN: Duration = Duration::from_millis(500);

/// Outcome of a native query.
pub enum NativeOutcome {
    /// The native backend answered (successfully or with a mapped error).
    Done(Result<RawUiaSnapshot>),
    /// COM or `CUIAutomation` could not be initialized; the reason includes the `HRESULT`.
    Unavailable(String),
}

/// What a job asks the worker for.
#[derive(Debug, Clone, Copy)]
enum JobKind {
    /// Full snapshot capped at `limit` nodes.
    Snapshot { pid: Option<i32>, limit: usize },
    /// Address-bar URL and viewport only (no node walk).
    PageInfo { pid: Option<i32> },
    /// The desktop root element, read through the level request (tests only).
    #[cfg(test)]
    DesktopProbe,
}

struct Job {
    kind: JobKind,
    deadline: Instant,
    reply: mpsc::SyncSender<Result<RawUiaSnapshot>>,
}

#[derive(Clone)]
struct WorkerHandle {
    generation: u64,
    tx: mpsc::Sender<Job>,
    life: Arc<AtomicU8>,
}

enum SlotState {
    Empty,
    Starting,
    Ready(WorkerHandle),
}

struct Slot {
    state: Mutex<SlotState>,
    changed: Condvar,
}

static SLOT: Slot = Slot {
    state: Mutex::new(SlotState::Empty),
    changed: Condvar::new(),
};
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
static ABANDONED_WORKERS: AtomicUsize = AtomicUsize::new(0);
/// Set once COM initialization has failed on every attempt; later queries report
/// [`NativeOutcome::Unavailable`] without starting another worker.
static INIT_FAILURE: Mutex<Option<String>> = Mutex::new(None);
/// Set after the first successful native snapshot has been logged at `info`.
static FIRST_SNAPSHOT_LOGGED: AtomicBool = AtomicBool::new(false);

fn lock_slot() -> MutexGuard<'static, SlotState> {
    SLOT.state.lock().unwrap_or_else(PoisonError::into_inner)
}

fn init_failure() -> Option<String> {
    INIT_FAILURE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

fn timeout_error(context: &str) -> WayboundError {
    WayboundError::Timeout {
        timeout_ms: UIA_QUERY_TIMEOUT_MS,
        context: context.to_owned(),
    }
}

/// Runs one snapshot capped at `limit` nodes on the COM worker.
pub fn query(pid: Option<i32>, limit: usize) -> NativeOutcome {
    run_job(JobKind::Snapshot { pid, limit })
}

/// Reads only the address-bar URL and the viewport (no node walk) on the COM worker.
pub fn query_page_info(pid: Option<i32>) -> NativeOutcome {
    run_job(JobKind::PageInfo { pid })
}

/// Runs `kind` on the worker, re-sending it while it comes back `transient` (page between
/// documents, stale element) for up to [`TRANSIENT_RETRY_BUDGET`], never past the deadline.
/// The pauses happen here, so the worker serves other callers meanwhile.
fn run_job(kind: JobKind) -> NativeOutcome {
    let started = Instant::now();
    let deadline = started + Duration::from_millis(UIA_QUERY_TIMEOUT_MS);
    let retry_until = (started + TRANSIENT_RETRY_BUDGET).min(
        deadline
            .checked_sub(WALK_DEADLINE_MARGIN)
            .unwrap_or(deadline),
    );
    let mut attempts = 1u32;
    loop {
        let outcome = run_once(kind, deadline);
        let transient = matches!(
            &outcome,
            NativeOutcome::Done(Err(WayboundError::Transient { .. }))
        );
        if !transient || Instant::now() + TRANSIENT_RETRY_PAUSE >= retry_until {
            if attempts > 1 {
                tracing::debug!(
                    ?kind,
                    attempts,
                    transient,
                    "Windows UIAutomation query re-sent"
                );
            }
            return outcome;
        }
        attempts += 1;
        std::thread::sleep(TRANSIENT_RETRY_PAUSE);
    }
}

fn run_once(kind: JobKind, deadline: Instant) -> NativeOutcome {
    let worker = match acquire_worker(deadline) {
        Ok(worker) => worker,
        Err(WorkerStart::Unavailable(reason)) => return NativeOutcome::Unavailable(reason),
        Err(WorkerStart::Failed(err)) => return NativeOutcome::Done(Err(err)),
    };

    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    let job = Job {
        kind,
        deadline,
        reply: reply_tx,
    };
    if worker.tx.send(job).is_err() {
        forget_worker(&worker, false);
        return NativeOutcome::Done(Err(WayboundError::BackendUnavailable {
            backend: "windows".to_owned(),
            reason: "Windows UIAutomation (native COM) worker thread exited".to_owned(),
        }));
    }

    match reply_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(result) => NativeOutcome::Done(result),
        Err(RecvTimeoutError::Timeout) => {
            tracing::warn!(
                generation = worker.generation,
                timeout_ms = UIA_QUERY_TIMEOUT_MS,
                "Windows UIAutomation (native COM) query timed out; abandoning worker thread"
            );
            forget_worker(&worker, true);
            NativeOutcome::Done(Err(timeout_error(
                "Windows UIAutomation (native COM) query",
            )))
        }
        Err(RecvTimeoutError::Disconnected) => {
            forget_worker(&worker, false);
            NativeOutcome::Done(Err(WayboundError::BackendUnavailable {
                backend: "windows".to_owned(),
                reason: "Windows UIAutomation (native COM) worker dropped the request".to_owned(),
            }))
        }
    }
}

enum WorkerStart {
    Unavailable(String),
    Failed(WayboundError),
}

/// Returns the live worker, starting one if needed. Never holds the slot lock while a worker
/// initializes; callers that find one starting wait (bounded by `deadline`) for the outcome.
fn acquire_worker(deadline: Instant) -> std::result::Result<WorkerHandle, WorkerStart> {
    let mut state = lock_slot();
    loop {
        if let Some(reason) = init_failure() {
            return Err(WorkerStart::Unavailable(reason));
        }
        match &*state {
            SlotState::Ready(worker) => return Ok(worker.clone()),
            SlotState::Starting => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(WorkerStart::Failed(timeout_error(
                        "Windows UIAutomation (native COM) waiting for the worker to start",
                    )));
                }
                state = SLOT
                    .changed
                    .wait_timeout(state, remaining)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
            SlotState::Empty => break,
        }
    }
    if Instant::now() >= deadline {
        return Err(WorkerStart::Failed(timeout_error(
            "Windows UIAutomation (native COM) query",
        )));
    }
    if ABANDONED_WORKERS.load(Ordering::SeqCst) >= MAX_ABANDONED_WORKERS {
        return Err(WorkerStart::Failed(timeout_error(
            "Windows UIAutomation (native COM): earlier queries are still hung in the provider",
        )));
    }
    *state = SlotState::Starting;
    drop(state);

    let started = start_worker(deadline);

    let mut state = lock_slot();
    *state = started
        .as_ref()
        .map_or(SlotState::Empty, |worker| SlotState::Ready(worker.clone()));
    drop(state);
    SLOT.changed.notify_all();
    started
}

fn start_worker(deadline: Instant) -> std::result::Result<WorkerHandle, WorkerStart> {
    let generation = NEXT_GENERATION.fetch_add(1, Ordering::SeqCst);
    let life = Arc::new(AtomicU8::new(worker_life::LIVE));
    let (tx, rx) = mpsc::channel::<Job>();
    let (init_tx, init_rx) = mpsc::sync_channel::<std::result::Result<&'static str, String>>(1);
    let worker_life_flag = Arc::clone(&life);
    let spawned = std::thread::Builder::new()
        .name(format!("waybound-uia-{generation}"))
        .spawn(move || worker_main(&rx, &init_tx, &worker_life_flag));
    if let Err(err) = spawned {
        return Err(WorkerStart::Failed(WayboundError::Io(err)));
    }

    match init_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(Ok(flavor)) => {
            tracing::info!(
                backend = "native-com",
                automation = flavor,
                generation,
                "Windows UIAutomation backend ready (in-process COM, MTA worker thread)"
            );
            Ok(WorkerHandle {
                generation,
                tx,
                life,
            })
        }
        Ok(Err(reason)) => {
            tracing::warn!(%reason, "Windows UIAutomation COM initialization failed");
            *INIT_FAILURE.lock().unwrap_or_else(PoisonError::into_inner) = Some(reason.clone());
            Err(WorkerStart::Unavailable(reason))
        }
        Err(RecvTimeoutError::Timeout) => {
            // Stuck in CoCreateInstance; it exits once it notices `tx` is gone.
            let _ = worker_life::abandon(&life, &ABANDONED_WORKERS);
            Err(WorkerStart::Failed(timeout_error(
                "Windows UIAutomation (native COM) initialization",
            )))
        }
        Err(RecvTimeoutError::Disconnected) => {
            Err(WorkerStart::Failed(WayboundError::BackendUnavailable {
                backend: "windows".to_owned(),
                reason: "Windows UIAutomation (native COM) worker thread exited during \
                         initialization"
                    .to_owned(),
            }))
        }
    }
}

/// Drops `worker` from the slot so the next request starts a fresh one. With `hung`, the
/// worker is counted as abandoned until its thread exits.
fn forget_worker(worker: &WorkerHandle, hung: bool) {
    if hung {
        let _ = worker_life::abandon(&worker.life, &ABANDONED_WORKERS);
    }
    let mut state = lock_slot();
    if matches!(&*state, SlotState::Ready(current) if current.generation == worker.generation) {
        *state = SlotState::Empty;
        drop(state);
        SLOT.changed.notify_all();
    }
}

/// Records the worker thread's exit on every return path of [`worker_main`].
struct ExitGuard<'a>(&'a AtomicU8);

impl Drop for ExitGuard<'_> {
    fn drop(&mut self) {
        worker_life::exited(self.0, &ABANDONED_WORKERS);
    }
}

fn worker_main(
    rx: &mpsc::Receiver<Job>,
    init_tx: &mpsc::SyncSender<std::result::Result<&'static str, String>>,
    life: &AtomicU8,
) {
    let _exit = ExitGuard(life);
    // Declared before every COM object, so it is dropped after them: all of them must be
    // released before `CoUninitialize` runs.
    let _apartment = match ComApartment::init_mta() {
        Ok(apartment) => apartment,
        Err(err) => {
            let _ = init_tx.send(Err(format!(
                "CoInitializeEx(COINIT_MULTITHREADED) failed: {}",
                describe(&err)
            )));
            return;
        }
    };
    let session = match UiaSession::new_with_retry() {
        Ok(session) => session,
        Err(reason) => {
            let _ = init_tx.send(Err(reason));
            return;
        }
    };
    if init_tx.send(Ok(session.flavor)).is_err() {
        return;
    }

    while let Ok(job) = rx.recv() {
        if Instant::now() >= job.deadline {
            // Its caller already timed out and returned; nobody reads the reply.
            continue;
        }
        let started = Instant::now();
        let result = session.run(job.kind, job.deadline);
        log_result(job.kind, &result, started);
        // The caller may have timed out meanwhile; that is fine.
        let _ = job.reply.send(result);
    }
}

fn log_result(kind: JobKind, result: &Result<RawUiaSnapshot>, started: Instant) {
    let elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    match result {
        Ok(raw)
            if matches!(kind, JobKind::Snapshot { .. })
                && !FIRST_SNAPSHOT_LOGGED.swap(true, Ordering::Relaxed) =>
        {
            tracing::info!(
                backend = "native-com",
                ?kind,
                nodes = raw.nodes.len(),
                truncated = raw.truncated,
                elapsed_us,
                "first Windows UIAutomation snapshot"
            );
        }
        Ok(raw) => tracing::debug!(
            backend = "native-com",
            ?kind,
            nodes = raw.nodes.len(),
            truncated = raw.truncated,
            elapsed_us,
            "Windows UIAutomation query"
        ),
        Err(err) => tracing::debug!(
            backend = "native-com",
            ?kind,
            error = %err,
            elapsed_us,
            "Windows UIAutomation query failed"
        ),
    }
}

/// Formats a COM error as `HRESULT 0x........ (message)`.
fn describe(err: &windows::core::Error) -> String {
    format!(
        "HRESULT 0x{:08X} ({})",
        err.code().0.cast_unsigned(),
        err.message().trim()
    )
}

/// `true` when a COM call returned success with a null interface pointer, which
/// `windows-rs` reports as an error whose code is `S_OK` (for example `FindFirst` with no match).
const fn is_null_result(err: &windows::core::Error) -> bool {
    err.code().0 == 0
}

const fn hresult(err: &windows::core::Error) -> u32 {
    err.code().0.cast_unsigned()
}

/// A failed COM call together with the operation it belonged to.
struct CallError {
    err: windows::core::Error,
    operation: &'static str,
    kind: CallKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CallKind {
    /// Classified by `classify_hresult`.
    Plain,
    /// Read the web content tree, where `E_FAIL` means a document mid-navigation.
    Tree,
    /// The Edit/Document search: any failure is transient (or a timeout).
    Search,
}

impl CallError {
    const fn new(err: windows::core::Error, operation: &'static str) -> Self {
        Self {
            err,
            operation,
            kind: CallKind::Plain,
        }
    }

    const fn tree(err: windows::core::Error, operation: &'static str) -> Self {
        Self {
            err,
            operation,
            kind: CallKind::Tree,
        }
    }

    const fn search(err: windows::core::Error, operation: &'static str) -> Self {
        Self {
            err,
            operation,
            kind: CallKind::Search,
        }
    }

    const fn class(&self) -> HresultClass {
        let code = hresult(&self.err);
        match self.kind {
            CallKind::Plain => uia_model::classify_hresult(code),
            CallKind::Tree => uia_model::classify_tree_hresult(code),
            CallKind::Search => uia_model::classify_search_hresult(code),
        }
    }

    fn into_waybound(self) -> WayboundError {
        uia_model::uia_error(
            self.class(),
            hresult(&self.err),
            self.operation,
            &self.err.message(),
            UIA_QUERY_TIMEOUT_MS,
        )
    }
}

/// Membership of the current thread in the COM multithreaded apartment. Not `Send`: the
/// matching `CoUninitialize` must run on the thread that called `CoInitializeEx`.
struct ComApartment {
    _not_send: PhantomData<*const ()>,
}

impl ComApartment {
    fn init_mta() -> windows::core::Result<Self> {
        // SAFETY: `CoInitializeEx` has no pointer arguments besides the reserved `None`; it only
        // changes this thread's COM state, which `Drop` undoes on the same thread.
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.ok()?;
        Ok(Self {
            _not_send: PhantomData,
        })
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        // SAFETY: balances the successful `CoInitializeEx` in `init_mta` (S_OK or S_FALSE both
        // require it), on the same thread because `ComApartment` is not `Send`.
        unsafe { CoUninitialize() };
    }
}

/// A caller-owned `VARIANT` (from `GetCachedPropertyValue`).
///
/// `windows::Win32::System::Variant::VARIANT` already implements `Drop` via `VariantClear`, so
/// wrapping it without a second `Drop` impl releases its payload exactly once.
struct OwnedVariant(VARIANT);

impl OwnedVariant {
    fn from_i32(value: i32) -> Self {
        Self(VARIANT::from(value))
    }

    fn vt(&self) -> u16 {
        self.0.vt().0
    }

    fn as_i32(&self) -> Option<i32> {
        if self.vt() != VT_I4.0 {
            return None;
        }
        // SAFETY: the tag says `VT_I4`, so `lVal` is the initialized member.
        Some(unsafe { self.0.Anonymous.Anonymous.Anonymous.lVal })
    }

    fn as_bool(&self) -> Option<bool> {
        if self.vt() != VT_BOOL.0 {
            return None;
        }
        // SAFETY: the tag says `VT_BOOL`, so `boolVal` is the initialized member.
        Some(unsafe { self.0.Anonymous.Anonymous.Anonymous.boolVal }.as_bool())
    }

    fn as_string(&self) -> Option<String> {
        if self.vt() != VT_BSTR.0 {
            return None;
        }
        // SAFETY: the tag says `VT_BSTR`, so `bstrVal` is the initialized member. It is only
        // borrowed here; ownership stays with the VARIANT and `Drop` frees it.
        let bstr = unsafe { &self.0.Anonymous.Anonymous.Anonymous.bstrVal };
        Some(bstr.to_string())
    }

    /// Reads a one-dimensional `VT_ARRAY | VT_I4` (a runtime id).
    fn as_i32_vec(&self) -> Option<Vec<i32>> {
        if self.vt() != (VT_ARRAY.0 | VT_I4.0) {
            return None;
        }
        // SAFETY: the tag says `VT_ARRAY | VT_I4`, so `parray` is the initialized member. The
        // SAFEARRAY stays owned by the VARIANT; this only reads it.
        let array = unsafe { self.0.Anonymous.Anonymous.Anonymous.parray };
        if array.is_null() {
            return Some(Vec::new());
        }
        // SAFETY: `array` is a live SAFEARRAY owned by `self` for this whole function. The bound
        // queries only read its descriptor, and `SafeArrayGetElement` copies one `i32` (the
        // array's element type per the `VT_I4` tag) into a local, for indices inside the
        // bounds just read.
        unsafe {
            if SafeArrayGetDim(array) != 1 || SafeArrayGetElemsize(array) != 4 {
                return None;
            }
            let lower = SafeArrayGetLBound(array, 1).ok()?;
            let upper = SafeArrayGetUBound(array, 1).ok()?;
            let mut out = Vec::new();
            for index in lower..=upper {
                let mut element = 0i32;
                SafeArrayGetElement(array, &raw const index, (&raw mut element).cast()).ok()?;
                out.push(element);
            }
            Some(out)
        }
    }
}

fn element_count(array: &IUIAutomationElementArray) -> windows::core::Result<i32> {
    // SAFETY: COM method on a live interface pointer owned by this (worker) thread.
    unsafe { array.Length() }
}

fn elements_of(
    array: windows::core::Result<IUIAutomationElementArray>,
) -> windows::core::Result<Vec<IUIAutomationElement>> {
    let array = match array {
        Ok(array) => array,
        // UIA returns a null array (not an empty one) when nothing matched / no children.
        Err(err) if is_null_result(&err) => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let len = element_count(&array)?;
    let mut out = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    for index in 0..len {
        // SAFETY: COM method on a live interface pointer; `index` is within `0..Length()`.
        // The returned element is a new reference released on drop.
        out.push(unsafe { array.GetElement(index) }?);
    }
    Ok(out)
}

fn cached_variant(
    element: &IUIAutomationElement,
    property: UIA_PROPERTY_ID,
) -> windows::core::Result<OwnedVariant> {
    // SAFETY: COM method on a live interface pointer. The returned VARIANT is caller-owned
    // (`[out, retval]`) and is wrapped immediately so `VariantClear` runs on every path.
    unsafe { element.GetCachedPropertyValue(property) }.map(OwnedVariant)
}

fn cached_flag(element: &IUIAutomationElement, property: UIA_PROPERTY_ID) -> bool {
    cached_variant(element, property)
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn cached_i32_if(
    element: &IUIAutomationElement,
    probe: bool,
    available: UIA_PROPERTY_ID,
    property: UIA_PROPERTY_ID,
) -> Option<i64> {
    if !probe || !cached_flag(element, available) {
        return None;
    }
    cached_variant(element, property)
        .ok()
        .and_then(|v| v.as_i32())
        .map(i64::from)
}

fn cached_value(element: &IUIAutomationElement) -> Option<String> {
    if !cached_flag(element, UIA_IsValuePatternAvailablePropertyId) {
        return None;
    }
    cached_variant(element, UIA_ValueValuePropertyId)
        .ok()
        .and_then(|v| v.as_string())
}

/// `(x, y, width, height)` of an element.
type Rect = (f64, f64, f64, f64);

/// Reads the cached control type, name and bounding rectangle.
fn cached_basics(element: &IUIAutomationElement) -> windows::core::Result<(i32, String, Rect)> {
    // SAFETY: COM methods on a live interface pointer owned by this thread. They read the
    // local cache only. `CachedName` returns a caller-owned BSTR that `BSTR`'s `Drop` frees.
    let (control_type, name, rect) = unsafe {
        (
            element.CachedControlType()?,
            element.CachedName()?,
            element.CachedBoundingRectangle()?,
        )
    };
    Ok((
        control_type.0,
        name.to_string(),
        rect_to_xywh(rect.left, rect.top, rect.right, rect.bottom),
    ))
}

/// Reads one element of the tree cache into a [`RawUiaNode`], probing the same patterns, for
/// the same control types, as the PowerShell walker.
fn read_node(element: &IUIAutomationElement) -> windows::core::Result<(RawUiaNode, i32)> {
    let (ct, name, (x, y, width, height)) = cached_basics(element)?;
    // SAFETY: COM methods on a live interface pointer owned by this thread, reading the local
    // cache. `CachedLocalizedControlType` returns a caller-owned BSTR freed by its `Drop`.
    let (localized, focused, enabled) = unsafe {
        (
            element.CachedLocalizedControlType()?,
            element.CachedHasKeyboardFocus()?,
            element.CachedIsEnabled()?,
        )
    };
    let runtime_id = cached_variant(element, UIA_RuntimeIdPropertyId)
        .ok()
        .and_then(|v| v.as_i32_vec())
        .and_then(|parts| runtime_id_to_string(&parts));
    let value = cached_value(element);
    let url = if ct == control_type::HYPERLINK {
        value
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
    } else {
        None
    };
    let node = RawUiaNode {
        id: runtime_id,
        control_type: control_type_programmatic_name(ct).to_owned(),
        localized_control_type: Some(localized.to_string()),
        name: Some(name),
        value,
        x,
        y,
        width,
        height,
        focused: focused.as_bool(),
        toggle_state: cached_i32_if(
            element,
            probes_toggle_state(ct),
            UIA_IsTogglePatternAvailablePropertyId,
            UIA_ToggleToggleStatePropertyId,
        ),
        selected: if probes_selection_state(ct)
            && cached_flag(element, UIA_IsSelectionItemPatternAvailablePropertyId)
        {
            cached_variant(element, UIA_SelectionItemIsSelectedPropertyId)
                .ok()
                .and_then(|v| v.as_bool())
        } else {
            None
        },
        enabled: Some(enabled.as_bool()),
        expand_state: cached_i32_if(
            element,
            probes_expand_state(ct),
            UIA_IsExpandCollapsePatternAvailablePropertyId,
            UIA_ExpandCollapseExpandCollapseStatePropertyId,
        ),
        url,
    };
    Ok((node, ct))
}

fn process_name(pid: i32) -> Option<String> {
    let pid = u32::try_from(pid).ok()?;
    // SAFETY: `OpenProcess` takes plain values and has no memory-safety preconditions; the
    // handle it returns on success is wrapped in `Owned` on the next line.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    // SAFETY: `raw` is a fresh, valid process handle exclusively owned by this function, so
    // `Owned` may close it (once) on drop.
    let handle: Owned<HANDLE> = unsafe { Owned::new(raw) };
    let mut buffer = [0u16; 1024];
    let mut len = u32::try_from(buffer.len()).ok()?;
    // SAFETY: `buffer` is writable for `len` UTF-16 units and outlives the call; `len` points to
    // a live `u32` the call updates to the number of units written (without the terminator).
    unsafe {
        QueryFullProcessImageNameW(
            *handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &raw mut len,
        )
    }
    .ok()?;
    let written = buffer.get(..usize::try_from(len).ok()?)?;
    Some(process_name_from_image_path(&String::from_utf16_lossy(
        written,
    )))
}

/// What [`UiaSession::locate_chrome_parts`] found in the browser window.
#[derive(Default)]
struct Located {
    current_url: Option<String>,
    web_root: Option<IUIAutomationElement>,
    viewport: Option<RawBounds>,
    /// Counts and the chosen root, for the debug log.
    summary: String,
}

/// Everything the worker thread keeps between requests. Never leaves the worker thread.
struct UiaSession {
    automation: IUIAutomation,
    flavor: &'static str,
    edit_or_document: IUIAutomationCondition,
    /// `ControlType == Document`, for the raw-view transition check.
    document_condition: IUIAutomationCondition,
    true_condition: IUIAutomationCondition,
    /// Element-scoped cache for top-level windows: process id and control type.
    window_request: IUIAutomationCacheRequest,
    /// Element-scoped cache for `Edit`/`Document` descendants: type, name, bounds, value.
    locate_request: IUIAutomationCacheRequest,
    /// Raw-view cache for the transition check (and its debug log) of `Document` elements.
    diagnostic_request: IUIAutomationCacheRequest,
    /// Subtree cache over the control view (cache-only elements) for the node walk.
    tree_request: IUIAutomationCacheRequest,
    /// Element + children cache (full elements) for the level-by-level fallback walk.
    level_request: IUIAutomationCacheRequest,
    /// For per-call transaction timeouts (`None` before Windows 8).
    automation2: Option<IUIAutomation2>,
    /// The transaction timeout last set on `automation2`, in milliseconds.
    armed_ms: std::cell::Cell<u32>,
    /// Test-only hook (`WAYBOUND_WINDOWS_UIA_FORCE_LEVEL_WALK=1`): skip the subtree call and
    /// always walk level by level, so CI exercises the fallback.
    force_level_walk: bool,
}

/// Properties cached for every node of the walk.
const TREE_PROPERTIES: [UIA_PROPERTY_ID; 15] = [
    UIA_RuntimeIdPropertyId,
    UIA_ControlTypePropertyId,
    UIA_LocalizedControlTypePropertyId,
    UIA_NamePropertyId,
    UIA_BoundingRectanglePropertyId,
    UIA_HasKeyboardFocusPropertyId,
    UIA_IsEnabledPropertyId,
    UIA_IsValuePatternAvailablePropertyId,
    UIA_ValueValuePropertyId,
    UIA_IsTogglePatternAvailablePropertyId,
    UIA_ToggleToggleStatePropertyId,
    UIA_IsSelectionItemPatternAvailablePropertyId,
    UIA_SelectionItemIsSelectedPropertyId,
    UIA_IsExpandCollapsePatternAvailablePropertyId,
    UIA_ExpandCollapseExpandCollapseStatePropertyId,
];

/// Result of one snapshot.
struct Attempt {
    raw: RawUiaSnapshot,
    /// Microseconds spent finding the window, locating address bar + web root, and reading
    /// the tree (logged at `debug`, to show where a snapshot's time goes).
    phase_us: [u64; 3],
    /// Which element the walk started from (logged at `debug`).
    root: String,
}

/// Why a snapshot attempt did not produce a tree.
enum SnapError {
    /// A COM call failed.
    Call(CallError),
    /// The page is not readable yet (between documents, or an unreadable root): `transient`.
    NotReady(String),
    /// The query deadline left too little time to start a fallback walk.
    Timeout(String),
}

impl From<CallError> for SnapError {
    fn from(err: CallError) -> Self {
        Self::Call(err)
    }
}

impl SnapError {
    fn into_waybound(self) -> WayboundError {
        match self {
            Self::Call(err) => err.into_waybound(),
            Self::NotReady(reason) => WayboundError::Transient {
                backend: "windows".to_owned(),
                reason: format!("Windows UIAutomation (native COM): {reason}"),
            },
            Self::Timeout(operation) => WayboundError::Timeout {
                context: format!("Windows UIAutomation (native COM): {operation}"),
                timeout_ms: UIA_QUERY_TIMEOUT_MS,
            },
        }
    }
}

fn micros_since(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}

/// Tracks the address bar URL and viewport seen during a walk, mirroring the PowerShell
/// walker's in-walk fallbacks.
struct PageParts {
    current_url: Option<String>,
    viewport: Option<RawBounds>,
    /// The last per-node read failure, kept to explain an empty tree.
    last_skip: Option<String>,
}

impl PageParts {
    fn observe(&mut self, node: &RawUiaNode, ct: i32) {
        if self.current_url.is_none()
            && ct == control_type::EDIT
            && let Some(value) = node.value.as_deref()
            && is_address_bar_candidate(node.name.as_deref(), value)
        {
            self.current_url = Some(value.to_owned());
        }
        if self.viewport.is_none()
            && ct == control_type::DOCUMENT
            && node.width > 0.0
            && node.height > 0.0
        {
            self.viewport = Some(RawBounds {
                x: node.x,
                y: node.y,
                width: node.width,
                height: node.height,
            });
        }
    }
}

impl UiaSession {
    /// Creates the session, retrying a few times: the first CI run saw one transient
    /// `E_FAIL` from condition creation (see the module tests), and a permanent fallback for
    /// the daemon's lifetime is too high a price for one bad attempt.
    fn new_with_retry() -> std::result::Result<Self, String> {
        let mut failures = Vec::new();
        for attempt in 1..=SESSION_INIT_ATTEMPTS {
            match Self::new() {
                Ok(session) => {
                    if attempt > 1 {
                        tracing::warn!(
                            attempt,
                            earlier = %failures.join("; "),
                            "Windows UIAutomation session created after retrying"
                        );
                    }
                    return Ok(session);
                }
                Err(reason) => {
                    failures.push(format!("attempt {attempt}: {reason}"));
                    if attempt < SESSION_INIT_ATTEMPTS {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            }
        }
        Err(failures.join("; "))
    }

    fn new() -> std::result::Result<Self, String> {
        let (automation, flavor) = Self::create_automation()?;
        let fail = |what: &str, err: &windows::core::Error| format!("{what}: {}", describe(err));

        let automation2 = match automation.cast::<IUIAutomation2>() {
            Ok(automation2) => {
                // SAFETY: COM methods on a live interface pointer owned by this thread, taking
                // plain integers.
                let set = unsafe {
                    automation2
                        .SetConnectionTimeout(UIA_CONNECTION_TIMEOUT_MS)
                        .and_then(|()| {
                            automation2.SetTransactionTimeout(UIA_TRANSACTION_TIMEOUT_MS)
                        })
                };
                if let Err(err) = set {
                    tracing::warn!(error = %describe(&err), "could not set UIAutomation timeouts");
                }
                Some(automation2)
            }
            Err(err) => {
                tracing::warn!(
                    error = %describe(&err),
                    "IUIAutomation2 unavailable; UIAutomation calls use the system default timeouts"
                );
                None
            }
        };

        let edit = OwnedVariant::from_i32(UIA_EditControlTypeId.0);
        let document = OwnedVariant::from_i32(UIA_DocumentControlTypeId.0);
        // SAFETY: COM factory method on a live interface pointer owned by this thread; the
        // `VT_I4` VARIANT is borrowed for the call only (the callee copies `[in]` VARIANTs) and
        // the result is a new owned reference released on drop.
        let edit_cond =
            unsafe { automation.CreatePropertyCondition(UIA_ControlTypePropertyId, &edit.0) }
                .map_err(|err| fail("CreatePropertyCondition(ControlType = Edit)", &err))?;
        // SAFETY: same contract as the Edit condition above, with the Document VARIANT.
        let doc_cond =
            unsafe { automation.CreatePropertyCondition(UIA_ControlTypePropertyId, &document.0) }
                .map_err(|err| fail("CreatePropertyCondition(ControlType = Document)", &err))?;
        // SAFETY: COM factory method on a live interface pointer; both conditions are live
        // borrowed references, the result is a new owned reference.
        let edit_or_document = unsafe { automation.CreateOrCondition(&edit_cond, &doc_cond) }
            .map_err(|err| fail("CreateOrCondition", &err))?;
        // SAFETY: COM factory method on a live interface pointer without arguments; the result is
        // a new owned reference.
        let true_condition = unsafe { automation.CreateTrueCondition() }
            .map_err(|err| fail("CreateTrueCondition", &err))?;
        // SAFETY: COM method on a live interface pointer; returns an owned reference.
        let control_view = unsafe { automation.ControlViewCondition() }
            .map_err(|err| fail("ControlViewCondition", &err))?;

        let request = |properties: &[UIA_PROPERTY_ID], scope: TreeScope, cache_only: bool| {
            Self::cache_request(&automation, &control_view, properties, scope, cache_only)
        };
        let window_request = request(
            &[UIA_ProcessIdPropertyId, UIA_ControlTypePropertyId],
            TreeScope_Element,
            false,
        )
        .map_err(|err| fail("creating window cache request", &err))?;
        // The Edit/Document search uses the control view, exactly like the PowerShell
        // walker's `$targetWindow.FindAll(Descendants, ...)`: .NET's `FindAll` runs with the
        // default cache request, whose view condition is `Automation.ControlViewCondition`.
        let locate_request = request(
            &[
                UIA_ControlTypePropertyId,
                UIA_NamePropertyId,
                UIA_BoundingRectanglePropertyId,
                UIA_IsValuePatternAvailablePropertyId,
                UIA_ValueValuePropertyId,
            ],
            TreeScope_Element,
            false,
        )
        .map_err(|err| fail("creating locate cache request", &err))?;
        let diagnostic_request = Self::cache_request(
            &automation,
            &true_condition,
            &[
                UIA_ControlTypePropertyId,
                UIA_NamePropertyId,
                UIA_BoundingRectanglePropertyId,
                UIA_IsControlElementPropertyId,
                UIA_IsOffscreenPropertyId,
            ],
            TreeScope_Element,
            false,
        )
        .map_err(|err| fail("creating diagnostic cache request", &err))?;
        let tree_request = request(&TREE_PROPERTIES, TreeScope_Subtree, true)
            .map_err(|err| fail("creating tree cache request", &err))?;
        let level_request = request(
            &TREE_PROPERTIES,
            TreeScope(TreeScope_Element.0 | TreeScope_Children.0),
            false,
        )
        .map_err(|err| fail("creating level cache request", &err))?;

        Ok(Self {
            automation,
            flavor,
            edit_or_document,
            document_condition: doc_cond,
            true_condition,
            window_request,
            locate_request,
            diagnostic_request,
            tree_request,
            level_request,
            automation2,
            armed_ms: std::cell::Cell::new(UIA_TRANSACTION_TIMEOUT_MS),
            force_level_walk: std::env::var(FORCE_LEVEL_WALK_ENV).is_ok_and(|v| v.trim() == "1"),
        })
    }

    fn create_automation() -> std::result::Result<(IUIAutomation, &'static str), String> {
        // SAFETY: `CoCreateInstance` with a valid CLSID pointer (a `'static` GUID), no outer
        // unknown, and an interface type parameter; the result is an owned reference released
        // on drop. COM is initialized on this thread by the caller.
        let modern: windows::core::Result<IUIAutomation> =
            unsafe { CoCreateInstance(&CUIAutomation8, None, CLSCTX_INPROC_SERVER) };
        match modern {
            Ok(automation) => Ok((automation, "CUIAutomation8")),
            Err(first) => {
                // SAFETY: as above, for the Windows 7 `CUIAutomation` class.
                let legacy: windows::core::Result<IUIAutomation> =
                    unsafe { CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER) };
                legacy
                    .map(|automation| (automation, "CUIAutomation"))
                    .map_err(|second| {
                        format!(
                            "CoCreateInstance(CUIAutomation8) failed: {}; CoCreateInstance(CUIAutomation) failed: {}",
                            describe(&first),
                            describe(&second)
                        )
                    })
            }
        }
    }

    /// Builds a cache request with an explicit tree filter: the control view for the walk
    /// (matching the PowerShell walker's `ControlViewWalker`), the raw view for the
    /// raw-view `Document` transition check.
    fn cache_request(
        automation: &IUIAutomation,
        filter: &IUIAutomationCondition,
        properties: &[UIA_PROPERTY_ID],
        scope: TreeScope,
        cache_only: bool,
    ) -> windows::core::Result<IUIAutomationCacheRequest> {
        // SAFETY: COM methods on live interface pointers owned by this thread, taking plain
        // values or a borrowed live condition.
        unsafe {
            let request = automation.CreateCacheRequest()?;
            for &property in properties {
                request.AddProperty(property)?;
            }
            request.SetTreeScope(scope)?;
            request.SetTreeFilter(filter)?;
            if cache_only {
                request.SetAutomationElementMode(AutomationElementMode_None)?;
            }
            Ok(request)
        }
    }

    fn run(&self, kind: JobKind, deadline: Instant) -> Result<RawUiaSnapshot> {
        match kind {
            JobKind::Snapshot { pid, limit } => {
                match Self::retry_stale(|| self.snapshot(pid, limit, deadline)) {
                    Ok(attempt) => {
                        tracing::debug!(
                            window_us = attempt.phase_us[0],
                            locate_us = attempt.phase_us[1],
                            tree_us = attempt.phase_us[2],
                            nodes = attempt.raw.nodes.len(),
                            root = %attempt.root,
                            "Windows UIAutomation snapshot phases"
                        );
                        Ok(attempt.raw)
                    }
                    Err(err) => Err(err.into_waybound()),
                }
            }
            JobKind::PageInfo { pid } => Self::retry_stale(|| self.page_info(pid, deadline))
                .map_err(SnapError::into_waybound),
            #[cfg(test)]
            JobKind::DesktopProbe => self
                .desktop_probe(deadline)
                .map_err(CallError::into_waybound),
        }
    }

    /// Runs `attempt`, and once more if it failed on a stale element (navigation or a tab
    /// switch replaced it mid-query).
    fn retry_stale<T>(
        mut attempt: impl FnMut() -> std::result::Result<T, SnapError>,
    ) -> std::result::Result<T, SnapError> {
        match attempt() {
            Err(SnapError::Call(err)) if err.class() == HresultClass::Stale => {
                tracing::debug!(
                    error = %describe(&err.err),
                    operation = err.operation,
                    "stale UIAutomation element; retrying once"
                );
                attempt()
            }
            other => other,
        }
    }

    /// Sets the UIA transaction timeout for the next cross-process call so it ends before
    /// the caller's deadline: `min(5 s, remaining - margin)`, at least 100 ms.
    fn arm(&self, deadline: Instant) {
        let Some(automation2) = &self.automation2 else {
            return;
        };
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .saturating_sub(TRANSACTION_MARGIN);
        let ms = u32::try_from(remaining.as_millis())
            .unwrap_or(u32::MAX)
            .clamp(100, UIA_TRANSACTION_TIMEOUT_MS);
        if self.armed_ms.get() == ms {
            return;
        }
        // SAFETY: COM method on a live interface pointer owned by this thread, taking a plain
        // integer.
        if unsafe { automation2.SetTransactionTimeout(ms) }.is_ok() {
            self.armed_ms.set(ms);
        }
    }

    fn find_window(
        &self,
        pid: Option<i32>,
        deadline: Instant,
    ) -> std::result::Result<Option<IUIAutomationElement>, CallError> {
        self.arm(deadline);
        // SAFETY: COM method on a live interface pointer; returns an owned reference.
        let root = unsafe { self.automation.GetRootElement() }
            .map_err(|err| CallError::new(err, "GetRootElement"))?;
        pid.map_or_else(
            || self.browser_window(&root),
            |pid| self.window_for_pid(&root, pid),
        )
        .map_err(|err| CallError::new(err, "window lookup"))
    }

    /// Address-bar URL and viewport only. Mid-transition (no control-view document yet) the
    /// URL still comes from the omnibox, which is browser UI and valid throughout, and the
    /// viewport is `None`, exactly what the PowerShell walker reported for a window without
    /// a control-view document.
    ///
    /// The PowerShell walker also inferred the viewport during its walk and again in
    /// `finalize_snapshot` (first control-view `Document` with a positive size). Both only see
    /// control-view documents, which the `FindAll` above already covered, so they could only
    /// add something when that search failed; a failed search is `transient` here instead.
    fn page_info(
        &self,
        pid: Option<i32>,
        deadline: Instant,
    ) -> std::result::Result<RawUiaSnapshot, SnapError> {
        let Some(window) = self.find_window(pid, deadline)? else {
            return Ok(RawUiaSnapshot::default());
        };
        let located = self.locate_chrome_parts(&window, deadline)?;
        Ok(RawUiaSnapshot {
            current_url: located.current_url,
            viewport_bounds: located.viewport,
            ..RawUiaSnapshot::default()
        })
    }

    fn snapshot(
        &self,
        pid: Option<i32>,
        limit: usize,
        deadline: Instant,
    ) -> std::result::Result<Attempt, SnapError> {
        let started = Instant::now();
        let window = self.find_window(pid, deadline)?;
        let window_us = micros_since(started);
        let Some(window) = window else {
            // No top-level element for the pid: an empty tree, as the PowerShell walker
            // returned. Wait loops poll on `ElementNotFound` anyway.
            return Ok(Attempt {
                raw: RawUiaSnapshot::default(),
                phase_us: [window_us, 0, 0],
                root: "none (no window)".to_owned(),
            });
        };

        let started = Instant::now();
        let located = self.locate_chrome_parts(&window, deadline)?;
        let locate_us = micros_since(started);
        let root = if located.web_root.is_some() {
            located.summary
        } else {
            // No control-view document. If the raw view has one, the page is between
            // documents (new renderer, navigation, reload): never return the browser UI then.
            let raw_documents = self.raw_documents(&window, deadline)?;
            if raw_documents > 0 {
                return Err(SnapError::NotReady(format!(
                    "web document not in the control view yet ({raw_documents} raw-view \
                     documents, {})",
                    located.summary
                )));
            }
            // No document anywhere: not a browser page; walk the window like PowerShell.
            format!(
                "{}; root=window (no document in the raw view either)",
                located.summary
            )
        };
        let started = Instant::now();
        let mut parts = PageParts {
            current_url: located.current_url,
            viewport: located.viewport,
            last_skip: None,
        };
        let base = located.web_root.unwrap_or(window);

        let subtree = if self.force_level_walk {
            None
        } else {
            self.arm(deadline);
            // SAFETY: COM method on a live interface pointer with a live cache request;
            // returns an owned, cache-populated element.
            Some(unsafe { base.BuildUpdatedCache(&self.tree_request) })
        };
        let (nodes, truncated) = match subtree {
            Some(Ok(cached_root)) => Self::walk_cached(cached_root, limit, &mut parts),
            Some(Err(err)) => {
                let failed = CallError::tree(err, "tree snapshot (BuildUpdatedCache subtree)");
                if failed.class() == HresultClass::Stale
                    && hresult(&failed.err) != uia_model::E_FAIL
                {
                    return Err(failed.into());
                }
                tracing::info!(
                    error = %describe(&failed.err),
                    "UIAutomation subtree snapshot failed; walking level by level"
                );
                self.walk_levels(&base, limit, deadline, &mut parts, Some(failed))?
            }
            None => {
                tracing::debug!(
                    "WAYBOUND_WINDOWS_UIA_FORCE_LEVEL_WALK set; walking level by level"
                );
                self.walk_levels(&base, limit, deadline, &mut parts, None)?
            }
        };

        if nodes.is_empty() {
            return Err(SnapError::NotReady(format!(
                "walk root unreadable: {}",
                parts.last_skip.as_deref().unwrap_or("no error recorded")
            )));
        }
        let tree_us = micros_since(started);
        Ok(Attempt {
            raw: RawUiaSnapshot {
                nodes,
                truncated,
                current_url: parts.current_url,
                viewport_bounds: parts.viewport,
            },
            phase_us: [window_us, locate_us, tree_us],
            root,
        })
    }

    /// Walks a subtree cache built by `tree_request` (no cross-process calls).
    fn walk_cached(
        cached_root: IUIAutomationElement,
        limit: usize,
        parts: &mut PageParts,
    ) -> (Vec<RawUiaNode>, bool) {
        bfs_limited(cached_root, limit, |element, _room| {
            let (node, ct) = match read_node(&element) {
                Ok(read) => read,
                Err(err) => {
                    let error = describe(&err);
                    tracing::debug!(%error, "skipping unreadable UIA node");
                    parts.last_skip = Some(error);
                    return Visit::Skip;
                }
            };
            parts.observe(&node, ct);
            // SAFETY: COM method on a live, cache-populated element; reads the local cache.
            let children = elements_of(unsafe { element.GetCachedChildren() }).unwrap_or_default();
            Visit::Node(node, children)
        })
    }

    /// Bounded fallback walk: one `BuildUpdatedCache(Element | Children)` per visited node
    /// whose children can still be queued, stopping at `limit` nodes or shortly before
    /// `deadline` (then `truncated`). Not started with less than [`MIN_LEVEL_WALK`] left.
    fn walk_levels(
        &self,
        base: &IUIAutomationElement,
        limit: usize,
        deadline: Instant,
        parts: &mut PageParts,
        trigger_error: Option<CallError>,
    ) -> std::result::Result<(Vec<RawUiaNode>, bool), SnapError> {
        if deadline.saturating_duration_since(Instant::now()) < MIN_LEVEL_WALK {
            return Err(trigger_error.map_or_else(
                || {
                    SnapError::Timeout(
                        "not enough time left for the level-by-level walk".to_owned(),
                    )
                },
                SnapError::Call,
            ));
        }
        self.arm(deadline);
        // SAFETY: COM method on a live interface pointer with a live cache request; returns an
        // owned element whose own properties and children are cached.
        let root = unsafe { base.BuildUpdatedCache(&self.level_request) }
            .map_err(|err| CallError::tree(err, "tree snapshot (level walk root)"))?;
        let stop_at = deadline
            .checked_sub(WALK_DEADLINE_MARGIN)
            .unwrap_or(deadline);
        Ok(bfs_limited(root, limit, |element, room| {
            if Instant::now() >= stop_at {
                return Visit::Stop;
            }
            let (node, ct) = match read_node(&element) {
                Ok(read) => read,
                Err(err) => {
                    let error = describe(&err);
                    tracing::debug!(%error, "skipping unreadable UIA node");
                    parts.last_skip = Some(error);
                    return Visit::Skip;
                }
            };
            parts.observe(&node, ct);
            if room == 0 {
                return Visit::NodeOnly(node);
            }
            self.arm(deadline);
            // SAFETY: COM methods on a live full-mode element with a live cache request; the
            // refreshed element and its cached children array are owned references.
            let children = unsafe {
                element
                    .BuildUpdatedCache(&self.level_request)
                    .and_then(|refreshed| refreshed.GetCachedChildren())
            };
            let children = match elements_of(children) {
                Ok(list) => list,
                Err(err) if uia_model::classify_hresult(hresult(&err)) == HresultClass::Timeout => {
                    tracing::debug!(
                        error = %describe(&err),
                        "level walk child fetch timed out; stopping with partial tree"
                    );
                    return Visit::Stop;
                }
                Err(_) => Vec::new(),
            };
            Visit::Node(node, children)
        }))
    }

    #[cfg(test)]
    fn desktop_probe(&self, deadline: Instant) -> std::result::Result<RawUiaSnapshot, CallError> {
        self.arm(deadline);
        // SAFETY: COM methods on live interface pointers owned by this thread.
        let root = unsafe {
            self.automation
                .GetRootElement()
                .and_then(|r| r.BuildUpdatedCache(&self.level_request))
        }
        .map_err(|err| CallError::new(err, "desktop root"))?;
        let (node, _) = read_node(&root).map_err(|err| CallError::new(err, "read desktop root"))?;
        Ok(RawUiaSnapshot {
            nodes: vec![node],
            ..RawUiaSnapshot::default()
        })
    }

    fn window_for_pid(
        &self,
        root: &IUIAutomationElement,
        pid: i32,
    ) -> windows::core::Result<Option<IUIAutomationElement>> {
        let pid_value = OwnedVariant::from_i32(pid);
        // SAFETY: COM methods on live interface pointers owned by this thread; the VARIANT is
        // borrowed for the call only. Results are owned references released on drop.
        let found = unsafe {
            let condition = self
                .automation
                .CreatePropertyCondition(UIA_ProcessIdPropertyId, &pid_value.0)?;
            root.FindFirst(TreeScope_Children, &condition)
        };
        match found {
            Ok(window) => Ok(Some(window)),
            Err(err) if is_null_result(&err) => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn browser_window(
        &self,
        root: &IUIAutomationElement,
    ) -> windows::core::Result<Option<IUIAutomationElement>> {
        // SAFETY: COM method on a live interface pointer with live condition and cache request;
        // returns an owned array.
        let windows = elements_of(unsafe {
            root.FindAllBuildCache(
                TreeScope_Children,
                &self.true_condition,
                &self.window_request,
            )
        })?;
        let candidates: Vec<WindowCandidate> = windows
            .iter()
            .map(|window| {
                // SAFETY: COM methods on a live element, reading the cache built above.
                let (pid, ct) = unsafe { (window.CachedProcessId(), window.CachedControlType()) };
                let pid = pid.unwrap_or(0);
                WindowCandidate {
                    process_name: process_name(pid),
                    pid,
                    is_window: ct.is_ok_and(|ct| ct == UIA_WindowControlTypeId),
                }
            })
            .collect();
        Ok(pick_browser_window(&candidates).and_then(|idx| windows.into_iter().nth(idx)))
    }

    /// Finds the omnibox URL and the web content root among the window's descendants, like
    /// the PowerShell walker's two `FindAll` passes (in one call here). Failures are
    /// propagated as `CallError` so callers never misread a failed search as "no document".
    fn locate_chrome_parts(
        &self,
        window: &IUIAutomationElement,
        deadline: Instant,
    ) -> std::result::Result<Located, CallError> {
        self.arm(deadline);
        // SAFETY: COM method on a live interface pointer with live condition and cache request;
        // returns an owned array.
        let found = elements_of(unsafe {
            window.FindAllBuildCache(
                TreeScope_Descendants,
                &self.edit_or_document,
                &self.locate_request,
            )
        });
        // A failed search is never "no document": it is transient (or a timeout).
        let elements = found.map_err(|err| CallError::search(err, "Edit/Document search"))?;

        // Same order and tie-break as the PowerShell walker: the first Edit (tree order) whose
        // name or value looks like an address bar; the Document with the largest positive
        // area (first on ties), else the first Document.
        let mut current_url = None;
        let mut documents = Vec::new();
        let mut document_rects = Vec::new();
        let mut edits = 0usize;
        for element in elements {
            let Ok((ct, name, rect)) = cached_basics(&element) else {
                continue;
            };
            if ct == control_type::EDIT {
                edits += 1;
                if current_url.is_none()
                    && let Some(value) = cached_value(&element)
                    && is_address_bar_candidate(Some(&name), &value)
                {
                    current_url = Some(value);
                }
            } else if ct == control_type::DOCUMENT {
                documents.push((element, name));
                document_rects.push(rect);
            }
        }

        let mut summary = format!("control view: edits={edits} documents={}", documents.len());
        let (web_root, viewport) = match select_web_root(&document_rects) {
            Some((idx, bounds)) => {
                let chosen = documents.into_iter().nth(idx);
                if let Some((_, name)) = &chosen {
                    let _ = write!(summary, "; root=Document #{idx} name={name:?}");
                }
                (
                    chosen.map(|(element, _)| element),
                    bounds.map(|b| RawBounds {
                        x: b.x,
                        y: b.y,
                        width: b.width,
                        height: b.height,
                    }),
                )
            }
            None => (None, None),
        };
        Ok(Located {
            current_url,
            web_root,
            viewport,
            summary,
        })
    }

    /// Counts the `Document` elements under the window in the raw view (one cross-process
    /// call), logging each one (name, bounds, `IsControlElement`, `IsOffscreen`, raw child
    /// count) when debug logging is on. Only called when the control view has no document.
    fn raw_documents(
        &self,
        window: &IUIAutomationElement,
        deadline: Instant,
    ) -> std::result::Result<usize, CallError> {
        self.arm(deadline);
        // SAFETY: COM method on a live interface pointer with live condition and cache request;
        // returns an owned array.
        let documents = elements_of(unsafe {
            window.FindAllBuildCache(
                TreeScope_Descendants,
                &self.document_condition,
                &self.diagnostic_request,
            )
        })
        .map_err(|err| CallError::search(err, "raw-view Document search"))?;
        if tracing::enabled!(tracing::Level::DEBUG) {
            for (idx, document) in documents.iter().enumerate() {
                if Instant::now() >= deadline {
                    break;
                }
                let (name, rect) = cached_basics(document)
                    .map(|(_, name, rect)| (name, rect))
                    .unwrap_or_default();
                self.arm(deadline);
                // SAFETY: COM method on a live element with a live condition; returns an owned
                // array. Debug logging only.
                let children = elements_of(unsafe {
                    document.FindAll(TreeScope_Children, &self.true_condition)
                })
                .map_or(-1, |c| i64::try_from(c.len()).unwrap_or(i64::MAX));
                tracing::debug!(
                    idx,
                    name = %name,
                    x = rect.0,
                    y = rect.1,
                    width = rect.2,
                    height = rect.3,
                    control = cached_flag(document, UIA_IsControlElementPropertyId),
                    offscreen = cached_flag(document, UIA_IsOffscreenPropertyId),
                    raw_children = children,
                    "raw-view Document candidate"
                );
            }
        }
        Ok(documents.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads the desktop root through the single worker (thread start, COM init, cache
    /// request, cached properties, runtime-id SAFEARRAY decoding).
    ///
    /// The first CI run created a second `CUIAutomation` + conditions on the test thread
    /// concurrently with the worker test, and that path failed in `CreatePropertyCondition`
    /// with `E_FAIL` while the identical code on the worker succeeded. Production only ever
    /// has one automation object (the worker's), so the test now goes through it too.
    #[test]
    fn desktop_root_snapshot_reads_cached_properties() {
        match run_job(JobKind::DesktopProbe) {
            NativeOutcome::Done(Ok(raw)) => {
                let root = raw.nodes.first();
                // The desktop is an HWND-based element, whose runtime id is `[42, hwnd]`.
                assert!(
                    root.and_then(|n| n.id.as_deref())
                        .is_some_and(|id| id.starts_with("42-")),
                    "desktop root runtime id: {root:?}"
                );
                assert_eq!(
                    root.map(|n| n.control_type.as_str()),
                    Some("ControlType.Pane"),
                    "{root:?}"
                );
            }
            NativeOutcome::Done(Err(err)) => assert_eq!(format!("{err}"), "", "desktop probe"),
            NativeOutcome::Unavailable(reason) => assert_eq!(reason, "", "COM unavailable"),
        }
    }

    /// Runs the real worker end to end without a browser. The own-pid query must succeed
    /// (`FindFirst` with no match is an empty snapshot); the no-pid query may meet a desktop
    /// in flux, so `transient`/`timeout` are tolerated there. Neither may report native COM
    /// as unavailable, which would mean production silently ran on PowerShell.
    #[test]
    fn worker_answers_without_a_browser() {
        let own_pid = i32::try_from(std::process::id()).unwrap_or(i32::MAX);
        match query(Some(own_pid), 10) {
            NativeOutcome::Done(Ok(raw)) => assert!(raw.nodes.len() <= 10),
            NativeOutcome::Done(Err(err)) => assert_eq!(format!("{err}"), "", "own pid"),
            NativeOutcome::Unavailable(reason) => assert_eq!(reason, "", "COM unavailable"),
        }
        match query(None, 10) {
            NativeOutcome::Done(Ok(raw)) => assert!(raw.nodes.len() <= 10),
            NativeOutcome::Done(Err(
                WayboundError::Transient { .. } | WayboundError::Timeout { .. },
            )) => {}
            NativeOutcome::Done(Err(err)) => assert_eq!(format!("{err}"), "", "no pid"),
            NativeOutcome::Unavailable(reason) => assert_eq!(reason, "", "COM unavailable"),
        }
        match query_page_info(Some(own_pid)) {
            NativeOutcome::Done(Ok(raw)) => {
                assert!(raw.nodes.is_empty());
                assert_eq!(raw.current_url, None);
            }
            NativeOutcome::Done(Err(err)) => assert_eq!(format!("{err}"), "", "page info"),
            NativeOutcome::Unavailable(reason) => assert_eq!(reason, "", "COM unavailable"),
        }
    }

    #[test]
    fn variant_helpers_round_trip_plain_values() {
        let v = OwnedVariant::from_i32(-7);
        assert_eq!(v.as_i32(), Some(-7));
        assert_eq!(v.as_bool(), None);
        assert_eq!(v.as_string(), None);
        assert_eq!(v.as_i32_vec(), None);
    }
}

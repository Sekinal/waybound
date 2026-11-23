//! In-process COM `IUIAutomation` backend (Windows only).
//!
//! # Threading and timeouts
//!
//! All COM objects live on one dedicated worker thread that joins the multithreaded apartment
//! (`CoInitializeEx(COINIT_MULTITHREADED)`). UIA client objects need no message pump in the MTA,
//! and keeping them on one thread means no interface pointer ever crosses threads. Callers send
//! a [`Job`] over a channel and wait at most [`UIA_QUERY_TIMEOUT_MS`] for the reply, so the
//! daemon never blocks longer than the PowerShell backend did.
//!
//! Two layers bound a hung provider:
//! 1. `IUIAutomation2::SetConnectionTimeout` / `SetTransactionTimeout` make each cross-process
//!    call fail with `UIA_E_TIMEOUT` instead of blocking.
//! 2. The caller's channel wait. When it expires the caller returns
//!    [`WayboundError::Timeout`] (error code `timeout`, as before) and abandons the worker: the
//!    next request starts a fresh one, and the abandoned thread exits as soon as its current
//!    call returns. At most [`MAX_ABANDONED_WORKERS`] abandoned workers may be outstanding.
//!
//! # Snapshot cost
//!
//! A snapshot is a fixed number of cross-process calls, independent of tree size:
//! `FindFirst` (window by pid) or one `FindAllBuildCache` over top-level windows, one
//! `FindAllBuildCache` for the window's `Edit`/`Document` descendants (address bar and web
//! root), and one `BuildUpdatedCache` with `TreeScope_Subtree` over the control view of the web
//! root. Everything else reads the local cache.
//!
//! The subtree is fetched whole and `max_nodes` is applied while walking the cache. UIA has no
//! way to cap a subtree cache request, and fetching level by level costs one cross-process call
//! per expanded node, which is what made the PowerShell walker slow. A very large page therefore
//! costs one large call rather than being cut short on the provider side; the transaction
//! timeout still bounds it.

use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use waybound_core::{Result, WayboundError};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::System::Ole::{
    SafeArrayGetDim, SafeArrayGetElement, SafeArrayGetLBound, SafeArrayGetUBound,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::Win32::System::Variant::{VARIANT, VT_ARRAY, VT_BOOL, VT_BSTR, VT_I4, VariantClear};
use windows::Win32::UI::Accessibility::{
    AutomationElementMode_None, CUIAutomation, CUIAutomation8, IUIAutomation, IUIAutomation2,
    IUIAutomationCacheRequest, IUIAutomationCondition, IUIAutomationElement,
    IUIAutomationElementArray, TreeScope, TreeScope_Children, TreeScope_Descendants,
    TreeScope_Subtree, UIA_BoundingRectanglePropertyId, UIA_ControlTypePropertyId,
    UIA_DocumentControlTypeId, UIA_EditControlTypeId,
    UIA_ExpandCollapseExpandCollapseStatePropertyId, UIA_HasKeyboardFocusPropertyId,
    UIA_IsEnabledPropertyId, UIA_IsExpandCollapsePatternAvailablePropertyId,
    UIA_IsSelectionItemPatternAvailablePropertyId, UIA_IsTogglePatternAvailablePropertyId,
    UIA_IsValuePatternAvailablePropertyId, UIA_LocalizedControlTypePropertyId, UIA_NamePropertyId,
    UIA_PROPERTY_ID, UIA_ProcessIdPropertyId, UIA_RuntimeIdPropertyId,
    UIA_SelectionItemIsSelectedPropertyId, UIA_ToggleToggleStatePropertyId,
    UIA_ValueValuePropertyId,
};
use windows::core::{Interface, Owned, PWSTR};

use crate::uia::{RawBounds, RawUiaNode, RawUiaSnapshot, UIA_QUERY_TIMEOUT_MS};
use crate::uia_model::{
    self, bfs_limited, control_type, control_type_programmatic_name, is_address_bar_candidate,
    pick_browser_window, probes_expand_state, probes_selection_state, probes_toggle_state,
    process_name_from_image_path, rect_to_xywh, runtime_id_to_string, select_web_root,
};

/// UIA connection timeout: how long UIA waits for a provider to accept a call.
const UIA_CONNECTION_TIMEOUT_MS: u32 = 2_000;
/// UIA transaction timeout: how long one cross-process call may run. Kept below
/// [`UIA_QUERY_TIMEOUT_MS`] so a hung provider normally surfaces as `UIA_E_TIMEOUT` from the
/// worker before the caller gives up on the channel.
const UIA_TRANSACTION_TIMEOUT_MS: u32 = 8_000;
/// How many abandoned (hung) workers may exist before requests fail fast.
const MAX_ABANDONED_WORKERS: usize = 4;

/// Outcome of a native query.
pub enum NativeOutcome {
    /// The native backend answered (successfully or with a mapped error).
    Done(Result<RawUiaSnapshot>),
    /// COM or `CUIAutomation` could not be initialized; the reason includes the `HRESULT`.
    /// Callers fall back to PowerShell.
    Unavailable(String),
}

struct Job {
    pid: Option<i32>,
    limit: usize,
    reply: mpsc::SyncSender<Result<RawUiaSnapshot>>,
}

struct WorkerSlot {
    generation: u64,
    tx: mpsc::Sender<Job>,
    abandoned: Arc<AtomicBool>,
}

static WORKER: Mutex<Option<WorkerSlot>> = Mutex::new(None);
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
static ABANDONED_WORKERS: AtomicUsize = AtomicUsize::new(0);
/// Set once COM initialization has failed; every later query falls back to PowerShell.
static INIT_FAILURE: Mutex<Option<String>> = Mutex::new(None);

fn timeout_error(context: &str) -> WayboundError {
    WayboundError::Timeout {
        timeout_ms: UIA_QUERY_TIMEOUT_MS,
        context: context.to_owned(),
    }
}

/// Runs one snapshot on the COM worker, starting the worker if needed.
pub fn query(pid: Option<i32>, limit: usize) -> NativeOutcome {
    let init_failure = INIT_FAILURE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    if let Some(reason) = init_failure {
        return NativeOutcome::Unavailable(reason);
    }

    let deadline = Instant::now() + Duration::from_millis(UIA_QUERY_TIMEOUT_MS);
    let (generation, tx, abandoned) = match current_worker(deadline) {
        Ok(slot) => slot,
        Err(WorkerStart::Unavailable(reason)) => return NativeOutcome::Unavailable(reason),
        Err(WorkerStart::Failed(err)) => return NativeOutcome::Done(Err(err)),
    };

    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    let job = Job {
        pid,
        limit,
        reply: reply_tx,
    };
    if tx.send(job).is_err() {
        // The worker exited (it only does so after a fatal error); start over next time.
        forget_worker(generation, &abandoned, false);
        return NativeOutcome::Done(Err(WayboundError::BackendUnavailable {
            backend: "windows".to_owned(),
            reason: "Windows UIAutomation (native COM) worker thread exited".to_owned(),
        }));
    }
    drop(tx);

    let wait = deadline.saturating_duration_since(Instant::now());
    match reply_rx.recv_timeout(wait) {
        Ok(result) => NativeOutcome::Done(result),
        Err(RecvTimeoutError::Timeout) => {
            tracing::warn!(
                generation,
                timeout_ms = UIA_QUERY_TIMEOUT_MS,
                "Windows UIAutomation (native COM) query timed out; abandoning worker thread"
            );
            forget_worker(generation, &abandoned, true);
            NativeOutcome::Done(Err(timeout_error(
                "Windows UIAutomation (native COM) query",
            )))
        }
        Err(RecvTimeoutError::Disconnected) => {
            forget_worker(generation, &abandoned, false);
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

fn current_worker(
    deadline: Instant,
) -> std::result::Result<(u64, mpsc::Sender<Job>, Arc<AtomicBool>), WorkerStart> {
    let mut slot = WORKER.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(existing) = slot.as_ref() {
        return Ok((
            existing.generation,
            existing.tx.clone(),
            Arc::clone(&existing.abandoned),
        ));
    }

    if ABANDONED_WORKERS.load(Ordering::SeqCst) >= MAX_ABANDONED_WORKERS {
        return Err(WorkerStart::Failed(timeout_error(
            "Windows UIAutomation (native COM): earlier queries are still hung in the provider",
        )));
    }

    let generation = NEXT_GENERATION.fetch_add(1, Ordering::SeqCst);
    let abandoned = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<Job>();
    let (init_tx, init_rx) = mpsc::sync_channel::<std::result::Result<&'static str, String>>(1);
    let worker_abandoned = Arc::clone(&abandoned);
    let spawned = std::thread::Builder::new()
        .name(format!("waybound-uia-{generation}"))
        .spawn(move || worker_main(&rx, &init_tx, &worker_abandoned));
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
        }
        Ok(Err(reason)) => {
            tracing::warn!(
                %reason,
                "Windows UIAutomation COM initialization failed; falling back to PowerShell"
            );
            *INIT_FAILURE.lock().unwrap_or_else(PoisonError::into_inner) = Some(reason.clone());
            return Err(WorkerStart::Unavailable(reason));
        }
        Err(_) => {
            // The worker is stuck in CoCreateInstance; leave it to exit when the channel drops.
            abandoned.store(true, Ordering::SeqCst);
            let _ = ABANDONED_WORKERS.fetch_add(1, Ordering::SeqCst);
            return Err(WorkerStart::Failed(timeout_error(
                "Windows UIAutomation (native COM) initialization",
            )));
        }
    }

    *slot = Some(WorkerSlot {
        generation,
        tx: tx.clone(),
        abandoned: Arc::clone(&abandoned),
    });
    drop(slot);
    Ok((generation, tx, abandoned))
}

/// Drops the worker `generation` from the slot so the next request starts a fresh one.
/// With `hung`, the worker is counted as abandoned until its thread exits.
fn forget_worker(generation: u64, abandoned: &AtomicBool, hung: bool) {
    let mut slot = WORKER.lock().unwrap_or_else(PoisonError::into_inner);
    if slot.as_ref().is_some_and(|s| s.generation == generation) {
        if hung && !abandoned.swap(true, Ordering::SeqCst) {
            let _ = ABANDONED_WORKERS.fetch_add(1, Ordering::SeqCst);
        }
        *slot = None;
    }
}

/// Decrements [`ABANDONED_WORKERS`] when an abandoned worker thread finally exits, on every
/// return path of [`worker_main`].
struct AbandonedOnExit<'a>(&'a AtomicBool);

impl Drop for AbandonedOnExit<'_> {
    fn drop(&mut self) {
        if self.0.load(Ordering::SeqCst) {
            let _ = ABANDONED_WORKERS.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Set after the first successful native snapshot has been logged at `info`.
static FIRST_SNAPSHOT_LOGGED: AtomicBool = AtomicBool::new(false);

fn worker_main(
    rx: &mpsc::Receiver<Job>,
    init_tx: &mpsc::SyncSender<std::result::Result<&'static str, String>>,
    abandoned: &AtomicBool,
) {
    let _exit = AbandonedOnExit(abandoned);
    // Declared before every COM object so it is dropped after them: all of them must be
    // released before `CoUninitialize` runs. so it is dropped last: every COM object below must be released before
    // `CoUninitialize` runs.
    let apartment = match ComApartment::init_mta() {
        Ok(apartment) => apartment,
        Err(err) => {
            let _ = init_tx.send(Err(format!(
                "CoInitializeEx(COINIT_MULTITHREADED) failed: {}",
                describe(&err)
            )));
            return;
        }
    };
    let session = match UiaSession::new() {
        Ok(session) => session,
        Err(reason) => {
            let _ = init_tx.send(Err(reason));
            drop(apartment);
            return;
        }
    };
    if init_tx.send(Ok(session.flavor)).is_err() {
        return;
    }

    while let Ok(job) = rx.recv() {
        let started = Instant::now();
        let result = session.snapshot_with_retry(job.pid, job.limit);
        let elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        match &result {
            Ok(raw) if !FIRST_SNAPSHOT_LOGGED.swap(true, Ordering::Relaxed) => tracing::info!(
                backend = "native-com",
                pid = ?job.pid,
                limit = job.limit,
                nodes = raw.nodes.len(),
                truncated = raw.truncated,
                elapsed_us,
                "first Windows UIAutomation snapshot"
            ),
            Ok(raw) => tracing::debug!(
                backend = "native-com",
                pid = ?job.pid,
                limit = job.limit,
                nodes = raw.nodes.len(),
                truncated = raw.truncated,
                elapsed_us,
                "Windows UIAutomation snapshot"
            ),
            Err(err) => tracing::debug!(
                backend = "native-com",
                pid = ?job.pid,
                error = %err,
                "Windows UIAutomation snapshot failed"
            ),
        }
        // The caller may have timed out and gone; that is fine.
        let _ = job.reply.send(result);
    }

    drop(session);
    drop(apartment);
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

fn to_waybound(err: &windows::core::Error, operation: &str) -> WayboundError {
    uia_model::uia_error(
        err.code().0.cast_unsigned(),
        operation,
        &err.message(),
        UIA_QUERY_TIMEOUT_MS,
    )
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

/// A caller-owned `VARIANT` (from `GetCachedPropertyValue`) released with `VariantClear`.
struct OwnedVariant(VARIANT);

impl Drop for OwnedVariant {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a VARIANT this wrapper exclusively owns (returned by an `[out]`
        // parameter or built from plain data); `VariantClear` frees its BSTR/SAFEARRAY/interface
        // payload exactly once and leaves it `VT_EMPTY`.
        let _ = unsafe { VariantClear(&raw mut self.0) };
    }
}

impl OwnedVariant {
    fn from_i32(value: i32) -> Self {
        let mut variant = VARIANT::default();
        // SAFETY: `VARIANT::default()` is all-zero (`VT_EMPTY`); writing the `vt` tag and the
        // matching `lVal` member of the plain-data union produces a valid `VT_I4` VARIANT with
        // nothing to free.
        unsafe {
            let inner = &mut *variant.Anonymous.Anonymous;
            inner.vt = VT_I4;
            inner.Anonymous.lVal = value;
        }
        Self(variant)
    }

    fn vt(&self) -> u16 {
        // SAFETY: every VARIANT, including the zeroed default, starts with a valid `vt` tag;
        // reading it through the union does not depend on which member is active.
        unsafe { self.0.Anonymous.Anonymous.vt.0 }
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
            if SafeArrayGetDim(array) != 1 {
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

/// Everything the worker thread keeps between requests. Never leaves the worker thread.
struct UiaSession {
    automation: IUIAutomation,
    flavor: &'static str,
    edit_or_document: IUIAutomationCondition,
    true_condition: IUIAutomationCondition,
    /// Element-scoped cache for top-level windows: process id.
    window_request: IUIAutomationCacheRequest,
    /// Element-scoped cache for `Edit`/`Document` descendants: type, name, bounds, value.
    locate_request: IUIAutomationCacheRequest,
    /// Subtree cache over the control view (cache-only elements) for the node walk.
    tree_request: IUIAutomationCacheRequest,
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

impl UiaSession {
    fn new() -> std::result::Result<Self, String> {
        let (automation, flavor) = Self::create_automation()?;
        let fail = |what: &str, err: &windows::core::Error| format!("{what}: {}", describe(err));

        match automation.cast::<IUIAutomation2>() {
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
            }
            Err(err) => tracing::warn!(
                error = %describe(&err),
                "IUIAutomation2 unavailable; UIAutomation calls use the system default timeouts"
            ),
        }

        let edit = OwnedVariant::from_i32(UIA_EditControlTypeId.0);
        let document = OwnedVariant::from_i32(UIA_DocumentControlTypeId.0);
        // SAFETY: COM factory methods on a live interface pointer owned by this thread. The
        // VARIANT arguments are borrowed for the call only (the callee copies `[in]` VARIANTs);
        // each result is a new owned reference released on drop.
        let conditions = unsafe {
            automation
                .CreatePropertyCondition(UIA_ControlTypePropertyId, &edit.0)
                .and_then(|edit_cond| {
                    let doc_cond = automation
                        .CreatePropertyCondition(UIA_ControlTypePropertyId, &document.0)?;
                    automation.CreateOrCondition(&edit_cond, &doc_cond)
                })
                .and_then(|or| Ok((or, automation.CreateTrueCondition()?)))
        };
        let (edit_or_document, true_condition) =
            conditions.map_err(|err| fail("creating UIAutomation conditions", &err))?;

        let window_request =
            Self::cache_request(&automation, &[UIA_ProcessIdPropertyId], None, false)
                .map_err(|err| fail("creating window cache request", &err))?;
        let locate_request = Self::cache_request(
            &automation,
            &[
                UIA_ControlTypePropertyId,
                UIA_NamePropertyId,
                UIA_BoundingRectanglePropertyId,
                UIA_IsValuePatternAvailablePropertyId,
                UIA_ValueValuePropertyId,
            ],
            None,
            false,
        )
        .map_err(|err| fail("creating locate cache request", &err))?;
        let tree_request =
            Self::cache_request(&automation, &TREE_PROPERTIES, Some(TreeScope_Subtree), true)
                .map_err(|err| fail("creating tree cache request", &err))?;

        Ok(Self {
            automation,
            flavor,
            edit_or_document,
            true_condition,
            window_request,
            locate_request,
            tree_request,
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

    fn cache_request(
        automation: &IUIAutomation,
        properties: &[UIA_PROPERTY_ID],
        scope: Option<TreeScope>,
        cache_only: bool,
    ) -> windows::core::Result<IUIAutomationCacheRequest> {
        // SAFETY: COM methods on live interface pointers owned by this thread, taking plain
        // values. The default tree filter (the control view) is kept, matching the PowerShell
        // walker's `ControlViewWalker` and .NET's default cache request.
        unsafe {
            let request = automation.CreateCacheRequest()?;
            for &property in properties {
                request.AddProperty(property)?;
            }
            if let Some(scope) = scope {
                request.SetTreeScope(scope)?;
            }
            if cache_only {
                request.SetAutomationElementMode(AutomationElementMode_None)?;
            }
            Ok(request)
        }
    }

    /// Takes a snapshot, retrying once when an element went stale mid-query (navigation or a
    /// tab switch), then mapping errors to [`WayboundError`].
    fn snapshot_with_retry(&self, pid: Option<i32>, limit: usize) -> Result<RawUiaSnapshot> {
        match self.snapshot(pid, limit) {
            Ok(raw) => Ok(raw),
            Err((err, _))
                if uia_model::classify_hresult(err.code().0.cast_unsigned())
                    == uia_model::HresultClass::Stale =>
            {
                tracing::debug!(error = %describe(&err), "stale UIAutomation element; retrying once");
                self.snapshot(pid, limit)
                    .map_err(|(err, operation)| to_waybound(&err, operation))
            }
            Err((err, operation)) => Err(to_waybound(&err, operation)),
        }
    }

    fn snapshot(
        &self,
        pid: Option<i32>,
        limit: usize,
    ) -> std::result::Result<RawUiaSnapshot, (windows::core::Error, &'static str)> {
        // SAFETY: COM method on a live interface pointer; returns an owned reference.
        let root =
            unsafe { self.automation.GetRootElement() }.map_err(|err| (err, "GetRootElement"))?;
        let window = pid
            .map_or_else(
                || self.browser_window(&root),
                |pid| self.window_for_pid(&root, pid),
            )
            .map_err(|err| (err, "window lookup"))?;
        let Some(window) = window else {
            return Ok(RawUiaSnapshot::default());
        };

        let (mut current_url, web_root, mut viewport) = self.locate_chrome_parts(&window);
        let base = web_root.unwrap_or(window);

        // SAFETY: COM method on a live interface pointer with a live cache request; returns an
        // owned, cache-populated element.
        let cached_root = unsafe { base.BuildUpdatedCache(&self.tree_request) }
            .map_err(|err| (err, "tree snapshot (BuildUpdatedCache)"))?;

        let (nodes, truncated) = bfs_limited(cached_root, limit, |element| {
            let (node, ct) = match read_node(&element) {
                Ok(read) => read,
                Err(err) => {
                    tracing::trace!(error = %describe(&err), "skipping unreadable UIA node");
                    return None;
                }
            };
            if current_url.is_none()
                && ct == control_type::EDIT
                && let Some(value) = node.value.as_deref()
                && is_address_bar_candidate(node.name.as_deref(), value)
            {
                current_url = Some(value.to_owned());
            }
            if viewport.is_none()
                && ct == control_type::DOCUMENT
                && node.width > 0.0
                && node.height > 0.0
            {
                viewport = Some(RawBounds {
                    x: node.x,
                    y: node.y,
                    width: node.width,
                    height: node.height,
                });
            }
            // SAFETY: COM method on a live, cache-populated element; reads the local cache.
            let children = elements_of(unsafe { element.GetCachedChildren() }).unwrap_or_default();
            Some((node, children))
        });

        Ok(RawUiaSnapshot {
            nodes,
            truncated,
            current_url,
            viewport_bounds: viewport,
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
        let names: Vec<Option<String>> = windows
            .iter()
            .map(|window| {
                // SAFETY: COM method on a live element, reading the cache built above.
                unsafe { window.CachedProcessId() }
                    .ok()
                    .and_then(process_name)
            })
            .collect();
        Ok(pick_browser_window(&names).and_then(|idx| windows.into_iter().nth(idx)))
    }

    /// Finds the omnibox URL and the web content root among the window's descendants, like
    /// the PowerShell walker's two `FindAll` passes (in one call here). Failures are logged
    /// and ignored, as the walker's `try {} catch {}` did.
    fn locate_chrome_parts(
        &self,
        window: &IUIAutomationElement,
    ) -> (
        Option<String>,
        Option<IUIAutomationElement>,
        Option<RawBounds>,
    ) {
        // SAFETY: COM method on a live interface pointer with live condition and cache request;
        // returns an owned array.
        let found = elements_of(unsafe {
            window.FindAllBuildCache(
                TreeScope_Descendants,
                &self.edit_or_document,
                &self.locate_request,
            )
        });
        let elements = match found {
            Ok(elements) => elements,
            Err(err) => {
                tracing::debug!(error = %describe(&err), "UIAutomation Edit/Document search failed");
                return (None, None, None);
            }
        };

        let mut current_url = None;
        let mut documents = Vec::new();
        let mut document_rects = Vec::new();
        for element in elements {
            let Ok((ct, name, rect)) = cached_basics(&element) else {
                continue;
            };
            if ct == control_type::EDIT {
                if current_url.is_none()
                    && let Some(value) = cached_value(&element)
                    && is_address_bar_candidate(Some(&name), &value)
                {
                    current_url = Some(value);
                }
            } else if ct == control_type::DOCUMENT {
                documents.push(element);
                document_rects.push(rect);
            }
        }

        match select_web_root(&document_rects) {
            Some((idx, bounds)) => (
                current_url,
                documents.into_iter().nth(idx),
                bounds.map(|b| RawBounds {
                    x: b.x,
                    y: b.y,
                    width: b.width,
                    height: b.height,
                }),
            ),
            None => (current_url, None, None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercises COM initialization, a cache request, cached properties and the runtime-id
    /// SAFEARRAY decoding against the desktop root and its direct children (bounded: no
    /// subtree fetch). Runs on its own thread so a stuck desktop fails the test instead of
    /// hanging it.
    #[test]
    fn desktop_root_snapshot_reads_cached_properties() {
        let (tx, rx) = mpsc::sync_channel(1);
        let _ = std::thread::spawn(move || {
            let result = (|| -> std::result::Result<Vec<RawUiaNode>, String> {
                let _apartment = ComApartment::init_mta().map_err(|e| describe(&e))?;
                let session = UiaSession::new()?;
                let request = UiaSession::cache_request(
                    &session.automation,
                    &TREE_PROPERTIES,
                    Some(TreeScope(3)), // TreeScope_Element | TreeScope_Children
                    true,
                )
                .map_err(|e| describe(&e))?;
                // SAFETY: COM methods on live interface pointers owned by this thread.
                let root = unsafe {
                    session
                        .automation
                        .GetRootElement()
                        .and_then(|r| r.BuildUpdatedCache(&request))
                }
                .map_err(|e| describe(&e))?;
                let (node, _) = read_node(&root).map_err(|e| describe(&e))?;
                Ok(vec![node])
            })();
            let _ = tx.send(result);
        });
        match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(Ok(nodes)) => {
                let root = nodes.first();
                // The desktop is an HWND-based element, whose runtime id is `[42, hwnd]`.
                assert!(
                    root.and_then(|n| n.id.as_deref())
                        .is_some_and(|id| id.starts_with("42-")),
                    "desktop root runtime id: {root:?}"
                );
                assert_eq!(
                    root.map(|n| n.control_type.as_str()),
                    Some("ControlType.Pane")
                );
            }
            Ok(Err(reason)) => assert_eq!(reason, "", "native UIAutomation failed"),
            Err(_) => assert_eq!(0, 1, "native UIAutomation desktop query hung for 30s"),
        }
    }

    /// Runs the real worker end to end (thread start, COM init, condition with a VARIANT,
    /// `FindFirst` with no match, top-level window enumeration with process names). Bounded
    /// by the worker's own 10 s channel timeout.
    #[test]
    fn worker_answers_without_a_browser() {
        let own_pid = i32::try_from(std::process::id()).unwrap_or(i32::MAX);
        for pid in [Some(own_pid), None] {
            match query(pid, 10) {
                NativeOutcome::Done(Ok(raw)) => assert!(raw.nodes.len() <= 10, "{pid:?}"),
                NativeOutcome::Done(Err(err)) => assert_eq!(format!("{err}"), "", "{pid:?}"),
                NativeOutcome::Unavailable(reason) => {
                    assert_eq!(reason, "", "COM unavailable");
                }
            }
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

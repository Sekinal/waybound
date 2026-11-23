//! Pure-Rust headless Wayland server implementation (`#[cfg(unix)]`).

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use tracing::{debug, trace, warn};
use waybound_core::{InputEvent, KeyModifier, MouseButton, Point, Result, WayboundError};
use wayland_protocols::xdg::shell::server::{
    xdg_popup::{self, XdgPopup},
    xdg_positioner::{self, XdgPositioner},
    xdg_surface::{self, XdgSurface},
    xdg_toplevel::{self, XdgToplevel},
    xdg_wm_base::{self, XdgWmBase},
};
use wayland_server::backend::{ClientData, ClientId, DisconnectReason};
use wayland_server::protocol::{
    wl_buffer::{self, WlBuffer},
    wl_callback::{self, WlCallback},
    wl_compositor::{self, WlCompositor},
    wl_data_device::{self, WlDataDevice},
    wl_data_device_manager::{self, WlDataDeviceManager},
    wl_data_offer::{self, WlDataOffer},
    wl_data_source::{self, WlDataSource},
    wl_keyboard::{self, WlKeyboard},
    wl_output::{self, WlOutput},
    wl_pointer::{self, WlPointer},
    wl_region::{self, WlRegion},
    wl_seat::{self, WlSeat},
    wl_shm::{self, WlShm},
    wl_shm_pool::{self, WlShmPool},
    wl_subcompositor::{self, WlSubcompositor},
    wl_subsurface::{self, WlSubsurface},
    wl_surface::{self, WlSurface},
    wl_touch::{self, WlTouch},
};
use wayland_server::{
    Client, DataInit, Dispatch, Display, DisplayHandle, GlobalDispatch, ListeningSocket, New,
    Resource, WEnum,
};

use crate::buffer::{argb8888_to_rgba, encode_rgba_png, validate_buffer_bounds, xrgb8888_to_rgba};
use crate::config::{CompositorConfig, WindowInfo};
use crate::keymap::{
    EVDEV_LEFTSHIFT, XKB_US_KEYMAP, keycode_to_evdev, modifier_to_evdev, modifier_xkb_mask,
};

/// Linux `evdev` button code for `BTN_LEFT`.
const BTN_LEFT: u32 = 0x110;
/// Linux `evdev` button code for `BTN_RIGHT`.
const BTN_RIGHT: u32 = 0x111;
/// Linux `evdev` button code for `BTN_MIDDLE`.
const BTN_MIDDLE: u32 = 0x112;

/// Maximum sleep duration allowed for synthetic key/click hold durations.
const MAX_HOLD_MS: u64 = 5_000;

/// Commands sent from [`ServerHandle`] to the compositor background thread.
pub enum Command {
    ListWindows {
        reply: Sender<Vec<WindowInfo>>,
    },
    ScreenshotPng {
        window_id: Option<u64>,
        reply: Sender<Result<Vec<u8>>>,
    },
    DispatchInput {
        window_id: Option<u64>,
        event: InputEvent,
        reply: Sender<Result<()>>,
    },
    CloseWindow {
        window_id: u64,
        reply: Sender<Result<()>>,
    },
    Shutdown,
}

/// Running compositor thread handle and communication channels.
pub struct ServerHandle {
    socket_name: String,
    runtime_dir: PathBuf,
    socket_path: PathBuf,
    cmd_tx: Sender<Command>,
    wake_tx: UnixStream,
    thread: Option<JoinHandle<()>>,
}

impl ServerHandle {
    pub fn start(config: CompositorConfig) -> Result<Self> {
        config.validate()?;

        let runtime_dir = resolve_runtime_dir(config.runtime_dir.as_deref());
        std::fs::create_dir_all(&runtime_dir)?;

        let socket_name = config
            .socket_name
            .clone()
            .unwrap_or_else(generate_socket_name);
        let socket_path = runtime_dir.join(&socket_name);

        let listener = ListeningSocket::bind_absolute(socket_path.clone()).map_err(|err| {
            WayboundError::Io(std::io::Error::other(format!(
                "failed to bind Wayland socket {}: {err}",
                socket_path.display()
            )))
        })?;

        let (wake_tx, wake_rx) = UnixStream::pair()?;
        wake_tx.set_nonblocking(true)?;
        wake_rx.set_nonblocking(true)?;

        let (cmd_tx, cmd_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<()>>();

        let thread_config = config;
        let thread = thread::Builder::new()
            .name("waybound-compositor".to_owned())
            .spawn(move || {
                run_event_loop(thread_config, &listener, wake_rx, &cmd_rx, &ready_tx);
            })
            .map_err(WayboundError::Io)?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                socket_name,
                runtime_dir,
                socket_path,
                cmd_tx,
                wake_tx,
                thread: Some(thread),
            }),
            Ok(Err(err)) => {
                let _ = thread.join();
                Err(err)
            }
            Err(_) => {
                let _ = thread.join();
                Err(WayboundError::BackendUnavailable {
                    backend: "wayland-compositor".to_owned(),
                    reason: "compositor thread exited before becoming ready".to_owned(),
                })
            }
        }
    }

    pub(crate) fn socket_name(&self) -> &str {
        &self.socket_name
    }

    pub(crate) fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub(crate) fn windows(&self) -> Result<Vec<WindowInfo>> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.send_command(Command::ListWindows { reply: reply_tx })?;
        reply_rx.recv().map_err(|_| compositor_stopped_error())
    }

    pub(crate) fn screenshot_png(&self, window_id: Option<u64>) -> Result<Vec<u8>> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.send_command(Command::ScreenshotPng {
            window_id,
            reply: reply_tx,
        })?;
        reply_rx.recv().map_err(|_| compositor_stopped_error())?
    }

    pub(crate) fn dispatch_input(&self, window_id: Option<u64>, event: &InputEvent) -> Result<()> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.send_command(Command::DispatchInput {
            window_id,
            event: event.clone(),
            reply: reply_tx,
        })?;
        reply_rx.recv().map_err(|_| compositor_stopped_error())?
    }

    pub(crate) fn close_window(&self, window_id: u64) -> Result<()> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.send_command(Command::CloseWindow {
            window_id,
            reply: reply_tx,
        })?;
        reply_rx.recv().map_err(|_| compositor_stopped_error())?
    }

    fn send_command(&self, cmd: Command) -> Result<()> {
        self.cmd_tx
            .send(cmd)
            .map_err(|_| compositor_stopped_error())?;
        // Wake the poll loop; ignore WouldBlock if a wake byte is already queued.
        let mut wake = &self.wake_tx;
        let _ = wake.write(&[1_u8]);
        Ok(())
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        let _ = self.send_command(Command::Shutdown);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }
        let lock_path = PathBuf::from(format!("{}.lock", self.socket_path.display()));
        if lock_path.exists() {
            let _ = std::fs::remove_file(lock_path);
        }
    }
}

fn compositor_stopped_error() -> WayboundError {
    WayboundError::BackendUnavailable {
        backend: "wayland-compositor".to_owned(),
        reason: "compositor event loop is no longer running".to_owned(),
    }
}

fn resolve_runtime_dir(configured: Option<&Path>) -> PathBuf {
    if let Some(dir) = configured {
        return dir.to_path_buf();
    }
    if let Ok(env_dir) = std::env::var("XDG_RUNTIME_DIR")
        && !env_dir.is_empty()
    {
        return PathBuf::from(env_dir);
    }
    std::env::temp_dir()
}

fn generate_socket_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("waybound-wl-{}-{seq}", std::process::id())
}

/// Per-client user data required by `wayland-server`.
#[derive(Debug, Default)]
struct WayboundClientData;

impl ClientData for WayboundClientData {
    fn initialized(&self, client_id: ClientId) {
        debug!(?client_id, "wayland client connected");
    }

    fn disconnected(&self, client_id: ClientId, reason: DisconnectReason) {
        debug!(?client_id, ?reason, "wayland client disconnected");
    }
}

/// User data attached to `wl_shm_pool` resources.
#[derive(Debug, Clone, Copy)]
struct PoolData(u64);

/// User data attached to `wl_buffer` resources.
#[derive(Debug, Clone, Copy)]
struct BufferData(u64);

/// User data attached to `wl_surface` resources.
#[derive(Debug, Clone, Copy)]
struct SurfaceData(u64);

/// User data attached to `xdg_surface` resources.
#[derive(Debug, Clone, Copy)]
struct XdgSurfaceData(u64);

/// User data attached to `xdg_toplevel` resources.
#[derive(Debug, Clone, Copy)]
struct ToplevelData(u64);

/// User data attached to `xdg_popup` resources.
#[derive(Debug, Clone, Copy)]
struct PopupData {
    surface_id: u64,
}

struct ShmPoolBacking {
    file: File,
    size: AtomicU64,
}

struct ShmBuffer {
    pool: Arc<ShmPoolBacking>,
    offset: u64,
    width: u32,
    height: u32,
    stride: u32,
    format: wl_shm::Format,
}

struct CommittedFrame {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
}

enum PendingBuffer {
    Unchanged,
    Detach,
    Attach(WlBuffer),
}

struct SurfaceState {
    wl_surface: WlSurface,
    pending_buffer: PendingBuffer,
    pending_callbacks: Vec<WlCallback>,
    current_frame: Option<CommittedFrame>,
    toplevel_id: Option<u64>,
    parent_surface_id: Option<u64>,
    popup: Option<PopupState>,
}

struct PopupState {
    xdg_surface: XdgSurface,
    xdg_popup: XdgPopup,
    initial_configure_sent: bool,
}

struct WindowState {
    id: u64,
    surface_id: u64,
    client_id: Option<ClientId>,
    xdg_surface: XdgSurface,
    xdg_toplevel: XdgToplevel,
    title: String,
    app_id: String,
    width: u32,
    height: u32,
    has_buffer: bool,
    initial_configure_sent: bool,
}

struct CompositorState {
    config: CompositorConfig,
    start_instant: Instant,
    next_id: u64,
    next_serial: u32,
    pools: HashMap<u64, Arc<ShmPoolBacking>>,
    buffers: HashMap<u64, ShmBuffer>,
    surfaces: HashMap<u64, SurfaceState>,
    windows: HashMap<u64, WindowState>,
    window_order: Vec<u64>,
    pending_frame_callbacks: Vec<WlCallback>,
    client_outputs: HashMap<ClientId, Vec<WlOutput>>,
    client_pointers: HashMap<ClientId, Vec<WlPointer>>,
    client_keyboards: HashMap<ClientId, Vec<WlKeyboard>>,
    pointer_focus: Option<(ClientId, u64)>,
    keyboard_focus: Option<(ClientId, u64)>,
    last_pointer_pos: Point,
}

impl CompositorState {
    fn new(config: CompositorConfig) -> Self {
        Self {
            config,
            start_instant: Instant::now(),
            next_id: 1,
            next_serial: 1,
            pools: HashMap::new(),
            buffers: HashMap::new(),
            surfaces: HashMap::new(),
            windows: HashMap::new(),
            window_order: Vec::new(),
            pending_frame_callbacks: Vec::new(),
            client_outputs: HashMap::new(),
            client_pointers: HashMap::new(),
            client_keyboards: HashMap::new(),
            pointer_focus: None,
            keyboard_focus: None,
            last_pointer_pos: Point { x: 0.0, y: 0.0 },
        }
    }

    const fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    const fn next_serial(&mut self) -> u32 {
        let serial = self.next_serial;
        self.next_serial = self.next_serial.wrapping_add(1);
        serial
    }

    fn elapsed_ms(&self) -> u32 {
        let millis = self.start_instant.elapsed().as_millis();
        u32::try_from(millis % u128::from(u32::MAX)).unwrap_or(0)
    }

    fn list_windows(&self) -> Vec<WindowInfo> {
        self.window_order
            .iter()
            .filter_map(|id| self.windows.get(id))
            .map(|win| WindowInfo {
                id: win.id,
                title: win.title.clone(),
                app_id: win.app_id.clone(),
                width: win.width,
                height: win.height,
                has_buffer: win.has_buffer,
            })
            .collect()
    }

    fn close_window(&self, window_id: u64) -> Result<()> {
        let win = self
            .windows
            .get(&window_id)
            .ok_or_else(|| WayboundError::ElementNotFound {
                query: format!("window id {window_id}"),
            })?;
        if win.xdg_toplevel.is_alive() {
            win.xdg_toplevel.close();
        }
        Ok(())
    }

    fn remove_window(&mut self, window_id: u64) {
        if let Some(win) = self.windows.remove(&window_id) {
            if let Some(surface) = self.surfaces.get_mut(&win.surface_id)
                && surface.toplevel_id == Some(window_id)
            {
                surface.toplevel_id = None;
            }
            if self
                .pointer_focus
                .as_ref()
                .is_some_and(|(_, sid)| *sid == win.surface_id)
            {
                self.pointer_focus = None;
            }
            if self
                .keyboard_focus
                .as_ref()
                .is_some_and(|(_, sid)| *sid == win.surface_id)
            {
                self.keyboard_focus = None;
            }
        }
        self.window_order.retain(|&id| id != window_id);
    }

    fn resolve_target_window_id(&self, requested: Option<u64>) -> Result<u64> {
        if let Some(id) = requested {
            if self.windows.contains_key(&id) {
                return Ok(id);
            }
            return Err(WayboundError::ElementNotFound {
                query: format!("window id {id}"),
            });
        }
        // Prefer the most recently created window that has committed a buffer; otherwise the latest window.
        if let Some(&id) = self
            .window_order
            .iter()
            .rev()
            .find(|id| self.windows.get(id).is_some_and(|win| win.has_buffer))
        {
            return Ok(id);
        }
        self.window_order
            .last()
            .copied()
            .ok_or_else(|| WayboundError::ElementNotFound {
                query: "any xdg_toplevel window".to_owned(),
            })
    }

    fn root_toplevel_id(&self, surface_id: u64) -> Option<u64> {
        let mut current = Some(surface_id);
        for _ in 0..16 {
            let sid = current?;
            let surface = self.surfaces.get(&sid)?;
            if let Some(tid) = surface.toplevel_id {
                return Some(tid);
            }
            current = surface.parent_surface_id;
        }
        None
    }

    fn best_window_frame(&self, window_id: u64) -> Option<&CommittedFrame> {
        let mut best: Option<&CommittedFrame> = None;
        let mut best_area: u64 = 0;
        for (&sid, surface) in &self.surfaces {
            if self.root_toplevel_id(sid) == Some(window_id)
                && let Some(ref frame) = surface.current_frame
            {
                let area = u64::from(frame.width).saturating_mul(u64::from(frame.height));
                if area >= best_area {
                    best_area = area;
                    best = Some(frame);
                }
            }
        }
        best
    }

    fn screenshot_png(&self, window_id: Option<u64>) -> Result<Vec<u8>> {
        let target_id = self.resolve_target_window_id(window_id)?;
        let _win = self
            .windows
            .get(&target_id)
            .ok_or_else(|| WayboundError::ElementNotFound {
                query: format!("window id {target_id}"),
            })?;
        let frame = self
            .best_window_frame(target_id)
            .ok_or_else(|| WayboundError::Transient {
                backend: "wayland-compositor".to_owned(),
                reason: format!("window {target_id} has not committed a pixel buffer yet"),
            })?;
        encode_rgba_png(&frame.rgba, frame.width, frame.height)
    }

    fn fire_frame_callbacks(&mut self) {
        if self.pending_frame_callbacks.is_empty() {
            return;
        }
        let now_ms = self.elapsed_ms();
        let callbacks = std::mem::take(&mut self.pending_frame_callbacks);
        for cb in callbacks {
            if cb.is_alive() {
                cb.done(now_ms);
            }
        }
    }

    fn snapshot_buffer(&self, wl_buffer: &WlBuffer) -> Option<CommittedFrame> {
        let buf_data = wl_buffer.data::<BufferData>()?;
        let buf = self.buffers.get(&buf_data.0)?;
        let pool_size = buf.pool.size.load(Ordering::Relaxed);
        let byte_len =
            validate_buffer_bounds(buf.offset, buf.width, buf.height, buf.stride, pool_size)
                .ok()?;

        let mut raw = vec![0_u8; byte_len];
        if let Err(err) = buf.pool.file.read_exact_at(&mut raw, buf.offset) {
            warn!(?err, "failed to read wl_shm buffer bytes");
            return None;
        }

        let rgba = match buf.format {
            wl_shm::Format::Argb8888 => {
                argb8888_to_rgba(&raw, buf.width, buf.height, buf.stride).ok()?
            }
            wl_shm::Format::Xrgb8888 => {
                xrgb8888_to_rgba(&raw, buf.width, buf.height, buf.stride).ok()?
            }
            other => {
                warn!(?other, "unsupported wl_shm buffer format");
                return None;
            }
        };

        Some(CommittedFrame {
            width: buf.width,
            height: buf.height,
            rgba,
        })
    }

    fn send_initial_toplevel_configure(&mut self, window_id: u64) {
        let Some(win) = self.windows.get_mut(&window_id) else {
            return;
        };
        if win.initial_configure_sent {
            return;
        }
        win.initial_configure_sent = true;
        let surface_id = win.surface_id;
        let client_id = win.client_id.clone();
        let xdg_toplevel = win.xdg_toplevel.clone();
        let xdg_surface = win.xdg_surface.clone();

        // Notify the surface which output it resides on so clients report 1920x1080 screen geometry.
        if let Some(cid) = client_id
            && let Some(outputs) = self.client_outputs.get(&cid)
            && let Some(surface) = self.surfaces.get(&surface_id)
        {
            for output in outputs {
                if output.is_alive() {
                    surface.wl_surface.enter(output);
                }
            }
        }

        let width_i32 = i32::try_from(self.config.width).unwrap_or(1920);
        let height_i32 = i32::try_from(self.config.height).unwrap_or(1080);
        let activated = (xdg_toplevel::State::Activated as u32)
            .to_ne_bytes()
            .to_vec();
        let serial = self.next_serial();
        if xdg_toplevel.version() >= 4 {
            xdg_toplevel.configure_bounds(width_i32, height_i32);
        }
        xdg_toplevel.configure(width_i32, height_i32, activated);
        xdg_surface.configure(serial);
        debug!(
            window_id,
            serial, width_i32, height_i32, "sent initial xdg_toplevel configure"
        );
    }

    fn dispatch_input(
        &mut self,
        window_id: Option<u64>,
        event: &InputEvent,
        display: &mut Display<Self>,
    ) -> Result<()> {
        let target_id = self.resolve_target_window_id(window_id)?;
        let (surface_id, client_id) = {
            let win =
                self.windows
                    .get(&target_id)
                    .ok_or_else(|| WayboundError::ElementNotFound {
                        query: format!("window id {target_id}"),
                    })?;
            (win.surface_id, win.client_id.clone())
        };
        let Some(cid) = client_id else {
            return Err(WayboundError::InvalidElementState {
                detail: format!("window {target_id} has no associated Wayland client"),
            });
        };

        match event {
            InputEvent::PointerMove { to } | InputEvent::PointerDrag { to, .. } => {
                self.dispatch_pointer_move(&cid, surface_id, *to);
                Ok(())
            }
            InputEvent::MouseDown { button } => {
                self.dispatch_mouse_button(
                    &cid,
                    surface_id,
                    *button,
                    wl_pointer::ButtonState::Pressed,
                );
                Ok(())
            }
            InputEvent::MouseUp { button } => {
                self.dispatch_mouse_button(
                    &cid,
                    surface_id,
                    *button,
                    wl_pointer::ButtonState::Released,
                );
                Ok(())
            }
            InputEvent::MouseClick { button, hold_ms } => {
                self.dispatch_mouse_button(
                    &cid,
                    surface_id,
                    *button,
                    wl_pointer::ButtonState::Pressed,
                );
                if *hold_ms > 0 {
                    let _ = display.flush_clients();
                    thread::sleep(Duration::from_millis((*hold_ms).min(MAX_HOLD_MS)));
                }
                self.dispatch_mouse_button(
                    &cid,
                    surface_id,
                    *button,
                    wl_pointer::ButtonState::Released,
                );
                Ok(())
            }
            InputEvent::Scroll { delta_x, delta_y } => {
                self.dispatch_scroll(&cid, surface_id, *delta_x, *delta_y);
                Ok(())
            }
            InputEvent::KeyPress {
                key,
                modifiers,
                hold_ms,
            } => self.dispatch_key_press(&cid, surface_id, key, modifiers, *hold_ms, display),
        }
    }

    fn ensure_pointer_focus(&mut self, cid: &ClientId, surface_id: u64, pos: Point) {
        let pointers: Vec<WlPointer> = self
            .client_pointers
            .get(cid)
            .map(|list| list.iter().filter(|p| p.is_alive()).cloned().collect())
            .unwrap_or_default();
        if pointers.is_empty() {
            return;
        }
        if self
            .pointer_focus
            .as_ref()
            .is_some_and(|(old_cid, old_sid)| old_cid == cid && *old_sid == surface_id)
        {
            return;
        }
        if let Some((old_cid, old_id)) = self.pointer_focus.take()
            && let Some(old_surface) = self.surfaces.get(&old_id).map(|s| s.wl_surface.clone())
            && old_surface.is_alive()
        {
            let old_pointers: Vec<WlPointer> = self
                .client_pointers
                .get(&old_cid)
                .map(|list| list.iter().filter(|p| p.is_alive()).cloned().collect())
                .unwrap_or_default();
            if !old_pointers.is_empty() {
                let serial = self.next_serial();
                for ptr in &old_pointers {
                    ptr.leave(serial, &old_surface);
                    if ptr.version() >= 5 {
                        ptr.frame();
                    }
                }
            }
        }
        if let Some(new_surface) = self.surfaces.get(&surface_id).map(|s| s.wl_surface.clone())
            && new_surface.is_alive()
        {
            let serial = self.next_serial();
            for ptr in &pointers {
                ptr.enter(serial, &new_surface, pos.x, pos.y);
                if ptr.version() >= 5 {
                    ptr.frame();
                }
            }
            self.pointer_focus = Some((cid.clone(), surface_id));
        }
    }

    fn dispatch_pointer_move(&mut self, cid: &ClientId, surface_id: u64, to: Point) {
        self.last_pointer_pos = to;
        self.ensure_pointer_focus(cid, surface_id, to);
        let time_ms = self.elapsed_ms();
        if let Some(pointers) = self.client_pointers.get(cid) {
            for ptr in pointers {
                if ptr.is_alive() {
                    ptr.motion(time_ms, to.x, to.y);
                    if ptr.version() >= 5 {
                        ptr.frame();
                    }
                }
            }
        }
    }

    fn dispatch_mouse_button(
        &mut self,
        cid: &ClientId,
        surface_id: u64,
        button: MouseButton,
        state: wl_pointer::ButtonState,
    ) {
        let pos = self.last_pointer_pos;
        self.ensure_pointer_focus(cid, surface_id, pos);
        let btn_code = match button {
            MouseButton::Left => BTN_LEFT,
            MouseButton::Right => BTN_RIGHT,
            MouseButton::Middle => BTN_MIDDLE,
        };
        let serial = self.next_serial();
        let time_ms = self.elapsed_ms();
        if let Some(pointers) = self.client_pointers.get(cid) {
            for ptr in pointers {
                if ptr.is_alive() {
                    ptr.button(serial, time_ms, btn_code, state);
                    if ptr.version() >= 5 {
                        ptr.frame();
                    }
                }
            }
        }
    }

    fn dispatch_scroll(&mut self, cid: &ClientId, surface_id: u64, delta_x: f64, delta_y: f64) {
        let pos = self.last_pointer_pos;
        self.ensure_pointer_focus(cid, surface_id, pos);
        let time_ms = self.elapsed_ms();
        if let Some(pointers) = self.client_pointers.get(cid) {
            for ptr in pointers {
                if ptr.is_alive() {
                    if delta_y != 0.0 {
                        ptr.axis(time_ms, wl_pointer::Axis::VerticalScroll, delta_y);
                    }
                    if delta_x != 0.0 {
                        ptr.axis(time_ms, wl_pointer::Axis::HorizontalScroll, delta_x);
                    }
                    if ptr.version() >= 5 {
                        ptr.frame();
                    }
                }
            }
        }
    }

    fn ensure_keyboard_focus(&mut self, cid: &ClientId, surface_id: u64) -> Vec<WlKeyboard> {
        let keyboards: Vec<WlKeyboard> = self
            .client_keyboards
            .get(cid)
            .map(|list| list.iter().filter(|k| k.is_alive()).cloned().collect())
            .unwrap_or_default();
        if keyboards.is_empty() {
            return keyboards;
        }
        let already_focused = self
            .keyboard_focus
            .as_ref()
            .is_some_and(|(old_cid, old_sid)| old_cid == cid && *old_sid == surface_id);
        if !already_focused {
            if let Some((old_cid, old_id)) = self.keyboard_focus.take()
                && let Some(old_surface) = self.surfaces.get(&old_id).map(|s| s.wl_surface.clone())
                && old_surface.is_alive()
            {
                let old_keyboards: Vec<WlKeyboard> = self
                    .client_keyboards
                    .get(&old_cid)
                    .map(|list| list.iter().filter(|k| k.is_alive()).cloned().collect())
                    .unwrap_or_default();
                if !old_keyboards.is_empty() {
                    let serial = self.next_serial();
                    for kb in &old_keyboards {
                        kb.leave(serial, &old_surface);
                    }
                }
            }
            if let Some(new_surface) = self.surfaces.get(&surface_id).map(|s| s.wl_surface.clone())
                && new_surface.is_alive()
            {
                let serial = self.next_serial();
                for kb in &keyboards {
                    kb.enter(serial, &new_surface, Vec::new());
                }
                self.keyboard_focus = Some((cid.clone(), surface_id));
            }
        }
        keyboards
    }

    fn dispatch_key_press(
        &mut self,
        cid: &ClientId,
        surface_id: u64,
        key: &waybound_core::KeyCode,
        modifiers: &[KeyModifier],
        hold_ms: u64,
        display: &mut Display<Self>,
    ) -> Result<()> {
        let Some((keycode, needs_shift)) = keycode_to_evdev(key) else {
            return Err(WayboundError::UnsupportedInput {
                backend: "wayland-compositor".to_owned(),
                reason: format!("key {key:?} is not mapped in the US-QWERTY keymap"),
            });
        };

        let keyboards = self.ensure_keyboard_focus(cid, surface_id);
        if keyboards.is_empty() {
            return Ok(());
        }

        let mut mod_codes: Vec<u32> = modifiers.iter().map(|m| modifier_to_evdev(*m)).collect();
        if needs_shift && !mod_codes.contains(&EVDEV_LEFTSHIFT) {
            mod_codes.push(EVDEV_LEFTSHIFT);
        }
        let mod_mask = modifier_xkb_mask(modifiers, needs_shift);

        // Press modifiers
        for &mcode in &mod_codes {
            let serial = self.next_serial();
            let time_ms = self.elapsed_ms();
            for kb in &keyboards {
                kb.key(serial, time_ms, mcode, wl_keyboard::KeyState::Pressed);
            }
        }
        if mod_mask != 0 {
            let serial = self.next_serial();
            for kb in &keyboards {
                kb.modifiers(serial, mod_mask, 0, 0, 0);
            }
        }

        // Press key
        let press_serial = self.next_serial();
        let press_time = self.elapsed_ms();
        for kb in &keyboards {
            kb.key(
                press_serial,
                press_time,
                keycode,
                wl_keyboard::KeyState::Pressed,
            );
        }

        if hold_ms > 0 {
            let _ = display.flush_clients();
            thread::sleep(Duration::from_millis(hold_ms.min(MAX_HOLD_MS)));
        }

        // Release key
        let release_serial = self.next_serial();
        let release_time = self.elapsed_ms();
        for kb in &keyboards {
            kb.key(
                release_serial,
                release_time,
                keycode,
                wl_keyboard::KeyState::Released,
            );
        }

        // Release modifiers
        if mod_mask != 0 {
            let serial = self.next_serial();
            for kb in &keyboards {
                kb.modifiers(serial, 0, 0, 0, 0);
            }
        }
        for &mcode in mod_codes.iter().rev() {
            let serial = self.next_serial();
            let time_ms = self.elapsed_ms();
            for kb in &keyboards {
                kb.key(serial, time_ms, mcode, wl_keyboard::KeyState::Released);
            }
        }

        Ok(())
    }
    fn destroy_surface(&mut self, surface_id: u64) {
        if let Some(removed) = self.surfaces.remove(&surface_id)
            && let Some(window_id) = removed.toplevel_id
        {
            self.remove_window(window_id);
        }
        if self
            .pointer_focus
            .as_ref()
            .is_some_and(|(_, sid)| *sid == surface_id)
        {
            self.pointer_focus = None;
        }
        if self
            .keyboard_focus
            .as_ref()
            .is_some_and(|(_, sid)| *sid == surface_id)
        {
            self.keyboard_focus = None;
        }
    }

    fn process_commands(
        &mut self,
        cmd_rx: &Receiver<Command>,
        display: &mut Display<Self>,
    ) -> bool {
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                Command::ListWindows { reply } => {
                    let _ = reply.send(self.list_windows());
                }
                Command::ScreenshotPng { window_id, reply } => {
                    let _ = reply.send(self.screenshot_png(window_id));
                }
                Command::DispatchInput {
                    window_id,
                    event,
                    reply,
                } => {
                    let res = self.dispatch_input(window_id, &event, display);
                    let _ = reply.send(res);
                }
                Command::CloseWindow { window_id, reply } => {
                    let _ = reply.send(self.close_window(window_id));
                }
                Command::Shutdown => return true,
            }
        }
        false
    }
}

fn run_event_loop(
    config: CompositorConfig,
    listener: &ListeningSocket,
    mut wake_rx: UnixStream,
    cmd_rx: &Receiver<Command>,
    ready_tx: &Sender<Result<()>>,
) {
    let mut display: Display<CompositorState> = match Display::new() {
        Ok(d) => d,
        Err(err) => {
            let _ = ready_tx.send(Err(WayboundError::Io(std::io::Error::other(err))));
            return;
        }
    };

    let dh = display.handle();
    let _compositor_global = dh.create_global::<CompositorState, WlCompositor, _>(5, ());
    let _subcompositor_global = dh.create_global::<CompositorState, WlSubcompositor, _>(1, ());
    let _shm_global = dh.create_global::<CompositorState, WlShm, _>(1, ());
    let _output_global = dh.create_global::<CompositorState, WlOutput, _>(4, ());
    let _wm_base_global = dh.create_global::<CompositorState, XdgWmBase, _>(5, ());
    let _seat_global = dh.create_global::<CompositorState, WlSeat, _>(7, ());
    let _data_dev_mgr_global = dh.create_global::<CompositorState, WlDataDeviceManager, _>(3, ());

    let frame_interval_ns = 1_000_000_000_000_u64
        .checked_div(u64::from(config.refresh_mhz))
        .unwrap_or(16_666_667)
        .max(1_000_000);
    let frame_interval = Duration::from_nanos(frame_interval_ns);

    let mut state = CompositorState::new(config);
    let _ = ready_tx.send(Ok(()));

    let mut next_frame_tick = Instant::now() + frame_interval;
    let mut wake_buf = [0_u8; 64];

    loop {
        // 1. Accept any pending Wayland client connections.
        loop {
            match listener.accept() {
                Ok(Some(stream)) => {
                    if let Err(err) = display
                        .handle()
                        .insert_client(stream, Arc::new(WayboundClientData))
                    {
                        warn!(?err, "failed to insert Wayland client");
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    warn!(?err, "Wayland listener accept error");
                    break;
                }
            }
        }

        // 2. Process all queued control commands.
        if state.process_commands(cmd_rx, &mut display) {
            break;
        }

        // 3. Dispatch incoming Wayland protocol requests.
        if let Err(err) = display.dispatch_clients(&mut state) {
            warn!(?err, "Wayland dispatch_clients error");
        }

        // 4. Fire 60 Hz frame callbacks when due.
        let now = Instant::now();
        if now >= next_frame_tick {
            state.fire_frame_callbacks();
            next_frame_tick = now + frame_interval;
        }

        // 5. Flush outgoing Wayland events to all clients.
        if let Err(err) = display.flush_clients() {
            warn!(?err, "Wayland flush_clients error");
        }

        // 6. Wait for socket accept, client traffic, command wake-up, or next frame tick.
        let wait = next_frame_tick.saturating_duration_since(Instant::now());
        let timespec = Timespec {
            tv_sec: i64::try_from(wait.as_secs()).unwrap_or(0),
            tv_nsec: i64::from(wait.subsec_nanos()),
        };

        let display_poll_fd = display.backend().poll_fd();
        let mut poll_fds = [
            PollFd::new(&listener, PollFlags::IN),
            PollFd::new(&display_poll_fd, PollFlags::IN),
            PollFd::new(&wake_rx, PollFlags::IN),
        ];

        if let Err(err) = poll(&mut poll_fds, Some(&timespec)) {
            trace!(?err, "poll interrupted");
        }

        // Drain any wake bytes so the wake fd does not remain readable.
        loop {
            match wake_rx.read(&mut wake_buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GlobalDispatch & Dispatch implementations
// ---------------------------------------------------------------------------

impl GlobalDispatch<WlCompositor, ()> for CompositorState {
    fn bind(
        _state: &mut Self,
        _handle: &DisplayHandle,
        _client: &Client,
        resource: New<WlCompositor>,
        _global_data: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        let _ = data_init.init(resource, ());
    }
}

impl Dispatch<WlCompositor, ()> for CompositorState {
    fn request(
        state: &mut Self,
        _client: &Client,
        _resource: &WlCompositor,
        request: wl_compositor::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        match request {
            wl_compositor::Request::CreateSurface { id } => {
                let surface_id = state.alloc_id();
                let wl_surface = data_init.init(id, SurfaceData(surface_id));
                let _ = state.surfaces.insert(
                    surface_id,
                    SurfaceState {
                        wl_surface,
                        pending_buffer: PendingBuffer::Unchanged,
                        pending_callbacks: Vec::new(),
                        current_frame: None,
                        toplevel_id: None,
                        parent_surface_id: None,
                        popup: None,
                    },
                );
            }
            wl_compositor::Request::CreateRegion { id } => {
                let _ = data_init.init(id, ());
            }
            _ => {}
        }
    }
}

impl Dispatch<WlRegion, ()> for CompositorState {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &WlRegion,
        _request: wl_region::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
    }
}

impl GlobalDispatch<WlSubcompositor, ()> for CompositorState {
    fn bind(
        _state: &mut Self,
        _handle: &DisplayHandle,
        _client: &Client,
        resource: New<WlSubcompositor>,
        _global_data: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        let _ = data_init.init(resource, ());
    }
}

impl Dispatch<WlSubcompositor, ()> for CompositorState {
    fn request(
        state: &mut Self,
        _client: &Client,
        _resource: &WlSubcompositor,
        request: wl_subcompositor::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        if let wl_subcompositor::Request::GetSubsurface {
            id,
            surface,
            parent,
        } = request
        {
            if let (Some(child_data), Some(parent_data)) =
                (surface.data::<SurfaceData>(), parent.data::<SurfaceData>())
                && let Some(child_state) = state.surfaces.get_mut(&child_data.0)
            {
                child_state.parent_surface_id = Some(parent_data.0);
            }
            let _ = data_init.init(id, ());
        }
    }
}

impl Dispatch<WlSubsurface, ()> for CompositorState {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &WlSubsurface,
        _request: wl_subsurface::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
    }
}

impl Dispatch<WlCallback, ()> for CompositorState {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &WlCallback,
        _request: wl_callback::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
    }
}

impl Dispatch<WlSurface, SurfaceData> for CompositorState {
    fn request(
        state: &mut Self,
        _client: &Client,
        _resource: &WlSurface,
        request: wl_surface::Request,
        data: &SurfaceData,
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        let surface_id = data.0;
        match request {
            wl_surface::Request::Attach { buffer, .. } => {
                if let Some(surface) = state.surfaces.get_mut(&surface_id) {
                    surface.pending_buffer =
                        buffer.map_or(PendingBuffer::Detach, PendingBuffer::Attach);
                }
            }
            wl_surface::Request::Frame { callback } => {
                let cb = data_init.init(callback, ());
                if let Some(surface) = state.surfaces.get_mut(&surface_id) {
                    surface.pending_callbacks.push(cb);
                }
            }
            wl_surface::Request::Commit => {
                let (pending_buf, pending_cbs, toplevel_id, popup_needs_cfg) = {
                    let Some(surface) = state.surfaces.get_mut(&surface_id) else {
                        return;
                    };
                    let buf =
                        std::mem::replace(&mut surface.pending_buffer, PendingBuffer::Unchanged);
                    let cbs = std::mem::take(&mut surface.pending_callbacks);
                    let tl = surface.toplevel_id;
                    let popup_cfg = surface.popup.as_mut().and_then(|p| {
                        if p.initial_configure_sent {
                            None
                        } else {
                            p.initial_configure_sent = true;
                            Some((p.xdg_surface.clone(), p.xdg_popup.clone()))
                        }
                    });
                    (buf, cbs, tl, popup_cfg)
                };

                state.pending_frame_callbacks.extend(pending_cbs);

                if let Some(window_id) = toplevel_id {
                    state.send_initial_toplevel_configure(window_id);
                }

                if let Some((xdg_surface, xdg_popup)) = popup_needs_cfg {
                    let serial = state.next_serial();
                    xdg_popup.configure(0, 0, 200, 200);
                    xdg_surface.configure(serial);
                }

                match pending_buf {
                    PendingBuffer::Attach(wl_buffer) => {
                        let frame = state.snapshot_buffer(&wl_buffer);
                        // Release buffer immediately so the client can reuse it without stalling.
                        wl_buffer.release();

                        if let Some(frame) = frame {
                            let (fw, fh) = (frame.width, frame.height);
                            if let Some(surface) = state.surfaces.get_mut(&surface_id) {
                                surface.current_frame = Some(frame);
                            }
                            if let Some(window_id) = state.root_toplevel_id(surface_id)
                                && let Some(win) = state.windows.get_mut(&window_id)
                            {
                                let new_area = u64::from(fw).saturating_mul(u64::from(fh));
                                let cur_area =
                                    u64::from(win.width).saturating_mul(u64::from(win.height));
                                if !win.has_buffer || new_area >= cur_area {
                                    win.width = fw;
                                    win.height = fh;
                                }
                                win.has_buffer = true;
                            }
                        }
                    }
                    PendingBuffer::Detach => {
                        if let Some(surface) = state.surfaces.get_mut(&surface_id) {
                            surface.current_frame = None;
                        }
                        if let Some(window_id) = state.root_toplevel_id(surface_id) {
                            let still_has_frame = state.best_window_frame(window_id).is_some();
                            if let Some(win) = state.windows.get_mut(&window_id) {
                                win.has_buffer = still_has_frame;
                            }
                        }
                    }
                    PendingBuffer::Unchanged => {}
                }
            }
            wl_surface::Request::Destroy => {
                state.destroy_surface(surface_id);
            }
            _ => {}
        }
    }
}

impl GlobalDispatch<WlShm, ()> for CompositorState {
    fn bind(
        _state: &mut Self,
        _handle: &DisplayHandle,
        _client: &Client,
        resource: New<WlShm>,
        _global_data: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        let shm = data_init.init(resource, ());
        shm.format(wl_shm::Format::Argb8888);
        shm.format(wl_shm::Format::Xrgb8888);
    }
}

impl Dispatch<WlShm, ()> for CompositorState {
    fn request(
        state: &mut Self,
        _client: &Client,
        _resource: &WlShm,
        request: wl_shm::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        if let wl_shm::Request::CreatePool { id, fd, size } = request {
            let pool_id = state.alloc_id();
            let size_u64 = u64::try_from(size).unwrap_or(0);
            let _ = state.pools.insert(
                pool_id,
                Arc::new(ShmPoolBacking {
                    file: File::from(fd),
                    size: AtomicU64::new(size_u64),
                }),
            );
            let _ = data_init.init(id, PoolData(pool_id));
        }
    }
}

impl Dispatch<WlShmPool, PoolData> for CompositorState {
    fn request(
        state: &mut Self,
        _client: &Client,
        _resource: &WlShmPool,
        request: wl_shm_pool::Request,
        data: &PoolData,
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        let pool_id = data.0;
        match request {
            wl_shm_pool::Request::CreateBuffer {
                id,
                offset,
                width,
                height,
                stride,
                format,
            } => {
                let buf_id = state.alloc_id();
                let fmt = match format {
                    WEnum::Value(f) => f,
                    WEnum::Unknown(_) => wl_shm::Format::Argb8888,
                };
                if let Some(pool) = state.pools.get(&pool_id).cloned() {
                    let _ = state.buffers.insert(
                        buf_id,
                        ShmBuffer {
                            pool,
                            offset: u64::try_from(offset).unwrap_or(0),
                            width: u32::try_from(width).unwrap_or(0),
                            height: u32::try_from(height).unwrap_or(0),
                            stride: u32::try_from(stride).unwrap_or(0),
                            format: fmt,
                        },
                    );
                }
                let _ = data_init.init(id, BufferData(buf_id));
            }
            wl_shm_pool::Request::Resize { size } => {
                if let Ok(new_size) = u64::try_from(size)
                    && let Some(pool) = state.pools.get(&pool_id)
                {
                    let _ = pool.size.fetch_max(new_size, Ordering::Relaxed);
                }
            }
            wl_shm_pool::Request::Destroy => {
                let _ = state.pools.remove(&pool_id);
            }
            _ => {}
        }
    }
}

impl Dispatch<WlBuffer, BufferData> for CompositorState {
    fn request(
        state: &mut Self,
        _client: &Client,
        _resource: &WlBuffer,
        request: wl_buffer::Request,
        data: &BufferData,
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
        if matches!(request, wl_buffer::Request::Destroy) {
            let _ = state.buffers.remove(&data.0);
        }
    }
}

impl GlobalDispatch<WlOutput, ()> for CompositorState {
    fn bind(
        state: &mut Self,
        _handle: &DisplayHandle,
        client: &Client,
        resource: New<WlOutput>,
        _global_data: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        let output = data_init.init(resource, ());
        let width_i32 = i32::try_from(state.config.width).unwrap_or(1920);
        let height_i32 = i32::try_from(state.config.height).unwrap_or(1080);
        let refresh_i32 = i32::try_from(state.config.refresh_mhz).unwrap_or(60_000);
        // Approximate 96 DPI physical size in millimeters.
        let phys_w = i32::try_from(u64::from(state.config.width) * 254 / 960).unwrap_or(508);
        let phys_h = i32::try_from(u64::from(state.config.height) * 254 / 960).unwrap_or(286);

        output.geometry(
            0,
            0,
            phys_w,
            phys_h,
            wl_output::Subpixel::None,
            "waybound".to_owned(),
            "headless".to_owned(),
            wl_output::Transform::Normal,
        );
        output.mode(
            wl_output::Mode::Current | wl_output::Mode::Preferred,
            width_i32,
            height_i32,
            refresh_i32,
        );
        if output.version() >= 2 {
            output.scale(state.config.scale);
        }
        if output.version() >= 4 {
            output.name("WL-1".to_owned());
            output.description("Waybound Headless Output".to_owned());
        }
        if output.version() >= 2 {
            output.done();
        }

        state
            .client_outputs
            .entry(client.id())
            .or_default()
            .push(output);
    }
}

impl Dispatch<WlOutput, ()> for CompositorState {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &WlOutput,
        _request: wl_output::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
    }
}

impl GlobalDispatch<XdgWmBase, ()> for CompositorState {
    fn bind(
        _state: &mut Self,
        _handle: &DisplayHandle,
        _client: &Client,
        resource: New<XdgWmBase>,
        _global_data: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        let _ = data_init.init(resource, ());
    }
}

impl Dispatch<XdgWmBase, ()> for CompositorState {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &XdgWmBase,
        request: xdg_wm_base::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        match request {
            xdg_wm_base::Request::CreatePositioner { id } => {
                let _ = data_init.init(id, ());
            }
            xdg_wm_base::Request::GetXdgSurface { id, surface } => {
                let surface_id = surface.data::<SurfaceData>().map_or(0, |d| d.0);
                let _ = data_init.init(id, XdgSurfaceData(surface_id));
            }
            _ => {}
        }
    }
}

impl Dispatch<XdgPositioner, ()> for CompositorState {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &XdgPositioner,
        _request: xdg_positioner::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
    }
}

impl Dispatch<XdgSurface, XdgSurfaceData> for CompositorState {
    fn request(
        state: &mut Self,
        client: &Client,
        resource: &XdgSurface,
        request: xdg_surface::Request,
        data: &XdgSurfaceData,
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        let surface_id = data.0;
        match request {
            xdg_surface::Request::GetToplevel { id } => {
                let window_id = state.alloc_id();
                let xdg_toplevel = data_init.init(id, ToplevelData(window_id));
                let width = state.config.width;
                let height = state.config.height;

                let _ = state.windows.insert(
                    window_id,
                    WindowState {
                        id: window_id,
                        surface_id,
                        client_id: Some(client.id()),
                        xdg_surface: resource.clone(),
                        xdg_toplevel,
                        title: String::new(),
                        app_id: String::new(),
                        width,
                        height,
                        has_buffer: false,
                        initial_configure_sent: false,
                    },
                );
                state.window_order.push(window_id);
                if let Some(surface) = state.surfaces.get_mut(&surface_id) {
                    surface.toplevel_id = Some(window_id);
                }
            }
            xdg_surface::Request::GetPopup { id, .. } => {
                let xdg_popup = data_init.init(id, PopupData { surface_id });
                if let Some(surface) = state.surfaces.get_mut(&surface_id) {
                    surface.popup = Some(PopupState {
                        xdg_surface: resource.clone(),
                        xdg_popup,
                        initial_configure_sent: false,
                    });
                }
            }
            xdg_surface::Request::Destroy => {
                if let Some(surface) = state.surfaces.get_mut(&surface_id) {
                    surface.popup = None;
                    if let Some(window_id) = surface.toplevel_id.take() {
                        state.remove_window(window_id);
                    }
                }
                let matching: Vec<u64> = state
                    .windows
                    .iter()
                    .filter_map(|(&wid, w)| (w.surface_id == surface_id).then_some(wid))
                    .collect();
                for wid in matching {
                    state.remove_window(wid);
                }
            }
            _ => {}
        }
    }
}

impl Dispatch<XdgToplevel, ToplevelData> for CompositorState {
    fn request(
        state: &mut Self,
        _client: &Client,
        _resource: &XdgToplevel,
        request: xdg_toplevel::Request,
        data: &ToplevelData,
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
        let window_id = data.0;
        match request {
            xdg_toplevel::Request::SetTitle { title } => {
                if let Some(win) = state.windows.get_mut(&window_id) {
                    win.title = title;
                }
            }
            xdg_toplevel::Request::SetAppId { app_id } => {
                if let Some(win) = state.windows.get_mut(&window_id) {
                    win.app_id = app_id;
                }
            }
            xdg_toplevel::Request::Destroy => {
                state.remove_window(window_id);
            }
            _ => {}
        }
    }
}

impl Dispatch<XdgPopup, PopupData> for CompositorState {
    fn request(
        state: &mut Self,
        _client: &Client,
        _resource: &XdgPopup,
        request: xdg_popup::Request,
        data: &PopupData,
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
        if matches!(request, xdg_popup::Request::Destroy)
            && let Some(surface) = state.surfaces.get_mut(&data.surface_id)
        {
            surface.popup = None;
        }
    }
}

impl GlobalDispatch<WlSeat, ()> for CompositorState {
    fn bind(
        _state: &mut Self,
        _handle: &DisplayHandle,
        _client: &Client,
        resource: New<WlSeat>,
        _global_data: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        let seat = data_init.init(resource, ());
        seat.capabilities(wl_seat::Capability::Pointer | wl_seat::Capability::Keyboard);
        if seat.version() >= 2 {
            seat.name("seat0".to_owned());
        }
    }
}

impl Dispatch<WlSeat, ()> for CompositorState {
    fn request(
        state: &mut Self,
        client: &Client,
        _resource: &WlSeat,
        request: wl_seat::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        match request {
            wl_seat::Request::GetPointer { id } => {
                let ptr = data_init.init(id, ());
                state
                    .client_pointers
                    .entry(client.id())
                    .or_default()
                    .push(ptr);
            }
            wl_seat::Request::GetKeyboard { id } => {
                let kb = data_init.init(id, ());
                if let Some((file, len)) = create_keymap_file() {
                    let _ = file.as_raw_fd();
                    kb.keymap(wl_keyboard::KeymapFormat::XkbV1, file.as_fd(), len);
                }
                if kb.version() >= 4 {
                    kb.repeat_info(25, 600);
                }
                state
                    .client_keyboards
                    .entry(client.id())
                    .or_default()
                    .push(kb);
            }
            wl_seat::Request::GetTouch { id } => {
                let _ = data_init.init(id, ());
            }
            _ => {}
        }
    }
}

fn create_keymap_file() -> Option<(File, u32)> {
    let mut file = tempfile::tempfile().ok()?;
    let bytes = XKB_US_KEYMAP.as_bytes();
    file.write_all(bytes).ok()?;
    file.write_all(&[0_u8]).ok()?;
    let _ = file.seek(SeekFrom::Start(0)).ok()?;
    let len = u32::try_from(bytes.len() + 1).ok()?;
    Some((file, len))
}

impl Dispatch<WlPointer, ()> for CompositorState {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &WlPointer,
        _request: wl_pointer::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
    }
}

impl Dispatch<WlKeyboard, ()> for CompositorState {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &WlKeyboard,
        _request: wl_keyboard::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
    }
}

impl Dispatch<WlTouch, ()> for CompositorState {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &WlTouch,
        _request: wl_touch::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
    }
}

impl GlobalDispatch<WlDataDeviceManager, ()> for CompositorState {
    fn bind(
        _state: &mut Self,
        _handle: &DisplayHandle,
        _client: &Client,
        resource: New<WlDataDeviceManager>,
        _global_data: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        let _ = data_init.init(resource, ());
    }
}

impl Dispatch<WlDataDeviceManager, ()> for CompositorState {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &WlDataDeviceManager,
        request: wl_data_device_manager::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        match request {
            wl_data_device_manager::Request::CreateDataSource { id } => {
                let _ = data_init.init(id, ());
            }
            wl_data_device_manager::Request::GetDataDevice { id, .. } => {
                let _ = data_init.init(id, ());
            }
            _ => {}
        }
    }
}

impl Dispatch<WlDataDevice, ()> for CompositorState {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &WlDataDevice,
        _request: wl_data_device::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
    }
}

impl Dispatch<WlDataSource, ()> for CompositorState {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &WlDataSource,
        _request: wl_data_source::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
    }
}

impl Dispatch<WlDataOffer, ()> for CompositorState {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &WlDataOffer,
        _request: wl_data_offer::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
    }
}

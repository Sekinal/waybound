//! Audited macOS `CoreFoundation`, `ApplicationServices` (`AXUIElement`), and
//! `CoreGraphics` (`CGEvent`) FFI declarations wrapped in RAII handles.

#![cfg(target_os = "macos")]

use std::ffi::{CString, c_char, c_void};
use std::ptr::{self, NonNull};

/// Opaque CoreFoundation type reference.
pub type CfTypeRef = *const c_void;
/// Opaque CoreFoundation string reference.
pub type CfStringRef = *const c_void;
/// Opaque CoreFoundation array reference.
pub type CfArrayRef = *const c_void;
/// Opaque CoreFoundation boolean reference.
pub type CfBooleanRef = *const c_void;
/// Opaque Accessibility UI element reference.
pub type AxUiElementRef = *const c_void;
/// Opaque Accessibility value wrapper reference (`CGPoint`, `CGSize`, etc.).
pub type AxValueRef = *const c_void;
/// Opaque CoreGraphics event reference.
pub type CgEventRef = *const c_void;

/// UTF-8 string encoding constant (`kCFStringEncodingUTF8`).
pub const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
/// Accessibility success code (`kAXErrorSuccess`).
pub const K_AX_ERROR_SUCCESS: i32 = 0;
/// `kAXValueTypeCGPoint`.
pub const K_AX_VALUE_TYPE_CG_POINT: i32 = 1;
/// `kAXValueTypeCGSize`.
pub const K_AX_VALUE_TYPE_CG_SIZE: i32 = 2;

/// `kCGHIDEventTap`.
pub const K_CG_HID_EVENT_TAP: u32 = 0;
/// `kCGScrollEventUnitPixel`.
pub const K_CG_SCROLL_EVENT_UNIT_PIXEL: u32 = 0;

/// `kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements`.
pub const K_CG_WINDOW_LIST_ON_SCREEN_EXCLUDE_DESKTOP: u32 = (1 << 0) | (1 << 4);
/// `kCFNumberSInt64Type` (`CFNumberType` is `CFIndex` / `isize` on macOS).
pub const K_CF_NUMBER_SINT64_TYPE: isize = 4;

/// CoreGraphics modifier flags (`CGEventFlags`).
pub const K_CG_EVENT_FLAG_MASK_SHIFT: u64 = 0x0002_0000;
/// `kCGEventFlagMaskControl`.
pub const K_CG_EVENT_FLAG_MASK_CONTROL: u64 = 0x0004_0000;
/// `kCGEventFlagMaskAlternate`.
pub const K_CG_EVENT_FLAG_MASK_ALTERNATE: u64 = 0x0008_0000;
/// `kCGEventFlagMaskCommand`.
pub const K_CG_EVENT_FLAG_MASK_COMMAND: u64 = 0x0010_0000;

/// CoreGraphics `CGPoint`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CgPoint {
    /// Horizontal coordinate.
    pub x: f64,
    /// Vertical coordinate.
    pub y: f64,
}

/// CoreGraphics `CGSize`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CgSize {
    /// Width.
    pub width: f64,
    /// Height.
    pub height: f64,
}

/// CoreGraphics mouse event types.
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum CgEventType {
    /// `kCGEventLeftMouseDown`
    LeftMouseDown = 1,
    /// `kCGEventLeftMouseUp`
    LeftMouseUp = 2,
    /// `kCGEventRightMouseDown`
    RightMouseDown = 3,
    /// `kCGEventRightMouseUp`
    RightMouseUp = 4,
    /// `kCGEventMouseMoved`
    MouseMoved = 5,
    /// `kCGEventOtherMouseDown`
    OtherMouseDown = 25,
    /// `kCGEventOtherMouseUp`
    OtherMouseUp = 26,
}

/// CoreGraphics mouse buttons.
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum CgMouseButton {
    /// `kCGMouseButtonLeft`
    Left = 0,
    /// `kCGMouseButtonRight`
    Right = 1,
    /// `kCGMouseButtonCenter`
    Center = 2,
}

unsafe extern "C" {
    pub static kCFBooleanTrue: CfBooleanRef;

    pub fn CFRelease(cf: CfTypeRef);
    pub fn CFRetain(cf: CfTypeRef) -> CfTypeRef;
    pub fn CFGetTypeID(cf: CfTypeRef) -> usize;
    pub fn CFStringGetTypeID() -> usize;
    pub fn CFArrayGetTypeID() -> usize;
    pub fn CFBooleanGetTypeID() -> usize;
    pub fn CFDictionaryGetTypeID() -> usize;
    pub fn CFDictionaryGetValue(the_dict: CfTypeRef, key: CfTypeRef) -> CfTypeRef;
    pub fn CFNumberGetTypeID() -> usize;
    pub fn CFNumberGetValue(number: CfTypeRef, the_type: isize, value_ptr: *mut c_void) -> u8;
    pub fn CFURLGetTypeID() -> usize;
    pub fn CFURLGetString(an_url: CfTypeRef) -> CfStringRef;
    pub fn CGWindowListCopyWindowInfo(option: u32, relative_to_window: u32) -> CfArrayRef;
    pub fn CFBooleanGetValue(boolean: CfBooleanRef) -> u8;
    pub fn CFStringCreateWithCString(
        alloc: CfTypeRef,
        c_str: *const c_char,
        encoding: u32,
    ) -> CfStringRef;
    pub fn CFStringGetLength(the_string: CfStringRef) -> isize;
    pub fn CFStringGetMaximumSizeForEncoding(length: isize, encoding: u32) -> isize;
    pub fn CFStringGetCString(
        the_string: CfStringRef,
        buffer: *mut c_char,
        buffer_size: isize,
        encoding: u32,
    ) -> u8;
    pub fn CFArrayGetCount(the_array: CfArrayRef) -> isize;
    pub fn CFArrayGetValueAtIndex(the_array: CfArrayRef, idx: isize) -> CfTypeRef;

    pub fn AXIsProcessTrusted() -> u8;
    pub fn AXUIElementGetTypeID() -> usize;
    pub fn AXValueGetTypeID() -> usize;
    pub fn AXUIElementCreateApplication(pid: i32) -> AxUiElementRef;
    pub fn AXUIElementCopyAttributeValue(
        element: AxUiElementRef,
        attribute: CfStringRef,
        value: *mut CfTypeRef,
    ) -> i32;
    pub fn AXUIElementSetAttributeValue(
        element: AxUiElementRef,
        attribute: CfStringRef,
        value: CfTypeRef,
    ) -> i32;
    pub fn AXValueGetValue(value: AxValueRef, value_type: i32, value_ptr: *mut c_void) -> u8;

    pub fn CGEventCreateMouseEvent(
        source: CfTypeRef,
        mouse_type: u32,
        mouse_cursor_position: CgPoint,
        mouse_button: u32,
    ) -> CgEventRef;
    /// Non-variadic scroll wheel event constructor (macOS 10.13+, safe on ARM64 PCS).
    pub fn CGEventCreateScrollWheelEvent2(
        source: CfTypeRef,
        units: u32,
        wheel_count: u32,
        wheel1: i32,
        wheel2: i32,
        wheel3: i32,
    ) -> CgEventRef;
    pub fn CGEventCreateKeyboardEvent(
        source: CfTypeRef,
        virtual_key: u16,
        key_down: u8,
    ) -> CgEventRef;
    pub fn CGEventKeyboardSetUnicodeString(
        event: CgEventRef,
        string_length: usize,
        unicode_string: *const u16,
    );
    pub fn CGEventSetFlags(event: CgEventRef, flags: u64);
    /// Creates an empty event carrying the current pointer location (`+1` retained).
    pub fn CGEventCreate(source: CfTypeRef) -> CgEventRef;
    /// Returns the event location in global display coordinates (top-left origin).
    pub fn CGEventGetLocation(event: CgEventRef) -> CgPoint;
    pub fn CGEventPost(tap: u32, event: CgEventRef);
}

/// RAII owner of a retained CoreFoundation object (`CFRelease` on `Drop`).
#[derive(Debug)]
pub struct OwnedCf {
    ptr: NonNull<c_void>,
}

impl OwnedCf {
    /// Takes ownership of a `+1` retained CoreFoundation pointer (such as from a `Create`/`Copy` API).
    ///
    /// # Safety
    ///
    /// If `raw` is non-null, it must be a valid CoreFoundation object pointer with a `+1`
    /// retain count that the caller is transferring exclusively to this [`OwnedCf`].
    #[must_use]
    pub unsafe fn from_owned(raw: CfTypeRef) -> Option<Self> {
        NonNull::new(raw.cast_mut()).map(|ptr| Self { ptr })
    }

    /// Retains a borrowed CoreFoundation pointer (`+0`) and wraps it in an owned handle.
    ///
    /// # Safety
    ///
    /// If `raw` is non-null, it must point to a live, valid CoreFoundation object.
    #[must_use]
    pub unsafe fn retain(raw: CfTypeRef) -> Option<Self> {
        if raw.is_null() {
            return None;
        }
        // SAFETY: Caller guarantees `raw` is a live CoreFoundation object; `CFRetain` increments its refcount.
        let retained = unsafe { CFRetain(raw) };
        // SAFETY: `CFRetain` returns a `+1` retained handle to the same object.
        unsafe { Self::from_owned(retained) }
    }

    /// Returns the underlying raw pointer without transferring ownership.
    #[must_use]
    pub const fn as_ptr(&self) -> CfTypeRef {
        self.ptr.as_ptr().cast_const()
    }
}

impl Drop for OwnedCf {
    fn drop(&mut self) {
        // SAFETY: `OwnedCf` exclusively owns one retain count on `self.ptr`.
        unsafe { CFRelease(self.as_ptr()) };
    }
}

/// Creates an owned `CFString` from a Rust `&str`.
#[must_use]
pub fn cf_string(text: &str) -> Option<OwnedCf> {
    let c_str = CString::new(text).ok()?;
    // SAFETY: `c_str` is a valid NUL-terminated UTF-8 string; `CFStringCreateWithCString` returns a `+1` ref or null.
    unsafe {
        let raw = CFStringCreateWithCString(ptr::null(), c_str.as_ptr(), K_CF_STRING_ENCODING_UTF8);
        OwnedCf::from_owned(raw)
    }
}

/// Converts an owned `CFTypeRef` to a Rust `String` if its runtime type is `CFString`.
#[must_use]
pub fn cf_to_string(obj: &OwnedCf) -> Option<String> {
    let raw = obj.as_ptr();
    // SAFETY: `obj` guarantees `raw` is a live CoreFoundation object; type ID check verifies `CFString`.
    unsafe {
        if CFGetTypeID(raw) != CFStringGetTypeID() {
            return None;
        }
        let len = CFStringGetLength(raw);
        let max_bytes = CFStringGetMaximumSizeForEncoding(len, K_CF_STRING_ENCODING_UTF8);
        if max_bytes < 0 {
            return None;
        }
        let max_size = max_bytes.checked_add(1)?;
        let buf_len = usize::try_from(max_size).ok()?;
        let mut buffer = vec![0u8; buf_len];
        let ok = CFStringGetCString(
            raw,
            buffer.as_mut_ptr().cast::<c_char>(),
            max_size,
            K_CF_STRING_ENCODING_UTF8,
        );
        if ok == 0 {
            return None;
        }
        let nul_pos = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
        String::from_utf8(buffer[..nul_pos].to_vec()).ok()
    }
}

/// Converts an owned `CFTypeRef` to `bool` if its runtime type is `CFBoolean`.
#[must_use]
pub fn cf_to_bool(obj: &OwnedCf) -> Option<bool> {
    let raw = obj.as_ptr();
    // SAFETY: `obj` guarantees `raw` is a live CoreFoundation object; type ID check verifies `CFBoolean`.
    unsafe {
        if CFGetTypeID(raw) != CFBooleanGetTypeID() {
            return None;
        }
        Some(CFBooleanGetValue(raw) != 0)
    }
}

/// Extracts a URL string from an owned `CFURL` or `CFString` object.
#[must_use]
pub fn cf_to_url_string(obj: &OwnedCf) -> Option<String> {
    if let Some(s) = cf_to_string(obj) {
        return Some(s);
    }
    let raw = obj.as_ptr();
    // SAFETY: `obj` guarantees `raw` is a live CoreFoundation object; type ID check verifies `CFURL`.
    // `CFURLGetString` follows the Get Rule (+0 borrowed ref), so we retain it into `OwnedCf`.
    let url_cf_str = unsafe {
        if CFGetTypeID(raw) != CFURLGetTypeID() {
            return None;
        }
        OwnedCf::retain(CFURLGetString(raw))?
    };
    cf_to_string(&url_cf_str)
}

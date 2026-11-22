//! Native macOS browser window screenshot capture (`CGWindowListCopyWindowInfo` + `screencapture`).

#![cfg(target_os = "macos")]

use std::ffi::c_void;
use std::path::Path;
use std::process::{Command, Stdio};

use waybound_core::{Result, WayboundError};

use crate::ffi::{
    CFArrayGetCount, CFArrayGetTypeID, CFArrayGetValueAtIndex, CFDictionaryGetTypeID,
    CFDictionaryGetValue, CFGetTypeID, CFNumberGetTypeID, CFNumberGetValue,
    CGWindowListCopyWindowInfo, K_CF_NUMBER_SINT64_TYPE,
    K_CG_WINDOW_LIST_ON_SCREEN_EXCLUDE_DESKTOP, OwnedCf, cf_string,
};

/// Finds the primary on-screen `CGWindowID` belonging to `pid` (layer 0).
#[must_use]
pub fn find_window_id(pid: i32) -> Option<u32> {
    if pid <= 0 {
        return None;
    }

    // SAFETY: `CGWindowListCopyWindowInfo` returns a `+1` retained `CFArrayRef` or null.
    let list = unsafe {
        OwnedCf::from_owned(CGWindowListCopyWindowInfo(
            K_CG_WINDOW_LIST_ON_SCREEN_EXCLUDE_DESKTOP,
            0,
        ))
    }?;

    let key_pid = cf_string("kCGWindowOwnerPID")?;
    let key_layer = cf_string("kCGWindowLayer")?;
    let key_num = cf_string("kCGWindowNumber")?;

    // SAFETY: Verify `list` is a `CFArray` and each element is a `CFDictionary` before reading keys.
    unsafe {
        if CFGetTypeID(list.as_ptr()) != CFArrayGetTypeID() {
            return None;
        }
        let dict_type_id = CFDictionaryGetTypeID();
        let count = CFArrayGetCount(list.as_ptr());
        for idx in 0..count {
            let entry = CFArrayGetValueAtIndex(list.as_ptr(), idx);
            if entry.is_null() || CFGetTypeID(entry) != dict_type_id {
                continue;
            }
            let owner_pid = dict_i64(entry, &key_pid);
            let layer = dict_i64(entry, &key_layer);
            if owner_pid == Some(i64::from(pid))
                && layer == Some(0)
                && let Some(win_id) = dict_i64(entry, &key_num).and_then(|v| u32::try_from(v).ok())
            {
                return Some(win_id);
            }
        }
    }

    None
}

/// SAFETY: Caller must guarantee `dict` is a valid non-null `CFDictionaryRef`.
unsafe fn dict_i64(dict: crate::ffi::CfTypeRef, key: &OwnedCf) -> Option<i64> {
    // SAFETY: `dict` is a valid `CFDictionaryRef` and `key` is a retained `CFString`.
    let val = unsafe { CFDictionaryGetValue(dict, key.as_ptr()) };
    if val.is_null() {
        return None;
    }
    // SAFETY: Verify runtime type is `CFNumber` before reading into `out`.
    unsafe {
        if CFGetTypeID(val) != CFNumberGetTypeID() {
            return None;
        }
        let mut out = 0i64;
        let ok = CFNumberGetValue(
            val,
            K_CF_NUMBER_SINT64_TYPE,
            (&raw mut out).cast::<c_void>(),
        );
        (ok != 0).then_some(out)
    }
}

/// Captures the target browser window owned by `pid` to `output_path` as a PNG.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if no on-screen window is found for `pid`
/// or if `/usr/sbin/screencapture` fails (e.g., missing Screen Recording permission).
pub fn capture_window_png(pid: i32, output_path: &Path) -> Result<()> {
    let win_id = find_window_id(pid).ok_or_else(|| WayboundError::BackendUnavailable {
        backend: "macos_native".to_owned(),
        reason: format!("no on-screen browser window found for pid {pid}"),
    })?;

    let status = Command::new("/usr/sbin/screencapture")
        .args(["-x", "-o", "-l", &win_id.to_string()])
        .arg(output_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(WayboundError::Io)?;

    if !status.success() || !output_path.exists() {
        return Err(WayboundError::BackendUnavailable {
            backend: "macos_native".to_owned(),
            reason: format!(
                "screencapture failed for window {win_id} (ensure Screen Recording permission is granted in System Settings > Privacy & Security > Screen & System Audio Recording)"
            ),
        });
    }

    Ok(())
}

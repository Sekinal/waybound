//! Pure-Rust Wayland shared-memory pixel conversion and PNG encoding.

use waybound_core::{Result, WayboundError};

/// Maximum supported buffer width or height in pixels (guards against huge allocations).
pub const MAX_BUFFER_DIMENSION: u32 = 8192;

/// Validates `wl_shm_pool` buffer geometry against the pool size without integer overflow.
///
/// Returns the total byte length (`stride * height`) required to read the buffer.
///
/// # Errors
///
/// Returns [`WayboundError::InvalidElementState`] if dimensions, stride, or offset exceed
/// safe bounds or `pool_size`.
pub fn validate_buffer_bounds(
    offset: u64,
    width: u32,
    height: u32,
    stride: u32,
    pool_size: u64,
) -> Result<usize> {
    if width == 0 || height == 0 || width > MAX_BUFFER_DIMENSION || height > MAX_BUFFER_DIMENSION {
        return Err(WayboundError::InvalidElementState {
            detail: format!(
                "invalid wl_shm buffer dimensions {width}x{height} (max {MAX_BUFFER_DIMENSION})"
            ),
        });
    }
    let min_stride = width
        .checked_mul(4)
        .ok_or_else(|| WayboundError::InvalidElementState {
            detail: format!("wl_shm buffer width overflow: {width}"),
        })?;
    if stride < min_stride {
        return Err(WayboundError::InvalidElementState {
            detail: format!("wl_shm stride {stride} is smaller than minimum {min_stride}"),
        });
    }
    let byte_len_u64 = u64::from(stride)
        .checked_mul(u64::from(height))
        .ok_or_else(|| WayboundError::InvalidElementState {
            detail: "wl_shm buffer byte length overflow".to_owned(),
        })?;
    let end =
        offset
            .checked_add(byte_len_u64)
            .ok_or_else(|| WayboundError::InvalidElementState {
                detail: "wl_shm buffer offset overflow".to_owned(),
            })?;
    if end > pool_size {
        return Err(WayboundError::InvalidElementState {
            detail: format!("wl_shm buffer range {offset}..{end} exceeds pool size {pool_size}"),
        });
    }
    usize::try_from(byte_len_u64).map_err(|_| WayboundError::InvalidElementState {
        detail: format!("wl_shm buffer length {byte_len_u64} exceeds addressable memory"),
    })
}

/// Converts little-endian `ARGB8888` (`[B, G, R, A]` in memory) pixels into tightly packed `RGBA`.
///
/// # Errors
///
/// Returns [`WayboundError::InvalidElementState`] if dimensions, stride, or slice length are invalid.
pub fn argb8888_to_rgba(src: &[u8], width: u32, height: u32, stride: u32) -> Result<Vec<u8>> {
    convert_bgra_to_rgba(src, width, height, stride, false)
}

/// Converts little-endian `XRGB8888` (`[B, G, R, X]` in memory) pixels into tightly packed opaque `RGBA`.
///
/// # Errors
///
/// Returns [`WayboundError::InvalidElementState`] if dimensions, stride, or slice length are invalid.
pub fn xrgb8888_to_rgba(src: &[u8], width: u32, height: u32, stride: u32) -> Result<Vec<u8>> {
    convert_bgra_to_rgba(src, width, height, stride, true)
}

fn convert_bgra_to_rgba(
    src: &[u8],
    width: u32,
    height: u32,
    stride: u32,
    force_opaque: bool,
) -> Result<Vec<u8>> {
    let required = validate_buffer_bounds(0, width, height, stride, src.len() as u64)?;
    if src.len() < required {
        return Err(WayboundError::InvalidElementState {
            detail: format!("source buffer too small: {} < {required}", src.len()),
        });
    }

    let width_usize = usize::try_from(width).map_err(|_| WayboundError::InvalidElementState {
        detail: format!("buffer width {width} overflows usize"),
    })?;
    let height_usize = usize::try_from(height).map_err(|_| WayboundError::InvalidElementState {
        detail: format!("buffer height {height} overflows usize"),
    })?;
    let stride_usize = usize::try_from(stride).map_err(|_| WayboundError::InvalidElementState {
        detail: format!("buffer stride {stride} overflows usize"),
    })?;
    let row_bytes =
        width_usize
            .checked_mul(4)
            .ok_or_else(|| WayboundError::InvalidElementState {
                detail: "RGBA row byte count overflow".to_owned(),
            })?;
    let out_len =
        row_bytes
            .checked_mul(height_usize)
            .ok_or_else(|| WayboundError::InvalidElementState {
                detail: "RGBA output buffer size overflow".to_owned(),
            })?;

    let mut rgba = Vec::with_capacity(out_len);
    for row in 0..height_usize {
        let row_start = row * stride_usize;
        let row_slice = &src[row_start..row_start + row_bytes];
        let (pixels, _) = row_slice.as_chunks::<4>();
        for &[b, g, r, a] in pixels {
            rgba.push(r);
            rgba.push(g);
            rgba.push(b);
            rgba.push(if force_opaque { 0xFF } else { a });
        }
    }
    Ok(rgba)
}

/// Encodes tightly packed `RGBA8` pixels into a PNG byte buffer.
///
/// # Errors
///
/// Returns [`WayboundError::InvalidElementState`] if dimensions or buffer length are invalid,
/// or [`WayboundError::Io`] if PNG encoding fails.
pub fn encode_rgba_png(rgba: &[u8], width: u32, height: u32) -> Result<Vec<u8>> {
    if width == 0 || height == 0 || width > MAX_BUFFER_DIMENSION || height > MAX_BUFFER_DIMENSION {
        return Err(WayboundError::InvalidElementState {
            detail: format!("invalid PNG dimensions {width}x{height} (max {MAX_BUFFER_DIMENSION})"),
        });
    }
    let expected = usize::try_from(width)
        .ok()
        .and_then(|w| usize::try_from(height).ok().and_then(|h| w.checked_mul(h)))
        .and_then(|px| px.checked_mul(4))
        .ok_or_else(|| WayboundError::InvalidElementState {
            detail: "PNG byte length overflow".to_owned(),
        })?;
    if rgba.len() != expected {
        return Err(WayboundError::InvalidElementState {
            detail: format!(
                "RGBA slice length {} does not match {width}x{height}x4 ({expected})",
                rgba.len()
            ),
        });
    }

    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, width, height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder
            .write_header()
            .map_err(|err| WayboundError::Io(std::io::Error::other(err)))?;
        writer
            .write_image_data(rgba)
            .map_err(|err| WayboundError::Io(std::io::Error::other(err)))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swizzles_argb8888_and_xrgb8888_with_stride_padding() {
        // 2x2 image with stride 12 (4 bytes padding per row).
        // Little-endian BGRA bytes: pixel(0,0) = B=0x10, G=0x20, R=0x30, A=0x40
        let raw = [
            0x10, 0x20, 0x30, 0x40, 0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0, 0, // row 0
            0x01, 0x02, 0x03, 0x00, 0x11, 0x22, 0x33, 0x7F, 0, 0, 0, 0, // row 1
        ];

        let argb = argb8888_to_rgba(&raw, 2, 2, 12);
        assert!(argb.is_ok());
        assert_eq!(
            argb.ok(),
            Some(vec![
                0x30, 0x20, 0x10, 0x40, 0xCC, 0xBB, 0xAA, 0xDD, // row 0
                0x03, 0x02, 0x01, 0x00, 0x33, 0x22, 0x11, 0x7F, // row 1
            ])
        );

        let xrgb = xrgb8888_to_rgba(&raw, 2, 2, 12);
        assert_eq!(
            xrgb.ok(),
            Some(vec![
                0x30, 0x20, 0x10, 0xFF, 0xCC, 0xBB, 0xAA, 0xFF, // row 0
                0x03, 0x02, 0x01, 0xFF, 0x33, 0x22, 0x11, 0xFF, // row 1
            ])
        );
    }

    #[test]
    fn encodes_valid_png_with_expected_dimensions() {
        let rgba = vec![
            0x22, 0x66, 0xCC, 0xFF, 0x22, 0x66, 0xCC, 0xFF, // row 0
            0x22, 0x66, 0xCC, 0xFF, 0x22, 0x66, 0xCC, 0xFF, // row 1
        ];
        let encoded = encode_rgba_png(&rgba, 2, 2);
        assert!(encoded.is_ok());
        let bytes = encoded.unwrap_or_default();
        assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"));

        let decoder = png::Decoder::new(std::io::Cursor::new(&bytes));
        let reader = decoder.read_info();
        assert!(reader.is_ok());
        if let Ok(mut reader) = reader {
            let info = reader.info();
            assert_eq!(info.width, 2);
            assert_eq!(info.height, 2);
            let mut pixels = vec![0_u8; reader.output_buffer_size()];
            assert!(reader.next_frame(&mut pixels).is_ok());
            assert_eq!(pixels, rgba);
        }
    }

    #[test]
    fn rejects_out_of_bounds_and_invalid_geometry() {
        assert!(validate_buffer_bounds(0, 0, 10, 40, 1024).is_err());
        assert!(validate_buffer_bounds(0, MAX_BUFFER_DIMENSION + 1, 1, 40_000, 100_000).is_err());
        assert!(validate_buffer_bounds(0, 10, 10, 36, 1024).is_err());
        assert!(validate_buffer_bounds(100, 10, 10, 40, 499).is_err());
        assert!(validate_buffer_bounds(u64::MAX, 1, 1, 4, u64::MAX).is_err());
        assert!(encode_rgba_png(&[0_u8; 3], 1, 1).is_err());
    }
}

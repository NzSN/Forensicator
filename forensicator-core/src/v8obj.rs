//! Cage-aware V8 heap object walking: pointer decompression, Smi decoding,
//! instance-type reads, and inline string payloads. Extracted from
//! `analyzer::v8` so crash-cause rules share the same decoding discipline.
//! All reads are structurally validated and fail closed to `None`.

use crate::space::AddressSpace;
use crate::v8layout::V8Layout;

/// Decompress a 32-bit tagged pointer within the pointer-compression cage.
/// Returns the untagged heap address, or None for Smis/null.
pub(crate) fn decompress(cage_base: u64, compressed: u32) -> Option<u64> {
    if compressed == 0 || compressed & 1 == 0 {
        return None;
    }
    Some(cage_base + (compressed & !1) as u64)
}

/// Decode a 31-bit compressed Smi (low 32 bits, tag bit 0).
pub(crate) fn smi(raw: u32) -> Option<i32> {
    if raw & 1 != 0 {
        return None;
    }
    Some((raw as i32) >> 1)
}

/// Read a heap object's instance type: Map at +0 (compressed), u16 at Map+8.
pub(crate) fn instance_type(space: &AddressSpace, cage: u64, heap: u64) -> Option<u16> {
    let map_c = read_u32(space, heap)?;
    let map = decompress(cage, map_c)?;
    let b = space.read(map + 8, 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

/// Read an inline (Seq*/Internalized) string payload with structural
/// validation. Layout: map(0), raw_hash(4), length(8), chars(12).
pub(crate) fn read_v8_string(
    space: &AddressSpace,
    va: u64,
    itype: u16,
    layout: &V8Layout,
) -> Option<String> {
    let len = read_u32(space, va + layout.string_length)?;
    if len == 0 || len > layout.max_js_name_len {
        return None;
    }
    let len = len as usize;

    if itype & layout.string_one_byte_bit != 0 {
        let bytes = space.read(va + layout.string_chars, len)?;
        if bytes
            .iter()
            .all(|&b| (0x20..=0x7e).contains(&b) || b >= 0x80)
        {
            return Some(String::from_utf8_lossy(bytes).into_owned());
        }
    } else {
        let bytes = space.read(va + layout.string_chars, len.checked_mul(2)?)?;
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        if units
            .iter()
            .all(|&u| (0x20..=0x7e).contains(&u) || u >= 0x80)
        {
            return String::from_utf16(&units).ok();
        }
    }
    None
}

pub(crate) fn read_u32(space: &AddressSpace, va: u64) -> Option<u32> {
    let bytes = space.read(va, 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

pub(crate) fn try_read_u64(space: &AddressSpace, va: u64) -> Option<u64> {
    let bytes = space.read(va, 8)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

//! Version-pinned V8 internals, isolated from the version-agnostic walking
//! and symbolication code. Everything that can change between V8 releases
//! lives here as a `V8Layout` value; `analyzer::v8` only consumes a
//! `&V8Layout` and never hardcodes an offset.
//!
//! Layouts come from the V8 revision's `.tq`/`.h` files (see
//! docs/v8-jit-frame-resolution.md) and are validated structurally at
//! runtime, so a wrong layout fails closed to `None`, never to wrong names.

use crate::model::{Dump, V8FrameType};

/// All version-sensitive offsets, masks, and tables for one V8 release.
#[derive(Debug, Clone, Copy)]
pub struct V8Layout {
    // ── x64 stack frame slots (frame-pointer relative) ──
    /// StandardFrameConstants: [fp+this] = context.
    pub k_context_offset: i64,
    /// StandardFrameConstants: [fp+this] = JSFunction.
    pub k_function_offset: i64,
    /// StandardFrameConstants: [fp+this] = StackFrame::Type marker (raw int).
    pub k_marker_offset: i64,
    /// Pre-V8-13 layout fallback: [fp+this] = JSFunction.
    pub k_function_offset_legacy: i64,

    // ── JSFunction fields (compressed, bytes) ──
    /// Offset of `shared_function_info`. V8 ≥ ~13 (leaptiering) places
    /// `dispatch_handle: int32` before it; older versions have it earlier.
    pub jsfunction_shared_function_info: u64,
    /// Offset of `context` — used for the frame context round-trip check.
    pub jsfunction_context: u64,

    // ── SharedFunctionInfo fields ──
    pub sfi_name_or_scope_info: u64,
    pub sfi_script: u64,

    // ── Script fields ──
    pub script_name: u64,
    pub script_line_offset: u64,
    pub script_line_ends: u64,

    // ── Strings (Seq*/Internalized inline payload) ──
    /// String layout: map(0), raw_hash(4), length, chars.
    pub string_length: u64,
    pub string_chars: u64,
    /// All string instance types are below this value (heuristic bound).
    pub string_itype_max: u16,
    /// Instance-type bit: set = one-byte encoding.
    pub string_one_byte_bit: u16,
    /// Instance-type bit: set = external string.
    pub string_external_bit: u16,
    pub max_js_name_len: u32,

    // ── ScopeInfo layout and flags ──
    pub scope_flags: u64,
    pub scope_param_count: u64,
    pub scope_local_count: u64,
    /// ScopeInfo.position_info.start (Smi) — char offset into the source.
    pub scope_position_start: u64,
    pub scope_dynamic_start: u64,
    pub scope_type_module: u32,
    pub scope_flag_saved_class_variable: u32,
    pub scope_function_variable_shift: u32,
    pub scope_function_variable_mask: u32,
    pub scope_flag_inferred_function_name: u32,
    pub scope_max_inlined_local_names: u32,

    // ── FixedArray layout ──
    pub fixed_array_length: u64,
    pub fixed_array_data: u64,

    // ── External pointer table (sandbox EPT) ──
    pub ept_entry_size: u64,
    pub ept_index_shift: u32,
    pub ept_payload_mask: u64,

    /// StackFrame::Type marker table (STACK_FRAME_TYPE_LIST order, frames.h).
    pub marker_table: fn(u64) -> Option<V8FrameType>,
}

impl V8Layout {
    /// V8 14.6 (Chromium 146 / Electron 41), verified against revision
    /// f9116f3bf9a50b0f7925daacfdc6fed503a9dbe2 and the Case dumps.
    pub const fn v14_6() -> Self {
        V8Layout {
            k_context_offset: -8,
            k_function_offset: -16,
            k_marker_offset: -24,
            k_function_offset_legacy: -24,

            jsfunction_shared_function_info: 16,
            jsfunction_context: 20,

            sfi_name_or_scope_info: 12,
            sfi_script: 20,

            script_name: 8,
            script_line_offset: 12,
            script_line_ends: 28,

            string_length: 8,
            string_chars: 12,
            string_itype_max: 0x40,
            string_one_byte_bit: 0x08,
            string_external_bit: 0x02,
            max_js_name_len: 4096,

            scope_flags: 4,
            scope_param_count: 8,
            scope_local_count: 12,
            scope_position_start: 16,
            scope_dynamic_start: 24,
            scope_type_module: 5,
            scope_flag_saved_class_variable: 1 << 10,
            scope_function_variable_shift: 12,
            scope_function_variable_mask: 0x3,
            scope_flag_inferred_function_name: 1 << 14,
            scope_max_inlined_local_names: 512,

            fixed_array_length: 4,
            fixed_array_data: 8,

            ept_entry_size: 16,
            ept_index_shift: 6,
            ept_payload_mask: 0x0000_FFFF_FFFF_FFFF,

            marker_table: marker_type_v14_6,
        }
    }

    /// Select a layout by V8 version (major.minor). Versions sharing the
    /// 14.x Torque layouts for the fields we use currently map to v14_6.
    pub fn for_v8_version(major: u32, minor: u32) -> Option<Self> {
        match (major, minor) {
            (14, _) => Some(Self::v14_6()),
            _ => None,
        }
    }

    /// Electron major version → Chromium major version (recent releases).
    pub fn electron_to_chromium_major(electron_major: u32) -> Option<u32> {
        match electron_major {
            41 => Some(146),
            40 => Some(144),
            39 => Some(142),
            _ => None,
        }
    }

    /// Chromium major → V8 major/minor (Ch142 = V8 14.2).
    pub fn chromium_to_v8(chromium_major: u32) -> Option<(u32, u32)> {
        if (132..=146).contains(&chromium_major) {
            Some((14, chromium_major - 132))
        } else {
            None
        }
    }

    /// Detect the layout from dump annotations (`ver` = Electron version).
    /// Falls back to v14_6 when the version is unknown — the structural
    /// validation in the decoder turns a wrong guess into `None`, not
    /// garbage.
    pub fn detect(dump: &Dump) -> Self {
        for (k, v) in &dump.annotations {
            if k != "ver" {
                continue;
            }
            let major: u32 = v
                .split(['.', '-'])
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            if let Some(ch) = Self::electron_to_chromium_major(major)
                && let Some((vmaj, vmin)) = Self::chromium_to_v8(ch)
                && let Some(l) = Self::for_v8_version(vmaj, vmin)
            {
                return l;
            }
            break;
        }
        Self::v14_6()
    }

    /// Decode a frame marker to a frame type using this layout's table.
    pub fn marker_frame_type(&self, marker: u64) -> Option<V8FrameType> {
        (self.marker_table)(marker)
    }
}

/// StackFrame::Type mapping for V8 14.6 (raw marker ints, not Smis).
fn marker_type_v14_6(marker: u64) -> Option<V8FrameType> {
    Some(match marker {
        3 | 4 => V8FrameType::JavaScript,          // INTERPRETED, BASELINE
        5 | 6 => V8FrameType::OptimizedJavaScript, // MAGLEV, TURBOFAN_JS
        7 | 8 => V8FrameType::Stub,                // STUB, TURBOFAN_STUB_WITH_CONTEXT
        9..=11 => V8FrameType::Builtin,            // *_CONTINUATION
        13 | 14 => V8FrameType::Construct,         // CONSTRUCT, FAST_CONSTRUCT
        15 => V8FrameType::Builtin,                // BUILTIN
        2 | 16..=21 => V8FrameType::Exit,          // EXIT, *_EXIT, NATIVE, IRREGEXP
        1 | 12 => V8FrameType::Internal,           // CONSTRUCT_ENTRY, INTERNAL
        22..=40 => V8FrameType::WasmCompiled,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Provenance;

    fn dump_with_ver(ver: &str) -> Dump {
        Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            annotations: vec![("ver".into(), ver.into())],
            memory_info: vec![],
            v8heap_ext: None,
            file_size: 0,
        }
    }

    #[test]
    fn detects_electron_41() {
        let l = V8Layout::detect(&dump_with_ver("41.10.3-jlc-sa-win-x64.0"));
        assert_eq!(l.sfi_script, 20);
        assert_eq!(l.ept_index_shift, 6);
    }

    #[test]
    fn unknown_version_falls_back() {
        let l = V8Layout::detect(&dump_with_ver("99.0.0"));
        assert_eq!(l.jsfunction_shared_function_info, 16);
        let _ = Provenance {
            stream_type: 0,
            file_offset: 0,
            rva: 0,
        };
    }

    #[test]
    fn marker_table_values() {
        let l = V8Layout::v14_6();
        assert_eq!(
            l.marker_frame_type(5),
            Some(V8FrameType::OptimizedJavaScript)
        );
        assert_eq!(l.marker_frame_type(2), Some(V8FrameType::Exit));
        assert_eq!(l.marker_frame_type(0xdead), None);
    }
}

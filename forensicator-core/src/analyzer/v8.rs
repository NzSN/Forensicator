//! V8 JavaScript engine stack analyzer.
//! Walks native call stacks, resolves symbols via PDB, classifies V8 frames.

use std::path::Path;

use crate::analyzer::{Analyzer, AnalyzerOutput};
use crate::model::{Dump, V8FrameType, V8StackFrame};
use crate::space::AddressSpace;
use crate::symbolizer::Symbolizer;

pub struct V8Analyzer {
    pdb_dir: Option<String>,
}

impl V8Analyzer {
    pub fn new() -> Self {
        V8Analyzer { pdb_dir: None }
    }

    pub fn with_pdb_dir(mut self, dir: impl Into<String>) -> Self {
        self.pdb_dir = Some(dir.into());
        self
    }
}

impl Default for V8Analyzer {
    fn default() -> Self {
        V8Analyzer::new()
    }
}

impl Analyzer for V8Analyzer {
    fn name(&self) -> &str {
        "v8"
    }

    fn description(&self) -> &str {
        "Recovers JS stack traces by walking native stacks and classifying V8 frames"
    }

    fn analyze(&self, dump: &Dump, space: &AddressSpace) -> AnalyzerOutput {
        let mut out = AnalyzerOutput::new("v8");

        let isolate_va = resolve_v8_isolate(dump);

        let sym = if let Some(ref dir) = self.pdb_dir {
            Symbolizer::load(dump, Path::new(dir)).ok()
        } else {
            Symbolizer::load(dump, Path::new(".")).ok()
        };

        let frames = walk_thread_stacks(dump, space, isolate_va, sym.as_ref());
        let frames_json: Vec<serde_json::Value> = frames
            .iter()
            .map(|f| {
                serde_json::json!({
                    "thread_id": f.thread_id,
                    "depth": f.depth,
                    "frame_type": format!("{:?}", f.frame_type),
                    "native_symbol": f.native_symbol,
                    "native_offset": f.native_offset,
                    "return_address": format!("0x{:X}", f.return_address),
                    "frame_pointer": format!("0x{:X}", f.frame_pointer),
                    "js_function_name": f.js_function_name,
                    "script_name": f.script_name,
                    "script_line": f.script_line,
                })
            })
            .collect();

        out.custom.push((
            "v8_frames".to_string(),
            serde_json::Value::Array(frames_json),
        ));
        out.custom.push((
            "v8_frame_count".to_string(),
            serde_json::json!(frames.len()),
        ));

        if let Some(disasm) = disassemble_exception(dump, space) {
            out.custom.push(("crash_disasm".to_string(), disasm));
        }

        // Whether V8 heap memory was captured (false for stack-only dumps) —
        // JS names/scripts/lines are only recoverable when it is.
        let heap_captured = annotation_hex(dump, "v8_ro_space_firstpage_address")
            .map(|cage| space.region_at(cage).is_some())
            .unwrap_or(false);
        out.custom.push((
            "v8_heap_captured".to_string(),
            serde_json::json!(heap_captured),
        ));

        out
    }
}

/// Disassemble ~10 instructions at the exception address (bytes come from the
/// dump or, for stack-only minidumps, from the supplemented module image).
fn disassemble_exception(dump: &Dump, space: &AddressSpace) -> Option<serde_json::Value> {
    let exc = dump.exception.as_ref()?;
    let pc = exc.address;
    let bytes = space.read(pc, 64)?;
    let mut decoder = iced_x86::Decoder::with_ip(64, bytes, pc, iced_x86::DecoderOptions::NONE);
    let mut lines = Vec::new();
    let mut instr = iced_x86::Instruction::default();
    let mut output = FormatterOutputImpl(String::new());
    while lines.len() < 10 && decoder.can_decode() {
        decoder.decode_out(&mut instr);
        output.0.clear();
        let mut formatter = iced_x86::IntelFormatter::new();
        iced_x86::Formatter::format(&mut formatter, &instr, &mut output);
        lines.push(serde_json::json!({
            "va": format!("0x{:X}", instr.ip()),
            "text": output.0.clone(),
        }));
    }
    if lines.is_empty() {
        return None;
    }
    Some(serde_json::Value::Array(lines))
}

struct FormatterOutputImpl(String);

impl iced_x86::FormatterOutput for FormatterOutputImpl {
    fn write(&mut self, text: &str, _kind: iced_x86::FormatterTextKind) {
        self.0.push_str(text);
    }
}

fn resolve_v8_isolate(dump: &Dump) -> Option<u64> {
    annotation_hex(dump, "v8_isolate_address")
}

fn annotation_hex(dump: &Dump, key: &str) -> Option<u64> {
    for (k, v) in &dump.annotations {
        if k == key {
            let hex = v.trim_start_matches("0x").trim_start_matches("0X");
            if let Ok(va) = u64::from_str_radix(hex, 16) {
                return Some(va);
            }
        }
    }
    None
}

/// x64 StandardFrameConstants / JavaScript frame slots (V8 ≥ 13, frame pointer
/// relative). Layout: [fp-8]=context, [fp-16]=JSFunction, [fp-24]=type marker.
const K_CONTEXT_OFFSET: i64 = -8;
const K_FUNCTION_OFFSET: i64 = -16;
const K_MARKER_OFFSET: i64 = -24;
/// Pre-V8-13 layout: [fp-8]=marker, [fp-16]=context, [fp-24]=JSFunction.
const K_FUNCTION_OFFSET_LEGACY: i64 = -24;

/// Compressed-pointer heap layouts (bytes) for V8 14.6 (Chromium 146 /
/// Electron 41), from js-function.tq / shared-function-info.tq / scope-info.tq.
const JSFUNCTION_SHARED_FUNCTION_INFO: u64 = 16; // after dispatch_handle(int32)
const JSFUNCTION_CONTEXT: u64 = 20;
const SFI_NAME_OR_SCOPE_INFO: u64 = 12; // after trusted + untrusted func data

/// V8 String: map(0), raw_hash_field(4), length(8), chars(12).
const STRING_LENGTH: u64 = 8;
const STRING_CHARS: u64 = 12;
const MAX_JS_NAME_LEN: u32 = 4096;

/// Instance-type heuristics: string types occupy the low range (< 0x40) and
/// the one-byte encoding bit is 0x08 (SEQ_ONE=0x28, INTERNALIZED_ONE=0x08).
const STRING_ITYPE_MAX: u16 = 0x40;
const STRING_ONE_BYTE_BIT: u16 = 0x08;
const STRING_EXTERNAL_BIT: u16 = 0x02;

/// SFI/Script field offsets (script.tq).
const SFI_SCRIPT: u64 = 20;
const SCRIPT_NAME: u64 = 8;
const SCRIPT_LINE_OFFSET: u64 = 12;
const SCRIPT_LINE_ENDS: u64 = 28;
/// ScopeInfo position_info.start (Smi) — character offset into the source.
const SCOPE_POSITION_START: u64 = 16;
/// FixedArray: map(0), length Smi(4), elements(8).
const FIXED_ARRAY_LENGTH: u64 = 4;
const FIXED_ARRAY_DATA: u64 = 8;

/// External pointer table (sandbox EPT), V8 14.6: 16-byte tagged entries,
/// handle = index << 6, payload = entry & 48-bit mask, resource chars at +16.
const EPT_ENTRY_SIZE: u64 = 16;
const EPT_INDEX_SHIFT: u32 = 6;
const EPT_PAYLOAD_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

/// ScopeInfo layout (scope-info.tq): flags(4), parameter_count Smi(8),
/// context_local_count Smi(12), position_info two Smis(16,20), then
/// flag-dependent slots from +24.
const SCOPE_FLAGS: u64 = 4;
const SCOPE_PARAM_COUNT: u64 = 8;
const SCOPE_LOCAL_COUNT: u64 = 12;
const SCOPE_DYNAMIC_START: u64 = 24;
const SCOPE_SCOPE_TYPE_MASK: u32 = 0xF;
const SCOPE_TYPE_MODULE: u32 = 5;
const SCOPE_FLAG_SAVED_CLASS_VARIABLE: u32 = 1 << 10;
const SCOPE_FUNCTION_VARIABLE_SHIFT: u32 = 12;
const SCOPE_FUNCTION_VARIABLE_MASK: u32 = 0x3;
const SCOPE_FLAG_INFERRED_FUNCTION_NAME: u32 = 1 << 14;
const SCOPE_MAX_INLINED_LOCAL_NAMES: u32 = 512;

fn walk_thread_stacks(
    dump: &Dump,
    space: &AddressSpace,
    isolate_va: Option<u64>,
    symbolizer: Option<&Symbolizer>,
) -> Vec<V8StackFrame> {
    let mut frames = Vec::new();
    let ept_base = std::cell::Cell::new(None);

    // Pointer-compression cage base: RO space starts at the cage start in
    // shared-cage builds; fall back to deriving it from frame JSFunctions.
    let cage_base = annotation_hex(dump, "v8_ro_space_firstpage_address");

    // Build module VA ranges for frame classification
    let module_ranges: Vec<(u64, u64)> = dump.modules.iter().map(|m| (m.base_va, m.size)).collect();
    let mut unwind_tables = crate::unwind::UnwindTables::new(&dump.modules);

    for thread in &dump.threads {
        let tid = thread.id;

        // Prefer exception context for the crashed thread
        let mut regs = thread.registers.clone();
        if let Some(ref exc) = dump.exception
            && exc.thread_id == tid
            && let Some(ref ctx) = exc.context
        {
            regs = ctx.clone();
        }

        let stack_va = thread.stack_va;
        let stack_end = thread.stack_va.saturating_add(thread.stack_size);
        let mut depth = 0usize;
        let mut seen = std::collections::HashSet::new();
        let mut via_leaf = false;

        loop {
            let rip = regs.rip();
            let rsp = regs.rsp();
            let rbp = regs.rbp();
            if rip == 0 || depth >= 256 || !seen.insert((rip, rsp)) {
                break;
            }
            // Reject implausible PCs (garbage unwound frames): must be in a
            // module or a captured region — unless we got here via a
            // validated fp-chain link (JIT code pages may be uncaptured).
            let in_module = module_ranges.iter().any(|&(b, s)| rip >= b && rip < b + s);
            if !in_module && space.region_at(rip).is_none() && via_leaf {
                break;
            }

            let marker = read_u64(space, rbp.wrapping_add_signed(K_MARKER_OFFSET));
            let sym_name = symbolizer
                .and_then(|s| s.resolve(rip))
                .map(|r| r.function_name.clone())
                .unwrap_or_else(|| format!("0x{:X}", rip));
            let offset = symbolizer
                .and_then(|s| s.resolve(rip))
                .map(|r| r.offset)
                .unwrap_or(0);

            let frame_type = classify_frame(rip, &module_ranges, space, marker);
            let js = decode_js_frame(space, rbp, cage_base, isolate_va, &module_ranges, &ept_base);
            let frame_type = refine_type(frame_type, js.is_some(), rip, &module_ranges);
            let (js_function_name, script_name, script_line) = js
                .map(|i| (i.name, i.script_name, i.script_line))
                .unwrap_or((None, None, None));

            frames.push(V8StackFrame {
                thread_id: tid,
                depth,
                frame_type,
                native_symbol: sym_name,
                native_offset: offset,
                return_address: rip,
                frame_pointer: rbp,
                js_function_name,
                script_name,
                script_line,
            });
            depth += 1;

            // Advance, in order of preference:
            // 1. x64 unwind info (.pdata) — authoritative for module code
            //    (Chrome is built without frame pointers; rbp is just a GPR).
            let mut advanced = false;
            if let Some((base, rt)) = unwind_tables.lookup(space, rip)
                && crate::unwind::unwind_step(&mut regs, space, base, rt)
            {
                advanced = true;
            }
            if advanced {
                via_leaf = false;
                continue;
            }
            // 2. V8-style frame-pointer chain — JIT frames have real frame
            //    pointers but no RUNTIME_FUNCTION records.
            let saved_rbp = read_u64(space, rbp);
            let fp_ret = read_u64(space, rbp.wrapping_add(8));
            let fp_chain = rbp >= stack_va && saved_rbp > rbp && saved_rbp < stack_end;
            // Terminal link: the final builtin/C++ boundary frame may have its
            // fp outside the captured stack; still follow its return address
            // once when it looks like plausible code.
            let terminal_link = !fp_chain
                && rbp >= stack_va
                && rbp < stack_end
                && fp_ret != 0
                && (module_ranges
                    .iter()
                    .any(|&(b, s)| fp_ret >= b && fp_ret < b + s)
                    || space
                        .region_at(fp_ret)
                        .map(|r| r.protection & crate::model::Protection::EXECUTE != 0)
                        .unwrap_or(false));
            if fp_ret != 0 && (fp_chain || terminal_link) {
                regs.set(crate::arch::x64_indices::RIP, fp_ret);
                regs.set(crate::arch::x64_indices::RBP, saved_rbp);
                regs.set(crate::arch::x64_indices::RSP, rbp + 16);
                via_leaf = false;
                continue;
            }
            // 3. Leaf function: return address at [rsp]
            let leaf_ret = read_u64(space, rsp);
            if leaf_ret != 0 {
                regs.set(crate::arch::x64_indices::RIP, leaf_ret);
                regs.set(crate::arch::x64_indices::RSP, rsp + 8);
                via_leaf = true;
                continue;
            }
            break;
        }
    }

    frames
}

/// If a validated JSFunction was decoded but the marker-based classification
/// missed it, upgrade non-JS types when the return address is JIT code
/// (outside all loaded modules).
fn refine_type(
    frame_type: V8FrameType,
    has_js_function: bool,
    return_address: u64,
    module_ranges: &[(u64, u64)],
) -> V8FrameType {
    if !has_js_function {
        return frame_type;
    }
    match frame_type {
        V8FrameType::JavaScript | V8FrameType::OptimizedJavaScript => frame_type,
        _ => {
            let in_module = module_ranges
                .iter()
                .any(|&(base, size)| return_address >= base && return_address < base + size);
            if in_module {
                V8FrameType::JavaScript
            } else {
                V8FrameType::OptimizedJavaScript
            }
        }
    }
}

fn classify_frame(
    return_address: u64,
    module_ranges: &[(u64, u64)],
    space: &AddressSpace,
    frame_marker: u64,
) -> V8FrameType {
    // Check V8 frame marker first
    if let Some(ft) = decode_v8_marker(frame_marker) {
        return ft;
    }

    // Check if address falls within any loaded module
    let in_module = module_ranges
        .iter()
        .any(|&(base, size)| return_address >= base && return_address < base + size);

    if in_module {
        return V8FrameType::Builtin;
    }

    // Check if address is in executable memory (likely JIT-compiled JS code)
    if let Some(region) = space.region_at(return_address) {
        let is_exec = region.protection & crate::model::Protection::EXECUTE != 0;
        if is_exec {
            return V8FrameType::OptimizedJavaScript;
        }
    }

    V8FrameType::Cpp
}

/// Decode a V8 frame marker to a frame type.
/// Markers are raw `StackFrame::Type` ints (STACK_FRAME_TYPE_LIST order,
/// frames.h) stored at [fp + K_MARKER_OFFSET].
fn decode_v8_marker(marker: u64) -> Option<V8FrameType> {
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

fn read_u64(space: &AddressSpace, va: u64) -> u64 {
    match space.read(va, 8) {
        Some(bytes) => {
            let arr: [u8; 8] = bytes.try_into().unwrap();
            u64::from_le_bytes(arr)
        }
        None => 0,
    }
}

fn read_u32(space: &AddressSpace, va: u64) -> Option<u32> {
    let bytes = space.read(va, 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

/// Decompress a 32-bit tagged pointer within the pointer-compression cage.
/// Returns the untagged heap address, or None for Smis/null.
fn decompress(cage_base: u64, compressed: u32) -> Option<u64> {
    if compressed == 0 || compressed & 1 == 0 {
        return None;
    }
    Some(cage_base + (compressed & !1) as u64)
}

/// Everything decoded from a JavaScript stack frame's JSFunction.
struct JsFrameInfo {
    name: Option<String>,
    script_name: Option<String>,
    script_line: Option<u32>,
}

/// Resolve JS frame info at `fp` by walking
/// JSFunction → SharedFunctionInfo → {name_or_scope_info, script}, decoding
/// the function name (direct String or ScopeInfo slots), the script name
/// (inline or external string), and the line number (ScopeInfo position vs
/// Script.line_ends). Validates the JSFunction via its context field matching
/// [fp-8]. Returns None when the frame has no valid JSFunction.
fn decode_js_frame(
    space: &AddressSpace,
    fp: u64,
    cage_hint: Option<u64>,
    isolate_va: Option<u64>,
    module_ranges: &[(u64, u64)],
    ept_base: &std::cell::Cell<Option<u64>>,
) -> Option<JsFrameInfo> {
    for slot in [K_FUNCTION_OFFSET, K_FUNCTION_OFFSET_LEGACY] {
        let tagged = read_u64(space, fp.wrapping_add_signed(slot));
        if tagged & 1 != 1 {
            continue;
        }
        let heap = tagged & !1;
        // Cage base is 4 GiB-aligned; prefer the annotation when it agrees.
        let derived = tagged & 0xFFFF_FFFF_0000_0000;
        let cage = match cage_hint {
            Some(h) if heap >= h && heap < h + (1 << 32) => h,
            _ => derived,
        };

        // Validate: JSFunction.context (+20) must equal the frame's context
        // slot [fp-8] after decompression.
        let frame_context = read_u64(space, fp.wrapping_add_signed(K_CONTEXT_OFFSET));
        let fn_context = read_u32(space, heap + JSFUNCTION_CONTEXT)
            .and_then(|c| decompress(cage, c))
            .map(|h| h | 1);
        if fn_context != Some(frame_context) {
            continue;
        }

        let Some(sfi) = read_u32(space, heap + JSFUNCTION_SHARED_FUNCTION_INFO)
            .and_then(|c| decompress(cage, c))
        else {
            continue;
        };

        let mut info = JsFrameInfo {
            name: None,
            script_name: None,
            script_line: None,
        };
        let mut position = None;

        if let Some(name_or_scope) =
            read_u32(space, sfi + SFI_NAME_OR_SCOPE_INFO).and_then(|c| decompress(cage, c))
            && let Some(itype) = instance_type(space, cage, name_or_scope)
        {
            if itype < STRING_ITYPE_MAX {
                info.name = read_v8_string(space, name_or_scope, itype);
            } else {
                info.name = scope_info_function_name(space, cage, name_or_scope);
                position = read_u32(space, name_or_scope + SCOPE_POSITION_START).and_then(smi);
            }
        }
        if info.name.is_none() {
            info.name = Some("<anonymous>".to_string());
        }

        if let Some(script) = read_u32(space, sfi + SFI_SCRIPT).and_then(|c| decompress(cage, c)) {
            info.script_name =
                decode_script_name(space, cage, script, isolate_va, module_ranges, ept_base);
            if let Some(pos) = position {
                info.script_line = decode_script_line(space, cage, script, pos);
            }
        }
        return Some(info);
    }
    None
}

/// Decode Script.name — an inline or external string.
fn decode_script_name(
    space: &AddressSpace,
    cage: u64,
    script: u64,
    isolate_va: Option<u64>,
    module_ranges: &[(u64, u64)],
    ept_base: &std::cell::Cell<Option<u64>>,
) -> Option<String> {
    let name_obj = read_u32(space, script + SCRIPT_NAME).and_then(|c| decompress(cage, c))?;
    let itype = instance_type(space, cage, name_obj)?;
    if itype >= STRING_ITYPE_MAX {
        return None;
    }
    if itype & STRING_EXTERNAL_BIT == 0 {
        return read_v8_string(space, name_obj, itype);
    }

    // External string: resource is an EPT handle at +12.
    let handle = read_u32(space, name_obj + STRING_CHARS)?;
    if handle == 0 || handle as u64 & ((1 << EPT_INDEX_SHIFT) - 1) != 0 {
        return None;
    }
    let len = read_u32(space, name_obj + STRING_LENGTH)?;
    if len == 0 || len > MAX_JS_NAME_LEN {
        return None;
    }

    let one_byte = itype & STRING_ONE_BYTE_BIT != 0;
    let base = match ept_base.get() {
        Some(b) => Some(b),
        None => {
            let b = find_ept_base(space, isolate_va?, handle, len, one_byte, module_ranges);
            ept_base.set(b);
            b
        }
    }?;
    external_string_via_ept(space, base, handle, len, one_byte)
}

/// Decode an external string's chars through the external pointer table.
fn external_string_via_ept(
    space: &AddressSpace,
    ept_base: u64,
    handle: u32,
    len: u32,
    one_byte: bool,
) -> Option<String> {
    let entry = try_read_u64(
        space,
        ept_base + EPT_ENTRY_SIZE * (handle as u64 >> EPT_INDEX_SHIFT),
    )?;
    let resource = entry & EPT_PAYLOAD_MASK;
    if resource == 0 {
        return None;
    }
    // ExternalOneByteStringResource: vtable(0), impl fields, char data at +16
    // (blink layout, verified against this Chromium build).
    let chars = try_read_u64(space, resource + 16)?;
    read_external_chars(space, chars, len, one_byte)
}

/// Locate the external pointer table base by scanning the isolate region for
/// a pointer B whose table entry for `handle` resolves to a resource with a
/// module vtable and a fully printable char payload of exactly `len` chars.
fn find_ept_base(
    space: &AddressSpace,
    isolate_va: u64,
    handle: u32,
    len: u32,
    one_byte: bool,
    module_ranges: &[(u64, u64)],
) -> Option<u64> {
    let region = space.region_at(isolate_va)?;
    let idx = handle as u64 >> EPT_INDEX_SHIFT;
    // Pass 1 rejects payloads that fall back into the candidate table's own
    // reservation window (evacuation entries / wrong tables like the
    // CodePointerTable). Pass 2 (fallback) accepts any validated payload.
    for reject_internal in [true, false] {
        for chunk in region.data.chunks_exact(8) {
            let b = u64::from_le_bytes(chunk.try_into().unwrap());
            if b < 0x10000 || b & 7 != 0 {
                continue;
            }
            let Some(entry) = try_read_u64(space, b + EPT_ENTRY_SIZE * idx) else {
                continue;
            };
            let resource = entry & EPT_PAYLOAD_MASK;
            if resource == 0 {
                continue;
            }
            if reject_internal && resource >= b && resource < b + (2 << 20) {
                continue;
            }
            // The resource is a heap object (not module code), whose first
            // word is a vtable inside a loaded module.
            if module_ranges
                .iter()
                .any(|&(base, size)| resource >= base && resource < base + size)
            {
                continue;
            }
            let Some(vtable) = try_read_u64(space, resource) else {
                continue;
            };
            if !module_ranges
                .iter()
                .any(|&(base, size)| vtable >= base && vtable < base + size)
            {
                continue;
            }
            // Full end-to-end check: chars must be readable and printable.
            let Some(chars) = try_read_u64(space, resource + 16) else {
                continue;
            };
            if read_external_chars(space, chars, len, one_byte).is_some() {
                return Some(b);
            }
        }
    }
    None
}

/// Read `len` characters from an external string's char buffer.
fn read_external_chars(space: &AddressSpace, ptr: u64, len: u32, one_byte: bool) -> Option<String> {
    let len = len as usize;
    if one_byte {
        let bytes = space.read(ptr, len)?;
        if bytes
            .iter()
            .all(|&b| (0x20..=0x7e).contains(&b) || b >= 0x80)
        {
            return Some(String::from_utf8_lossy(bytes).into_owned());
        }
    } else {
        let bytes = space.read(ptr, len.checked_mul(2)?)?;
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

/// Compute a 1-based line number: binary-search Script.line_ends (FixedArray
/// of Smi source positions, one per line end) for the function's start
/// position, then add Script.line_offset.
fn decode_script_line(space: &AddressSpace, cage: u64, script: u64, position: i32) -> Option<u32> {
    let line_ends = read_u32(space, script + SCRIPT_LINE_ENDS).and_then(|c| decompress(cage, c))?;
    let len = smi(read_u32(space, line_ends + FIXED_ARRAY_LENGTH)?)?;
    if !(0..=10_000_000).contains(&len) {
        return None;
    }
    let line_offset = smi(read_u32(space, script + SCRIPT_LINE_OFFSET)?).unwrap_or(0);

    let (mut lo, mut hi) = (0i32, len);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let v = smi(read_u32(
            space,
            line_ends + FIXED_ARRAY_DATA + 4 * mid as u64,
        )?)?;
        if v < position {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    u32::try_from(lo + line_offset + 1).ok()
}

fn try_read_u64(space: &AddressSpace, va: u64) -> Option<u64> {
    let bytes = space.read(va, 8)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

/// Read a heap object's instance type: Map at +0 (compressed), u16 at Map+8.
fn instance_type(space: &AddressSpace, cage: u64, heap: u64) -> Option<u16> {
    let map_c = read_u32(space, heap)?;
    let map = decompress(cage, map_c)?;
    let b = space.read(map + 8, 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

/// Read an inline (Seq*/Internalized) string payload with structural
/// validation. Layout: map(0), raw_hash(4), length(8), chars(12).
fn read_v8_string(space: &AddressSpace, va: u64, itype: u16) -> Option<String> {
    let len = read_u32(space, va + STRING_LENGTH)?;
    if len == 0 || len > MAX_JS_NAME_LEN {
        return None;
    }
    let len = len as usize;

    if itype & STRING_ONE_BYTE_BIT != 0 {
        let bytes = space.read(va + STRING_CHARS, len)?;
        if bytes
            .iter()
            .all(|&b| (0x20..=0x7e).contains(&b) || b >= 0x80)
        {
            return Some(String::from_utf8_lossy(bytes).into_owned());
        }
    } else {
        let bytes = space.read(va + STRING_CHARS, len.checked_mul(2)?)?;
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

/// Extract a function name from a ScopeInfo when the SFI has no direct name.
/// Walks the flag-dependent slots to function_variable_info.name and
/// inferred_function_name (both String|Undefined|Zero).
fn scope_info_function_name(space: &AddressSpace, cage: u64, scope: u64) -> Option<String> {
    let flags = read_u32(space, scope + SCOPE_FLAGS)?;
    let local_count = smi(read_u32(space, scope + SCOPE_LOCAL_COUNT)?)?;
    if local_count < 0 || local_count as u32 > 0x10000 {
        return None;
    }
    let _ = read_u32(space, scope + SCOPE_PARAM_COUNT)?;

    let mut off = SCOPE_DYNAMIC_START;
    if flags & SCOPE_SCOPE_TYPE_MASK == SCOPE_TYPE_MODULE {
        off += 4; // module_variable_count
    }
    let n = local_count as u64;
    // context_local_names[n] (inlined) or names hashtable pointer
    off += if (n as u32) < SCOPE_MAX_INLINED_LOCAL_NAMES {
        4 * n
    } else {
        4
    };
    off += 4 * n; // context_local_infos[n]
    if flags & SCOPE_FLAG_SAVED_CLASS_VARIABLE != 0 {
        off += 4;
    }

    let mut candidates = [None, None];
    let alloc = (flags >> SCOPE_FUNCTION_VARIABLE_SHIFT) & SCOPE_FUNCTION_VARIABLE_MASK;
    if alloc != 0 {
        candidates[0] = Some(off); // function_variable_info.name
        off += 8; // name + context_or_stack_slot_index
    }
    if flags & SCOPE_FLAG_INFERRED_FUNCTION_NAME != 0 {
        candidates[1] = Some(off); // inferred_function_name
    }

    for slot in candidates.into_iter().flatten() {
        let Some(name_obj) = read_u32(space, scope + slot).and_then(|c| decompress(cage, c)) else {
            continue;
        };
        let Some(itype) = instance_type(space, cage, name_obj) else {
            continue;
        };
        if itype < STRING_ITYPE_MAX
            && let Some(name) = read_v8_string(space, name_obj, itype)
        {
            return Some(name);
        }
    }
    None
}

/// Decode a 31-bit compressed Smi (low 32 bits, tag bit 0).
fn smi(raw: u32) -> Option<i32> {
    if raw & 1 != 0 {
        return None;
    }
    Some((raw as i32) >> 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::RegisterSet;
    use crate::arch::x64_indices;
    use crate::error::Provenance;
    use crate::model::{MemState, Module, RegionClass, Thread};
    use crate::space::{AddressRegion, AddressSpace};

    fn make_stack_thread(rbp: u64, rsp: u64, rip: u64, stack_va: u64, stack_size: u64) -> Thread {
        let mut regs = RegisterSet::new();
        regs.set(x64_indices::RBP, rbp);
        regs.set(x64_indices::RSP, rsp);
        regs.set(x64_indices::RIP, rip);
        Thread {
            id: 1,
            registers: regs,
            stack_va,
            stack_size,
            teb_va: 0,
            provenance: Provenance {
                stream_type: 3,
                file_offset: 0,
                rva: 0,
            },
        }
    }

    fn make_synthetic_stack() -> (AddressSpace, Dump) {
        let mut space = AddressSpace::new(2);
        let mut stack_data = vec![0u8; 0x500];
        // RBP=0x1000: saved_RBP=0x1200, return_addr=0x7FFA1000
        // RBP=0x1200: saved_RBP=0x1400, return_addr=0x7FFA2000
        // RBP=0x1400: saved_RBP=0
        stack_data[0x000..0x008].copy_from_slice(&0x1200u64.to_le_bytes());
        stack_data[0x008..0x010].copy_from_slice(&0x7FFA1000u64.to_le_bytes());
        stack_data[0x200..0x208].copy_from_slice(&0x1400u64.to_le_bytes());
        stack_data[0x208..0x210].copy_from_slice(&0x7FFA2000u64.to_le_bytes());
        stack_data[0x400..0x408].copy_from_slice(&0u64.to_le_bytes());
        stack_data[0x408..0x410].copy_from_slice(&0u64.to_le_bytes());
        space
            .add_region(AddressRegion {
                va_start: 0x1000,
                size: 0x500,
                data: stack_data,
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Stack,
            })
            .unwrap();
        space
            .add_region(AddressRegion {
                va_start: 0x7FFA0000,
                size: 0x10000,
                data: vec![0u8; 0x10000],
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Image,
            })
            .unwrap();

        let dump = Dump {
            system_info: None,
            modules: vec![Module {
                name: "test.dll".into(),
                base_va: 0x7FFA0000,
                size: 0x10000,
                checksum: 0,
                codeview_guid: None,
                pdb_name: None,
                provenance: Provenance {
                    stream_type: 2,
                    file_offset: 0,
                    rva: 0,
                },
            }],
            threads: vec![make_stack_thread(0x1000, 0x1000, 0x7FFA1000, 0x1000, 0x500)],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            annotations: vec![],
            file_size: 0,
        };

        (space, dump)
    }

    #[test]
    fn empty_stack_produces_no_frames() {
        let space = AddressSpace::new(4);
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            annotations: vec![],
            file_size: 0,
        };
        let a = V8Analyzer::new();
        let out = a.analyze(&dump, &space);
        let frames = out.custom.iter().find(|(k, _)| k == "v8_frames");
        assert!(frames.is_some());
    }

    #[test]
    fn synthetic_stack_walks_correct_frame_count() {
        let (space, dump) = make_synthetic_stack();
        let a = V8Analyzer::new();
        let out = a.analyze(&dump, &space);
        let count: usize = out
            .custom
            .iter()
            .find(|(k, _)| k == "v8_frame_count")
            .and_then(|(_, v): &(String, serde_json::Value)| v.as_u64().map(|n| n as usize))
            .unwrap_or(0);
        assert!(count >= 2, "expected at least 2 frames, got {count}");
    }

    #[test]
    fn terminates_on_loop() {
        let mut space = AddressSpace::new(2);
        let mut stack_data = vec![0u8; 0x200];
        stack_data[0x000..0x008].copy_from_slice(&0x1000u64.to_le_bytes()); // self-loop
        stack_data[0x008..0x010].copy_from_slice(&0x7FFA1000u64.to_le_bytes());
        space
            .add_region(AddressRegion {
                va_start: 0x1000,
                size: 0x200,
                data: stack_data,
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Stack,
            })
            .unwrap();
        space
            .add_region(AddressRegion {
                va_start: 0x7FFA0000,
                size: 0x10000,
                data: vec![0u8; 0x10000],
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Image,
            })
            .unwrap();

        let dump = Dump {
            system_info: None,
            modules: vec![Module {
                name: "test.dll".into(),
                base_va: 0x7FFA0000,
                size: 0x10000,
                checksum: 0,
                codeview_guid: None,
                pdb_name: None,
                provenance: Provenance {
                    stream_type: 2,
                    file_offset: 0,
                    rva: 0,
                },
            }],
            threads: vec![make_stack_thread(0x1000, 0x1000, 0x7FFA1000, 0x1000, 0x200)],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            annotations: vec![],
            file_size: 0,
        };

        let a = V8Analyzer::new();
        let out = a.analyze(&dump, &space);
        let count: usize = out
            .custom
            .iter()
            .find(|(k, _)| k == "v8_frame_count")
            .and_then(|(_, v): &(String, serde_json::Value)| v.as_u64().map(|n| n as usize))
            .unwrap_or(0);
        assert!(count <= 256, "should terminate on loop");
    }

    #[test]
    fn resolve_isolate_from_annotations() {
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            annotations: vec![("v8_isolate_address".into(), "0x68340051c000".into())],
            file_size: 0,
        };
        let iso = resolve_v8_isolate(&dump);
        assert_eq!(iso, Some(0x68340051c000));
    }

    #[test]
    fn no_annotations_returns_none() {
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            annotations: vec![],
            file_size: 0,
        };
        assert_eq!(resolve_v8_isolate(&dump), None);
    }

    // ── JS frame decoding tests ──────────────────────────────────────────

    const CAGE: u64 = 0x1_0000_0000;
    const FP: u64 = 0x8100;

    struct V8HeapBuilder {
        data: Vec<u8>,
    }

    impl V8HeapBuilder {
        fn new() -> Self {
            V8HeapBuilder {
                data: vec![0u8; 0x1000],
            }
        }
        fn w32(&mut self, off: usize, v: u32) -> &mut Self {
            self.data[off..off + 4].copy_from_slice(&v.to_le_bytes());
            self
        }
        fn bytes(&mut self, off: usize, b: &[u8]) -> &mut Self {
            self.data[off..off + b.len()].copy_from_slice(b);
            self
        }
        fn cptr(off: usize) -> u32 {
            (off as u32) | 1
        }
        // map object with the given instance type at off
        fn map(&mut self, off: usize, itype: u16) -> &mut Self {
            self.w32(off, 0); // meta map (unused)
            self.data[off + 8..off + 10].copy_from_slice(&itype.to_le_bytes());
            self
        }
        // one-byte string at off, with map at map_off
        fn string(&mut self, off: usize, map_off: usize, s: &str) -> &mut Self {
            self.w32(off, Self::cptr(map_off));
            self.w32(off + 4, 0x1234_5678); // raw hash
            self.w32(off + 8, s.len() as u32);
            self.bytes(off + 12, s.as_bytes());
            self
        }
    }

    const MAP_STRING: usize = 0x100;
    const MAP_SCOPE: usize = 0x140;
    const NAME_STR: usize = 0x200;
    const SFI: usize = 0x300;
    const SCOPE: usize = 0x400;
    const FUNC: usize = 0x500;
    const CONTEXT: usize = 0x600;

    fn build_space(heap: V8HeapBuilder, fp16: u64) -> AddressSpace {
        let mut space = AddressSpace::new(4);
        space
            .add_region(AddressRegion {
                va_start: CAGE,
                size: heap.data.len() as u64,
                data: heap.data,
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Private,
            })
            .unwrap();
        let mut stack = vec![0u8; 0x1000];
        let fp_off = (FP - 0x8000) as usize;
        // [fp-8] = context (full tagged pointer), [fp-16] = JSFunction
        stack[fp_off - 8..fp_off].copy_from_slice(&((CAGE + CONTEXT as u64) | 1).to_le_bytes());
        stack[fp_off - 16..fp_off - 8].copy_from_slice(&fp16.to_le_bytes());
        space
            .add_region(AddressRegion {
                va_start: 0x8000,
                size: 0x1000,
                data: stack,
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Stack,
            })
            .unwrap();
        space
    }

    fn base_heap() -> V8HeapBuilder {
        let mut h = V8HeapBuilder::new();
        h.map(MAP_STRING, 0x28); // SEQ_ONE_BYTE_STRING-ish
        h.map(MAP_SCOPE, 0x11e);
        h.string(NAME_STR, MAP_STRING, "render0");
        h.w32(FUNC + 16, V8HeapBuilder::cptr(SFI)); // shared_function_info
        h.w32(FUNC + 20, V8HeapBuilder::cptr(CONTEXT)); // context
        h
    }

    fn decode(space: &AddressSpace, fp: u64) -> Option<JsFrameInfo> {
        let ept = std::cell::Cell::new(None);
        decode_js_frame(space, fp, Some(CAGE), None, &[], &ept)
    }

    #[test]
    fn decodes_direct_string_name() {
        let mut h = base_heap();
        h.w32(SFI + 12, V8HeapBuilder::cptr(NAME_STR)); // name_or_scope_info
        let space = build_space(h, (CAGE + FUNC as u64) | 1);
        let info = decode(&space, FP).unwrap();
        assert_eq!(info.name.as_deref(), Some("render0"));
    }

    #[test]
    fn decodes_scope_info_function_variable_name() {
        let mut h = base_heap();
        h.w32(SFI + 12, V8HeapBuilder::cptr(SCOPE));
        // ScopeInfo: flags with function_variable = STACK (1 << 12), locals = 0
        h.w32(SCOPE, V8HeapBuilder::cptr(MAP_SCOPE));
        h.w32(SCOPE + 4, 1 << 12); // flags
        h.w32(SCOPE + 8, 0); // parameter_count Smi
        h.w32(SCOPE + 12, 0); // context_local_count Smi
        h.w32(SCOPE + 24, V8HeapBuilder::cptr(NAME_STR)); // function_variable_info.name
        let space = build_space(h, (CAGE + FUNC as u64) | 1);
        let info = decode(&space, FP).unwrap();
        assert_eq!(info.name.as_deref(), Some("render0"));
    }

    #[test]
    fn anonymous_when_scope_has_no_name() {
        let mut h = base_heap();
        h.w32(SFI + 12, V8HeapBuilder::cptr(SCOPE));
        h.w32(SCOPE, V8HeapBuilder::cptr(MAP_SCOPE));
        h.w32(SCOPE + 4, 4); // flags: FUNCTION_SCOPE, no function_variable
        let space = build_space(h, (CAGE + FUNC as u64) | 1);
        let info = decode(&space, FP).unwrap();
        assert_eq!(info.name.as_deref(), Some("<anonymous>"));
    }

    #[test]
    fn rejects_frame_without_jsfunction() {
        let h = base_heap();
        let space = build_space(h, 0); // fp-16 not a tagged pointer
        assert!(decode(&space, FP).is_none());
    }

    #[test]
    fn rejects_context_mismatch() {
        let mut h = base_heap();
        h.w32(SFI + 12, V8HeapBuilder::cptr(NAME_STR));
        h.w32(FUNC + 20, V8HeapBuilder::cptr(0x700)); // wrong context
        let space = build_space(h, (CAGE + FUNC as u64) | 1);
        assert!(decode(&space, FP).is_none());
    }

    // ── script name / line tests ─────────────────────────────────────────

    const SCRIPT: usize = 0x700;
    const LINE_ENDS: usize = 0x780;
    const EXT_NAME: usize = 0x7c0;
    const MAP_EXT_STRING: usize = 0x180;

    /// Heap with SFI → ScopeInfo (position 45) and SFI → Script.
    fn heap_with_script() -> V8HeapBuilder {
        let mut h = base_heap();
        h.w32(SFI + 12, V8HeapBuilder::cptr(SCOPE));
        h.w32(SCOPE, V8HeapBuilder::cptr(MAP_SCOPE));
        h.w32(SCOPE + 4, 4); // FUNCTION_SCOPE, no name slots
        h.w32(SCOPE + 16, 45 << 1); // position_info.start Smi = 45
        h.w32(SFI + 20, V8HeapBuilder::cptr(SCRIPT)); // script
        // Script: name = external string, line_offset = 0, line_ends FixedArray
        h.w32(SCRIPT + 8, V8HeapBuilder::cptr(EXT_NAME));
        h.w32(SCRIPT + 12, 0); // line_offset Smi
        h.w32(SCRIPT + 28, V8HeapBuilder::cptr(LINE_ENDS));
        h.w32(LINE_ENDS, 0); // map (unused)
        h.w32(LINE_ENDS + 4, 5 << 1); // length Smi = 5
        for (i, pos) in [10i32, 20, 30, 40, 50].iter().enumerate() {
            h.w32(LINE_ENDS + 8 + 4 * i, (pos << 1) as u32);
        }
        // External name string: map itype 0x2a, len 6, EPT handle at +12
        h.map(MAP_EXT_STRING, 0x2a);
        h.w32(EXT_NAME, V8HeapBuilder::cptr(MAP_EXT_STRING));
        h.w32(EXT_NAME + 4, 0xdead_beef);
        h.w32(EXT_NAME + 8, 6); // length
        h.w32(EXT_NAME + 12, 3 << EPT_INDEX_SHIFT); // handle → index 3
        h
    }

    #[test]
    fn resolves_script_line_from_line_ends() {
        let h = heap_with_script();
        let space = build_space(h, (CAGE + FUNC as u64) | 1);
        let info = decode(&space, FP).unwrap();
        // position 45 → first line_end >= 45 is index 4 → line 5
        assert_eq!(info.script_line, Some(5));
    }

    #[test]
    fn resolves_external_script_name_via_ept() {
        const ISOLATE: u64 = 0x9_0000;
        const EPT_BASE: u64 = 0x9_4000;
        const RESOURCE: u64 = 0xa_0000;
        const CHARS: u64 = 0xa_1000;
        const MODULE: (u64, u64) = (0x7ff0_0000, 0x1_0000);

        let h = heap_with_script();
        let mut space = build_space(h, (CAGE + FUNC as u64) | 1);

        // isolate region containing the EPT base pointer
        let mut iso = vec![0u8; 0x8000];
        iso[(EPT_BASE - ISOLATE) as usize..(EPT_BASE - ISOLATE) as usize + 8]
            .copy_from_slice(&EPT_BASE.to_le_bytes());
        // EPT entry 3 → resource
        iso[(EPT_BASE - ISOLATE) as usize + 16 * 3..(EPT_BASE - ISOLATE) as usize + 16 * 3 + 8]
            .copy_from_slice(&RESOURCE.to_le_bytes());
        space
            .add_region(AddressRegion {
                va_start: ISOLATE,
                size: iso.len() as u64,
                data: iso,
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Private,
            })
            .unwrap();

        // resource: vtable into module, chars at +16
        let mut res = vec![0u8; 0x2000];
        res[0..8].copy_from_slice(&(MODULE.0 + 0x100).to_le_bytes());
        res[16..24].copy_from_slice(&CHARS.to_le_bytes());
        res[(CHARS - RESOURCE) as usize..(CHARS - RESOURCE) as usize + 6]
            .copy_from_slice(b"app.js");
        space
            .add_region(AddressRegion {
                va_start: RESOURCE,
                size: res.len() as u64,
                data: res,
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Private,
            })
            .unwrap();

        let ept = std::cell::Cell::new(None);
        let info = decode_js_frame(&space, FP, Some(CAGE), Some(ISOLATE), &[MODULE], &ept).unwrap();
        assert_eq!(info.script_name.as_deref(), Some("app.js"));
        assert_eq!(info.script_line, Some(5));
    }
}

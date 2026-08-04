//! Crash-cause diagnosis: fuses exception semantics, disassembly,
//! MemoryInfoList classification, and cage-aware fault analysis into a
//! single verdict with confidence and evidence. Fails closed to `Unknown`.

use crate::analyzer::v8::annotation_hex;
use crate::analyzer::{Analyzer, AnalyzerOutput};
use crate::disasm::{self, InstrKind, Instruction};
use crate::model::{Dump, MemState};
use crate::space::AddressSpace;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrashVerdict {
    V8CheckFailure,
    V8OutOfMemory,
    StackOverflow,
    SmiTypeConfusion,
    V8ObjectAccess { instance_type: u16 },
    NullDeref,
    WildAccess,
    CorruptedCodePointer,
    WasmGuardFault,
    NoException,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Read,
    Write,
    Execute,
}

#[derive(Debug, Clone)]
pub struct CrashDiagnosis {
    pub verdict: CrashVerdict,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
    pub fault_va: Option<u64>,
    pub access: Option<AccessKind>,
    pub fatal_message: Option<String>,
    pub alternatives: Vec<(CrashVerdict, Confidence)>,
}

// Win32 page-protection bits (MemoryInfoList protection is raw).
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_GUARD: u32 = 0x100;
const PAGE_EXECUTE_ANY: u32 = 0x10 | 0x20 | 0x40 | 0x80;

const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC000_0005;
const EXCEPTION_BREAKPOINT: u32 = 0x8000_0003;
const EXCEPTION_STACK_OVERFLOW: u32 = 0xC000_00FD;

/// One classification rule's hit.
struct Hit {
    rule: u8,
    verdict: CrashVerdict,
    confidence: Confidence,
    evidence: Vec<String>,
}

struct Ctx<'a> {
    dump: &'a Dump,
    space: &'a AddressSpace,
    fault_va: Option<u64>,
    disasm: Vec<Instruction>,
    cage_base: Option<u64>,
}

/// Diagnose the dump's exception into a ranked verdict. Pure over
/// (dump, space); `Unknown` when nothing fires, `NoException` without an
/// exception stream.
pub fn diagnose(dump: &Dump, space: &AddressSpace) -> CrashDiagnosis {
    let Some(exc) = &dump.exception else {
        return CrashDiagnosis {
            verdict: CrashVerdict::NoException,
            confidence: Confidence::High,
            evidence: vec!["no exception stream in dump".into()],
            fault_va: None,
            access: None,
            fatal_message: None,
            alternatives: vec![],
        };
    };

    let fault_va = match exc.code {
        EXCEPTION_ACCESS_VIOLATION => exc.parameters.get(1).copied(),
        _ => None,
    };
    let access = if exc.code == EXCEPTION_ACCESS_VIOLATION {
        match exc.parameters.first() {
            Some(0) => Some(AccessKind::Read),
            Some(1) => Some(AccessKind::Write),
            Some(8) => Some(AccessKind::Execute),
            _ => None,
        }
    } else {
        None
    };
    let ctx = Ctx {
        dump,
        space,
        fault_va,
        disasm: disasm::decode_window(space, exc.address, 10),
        cage_base: annotation_hex(dump, "v8_ro_space_firstpage_address"),
    };

    let rules: Vec<fn(&Ctx) -> Option<Hit>> = vec![
        rule_fatal_message,
        rule_breakpoint,
        rule_stack_overflow,
        rule_wasm_guard,
        rule_smi_confusion,
        rule_object_access,
        rule_oom_state,
        rule_corrupted_code_pointer,
        rule_null_deref,
        rule_wild_access,
    ];
    let mut hits: Vec<Hit> = rules.iter().filter_map(|r| r(&ctx)).collect();
    // Highest confidence wins; ties break by rule order (lower rule id first).
    hits.sort_by(|a, b| b.confidence.cmp(&a.confidence).then(a.rule.cmp(&b.rule)));

    let fatal_message = fatal_message(dump, space, exc.thread_id);
    let Some(head) = hits.first() else {
        return CrashDiagnosis {
            verdict: CrashVerdict::Unknown,
            confidence: Confidence::Low,
            evidence: vec![format!(
                "exception code 0x{:08X} matched no classification rule",
                exc.code
            )],
            fault_va,
            access,
            fatal_message,
            alternatives: vec![],
        };
    };

    CrashDiagnosis {
        verdict: head.verdict.clone(),
        confidence: head.confidence,
        evidence: head.evidence.clone(),
        fault_va,
        access,
        fatal_message,
        alternatives: hits[1..]
            .iter()
            .map(|h| (h.verdict.clone(), h.confidence))
            .collect(),
    }
}

/// Rule 1: a captured V8 fatal/OOM message settles the cause.
fn rule_fatal_message(c: &Ctx) -> Option<Hit> {
    let exc = c.dump.exception.as_ref()?;
    let msg = fatal_message(c.dump, c.space, exc.thread_id)?;
    let oom = is_oom_message(&msg);
    Some(Hit {
        rule: 1,
        verdict: if oom {
            CrashVerdict::V8OutOfMemory
        } else {
            CrashVerdict::V8CheckFailure
        },
        confidence: Confidence::High,
        evidence: vec![format!("captured fatal message: {msg}")],
    })
}

/// Rule 2: breakpoint exception or int3/ud2 at RIP — V8 CHECK/DCHECK/abort.
fn rule_breakpoint(c: &Ctx) -> Option<Hit> {
    let exc = c.dump.exception.as_ref()?;
    let code_hit = exc.code == EXCEPTION_BREAKPOINT;
    let disasm_hit = matches!(
        c.disasm.first().map(|i| &i.kind),
        Some(InstrKind::Int3) | Some(InstrKind::Ud2)
    );
    if !code_hit && !disasm_hit {
        return None;
    }
    let mut evidence = Vec::new();
    if code_hit {
        evidence.push(format!(
            "exception code 0x{EXCEPTION_BREAKPOINT:08X} (breakpoint)"
        ));
    }
    if disasm_hit {
        evidence.push(format!(
            "faulting instruction is {:?} at 0x{:X}",
            c.disasm[0].kind, c.disasm[0].va
        ));
    }
    Some(Hit {
        rule: 2,
        verdict: CrashVerdict::V8CheckFailure,
        confidence: if code_hit && disasm_hit {
            Confidence::High
        } else {
            Confidence::Medium
        },
        evidence,
    })
}

/// Rule 3: stack overflow — dedicated code, or AV touching a guard page
/// adjacent to a stack region.
fn rule_stack_overflow(c: &Ctx) -> Option<Hit> {
    let exc = c.dump.exception.as_ref()?;
    if exc.code == EXCEPTION_STACK_OVERFLOW {
        return Some(Hit {
            rule: 3,
            verdict: CrashVerdict::StackOverflow,
            confidence: Confidence::High,
            evidence: vec![format!(
                "exception code 0x{EXCEPTION_STACK_OVERFLOW:08X} (stack overflow)"
            )],
        });
    }
    let fault = c.fault_va?;
    let guard = c
        .dump
        .memory_info
        .iter()
        .find(|mi| mi.protection & PAGE_GUARD != 0 && in_range(fault, mi.va_start, mi.size))?;
    // Stronger when the guard page sits next to a thread's stack range.
    let near_stack = c.dump.threads.iter().any(|t| {
        let s = t.stack_va;
        let e = t.stack_va.saturating_add(t.stack_size);
        guard.va_start >= s.saturating_sub(0x10000) && guard.va_start <= e.saturating_add(0x10000)
    });
    Some(Hit {
        rule: 3,
        verdict: CrashVerdict::StackOverflow,
        confidence: if near_stack {
            Confidence::High
        } else {
            Confidence::Medium
        },
        evidence: vec![format!(
            "fault VA 0x{fault:X} inside PAGE_GUARD region at 0x{:X} (stack guard page)",
            guard.va_start
        )],
    })
}

/// Rule 4: fault inside a large reserved guard region near executable code —
/// wasm trap-based bounds-check miss.
fn rule_wasm_guard(c: &Ctx) -> Option<Hit> {
    let fault = c.fault_va?;
    let reserved = c.dump.memory_info.iter().find(|mi| {
        mi.state == MemState::Reserve
            && mi.size >= (1 << 30)
            && mi.protection & PAGE_NOACCESS != 0
            && in_range(fault, mi.va_start, mi.size)
    })?;
    let code_nearby = c.dump.memory_info.iter().any(|mi| {
        mi.state == MemState::Commit
            && mi.protection & PAGE_EXECUTE_ANY != 0
            && mi.va_start.abs_diff(reserved.va_start) < (4 << 30)
    });
    if !code_nearby {
        return None;
    }
    Some(Hit {
        rule: 4,
        verdict: CrashVerdict::WasmGuardFault,
        confidence: Confidence::Low,
        evidence: vec![format!(
            "fault VA 0x{fault:X} inside 0x{:X}-byte reserved guard region at 0x{:X} with executable code nearby",
            reserved.size, reserved.va_start
        )],
    })
}

/// Rule 5: AV where the faulting base register holds a compressed Smi
/// dereferenced as a pointer — the JIT type-confusion signature.
fn rule_smi_confusion(c: &Ctx) -> Option<Hit> {
    let fault = c.fault_va?;
    let exc = c.dump.exception.as_ref()?;
    let regs = exc.context.as_ref()?;
    let (base, disp) = match c.disasm.first().map(|i| &i.kind) {
        Some(InstrKind::MemRead { base, disp }) | Some(InstrKind::MemWrite { base, disp }) => {
            (*base, *disp)
        }
        _ => return None,
    };
    let base_val = regs.get(base?);
    // Effective address = base + disp; base must be a non-zero compressed
    // Smi (31-bit value, tag bit clear).
    if base_val == 0 || base_val >= (1 << 32) || base_val & 1 != 0 {
        return None;
    }
    if fault != base_val.wrapping_add_signed(disp) {
        return None;
    }
    Some(Hit {
        rule: 5,
        verdict: CrashVerdict::SmiTypeConfusion,
        confidence: Confidence::High,
        evidence: vec![format!(
            "base register holds compressed Smi (value {}), dereferenced as pointer: {}",
            (base_val as i64) >> 1,
            c.disasm[0].text
        )],
    })
}

/// Rule 6: AV while accessing a field of a V8 heap object — decode the
/// object's instance type to name what was being touched.
fn rule_object_access(c: &Ctx) -> Option<Hit> {
    let fault = c.fault_va?;
    let cage = c.cage_base?;
    if fault < cage || fault >= cage + (1u64 << 32) {
        return None;
    }
    let exc = c.dump.exception.as_ref()?;
    let regs = exc.context.as_ref()?;
    let (base, disp) = match c.disasm.first().map(|i| &i.kind) {
        Some(InstrKind::MemRead {
            base: Some(b),
            disp,
        })
        | Some(InstrKind::MemWrite {
            base: Some(b),
            disp,
        }) => (*b, *disp),
        _ => return None,
    };
    let tagged = regs.get(base);
    if tagged & 1 != 1 {
        return None;
    }
    let heap = tagged & !1;
    if heap < cage || heap >= cage + (1u64 << 32) {
        return None;
    }
    // The fault VA must be exactly the effective address base+disp.
    if fault != tagged.wrapping_add_signed(disp) {
        return None;
    }
    let itype = crate::v8obj::instance_type(c.space, cage, heap)?;
    Some(Hit {
        rule: 6,
        verdict: CrashVerdict::V8ObjectAccess {
            instance_type: itype,
        },
        confidence: Confidence::Medium,
        evidence: vec![format!(
            "fault VA 0x{fault:X} = object 0x{heap:X} {disp:+#x}; instance type 0x{itype:04X} (layout {})",
            layout_name(c.dump)
        )],
    })
}

/// Rule 7: V8HE v2 shows the allocation area exhausted at the fault site.
fn rule_oom_state(c: &Ctx) -> Option<Hit> {
    let ext = c.dump.v8heap_ext.as_ref()?;
    if ext.alloc_top_va == 0 || ext.alloc_limit_va == 0 {
        return None;
    }
    let headroom = ext.alloc_limit_va.saturating_sub(ext.alloc_top_va);
    if headroom >= 0x10000 {
        return None;
    }
    let fault = c.fault_va.unwrap_or(ext.alloc_top_va);
    if fault < ext.alloc_top_va || fault > ext.alloc_limit_va.saturating_add(0x1000) {
        return None;
    }
    Some(Hit {
        rule: 7,
        verdict: CrashVerdict::V8OutOfMemory,
        confidence: Confidence::Medium,
        evidence: vec![format!(
            "allocation area exhausted: top 0x{:X}, limit 0x{:X} (headroom {headroom:#x}), fault VA 0x{fault:X}",
            ext.alloc_top_va, ext.alloc_limit_va
        )],
    })
}

/// Rule 8: RIP targets unmapped or non-executable memory — corrupted code
/// pointer (smashed return address / vtable / callback).
fn rule_corrupted_code_pointer(c: &Ctx) -> Option<Hit> {
    let exc = c.dump.exception.as_ref()?;
    if exc.code == EXCEPTION_BREAKPOINT || exc.code == EXCEPTION_STACK_OVERFLOW {
        return None;
    }
    let in_module = c
        .dump
        .modules
        .iter()
        .any(|m| exc.address >= m.base_va && exc.address < m.base_va + m.size);
    if in_module {
        return None;
    }
    let bad_target = match c.space.region_at(exc.address) {
        None => true,
        Some(r) => r.protection & PAGE_EXECUTE_ANY == 0,
    };
    if !bad_target {
        return None;
    }
    Some(Hit {
        rule: 8,
        verdict: CrashVerdict::CorruptedCodePointer,
        confidence: Confidence::High,
        evidence: vec![format!(
            "RIP 0x{:X} is outside all modules and in unmapped/non-executable memory",
            exc.address
        )],
    })
}

/// Rule 9: AV within the null page.
fn rule_null_deref(c: &Ctx) -> Option<Hit> {
    let fault = c.fault_va?;
    if fault >= 0x10000 {
        return None;
    }
    Some(Hit {
        rule: 9,
        verdict: CrashVerdict::NullDeref,
        confidence: Confidence::High,
        evidence: vec![format!("fault VA 0x{fault:X} is in the null page")],
    })
}

/// Rule 10: any other access violation.
fn rule_wild_access(c: &Ctx) -> Option<Hit> {
    let exc = c.dump.exception.as_ref()?;
    if exc.code != EXCEPTION_ACCESS_VIOLATION {
        return None;
    }
    Some(Hit {
        rule: 10,
        verdict: CrashVerdict::WildAccess,
        confidence: Confidence::Low,
        evidence: vec![match c.fault_va {
            Some(f) => format!("access violation at fault VA 0x{f:X}, no V8 correlation"),
            None => "access violation, fault VA not recorded".into(),
        }],
    })
}

// ── shared helpers ──

fn in_range(va: u64, start: u64, size: u64) -> bool {
    va >= start && va < start.saturating_add(size)
}

fn is_oom_message(msg: &str) -> bool {
    msg.contains("Out of memory")
        || msg.contains("out of memory")
        || msg.contains("CALL_AND_RETRY_LAST")
        || msg.contains("Allocation failed")
}

/// Fatal message from, in order: V8HE v2 extension, Crashpad annotation,
/// or a string scan of the crashed thread's stack region.
fn fatal_message(dump: &Dump, space: &AddressSpace, thread_id: u32) -> Option<String> {
    if let Some(ext) = &dump.v8heap_ext
        && let Some(msg) = &ext.fatal_message
    {
        return Some(msg.clone());
    }
    for (k, v) in &dump.annotations {
        if k == "v8_fatal_message" && !v.is_empty() {
            return Some(v.clone());
        }
    }
    scan_stack_for_fatal(dump, space, thread_id)
}

const FATAL_NEEDLES: &[&[u8]] = &[
    b"Check failed:",
    b"Fatal error in",
    b"# Fatal",
    b"Out of memory",
];

fn scan_stack_for_fatal(dump: &Dump, space: &AddressSpace, thread_id: u32) -> Option<String> {
    let thread = dump.threads.iter().find(|t| t.id == thread_id)?;
    let region = space.region_at(thread.stack_va)?;
    for needle in FATAL_NEEDLES {
        if let Some(pos) = find_subslice(&region.data, needle) {
            let end = region.data[pos..]
                .iter()
                .position(|&b| b == 0 || b == b'\n')
                .map(|n| pos + n)
                .unwrap_or(region.data.len())
                .min(pos + 512);
            let text = String::from_utf8_lossy(&region.data[pos..end]).into_owned();
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn layout_name(dump: &Dump) -> String {
    for (k, v) in &dump.annotations {
        if k == "ver" {
            return format!("electron {v}");
        }
    }
    "generic".to_string()
}

pub struct CrashCauseAnalyzer;

impl Analyzer for CrashCauseAnalyzer {
    fn name(&self) -> &str {
        "cause"
    }

    fn description(&self) -> &str {
        "Diagnoses why the process crashed: exception semantics, disassembly, cage fault analysis"
    }

    fn analyze(&self, dump: &Dump, space: &AddressSpace) -> AnalyzerOutput {
        let mut out = AnalyzerOutput::new("cause");
        let d = diagnose(dump, space);
        out.custom.push((
            "crash_diagnosis".to_string(),
            serde_json::json!({
                "verdict": format!("{:?}", d.verdict),
                "confidence": format!("{:?}", d.confidence),
                "evidence": d.evidence,
                "fault_va": d.fault_va.map(|v| format!("0x{v:X}")),
                "access": d.access.map(|a| format!("{a:?}")),
                "fatal_message": d.fatal_message,
                "alternatives": d
                    .alternatives
                    .iter()
                    .map(|(v, c)| format!("{v:?}/{c:?}"))
                    .collect::<Vec<_>>(),
            }),
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::RegisterSet;
    use crate::arch::x64_indices;
    use crate::error::Provenance;
    use crate::model::{
        ExceptionInfo, MemType, MemoryInfoEntry, Module, RegionClass, Thread, V8HeapExt,
    };
    use crate::space::{AddressRegion, AddressSpace};

    fn prov() -> Provenance {
        Provenance {
            stream_type: 1,
            file_offset: 0,
            rva: 0,
        }
    }

    fn base_dump() -> Dump {
        Dump {
            system_info: None,
            modules: vec![Module {
                name: "app.exe".into(),
                base_va: 0x7FF0_0000,
                size: 0x1_0000,
                checksum: 0,
                codeview_guid: None,
                pdb_name: None,
                provenance: prov(),
            }],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            annotations: vec![],
            memory_info: vec![],
            v8heap_ext: None,
            file_size: 0,
        }
    }

    fn exception(code: u32, address: u64, params: Vec<u64>) -> ExceptionInfo {
        ExceptionInfo {
            code,
            address,
            thread_id: 1,
            flags: 0,
            parameters: params,
            context: None,
            provenance: prov(),
        }
    }

    fn add_region(space: &mut AddressSpace, va: u64, data: Vec<u8>, class: RegionClass) {
        space
            .add_region(AddressRegion {
                va_start: va,
                size: data.len() as u64,
                data,
                protection: 0x40, // PAGE_EXECUTE_READWRITE
                state: MemState::Commit,
                classification: class,
            })
            .unwrap();
    }

    #[test]
    fn no_exception_stream_yields_no_exception() {
        let dump = base_dump();
        let space = AddressSpace::new(4);
        let d = diagnose(&dump, &space);
        assert_eq!(d.verdict, CrashVerdict::NoException);
    }

    #[test]
    fn breakpoint_with_int3_is_check_failure() {
        let mut dump = base_dump();
        dump.exception = Some(exception(EXCEPTION_BREAKPOINT, 0x5000, vec![]));
        let mut space = AddressSpace::new(4);
        add_region(
            &mut space,
            0x5000,
            vec![0xCC, 0x90, 0x90],
            RegionClass::Image,
        );
        let d = diagnose(&dump, &space);
        assert_eq!(d.verdict, CrashVerdict::V8CheckFailure);
        assert_eq!(d.confidence, Confidence::High);
    }

    #[test]
    fn fatal_message_in_v8heap_ext_wins() {
        let mut dump = base_dump();
        dump.exception = Some(exception(
            EXCEPTION_ACCESS_VIOLATION,
            0x7FF0_1000,
            vec![0, 0xDEAD],
        ));
        dump.v8heap_ext = Some(V8HeapExt {
            alloc_top_va: 0,
            alloc_limit_va: 0,
            gc_state: 0,
            last_gc_reason: 0,
            fatal_message: Some("Check failed: !ptr->IsSmi().".into()),
        });
        let space = AddressSpace::new(4);
        let d = diagnose(&dump, &space);
        assert_eq!(d.verdict, CrashVerdict::V8CheckFailure);
        assert_eq!(d.confidence, Confidence::High);
        assert_eq!(
            d.fatal_message.as_deref(),
            Some("Check failed: !ptr->IsSmi().")
        );
    }

    #[test]
    fn oom_wording_maps_to_out_of_memory() {
        let mut dump = base_dump();
        dump.exception = Some(exception(EXCEPTION_BREAKPOINT, 0x5000, vec![]));
        dump.annotations = vec![(
            "v8_fatal_message".into(),
            "Fatal error in : Out of memory".into(),
        )];
        let space = AddressSpace::new(4);
        let d = diagnose(&dump, &space);
        assert_eq!(d.verdict, CrashVerdict::V8OutOfMemory);
    }

    #[test]
    fn fatal_message_scanned_from_stack() {
        let mut dump = base_dump();
        dump.threads.push(Thread {
            id: 1,
            registers: RegisterSet::new(),
            stack_va: 0x8000,
            stack_size: 0x1000,
            teb_va: 0,
            provenance: prov(),
        });
        dump.exception = Some(exception(EXCEPTION_BREAKPOINT, 0x5000, vec![]));
        let mut space = AddressSpace::new(4);
        let mut stack = vec![0u8; 0x1000];
        stack[0x100..0x100 + b"Check failed:".len()].copy_from_slice(b"Check failed:");
        add_region(&mut space, 0x8000, stack, RegionClass::Stack);
        let d = diagnose(&dump, &space);
        assert_eq!(d.verdict, CrashVerdict::V8CheckFailure);
        assert!(d.fatal_message.is_some());
    }

    #[test]
    fn stack_overflow_code() {
        let mut dump = base_dump();
        dump.exception = Some(exception(EXCEPTION_STACK_OVERFLOW, 0x7FF0_1000, vec![]));
        let space = AddressSpace::new(4);
        let d = diagnose(&dump, &space);
        assert_eq!(d.verdict, CrashVerdict::StackOverflow);
        assert_eq!(d.confidence, Confidence::High);
    }

    #[test]
    fn smi_confusion_from_register_and_disasm() {
        let mut dump = base_dump();
        let mut regs = RegisterSet::new();
        regs.set(x64_indices::RCX, 0x2A); // compressed Smi 21
        let mut exc = exception(EXCEPTION_ACCESS_VIOLATION, 0x5000, vec![0, 0x2A + 0x1B]);
        exc.context = Some(regs);
        dump.exception = Some(exc);
        let mut space = AddressSpace::new(4);
        // mov rax, [rcx+0x1B]
        add_region(
            &mut space,
            0x5000,
            vec![0x48, 0x8B, 0x41, 0x1B],
            RegionClass::Image,
        );
        let d = diagnose(&dump, &space);
        assert_eq!(d.verdict, CrashVerdict::SmiTypeConfusion);
        assert_eq!(d.confidence, Confidence::High);
    }

    #[test]
    fn object_access_in_cage_decodes_instance_type() {
        const CAGE: u64 = 0x1_0000_0000;
        let mut dump = base_dump();
        dump.annotations = vec![("v8_ro_space_firstpage_address".into(), format!("{CAGE:#x}"))];
        let obj = CAGE + 0x40000;
        let mut regs = RegisterSet::new();
        regs.set(x64_indices::RCX, obj | 1);
        // fault VA = tagged (obj|1) + disp (0x1B) = obj + 0x1C
        let mut exc = exception(EXCEPTION_ACCESS_VIOLATION, 0x5000, vec![0, obj + 0x1C]);
        exc.context = Some(regs);
        dump.exception = Some(exc);

        let mut space = AddressSpace::new(8);
        // cage page: object at +0x40000 with map -> +0x100, itype at map+8
        let mut cage_page = vec![0u8; 0x50000];
        cage_page[0x40000..0x40004].copy_from_slice(&0x101u32.to_le_bytes());
        cage_page[0x108..0x10A].copy_from_slice(&0x0042u16.to_le_bytes());
        add_region(&mut space, CAGE, cage_page, RegionClass::Private);
        // mov rax, [rcx+0x1B]
        add_region(
            &mut space,
            0x5000,
            vec![0x48, 0x8B, 0x41, 0x1B],
            RegionClass::Image,
        );
        let d = diagnose(&dump, &space);
        assert_eq!(
            d.verdict,
            CrashVerdict::V8ObjectAccess {
                instance_type: 0x42
            }
        );
    }

    #[test]
    fn oom_from_exhausted_allocation_area() {
        let mut dump = base_dump();
        dump.exception = Some(exception(
            EXCEPTION_ACCESS_VIOLATION,
            0x7FF0_1000, // RIP inside the module
            vec![1, 0x50005],
        ));
        dump.v8heap_ext = Some(V8HeapExt {
            alloc_top_va: 0x50000,
            alloc_limit_va: 0x50040,
            gc_state: 0,
            last_gc_reason: 0,
            fatal_message: None,
        });
        let space = AddressSpace::new(4);
        let d = diagnose(&dump, &space);
        assert_eq!(d.verdict, CrashVerdict::V8OutOfMemory);
        assert_eq!(d.confidence, Confidence::Medium);
    }

    #[test]
    fn rip_into_unmapped_is_corrupted_code_pointer() {
        let mut dump = base_dump();
        dump.exception = Some(exception(
            EXCEPTION_ACCESS_VIOLATION,
            0xDEAD_0000,
            vec![8, 0xDEAD_0000],
        ));
        let space = AddressSpace::new(4);
        let d = diagnose(&dump, &space);
        assert_eq!(d.verdict, CrashVerdict::CorruptedCodePointer);
    }

    #[test]
    fn null_page_fault_is_null_deref() {
        let mut dump = base_dump();
        dump.exception = Some(exception(
            EXCEPTION_ACCESS_VIOLATION,
            0x7FF0_1000,
            vec![0, 0x18],
        ));
        let space = AddressSpace::new(4);
        let d = diagnose(&dump, &space);
        assert_eq!(d.verdict, CrashVerdict::NullDeref);
    }

    #[test]
    fn plain_av_falls_back_to_wild_access() {
        let mut dump = base_dump();
        dump.exception = Some(exception(
            EXCEPTION_ACCESS_VIOLATION,
            0x7FF0_1000,
            vec![0, 0x1234_5678_9ABC],
        ));
        let space = AddressSpace::new(4);
        let d = diagnose(&dump, &space);
        assert_eq!(d.verdict, CrashVerdict::WildAccess);
        assert_eq!(d.confidence, Confidence::Low);
    }

    #[test]
    fn wasm_guard_region_fault() {
        let mut dump = base_dump();
        dump.exception = Some(exception(
            EXCEPTION_ACCESS_VIOLATION,
            0x7FF0_1000,
            vec![0, 0x8_0000_1000],
        ));
        dump.memory_info = vec![
            MemoryInfoEntry {
                va_start: 0x8_0000_0000,
                size: 0x2_0000_0000, // 8 GiB reservation
                protection: PAGE_NOACCESS,
                state: MemState::Reserve,
                mem_type: MemType::Private,
            },
            MemoryInfoEntry {
                va_start: 0x8_0000_0000 - 0x1_0000,
                size: 0x1_0000,
                protection: 0x40, // PAGE_EXECUTE_READWRITE
                state: MemState::Commit,
                mem_type: MemType::Private,
            },
        ];
        let space = AddressSpace::new(4);
        let d = diagnose(&dump, &space);
        assert_eq!(d.verdict, CrashVerdict::WasmGuardFault);
        assert_eq!(d.confidence, Confidence::Low);
    }

    #[test]
    fn unknown_code_yields_unknown() {
        let mut dump = base_dump();
        dump.exception = Some(exception(0xE043_4352, 0x7FF0_1000, vec![]));
        let space = AddressSpace::new(4);
        let d = diagnose(&dump, &space);
        assert_eq!(d.verdict, CrashVerdict::Unknown);
    }

    #[test]
    fn ranking_prefers_fatal_message_over_breakpoint() {
        let mut dump = base_dump();
        dump.exception = Some(exception(EXCEPTION_BREAKPOINT, 0x5000, vec![]));
        dump.v8heap_ext = Some(V8HeapExt {
            alloc_top_va: 0,
            alloc_limit_va: 0,
            gc_state: 0,
            last_gc_reason: 0,
            fatal_message: Some("Check failed: x".into()),
        });
        let mut space = AddressSpace::new(4);
        add_region(&mut space, 0x5000, vec![0xCC], RegionClass::Image);
        let d = diagnose(&dump, &space);
        assert_eq!(d.verdict, CrashVerdict::V8CheckFailure);
        assert_eq!(d.confidence, Confidence::High);
        // both rules fired; the loser is reported as an alternative
        assert!(!d.alternatives.is_empty());
    }
}

# Crash-Cause Diagnosis — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the crash-cause diagnosis from `docs/superpowers/specs/2026-08-04-crash-cause-design.md`: a `cause` analyzer that fuses exception semantics, disassembly, MemoryInfoList, and cage-aware heap decoding into a `CrashDiagnosis` verdict, fed by a V8HE v2 capture-side extension.

**Architecture:** Pure additions around the existing S1 (parse) / S2 (analyzer pipeline) split. Two utility modules (`disasm`, `v8obj`) are extracted from `analyzer/v8.rs` so the new analyzer shares, never duplicates, V8 knowledge. All verdicts fail closed to `Unknown`.

**Tech Stack:** Rust 2024 edition, `serde_json`, `iced-x86` (already a core dep). No new dependencies.

---

### File Map

| File | Action | Purpose |
|------|--------|---------|
| `forensicator-core/src/model.rs` | Modify | `ExceptionInfo.parameters`, `V8HeapExt`, `Dump.v8heap_ext` |
| `forensicator-core/src/parse/exception.rs` | Modify | Decode `NumberParameters` + `ExceptionInformation[]` |
| `forensicator-core/src/parse/v8heap.rs` | Modify | Version-gated v2 extension decode |
| `forensicator-core/src/parse/dump.rs` | Modify | Wire v2 ext into `Dump` |
| `forensicator-core/src/disasm.rs` | Create | iced-x86 window decode + `InstrKind` classification |
| `forensicator-core/src/v8obj.rs` | Create | Cage-aware object walking (moved from `analyzer/v8.rs`) |
| `forensicator-core/src/analyzer/v8.rs` | Modify | Use `disasm`/`v8obj`; behavior unchanged |
| `forensicator-core/src/analyzer/cause.rs` | Create | `CrashCauseAnalyzer`, rules, verdict ranking |
| `forensicator-core/src/analyzer.rs` | Modify | `pub mod cause;` + register in `default_pipeline()` |
| `forensicator-core/src/lib.rs` | Modify | `pub mod disasm; pub mod v8obj;` |
| `forensicator-cli/src/main.rs` | Modify | Register `cause` in `cmd_analyze`; verdict line in `inspect` |
| `specs/CrashCause.tla` | Create | Model for verdict invariant |
| `forensicator-core/tests/mbt_crash_cause.rs` | Create | Opt-in MBT stub (auto-skip without `MIRROR_BIN`) |

**Mechanical touch:** adding `Dump.v8heap_ext` breaks all 42 `Dump { … }` struct literals in tests — each gets `v8heap_ext: None,` inserted next to its `annotations:` field.

---

### Task 1: Decode exception parameters

**Files:**
- Modify: `forensicator-core/src/model.rs`
- Modify: `forensicator-core/src/parse/exception.rs`

- [ ] **Step 1: Add `parameters` to `ExceptionInfo` (model.rs:143)**

```rust
pub struct ExceptionInfo {
    pub code: u32,
    pub address: u64,
    pub thread_id: u32,
    pub flags: u32,
    /// ExceptionInformation[0..NumberParameters]. For 0xC0000005:
    /// [0]=access (0 read, 1 write, 8 exec), [1]=fault VA.
    pub parameters: Vec<u64>,
    pub context: Option<RegisterSet>,
    pub provenance: Provenance,
}
```

Also update `Dump::set_exception` (model.rs:286) to set `parameters: vec![]`.

- [ ] **Step 2: Decode parameters in parse/exception.rs**

In `decode_exception_with_dump`, after reading `address` (record layout: NumberParameters u32 @ +32, array of 15 u64 @ +40):

```rust
let parameters = if data.len() >= 40 {
    let n = u32::from_le_bytes(data[32..36].try_into().unwrap()).min(15) as usize;
    let avail = (data.len() - 40) / 8;
    (0..n.min(avail))
        .map(|i| u64::from_le_bytes(data[40 + 8 * i..48 + 8 * i].try_into().unwrap()))
        .collect()
} else {
    Vec::new()
};
```

- [ ] **Step 3: Fix the two `ExceptionInfo` literals in model.rs tests** (add `parameters: vec![]`), then add tests to `parse/exception.rs`:

```rust
#[test]
fn decodes_av_parameters() {
    let mut data = vec![0u8; 168];
    data[8..12].copy_from_slice(&0xC0000005u32.to_le_bytes());
    data[32..36].copy_from_slice(&2u32.to_le_bytes()); // NumberParameters
    data[40..48].copy_from_slice(&1u64.to_le_bytes());  // write
    data[48..56].copy_from_slice(&0xDEADu64.to_le_bytes()); // fault VA
    let exc = decode_exception(&data, dummy_prov()).unwrap();
    assert_eq!(exc.parameters, vec![1, 0xDEAD]);
}

#[test]
fn clamps_to_stream_length() {
    let mut data = vec![0u8; 48]; // room for only 1 param
    data[32..36].copy_from_slice(&15u32.to_le_bytes());
    let exc = decode_exception(&data, dummy_prov()).unwrap();
    assert_eq!(exc.parameters.len(), 1);
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p forensicator-core -- parse 2>&1`

Expected: all pass.

- [ ] **Step 5: Commit**

Run: `git add -A; git commit -m "feat(parse): decode ExceptionInformation parameters from exception stream"`

---

### Task 2: Extract disasm.rs utility

**Files:**
- Create: `forensicator-core/src/disasm.rs`
- Modify: `forensicator-core/src/lib.rs`
- Modify: `forensicator-core/src/analyzer/v8.rs`

- [ ] **Step 1: Create disasm.rs**

Move the iced-x86 usage out of `analyzer/v8.rs` (lines 98–130) into a reusable decoder that also classifies each instruction. Register-index mapping uses `iced_x86::Register` → our `arch::x64_indices`.

```rust
//! Minimal iced-x86 wrapper: decode a window of instructions at a VA and
//! classify the forms crash-cause rules care about.

use crate::space::AddressSpace;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstrKind {
    Int3,
    Ud2,
    /// base = RegisterSet index when the memory operand is [reg + disp]
    /// (None for RIP-relative or absolute forms).
    MemRead { base: Option<usize>, disp: i64 },
    MemWrite { base: Option<usize>, disp: i64 },
    IndirectCall,
    IndirectJump,
    Other,
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub va: u64,
    pub text: String,
    pub kind: InstrKind,
}

/// Decode up to `max` instructions starting at `ip`. Empty when the bytes
/// are not captured. Never fails — garbage bytes classify as `Other`.
pub fn decode_window(space: &AddressSpace, ip: u64, max: usize) -> Vec<Instruction> {
    let Some(bytes) = space.read(ip, 64) else { return Vec::new() };
    let mut decoder = iced_x86::Decoder::with_ip(64, bytes, ip, iced_x86::DecoderOptions::NONE);
    let mut out = Vec::new();
    let mut instr = iced_x86::Instruction::default();
    let mut sink = FmtSink(String::new());
    while out.len() < max && decoder.can_decode() {
        decoder.decode_out(&mut instr);
        sink.0.clear();
        iced_x86::IntelFormatter::new().format(&instr, &mut sink);
        let kind = classify(&instr);
        out.push(Instruction { va: instr.ip(), text: sink.0.clone(), kind });
    }
    out
}

fn classify(i: &iced_x86::Instruction) -> InstrKind {
    use iced_x86::Mnemonic::*;
    match i.mnemonic() {
        Int3 => InstrKind::Int3,
        Ud2 => InstrKind::Ud2,
        Call if i.op0_kind() == iced_x86::OpKind::Memory
            || matches!(i.op0_kind(), iced_x86::OpKind::Register) => InstrKind::IndirectCall,
        Jmp if i.op0_kind() != iced_x86::OpKind::NearBranch16
            && i.op0_kind() != iced_x86::OpKind::NearBranch32
            && i.op0_kind() != iced_x86::OpKind::NearBranch64 => InstrKind::IndirectJump,
        _ => {
            for op in 0..i.op_count() {
                if i.op_kind(op) == iced_x86::OpKind::Memory {
                    let base = reg_index(i.memory_base());
                    let disp = i.memory_displacement64() as i64;
                    return if i.is_instruction_memory_read_for(op) {
                        InstrKind::MemRead { base, disp }
                    } else {
                        InstrKind::MemWrite { base, disp }
                    };
                }
            }
            InstrKind::Other
        }
    }
}

fn reg_index(r: iced_x86::Register) -> Option<usize> {
    use crate::arch::x64_indices as x;
    use iced_x86::Register::*;
    Some(match r {
        RAX => x::RAX, RBX => x::RBX, RCX => x::RCX, RDX => x::RDX,
        RSI => x::RSI, RDI => x::RDI, RBP => x::RBP, RSP => x::RSP,
        R8 => x::R8, R9 => x::R9, R10 => x::R10, R11 => x::R11,
        R12 => x::R12, R13 => x::R13, R14 => x::R14, R15 => x::R15,
        _ => return None, // RIP-relative, segment, etc.
    })
}

struct FmtSink(String);
impl iced_x86::FormatterOutput for FmtSink {
    fn write(&mut self, text: &str, _kind: iced_x86::FormatterTextKind) {
        self.0.push_str(text);
    }
}
```

NOTE: `is_instruction_memory_read_for` does not exist — implement read/write disambiguation by checking the mnemonic against a small write-list (`Mov` with op0=memory → write; else if any memory operand → read; `Cmp/Test/Add/Sub/Xor/And/Or` with memory operand → read unless op0=memory → write). Verify exact iced-x86 API in the vendored version (`cargo doc -p iced-x86` or source under `~/.cargo/registry`); adjust `classify` accordingly. Register indices: read `arch.rs` `x64_indices` first and match its actual constant names.

- [ ] **Step 2: Add tests with hand-assembled bytes**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MemState, RegionClass};
    use crate::space::{AddressRegion, AddressSpace};

    fn space_with(ip: u64, code: &[u8]) -> AddressSpace {
        let mut space = AddressSpace::new(2);
        space.add_region(AddressRegion {
            va_start: ip, size: code.len() as u64, data: code.to_vec(),
            protection: 5, state: MemState::Commit, classification: RegionClass::Image,
        }).unwrap();
        space
    }

    #[test]
    fn classifies_int3() {
        let s = space_with(0x1000, &[0xCC, 0x90]);
        assert_eq!(decode_window(&s, 0x1000, 4)[0].kind, InstrKind::Int3);
    }

    #[test]
    fn classifies_ud2() {
        let s = space_with(0x1000, &[0x0F, 0x0B]);
        assert_eq!(decode_window(&s, 0x1000, 4)[0].kind, InstrKind::Ud2);
    }

    #[test]
    fn classifies_mem_read_with_disp() {
        // mov rax, [rcx+0x1B]  = 48 8B 41 1B
        let s = space_with(0x1000, &[0x48, 0x8B, 0x41, 0x1B]);
        let ins = &decode_window(&s, 0x1000, 4)[0];
        assert_eq!(ins.kind, InstrKind::MemRead { base: Some(crate::arch::x64_indices::RCX), disp: 0x1B });
    }

    #[test]
    fn uncaptured_va_decodes_nothing() {
        let s = AddressSpace::new(2);
        assert!(decode_window(&s, 0x1000, 4).is_empty());
    }
}
```

- [ ] **Step 3: lib.rs** — insert `pub mod disasm;` and `pub mod v8obj;` (alphabetical, matching existing ordering).

- [ ] **Step 4: Refactor analyzer/v8.rs** — replace `disassemble_exception`'s body with `decode_window(space, pc, 10)` mapped to the same JSON shape (`va`/`text` objects), and delete `FormatterOutputImpl`. The `crash_disasm` output must be byte-identical for the same input.

- [ ] **Step 5: Run tests**

Run: `cargo test -p forensicator-core -- disasm 2>&1 && cargo test -p forensicator-core -- analyzer::v8 2>&1`

Expected: new disasm tests pass; all existing v8 analyzer tests pass unchanged.

- [ ] **Step 6: Commit**

Run: `git add -A; git commit -m "refactor: extract iced-x86 window decode into disasm.rs with InstrKind classification"`

---

### Task 3: Extract v8obj.rs heap-walk utility

**Files:**
- Create: `forensicator-core/src/v8obj.rs`
- Modify: `forensicator-core/src/analyzer/v8.rs`

- [ ] **Step 1: Create v8obj.rs** — move these functions from `analyzer/v8.rs`, unchanged, made `pub(crate)`: `decompress` (v8.rs:368), `smi` (v8.rs:776), `instance_type` (v8.rs:672), `read_v8_string` (v8.rs:681). Also move the private `read_u32`/`try_read_u64` helpers they depend on (v8.rs keeps its own `read_u64` used by the walker — duplicate that one, it is 7 lines and the walker is unrelated to object decoding).

- [ ] **Step 2: Update analyzer/v8.rs** — delete the moved functions, call `crate::v8obj::{decompress, smi, instance_type, read_v8_string}`. No behavior change.

- [ ] **Step 3: Run tests**

Run: `cargo test -p forensicator-core -- analyzer::v8 2>&1`

Expected: all 14+ existing tests pass unchanged (they exercise these helpers through `decode_js_frame`).

- [ ] **Step 4: Commit**

Run: `git add -A; git commit -m "refactor: extract cage-aware object walking into v8obj.rs"`

---

### Task 4: V8HE v2 extension + Dump wiring

**Files:**
- Modify: `forensicator-core/src/model.rs`
- Modify: `forensicator-core/src/parse/v8heap.rs`
- Modify: `forensicator-core/src/parse/dump.rs`
- Modify: all `Dump { … }` literals (42 sites) — add `v8heap_ext: None,`

- [ ] **Step 1: Add V8HeapExt to model.rs**

```rust
/// Optional V8HE v2 extension facts captured by the instrumented handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V8HeapExt {
    pub alloc_top_va: u64,
    pub alloc_limit_va: u64,
    pub gc_state: u32,
    pub last_gc_reason: u32,
    pub fatal_message: Option<String>,
}
```

Add `pub v8heap_ext: Option<V8HeapExt>` to `Dump` (model.rs:154, after `annotations`).

- [ ] **Step 2: Extend parse/v8heap.rs**

Change signature to return the ext alongside ranges, and gate on `version`:

```rust
pub fn decode_v8heap(
    data: &[u8],
    prov: Provenance,
) -> Result<(Vec<RawMemoryRange>, Option<V8HeapExt>), Anomaly> {
    // v1 header checks as today, then:
    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let (ext, region_table_off) = if version >= 2 {
        (parse_v2_ext(data, prov.clone()), HEADER_SIZE + V2_EXT_SIZE)
    } else {
        (None, HEADER_SIZE)
    };
    // region table now starts at region_table_off; region file_offsets remain
    // relative to stream start (handler contract, unchanged).
}

const V2_EXT_SIZE: usize = 48;

fn parse_v2_ext(data: &[u8], prov: Provenance) -> Option<V8HeapExt> {
    if data.len() < HEADER_SIZE + V2_EXT_SIZE { return None; } // truncated → v1-ish
    let b = &data[HEADER_SIZE..HEADER_SIZE + V2_EXT_SIZE];
    let msg_len = u32::from_le_bytes(b[24..28].try_into().unwrap()) as usize;
    let msg_start = HEADER_SIZE + V2_EXT_SIZE;
    let fatal_message = if msg_len > 0 && msg_len <= 4096 && msg_start + msg_len <= data.len() {
        Some(String::from_utf8_lossy(&data[msg_start..msg_start + msg_len]).into_owned())
    } else { None };
    Some(V8HeapExt {
        alloc_top_va: u64::from_le_bytes(b[0..8].try_into().unwrap()),
        alloc_limit_va: u64::from_le_bytes(b[8..16].try_into().unwrap()),
        gc_state: u32::from_le_bytes(b[16..20].try_into().unwrap()),
        last_gc_reason: u32::from_le_bytes(b[20..24].try_into().unwrap()),
        fatal_message,
    })
}
```

IMPORTANT wire-format decision: the v2 layout places the 48-byte ext at +32 and the **fatal message bytes between the ext and the region table**. Region table offset = `HEADER_SIZE + V2_EXT_SIZE + msg_len` (not the constant used above — adjust: parse msg_len first, then compute the table offset). Update the handler's `v8_heap_format.h` comment block in the same commit message so both sides stay in lock-step.

- [ ] **Step 3: Wire into parse/dump.rs** — destructure the tuple at the existing call site (dump.rs:143), store ext in the built `Dump` (dump.rs:242).

- [ ] **Step 4: Update the 42 Dump literals** — insert `v8heap_ext: None,` next to each `annotations:` field (34 are `annotations: vec![]`; the rest have non-empty annotations — check `analyzer/v8.rs:1016`, `analyzer.rs` tests, `parse.rs` tests, model.rs tests, pipeline tests).

Run: `cargo check -p forensicator-core --all-targets 2>&1 | grep "missing field"` — iterate until zero.

- [ ] **Step 5: Tests in parse/v8heap.rs**

Extend `make_v8he()` with a `version: u32` parameter and add:

```rust
#[test]
fn v2_decodes_ext_and_message() { /* version=2, top/limit, msg "Check failed: x" */ }

#[test]
fn v1_stream_decodes_as_before() { /* version=1 → ext None, regions intact */ }

#[test]
fn v2_truncated_message_falls_back_to_no_ext() { /* ext None, regions still decode */ }
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p forensicator-core 2>&1`

Expected: full core suite green.

- [ ] **Step 7: Commit**

Run: `git add -A; git commit -m "feat(parse): V8HE v2 extension (alloc top/limit, GC state, fatal message)"`

---

### Task 5: CrashCauseAnalyzer — rules and ranking

**Files:**
- Create: `forensicator-core/src/analyzer/cause.rs`
- Modify: `forensicator-core/src/analyzer.rs`

- [ ] **Step 1: Create analyzer/cause.rs** — types first:

```rust
//! Crash-cause diagnosis: fuses exception semantics, disassembly,
//! MemoryInfoList classification, and cage-aware fault analysis into a
//! single verdict with confidence and evidence. Fails closed to Unknown.

use crate::analyzer::{Analyzer, AnalyzerOutput};
use crate::disasm::{self, InstrKind};
use crate::model::{Dump, MemState, Protection, RegionClass};
use crate::space::AddressSpace;
use crate::v8obj;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence { Low, Medium, High }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind { Read, Write, Execute }
```

Rules as pure functions returning `Option<(CrashVerdict, Confidence, Vec<String>)>`, evaluated over a small `Ctx` struct (`exc`, `params`, `disasm: &[Instruction]`, `cage_base`, `layout`):

```rust
struct Ctx<'a> {
    dump: &'a Dump,
    space: &'a AddressSpace,
}

fn rule_fatal_message(c: &Ctx) -> Option<(CrashVerdict, Confidence, Vec<String>)> {
    // 1. dump.v8heap_ext.fatal_message
    // 2. annotation "v8_fatal_message"
    // 3. scan crashed thread's stack region bytes for "Check failed:" /
    //    "Fatal error in" / "# Fatal" (cap 64 KiB from rsp down)
    // OOM wording → V8OutOfMemory, else V8CheckFailure. Confidence::High.
}

fn rule_breakpoint(c: &Ctx) -> Option<…> {
    // code 0x80000003 or disasm[0].kind ∈ {Int3, Ud2}
    // → V8CheckFailure, Medium (High if fatal message also present — handled by ranking merge)
}

fn rule_stack_overflow(c: &Ctx) -> Option<…> {
    // code 0xC00000FD → High
    // OR AV fault VA inside a region with Protection::GUARD adjacent to RegionClass::Stack
}

fn rule_wasm_guard(c: &Ctx) -> Option<…> {
    // AV; fault VA inside MemState::Reserve region ≥ 1 GiB; RX-committed region
    // within 4 GiB of that reservation → WasmGuardFault, Low
}

fn rule_smi_confusion(c: &Ctx) -> Option<…> {
    // AV; fault VA = params[1]; 0 < fault_va < 2^32; even;
    // disasm[0] is MemRead/MemWrite whose base register (from exc.context)
    // equals fault_va → SmiTypeConfusion, High
}

fn rule_object_access(c: &Ctx) -> Option<…> {
    // AV; disasm[0] MemRead{base: Some(r), disp}; tagged = ctx[r];
    // tagged & 1 == 1; heap = tagged & !1 inside cage;
    // v8obj::instance_type(space, cage, heap) = Some(itype);
    // fault_va == heap + disp (±tag) → V8ObjectAccess{itype}, Medium
}

fn rule_oom_state(c: &Ctx) -> Option<…> {
    // v8heap_ext present; alloc_limit_va - alloc_top_va < 64 KiB;
    // fault VA within [top, limit + 0x1000) → V8OutOfMemory, Medium
}

fn rule_corrupted_code_pointer(c: &Ctx) -> Option<…> {
    // exc.address not in any module; space.region_at(exc.address) is None
    // or non-executable → CorruptedCodePointer, High
}

fn rule_null_deref(c: &Ctx) -> Option<…> { /* AV; fault VA < 64 KiB → High */ }

fn rule_wild_access(c: &Ctx) -> Option<…> { /* any AV → WildAccess, Medium (fallback) */ }
```

`analyze()`:

```rust
impl Analyzer for CrashCauseAnalyzer {
    fn name(&self) -> &str { "cause" }
    fn description(&self) -> &str {
        "Diagnoses why the process crashed: exception semantics, disassembly, cage fault analysis"
    }
    fn analyze(&self, dump: &Dump, space: &AddressSpace) -> AnalyzerOutput {
        let mut out = AnalyzerOutput::new("cause");
        let d = diagnose(dump, space);
        out.custom.push(("crash_diagnosis".to_string(), serde_json::json!({
            "verdict": format!("{:?}", d.verdict),
            "confidence": format!("{:?}", d.confidence),
            "evidence": d.evidence,
            "fault_va": d.fault_va.map(|v| format!("0x{v:X}")),
            "access": d.access.map(|a| format!("{a:?}")),
            "fatal_message": d.fatal_message,
            "alternatives": d.alternatives.iter()
                .map(|(v, c)| format!("{v:?}/{c:?}")).collect::<Vec<_>>(),
        })));
        out
    }
}

pub fn diagnose(dump: &Dump, space: &AddressSpace) -> CrashDiagnosis {
    let Some(exc) = &dump.exception else {
        return CrashDiagnosis { verdict: CrashVerdict::NoException, /* … */ };
    };
    let disasm = disasm::decode_window(space, exc.address, 10);
    let cage_base = /* annotation v8_ro_space_firstpage_address, as in v8.rs */;
    // collect all rule hits, sort by confidence desc, head = verdict,
    // tail = alternatives. None → Unknown/Low.
}
```

Register-access for rules 5–6: `exc.context.as_ref()?.get(reg_idx)`.

- [ ] **Step 2: Register the analyzer** — `pub mod cause;` in analyzer.rs; `p.register(cause::CrashCauseAnalyzer);` **before** `v8` in `default_pipeline()` (analyzer.rs:101).

- [ ] **Step 3: Tests** — synthetic `Dump`+`AddressSpace` per rule (reuse the `V8HeapBuilder` style from `analyzer/v8.rs` tests; stack region containing `b"Check failed: !ptr->IsSmi()\0"` for rule 1; `0xCC` byte region + exception for rule 2; `params=[1, 0x2A]` with context RCX=0x2A and `mov rax,[rcx+0x1B]` bytes for rule 5; cage region + Map + object for rule 6). Plus a ranking test: rules 1+2 both fire → verdict from the higher-confidence rule, other listed in `alternatives`. Plus `no_exception_stream_yields_no_exception`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p forensicator-core -- analyzer::cause 2>&1 && cargo test -p forensicator-core 2>&1`

Expected: new tests pass, suite green.

- [ ] **Step 5: Commit**

Run: `git add -A; git commit -m "feat(analyzer): add CrashCauseAnalyzer with fused crash-cause rules"`

---

### Task 6: CLI wiring

**Files:**
- Modify: `forensicator-cli/src/main.rs`

- [ ] **Step 1: Register in cmd_analyze** (main.rs:~193): `p.register(forensicator_core::analyzer::cause::CrashCauseAnalyzer);` before the v8 registration.

- [ ] **Step 2: Verdict line in inspect** (main.rs:63) — when `dump.exception.is_some()`, run `cause::diagnose(&dump, &space)` and print:

```
Diagnosis: V8CheckFailure (High) — Check failed: !ptr->IsSmi().
```

(fatal_message when present, else first evidence line). `--json` adds `"diagnosis"` to the inspect JSON. `--quiet` suppresses.

- [ ] **Step 3: Run CLI tests**

Run: `cargo test -p forensicator-cli 2>&1 && cargo clippy --all-targets 2>&1`

Expected: green, no new warnings.

- [ ] **Step 4: Commit**

Run: `git add -A; git commit -m "feat(cli): wire cause analyzer; show crash diagnosis in inspect"`

---

### Task 7: TLA+ spec + MBT stub

**Files:**
- Create: `specs/CrashCause.tla`
- Create: `forensicator-core/tests/mbt_crash_cause.rs`

- [ ] **Step 1: Write specs/CrashCause.tla** per the design §TLA+: state (`exc_kind`, `fault_va`, `rule_matches`, `verdict`, `confidence`), actions `ClassifyException`, `FireRule`, `Decide`, invariant `CrashCauseInvariant` (verdict ∈ rule_matches; UNKNOWN ⇔ no matches; totality of classification).

- [ ] **Step 2: Write mbt_crash_cause.rs** following the `mbt_model.rs` auto-skip pattern (`MIRROR_BIN`/`APALACHE_MC` unset → print message, return Ok).

- [ ] **Step 3: Run full suite**

Run: `cargo test --workspace 2>&1`

Expected: green; MBT test skips with message.

- [ ] **Step 4: Commit**

Run: `git add -A; git commit -m "test: CrashCause.tla spec + MBT stub"`

---

### Task 8: Update AGENTS.md

**Files:**
- Modify: `AGENTS.md`

- [ ] **Step 1:** Add `cause` to the architecture pipeline description and the analyzer list; document the V8HE v2 stream fields under a "Custom streams" note; add `mbt_crash_cause.rs` to the MBT file list.

- [ ] **Step 2: Commit**

Run: `git add -A; git commit -m "docs: AGENTS.md — cause analyzer, V8HE v2, mbt_crash_cause"`

---

### Verification (end of plan)

- [ ] `cargo build` — clean
- [ ] `cargo test --workspace` — all green (MBT auto-skips)
- [ ] `cargo clippy --all-targets` — no new warnings
- [ ] `cargo fmt --all` — no diff
- [ ] Manual: run `forensicator inspect` on an existing Case dump with an exception → a `Diagnosis:` line appears and is not `Unknown` for dumps whose cause is known

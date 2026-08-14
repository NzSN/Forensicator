# Crash-Cause Diagnosis — Design Spec

> **Lean-port note (2026-08-13):** Rust-era document — the implementation is
> now the Lean 4 tree (`Forensicator/`, `Main.lean`, `Test/`; module map in
> `docs/arch/README.md`). Rust references below (`forensicator-core/src/…`,
> `cargo`, `tests/mbt_*`) are historical and kept as written for the record.

## Status
Draft, pending review.

## Summary
Add a **`cause` analyzer** (`CrashCauseAnalyzer`) to forensicator-core that answers *why* V8 crashed, plus a **V8HE v2 capture-side extension** that feeds it the facts a minidump cannot otherwise hold (fatal error message, allocation top/limit, GC state).

Today the pipeline tells you *where* it crashed (exception stream, `V8Analyzer` stack walk, `crash_disasm`) but not *why*: a V8 `CHECK` failure, an OOM at allocation, a JIT type confusion, and a wild native write all surface as the same `0xC0000005`/`0x80000003` pair with a raw stack. This design fuses exception semantics, disassembly pattern-matching, MemoryInfoList region classification, and pointer-compression-cage object decoding into a single structured verdict with evidence.

## Motivation
Existing assets and their gaps:

| Asset | What it gives | Gap |
|---|---|---|
| `parse/exception.rs` | code, address, context | `ExceptionInformation[]` (access type + fault VA for AVs) is on the wire but **not decoded** |
| `analyzer/v8.rs::disassemble_exception` | 10 instructions at RIP | bytes are formatted, never classified (`int3` vs `ud2` vs data-access shape) |
| `parse/memory_info.rs` | region state/protection | never cross-referenced with the fault address (guard pages, wasm reservations) |
| `parse/v8heap.rs` (V8HE v1) | cage base, isolate VA, heap regions | no allocation top/limit, no GC state, no fatal message |
| Crashpad annotations | `v8_isolate_address`, `v8_ro_space_firstpage_address` | no fatal-message annotation; no handler-side hooks |

The three highest-value crash causes in production Electron dumps — `CHECK`/`DCHECK` failures, OOM, and Smi/type confusion from JIT code — are each decidable with one of these fusions.

## Architecture

```
                    ┌──────────────── capture side (handler) ────────────────┐
                    │ V8::SetFatalErrorHandler / SetOOMErrorHandler          │
                    │   → static buffer → Crashpad annotation (always)       │
                    │   → V8HE v2 stream (when heap capture enabled)         │
                    └──────────────┬─────────────────────────────────────────┘
                                   │
Dump (exception+params, memory_info, annotations, V8HE v2 header fields)
                                   │
                ┌──────────────────▼──────────────────┐
                │   cause::CrashCauseAnalyzer          │
                │                                      │
                │  1. ExceptionClass    (code, params) │
                │  2. DisasmClassifier  (iced-x86)     │  ← shared disasm util
                │  3. FaultSiteClassifier              │  ← MemoryInfoList × fault VA
                │  4. CageFaultAnalyzer                │  ← shared heap-walk util
                │  5. FatalMessageExtractor            │  ← V8HE v2 / annotations / scan
                │  6. OomStateChecker                  │  ← top/limit, GC state
                │                                      │
                │  → rank rules → CrashDiagnosis       │
                └──────────────────┬──────────────────┘
                                   │
                    AnalyzerOutput.custom["crash_diagnosis"]
                    { verdict, confidence, evidence[], details{} }
```

Design rules:
- **Fail closed.** Every rule emits `None` or `Unknown` on any inconsistency, never a wrong verdict (same discipline as `V8Layout`).
- **Pure fusion, no mutation.** The analyzer only reads `Dump` + `AddressSpace`; capture changes are additive and version-gated.
- **Shared utilities, not duplication.** `analyzer/v8.rs`'s private helpers (`decompress`, `instance_type`, `read_v8_string`, disassembly) move to reusable modules; `v8.rs` keeps its stack-walking role.

## Module layout

```
forensicator-core/src/
├── disasm.rs            # NEW: minimal iced-x86 wrapper (decode window, classify)
├── v8obj.rs             # NEW: cage-aware object walking (moved from analyzer/v8.rs)
│                        #      decompress, smi, instance_type, read_v8_string
├── analyzer/
│   ├── cause.rs         # NEW: CrashCauseAnalyzer + verdict ranking
│   └── v8.rs            # refactor: use v8obj + disasm, unchanged behavior
└── parse/
    ├── exception.rs     # extend: decode NumberParameters + ExceptionInformation
    └── v8heap.rs        # extend: V8HE v2 header fields + fatal message
```

## Core Types

### ExceptionInfo extension (`model.rs`)

```rust
pub struct ExceptionInfo {
    pub code: u32,
    pub address: u64,
    pub thread_id: u32,
    pub flags: u32,
    /// ExceptionInformation[0..NumberParameters], as decoded from the stream.
    /// For 0xC0000005: [0]=access (0 read, 1 write, 8 exec), [1]=fault VA.
    pub parameters: Vec<u64>,
    pub context: Option<RegisterSet>,
    pub provenance: Provenance,
}
```

Parser change is additive: read `NumberParameters` at +32, array at +40 (≤15 entries, clamped by stream length). Existing callers unaffected.

### CrashDiagnosis

```rust
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum CrashVerdict {
    /// int3/ud2 at RIP, or a captured fatal message. V8's own invariant fired.
    V8CheckFailure,
    /// OOM handler message, or allocation top == limit with AV at top.
    V8OutOfMemory,
    /// 0xC00000FD, or AV touching a PAGE_GUARD region at a stack base.
    StackOverflow,
    /// AV fault VA is a small even value (compressed Smi) — Smi deref'd as pointer.
    SmiTypeConfusion,
    /// AV where the base register holds a tagged pointer into the cage and the
    /// object at it decodes — report the instance type being accessed.
    V8ObjectAccess { instance_type: u16 },
    /// AV read/write with no V8 correlation.
    NullDeref,
    WildAccess,
    /// RIP targets unmapped/non-executable memory — corrupted code pointer.
    CorruptedCodePointer,
    /// Fault VA inside a large MEM_RESERVE guard region adjacent to RX code
    /// (wasm trap-based bounds checks) — trap-handler miss.
    WasmGuardFault,
    /// Exception with no exception stream (dump captured without crash).
    NoException,
    Unknown,
}

pub struct CrashDiagnosis {
    pub verdict: CrashVerdict,
    pub confidence: Confidence,        // High | Medium | Low (project convention)
    pub evidence: Vec<String>,         // human-readable, ordered by weight
    pub fault_va: Option<u64>,
    pub access: Option<AccessKind>,    // Read | Write | Execute
    pub fatal_message: Option<String>,
    pub details: serde_json::Value,    // per-verdict extras (gc_state, space, itype…)
}
```

### Disasm utility (`disasm.rs`)

Extract `analyzer/v8.rs::disassemble_exception` into:

```rust
pub struct Instruction { pub va: u64, pub text: String, pub kind: InstrKind }

pub enum InstrKind {
    Int3, Ud2,
    MemRead { base: Option<usize>, disp: i64 },   // reg index into RegisterSet
    MemWrite { base: Option<usize>, disp: i64 },
    IndirectCall, IndirectJump,
    Other,
}

pub fn decode_window(space: &AddressSpace, ip: u64, max: usize) -> Vec<Instruction>;
```

`analyzer/v8.rs` keeps formatting its `crash_disasm` JSON from `decode_window`; `cause.rs` consumes `InstrKind`. First instruction at exactly `exc.address` is the faulting one.

### Heap-walk utility (`v8obj.rs`)

Move from `analyzer/v8.rs` (unchanged semantics, now `pub(crate)`):

```rust
pub fn decompress(cage: u64, compressed: u32) -> Option<u64>;
pub fn smi(raw: u32) -> Option<i32>;
pub fn instance_type(space: &AddressSpace, cage: u64, heap: u64) -> Option<u16>;
pub fn read_v8_string(space: &AddressSpace, va: u64, itype: u16, layout: &V8Layout) -> Option<String>;
```

## Classification rules (evaluated in order; first match wins)

| # | Rule | Inputs | Verdict (confidence) |
|---|------|--------|----------------------|
| 1 | Fatal message present (V8HE v2 field, `v8_fatal_message` annotation, or `"Check failed:"`/`"Fatal error in"` string within the crashed thread's stack region) | message | `V8CheckFailure` (High); message containing `Out of memory`/`CALL_AND_RETRY_LAST` → `V8OutOfMemory` (High) |
| 2 | code = `0x80000003` (or first instr = `Int3`/`Ud2`) | exc, disasm | `V8CheckFailure` (Medium without message, High with) |
| 3 | code = `0xC00000FD`, or AV fault VA inside a `GUARD`-protected region adjacent to a `RegionClass::Stack` region | exc, params, regions | `StackOverflow` (High) |
| 4 | AV fault VA inside a `MemState::Reserve` region ≥ 1 GiB with an RX-committed region within 4 GiB | exc, params, memory_info | `WasmGuardFault` (Low) |
| 5 | AV: fault VA ≠ 0, `< 2³²`, even → equals a compressed Smi; and faulting instr is `MemRead/Write` whose base register holds that same value | exc, params, disasm, ctx | `SmiTypeConfusion` (High) |
| 6 | AV: faulting instr `MemRead{base, disp}`; ctx[base] is a tagged pointer into the cage; object at ctx[base]&~1 decodes a Map; fault VA = object+disp | exc, params, disasm, ctx, cage | `V8ObjectAccess{itype}` (Medium) — "crashed reading field +0x1B of a JS_FUNCTION-type object" |
| 7 | V8HE v2: `alloc_limit - alloc_top < 64 KiB` and fault VA within [top, limit+page) | v2 header, params | `V8OutOfMemory` (Medium) |
| 8 | RIP not in any module and `space.region_at(rip)` is None or non-exec | exc, space | `CorruptedCodePointer` (High) |
| 9 | AV fault VA < 64 KiB | params | `NullDeref` (High) |
| 10 | AV otherwise | params | `WildAccess` (Medium) |
| — | no exception stream | — | `NoException` |

All rules are pure functions over `(dump, space)` → `Option<(CrashVerdict, Confidence, Vec<String>)>`; the analyzer collects all matches, sorts by confidence, and reports the head as the verdict with the rest under `details.alternatives`.

## V8HE v2 wire format (capture side)

Version field already exists in the v1 header; v2 extends it. All additions live **between the header and the region table**, gated by `version >= 2`:

```
V8HeapExtensionHeader (v1, 32 B)          v2 extension (32 B, immediately after header)
  +0  u32 stream_type ('V8HE')              +0  u64 alloc_top_va      (0 = unknown)
  +4  u32 version (=2)                      +8  u64 alloc_limit_va
  +8  u64 cage_base                         +16 u32 gc_state          (v8::internal::Heap::GCState)
 +16  u64 isolate_va                        +20 u32 last_gc_reason    (v8::internal::GarbageCollectionReason)
 +24  u32 region_count                      +24 u32 fatal_msg_len     (bytes; 0 = none)
 +28  u32 flags                             +28 u32 reserved (=0)
                                            fatal message bytes (UTF-8, len above) follow here;
                                            region table + region bytes follow the message
```

Handler-side obligations (out of scope for this repo, specified here for the handler owner):
- Register `V8::SetFatalErrorHandler` + `SetOOMErrorHandler` at isolate init; copy the message into a `static char[4096]`; at dump time write it into the v2 extension **and** into a Crashpad annotation `v8_fatal_message` (so stack-only minidumps keep rule #1).
- Read `heap->NewSpaceAllocationTopAddress()`/limit and `heap->gc_state()` at capture; zero-fill when unavailable.
- Decoder behavior: `version == 1` → v1 path exactly (current code); `version >= 2` → parse extension, tolerate truncation (decode what's there, never fail the dump — same policy as v1 regions); unknown `version` → v1 path + anomaly.

`Dump` gains `v8heap_ext: Option<V8HeapExt>`:

```rust
pub struct V8HeapExt {
    pub alloc_top_va: u64,
    pub alloc_limit_va: u64,
    pub gc_state: u32,
    pub last_gc_reason: u32,
    pub fatal_message: Option<String>,
}
```

## Analyzer wiring

```rust
pub struct CrashCauseAnalyzer;

impl Analyzer for CrashCauseAnalyzer {
    fn name(&self) -> &str { "cause" }
    fn description(&self) -> &str {
        "Diagnoses why the process crashed: exception semantics, disassembly, cage fault analysis"
    }
    fn analyze(&self, dump: &Dump, space: &AddressSpace) -> AnalyzerOutput {
        // rules → CrashDiagnosis → out.custom["crash_diagnosis"] = serde_json::to_value(d)
    }
}
```

Registered in `Pipeline::default_pipeline()` before `v8` (cheap, and its verdict contextualizes the stack walk). CLI: surfaced by the existing `analyze`/recover-style commands via `--analyzers cause`; `inspect` prints the one-line verdict when an exception is present:

```
Diagnosis: V8CheckFailure (high) — "Check failed: !ptr->IsSmi(). in v8::internal::Cast..."
```

## TLA+ Specification (`specs/CrashCause.tla`)

### State variables

```
VARIABLES
    exc_kind,        \* NONE | BREAKPOINT | AV | STACK_OVERFLOW | OTHER
    fault_va,        \* 0..2^64-1
    rule_matches,    \* set of rule ids that fired
    verdict,         \* UNSET | rule id
    confidence       \* UNSET | HIGH | MEDIUM | LOW
```

### Actions

- **ClassifyException(code)** — map raw code to `exc_kind`; total function, `OTHER` for unmapped codes.
- **FireRule(r)** — enabled when rule r's preconditions hold over (`exc_kind`, `fault_va`, region model); adds r to `rule_matches` with its confidence.
- **Decide** — enabled when no more rules can fire; sets `verdict` to the highest-confidence match, or `UNKNOWN` when `rule_matches = {}`.

### Invariants

```
CrashCauseInvariant ==
    /\ verdict # UNSET => verdict \in rule_matches
        \* The verdict is always one of the fired rules — never invented.
    /\ verdict = UNKNOWN <=> rule_matches = {}
    /\ \A r \in rule_matches: confidence[r] \in {HIGH, MEDIUM, LOW}
    /\ exc_kind \in {NONE, BREAKPOINT, AV, STACK_OVERFLOW, OTHER}
        \* Classification is total: every raw code lands somewhere.
```

Composition into `Forensicator.tla` follows the Symbolizer pattern (`C == INSTANCE CrashCause`, conjunct added to `ForensicatorInvariant`).

## Dependencies

None. `iced-x86` is already a core dependency (used by `analyzer/v8.rs`); this design only moves the code.

## Testing Strategy

- **Parser**: v2 round-trip (header + message + regions), v1 stream still decodes, v2 truncated message tolerated, exception parameters decoded (clamped to stream length).
- **Disasm**: hand-assembled byte windows — `int3`, `ud2`, `mov rax,[rcx+0x1B]`, `call qword [rax]`, RIP-relative forms (base=None).
- **Rules**: one synthetic `Dump`+`AddressSpace` per rule row in the table above, mirroring the `make_synthetic_stack`/`V8HeapBuilder` fixtures already in `analyzer/v8.rs` tests. Rule #6 reuses `V8HeapBuilder` to place a Map + object in a cage region.
- **Ranking**: two rules firing (e.g. #1 + #2) → higher-confidence wins, loser listed under `alternatives`.
- **Regression**: existing `analyzer::v8::tests` must pass unchanged after the `v8obj`/`disasm` extraction.
- **MBT**: `mbt_crash_cause.rs` following the existing `mbt_*` pattern (opt-in via `MIRROR_BIN`).

## Open Questions

1. **GC-state enum pinning**: `gc_state`/`last_gc_reason` are raw u32s from V8 headers. Keep them raw in JSON (self-describing only to V8 source readers), or add a `V8Layout`-pinned name table? Lean: raw + name table for the 5 common values, pinned per V8 version in `v8layout.rs`.
2. **Fatal-message string scan (rule #1 fallback)**: scanning the whole crashed thread's stack region is cheap; scanning *all* captured regions for `"Check failed:"` is O(heap). Cap to stack regions + V8HE regions, or allow a `--deep-fatal-scan` flag?
3. **Multi-isolate**: v2 captures one isolate's top/limit. For Electron renderer+node processes, the extension may need an isolate array in v3. Defer — current handler captures the crashing isolate.

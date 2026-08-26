# V8 Type-Feedback Recovery — Design Spec

> **Lean-port context:** this design extends the shipped `v8` analyzer
> (`Forensicator/Analyzer/V8.lean`, documented in
> `docs/v8-jit-frame-resolution.md`) which already resolves
> `JSFunction → SharedFunctionInfo → Script → name/line` for JIT frames.
> That chain recovers *what* was running but not *why Turbofan generated
> wrong code*. This design adds the missing link: recovering the **type
> feedback** Turbofan trusted, the **bytecode** it compiled from, and the
> **source position** the faulting native instruction maps back to.

## Status

Draft, grounded in the V8 14.6 object model (Electron 41 / Chromium 146,
revision `f9116f3bf9a50b0f7925daacfdc6fed503a9dbe2`). All offsets below are
from that revision's `.tq`/`.h` files; the implementation must verify each
against the dump before trusting it (same fail-closed discipline as the
existing `V8Layout`).

## Summary

Add a **`jit` analyzer** (`Forensicator/Analyzer/Jit.lean`) and extend
`Forensicator/Util/V8Layout.lean` with V8 14.6 offsets for
`FeedbackVector`, `FeedbackCell`, `FeedbackMetadataSlot`, `BytecodeArray`,
`Code`, `DeoptimizationData`, and the trusted-space tables. The analyzer
walks from each recovered `JSFunction` (already produced by the `v8`
analyzer) through:

```
JSFunction
  ├─+16  SharedFunctionInfo (SFI)          ← already walked
  │   ├─+12  name_or_scope_info            ← already decoded
  │   ├─+20  script                         ← already decoded
  │   ├─ function_data → BytecodeArray      ← NEW (trusted ptr, Phase 2)
  │   └─ ...
  ├─+24  feedback_cell (compressed)         ← NEW (in-cage, Phase 1)
  │       └─→ FeedbackVector
  │            ├─ slots[]  (IC type feedback) ← NEW (Phase 1, the key data)
  │            └─ shared_function_info        ← NEW (back-ref cross-check)
  └─+12  dispatch_handle (int32)            ← NEW (trusted, Phase 2)
          └─→ JSDispatchTable → Code
               ├─ instruction_start           ← NEW
               ├─ deoptimization_data          ← NEW (trusted ptr, Phase 2)
               │    └→ DeoptimizationData
               │         └→ source positions (native offset → bytecode pos)
               └─ source_position_table        ← NEW (trusted, Phase 2)
```

Two delivery phases:

| Phase | What it recovers | Trusted space? | Value |
|---|---|---|---|
| **1** (in-cage) | `FeedbackVector` + IC slot type feedback | No — all compressed ptrs in the 4 GB cage | The types Turbofan *observed* and *trusted* — direct evidence of a type-narrowing error |
| **2** (trusted) | `BytecodeArray`, `Code`, `DeoptimizationData`, source positions | Yes — requires `TrustedPointerTable` discovery | The exact bytecode → native offset mapping; pinpoints the eliminated guard |

Phase 1 alone turns a "likely JIT bug" into "here are the types Turbofan
assumed and here is the function that broke the assumption." Phase 2 adds
bytecode-level proof.

## Motivation

### The gap this fills

The cross-tool investigation of the JLCEDA Pro fulldump
(`Case/fulldump/ed633e36-…dmp`) established:

- **Forensicator `cause`**: `SmiTypeConfusion` at `0x7FF7B2C28121` — V8
  optimized code dereferenced a Smi as a HeapObject. High confidence.
- **Forensicator `v8`**: the crashing JS stack is `renderPlanes →
  renderByMatrix → yye` (OptimizedJavaScript frames), shader-generation
  code.
- **medioxor/v8-forensics**: zero exploit artifacts across 2.09M arrays —
  not an exploitation attack.
- **Baggili port**: heap structurally valid (67,283 maps cross-validated).

What none of these can answer: **which feedback slot's type was wrong, and
which guard was eliminated?** That is exactly what a JIT root-cause needs,
and it lives in the `FeedbackVector` (Phase 1) and `Code`/`DeoptimizationData`
(Phase 2).

### Why a minidump can do this

A full process minidump captures the entire renderer address space,
including all V8 heap spaces (read-only, old, new) **and** trusted space
(the `Code` objects, `BytecodeArray`s, and pointer tables). The existing
`v8` analyzer already proves in-cage objects are reachable via compressed
pointer decompression. Trusted-space objects require indirect-pointer
handle resolution — harder but the data is physically present.

## Background: V8 type feedback and the JIT pipeline

### How Turbofan uses feedback

V8's JIT pipeline:

```
JavaScript source
  → Ignition (bytecode interpreter) collects type feedback in FeedbackVector
  → Sparkplug (baseline compiler) uses feedback for simple specialization
  → Maglev / Turbofan (optimizing compilers) use feedback for type narrowing
```

Each **feedback slot** in the `FeedbackVector` records what Ignition observed
at a specific bytecode position: the maps of loaded objects, the call targets,
the element kinds. Turbofan reads these slots and **narrows types** based on
them — e.g., "slot 12 always saw a HeapNumber, so I'll generate a direct
float load and skip the Smi check."

A **type confusion** occurs when the feedback was incomplete or stale:
Turbofan narrowed to "always HeapNumber" but a Smi later arrived, and the
eliminated guard was the one that would have caught it.

### FeedbackVector structure (V8 14.6)

`FeedbackVector` is a `HeapObject` in the regular heap (instance type
`0x0083` = `FEEDBACK_VECTOR_TYPE`, confirmed in the dump with 6 live maps):

```
FeedbackVector:
  +0   map                    compressed HeapObject ptr → MAP_TYPE
  +4   weak_id / flags        (implementation detail, not needed)
  +8   length (Smi)           number of feedback slots
  +12  shared_function_info   compressed ptr → SFI (back-reference for cross-check)
  +16  invocation_count       (Smi, not needed)
  +20  profiler_tier          (Smi, not needed)
  +24  slots[]                array of Tagged<MaybeObject> — the IC state
```

Each slot at `+24 + 4*i` is a 4-byte compressed tagged value whose meaning
depends on the slot **kind** (encoded in the `FeedbackMetadata`):

| Slot kind | What it records | Type-confusion relevance |
|---|---|---|
| `CALL_IC` | Call target (JSFunction / Builtin) | Wrong call target → wrong code |
| `LOAD_IC` | Map of the loaded object's holder | Wrong map assumption → wrong field offset |
| `STORE_IC` | Map after store | Same |
| `LOAD_GLOBAL_IC` | PropertyCell | — |
| `KEYED_LOAD_IC` | Maps of objects + element kind | OOB / type confusion via elements |
| `DEFINE_KEYED_OWN_IC` | Element kind transitions | — |
| `BINARY_OP_IC` | Observed Smi/HeapNumber/BigInt mix | **Directly relevant** to Smi-type-confusion |

A `BINARY_OP_IC` slot that recorded only `HeapNumber` feedback would cause
Turbofan to skip the Smi check — exactly the bug pattern in the case dump.

### Slot state encoding

A slot can be in one of several states:

| State | Encoding (compressed) | Meaning |
|---|---|---|
| Uninitialized | Smi 0 | No feedback yet (deoptimized on first hit) |
| Monomorphic | One HeapObject ptr (map or function) | One type observed |
| Polymorphic | `WeakArrayList` of 2–6 ptrs | A few types observed |
| Megamorphic | Special marker | Too many types — generic path |
| Generic | Special marker | No specialization |

For type-confusion analysis, **monomorphic** slots are the smoking gun:
Turbofan fully trusted a single type and eliminated all guards.

### Leaptiering and trusted space

V8 14.6 has **leaptiering** (`V8_ENABLE_LEAPTIERING`): `JSFunction` stores
a `dispatch_handle: int32` (at +12) indexing the per-Isolate
`JSDispatchTable`, not a direct `Code` pointer. The dispatch table and
`Code` objects live in **trusted space** — outside the 4 GB pointer-
compression cage, reachable only via the `TrustedPointerTable`.

```
cage (4 GB, base 0x290_00000000)
  ├── read-only space: maps, internalized strings
  ├── old space: SFIs, Scripts, FeedbackVectors, contexts
  └── (all compressed-tagged, directly decompressible)

trusted space (outside cage)
  ├── Code objects (executable, RX)
  ├── BytecodeArray objects
  ├── JSDispatchTable (segmented array)
  └── (reachable only via TrustedPointerTable handles)
```

This split is why the existing `v8` analyzer explicitly avoids trusted
space ("we never need to follow those"). Phase 1 of this design stays in
the cage; Phase 2 crosses the boundary.

## Architecture

```
                     ┌────── from v8 analyzer ──────┐
                     │  V8StackFrame (per thread)    │
                     │   .framePointer               │
                     │   .jsFunctionName             │
                     └───────────┬──────────────────┘
                                 │
                    ┌────────────▼────────────────────┐
                    │  JitAnalyzer.run                 │
                    │  (Dump → AddressSpace → Output)  │
                    │                                  │
                    │  for each JS frame:              │
                    │    1. JSFunction ← [fp-16]       │  (existing helper)
                    │    2. validate (context RT)      │  (existing helper)
                    │    3. Phase 1:                   │
                    │       feedback_cell ← fn+24      │
                    │       feedback_vector ← fc+off   │
                    │       for each slot:             │
                    │         decode slot kind         │
                    │         decode slot state        │
                    │         extract type/map info    │
                    │    4. Phase 2 (if TPT found):    │
                    │       dispatch_handle ← fn+12    │
                    │       Code ← JSDT[handle]        │
                    │       fault_offset = faultVA     │
                    │         - Code.instruction_start │
                    │       DeoptData ← Code+off       │
                    │       source_pos = deopt lookup  │
                    │    → JitFrameInfo                │
                    └────────────┬────────────────────┘
                                 │
                    AnalyzerOutput.custom["jit_frame_info"]
                    { function, feedback_slots[], fault_source_pos }
```

### Design rules (inherited from existing analyzers)

- **Fail closed.** Every decode returns `None` on any inconsistency —
  wrong instance type, out-of-range length, unreadable memory. Never
  produce a wrong slot interpretation.
- **Pure, no mutation.** The analyzer only reads `Dump` + `AddressSpace`.
- **Shared utilities.** Reuses `decompress`, `instanceType`, `readU32o`,
  `readV8String`, `smi` from `V8.lean` (to be moved to a shared
  `Forensicator/Util/V8Obj.lean` — see Implementation map).
- **Version-gated.** All offsets come from `V8Layout`; a wrong version
  fails closed to `None`, never to wrong data.
- **Confidence scores.** Each recovered slot carries a confidence level
  (monomorphic slots = high; polymorphic = medium; uninitialized = N/A).

## Phase 1: In-cage FeedbackVector recovery

### Object graph (all compressed pointers, no trusted space)

```
JSFunction @ heap
  +24  feedback_cell (compressed)  → FeedbackCell

FeedbackCell @ heap
  +12  feedback_vector (compressed) → FeedbackVector
       (FeedbackCell is a small HeapObject: map + flags + parent_cell + feedback_vector)

FeedbackVector @ heap
  +0   map → instance type 0x0083 (FEEDBACK_VECTOR_TYPE)  ← validate
  +8   length (Smi)             ← slot count
  +12  shared_function_info     ← cross-check against SFI from frame
  +24  slots[length]            ← the IC state
```

### Slot decode

For each slot `i` in `0..length`:

```
slot_addr = feedback_vector + 24 + 4*i
raw       = readU32o(space, slot_addr)
```

1. **If `raw & 1 == 0` (Smi):** the slot is either uninitialized (value 0)
   or encodes a small integer (e.g., element kind, call count). Record
   as `SmiFeedback(value)`.

2. **If `raw & 1 == 1` (HeapObject):** decompress to `cage + (raw & ~1)`.
   Read the object's instance type:
   - **`WeakArrayList` (polymorphic):** the slot holds 2–6 weak references
     to maps/functions. Iterate the array (it's a `HeapObject` with a
     `length` Smi at +4 and compressed entries at +8). Record as
     `PolymorphicFeedback(maps[])`.
   - **Map (instance type 0x0116):** monomorphic — Turbofan saw exactly
     one object shape. Record as `MonomorphicFeedback(map_addr,
     instance_type, elements_kind)`. This is the highest-value finding.
   - **JSFunction (instance type 0x0812):** monomorphic call target.
     Record as `MonomorphicCall(target_addr, name?)`.
   - **Other HeapObject:** record as `UnknownFeedback(itype)`.

3. **Slot kind:** requires reading the `FeedbackMetadata`, which is stored
   on the `SharedFunctionInfo` (compressed pointer). The metadata maps
   slot index → slot kind (`LOAD_IC`, `CALL_IC`, `BINARY_OP_IC`, etc.).
   This adds the semantic label to each slot's raw state.

### Cross-validation

The `FeedbackVector.shared_function_info` (+12) must match the SFI already
resolved from the frame (`JSFunction +16`). If they disagree, the
feedback_cell pointer was stale or misread — abort and return `None` for
that frame. This is the same "context round-trip" discipline the existing
`v8` analyzer uses for JSFunction validation.

### What Phase 1 tells you

For the case dump's crashing function `yye` (tid 22024, depth 3):

```
yye (OptimizedJavaScript frame)
  FeedbackVector @ 0x2900????????
    slot 0: LOAD_IC      Monomorphic  map 0x2900??????? (JS_OBJECT_TYPE, ek=PACKED_ELEMENTS)
    slot 1: LOAD_IC      Monomorphic  map 0x2900??????? (JS_OBJECT_TYPE, ek=PACKED_ELEMENTS)
    slot 2: BINARY_OP_IC Monomorphic  HeapNumber        ← Turbofan assumed always HeapNumber
    slot 3: CALL_IC      Monomorphic  JSFunction "renderByMatrix"
    ...
```

If slot 2 shows monomorphic `HeapNumber` feedback, that is the direct
explanation: Turbofan saw only HeapNumbers during profiling, eliminated
the Smi check, and a Smi arrived at runtime. Combined with the `cause`
analyzer's `SmiTypeConfusion` verdict, this is root-cause-grade evidence.

## Phase 2: Trusted-space crossing (Code, BytecodeArray, DeoptimizationData)

### The challenge: indirect pointers

Trusted-space objects (`Code`, `BytecodeArray`, the dispatch tables) are
not in the 4 GB cage. They are reached via **trusted pointer handles** —
indices into the `TrustedPointerTable`, which itself lives in trusted
space. A trusted pointer field in a heap object stores:

```
trusted_ptr_field: u32
  index = field >> kTrustedPointerHandleShift  (typically >> kTaggedSizeLog2 = 2)
  entry = trusted_pointer_table_base + 16 * index
  target = entry & kTrustedPointerPayloadMask  (low 48 bits, minus tag bits)
```

The `trusted_pointer_table_base` is stored in the `Isolate` (whose address
is available from the `v8_isolate_address` annotation: `0x68340051c000`).
Finding the exact offset within the Isolate is version-specific; for V8
14.6 it requires either:
- The `Isolate` struct layout from V8 source (a large C++ struct — offsets
  are not in `.tq` files, only in `.h` files), or
- Runtime discovery (scan the Isolate's memory region for a value that,
  when used as a table base, correctly resolves a known handle to a known
  object — analogous to the EPT base discovery in the existing `v8`
  analyzer).

### Discovery approach (mirrors EPT discovery)

The existing `v8` analyzer already solves an analogous problem: finding
the **external pointer table (EPT) base** by brute-force scanning the
isolate's memory and validating each candidate against a known string
handle. The same technique applies here:

```
for each 8-byte-aligned u64 B in the isolate's memory region:
    for a known trusted handle H (e.g., SFI.function_data → BytecodeArray):
        entry    = read_u64(B + 16 * (H >> 2))
        target   = entry & 0x0000FFFFFFFFFFFF
        accept B iff:
          1. target is non-zero and readable
          2. target's map pointer (compressed, first 4 bytes) resolves to
             a Map with instance_type matching the expected object type
             (BytecodeArray = 0x0088, Code = 0x04e0)
          3. end-to-end: the object's known fields are sane (e.g.,
             BytecodeArray has a plausible bytecode_length and the first
             bytecodes decode as valid V8 bytecode opcodes)
```

Criterion 3 is critical: the Isolate holds pointers to several lookalike
segmented tables (`TrustedPointerTable`, `ExternalPointerTable`,
`CodePointerTable`, `CppHeapPointerTable`). Only the end-to-end decode
distinguishes them.

### JSDispatchTable → Code

With leaptiering, the path from `JSFunction` to `Code` is:

```
JSFunction +12  →  dispatch_handle (int32, even value)
                    index = dispatch_handle / entry_size  (entry_size = 16 on x64)
                    JSDispatchTable is a segmented array:
                      segment_base = jsdt_base + 4096 * (index >> 8)
                      entry = segment_base + 16 * (index & 0xFF)
                    Code* = entry & payload_mask  (trusted pointer)
```

The `jsdt_base` is another Isolate-relative pointer, discovered the same
way as the TPT base.

### Code → DeoptimizationData → source positions

Once we have the `Code` object:

```
Code @ trusted_space_addr
  +0   map → instance type 0x04e0 (CODE_TYPE)
  +??  instruction_start (raw code bytes, this is where 0x7FF7B2C28121 lives)
  +??  deoptimization_data (trusted ptr) → DeoptimizationData

DeoptimizationData
  +??  bytecode_position_table → FixedArray
        Each entry: (native_offset, bytecode_offset) pairs
        Binary search for fault_offset = faultVA - instruction_start
        → bytecode_offset

BytecodeArray @ trusted_space_addr
  +??  bytecode (raw V8 bytecode)
  +??  source_position_table → FixedArray
        Maps bytecode_offset → source position (char offset into script)
        → line number via Script.line_ends (already decoded by v8 analyzer)
```

The exact `Code` and `DeoptimizationData` field offsets are not in `.tq`
files (they are C++ structs, not Torque classes). They must be extracted
from `src/objects/code.h` / `src/deoptimizer/deoptimization-data.h` for
V8 14.6 and added to `V8Layout`.

### What Phase 2 tells you

```
Faulting native offset: 0x7FF7B2C28121
  = Code.instruction_start + 0x???? (offset within the Code object)

DeoptimizationData lookup:
  native_offset 0x???? → bytecode_offset 0x????

Source position:
  bytecode_offset 0x???? → Script char offset 0x????
  → line 34 (in the generated shader source "m=k*.5;half n=...")

Result: the faulting instruction corresponds to bytecode position 0x????,
  which is the BINARY_OP at source line 34, column ?? — the exact V8
  bytecode instruction that Turbofan compiled into the faulty dereference.
```

## V8Layout extensions

New fields for `V8Layout.lean` (all version-gated to `v14_6`):

### Phase 1 (in-cage, compressed pointers)

```lean
-- JSFunction (extends existing)
jsfunctionFeedbackCell : UInt64   -- +24

-- FeedbackCell
feedbackCellVector : UInt64       -- +12 (compressed ptr to FeedbackVector)

-- FeedbackVector
feedbackVectorLength : UInt64     -- +8 (Smi, slot count)
feedbackVectorSfi : UInt64        -- +12 (compressed ptr, cross-check)
feedbackVectorSlots : UInt64      -- +24 (start of slot array)

-- FeedbackMetadata (on SFI, for slot kinds)
sfiFeedbackMetadata : UInt64      -- offset of metadata ptr on SFI
feedbackMetadataSlotCount : UInt64
feedbackMetadataSlotKindsStart : UInt64  -- array of slot kind bytes

-- Instance type constants
itypeFeedbackVector : UInt16      -- 0x0083
itypeWeakArrayList : UInt16       -- 0x008c
itypeMap : UInt16                 -- 0x0116
```

### Phase 2 (trusted space)

```lean
-- TrustedPointerTable
trustedPtrHandleShift : Nat       -- 2 (kTaggedSizeLog2)
trustedPtrEntrySize : UInt64      -- 16
trustedPtrPayloadMask : UInt64    -- 0x0000FFFFFFFFFFFF

-- JSDispatchTable
jsdtEntrySize : UInt64            -- 16
jsdtSegmentBits : Nat             -- 8 (entries per segment = 256)

-- Code (offsets from code.h, not .tq)
codeInstructionStart : UInt64
codeDeoptData : UInt64            -- trusted ptr field offset

-- BytecodeArray
bytecodeArrayLength : UInt64
bytecodeArrayBytecodes : UInt64   -- start of bytecode bytes
bytecodeArraySourcePositions : UInt64  -- trusted ptr to FixedArray

-- DeoptimizationData
deoptDataBytecodePosTable : UInt64  -- trusted ptr to FixedArray

-- Instance type constants
itypeCode : UInt16                -- 0x04e0
itypeBytecodeArray : UInt16       -- 0x0088
```

## Output model

The `jit` analyzer produces `AnalyzerOutput.custom` entries:

```json
{
  "jit_frame_info": {
    "thread_id": 22024,
    "depth": 3,
    "function_name": "yye",
    "script_name": "m=k*.5;half n=b==e?0.:f/(m>.5?2.-k:k);return half3(j,n,m);}",
    "script_line": 34,
    "feedback_vector": {
      "address": "0x2900???????",
      "slot_count": 42,
      "sfi_crosscheck": true
    },
    "feedback_slots": [
      {"index": 0, "kind": "LOAD_IC", "state": "monomorphic",
       "map": "0x2900???????", "instance_type": "JS_OBJECT_TYPE",
       "elements_kind": "PACKED_ELEMENTS", "confidence": "high"},
      {"index": 2, "kind": "BINARY_OP_IC", "state": "monomorphic",
       "observed_type": "HeapNumber", "confidence": "high"},
      {"index": 7, "kind": "CALL_IC", "state": "monomorphic",
       "target": "0x2900???????", "target_name": "renderByMatrix",
       "confidence": "high"}
    ],
    "fault_info": {
      "fault_va": "0x7FF7B2C28121",
      "native_offset_in_code": null,
      "bytecode_offset": null,
      "source_position": null,
      "phase2_available": false
    }
  }
}
```

Phase 1 fills `feedback_slots[]`. Phase 2 fills `fault_info.{native_offset,
bytecode_offset, source_position}`.

## Validation strategy

| Check | Rejects |
|---|---|
| FeedbackCell: instance type matches `FEEDBACK_CELL_TYPE` | wild pointers |
| FeedbackVector: instance type == 0x0083 | wrong object |
| FeedbackVector SFI cross-check: `fv+12` decompressed == SFI from frame | stale/misread vector |
| Slot length: 0 < length ≤ 65536 | garbage length field |
| Slot map: instance type 0x0116, readable, inside cage | non-map HeapObject |
| WeakArrayList: length 2–6, entries inside cage | garbage arrays |
| TPT base (Phase 2): end-to-end BytecodeArray decode | lookalike tables |
| Code: instance type 0x04e0, instruction_start inside an RX region | wrong table / corrupted code |
| DeoptData: bytecode positions monotonically increasing | garbage deopt table |

All checks fail closed to `None` — no slot is ever reported with a wrong
interpretation.

## Worked example (expected from case dump)

Starting from frame `#3` (`yye`, tid 22024, `fp = 0x52C1FD200`):

```
[fp-16] = 0x0000029005999B19    JSFunction @ 0x29005999B18  (validated by context RT)

JSFunction @ 0x29005999B18:
  +24  feedback_cell = 0x???????? → FeedbackCell @ 0x2900????????

FeedbackCell @ 0x2900????????:
  +12  feedback_vector = 0x???????? → FeedbackVector @ 0x2900????????

FeedbackVector @ 0x2900????????:
  +0   map → instance type 0x0083 = FEEDBACK_VECTOR_TYPE  ✓
  +8   length = 42 (Smi)           ← 42 feedback slots
  +12  shared_function_info = 0x08B4E3B9 → 0x29008B4E3B8   ✓ (matches frame SFI)
  +24  slots[42]:
       slot 0:  0x2900?????|1 (HeapObject → Map)           Monomorphic LOAD_IC
       slot 1:  0x2900?????|1 (HeapObject → Map)           Monomorphic LOAD_IC
       slot 2:  0x0000????|0 (Smi) or HeapNumber ptr       BINARY_OP_IC — KEY SLOT
       ...
```

If slot 2 is monomorphic `HeapNumber`, the root-cause chain is complete:

```
cause analyzer:   SmiTypeConfusion (rsi = Smi, dereferenced as HeapObject)
jit analyzer:     BINARY_OP_IC slot 2 = monomorphic HeapNumber
                 → Turbofan eliminated CheckSmi, expecting always HeapNumber
                 → a Smi arrived at runtime
                 → access violation at [Smi+8]

Conclusion: V8 14.6 Turbofan type-narrowing bug in the number-handling
builtin of function yye, line 34 of the generated shader source.
```

## Implementation map

```
Forensicator/
├── Util/
│   ├── V8Layout.lean          EXTEND: add Phase 1 + Phase 2 offset fields
│   └── V8Obj.lean             NEW: shared cage-walking helpers
│                                (decompress, instanceType, readV8String,
│                                 smi — moved from Analyzer/V8.lean so
│                                 Jit.lean and V8.lean share them)
├── Analyzer/
│   ├── V8.lean                MODIFY: import V8Obj, use shared helpers
│   ├── Jit.lean               NEW: the jit analyzer
│   │                            - JitFrameInfo structure
│   │                            - decodeFeedbackVector (Phase 1)
│   │                            - decodeFeedbackSlots (Phase 1)
│   │                            - findTrustedPointerTableBase (Phase 2)
│   │                            - resolveCodeViaDispatchTable (Phase 2)
│   │                            - decodeSourcePosition (Phase 2)
│   │                            - analyzer registration
│   └── Registry.lean          MODIFY: add Jit.analyzer to defaultPipeline
└── Main.lean                  MODIFY: --plugin jit CLI path + output printing
```

### Task breakdown

1. **Extract shared helpers** to `Util/V8Obj.lean` (decompress, instanceType,
   readU32o, readV8String, smi, wadd). Update `V8.lean` to import them.
   Build green, gate green — no behavior change.

2. **Extend `V8Layout.lean`** with Phase 1 fields (FeedbackCell, FeedbackVector,
   FeedbackMetadata offsets + instance type constants). Add to `v14_6` table.

3. **Implement `Jit.lean` Phase 1**: `decodeFeedbackVector` + `decodeFeedbackSlots`.
   Walk from each `V8StackFrame`'s JSFunction (reuse the frame list already
   produced by `V8.lean`). Output `JitFrameInfo` with `feedback_slots[]`.

4. **Register `jit` analyzer** in `Registry.lean`, add `--plugin jit` CLI path
   in `Main.lean`. Verify against the case dump: `yye`'s FeedbackVector should
   have 40+ slots with at least one monomorphic slot.

5. **Add guard-suite tests** (`Test/Spec.lean`): synthetic V8 cage with a
   FeedbackVector containing known slot states (monomorphic map,
   polymorphic WeakArrayList, uninitialized). Verify exact decode.

6. **Phase 2 (separate milestone)**: extend `V8Layout` with trusted-space
   offsets. Implement TPT base discovery. Implement `resolveCodeViaDispatchTable`
   + `decodeSourcePosition`. Gate against the case dump's fault VA
   `0x7FF7B2C28121`.

## Dependencies and risks

| Risk | Mitigation |
|---|---|
| V8 14.6 `.h` offsets (Code, DeoptData) not in `.tq` — must be hand-extracted from C++ headers | Phase 2 is gated behind Phase 1; the highest-value data (feedback slots) needs only `.tq` offsets |
| TrustedPointerTable discovery might find a lookalike table | End-to-end validation (decode a known BytecodeArray through the candidate base); same technique already proven for EPT |
| FeedbackVector slot kinds need FeedbackMetadata, which is on the SFI — another indirection | SFI is already reachable; metadata is a compressed pointer on the SFI (in-cage) |
| Minified production code may have huge FeedbackVectors (100+ slots) | Cap at 256 slots per frame; report truncated count |
| Some slots may be `WeakRef` (weak pointers) not strong `HeapObject` | Weak refs have the same compressed encoding; `WeakArrayList` entries are `MaybeObject` — treat as best-effort, record as `weak` |

## Relationship to existing tools

| Tool | What it recovers | This design adds |
|---|---|---|
| Forensicator `v8` analyzer | JS stack: function names, script names, lines | Type feedback (what Turbofan assumed), bytecode mapping, source position of fault |
| Forensicator `cause` analyzer | Crash verdict (SmiTypeConfusion, OOM, CHECK) | The *specific feedback slot* and *bytecode position* that caused the type confusion |
| medioxor/v8-forensics | Exploit artifacts (OOB, fakeobj, type confusion at JSArray level) | — (complementary; confirms no exploit, this design explains the JIT bug) |
| Baggili V8MapScan port | Object/property recovery, map census | — (complementary; object-level semantics) |

## V8 source references

All at revision `f9116f3bf9a50b0f7925daacfdc6fed503a9dbe2`:

- `src/objects/feedback-vector.tq` — FeedbackVector field layout
- `src/objects/feedback-vector-inl.h` — slot access, `FeedbackSlot` indexing
- `src/objects/feedback-cell.tq` — FeedbackCell layout
- `src/objects/shared-function-info.tq` — SFI `function_data`, `feedback_metadata`
- `src/objects/feedback-metadata.h` — slot kind enum, `SlotKind`
- `src/objects/code.h` — Code field layout (instruction_start, deopt_data)
- `src/objects/bytecode-array.h` — BytecodeArray layout
- `src/deoptimizer/deoptimization-data.h` — DeoptimizationData layout
- `src/sandbox/trusted-pointer-table.h` — TPT handle/entry encoding
- `src/sandbox/js-dispatch-table.h` — JSDispatchTable layout (leaptiering)
- `src/ic/ic.h` — IC state semantics (monomorphic/polymorphic/megamorphic)

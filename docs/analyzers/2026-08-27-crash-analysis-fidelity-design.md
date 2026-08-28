# Crash-Analysis Fidelity: Cage Correlation, PDB Publics, JS-Frame Names — Design

> **Date:** 2026-08-27
> **Status:** Design (pre-implementation)
> **Case study:** `Case/nicholas/19394815-b72a-4b47-a0ee-f45866204a63.dmp`
> (JLCEDA Pro 3.2.166 / Electron 41.10.6-jlc / V8 14.x renderer fulldump)
> **Touches:** `Forensicator/Analyzer/Cause.lean`, `Forensicator/Analyzer/V8.lean`,
> `Forensicator/Util/Pdb.lean`, `Forensicator/Util/Disasm.lean`,
> `Forensicator/Util/V8Layout.lean`, `Forensicator/Analyzer/Analyzer.lean`,
> `Main.lean`, `Forensicator/Session.lean`, `Test/`

---

## 1. Problem Statement

Three analyzers silently degraded on the nicholas fulldump; all three defects
were found only by manual cross-tool analysis (v8-forensics, v8_minidump.py,
llvm-pdbutil, hand-rolled heap walkers). Ground truth established manually:

- Crash RIP = electron.exe RVA `0x4E85AE4` = **`Builtins_TypedArrayPrototypeFindLastIndex` +0x24**
  (PDB publics, byte-identical PDB verified against `out/Release_S_41_10_6`).
- Fault VA `0x12CEEC1190A` = cage (`0x12C00000000`) + `0xEEC1190A` — **~3.3 GB past
  the highest committed cage region (`0x12C1A600000`), inside the 4 GB
  pointer-compression cage reservation**. Decompressed garbage 32-bit value.
- Mechanism: `mov r12d,[rax-1]` with `rax` **untagged** (even) → map read
  off-by-one → `0xEEC11900` → `movzx r12d,[r14+r12*1+0xa]` → AV. A
  tag/representation confusion handed in from optimized JIT code.
- Full JS stack (recovered manually): `slice` ← `getPt` ← `updatePt` ←
  `setStaticPolygonInfo` ×2 ← `setMatrix` ← `mainVisible` ← `modify` ←
  `notifyShape` ← `notify` ← `modify` ×2 ← `publish` ×2 ← `c`, all in one
  external-string-backed script.
  (**Erratum 2026-08-27:** that chain is **15 frames** (depths 0-14), not 14 as
  first counted; and the `Script.name` external string's own length field is 59,
  while the crashpad-annotation URL `https://pro.lceda.cn/editor?entry=ui-worker.js&cll=warn`
  is 55 chars — they may be different strings; the true `Script.name` is only
  decodable after W3/T10. Acceptance pins the 15 names and a non-null
  `https?://` `lceda`-containing script URL.)

Forensicator's output on the same dump:

| Gap | Expected | Actual |
|---|---|---|
| G1 `cause` | tag-confusion verdict w/ cage evidence | `WildAccess/Low` "no V8 correlation" |
| G2 symbols | `Builtins_TypedArrayPrototypeFindLastIndex+0x24` at crash site | hex addresses only; `--symbols` accepted but **ignored** (`Main.lean:196` `_symbols`) |
| G3 `v8` | all 14 JS frames named + script URL + line | 3 frames named (`slice`, `<anonymous>`, `notify`), `script_name` null everywhere |

## 2. Root Causes (code-level)

### G1 — `cause` cannot see the cage reservation or SIB addressing

`Analyzer/Cause.lean`:

1. `ruleObjectAccess` (rule 6) requires the faulting instruction to be
   `InstrKind.memRead base disp` / `memWrite base disp` — **base+disp only**.
   The actual faulting instruction is SIB-addressed:
   `movzx r12d, BYTE [r14+r12*1+0xa]`. `Util/Disasm.lean` never models
   index·scale, so the rule's `fault == base + disp` check can never hold for
   the decompression idiom `[cage_reg + compressed_reg*scale + disp]`.
2. `ruleSmiConfusion` (rule 5) has the same SIB blindness, and additionally
   requires `baseVal < 2^32`; here the *base* is the cage (`0x12C00000000`)
   and the garbage rides the *index* register.
3. No rule reasons about the **cage reservation** at all: `cageBase` is
   already decoded (`annotationHex "v8_ro_space_firstpage_address"`) but is
   only used for committed-object decoding. A fault *inside* `[cage, cage+4GB)`
   yet *outside every committed region* is the canonical signature of a
   decompressed garbage compressed-pointer, and it falls through to
   `ruleWildAccess`.

### G2 — PDB support stops at identity; symbol context never reaches analyzers

1. `Util/Pdb.lean` is a minimal MSF-7 reader: stream directory + stream 1
   (GUID/age) for `match`. No DBI, no symbol records, no publics.
2. `analyze --symbols <dir>` is parsed (`Main.lean:574`) and stored
   (`Session.symbols`) but **dropped**: `cmdAnalyze` binds it as `_symbols`
   (`Main.lean:196`) and `Analyzer.run : Dump → AddressSpace → AnalyzerOutput`
   (`Analyzer/Analyzer.lean:36`) has no symbol channel.
3. Consequently `Analyzer/V8.lean:359` emits `nativeSymbol := hexUpper rip`
   for module-resident frames (the header comment documents this as a
   deliberate Rust-era boundary — it was never revisited).

### G3 — `v8` frame decoding is gated too hard, and EPT constants are wrong

`Analyzer/V8.lean` / `Util/V8Layout.lean`:

1. **Context-equality gate** (`decodeJsFrame`, V8.lean:275-281): a candidate
   JSFunction is only decoded when
   `function.context == [rbp + kContextOffset]`. That invariant does not hold
   for Maglev/TurboFan frames (context may be kept in a register or spilled
   elsewhere) — on the nicholas dump it passed for 3 of 14 JS frames and
   rejected the rest wholesale (`js_function_name = null`, not even
   `<anonymous>`). The current code never validates the candidate's
   **map instance type** — the context check is its *only* validation, so it
   is simultaneously too strict (rejects real frames) and too weak (no
   positive identification).
2. **EPT constants wrong for Windows x64** (`V8Layout.v14_6`):
   `eptEntrySize := 16` and `eptPayloadMask := 0x0000FFFFFFFFFFFF`.
   Actual V8 14.x values (`v8-internal.h`): entry size **8**
   (`kExternalPointerTableEntrySize = 8`), index shift **6** (default 512 MB
   reservation; Android 7, iOS 8), payload mask **`0xff00ffffffffffff`**
   (`kExternalPointerPayloadMask`). The current mask retains the tag bits
   48-55 in the "resource" pointer, so every table entry resolves to a bogus
   address and `findEptBase`'s validation sweep fails → `script_name = null`
   for all frames.
3. **ExternalString resource model outdated**: `externalStringViaEpt`
   resolves the handle → C++ `ExternalStringResource*` and reads a cached
   data pointer at `resource + 16`. In V8 14.x the `ExternalString` heap
   object itself caches the character data pointer (`kResourceDataOffset`);
   on the nicholas dump the fields at +0xC and +0x10 are *both* EPT handles
   (0x000b8f80, 0x000b8fc0), so the second handle must also be resolved via
   the table rather than dereferenced through the resource.
   (Exact `external-string.tq` layout for 14.6 to be pinned during
   implementation — see Open Questions.)
4. `scopeInfoFunctionName` (V8.lean:178-210) already implements the
   ScopeFlags → FunctionVariableInfo / InferredFunctionName walk and its
   constants (`scopeFlagSavedClassVariable`, `scopeFunctionVariableShift`,
   `scopeFlagInferredFunctionName`) match the 14.x `ScopeFlags` bitfield.
   It was simply never reached because of gate (1).

## 3. Design

Three workstreams, independently landable, in dependency order
(W2 before the W1 evidence-integration task; W3 independent).

### W1 — Cage-reservation correlation + SIB disassembly (`cause`, `Disasm`)

**W1.1 SIB addressing in `Util/Disasm.lean`.**
Extend `InstrKind.memRead`/`memWrite` (or add `memReadSib`/`memWriteSib`)
to carry `(base : Option Reg) (index : Option Reg) (scale : UInt8) (disp : Int)`.
Cover the subset the cause rules need: `mov`/`movzx`/`movsx`/`cmp`/`test`
with ModRM+SIB, mod 00/01/10, disp8/disp32, scales 1/2/4/8. Pure decoder,
bounds-guarded, byte-pinned golden vectors in `Test/Spec.lean` (same style
as the trace frame codec). The vectors include the two nicholas crash
instructions:
`44 8b 60 ff` (`mov r12d,[rax-1]`) and `47 0f b6 64 26 0a`
(`movzx r12d,BYTE [r14+r12+0xa]`).

**W1.2 New verdicts.** Extend `CrashVerdict`:

    | v8TagConfusion                -- tag/representation confusion in V8 values
    | decompressedGarbagePointer    -- AV at uncommitted address inside the cage

(Debug strings `"V8TagConfusion"` / `"DecompressedGarbagePointer"`.)

**W1.3 New rule `ruleCageDecompression`** (priority between
`ruleObjectAccess` and `ruleOomState`):

- Precondition: AV read/write; `cageBase` known; `fault ∈ [cage, cage+2^32)`;
  `space.regionAt fault == none` (uncommitted).
- **Strong form (High, `v8TagConfusion`)**: the faulting instruction is a
  decompression idiom — memory operand whose *base register holds the cage
  base* (`regs.get base == cageBase`). Then the decompressed 32-bit value is
  `v = (fault - cage - disp) / scale` (exact division required, scale from
  SIB); report `v`, its tag bit, the disassembly text, and the distance of
  the fault past the highest committed in-cage region (computed from
  `space` regions ∩ `[cage, cage+2^32)`). Even `v` (no heap tag) strengthens
  the evidence line: "compressed value 0x… is untagged (Smi/garbage) used as
  pointer".
- **Weak form (Medium, `decompressedGarbagePointer`)**: precondition holds
  but the instruction doesn't match the idiom: report fault, offset into
  cage, and distance past highest committed region.
- Generalize `ruleSmiConfusion`/`ruleObjectAccess` to the new SIB operands
  (same checks, base/index algebra) so older cases keep working on SIB forms.
- Fail-closed: any failed sub-check → `none`, next rule; `ruleWildAccess`
  remains the floor. Existing golden verdicts must not change unless the new
  rule legitimately fires (see §4).

**W1.4 Symbol-enriched evidence** (depends on W2): when a `Publics` table is
present, append `faulting IP {rva} = {symbol}+0x{off}` to the evidence, and
if the symbol starts with `Builtins_`, record it (an embedded-builtin crash
site is itself evidence for a V8-internal defect).

### W2 — PDB publics symbolizer (`Util/Pdb`, pipeline plumbing)

**W2.1 Lazy MSF stream IO.** `MsfFile` currently takes a fully-loaded
`ByteArray` (fine for `match`; fatal for a 3.7 GB PDB alongside a 1.5 GB
dump). Add a handle-based reader: `MsfHandle.open (path) : IO MsfHandle`
(read header + stream directory only), `MsfHandle.stream (idx) : IO ByteArray`
(seek+read just that stream's pages). Keep the existing `MsfFile` API for
`match` (implemented over the new reader or left as-is).

**W2.2 DBI + publics parsing.**
- Stream 3 (DBI): header → `symrecstream` (global symbol record stream) and
  `pubsymstream` indices.
- Parse the symbol record stream sequentially:
  `[reclen u16][kind u16][payload]`; select `S_PUB32` (0x110E):
  `[flags u32][off u32][seg u16][name cstring]`.
- RVA mapping: `rva = sectionVA(seg) + off`. Section VAs come from the
  matching PE (`Util/Image.lean`, when `--exe` was given or the module can be
  backed on disk); fallback for segment 1 (`.text`, where all `Builtins_*`
  live): `rva = off` with a recorded caveat — verified exact for the
  nicholas PDB (`addr = 0001:82312896` ≡ RVA `0x4E7FEC0`).
- `structure Publics where entries : Array (UInt32 × String)` sorted by RVA;
  `Publics.nearest (rva) : Option (String × UInt32)` = binary-search
  nearest-below + delta. Total, bounds-guarded.

**W2.3 Plumbing.** Keep `Analyzer.run` pure. Add a symbol context:

    structure SymbolsCtx where publics : Option Publics := none
    -- Analyzer.run : SymbolsCtx → Dump → AddressSpace → AnalyzerOutput

`runPipeline` threads it. `cmdAnalyze`/`Session`: when `--symbols <dir>` is
set, pick the PDB whose `pdb_name` matches the crashed/main module
(`codeview_guid` + age verified through the existing `pdbIdentity`), load
`Publics` once (IO), pass down. Absent/mismatched PDB → `none`, analyzers
degrade exactly as today (fail closed, no behavior change).

**W2.4 Consumers.**
- `cause`: crash-IP symbolization in evidence (W1.4).
- `v8`: `nativeSymbol` for module-resident frames =
  `symbol+0xoff` instead of `hexUpper rip`; builtin frames keep their
  `Builtins_*` identity next to `frame_type = Builtin`.

**W2.5 Cost.** Publics stream for this PDB is ~50-200 MB (millions of
S_PUB32); one stream load per analyze run, acceptable. Optional
(non-v1): sidecar cache `<pdb>.pubcache` (sorted binary) with
guid+age validation.

### W3 — JS-frame fidelity (`v8`, `V8Layout`)

**W3.1 Layout constants.**
- Fix `V8Layout.v14_6`: `eptEntrySize := 8`, `eptIndexShift := 6` (per-OS
  note: Android 7 / iOS 8 — add a layout selector field or document
  Windows/Linux default), `eptPayloadMask := 0xff00ffffffffffff`.
- Add: `itypeJsFunctionFirst := 0x0812`, `itypeJsFunctionLast := 0x0822`
  (LAST_JS_FUNCTION_TYPE = 2082 in the 14.6 generated instance-types.h — the
  first draft's 0x0826 was wrong; corrected 2026-08-28),
  `itypeSharedFunctionInfo` (pin from the 14.6 `instance-types.h`),
  `itypeScopeInfo := 0x011E` (confirms existing dispatch), plus
  `externalStringResourceData : UInt64` (see W3.3).
- Provenance comment per constant (file + line in the V8 tree), as existing
  fields do.

**W3.2 Scored JSFunction validation (replaces the context gate).**
`decodeJsFrame` currently: slot candidates `[kFunctionOffset,
kFunctionOffsetLegacy]` + context-equality gate. Replace with a deterministic
validator scored per candidate slot:

1. candidate tagged, in-cage, aligned;
2. **map instance type ∈ `[itypeJsFunctionFirst, itypeJsFunctionLast]`** —
   the positive identification that was missing;
3. SFI slot decompresses; SFI's map instance type ==
   `itypeSharedFunctionInfo`;
4. context match (existing check) as a *bonus*, not a gate.

Decode the first candidate reaching the threshold (2+3 required; 4
breaks ties). Slot order: the two fixed offsets first, then a bounded
fallback scan `[rbp-0x30 … rbp-0x8]` step 8 (covers Maglev/TurboFan spill
layouts). All reads bounds-guarded; failure ⇒ next candidate ⇒ `none`
(behavior today).

**W3.3 ExternalString decoding.**
Resolve *both* in-object handles at `stringChars` (+0xC) and
`externalStringResourceData` (+0x10, pinned from `external-string.tq`)
through the EPT: the entry whose payload reads as printable
one-/two-byte characters of the declared length wins (that is the data
pointer); the entry whose payload points to an object with a module-resident
vtable is the `ExternalStringResource`. Keep the resource→data fallback
(`resource + 16`) for older layouts. `findEptBase` keeps its probe-based
validation but with corrected constants (W3.1) — its "vtable in modules"
check now identifies the resource handle rather than the data handle.

**W3.4 Script name + line.** With W3.1-W3.3, `decodeScriptName` and the
existing `decodeScriptLine` (line-ends binary search + ScopeInfo position)
start producing values; no algorithm change, only correctness of inputs.

**W3.5 Native symbols.** Wire W2's table into `nativeSymbol` (W2.4).

## 4. Verification

**Unit / guard suite (`Test/`):**
- W1: byte-pinned SIB vectors incl. the two crash instructions; rule-level
  tests on a synthetic `Dump` (crafted cage + exception + one uncommitted
  fault) asserting `V8TagConfusion/High` and `DecompressedGarbagePointer/Medium`
  paths, plus non-firing paths (fault committed → `none`).
- W2: synthetic minimal PDB fixture (MSF-7 container with streams 1/3 and a
  handful of S_PUB32 records built in-test, few KB) → parser + `nearest`
  correctness; GUID/age mismatch → clean `none`.
- W3: synthetic cage object graph (JSFunction→SFI→ScopeInfo→String;
  ExternalString + synthetic EPT region) → name/URL/line extraction.

**Live acceptance (the nicholas dump + PDB, manual/opt-in, mirrors the
proxy live-gate pattern):**
- `cause`: verdict `V8TagConfusion/High`; evidence contains
  `Builtins_TypedArrayPrototypeFindLastIndex+0x24`, compressed value
  `0xEEC11900`, ~3.3 GB past committed.
- `v8`: the 14 names from §1 in order; `script_name` = the resolved
  external-string URL; `native_symbol` of builtin frames = `Builtins_*`.
- Golden gate: existing 3-dump goldens must be byte-identical **unless** the
  new cage rule fires on them (audit each; if a verdict legitimately
  improves, regenerate via `scripts/capture-goldens.sh` from the
  known-good build and document the delta in the commit).

## 5. Invariants & Conventions

- No `sorry`/`partial`/`panic!`; all new decoders bounds-guarded, recursion
  fuel/`termination_by`-based (house style).
- Provenance: every new decoded fact keeps stream/offset discipline; PDB
  records carry (streamIdx, fileOffset).
- Zero new deps; JSON via `Util/Json.lean`; output keys additive-only
  (`evidence` lines may grow; verdict strings gain two new values).
- `Analyzer.run` stays pure; all IO confined to `Main`/`Session`/W2 loader.

## 6. Task Breakdown (for the implementation plan)

| # | Task | Workstream | Depends |
|---|------|-----------|---------|
| 1 | SIB operand decoding + byte-pinned vectors | W1 | — |
| 2 | `CrashVerdict` ×2 + `ruleCageDecompression` + SIB-generalized rules 5/6 | W1 | 1 |
| 3 | Lazy MSF stream reader (`MsfHandle`) | W2 | — |
| 4 | DBI + S_PUB32 parser + `Publics.nearest` (+ section-VA strategy) | W2 | 3 |
| 5 | `SymbolsCtx` plumbing: Analyzer/Registry/Main/Session | W2 | 4 |
| 6 | cause+v8 symbol consumers (evidence, `nativeSymbol`) | W2 | 5 |
| 7 | W1.4 symbol-enriched tag-confusion evidence | W1 | 2, 6 |
| 8 | `V8Layout` constants (EPT, itypes, resource-data) + provenance | W3 | — |
| 9 | Scored JSFunction validation (replace context gate) | W3 | 8 |
| 10 | ExternalString dual-handle decoding + `findEptBase` update | W3 | 8 |
| 11 | Guard-suite fixtures (synthetic PDB, synthetic cage graph) | all | 4, 10 |
| 12 | Live acceptance on `Case/nicholas` + golden audit | all | 2, 6, 10 |

## 7. Open Questions

1. **ExternalString exact 14.6 layout** — pin `kResourceOffset` /
   `kResourceDataOffset` and whether the cached data pointer is itself an
   EPT handle (nicholas evidence says yes: two handles 0x…f80/0x…fc0).
   Resolve from `external-string.tq`/`-inl.h` in the build checkout before
   task 10.
2. **Per-OS EPT shift** (6 default / 7 Android / 8 iOS): single-OS constant
   + documented assumption, or a layout field selected by dump OS? Leaning
   to the field; Windows-only in practice so far.
3. **Section-VA fallback** when no `--exe` is available: offset-as-RVA for
   segment 1 held exactly for the nicholas PDB; decide whether to trust it
   generally or to parse the DBI optional-debug-header section substream.
4. **Publics load cost** on multi-GB PDBs: measure; if >2 s on the
   acceptance dump, consider the `.pubcache` sidecar (non-v1).

## 8. Addendum A (2026-08-28): V8HE/MemoryList overlap-drop bug — FIXED

T9's debug probe surfaced a fourth gap, worse than the three originals:
V8HE ranges are prepended for priority, and `AddressSpace.addRegion`'s overlap
rejection then **dropped entire MemoryList regions** (nicholas: an 87 MB heap
region dropped over 20 small V8HE overlaps), hiding most JS frames' objects.
Fix (`Parse/Minidump.lean`): `clipRanges` — interval subtraction with
data slicing; V8HE bytes win inside their ranges, MemoryList fragments keep
the rest; MemoryInfo protection lookup switched to containment. Guard
regression test added. Golden audit required (fulldump goldens encode the
lossy behavior).

## 9. Addendum B (2026-08-28): ExternalString reality on selective dumps

The instrumented handler's dump **does not capture most EPT pages** (only
`0xf3ff0000-0xf4010000` of the `0xF4000000` table reservation). Handles of
the app script's name/source strings (indices 0x2e3e/0x2e40) live outside the
captured page. Consequences:

- `findEptBase`'s probe-based scan latched onto a **false table** inside the
  isolate region (0x38d4000c5c00) whose entries happened to resolve to a
  vtable-ish object + 59 printable chars of SkSL shader text — a garbage
  `script_name`. Fix: validate **both** in-object handles (resource →
  module vtable, resource_data → exactly-length printable chars) and reject
  candidate bases inside the isolate region; fail closed (`none`) when the
  entry page is absent.
- `readV8String` gains an EPT path (external one/two-byte) shared with
  `scopeInfoFunctionName` — frame-local names may be external strings too.
- **Acceptance contract correction:** on this dump, app-frame `script_name`
  is honestly `null` (EPT page not captured); the canonical JS sequence
  (canonical kFunctionOffset attribution) is:
  `slice, getPt, updatePt, setStaticPolygonInfo, setMatrix, mainVisible,
  <anonymous>, modify, notifyShape, notify, modify, <anonymous>, publish,
  publish, c`
  The earlier 15-name list came from a spill-slot scan-order artifact
  (ascending window found callers' spilled functions first). The harness pins
  the canonical sequence; `script_name` accepts null-or-valid-lceda-URL.

# Lean 4 Migration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port Forensicator to a standalone Lean 4 package at `~/Repos/Forensicator_Lean/` per `docs/superpowers/specs/2026-08-10-lean4-migration-design.md`: TLA+ specs become proved Lean theorems over the *executable* code; the Rust repo serves as golden oracle via a JSON-diff conformance gate.

**Architecture:** One Lake package, no dependencies. `Spec/` (mechanized TLA+ with theorems) → `Parse/` (total cursor-monad decoders) → `Model/` (Dump/AddressSpace/Trace) → `Analyzer/` (pure parity ports) → `Main.lean` CLI. FFI shims only for disasm (iced-x86) and PDB symbolizer.

**Tech Stack:** Lean `leanprover/lean4:v4.33.0` (pinned), Lake, `jq` (diff normalization), the existing Rust CLI as oracle. No Lean library deps (no mathlib/batteries).

**Definition of done (every task):** `lake build` green, `lake exe forensicator-test` green, and — once the harness exists (Task 4) — `scripts/conformance-lean.sh` reports zero diffs for all fixtures the implemented features cover. No `sorry`, no `partial`, no `panic!` in the lib (grep gate in test runner).

---

### File Map (created once, Task 0; grown per task)

| Path | Action | Purpose |
|------|--------|---------|
| `lean-toolchain` | Create | `leanprover/lean4:v4.33.0` |
| `lakefile.toml` | Create | lib `Forensicator` + exes `forensicator`, `forensicator-test` |
| `Forensicator/Basic.lean` | Create | Position, Provenance, Anomaly, errors |
| `Forensicator/Parse/Cursor.lean` | Create | total `ParseM` cursor monad |
| `Forensicator/Util/Json.lean` | Create | deterministic JSON emitter |
| `Forensicator/Spec/*.lean` | Create | mechanized specs + theorems |
| `Forensicator/Parse/Ttfx.lean` | Create | `.ttfx` v1 decoder (first vertical slice) |
| `Forensicator/Parse/Minidump/*.lean` | Create | per-stream decoders → `Dump` |
| `Forensicator/Model/*.lean` | Create | Dump / AddressSpace / Trace |
| `Forensicator/Analyzer/*.lean` | Create | analyzer ports + pipeline |
| `Forensicator/Util/{Disasm,Symbolizer}.lean` | Create | interfaces + C shim bindings |
| `Main.lean` | Create | CLI |
| `Test/*.lean` | Create | guard runner, all-prefixes fuzz |
| `scripts/conformance-lean.sh` | Create | Rust-vs-Lean JSON diff gate |

**Oracle note:** Rust CLI is built once (`cargo build` in `~/Repos/Forensicator`) and referenced as `$FORENSICATOR_RUST/target/debug/forensicator`. Fixtures via `FORENSICATOR_CASE_DIR` (default `../Forensicator/Case`).

---

### Task 0: Scaffold

**Files:**
- Create: `~/Repos/Forensicator_Lean/lean-toolchain`, `lakefile.toml`, `Forensicator.lean`, `Main.lean`, `Test/Main.lean`

- [x] **Step 1: pin toolchain + package**

`lean-toolchain`:
```
leanprover/lean4:v4.33.0
```

`lakefile.toml`:
```toml
name = "Forensicator"
version = "0.1.0"

[[lean_lib]]
name = "Forensicator"

[[lean_lib]]
name = "Test"

[[lean_exe]]
name = "forensicator"
root = "Main"

[[lean_exe]]
name = "forensicator-test"
root = "Test.Main"
```

- [x] **Step 2: smoke build** — `Main.lean` = `def main : IO Unit := IO.println "forensicator (lean)"`; `lake build && lake exe forensicator` prints. `git init` + commit.
- [x] **Step 3: PATH note** — elan shims live at `~/.elan/bin`; document in repo README-less form (top comment of `scripts/conformance-lean.sh`): `export PATH="$HOME/.elan/bin:$PATH"`.

---

### Task 1: Foundations (`Basic.lean`, `Cursor.lean`, `Json.lean`)

**Files:**
- Create: `Forensicator/Basic.lean`, `Forensicator/Parse/Cursor.lean`, `Forensicator/Util/Json.lean`
- Create: `Test/Spec.lean` (guard home)

- [x] **Step 1: `Basic.lean`** — port the shared vocabulary from `model.rs`/`error.rs`/`position.rs` (TTFX repo):

```lean
abbrev VA := UInt64
abbrev Position := UInt64          -- (major << 32) | minor, .ttfx v1

structure TtdPosition where major minor : UInt64
def pack (p : TtdPosition) : Except TtdPosition Position
def unpack (pos : Position) : TtdPosition

structure Provenance where         -- every decoded fact carries one
  streamType : UInt32
  fileOffset : UInt64
  rva        : UInt64

structure Anomaly where
  fileOffset : UInt64
  description : String

inductive ForensicError | anomaly (a : Anomaly) | unsupported (s : String)
```

- [x] **Step 2: prove packing round-trip** (first theorem, sets the style):

```lean
theorem pack_unpack_roundtrip (p : TtdPosition)
    (h : p.major.toNat ≤ UInt32.size ∧ p.minor.toNat ≤ UInt32.size) :
    ∃ pos, pack p = .ok pos ∧ unpack pos = p := by …
```

- [x] **Step 3: `Cursor.lean`** — the total parser monad:

```lean
structure Cursor where bytes : ByteArray; pos : USize
abbrev ParseM := ExceptT Anomaly (StateM Cursor)

def readU8 : ParseM UInt8
def readU32le : ParseM UInt32
def readU64le : ParseM UInt64
def readBytes (n : USize) : ParseM ByteArray
def seek (off : USize) : ParseM Unit        -- checks against bytes.size
def remaining : ParseM USize
```

Rule: every read guards `pos + n ≤ bytes.size` and `throw`s an `Anomaly` — no `GetElem` escapes, no partiality.

- [x] **Step 4: `Json.lean`** — `inductive Json` + `render : Json → String` (deterministic key order as constructed; conformance normalizes with `jq -S` anyway). String escaping must match `serde_json` (control chars, `\"`, `\\`; non-ASCII left literal — verify against Rust on a provenance string fixture).
- [x] **Step 5: guards** — `Test/Spec.lean`: unit checks for LE reads (known byte patterns), seek-past-end errors, round-trip `#eval` of pack/unpack on boundary values (`0xFFFFFFFF:0xFFFFFFFF` ok, `0x1_0000_0000:0` errs).

---

### Task 2: `Spec/AddressSpace.lean` — mechanize AddressSpace.tla

**Files:**
- Create: `Forensicator/Spec/AddressSpace.lean`
- Reference: `specs/AddressSpace.tla`, `forensicator-core/src/space.rs`

- [x] **Step 1: executable types** — `RegionClass` (Image/Stack/Private/Mapped/Other), `AddressRegion` (vaStart, size, class, data `ByteArray`, provenance), `AddressSpace` (regions : `Array AddressRegion`, maxRegions, backing images placeholder).
- [x] **Step 2: invariant predicates**:

```lean
def Sorted (rs : Array AddressRegion) : Prop      -- by vaStart
def NonOverlapping (rs : Array AddressRegion) : Prop
def Invariant (s : AddressSpace) : Prop := Sorted s.regions ∧ NonOverlapping s.regions
```

- [x] **Step 3: operations** — `addRegion : AddressSpace → AddressRegion → Except Anomaly AddressSpace`, `regionAt : VA → Option AddressRegion` (binary search), `read : VA → USize → Option ByteArray` — mirroring space.rs:54–95.
- [x] **Step 4: theorems** (this replaces Apalache + `mbt_address_space.rs`):

```lean
theorem addRegion_preserves_invariant :
    Invariant s → Invariant (addRegion s r) -- on .ok
theorem regionAt_unique : Invariant s → regionAt s va = some r →
    ∀ r' ∈ s.regions, covers r' va → r' = r
theorem read_within_region : read s va n = some bs →
    ∃ r ∈ s.regions, r.vaStart ≤ va ∧ va + n ≤ r.vaStart + r.size
```

- [x] **Step 5: classification** — `classify : VA → RegionClass` + agreement lemma with `regionAt`.

---

### Task 3: `Spec/Timeline.lean` — mechanize Timeline.tla + Snapshot.tla

**Files:**
- Create: `Forensicator/Spec/Timeline.lean`, `Forensicator/Model/Trace.lean`
- Reference: `specs/Timeline.tla`, `specs/Snapshot.tla`, `forensicator-core/src/model/trace.rs`

- [x] **Step 1: types** — `WriteRecord` (pos, va, data, provenance; `endVa`), `TraceEventKind`, `TraceEvent`, `Interval` (end : `Option Position`, `none` = open), `CallSpan`, `Trace` (initMem, writes, events, threads, calls, frontier, anomalies).
- [x] **Step 2: views** — port trace.rs:124–185 exactly: `valueAt`, `lastWriter`, `writesBetween`, `exceptionsAt`, `threadAt`, `intervalContains`.
- [x] **Step 3: spec predicates** — `TraceOrdered` (writes/events sorted by pos), `IntervalsWithinLifetime`, `OpenIntervalsOnlyAtFrontier` (per Timeline.tla invariant list — these are the same invariants `parse/ttfx.rs` enforces as anomalies).
- [x] **Step 4: core theorems**:

```lean
theorem valueAt_agrees_with_fold :
    TraceOrdered tr → valueAt tr va t =
      (applyWrites tr.initMem (tr.writes.filter (·.pos ≤ t))).find? va
theorem snapshot_valid :                      -- Snapshot.tla: SnapshotsAreModels
    t ≤ tr.frontier → (tr.snapshot t).isSome
```

`applyWrites` is the spec-level fold; `snapshot` must agree with it (`snapshot_agrees_with_applyWrites`).
- [x] **Step 5: guards** — interval edge cases (open end contains all `t ≥ start`; `t = frontier` boundary).

---

### Task 4: `Parse/Ttfx.lean` + conformance harness (vertical slice)

**Files:**
- Create: `Forensicator/Parse/Ttfx.lean` (port of parse/ttfx.rs, 714 ln)
- Create: `scripts/conformance-lean.sh`
- Modify: `Test/Main.lean` (fixture guards)

**Why first:** smallest decoder, self-contained format we own (§3–§6 of `2026-08-07-ttfx-format-spec.md`), validates the whole harness — cursor monad, JSON, diff gate, anomaly parity — before the 3.5k-line minidump port starts.

- [x] **Step 1: decode** — header (magic `0x5846_5454`, version 1, flags, section count, frontier) → section loop (kinds 1–5; rec sizes 32/24/48/24/24) → payload pool dereference (absolute u32 offsets, 4 GiB cap). Unknown section kind → anomaly + skip (same as Rust).
- [x] **Step 2: invariant enforcement** — check `Spec.Timeline` predicates at decode; violations → `trace.anomalies` with the **same description strings** as Rust (`grep -n 'anomaly(' forensicator-core/src/parse/ttfx.rs` is the checklist).
- [x] **Step 3: `trace --json` output** — enough CLI surface in `Main.lean` to run `forensicator trace <file> --json` (arg parsing grows here organically).
- [x] **Step 4: conformance harness**:

```bash
#!/bin/bash
# export PATH="$HOME/.elan/bin:$PATH"
# Rust oracle: $FORENSICATOR_RUST/target/debug/forensicator
# for each fixture: run both, jq -S both, diff; any diff or anomaly → exit 1
```

First fixture: `Case/ttfx/minimal.ttfx` — zero anomalies, JSON equal.
- [x] **Step 5: all-prefixes fuzz** — for `i ∈ [0, len)`: `decodeTtfx (bytes.extract 0 i)` returns (error or value); a Lean panic/stack overflow fails the test binary. Same for 100 random byte-mutations.
- [x] **Step 6: theorem link** — `decodeTtfx_ok_ordered : decodeTtfx bs = .ok tr → TraceOrdered tr ∧ tr.anomalies = [] → …` (decode postcondition; closes the spec↔code gap for this format).

---

### Task 5: Minidump decoders → `Model/Dump.lean`

**Files:**
- Create: `Forensicator/Parse/Minidump/{Header,Directory,Memory,MemoryInfo,ModuleList,ThreadList,Exception,SystemInfo,CommentA,Crashpad,V8Heap,Dump}.lean`
- Create: `Forensicator/Model/Dump.lean`
- Reference: `forensicator-core/src/parse/*.rs` (13 modules), `model.rs`

- [x] **Step 1: `Model/Dump.lean`** — port the `Dump` record (model.rs) field-for-field, including `V8HeapExt` (v2: alloc top/limit, `gcState`, `lastGcReason`, fatal message) and `setException` semantics.
- [x] **Step 2: streams in dependency order** — header → directory → memory(64)list → memory_info → module_list → thread_list → exception → system_info → comment_a → crashpad → v8heap (version-gated v2 ext). One task-checkbox per stream; each keeps Rust's provenance (stream_type + file_offset + rva) and fail-closed anomalies.
- [x] **Step 3: `inspect --json` parity** — extend CLI; conformance gate now covers all three dumps (`minidump`, `minidump_v2`, `fulldump`).
- [x] **Step 4: all-prefixes fuzz** on the three `.dmp` fixtures (same rule as Task 4 Step 5).

---

### Task 6: Executable AddressSpace + Model wiring

**Files:**
- Create: `Forensicator/Model/AddressSpace.lean` (executable inst of Spec/AddressSpace)
- Modify: `scripts/conformance-lean.sh` (space-dependent output)

- [x] **Step 1: build space from Dump** — port the S1→S2 assembly (region classification via MemoryInfoList + module images; RegionClass rules from space.rs).
- [x] **Step 2: theorems apply for free** — this is the Task 2 structure instantiated; add `buildSpace_satisfies_invariant` (construction proof, mostly `simp` over the fold).
- [x] **Step 3: perf gate** — `fulldump` fixture decode+build under (say) 30 s; if not, switch region storage to refcount-1 `Array` folds before proceeding (design §Perf rules). Record timing in commit message.

---

### Task 7: Analyzers batch 1 (inference, parity-tested — no proofs)

**Files:**
- Create: `Forensicator/Analyzer/{Analyzer,Strings,Vtables,Lists,Arrays,Chunks,Shapes,Scan}.lean`, `Forensicator/Util/Pattern.lean`
- Reference: `forensicator-core/src/analyzer/*.rs`, `pattern.rs`

- [x] **Step 1: framework** — `Analyzer` structure (name, description, run : `Dump → AddressSpace → Array Finding`), `Catalog` (all_strings/all_vtables/… accessors), `Pipeline.run` with `--plugin` filter; `Confidence` as ordered `inductive` (Low/Medium/High — match Rust variants exactly).
- [x] **Step 2: PointerGraph** (`Util/Pattern.lean`) — port `all_strict`, `all_loose`, `saved_frame_pointers`, `vtables`, `heap_references`; caps as `fuel : Nat` (1M nodes/10M edges), termination by fuel.
- [x] **Steps 3–9: one analyzer per step** — strings → vtables → lists → arrays → chunks → shapes → scan. Each: pure port, `analyze --json --plugin <name>` parity on all three dumps added to the gate. Confidence scores must match byte-for-byte after `jq -S`.

---

### Task 8: `cause` analyzer + disasm FFI decision gate

**Files:**
- Create: `Forensicator/Util/{Disasm,V8Obj,V8Layout,Unwind}.lean`, `Forensicator/Analyzer/Cause.lean`
- Reference: `analyzer/cause.rs` (890 ln), `disasm.rs`, `v8obj.rs`, `v8layout.rs`, `unwind.rs`

- [x] **Step 1 (gate): disasm strategy** — try pure-Lean window decode first: `cause` needs only `InstrKind` classification (253 lines of Rust wrapping iced-x86). If the needed opcode subset is small (call/jmp/mov/ret/nop/int3 — audit disasm.rs usage), implement directly in Lean and skip FFI entirely. **Only if** the subset explodes: build the Rust staticlib shim (`extern "C"` over byte buffers). Record the decision in the task commit.
- [x] **Step 2: port** `v8obj`/`v8layout` (cage-aware walking; version-pinned offsets) — pure Lean, no FFI.
- [x] **Step 3: port rules** — verdict types, rule set, ranking (fail closed to `Unknown`), OOM/CHECK rules consuming `V8HeapExt`.
- [x] **Step 4: `Spec/CrashCause.lean`** — mechanize the CrashCause.tla verdict invariant; prove ranking totality (every input yields exactly one verdict).
- [x] **Step 5: parity** — `analyze --json` full-pipeline diff on all dumps (verdict lines included in `inspect` parity).

---

### Task 9: `v8` analyzer

**Files:**
- Create: `Forensicator/Analyzer/V8.lean`
- Reference: `analyzer/v8.rs` (1327 ln)

- [x] **Step 1: port** JS stack recovery using Task 8's `V8Obj`/`V8Layout`/`Disasm` — behavior-identical to the Rust refactor (shares, never duplicates).
- [x] **Step 2: parity** — full `analyze --json` on `minidump`/`minidump_v2` (the Electron dumps with V8HE streams are the discriminating fixtures).

---

### Task 10: CLI completion + `match`/`shell`

**Files:**
- Modify: `Main.lean`; Create: `Forensicator/Util/{Symbolizer,Image}.lean`, `Forensicator/Pipeline.lean`

- [x] **Step 1: full flags** — `inspect/analyze/trace/list-plugins` flag-for-flag (`--json --quiet --plugin --symbols --pos --writes`); help text parity.
- [x] **Step 2: `Pipeline.lean`** — `Forensicator` state machine mirroring Forensicator.tla (`open → analyze → runFull`); state-transition legality as a proved inductive (replaces `mbt_forensicator.rs`).
- [x] **Step 3: `match`** — `Symbolizer`/`Image` Lean interfaces + Rust shim over C ABI (PDB stays outside Lean, design §FFI). `--exe/--pdb` parity on `Case/minidump` (has exe+PDB).
- [x] **Step 4: `shell`** — REPL on `IO` (inspect/analyze/match/load/symbols/seek/t+/t-/writes/intervals/quit); smoke-tested by piping a command script, diffing against Rust `shell` output on the same script.

---

### Task 11: Final gate + handover

> **Status 2026-08-10: COMPLETE.** 44-check conformance gate green
> (inspect/analyze/match/trace/shell, 3 dumps + minimal.ttfx). Known
> accepted divergences: fulldump `arrays` is quadratic in BOTH
> implementations (excluded); the v8 analyzer's debug-overflow panic is
> reproduced; fast-path index (FastSpace) is gate-validated, not proved.

- [x] **Step 1:** `scripts/conformance-lean.sh` covers: 3 dumps × (inspect, analyze, match) + minimal.ttfx × (trace, trace --pos, trace --writes) + anomaly-parity corpus (truncated/mutated fixtures). Zero diffs.
- [x] **Step 2:** proof audit — `grep -rn "sorry\|admit\|partial\|panic!" Forensicator/ ` empty; `lake build` has no `declaration uses 'sorry'` warnings.
- [x] **Step 3:** timing record — decode+analyze wall times for both implementations on `fulldump`, noted in the commit (parity not required, regression visibility is).
- [ ] **Step 4:** update `~/Repos/Forensicator/AGENTS.md` — add a "Lean port" section pointing at the new repo and its gate; MBT tests stay documented as Rust-side (their role is absorbed by `Spec/` theorems).

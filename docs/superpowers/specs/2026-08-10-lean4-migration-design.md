# Lean 4 Migration — Design Spec

## Status
Draft, pending review.

## Summary
Port Forensicator (12k lines Rust, `forensicator-core` + `forensicator-cli`) to a standalone Lean 4 package at `~/Repos/Forensicator_Lean/` (leanprover/lean4:**v4.33.0**, via elan). The existing TLA+ specs (`specs/*.tla`, Apalache-checked) become **Lean definitions + proved theorems**; the Rust pipeline becomes **executable Lean** compiled to native code. During migration the Rust repo is the **golden oracle**: every phase is gated on byte-level/JSON parity against the existing CLI over the `Case/` fixtures.

One package does both jobs because Lean 4 is simultaneously the proof language and a practical compiled language (`IO`, `ByteArray`, `UInt64`, mutable-in-refs arrays). No FFI split for the core; FFI is reserved for two leaf dependencies (disassembly, PDB).

## Motivation

The repo's correctness story today is: TLA+ specs model-check *bounded* state spaces (Apalache, depth ~10), and `mbt_*.rs` tests replay model traces against Rust. Two gaps:

1. **Boundedness** — AddressSpace disjointness, Timeline snapshot validity, TraceOrdered etc. are verified only up to small constants. A Lean proof is unbounded: it covers 10M-edge pointer graphs and 512 MiB initmem closures by construction.
2. **Spec↔code distance** — TLA+ invariants are *checked against* Rust indirectly (MBT harness, `mirrorrust`). In Lean the invariant predicates and the executable code share types; the proof *is about* the shipping function, not a model of it.

A secondary benefit: the parse layer's fail-closed contract ("malformed input → anomalies, never panic") becomes a *type-level* property — the decoder is written in a total `Except`-returning style with no partial functions, which Lean's compiler enforces.

## Non-goals

- **Proving the heuristic analyzers** (`strings`, `vtables`, `lists`, `arrays`, `chunks`, `shapes`, `v8`, `cause`). They are confidence-scored inference, not theorems. They are ported as pure functions and *parity-tested*, not verified.
- **Native Lean reimplementation of iced-x86 or PDB.** `disasm` and `symbolizer` sit behind Lean interfaces with Rust/C shims initially (§ FFI boundary).
- **Changing the `.ttfx` wire format or any TLA+ spec semantics.** The specs are the contract; the Lean `Spec/` modules are their mechanization. TTFX extractor repo (`D:\Codebase\TTFX`) is untouched.
- **Performance parity.** Lean output must be correct; it need not match Rust wall-clock. (Multi-MB dumps are still fine — see Parser/perf rules.)
- **Deleting the Rust repo.** It remains the oracle until the plan's final task; MBT tests stay there.

## Toolchain

- `lean-toolchain`: `leanprover/lean4:v4.33.0` (installed; elan default `stable` resolves to it).
- **No dependencies.** No mathlib, no batteries. The domain needs `UInt8/32/64`, `ByteArray`, `Array`, sorting, and finite maps — all in the v4.33 core/`Std` namespace. Heavy deps would dominate build time and upgrade churn for zero theorem power we use.
- Build: `lake build`; test: `lake exe forensicator-test` plus `#eval` guards compiled into a `Test/` lib (no test-framework dep; a failing guard fails the build via `example ... := by native_decide` where decidable, or an IO runner asserting and exiting non-zero).

## Repository layout

```
~/Repos/Forensicator_Lean/
├── lean-toolchain                  # leanprover/lean4:v4.33.0
├── lakefile.toml                   # package Forensicator; lib + 2 exe targets
├── Forensicator.lean               # lib root (re-exports)
├── Forensicator/
│   ├── Spec/                       # mechanized specs (was specs/*.tla)
│   │   ├── AddressSpace.lean       # Sorted/NonOverlapping predicates + proofs
│   │   ├── Timeline.lean           # views + snapshot theorems (Timeline.tla/Snapshot.tla)
│   │   ├── Arch.lean               # Arch.tla
│   │   ├── Model.lean              # Model.tla invariant as a Lean predicate
│   │   ├── CrashCause.lean         # verdict invariant (CrashCause.tla)
│   │   └── PointerGraph.lean       # caps as fuel; structural lemmas only
│   ├── Basic.lean                  # Position, VA, Provenance, Anomaly, ForensicError
│   ├── Parse/
│   │   ├── Cursor.lean             # ParseM: ExceptT Anomaly (StateM Cursor) — total
│   │   ├── Ttfx.lean               # parse/ttfx.rs port (first: validates harness)
│   │   ├── Minidump/
│   │   │   ├── Header.lean Directory.lean Memory.lean MemoryInfo.lean
│   │   │   ├── ModuleList.lean ThreadList.lean Exception.lean SystemInfo.lean
│   │   │   ├── CommentA.lean Crashpad.lean V8Heap.lean   # V8HE incl. v2 ext
│   │   │   └── Dump.lean                                 # assembly → Model.Dump
│   ├── Model/
│   │   ├── Dump.lean               # Dump, MemoryRegion, ExceptionInfo, V8HeapExt…
│   │   ├── AddressSpace.lean       # executable space (specs link here)
│   │   └── Trace.lean              # Trace + views + snapshot
│   ├── Analyzer/
│   │   ├── Analyzer.lean           # Analyzer structure + Pipeline + Catalog
│   │   ├── Strings.lean Vtables.lean Lists.lean Arrays.lean
│   │   ├── Chunks.lean Shapes.lean Scan.lean
│   │   ├── Cause.lean              # needs Disasm/V8Obj shims
│   │   └── V8.lean
│   ├── Util/
│   │   ├── Json.lean               # minimal deterministic emitter (no dep)
│   │   ├── Disasm.lean             # interface + iced-x86 C shim (FFI)
│   │   ├── V8Obj.lean V8Layout.lean
│   │   ├── Unwind.lean Image.lean Symbolizer.lean  # interfaces; Rust shim
│   │   └── Pattern.lean            # PointerGraph (fuel-bounded)
│   └── Pipeline.lean               # Forensicator state machine (Forensicator.tla)
├── Main.lean                       # exe `forensicator`: CLI parity
├── Test/
│   ├── Main.lean                   # exe `forensicator-test`: IO guard runner
│   ├── Spec.lean                   # unit checks + all-prefixes fuzz
│   └── Conformance.lean            # fixture decode guards
└── scripts/
    └── conformance-lean.sh         # Rust-vs-Lean JSON diff gate
```

## Rust → Lean mapping rules

| Rust | Lean 4 | Notes |
|---|---|---|
| `Result<T, Anomaly>` | `Except Anomaly α` | fail-closed preserved |
| `&[u8]` + manual offsets | `ByteArray` + `ParseM` cursor | all reads bounds-**checked** (return error), never `GetElem` partiality |
| `u64` VA / `Position` | `UInt64` (`abbrev Position := UInt64`) | wrap semantics explicit via `UInt64.add` etc. |
| struct + provenance | `structure` + field | unchanged shape |
| `trait Analyzer` | `structure Analyzer` with method fields; registry = `Array Analyzer` | no typeclass needed |
| `Option<Position>` open interval | `Option Position` | `none` ≡ TLA `-1` ≡ `OPEN_END` |
| caps (`max_nodes`, fuel) | `Nat` fuel parameter + `partial` nowhere | termination by fuel, provably |
| `impl Iterator` | `Array`/`List` materialization | analyzers are batch, not streaming |

**Perf rules** (multi-MB inputs): `ByteArray`/`Array` only, never `List`, in hot paths; single-threaded `fold` over arrays keeps refcount 1 → in-place updates; no string building in loops.

## Spec → theorem mapping (the point of the migration)

Each TLA+ invariant gets a Lean theorem about the *executable* function:

| TLA+ | Lean theorem (statement shape) |
|---|---|
| `AddressSpace.tla` inv | `add_region_preserves_invariant : Invariant s → Invariant (addRegion s r)` for `Invariant = Sorted ∧ NonOverlapping`; `region_at_unique`, `read_within_region` |
| `Timeline.tla` `TraceOrdered` | decode postcondition: `decodeTtfx ok → OrderedBy (·≤·) trace.writes` |
| `Timeline.tla` views | `value_at_agrees_with_fold`: `valueAt va t = fold writes≤t over initMem` |
| `Snapshot.tla` `SnapshotsAreModels` | `snapshot_valid : ∀ t ≤ frontier, (snapshot t).isSome ∧ Model.Invariant (snapshot t).dump` |
| position packing (D3) | `pack_unpack_roundtrip : unpack (pack p) = p` when halves ≤ u32 |
| `Arch.tla`, `Model.tla`, `CrashCause.tla` | same pattern: invariant predicates + preservation theorems |
| parser safety (implicit in Rust) | totality: no `sorry`, no `partial`, no `panic!` anywhere in `Parse/` — enforced by the kernel + CI grep |

`PointerGraph` gets structural lemmas only; its 1M/10M caps become fuel.

## Verification strategy — Rust as golden oracle

Every executable phase is gated on **output equality with the Rust CLI**, not on tests written from scratch:

1. **JSON parity**: `scripts/conformance-lean.sh` runs both binaries over every `Case/` fixture —
   - `Case/minidump/*.dmp`, `Case/minidump_v2/*.dmp`, `Case/fulldump/*.dmp` → `inspect --json`, `analyze --json`
   - `Case/ttfx/minimal.ttfx` → `trace --json` (must report **zero anomalies**)
   Outputs normalized through `jq -S` (key-sort) before `diff`, so field order is free but values must match exactly, including confidence scores and provenance offsets.
2. **All-prefixes fuzz** (Lean-side, `Test/Spec.lean`): for every prefix of every fixture, decoders must *return* (error or value) — never stack overflow / kernel `panic`. Runs as an IO guard in `forensicator-test`.
3. **Anomaly parity**: malformed variants (truncated section table, bad magic, unknown stream) must produce the same anomaly *descriptions* as Rust. This pins the fail-closed contract.

Fixtures are referenced via `FORENSICATOR_CASE_DIR` (default `../Forensicator/Case`) — not copied into the Lean repo.

## Parser design (`Parse/Cursor.lean`)

```lean
structure Cursor where
  bytes : ByteArray
  pos   : USize
deriving Inhabited

abbrev ParseM := ExceptT Anomaly (StateM Cursor)

def readU32le : ParseM UInt32          -- bounds-checked LE reads
def readU64le : ParseM UInt64
def readBytes (n : USize) : ParseM ByteArray
def seek (off : USize) : ParseM Unit   -- every seek checked against size
def withProvenance (stream : UInt32) (p : ParseM α) : ParseM (α × Provenance)
```

- **Totality**: all partiality lives in `Except`; no `GetElem` proof obligations escape because every index is guarded by an explicit `size` check returning `throw`.
- **Truncation-tolerant**: section decoders catch per-section errors into `anomalies` exactly where `parse/ttfx.rs` does (decode_ttfx, forensicator-core/src/parse/ttfx.rs:79).
- **Provenance** (stream_type + file_offset + rva) is threaded by the monad, matching `Provenance` in model.rs.

## CLI parity surface

`inspect`, `analyze`, `match`, `list-plugins`, `trace`, `shell` — same flags (`--json`, `--quiet`, `--plugin`, `--symbols`, `--exe`, `--pdb`, `--pos`, `--writes`). `match`/`shell` land last; until then they exit with a distinct "not yet implemented" code (fail closed, never silently wrong). Hand-rolled arg parsing (~150 lines; no clap equivalent exists and none is needed).

## FFI boundary

Two leaf capabilities stay outside Lean initially:

- **Disassembly** (`disasm.rs`, iced-x86): Lean `Util/Disasm.lean` defines `InstrKind` + `classifyWindow : ByteArray → VA → Array Instr`; implementation is a C shim calling a tiny Rust staticlib built from the existing crate. `cause` consumes only the interface.
- **PDB symbolizer + on-disk image backing** (`symbolizer.rs`, `image.rs`): same pattern — Lean interface, Rust shim. Required only for `match` and `--symbols`.

Everything else is pure Lean. The shims are linked only into the exe, keeping the lib kernel-checkable.

## Risks

| Risk | Mitigation |
|---|---|
| Proof effort sprawls into analyzers | Hard rule: proofs live in `Spec/` + `Parse/` boundary only; analyzers are parity-tested |
| Lean array perf on 100+ MB dumps | ByteArray + refcount-1 folds; profile with the `fulldump` fixture in Task 6 before proceeding |
| JSON drift (float formatting, field sets) | `jq -S` normalization; conformance gate blocks merge per task |
| v4.33 API churn on upgrade | toolchain pinned; upgrade is its own explicit task, never drive-by |
| Shim ABI pain (iced-x86) | shim speaks C ABI over byte buffers; no Lean/Rust type sharing across FFI |

## Sizing

~12k Rust lines → est. 8–10k Lean lines (proofs add ~15%). Phase order in the plan is chosen so the *harness* is validated on the smallest decoder (`.ttfx`, 714 lines) before the minidump decoders (3.5k lines) start.

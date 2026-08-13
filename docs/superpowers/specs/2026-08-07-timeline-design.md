# Timeline (TTD Trace Model) — Design Spec

> **Lean-port note (2026-08-13):** Rust-era document — the implementation is
> now the Lean 4 tree (`Forensicator/`, `Main.lean`, `Test/`; module map in
> `docs/arch/README.md`). Rust references below (`forensicator-core/src/…`,
> `cargo`, `tests/mbt_*`) are historical and kept as written for the record.

## Status
Draft, pending review.

## Summary
Implement `specs/Timeline.tla` in forensicator-core: a **`Trace` model** (initial memory + append-only write/event logs + thread/call intervals), a **versioned `.ttfx` wire format** to carry traces between hosts, and a **`Snapshot` materializer** that turns any position into the existing `(Dump, AddressSpace)` pair so the current analyzer pipeline runs unchanged at any point in time.

This does **not** parse Microsoft's proprietary `.run` container. The `.run` file stays behind the TTDReplay engine; a Windows-side extractor (separate component, separate design) emits `.ttfx`. `Timeline.tla` is the formal contract for everything on our side of that boundary — the extractor's output must satisfy its invariants, and the core decoder enforces them (fail-closed, as usual).

## Motivation

Post-mortem minidump analysis answers *what state was the process in when it crashed*. The recurring failure of that model in our Electron/WebGL investigations: the interesting question is *who wrote this pointer earlier* — the corruption happens minutes before the crash. WinDbg TTD answers it but is interactive-only, UI-capped, and cannot run our analyzers. Modeling the observable TTD structure (positions, write log, intervals, cursor) lets Forensicator:

1. run the **existing 8 analyzers at any recorded position** (`snapshot(t)` → `Pipeline::run`), and
2. answer queries no single snapshot can: `writes_between(va, t1, t2)` (pointer-corruption provenance), verdict timelines (`ExceptionsAt` → `cause` per position), per-position stack recovery (`v8` at t).

`Timeline.tla` (committed, Apalache-verified to depth 10) already pins the semantics; this design is its Rust realization. The follow-up `Snapshot.tla` (Apalache-verified, `--features=no-rows`) formalizes the link to `Model.tla`: `EXTENDS Timeline`, an explicit re-indexing operator `ModelAt(t)` mapping each timeline position to a Model-shaped state, and an `INSTANCE Model WITH ModelAt(cursor).f` anchor — checked properties: `SnapshotValid` (real `M!ModelInvariant` at the cursor), `SnapshotsAreModels` (`∀ t ≤ frontier`), `LinkAtCursor` (restatement ≡ real invariant). Together: `Trace::snapshot(t)` yields a valid `Dump` at every recorded position.

## Non-goals

- Parsing `.run` files (proprietary; Windows-only engine). Extractor is a separate design.
- Live debugging, breakpoints, single-stepping semantics.
- Register files per position (Timeline.tla omits them deliberately; v2 candidate).
- The `TemporalAnalyzer` trait (cross-position reasoning) — deferred to a follow-up once `Trace` consumers exist.

## Architecture

```
[Windows]  trace.run ──TTTDReplay SDK──► extractor.exe ──► trace.ttfx ──scp──►
                                                                                │
[analysis host]              ┌─────────────────────────────▼───────────────────┐
                             │ parse/ttfx.rs (hand-written, like parse/v8heap) │
                             │   header → sections → Trace + anomalies         │
                             │   validates Timeline.tla invariants at decode   │
                             └─────────────────────────────┬───────────────────┘
                                                           │ model::trace::Trace
                              ┌────────────────────────────┼──────────────────┐
                              │                            │                  │
                    value_at / last_writer /      snapshot(t) ──► Snapshot { dump,
                    writes_between / exceptions_at  (materialize)    space, pos }
                              │                            │                  │
                     session commands           Forensicator::analyze ──► StructureCatalog
                     (seek, t+, t-, writes)     (existing Pipeline, unchanged)
```

Design rules (unchanged from repo conventions):
- **Fail closed**: malformed sections → `Trace.anomalies`, never a panic; `snapshot(t > frontier)` → `None`.
- **Hand-written parser**, no external parse crate; truncation-tolerant, provenance on every decoded fact.
- **`Analyzer` trait untouched**: analyzers keep consuming `(&Dump, &AddressSpace)`. Time enters only through *which* snapshot they see.
- **Spec↔code 1:1**: every `Timeline.tla` variable/invariant has a named Rust counterpart (table below).

## Data model (`forensicator-core/src/model/trace.rs`, new)

```rust
pub type Position = u64;                    // TTD Major:Minor packed: (major << 32) | minor

pub struct WriteRecord {                    // Timeline.tla: (wr_pos[i], wr_addr[i], wr_val[i])
    pub pos: Position,
    pub va: u64,                            // start address of the written range
    pub data: Vec<u8>,                      // bytes written (spec abstracts to one cell)
    pub provenance: Provenance,             // section offset in the .ttfx file
}

pub enum TraceEventKind { Exception, ModuleLoad, ModuleUnload }   // EventKinds
pub struct TraceEvent {
    pub pos: Position,
    pub kind: TraceEventKind,
    pub payload: EventPayload,              // Exception{code, address, thread_id} |
                                            // Module{name, base_va, size} | Unload{base_va}
    pub provenance: Provenance,
}

pub struct Interval { pub start: Position, pub end: Option<Position> }  // None = spec's -1
pub struct CallSpan { pub interval: Interval, pub thread: u32 }

pub struct Trace {
    pub init_mem: Vec<MemoryRegion>,        // contents at position 0 (spec: init_mem)
    pub writes: Vec<WriteRecord>,           // append-only, position-ordered (checked)
    pub events: Vec<TraceEvent>,
    pub threads: Vec<(u32, Interval)>,      // thread id + lifetime
    pub calls: Vec<CallSpan>,
    pub frontier: Position,                 // record head
    pub anomalies: Vec<Anomaly>,
}
```

Note the one deliberate generalization over the spec: the spec's write log stores single cells (`wr_addr/wr_val`); the Rust model stores **byte ranges** (`va` + `data`) — real TTD memory accesses are 1–16 bytes, and ranges keep the log compact. `value_at` reduces to the spec's definition (last overlapping write wins, byte-wise).

### Views (pure functions on `&Trace`)

```rust
impl Trace {
    /// LastWriter(a, t): index of the last write covering va at or before t.
    pub fn last_writer(&self, va: u64, t: Position) -> Option<usize>;
    /// ValueAt(a, t): byte at va at position t (init_mem if never written).
    pub fn value_at(&self, va: u64, t: Position) -> Option<u8>;
    /// WritesBetween(a, t1, t2): all writes overlapping [va, va+len) in (t1, t2].
    pub fn writes_between(&self, va: u64, len: u64, t1: Position, t2: Position)
        -> Vec<&WriteRecord>;
    /// ExceptionsAt(t).
    pub fn exceptions_at(&self, t: Position) -> Vec<&TraceEvent>;
    /// Materialize position t as a time-point snapshot. None if t > frontier
    /// (CursorBounded, fail-closed).
    pub fn snapshot(&self, t: Position) -> Option<Snapshot>;
}

pub struct Snapshot {
    pub dump: Dump,          // memory regions = init_mem overlaid with writes ≤ t;
                             // exception = last ExceptionsAt(t); modules = loads − unloads ≤ t
    pub space: AddressSpace, // Forensicator::build_address_space(&dump)
    pub pos: Position,
}
```

Lookup performance: `writes` kept position-sorted (parse-enforced), so `last_writer`/`value_at` are binary search + backward scan; an optional per-region write index can be added if profiling on real traces demands it — the model API doesn't change.

## Wire format (`parse/ttfx.rs`, new)

```
TTFX header (32 bytes, little-endian):
  magic       "TTFX"            (4)
  version     u32 = 1
  flags       u32               (bit 0: has_init_mem)
  section_cnt u32
  frontier    u64               (record head; CursorBounded enforced against it)
  reserved    12 bytes

section header (16 bytes):
  kind        u32   (1=INITMEM 2=WRITES 3=EVENTS 4=THREADS 5=CALLS)
  record_size u32
  record_cnt  u64

records: fixed-size per section kind, tightly packed.
  INITMEM:  va u64, size u64, prot u32, state u32, rva u32 (into byte pool)
  WRITES:   pos u64, va u64, len u32, rva u32 (bytes in pool)
  EVENTS:   pos u64, kind u32, code u32, address u64, thread_id u32, pad u32
  THREADS:  thread_id u32, pad u32, start u64, end u64 (u64::MAX = open)
  CALLS:    thread_id u32, pad u32, start u64, end u64
byte pool:  concatenated region/write payloads, referenced by rva
```

Rationale: fixed-size records = O(1) skip, truncation detection by `record_cnt` vs remaining bytes, and a `memory(64)`-style byte pool so large `init_mem` regions don't inflate record size. Same wire discipline as V8HE (`parse/v8heap.rs`): versioned, additive, truncation-tolerant, every section offset becomes `Provenance`.

Decode-time validation (spec invariants as parse errors/anomalies):
- `wr_pos` non-decreasing, all `pos ≤ frontier` → else anomaly `trace_unordered` (**TraceOrdered**)
- per-thread call spans disjoint-or-nested → else anomaly `call_crossing` (**CallNesting**)
- calls within their thread's lifetime → anomaly `call_outside_thread` (**CallsWithinThreads**)
- thread `start ≤ end` → anomaly `bad_interval` (**ThreadIntervals**)

Anomalies degrade, never abort: sections after the first anomaly are still attempted.

## Spec ↔ code mapping

| Timeline.tla | Rust |
|---|---|
| `init_mem`, `wr_pos/wr_addr/wr_val`, `ev_pos/ev_kind` | `Trace.init_mem/writes/events` |
| `threads`, `calls` (`end = -1`) | `Interval { end: Option<Position> }` |
| `frontier`, `cursor` | `Trace.frontier`; cursor lives in the **session** (below), not in `Trace` |
| `LastWriter`, `ValueAt`, `WritesBetween`, `ExceptionsAt` | `Trace::last_writer/value_at/writes_between/exceptions_at` |
| `TraceOrdered`, `CallNesting`, `CallsWithinThreads`, `ThreadIntervals` | parse-time validation → `Trace.anomalies` |
| `CursorBounded` | `snapshot(t)` returns `None` for `t > frontier`; session never moves cursor out of range |
| `SnapshotConsistent` | property test: `value_at` vs brute-force fold over writes (below) |

## CLI / session integration

The interactive shell (just landed) is the natural cursor owner — matching WinDbg's `!tt`:

```
forensicator[trace]> load trace.ttfx
forensicator[trace @ 3/4]> threads
forensicator[trace @ 3/4]> seek 0x1A3F00000012        # Seek
forensicator[trace @ …]> t+ / t-                     # Advance / Retreat
forensicator[trace @ …]> writes 0x1BE15FC0F0 8       # writes_between(va, len, 0, cursor)
forensicator[trace @ …]> analyze --plugin cause      # pipeline at cursor snapshot
forensicator[trace @ …]> inspect                     # snapshot's Dump
```

`Session` gains `trace: Option<Trace>` + `cursor: Position` (CursorBounded enforced in `seek`/`t+`/`t-`). When a trace is loaded, `analyze`/`inspect` operate on `trace.snapshot(cursor)` instead of a dump file; `load <file>` dispatches on extension/magic (`.dmp` vs `TTFX`). One-shot CLI gains `trace <file.ttfx> [--pos <p>] [--writes <va> <len>]` as a non-interactive front-end over the same code.

## Testing

- **Unit** (`model::trace::tests`, `parse::ttfx::tests`): synthetic `Trace` builders mirroring `V8HeapBuilder`; round-trip writer→reader; truncation at every section boundary; each anomaly path.
- **Property** (`SnapshotConsistent`, proptest-free like the rest of the repo — deterministic table of random-seeded cases): for all `(va, t)` in a generated trace, `value_at(va, t)` == fold of init_mem + writes ≤ t computed naively. Also `CallNesting`/`CallsWithinThreads` hold for every generated well-formed trace and are *rejected* for mutated ones.
- **MBT stub** (`tests/mbt_timeline.rs`): auto-skipping mirrorrust harness, `Timeline.tla` actions ↔ `Trace` mutators, activated when `MIRROR_BIN`/`APALACHE_MC` are set — same pattern as `mbt_crash_cause.rs`.
- **Golden fixture**: a tiny hand-assembled `trace.ttfx` (2 regions, 4 writes, 2 threads, 2 calls, 1 exception) committed under `Case/ttfx/`; session smoke test in CLI tests.

## Module layout

```
forensicator-core/src/
  model.rs              → pub mod trace;  (Trace, WriteRecord, TraceEvent, Interval, CallSpan, Snapshot)
  model/trace.rs        (new, ~350 lines + tests)
  parse.rs              → pub mod ttfx;
  parse/ttfx.rs         (new, ~300 lines + tests)
  pipeline.rs           → S1Output gains trace: Option<Trace> (additive, None everywhere today)
forensicator-cli/src/
  session.rs            → trace/cursor state + seek/t+/t-/writes commands
  main.rs               → trace subcommand
tests/
  mbt_timeline.rs       (new, auto-skip stub)
Case/ttfx/minimal.ttfx  (new fixture)
specs/Timeline.tla      (unchanged — already committed)
```

## Phases / task checklist

1. `model/trace.rs`: types + views + unit tests; `Snapshot::materialize` reusing `Forensicator::build_address_space`.
2. `.ttfx` writer helper (dev-only, used by tests + future extractor) + `parse/ttfx.rs` reader with invariant validation; golden fixture `Case/ttfx/minimal.ttfx`.
3. Session integration: `load` dispatch on magic, cursor commands, `analyze`/`inspect` over snapshots.
4. One-shot `trace` subcommand; docs (AGENTS.md, README).
5. `mbt_timeline.rs` stub.
6. Follow-up designs (not this one): Windows extractor (TTDReplay → TTFX), `TemporalAnalyzer` trait, per-position register files.

## Open questions

1. **Write-log granularity vs size.** Full store logs from a busy renderer are enormous; expect the extractor to support VA-range filters and a ring window (the LATS argument). The format itself is filter-agnostic — but should the header carry a `filter description` for provenance? Lean: yes, a free-form annotation section (like Crashpad annotations), v1.1.
2. **Position mapping.** TTD positions are `Major:Minor` pairs; packed `u64` loses nothing but ties us to 32/32 split. Confirm against real traces before freezing v1.
3. **Module load/unload at snapshot time**: minidump modules are static; traces aren't. Snapshot builds the module list as loads−unloads ≤ t — but module *bytes* (Image backing) don't exist in `.ttfx`; snapshot's `space` gets `Private` regions only. Symbolization of JIT/native code at position t needs the extractor to also emit module load addresses — flagged for the extractor design.

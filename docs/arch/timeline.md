# Timeline: TTD Trace Support

Spec: `specs/Timeline.tla` (Apalache-verified).
Design: `docs/superpowers/specs/2026-08-07-timeline-design.md`.
Format: `docs/superpowers/specs/2026-08-07-ttfx-format-spec.md` (TTFX v1).
Code: `forensicator-core/src/model/trace.rs`, `forensicator-core/src/parse/ttfx.rs`.

## Why a separate container

Microsoft's `.run` trace format is proprietary and its only reader
(`TTDReplay.dll`) is Windows-only COM. Forensicator never parses `.run`.
Instead a Windows-side **extractor** (`ttfx-extract`, at `D:\Repositories\TTFX`
— design: `docs/superpowers/specs/2026-08-09-ttfx-extractor-design.md`) emits
our own versioned container, and everything downstream is pure Rust,
specifiable, and testable with synthetic fixtures.
`Timeline.tla` is the formal contract the extractor's output must satisfy —
the same capture-side/analysis-side split as the V8HE crash handler.

## Model (`model/trace.rs`) — Timeline.tla realized

```rust
pub struct Trace {
    pub init_mem: Vec<MemoryRegionInfo>,   // contents at position 0
    pub writes: Vec<WriteRecord>,          // (pos, va, data) — append-only, ordered
    pub events: Vec<TraceEvent>,           // Exception / ModuleLoad / ModuleUnload
    pub threads: Vec<(u32, Interval)>,     // lifetimes; end = None while alive
    pub calls: Vec<CallSpan>,              // [start, end) per thread
    pub frontier: Position,                // record head
    pub anomalies: Vec<Anomaly>,
}
```

`Position = u64` packs TTD's `Major:Minor` pair. Spec's `end = -1` ↔ Rust
`Interval.end = None`.

### Views (spec operators → methods)

| Timeline.tla | `Trace` method | Meaning |
|---|---|---|
| `LastWriter(a,t)` | `last_writer(va, t)` | last write covering `va` at/before `t` |
| `ValueAt(a,t)` | `value_at(va, t)` | byte at `va` at `t` (snapshot-faithful: out-of-region writes never mask valid ones) |
| `WritesBetween(a,t1,t2)` | `writes_between(va, len, t1, t2)` | "who wrote this range" |
| `ExceptionsAt(t)` | `exceptions_at(t)` | CrashCause input, time-indexed |
| — | `snapshot(t)` | materialize position into `Snapshot { dump, space, pos }`; `None` for `t > frontier` (CursorBounded) |

`snapshot(t)` builds: memory = init_mem overlaid with writes ≤ t (last write
per byte wins); modules = loads − unloads ≤ t; exception = last exception ≤ t;
then a standard `AddressSpace`. The existing 8 analyzers consume it unchanged.

## Wire format (`.ttfx`, v1)

32-byte header (`TTFX` magic, version, flags, section count, frontier) → fixed
-record sections (`INITMEM`, `WRITES`, `EVENTS`, `THREADS`, `CALLS`) → payload
pool referenced by absolute offsets. Versioned, truncation-tolerant; the full
byte-level reference with a worked fixture dump is
[ttfx-format.md](ttfx-format.md). Reader and writer are both in
`parse/ttfx.rs` (writer serves tests/fixtures and the future extractor).

## Invariants as decode-time validation

| Timeline.tla invariant | decode_ttfx behavior |
|---|---|
| `TraceOrdered` | non-decreasing positions, `pos ≤ frontier` → anomalies `write/event out of order`, `… beyond frontier` |
| `ThreadIntervals` | `start ≤ end` → `thread … interval inverted` |
| `CallNesting` | same-thread closed spans disjoint-or-nested → `crossing call spans` |
| `CallsWithinThreads` | known thread, span ⊆ lifetime → `call on unknown thread`, `call outside thread … lifetime` |
| `CursorBounded` | `snapshot(t > frontier)` → `None`; session refuses to move the cursor |
| `SnapshotConsistent` | property test: `value_at` vs brute-force fold |

Anomalies degrade, never abort: decoding continues past bad records.

## Cursor ownership

The cursor is *not* part of `Trace` — it belongs to the consumer. The
interactive shell (`forensicator-cli shell trace.ttfx`) owns it:
`seek`/`t+`/`t-`/`position` move it, `writes`/`intervals` query at it, and
`inspect`/`analyze`/`match` operate on `trace.snapshot(cursor)`.

## Boundaries and non-goals

- No `.run` parsing, no live debugging, no per-position register files (v2 candidate).
- The `TemporalAnalyzer` trait (cross-position reasoning: verdict timelines,
  corruption provenance) is designed but not yet implemented.
- Extractor selectivity matters: full store logs from a renderer are huge;
  expect VA-range filters / ring windows at extraction time (the LATS
  argument) — the format itself is filter-agnostic.

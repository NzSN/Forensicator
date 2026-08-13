# Timeline: TTD Trace Support

Spec: `specs/Timeline.tla` (Apalache-verified); mechanized theorems in
`Forensicator/Spec/Timeline.lean` and `Forensicator/Model/Trace.lean`.
Design: `docs/superpowers/specs/2026-08-07-timeline-design.md`.
Code: `Forensicator/Model/Trace.lean` (model + views + `snapshot`).

**Pivot state (2026-08-13):** the eager `.ttfx` v1 path is **removed**
(decoder/encoder, `trace` subcommand, fixture — plan:
`docs/plans/2026-08-13-remove-eager-trace-path.md`). The `Trace` model,
views, and theorems stay; what is gone is the file loader. Trace consumption
returns as the lazy jigsaw proxy (design authority:
`docs/superpowers/specs/2026-08-12-lazy-trace-proxy-design.md`, D1–D9 +
Implementation notes; loading-path spec `specs/JigSawSpawner.tla`,
Apalache-verified) — a resident Windows proxy serves positioned memory on
demand and the analysis host accumulates pieces with validity intervals.
The Lean proxy client (design D7, `IO.Process` stdio) is a follow-up plan;
until it lands, no loader constructs a `Trace` at runtime. The `.ttfx` v1
format doc survives as historical reference for a possible v2
jigsaw-persistence format ([ttfx-format.md](ttfx-format.md), design §D8).

## Why a separate container

Microsoft's `.run` trace format is proprietary and its only readers
(`TTDReplay.dll` / the dbgeng stack) are Windows-only. Forensicator never
parses `.run`. A Windows-side component produces our own versioned container,
and everything downstream is pure Lean, specifiable, and testable with
synthetic fixtures. `Timeline.tla` is the formal contract the Windows side's
output must satisfy — the same capture-side/analysis-side split as the V8HE
crash handler.

## Model (`Model/Trace.lean`) — Timeline.tla realized

```lean
structure Trace where
  initMem  : List MemoryRegionInfo   -- contents at position 0
  writes   : List WriteRecord        -- (pos, va, data) — append-only, ordered
  events   : List TraceEvent         -- Exception / ModuleLoad / ModuleUnload
  threads  : List (UInt32 × Interval)  -- lifetimes; stop = none while alive
  calls    : List CallSpan           -- [start, end) per thread
  frontier : Position                -- record head
  anomalies : List Anomaly
```

`Position = UInt64` packs TTD's `Major:Minor` pair (`(major <<< 32) ||| minor`,
`Basic.lean`). Spec's `end = -1` ↔ Lean `Interval.stop = none`.

### Views (spec operators → defs)

| Timeline.tla | `Trace` def | Meaning |
|---|---|---|
| `LastWriter(a,t)` | `lastWriter tr va t` | last write covering `va` at/before `t` |
| `ValueAt(a,t)` | `valueAt tr va t` | byte at `va` at `t` (snapshot-faithful: out-of-region writes never mask valid ones) |
| `WritesBetween(a,t1,t2)` | `writesBetween tr va len t1 t2` | "who wrote this range" |
| `ExceptionsAt(t)` | `exceptionsAt tr t` | CrashCause input, time-indexed |
| — | `snapshot tr t` | materialize position into `Snapshot { dump, space, pos }`; `none` for `t > frontier` (CursorBounded) |

`snapshot` builds: memory = initMem overlaid with writes ≤ t (last write per
byte wins); modules = loads − unloads ≤ t; exception = last exception ≤ t;
then a standard `AddressSpace` (`Pipeline.buildAddressSpace`). The existing 8
analyzers consume it unchanged. Byte-level faithfulness is proved:
`valueAt_agrees_with_fold` (the `SnapshotConsistent` counterpart) and
`snapshot_isSome` live in `Spec/Timeline.lean`; divergences from Rust are
Nat-lifted (`endVaNat`, overlap bounds — no `u64` wrap edges).

## Wire format (`.ttfx`, v1) — historical

The eager container (32-byte header → fixed-record sections `INITMEM`,
`WRITES`, `EVENTS`, `THREADS`, `CALLS` → payload pool) is documented in
[ttfx-format.md](ttfx-format.md) for the record; the decoder/encoder were
removed with the eager path (2026-08-13). A v2 jigsaw-persistence format
(design §D8 `DUMP CACHE`) may reuse the section ideas.

## Invariants as load-time validation

On the proxy path, the Timeline invariants are enforced as the client's
index/event windows arrive (design D5/D6; `JigSawSpawner.tla`'s
`JigSawInvariant` — `CacheSound`, `AbsentSound`, `HorizonBounded` — is the
loading-path counterpart). The eager decoder's anomaly mapping
(`TraceOrdered` → `… out of order`/`… beyond frontier`, etc.) is preserved
in `ttfx-format.md` §8 for the record.

## Cursor ownership

The cursor is *not* part of `Trace` — it belongs to the consumer. The
interactive shell owns it (`seek`/`t+`/`t-`/`position` move it,
`writes`/`intervals` query at it, `inspect`/`analyze`/`match` operate on
`trace.snapshot cursor`) — currently unreachable until the Lean proxy
client constructs trace sessions (`Session.lean`, `Target.trace`).

## Boundaries and non-goals

- No `.run` parsing, no live debugging, no per-position register files
  (the public Replay API's `GetCrossPlatformContext` makes them cheap —
  design P0′; candidate for the proxy era).
- Cross-position reasoning (verdict timelines, corruption provenance — the
  Rust-era `TemporalAnalyzer` sketch) is designed but not implemented.
- The lazy proxy's write index is windowed: full store logs from a renderer
  are huge; the host fetches per-range horizons (design D1) instead of one
  eager log.

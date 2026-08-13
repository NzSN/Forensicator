# Timeline: TTD Trace Support

Spec: `specs/Timeline.tla` (Apalache-verified); mechanized theorems in
`Forensicator/Spec/Timeline.lean` and `Forensicator/Model/Trace.lean`.
Design: `docs/superpowers/specs/2026-08-07-timeline-design.md`.
Code: `Forensicator/Model/Trace.lean` (model + views + `snapshot`).

**Pivot state (2026-08-13):** the eager `.ttfx` v1 path is **removed**
(decoder/encoder, `trace` subcommand, fixture — plan:
`docs/plans/2026-08-13-remove-eager-trace-path.md`), and trace consumption
returned the same day as the **shipped** lazy jigsaw proxy client (plan:
`docs/plans/2026-08-13-lean-trace-client.md`; design authority:
`docs/superpowers/specs/2026-08-12-lazy-trace-proxy-design.md`, D1–D9 +
Implementation notes; loading-path spec `specs/JigSawSpawner.tla`,
Apalache-verified). A resident Windows proxy (`ttfx-proxy.exe`,
`D:\Codebase\JigsawSpawner`) serves positioned memory on demand; the Lean
client (`Forensicator/Trace/`) accumulates pieces with validity intervals.
The `.ttfx` v1 format doc survives as historical reference for a possible v2
jigsaw-persistence format ([ttfx-format.md](ttfx-format.md), design §D8).

## Loading path (the Lean trace client)

`Forensicator/Trace/` mirrors `JigSawSpawner.tla`: everything checkable is
pure and total; IO is confined to `Client.lean` (`IO.Process` spawn, one
outstanding request, blocking with no read timeout in v1).

| Module | Role |
|---|---|
| `Trace/Proto.lean` | Wire protocol v1 (D6): pure total frame codec; golden vectors byte-pinned against the proxy's `proto.rs` tests |
| `Trace/Index.lean` | Windowed write index (D1): per-page horizons `idx_F`, `mergeWindow` (dedup by `(pos, va, len)`, `index window gap` + beyond-frontier anomalies) |
| `Trace/Jigsaw.lean` | Page cache (D2/D3): validity intervals from the index, ABSENT point intervals, LRU cap, p+1-clamped fetch positions, P3 next-write fallback positions |
| `Trace/Client.lean` | The only IO: spawn (local interop / ssh), handshake → skeleton, request loop, two-phase `valueAt`/`writesBetween`/`writeBytes`/`snapshotAt`, session-fatal poisoning |

Host-side position knowledge (D9) computes `KnownAt`/`KnownAbsentAt`/
`NeedsIndex`/`GapAt` from skeleton + index + cache. Two-phase snapshots
(D4) derive regions — never enumerate (P3): closure pages from the index at
the cursor ∪ probed pages, adjacent committed pages merged, `prot` R|W
approximate. The mechanized counterpart of `CacheSound`'s pure half is
`Spec/JigSaw.lean`'s `IndexState.history_agree` (the known write history is
constant over a piece's validity interval), with `mergeRecords`/
`mergeWindow` order/dedup/membership invariants — all `sorry`-free.

Documented position-level divergences (Implementation notes): a write
exactly at the frontier never materializes in any engine state (p+1 clamp);
page-lifecycle staleness (free/recommit without write records) is a
residual risk — the cache trusts the index (`NoRecommitWithin` assumption)
until the proxy-side N-mask watchpoint exists.

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

On the proxy path the Timeline invariants are enforced client-side as the
skeleton/index windows arrive and recorded in `anomalies` (degrade, never
abort): `events out of order`, `event beyond frontier`, `thread interval
inverted`/`beyond frontier`, `index record beyond frontier`,
`index window gap`, `piece outside frontier`, `piece invalid interval`.
`JigSawSpawner.tla`'s `JigSawInvariant` (`CacheSound`, `AbsentSound`,
`HorizonBounded`) is the loading-path counterpart; its pure halves are
proved in `Spec/JigSaw.lean` and exercised by the guard suite's
property checks (random fetch/query against a pure engine oracle).

## Cursor ownership

The cursor is *not* part of `Trace` — it belongs to the consumer. The
interactive shell owns it (`seek`/`t+`/`t-`/`position` move it,
`writes`/`intervals` query at it, `inspect`/`analyze`/`match` operate on
the cursor snapshot) — reachable via `shell --proxy` / `load --proxy`
(`Session.lean`, `Target.trace` + `Session.proxy`). Cursor commands are
pure over the skeleton; memory-reading commands are two-phase through the
proxy (see "Loading path" above).

## Boundaries and non-goals

- No `.run` parsing, no live debugging, no per-position register files
  (the public Replay API's `GetCrossPlatformContext` makes them cheap —
  design P0′; candidate for the proxy era).
- Cross-position reasoning (verdict timelines, corruption provenance — the
  Rust-era `TemporalAnalyzer` sketch) is designed but not implemented.
- The write index is windowed (design D1): the host fetches per-range
  windows with per-page horizons; `snapshotAt` collapses to one full-space
  window past the fan-out limit (435k records ≈ 10 MB on the fixture —
  eager-carryable).

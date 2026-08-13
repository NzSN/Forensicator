# Lazy Trace Proxy — jigsaw memory over TTDReplay (supersedes eager extraction for interactive work)

Date: 2026-08-12
Status: **design authority** — a Rust client was implemented and gate-verified
(2026-08-12) and discarded with the Rust tree (2026-08-13); this document plus
`specs/JigSawSpawner.tla` are now the specification for the Lean client
(follow-up plan). Proxy: `D:\Codebase\JigsawSpawner` (the design's
`D:\Repositories\TTFX` path had drifted; the proxy is a standalone crate
reusing the TTFX backend code). Implementation findings are preserved in
"Implementation notes" below.
Supersedes: the eager INITMEM path of `2026-08-09-ttfx-extractor-design.md`
for interactive sessions (the batch extractor stays as the offline/archive
path).
Behavioral contract: `specs/Timeline.tla` (unchanged — same views, new backing).
Prerequisites: P0/P3 spike findings in the extractor design (channels A/B/C).

## Summary

Do not transform `.run` → `.ttfx` up front. Instead run a resident
Windows-side **proxy** (`ttfx-proxy.exe`) that holds the `.run` open through
the dbgeng/TTD stack and serves **positioned memory on demand**. The analysis
side treats trace memory as a **jigsaw**: pieces are 4 KiB pages fetched
lazily, each carrying a **validity interval** computed from the write log, so
every fetched piece is reusable across a whole range of positions.

The model API is untouched: `Trace.lastWriter / valueAt / writesBetween /
snapshot` keep their signatures and `Timeline.tla` semantics. Only the backing
store changes — eager `initMem : List MemoryRegionInfo` becomes a
`MemorySource` with a jigsaw cache in front of the proxy.

## Motivation

The eager design's weakest point is INITMEM (extractor design P3): **all
region-enumeration APIs fail on TTD targets** (`QueryVirtual` E_FAIL,
`!address` "target does not provide full memory information",
`GetNextDifferentlyValidOffsetVirtual` garbage). So eager INITMEM is only a
referenced closure at min position — `valueAt` on a never-written,
never-captured page returns `none` forever. That is precisely the gap a
corruption-provenance investigation hits: the interesting pointer is usually
in a page nobody captured.

Lazy fetching removes the gap entirely: any page readable at any position
becomes available. Side benefits: no multi-GB `.ttfx` for renderer traces, no
2m40s extraction runs before the first query, and the dx `Value`
8-byte-truncation on wide writes disappears (page reads are the truthful
source; P2's `wide-truncated` counter goes away).

## Proven primitives (extractor spike, 2026-08-09)

| Channel | What | Status |
|---|---|---|
| A — IModelObject walk | threads, events, Lifetime (frontier) | proven, cheap |
| B — `!tt pos` + `IDebugDataSpaces4::ReadVirtual` | read bytes at any position | proven |
| C — `dx @$cursession.TTD.Memory(lo,hi,"w")` | positioned write log per VA range | proven |
| — | region enumeration at any position | **does not exist** (P3) |

Engine constraints that shape the design:

- `!tt` seek mutates **global engine state** → all positioned reads are
  serialized on one mutex; one outstanding request per proxy process.
- `[Unindexed]` traces still answer `TTD.Memory` (slower; `!index` when
  present is free speed).
- The jsprovider exit crash is handled by `TerminateProcess` at shutdown
  (documented in extractor README).

## P0′ findings — the public TTD Replay API (2026-08-12)

Verified against `microsoft/WinDbg-Samples` `TTD/ReplayApi` and the NuGet
package `Microsoft.TimeTravelDebugging.Apis` headers (`TTD/IReplayEngine.h`,
131 virtuals). **Region enumeration does not exist here either** — the
memory surface is point queries only:

- `ICursorView::QueryMemoryBuffer(GuestAddress, BufferView, policy)` —
  positioned read (cursor carries the position; no `!tt` text channel).
- `QueryMemoryRange(GuestAddress, policy)` → `MemoryRange { Address, Memory,
  Sequence }` — the contiguous recorded range containing the address **plus
  the SequenceId it was recorded at** — per-piece provenance from the engine.
- `QueryMemoryBufferWithRanges` — a filled buffer decomposed into per-range
  positions. Jigsaw validity metadata for free.
- `QueryMemoryPolicy`: `ThreadLocal | GloballyConservative |
  GloballyAggressive | InFragmentAggressive` — how hard the engine searches
  past/future positions for a value. The engine *is* a jigsaw fetcher with
  configurable effort.
- `GetCrossPlatformContext` / `GetAvxExtendedContext` — **full register file
  at any position** (Timeline v2 candidate, available now).
- `AddMemoryWatchpoint(range, R/W/E/C mask)` + `ReplayForward/Backward` —
  native positioned write/read/exec scanning (replaces channel C text
  parsing; also `Overwrite`/`NewData`/`Mismatch` events).
- `IReplayEngineView`: lifetime, threads, modules + load/unload times,
  exceptions, keyframes, PEB (replaces channel A).
- **"Many cursors can be created for a single engine object"** — position
  state is per-cursor, so the extractor spike's global-`!tt` serialization
  constraint does not apply to this backend (multithreaded replay is a
  first-class pattern in the TraceAnalysis sample).

No `QueryVirtual` equivalent, no protection/state/type (`MEM_*`) anywhere —
same conclusion as P3: **the region map must still be derived** (D4 stands).

Impact on this design (revisions, not rewrites):

- **Backend**: the proxy should target the public COM API
  (`MakeReplayEngine()` from `TTDReplay.dll`, no license handshake — the
  blocker that killed D1's direct-COM route in the extractor design is gone)
  with the dbgeng hybrid channels as fallback. Native types in, no dx text
  parsing out.
- **D6 revision**: one outstanding request is no longer forced by the
  engine; the proxy may run a small cursor pool. Keep the protocol
  request/response regardless (simpler client, backpressure for free).
- **D2 revision**: prefer `QueryMemoryBufferWithRanges` with
  `GloballyAggressive` for piece fetches — the returned per-range
  `Sequence`s refine the validity intervals computed from the write index,
  and `InFragmentAggressive` recovers pieces our index says nothing about.
- **New section candidate**: REGISTERS via `GetCrossPlatformContext` —
  per-position register files move from "Timeline v2" to "cheap at snapshot
  time" (`Snapshot` gains a `regs` field; analyzers may ignore it).

### Symbol resolution (decided 2026-08-12: host-side derivation)

**Neither backend has symbol APIs** (grep-verified across the NuGet headers;
the dbgeng route has `IDebugSymbols3` but it is the *generic* debugger
facility, not trace-aware). Global-symbol addresses are derived, not queried.
**Decision: host-side only — the proxy never resolves symbols.**

- The trace provides, per module instance: `(name, base, size,
  [LoadTime, UnloadTime))` (Replay API `GetModuleInstanceList`, or channel A
  module events on the dbgeng route).
- `symbol_va(t) = module.base + RVA`, where `RVA` comes from the existing
  host machinery — `symbolizer` (PDB) in the Rust tree / the MSF-7 reader in
  the Lean port, or the on-disk PE export table for DLL exports (`image`
  module backing). This is the extractor design's split, unchanged:
  symbolization stays on the analysis host.
- Validity: the address is meaningful exactly on the module instance's
  position interval; `snapshot(t)` already computes loads − unloads ≤ t, so
  symbol tables are built per snapshot, per module instance. ASLR is pinned
  per instance, so a resolved address never drifts within the interval.
- The dbgeng `IDebugSymbols3::GetOffsetByNameWide` route is **dropped** — one
  truth source, no Windows-side symbol-path dependency, no
  resolution-divergence risk between proxy and host.

## Architecture

```
[Windows]  trace.run ──dbgeng──► ttfx-proxy.exe  (owns the cursor via !tt)
                                       │  length-prefixed LE binary over stdio
[WSL]      forensicator ── spawn ──────┘  (WSL interop, like conformance.sh)
              │
              │ MemorySource::Proxy { client, jigsaw cache }
              ▼
        Model.Trace — same views, Timeline.tla semantics
```

One proxy process per `.run`, spawned by the analysis host via interop
(`/mnt/d/Repositories/TTFX/target/release/ttfx-proxy.exe --stdio`), matching
how `scripts/conformance.sh` already invokes the extractor. stdio transport
keeps the client socket-free (matters for the Lean port — `IO.Process`
suffices; no networking in the library).

## Key decisions

### D1 — Skeleton eagerly, memory lazily

At session start the proxy emits, unprompted:

- **INFO**: frontier, threads, events (channel A — cheap, small);
- **WRITE INDEX**: write *metadata* — `(pos, va, len)` per write, no payloads
  — from channel C with the `Value` field dropped.

The index is fetched **windowed** (`WRITES_INDEX va_lo va_hi t1 t2`), because
a renderer's full store log is the thing that blows up; windows are merged,
deduped by `(pos, va, len)`, and the fetched-window list is kept. The
fixture's full index would be ~568,550 × 24 B ≈ 13 MB — eager-carryable, but
windowing is the default anyway so behavior is uniform across trace sizes.

Everything with volume (page contents, wide-write payloads) is lazy.

### D2 — Jigsaw piece = (page, validity interval)

The central cache rule. A page read at position `t` (channel B) yields content
valid for **every** `t'` that has the same last-write position on that page:

```
validity(t) = ( W_last , W_next ]
  W_last = last write position ≤ t on this page   (0 if none)
  W_next = first write position > t on this page  (frontier+1 if none)
```

Both bounds come from the local write index (D1). Consequences:

- never-written page → one fetch, valid for the whole trace;
- snapshot walks near the cursor reuse pieces across seeks;
- cache eviction can be pure LRU — correctness never depends on retention.

Dependency rule: `READ_AT` on a page whose VA range has no fetched index
first triggers `WRITES_INDEX` for that single page (tiny range), because
validity is only computable once the page's write history is known.

### D3 — Absent piece is not an error

`ReadVirtual` failure at position `t` = page not committed then → the piece
is recorded as **absent** (with the same validity-interval rule) and
`valueAt` returns `none` — exactly the extractor's referenced-closure
semantics (P3: 66 such pages on the fixture). Only *protocol* failures
(framing errors, proxy crash, version mismatch) are session-fatal. Fail
closed, never fudge: no zero-fill, no guessing.

### D4 — Region map is derived, never enumerated

There is no `QueryVirtual` at any position (P3), so the jigsaw *is* the
region map. Regions for `snapshot(t)`:

1. pages with any write ≤ t (from the index) — the referenced closure;
2. pages explicitly requested and found committed at t;
3. adjacent same-class committed pages merge (as in the extractor).

`prot` stays approximate (closure = R|W); `state = Commit`. Same
approximations as the eager path, but now the map grows with use instead of
being frozen at extraction time.

### D5 — `Trace` gets a `MemorySource` seam; views unchanged

```text
MemorySource =
  | eager  : List MemoryRegionInfo            -- .ttfx INITMEM (today)
  | lazy   : ProxyClient × JigsawCache        -- this design
```

`valueAt(va, t)`: write index decides the source (last covering write ≤ t →
that write's page at `t`; else the page at `t`), then cache hit → bytes,
miss → proxy. `writesBetween` answers straight from the index (payloads only
fetched if the caller wants bytes). `snapshot(t)` materializes the D4 region
set, reading every missing committed piece at `t` — one engine pass, pieces
cached for later snapshots.

Timeline.tla mapping is unchanged (`TraceOrdered`, `CursorBounded`, …). New
anomaly kinds, decode-side only: `index window gap` (overlapping/unsorted
index windows), `piece outside frontier`.

### D6 — Wire protocol v1 (stdio, one outstanding request)

Length-prefixed little-endian frames: `len u32, tag u32, payload`.

```
→ HELLO        client_version u32
← HELLO_ACK    proxy_version u32, frontier u64
→ WRITES_INDEX va_lo u64, va_hi u64, t1 u64, t2 u64
← INDEX        record_cnt u64, then (pos u64, va u64, len u32, pad u32)*
→ READ_AT      pos u64, va u64, len u32
← PIECE        status u32 (0=ok 1=not_committed), len u32, bytes*
→ INFO         (threads/events dump; emitted once after HELLO_ACK)
← EVENTS/THREADS  (channel A records, same shape as .ttfx sections 3/4)
→ CLOSE
← (anything else) ERROR  msg
```

One outstanding request (engine is stateful). Client batches: pending
`READ_AT`s are sorted by position so runs of same-position reads share one
`!tt` seek; interactive use is cursor-local, so this is the common case.

### D7 — Implementation split

- **Proxy**: new bin in the existing Windows crate (`D:\Repositories\TTFX`),
  reusing `position.rs` (D3 pack check applies verbatim) and the channel A/B/C
  backend code from `ttfx-extract`. The `ReplayBackend` trait already has the
  right shape (`read_memory`, `writes`) — add `write_index(range)` returning
  metadata only.
- **Client**: Rust worktree first (`rust-backup`, where the session/shell and
  `Trace` already have IO around them); the Lean port follows once the
  protocol stabilizes — its client is stdio-only via `IO.Process`, no socket
  dependency in the library. Conformance gate gains a proxy-session golden
  run alongside the existing `.ttfx` ones.

### D8 — Relationship to `.ttfx`

No format change. A session either opens a `.ttfx` (eager source, offline
artifact, archiving/shipping across machines) or attaches to a proxy (lazy
source, interactive deep-dive). Same `Trace` API over both. A later v1.1 may
add `DUMP CACHE` (persist the jigsaw into a partial `.ttfx`) so a deep-dive
session can be saved and reopened offline.

### D9 — Position knowledge lives host-side

The proxy is a fetcher, not a knowledge base. Everything position-shaped
accumulates on the analysis host: frontier/threads/events (eager skeleton),
per-page write-index windows with horizons, PRESENT pieces with validity
intervals, ABSENT points. From these the host derives locally
`KnownAt(p,t)` / `KnownAbsentAt(p,t)` / `NeedsIndex(p,t)` / `GapAt(p,t)`
(formalized in `specs/JigSawSpawner.tla`) — it computes what it can answer
and what to fetch next. The proxy never drives navigation and never decides
coverage; the engine stays interchangeable behind `ReplayBackend` (Replay
API or dbgeng channels). This is what makes the Timeline state "empty
initially, filled lazily by query" (`docs/timeline.md`) without making the
host a thin terminal of the engine.

## Project layout

```
D:\Repositories\TTFX (existing crate, new bin)
  src/bin/ttfx-proxy.rs   # stdio protocol loop, request scheduler, mutex on engine
  src/proto.rs            # frame codec (shared shape with forensicator client)
  src/backend/dbgeng.rs   # unchanged channels A/B/C + write_index()

rust worktree (client first)
  forensicator-core/src/model/source.rs     # MemorySource, JigsawCache, validity intervals
  forensicator-core/src/trace_client.rs     # stdio spawn + frame codec + batching
  forensicator-cli/src/session.rs           # `load --proxy trace.run` attaches instead of parsing
```

## Conformance & testing

1. **Protocol round-trip**: frame codec unit tests both sides (same bytes,
   same offsets — mirrored by hand, as with `emit.rs`).
2. **Golden equivalence** (the real gate): scripted session over
   `traces\hostname01.run` — `valueAt`/`writesBetween`/`snapshot` results via
   proxy must equal the eager `.ttfx` path's results on the closure, and
   strictly exceed it on never-captured pages (assert `some` where eager
   gives `none`).
3. **Spot equivalence**: proxy `READ_AT(va, t)` vs WinDbg `!tt t` + `db va`
   (manual checklist, as in the extractor design).
4. **Cache property test**: for random (fetch position, query position) pairs
   within one validity interval, cached bytes == refetched bytes.
5. **Timeline invariants**: unchanged — enforced host-side on the index/
   events as they arrive (`TraceOrdered` etc.), anomalies degrade never abort.

## Phases

0. Spike ✅ (channels proven in extractor design).
1. Proxy skeleton: HELLO/INFO + frame codec + Rust client; session attaches,
   `threads`/`events` work.
2. `READ_AT` + jigsaw cache with validity intervals; `valueAt` over the proxy.
3. `WRITES_INDEX` windowing; `writesBetween` over the index; D2 dependency
   rule.
4. `snapshot(t)` over the jigsaw (D4 region derivation, one positioned pass);
   `analyze` at cursor.
5. Conformance harness + Lean-side client decision point.

## Risks / open questions

1. **Seek cost on big traces**: `!tt` is engine-speed, not recorded-speed;
   D6's position-sorted batching plus cursor locality should dominate. Measure
   on a multi-minute renderer trace before committing the Lean port.
2. **Unindexed traces**: `TTD.Memory` index queries are slower without
   `!index`; consider auto-indexing on attach (cheap, one-time).
3. **Position drift across WinDbg versions**: extractor risk #1 applies
   unchanged — pin the probed build, vtable mismatch faults loudly.
4. **Concurrent sessions**: one proxy per `.run`, one client per proxy; a
   second analysis host spawns a second proxy (engine instances are
   independent). No sharing protocol in v1.
5. **Wide-write payloads**: the jigsaw makes them fully recoverable (page at
   `t` holds all bytes). Should `WriteRecord.data` on the lazy path stay
   metadata-only and always resolve through the cache? Lean: yes — one truth
   source, no 8-byte dx `Value` copies lingering in the model.

## Implementation notes (2026-08-12, probe-verified on the fixture)

- **Off-by-one write visibility**: a TTD write at position `p` is
  materialized at engine position `p+1` (state at `p` is pre-instruction;
  `!tt` seeks to the start of the instruction). The lazy path reproduces
  the eager model's `pos ≤ t` convention by fetching at `t+1`, clamped at
  the frontier. A write exactly AT the frontier never materializes in any
  engine state — the one documented position-level divergence (the eager
  model applies it, the proxy cannot).
- **P3 class confirmed**: some pages (72 on the fixture) have write records
  but are unreadable at every position. Absent pieces (D3) are the right
  behavior; `write_bytes` falls back to the next write's position (with an
  overlap guard) before giving up. The dx `Value` payloads for these pages
  exist only in the eager `.ttfx` — a documented lazy-path limitation.
- **Page-lifecycle divergence (new)**: some pages' content changes without
  write records (free + recommit; Timeline.tla has no free op). The eager
  model shows stale write values; the D2 index-based cache validity rule can
  likewise serve stale bytes across the lifecycle break. The gate classifies
  these via a raw (cache-bypassing) probe at the write's post-state. A v1.1
  candidate: piece certification by position-verified refetch.
- **API note**: `value_at`/`writes_between`/`snapshot`/`write_bytes` take
  `&mut self` (window fetches mutate the merged index); `last_writer` stays
  `&self` (raw-log view over fetched windows).
- **Transport**: the client spawns the proxy via WSL interop on a single
  machine, or through `ssh` when the analysis host and the proxy host
  differ (the stdio protocol rides the ssh pipes; no networking in the
  library).
</content>

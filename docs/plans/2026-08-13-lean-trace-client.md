# Lean trace client (jigsaw proxy) — design + plan (2026-08-13)

**Status: shipped 2026-08-13.** All tasks landed the same day; gap D-B of
the removal plan is closed. Live-verified against `hostname01.run`
(435,030 index records == eager `.ttfx`; sampled payloads + 35/35 INITMEM
regions byte-equal; opt-in live gate green). Notable implementation
findings beyond the plan text: `IO.FS.Handle.read n` blocks until all `n`
bytes or EOF (fread semantics — the client reads exact header/body sizes,
never "up to n"); `Handle.readExact` loops handle short reads; proxy stderr
is inherited (an undrained pipe would deadlock the proxy); the eager
`~568,550` estimate was off — the true fixture write count is 435,030.

**Goal:** restore trace consumption in the Lean-only tree by implementing
the analysis-host side of the lazy trace proxy: spawn `ttfx-proxy.exe`,
speak the stdio protocol, accumulate the write index + jigsaw cache, and
construct `Target.trace` sessions so `seek`/`t+`/`writes`/`analyze`-at-
cursor work again. Closes gap D-B of
`docs/plans/2026-08-13-remove-eager-trace-path.md`.

**Design authority:**
`docs/trace/2026-08-12-lazy-trace-proxy-design.md` (D1–D9 +
Implementation notes — p+1 write visibility, P3 absent pages,
page-lifecycle divergence, transport). Loading-path spec:
`specs/JigSawSpawner.tla` (Apalache full run OK, depth 12). There is no
Rust reference to port (total removal, 2026-08-13); this document + those
two are the specification.

**Non-goals (v1):** v2 `DUMP CACHE` persistence (design §D8), per-position
register files (design P0′ — `GetCrossPlatformContext`; cheap follow-up),
proxy cursor pools/concurrency (one outstanding request), the one-shot
`trace` subcommand (shell-first), symbol resolution changes (host-side
derivation per design §"Symbol resolution" is unchanged).

## Architecture

```
Main.lean / Session.lean            (commands, cursor, two-phase answers)
        │
Forensicator/Trace/Jigsaw.lean      (pure: cache, validity, KnownAt/GapAt)
Forensicator/Trace/Index.lean       (pure: write-index windows, horizons)
Forensicator/Trace/Proto.lean       (pure: frame codec, golden-vector tests)
        │
Forensicator/Trace/Client.lean      (IO: spawn, request loop, batching)
        │  IO.Process stdio pipes
        ▼
ttfx-proxy.exe  (Windows; D:\Codebase\JigsawSpawner; the engine boundary)
```

The split mirrors `JigSawSpawner.tla`: everything checkable is pure and
total; IO is confined to `Client.lean`. This keeps the library's no-sorry/
no-partial/no-panic discipline and makes the codec/cache guard-testable
without a live proxy.

## Key decisions

### C1 — Two-phase answers, not monadic views

`Trace`'s pure views stay pure and unchanged in semantics. Every
memory-reading query is split:

1. **pure**: compute what the host knows/needs —
   `KnownAt p t` / `KnownAbsentAt p t` / `NeedsIndex p t` / `GapAt p t`
   (the spec's D9 views) over skeleton + cache;
2. **IO**: `Client` closes the gaps (`WRITES_INDEX` then `READ_AT`,
   dependency rule per design D2);
3. **pure**: answer from the now-populated cache.

`valueAt`/`writesBetween` at the session layer are `IO` wrappers around
this loop; the model-level theorems (`valueAt_agrees_with_fold`, …) remain
about the pure semantics.

### C2 — Skeleton eagerly, memory lazily (design D1)

At attach, `INFO` yields frontier, threads, events (validated against the
Timeline invariants → `Trace.anomalies`). The write log is metadata-only
and windowed: `WRITES_INDEX va_lo va_hi t1 t2` → `(pos, va, len)` records,
merged per page with a horizon `idx_F` (append-only ⇒ fetched facts never
invalidate — the spec's `HorizonBounded`).

`WriteRecord` gains `len : UInt64 := 0` (0 = payload-backed, `endVaNat`
uses `data.size`; non-zero = metadata-only index entry, `endVaNat` uses
`len`). Eager semantics are untouched (all eager records have `len = 0`);
`covers`/`endVaNat` proofs are re-checked in the guard suite. Index records
carry `data := #[]`, so model-level `valueAt` on them fails closed (`none`)
— correct: unknown until fetched.

### C3 — Jigsaw cache (design D2/D3; spec `FetchPage`/`Evict`)

- Piece = 4 KiB page at `(lo, hi]` validity from the index:
  `lo = lastKnownWrite p t`, `hi = nextKnownWrite p t` with the sentinel
  `idx_F[p] + 1` (never outrun knowledge — spec `HorizonBounded`).
- ABSENT pieces are point intervals `[t, t]` (uncommitted at `t`; the
  proxy's read failure is a fact, not an error).
- Eviction is LRU with a capacity cap (default 4096 pages / 16 MiB);
  correctness never depends on retention (spec: `Evict` is always enabled).
- **p+1 write visibility** (Implementation notes): a write at `p`
  materializes at engine position `p+1` — piece fetches read at `t+1`
  clamped at the frontier; a write exactly at the frontier is the one
  documented position-level divergence.
- **P3 pages** (writes recorded, page never readable): payload resolution
  falls back to the *next* write's position with an overlap guard before
  giving up (Implementation notes).
- **Page-lifecycle divergence** (free/recommit without write records):
  documented residual risk; the cache trusts the index (spec's
  `NoRecommitWithin` assumption) until the N-mask watchpoint mitigation
  exists proxy-side.

### C4 — Protocol v1 (design D6), pure codec

Length-prefixed LE frames `len u32, tag u32, payload`; `HELLO`,
`HELLO_ACK`, `INFO`, `WRITES_INDEX`/`INDEX`, `READ_AT`/`PIECE`
(`0=ok 1=not_committed`), `CLOSE`, `ERROR`. `Proto.lean` is a pure
total codec (`encode : Request → ByteArray`, incremental `decode` over a
buffer) pinned by golden frame vectors in the guard suite. `ERROR` frames
and framing violations are session-fatal (fail closed), never fudged.

Transport (`Client.lean`): `IO.Process.spawn` with piped stdin/stdout.

- Local (WSL interop): `FORENSICATOR_PROXY_EXE`, default
  `/mnt/d/Codebase/JigsawSpawner/target/debug/ttfx-proxy.exe`; trace path
  translated `/mnt/<drive>/…` → `<drive>:\…`.
- Remote: the spawn command may be `ssh <host> ttfx-proxy.exe …` — the
  stdio protocol rides the ssh pipes, keeping the library networking-free
  (same trick as the Rust client).

One outstanding request; pending `READ_AT`s are batched sorted by position
(cursor locality makes same-position runs the common case).

### C5 — Session integration

`Session` gains `proxy : Option ProxySession` (child handle + cache +
horizons). `load --proxy <trace.run>` (and `shell --proxy`) performs the
handshake + `INFO` and constructs `Target.trace skeleton frontier`. Cursor
commands are pure over the skeleton. `writes <va> <len>` resolves payloads
through the cache (two-phase). `analyze`/`inspect` at cursor run
**two-phase snapshot**: compute the referenced-closure page set from the
index at the cursor (design D4), batch-fetch missing committed pieces, then
materialize `Snapshot { dump, space, pos }` purely. Regions are derived,
never enumerated (P3): closure pages ∪ probed pages, adjacent same-class
merged, prot approximate (closure = R|W), per design D4.

### C6 — Verification

- **Golden frame vectors** (guard suite): request/response bytes pinned
  exactly (the protocol's conformance item 1).
- **Cache property checks** (guard suite): deterministic random
  (fetch, query) pairs against a pure model oracle — cached ≡ refetched ≡
  oracle, incl. absent pieces, eviction, horizon truncation (p+1 clamp).
- **Mechanized theorems** (`Forensicator/Spec/Timeline.lean` or a new
  `Spec/JigSaw.lean`): the pure half of `CacheSound` — validity-interval
  arithmetic: if the index has no write to `p` in `(lo, hi]`, any two
  positions in `[lo, hi]` have equal write-history, so a piece fetched at
  one serves the other (mirrors `valueAt_agrees_with_fold`'s structure);
  `mergeIndex` order/dedup invariants. The engine itself stays an abstract
  function parameter (as `CmAt`/`ValueAt` are in the spec).
- **Live gate** (opt-in, not default): `FORENSICATOR_PROXY_RUN=…` +
  proxy reachable → scripted session against `hostname01.run` on
  windows-dev: spot-compare `valueAt`/`writes` against known fixture
  values (the eager-golden equivalents are gone; the fixture's known
  answers are the record in the design's Implementation notes).

## Module layout

```
Forensicator/Trace/Proto.lean    # frame codec (pure) + Request/Response types
Forensicator/Trace/Index.lean    # write-index windows, horizons, mergeIndex, anomalies
Forensicator/Trace/Jigsaw.lean   # cache, Piece, validity, KnownAt/GapAt/NeedsIndex (pure)
Forensicator/Trace/Client.lean   # ProxySession, spawn, handshake, request loop (IO)
Forensicator/Model/Trace.lean    # + WriteRecord.len (C2) — the only edit to existing model code
Forensicator/Session.lean        # proxy field, load --proxy, two-phase commands
Main.lean                        # shell --proxy flag, re-enabled trace surface
Test/Spec.lean                   # codec vectors, cache properties, interval lemmas' guards
```

## Tasks

- [x] 0. **Spike `IO.Process`** (half a day, unblocks everything): spawn
      `cat` with piped stdio, write/read frames, detect EOF/exit. Confirms
      the toolchain's `IO.Process` API shape (no deps allowed —
      `Init.System.IO` only; `Std` is already used by `Session.lean`).
- [x] 1. **`Trace/Proto.lean`** — types + pure total codec + golden frame
      vectors in `Test/Spec.lean`. Verify: `lake build`, guard suite green.
- [x] 2. **`Trace/Client.lean` handshake + INFO → skeleton** — spawn,
      HELLO/HELLO_ACK (version check, frontier), INFO → `Trace` skeleton
      (threads/events with Timeline-invariant anomalies). Session:
      `load --proxy` constructs `Target.trace`; banner shows lazy mode.
      Verify: manual smoke against the real proxy via interop.
- [x] 3. **`Trace/Index.lean`** — WRITES_INDEX windows, per-page horizons,
      `mergeIndex` (dedup by `(pos, va, len)`, `index window gap` +
      beyond-frontier anomalies), fan-out limit → full-space window for
      wide ranges. `WriteRecord.len` (C2) + guard-suite repairs.
- [x] 4. **`Trace/Jigsaw.lean`** — cache with validity intervals, ABSENT
      points, LRU cap, p+1 clamped fetch positions, next-write fallback
      for P3 pages. Cache property checks green.
- [x] 5. **Two-phase commands** — `writes` payload resolution; two-phase
      snapshot (D4 closure derivation + batch fetch + pure materialize);
      `analyze`/`inspect` at cursor. Verify: scripted shell session over
      the real proxy reproduces known fixture facts (writes counts,
      closure samples from the Implementation notes).
- [x] 6. **Theorems** — validity-interval arithmetic + `mergeIndex`
      invariants (`Spec/JigSaw.lean`); `sorry`-free. Verify: `lake build`.
- [x] 7. **Opt-in live gate** — env-gated proxy check in
      `scripts/conformance-lean.sh` (skip by default; requires
      `FORENSICATOR_PROXY_EXE` + fixture trace on windows-dev).
- [x] 8. **Docs** — AGENTS.md (gap D-B note flips to shipped; commands
      gain `shell --proxy`), `docs/arch/timeline.md` (loading-path section
      becomes real), `docs/arch/cli.md` (trace group un-pended),
      `docs/arch/verification.md` (opt-in proxy check).

## Risks

1. **`IO.Process` API limits** (no async/timeout in core) — v1 is blocking
   with no read timeout; a hung proxy hangs the session (documented; Ctrl-C
   is the remedy). Spike (Task 0) de-risks the API shape.
2. **Seek cost on big traces** (design risk 1) — batching + cursor locality;
   measure on a renderer trace before declaring the two-phase snapshot
   interactive-grade.
3. **`WriteRecord.len` theorem churn** (C2) — bounded: eager records keep
   `len = 0`; proofs re-checked by the guard suite + `lake build`.
4. **Page-lifecycle staleness** — accepted residual (C3); the fix is
   proxy-side (N-mask watchpoint), tracked in the design doc.

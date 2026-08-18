# Verification: Specs, Theorems, Fixtures, Golden Gate

## TLA+ specifications (`specs/`)

| Spec | Models | Checked by |
|---|---|---|
| `Forensicator.tla` | Root workflow composition (S1 parse latches → S2 analyzer pipeline) | Apalache |
| `Model.tla` | Decoded `Dump` facts (append-only, provenance, bounded counts) | Apalache |
| `ParsePipeline.tla` | S1 phase machine (Init→…→Built/Done/Fatal) | Apalache |
| `AddressSpace.tla` | Region map invariants (`NoOverlap`, classify totality) | TLC + Apalache |
| `Arch.tla` | Exception CONTEXT register file | Apalache |
| `Symbolizer.tla` | Module/symbol tables, sorted resolution | Apalache |
| `CrashCause.tla` | Verdict discipline (classify → fire rules → decide; verdicts justified by fired rules) | Apalache |
| `Timeline.tla` | TTD trace semantics: ordered logs, cursor bounds, snapshot consistency, call nesting | Apalache (depth 10) |
| `Snapshot.tla` | The Timeline→Model link (`ModelAt(t)`, `SnapshotValid`, `SnapshotsAreModels`) | Apalache (`--features=no-rows`) |
| `JigSawSpawner.tla` | Lazy-proxy loading path over the ReplayApi engine surface (2026-08-18 refactor; the dbgeng-oracle revision was Apalache depth-10 green): watchpoint-scan index horizons, jigsaw cache validity, `CacheSound`/`AbsentSound` | Apalache length-1 smoke only — re-verification deferred (decision 2026-08-18) |
| `ReplayApi.tla` | The public TTD Replay API as an engine surface (pinned to the real v0.9.5 NuGet header): independent cursors, policy-driven memory queries (`QueryHonest`, `ExactAtCursor`), range provenance (`RangeFresh`), EventMask-gated watchpoint replay scans (`WatchStopsFirst`/`PwpStopsFirst`/`EventStopsFirst` with mask membership) | Apalache (`--features=no-rows`; NoError to length 6, depth 8 clean pre-fix; EventMask-fix re-check in flight 2026-08-15) |

Conventions: tiny model-checking bounds, flat parallel sequences, `@type`
annotations, constant quantifier domains with `Len` guards (Apalache's
dynamic-range limitation), safety invariants only.

## Mechanized theorems (Lean, `Forensicator/Spec/` + in-module)

The specs are not just checked — their content is **proved about the
shipping functions** (no `sorry`/`partial`/`panic!` in the library):

| Theorem | Where | Proves |
|---|---|---|
| `regionAt_unique`, `WellFormed.*`, `addRegion` preservation | `Spec/AddressSpace.lean` | sorted, non-overlapping region map; `NoOverlap` |
| `buildAddressSpace_wellFormed` | `Pipeline.lean` | the orchestrator only produces well-formed spaces |
| `valueAt_agrees_with_fold` | `Spec/Timeline.lean` | `SnapshotConsistent`: `valueAt` ≡ brute-force fold over writes |
| `snapshot_isSome` | `Spec/Timeline.lean` | `CursorBounded`: snapshot succeeds exactly within the frontier |
| `PositionOrdered`/`EventsOrdered` lemmas | `Spec/Timeline.lean` | `TraceOrdered` building blocks |
| `IndexState.history_agree` | `Spec/JigSaw.lean` | pure `CacheSound` half: the known write history is constant over a piece's validity interval `[lo, hi)` |
| `IndexState.lastKnownWrite_le`/`lt_nextKnownWrite`/`no_known_write_within` | `Spec/JigSaw.lean` | interval bounds + emptiness (`HorizonBounded` shape) |
| `mergeRecords_sorted`/`nodupKeys`/`mem_*`, `mergeWindow_sorted`/`mergeWindow_mem` | `Spec/JigSaw.lean` | mergeIndex order/dedup/absorption invariants |

The Rust-era model-based tests (`forensicator-core/tests/mbt_*.rs`,
mirrorrust) were retired with the Rust tree (2026-08-13) — their role is
absorbed by these theorems. The `.ttfx` decoder theorems
(`decodeRecord_*`/`decodeEvent_*`) died with the eager path the same day.

## Guard suite (`forensicator-test`, `Test/`)

In-process checks over synthetic builders (`Dump`, `AddressSpace`, `Trace`,
V8 heap cages) — no live dumps needed; 114 named `check`s in
`Test/Spec.lean`, including the trace-client surfaces: protocol golden
frame vectors (byte-pinned against the proxy's `proto.rs` tests), index
merge/horizon checks, and the jigsaw cache property run (400 deterministic
random fetch/query pairs against a pure engine oracle — CacheSound/
AbsentSound, absent points, eviction, horizon truncation, p+1 clamp).
With `FORENSICATOR_CASE_DIR` set, the suite also runs the minidump
prefix/mutation fuzz over `Case/` (review-hardening guards).

## Golden gate (`scripts/conformance-lean.sh`)

Post-pivot (2026-08-13): **Lean-only golden regression**. The gate compares
the Lean CLI against reference outputs in `Case/golden/` (untracked, like
the fixtures): 3 dumps × inspect (`--quiet` byte-exact, `--json` key-sorted)
+ analyze + match + shell scripts, plus the guard suite, the minidump fuzz,
and a negative guard (the binary must reject `.ttfx` input with the explicit
"ttfx removed" error). Goldens regenerate from a known-good build via
`scripts/capture-goldens.sh` when fixtures change.

**Opt-in live proxy gate** (off by default):
`FORENSICATOR_PROXY_RUN=<trace.run>` plus a transport
(`FORENSICATOR_PROXY_SSH=windows-dev` or a local `FORENSICATOR_PROXY_EXE`)
adds a scripted lazy-proxy session against the fixture trace — banner,
eager-`.ttfx` payload equality, overlapping write-count spots, and the
documented P3 fail-closed record (all pinned against fixture facts).

## Golden fixtures (`Case/`, gitignored except where forced)

| Fixture | Content |
|---|---|
| `Case/minidump/` | stack-only Crashpad dumps |
| `Case/minidump_v2/` | instrumented-handler dump + matching `electron.exe` + `.pdb` |
| `Case/fulldump/` | 1.2 GB full dump (slow; prefer `analyze` over `inspect`) |
| `Case/golden/` | gate reference outputs (untracked) |

(`Case/ttfx/minimal.ttfx` was deleted with the eager trace path,
2026-08-13.)

## Commands

```
lake build                          # library + CLI + forensicator-test
.lake/build/bin/forensicator-test   # guard suite (FORENSICATOR_CASE_DIR=Case for fuzz)
./scripts/conformance-lean.sh       # golden gate
FORENSICATOR_PROXY_RUN=… FORENSICATOR_PROXY_SSH=windows-dev ./scripts/conformance-lean.sh  # + live proxy gate
```

## Known spec hygiene issues

- `specs/Forensicator.cfg` references a nonexistent `RootInvariant` (the
  invariant is `ForensicatorInvariant`).
- `specs/PointerGraph.cfg` is orphaned — its spec was removed in `bf94b03`.
- `specs/ParsePipeline.tla`'s `INSTANCE Model WITH` predates Model's
  `ann_key`/`ann_val` variables and may not check as-is.

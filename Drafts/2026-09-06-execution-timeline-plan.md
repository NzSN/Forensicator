# Execution timeline implementation plan

Date: 2026-09-06
Design: [execution timeline](../docs/trace/2026-09-06-execution-timeline-design.md)
Status: T1–T5 implemented; local T6 checks passed; fixture golden/live gates unavailable

## Outcome

Replace timeline-position-to-`Dump` materialization with a source-scoped execution
view of address space, exact events and thread state. Support interval queries,
lazy knowledge acquisition and existing analyzers through that interface. Preserve
parsed minidumps as capture artifacts and retain useful capture-specific evidence.

## Dependencies and ownership

```text
T1 Core vocabulary and capture adapter (integrator)
 ├─ T2 Pure trace views, proofs and formal contract (timeline worker)
 ├─ T3 Analyzer migration and uncertainty rules (analyzer worker)
 └─ T4 Proxy views and explicit materialization (proxy worker)
T2 + T3 + T4 -> T5 Session/CLI integration (integrator)
T1..T5 -> T6 Behavioral gates and documentation reconciliation (integrator)
```

Workers are not alone in the checkout. They must keep to the listed ownership,
preserve other edits, and communicate any required changes outside their scope.
The integrator owns existing shared test files and task status. Workers may add
dedicated new test modules and report how to register them. No commits, pushes,
Rust tooling, proxy protocol changes or golden regeneration are part of this plan.

## T1 — Shared execution vocabulary and capture adapter

- [x] Extract neutral CPU/module/thread/memory/exception types into
  `Forensicator/Model/ExecutionTypes.lean`; keep dump parsing behavior unchanged.
- [x] Add `Model/Execution.lean`: source/point identity, knowledge/coverage,
  memory state, exact event payloads, thread execution/stack state and analysis
  input/context with position-scoped observations.
- [x] Add `Model/Capture.lean` to adapt a dump and existing address space into a
  single capture point without fabricating a TTD coordinate or lifetime.
- [x] Publish exact type/function names to workers before dependent edits.

Owner: integrator. Files: new model files, `Model/Dump.lean`, root imports.

Acceptance: no `Dump` field in execution input; unavailable registers differ from
zero registers; mapping evidence survives adaptation; exception payload/context,
module identities, system info and V8 observations survive with correct scope.

## T2 — Pure timeline views and contracts

- [x] Replace `Snapshot { dump, space, pos }` with execution-point construction.
- [x] Add exact `eventsAt`, validated `eventsBetween`, and validated write-range
  queries; preserve the pure last-write and byte-fold behavior.
- [x] Derive active modules and lifetime-only thread views without synthetic
  dumps; track malformed module/lifetime observations as anomalies.
- [x] Update Lean proofs to target the new interface and add point/event laws.
- [x] Update the active `Timeline`/`ExecutionState` contracts; replace the
  Dump-shaped Snapshot projection with partial execution-point materialization
  and retain `SnapshotMBT` only as a compatibility entry. Update the cache
  contract and add focused regression models.
- [x] Add dedicated timeline contract tests and communicate registration.

Owner: timeline worker (assignment recorded below). Files:
`Model/Trace.lean`, `Spec/Timeline.lean`, new spec files, active Snapshot/cache contracts,
new `Test/Timeline.lean`. Depends on T1.

Acceptance: exact exceptions do not persist at later positions; empty/reversed/
out-of-domain ranges are distinguished; thread start/stop and module reuse work;
theorems compile without `sorry`, `partial` or `panic!`.

## T3 — Analyzer migration

- [x] Change analyzer/pipeline input to `AnalysisInput` and remove `Dump` from
  scanner and semantic analyzer interfaces.
- [x] Preserve symbols, current exception parameters/context, available thread
  registers/stack bounds, mapping metadata, active module artifacts and scoped
  V8 observations.
- [x] Require positive evidence before diagnosing absent/uncommitted memory or
  unmapped code; unknown lazy coverage cannot produce those conclusions.
- [x] Make multiple unselected exceptions and unavailable thread contexts fail
  closed; preserve useful analysis when only some threads have enough context.
- [x] Add focused analyzer tests in an independently owned module if needed.

Owner: analyzer worker. Files: `Forensicator/Analyzer/**`,
`Forensicator/Util/V8Layout.lean`, new `Test/ExecutionAnalyzers.lean` if needed.
Depends on T1. Do not edit Main, Session or existing monolithic tests.

Acceptance: no synthetic-dump adapter in analysis; existing synthetic cause,
V8/JIT and symbols behavior retained where supported by evidence; explicit tests
for unknown versus known-absent memory and position-scoped observations.

## T4 — Proxy execution views and explicit materialization

- [x] Add a cache-only point view using eager events/thread lifetimes.
- [x] Add targeted range preparation and explicit touched-page preparation for
  batch analysis; keep interval write queries and add temporal bound validation.
- [x] Accumulate fetched pages into immutable results immediately so eviction
  cannot erase earlier successful observations.
- [x] Surface coverage, absence, index/cache anomalies and unavailable thread
  registers/stack data without fabricated protections/classification.
- [x] Guard unsupported maximum frontier and frontier write visibility; retain
  honest P3 fallback intervals and current wire protocol.
- [x] Add dedicated pure/materialization tests using a controllable fetch seam.

Owner: proxy worker. Files: `Trace/Client.lean`, narrowly necessary
`Trace/Jigsaw.lean`/`Trace/Index.lean` changes, new `Test/ExecutionProxy.lean`.
Depends on T1/T2 names. Session is owned by the integrator.

Acceptance: point creation triggers no fetch; targeted reads avoid full-index
discovery; materialization exceeding cache capacity retains fetched data; unknown
and absent differ; no process metadata is invented; no external protocol changes.

## T5 — Session and CLI integration

- [x] Add common execution-input access for dump and trace sessions.
- [x] Route `analyze` through explicit preparation and the new analyzer input.
- [x] Keep dump inspect/match rendering; introduce trace point inspection and
  module-based matching without constructing a `Dump`.
- [x] Resolve symbols from active modules and current selected event.
- [x] Preserve navigation and write/interval commands; update obsolete errors.
- [x] Adapt existing test call sites and register new test modules.

Owner: integrator. Files: `Session.lean`, `Main.lean`, `Test/Spec.lean`,
`Test/Symbols.lean`, `Test/Main.lean`, root imports. Depends on T2/T3/T4.

## T6 — Verification and reconciliation

- [x] Run the local `lake build` and full guard binary.
- [x] Check golden conformance availability; `Case/golden` is missing. Record
  the exact missing prerequisite and exercise synthetic CLI captures.
- [x] Run the new TLA+ model if Apalache is available; distinguish compilation
  and proof checking from external bounded model checking.
- [x] Check live proxy availability: `FORENSICATOR_PROXY_RUN` is unset. The real
  Windows gate is unavailable; deterministic protocol integration is tested.
- [x] Review no-synthetic-Dump call paths, unsupported knowledge, file ownership,
  and final diffs; reconcile design/plan and current architecture documentation.

Owner: integrator. Completion evidence is recorded below; unchecked work is not
reported as shipped. Do not overwrite goldens to force acceptance.

## Assignment log

| Task | Assigned agent | Status |
|---|---|---|
| T1 core and capture adapter | integrator | Complete; capture validity corrections included |
| T2 trace views, proofs, formal contract | `implement_timeline` | Complete |
| T3 analyzer migration | `implement_analyzers` | Complete |
| T4 proxy views and materialization | `implement_proxy` | Complete |
| T5 session/CLI integration | integrator | Complete |
| T1/T6 core behavior guards | `execution_tests` | 38 guards implemented and passed |
| T6 combined verification | integrator | Local checks passed; external fixture gates unavailable |

Read-only preparation was completed by `analyzer_migration`, `timeline_contract`
and `proxy_migration`. User explicitly authorized starting implementation.

## Verification evidence

- Initial checkout was clean. Baseline `lake build` and baseline guards passed
  after creating the guard runner's required `tmp/` directory. The runner now
  creates that gitignored directory itself.
- Final `lake build`: passed, 107 jobs; existing linter warnings remain.
- Full `.lake/build/bin/forensicator-test`: passed, **291 checks**. This includes
  38 core/capture, 18 timeline, 27 analyzer and 19 proxy checks for this design,
  alongside the existing guard coverage.
- `python3 scripts/test-execution-shell.py`: **14 checks passed**. Real Lean
  stdio transport is exercised against a deterministic Python proxy: no-fetch
  inspection/navigation, exact/range events, targeted reads, invalid input,
  unknown versus absent memory, classification-independent scanning, module
  unload/reload, frontier visibility and explicit exception selection.
- TLA+ follow-up strengthened the active base/view/materialization/cache
  contracts. Current results are recorded in the table below; the earlier
  lightweight ExecutionState check has been superseded.
- Synthetic capture comparison against the pre-change binary: text/quiet/JSON
  inspection and scripted inspect/match shell presentation matched exactly.
  An unclassified captured string previously skipped by the analyzer now produces
  one finding instead of zero, as intended by the known-byte contract.
- `./scripts/conformance-lean.sh` was invoked and exited at preflight because
  `/home/nzsn/Repos/Forensicator/Case/golden` does not exist. No golden files were
  regenerated and no fixture-level parity is claimed.
- `FORENSICATOR_PROXY_RUN` is unset. Real Windows replay was not run. The protocol
  simulation does not verify native replay behavior or lifecycle completeness.

Review found and resolved missing-context zero registers, invalid mapping states
promoted to absence, a clamped frontier fallback contaminating earlier cached
knowledge, unknown-class pages being skipped by scanners, and local range errors
poisoning the proxy session. Regression tests cover the applicable evidence and
transport paths. See the design's implementation notes for deliberate output
changes and external proxy capabilities that remain unavailable.

## Remaining external validation

- [ ] Run the golden gate against the real `Case` dumps and review intentional
  diagnosis/scanning differences before accepting any reference update.
- [ ] Run the live Windows proxy gate with an actual configured trace. Extend
  native protocol capabilities separately for register/stack retrieval.

## Active TLA+ follow-up (2026-09-06)

The base spec now exposes exact `ExceptionsAt` and historical `ExceptionsThrough`.
ExecutionState stores observations instead of recomputing them on reads, separates
trace and capture identities, and models per-thread context availability. Returned
event sequences have membership/order checks; valid selection must succeed using
the point's local event indices. Scoped context evidence has a checked consumer.

Snapshot now returns only point identity, address space, events and thread state.
Attempted reads and positive observations are separate; an unknown read may finish
without becoming a known zero. A published result survives subsequent cache work
and acquisition for the next request until replaced explicitly. The cache spec
suppresses frontier values, requires strict fallback bounds, and tracks requested
versus observed positions. The obsolete Dump-shaped Snapshot/MBT projection is gone.

| Model/check | Bound | Result |
|---|---|---|
| Timeline | 10 transitions | NoError; 208.849 s |
| ExecutionState | 10 transitions | NoError; 478.834 s |
| Snapshot, full initialization | 6 transitions | NoError; 253.734 s |
| SnapshotRegression, loaded sources | 8 transitions | NoError; 418.619 s |
| JigSawSpawner, normal initialization | 6 transitions | NoError; 151.540 s |
| JigSawSpawnerRegression | 4 transitions | NoError; 27.692 s |
| Six deliberately incorrect mutations | Counterexamples at 0–4 transitions | All rejected |

`SnapshotMBT` and `ReplayApi` also passed typechecking against the current base
contract. The gate scripts passed syntax checks; their individual model-check
commands were run as recorded above.

The mutation gate rejects wrong-source memory, unknown-to-zero conversion, dropped
events, always-failing selection, publishing the final cache instead of accumulated
pages, and the old `<= frontier` fallback. Each case requires an invariant violation,
not a parser/type error. Scripts: `scripts/check-timeline-specs.sh` and
`scripts/test-timeline-spec-mutations.py`.

Broader ten-transition Snapshot and JigSaw attempts were stopped during transition
8 as search cost grew; they are incomplete and are not counted as passes. The
completed shorter general checks are paired with loaded-source regression profiles
that reach the relevant acquisition/fallback paths directly. These are bounded
checks, not proofs for arbitrary trace size or native replay lifecycle behavior.

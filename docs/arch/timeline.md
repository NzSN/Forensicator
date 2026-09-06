# Timeline: execution points and lazy knowledge

Current design: [execution timeline](../trace/2026-09-06-execution-timeline-design.md).
Implementation and verification: [plan](../../Drafts/2026-09-06-execution-timeline-plan.md).

## Model and analysis interface

`Model/Execution.lean` defines a source-scoped `ExecutionPoint` containing memory
knowledge, events occurring at the point, and thread execution/stack knowledge.
`AnalysisInput` adds separately scoped system, active-module and runtime context.
The point and analyzer interface contain no `Dump` aggregate.

`Model/ExecutionTypes.lean` holds neutral process records. `Model/Dump.lean` retains
the parsed capture aggregate; `Model/Capture.lean` adapts it to one capture point.
A capture is not assigned a fictitious TTD position or a thread lifetime.

| Information | Representation |
|---|---|
| Point identity | Source key plus `capture` or packed TTD `trace position` |
| Memory | `AddressSpace` known bytes, mapping observations, independent coverage and positive absence ranges |
| Events | Payloads at the exact point, with explicit exception selection when ambiguous |
| Threads | ID/lifetime, known/unknown/unavailable registers and stack ranges, recovered-frame knowledge |
| Supporting facts | Active module projection and exact-point runtime observations in `AnalysisContext` |

Unknown bytes are not zero bytes or proof of absence. Captured register validity
survives parsing; missing/invalid contexts remain unavailable. A valid zero-valued
context is still known. MemoryInfoList uses native Windows layout/constants and
rejects invalid states instead of turning them into positive free-memory evidence.

## Current host stack and identity increment

The [completion task board](../../Drafts/2026-09-06-timeline-task-board.md) tracks
active and queued subagent ownership. `Execution/Stack.lean` now provides pure,
budgeted x64 recovery with dependencies, stop reasons and observation evidence.
The shell's `stack` command retains partial capture results; `inspect --point`
exposes them through the common execution view. Ordinary dump inspection keeps its
capture format. Point inspection itself does not run recovery or acquire bytes.

Retained results are scoped to the current attachment and checked against point,
thread, effective selected-exception/thread registers, system/module information
and observed reads. Reload drops this knowledge. The production path currently
uses conservative frame-pointer recovery unless independently verified unwind
artifacts are supplied; it does not invent a terminal witness. V8/JIT migration to
this shared walk, native v2 contexts and broader/per-register recovery remain queued.

`Model/Observation.lean` adds native 64+64 coordinates, identity and applicability
primitives with tests/proofs; these do not yet replace the live legacy coordinate
or path-based identity. `Util/Digest.lean` supplies streaming SHA-256 for future
source/cache integrity, not a persistence format.

The actual SDK's conservative policy is confidence-based, not an exactness
certificate. Existing replay/cache oracle assumptions are now labelled explicitly.
See the [native report](../../Drafts/2026-09-06-timeline-native-prerequisites.md)
for verified ABI facts and remaining replay/fixture gates.

## Pure timeline queries

`Model/Trace.lean` retains the trace logs and initial memory model:

| Query | Contract |
|---|---|
| `pointAt t source` | Optional execution point; no result beyond frontier |
| `analysisAt t source` | Point plus its active contextual projection |
| `eventsAt t` | Events exactly at `t` |
| `eventsBetween a b` | Checked `(a,b]` event query |
| `writesBetweenChecked va len a b` | Checked overlapping-write query in `(a,b]` |
| `modulesAt t` | Active modules after events through `t`; conflicting evidence is excluded with anomalies |
| `threadsAt t` | Active, unambiguous thread lifetimes with context availability |
| `valueAt va t` | Pure last-write byte view within initial backing |

Equal interval endpoints return no events/writes; invalid bounds are errors.
Thread lifetimes are `[start,stop)`. Pure event/write lists retain list order.
The proxy write index instead retains its established `(position, address, length)`
ordering and deduplication; v1 has no record identity for resolving simultaneous
writes across windows. Do not infer writer identity or instruction succession
from packed position arithmetic alone.

## Proxy loading and materialization

The proxy path is the only trace input path. Forensicator does not parse `.run`,
and eager `.ttfx` loading remains removed. `Proto`, `Index` and `Jigsaw` remain pure;
`Client` owns the `IO.Process` transport and two-phase acquisition.

| Client operation | Work performed |
|---|---|
| `viewAt t` | Reads current cache/index knowledge and eager inventory; sends no requests |
| `materializeRanges t ranges` | Fetches requested pages and their index dependencies |
| `prepareAnalysisAt t` | Explicit full-index discovery and touched/probed-page preparation for batch analyzers |
| `writesBetween ...` / `writeBytes` | Write-history and payload acquisition |

Each prepared page is added immediately to the returned immutable result, so
subsequent cache eviction cannot erase successful reads. Derived pages retain
unknown mapping protections/classification. Strings and pointer inference scan
known bytes regardless of unknown class; class-specific heap/vtable inference
still requires corresponding evidence.

A page affected by an unobservable frontier write remains unknown. A P3 fallback
must reach a write strictly before the frontier; its later bytes cannot satisfy
an earlier point. A finite cache may forget evidence; completed query results
retain their evidence. UInt64-maximum frontier and unrepresentable final-page
requests are rejected before unsupported arithmetic can wrap.

Protocol v1 supplies no registers, stack bounds, recovered frames, writer thread
IDs or complete mapping inventory. Those capabilities are explicitly unavailable.
Untouched, unprobed memory remains unknown. Free/recommit without indexed writes
remains an external completeness assumption; local tests do not establish it.

## Session and shell

`Session.currentIO` obtains a cache-only execution view. `Session.prepareAnalysis`
explicitly acquires the finite region set needed by batch analyzers. Parsed dump
inspection remains capture-specific; trace inspection reports point knowledge.
Matching consumes the active module projection, and verified symbols are loaded
for the current input and bound to the selected module base.

```text
shell --proxy <trace.run>       attach to the trace
seek <position>               select an encoded position
t+ / t- / position             navigate or display the cursor
inspect [--json|--quiet]       inspect trace point knowledge without fetching
inspect --point [--json]       inspect a capture through the execution view
stack <thread-id> [--json]     recover/retain a bounded host stack
read <address> <length>        acquire up to 65536 bytes for display
events                        occurrences exactly at the current point
events <from> <to>             recorded events in (from,to]
writes <address> <length>      write history through the cursor
intervals                     thread/call lifetime inventory
analyze [--event <index>]      explicitly prepare memory, then run analyzers
```

`--event` indexes the current point's event list. Missing/ambiguous exception
context does not reuse an older exception. An unavailable write payload prints
`<unavailable>` rather than asserting that its memory was uncommitted.

## Verification

`Spec/Timeline.lean` preserves ordered-list and byte-fold proofs and adds point
identity/bounds, exact event membership and interval partition laws. These prove
properties of the shipping pure functions, not complete recovery of process state.
`Spec/JigSaw.lean` continues to prove write-index and cache-history arithmetic.

The active TLA+ contracts are:

| Spec | Contract |
|---|---|
| `Timeline.tla` | Recorded memory, exact events, checked intervals and half-open thread lifetimes |
| `ExecutionState.tla` | Stored source/position-scoped knowledge, tagged capture points, per-thread context availability, complete ordered events and explicit selection |
| `Snapshot.tla` | Explicit acquisition into an execution point, partial completion, and a retained published result independent of the cache |
| `JigSawSpawner.tla` | Index/engine-backed cache knowledge, unobservable frontier suppression and strictly observable P3 fallback |
| `SnapshotRegression.tla` | Loaded trace/capture materialization, including two requested cells in a one-cell cache |
| `JigSawSpawnerRegression.tla` | Real write/commit-log cases for ordinary and frontier fallback |

`Snapshot.tla` no longer instantiates `Model` or produces a Dump-shaped record.
`SnapshotMBT.tla/.cfg` are compatibility entry names for this current contract;
the obsolete Rust echo state has been removed. `Model.tla` remains the separate
capture aggregate used by parsing/workflow specs.

Run `./scripts/check-timeline-specs.sh` for the bounded gates and
`python3 scripts/test-timeline-spec-mutations.py` to verify that intentionally
incorrect variants fail. The latter uses temporary copies and requires actual
invariant counterexamples; parser/type errors do not count as detected defects.
See the plan for bounds and completed results.

The materialization model distinguishes attempted cells from positively observed
cells. Unknown reads can finish without becoming zero bytes or absence. The last
published point remains valid while another request acquires pages; publishing
its replacement ends that result's modeled lifetime. Multiple caller-held result
objects, native register layouts, address-range encoding, and replay lifecycle
completeness are explicit abstraction limits. Memory/context adapter observations
are assumed truthful; the cache model separately checks its engine/index mapping.

`Test/Execution.lean`, `Test/Timeline.lean`, `Test/ExecutionProxy.lean`, and
`Test/ExecutionAnalyzers.lean` cover the new contracts inside the full guard
runner. `python3 scripts/test-execution-shell.py` exercises the real CLI and
transport against a deterministic stdio proxy. The fixture golden/live gates
remain separate; see the plan for their actual availability and results.

The completion increment adds `Test/Digest.lean`, `Test/Observation.lean`,
`Test/Stack.lean` and `Test/StackSession.lean`, plus
`python3 scripts/test-stack-shell.py`. `ObservationScopes.tla` and
`StackRecovery.tla` check the new pure eligibility and host-recovery contracts.
The task board records their bounds, negative controls and integrated results.

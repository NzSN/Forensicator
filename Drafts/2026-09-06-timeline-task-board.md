# Timeline completion tasks and subagent assignments

Date: 2026-09-06

Baseline: `68d34bdd6d9e9a322210bc44e8ef7c96c10486c3`.

Authority: [completion plan](2026-09-06-timeline-completion-plan.md),
[design](../docs/trace/2026-09-06-timeline-completion-design.md),
[v2 draft](../docs/trace/2026-09-06-proxy-v2-contract-draft.md).

The user authorized task development and subagent assignment. Implementation has
started in bounded local increments. The 16 parent tasks below keep their original
acceptance gates; completing a prerequisite subtask does not close its parent gap.
Queued assignments are ownership reservations, not claims that their code is running.

## 1. Parent-task ownership and gates

| Task | Assigned subagent / integration owner | Current dispatch | Required gate before the remaining work |
|---|---|---|---|
| V0 fixtures/baseline | `completion_native_prereqs` | Availability audit completed; real golden gate blocked | Actual `Case`/golden fixture location |
| R0 native capabilities | `completion_native_prereqs` | R0a package/ABI probe completed; R0b replay matrix pending | Current proxy checkout/binary and scoped native comparisons |
| R1 identities/coordinates | `completion_identity` | R1a pure primitives implemented; R1b runtime migration queued | Shared live identity/resolution contract and coordinated consumer migration |
| R2 v2 protocol/fake provider | `completion_identity` | Queued | R0 replay semantics, R1b types and frozen field/tag contract |
| R3 external provider | `completion_native_prereqs` | Queued, external checkout missing | R0/R2; no external code changes without the actual owner/checkout |
| R4 validated acquisition | `completion_identity`, integrator | Queued | R1b/R2; native certification additionally requires R3 |
| S0 pure stack recovery | `completion_stack_core` | S0a current-model native core implemented | S0b validity-mask and wider-unwind work follows coordinated types |
| S1 shared frame knowledge | `completion_stack_core`, integrator | S1a capture/session integration completed | S1b requires R4/native contexts, verified artifacts, and V8/JIT shared-walk migration |
| M0 point mappings | `implement_proxy` | Queued | R4 and an R0-verified replay-target metadata route |
| M1 lifecycle/reuse | `implement_proxy` | Queued | M0 plus certified lifecycle/continuity coverage |
| P0 exact-point persistence | `completion_digest` | P0a digest prerequisite implemented; store queued | R1b evidence/origin identities and format freeze |
| P1 offline/derived storage | `completion_digest` | Queued | P0; interval certificates additionally require M1 |
| T0 history/evidence registry | `implement_analyzers` | Queued | R1b canonical observation registry/runtime binding |
| T1 attributed access index | `implement_proxy` (host), `completion_native_prereqs` (native) | Queued | R0/R2/R4 and verified stable occurrence/coverage semantics |
| T2 explanations | `implement_analyzers` | Queued | T0/T1; S1/M1 for edges needing frames/epochs; candidates remain explicitly weaker |
| V1 certification | `completion_formal` (local/formal), `completion_native_prereqs` (native), integrator | Local milestone checks passed; native certification pending | Integrated revisions and V0/R0/R3 fixtures/capabilities |

## 2. Ready-wave implementation tickets

### R0a / V0a — Establish actual prerequisites

Owner: `completion_native_prereqs`.

Owned output: [native prerequisite report](2026-09-06-timeline-native-prerequisites.md)
and temporary acquisition/probe artifacts. External checkouts are read-only.

Acceptance:

- [x] Check real fixture/proxy/runner availability without reading credentials.
- [x] Pin the actual 0.9.5 NuGet package and header digests.
- [x] Compile/run an x64 Windows ABI probe, separating ABI facts from replay behavior.
- [x] Report current proxy/golden prerequisites and precise native follow-up cases.
- [ ] R0b: verify requested/actual global and per-thread positions, event sides,
  read provenance/outcomes and capability behavior on real replay.

Findings: Windows/MSVC, a historical `hostname01.run`, and staged replay DLLs
exist under the discovered historical extractor setup. Native Position is 16 bytes
with two UInt64 components. The current proxy and Case/goldens remain missing.
The SDK's conservative query policy does not promise exactness; certification
cannot follow from a policy name alone.

### R1a — Pure identity and native-coordinate primitives

Owner: `completion_identity`.

Files: `Forensicator/Model/Observation.lean`, `Test/Observation.lean`.

Acceptance:

- [x] Native pair preserves high halves and lexicographic order.
- [x] Legacy conversion round-trips representable coordinates and rejects overflow.
- [x] Explicit interval endpoints avoid a synthetic overflowing successor.
- [x] Source aliases, identity claims/certification, epochs, threads, phases and
  interpretation scope are separate; exact applicability is policy-independent.
- [x] Live replies require the attachment epoch; durable reuse requires verified
  matching content and compatible scope.
- [x] Lean order/roundtrip/scope lemmas and targeted guards compile/pass.
- [ ] R1b: migrate live Session/PointId/trace-coordinate consumers in one coordinated
  change; add actual source binding, register validity and resolved-point controllers.

Scope limit: these are standalone primitives. The current live runtime still uses
its existing PointId and legacy coordinate representation. A parsed digest remains
an unverified claim until a trusted adapter validates its manifest.

### P0a — Streaming content digest

Owner: `completion_digest`.

Files: `Forensicator/Util/Digest.lean`, `Test/Digest.lean`.

Acceptance:

- [x] Exactly 32-byte digest representation with checked bytes/hex parsing.
- [x] Total incremental SHA-256 with bounded retained input and length checks.
- [x] Standard vectors, padding/chunk boundaries and malformed-state guards.
- [x] Independent deterministic Python hashlib comparisons.
- [ ] P0b: FTLC codec, manifest verification and save-generation publication.

No cache format or cross-session reuse is claimed by this prerequisite. Raw hash
state is not an authenticated serialization format. Cryptographic properties are
standard assumptions; the implementation has behavioral checks, not a formal proof
of SHA-256 or CAVP certification.

### S0a — Pure native stack recovery on current execution inputs

Owner: `completion_stack_core`.

Files: `Forensicator/Execution/Stack.lean`, `Test/Stack.lean`.

Acceptance:

- [x] Recover one exact point/thread instance with explicit frame/read budgets.
- [x] Return partial frames, stop reason, missing dependencies and read/register/
  artifact evidence without IO or a hidden stack cache.
- [x] Prefer a valid selected/sole exact exception context for the matching thread;
  malformed context fails closed and unrelated events do not override registers.
- [x] Strict supported native forms reuse the existing unwind helper after preflight.
- [x] Missing metadata, unsupported forms, cycles and unknown bytes stay incomplete.
- [x] Complete results require an independently validated exact typed root witness,
  no outstanding dependencies and no frame-pointer heuristic.
- [ ] S0b: per-register validity, broader verified unwind forms and V8/JIT extraction.

Production trusted artifact/root-witness construction is still pending. Default
capture use can yield useful partial frame-pointer results; it does not certify
every native stack or infer a complete root from a zero return address.

### S1a — Capture-side retained frame knowledge

Owner: integrator, with `completion_stack_core` review.

Files: `Forensicator/Session.lean`, `Main.lean`, new session integration tests;
shared imports/test registration remain integrator-owned.

Acceptance:

- [x] Add explicit bounded stack recovery for a selected thread instance.
- [x] Retain validated recovery results within the attachment and enrich
  `ExecutionPoint.threads[].frames` on subsequent execution-view access.
- [x] Check point/thread/register/dependency agreement before reusing a result.
- [x] Preserve dump inspect output; expose enriched execution inspection explicitly.
- [x] Keep ordinary point inspection free of acquisition/recovery work.
- [x] Verify selection errors, stale points, incomplete recovery and retained results.

Scope limit: proxy-v1 contexts remain unavailable; automatic dependency acquisition,
production artifact verification and V8/JIT consumption of the shared walk remain
S1b work. This does not close the entire thread-stack gap.

### V1a — Local integration and bounded formal checks

Owners: `completion_formal` and integrator.

Files: new observation-scope/stack-recovery specs/configs, narrow assumption comments,
root imports/test runner, current architecture/task status.

Acceptance:

- [x] Register all new guards and run the integrated build/guard suite.
- [x] Exercise new shell behavior and existing simulated-proxy regression checks.
- [x] Check small models for live/restore scope eligibility and partial stack
  recovery/root/dependency rules, with meaningful negative controls.
- [x] Describe existing ReplayApi exact-query modeling as an explicit idealization,
  rather than a guarantee from the inspected conservative-policy header.
- [x] Record native replay/golden limitations separately; do not mark V1 complete.

## 3. Dispatch rules for the queued work

R1b is the next integration seam: freeze live source/coordinate/evidence interfaces
with the actual R0 findings before R2/R4 or store/index consumers modify them.
The shared API owner coordinates all changes to Basic, Execution, Proto, Session
and existing proof/test call sites. Each queued task inherits the detailed behavior
and closure gate from the parent plan; it is activated as a bounded follow-up after
those dependencies are satisfied.

For native work, the remaining path request concerns the current proxy checkout/
binary and real Case fixtures. The discovered historical extractor, Windows runner
and old trace are useful inputs, not substitutes for a verified current proxy.

For M1, unsupported lifecycle acquisition leaves the gap open. For P0/P1,
session-only identity cannot authorize restoration. For T1/T2, speculative ordering,
ambiguous access identity and missing premises remain explicit rather than being
converted into supported causal edges.

## 4. Validation results

Component results already reported by their owners:

| Milestone | Result |
|---|---|
| R0a ABI | Actual package/header hashes and Windows/MSVC layout probe recorded in native report |
| R1a primitives | 25 guards and Lean roundtrip/order/scope lemmas passed |
| P0a digest | 17 guards, 56 independent hashlib comparisons passed; 16 MiB native streaming benchmark matched |
| S0a stack core | 51 guards passed, including exception-context selection and provenance |
| S1a/V1a integration | Build and 402 guards passed; 10 capture-stack and 14 proxy shell checks passed |

Parent tasks are not marked complete merely because their prerequisite rows pass.

## 5. Integrated ready-wave outcome

The host now exposes `stack <thread-id> [--max-frames N] [--max-bytes N] [--json]`.
`inspect --point` shows enriched capture execution views while ordinary capture
inspection retains its format. Successful partial recoveries are held inside the
attachment and reused only when point/thread, effective register observation,
system/module interpretation and recorded read dependencies still match. Reload
clears retained recovery; previously returned points remain immutable.

The parser now requires the x64 CONTROL and INTEGER context groups before its
current consumers treat captured core registers as available. This was needed for
safe production use of the stack primitive. Missing/partial group flags stay
unavailable, while valid zero-valued registers remain known. Per-register masks
and coordinated native-coordinate runtime migration remain R1b work.

Validation completed in this wave:

- `lake build`: passed (121 jobs; existing linter warnings remain).
- Complete guard binary: 402 checks passed, including 15 new session-retention
  checks, core-context flag regressions, and invalid module/region return-target guards.
- `python3 scripts/test-stack-shell.py`: 10 checks passed.
- `python3 scripts/test-execution-shell.py`: 14 checks passed.
- `ObservationScopes.tla`: NoError through 6 transitions (3.521 s).
- `StackRecovery.tla`: NoError through 8 transitions (5.310 s).
- `python3 scripts/test-timeline-spec-mutations.py`: all 12 incorrect variants
  rejected by actual invariant counterexamples. The original six models were not
  rerun merely for comment-only changes to their documented assumptions.
- SHA-256 standard vectors and 56 independent hashlib comparisons passed.
- Actual SDK/Windows ABI was inspected and probed; live replay/proxy semantics,
  current proxy implementation and real-dump golden certification remain open.

No R2/R3 v2 implementation, complete mapping provider, persistence container,
attributed access index or causal engine is claimed. The queued gates above are
preserved. This milestone builds on the baseline checkpoint.

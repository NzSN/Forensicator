# Completing timeline knowledge and temporal inference

Date: 2026-09-06

Status: design with bounded host implementation in progress; see the
[task board](../../Drafts/2026-09-06-timeline-task-board.md) for actual completion.

Baseline: commit `68d34bdd6d9e9a322210bc44e8ef7c96c10486c3`
(`feat: introduce execution timeline views and formal contracts`).

Related documents:

- [Implemented execution-point design](2026-09-06-execution-timeline-design.md)
- [Proposed proxy v2 handoff](2026-09-06-proxy-v2-contract-draft.md)
- [Implementation plan and acceptance gates](../../Drafts/2026-09-06-timeline-completion-plan.md)

## 1. Outcome and scope

Complete the information needed to investigate a process across one timeline:
address-space knowledge, exact events, and the stacks/execution contexts of its
threads. Preserve the current small execution-point interface. Modules, symbols,
capture metadata and interpretation settings remain supporting context.

The remaining work has five outcomes:

| Gap | Desired outcome | Current constraint |
|---|---|---|
| Thread stacks | Acquire thread context at a resolved point and populate recovered-frame knowledge | Proxy v1 exposes lifetimes only; capture walkers return analyzer output rather than shared frame knowledge |
| Mappings/lifecycles | Query historical mappings and limit cached facts to their valid allocation/protection epochs | Readable pages and the write index do not establish a complete map or detect every recommit |
| Persistence | Save verified knowledge and reopen it without treating gaps as absent memory | Source identity is currently a path; no durable knowledge format exists |
| Temporal inference | Produce bounded, inspectable explanations connecting writes, uses, frames and exceptions | Interval queries exist, but writer identity, continuity and dependency evidence are incomplete |
| Native validation | Exercise the new interfaces against real captures/replay and reviewed references | `Case/golden` and a configured live Windows trace were absent at the checkpoint |

Source identity, position interpretation, capability negotiation and acquisition
outcomes are shared prerequisites. They are included below because implementing
the five outcomes without them would allow evidence from different recordings or
execution states to be combined.

## 2. Evidence and authority

Current implementation facts are established by
[Execution.lean](../../Forensicator/Model/Execution.lean),
[Proto.lean](../../Forensicator/Trace/Proto.lean), and
[Client.lean](../../Forensicator/Trace/Client.lean). In particular, v1 has no
observed-position echo, register request, mapping request or durable source ID.

The [2026-08-12 investigation](2026-08-12-lazy-trace-proxy-design.md) reports
register APIs and a lack of region enumeration. The later
[header re-pin](../plans/2026-08-15-replay-api-header-repin.md) corrected inaccurate
sample-documentation signatures and query-policy descriptions. The authoritative
implementation handoff must pin the actual SDK headers, proxy revision and replay
DLL, then record Windows probes. The subsequent
[native prerequisite report](../../Drafts/2026-09-06-timeline-native-prerequisites.md)
verifies the actual SDK and x64 ABI and locates a historical extractor/trace and
Windows runner. Current proxy behavior and real golden comparisons remain uncertified.

Microsoft's [TTD concepts](https://github.com/microsoft/WinDbg-Samples/blob/master/TTD/docs/Concepts.md)
describe full native position pairs, adjustment of invalid coordinates, fragment
ordering and speculative callbacks. These motivate the contracts below; exact ABI
declarations must come from the pinned package, not sample snippets. Microsoft
also distinguishes a trace-unique thread ID from the reusable OS TID in its
[thread-object documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/time-travel-debugging-thread-objects).

The actual SDK header promises confidence/consistency, not strict exactness, for
its memory policies. Conservative acquisition therefore requires separate
applicability evidence before exact use. The `QueryExact` abstraction in
[ReplayApi.tla](../../specs/ReplayApi.tla) is an explicit idealized oracle, not a
header guarantee. Buffer-query provenance and thread scheduling are additional
model limits. A recording Sequence alone is weaker than an exact Sequence:Steps
coordinate; search results cannot be promoted to exact points by naming a policy.

## 3. G0 — Identity, positions and acquisition

### Source identity

Introduce two separate identities:

- `SourceId`: a verified content identity for the immutable recording/capture.
- `SessionEpoch`: one attachment to a provider; it changes on reconnect/reload.

Path strings become display aliases. Prefer a provider-reported recording identity
validated against a manifest of immutable trace inputs and content hashes. A group
ID for multiple recorded processes is not a unique process-trace identity. When
the provider cannot establish durable identity, use a session-only ID and disable
cross-session cache reuse. Identical copied recordings may share durable facts;
same-path replacement must never do so.

Record interpretation separately: SDK/DLL/proxy build, memory policy, architecture,
position-semantics revision and relevant layout/decoder revisions. Changes can
invalidate applicability without changing the underlying recording's identity.

Give observations stable IDs and retain byte origin alongside the fast
`AddressSpace` view: captured process bytes, exact replay, supplemental image
artifacts and search/assumption-based results are distinct. Persistence and temporal
rules consume these IDs; they must not infer process observation merely because a
read was satisfied by an on-disk image fallback.

### Native positions and execution-state agreement

The current packed `UInt64` coordinate contains two `UInt32` halves. The proposed
v2 wire carries `Sequence:UInt64` and `Steps:UInt64`, subject to the header/probe
gate. Add a neutral native-position type and explicit lossless v1 conversions;
oversized halves are errors, never truncations. Use explicit exclusive/end-of-trace
bounds rather than overflowing `frontier + 1` sentinels during this migration.

A positioned operation first obtains a `ResolvedPoint`:

```text
source identity + session epoch
requested logical point and semantics revision
actual global native position and exact/adjusted/unavailable outcome
opaque observation token
```

The existing logical view applies writes through its position. Keep that contract
versioned; do not silently replace it with pre-instruction memory. Establish the
native mapping by observing real store, exception and sequence boundaries rather
than assuming arithmetic `p+1` is always the next valid native step.

Registers, stack metadata and memory used together must refer to the same resolved
global observation. Record each thread's own reported position separately: a
non-current thread can have a different last execution position. Its context is
usable only when the provider certifies it as the thread's projection in the
resolved global view. Writer-before-instruction context is a distinct event-side
observation and must not be inserted into an after-write point's register fields.

An adjusted native position is returned explicitly. Exact reads cannot accept it
under the requested identity; navigation may expose an explicit nearest-position
choice. Failed resolution does not move the user's cursor or publish a mixed point.

### Acquisition interface

Keep point inspection free of fetches. A host acquisition module coordinates
bounded reads, context requests, range-index queries and stack recovery. Results
distinguish positive observations, unknown/unrecorded data, unsupported capability,
invalid request, budget exhaustion, cancellation and fatal transport failure.

Only malformed/corrupt transport or a dead provider poisons the session. A valid
unsupported/partial response does not. Retain validated completed chunks after
interruption with their precise coverage. Late replies from an earlier epoch/token
cannot enter current knowledge. Begin with one outstanding operation; request IDs
still identify replies and paginated results. Concurrency is a separate optimization.

## 4. G1 — Thread execution and recovered stacks

### Capture and proxy inputs

Use trace-unique thread identity when available, with OS TID as a label. Capture
thread instances use source/provenance identity; duplicated TIDs cannot silently
select one record. Preserve unknown birth/death bounds.

Extend register knowledge to carry an architecture and validity mask. Known zero
registers differ from missing registers. The capture adapter must respect available
context flags; the external proxy must report which registers it actually supplied.

Probe thread-scoped context retrieval and replay-target TEB access independently.
Stack bounds may come from verified engine metadata or the recorded thread's
NT_TIB under the resolved observation. A readable range containing RSP is useful
memory evidence, but is not by itself a certified complete stack range. Fibers,
stack switching, growth, inactive threads and thread-ID reuse are required cases.

### One recovery module and one retained result

Extract reusable native stack recovery from the current V8 walk into a host-side
pure module. Retain V8/JIT enrichment as consumers of recovered frames and their
supporting runtime evidence. The recovery interface should expose missing inputs:

```text
recoverStack(context, knownMemory, moduleArtifacts, budget)
  -> frames + dependenciesNeeded + coverage + stopReason + evidence
```

The acquisition module closes only requested dependencies and reruns the pure
recovery step. It records frames in `ThreadState.frames`; `stack`, `inspect`, V8
and JIT then share that result. Avoid an independent second stack cache hidden in
an analyzer. Each result records its point, thread instance, register observation,
memory facts, unwind artifacts, algorithm revision and optional V8 layout revision.

Frame dependencies include verified PE unwind data where applicable. Missing
symbols can leave names unavailable while retaining supported frame addresses.
Unknown V8 layout cannot become a guessed JS frame. Preserve useful partial frames
when later frames require unavailable bytes or unsupported unwind instructions.

Stop reasons include validated root, missing context, missing memory, unsupported
metadata, cycle/corruption, invalid stack transition and exhausted budget. Only a
validated terminal condition makes recovery complete; a zero-filled fallback or
empty list does not. Cache frames at exact points initially. Reuse across positions
requires unchanged registers and all memory/artifact dependencies.

Proposed interaction: `stack <thread> [--at <position>]` acquires a bounded stack;
`inspect` reports existing knowledge. Ambiguous TIDs require an instance selection.

## 5. G2 — Historical mappings and lifecycle evidence

Keep three questions separate:

1. Which bytes are known/readable at a point?
2. Which mapping state/protection/type facts are observed there?
3. Which intervals have complete coverage of allocation/protection changes?

A feasibility task must establish an actual replay-target metadata provider.
Candidate routes include supported recorded metadata and recorder instrumentation.
Neither current host `VirtualQueryEx`, module lists nor touched-page enumeration
is a complete historical process map. If the backend lacks a complete inventory
route, ship partial mapping queries and keep the full-inventory capability false.
Record a separate recorder/instrumentation proposal instead of inventing coverage.

Represent mapping instances and epochs with source, address range, observed state,
protection/type availability, lifetime/change bounds and evidence. Completeness is
relative to an explicit address/time domain. Known byte coverage remains independent.

For reusable byte pieces, intersect the write-index interval with certified
lifecycle/protection validity and source/interpretation scope. Free/recommit or
same-address allocation reuse invalidates the previous epoch even if bytes happen
to match. Without lifecycle coverage, strict reuse is point-only; the existing
index-only interval rule remains explicitly assumption-based, not certified truth.

NewData/Overwrite callbacks are candidates for detecting changes, not proof of
complete allocation history. Unknown gaps end certified coverage. A range scan
becomes complete only when the provider confirms its entire interval; a returned
late hit or speculative callback is not a completion certificate.

Proposed interaction: `mappings [address length] [--at position]` shows observed
ranges and coverage. It must explain uncovered domains instead of showing them as
free. Full enumeration is enabled only by a verified capability and terminal marker.

## 6. G3 — Persistent knowledge

Persistence stores evidence, not reconstructed full traces. Introduce a distinct
versioned `FTLC` cache container; `.ttfx` remains rejected. Start with explicit
`cache save <path>` and `load --cache <path>` routes rather than implicit writes.

The format contains a source/interpretation manifest, typed length-delimited
chunks, integrity digests and a committed manifest/footer. Store exact point bytes
and absence, index windows with coverage, module identities, thread observations,
mapping epochs and derived results with dependency revisions. Never serialize a
missing read as zero data, incomplete coverage as complete, or a process handle.

The initial milestone persists exact observations only. Persist interval reuse
certificates after G2 can validate them; a saved index horizon alone is insufficient.
Unresolved, assumed and confirmed evidence retain their distinct status on reload.

Write a temporary generation, flush/close it, and atomically publish it. Specify
atomic visibility separately from power-loss durability; verify the actual Lean/OS
flush primitives before promising the latter. Bound chunk sizes, total bytes,
counts and decompression work. Begin without compression to keep parsing auditable.
Use SHA-256 for content and chunk identity. The external provider computes trace
manifests using platform crypto. The host uses a streaming total implementation,
checked against standard vectors and an independent platform implementation, so
offline cache loading does not require a new runtime command or Lean dependency.

On restore, verify the container, source ID and interpretation compatibility before
facts become usable. Reject or quarantine corrupt chunks with explicit gaps; do not
silently trust the remaining footer after truncation. Recompute derived frames and
findings when a dependency or algorithm/layout revision differs.

An offline cache describes the original verified source identity. It does not
assert that a file currently at an old path is unchanged. Missing offline knowledge
remains unknown, and unavailable live capabilities are reported honestly.

## 7. G4 — Temporal explanations

### Evidence before verdicts

Introduce stable evidence and finding IDs, scoped to source, point/range and
interpretation. Separate directly observed facts, supported derivations and
candidates. Each temporal result includes supporting IDs, missing dependencies,
coverage, alternatives and a ranking/confidence indication with its meaning stated.

An explanation graph can initially contain these relationships:

| Relationship | Evidence required |
|---|---|
| Recorded before/after | Valid positions and the recorded ordering convention |
| Same-thread program order | Thread-instance identity and continuity |
| Wrote a byte range | Confirmed write occurrence and exact affected range |
| Same allocation instance | Certified lifecycle/epoch evidence |
| Value reaches a recorded use | Read/write value evidence, appropriate ordering and complete relevant write coverage |
| Frame was active at an event | Context with the correct event side/point and supported stack recovery |
| Candidate explanation | Explicitly listed missing premises; never upgraded solely by temporal proximity |

Retain every intervening write for `0 -> 1 -> 0`; equal endpoints do not remove
history. An address reused by another allocation does not preserve object identity.
Recorded fragment order is useful for navigation but cannot alone establish a
hardware ordering or cross-thread causal dependency. Gap/continuity evidence is
required before asserting a complete same-thread chain across missing recording.
Matching byte values alone do not identify the writer. Preserve alternative writes
when the evidence does not distinguish them, and label whether a supported relation
is established under replay ordering or stronger observed synchronization evidence.
The distinction follows the documented
[TTD execution model](https://github.com/microsoft/WinDbg-Samples/blob/master/TTD/docs/Concepts.md#timeline-positions-and-execution-model).

### Writer and access identity

Extend index records with a stable access identity, thread instance, instruction
address and available before/after access data. Stability must hold across paging,
overlapping queries and speculative callback re-observation. If the backend cannot
distinguish same-position occurrences, return an ambiguous group rather than
inventing an ordinal from response order. Redesign index dedup/order proofs together
with this contract; the current `(pos,va,len)` key is not sufficient for attribution.

Begin with bounded history and candidate explanations over existing write/event
queries. Stronger value-flow edges require read/access evidence and supported
instruction semantics; unsupported x64/V8 cases remain unresolved. Use the current
cause analyzer's point verdict as an input finding, not as proof of its own history.

Proposed commands:

```text
history <address> <length> --from <a> --to <b>
explain --event <event-id> --from <a> [--budget <limit>]
```

Every query has limits on scanned interval, access count, bytes, frames and graph
nodes. A truncated result identifies what was checked and offers a continuation;
it does not claim there was no earlier writer. The first release targets short
memory-corruption trails, then expands supported dependency rules incrementally.
For compatibility, a current-point event index can resolve to a stable occurrence
at dispatch; background acquisition must not change what the selection identifies.

## 8. G5 — Validation and formal contracts

Before widening functionality, recover or provision the real fixture suite and a
pinned Windows runner. Compare the checkpoint against existing references and
review intentional parser/scanning/diagnosis changes before any golden update.
Add independent WinDbg comparisons at exact native/thread positions; do not use
the new proxy as its own sole oracle.

Required scenarios include source replacement/rename, adjusted positions, sequence
boundaries, hard exceptions, current/non-current threads, reused TIDs, stack growth,
module reload, mapping/protection changes, recommit without writes, incomplete
queries, speculative/repeated access records, interrupted acquisition, corrupted
cache generations and results larger than reusable caches.

Keep platform-free fake-provider tests and byte-pinned protocol vectors. Update
shipping Lean invariants and TLA+ models alongside each interface change:

- Identity/capabilities: source/epoch/token agreement and explicit normalization.
- Threads: same-observation context, validity masks, lifetime identity and partial recovery.
- Mappings: known versus absent versus unreadable, epoch invalidation and coverage gaps.
- Persistence: no invented facts after restore; committed generations and identity checks.
- Temporal reasoning: supported edges require all premises; gaps prohibit unjustified
  certainty, and ordering alone cannot create a causal edge.

Use mutation controls that deliberately mix source/point/thread contexts, accept
stale epochs, restore corrupt chunks, deduplicate distinct writes, or create causal
edges without premises. State model bounds and external assumptions separately from
native validation. The existing six models remain the regression baseline.

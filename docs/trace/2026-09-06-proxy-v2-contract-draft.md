# Proxy v2 contract draft for timeline completion

Date: 2026-09-06

Status: proposed host/external-proxy handoff. Request names and semantics below
are design decisions, not claims about a shipped Windows implementation.

Baseline: `68d34bdd6d9e9a322210bc44e8ef7c96c10486c3`.

See the [completion design](2026-09-06-timeline-completion-design.md) and
[plan](../../Drafts/2026-09-06-timeline-completion-plan.md). Actual SDK ABI calls,
limits and observation semantics must pass task R0 before byte vectors are frozen.

## 1. Compatibility and framing

Preserve v1 exactly. A v2-capable server supports an explicitly selected major
version; v1 clients still receive the existing v1 handshake and inventories.
The first v2 client release uses an explicit protocol selection. It does not
interpret EOF, a crash or a framing failure as permission to silently downgrade.

Keep the outer frame convention: little-endian `body_length:u32`, `tag:u32`, then
payload. `HELLO` remains a special handshake frame containing the requested major
version. `HELLO(2)` selects v2; the v2 acknowledgment starts with major/minor and
the fields below. Existing v1 acknowledgment bytes are never extended in place.
For ordinary v2 messages, the payload begins with `request_id:u64` before the
request/response body. ID zero is reserved for the handshake and is not reused.

Initial limits: one outstanding work request, negotiated maximum frame/body/items,
and bounded batches with continuations. A request-completion flag does not imply
complete evidence coverage. Unknown required fields/capability revisions are
rejected; optional extensions need explicit lengths so they can be skipped safely.
R2 assigns numeric message tags, canonical field order and byte-pinned vectors.

## 2. Session and capability acknowledgment

The v2 acknowledgment supplies:

- Major/minor protocol and implementation identity.
- Session epoch and source identity class: session-only or verified content ID.
- Native first/last positions and position-semantics revision.
- Guest architecture and supported register schema.
- Capability descriptors and effective query budgets/limits.
- SDK/header/DLL/proxy build identifiers needed to interpret evidence.

A strong source identity may be established later by `SOURCE_MANIFEST`. Expensive
hashing must not block a minimal session handshake indefinitely. Promotion from a
session-only ID requires an explicit binding certificate for the same immutable
loaded inputs; it is not accomplished by changing the source name string.

V2 obtains the thread/lifetime and event skeleton through bounded `INVENTORY`
responses after the acknowledgment. An inventory selector is `all`, `at(point)` or
`between(a,b]`; `all` includes occurrences at the trace's first position. The host
records partial inventory coverage if an attachment budget stops pagination.
Missing inventory entries then remain unknown. Initialize the cursor from the
reported first valid point and resolution result, not an assumed numeric zero.

Capabilities are independently versioned. Unsupported capabilities stay false:

| Capability | Meaning |
|---|---|
| `source_manifest` | Verifiable recording identity and immutable input manifest |
| `resolve_exact_point` | Requested/actual position agreement can be established |
| `thread_context` | Thread-specific register observations with validity information |
| `thread_stack_bounds` | Bounds from replay-target evidence, not merely an RSP-containing page |
| `memory_exact` | Separately established applicability at the requested point; policy choice alone is insufficient |
| `memory_recording_provenance` | Actual range-level recording metadata, with its precision stated |
| `mapping_at` | Historical mapping observations for requested ranges |
| `mapping_history` | Observed allocation/protection transitions with coverage |
| `complete_mapping_inventory` | Complete enumeration within a declared domain, only after independent verification |
| `stable_access_ids` / `writer_context` | Stable access identity and available writer attribution |
| `read_accesses` / `continuity` | Observed uses and recording-gap coverage for stronger explanations |
| `cancel_request` | Cooperative cancellation; otherwise the host terminates the child and reconnects |

## 3. Shared data types

`NativePosition` uses two unsigned 64-bit components. R0a has verified this
against the actual SDK and Windows x64 ABI; see the
[native report](../../Drafts/2026-09-06-timeline-native-prerequisites.md). Legacy packed positions convert only
when both halves are representable; conversion never wraps or truncates. A recording
Sequence is encoded as a different provenance variant, never fabricated into a
full native position with Steps set to zero.

`SourceId` is a tagged identity, separate from its display path and session epoch.
`ThreadInstanceId` uses the trace-unique ID when exposed; OS TID is a separate
label. Unknown lifetime endpoints use tags, not overloaded maximal positions.

Address ranges are half-open. Their exclusive end has an explicit top-of-address-
space variant so the last virtual byte can be represented without u64 overflow.
Time ranges state their endpoint convention; write/event windows use `(a,b]`.
The native SDK PositionRange is closed, so its results need an explicit host
endpoint translation/filter rather than direct reuse of host interval semantics.
Opaque point/continuation tokens are valid only within their source and epoch.

Every positioned result carries:

```text
request_id, source identity, session epoch, observation token
requested logical point + semantics revision
actual global native position
thread instance + reported thread position, when applicable
query policy, data origin, applicability/coverage
recording provenance, only at the precision actually exposed
```

For all-thread state, the actual per-thread position can differ from the global
position. The provider must establish that the context belongs to that global
view. The host must not infer that an arbitrary earlier context remained unchanged.

Registers have architecture, register IDs/widths, values and a validity mask.
Absent registers are not transmitted as authoritative zero-valued slots. Start
with the x64 state required by native unwinding; vector state is a separate schema.

## 4. Operations

| Request | Required result and meaning |
|---|---|
| `SOURCE_MANIFEST` | Source identity, immutable input manifest, verification status and interpretation/build metadata |
| `INVENTORY(section, selector, continuation)` | Thread instances/lifetimes or event occurrences with stable IDs, bounds and inventory coverage |
| `RESOLVE_POINT` | Exact, adjusted, out-of-range or unavailable result; actual coordinate and observation token |
| `THREAD_STATE(token, instances, register_set)` | Per-thread known/unavailable fields, global/thread positions, TEB/bounds evidence when supported |
| `READ_EXACT(token, ranges)` | Owned byte chunks, explicit gaps/outcomes and certified applicability to the token |
| `MODULES_AT(token)` | Active instance descriptors plus available artifact identities; no guessed PDB match |
| `MAPPINGS_AT(token, ranges)` | Observed state/protection/type, unknown fields, declared domain and coverage |
| `MAPPING_CHANGES(ranges, interval)` | Epoch transitions, continuity gaps and confirmed coverage |
| `ACCESS_INDEX(ranges, interval, mask, continuation)` | Access occurrences/groups, attribution, stable IDs when supported and confirmed coverage |
| `CANCEL(request_id)` | Acknowledged completion/cancellation boundary when supported |
| `CLOSE` | End the epoch and release provider resources |

An exact read and thread-context request under one token use the same resolved
global view. Keep memory's current post-write logical convention explicit. For
writer-before-instruction observations, the request and response name that event
side separately; those registers cannot overwrite the point's after-write context.
The host can acquire relevant inventory explicitly when an events/threads query
needs more coverage. Cache-only point inspection does not perform that acquisition.

The server copies cursor-owned memory/context buffers before subsequent queries
invalidate them. No borrowed pointer or opaque host address enters the wire format.

## 5. Memory, mapping and coverage outcomes

Normal query outcomes include `known`, `unmapped_certified`, `not_recorded`,
`unreadable`, `partial`, `unsupported`, `invalid_point`, `invalid_thread`,
`budget_exhausted` and `cancelled`. These are distinct from fatal framing/transport
errors. A generic missing buffer or failed call is never promoted to unmapped.

For each range, return disjoint covered chunks and explicit unresolved portions.
Short data is not padded with zeros. The host validates source/token, lengths,
range arithmetic, ordering, coverage claims and data digests before merging facts.

The actual header does not make conservative policy an exactness guarantee.
Use it as an acquisition policy, then require separate applicability evidence for
`memory_exact`; otherwise return reported/uncertified or unavailable knowledge.
Search-policy results remain separately tagged observations. Range recording
provenance may help prove applicability but does not itself establish a complete
mapping or exact time-point value. A matching Sequence alone is insufficient.

Mapping data identifies observed state, protection and type independently; a
readable page does not fill missing flags. Inventory completeness requires a
declared address domain and verified terminal coverage. Lifecycle completeness
requires evidence through the requested time interval, including gaps. A callback
named NewData is not automatically an allocation event or a completeness proof.

`ACCESS_INDEX` distinguishes stable occurrences from ambiguous groups. A provider
must not assign cross-query IDs from response-local row numbers. Speculative hits
and repeated callbacks cannot advance confirmed coverage. Confirmed records are
ordered under the stated replay convention; same-position ambiguity stays explicit.
Only a completed, gap-free relevant window supports a negative claim such as no
intervening writer. Writer thread/IP, access values and before/after side are optional
evidence fields whose absence reduces the explanations that may be supported.

## 6. Failure and lifetime rules

- Local argument validation happens before requests are sent.
- Unsupported/invalid/partial outcomes leave the session usable.
- A timeout or explicit cancellation closes the request. If cooperative cancellation
  cannot be verified, terminate the provider and open a new epoch.
- Replies from old epochs or expired tokens are never merged into the new session.
- Corrupt framing, impossible correlation or contradictory source identity ends the
  affected connection; these are not ordinary unavailable-memory responses.
- Completed, validated observations are immutable. An interrupted later query cannot
  rewrite a published point or upgrade its incomplete coverage.

The host retains all cursor/navigation policy. It decides what to acquire and what
can be inferred; the proxy reports observations and their limits. A future cursor
pool must preserve these contracts rather than changing their meaning.

## 7. Handoff evidence required before implementation is certified

R0/R1 deliver an actual SDK/proxy/DLL pin, native position/phase transcript,
capability report, field/limit table, golden byte vectors and independent Windows
comparisons. Include current and non-current threads, invalid/normalized positions,
store/exception/sequence boundaries, missing context, partial reads, thread reuse,
speculative access duplication and interrupted requests. Keep proxy v1 transcript
tests unchanged. Unknown features remain advertised as unsupported.

The current proxy remains missing despite discovery of a historical extractor,
trace, runner and verified SDK ABI. These contracts are an implementation handoff,
not evidence that an external proxy already satisfies them.

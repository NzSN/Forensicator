---- MODULE ObservationScopes ----
EXTENDS Naturals, FiniteSets

\* Bounded stateful counterpart of Model/Observation.lean (2026-09-06).
\* The controller owns attachment epochs, reply acceptance and certification.
\* Live correlation is stricter than durable evidence reuse. A verified source
\* identity is an ADAPTER TRUST assertion, not a decoded digest or path label.
\* adapterValidated abstracts independent external applicability validation;
\* this model proves neither native replay exactness nor cryptographic identity.
\* A successful memory policy does not supply that assertion.
\*
\* Bounds: two content/process/interpretation IDs and epochs, two trace points,
\* a distinct capture tag, two thread instances plus no-thread, three phases.
\* Point integers abstract resolved native coordinates; no p+1 navigation rule.
\* The requested point may differ from the resolved observation. Only the latter
\* participates in applicability. A whole scope can change in one rebind step.

SourceKinds == {"session", "claimed", "verified"}
Phases == {"unknown", "before", "after"}
Origins == {"recorded", "replay", "artifact", "derived"}
Policies == {"default", "threadLocal", "conservative", "aggressive"}

\* @type: Set([kind: Str, position: Int]);
Points == {[kind |-> "capture", position |-> 0]} \cup
          {[kind |-> "trace", position |-> p] : p \in 0..1}

\* @type: Set([sourceKind: Str, content: Int, process: Int, epoch: Int,
\*   point: [kind: Str, position: Int], thread: Int, interpretation: Int, phase: Str]);
Scopes == [sourceKind : SourceKinds, content : 1..2, process : 1..2,
           epoch : 0..1, point : Points, thread : 0..2,
           interpretation : 1..2, phase : Phases]

VARIABLES
    \* @type: [sourceKind: Str, content: Int, process: Int, epoch: Int,
    \*   point: [kind: Str, position: Int], thread: Int, interpretation: Int, phase: Str];
    observed,
    \* @type: [sourceKind: Str, content: Int, process: Int, epoch: Int,
    \*   point: [kind: Str, position: Int], thread: Int, interpretation: Int, phase: Str];
    target,
    \* @type: [kind: Str, position: Int];
    requestedPoint,
    \* @type: Str;
    origin,
    \* @type: Str;
    policy,
    \* @type: Bool;
    adapterValidated,
    \* @type: Bool;
    certified,
    \* @type: Bool;
    liveAccepted,
    \* @type: Bool;
    reuseAccepted,
    \* @type: Bool;
    exactAccepted

scopeVars == <<observed, target, requestedPoint, origin, policy,
               adapterValidated, certified, liveAccepted, reuseAccepted, exactAccepted>>

\* Equality includes identity class: an unverified claim cannot be promoted by
\* finding the same digest in a verified attachment. Process selectors matter.
\* @type: ([sourceKind: Str, content: Int, process: Int, epoch: Int,
\*   point: [kind: Str, position: Int], thread: Int, interpretation: Int, phase: Str],
\*   [sourceKind: Str, content: Int, process: Int, epoch: Int,
\*   point: [kind: Str, position: Int], thread: Int, interpretation: Int, phase: Str]) => Bool;
SameSource(a, b) ==
    /\ a.sourceKind = b.sourceKind
    /\ a.content = b.content
    /\ a.process = b.process

\* @type: ([sourceKind: Str, content: Int, process: Int, epoch: Int,
\*   point: [kind: Str, position: Int], thread: Int, interpretation: Int, phase: Str],
\*   [sourceKind: Str, content: Int, process: Int, epoch: Int,
\*   point: [kind: Str, position: Int], thread: Int, interpretation: Int, phase: Str]) => Bool;
Reusable(a, b) ==
    /\ SameSource(a, b)
    /\ a.epoch = b.epoch \/ a.sourceKind = "verified"
    /\ a.point = b.point
    /\ a.thread = b.thread
    /\ a.interpretation = b.interpretation
    /\ a.phase = b.phase

ObservationInit ==
    /\ observed \in Scopes
    /\ target = observed
    /\ requestedPoint \in Points
    /\ origin \in Origins
    /\ policy \in Policies
    /\ adapterValidated \in BOOLEAN
    /\ certified = FALSE
    /\ liveAccepted = FALSE /\ reuseAccepted = FALSE /\ exactAccepted = FALSE

\* Only a trusted controller performs this transition. An arbitrary wire claim,
\* syntactically valid digest, or high-confidence policy cannot enable it.
Certify ==
    /\ adapterValidated
    /\ certified' = TRUE
    /\ UNCHANGED <<observed, target, requestedPoint, origin, policy,
                   adapterValidated, liveAccepted, reuseAccepted, exactAccepted>>

\* Request/response token checks are an additional transport obligation; all
\* modeled scope fields, including attachment epoch, must match a live reply.
AcceptLive ==
    /\ observed = target
    /\ liveAccepted' = TRUE
    /\ UNCHANGED <<observed, target, requestedPoint, origin, policy,
                   adapterValidated, certified, reuseAccepted, exactAccepted>>

AcceptStored ==
    /\ Reusable(observed, target)
    /\ reuseAccepted' = TRUE
    /\ UNCHANGED <<observed, target, requestedPoint, origin, policy,
                   adapterValidated, certified, liveAccepted, exactAccepted>>

PublishExact ==
    /\ Reusable(observed, target)
    /\ certified
    /\ observed.phase # "unknown"
    /\ origin \in {"recorded", "replay"}
    /\ exactAccepted' = TRUE
    /\ UNCHANGED <<observed, target, requestedPoint, origin, policy,
                   adapterValidated, certified, liveAccepted, reuseAccepted>>

\* Rebinding clears current-view acceptances. Stored observations survive and
\* can be reconsidered by AcceptStored; stale live replies still need equality.
Rebind ==
    /\ target' \in Scopes
    /\ liveAccepted' = FALSE /\ reuseAccepted' = FALSE /\ exactAccepted' = FALSE
    /\ UNCHANGED <<observed, requestedPoint, origin, policy, adapterValidated, certified>>

ChangePolicy ==
    /\ policy' \in Policies
    /\ UNCHANGED <<observed, target, requestedPoint, origin,
                   adapterValidated, certified, liveAccepted, reuseAccepted, exactAccepted>>

ObservationNext ==
    Certify \/ AcceptLive \/ AcceptStored \/ PublishExact \/ Rebind \/ ChangePolicy

TypeOk ==
    /\ observed \in Scopes /\ target \in Scopes /\ requestedPoint \in Points
    /\ origin \in Origins /\ policy \in Policies
    /\ adapterValidated \in BOOLEAN /\ certified \in BOOLEAN
    /\ liveAccepted \in BOOLEAN /\ reuseAccepted \in BOOLEAN /\ exactAccepted \in BOOLEAN

TrustedCertification == certified => adapterValidated
LiveAttachment == liveAccepted => observed = target

\* Spell fields independently of Reusable so weakening that gate is detectable.
ReuseScope ==
    (reuseAccepted \/ exactAccepted) =>
      /\ observed.sourceKind = target.sourceKind
      /\ observed.content = target.content /\ observed.process = target.process
      /\ observed.epoch = target.epoch \/ observed.sourceKind = "verified"
      /\ observed.point = target.point /\ observed.thread = target.thread
      /\ observed.phase = target.phase
      /\ observed.interpretation = target.interpretation

ExactRequiresEvidence ==
    exactAccepted =>
      /\ certified /\ adapterValidated
      /\ observed.phase # "unknown"
      /\ origin \in {"recorded", "replay"}

\* A normalized reply cannot serve the original point when the two differ.
RequestedIsNotResolved ==
    (exactAccepted /\ requestedPoint # observed.point) => target.point # requestedPoint

ObservationInvariant ==
    /\ TypeOk /\ TrustedCertification /\ LiveAttachment /\ ReuseScope
    /\ ExactRequiresEvidence /\ RequestedIsNotResolved

ObservationSpec == ObservationInit /\ [][ObservationNext]_scopeVars
=============================================================================

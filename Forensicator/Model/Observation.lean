/- Shared observation-scope primitives for the native-coordinate migration.
   These do not replace ExecutionPoint or install a second evidence store.
   SDK pin: Microsoft.TimeTravelDebugging.Apis 0.9.5, IReplayEngine.h:375–400.
   Native positions have two u64 components and lexicographic comparison.
   Certification constructors below are a trusted adapter boundary, not evidence
   that parsing a digest or receiving replay bytes verifies their applicability. -/
import Forensicator.Basic
import Forensicator.Util.Digest

namespace Forensicator.Model.Observation

/-- Lossless native coordinate. A representable coordinate need not exist in a
    recording; resolution and instruction navigation remain provider operations. -/
structure NativePosition where
  sequence : UInt64
  steps : UInt64
  deriving Repr, DecidableEq, BEq, Inhabited

namespace NativePosition

instance : LT NativePosition where
  lt a b := a.sequence.toNat < b.sequence.toNat ∨
    (a.sequence = b.sequence ∧ a.steps.toNat < b.steps.toNat)

instance : LE NativePosition where
  le a b := a.sequence.toNat < b.sequence.toNat ∨
    (a.sequence = b.sequence ∧ a.steps.toNat ≤ b.steps.toNat)

instance (a b : NativePosition) : Decidable (a < b) :=
  inferInstanceAs (Decidable (_ ∨ _))

instance (a b : NativePosition) : Decidable (a ≤ b) :=
  inferInstanceAs (Decidable (_ ∨ _))

instance : Ord NativePosition where
  compare a b := match compare a.sequence.toNat b.sequence.toNat with
    | .eq => compare a.steps.toNat b.steps.toNat
    | result => result

/-- Hexadecimal `Sequence:Steps`, preserving all 64 bits of both components. -/
def format (p : NativePosition) : String :=
  hexPadUpper p.sequence 1 ++ ":" ++ hexPadUpper p.steps 1

instance : ToString NativePosition := ⟨format⟩

/-- Every v1 packed coordinate has an exact native representation. -/
def fromLegacy (p : Position) : NativePosition :=
  ⟨UInt64.ofNat (p.toNat / posRadix), UInt64.ofNat (p.toNat % posRadix)⟩

/-- Reject oversized halves; never truncate a native position to v1. -/
def toLegacy (p : NativePosition) : Option Position :=
  if p.sequence.toNat < posRadix ∧ p.steps.toNat < posRadix then
    some (UInt64.ofNat (p.sequence.toNat * posRadix + p.steps.toNat))
  else none

theorem lt_irrefl (p : NativePosition) : ¬p < p := by
  change ¬(_ ∨ _)
  omega

theorem lt_trans {a b c : NativePosition} (hab : a < b) (hbc : b < c) : a < c := by
  change _ ∨ _ at hab hbc ⊢
  rcases hab with hab | ⟨hab, hab'⟩ <;> rcases hbc with hbc | ⟨hbc, hbc'⟩
  · exact Or.inl (Nat.lt_trans hab hbc)
  · exact Or.inl (hbc ▸ hab)
  · exact Or.inl (hab ▸ hbc)
  · exact Or.inr ⟨hab.trans hbc, Nat.lt_trans hab' hbc'⟩

theorem toLegacy_fromLegacy (p : Position) : (fromLegacy p).toLegacy = some p := by
  have hp : p.toNat < 2 ^ 64 := p.toNat_lt_size
  have hs : p.toNat / posRadix < 2 ^ 64 := by simp only [posRadix]; omega
  have ht : p.toNat % posRadix < 2 ^ 64 := by simp only [posRadix]; omega
  have hs' : p.toNat / posRadix < posRadix := by simp only [posRadix]; omega
  have ht' : p.toNat % posRadix < posRadix := by simp only [posRadix]; omega
  simp only [fromLegacy, toLegacy, UInt64.toNat_ofNat_of_lt' hs,
    UInt64.toNat_ofNat_of_lt' ht, hs', ht', and_self, ↓reduceIte]
  have he : p.toNat / posRadix * posRadix + p.toNat % posRadix = p.toNat := by
    simp only [posRadix]
    omega
  rw [he]
  simp

end NativePosition

/-- Endpoint tags preserve both closed native ranges and half-open host ranges.
    In particular, an inclusive maximum does not require a fabricated successor. -/
inductive NativeUpperBound where
  | exclusive (point : NativePosition)
  | inclusive (point : NativePosition)
  | unbounded
  deriving Repr, DecidableEq, BEq, Inhabited

def NativeUpperBound.contains (bound : NativeUpperBound) (p : NativePosition) : Bool :=
  match bound with
  | .exclusive last => decide (p < last)
  | .inclusive last => decide (p ≤ last)
  | .unbounded => true

structure NativeInterval where
  start : NativePosition
  stop : NativeUpperBound
  deriving Repr, DecidableEq, BEq, Inhabited

def NativeInterval.contains (interval : NativeInterval) (p : NativePosition) : Bool :=
  decide (interval.start ≤ p) && interval.stop.contains p

inductive NativePoint where
  | capture
  | trace (position : NativePosition)
  deriving Repr, DecidableEq, BEq, Inhabited

/-- Digest of the canonical immutable-input manifest, plus its unique process
    selector. A recording containing several processes must distinguish them. -/
structure ContentIdentity where
  manifestDigest : Digest256
  processKey : String
  deriving Repr, DecidableEq, BEq

/-- `verifiedContent` may only be constructed by a trusted controller after it
    binds the current attachment to a verified immutable manifest. This module
    cannot prove external file immutability, process selection, or a provider's
    attestation. Never decode this constructor directly from untrusted wire data. -/
inductive SourceIdentity where
  | sessionOnly (nonce : String)
  | claimedContent (content : ContentIdentity)
  | verifiedContent (content : ContentIdentity)
  deriving Repr, DecidableEq, BEq

/-- Syntax validation produces an unverified claim, never a durable identity. -/
def SourceIdentity.parseClaim (digestHex processKey : String) : Option SourceIdentity := do
  let digest ← Digest256.ofHex digestHex
  if processKey.isEmpty then none
  else some (.claimedContent ⟨digest, processKey⟩)

/-- Display paths do not participate in evidence identity or reuse. -/
structure SourceAlias where
  displayPath : String
  deriving Repr, DecidableEq, BEq, Inhabited

/-- Controller-issued attachment generation. Controllers must use fresh epochs
    across reconnects/restarts; a persisted session-only ID cannot manufacture a
    matching live epoch. -/
structure AttachmentEpoch where
  value : Nat
  deriving Repr, DecidableEq, BEq, Inhabited

def SourceIdentity.isDurable : SourceIdentity → Bool
  | .verifiedContent _ => true
  | _ => false

/-- Reuse checks equality of the identity class as well as its content. Claimed
    or session-only sources cannot be restored into a different attachment. -/
def SourceIdentity.canReuse (stored current : SourceIdentity)
    (storedEpoch currentEpoch : AttachmentEpoch) : Bool :=
  decide (stored = current) && (decide (storedEpoch = currentEpoch) || stored.isDurable)

/-- A trace-unique thread ID differs from the reused OS TID label. Captures bind
    thread identity to a distinct source record and its row, not just an OS TID. -/
inductive ThreadInstanceKey where
  | trace (uniqueId : UInt32)
  | capture (recordOffset : UInt64) (row : Nat)
  deriving Repr, DecidableEq, BEq, Inhabited

/-- Fingerprint of the canonical interpretation manifest: architecture, semantics
    revision, SDK/DLL/proxy builds, register/unwind schema and relevant settings.
    Equality is deliberately conservative; compatibility needs a separate proof. -/
structure InterpretationId where
  manifestDigest : Digest256
  deriving Repr, DecidableEq, BEq

/-- Phase is explicit and versioned by the interpretation. Unknown phase is never
    silently promoted to before/after instruction or after-write semantics. -/
inductive NativePhase where
  | unknown
  | captured
  | beforeInstruction
  | duringAccess
  | afterInstruction
  | afterWrite
  deriving Repr, DecidableEq, BEq, Inhabited

structure ObservationScope where
  source : SourceIdentity
  epoch : AttachmentEpoch
  point : NativePoint
  thread : Option ThreadInstanceKey
  interpretation : InterpretationId
  phase : NativePhase
  deriving Repr, DecidableEq, BEq

/-- A live reply must belong to the same attachment and resolved observation.
    Transport request/token correlation is an additional controller obligation. -/
def ObservationScope.matchesLive (stored current : ObservationScope) : Bool :=
  decide (stored = current)

/-- Durable facts may survive attachment changes, but never changes to point,
    thread instance, semantics phase or interpretation. -/
def ObservationScope.canReuse (stored current : ObservationScope) : Bool :=
  stored.source.canReuse current.source stored.epoch current.epoch
    && decide (stored.point = current.point)
    && decide (stored.thread = current.thread)
    && decide (stored.interpretation = current.interpretation)
    && decide (stored.phase = current.phase)

theorem ObservationScope.matchesLive_iff (a b : ObservationScope) :
    a.matchesLive b = true ↔ a = b := by
  simp [ObservationScope.matchesLive]

theorem ObservationScope.canReuse_point (a b : ObservationScope)
    (h : a.canReuse b = true) : a.point = b.point := by
  simp only [ObservationScope.canReuse, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.1.1.2

theorem SourceIdentity.sessionOnly_reuse_epoch (nonce : String)
    (a b : AttachmentEpoch)
    (h : (SourceIdentity.sessionOnly nonce).canReuse (.sessionOnly nonce) a b = true) :
    a = b := by
  simpa [SourceIdentity.canReuse, SourceIdentity.isDurable] using h

/-- Names match SDK 0.9.5 policies. Even globallyConservative promises confidence,
    not exact point-state bytes. Policy is provenance, never certification. -/
inductive MemoryQueryPolicy where
  | unspecified
  | sdkDefault
  | threadLocal
  | globallyConservative
  | globallyAggressive
  | inFragmentAggressive
  deriving Repr, DecidableEq, BEq, Inhabited

inductive ObservationOrigin where
  | unknown
  | recordedProcess
  | replayReconstruction
  | artifact
  | derived
  deriving Repr, DecidableEq, BEq, Inhabited

/-- `certifiedAtResolvedPoint` is an assertion from the trusted adapter, after
    verifying requested/actual semantics, thread projection and data provenance.
    It is not established by a successful SDK query or by a policy name. -/
inductive ExactApplicability where
  | uncertified
  | certifiedAtResolvedPoint
  deriving Repr, DecidableEq, BEq, Inhabited

structure ObservationMetadata where
  scope : ObservationScope
  /-- Original request; `scope.point` records the actual resolved observation. -/
  requestedPoint : NativePoint
  policy : MemoryQueryPolicy := .unspecified
  origin : ObservationOrigin := .unknown
  applicability : ExactApplicability := .uncertified
  deriving Repr, DecidableEq, BEq

/-- Exact process-state use requires explicit certification and matching scope.
    Artifact and derived bytes are never promoted to observed process memory.
    A normalized observation may be used at its actual point only; comparison
    against the original requested point naturally fails when they differ. -/
def ObservationMetadata.exactProcessAt (observation : ObservationMetadata)
    (target : ObservationScope) : Bool :=
  observation.scope.canReuse target
    && observation.applicability == .certifiedAtResolvedPoint
    && observation.scope.phase != .unknown
    && (observation.origin == .recordedProcess || observation.origin == .replayReconstruction)

/-- Query-policy selection cannot create an exactness guarantee. -/
theorem ObservationMetadata.exactProcessAt_policy (observation : ObservationMetadata)
    (target : ObservationScope) (policy : MemoryQueryPolicy) :
    ({ observation with policy } : ObservationMetadata).exactProcessAt target =
      observation.exactProcessAt target := rfl

end Forensicator.Model.Observation

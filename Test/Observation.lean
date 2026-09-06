/- Guards for the bounded native-coordinate/observation-scope precursor.
   Synthetic certification below stands in for a trusted adapter; it does not
   claim the native replay applicability matrix has been verified. -/
import Forensicator.Model.Observation

namespace Test.Observation

open Forensicator Forensicator.Model.Observation

private def check (failures : IO.Ref Nat) (name : String) (ok : Bool) : IO Unit := do
  if ok then IO.println s!"ok    {name}"
  else
    failures.modify (· + 1)
    IO.println s!"FAIL  {name}"

def runAll : IO UInt32 := do
  let failures ← IO.mkRef 0
  let check := check failures
  let p : NativePosition := ⟨1, 9⟩
  let high : NativePosition := ⟨0x123456789ABCDEF0, 0xFEDCBA9876543210⟩
  let max : NativePosition := ⟨0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF⟩
  check "native position retains both full-width components in formatting"
    (high.format == "123456789ABCDEF0:FEDCBA9876543210"
      && max.format == "FFFFFFFFFFFFFFFF:FFFFFFFFFFFFFFFF")
  check "native position order compares sequence before steps"
    (decide ((⟨1, 0xFFFFFFFFFFFFFFFF⟩ : NativePosition) < ⟨2, 0⟩)
      && compare (⟨1, 0xFFFFFFFFFFFFFFFF⟩ : NativePosition) ⟨2, 0⟩ == .lt
      && compare (⟨2, 0⟩ : NativePosition) ⟨1, 0xFFFFFFFFFFFFFFFF⟩ == .gt)
  check "native position order retains high step bits within a sequence"
    (decide ((⟨1, 0xFFFFFFFF⟩ : NativePosition) < ⟨1, 0x100000000⟩)
      && compare high high == .eq && decide (high ≤ high))
  let legacy : List Position :=
    [0, 1, 0xFFFFFFFF, 0x100000000, 0x100000001, 0xFFFFFFFF00000000,
      0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF]
  check "native conversion round-trips packed boundary positions"
    (legacy.all fun value => (NativePosition.fromLegacy value).toLegacy == some value)
  check "native conversion round-trips varying packed halves"
    ((List.range 257).all fun i =>
      let value := UInt64.ofNat (i * 0xFA000000 + (256 - i) * 0x100000000)
      (NativePosition.fromLegacy value).toLegacy == some value)
  check "legacy conversion rejects either oversized half without truncation"
    ((NativePosition.toLegacy ⟨0x100000000, 0⟩).isNone
      && (NativePosition.toLegacy ⟨0, 0x100000000⟩).isNone
      && high.toLegacy.isNone && max.toLegacy.isNone
      && NativePosition.toLegacy ⟨0xFFFFFFFF, 0xFFFFFFFF⟩ == some 0xFFFFFFFFFFFFFFFF)
  check "explicit native interval preserves open and closed endpoint meaning"
    (!(NativeInterval.contains ⟨p, .exclusive p⟩ p)
      && NativeInterval.contains ⟨p, .inclusive p⟩ p
      && !(NativeInterval.contains ⟨p, .unbounded⟩ ⟨1, 8⟩))
  check "inclusive maximum and unbounded ends need no fabricated successor"
    (NativeInterval.contains ⟨p, .inclusive max⟩ max
      && NativeInterval.contains ⟨p, .unbounded⟩ max
      && !(NativeInterval.contains ⟨p, .exclusive max⟩ max))
  let some manifest := sha256 "immutable source manifest".toUTF8
    | IO.println "FAIL  source-manifest SHA-256 fixture"; return 1
  let some otherManifest := sha256 "different immutable source manifest".toUTF8
    | IO.println "FAIL  different-source SHA-256 fixture"; return 1
  let some interpretation := sha256 "interpretation manifest revision 1".toUTF8
    | IO.println "FAIL  interpretation SHA-256 fixture"; return 1
  let content : ContentIdentity := ⟨manifest, "process-1"⟩
  let verified : SourceIdentity := .verifiedContent content
  let claimed : SourceIdentity := .claimedContent content
  let session : SourceIdentity := .sessionOnly "attachment-nonce"
  let oldEpoch : AttachmentEpoch := ⟨10⟩
  let newEpoch : AttachmentEpoch := ⟨11⟩
  check "parsing a content digest only constructs an unverified claim"
    (SourceIdentity.parseClaim manifest.toHex "process-1" == some claimed
      && !claimed.isDurable && verified.isDurable)
  check "content identity parsing rejects missing process selector or invalid digest"
    ((SourceIdentity.parseClaim manifest.toHex "").isNone
      && (SourceIdentity.parseClaim "1234" "process-1").isNone)
  check "session-only identity stays within its attachment epoch"
    (session.canReuse session oldEpoch oldEpoch
      && !(session.canReuse session oldEpoch newEpoch))
  check "claimed content cannot authorize restoration or self-promote to verified"
    (claimed.canReuse claimed oldEpoch oldEpoch
      && !(claimed.canReuse claimed oldEpoch newEpoch)
      && !(claimed.canReuse verified oldEpoch oldEpoch))
  check "matching verified content survives attachment changes"
    (verified.canReuse verified oldEpoch newEpoch)
  check "content and process-selector mismatches reject identity reuse"
    (!(verified.canReuse (.verifiedContent ⟨otherManifest, "process-1"⟩) oldEpoch oldEpoch)
      && !(verified.canReuse (.verifiedContent ⟨manifest, "process-2"⟩) oldEpoch oldEpoch))
  let originalAlias : SourceAlias := ⟨"D:/capture/source.run"⟩
  let copiedAlias : SourceAlias := ⟨"E:/renamed/source.run"⟩
  check "path aliases are independent of verified content reuse"
    (originalAlias != copiedAlias && verified.canReuse verified oldEpoch newEpoch)
  let scope : ObservationScope :=
    { source := verified, epoch := oldEpoch, point := .trace p
      thread := some (.trace 42), interpretation := ⟨interpretation⟩, phase := .afterWrite }
  check "identical observation scope accepts live matching and fact reuse"
    (scope.matchesLive scope && scope.canReuse scope)
  check "old-epoch live replies reject even when durable facts could be restored"
    (!(scope.matchesLive { scope with epoch := newEpoch })
      && scope.canReuse { scope with epoch := newEpoch })
  let wrongScopes : List ObservationScope :=
    [{ scope with source := .verifiedContent ⟨otherManifest, "process-1"⟩ },
     { scope with point := .trace ⟨1, 10⟩ },
     { scope with point := .capture },
     { scope with thread := some (.trace 43) },
     { scope with thread := none },
     { scope with interpretation := ⟨otherManifest⟩ },
     { scope with phase := .beforeInstruction }]
  check "source point thread interpretation and phase mismatches all reject"
    (wrongScopes.all fun target => !scope.matchesLive target && !scope.canReuse target)
  check "capture thread record identities do not collapse reused OS labels"
    (!(scope.canReuse { scope with thread := some (.capture 0x200 0) })
      && ((ThreadInstanceKey.capture 0x200 0) != .capture 0x200 1)
      && ((ThreadInstanceKey.capture 0x200 0) != .capture 0x300 0))
  let observation : ObservationMetadata :=
    { scope, requestedPoint := scope.point, origin := .replayReconstruction }
  let policies : List MemoryQueryPolicy :=
    [.unspecified, .sdkDefault, .threadLocal, .globallyConservative,
      .globallyAggressive, .inFragmentAggressive]
  check "no SDK memory policy alone certifies exact process-state bytes"
    (policies.all fun policy =>
      !({ observation with policy } : ObservationMetadata).exactProcessAt scope)
  let certified : ObservationMetadata :=
    { observation with applicability := .certifiedAtResolvedPoint }
  check "adapter-certified exact process observation accepts only matching scope"
    (certified.exactProcessAt scope
      && wrongScopes.all fun target => !certified.exactProcessAt target)
  check "artifact derived and unknown origins never become exact process bytes"
    ([ObservationOrigin.artifact, .derived, .unknown].all fun origin =>
      !({ certified with origin } : ObservationMetadata).exactProcessAt scope)
  let unknownPhase := { scope with phase := NativePhase.unknown }
  check "unknown native phase prevents exact process-state applicability"
    (!({ certified with scope := unknownPhase } : ObservationMetadata).exactProcessAt unknownPhase)
  let requested : ObservationScope := { scope with point := .trace ⟨1, 8⟩ }
  let adjusted : ObservationMetadata := { certified with requestedPoint := requested.point }
  check "adjusted resolution cannot satisfy the original requested point"
    (!adjusted.exactProcessAt requested && adjusted.exactProcessAt scope)
  let captured : ObservationScope :=
    { scope with point := .capture, thread := some (.capture 0x200 0), phase := .captured }
  let capturedObservation : ObservationMetadata :=
    { scope := captured, requestedPoint := .capture, origin := .recordedProcess
      applicability := .certifiedAtResolvedPoint }
  check "capture observations require no fabricated native position"
    (capturedObservation.exactProcessAt captured && !capturedObservation.exactProcessAt scope)
  let n ← failures.get
  IO.println (if n == 0 then "== ALL OBSERVATION GUARDS PASSED =="
    else s!"== {n} OBSERVATION FAILURE(S) ==")
  pure n.toUInt32

end Test.Observation

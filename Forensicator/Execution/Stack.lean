/- Bounded host-native stack recovery. Acquisition and retained frame storage
   belong to the caller; this module only consumes exact-point observations.
   Its strict v1 unwind subset deliberately rejects forms the legacy helper
   cannot safely distinguish (chaining, prolog/epilog and machine frames). -/
import Forensicator.Model.Execution
import Forensicator.Util.Unwind

namespace Forensicator.Execution.Stack

open Forensicator.Model Forensicator.Spec Forensicator.Util

abbrev ThreadKey := UInt32 × Option Position

inductive StopReason where
  | validatedRoot | missingThread | missingContext | missingArchitecture
  | unsupportedArchitecture | missingStackBounds | missingMemory | absentMemory
  | missingArtifact | invalidArtifact | unsupportedUnwind | invalidContext
  | invalidStackTransition | invalidReturnAddress | cycle | frameBudget | byteBudget
  | contextMismatch
  deriving Repr, DecidableEq, BEq, Inhabited

inductive Dependency where
  | registers (thread : ThreadKey)
  | stackBounds (thread : ThreadKey)
  | memory (range : AddressRange)
  | unwindArtifact (moduleBase : VA)
  | artifactBytes (moduleBase : VA) (range : AddressRange)
  deriving Repr, DecidableEq, BEq, Inhabited

/-- The caller verifies artifact identity against this active module instance.
    `functions` must be the complete static exception directory. Metadata bytes
    are read only from explicit regions, never an implicit image fallback.
    An arbitrary parsed image is not a verified artifact. -/
structure VerifiedUnwindArtifact where
  pointId : PointId
  module : Module
  identityEvidence : String
  functions : Array RuntimeFunction
  metadata : AddressSpace
  deriving Inhabited

/-- A terminal witness must come from one of these independent validations,
    never from a null return-address slot or a zero-filled register fallback. -/
inductive TerminalKind where
  | runtimeThreadRoot
  | verifiedEntryBoundary
  deriving Repr, DecidableEq, BEq, Inhabited

/-- Independent evidence for a terminal frame. A null pointer alone is not a
    witness. Producers must establish this condition from capture/runtime
    knowledge: `runtimeThreadRoot` requires an authoritative thread-root
    observation; `verifiedEntryBoundary` requires matched entry code plus its
    terminal stack contract. Describe that evidence in `reason`. -/
structure TerminalWitness where
  kind : TerminalKind
  pointId : PointId
  thread : ThreadKey
  instruction : VA
  stackPointer : VA
  reason : String
  provenance : Provenance := {}
  deriving Inhabited

structure StackOptions where
  maxFrames : Nat := 128
  maxReadBytes : Nat := 65536
  artifacts : List VerifiedUnwindArtifact := []
  terminals : List TerminalWitness := []
  deriving Inhabited

inductive ReadOrigin where
  | observedMemory
  | verifiedArtifact (identityEvidence : String)
  deriving Repr, DecidableEq, BEq, Inhabited

structure ReadEvidence where
  range : AddressRange
  bytes : ByteArray
  origin : ReadOrigin
  deriving Inhabited

inductive RegisterOrigin where
  | thread
  | exceptionEvent (eventIndex : Nat)
  deriving Repr, DecidableEq, BEq, Inhabited

structure RegisterObservation where
  registers : RegisterSet
  origin : RegisterOrigin
  provenance : Provenance
  deriving Repr, DecidableEq, Inhabited

structure RecoveryEvidence where
  pointId : PointId
  thread : ThreadKey
  registers : Option RegisterSet := none
  registerOrigin : Option RegisterOrigin := none
  registerProvenance : Option Provenance := none
  stackRange : Option AddressRange := none
  threadProvenance : Provenance := {}
  reads : List ReadEvidence := []
  artifacts : List String := []
  terminal : Option TerminalWitness := none
  usedFramePointer : Bool := false
  algorithmRevision : String := "native-stack-v1-strict"
  deriving Inhabited

structure StackRecovery where
  stack : RecoveredStack
  stopReason : StopReason
  dependencies : List Dependency
  evidence : RecoveryEvidence
  bytesRead : Nat
  deriving Inhabited

private structure RecoveryLog where
  frames : List RecoveredFrame := []
  dependencies : List Dependency := []
  evidence : RecoveryEvidence
  bytesRead : Nat := 0
  confidence : Float := 1.0

private abbrev RecoverM := ExceptT StopReason (StateM RecoveryLog)

/-- Attach the selected event's actual index without changing the common
    analysis event-selection policy. An unselected ambiguous exception set
    produces no override, exactly as `AnalysisInput.exception` does. -/
private def selectedException (input : AnalysisInput) : Option (ExceptionInfo × Nat) := do
  let exception ← input.exception
  let index ← match input.selectedEvent with
    | some index => some index
    | none => (input.point.events.zipIdx.find? (fun (e, _) => e.kind == .Exception)).map (·.2)
  pure (exception, index)

private def registerCandidate (input : AnalysisInput) (thread : ThreadState) :
    Knowledge RegisterObservation :=
  match selectedException input with
  | some (exception, index) =>
    if exception.threadId == thread.id then
      match exception.context with
      | some registers => .known {
          registers, origin := .exceptionEvent index
          provenance := exception.provenance }
      | none => fromThread
    else fromThread
  | none => fromThread
where
  fromThread : Knowledge RegisterObservation :=
    match thread.registers with
    | .unknown => .unknown
    | .unavailable reason => .unavailable reason
    | .known registers => .known { registers, origin := .thread, provenance := thread.provenance }

/-- Effective initial registers for recovery and retained-result validation.
    A selected (or sole) exact exception overrides the matching thread's
    registers, including previously unavailable thread registers. A malformed
    exception context is an error, never permission to silently use another
    observation. This helper selects registers; native CPU/lifetime/stack
    checks still belong to `recoverStack`. -/
def effectiveRegisters (input : AnalysisInput) (threadKey : ThreadKey) :
    Except StopReason RegisterObservation := do
  if input.context.pointId != input.point.id then throw .contextMismatch
  else
    match input.point.threadAt threadKey with
    | none => throw .missingThread
    | some thread =>
      match registerCandidate input thread with
      | .unknown | .unavailable _ => throw .missingContext
      | .known observation =>
        if observation.registers.values.size != 32 then throw .invalidContext
        else pure observation

private def need (d : Dependency) : RecoverM Unit :=
  modify fun s => if s.dependencies.contains d then s
    else { s with dependencies := s.dependencies ++ [d] }

private def fail (reason : StopReason) : RecoverM α := throw reason

private def validRange (r : AddressRange) : Bool :=
  r.size != 0 && r.va.toNat + r.size.toNat ≤ 2^64

private def addAddress (va : VA) (n : Nat) : RecoverM VA :=
  if va.toNat + n < 2^64 then pure (UInt64.ofNat (va.toNat + n))
  else fail .invalidStackTransition

private def recordRead (options : StackOptions) (va : VA) (len : Nat)
    (origin : ReadOrigin) (read : Unit → MemoryRead) : RecoverM ByteArray := do
  let s ← get
  if s.bytesRead + len > options.maxReadBytes then fail .byteBudget
  else if va.toNat + len > 2^64 then fail .invalidStackTransition
  else
    match read () with
    | .known bytes =>
      if bytes.size != len then fail .missingMemory
      else
        modify fun s => { s with
          bytesRead := s.bytesRead + len
          evidence := { s.evidence with reads := s.evidence.reads ++
            [{ range := ⟨va, UInt64.ofNat len⟩, bytes, origin }] } }
        pure bytes
    | .absent => fail .absentMemory
    | .unknown =>
      need (.memory ⟨va, UInt64.ofNat len⟩)
      fail .missingMemory

private def readStack (point : ExecutionPoint) (options : StackOptions)
    (bounds : AddressRange) (va : VA) (len : Nat) : RecoverM ByteArray := do
  if !bounds.covers va len then fail .invalidStackTransition
  else
    -- An on-disk image is never evidence for recorded stack bytes.
    let memory := { point.memory with space := { point.memory.space with backing := none } }
    recordRead options va len .observedMemory (fun _ => memory.read va len)

private def readMetadata (options : StackOptions) (a : VerifiedUnwindArtifact)
    (va : VA) (len : Nat) : RecoverM ByteArray := do
  if len == 0 then pure ByteArray.empty
  else if !(AddressRange.mk a.module.baseVa a.module.size).covers va len then fail .invalidArtifact
  else
    let space := { a.metadata with backing := none }
    if (space.read va len).isNone then
      need (.artifactBytes a.module.baseVa ⟨va, UInt64.ofNat len⟩)
      fail .missingArtifact
    else recordRead options va len (.verifiedArtifact a.identityEvidence) fun _ =>
        match space.read va len with
        | some bytes => .known bytes
        | none => .unknown

private def moduleMatches (a b : Module) : Bool :=
  a.name == b.name && a.baseVa == b.baseVa && a.size == b.size
    && a.checksum == b.checksum && a.codeviewGuid == b.codeviewGuid
    && a.codeviewAge == b.codeviewAge

private def tableValid (a : VerifiedUnwindArtifact) : Bool := Id.run do
  let mut lastEnd : Nat := 0
  for f in a.functions do
    if f.begin.toNat < lastEnd || f.begin ≥ f.stop
      || f.stop.toNat > a.module.size.toNat || f.unwindInfo.toNat + 4 > a.module.size.toNat
      || f.unwindInfo.toNat % 4 != 0 then
      return false
    lastEnd := f.stop.toNat
  return true

private def selectArtifact (input : AnalysisInput) (options : StackOptions) (rip : VA) :
    RecoverM (Option VerifiedUnwindArtifact) := do
  match input.modules.filter (fun m => (AddressRange.mk m.baseVa m.size).covers rip) with
  | [] => pure none
  | [m] =>
    if !validRange ⟨m.baseVa, m.size⟩ then fail .invalidArtifact
    else
      match options.artifacts.filter (fun a => moduleMatches a.module m) with
      | [] => need (.unwindArtifact m.baseVa); pure none
      | [a] =>
        if a.pointId != input.point.id || a.identityEvidence.isEmpty || !tableValid a then
          fail .invalidArtifact
        else
          modify fun s => { s with evidence := { s.evidence with
            artifacts := if s.evidence.artifacts.contains a.identityEvidence then s.evidence.artifacts
              else s.evidence.artifacts ++ [a.identityEvidence] } }
          pure (some a)
      | _ => fail .invalidArtifact
  | _ => fail .invalidArtifact

private def pushMap (i : Nat) : Option Nat :=
  -- Only nonvolatile integer registers are legal PUSH_NONVOL operands.
  match i with
  | 3 => some X64.RBX | 5 => some X64.RBP | 6 => some X64.RSI | 7 => some X64.RDI
  | 12 => some X64.R12 | 13 => some X64.R13 | 14 => some X64.R14 | 15 => some X64.R15
  | _ => none

/-- Preflight each byte/arithmetic operation before using the shared legacy
    helper. Accepted forms are PUSH_NONVOL and small/large stack allocations.
    Complex forms stop; they are never treated as no-ops or leaf frames. -/
private def nativeStep (input : AnalysisInput) (options : StackOptions)
    (bounds : AddressRange) (a : VerifiedUnwindArtifact) (rt : RuntimeFunction)
    (regs : RegisterSet) : RecoverM RegisterSet := do
  let hdrVa ← addAddress a.module.baseVa rt.unwindInfo.toNat
  let hdr ← readMetadata options a hdrVa 4
  let versionFlags := hdr.get! 0
  let prolog := (hdr.get! 1).toNat
  let count := (hdr.get! 2).toNat
  if versionFlags != 1 || hdr.get! 3 != 0 then fail .unsupportedUnwind
  else if (count != 0 && prolog == 0) || prolog > rt.stop.toNat - rt.begin.toNat then
    fail .invalidArtifact
  else if regs.rip.toNat - a.module.baseVa.toNat - rt.begin.toNat < prolog then
    fail .unsupportedUnwind
  else
    -- No epilog decoder yet: accept only a current opcode that cannot begin
    -- the x64 epilog grammar (RET/POP/ADD/LEA/JMP and relevant prefixes).
    let code ← readMetadata options a regs.rip 1
    let opcode := code.get! 0
    if opcode == 0xC2 || opcode == 0xC3 || opcode == 0xE9 || opcode == 0xEB
      || opcode == 0xFF || (opcode ≥ 0x40 && opcode ≤ 0x5F)
      || opcode == 0x66 || opcode == 0xF2 || opcode == 0xF3 then fail .unsupportedUnwind
    else
      let codesVa ← addAddress hdrVa 4
      let codes ← readMetadata options a codesVa (2 * count)
      let rec applyCodes (fuel i previousOffset : Nat) (r : RegisterSet) : RecoverM RegisterSet := do
        match fuel with
        | 0 => if i ≥ count then pure r else fail .unsupportedUnwind
        | fuel + 1 =>
          if i ≥ count then pure r
          else
            let codeOff := (codes.get! (2 * i)).toNat
            let opInfo := codes.get! (2 * i + 1)
            let op := opInfo &&& 0xF
            let info := (opInfo >>> 4).toNat
            if codeOff == 0 || codeOff > previousOffset then fail .invalidArtifact
            else
              match op with
              | 0 =>
                match pushMap info with
                | none => fail .unsupportedUnwind
                | some idx =>
                  let value ← readStack input.point options bounds r.rsp 8
                  let rsp ← addAddress r.rsp 8
                  applyCodes fuel (i + 1) codeOff ((r.set idx (readU64leAt value 0)).set X64.RSP rsp)
              | 1 =>
                if info == 0 && i + 2 ≤ count then
                  let amount := (readU16leAt codes (2 * (i + 1))).toNat * 8
                  if amount == 0 then fail .invalidArtifact
                  else
                    let rsp ← addAddress r.rsp amount
                    applyCodes fuel (i + 2) codeOff (r.set X64.RSP rsp)
                else if info == 1 && i + 3 ≤ count then
                  let amount := (readU32leAt codes (2 * (i + 1))).toNat
                  if amount == 0 || amount % 8 != 0 then fail .invalidArtifact
                  else
                    let rsp ← addAddress r.rsp amount
                    applyCodes fuel (i + 3) codeOff (r.set X64.RSP rsp)
                else fail .unsupportedUnwind
              | 2 =>
                let rsp ← addAddress r.rsp (8 * (info + 1))
                applyCodes fuel (i + 1) codeOff (r.set X64.RSP rsp)
              | _ => fail .unsupportedUnwind
      let restored ← applyCodes (count + 1) 0 prolog regs
      let bytes ← readStack input.point options bounds restored.rsp 8
      let rsp ← addAddress restored.rsp 8
      let expected := (restored.set X64.RIP (readU64leAt bytes 0)).set X64.RSP rsp
      -- The helper receives only evidence bytes already read and budgeted.
      let log ← get
      let regions := log.evidence.reads.map fun e =>
        ({ vaStart := e.range.va, size := e.range.size, data := e.bytes } : AddressRegion)
      -- Reads overlap (e.g. repeated metadata); select an entire covering
      -- observed read per helper request by retaining the widest first.
      let regions := regions.mergeSort (fun x y => x.size ≥ y.size)
      let space : AddressSpace := { regions, maxRegions := regions.length }
      match unwindStep regs space a.module.baseVa rt with
      | some next => if next == expected then pure next else fail .unsupportedUnwind
      | none => fail .unsupportedUnwind

private def leafStep (input : AnalysisInput) (options : StackOptions)
    (bounds : AddressRange) (regs : RegisterSet) : RecoverM RegisterSet := do
  let bytes ← readStack input.point options bounds regs.rsp 8
  let rsp ← addAddress regs.rsp 8
  pure ((regs.set X64.RIP (readU64leAt bytes 0)).set X64.RSP rsp)

private def framePointerStep (input : AnalysisInput) (options : StackOptions)
    (bounds : AddressRange) (regs : RegisterSet) : RecoverM RegisterSet := do
  if regs.rbp == 0 then fail .missingArtifact
  else if regs.rbp < regs.rsp || regs.rbp.toNat % 8 != 0 then fail .invalidStackTransition
  else
    let bytes ← readStack input.point options bounds regs.rbp 16
    let saved := readU64leAt bytes 0
    let ret := readU64leAt bytes 8
    if saved != 0 && saved ≤ regs.rbp then fail .cycle
    else if saved != 0 && !bounds.covers saved 16 then fail .invalidStackTransition
    else
      let rsp ← addAddress regs.rbp 16
      modify fun s => { s with
        confidence := min s.confidence 0.65
        evidence := { s.evidence with usedFramePointer := true } }
      pure (((regs.set X64.RIP ret).set X64.RSP rsp).set X64.RBP saved)

private def walk (input : AnalysisInput) (options : StackOptions) (thread : ThreadState)
    (bounds : AddressRange) (fuel : Nat) (regs : RegisterSet)
    (seen : List (VA × VA)) : RecoverM Unit := do
  match fuel with
  | 0 => fail .frameBudget
  | fuel + 1 =>
    if seen.contains (regs.rip, regs.rsp) then fail .cycle
    else if regs.rip == 0 then fail .invalidReturnAddress
    else if regs.rsp.toNat % 8 != 0 || !bounds.covers regs.rsp then fail .invalidStackTransition
    else
      modify fun s => { s with frames := s.frames ++
        [{ instruction := regs.rip, stackPointer := regs.rsp, framePointer := some regs.rbp
           confidence := s.confidence, provenance := thread.provenance }] }
      match options.terminals.find? (fun t => t.pointId == input.point.id
        && t.thread == thread.key && t.instruction == regs.rip
        && t.stackPointer == regs.rsp && !t.reason.isEmpty) with
      | some terminal =>
        modify fun s => { s with evidence := { s.evidence with terminal := some terminal } }
        fail .validatedRoot
      | none =>
        let artifact ← selectArtifact input options regs.rip
        let next ← match artifact with
          | none => framePointerStep input options bounds regs
          | some a =>
            match a.functions.toList.find? (fun f =>
              f.begin.toNat ≤ regs.rip.toNat - a.module.baseVa.toNat
                && regs.rip.toNat - a.module.baseVa.toNat < f.stop.toNat) with
            | some rt => nativeStep input options bounds a rt regs
            | none => leafStep input options bounds regs
        if next.rsp ≤ regs.rsp then fail .invalidStackTransition
        else if next.rip == 0 then fail .invalidReturnAddress
        else if next.rsp.toNat > bounds.va.toNat + bounds.size.toNat then
          fail .invalidStackTransition
        else
          -- An unverified frame-pointer target must be supported by an active
          -- module or positively observed executable memory before retention.
          let inModule := input.modules.any fun m =>
            validRange ⟨m.baseVa, m.size⟩ && (AddressRange.mk m.baseVa m.size).covers next.rip
          let executable := ((input.point.space.regionAt next.rip).map fun r =>
            validRange ⟨r.vaStart, r.size⟩ && r.state == .Commit
              && r.protection &&& Protection.EXECUTE != 0).getD false
          if !inModule && !executable then fail .invalidReturnAddress
          else walk input options thread bounds fuel next ((regs.rip, regs.rsp) :: seen)

/-- Recover one thread instance without IO, acquisition, or mutation of the
    point. Missing and unavailable contexts never become default registers.
    Current RegisterSet has no per-register mask: only a complete 32-slot known
    context is accepted; partial validity support belongs to the R1 migration. -/
def recoverStack (input : AnalysisInput) (threadKey : ThreadKey)
    (options : StackOptions := {}) : StackRecovery := Id.run do
  let initial : RecoveryLog := { evidence := { pointId := input.point.id, thread := threadKey } }
  let action : RecoverM Unit := do
    if input.context.pointId != input.point.id then fail .contextMismatch
    else
      match input.systemInfo with
      | none => fail .missingArchitecture
      | some system =>
        if system.cpu != .X64 then fail .unsupportedArchitecture
        else
          match input.point.threadAt threadKey with
          | none => fail .missingThread
          | some thread =>
            match input.point.id.position, thread.lifetime with
            | .trace p, some lifetime =>
              if !lifetime.contains p then fail .invalidContext else pure ()
            | _, _ => pure ()
            modify fun s => { s with evidence := { s.evidence with
              threadProvenance := thread.provenance
              stackRange := thread.stackRange.toOption } }
            match registerCandidate input thread with
            | .unknown => need (.registers threadKey); fail .missingContext
            | .unavailable _ => fail .missingContext
            | .known observation =>
              let regs := observation.registers
              modify fun s => { s with evidence := { s.evidence with
                registers := some regs, registerOrigin := some observation.origin
                registerProvenance := some observation.provenance } }
              if regs.values.size != 32 then fail .invalidContext
              else if regs.rip == 0 || regs.rsp == 0 then fail .invalidContext
              else
                match thread.stackRange with
                | .unknown => need (.stackBounds threadKey); fail .missingStackBounds
                | .unavailable _ => fail .missingStackBounds
                | .known bounds =>
                  if !validRange bounds then fail .invalidStackTransition
                  else walk input options thread bounds options.maxFrames regs []
  let (outcome, log) := action.run initial
  let stop := match outcome with | .error r => r | .ok _ => .invalidContext
  return { stack := { frames := log.frames
                      coverage := if stop == .validatedRoot && log.dependencies.isEmpty
                        && !log.evidence.usedFramePointer then .complete else .incomplete
                      confidence := if log.frames.isEmpty then 0 else log.confidence }
           stopReason := stop, dependencies := log.dependencies
           evidence := log.evidence, bytesRead := log.bytesRead }

end Forensicator.Execution.Stack

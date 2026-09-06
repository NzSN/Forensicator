/- Native stack recovery guards exercise evidence and stopping boundaries,
   including unavailable input, bounded reads, artifact identity and cycles. -/
import Forensicator.Execution.Stack

namespace Test.Stack

open Forensicator Forensicator.Model Forensicator.Spec Forensicator.Util
open Forensicator.Execution.Stack

private def prov : Provenance := { streamType := 3, fileOffset := 64, rva := 128 }
private def pointId : PointId := { source := "stack-fixture", position := .capture }
private def threadKey : ThreadKey := (7, none)
private def bounds : AddressRange := ⟨0x8000, 0x100⟩

private def regs : RegisterSet :=
  ((RegisterSet.new.set X64.RIP 0x1110).set X64.RSP 0x8000).set X64.RBP 0x8020

private def module : Module :=
  { name := "fixture.exe", baseVa := 0x1000, size := 0x1000, checksum := 0xABCD
    provenance := prov }

private def writeBytes (bytes : ByteArray) (offset : Nat) (values : List UInt8) : ByteArray :=
  ⟨(values.zipIdx).foldl (fun acc (v, i) => acc.set! (offset + i) v) bytes.data⟩

private def write64 (bytes : ByteArray) (offset : Nat) (value : UInt64) : ByteArray :=
  writeBytes bytes offset ((List.range 8).map fun i => (value >>> (8 * UInt64.ofNat i)).toUInt8)

private def memory (bytes : ByteArray) : MemoryState :=
  { space := { regions := [{ vaStart := bounds.va, size := bounds.size, data := bytes
                             protection := 3, classification := .Stack }]
               maxRegions := 32 } }

private def input (bytes : ByteArray := ⟨Array.replicate 256 0⟩) : AnalysisInput :=
  { point := { id := pointId, memory := memory bytes
               threads := [{ id := 7, registers := .known regs, stackRange := .known bounds
                             provenance := prov }] }
    context := { pointId, modules := [module]
                 systemInfo := some { os := .Windows, cpu := .X64,
                                      version := (10, 0, 0, 0), provenance := prov } } }

private def withThread (a : AnalysisInput) (change : ThreadState → ThreadState) : AnalysisInput :=
  { a with point := { a.point with threads := a.point.threads.map change } }

private def metadata (header : List UInt8) : AddressSpace :=
  { regions := [{ vaStart := 0x1000, size := 0x1000
                  data := writeBytes ⟨Array.replicate 4096 0x90⟩ 0x300 header }]
    maxRegions := 32 }

private def artifact (header : List UInt8 := [1, 4, 1, 0, 4, 0x12]) : VerifiedUnwindArtifact :=
  { pointId, module, identityEvidence := "fixture-matched-checksum-and-build-id"
    functions := #[{ begin := 0x100, stop := 0x200, unwindInfo := 0x300 }]
    metadata := metadata header }

private def terminal (rip rsp : VA) : TerminalWitness :=
  { kind := .runtimeThreadRoot, pointId, thread := threadKey
    instruction := rip, stackPointer := rsp
    reason := "authoritative fixture thread-root observation", provenance := prov }

private def run (a : AnalysisInput) (options : StackOptions := {}) : StackRecovery :=
  recoverStack a threadKey options

private def assertCheck (failures : IO.Ref Nat) (name : String) (ok : Bool) : IO Unit := do
  if ok then IO.println s!"ok    stack {name}"
  else
    failures.modify (· + 1)
    IO.println s!"FAIL  stack {name}"

def runAll : IO UInt32 := do
  let failures ← IO.mkRef 0
  let check := assertCheck failures
  let unknown := run (withThread (input) fun t => { t with registers := .unknown })
  check "unknown registers request context without fabricated frames"
    (unknown.stopReason == .missingContext && unknown.stack.frames.isEmpty
      && unknown.dependencies == [.registers threadKey])
  let unavailable := run (withThread (input) fun t => { t with registers := .unavailable "unsupported" })
  check "unavailable registers remain unavailable, without acquisition loop"
    (unavailable.stopReason == .missingContext && unavailable.dependencies.isEmpty)
  let zero := run (withThread (input) fun t => { t with registers := .known RegisterSet.new })
  check "known zero differs from missing registers"
    (zero.stopReason == .invalidContext && zero.evidence.registers.isSome
      && zero.stack.coverage == .incomplete)
  let truncated := run (withThread (input) fun t => { t with registers := .known ⟨#[0]⟩ })
  check "truncated register arrays cannot acquire default slots" (truncated.stopReason == .invalidContext)
  let noBounds := run (withThread (input) fun t => { t with stackRange := .unknown })
  check "readable memory does not invent complete stack bounds"
    (noBounds.stopReason == .missingStackBounds && noBounds.dependencies == [.stackBounds threadKey])
  let noCpu := run { input with context := { (input).context with systemInfo := none } }
  check "missing CPU architecture is explicit" (noCpu.stopReason == .missingArchitecture)
  let otherCpu := run { input with context := { (input).context with
    systemInfo := some { os := .Windows, cpu := .Arm64, version := (0,0,0,0), provenance := prov } } }
  check "non-x64 input is rejected" (otherCpu.stopReason == .unsupportedArchitecture)
  let wrongPoint := run { input with context := { (input).context with pointId := { source := "other" } } }
  check "context cannot cross point identity" (wrongPoint.stopReason == .contextMismatch)
  let duplicate := run { input with point := { (input).point with threads := (input).point.threads ++ (input).point.threads } }
  check "duplicated thread keys are not silently selected" (duplicate.stopReason == .missingThread)

  let exceptionRegs := ((regs.set X64.RIP 0x1150).set X64.RSP 0x8040).set X64.RBP 0x8060
  let exceptionProv : Provenance := { streamType := 6, fileOffset := 0x300, rva := 0x400 }
  let exceptionEvent : ExecutionEvent := {
    kind := .Exception, threadId := 7
    context := some exceptionRegs, provenance := exceptionProv }
  let exceptionInput := { input with point := { (input).point with events := [exceptionEvent] } }
  let overridden := run exceptionInput { terminals := [terminal 0x1150 0x8040] }
  check "sole exact exception context overrides matching thread registers"
    (overridden.stopReason == .validatedRoot
      && (overridden.stack.frames[0]?).map (·.instruction) == some 0x1150
      && overridden.evidence.registerOrigin == some (.exceptionEvent 0)
      && overridden.evidence.registerProvenance == some exceptionProv
      && overridden.evidence.registers == some exceptionRegs)
  check "exception recovery preserves original point registers"
    (((exceptionInput.point.threads[0]?).bind fun t => t.registers.toOption) == some regs)
  check "effective register helper exposes the same observation as recovery"
    ((effectiveRegisters exceptionInput threadKey).toOption ==
      some { registers := exceptionRegs, origin := .exceptionEvent 0, provenance := exceptionProv })
  let otherwiseUnknown := withThread exceptionInput fun t => { t with registers := .unknown }
  check "valid exact exception context can supply unavailable thread context"
    ((run otherwiseUnknown { terminals := [terminal 0x1150 0x8040] }).stopReason == .validatedRoot)
  let wrongThreadInput := { input with point := { (input).point with
    events := [{ exceptionEvent with threadId := 8 }] } }
  let wrongThread := run wrongThreadInput { terminals := [terminal 0x1110 0x8000] }
  check "another thread's exception does not override registers"
    (wrongThread.stopReason == .validatedRoot && wrongThread.evidence.registerOrigin == some .thread
      && wrongThread.evidence.registers == some regs)
  let ambiguousEvents := { input with point := { (input).point with
    events := [exceptionEvent, exceptionEvent] } }
  let ambiguousContext := run ambiguousEvents { terminals := [terminal 0x1110 0x8000] }
  check "ambiguous unselected exception events do not override registers"
    (ambiguousContext.stopReason == .validatedRoot && ambiguousContext.evidence.registerOrigin == some .thread)
  let selectedContext := run { ambiguousEvents with selectedEvent := some 1 }
    { terminals := [terminal 0x1150 0x8040] }
  check "explicit event selection records the actual overriding event index"
    (selectedContext.stopReason == .validatedRoot
      && selectedContext.evidence.registerOrigin == some (.exceptionEvent 1))
  let malformedException := { input with point := { (input).point with
    events := [{ exceptionEvent with context := some ⟨#[1]⟩ }] } }
  let invalidException := run malformedException { terminals := [terminal 0x1110 0x8000] }
  check "malformed exact exception context fails closed instead of falling back"
    (invalidException.stopReason == .invalidContext && invalidException.stack.frames.isEmpty
      && invalidException.evidence.registerOrigin == some (.exceptionEvent 0)
      && (effectiveRegisters malformedException threadKey).toOption.isNone)

  let root := run input { terminals := [terminal 0x1110 0x8000] }
  check "independent exact root witness permits completeness"
    (root.stopReason == .validatedRoot && root.stack.coverage == .complete
      && root.stack.frames.length == 1 && root.evidence.terminal.isSome)
  let wrongRoot := run input { terminals := [{ (terminal 0x1110 0x8000) with pointId := { source := "other" } }] }
  check "foreign root witness cannot claim completeness"
    (wrongRoot.stopReason != .validatedRoot && wrongRoot.stack.coverage == .incomplete)
  let noBudget := run input { maxFrames := 0, terminals := [terminal 0x1110 0x8000] }
  check "zero frame budget stays incomplete" (noBudget.stopReason == .frameBudget && noBudget.stack.frames.isEmpty)

  let nativeBytes := write64 ⟨Array.replicate 256 0⟩ 16 0x1140
  let native := run (input nativeBytes) { artifacts := [artifact], terminals := [terminal 0x1140 0x8018] }
  check "ALLOC_SMALL shares native helper and preserves exact return state"
    (native.stopReason == .validatedRoot && native.stack.frames.length == 2
      && (native.stack.frames[1]?).map (·.stackPointer) == some 0x8018
      && native.evidence.reads.any (fun r => r.range == AddressRange.mk 0x8010 8)
      && native.bytesRead == 15)
  check "native stack recovery does not require a PDB"
    (native.stack.coverage == .complete && module.pdbName.isNone)
  let noNullRoot := run (input nativeBytes) { artifacts := [artifact] }
  check "observed null return does not establish root"
    (noNullRoot.stopReason == .invalidReturnAddress && noNullRoot.stack.coverage == .incomplete
      && noNullRoot.stack.frames.length == 2)
  let truncatedMemory := run (input ⟨Array.replicate 16 0⟩) { artifacts := [artifact] }
  check "missing return bytes preserve supported frame and request exact range"
    (truncatedMemory.stopReason == .missingMemory && truncatedMemory.stack.frames.length == 1
      && truncatedMemory.dependencies == [.memory ⟨0x8010, 8⟩])
  let absentInput := { (input nativeBytes) with point := { (input nativeBytes).point with
    memory := { (input nativeBytes).point.memory with absentRanges := [⟨0x8010, 8⟩] } } }
  let absent := run absentInput { artifacts := [artifact] }
  check "known-absent stack bytes are not retried as unknown"
    (absent.stopReason == .absentMemory && absent.dependencies.isEmpty)
  let byteLimited := run (input nativeBytes) { artifacts := [artifact], maxReadBytes := 14 }
  check "byte budget accounts for metadata and memory reads"
    (byteLimited.stopReason == .byteBudget && byteLimited.bytesRead ≤ 14 && byteLimited.stack.frames.length == 1)
  let frameLimited := run (input nativeBytes) { artifacts := [artifact], maxFrames := 1 }
  check "partial frame list survives exhausted frame budget"
    (frameLimited.stopReason == .frameBudget && frameLimited.stack.frames.length == 1)
  let leafBytes := write64 ⟨Array.replicate 256 0⟩ 0 0x1140
  let leaf := run (input leafBytes) {
    artifacts := [{ artifact with functions := #[] }]
    terminals := [terminal 0x1140 0x8008] }
  check "complete verified exception directory permits native leaf return"
    (leaf.stopReason == .validatedRoot && leaf.stack.coverage == .complete
      && leaf.stack.frames.length == 2 && leaf.bytesRead == 8)

  let pushBytes := write64 (write64 ⟨Array.replicate 256 0⟩ 0 0) 8 0x1140
  let push := run (input pushBytes) {
    artifacts := [artifact [1, 1, 1, 0, 1, 0x30]]
    terminals := [terminal 0x1140 0x8010] }
  check "PUSH_NONVOL restores known-zero RBX and reads return address"
    (push.stopReason == .validatedRoot && push.stack.frames.length == 2 && push.bytesRead == 23)
  let large := run (input nativeBytes) {
    artifacts := [artifact [1, 7, 2, 0, 7, 1, 2, 0]]
    terminals := [terminal 0x1140 0x8018] }
  check "ALLOC_LARGE slot counts are checked" (large.stopReason == .validatedRoot && large.stack.frames.length == 2)
  let large32 := run (input nativeBytes) {
    artifacts := [artifact [1, 7, 3, 0, 7, 0x11, 16, 0, 0, 0]]
    terminals := [terminal 0x1140 0x8018] }
  check "unscaled ALLOC_LARGE supports its complete operand" (large32.stopReason == .validatedRoot)
  let shortOperand := run (input nativeBytes) { artifacts := [artifact [1, 7, 1, 0, 7, 1]] }
  check "truncated unwind operands stop explicitly" (shortOperand.stopReason == .unsupportedUnwind)
  let unsupported := run (input nativeBytes) { artifacts := [artifact [1, 1, 1, 0, 1, 0x0A]] }
  check "machine frames never silently use ordinary return pop"
    (unsupported.stopReason == .unsupportedUnwind && unsupported.stack.frames.length == 1)
  let chain := run (input nativeBytes) { artifacts := [artifact [0x21, 0, 0, 0]] }
  check "chained metadata remains explicitly unsupported" (chain.stopReason == .unsupportedUnwind)
  let prolog := run (input nativeBytes) { artifacts := [artifact [1, 32, 1, 0, 32, 0x12]] }
  check "partial prolog is not unwound as completed allocation" (prolog.stopReason == .unsupportedUnwind)
  let epilogArtifact := { artifact with metadata := {
    regions := [{ vaStart := 0x1000, size := 0x1000
                  data := writeBytes (writeBytes ⟨Array.replicate 4096 0x90⟩ 0x300
                    [1,4,1,0,4,0x12]) 0x110 [0xC3] }]
    maxRegions := 32 } }
  check "epilog return rejects full-prolog replay"
    ((run (input nativeBytes) { artifacts := [epilogArtifact] }).stopReason == .unsupportedUnwind)
  let wrongArtifact := { artifact with pointId := { source := "other" } }
  check "artifact cannot cross exact point identity"
    ((run input { artifacts := [wrongArtifact] }).stopReason == .invalidArtifact)
  let missingArtifactBytes := { artifact with metadata := AddressSpace.new 32 }
  check "missing artifact bytes request artifact origin rather than stack memory"
    ((run input { artifacts := [missingArtifactBytes] }).dependencies == [.artifactBytes 0x1000 ⟨0x1300, 4⟩])
  let invalidTable := { artifact with functions := #[{ begin := 0x200, stop := 0x100, unwindInfo := 0x300 }] }
  check "invalid native directory cannot justify a leaf"
    ((run input { artifacts := [invalidTable] }).stopReason == .invalidArtifact)
  let badOrder := run (input nativeBytes) { artifacts := [artifact [1, 4, 2, 0, 1, 0x02, 4, 0x02]] }
  check "out-of-order unwind codes fail closed" (badOrder.stopReason == .invalidArtifact)
  let bogusProlog := run (input nativeBytes) { artifacts := [artifact [1, 0, 1, 0, 0, 0x12]] }
  check "zero-sized prolog cannot contain stack allocation codes" (bogusProlog.stopReason == .invalidArtifact)

  let fpBytes := write64 (write64 ⟨Array.replicate 256 0⟩ 0x20 0x8040) 0x28 0x1140
  let fp := run (input fpBytes) { maxFrames := 2 }
  check "frame-pointer fallback preserves partial frames and artifact dependency"
    (fp.stack.frames.length == 2 && fp.evidence.usedFramePointer
      && fp.dependencies.contains (.unwindArtifact 0x1000) && fp.stack.coverage == .incomplete)
  let fallbackRoot := run (input fpBytes) { terminals := [terminal 0x1140 0x8030] }
  check "root witness does not upgrade heuristic or missing-artifact frames to complete"
    (fallbackRoot.stopReason == .validatedRoot && fallbackRoot.stack.coverage == .incomplete)
  let cyclic := run (input (write64 fpBytes 0x20 0x8020))
  check "frame-pointer cycle does not repeat frames" (cyclic.stopReason == .cycle && cyclic.stack.frames.length == 1)
  let escaped := run (input (write64 fpBytes 0x20 0x9000))
  check "frame-pointer transition outside certified bounds stops" (escaped.stopReason == .invalidStackTransition)
  let badPc : VA := 0xFFFFFFFFFFFFFFF8
  let badPcInput := input (write64 fpBytes 0x28 badPc)
  let wrappingModule : Module :=
    { name := "invalid.exe", baseVa := 0xFFFFFFFFFFFFFFF0, size := 0x100, provenance := prov }
  let badModuleResult := run { badPcInput with context := {
    badPcInput.context with modules := badPcInput.modules ++ [wrappingModule] } }
  check "overflowing module cannot justify a recovered return target"
    (badModuleResult.stopReason == .invalidReturnAddress && badModuleResult.stack.frames.length == 1)
  let invalidExec : AddressRegion :=
    { vaStart := 0xFFFFFFFFFFFFFFF0, size := 0x100, state := .Commit
      protection := Protection.EXECUTE }
  let badExecResult := run { badPcInput with point := { badPcInput.point with
    memory := { badPcInput.point.memory with space := { badPcInput.space with
      regions := badPcInput.space.regions ++ [invalidExec] } } } }
  check "overflowing executable region cannot justify a recovered return target"
    (badExecResult.stopReason == .invalidReturnAddress && badExecResult.stack.frames.length == 1)
  let unaligned := run (withThread (input) fun t => { t with registers := .known (regs.set X64.RSP 0x8001) })
  check "unaligned stack pointer is not followed" (unaligned.stopReason == .invalidStackTransition)
  let traceId : PointId := { source := "trace-stack", position := .trace 8 }
  let deadThread := withThread { input with
    point := { (input).point with id := traceId }
    context := { (input).context with pointId := traceId } } fun t =>
      { t with lifetime := some { start := 1, stop := some 8 } }
  check "thread state outside its half-open lifetime is rejected"
    ((recoverStack deadThread (7, some 1)).stopReason == .invalidContext)
  let image : ImageFile := {
    baseVa := 0x8000, sizeOfImage := 0x100, data := fpBytes
    headerSize := 0x100, sections := [] }
  let imageOnly := { input with point := { (input).point with memory := {
    space := { regions := [], maxRegions := 32, backing := some { images := [image] } } } } }
  let backed := run imageOnly
  check "on-disk image fallback cannot supply observed stack bytes"
    (backed.stopReason == .missingMemory && backed.dependencies.contains (.memory ⟨0x8020, 16⟩))
  check "evidence retains point, thread, register observation and provenance"
    (native.evidence.pointId == pointId && native.evidence.thread == threadKey
      && native.evidence.registers == some regs && native.evidence.threadProvenance == prov
      && native.evidence.registerOrigin == some .thread && native.evidence.registerProvenance == some prov
      && native.evidence.algorithmRevision == "native-stack-v1-strict")
  return UInt32.ofNat (← failures.get)

end Test.Stack

/- Guards for source-neutral execution observations and the minidump adapter.
   These exercise evidence boundaries: moving to another point must not reuse
   capture facts, and missing knowledge must not become invented state. -/
import Forensicator.Model.Capture
import Forensicator.Parse.Minidump
import Forensicator.Pipeline

namespace Test.Execution

open Forensicator Forensicator.Model

private structure Ctx where
  failures : IO.Ref Nat

private def check (ctx : Ctx) (name : String) (ok : Bool) : IO Unit := do
  if ok then IO.println s!"ok    {name}"
  else
    ctx.failures.modify (· + 1)
    IO.println s!"FAIL  {name}"

private def prov : Provenance :=
  { streamType := 6, fileOffset := 0x180, rva := 0x200 }

private def captured : Dump :=
  { systemInfo := some
      { os := .Windows, cpu := .X64, version := (10, 0, 22621, 0), provenance := prov }
    modules :=
      [{ name := "electron.exe", baseVa := 0x140000000, size := 0x10000
         checksum := 0xDEAD, codeviewGuid := some ⟨#[0x10, 0x20, 0x30]⟩
         codeviewAge := some 7, pdbName := some "electron.pdb", provenance := prov }]
    threads :=
      [{ id := 17, registers := (RegisterSet.new.set X64.RIP 0x140000111).set X64.RSP 0x1010
         stackVa := 0x1000, stackSize := 0x100, tebVa := 0x7000, provenance := prov }]
    exception := some
      { code := 0xC0000005, address := 0x140000111, threadId := 17, flags := 2
        parameters := [1, 0xDEADC0DE]
        context := some ((RegisterSet.new.set X64.RIP 0x140000111).set X64.RAX 0xDEADC0DE)
        provenance := prov }
    annotations := [("fatal_location", "allocation.cc:123")]
    v8heapExt := some
      { allocTopVa := 0x2000, allocLimitVa := 0x2000
        gcState := 1, fatalMessage := some "allocation failed" }
    memoryInfo :=
      [{ vaStart := 0x1000, size := 0x100, protection := 3, state := .Commit, memType := .Private },
       { vaStart := 0x2000, size := 0x100, protection := 0, state := .Reserve, memType := .Private },
       { vaStart := 0x3000, size := 0x100, protection := 0, state := .Free, memType := .Private },
       { vaStart := 0x4000, size := 0x100, protection := 5, state := .Commit, memType := .Image }]
    anomalies := [Anomaly.ofProv prov "partially captured memory"] }

private def space : Spec.AddressSpace :=
  { regions := [{ vaStart := 0x1000, size := 0x100, data := ⟨#[0xAA, 0xBB]⟩
                  protection := 3, classification := .Stack }]
    maxRegions := 64 }

private def isUnknown : MemoryRead → Bool
  | .unknown => true
  | _ => false

private def isAbsent : MemoryRead → Bool
  | .absent => true
  | _ => false

/-- One real ThreadList record whose context descriptor is varied independently
    of its stack metadata. The backing includes 256 zero bytes at RVA 64. -/
private def decodedThreadInput (contextSize contextRva : UInt32) : Option AnalysisInput := do
  let fields : List (Nat × UInt32) :=
    [(0, 1), (4, 17), (28, 0x1000), (36, 0x100), (44, contextSize), (48, contextRva)]
  let record := ByteArray.mk (fields.foldl (init := Array.replicate 52 (0 : UInt8))
    fun bytes (offset, value) =>
      (List.range 4).foldl (init := bytes) fun acc i =>
        acc.set! (offset + i) (value >>> (8 * UInt32.ofNat i)).toUInt8)
  let backing := ByteArray.mk (Array.replicate 320 0)
  let threads ← (Parse.Minidump.decodeThreadList record backing prov).toOption
  pure (AnalysisInput.ofDump { threads } (Spec.AddressSpace.new 64) "context-fixture")

private def lacksDecodedRegisters (input : Option AnalysisInput) : Bool :=
  match input with
  | none => false
  | some a =>
    a.threads.isEmpty && a.stackRanges == [(17, 0x1000, 0x100)]
      && (match a.point.threads with
          | [t] => match t.registers with | .unavailable _ => true | _ => false
          | _ => false)

private def le32 (value : UInt32) : List UInt8 :=
  (List.range 4).map fun i => (value >>> (8 * UInt32.ofNat i)).toUInt8

private def le64 (value : UInt64) : List UInt8 :=
  (List.range 8).map fun i => (value >>> (8 * UInt64.ofNat i)).toUInt8

/-- Native MINIDUMP_MEMORY_INFO: AllocationBase at +8 is deliberately different
    from RegionSize at +24; AllocationProtect at +16 differs from Protect +36. -/
private def nativeMemoryInfoEntry (va allocationBase size : UInt64)
    (state protection memType : UInt32) : List UInt8 :=
  le64 va ++ le64 allocationBase ++ le32 0x04 ++ le32 0 ++ le64 size
    ++ le32 state ++ le32 protection ++ le32 memType ++ le32 0

private def memoryInfoTable (firstState : UInt32 := 0x1000)
    (headerSize : UInt32 := 16) (entrySize : UInt32 := 48)
    (firstVa : UInt64 := 0x1000) (firstSize : UInt64 := 0x100) : ByteArray :=
  ByteArray.mk (le32 headerSize ++ le32 entrySize ++ le64 3
    ++ nativeMemoryInfoEntry firstVa 0xDEAD0000 firstSize firstState 0x140 0x1000000
    ++ nativeMemoryInfoEntry 0x2000 0xABAD0000 0x100 0x2000 0x01 0x40000
    ++ nativeMemoryInfoEntry 0x3000 0 0x100 0x10000 0 0).toArray

/-- Parse both native MemoryInfoList and a MemoryList with two captured bytes,
    then use the shipping address-space builder and capture adapter. -/
private def parsedMemoryInput (info : ByteArray) : Option AnalysisInput := do
  let memoryListRva := UInt32.ofNat (56 + info.size)
  let payloadRva := memoryListRva + 20
  let header := le32 0x504D444D ++ le32 0xA793 ++ le32 2 ++ le32 32
    ++ List.replicate 16 0
  let directory := le32 0x10 ++ le32 (UInt32.ofNat info.size) ++ le32 56
    ++ le32 5 ++ le32 20 ++ le32 memoryListRva
  let memoryList := le32 1 ++ le64 0x1000 ++ le32 2 ++ le32 payloadRva
  let bytes := ByteArray.mk
    (header ++ directory ++ info.data.toList ++ memoryList ++ [0xAA, 0xBB]).toArray
  let dump ← (Parse.Minidump.fromBytes bytes).toOption
  pure (AnalysisInput.ofDump dump (buildAddressSpace dump) "native-memory-fixture")

private def rejectsMemoryInfo (info : ByteArray) : Bool :=
  match parsedMemoryInput info with
  | none => false
  | some a => a.memoryInfo.isEmpty
      && a.anomalies.any (fun anomaly => anomaly.streamType == 0x10)
      && isUnknown (a.point.memory.read 0x2000 1)
      && !a.point.memory.knownAbsent 0x2000

def runAll : IO UInt32 := do
  let ctx : Ctx := ⟨← IO.mkRef 0⟩
  let input := AnalysisInput.ofDump captured space "capture-A"

  check ctx "execution capture has source identity without a trace coordinate"
    (input.point.id == { source := "capture-A", position := .capture }
      && input.point.threads.all (fun t => t.lifetime.isNone))
  check ctx "execution capture retains observed registers and stack range"
    (match input.threads with
     | [t] => t.id == 17 && t.registers.rip == 0x140000111
         && t.registers.rsp == 0x1010 && t.stackVa == 0x1000
         && t.stackSize == 0x100 && t.tebVa == 0x7000
     | _ => false)
  check ctx "execution capture preserves full exception evidence"
    (match input.exception with
     | some e => e.code == 0xC0000005 && e.address == 0x140000111 && e.threadId == 17
         && e.flags == 2 && e.parameters == [1, 0xDEADC0DE]
         && e.context.map (·.get X64.RAX) == some 0xDEADC0DE
         && decide (e.provenance = prov)
     | none => false)
  check ctx "execution capture keeps module identity for symbol verification"
    (match input.modules with
     | [m] => m.name == "electron.exe" && m.baseVa == 0x140000000 && m.size == 0x10000
         && m.checksum == 0xDEAD && m.codeviewAge == some 7
         && m.pdbName == some "electron.pdb"
         && (m.codeviewGuid.map (·.data)) == some #[0x10, 0x20, 0x30]
         && decide (m.provenance = prov)
     | _ => false)
  check ctx "execution capture retains system and mapping metadata"
    ((match input.systemInfo with
      | some s => s.os == .Windows && s.cpu == .X64 && s.version == (10, 0, 22621, 0)
      | none => false)
      && input.memoryInfo.any (fun r => r.vaStart == 0x4000 && r.state == .Commit
          && r.memType == .Image && r.protection == 5 && r.size == 0x100))
  check ctx "execution capture retains positioned diagnosis facts and anomalies"
    (input.annotations == [("fatal_location", "allocation.cc:123")]
      && input.v8heapExt.bind (·.fatalMessage) == some "allocation failed"
      && input.anomalies.any (fun a => a.description == "partially captured memory"
          && decide (a.fileOffset = prov.fileOffset)))
  check ctx "execution capture coverage stays incomplete"
    (input.point.memory.byteCoverage == .incomplete
      && input.point.memory.mappingCoverage == .incomplete
      && input.point.threadCoverage == .incomplete && input.point.eventCoverage == .incomplete)

  let moved := { input with point := { input.point with
    id := { source := "capture-A", position := .trace 12 } } }
  check ctx "execution another position cannot inherit capture observations or active modules"
    (moved.annotations.isEmpty && moved.v8heapExt.isNone && moved.modules.isEmpty)
  check ctx "execution source context can retain system facts across its positions"
    (moved.systemInfo.isSome)
  let foreign := { input with point := { input.point with
    id := { source := "capture-B", position := .capture } } }
  check ctx "execution another source cannot inherit observations modules or system facts"
    (foreign.annotations.isEmpty && foreign.v8heapExt.isNone
      && foreign.modules.isEmpty && foreign.systemInfo.isNone)
  let unrelated : List PositionedEvidence :=
    [{ pointId := foreign.point.id, annotations := [("wrong-source", "value")]
       v8heapExt := some { fatalMessage := some "wrong-source" } },
     { pointId := moved.point.id, annotations := [("wrong-position", "value")]
       v8heapExt := some { fatalMessage := some "wrong-position" } }]
  let mixed := { input with context := { input.context with
    observations := unrelated ++ input.context.observations } }
  check ctx "execution observation lookup skips unrelated evidence before current evidence"
    (mixed.annotations == input.annotations
      && mixed.v8heapExt.bind (·.fatalMessage) == some "allocation failed")

  let unknown : ThreadState := { id := 17, stackRange := .known ⟨0x1000, 0x100⟩ }
  let unavailable : ThreadState :=
    { unknown with registers := .unavailable "source has no register query" }
  let knownZero : ThreadState := { unknown with registers := .known RegisterSet.new }
  check ctx "execution unknown and unavailable registers never become zero registers"
    (unknown.observedThread.isNone && unavailable.observedThread.isNone
      && (knownZero.observedThread.map (·.registers.rip)) == some 0)
  check ctx "execution missing parsed thread context stays unavailable after capture adaptation"
    (lacksDecodedRegisters (decodedThreadInput 0 0)
      && lacksDecodedRegisters (decodedThreadInput 256 0))
  check ctx "execution truncated parsed thread context stays unavailable after capture adaptation"
    (lacksDecodedRegisters (decodedThreadInput 128 64))
  check ctx "execution out of bounds parsed thread context stays unavailable after capture adaptation"
    (lacksDecodedRegisters (decodedThreadInput 256 512))
  check ctx "execution valid all zero parsed thread context remains known"
    (match decodedThreadInput 256 64 with
     | some a =>
       (match a.point.threads with
        | [t] => match t.registers with
          | .known registers => registers.values.size == 32 && registers.values.all (· == 0)
          | _ => false
        | _ => false)
       && a.threads.length == 1 && a.stackRanges == [(17, 0x1000, 0x100)]
     | none => false)
  let noStack : ThreadState := { knownZero with stackRange := .unknown }
  check ctx "execution register knowledge alone cannot fabricate a stack range"
    (noStack.observedThread.isNone)
  let stackOnly : AnalysisInput :=
    { point := { id := input.point.id, threads := [unknown, unavailable] }
      context := { pointId := input.point.id } }
  check ctx "execution stack ranges remain accessible without register observations"
    (stackOnly.threads.isEmpty
      && stackOnly.stackRanges == [(17, 0x1000, 0x100), (17, 0x1000, 0x100)])
  let first : ThreadState := { unknown with lifetime := some ⟨1, some 5⟩ }
  let reused : ThreadState := { unknown with lifetime := some ⟨7, none⟩ }
  let threaded : ExecutionPoint := { id := input.point.id, threads := [first, reused] }
  check ctx "execution thread lookup distinguishes reused OS ids by lifetime start"
    (first.key != reused.key
      && (threaded.threadAt (17, some 1)).map (·.key) == some first.key
      && (threaded.threadAt (17, some 7)).map (·.key) == some reused.key
      && (threaded.threadAt (17, none)).isNone)
  let duplicate := { threaded with threads := [first, first, reused] }
  check ctx "execution ambiguous duplicate thread instances fail closed"
    ((duplicate.threadAt first.key).isNone && (duplicate.threadAt reused.key).isSome)

  check ctx "execution memory returns captured bytes"
    (match input.point.memory.read 0x1000 2 with
     | .known bytes => bytes.data == #[0xAA, 0xBB]
     | _ => false)
  check ctx "execution committed mapping with missing bytes remains unknown"
    (isUnknown (input.point.memory.read 0x1002 1)
      && isUnknown (input.point.memory.read 0x4000 1)
      && !input.point.memory.knownAbsent 0x4000)
  check ctx "execution reserve and free metadata provide positive byte absence"
    (isAbsent (input.point.memory.read 0x2000 1)
      && isAbsent (input.point.memory.read 0x3000 1))
  check ctx "execution uncaptured gaps never imply an absent mapping"
    (isUnknown (input.point.memory.read 0x5000 1)
      && !input.point.memory.knownAbsent 0x5000)
  let absentPage : MemoryState := { absentRanges := [⟨0x6000, 0x100⟩] }
  check ctx "execution explicit absence is range scoped and independent of byte coverage"
    (isAbsent (absentPage.read 0x6000 1)
      && isUnknown (absentPage.read 0x6100 1)
      && absentPage.byteCoverage == .unknown)
  check ctx "execution partial absence cannot classify an entire spanning read"
    (isUnknown (absentPage.read 0x60FF 2))

  let nativeInfo := memoryInfoTable
  let nativeInput := parsedMemoryInput nativeInfo
  check ctx "execution native memory states preserve commitment and positive absence"
    (match nativeInput with
     | some a => a.memoryInfo.map (·.state) == [.Commit, .Reserve, .Free]
         && isAbsent (a.point.memory.read 0x2000 1)
         && isAbsent (a.point.memory.read 0x3000 1)
         && isUnknown (a.point.memory.read 0x1002 1)
         && (match a.point.memory.read 0x1000 2 with
             | .known bytes => bytes.data == #[0xAA, 0xBB]
             | _ => false)
     | none => false)
  check ctx "execution native mapping types survive capture adaptation"
    (match nativeInput with
     | some a => (a.memoryInfo.take 2).map (·.memType) == [.Image, .Mapped]
         && (a.space.regionAt 0x1000).map (·.classification) == some .Image
     | none => false)
  check ctx "execution native protection translates for bytes while mappings keep PAGE flags"
    (match nativeInput with
     | some a => a.memoryInfo.head?.map (·.protection) == some 0x140
         && (a.space.regionAt 0x1000).map (·.protection)
           == some (Protection.READ ||| Protection.WRITE ||| Protection.EXECUTE ||| Protection.GUARD)
     | none => false)
  check ctx "execution native memory region size is independent of AllocationBase"
    (match Parse.Minidump.decodeMemoryInfoList nativeInfo prov with
     | .ok (entry :: _) => entry.vaStart == 0x1000 && entry.size == 0x100
         && entry.protection == 0x140
     | _ => false)
  check ctx "execution unknown native state cannot become positive absence"
    (rejectsMemoryInfo (memoryInfoTable 0)
      && rejectsMemoryInfo (memoryInfoTable 0x8000))
  check ctx "execution invalid declared memory header and entry sizes are anomalous"
    (rejectsMemoryInfo (memoryInfoTable 0x1000 8)
      && rejectsMemoryInfo (memoryInfoTable 0x1000 256)
      && rejectsMemoryInfo (memoryInfoTable 0x1000 16 40))
  check ctx "execution truncated native memory headers and entries cannot establish absence"
    (rejectsMemoryInfo (nativeInfo.extract 0 15)
      && rejectsMemoryInfo (nativeInfo.extract 0 63))
  check ctx "execution invalid native memory ranges cannot establish absence"
    (rejectsMemoryInfo (memoryInfoTable 0x1000 16 48 0x1000 0)
      && rejectsMemoryInfo (memoryInfoTable 0x1000 16 48 0xFFFFFFFFFFFFFFF0 0x100))

  let load : ExecutionEvent := { kind := .ModuleLoad, name := "electron.exe" }
  let ex1 : ExecutionEvent := { kind := .Exception, code := 1, threadId := 17 }
  let ex2 : ExecutionEvent := { kind := .Exception, code := 2, threadId := 18 }
  let ambiguous : AnalysisInput :=
    { point := { id := input.point.id, events := [load, ex1, ex2] }
      context := { pointId := input.point.id } }
  check ctx "execution multiple exceptions require selection"
    (ambiguous.exception.isNone)
  let selectedFirst := { ambiguous with selectedEvent := some 1 }
  let selectedSecond := { ambiguous with selectedEvent := some 2 }
  let selectedLoad := { ambiguous with selectedEvent := some 0 }
  let selectedMissing := { ambiguous with selectedEvent := some 3 }
  check ctx "execution selection identifies the exact event index"
    (selectedFirst.exception.map (·.code) == some 1
      && selectedSecond.exception.map (·.threadId) == some 18)
  check ctx "execution invalid or nonexception selection does not fall back"
    (selectedLoad.exception.isNone && selectedMissing.exception.isNone)
  let sole := { ambiguous with point := { ambiguous.point with events := [load, ex1] } }
  check ctx "execution sole exception is usable alongside nonexception events"
    (sole.exception.map (·.code) == some 1)

  let n ← ctx.failures.get
  IO.println (if n == 0 then "== ALL EXECUTION GUARDS PASSED =="
    else s!"== {n} EXECUTION FAILURE(S) ==")
  pure n.toUInt32

end Test.Execution

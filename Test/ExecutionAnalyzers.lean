/- Behavioral guards for source-neutral analyzers and incomplete knowledge. -/
import Forensicator.Analyzer.Registry

namespace Test.ExecutionAnalyzers

open Forensicator Forensicator.Model Forensicator.Spec

private def pointId : PointId := { source := "analyzer-fixture", position := .trace 3 }

private def faultEvent : ExecutionEvent :=
  { kind := .Exception, code := 0xC0000005, address := 0x140001000
    threadId := 7, parameters := [0, 0x200080000] }

private def input : AnalysisInput :=
  { point := { id := pointId, events := [faultEvent] }
    context :=
      { pointId
        observations := [{ pointId, annotations :=
          [("v8_ro_space_firstpage_address", "0x200000000")] }] } }

private def verdict (a : AnalysisInput) : Analyzer.Cause.CrashVerdict :=
  (Analyzer.Cause.diagnose a a.space).verdict

private def withMemory (a : AnalysisInput) (m : MemoryState) : AnalysisInput :=
  { a with point := { a.point with memory := m } }

private def withMapping (protection : UInt32) : AnalysisInput :=
  withMemory input { mappings :=
    [{ vaStart := faultEvent.address, size := 0x1000, state := .Commit
       memType := .Private, protection }] }

private def stackSpace : AddressSpace :=
  match (AddressSpace.new 8).addRegion
      { vaStart := 0x10000, size := 0x40, classification := .Stack
        data := ByteArray.mk (Array.replicate 0x40 0) } with
  | .ok s => s
  | .error _ => .new 8

private def stackInput : AnalysisInput :=
  { input with point :=
      { input.point with
        memory := { space := stackSpace }
        threads := [{ id := 7, registers := .unavailable "proxy has no register API"
                      stackRange := .known ⟨0x10000, 0x40⟩ }] } }

private def registers : RegisterSet :=
  ((RegisterSet.new.set X64.RIP 0x30000).set X64.RSP 0x10000).set X64.RBP 0x10000

private def observedInput : AnalysisInput :=
  { stackInput with point := { stackInput.point with threads :=
    [{ id := 7, registers := .known registers, stackRange := .known ⟨0x10000, 0x40⟩ }] } }

private def writeBytes (bytes : ByteArray) (offset : Nat) (values : List UInt8) : ByteArray :=
  ⟨values.zipIdx.foldl (fun acc (v, i) => acc.set! (offset + i) v) bytes.data⟩

private def leBytes (value : UInt64) (len : Nat) : List UInt8 :=
  (List.range len).map fun i => (value >>> (8 * UInt64.ofNat i)).toUInt8

private def write64 (bytes : ByteArray) (offset : Nat) (value : UInt64) : ByteArray :=
  writeBytes bytes offset (leBytes value 8)

private def walkModule : Module :=
  { name := "bounded-walk.exe", baseVa := 0x30000, size := 0x1000, provenance := {} }

private def walkRegs (rsp rbp : VA) : RegisterSet :=
  ((RegisterSet.new.set X64.RIP 0x30110).set X64.RSP rsp).set X64.RBP rbp

private def walkInput (regions : List AddressRegion) (rsp rbp : VA)
    (base : VA := 0x10000) (size : UInt64 := 0x40) : AnalysisInput :=
  { point := { id := pointId, memory := { space := { regions, maxRegions := 32 } }
               threads := [{ id := 7, registers := .known (walkRegs rsp rbp)
                             stackRange := .known ⟨base, size⟩ }] }
    context := { pointId, modules := [walkModule] } }

private def stackRegion (bytes : ByteArray) (base : VA := 0x10000) : AddressRegion :=
  { vaStart := base, size := UInt64.ofNat bytes.size, data := bytes, classification := .Stack }

private def walked (a : AnalysisInput) : List VA :=
  (Analyzer.V8.walkThreadStacks none a a.space).map (·.returnAddress)

/-- A complete minimal PE header with one runtime function. The unwind blob
    is parameterized so bounds guards exercise the actual legacy helper. -/
private def unwindRegion (unwind : List UInt8) : AddressRegion :=
  let fields : List (Nat × List UInt8) :=
    [(0, [0x4D, 0x5A]), (0x3C, leBytes 0x80 4), (0x80, [0x50, 0x45, 0, 0]),
     (0x98, [0x0B, 0x02]), (0x120, leBytes 0x400 4), (0x124, leBytes 12 4),
     (0x400, leBytes 0x100 4 ++ leBytes 0x200 4 ++ leBytes 0x500 4), (0x500, unwind)]
  { vaStart := walkModule.baseVa, size := walkModule.size, classification := .Image
    data := fields.foldl (fun bytes (offset, values) => writeBytes bytes offset values)
      ⟨Array.replicate 0x1000 0⟩ }

private def boundedUnwind (a : AnalysisInput) : Option RegisterSet :=
  Util.unwindStep (a.point.threads.head!.registers.toOption.getD .new) a.space walkModule.baseVa
    { begin := 0x100, stop := 0x200, unwindInfo := 0x500 } (some (0x10000, 0x40))

private def check (failures : IO.Ref Nat) (name : String) (ok : Bool) : IO Unit := do
  if ok then IO.println s!"ok    {name}"
  else
    failures.modify (· + 1)
    IO.println s!"FAIL  {name}"

def runAll : IO UInt32 := do
  let failures ← IO.mkRef 0
  let check := check failures
  check "execution cause: unknown cage bytes do not establish uncommitted memory"
    (verdict input == .wildAccess)
  let absent := withMemory input { absentRanges := [⟨0x200080000, 1⟩] }
  check "execution cause: positive cage absence supports decompressed garbage inference"
    (verdict absent == .decompressedGarbagePointer)
  let reserved := withMemory input { mappings :=
    [{ vaStart := 0x200080000, size := 0x1000, state := .Reserve
       memType := .Private, protection := 0 }] }
  check "execution cause: reserved mapping supplies positive cage evidence"
    (verdict reserved == .decompressedGarbagePointer)
  let absentCode := withMemory input { absentRanges := [⟨faultEvent.address, 1⟩] }
  check "execution cause: positive instruction-address absence supports corrupt code pointer"
    (verdict absentCode == .corruptedCodePointer)
  check "execution cause: observed native read-write mapping is non-executable"
    (verdict (withMapping 0x04) == .corruptedCodePointer)
  check "execution cause: unknown native protection does not establish non-executable memory"
    (verdict (withMapping 0) == .wildAccess)
  check "execution cause: executable native mapping is not a corrupt code pointer"
    (verdict (withMapping 0x20) == .wildAccess)
  let unknownProtection := match (AddressSpace.new 8).addRegion
      { vaStart := faultEvent.address, size := 1, data := ByteArray.mk #[0x90] } with
    | .ok space => withMemory input { space }
    | .error _ => input
  check "execution cause: page bytes with default protection do not prove mapping protection"
    (verdict unknownProtection == .wildAccess)

  let overflow : ExecutionEvent := { faultEvent with code := 0xC00000FD }
  let ambiguous := { input with point := { input.point with events := [faultEvent, overflow] } }
  check "execution cause: multiple unselected exceptions fail closed"
    (verdict ambiguous == .unknown)
  check "execution cause: explicit event selection selects the current exception"
    (verdict { ambiguous with selectedEvent := some 1 } == .stackOverflow)

  let fatal := { input with context := { input.context with observations :=
    [{ pointId, annotations := [("v8_fatal_message", "Check failed: fixture")] }] } }
  check "execution cause: same-point fatal observation is available"
    (verdict fatal == .v8CheckFailure)
  let moved := { fatal with point := { fatal.point with id := { pointId with position := .trace 4 } } }
  check "execution cause: prior-point fatal observation does not leak after cursor movement"
    (verdict moved == .wildAccess)

  check "execution V8: unavailable registers do not fabricate stack frames"
    ((Analyzer.V8.walkThreadStacks none stackInput stackInput.space).isEmpty)
  check "execution V8: missing contexts are reported separately from recovered frame count"
    ((Analyzer.V8.analyzer.run {} stackInput).custom.any (·.1 == "v8_unavailable_threads"))
  let selectedContext := { stackInput with point := { stackInput.point with
    events := [{ faultEvent with context := some registers }] } }
  check "execution V8: exact exception context supplies unavailable thread registers"
    ((Analyzer.V8.walkThreadStacks none selectedContext selectedContext.space).head?.map
      (·.returnAddress) == some 0x30000)
  let partialThreads := { observedInput with point := { observedInput.point with
    threads := observedInput.point.threads ++
      [{ id := 8, registers := .unavailable "not captured", stackRange := .unknown }] } }
  let frames := Analyzer.V8.walkThreadStacks none partialThreads partialThreads.space
  check "execution V8: supported threads survive unavailable neighboring threads"
    (!frames.isEmpty && frames.all (·.threadId == 7))

  let modules : List Module :=
    [{ name := "first.dll", baseVa := 0x30000, size := 0x1000, provenance := {} },
     { name := "second.dll", baseVa := 0x50000, size := 0x1000, provenance := {} }]
  let symbolInput := { observedInput with context := { observedInput.context with modules } }
  let pubs : Util.Publics := { entries := #[(0, "bound_symbol")] }
  let right := Analyzer.V8.walkThreadStacks (some pubs) symbolInput symbolInput.space (some 0x30000)
  let wrong := Analyzer.V8.walkThreadStacks (some pubs) symbolInput symbolInput.space (some 0x50000)
  check "execution V8: bound symbols resolve their verified module"
    (right.head?.map (·.nativeSymbol) == some "bound_symbol+0x0")
  check "execution V8: bound symbols do not label another active module"
    (wrong.head?.map (·.nativeSymbol) == some "0x30000")

  -- Captured bytes can extend beyond the declared thread stack. Neither V8
  -- nor JIT (which uses this walker) may promote those adjacent bytes to frames.
  let adjacent := write64 (write64 ⟨Array.replicate 0x80 0⟩ 0x38 0x30210) 0x40 0x30310
  check "execution V8: final in-bounds leaf pop retains its caller and stops at stack end"
    (walked (walkInput [stackRegion adjacent] 0x10038 0) == [0x30110, 0x30210])
  check "execution V8: initial out-of-bounds RSP cannot consume adjacent memory"
    (walked (walkInput [stackRegion adjacent] 0x10040 0) == [0x30110])
  check "execution V8: leaf return slot must fit completely within stack bounds"
    (walked (walkInput [stackRegion (write64 adjacent 0x3C 0x30210)] 0x1003C 0) == [0x30110])
  let high : UInt64 := 0xFFFFFFFFFFFFFFF0
  let highBytes := write64 ⟨Array.replicate 0x20 0⟩ 8 0x30210
  check "execution V8: overflowing declared stack range cannot authorize a leaf pop"
    (walked (walkInput [stackRegion highBytes high] (high + 8) 0 high 0x20) == [0x30110])
  check "execution V8: leaf pop cannot wrap a one-past RSP at 2^64"
    (walked (walkInput [stackRegion highBytes high] (high + 8) 0 high 0x10) == [0x30110])

  let fpBytes := write64 (write64 ⟨Array.replicate 0x80 0⟩ 0x10 0x10030) 0x18 0x30210
  check "execution V8: supported monotonic frame-pointer chain remains available"
    (walked (walkInput [stackRegion fpBytes] 0x10000 0x10010) == [0x30110, 0x30210])
  check "execution V8: terminal frame-pointer link retains a module caller"
    (walked (walkInput [stackRegion (write64 fpBytes 0x10 0)] 0x10000 0x10010)
      == [0x30110, 0x30210])
  check "execution V8: frame-pointer record cannot read its return slot past stack end"
    (walked (walkInput [stackRegion adjacent] 0x10000 0x10038) == [0x30110])
  check "execution V8: frame-pointer fallback cannot move RSP backward"
    (walked (walkInput [stackRegion fpBytes] 0x10030 0x10010) == [0x30110])
  let highFp := write64 (write64 ⟨Array.replicate 0x10 0⟩ 0 0) 8 0x30210
  check "execution V8: frame-pointer pop cannot wrap RSP at 2^64"
    (walked (walkInput [stackRegion highFp high] high high high 0x10) == [0x30110])

  let nativeBytes := write64 ⟨Array.replicate 0x80 0⟩ 0x10 0x30210
  let native := walkInput [stackRegion nativeBytes, unwindRegion [1, 4, 1, 0, 4, 0x12]]
    0x10000 0
  check "execution V8: supported bounded native allocation retains its caller"
    (walked native == [0x30110, 0x30210])
  let nativeEscaped := walkInput [stackRegion adjacent, unwindRegion [1, 4, 1, 0, 4, 0x72]]
    0x10000 0
  check "execution V8: native allocation cannot pop an adjacent out-of-stack return address"
    (walked nativeEscaped == [0x30110] && (boundedUnwind nativeEscaped).isNone)
  let saveBytes := write64 (write64 ⟨Array.replicate 0x80 0⟩ 0 0x30210) 0x40 0x10030
  let nativeSaved := walkInput [stackRegion saveBytes,
      unwindRegion [1, 4, 2, 0, 4, 0x54, 8, 0]] 0x10000 0
  let unboundedSaved := Util.unwindStep (walkRegs 0x10000 0) nativeSaved.space walkModule.baseVa
    { begin := 0x100, stop := 0x200, unwindInfo := 0x500 }
  check "execution V8: native SAVE_NONVOL cannot read outside bounds with a valid final RSP"
    ((boundedUnwind nativeSaved).isNone &&
      match unboundedSaved with
      | some regs => regs.rsp == 0x10008 && regs.rbp == 0x10030 && regs.rip == 0x30210
      | none => false)
  let savedGood := walkInput [stackRegion (write64 saveBytes 0x10 0x10030),
      unwindRegion [1, 4, 2, 0, 4, 0x54, 2, 0]] 0x10000 0
  check "execution V8: bounded SAVE_NONVOL retains supported register restoration"
    ((boundedUnwind savedGood).map (·.rbp) == some 0x10030
      && walked savedGood == [0x30110, 0x30210])
  let pushed := walkInput [stackRegion (write64 (write64 saveBytes 0 0x10030) 8 0x30210),
      unwindRegion [1, 4, 1, 0, 4, 0x50]] 0x10000 0
  check "execution V8: bounded PUSH_NONVOL retains supported native callers"
    ((boundedUnwind pushed).map (·.rbp) == some 0x10030
      && walked pushed == [0x30110, 0x30210])
  let nativeFar := walkInput [stackRegion saveBytes,
      unwindRegion [1, 4, 3, 0, 4, 0x55, 0x40, 0, 0, 0]] 0x10000 0
  check "execution V8: native SAVE_NONVOL_FAR also confines restored registers"
    ((boundedUnwind nativeFar).isNone)
  let nativeBack := walkInput [stackRegion saveBytes,
      unwindRegion [1, 4, 1, 5, 4, 3]] 0x10010 0x10000
  check "execution V8: native SET_FPREG cannot move intermediate RSP backward"
    ((boundedUnwind nativeBack).isNone)
  let restoredRsp := write64 saveBytes 0x10 0xFFF0
  let nativeRestored := walkInput [stackRegion restoredRsp,
      unwindRegion [1, 4, 2, 0, 4, 0x44, 2, 0]] 0x10000 0
  check "execution V8: restored RSP is checked before subsequent native reads"
    ((boundedUnwind nativeRestored).isNone)
  let nativeWrap := walkInput [stackRegion highBytes high,
      unwindRegion [1, 4, 1, 0, 4, 0x12],
      stackRegion (write64 ⟨Array.replicate 0x20 0⟩ 8 0x30210) 0]
    (high + 8) 0 high 0x10
  check "execution V8: native intermediate allocation cannot wrap into low memory"
    ((Util.unwindStep (walkRegs (high + 8) 0) nativeWrap.space walkModule.baseVa
      { begin := 0x100, stop := 0x200, unwindInfo := 0x500 } (some (high, 0x10))).isNone
      && walked nativeWrap == [0x30110])

  let pointerSpace := match (AddressSpace.new 8).addRegion
      { vaStart := 0x10000, size := 8, classification := .Stack
        data := ByteArray.mk #[0, 0, 2, 0, 0, 0, 0, 0] } with
    | .ok s => s
    | .error _ => .new 8
  let stackOnly := withMemory stackInput { space := pointerSpace }
  let candidates := Analyzer.pointerScan pointerSpace stackOnly [PointerPattern.allLoose]
  check "execution pointer scan: stack ownership does not require register knowledge"
    (candidates.any fun c => match c.sourceCtx with
      | .stack (some id) => id == 7
      | _ => false)

  -- A prepared page can have known bytes with no classification/protection
  -- metadata. Generic inference must consume those bytes without calling it
  -- heap or image memory. The same contract applies to sparse captures.
  let pageBytes := (ByteArray.mk #[8, 0, 1, 0, 0, 0, 0, 0,
                                16, 0, 1, 0, 0, 0, 0, 0,
                                24, 0, 1, 0, 0, 0, 0, 0]).append
                    ("known page string".toUTF8.push 0)
  let page (classification : RegionClass) : AnalysisInput :=
    match (AddressSpace.new 8).addRegion
        { vaStart := 0x10000, size := 0x1000, data := pageBytes, classification } with
    | .ok space => withMemory input { space }
    | .error _ => input
  let unclassified := page .Other
  let imagePage := page .Image
  let scanned := Analyzer.pointerScan unclassified.space unclassified [PointerPattern.allLoose]
  let imageScanned := Analyzer.pointerScan imagePage.space imagePage [PointerPattern.allLoose]
  check "execution scanning: known unclassified page yields strings"
    (((Analyzer.Strings.analyzer {}).run {} unclassified).strings.any fun s =>
      s.content == "known page string" && s.va == 0x10018)
  check "execution scanning: known unclassified page yields pointer candidates"
    (scanned.length == 3 && scanned.all fun c => match c.sourceCtx, c.targetCtx with
      | .anyCommitted, .anyReadable => true
      | _, _ => false)
  check "execution scanning: unknown target classification receives no image confidence bonus"
    (match scanned.head?, imageScanned.head? with
      | some a, some b => a.confidence < b.confidence
      | _, _ => false)
  let arrays := ((Analyzer.Arrays.analyzer {}).run {} unclassified).arrays
  let imageArrays := ((Analyzer.Arrays.analyzer {}).run {} imagePage).arrays
  check "execution scanning: unclassified pointer stride yields an array with unknown class"
    (arrays.any fun a => a.startVa == 0x10000 && a.count == 3 && a.regionClass == .Other)
  check "execution scanning: unknown array class omits classification corroboration"
    (match arrays.head?, imageArrays.head? with
      | some a, some b => a.confidence < b.confidence
      | _, _ => false)
  check "execution scanning: unclassified pointer chain yields linked-list inference"
    (((Analyzer.Lists.analyzer {}).run {} unclassified).linkedLists.any fun l =>
      l.headVa == 0x10000 && l.length == 4)
  check "execution scanning: shape inference preserves unknown target classification"
    ((Analyzer.Shapes.analyzer.run {} unclassified).shapeClusters.any fun g =>
      g.memberCount == 3 && g.signature.edges.all (·.2 == .Other))
  check "execution scanning: unknown mapping class does not invent heap chunks or vtables"
    (((Analyzer.Chunks.analyzer {}).run {} unclassified).chunks.isEmpty
      && ((Analyzer.Vtables.analyzer {}).run {} unclassified).vtables.isEmpty)

  let n ← failures.get
  IO.println (if n == 0 then "== ALL EXECUTION ANALYZER GUARDS PASSED =="
    else s!"== {n} EXECUTION ANALYZER FAILURE(S) ==")
  pure n.toUInt32

end Test.ExecutionAnalyzers

/- Forensicator.Analyzer.Jit — V8 type-feedback recovery (Phase 1, in-cage).
    Walks each recovered JSFunction's feedback_cell → FeedbackVector → IC
    slots, decoding the type state Turbofan trusted. This is the missing
    link for JIT type-confusion root-cause: it shows *which types* the
    compiler assumed and *which guard* it eliminated.

    Design: docs/analyzers/2026-08-26-v8-type-feedback-recovery-design.md
    Phase 1 only — no trusted-space crossing (Code, BytecodeArray,
    DeoptimizationData are Phase 2, future milestone). -/
import Forensicator.Analyzer.Analyzer
import Forensicator.Analyzer.V8
import Forensicator.Analyzer.Cause
import Forensicator.Util.V8Layout
import Forensicator.Util.V8Obj
import Forensicator.Util.Json
import Forensicator.Util.Text

namespace Forensicator.Analyzer.Jit

open Forensicator.Model Forensicator.Spec Forensicator.Util

/-- The state of a single feedback slot (IC state classification). -/
inductive SlotState where
  /-- Uninitialized — no feedback recorded yet (Smi 0). -/
  | uninitialized
  /-- Monomorphic — one type observed (single HeapObject ptr, usually a Map). -/
  | monomorphic (obj : VA) (instanceType : Option UInt16)
  /-- Polymorphic — multiple types observed (WeakArrayList of maps/functions). -/
  | polymorphic (count : Nat)
  /-- Smi-encoded feedback (e.g., call count, element kind). -/
  | smiFeedback (value : Int)
  /-- Could not classify — recorded for completeness but not actionable. -/
  | unknown
  deriving Repr, Inhabited

/-- A decoded feedback slot. -/
structure FeedbackSlot where
  index : Nat
  raw : UInt32
  state : SlotState
  deriving Inhabited

/-- Phase 2: Code object resolved via JSDispatchTable. -/
structure CodeResolution where
  /-- The dispatch_handle from JSFunction+12. -/
  dispatchHandle : UInt32
  /-- Entrypoint address (in CodeRange, from JSDT entry +0). -/
  entrypoint : VA
  /-- Code object address (in trusted space, from JSDT entry +8, low 48 bits). -/
  codeObject : VA
  /-- The return address of this frame (in the caller's Code). -/
  returnAddress : VA
  /-- Native offset: return_address - caller's entrypoint (if found). -/
  nativeOffset : Option UInt64
  /-- The caller's Code object (if the return address was matched to a JSDT entry). -/
  callerCodeObject : Option VA
  deriving Inhabited

/-- Type-feedback info recovered for a single JS frame. -/
structure JitFrameInfo where
  threadId : UInt32
  depth : Nat
  functionName : Option String
  scriptName : Option String
  scriptLine : Option UInt32
  feedbackVector : Option VA
  slotCount : Nat
  slots : List FeedbackSlot
  sfiCrosscheck : Bool
  /-- How the FeedbackVector was found (or why it wasn't). -/
  feedbackPath : String
  /-- Phase 2: Code object resolution via JSDT. -/
  codeResolution : Option CodeResolution
  deriving Inhabited

/-- Maximum slots to decode per frame (prevents pathological minified code). -/
def maxSlots : Nat := 256

/-- JSDT entry: entrypoint (u64) + code_object (u64, top 16 bits = param_count). -/
structure JSDTEntry where
  entrypoint : VA
  codeObject : VA
  deriving Inhabited

/-- JSDispatchTable handle shift for V8 14.6 (Electron 41).
    In sandbox mode with lower-limits: 12. Without: 8.
    Electron 41 uses shift=16 empirically (verified against the case dump:
    dispatch_handle 0x023d6a00 >> 16 = 573, which maps to a valid JSDT entry
    whose entrypoint is in the CodeRange). -/
def jsdtHandleShift : Nat := 16

/-- JSDT entry size: 16 bytes (kJSDispatchTableEntrySize). -/
def jsdtEntrySize : UInt64 := 16

/-- Code object pointer payload mask: low 48 bits (top 16 bits = parameter count). -/
def codePtrMask : UInt64 := 0x0000FFFFFFFFFFFF

/-- A discovered JSDT segment: base address and entry count. -/
structure JSDTSegment where
  base : VA
  entryCount : Nat
  deriving Inhabited

/-- Count consecutive JSDT entries starting at `off` in `data`.
    Returns (count, nextOffsetAfterTheRun). -/
private def countConsecutive (data : ByteArray) (off : Nat)
    (crStart crEnd : VA) (count : Nat) : Nat × Nat :=
  if off + 16 > data.size then (count, off)
  else
    let ep := readU64leAt data off
    if ep ≥ crStart && ep < crEnd then
      countConsecutive data (off + 16) crStart crEnd (count + 1)
    else (count, off)
  termination_by data.size - off

/-- Scan a single region for JSDT segments. -/
private def scanRegion (r : AddressRegion) (space : AddressSpace)
    (crStart crEnd : VA) : List JSDTSegment :=
  let rec scan (off : Nat) (acc : List JSDTSegment) : List JSDTSegment :=
    if off + 16 > r.data.size then acc
    else
      let ep := readU64leAt r.data off
      if ep ≥ crStart && ep < crEnd then
        let (count, nextOff) := countConsecutive r.data off crStart crEnd 0
        if count ≥ 2 then
          let seg : JSDTSegment := { base := r.vaStart + UInt64.ofNat off, entryCount := count }
          -- nextOff = off + 16 * count, and count ≥ 2, so nextOff ≥ off + 32 > off
          scan (off + 16 * count) (acc ++ [seg])
        else
          scan (off + 16) acc
      else
        scan (off + 16) acc
  termination_by r.data.size - off
  scan 0 []

/-- Discover JSDT segments by scanning all regions for consecutive 16-byte
    entries where the first u64 (entrypoint) points into the CodeRange.
    A segment is a run of ≥2 consecutive such entries. -/
private def discoverJSDTSegments (space : AddressSpace)
    (codeRangeStart codeRangeEnd : VA) : List JSDTSegment :=
  let rec scanRegions (regs : List AddressRegion) (acc : List JSDTSegment) :
      List JSDTSegment :=
    match regs with
    | [] => acc
    | r :: rest =>
      if r.vaStart ≥ codeRangeStart && r.vaStart < codeRangeEnd then
        scanRegions rest acc
      else
        let found := scanRegion r space codeRangeStart codeRangeEnd
        scanRegions rest (acc ++ found)
  scanRegions space.regions []

/-- Read a JSDT entry at `segBase + entrySize * index`. -/
private def readJSDTEntry (space : AddressSpace) (segBase : VA) (index : Nat) :
    Option JSDTEntry := do
  let addr := segBase + jsdtEntrySize * UInt64.ofNat index
  let ep ← Util.readU64o space addr
  let cp ← Util.readU64o space (addr + 8)
  let codeObj := cp &&& codePtrMask
  if codeObj == 0 then none
  else some { entrypoint := ep, codeObject := codeObj }

/-- Resolve a JSFunction's dispatch_handle to a Code object via the JSDT.
    Tries each discovered segment; the correct segment has enough entries
    to contain the index. -/
private def resolveViaJSDT (space : AddressSpace)
    (segments : List JSDTSegment) (dispatchHandle : UInt32) :
    Option JSDTEntry :=
  let index := dispatchHandle.toNat.shiftRight jsdtHandleShift
  let rec trySegs (segs : List JSDTSegment) : Option JSDTEntry :=
    match segs with
    | [] => none
    | seg :: rest =>
      if index < seg.entryCount then
        readJSDTEntry space seg.base index
      else trySegs rest
  trySegs segments

/-- Find the JSDT entry whose entrypoint is the largest value ≤ `retAddr`
    and in the CodeRange. This identifies the CALLER's Code object (the
    Code that contains the call site that produced the return address). -/
private def findCallerCode (space : AddressSpace)
    (segments : List JSDTSegment) (retAddr : VA) : Option (JSDTEntry × UInt64) :=
  let rec scanSegs (segs : List JSDTSegment) (best : Option (JSDTEntry × UInt64)) :
      Option (JSDTEntry × UInt64) :=
    match segs with
    | [] => best
    | seg :: rest =>
      let rec scanEntries (i : Nat) (best : Option (JSDTEntry × UInt64)) :
          Option (JSDTEntry × UInt64) :=
        if i ≥ seg.entryCount then best
        else
          match readJSDTEntry space seg.base i with
          | some entry =>
            if entry.entrypoint ≤ retAddr then
              -- This is a candidate; check if it's better than current best
              let newBest :=
                match best with
                | none => some (entry, retAddr - entry.entrypoint)
                | some (_, off) =>
                  if (retAddr - entry.entrypoint) ≤ off then
                    some (entry, retAddr - entry.entrypoint)
                  else best
              scanEntries (i + 1) newBest
            else scanEntries (i + 1) best
          | none => scanEntries (i + 1) best
      termination_by seg.entryCount - i
      scanEntries 0 (scanSegs rest best)
  scanSegs segments none

/-- Discover the CodeRange bounds from the return addresses of all frames.
    The CodeRange is the region containing all Turbofan return addresses. -/
private def discoverCodeRange (frames : List V8.V8StackFrame) : Option (VA × VA) :=
  let jsFrames := frames.filter fun f =>
    f.frameType == .optimizedJavaScript || f.frameType == .javaScript
  let retAddrs := jsFrames.map (·.returnAddress)
  match retAddrs with
  | [] => none
  | first :: rest =>
    let lo := rest.foldl (min ·) first
    let hi := rest.foldl (max ·) first
    -- The CodeRange is a large region; expand bounds to page alignment
    let pageAlign (v : VA) := v &&& 0xFFFFFFFFFFFFF000
    let start := pageAlign lo
    -- Find the region containing `hi` and use its end
    some (start, hi + 0x1000)

/-- Decode a single feedback slot at `feedbackVector + slotsStart + 4*index`.
    Returns the raw value and the classified state. -/
private def decodeSlot (space : AddressSpace) (cage : VA) (fv : VA)
    (slotsStart : UInt64) (layout : V8Layout) (index : Nat) : Option FeedbackSlot := do
  let slotAddr := fv + slotsStart + 4 * UInt64.ofNat index
  let raw ← Util.readU32o space slotAddr
  -- Classify the slot state
  let st : SlotState :=
    if raw &&& 1 == 0 then
      -- Smi or uninitialized
      match Util.smi raw with
      | some 0 => .uninitialized
      | some v => .smiFeedback v
      | none => .unknown
    else
      -- HeapObject — try to decompress and read its instance type
      match Util.decompress cage raw with
      | none => .unknown
      | some obj =>
        match Util.instanceType space cage obj with
        | some itype =>
          if itype == layout.itypeMap then
            -- Monomorphic: single Map observed
            .monomorphic obj (some itype)
          else if itype == layout.itypeWeakArrayList then
            -- Polymorphic: WeakArrayList of maps/functions
            -- Read the array length (Smi at weakArrayListLength)
            match Util.readU32o space (obj + layout.weakArrayListLength) with
            | some lenRaw =>
              match Util.smi lenRaw with
              | some n =>
                if n < 0 || n.toNat > 64 then .unknown  -- sanity bound
                else .polymorphic n.toNat
              | none => .unknown
            | none => .unknown
          else
            -- Other HeapObject (could be a JSFunction for CALL_IC, etc.)
            .monomorphic obj (some itype)
        | none =>
          -- HeapObject but unreadable — still record the address
          .monomorphic obj none
  some { index := index, raw := raw, state := st }

/-- Decode all slots of a FeedbackVector. -/
private def decodeSlots (space : AddressSpace) (cage : VA) (fv : VA)
    (slotCount : Nat) (slotsStart : UInt64) (layout : V8Layout) :
    List FeedbackSlot :=
  let n := if slotCount > maxSlots then maxSlots else slotCount
  (List.range n).filterMap (decodeSlot space cage fv slotsStart layout ·)

/-- Decode a FeedbackVector starting at `fv`.
    Validates instance type == FEEDBACK_VECTOR_TYPE, reads slot count,
    cross-checks the SFI back-reference against the expected SFI address.
    Returns (vector_info, sfi_crosscheck_passed). -/
private def decodeFeedbackVector (space : AddressSpace) (cage : VA)
    (fv : VA) (expectedSfi : VA) (layout : V8Layout) :
    Option (Nat × List FeedbackSlot × Bool) := do
  -- Validate instance type
  let itype ← Util.instanceType space cage fv
  if itype != layout.itypeFeedbackVector then none
  -- Read slot count (int32 at feedbackVectorLength, NOT a Smi)
  let lenRaw ← Util.readU32o space (fv + layout.feedbackVectorLength)
  -- FeedbackVector.length is a raw int32, not Smi-tagged
  let slotCount ←
    if lenRaw == 0 then some 0
    else if lenRaw > 65536 then none  -- sanity bound
    else some lenRaw.toNat
  -- Cross-check SFI: feedbackVectorSfi should decompress to expectedSfi
  let sfiMatch :=
    match Util.readU32o space (fv + layout.feedbackVectorSfi) with
    | some sfiC =>
      match Util.decompress cage sfiC with
      | some sfi => sfi == expectedSfi
      | none => false
    | none => false
  -- Decode slots
  let slots := decodeSlots space cage fv slotCount layout.feedbackVectorSlots layout
  some (slotCount, slots, sfiMatch)

/-- Resolve the JSFunction from a frame pointer, mirroring V8.lean's
    decodeJsFrame validation (context round-trip). Returns the JSFunction
    heap address and its SFI address if validation passes. -/
private def resolveJsFunction (space : AddressSpace) (fp : VA)
    (cage : VA) (layout : V8Layout) : Option (VA × VA) := do
  -- [fp-16] = JSFunction (full tagged pointer)
  let tagged := Util.readU64 space (Util.wadd fp layout.kFunctionOffset)
  if tagged &&& 1 != 1 then none
  let heap := tagged &&& 0xFFFFFFFFFFFFFFFE
  -- Context round-trip: [fp-8] == decompress(fn+20)|1
  let frameCtx := Util.readU64 space (Util.wadd fp layout.kContextOffset)
  let fnCtx :=
    match Util.readU32o space (heap + layout.jsfunctionContext) with
    | some c => (Util.decompress cage c).map (· ||| 1)
    | none => none
  if fnCtx != some frameCtx then none
  -- Read SFI (compressed at fn+16)
  let sfiC ← Util.readU32o space (heap + layout.jsfunctionSharedFunctionInfo)
  let sfi ← Util.decompress cage sfiC
  some (heap, sfi)

/-- Try to find a FeedbackVector by scanning cage regions for objects whose
    SFI cross-reference (at feedbackVectorSfi) matches `expectedSfi`.
    This is a fallback for when the JSFunction → FeedbackCell path leads to
    a ClosureFeedbackCellArray (lazy feedback) instead of a FeedbackVector. -/
private def findFeedbackVectorBySfi (space : AddressSpace) (cage : VA)
    (expectedSfi : VA) (layout : V8Layout) : Option VA :=
  let sfiComp := ((expectedSfi - cage) ||| 1).toUInt32
  let needle := sfiComp
  -- Scan all regions in the cage for the SFI compressed value
  let rec scan (regions : List AddressRegion) : Option VA :=
    match regions with
    | [] => none
    | r :: rest =>
      -- Only scan regions inside the cage
      if r.vaStart ≥ cage + ((1 : UInt64) <<< 32) || r.vaStart + UInt64.ofNat r.data.size ≤ cage then
        scan rest
      else
        -- Search for the 4-byte needle in this region's data
        let rec search (off : Nat) : Option VA :=
          if off + 4 > r.data.size then none
          else
            let candidate := readU32leAt r.data off
            if candidate == needle then
              -- This could be the SFI field (+16) of a FeedbackVector at off-16
              let fvAddr := r.vaStart + UInt64.ofNat off - layout.feedbackVectorSfi
              -- Validate: is this a FeedbackVector?
              match Util.instanceType space cage fvAddr with
              | some itype =>
                if itype == layout.itypeFeedbackVector then some fvAddr
                else search (off + 4)
              | none => search (off + 4)
            else search (off + 4)
        termination_by r.data.size - off
        match search 0 with
        | some fv => some fv
        | none => scan rest
  scan space.regions

/-- Phase 2: Compute CodeResolution for a JSFunction.
    Pure function (not monadic) to avoid universe issues in the do-block. -/
private def computeCodeRes (space : AddressSpace) (heap : VA)
    (retAddr : VA) (jsdtSegments : List JSDTSegment) : Option CodeResolution :=
  let dispatchHandle := Util.readU32o space (heap + 12)
  match dispatchHandle with
  | some dh =>
    match resolveViaJSDT space jsdtSegments dh with
    | some entry =>
      match findCallerCode space jsdtSegments retAddr with
      | some (callerEntry, nativeOff) =>
        some { dispatchHandle := dh
             , entrypoint := entry.entrypoint
             , codeObject := entry.codeObject
             , returnAddress := retAddr
             , nativeOffset := some nativeOff
             , callerCodeObject := some callerEntry.codeObject : CodeResolution }
      | none =>
        some { dispatchHandle := dh
             , entrypoint := entry.entrypoint
             , codeObject := entry.codeObject
             , returnAddress := retAddr
             , nativeOffset := none
             , callerCodeObject := none : CodeResolution }
    | none => none
  | none => none

/-- Recover type-feedback and Code resolution for a single V8 stack frame.
    Phase 1: FeedbackVector IC slots (in-cage).
    Phase 2: JSDT → Code resolution (trusted space). -/
private def analyzeFrame (space : AddressSpace) (cage : VA)
    (frame : V8.V8StackFrame) (layout : V8Layout)
    (jsdtSegments : List JSDTSegment) : Option JitFrameInfo :=
  match frame.jsFunctionName with
  | none => none
  | some jsName =>
    match resolveJsFunction space frame.framePointer cage layout with
  | none => none
  | some (heap, sfi) =>
    let codeRes := computeCodeRes space heap frame.returnAddress jsdtSegments
    let fcC := Util.readU32o space (heap + layout.jsfunctionFeedbackCell)
    match fcC.bind (Util.decompress cage) with
    | none => none
    | some fc =>
      let valC := Util.readU32o space (fc + layout.feedbackCellVector)
      let fvDirect : Option VA :=
        match valC.bind (Util.decompress cage) with
        | some obj =>
          match Util.instanceType space cage obj with
          | some itype => if itype == layout.itypeFeedbackVector then some obj else none
          | none => none
        | none => none
      let fvScanned := findFeedbackVectorBySfi space cage sfi layout
      let fv := fvDirect.orElse (fun _ => fvScanned)
      match fv with
      | none =>
        some
          { threadId := frame.threadId
            depth := frame.depth
            functionName := jsName
            scriptName := frame.scriptName
            scriptLine := frame.scriptLine
            feedbackVector := none
            slotCount := 0
            slots := []
            sfiCrosscheck := false
            feedbackPath := "no_feedback_vector (lazy/closure feedback or flushed)"
            codeResolution := codeRes }
      | some fvAddr =>
        match decodeFeedbackVector space cage fvAddr sfi layout with
        | some (slotCount, slots, sfiXcheck) =>
          some
            { threadId := frame.threadId
              depth := frame.depth
              functionName := jsName
              scriptName := frame.scriptName
              scriptLine := frame.scriptLine
              feedbackVector := some fvAddr
              slotCount := slotCount
              slots := slots
              sfiCrosscheck := sfiXcheck
              feedbackPath :=
                if fvDirect == some fvAddr then "feedback_cell_direct"
                else "sfi_scan_fallback"
              codeResolution := codeRes }
        | none =>
          some
            { threadId := frame.threadId
              depth := frame.depth
              functionName := jsName
              scriptName := frame.scriptName
              scriptLine := frame.scriptLine
              feedbackVector := some fvAddr
              slotCount := 0
              slots := []
              sfiCrosscheck := false
              feedbackPath := "decode_failed"
              codeResolution := codeRes }

/-- Slot state → JSON for output. Returns a key-sorted object. -/
private def slotStateJson (st : SlotState) : Json :=
  match st with
  | .uninitialized => .obj [("state", .str "uninitialized")]
  | .monomorphic obj itype =>
    .obj [ ("instance_type", match itype with
            | some i => .str (s!"0x{toString i.toNat}") | none => .null)
         , ("object", .str (hexUpper obj))
         , ("state", .str "monomorphic") ]
  | .polymorphic n =>
    .obj [ ("state", .str "polymorphic"), ("type_count", .ofNat n) ]
  | .smiFeedback v =>
    .obj [ ("state", .str "smi"), ("value", .int v.toNat) ]
  | .unknown => .obj [("state", .str "unknown")]

/-- Convert a FeedbackSlot to JSON. -/
private def slotJson (s : FeedbackSlot) : Json :=
  .obj [ ("index", .ofNat s.index)
       , ("raw", .str (s!"0x{toString s.raw.toNat}"))
       , ("state", slotStateJson s.state) ]

/-- Convert a CodeResolution to JSON. -/
private def codeResJson (cr : CodeResolution) : Json :=
  .obj
    [ ("dispatch_handle", .str (s!"0x{toString cr.dispatchHandle.toNat}"))
    , ("entrypoint", .str (hexUpper cr.entrypoint))
    , ("code_object", .str (hexUpper cr.codeObject))
    , ("return_address", .str (hexUpper cr.returnAddress))
    , ("native_offset", match cr.nativeOffset with | some o => .str (s!"0x{toString o.toNat}") | none => .null)
    , ("caller_code_object", match cr.callerCodeObject with | some v => .str (hexUpper v) | none => .null) ]

/-- Convert a JitFrameInfo to JSON. -/
private def frameInfoJson (info : JitFrameInfo) : Json :=
  .obj
    [ ("thread_id", .ofNat info.threadId.toNat)
    , ("depth", .ofNat info.depth)
    , ("function_name", match info.functionName with | some s => .str s | none => .null)
    , ("script_name", match info.scriptName with | some s => .str s | none => .null)
    , ("script_line", match info.scriptLine with | some l => .ofNat l.toNat | none => .null)
    , ("feedback_vector", match info.feedbackVector with | some v => .str (hexUpper v) | none => .null)
    , ("slot_count", .ofNat info.slotCount)
    , ("sfi_crosscheck", .bool info.sfiCrosscheck)
    , ("feedback_path", .str info.feedbackPath)
    , ("code_resolution", match info.codeResolution with | some cr => codeResJson cr | none => .null)
    , ( "feedback_slots"
      , .arr (info.slots.map slotJson) ) ]

/-- The jit analyzer. Walks all thread stacks (reusing V8.walkThreadStacks),
    then for each frame with a resolved JSFunction, decodes its
    FeedbackVector and IC slots (Phase 1) and resolves Code objects via
    the JSDispatchTable (Phase 2). -/
def analyzer : Forensicator.Analyzer where
  name := "jit"
  description := "Recovers V8 type feedback and Code resolution for JIT-compiled frames"
  run dump space :=
    let layout := V8Layout.detect dump
    let cage := Cause.annotationHex dump "v8_ro_space_firstpage_address"
    -- Reuse the V8 analyzer's stack walk to get all frames
    let frames := V8.walkThreadStacks dump space
    -- Phase 2: Discover CodeRange and JSDT segments
    let codeRange := discoverCodeRange frames
    let jsdtSegments : List JSDTSegment :=
      match codeRange with
      | some (crStart, crEnd) => discoverJSDTSegments space crStart crEnd
      | none => []
    -- For each frame, try to recover type feedback + Code resolution
    let infos := match cage with
      | some c => frames.filterMap (analyzeFrame space c · layout jsdtSegments)
      | none => []
    let custom : List (String × Json) :=
      [ ("jit_frame_count", .ofNat infos.length)
      , ("jit_frames", .arr (infos.map frameInfoJson))
      ]
    { Forensicator.AnalyzerOutput.new "jit" with custom := custom }

end Forensicator.Analyzer.Jit

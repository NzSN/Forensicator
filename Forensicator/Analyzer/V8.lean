/- Forensicator.Analyzer.V8 — V8 JS stack recovery (analyzer/v8.rs port):
   walks native stacks (unwind tables → fp-chain → leaf), classifies V8
   frames, decodes JSFunction → name/script/line. The PDB symbolizer is an
   FFI boundary and out of scope: native_symbol falls back to hex, exactly
   as Rust does when no PDBs are found (the gate's environment has none). -/
import Forensicator.Analyzer.Scan
import Forensicator.Analyzer.Cause
import Forensicator.Util.V8Layout
import Forensicator.Util.Unwind
import Forensicator.Util.Disasm
import Std.Data.HashSet

namespace Forensicator.Analyzer.V8

open Forensicator.Model Forensicator.Spec Forensicator.Util

/-- A recovered stack frame (model.rs V8StackFrame). -/
structure V8StackFrame where
  threadId : UInt32
  depth : Nat
  frameType : V8FrameType
  nativeSymbol : String
  nativeOffset : UInt64
  returnAddress : VA
  framePointer : VA
  jsFunctionName : Option String
  scriptName : Option String
  scriptLine : Option UInt32

private def readU64 (space : AddressSpace) (va : VA) : UInt64 :=
  (space.read va 8).map (readU64leAt · 0) |>.getD 0

private def readU32o (space : AddressSpace) (va : VA) : Option UInt32 :=
  (space.read va 4).map (readU32leAt · 0)

private def readU64o (space : AddressSpace) (va : VA) : Option UInt64 :=
  (space.read va 8).map (readU64leAt · 0)

/-- Wrapping address + signed offset (Rust wrapping_add_signed). -/
private def wadd (va : VA) (off : Int) : VA :=
  UInt64.ofNat ((Int.ofNat va.toNat + off).emod (2 ^ 64)).toNat

private def decompress (cage : VA) (compressed : UInt32) : Option VA :=
  if compressed == 0 || compressed &&& 1 == 0 then none
  else some (cage + (compressed &&& 0xFFFFFFFE).toUInt64)

private def smi (raw : UInt32) : Option Int :=
  if raw &&& 1 != 0 then none
  else some (Int.ofNat (raw >>> 1).toNat)

private def instanceType (space : AddressSpace) (cage heap : VA) : Option UInt16 := do
  let mapC ← readU32o space heap
  let map ← decompress cage mapC
  (space.read (map + 8) 2).map (readU16leAt · 0)

private def readV8String (space : AddressSpace) (va : VA) (itype : UInt16)
    (layout : V8Layout) : Option String := do
  let len ← readU32o space (va + layout.stringLength)
  if len == 0 || len > layout.maxJsNameLen then none
  else
    if itype &&& layout.stringOneByteBit != 0 then
      let bytes ← space.read (va + layout.stringChars) len.toNat
      if bytes.toList.all (fun b => (b ≥ 0x20 && b ≤ 0x7E) || b ≥ 0x80) then
        some (fromUTF8Lossy bytes)
      else none
    else
      let bytes ← space.read (va + layout.stringChars) (len.toNat * 2)
      let units := (List.range len.toNat).map fun k => readU16leAt bytes (2 * k)
      if units.all (fun u => (u ≥ 0x20 && u ≤ 0x7E) || u ≥ 0x80) then
        some (utf16Lossy units)
      else none

private def readExternalChars (space : AddressSpace) (ptr : VA) (len : UInt32) (oneByte : Bool) :
    Option String := do
  if oneByte then
    let bytes ← space.read ptr len.toNat
    if bytes.toList.all (fun b => (b ≥ 0x20 && b ≤ 0x7E) || b ≥ 0x80) then
      some (fromUTF8Lossy bytes)
    else none
  else
    let bytes ← space.read ptr (len.toNat * 2)
    let units := (List.range len.toNat).map fun k => readU16leAt bytes (2 * k)
    if units.all (fun u => (u ≥ 0x20 && u ≤ 0x7E) || u ≥ 0x80) then
      some (utf16Lossy units)
    else none

private def externalStringViaEpt (space : AddressSpace) (eptBase : VA) (handle : UInt32)
    (len : UInt32) (oneByte : Bool) (layout : V8Layout) : Option String := do
  let entry ← readU64o space (eptBase + layout.eptEntrySize * (handle.toUInt64 >>> (UInt64.ofNat layout.eptIndexShift)))
  let resource := entry &&& layout.eptPayloadMask
  if resource == 0 then none
  else
    let chars ← readU64o space (resource + 16)
    readExternalChars space chars len oneByte

/-- Scan the isolate region for the EPT base (v8.rs find_ept_base). -/
private def findEptBase (space : AddressSpace) (isolateVa : VA) (handle : UInt32)
    (len : UInt32) (oneByte : Bool) (moduleRanges : List (VA × UInt64))
    (layout : V8Layout) : Except Unit (Option VA) :=
  match space.regionAt isolateVa with
  | none => .ok none
  | some region =>
    let idx := handle.toUInt64 >>> (UInt64.ofNat layout.eptIndexShift)
    let inModules (v : VA) : Bool :=
      moduleRanges.any fun (base, size) =>
        decide (v ≥ base ∧ v.toNat < base.toNat + size.toNat)
    let rec pass (rejectInternal : Bool) : Except Unit (Option VA) :=
      let rec scan (off : Nat) : Except Unit (Option VA) :=
        if off + 8 ≤ region.data.size then
          let b := readU64leAt region.data off
          if b < 0x10000 || b &&& 7 != 0 then scan (off + 8)
          else
            -- v8.rs:539 overflow → checked_add skips the candidate (fixed
            -- upstream after the 13c81d0 investigation; the panic
            -- reproduction is retired)
            if b.toNat + layout.eptEntrySize.toNat * idx.toNat ≥ 2 ^ 64 then scan (off + 8)
            else
              match readU64o space (b + layout.eptEntrySize * idx) with
              | none => scan (off + 8)
              | some entry =>
                let resource := entry &&& layout.eptPayloadMask
                if resource == 0 then scan (off + 8)
                else if rejectInternal && resource ≥ b && resource < b + ((2 : UInt64) <<< 20) then
                  scan (off + 8)
                else if inModules resource then scan (off + 8)
                else
                  match readU64o space resource with
                  | none => scan (off + 8)
                  | some vtable =>
                    if !inModules vtable then scan (off + 8)
                    else
                      match readU64o space (resource + 16) with
                      | none => scan (off + 8)
                      | some chars =>
                        match readExternalChars space chars len oneByte with
                        | some _ => .ok (some b)
                        | none => scan (off + 8)
        else .ok none
    termination_by region.data.size + 8 - off
    scan 0
  match pass true with
  | .error () => .error ()
  | .ok (some b) => .ok (some b)
  | .ok none => pass false

private def decodeScriptName (space : AddressSpace) (cage : VA) (script : VA)
    (isolateVa : Option VA) (moduleRanges : List (VA × UInt64))
    (eptBase : Option VA) (layout : V8Layout) : Except Unit (Option String × Option VA) := do
  let nameObjO := (readU32o space (script + layout.scriptName)).bind (decompress cage)
  match nameObjO with
  | none => .ok (none, eptBase)
  | some nameObj =>
    match instanceType space cage nameObj with
    | none => .ok (none, eptBase)
    | some itype =>
      if itype ≥ layout.stringItypeMax then .ok (none, eptBase)
      else if itype &&& layout.stringExternalBit == 0 then
        .ok (readV8String space nameObj itype layout, eptBase)
      else
        match readU32o space (nameObj + layout.stringChars) with
        | none => .ok (none, eptBase)
        | some handle =>
          if handle == 0 || handle.toUInt64 &&& (((1 : UInt64) <<< (UInt64.ofNat layout.eptIndexShift)) - 1) != 0 then
            .ok (none, eptBase)
          else
            match readU32o space (nameObj + layout.stringLength) with
            | none => .ok (none, eptBase)
            | some len =>
              if len == 0 || len > layout.maxJsNameLen then .ok (none, eptBase)
              else
                let oneByte := itype &&& layout.stringOneByteBit != 0
                match eptBase with
                | some b =>
                  .ok (externalStringViaEpt space b handle len oneByte layout, some b)
                | none =>
                  match isolateVa with
                  | none => .ok (none, eptBase)
                  | some iso =>
                    match findEptBase space iso handle len oneByte moduleRanges layout with
                    | .error () => .error ()
                    | .ok none => .ok (none, eptBase)
                    | .ok (some b) =>
                      -- Rust sets the ept_base cell when found, even if the
                      -- string read then fails.
                      .ok (externalStringViaEpt space b handle len oneByte layout, some b)

private def decodeScriptLine (space : AddressSpace) (cage : VA) (script : VA)
    (position : Int) (layout : V8Layout) : Option UInt32 := do
  let lineEnds ← decompress cage (← readU32o space (script + layout.scriptLineEnds))
  let lenI ← smi (← readU32o space (lineEnds + layout.fixedArrayLength))
  if lenI < 0 || lenI > 10000000 then none
  else
    let lineOffset := (smi (← readU32o space (script + layout.scriptLineOffset))).getD 0
    let rec binO (lo hi : Int) : Option Int :=
      if lo < hi then
        let mid := lo + (hi - lo) / 2
        match readU32o space (lineEnds + layout.fixedArrayData + 4 * mid.toNat.toUInt64) with
        | none => none
        | some raw =>
          match smi raw with
          | none => none
          | some v => if v < position then binO (mid + 1) hi else binO lo mid
      else some lo
    termination_by (hi - lo).toNat
    match ← binO 0 lenI with
    | lo =>
      let out := lo + lineOffset + 1
      if out ≥ 0 then some ((UInt64.ofNat out.toNat).toUInt32) else none

/-- Extract a function name from a ScopeInfo (v8.rs scope_info_function_name). -/
private def scopeInfoFunctionName (space : AddressSpace) (cage : VA) (scope : VA)
    (layout : V8Layout) : Option String := do
  let flags ← readU32o space (scope + layout.scopeFlags)
  let localCount ← smi (← readU32o space (scope + layout.scopeLocalCount))
  if localCount < 0 || localCount > 0x10000 then none
  else
    let mut off := layout.scopeDynamicStart
    if flags &&& 0xF == layout.scopeTypeModule then
      off := off + 4
    let n := localCount.toNat.toUInt64
    off := off + (if n.toUInt32 < layout.scopeMaxInlinedLocalNames then 4 * n else 4)
    off := off + 4 * n
    if flags &&& layout.scopeFlagSavedClassVariable != 0 then
      off := off + 4
    let alloc := (flags >>> layout.scopeFunctionVariableShift) &&& layout.scopeFunctionVariableMask
    let mut candidates : List UInt64 := []
    if alloc != 0 then
      candidates := [off]
      off := off + 8
    if flags &&& layout.scopeFlagInferredFunctionName != 0 then
      candidates := candidates ++ [off]
    candidates.findSome? fun slot =>
      match readU32o space (scope + slot) with
      | none => none
      | some c =>
        match decompress cage c with
        | none => none
        | some nameObj =>
          match instanceType space cage nameObj with
          | none => none
          | some itype =>
            if itype < layout.stringItypeMax then readV8String space nameObj itype layout
            else none

/-- Everything decoded from a JavaScript stack frame's JSFunction. -/
private structure JsFrameInfo where
  name : Option String
  scriptName : Option String
  scriptLine : Option UInt32

/-- Resolve JS frame info at `fp` (v8.rs decode_js_frame). `eptBase` is
    threaded in/out (the Rust version shares a Cell across frames). -/
private def decodeJsFrame (space : AddressSpace) (fp : VA) (cageHint : Option VA)
    (isolateVa : Option VA) (moduleRanges : List (VA × UInt64)) (eptBase : Option VA)
    (layout : V8Layout) : Except Unit (Option (JsFrameInfo × Option VA)) := do
  let decodeAt (heap cage : VA) : Except Unit (Option (JsFrameInfo × Option VA)) := do
    match readU32o space (heap + layout.jsfunctionSharedFunctionInfo) with
    | none => .ok none
    | some sfiC =>
      match decompress cage sfiC with
      | none => .ok none
      | some sfi =>
        let mut info : JsFrameInfo := ⟨none, none, none⟩
        let mut position : Option Int := none
        let mut ept := eptBase
        match readU32o space (sfi + layout.sfiNameOrScopeInfo) with
        | some c0 =>
          match decompress cage c0 with
          | some nameOrScope =>
            match instanceType space cage nameOrScope with
            | some itype =>
              if itype < layout.stringItypeMax then
                info := { info with name := readV8String space nameOrScope itype layout }
              else
                info := { info with name := scopeInfoFunctionName space cage nameOrScope layout }
                position := match readU32o space (nameOrScope + layout.scopePositionStart) with
                  | some raw => smi raw
                  | none => none
            | none => pure ()
          | none => pure ()
        | none => pure ()
        if info.name.isNone then
          info := { info with name := some "<anonymous>" }
        match readU32o space (sfi + layout.sfiScript) with
        | none => .ok (some (info, ept))
        | some c1 =>
          match decompress cage c1 with
          | none => .ok (some (info, ept))
          | some script =>
            match (← decodeScriptName space cage script isolateVa moduleRanges ept layout) with
            | (sn, ept') =>
              ept := ept'
              let line := match position with
                | some pos => decodeScriptLine space cage script pos layout
                | none => none
              .ok (some ({ info with scriptName := sn, scriptLine := line }, ept))
  let rec trySlot (slots : List Int) : Except Unit (Option (JsFrameInfo × Option VA)) :=
    match slots with
    | [] => .ok none
    | slot :: rest =>
      let tagged := readU64 space (wadd fp slot)
      if tagged &&& 1 != 1 then trySlot rest
      else
        let heap := tagged &&& 0xFFFFFFFFFFFFFFFE
        let derived := tagged &&& 0xFFFFFFFF00000000
        let cage := match cageHint with
          | some h => if heap ≥ h && heap < h + ((1 : UInt64) <<< 32) then h else derived
          | none => derived
        let frameContext := readU64 space (wadd fp layout.kContextOffset)
        let fnContext :=
          match readU32o space (heap + layout.jsfunctionContext) with
          | none => none
          | some c => (decompress cage c).map (· ||| 1)
        if fnContext != some frameContext then trySlot rest
        else decodeAt heap cage
  trySlot [layout.kFunctionOffset, layout.kFunctionOffsetLegacy]

/-- Classify a frame (v8.rs classify_frame). -/
private def classifyFrame (returnAddress : VA) (moduleRanges : List (VA × UInt64))
    (space : AddressSpace) (marker : UInt64) (layout : V8Layout) : V8FrameType :=
  match layout.markerFrameType marker with
  | some ft => ft
  | none =>
    if moduleRanges.any fun (base, size) =>
        decide (returnAddress ≥ base ∧ returnAddress.toNat < base.toNat + size.toNat) then .builtin
    else
      match space.regionAt returnAddress with
      | some region =>
        if region.protection &&& Protection.EXECUTE != 0 then .optimizedJavaScript else .cpp
      | none => .cpp

/-- refine_type: upgrade non-JS types when a validated JSFunction exists and
    the return address is JIT code (outside all modules). -/
private def refineType (frameType : V8FrameType) (hasJsFunction : Bool) (returnAddress : VA)
    (moduleRanges : List (VA × UInt64)) : V8FrameType :=
  if !hasJsFunction then frameType
  else
    match frameType with
    | .javaScript | .optimizedJavaScript => frameType
    | _ =>
      if moduleRanges.any fun (base, size) =>
          decide (returnAddress ≥ base ∧ returnAddress.toNat < base.toNat + size.toNat)
      then .javaScript else .optimizedJavaScript

/-- Static walker context. -/
private structure WalkCtx where
  dump : Dump
  space : AddressSpace
  isolateVa : Option VA
  layout : V8Layout
  moduleRanges : List (VA × UInt64)
  cage : Option VA
  thread : Thread
  stackVa : VA
  stackEnd : VA

/-- Walker state: current registers + metadata. -/
private structure WalkState where
  regs : RegisterSet
  depth : Nat
  seen : Std.HashSet (VA × VA)
  viaLeaf : Bool
  eptBase : Option VA
  tables : UnwindTables

private def walkGo (ctx : WalkCtx) (st : WalkState) (acc : List V8StackFrame)
    (fuel : Nat) : Except Unit (List V8StackFrame × UnwindTables) :=
  match fuel with
  | 0 => .ok (acc, st.tables)
  | fuel + 1 =>
    let space := ctx.space
    let rip := st.regs.rip
    let rsp := st.regs.rsp
    let rbp := st.regs.rbp
    if rip == 0 || st.depth ≥ 256 || st.seen.contains (rip, rsp) then .ok (acc, st.tables)
    else
      let inModule := ctx.moduleRanges.any fun (b, s) =>
        decide (rip ≥ b ∧ rip.toNat < b.toNat + s.toNat)
      if !inModule && (space.regionAt rip).isNone && st.viaLeaf then .ok (acc, st.tables)
      else
        let marker := readU64 space (wadd rbp ctx.layout.kMarkerOffset)
        let frameType := classifyFrame rip ctx.moduleRanges space marker ctx.layout
        match decodeJsFrame space rbp ctx.cage ctx.isolateVa ctx.moduleRanges st.eptBase ctx.layout with
        | .error () => .error ()
        | .ok js =>
        let (jsInfo, ept') := match js with
          | some (i, e) => (some i, e)
          | none => (none, st.eptBase)
        let frameType := refineType frameType jsInfo.isSome rip ctx.moduleRanges
        let (fnName, scriptName, scriptLine) := match jsInfo with
          | some i => (i.name, i.scriptName, i.scriptLine)
          | none => (none, none, none)
        let frame : V8StackFrame :=
          { threadId := ctx.thread.id, depth := st.depth, frameType := frameType
            nativeSymbol := hexUpper rip, nativeOffset := 0
            returnAddress := rip, framePointer := rbp
            jsFunctionName := fnName, scriptName := scriptName, scriptLine := scriptLine }
        let st1 := { st with depth := st.depth + 1, seen := st.seen.insert (rip, rsp)
                             eptBase := ept' }
        -- advance 1: unwind tables (.pdata)
        let (hit, tables') := st.tables.lookup space rip
        let st2 := { st1 with tables := tables' }
        match hit with
        | some (base, rt) =>
          match unwindStep st.regs space base rt with
          | some regs' => walkGo ctx { st2 with regs := regs', viaLeaf := false } (acc ++ [frame]) fuel
          | none => fpOrLeaf ctx st2 frame acc fuel rip rsp rbp
        | none => fpOrLeaf ctx st2 frame acc fuel rip rsp rbp
where
  fpOrLeaf (ctx : WalkCtx) (st : WalkState) (frame : V8StackFrame) (acc : List V8StackFrame)
      (fuel : Nat) (_rip rsp rbp : VA) : Except Unit (List V8StackFrame × UnwindTables) :=
    let space := ctx.space
    let savedRbp := readU64 space rbp
    let fpRet := readU64 space (rbp + 8)
    let fpChain := rbp ≥ ctx.stackVa && savedRbp > rbp && savedRbp < ctx.stackEnd
    let terminalLink := !fpChain && rbp ≥ ctx.stackVa && rbp < ctx.stackEnd && fpRet != 0
      && (ctx.moduleRanges.any (fun (b, s) => decide (fpRet ≥ b ∧ fpRet.toNat < b.toNat + s.toNat))
        || ((space.regionAt fpRet).map (fun r => r.protection &&& Protection.EXECUTE != 0)).getD false)
    if fpRet != 0 && (fpChain || terminalLink) then
      let regs' := ((st.regs.set X64.RIP fpRet).set X64.RBP savedRbp).set X64.RSP (rbp + 16)
      walkGo ctx { st with regs := regs', viaLeaf := false } (acc ++ [frame]) fuel
    else
      let leafRet := readU64 space rsp
      if leafRet != 0 then
        let regs' := (st.regs.set X64.RIP leafRet).set X64.RSP (rsp + 8)
        walkGo ctx { st with regs := regs', viaLeaf := true } (acc ++ [frame]) fuel
      else .ok (acc ++ [frame], st.tables)

private def walkThread (ctx : WalkCtx) (init : UnwindTables) :
    Except Unit (List V8StackFrame × UnwindTables) :=
  let regs0 :=
    match ctx.dump.exception with
    | some exc =>
      if exc.threadId == ctx.thread.id then (exc.context.getD ctx.thread.registers)
      else ctx.thread.registers
    | none => ctx.thread.registers
  walkGo ctx { regs := regs0, depth := 0, seen := Std.HashSet.emptyWithCapacity
               viaLeaf := false, eptBase := none, tables := init } [] 256

/-- Walk all threads' stacks (v8.rs walk_thread_stacks). The error case is
    the reproduced Rust debug overflow panic (v8.rs:539). -/
def walkThreadStacks (dump : Dump) (space : AddressSpace) : Except Unit (List V8StackFrame) :=
  let layout := V8Layout.detect dump
  let isolateVa := Cause.annotationHex dump "v8_isolate_address"
  let cage := Cause.annotationHex dump "v8_ro_space_firstpage_address"
  let moduleRanges := dump.modules.map fun m => (m.baseVa, m.size)
  let rec go (threads : List Thread) (tables : UnwindTables) (acc : List V8StackFrame) :
      Except Unit (List V8StackFrame) :=
    match threads with
    | [] => .ok acc
    | t :: rest =>
      let ctx : WalkCtx :=
        { dump := dump, space := space, isolateVa := isolateVa, layout := layout
          moduleRanges := moduleRanges, cage := cage, thread := t
          stackVa := t.stackVa, stackEnd := t.stackVa + t.stackSize }
      match walkThread ctx tables with
      | .error () => .error ()
      | .ok (frames, tables') => go rest tables' (acc ++ frames)
  go dump.threads (UnwindTables.new dump.modules) []

/-- Disassemble up to 10 instructions at the exception address. -/
def disassembleException (dump : Dump) (space : AddressSpace) : Option Json := do
  let exc ← dump.exception
  let fs := FastSpace.ofSpace space
  let rec collect (ip : VA) (n : Nat) (acc : List Json) : List Json :=
    if n ≥ 10 then acc
    else
      match decodeFirst fs ip with
      | none => acc
      | some i => collect (ip + UInt64.ofNat i.len) (n + 1)
          (acc ++ [.obj [("va", .str (hexUpper i.va)), ("text", .str i.text)]])
  let lines := collect exc.address 0 []
  if lines.isEmpty then none
  else some (.arr lines)

/-- The v8 analyzer. -/
def analyzer : Forensicator.Analyzer where
  name := "v8"
  description := "Recovers JS stack traces by walking native stacks and classifying V8 frames"
  run dump space :=
    match walkThreadStacks dump space with
    | .error () =>
      -- reproduced Rust debug overflow panic (pipeline catch_unwind output)
      { Forensicator.AnalyzerOutput.new "v8" with
        custom := [("error", .str "analyzer 'v8' panicked")] }
    | .ok frames => analyzerOk dump space frames
where
  analyzerOk (dump : Dump) (space : AddressSpace) (frames : List V8StackFrame) :
      Forensicator.AnalyzerOutput :=
    let framesJson := frames.map fun f =>
      Json.obj [
        ("thread_id", .ofNat f.threadId.toNat),
        ("depth", .ofNat f.depth),
        ("frame_type", .str f.frameType.debug),
        ("native_symbol", .str f.nativeSymbol),
        ("native_offset", .ofUInt64 f.nativeOffset),
        ("return_address", .str (hexUpper f.returnAddress)),
        ("frame_pointer", .str (hexUpper f.framePointer)),
        ("js_function_name", match f.jsFunctionName with | some s => .str s | none => .null),
        ("script_name", match f.scriptName with | some s => .str s | none => .null),
        ("script_line", match f.scriptLine with | some l => .ofNat l.toNat | none => .null)]
    let heapCaptured :=
      match Cause.annotationHex dump "v8_ro_space_firstpage_address" with
      | some cage => (space.regionAt cage).isSome
      | none => false
    let custom : List (String × Json) :=
      [("v8_frames", .arr framesJson), ("v8_frame_count", .ofNat frames.length)]
        ++ (match disassembleException dump space with
            | some d => [("crash_disasm", d)] | none => [])
        ++ [("v8_heap_captured", .bool heapCaptured)]
    { Forensicator.AnalyzerOutput.new "v8" with custom := custom }

end Forensicator.Analyzer.V8

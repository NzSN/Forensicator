/- Forensicator.Analyzer.V8 — V8 JS stack recovery (analyzer/v8.rs port):
   walks native stacks (unwind tables → fp-chain → leaf), classifies V8
   frames, decodes JSFunction → name/script/line. With a publics table
   (design §W2.4) native_symbol becomes NAME+0xOFF for module-resident
   frames (builtin frames land on Builtins_* entries) and falls back to
   hex without one, exactly as before. -/
import Forensicator.Analyzer.Scan
import Forensicator.Analyzer.Cause
import Forensicator.Util.Pdb
import Forensicator.Util.V8Layout
import Forensicator.Util.V8Obj
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

-- Shared cage-walking helpers now live in Util/V8Obj.lean.
-- These local aliases keep the rest of V8.lean unchanged.
private def readU64 := @Util.readU64
private def readU32o := @Util.readU32o
private def readU64o := @Util.readU64o
private def wadd := @Util.wadd
private def decompress := @Util.decompress
private def smi := @Util.smi
private def instanceType := @Util.instanceType
private def readV8String := @Util.readV8String

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

private def externalStringViaEpt (space : AddressSpace) (eptBase : VA)
    (hRes hData : UInt32) (len : UInt32) (oneByte : Bool)
    (moduleRanges : List (VA × UInt64)) (layout : V8Layout) : Option String :=
  let entryAt (h : UInt32) : Option UInt64 := do
    let idx := h.toUInt64 >>> (UInt64.ofNat layout.eptIndexShift)
    if eptBase.toNat + layout.eptEntrySize.toNat * idx.toNat ≥ 2 ^ 64 then none
    else readU64o space (eptBase + layout.eptEntrySize * idx)
  let payloadOf (h : UInt32) : Option UInt64 :=
    (entryAt h).map (· &&& layout.eptPayloadMask)
  -- data path (design §W3.3: content-classified — the entry whose payload
  -- reads as exactly len printable one-/two-byte chars is the cached char
  -- pointer; checked across BOTH in-object handles, slot order first);
  -- hData = 0 disables it (UNCACHED_EXTERNAL_* lacks the field, string.tq:87)
  let charsOf (h : UInt32) : Option String :=
    match h with
    | 0 => none
    | _ =>
      match payloadOf h with
      | none => none
      | some p => if p == 0 then none else readExternalChars space p len oneByte
  let dataStr : Option String :=
    match hData with
    | 0 => none
    | _ => (charsOf hRes).orElse (charsOf hData)
  -- resource path: payload pointing at an object with a module-resident
  -- vtable is the ExternalStringResource; +16 is the older/uncached fallback
  let resourceOf (p : UInt64) : Option VA :=
    if p == 0 then none
    else
      match readU64o space p with
      | none => none
      | some vtable =>
        if moduleRanges.any fun (b, s) =>
            decide (vtable ≥ b ∧ vtable.toNat < b.toNat + s.toNat)
        then some p else none
  let resource : Option VA :=
    match (payloadOf hRes).bind resourceOf with
    | some r => some r
    | none =>
      match hData with
      | 0 => none
      | _ => (payloadOf hData).bind resourceOf
  match dataStr with
  | some s => some s
  | none =>
    match resource with
    | none => none
    | some r =>
      match readU64o space (r + 16) with
      | none => none
      | some chars => readExternalChars space chars len oneByte

/-- Scan the isolate region for the EPT base (design §W3.3, addendum B).
    Content-classified validation across BOTH in-object handles: one
    payload must read as exactly len printable chars (the data pointer)
    and one must point at an object with a module-resident vtable (the
    resource); hData = 0 falls back to the legacy single-handle resource+16
    check. Rejects bases inside the isolate region / modules — the addendum
    B false table (0x38d4000c5c00) lived in the isolate. Unreadable entry
    pages fail closed (-> none). -/
private def findEptBase (space : AddressSpace) (isolateVa : VA)
    (hRes hData : UInt32) (len : UInt32) (oneByte : Bool)
    (moduleRanges : List (VA × UInt64)) (layout : V8Layout) : Option VA :=
  match space.regionAt isolateVa with
  | none => none
  | some region =>
    let isoStart := region.vaStart
    let isoEnd := region.vaStart + region.size
    let inIso (v : VA) : Bool := decide (v ≥ isoStart ∧ v < isoEnd)
    let inModules (v : VA) : Bool :=
      moduleRanges.any fun (b, s) =>
        decide (v ≥ b ∧ v.toNat < b.toNat + s.toNat)
    let idxOf (h : UInt32) : UInt64 := h.toUInt64 >>> (UInt64.ofNat layout.eptIndexShift)
    let entryAt (b : VA) (h : UInt32) : Option UInt64 := do
      let idx := idxOf h
      -- v8.rs:539 overflow guard, Nat-lifted (upstream bd46529)
      if b.toNat + layout.eptEntrySize.toNat * idx.toNat ≥ 2 ^ 64 then none
      else readU64o space (b + layout.eptEntrySize * idx)
    let payloadAt (b : VA) (h : UInt32) : Option UInt64 :=
      (entryAt b h).map (· &&& layout.eptPayloadMask)
    let printableAt (b : VA) (h : UInt32) : Bool :=
      match payloadAt b h with
      | none => false
      | some p =>
        p != 0 && !inModules p && !inIso p &&
          (readExternalChars space p len oneByte).isSome
    let vtableObjAt (b : VA) (h : UInt32) : Bool :=
      match payloadAt b h with
      | none => false
      | some p =>
        p != 0 && !inModules p && !inIso p &&
          (match readU64o space p with
           | none => false
           | some vtable => inModules vtable)
    -- content classification (design §W3.3): the data entry is whichever
    -- payload prints, the resource entry whichever carries a module vtable —
    -- checked across BOTH in-object handles; both classes must validate
    -- (addendum B). hData = 0 (uncached): legacy single-handle validation,
    -- chars come from resource+16.
    let legacyOk (b : VA) : Bool :=
      match payloadAt b hRes with
      | none => false
      | some p =>
        p != 0 && !inModules p && !inIso p &&
          (match readU64o space p with
           | none => false
           | some vt => inModules vt) &&
          (match readU64o space (p + 16) with
           | none => false
           | some chars => (readExternalChars space chars len oneByte).isSome)
    let dataOk (b : VA) : Bool :=
      match hData with
      | 0 => legacyOk b
      | _ => printableAt b hRes || printableAt b hData
    let resourceOk (b : VA) : Bool :=
      match hData with
      | 0 => vtableObjAt b hRes
      | _ => vtableObjAt b hRes || vtableObjAt b hData
    let rec scan (off : Nat) : Option VA :=
      if off + 8 ≤ region.data.size then
        let b := readU64leAt region.data off
        if b < 0x10000 || b &&& 7 != 0 then scan (off + 8)
        else if inModules b || inIso b then scan (off + 8)
        else if dataOk b && resourceOk b then some b
        else scan (off + 8)
      else none
    termination_by region.data.size + 8 - off
    scan 0

/-- Decode a V8 String object (inline one/two-byte, or external via EPT).
    Shared by the script-name, frame-name, and ScopeInfo paths (design
    §W3.3; addendum B: frame-local names may be external too). The
    external test is (itype &&& stringRepMask) == stringExternalBit — a
    bare &&& 2 would misclassify sliced strings (rep 3). Threads eptBase
    in/out (the Rust version shares a Cell across frames). -/
private def decodeStringObject (space : AddressSpace) (va : VA) (itype : UInt16)
    (isolateVa : Option VA) (moduleRanges : List (VA × UInt64)) (eptBase : Option VA)
    (layout : V8Layout) : Option String × Option VA :=
  if itype ≥ layout.stringItypeMax then (none, eptBase)
  else if (itype &&& layout.stringRepMask) != layout.stringExternalBit then
    (readV8String space va itype layout, eptBase)
  else
    let shiftMask := ((1 : UInt64) <<< (UInt64.ofNat layout.eptIndexShift)) - 1
    match readU32o space (va + layout.stringChars) with
    | none => (none, eptBase)
    | some h1 =>
      -- valid handles: low index-shift bits clear; 0 = null handle
      -- (external-pointer-table-inl.h:313 IsValidHandle)
      if h1 == 0 || h1.toUInt64 &&& shiftMask != 0 then (none, eptBase)
      else
        let cached := (itype &&& layout.stringUncachedExternalBit) == 0
        let h2 : UInt32 :=
          if cached then
            match readU32o space (va + layout.externalStringResourceData) with
            | some h => h
            | none => 0
          else 0
        if cached && (h2 == 0 || h2.toUInt64 &&& shiftMask != 0) then (none, eptBase)
        else
          match readU32o space (va + layout.stringLength) with
          | none => (none, eptBase)
          | some len =>
            if len == 0 || len > layout.maxJsNameLen then (none, eptBase)
            else
              let oneByte := itype &&& layout.stringOneByteBit != 0
              match eptBase with
              | some b =>
                (externalStringViaEpt space b h1 h2 len oneByte moduleRanges layout, some b)
              | none =>
                match isolateVa with
                | none => (none, eptBase)
                | some iso =>
                  match findEptBase space iso h1 h2 len oneByte moduleRanges layout with
                  | none => (none, eptBase)
                  | some b =>
                    -- Rust sets the ept_base cell when found, even if the
                    -- string read then fails.
                    (externalStringViaEpt space b h1 h2 len oneByte moduleRanges layout, some b)

private def decodeScriptName (space : AddressSpace) (cage : VA) (script : VA)
    (isolateVa : Option VA) (moduleRanges : List (VA × UInt64))
    (eptBase : Option VA) (layout : V8Layout) : Option String × Option VA :=
  match (readU32o space (script + layout.scriptName)).bind (decompress cage) with
  | none => (none, eptBase)
  | some nameObj =>
    match instanceType space cage nameObj with
    | none => (none, eptBase)
    | some itype =>
      decodeStringObject space nameObj itype isolateVa moduleRanges eptBase layout

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

/-- Extract a function name from a ScopeInfo (v8.rs scope_info_function_name);
    name candidates may be external strings decoded via the EPT
    (design §W3.3, addendum B). Threads eptBase in/out. -/
private def scopeInfoFunctionName (space : AddressSpace) (cage : VA) (scope : VA)
    (isolateVa : Option VA) (moduleRanges : List (VA × UInt64)) (eptBase : Option VA)
    (layout : V8Layout) : Option String × Option VA :=
  let hdrOk : Option (UInt32 × Int) := do
    let flags ← readU32o space (scope + layout.scopeFlags)
    let localCount ← smi (← readU32o space (scope + layout.scopeLocalCount))
    if localCount < 0 || localCount > 0x10000 then none
    else some (flags, localCount)
  match hdrOk with
  | none => (none, eptBase)
  | some (flags, localCount) =>
    let n := localCount.toNat.toUInt64
    let offNamed : UInt64 := layout.scopeDynamicStart +
      (if flags &&& 0xF == layout.scopeTypeModule then 4 else 0) +
      (if n.toUInt32 < layout.scopeMaxInlinedLocalNames then 4 * n else 4) + 4 * n
    let offVar : UInt64 :=
      if flags &&& layout.scopeFlagSavedClassVariable != 0 then offNamed + 4 else offNamed
    let alloc := (flags >>> layout.scopeFunctionVariableShift) &&& layout.scopeFunctionVariableMask
    -- function-variable slot (if allocated) is 8 bytes; the inferred-name
    -- slot follows it
    let candidates : List UInt64 :=
      (if alloc != 0 then [offVar] else []) ++
      (if flags &&& layout.scopeFlagInferredFunctionName != 0 then
        [offVar + (if alloc != 0 then 8 else 0)] else [])
    let rec go (cs : List UInt64) (ept : Option VA) : Option String × Option VA :=
      match cs with
      | [] => (none, ept)
      | slot :: rest =>
        match readU32o space (scope + slot) with
        | none => go rest ept
        | some c =>
          match decompress cage c with
          | none => go rest ept
          | some nameObj =>
            match instanceType space cage nameObj with
            | none => go rest ept
            | some itype =>
              let (nm, ept') :=
                decodeStringObject space nameObj itype isolateVa moduleRanges ept layout
              match nm with
              | some s => (some s, ept')
              | none => go rest ept'
    go candidates eptBase

/-- Everything decoded from a JavaScript stack frame's JSFunction. -/
private structure JsFrameInfo where
  name : Option String
  scriptName : Option String
  scriptLine : Option UInt32

/-- A slot value that passed the scored JSFunction validation (design
    2026-08-27 §W3.2): candidate heap address + resolved cage base. -/
private structure JsCandidate where
  heap : VA
  cage : VA

/-- Validate the tagged u64 at fp + slot as a JSFunction candidate
    (design §W3.2 checks 1-2): tagged, in-cage, aligned, map instance
    type in [itypeJsFunctionFirst, itypeJsFunctionLast]. none on any
    failure (fail closed; try next candidate, then none). -/
private def jsCandidateAt (space : AddressSpace) (fp : VA) (slot : Int)
    (cageHint : Option VA) (layout : V8Layout) : Option JsCandidate := do
  let tagged := readU64 space (wadd fp slot)
  if tagged &&& 1 != 1 then none
  else
    let heap := tagged &&& 0xFFFFFFFFFFFFFFFE
    -- kObjectAlignment = kTaggedSize = 4 under V8_ENABLE_COMPRESS_POINTERS
    -- (v8/src/common/globals.h; Electron 41 is a compressed-cage build):
    -- design §W3.2 check 1 "aligned".
    if heap &&& 3 != 0 then none
    else
      let derived := tagged &&& 0xFFFFFFFF00000000
      let cage := match cageHint with
        | some h => if heap ≥ h && heap < h + ((1 : UInt64) <<< 32) then h else derived
        | none => derived
      if heap < cage || heap ≥ cage + ((1 : UInt64) <<< 32) then none
      else
        let itype ← instanceType space cage heap
        if itype < layout.itypeJsFunctionFirst || itype > layout.itypeJsFunctionLast then none
        else
          -- check 3: the shared_function_info slot decompresses and its map
          -- is SHARED_FUNCTION_INFO_TYPE (design §W3.2).
          let sfiC ← readU32o space (heap + layout.jsfunctionSharedFunctionInfo)
          let sfi ← decompress cage sfiC
          let sfiItype ← instanceType space cage sfi
          if sfiItype != layout.itypeSharedFunctionInfo then none
          else some ⟨heap, cage⟩

/-- Resolve JS frame info at `fp` (v8.rs decode_js_frame). `eptBase` is
    threaded in/out (the Rust version shares a Cell across frames). -/
private def decodeJsFrame (space : AddressSpace) (fp : VA) (cageHint : Option VA)
    (isolateVa : Option VA) (moduleRanges : List (VA × UInt64)) (eptBase : Option VA)
    (layout : V8Layout) : Option (JsFrameInfo × Option VA) :=
  let decodeAt (heap cage : VA) : Option (JsFrameInfo × Option VA) := do
    match readU32o space (heap + layout.jsfunctionSharedFunctionInfo) with
    | none => none
    | some sfiC =>
      match decompress cage sfiC with
      | none => none
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
                let (nm, ept') :=
                  decodeStringObject space nameOrScope itype isolateVa moduleRanges ept layout
                ept := ept'
                info := { info with name := nm }
              else
                let (nm, ept') :=
                  scopeInfoFunctionName space cage nameOrScope isolateVa moduleRanges ept layout
                ept := ept'
                info := { info with name := nm }
                position := match readU32o space (nameOrScope + layout.scopePositionStart) with
                  | some raw => smi raw
                  | none => none
            | none => pure ()
          | none => pure ()
        | none => pure ()
        if info.name.isNone then
          info := { info with name := some "<anonymous>" }
        match readU32o space (sfi + layout.sfiScript) with
        | none => some (info, ept)
        | some c1 =>
          match decompress cage c1 with
          | none => some (info, ept)
          | some script =>
            let (sn, ept') := decodeScriptName space cage script isolateVa moduleRanges ept layout
            ept := ept'
            let line := match position with
              | some pos => decodeScriptLine space cage script pos layout
              | none => none
            some ({ info with scriptName := sn, scriptLine := line }, ept)
  let rec trySlot (slots : List Int) : Option (JsFrameInfo × Option VA) :=
    match slots with
    | [] => none
    | slot :: rest =>
      match jsCandidateAt space fp slot cageHint layout with
      | none => trySlot rest
      | some c => decodeAt c.heap c.cage
  -- fixed offsets first, then the bounded fallback scan [rbp-0x30 … rbp-0x8]
  -- step 8 (design §W3.2; covers Maglev/TurboFan spill layouts). Slot order
  -- is the deterministic tie-breaker (the §W3.2 context-match bonus).
  trySlot ([layout.kFunctionOffset, layout.kFunctionOffsetLegacy]
    ++ (List.range 6).map fun i => (-0x30 : Int) + 8 * Int.ofNat i)

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
  publics : Option Util.Publics
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
    (fuel : Nat) : List V8StackFrame × UnwindTables :=
  match fuel with
  | 0 => (acc, st.tables)
  | fuel + 1 =>
    let space := ctx.space
    let rip := st.regs.rip
    let rsp := st.regs.rsp
    let rbp := st.regs.rbp
    if rip == 0 || st.depth ≥ 256 || st.seen.contains (rip, rsp) then (acc, st.tables)
    else
      let inModule := ctx.moduleRanges.any fun (b, s) =>
        decide (rip ≥ b ∧ rip.toNat < b.toNat + s.toNat)
      if !inModule && (space.regionAt rip).isNone && st.viaLeaf then (acc, st.tables)
      else
        let marker := readU64 space (wadd rbp ctx.layout.kMarkerOffset)
        let frameType := classifyFrame rip ctx.moduleRanges space marker ctx.layout
        let js := decodeJsFrame space rbp ctx.cage ctx.isolateVa ctx.moduleRanges st.eptBase ctx.layout
        let (jsInfo, ept') := match js with
          | some (i, e) => (some i, e)
          | none => (none, st.eptBase)
        let frameType := refineType frameType jsInfo.isSome rip ctx.moduleRanges
        let (fnName, scriptName, scriptLine) := match jsInfo with
          | some i => (i.name, i.scriptName, i.scriptLine)
          | none => (none, none, none)
        let nativeSymbol : String := match ctx.publics with
          | none => hexUpper rip
          | some pubs =>
            match (ctx.moduleRanges.find? fun (b, s) =>
              decide (rip ≥ b && rip.toNat < b.toNat + s.toNat)) with
            | some (base, _) => (Util.Publics.symbol pubs base rip).getD (hexUpper rip)
            | none => hexUpper rip
        let frame : V8StackFrame :=
          { threadId := ctx.thread.id, depth := st.depth, frameType := frameType
            nativeSymbol := nativeSymbol, nativeOffset := 0
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
      (fuel : Nat) (_rip rsp rbp : VA) : List V8StackFrame × UnwindTables :=
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
      else (acc ++ [frame], st.tables)

private def walkThread (ctx : WalkCtx) (init : UnwindTables) :
    List V8StackFrame × UnwindTables :=
  let regs0 :=
    match ctx.dump.exception with
    | some exc =>
      if exc.threadId == ctx.thread.id then (exc.context.getD ctx.thread.registers)
      else ctx.thread.registers
    | none => ctx.thread.registers
  walkGo ctx { regs := regs0, depth := 0, seen := Std.HashSet.emptyWithCapacity
               viaLeaf := false, eptBase := none, tables := init } [] 256

/-- Walk all threads' stacks (v8.rs walk_thread_stacks). Overflow candidates
    in the EPT scan are skipped, never raised (upstream fix bd46529, v8.rs:539
    checked_add), so no exception channel survives. -/
def walkThreadStacks (publics : Option Util.Publics) (dump : Dump)
    (space : AddressSpace) : List V8StackFrame :=
  let layout := V8Layout.detect dump
  let isolateVa := Cause.annotationHex dump "v8_isolate_address"
  let cage := Cause.annotationHex dump "v8_ro_space_firstpage_address"
  let moduleRanges := dump.modules.map fun m => (m.baseVa, m.size)
  let rec go (threads : List Thread) (tables : UnwindTables) (acc : List V8StackFrame) :
      List V8StackFrame :=
    match threads with
    | [] => acc
    | t :: rest =>
      let ctx : WalkCtx :=
        { dump := dump, space := space, isolateVa := isolateVa, layout := layout
          moduleRanges := moduleRanges, cage := cage, publics := publics, thread := t
          stackVa := t.stackVa, stackEnd := t.stackVa + t.stackSize }
      let (frames, tables') := walkThread ctx tables
      go rest tables' (acc ++ frames)
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
  run ctx dump space := analyzerOk dump space (walkThreadStacks ctx.publics dump space)
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

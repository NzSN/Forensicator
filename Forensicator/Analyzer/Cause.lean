/- Forensicator.Analyzer.Cause — crash-cause diagnosis (analyzer/cause.rs
   port): fuses exception semantics, disassembly, MemoryInfoList
   classification, and cage-aware fault analysis into a ranked verdict.
   Fails closed to `Unknown`. -/
import Forensicator.Analyzer.Scan
import Forensicator.Util.Disasm
import Forensicator.Util.Text
import Forensicator.Util.Pdb

namespace Forensicator.Analyzer.Cause

open Forensicator.Model Forensicator.Spec Forensicator.Util

/-- Hex-valued annotation lookup (v8.rs annotation_hex). -/
def annotationHex (input : AnalysisInput) (key : String) : Option UInt64 :=
  (input.annotations.find? fun (k, _) => k == key).bind fun (_, v) =>
    let hex := (v.dropPrefix? "0x" <|> v.dropPrefix? "0X").map (·.toString) |>.getD v
    (hex.toList.foldlM (fun acc c => (hexVal c).map fun d => acc * 16 + d) 0)

/-- Verdict confidence (ranked Low < Medium < High). -/
inductive Confidence where
  | low | medium | high
  deriving Repr, DecidableEq, BEq, Inhabited

def Confidence.rank : Confidence → Nat
  | .low => 0 | .medium => 1 | .high => 2

def Confidence.debug : Confidence → String
  | .low => "Low" | .medium => "Medium" | .high => "High"

inductive CrashVerdict where
  | v8CheckFailure | v8OutOfMemory | stackOverflow | smiTypeConfusion
  | v8ObjectAccess (instanceType : UInt16)
  | v8TagConfusion | decompressedGarbagePointer
  | nullDeref | wildAccess | corruptedCodePointer | wasmGuardFault
  | noException | unknown
  deriving Repr, DecidableEq, Inhabited
  -- W1.2 (design §3): v8TagConfusion == tag/representation confusion in V8
  -- values (strong cage-decompression form); decompressedGarbagePointer ==
  -- AV at an uncommitted address inside the pointer-compression cage
  -- (weak form).

/-- Rust `{:?}` Debug names. -/
def CrashVerdict.debug : CrashVerdict → String
  | .v8CheckFailure => "V8CheckFailure"
  | .v8OutOfMemory => "V8OutOfMemory"
  | .stackOverflow => "StackOverflow"
  | .smiTypeConfusion => "SmiTypeConfusion"
  | .v8ObjectAccess it => "V8ObjectAccess { instance_type: " ++ toString it ++ " }"
  | .v8TagConfusion => "V8TagConfusion"
  | .decompressedGarbagePointer => "DecompressedGarbagePointer"
  | .nullDeref => "NullDeref"
  | .wildAccess => "WildAccess"
  | .corruptedCodePointer => "CorruptedCodePointer"
  | .wasmGuardFault => "WasmGuardFault"
  | .noException => "NoException"
  | .unknown => "Unknown"

inductive AccessKind where
  | read | write | execute
  deriving Repr, DecidableEq, BEq

def AccessKind.debug : AccessKind → String
  | .read => "Read" | .write => "Write" | .execute => "Execute"

structure CrashDiagnosis where
  verdict : CrashVerdict
  confidence : Confidence
  evidence : List String
  faultVa : Option VA
  access : Option AccessKind
  fatalMessage : Option String
  alternatives : List (CrashVerdict × Confidence)

-- Win32 page-protection bits + exception codes
private def PAGE_NOACCESS : UInt32 := 0x01
private def PAGE_GUARD : UInt32 := 0x100
private def PAGE_EXECUTE_ANY : UInt32 := 0x10 ||| 0x20 ||| 0x40 ||| 0x80
private def EXCEPTION_ACCESS_VIOLATION : UInt32 := 0xC0000005
private def EXCEPTION_BREAKPOINT : UInt32 := 0x80000003
private def EXCEPTION_STACK_OVERFLOW : UInt32 := 0xC00000FD

private def inRange (va start : UInt64) (size : UInt64) : Bool :=
  decide (start ≤ va ∧ va.toNat < start.toNat + size.toNat)

private structure Hit where
  rule : UInt8
  verdict : CrashVerdict
  confidence : Confidence
  evidence : List String

private structure Ctx where
  input : AnalysisInput
  space : AddressSpace
  fast : FastSpace
  faultVa : Option VA
  disasm : Option Instruction
  cageBase : Option VA
  publics : Option Util.Publics := none
  moduleBase : Option VA := none

private def isOomMessage (msg : String) : Bool :=
  ["Out of memory", "out of memory", "CALL_AND_RETRY_LAST", "Allocation failed"].any fun n =>
    (msg.splitOn n).length > 1

/-- Fatal message from: V8HE v2 ext, crashpad annotation, or a string scan
    of the crashed thread's stack region. -/
private def fatalMessage (input : AnalysisInput) (space : AddressSpace) (threadId : UInt32) : Option String :=
  match input.v8heapExt with
  | some ext => if ext.fatalMessage.isSome then ext.fatalMessage else rest input space threadId
  | none => rest input space threadId
where
  rest (input : AnalysisInput) (space : AddressSpace) (threadId : UInt32) : Option String :=
    match (input.annotations.find? fun (k, v) => k == "v8_fatal_message" && !v.isEmpty) with
    | some (_, v) => some v
    | none => scanStackForFatal input space threadId
  scanStackForFatal (input : AnalysisInput) (space : AddressSpace) (threadId : UInt32) : Option String :=
    let needles := ["Check failed:", "Fatal error in", "# Fatal", "Out of memory"]
    match input.stackRanges.find? (·.1 == threadId) with
    | none => none
    | some (_, stackVa, _) =>
      match space.regionAt stackVa with
      | none => none
      | some region =>
        needles.findSome? fun needle =>
          let nb := needle.toUTF8
          findSubslice region.data nb |>.bind fun pos =>
            let tail := region.data.extract pos region.data.size
            let endIdx := min (pos + findLineEnd tail) (pos + 512)
            let text := fromUTF8Lossy (region.data.extract pos endIdx)
            if text.isEmpty then none else some text
  findLineEnd (tail : ByteArray) : Nat :=
    let rec go (i : Nat) : Nat :=
      if i < tail.size then
        let b := tail.get! i
        if b == 0 || b == 0x0A then i else go (i + 1)
      else tail.size
    go 0
  findSubslice (haystack needle : ByteArray) : Option Nat :=
    let n := needle.size
    if n == 0 || haystack.size < n then none
    else
      let rec go (i : Nat) : Option Nat :=
        if i + n ≤ haystack.size then
          if haystack.extract i (i + n) == needle then some i else go (i + 1)
        else none
      termination_by haystack.size + 1 - i
      go 0

-- ── the ten rules ───────────────────────────────────────────────────

private def ruleFatalMessage (c : Ctx) : Option Hit :=
  c.input.exception.bind fun exc =>
    (fatalMessage c.input c.space exc.threadId).map fun msg =>
      { rule := 1
        verdict := if isOomMessage msg then .v8OutOfMemory else .v8CheckFailure
        confidence := .high
        evidence := [s!"captured fatal message: {msg}"] }

private def ruleBreakpoint (c : Ctx) : Option Hit :=
  c.input.exception.bind fun exc =>
    let codeHit := exc.code == EXCEPTION_BREAKPOINT
    let disasmHit := match c.disasm.map (·.kind) with
      | some .int3 | some .ud2 => true
      | _ => false
    if !codeHit && !disasmHit then none
    else
      let ev1 := if codeHit then
          [s!"exception code 0x{hexPadUpper EXCEPTION_BREAKPOINT.toUInt64 8} (breakpoint)"] else []
      let ev2 := if disasmHit then
          [s!"faulting instruction is {c.disasm.get!.kind.debug} at {hexUpper c.disasm.get!.va}"] else []
      some { rule := 2, verdict := .v8CheckFailure
             confidence := if codeHit && disasmHit then .high else .medium
             evidence := ev1 ++ ev2 }

private def ruleStackOverflow (c : Ctx) : Option Hit :=
  c.input.exception.bind fun exc =>
    if exc.code == EXCEPTION_STACK_OVERFLOW then
      some { rule := 3, verdict := .stackOverflow, confidence := .high
             evidence := [s!"exception code 0x{hexPadUpper EXCEPTION_STACK_OVERFLOW.toUInt64 8} (stack overflow)"] }
    else
      c.faultVa.bind fun fault =>
        (c.input.memoryInfo.find? fun mi =>
          mi.protection &&& PAGE_GUARD != 0 && inRange fault mi.vaStart mi.size).map fun guard =>
          let nearStack := c.input.stackRanges.any fun (_, s, size) =>
            let e := s + size
            decide (guard.vaStart + 0x10000 ≥ s ∧ guard.vaStart ≤ e + 0x10000)
          { rule := 3, verdict := .stackOverflow
            confidence := if nearStack then .high else .medium
            evidence := [s!"fault VA {hexUpper fault} inside PAGE_GUARD region at {hexUpper guard.vaStart} (stack guard page)"] }

private def ruleWasmGuard (c : Ctx) : Option Hit := do
  let fault ← c.faultVa
  let reserved ← c.input.memoryInfo.find? fun mi =>
    mi.state == .Reserve && mi.size ≥ (1 : UInt64) <<< 30
      && mi.protection &&& PAGE_NOACCESS != 0 && inRange fault mi.vaStart mi.size
  let codeNearby := c.input.memoryInfo.any fun mi =>
    mi.state == .Commit && mi.protection &&& PAGE_EXECUTE_ANY != 0
      && (if mi.vaStart ≥ reserved.vaStart then mi.vaStart - reserved.vaStart
          else reserved.vaStart - mi.vaStart) < ((4 : UInt64) <<< 30)
  if !codeNearby then none
  else some { rule := 4, verdict := .wasmGuardFault, confidence := .low
              evidence := [s!"fault VA {hexUpper fault} inside {hexUpper reserved.size}-byte reserved guard region at {hexUpper reserved.vaStart} with executable code nearby"] }

private def ruleSmiConfusion (c : Ctx) : Option Hit := do
  let fault ← c.faultVa
  let exc ← c.input.exception
  let regs ← exc.context
  let (base, index, _scale, disp) ← match c.disasm.map (·.kind) with
    | some (Util.InstrKind.memRead b i s d) | some (Util.InstrKind.memWrite b i s d) => some (b, i, s, d)
    | _ => none
  if index.isSome then none  -- SIB operand: index algebra lands with the cage rule (T2)
  else
    let baseIdx ← base
    let baseVal := regs.get baseIdx
    if baseVal == 0 || baseVal ≥ ((1 : UInt64) <<< 32) || baseVal &&& 1 != 0 then none
    else
      let effective := (Int.ofNat baseVal.toNat + disp).toNat % (2 ^ 64)
      if fault.toNat != effective then none
      else some { rule := 5, verdict := .smiTypeConfusion, confidence := .high
                  evidence := [s!"base register holds compressed Smi (value {(Int.ofNat baseVal.toNat) / 2}), dereferenced as pointer: {c.disasm.get!.text}"] }

private def ruleObjectAccess (c : Ctx) : Option Hit := do
  let fault ← c.faultVa
  let cage ← c.cageBase
  if fault < cage || fault ≥ cage + ((1 : UInt64) <<< 32) then none
  else
    let exc ← c.input.exception
    let regs ← exc.context
    let (base, index, _scale, disp) ← match c.disasm.map (·.kind) with
      | some (Util.InstrKind.memRead (some b) i s d) | some (Util.InstrKind.memWrite (some b) i s d) => some (b, i, s, d)
      | _ => none
    if index.isSome then none  -- SIB operand: index algebra lands with the cage rule (T2)
    else
      let tagged := regs.get base
      if tagged &&& 1 != 1 then none
      else
        let heap := tagged &&& (0xFFFFFFFFFFFFFFFF - 1)
        if heap < cage || heap ≥ cage + ((1 : UInt64) <<< 32) then none
        else
          let effective := (Int.ofNat tagged.toNat + disp).toNat % (2 ^ 64)
          if fault.toNat != effective then none
          else
            let itype ← v8InstanceType c.space cage heap
            some { rule := 6, verdict := .v8ObjectAccess itype, confidence := .medium
                   evidence := [s!"fault VA {hexUpper fault} = object {hexUpper heap} {dispTextRust disp}; instance type 0x{hexPadUpper itype.toUInt64 4} (layout {layoutName c.input})"] }
where
  dispTextRust (d : Int) : String :=
    -- Rust {disp:+#x}: lowercase hex with 0x and explicit sign
    if d ≥ 0 then "+0x" ++ String.ofList (Nat.toDigits 16 d.toNat)
    else "-0x" ++ String.ofList (Nat.toDigits 16 (-d).toNat)
  v8InstanceType (space : AddressSpace) (cage heap : VA) : Option UInt16 :=
    match space.read heap 4 with
    | none => none
    | some bs =>
      let compressed := readU32leAt bs 0
      if compressed == 0 || compressed &&& 1 == 0 then none
      else
        let map := cage + (compressed &&& (0xFFFFFFFF - 1)).toUInt64
        match space.read (map + 8) 2 with
        | none => none
        | some b2 => some (readU16leAt b2 0)
  layoutName (input : AnalysisInput) : String :=
    match input.annotations.find? fun (k, _) => k == "ver" with
    | some (_, v) => s!"electron {v}"
    | none => "generic"

/-- Crash-IP symbolization (design §W1.4): the exception address's RVA
    within its module, its nearest public symbol ("NAME+0xHEX" no-space via
    Util.Publics.symbol), plus an embedded-builtin note when the symbol is
    a V8 builtin (a builtin crash site is itself evidence for a V8-internal
    defect). Fail closed: no module covers the address or no symbol sits at
    or below the rva → no lines. -/
private def crashIpSymbolLines (pubs : Util.Publics) (input : AnalysisInput)
    (exc : ExceptionInfo) (moduleBase : Option VA) : List String :=
  match input.modules.find? fun m =>
    decide (exc.address ≥ m.baseVa
      && exc.address.toNat < m.baseVa.toNat + m.size.toNat) with
  | none => []
  | some m =>
    if moduleBase.isSome && moduleBase != some m.baseVa then []
    else match Util.Publics.symbol pubs m.baseVa exc.address with
    | none => []
    | some sym =>
      let line := s!"faulting IP {hexUpper (exc.address - m.baseVa)} = {sym}"
      if sym.startsWith "Builtins_" then
        [line, s!"crash site is inside embedded builtin {sym} — V8-internal defect evidence"]
      else [line]

private def ruleCageDecompression (c : Ctx) : Option Hit := do
  -- W1.3 (design §3): AV read/write fault inside the 4 GB V8 pointer-
  -- compression cage reservation but outside every committed region — the
  -- signature of a garbage 32-bit value decompressed as a pointer.
  -- Strong form (v8TagConfusion/High): the faulting instruction is the
  -- decompression idiom — memory base register holds the cage base and the
  -- compressed value rides the SIB index register ([cage_reg + idx*scale +
  -- disp]), with the effective address matching the fault VA.
  let fault ← c.faultVa
  let exc ← c.input.exception
  if exc.code != EXCEPTION_ACCESS_VIOLATION then none
  else
    let cage ← c.cageBase
    let cageEnd := cage + ((1 : UInt64) <<< 32)
    if fault < cage || fault ≥ cageEnd then none
    -- Missing captured bytes alone do not establish an uncommitted address.
    else if !c.input.point.memory.knownAbsent fault then none
    else
      let inCage := c.space.regions.filter fun r => r.vaStart ≥ cage && r.vaStart < cageEnd
      let pastText :=
        match inCage.getLast? with
        | none => ""
        | some r =>
          let e := r.vaStart + r.size
          if fault ≥ e then
            s!"; fault is 0x{String.ofList (Nat.toDigits 16 (fault - e).toNat)} past the highest observed cage region (end {hexUpper e})"
          else ""
      let symLines : List String := match c.publics with
        | none => []
        | some pubs => crashIpSymbolLines pubs c.input exc c.moduleBase
      let idiom : Option (UInt64 × UInt8 × Int) :=
        match c.disasm, exc.context with
        | some instr, some regs =>
          match instr.kind with
          | Util.InstrKind.memRead (some b) (some ix) s d =>
            if regs.get b == cage then some (regs.get ix, s, d) else none
          | Util.InstrKind.memWrite (some b) (some ix) s d =>
            if regs.get b == cage then some (regs.get ix, s, d) else none
          | _ => none
        | _, _ => none
      match idiom, c.disasm with
      | some (v, scale, disp), some instr =>
        let eff := (Int.ofNat cage.toNat + Int.ofNat v.toNat * Int.ofNat scale.toNat + disp).toNat % (2 ^ 64)
        if eff != fault.toNat then
          some { rule := 11, verdict := .decompressedGarbagePointer, confidence := .medium
                 evidence := [s!"access violation at fault VA {hexUpper fault}: inside the 4GB V8 cage reservation (base {hexUpper cage}) but uncommitted — decompressed garbage 32-bit value{pastText}"] ++ symLines }
        else
          let tagNote :=
            if v &&& 1 == 0 then " (untagged even value — Smi or garbage used as a heap pointer)"
            else " (tag bit set)"
          some { rule := 11, verdict := .v8TagConfusion, confidence := .high
                 evidence := [s!"access violation at uncommitted VA {hexUpper fault} inside the V8 pointer-compression cage (base {hexUpper cage}){pastText}",
                              s!"faulting instruction decompresses a compressed pointer: base register holds the cage base, compressed value 0x{String.ofList (Nat.toDigits 16 v.toNat)}{tagNote}: {instr.text}"] ++ symLines }
      | _, _ =>
        some { rule := 11, verdict := .decompressedGarbagePointer, confidence := .medium
               evidence := [s!"access violation at fault VA {hexUpper fault}: inside the 4GB V8 cage reservation (base {hexUpper cage}) but uncommitted — decompressed garbage 32-bit value{pastText}"] ++ symLines }

private def ruleOomState (c : Ctx) : Option Hit := do
  let ext ← c.input.v8heapExt
  if ext.allocTopVa == 0 || ext.allocLimitVa == 0 then none
  else
    let headroom := if ext.allocLimitVa ≥ ext.allocTopVa then ext.allocLimitVa - ext.allocTopVa else 0
    if headroom ≥ 0x10000 then none
    else
      let fault := c.faultVa.getD ext.allocTopVa
      if fault < ext.allocTopVa || fault > ext.allocLimitVa + 0x1000 then none
      else some { rule := 7, verdict := .v8OutOfMemory, confidence := .medium
                  evidence := [s!"allocation area exhausted: top {hexUpper ext.allocTopVa}, limit {hexUpper ext.allocLimitVa} (headroom 0x{String.ofList (Nat.toDigits 16 headroom.toNat)}), fault VA {hexUpper fault}"] }

private def ruleCorruptedCodePointer (c : Ctx) : Option Hit := do
  let exc ← c.input.exception
  if exc.code == EXCEPTION_BREAKPOINT || exc.code == EXCEPTION_STACK_OVERFLOW then none
  else
    let inModule := c.input.modules.any fun m =>
      decide (m.baseVa ≤ exc.address ∧ exc.address.toNat < m.baseVa.toNat + m.size.toNat)
    if inModule then none
    else
      -- Mapping metadata carries native Windows page protections. AddressSpace
      -- may include supplemental disk bytes or proxy pages with unknown
      -- protections, neither of which proves a non-executable live mapping.
      let badTarget := c.input.point.memory.knownAbsent exc.address
        || c.input.memoryInfo.any fun r =>
          r.state == .Commit && inRange exc.address r.vaStart r.size
            && ([0x01, 0x02, 0x04, 0x08] : List UInt32).contains (r.protection &&& 0xFF)
      if !badTarget then none
      else some { rule := 8, verdict := .corruptedCodePointer, confidence := .high
                  evidence := [s!"RIP {hexUpper exc.address} has observed absent/non-executable memory backing"] }

private def ruleNullDeref (c : Ctx) : Option Hit := do
  let fault ← c.faultVa
  if fault ≥ 0x10000 then none
  else some { rule := 9, verdict := .nullDeref, confidence := .high
              evidence := [s!"fault VA {hexUpper fault} is in the null page"] }

private def ruleWildAccess (c : Ctx) : Option Hit := do
  let exc ← c.input.exception
  if exc.code != EXCEPTION_ACCESS_VIOLATION then none
  else some { rule := 10, verdict := .wildAccess, confidence := .low
              evidence := [match c.faultVa with
                | some f => s!"access violation at fault VA {hexUpper f}, no V8 correlation"
                | none => "access violation, fault VA not recorded"] }

/-- Diagnose with an optional publics table (design §W1.4): the cage rule
    enriches its evidence with crash-IP symbolization when symbols are
    available; none behaves exactly as diagnose. -/
def diagnoseWith (publics : Option Util.Publics) (input : AnalysisInput)
    (space : AddressSpace) (moduleBase : Option VA := none) : CrashDiagnosis :=
  match input.exception with
  | none =>
    let hasExceptions := input.point.events.any (·.kind == .Exception)
    { verdict := if hasExceptions then .unknown else .noException
      confidence := if hasExceptions || input.point.eventCoverage != .complete then .low else .high
      evidence := [if hasExceptions then "no unique exception selected at this execution point"
                   else "no exception event available at this execution point"]
      faultVa := none, access := none, fatalMessage := none, alternatives := [] }
  | some exc =>
    let faultVa :=
      if exc.code == EXCEPTION_ACCESS_VIOLATION then (exc.parameters.drop 1).head?
      else none
    let access :=
      if exc.code == EXCEPTION_ACCESS_VIOLATION then
        match exc.parameters.head? with
        | some 0 => some AccessKind.read
        | some 1 => some AccessKind.write
        | some 8 => some AccessKind.execute
        | _ => none
      else none
    let ctx : Ctx :=
      { input := input
        space := space
        fast := FastSpace.ofSpace space
        faultVa := faultVa
        disasm := decodeFirst (FastSpace.ofSpace space) exc.address
        cageBase := annotationHex input "v8_ro_space_firstpage_address"
        publics := publics, moduleBase }
    let rules : List (Ctx → Option Hit) :=
      [ruleFatalMessage, ruleBreakpoint, ruleStackOverflow, ruleWasmGuard,
       ruleSmiConfusion, ruleObjectAccess, ruleCageDecompression, ruleOomState, ruleCorruptedCodePointer,
       ruleNullDeref, ruleWildAccess]
    let hits := rules.filterMap fun r => r ctx
    let hits := hits.mergeSort fun a b =>
      decide (b.confidence.rank ≤ a.confidence.rank) -- desc confidence; ties: rule order asc (stable sort preserves it)
    let fatal := fatalMessage input space exc.threadId
    match hits with
    | [] =>
      { verdict := .unknown, confidence := .low
        evidence := [s!"exception code 0x{hexPadUpper exc.code.toUInt64 8} matched no classification rule"]
        faultVa := faultVa, access := access, fatalMessage := fatal
        alternatives := [] }
    | head :: rest =>
      { verdict := head.verdict, confidence := head.confidence
        evidence := head.evidence
        faultVa := faultVa, access := access, fatalMessage := fatal
        alternatives := rest.map fun h => (h.verdict, h.confidence) }

/-- Diagnose the input's exception into a ranked verdict (cause.rs diagnose). -/
def diagnose (input : AnalysisInput) (space : AddressSpace) : CrashDiagnosis :=
  diagnoseWith none input space

/-- Append crash-IP symbolization to the evidence when a publics table is
    present (design §W1.4), but only when the verdict's own rule has not
    already added it; ruleCageDecompression carries the same lines inline,
    so the builtin note sits WITHIN the V8TagConfusion and
    DecompressedGarbagePointer evidence rather than trailing (T7).
    Fail closed: no change when there is no exception, no module covers
    the exception address, or no symbol is at or below it. -/
private def symbolEvidence (pubs : Util.Publics) (input : AnalysisInput)
    (d : CrashDiagnosis) (moduleBase : Option VA) : CrashDiagnosis :=
  match input.exception with
  | none => d
  | some exc =>
    let extra := crashIpSymbolLines pubs input exc moduleBase
    if extra.isEmpty || d.evidence.any (·.startsWith "faulting IP") then d
    else { d with evidence := d.evidence ++ extra }

/-- The cause analyzer. -/
def analyzer : Analyzer where
  name := "cause"
  description := "Diagnoses why the process crashed: exception semantics, disassembly, cage fault analysis"
  run ctx input :=
    let space := input.space
    let d := diagnoseWith ctx.publics input space ctx.moduleBase
    let d := match ctx.publics with
      | none => d
      | some pubs => symbolEvidence pubs input d ctx.moduleBase
    { AnalyzerOutput.new "cause" with
      custom := [("crash_diagnosis", .obj [
        ("verdict", .str d.verdict.debug),
        ("confidence", .str d.confidence.debug),
        ("evidence", .arr (d.evidence.map .str)),
        ("fault_va", match d.faultVa with | some v => .str (hexUpper v) | none => .null),
        ("access", match d.access with | some a => .str a.debug | none => .null),
        ("fatal_message", match d.fatalMessage with | some m => .str m | none => .null),
        ("alternatives", .arr (d.alternatives.map fun (v, c) =>
          .str s!"{v.debug}/{c.debug}"))])] }

end Forensicator.Analyzer.Cause

/- Forensicator.Analyzer.Cause — crash-cause diagnosis (analyzer/cause.rs
   port): fuses exception semantics, disassembly, MemoryInfoList
   classification, and cage-aware fault analysis into a ranked verdict.
   Fails closed to `Unknown`. -/
import Forensicator.Analyzer.Scan
import Forensicator.Util.Disasm
import Forensicator.Util.Text

namespace Forensicator.Analyzer.Cause

open Forensicator.Model Forensicator.Spec Forensicator.Util

/-- Hex-valued annotation lookup (v8.rs annotation_hex). -/
def annotationHex (dump : Dump) (key : String) : Option UInt64 :=
  (dump.annotations.find? fun (k, _) => k == key).bind fun (_, v) =>
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
  | nullDeref | wildAccess | corruptedCodePointer | wasmGuardFault
  | noException | unknown
  deriving Repr, DecidableEq, Inhabited

/-- Rust `{:?}` Debug names. -/
def CrashVerdict.debug : CrashVerdict → String
  | .v8CheckFailure => "V8CheckFailure"
  | .v8OutOfMemory => "V8OutOfMemory"
  | .stackOverflow => "StackOverflow"
  | .smiTypeConfusion => "SmiTypeConfusion"
  | .v8ObjectAccess it => "V8ObjectAccess { instance_type: " ++ toString it ++ " }"
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
  dump : Dump
  space : AddressSpace
  fast : FastSpace
  faultVa : Option VA
  disasm : Option Instruction
  cageBase : Option VA

private def isOomMessage (msg : String) : Bool :=
  ["Out of memory", "out of memory", "CALL_AND_RETRY_LAST", "Allocation failed"].any fun n =>
    (msg.splitOn n).length > 1

/-- Fatal message from: V8HE v2 ext, crashpad annotation, or a string scan
    of the crashed thread's stack region. -/
private def fatalMessage (dump : Dump) (space : AddressSpace) (threadId : UInt32) : Option String :=
  match dump.v8heapExt with
  | some ext => if ext.fatalMessage.isSome then ext.fatalMessage else rest dump space threadId
  | none => rest dump space threadId
where
  rest (dump : Dump) (space : AddressSpace) (threadId : UInt32) : Option String :=
    match (dump.annotations.find? fun (k, v) => k == "v8_fatal_message" && !v.isEmpty) with
    | some (_, v) => some v
    | none => scanStackForFatal dump space threadId
  scanStackForFatal (dump : Dump) (space : AddressSpace) (threadId : UInt32) : Option String :=
    let needles := ["Check failed:", "Fatal error in", "# Fatal", "Out of memory"]
    match dump.threads.find? (·.id == threadId) with
    | none => none
    | some thread =>
      match space.regionAt thread.stackVa with
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
  c.dump.exception.bind fun exc =>
    (fatalMessage c.dump c.space exc.threadId).map fun msg =>
      { rule := 1
        verdict := if isOomMessage msg then .v8OutOfMemory else .v8CheckFailure
        confidence := .high
        evidence := [s!"captured fatal message: {msg}"] }

private def ruleBreakpoint (c : Ctx) : Option Hit :=
  c.dump.exception.bind fun exc =>
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
  c.dump.exception.bind fun exc =>
    if exc.code == EXCEPTION_STACK_OVERFLOW then
      some { rule := 3, verdict := .stackOverflow, confidence := .high
             evidence := [s!"exception code 0x{hexPadUpper EXCEPTION_STACK_OVERFLOW.toUInt64 8} (stack overflow)"] }
    else
      c.faultVa.bind fun fault =>
        (c.dump.memoryInfo.find? fun mi =>
          mi.protection &&& PAGE_GUARD != 0 && inRange fault mi.vaStart mi.size).map fun guard =>
          let nearStack := c.dump.threads.any fun t =>
            let s := t.stackVa
            let e := t.stackVa + t.stackSize
            decide (guard.vaStart + 0x10000 ≥ s ∧ guard.vaStart ≤ e + 0x10000)
          { rule := 3, verdict := .stackOverflow
            confidence := if nearStack then .high else .medium
            evidence := [s!"fault VA {hexUpper fault} inside PAGE_GUARD region at {hexUpper guard.vaStart} (stack guard page)"] }

private def ruleWasmGuard (c : Ctx) : Option Hit := do
  let fault ← c.faultVa
  let reserved ← c.dump.memoryInfo.find? fun mi =>
    mi.state == .Reserve && mi.size ≥ (1 : UInt64) <<< 30
      && mi.protection &&& PAGE_NOACCESS != 0 && inRange fault mi.vaStart mi.size
  let codeNearby := c.dump.memoryInfo.any fun mi =>
    mi.state == .Commit && mi.protection &&& PAGE_EXECUTE_ANY != 0
      && (if mi.vaStart ≥ reserved.vaStart then mi.vaStart - reserved.vaStart
          else reserved.vaStart - mi.vaStart) < ((4 : UInt64) <<< 30)
  if !codeNearby then none
  else some { rule := 4, verdict := .wasmGuardFault, confidence := .low
              evidence := [s!"fault VA {hexUpper fault} inside {hexUpper reserved.size}-byte reserved guard region at {hexUpper reserved.vaStart} with executable code nearby"] }

private def ruleSmiConfusion (c : Ctx) : Option Hit := do
  let fault ← c.faultVa
  let exc ← c.dump.exception
  let regs ← exc.context
  let (base, disp) ← match c.disasm.map (·.kind) with
    | some (Util.InstrKind.memRead b d) | some (Util.InstrKind.memWrite b d) => some (b, d)
    | _ => none
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
    let exc ← c.dump.exception
    let regs ← exc.context
    let (base, disp) ← match c.disasm.map (·.kind) with
      | some (Util.InstrKind.memRead (some b) d) | some (Util.InstrKind.memWrite (some b) d) => some (b, d)
      | _ => none
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
                 evidence := [s!"fault VA {hexUpper fault} = object {hexUpper heap} {dispTextRust disp}; instance type 0x{hexPadUpper itype.toUInt64 4} (layout {layoutName c.dump})"] }
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
  layoutName (dump : Dump) : String :=
    match dump.annotations.find? fun (k, _) => k == "ver" with
    | some (_, v) => s!"electron {v}"
    | none => "generic"

private def ruleOomState (c : Ctx) : Option Hit := do
  let ext ← c.dump.v8heapExt
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
  let exc ← c.dump.exception
  if exc.code == EXCEPTION_BREAKPOINT || exc.code == EXCEPTION_STACK_OVERFLOW then none
  else
    let inModule := c.dump.modules.any fun m =>
      decide (m.baseVa ≤ exc.address ∧ exc.address.toNat < m.baseVa.toNat + m.size.toNat)
    if inModule then none
    else
      let badTarget := match c.space.regionAt exc.address with
        | none => true
        | some r => r.protection &&& PAGE_EXECUTE_ANY == 0
      if !badTarget then none
      else some { rule := 8, verdict := .corruptedCodePointer, confidence := .high
                  evidence := [s!"RIP {hexUpper exc.address} is outside all modules and in unmapped/non-executable memory"] }

private def ruleNullDeref (c : Ctx) : Option Hit := do
  let fault ← c.faultVa
  if fault ≥ 0x10000 then none
  else some { rule := 9, verdict := .nullDeref, confidence := .high
              evidence := [s!"fault VA {hexUpper fault} is in the null page"] }

private def ruleWildAccess (c : Ctx) : Option Hit := do
  let exc ← c.dump.exception
  if exc.code != EXCEPTION_ACCESS_VIOLATION then none
  else some { rule := 10, verdict := .wildAccess, confidence := .low
              evidence := [match c.faultVa with
                | some f => s!"access violation at fault VA {hexUpper f}, no V8 correlation"
                | none => "access violation, fault VA not recorded"] }

/-- Diagnose the dump's exception into a ranked verdict (cause.rs diagnose). -/
def diagnose (dump : Dump) (space : AddressSpace) : CrashDiagnosis :=
  match dump.exception with
  | none =>
    { verdict := .noException, confidence := .high
      evidence := ["no exception stream in dump"]
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
      { dump := dump
        space := space
        fast := FastSpace.ofSpace space
        faultVa := faultVa
        disasm := decodeFirst (FastSpace.ofSpace space) exc.address
        cageBase := annotationHex dump "v8_ro_space_firstpage_address" }
    let rules : List (Ctx → Option Hit) :=
      [ruleFatalMessage, ruleBreakpoint, ruleStackOverflow, ruleWasmGuard,
       ruleSmiConfusion, ruleObjectAccess, ruleOomState, ruleCorruptedCodePointer,
       ruleNullDeref, ruleWildAccess]
    let hits := rules.filterMap fun r => r ctx
    let hits := hits.mergeSort fun a b =>
      decide (b.confidence.rank ≤ a.confidence.rank) -- desc confidence; ties: rule order asc (stable sort preserves it)
    let fatal := fatalMessage dump space exc.threadId
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

/-- The cause analyzer. -/
def analyzer : Analyzer where
  name := "cause"
  description := "Diagnoses why the process crashed: exception semantics, disassembly, cage fault analysis"
  run dump space :=
    let d := diagnose dump space
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

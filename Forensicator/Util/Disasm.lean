/- Forensicator.Util.Disasm — minimal x86-64 window decoder (disasm.rs port).

   GATE DECISION (Task 8 step 1): native Lean decoder, no iced-x86 FFI.
   Covers exactly what the crash-cause rules consume:
     - Int3 (CC), Ud2 (0F 0B)                         — rule 2
     - MemRead/MemWrite { base, disp } classification — rules 5/6
     - IndirectCall/IndirectJump (FF /2 /4)           — classification parity
     - Intel text for the covered integer mem-op forms (rule-5 evidence;
       iced-x86 default-options number formatting: ≤ 9 decimal, uppercase
       hex with leading-zero-on-letter-nibble, no prefix/suffix).
   Anything else classifies as `Other` (fail-closed) with placeholder text;
   that text can only surface in outputs the fixtures don't exercise. -/
import Forensicator.Spec.AddressSpace
import Forensicator.Util.Bytes
import Forensicator.Model.Dump

namespace Forensicator.Util

open Forensicator.Spec

inductive InstrKind where
  | int3 | ud2
  | memRead (base : Option Nat) (disp : Int)
  | memWrite (base : Option Nat) (disp : Int)
  | indirectCall | indirectJump
  | other
  deriving Repr, DecidableEq, BEq, Inhabited

/-- Rust `{:?}` of disasm::InstrKind (rule-2 evidence). -/
def InstrKind.debug : InstrKind → String
  | .int3 => "Int3"
  | .ud2 => "Ud2"
  | .memRead _ _ => "MemRead { .. }"
  | .memWrite _ _ => "MemWrite { .. }"
  | .indirectCall => "IndirectCall"
  | .indirectJump => "IndirectJump"
  | .other => "Other"

structure Instruction where
  va : VA
  text : String
  kind : InstrKind
  len : Nat
  deriving Inhabited

/-- iced-x86 default number formatting: ≤ 9 decimal, else uppercase hex with
    a leading zero when the top nibble is a letter (no prefix/suffix). -/
def fmtNum (v : UInt64) : String :=
  if v ≤ 9 then toString v.toNat
  else
    let ds := (Nat.toDigits 16 v.toNat).map fun c => if c.isAlpha then c.toUpper else c
    match ds with
    | d :: _ => if d.isAlpha then "0" ++ String.ofList ds else String.ofList ds
    | [] => "0"

/-- ModRM register-file order → display names. -/
def regName64 (r : Nat) : String :=
  ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
   "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"].getD r "?"
def regName32 (r : Nat) : String :=
  ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
   "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"].getD r "?"
def regName8 (r : Nat) : String :=
  ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
   "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"].getD r "?"

/-- x64 CONTEXT order → display names (for memText, whose bases are
    already mapped to x64 indices). -/
def regNameX64 (r : Nat) : String :=
  ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9",
   "r10", "r11", "r12", "r13", "r14", "r15", "rbp", "rsp"].getD r "?"

/-- ModRM register-file order → x64 CONTEXT register index
    (disasm.rs reg_index onto arch.rs x64_indices). -/
def regToX64 (r : Nat) : Nat :=
  [Model.X64.RAX, Model.X64.RCX, Model.X64.RDX, Model.X64.RBX,
   Model.X64.RSP, Model.X64.RBP, Model.X64.RSI, Model.X64.RDI,
   Model.X64.R8, Model.X64.R9, Model.X64.R10, Model.X64.R11,
   Model.X64.R12, Model.X64.R13, Model.X64.R14, Model.X64.R15].getD r 0

private def sext8 (b : UInt8) : Int :=
  if b ≥ 0x80 then (Int.ofNat b.toNat) - 256 else Int.ofNat b.toNat
private def sext32 (v : UInt32) : Int :=
  if v ≥ 0x80000000 then (Int.ofNat v.toNat) - 4294967296 else Int.ofNat v.toNat

/-- A decoded memory operand (pre-relocation). -/
structure MemOp where
  baseX64 : Option Nat  -- x64 CONTEXT index; none = RIP-relative or absolute
  ripRel : Bool         -- disp is the raw disp32; absolute target = ip+len+disp
  disp : Int
  bytes : Nat           -- modrm+sib+disp byte count

/-- Decode ModRM/SIB/displacement at `pos`. Returns (regField, memOp?, bytes).
    `none` memOp = register-direct (mod=3). -/
private def decodeModRM (bytes : ByteArray) (pos : Nat)
    (rexR _rexX rexB : Bool) : Option (Nat × Option MemOp × Nat) :=
  if pos ≥ bytes.size then none
  else
    let modrm := bytes.get! pos
    let m := modrm.toNat / 64
    let reg := (modrm.toNat / 8) % 8 + (if rexR then 8 else 0)
    let rm := modrm.toNat % 8
    if m == 3 then some (reg, none, 1)
    else if rm == 4 then
      -- SIB
      if pos + 1 ≥ bytes.size then none
      else
        let sib := bytes.get! (pos + 1)
        let baseField := sib.toNat % 8
        let base := regToX64 (baseField + (if rexB then 8 else 0))
        let noBase := baseField == 5 && m == 0
        let dispLen := if noBase || m == 2 then 4 else m
        if pos + 2 + dispLen ≤ bytes.size then
          let disp : Int :=
            if dispLen == 0 then 0
            else if dispLen == 1 then sext8 (bytes.get! (pos + 2))
            else sext32 (readU32leAt bytes (pos + 2))
          some (reg, some { baseX64 := if noBase then none else some base
                            ripRel := false, disp := disp
                            bytes := 2 + dispLen }, 2 + dispLen)
        else none
    else if m == 0 && rm == 5 then
      -- RIP-relative
      if pos + 5 ≤ bytes.size then
        some (reg, some { baseX64 := none, ripRel := true
                          disp := sext32 (readU32leAt bytes (pos + 1))
                          bytes := 5 }, 5)
      else none
    else
      let base := regToX64 (rm + (if rexB then 8 else 0))
      let dispLen := if m == 0 then 0 else if m == 1 then 1 else 4
      if pos + 1 + dispLen ≤ bytes.size then
        let disp : Int :=
          if dispLen == 0 then 0
          else if dispLen == 1 then sext8 (bytes.get! (pos + 1))
          else sext32 (readU32leAt bytes (pos + 1))
        some (reg, some { baseX64 := some base, ripRel := false
                          disp := disp, bytes := 1 + dispLen }, 1 + dispLen)
      else none

private def dispText (d : Int) : String :=
  if d == 0 then ""
  else if d > 0 then "+" ++ fmtNum (UInt64.ofNat d.toNat)
  else "-" ++ fmtNum (UInt64.ofNat (-d).toNat)

/-- Memory operand text: "[base±disp]" / "[rip±disp]" / "[absolute]". -/
private def memText (mo : MemOp) (_ip : VA) (_totalLen : Nat) : String :=
  match mo.baseX64 with
  | some b => "[" ++ regNameX64 b ++ dispText mo.disp ++ "]"
  | none =>
    if mo.ripRel then
      "[rip" ++ dispText mo.disp ++ "]"
    else
      let a := if mo.disp ≥ 0 then UInt64.ofNat mo.disp.toNat
               else UInt64.ofNat ((-mo.disp).toNat % (2^64))
      "[" ++ fmtNum a ++ "]"

/-- memText with the RIP-relative target folded in for the KIND's disp. -/
private def finalDisp (mo : MemOp) (ip : VA) (totalLen : Nat) : Int :=
  if mo.ripRel then Int.ofNat ip.toNat + Int.ofNat totalLen + mo.disp else mo.disp

private def ptrSize : Nat → String
  | 1 => "byte ptr"
  | 2 => "word ptr"
  | 4 => "dword ptr"
  | _ => "qword ptr"

private def regNameOf (size : Nat) (r : Nat) : String :=
  if size == 1 then regName8 r else if size == 4 then regName32 r else regName64 r

/-- The decoder result. -/
structure Decoded where
  kind : InstrKind
  text : String
  len : Nat

private def grp1Name : Nat → String :=
  fun r => ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"].getD r "?"
private def grp3Name : Nat → String :=
  fun r => ["test", "test", "not", "neg", "mul", "imul", "div", "idiv"].getD r "?"

/-- Decode one instruction at the start of `bytes`. Total length `plen` is
    the prefix count; `ip` is the instruction VA (for RIP-relative). -/
private def decodeOpcode (bytes : ByteArray) (plen : Nat) (ip : VA)
    (rexW rexR rexX rexB : Bool) : Decoded :=
  let op := bytes.get! plen
  let other (len : Nat) (text : String) : Decoded := { kind := .other, text := text, len := plen + len }
  let size : Nat := if op == 0x38 || op == 0x80 || op == 0x84 || op == 0x86 || op == 0x88 || op == 0x8A
                       || op == 0xC6 || op == 0xF6 || op == 0xFE then 1
                    else if rexW then 8 else 4
  -- decode helper for modrm forms: returns (reg, memOp?, totalLen) or other
  let withModRM (immLen : Nat) (f : Nat → Option MemOp → Nat → Decoded) : Decoded :=
    match decodeModRM bytes (plen + 1) rexR rexX rexB with
    | none => other 1 "db"
    | some (reg, mo, memLen) => f reg mo (plen + 1 + memLen + immLen)
  match op with
  | 0xCC => { kind := .int3, text := "int3", len := plen + 1 }
  | 0x90 => other 1 "nop"
  | 0xC3 => other 1 "ret"
  | 0xE8 => other 5 "call"
  | 0xE9 => other 5 "jmp"
  | 0xEB => other 2 "jmp"
  | 0x38 | 0x39 =>  -- cmp r/m, reg (op0 mem read-only)
    withModRM 0 fun reg mo total =>
      match mo with
      | none => other 1 "db"
      | some mo =>
        { kind := .memRead mo.baseX64 (finalDisp mo ip total)
          text := s!"cmp {ptrSize size} {memText mo ip total},{regNameOf size reg}"
          len := total }
  | 0x84 | 0x85 =>  -- test r/m, reg  (op0 mem read-only)
    withModRM 0 fun reg mo total =>
      match mo with
      | none => other 1 "db"
      | some mo =>
        { kind := .memRead mo.baseX64 (finalDisp mo ip total)
          text := s!"test {ptrSize size} {memText mo ip total},{regNameOf size reg}"
          len := total }
  | 0x86 | 0x87 =>  -- xchg r/m, reg (op0 mem write)
    withModRM 0 fun reg mo total =>
      match mo with
      | none => other 1 "db"
      | some mo =>
        { kind := .memWrite mo.baseX64 (finalDisp mo ip total)
          text := s!"xchg {ptrSize size} {memText mo ip total},{regNameOf size reg}"
          len := total }
  | 0x88 | 0x89 =>  -- mov r/m, reg (write)
    withModRM 0 fun reg mo total =>
      match mo with
      | none => other 1 "db"
      | some mo =>
        { kind := .memWrite mo.baseX64 (finalDisp mo ip total)
          text := s!"mov {ptrSize size} {memText mo ip total},{regNameOf size reg}"
          len := total }
  | 0x8A | 0x8B =>  -- mov reg, r/m (read)
    withModRM 0 fun reg mo total =>
      match mo with
      | none => other 1 "db"
      | some mo =>
        { kind := .memRead mo.baseX64 (finalDisp mo ip total)
          text := s!"mov {regNameOf size reg},{ptrSize size} {memText mo ip total}"
          len := total }
  | 0x8D =>  -- lea: Other (memory operand but no access)
    withModRM 0 fun reg mo total =>
      match mo with
      | none => other 1 "db"
      | some mo =>
        { kind := .other
          text := s!"lea {regName64 reg},{memText mo ip total}"
          len := total }
  | 0x80 | 0x83 =>  -- grp1 r/m8 | r/mW, imm8
    withModRM 1 fun reg mo total =>
      match mo with
      | none => other 1 "db"
      | some mo =>
        let imm := bytes.get! (total - 1)
        let mne := grp1Name reg
        let kind :=
          if reg == 7 then InstrKind.memRead mo.baseX64 (finalDisp mo ip total)
          else InstrKind.memWrite mo.baseX64 (finalDisp mo ip total)
        { kind := kind
          text := s!"{mne} {ptrSize size} {memText mo ip total},{fmtNum imm.toUInt64}"
          len := total }
  | 0x81 =>  -- grp1 r/mW, imm32
    withModRM 4 fun reg mo total =>
      match mo with
      | none => other 1 "db"
      | some mo =>
        let imm := readU32leAt bytes (total - 4)
        let mne := grp1Name reg
        let kind :=
          if reg == 7 then InstrKind.memRead mo.baseX64 (finalDisp mo ip total)
          else InstrKind.memWrite mo.baseX64 (finalDisp mo ip total)
        { kind := kind
          text := s!"{mne} {ptrSize size} {memText mo ip total},{fmtNum imm.toUInt64}"
          len := total }
  | 0xC6 | 0xC7 =>  -- mov r/m, imm
    withModRM (if op == 0xC6 then 1 else 4) fun _reg mo total =>
      match mo with
      | none => other 1 "db"
      | some mo =>
        let imm :=
          if op == 0xC6 then (bytes.get! (total - 1)).toUInt64
          else (readU32leAt bytes (total - 4)).toUInt64
        { kind := .memWrite mo.baseX64 (finalDisp mo ip total)
          text := s!"mov {ptrSize size} {memText mo ip total},{fmtNum imm}"
          len := total }
  | 0xF6 | 0xF7 =>  -- grp3
    let immLen := if op == 0xF6 then 1 else 4
    withModRM immLen fun reg mo total =>
      match mo with
      | none => other 1 "db"
      | some mo =>
        let mne := grp3Name reg
        let isTest := reg == 0 || reg == 1
        let kind :=
          if isTest then InstrKind.memRead mo.baseX64 (finalDisp mo ip total)
          else InstrKind.memWrite mo.baseX64 (finalDisp mo ip total)
        let suffix :=
          if isTest then
            "," ++ fmtNum (if op == 0xF6 then (bytes.get! (total - 1)).toUInt64
                           else (readU32leAt bytes (total - 4)).toUInt64)
          else ""
        { kind := kind
          text := s!"{mne} {ptrSize size} {memText mo ip total}{suffix}"
          len := total }
  | 0xFE =>  -- inc/dec r/m8
    withModRM 0 fun reg mo total =>
      match mo with
      | none => other 1 "db"
      | some mo =>
        { kind := .memWrite mo.baseX64 (finalDisp mo ip total)
          text := s!"{if reg == 0 then "inc" else "dec"} byte ptr {memText mo ip total}"
          len := total }
  | 0xFF =>
    withModRM 0 fun reg mo total =>
      let toMemKind :=
        match mo with
        | none => none
        | some mo => some (mo, finalDisp mo ip total)
      match reg with
      | 2 => { kind := .indirectCall, text := "call", len := total }
      | 4 => { kind := .indirectJump, text := "jmp", len := total }
      | 0 | 1 =>
        match toMemKind with
        | none => other 1 "db"
        | some (mo, d) =>
          { kind := .memWrite mo.baseX64 d
            text := s!"{if reg == 0 then "inc" else "dec"} qword ptr {memText mo ip total}"
            len := total }
      | 6 =>
        match toMemKind with
        | none => other 1 "db"
        | some (mo, d) =>
          { kind := .memWrite mo.baseX64 d
            text := s!"push qword ptr {memText mo ip total}"
            len := total }
      | _ => other 1 "db"
  | 0xA0 | 0xA1 =>  -- mov al/rax, [absolute]
    if plen + 9 ≤ bytes.size then
      let a := readU64leAt bytes (plen + 1)
      let sz := if op == 0xA0 then 1 else 8
      { kind := .memRead none (Int.ofNat a.toNat)
        text := s!"mov {if sz == 1 then "al" else "rax"},{ptrSize sz} [{fmtNum a}]"
        len := plen + 9 }
    else other 1 "db"
  | 0xA2 | 0xA3 =>  -- mov [absolute], al/rax
    if plen + 9 ≤ bytes.size then
      let a := readU64leAt bytes (plen + 1)
      let sz := if op == 0xA2 then 1 else 8
      { kind := .memWrite none (Int.ofNat a.toNat)
        text := s!"mov {ptrSize sz} [{fmtNum a}],{if sz == 1 then "al" else "rax"}"
        len := plen + 9 }
    else other 1 "db"
  | 0x0F =>
    if plen + 1 ≥ bytes.size then other 1 "db"
    else
      let op2 := bytes.get! (plen + 1)
      match op2 with
      | 0x0B => { kind := .ud2, text := "ud2", len := plen + 2 }
      | 0x05 => other 2 "syscall"
      | 0xB6 | 0xBE =>  -- movzx/movsx r, r/m8
        withModRM2 (plen + 2) fun reg mo total =>
          match mo with
          | none => other 2 "db"
          | some mo =>
            let mne := if op2 == 0xB6 then "movzx" else "movsx"
            { kind := .memRead mo.baseX64 (finalDisp mo ip total)
              text := s!"{mne} {regName64 reg},byte ptr {memText mo ip total}"
              len := total }
      | 0xB7 | 0xBF =>  -- movzx/movsx r, r/m16
        withModRM2 (plen + 2) fun reg mo total =>
          match mo with
          | none => other 2 "db"
          | some mo =>
            let mne := if op2 == 0xB7 then "movzx" else "movsx"
            { kind := .memRead mo.baseX64 (finalDisp mo ip total)
              text := s!"{mne} {regName64 reg},word ptr {memText mo ip total}"
              len := total }
      | 0xAF =>  -- imul r, r/m
        withModRM2 (plen + 2) fun reg mo total =>
          match mo with
          | none => other 2 "db"
          | some mo =>
            { kind := .memRead mo.baseX64 (finalDisp mo ip total)
              text := s!"imul {regName64 reg},{ptrSize size} {memText mo ip total}"
              len := total }
      | _ => other 2 "db"
  | _ => other 1 "db"
where
  withModRM2 (opPos : Nat) (f : Nat → Option MemOp → Nat → Decoded) : Decoded :=
    match decodeModRM bytes opPos rexR rexX rexB with
    | none => { kind := .other, text := "db", len := plen + 2 }
    | some (reg, mo, memLen) => f reg mo (opPos + memLen)

/-- Decode the first instruction at `ip` (up to 64 bytes from the space,
    tail-truncated at region end, as in disasm.rs decode_window). -/
def decodeFirst (space : FastSpace) (ip : VA) : Option Instruction :=
  let bytes := match space.regionAt ip with
    | none => none
    | some r =>
      let off := ip.toNat - r.vaStart.toNat
      some (r.data.extract off (min (off + 64) r.data.size))
  match bytes with
  | none => none
  | some bytes =>
    if bytes.size == 0 then none
    else
      -- prefixes: REX (40-4F), 66, 67, segment, F0/F2/F3
      let rec pre (i : Nat) (rexW rexR rexX rexB : Bool) : Nat × Bool × Bool × Bool × Bool :=
        if i < bytes.size then
          let b := bytes.get! i
          if b ≥ 0x40 && b ≤ 0x4F then
            pre (i + 1) (b &&& 8 != 0) (b &&& 4 != 0) (b &&& 2 != 0) (b &&& 1 != 0)
          else if b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3
              || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65 then
            pre (i + 1) rexW rexR rexX rexB
          else (i, rexW, rexR, rexX, rexB)
        else (i, rexW, rexR, rexX, rexB)
      let (plen, rexW, rexR, rexX, rexB) := pre 0 false false false false
      if plen ≥ bytes.size then none
      else
        let d := decodeOpcode bytes plen ip rexW rexR rexX rexB
        some { va := ip, text := d.text, kind := d.kind, len := d.len }

end Forensicator.Util

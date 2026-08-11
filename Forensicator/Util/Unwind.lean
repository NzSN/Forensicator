/- Forensicator.Util.Unwind — x64 unwind-info stack walking via .pdata
   RUNTIME_FUNCTION records (unwind.rs port). Reads through the AddressSpace,
   so it works identically for full dumps and image-backed stack minidumps. -/
import Forensicator.Model.Dump
import Forensicator.Spec.AddressSpace
import Forensicator.Util.Bytes

namespace Forensicator.Util

open Forensicator.Model Forensicator.Spec

private def UNW_FLAG_CHAININFO : UInt8 := 4

/-- UNWIND_INFO register numbers → x64 CONTEXT indices. -/
private def uwregMap (i : Nat) : Nat :=
  [X64.RAX, X64.RCX, X64.RDX, X64.RBX, X64.RSP, X64.RBP, X64.RSI, X64.RDI,
   X64.R8, X64.R9, X64.R10, X64.R11, X64.R12, X64.R13, X64.R14, X64.R15].getD i 0

structure RuntimeFunction where
  begin : UInt32
  stop : UInt32
  unwindInfo : UInt32
  deriving Inhabited

/-- Parsed .pdata for one module (empty when it has none). -/
structure ModuleUnwind where
  funcs : Array RuntimeFunction

/-- Lazily parsed .pdata tables, keyed by module base. -/
structure UnwindTables where
  modules : List (UInt64 × Option ModuleUnwind)
  ranges : List (VA × UInt64)

def UnwindTables.new (modules : List Module) : UnwindTables :=
  { modules := [], ranges := modules.map fun m => (m.baseVa, m.size) }

private def readU32S (space : AddressSpace) (va : VA) : Option UInt32 :=
  (space.read va 4).map fun b => readU32leAt b 0

private def readU16S (space : AddressSpace) (va : VA) : Option UInt16 :=
  (space.read va 2).map fun b => readU16leAt b 0

private def readU64S (space : AddressSpace) (va : VA) : Option UInt64 :=
  (space.read va 8).map fun b => readU64leAt b 0

/-- Parse a module's exception data directory through the AddressSpace. -/
private def parsePdata (space : AddressSpace) (base : VA) : Option ModuleUnwind := do
  if space.read base 2 != some (ByteArray.mk #[0x4D, 0x5A]) then none else
  let peOff ← readU32S space (base + 0x3C)
  if space.read (base + peOff.toUInt64) 4 != some (ByteArray.mk #[0x50, 0x45, 0, 0]) then none else
  let opt := base + peOff.toUInt64 + 24
  let magic ← readU16S space opt
  if magic != 0x20B then none else
  let dir := opt + 112 + 24
  let pdataRva ← readU32S space dir
  let pdataSize ← readU32S space (dir + 4)
  if pdataRva == 0 || pdataSize == 0 then none else
  let count := pdataSize.toNat / 12
  let pdataVa := base + pdataRva.toUInt64
  -- read in 4096-record chunks
  let rec go (done : Nat) (acc : Array RuntimeFunction) : Array RuntimeFunction :=
    if done < count then
      let n := min (count - done) 4096
      match space.read (pdataVa + UInt64.ofNat (12 * done)) (12 * n) with
      | none => acc
      | some bytes =>
        let rec chunk (i : Nat) (acc : Array RuntimeFunction) : Array RuntimeFunction :=
          if i + 12 ≤ bytes.size then
            let rf : RuntimeFunction :=
              { begin := readU32leAt bytes i, stop := readU32leAt bytes (i + 4)
                unwindInfo := readU32leAt bytes (i + 8) }
            chunk (i + 12) (acc.push rf)
          else acc
        termination_by bytes.size + 12 - i
        go (done + n) (chunk 0 acc)
    else acc
  termination_by count + 1 - done
  some ⟨go 0 #[]⟩

/-- Find the RUNTIME_FUNCTION covering `va`, parsing on first use. -/
def UnwindTables.lookup (t : UnwindTables) (space : AddressSpace) (va : VA) :
    Option (VA × RuntimeFunction) × UnwindTables :=
  match t.ranges.find? fun (b, s) => decide (b ≤ va ∧ va.toNat < b.toNat + s.toNat) with
  | none => (none, t)
  | some (base, _) =>
    let (mu, modules') :=
      match t.modules.find? (·.1 == base) with
      | some (found) => (found.2, t.modules)
      | none =>
        let parsed := parsePdata space base
        (parsed, (base, parsed) :: t.modules)
    match mu with
    | none => (none, { t with modules := modules' })
    | some mu =>
      let rva := (va - base).toUInt32
      -- binary search by begin/end
      let rec bin (fuel lo hi : Nat) : Option RuntimeFunction :=
        match fuel with
        | 0 => none
        | fuel + 1 =>
          if lo < hi then
            let mid := (lo + hi) / 2
            let f := mu.funcs[mid]!
            if rva < f.begin then bin fuel lo mid
            else if rva ≥ f.stop then bin fuel (mid + 1) hi
            else some f
          else none
      ((bin (mu.funcs.size + 1) 0 mu.funcs.size).map (base, ·), { t with modules := modules' })

/-- One unwind step: simulate prolog unwind codes + return-address pop.
    Functional: returns the updated register set, none on failure. -/
def unwindStep (regs : RegisterSet) (space : AddressSpace) (moduleBase : VA)
    (rt : RuntimeFunction) : Option RegisterSet := do
  let rec loop (cur : RuntimeFunction) (regs : RegisterSet) (fuel : Nat) : Option RegisterSet :=
    match fuel with
    | 0 => none
    | fuel + 1 =>
    let hdrVa := moduleBase + cur.unwindInfo.toUInt64
    match space.read hdrVa 4 with
    | none => none
    | some hdr =>
      let versionFlags := hdr.get! 0
      let flags := versionFlags >>> 3
      let sizeOfProlog := (hdr.get! 1).toNat
      let count := (hdr.get! 2).toNat
      let frameReg := (hdr.get! 3) &&& 0xF
      let frameOffScaled := (hdr.get! 3) >>> 4
      let ripOff := regs.rip - moduleBase
      let pcInProlog :=
        if ripOff ≥ cur.begin.toUInt64 then
          (ripOff - cur.begin.toUInt64).toNat < sizeOfProlog
        else false
      let pcOffset := (ripOff - cur.begin.toUInt64).toNat
      let codesVa := hdrVa + 4
      -- apply unwind codes
      let rec codes (consumed : Nat) (regs : RegisterSet) : Option (RegisterSet × Nat) :=
        if consumed ≥ count then some (regs, consumed)
        else
          match space.read (codesVa + UInt64.ofNat (2 * consumed)) 2 with
          | none => none
          | some cb =>
            let codeOff := (cb.get! 0).toNat
            let op := (cb.get! 1) &&& 0xF
            let info := ((cb.get! 1) >>> 4).toNat
            if pcInProlog && codeOff > pcOffset then codes (consumed + 1) regs
            else
              let slot (slotIdx : Nat) : Option UInt32 :=
                (space.read (codesVa + UInt64.ofNat (2 * slotIdx)) 2).map fun b =>
                  (readU16leAt b 0).toUInt32
              let rsp := regs.rsp
              match op with
              | 0 =>  -- PUSH_NONVOL
                match readU64S space rsp with
                | none => none
                | some v =>
                  codes (consumed + 1) ((regs.set (uwregMap info) v).set X64.RSP (rsp + 8))
              | 1 =>  -- ALLOC_LARGE
                if info == 0 then
                  match slot (consumed + 1) with
                  | none => none
                  | some n => codes (consumed + 2) (regs.set X64.RSP (rsp + 8 * n.toUInt64))
                else
                  match slot (consumed + 1), slot (consumed + 2) with
                  | some lo, some hi =>
                    codes (consumed + 3)
                      (regs.set X64.RSP (rsp + (lo ||| (hi <<< 16)).toUInt64))
                  | _, _ => none
              | 2 =>  -- ALLOC_SMALL
                codes (consumed + 1) (regs.set X64.RSP (rsp + 8 * (UInt64.ofNat info + 1)))
              | 3 =>  -- SET_FPREG
                let frame := regs.get (uwregMap frameReg.toNat)
                codes (consumed + 1)
                  (regs.set X64.RSP (frame - 16 * frameOffScaled.toUInt64))
              | 4 =>  -- SAVE_NONVOL
                match slot (consumed + 1) with
                | none => none
                | some n =>
                  match readU64S space (rsp + 8 * n.toUInt64) with
                  | none => none
                  | some v => codes (consumed + 2) (regs.set (uwregMap info) v)
              | 5 =>  -- SAVE_NONVOL_FAR
                match slot (consumed + 1), slot (consumed + 2) with
                | some lo, some hi =>
                  match readU64S space (rsp + (lo ||| (hi <<< 16)).toUInt64) with
                  | none => none
                  | some v => codes (consumed + 3) (regs.set (uwregMap info) v)
                | _, _ => none
              | 6 => codes (consumed + 2) regs  -- EPILOG
              | 7 => codes (consumed + 1) regs  -- SPARE
              | 8 => codes (consumed + 2) regs  -- SAVE_XMM128
              | 9 => codes (consumed + 3) regs  -- SAVE_XMM128_FAR
              | 10 =>  -- PUSH_MACHFRAME
                codes (consumed + 1)
                  (regs.set X64.RSP (rsp + if info == 1 then 0x30 else 0x28))
              | _ => none
        termination_by count + 1 - consumed
      match codes 0 regs with
      | none => none
      | some (regs', _consumed') =>
        if flags &&& UNW_FLAG_CHAININFO != 0 then
          let slotCount := (count + 1) / 2 * 2
          let chainedVa := codesVa + UInt64.ofNat (2 * slotCount)
          match space.read chainedVa 12 with
          | none => none
          | some b =>
            loop { begin := readU32leAt b 0, stop := readU32leAt b 4
                   unwindInfo := readU32leAt b 8 } regs' fuel
        else
          -- standard return-address pop
          match readU64S space regs'.rsp with
          | none => none
          | some ret =>
            some ((regs'.set X64.RIP ret).set X64.RSP (regs'.rsp + 8))
  loop rt regs 64

end Forensicator.Util

/- Forensicator.Util.V8Obj — shared V8 cage-aware object-walking helpers.
    Extracted from Analyzer/V8.lean so that V8.lean (stack walking) and
    Jit.lean (type-feedback recovery) share the same decompress / instanceType
    / readV8String / smi primitives. No behavior change to V8.lean. -/
import Forensicator.Spec.AddressSpace
import Forensicator.Util.V8Layout
import Forensicator.Util.Bytes
import Forensicator.Util.Text

namespace Forensicator.Util

open Forensicator.Model Forensicator.Spec

/-- Read a little-endian u64 at `va`, defaulting to 0 on miss. -/
def readU64 (space : AddressSpace) (va : VA) : UInt64 :=
  (space.read va 8).map (readU64leAt · 0) |>.getD 0

/-- Read a little-endian u32 at `va`, or `none` on miss. -/
def readU32o (space : AddressSpace) (va : VA) : Option UInt32 :=
  (space.read va 4).map (readU32leAt · 0)

/-- Read a little-endian u64 at `va`, or `none` on miss. -/
def readU64o (space : AddressSpace) (va : VA) : Option UInt64 :=
  (space.read va 8).map (readU64leAt · 0)

/-- Wrapping address + signed offset (Rust wrapping_add_signed). -/
def wadd (va : VA) (off : Int) : VA :=
  UInt64.ofNat ((Int.ofNat va.toNat + off).emod (2 ^ 64)).toNat

/-- Decompress a 32-bit V8 tagged pointer relative to `cage`.
    Returns `none` for Smi (bit 0 = 0) or null. -/
def decompress (cage : VA) (compressed : UInt32) : Option VA :=
  if compressed == 0 || compressed &&& 1 == 0 then none
  else some (cage + (compressed &&& 0xFFFFFFFE).toUInt64)

/-- Decode a 32-bit V8 Smi to its signed integer value, or `none` if not a Smi. -/
def smi (raw : UInt32) : Option Int :=
  if raw &&& 1 != 0 then none
  else some (Int.ofNat (raw >>> 1).toNat)

/-- Read the instance_type (u16 LE at Map+8) of a heap object at `heap`.
    Walks: heap → compressed map ptr → decompress → Map+8 = instance_type. -/
def instanceType (space : AddressSpace) (cage heap : VA) : Option UInt16 := do
  let mapC ← readU32o space heap
  let map ← decompress cage mapC
  (space.read (map + 8) 2).map (readU16leAt · 0)

/-- Read an inline V8 String (SeqOneByte / SeqTwoByte / internalized).
    `itype` is the string object's instance type (must be < stringItypeMax). -/
def readV8String (space : AddressSpace) (va : VA) (itype : UInt16)
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

end Forensicator.Util

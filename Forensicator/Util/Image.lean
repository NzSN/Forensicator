/- Forensicator.Util.Image — PE image backing (image.rs port): supplements
   dump memory with bytes from on-disk module images, so .pdata/.text are
   reachable by VA in stack-only minidumps. -/
import Forensicator.Util.Bytes
import Forensicator.Basic
import Forensicator.Util.Text

namespace Forensicator.Util

/-- A PE section's VA→file mapping. -/
structure Section where
  vaSize : UInt32
  vaStart : UInt32
  rawSize : UInt32
  rawPtr : UInt32

/-- A single module image mapped at `baseVa` in the dumped process. -/
structure ImageFile where
  baseVa : VA
  sizeOfImage : UInt64
  data : ByteArray
  headerSize : UInt32
  sections : List Section

namespace ImageFile

private def orErr (o : Option α) (msg : String) : Except String α :=
  match o with | some v => .ok v | none => .error msg

private def r16 (d : ByteArray) (off : Nat) : Option UInt16 :=
  if off + 2 ≤ d.size then some (readU16leAt d off) else none
private def r32 (d : ByteArray) (off : Nat) : Option UInt32 :=
  if off + 4 ≤ d.size then some (readU32leAt d off) else none

/-- Parse a PE image, associating it with the dump's load base. -/
def fromBytes (data : ByteArray) (baseVa : VA) : Except String ImageFile := do
  if data.size < 0x40 || data.extract 0 2 != ByteArray.mk #[0x4D, 0x5A] then
    throw "not a PE (MZ missing)"
  let peOff ← orErr (r32 data 0x3C) "truncated PE"
  if data.extract peOff.toNat (peOff.toNat + 4) != ByteArray.mk #[0x50, 0x45, 0, 0] then
    throw "not a PE (signature missing)"
  let coff := peOff.toNat + 4
  let numSections ← orErr (r16 data (coff + 2)) "truncated PE"
  let optSize ← orErr (r16 data (coff + 16)) "truncated PE"
  let opt := coff + 20
  let magic ← orErr (r16 data opt) "truncated PE"
  if magic != 0x20B then throw "not a PE32+ image"
  let sizeOfImage ← orErr (r32 data (opt + 56)) "truncated PE"
  let headerSize ← orErr (r32 data (opt + 60)) "truncated PE"
  let secOff := opt + optSize.toNat
  let rec go (i : Nat) (acc : List Section) : Except String (List Section) :=
    if i < numSections.toNat then
      let s0 := secOff + i * 40
      if s0 + 40 > data.size then throw "truncated section table"
      else
        match r32 data (s0 + 8), r32 data (s0 + 12), r32 data (s0 + 16), r32 data (s0 + 20) with
        | some vaSize, some vaStart, some rawSize, some rawPtr =>
          go (i + 1) (acc ++ [{ vaSize := vaSize, vaStart := vaStart
                                rawSize := rawSize, rawPtr := rawPtr }])
        | _, _, _, _ => throw "truncated section table"
    else pure acc
  termination_by numSections.toNat + 1 - i
  let sections ← go 0 []
  pure { baseVa := baseVa, sizeOfImage := sizeOfImage.toUInt64
         data := data, headerSize := headerSize, sections := sections }

private def optOff (img : ImageFile) : Nat :=
  ((r32 img.data 0x3C).getD 0).toNat + 4 + 20

/-- PE optional-header CheckSum. -/
def peChecksum (img : ImageFile) : Option UInt32 :=
  r32 img.data (optOff img + 64)

private def rvaToOff (img : ImageFile) (rva : UInt32) : Option Nat :=
  if rva.toNat < img.headerSize.toNat then some rva.toNat
  else
    (img.sections.find? fun (s : Section) =>
      let span := max s.vaSize s.rawSize
      decide (s.vaStart ≤ rva ∧ rva.toNat < s.vaStart.toNat + span.toNat)).map
      fun (s : Section) => (s.rawPtr + (rva - s.vaStart)).toNat

/-- RSDS record from the PE debug directory. -/
structure Rsds where
  guid : ByteArray   -- 16 bytes
  age : UInt32
  pdbPath : String

/-- RSDS record from the debug directory, if present. -/
def rsds (img : ImageFile) : Option Rsds := do
  let opt := optOff img
  let dirRva ← r32 img.data (opt + 112 + 6 * 8)
  let dirSize ← r32 img.data (opt + 112 + 6 * 8 + 4)
  if dirRva == 0 then none
  else
    let dirOff ← rvaToOff img dirRva
    let rec scan (i : Nat) : Option Rsds :=
      if i < dirSize.toNat / 28 then
        let e := dirOff + i * 28
        match r32 img.data (e + 12) with
        | some 2 =>
          (match r32 img.data (e + 24) with
          | none => none
          | some raw =>
            let cv := img.data.extract raw.toNat (raw.toNat + 24)
            if cv.size < 24 || cv.extract 0 4 != ByteArray.mk #[0x52, 0x53, 0x44, 0x53] then none
            else
              let guid := cv.extract 4 20
              let age := readU32leAt cv 20
              let rest := img.data.extract (raw.toNat + 24) img.data.size
              let nul := (rest.toList.takeWhile (· != 0)).length
              some { guid := guid, age := age
                     pdbPath := fromUTF8Lossy (rest.extract 0 nul) })
        | _ => scan (i + 1)
      else none
    termination_by dirSize.toNat / 28 + 1 - i
    scan 0

/-- Read `len` bytes at `va` through the section table (full slice or none). -/
def read (img : ImageFile) (va : VA) (len : Nat) : Option ByteArray :=
  if va < img.baseVa then none
  else
    let rva := (va - img.baseVa).toUInt32
    match rvaToOff img rva with
    | none => none
    | some off =>
      if off + len ≤ img.data.size then some (img.data.extract off (off + len))
      else none

end ImageFile

/-- All discovered module images, keyed by load base. -/
structure ImageSet where
  images : List ImageFile

namespace ImageSet

def empty : ImageSet := ⟨[]⟩
def len (s : ImageSet) : Nat := s.images.length

def read (s : ImageSet) (va : VA) (len : Nat) : Option ByteArray :=
  s.images.findSome? fun i => i.read va len

end ImageSet

end Forensicator.Util

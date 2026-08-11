/- Forensicator.Util.Pdb — minimal MSF 7.0 reader: just enough to extract a
   PDB's identity (GUID + age) from the information stream (stream 1),
   replacing the `pdb` crate for symbolizer.rs pdb_identity. -/
import Forensicator.Util.Bytes
import Forensicator.Basic

namespace Forensicator.Util

/-- MSF 7.0 container: page size + stream directory location. -/
structure MsfFile where
  data : ByteArray
  pageSize : Nat
  dirBlocksOff : Nat  -- file offset of the stream-directory block list

private def msfU32 (d : ByteArray) (off : Nat) : Option UInt32 :=
  if off + 4 ≤ d.size then some (readU32leAt d off) else none

/-- The 32-byte MSF 7.0 magic. -/
private def msfMagic : ByteArray :=
  "Microsoft C/C++ MSF 7.00".toUTF8
    ++ ByteArray.mk #[0x0D, 0x0A, 0x1A] ++ "DS".toUTF8 ++ ByteArray.mk (Array.replicate 3 0)

private def orErr (o : Option α) (msg : String) : Except String α :=
  match o with | some v => .ok v | none => .error msg

/-- Open an MSF 7.0 file (magic + header). -/
def MsfFile.open (data : ByteArray) : Except String MsfFile := do
  if data.size < 56 || data.extract 0 32 != msfMagic then
    throw "not an MSF 7.0 file"
  let pageSize ← orErr (msfU32 data 32) "truncated MSF header"
  let _dirSize ← orErr (msfU32 data 44) "truncated MSF header"
  let blockMapPage ← orErr (msfU32 data 52) "truncated MSF header"
  pure { data := data, pageSize := pageSize.toNat
         dirBlocksOff := blockMapPage.toNat * pageSize.toNat }

/-- Read stream `idx`'s bytes (empty when absent/out of range). -/
def MsfFile.stream (msf : MsfFile) (idx : Nat) : Option ByteArray := do
  let d := msf.data
  let dirSize ← (msfU32 d 44).map UInt32.toNat
  -- directory pages
  let dirPageCount := (dirSize + msf.pageSize - 1) / msf.pageSize
  let dirPages := (List.range dirPageCount).filterMap fun i =>
    (msfU32 d (msf.dirBlocksOff + 4 * i)).map UInt32.toNat
  if dirPages.length < dirPageCount then none
  else
    let dirBytes := (dirPages.map fun pg =>
      d.extract (pg * msf.pageSize) (pg * msf.pageSize + msf.pageSize))
      |>.foldl (· ++ ·) ByteArray.empty
      |>.extract 0 dirSize
    let numStreams ← (msfU32 dirBytes 0).map UInt32.toNat
    if idx ≥ numStreams then none
    else
      -- sizes array then per-stream block lists
      let rec walk (i off : Nat) : Option Nat :=
        if i ≥ numStreams then none
        else
          match msfU32 dirBytes (4 + 4 * i) with
          | none => none
          | some sz =>
            if sz == 0xFFFFFFFF then
              if i == idx then some off  -- absent → handled by caller as empty
              else walk (i + 1) off
            else
              let blocks := (sz.toNat + msf.pageSize - 1) / msf.pageSize
              if i == idx then some off
              else walk (i + 1) (off + 4 * blocks)
      termination_by numStreams + 1 - i
      match walk 0 (4 + 4 * numStreams) with
      | none => none
      | some blockListOff =>
        let sz ← (msfU32 dirBytes (4 + 4 * idx)).map UInt32.toNat
        if sz == 0xFFFFFFFF then some ByteArray.empty
        else
          let blockCount := (sz + msf.pageSize - 1) / msf.pageSize
          let blocks := (List.range blockCount).filterMap fun i =>
            (msfU32 dirBytes (blockListOff + 4 * i)).map UInt32.toNat
          if blocks.length < blockCount then none
          else
            some ((blocks.map fun pg =>
              d.extract (pg * msf.pageSize) (pg * msf.pageSize + msf.pageSize))
              |>.foldl (· ++ ·) ByteArray.empty
              |>.extract 0 sz)

/-- A PDB's identity: age + 16-byte GUID from the information stream. -/
def pdbIdentity (data : ByteArray) : Except String (UInt32 × ByteArray) := do
  let msf ← MsfFile.open data
  let stream1 ← orErr (msf.stream 1) "no information stream"
  if stream1.size < 28 then throw "truncated PDB information stream"
  let age := readU32leAt stream1 8
  let guid := stream1.extract 12 28
  pure (age, guid)

end Forensicator.Util

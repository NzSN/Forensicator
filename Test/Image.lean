/- On-disk PE backing must not turn unrelated addresses or virtual tails
   into known memory. These fixtures retain real bytes beyond each mapped
   range so that an accidental file-contiguous read is observable. -/
import Forensicator.Model.Execution

namespace Test.Image

open Forensicator Forensicator.Util Forensicator.Spec Forensicator.Model

private def image : ImageFile :=
  { baseVa := 0x10000, sizeOfImage := 0x200
    data := ByteArray.mk #[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    headerSize := 4
    sections := [{ vaStart := 0x100, vaSize := 8, rawSize := 4, rawPtr := 8 }] }

private def check (failures : IO.Ref Nat) (name : String) (ok : Bool) : IO Unit := do
  if ok then IO.println s!"ok    image {name}"
  else
    failures.modify (· + 1)
    IO.println s!"FAIL  image {name}"

def runAll : IO UInt32 := do
  let failures ← IO.mkRef 0
  let check := check failures
  check "header and raw section reads retain the exact bytes"
    ((image.read 0x10000 4).map ByteArray.toList == some ([0, 1, 2, 3] : List UInt8)
      && (image.read 0x10100 4).map ByteArray.toList == some ([8, 9, 10, 11] : List UInt8))
  check "header reads stop at the header boundary"
    ((image.read 0x10002 3).isNone && (image.read 0x10004 1).isNone)
  check "section reads cannot include file bytes beyond the raw backing"
    ((image.read 0x10100 5).isNone && (image.read 0x10103 2).isNone)
  check "virtual zero-fill tails do not become known bytes from the file"
    ((image.read 0x10104 1).isNone && (image.read 0x10107 1).isNone)
  let padded := { image with sections := [{ vaStart := 0x100, vaSize := 2, rawSize := 4, rawPtr := 8 }] }
  check "raw section padding remains readable within SizeOfImage"
    ((padded.read 0x10102 2).map ByteArray.toList == some ([10, 11] : List UInt8))
  let clipped := { image with sizeOfImage := 0x102 }
  check "the whole read must fit the declared image"
    ((clipped.read 0x10100 2).map ByteArray.toList == some ([8, 9] : List UInt8)
      && (clipped.read 0x10101 2).isNone && (clipped.read 0x10102 1).isNone)
  check "addresses before the module and outside its image are unavailable"
    ((image.read 0xFFFF 1).isNone && (image.read 0x10200 1).isNone)
  check "RVA conversion cannot alias the image every 4 GiB"
    ((image.read 0x100010000 2).isNone && (image.read 0x200010100 2).isNone)
  let wrappedRaw := { image with sections := [
    { vaStart := 0x100, vaSize := 8, rawSize := 8, rawPtr := 0xFFFFFFFF }] }
  check "raw file offset addition does not wrap into the file"
    ((wrappedRaw.read 0x10102 2).isNone)
  let truncated := { image with sections := [
    { vaStart := 0x100, vaSize := 8, rawSize := 8, rawPtr := 12 }] }
  check "truncated raw bytes do not produce a partial slice"
    ((truncated.read 0x10100 4).map ByteArray.toList == some ([12, 13, 14, 15] : List UInt8)
      && (truncated.read 0x10100 5).isNone)
  let wide := { image with
    sizeOfImage := 0x100000004
    sections := [{ vaStart := 0xFFFFFFFF, vaSize := 4, rawSize := 4, rawPtr := 8 }] }
  check "an RVA range cannot cross the 32-bit address limit"
    ((wide.read 0x10000FFFF 1).map ByteArray.toList == some ([8] : List UInt8)
      && (wide.read 0x10000FFFF 2).isNone)
  let high := { image with baseVa := 0xFFFFFFFFFFFFFFFE, sizeOfImage := 4 }
  check "VA ranges may end at 2^64 but cannot wrap beyond it"
    ((high.read 0xFFFFFFFFFFFFFFFE 2).map ByteArray.toList == some ([0, 1] : List UInt8)
      && (high.read 0xFFFFFFFFFFFFFFFE 3).isNone)
  let other := { image with baseVa := 0x100010000, data := ByteArray.mk #[42, 43, 44, 45] }
  let images : ImageSet := ⟨[image, other]⟩
  check "an earlier image cannot shadow a real image 4 GiB later"
    ((images.read other.baseVa 2).map ByteArray.toList == some ([42, 43] : List UInt8))
  let space := (AddressSpace.new 1).setBacking ⟨[image]⟩
  check "AddressSpace backing rejects unrelated image aliases"
    ((space.read 0x10000 2).map ByteArray.toList == some ([0, 1] : List UInt8)
      && (space.read 0x100010000 2).isNone)
  let memory : MemoryState := { space }
  check "MemoryState preserves unknown memory at an image alias"
    (match memory.read 0x100010000 2 with | .unknown => true | _ => false)
  check "MemoryState preserves unknown memory at a virtual section tail"
    (match memory.read 0x10104 1 with | .unknown => true | _ => false)
  pure (UInt32.ofNat (← failures.get))

end Test.Image

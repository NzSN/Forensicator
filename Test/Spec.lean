/- Test.Spec — guard runner for foundations. Each `check` prints ok/FAIL;
   `runAll` returns the failure count as exit code. -/
import Forensicator

namespace Test.Spec

open Forensicator Forensicator.Parse Forensicator.Spec

private def mkRegion (va : UInt64) (sz : UInt64) (cls : Forensicator.RegionClass) : AddressRegion :=
  { vaStart := va, size := sz, data := ByteArray.mk (Array.replicate sz.toNat 0),
    protection := 3, state := .Commit, classification := cls }

private def addTo (s : AddressSpace) (r : AddressRegion) : AddressSpace :=
  match s.addRegion r with | .ok s' => s' | .error _ => s

structure Ctx where
  failures : IO.Ref Nat

def check (ctx : Ctx) (name : String) (ok : Bool) : IO Unit := do
  if ok then IO.println s!"ok    {name}"
  else do
    ctx.failures.modify (· + 1)
    IO.println s!"FAIL  {name}"

def isOk [BEq α] : Except Anomaly α → α → Bool
  | .ok a, b => a == b
  | _, _ => false

def isErr : Except Anomaly α → Bool
  | .error _ => true
  | _ => false

def ba (xs : List UInt8) : ByteArray := ByteArray.mk xs.toArray

def beqBytes (a b : ByteArray) : Bool := a.data == b.data

def runAll : IO UInt32 := do
  let ctx : Ctx := ⟨← IO.mkRef 0⟩

  -- Cursor: LE scalar reads
  let b1 := ba [0x78, 0x56, 0x34, 0x12, 0xEF, 0xBE, 0xAD, 0xDE, 0x01]
  check ctx "readU32le" (isOk (run b1 readU32le) 0x12345678)
  check ctx "readU64le" (isOk (run b1 readU64le) 0xDEADBEEF12345678)
  check ctx "readU16le" (isOk (run b1 readU16le) 0x5678)
  check ctx "readU8" (isOk (run b1 readU8) 0x78)
  check ctx "sequential reads compose"
    (isOk (run b1 (do let a ← readU32le; let b ← readU32le; pure (a, b)))
      (0x12345678, 0xDEADBEEF))

  -- Cursor: truncation is an error, never a panic
  check ctx "truncated readU64le errors" (isErr (run (ba [0x01, 0x02]) readU64le))
  check ctx "empty buffer readU8 errors" (isErr (run (ba []) readU8))
  check ctx "readU64le past exact end errors" (isErr (run b1 (do seek 2; readU64le)))

  -- Cursor: seek / readBytes / peekBytes
  check ctx "seek + readBytes"
    (match run b1 (do seek 4; readBytes 2) with
     | .ok bs => beqBytes bs (ba [0xEF, 0xBE])
     | _ => false)
  check ctx "peek does not advance" (isOk (run b1 (do let _ ← peekBytes 2; readU8)) 0x78)
  check ctx "seek past end errors" (isErr (run b1 (seek 100)))
  check ctx "readBytes exact"
    (match run b1 (readBytes 9) with | .ok bs => beqBytes bs b1 | _ => false)

  -- Position packing (theorem-backed, exercised at boundaries)
  check ctx "pack max" (pack ⟨0xFFFFFFFF, 0xFFFFFFFF⟩ == 0xFFFFFFFFFFFFFFFF)
  check ctx "pack zero" (pack ⟨0, 0⟩ == 0)
  check ctx "unpack∘pack boundary" (unpack (pack ⟨0xFFFFFFFF, 0xFFFFFFFF⟩) == ⟨0xFFFFFFFF, 0xFFFFFFFF⟩)
  check ctx "unpack splits" (unpack 0x0000002A00000007 == ⟨0x2A, 0x7⟩)
  check ctx "pack∘unpack roundtrip" (pack (unpack 0xDEADBEEFCAFEBABE) == 0xDEADBEEFCAFEBABE)

  -- Json rendering
  check ctx "json scalars"
    (Json.render (.obj [("a", .int 42), ("b", .bool true), ("c", .null)])
      == "{\"a\":42,\"b\":true,\"c\":null}")
  check ctx "json nesting"
    (Json.render (.obj [("xs", .arr [.int 1, .str "two"])])
      == "{\"xs\":[1,\"two\"]}")
  check ctx "json escaping"
    (Json.render (.str "a\"b\\c\nd") == "\"a\\\"b\\\\c\\nd\"")
  check ctx "json control char"
    (Json.render (.str (String.ofList [Char.ofNat 0x01])) == "\"\\u0001\"")

  -- AddressSpace (port of space.rs tests)
  let sp0 : AddressSpace := .new 4
  check ctx "space empty classify other"
    (sp0.classify 0 == .Other && sp0.classify 0x7FFF0000 == .Other)
  let sp1 := addTo sp0 (mkRegion 0x1000 0x2000 .Image)
  check ctx "space add and find"
    (match sp1.regionAt 0x1000 with
     | some r => r.vaStart == 0x1000 && r.size == 0x2000 | none => false)
  let sp2 := addTo sp0 (mkRegion 0x1000 0x1000 .Stack)
  check ctx "space regionAt midpoint"
    ((sp2.regionAt 0x1800).isSome && sp2.classify 0x1800 == .Stack)
  let sp3 := addTo sp0 (mkRegion 0 0x1000 .Image)
  check ctx "space boundaries"
    ((sp3.regionAt 0).isSome && (sp3.regionAt 0xFFF).isSome && (sp3.regionAt 0x1000).isNone)
  let sp4 := addTo sp0 (mkRegion 0x1000 100 .Private)
  check ctx "space read within"
    (match sp4.read 0x1000 50 with | some bs => bs.size == 50 | none => false)
  let sp5 := addTo sp0 (mkRegion 0x1000 50 .Private)
  check ctx "space read crossing fails" (sp5.read 0x1000 100 |>.isNone)
  check ctx "space read unmapped fails" (sp0.read 0 8 |>.isNone)
  let spc := addTo (addTo (.new 2) (mkRegion 0 100 .Image)) (mkRegion 0x1000 100 .Stack)
  check ctx "space capacity respected"
    (match spc.addRegion (mkRegion 0x2000 100 .Private) with
     | .error a => a.description == "AddressSpace at capacity" | _ => false)
  let sps := addTo (addTo (addTo sp0 (mkRegion 0x3000 100 .Private))
      (mkRegion 0x1000 100 .Image)) (mkRegion 0x2000 100 .Stack)
  check ctx "space regions remain sorted"
    (sps.regions.map (·.vaStart) == [0x1000, 0x2000, 0x3000])
  check ctx "space gap returns none"
    ((addTo (addTo sp0 (mkRegion 0 100 .Image)) (mkRegion 0x2000 100 .Stack)).regionAt 0x1000).isNone
  check ctx "space one past end none" ((sp2.regionAt 0x2000).isNone)
  let spm := addTo (addTo (addTo (addTo sp0 (mkRegion 0 100 .Image)) (mkRegion 0x1000 100 .Stack))
      (mkRegion 0x2000 100 .Mapped)) (mkRegion 0x3000 100 .Private)
  check ctx "space multiple classifications"
    (spm.classify 0 == .Image && spm.classify 0x1000 == .Stack
      && spm.classify 0x2000 == .Mapped && spm.classify 0x3000 == .Private
      && spm.classify 0x4000 == .Other)
  let rd := addTo sp0 { mkRegion 0x1000 100 .Private with
                        data := ByteArray.mk #[0xAB, 0xCD] ++ ByteArray.mk (Array.replicate 98 0) }
  check ctx "space read at region start"
    (match rd.read 0x1000 2 with
     | some bs => bs.size == 2 && bs.get! 0 == 0xAB && bs.get! 1 == 0xCD | none => false)
  check ctx "space zero-size error"
    (match sp0.addRegion (mkRegion 0 0 .Image) with
     | .error a => a.description == "zero-sized region" | _ => false)
  check ctx "space overlap error"
    (match sp1.addRegion (mkRegion 0x1800 0x1000 .Stack) with
     | .error a => a.description == "overlap" | _ => false)

  let n ← ctx.failures.get
  IO.println (if n == 0 then "== ALL GUARDS PASSED ==" else s!"== {n} FAILURE(S) ==")
  pure n.toUInt32

end Test.Spec

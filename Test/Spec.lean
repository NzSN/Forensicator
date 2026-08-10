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

  -- Trace model (port of model/trace.rs tests)
  let mregion (va : UInt64) (b : UInt8) (n : Nat) : Model.MemoryRegionInfo :=
    { vaStart := va, size := UInt64.ofNat n, data := ByteArray.mk (Array.replicate n b),
      protection := 3, state := .Commit, memType := .Private,
      provenance := { streamType := Model.TTFX_STREAM_TYPE }, regionClass := some .Private }
  let wr (pos : UInt64) (va : UInt64) (ds : List UInt8) : Model.WriteRecord :=
    { pos := pos, va := va, data := ba ds }
  let tr : Model.Trace := {
    initMem := [mregion 0x1000 0xAA 16, mregion 0x2000 0xBB 16]
    writes := [wr 1 0x1004 [0x11, 0x22], wr 2 0x1004 [0x33], wr 3 0x2FF0 [0xCC]]
    threads := [(7, { start := 0, stop := none })]
    frontier := 3 }
  check ctx "trace value_at initial"
    (tr.valueAt 0x1000 0 == some 0xAA && tr.valueAt 0x1004 0 == some 0xAA)
  check ctx "trace value_at ordered writes"
    (tr.valueAt 0x1004 1 == some 0x11 && tr.valueAt 0x1005 1 == some 0x22
      && tr.valueAt 0x1004 2 == some 0x33 && tr.valueAt 0x1005 2 == some 0x22)
  check ctx "trace value_at unmapped + dropped write"
    (tr.valueAt 0x9000 3 == none && tr.valueAt 0x2FF0 3 == none)
  -- SnapshotConsistent: valueAt == naive forward fold (brute force)
  check ctx "trace value_at vs brute force"
    (let vas : List UInt64 := [0x1000, 0x1001, 0x1002, 0x1003, 0x1004, 0x1005, 0x1006, 0x1007]
     let ts : List UInt64 := [0, 1, 2, 3]
     vas.all fun va => ts.all fun t =>
       tr.valueAt va t ==
         (tr.writes.filter (·.pos ≤ t)).foldl
           (fun acc w => if w.va.toNat ≤ va.toNat && va.toNat < w.va.toNat + w.data.size
             then w.byteAt va else acc)
           (some 0xAA))
  check ctx "trace writes_between window"
    ((tr.writesBetween 0x1004 1 0 3).length == 2
      && (tr.writesBetween 0x1004 1 0 1).length == 1
      && (tr.writesBetween 0x1005 1 0 1).length == 1)
  check ctx "trace snapshot cursor bounded"
    ((tr.snapshot 4).isNone && (tr.snapshot 3).isSome)
  let trE : Model.Trace := { tr with events := [
    { pos := 1, kind := .ModuleLoad, address := 0x70000000, name := "app.exe", size := 0x1000,
      provenance := { streamType := Model.TTFX_STREAM_TYPE } },
    { pos := 2, kind := .Exception, code := 0xC0000005, address := 0xDEAD, threadId := 7,
      provenance := { streamType := Model.TTFX_STREAM_TYPE } }] }
  check ctx "trace snapshot materializes memory/modules/exception"
    (match trE.snapshot 2, trE.snapshot 0 with
     | some snap, some snap0 =>
       snap.dump.modules.length == 1
         && snap.dump.modules.head?.map (·.name == "app.exe") == some true
         && snap.dump.exception.map (fun e => e.code == 0xC0000005 && e.threadId == 7) == some true
         && snap.space.read 0x1004 1 == some (ba [0x33])
         && snap0.dump.exception.isNone && snap0.dump.modules.isEmpty
     | _, _ => false)
  let trU : Model.Trace := { tr with events := [
    { pos := 1, kind := .ModuleLoad, address := 0x70000000, name := "app.exe", size := 0x1000,
      provenance := { streamType := Model.TTFX_STREAM_TYPE } },
    { pos := 2, kind := .ModuleUnload, address := 0x70000000,
      provenance := { streamType := Model.TTFX_STREAM_TYPE } }] }
  check ctx "trace module unload removes"
    ((trU.snapshot 1).map (·.dump.modules.length) == some 1
      && (trU.snapshot 2).map (·.dump.modules.length) == some 0)
  check ctx "trace clean snapshot no anomalies"
    ((tr.snapshot 3).map (·.dump.anomalies.isEmpty) == some true)
  let trO : Model.Trace := { tr with events := [
    { pos := 1, kind := .ModuleLoad, address := 0x70000000, name := "m1", size := 0x1000,
      provenance := { streamType := Model.TTFX_STREAM_TYPE } },
    { pos := 2, kind := .ModuleLoad, address := 0x70000800, name := "m2", size := 0x1000,
      provenance := { streamType := Model.TTFX_STREAM_TYPE } }] }
  check ctx "trace overlapping module anomaly"
    (match trO.snapshot 2, trO.snapshot 1 with
     | some snap, some snap1 =>
       snap.dump.modules.length == 2
         && (snap.dump.anomalies.filter (·.description == "overlapping module")).length == 1
         && snap1.dump.anomalies.isEmpty
     | _, _ => false)
  check ctx "trace thread_at"
    (tr.threadAt 7 2 == some { start := 0, stop := none }
      && tr.threadAt 8 2 == none)

  let n ← ctx.failures.get
  IO.println (if n == 0 then "== ALL GUARDS PASSED ==" else s!"== {n} FAILURE(S) ==")
  pure n.toUInt32

end Test.Spec

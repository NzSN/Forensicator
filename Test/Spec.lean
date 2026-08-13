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

def tprov : Provenance := { streamType := Model.TTFX_STREAM_TYPE }

def tregion (va : UInt64) (b : UInt8) (n : Nat) : Model.MemoryRegionInfo :=
  { vaStart := va, size := UInt64.ofNat n, data := ByteArray.mk (Array.replicate n b),
    protection := 3, state := .Commit, memType := .Private,
    provenance := tprov, regionClass := some .Private }

/-- The minimal trace (port of the Rust `minimal_trace()` fixture). -/
def minimalTraceFixture : Model.Trace := {
  initMem := [tregion 0x1000 0xAA 16, tregion 0x2000 0xBB 16]
  writes := [
    { pos := 1, va := 0x1004, data := ba [0x11, 0x22], provenance := tprov },
    { pos := 2, va := 0x1004, data := ba [0x33], provenance := tprov }]
  events := [
    { pos := 1, kind := .ModuleLoad, address := 0x70000000, name := "app.exe", size := 0x1000,
      provenance := tprov },
    { pos := 2, kind := .Exception, code := 0xC0000005, address := 0x1004, threadId := 7,
      provenance := tprov }]
  threads := [(7, { start := 0, stop := none })]
  calls := [
    { threadId := 7, interval := { start := 0, stop := some 2 } },
    { threadId := 7, interval := { start := 0, stop := some 1 } }]
  frontier := 2 }

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

  -- F5: minidump prefix + mutation fuzz over Case/*.dmp fixtures. The
  -- decoder must always *return* (ok or error); a Lean panic/stack overflow
  -- crashes this binary. Skipped when FORENSICATOR_CASE_DIR is unset or
  -- contains no .dmp files (lake build runs without fixtures).
  match (← IO.getEnv "FORENSICATOR_CASE_DIR") with
  | none => IO.println "skip  minidump fuzz (FORENSICATOR_CASE_DIR unset)"
  | some caseDir =>
    let budget : Nat := 4 * 1024 * 1024 * 1024
    let dumps ← try
      System.FilePath.walkDir (System.FilePath.mk caseDir) |>.map (·.toList)
    catch _ =>
      IO.println s!"skip  minidump fuzz (cannot walk {caseDir})"
      pure []
    let dmpFiles := dumps.filter fun p => p.toString.endsWith ".dmp"
    if dmpFiles.isEmpty then
      IO.println s!"skip  minidump fuzz (no *.dmp under {caseDir})"
    else
      let mut fuzzed : Nat := 0
      for p in dmpFiles do
        let data ← IO.FS.readBinFile p
        let fname := (System.FilePath.fileName p).getD p.toString
        -- ~500 prefixes for small dumps; huge dumps (fulldump ≈ 1.2 GB)
        -- get budget-scaled so total decode work stays ~constant per
        -- fixture (each prefix re-decodes its region payloads).
        let n := min 500 (max 1 (budget / data.size))
        let stride := max 1 (data.size / n)
        for k in [:n] do
          let cut := min data.size (k * stride)
          match Minidump.fromBytes (data.extract 0 cut) with
          | .ok _ => pure () | .error _ => pure ()
        let nMut := min 200 (max 1 (budget / data.size))
        for i in [:nMut] do
          let idx := (i * 37 + fname.toList.length) % data.size
          let mutated := data.set! idx ((data.get! idx) ^^^ 0xFF)
          match Minidump.fromBytes mutated with
          | .ok _ => pure () | .error _ => pure ()
        fuzzed := fuzzed + 1
      check ctx s!"minidump fuzz survived {fuzzed} fixture(s)" (fuzzed > 0)

  -- minidump decoder (port of parse/dump.rs tests)
  let le16 (v : Nat) : List UInt8 := [(UInt64.ofNat v).toUInt8, ((UInt64.ofNat v) >>> 8).toUInt8]
  let le32 (v : Nat) : List UInt8 :=
    (List.range 4).map fun i => ((UInt64.ofNat v) >>> (8 * UInt64.ofNat i)).toUInt8
  let le64 (v : UInt64) : List UInt8 :=
    (List.range 8).map fun i => (v >>> (8 * UInt64.ofNat i)).toUInt8
  let buildBuf (size : Nat) (writes : List (Nat × List UInt8)) : ByteArray :=
    ByteArray.mk (writes.foldl (init := Array.replicate size (0 : UInt8)) fun a (off, bs) =>
      bs.zipIdx.foldl (init := a) fun a2 (b, i) => a2.set! (off + i) b)
  let minimalDump := buildBuf 256 [
    (0, le32 0x504D444D), (4, le16 0xA793), (8, le32 1), (12, le32 64),
    (64, le32 7), (68, le32 56), (72, le32 128),
    (128, le16 0), (136, le16 9)]
  check ctx "minidump valid minimal parses"
    (match Minidump.fromBytes minimalDump with
     | .ok d => d.systemInfo.isSome && d.modules.isEmpty && d.anomalies.isEmpty
     | .error _ => false)
  check ctx "minidump bad magic rejected"
    (match Minidump.fromBytes (minimalDump.set! 0 0xFF) with
     | .error _ => true | .ok _ => false)
  check ctx "minidump directory OOB rejected"
    (match Minidump.fromBytes (buildBuf 256 [
      (0, le32 0x504D444D), (4, le16 0xA793), (8, le32 1), (12, le32 0xFFFFFFFF)]) with
     | .error _ => true | .ok _ => false)
  check ctx "minidump too small rejected"
    (match Minidump.fromBytes (ba (List.replicate 10 0)) with
     | .error _ => true | .ok _ => false)
  check ctx "minidump stream OOB message matches Rust format"
    (Minidump.Fatal.render (.streamOutOfBounds 0x07 0x2000 1024 512)
      == "stream 0x00000007 at RVA 8192 size 1024 out of bounds (file len 512)")
  -- V8HE stream ingestion (dump.rs v8heap_stream_lands_in_memory_regions)
  let cageBase : UInt64 := 0x0000010000000000
  let v8heBody :=
    le32 0x45483856 ++ le32 1 ++ le64 cageBase ++ le64 0x0000020000000000
      ++ le32 2 ++ le32 0
      ++ le64 cageBase ++ le64 16 ++ le64 (32 + 2 * 24)
      ++ le64 (cageBase + 0x10000000) ++ le64 8 ++ le64 (32 + 2 * 24 + 16)
      ++ List.replicate 16 0xAA ++ List.replicate 8 0xBB
  let v8heDump := buildBuf (44 + v8heBody.length) [
    (0, le32 0x504D444D), (4, le16 0xA793), (8, le32 1), (12, le32 32),
    (32, le32 0x45483856), (36, le32 v8heBody.length), (40, le32 44),
    (44, v8heBody)]
  check ctx "v8he stream lands in memory regions"
    (match Minidump.fromBytes v8heDump with
     | .error _ => false
     | .ok d =>
       d.memoryRegions.length == 2
        && d.memoryRegions.head?.map (·.vaStart == cageBase) == some true
        && d.memoryRegions.head?.map (·.data.size == 16) == some true
        && (d.memoryRegions.drop 1 |>.head?).map (fun r =>
             r.vaStart == cageBase + 0x10000000
              && r.data == ByteArray.mk (Array.replicate 8 0xBB)) == some true)

  -- disasm (port of disasm.rs tests + the fulldump crash instruction)
  let disasmSpace (code : List UInt8) : Forensicator.Spec.FastSpace :=
    let sp : Forensicator.Spec.AddressSpace := .new 2
    let region : Forensicator.Spec.AddressRegion :=
      { vaStart := 0x1000, size := UInt64.ofNat code.length
        data := ba code, protection := 5, state := .Commit
        classification := .Image }
    let sp := match sp.addRegion region with
      | .ok s => s | .error _ => sp
    Forensicator.Spec.FastSpace.ofSpace sp
  let decode1 (code : List UInt8) : Option Util.Instruction := Util.decodeFirst (disasmSpace code) 0x1000
  check ctx "disasm int3" ((decode1 [0xCC, 0x90]).map (·.kind) == some .int3)
  check ctx "disasm ud2" ((decode1 [0x0F, 0x0B]).map (·.kind) == some .ud2)
  check ctx "disasm mem read with disp"
    ((decode1 [0x48, 0x8B, 0x41, 0x1B]).map (·.kind) == some (Util.InstrKind.memRead (some 2) 0x1B))
  check ctx "disasm mem write"
    ((decode1 [0x48, 0x89, 0x42, 0x10]).map (·.kind) == some (Util.InstrKind.memWrite (some 3) 0x10))
  check ctx "disasm cmp op0 mem is read"
    (match (decode1 [0x48, 0x39, 0x01]).map (·.kind) with
     | some (Util.InstrKind.memRead _ _) => true | _ => false)
  check ctx "disasm call register indirect"
    ((decode1 [0xFF, 0xD0]).map (·.kind) == some .indirectCall)
  check ctx "disasm rip-relative has absolute disp"
    ((decode1 [0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00]).map (·.kind)
      == some (Util.InstrKind.memRead none 0x1017))
  check ctx "disasm fulldump crash instruction text"
    ((decode1 [0x80, 0x7E, 0x08, 0x00]).map (fun i => (i.kind, i.text))
      == some ((Util.InstrKind.memRead (some 4) 8), "cmp byte ptr [rsi+8],0"))

  -- v8 JS-frame resolution (port of v8.rs decodes_js_frame_from_captured_heap)
  let setU32 := fun (o : Nat) (v : UInt32) => (o, (List.range 4).map fun i => ((v.toUInt64 >>> (8 * UInt64.ofNat i)).toUInt8))
  let setU64 := fun (o : Nat) (v : UInt64) => (o, (List.range 8).map fun i => ((v >>> (8 * UInt64.ofNat i)).toUInt8))
  let setBytes := fun (o : Nat) (bs : List UInt8) => (o, bs)
  let cage : UInt64 := 0x100000000
  let mkHeap (va : UInt64) (writes : List (Nat × List UInt8)) : Forensicator.Spec.AddressRegion :=
    { vaStart := va, size := 0x100
      data := buildBuf 0x100 writes
      protection := 3, state := .Commit, classification := .Other }
  let jsSpace0 : AddressSpace := .new 64
  let jsRegions : List Forensicator.Spec.AddressRegion :=
    [ -- RO space: one-byte-string Map at cage+0x100 (itype 0x08 at Map+8)
      { vaStart := cage, size := 0x200, data := buildBuf 0x200 [setU32 0x108 0x08]
        protection := 3, state := .Commit, classification := .Other }
    , mkHeap (cage + 0x40000) [setU32 0 0x101, setU32 16 0x80001, setU32 20 0x180001]
    , mkHeap (cage + 0x80000) [setU32 0 0x101, setU32 12 0xC0001, setU32 20 0x100001]
    , mkHeap (cage + 0xC0000) [setU32 0 0x101, setU32 8 6, setBytes 12 [0x6D, 0x79, 0x46, 0x75, 0x6E, 0x63]]
    , mkHeap (cage + 0x100000) [setU32 0 0x101, setU32 8 0x140001]
    , mkHeap (cage + 0x140000) [setU32 0 0x101, setU32 8 7, setBytes 12 [0x74, 0x65, 0x73, 0x74, 0x2E, 0x6A, 0x73]]
    , -- stack: one JS frame at fp=0x10000 (marker/function/context at fp-24/-16/-8)
      { vaStart := 0xF000, size := 0x2000
        data := buildBuf 0x2000 [
          setU64 (0x10000 - 24 - 0xF000) 3,
          setU64 (0x10000 - 16 - 0xF000) ((cage + 0x40000) ||| 1),
          setU64 (0x10000 - 8 - 0xF000) ((cage + 0x180000) ||| 1)]
        protection := 3, state := .Commit, classification := .Stack } ]
  let jsSpace := jsRegions.foldl (fun sp r =>
    match sp.addRegion r with | .ok s => s | .error _ => sp) jsSpace0
  let jsRegs := (Model.RegisterSet.new.set Model.X64.RBP 0x10000).set Model.X64.RSP 0xFF00
    |>.set Model.X64.RIP 0x7FFA1000
  let jsDump : Model.Dump := {
    modules := [{ name := "test.dll", baseVa := 0x7FFA0000, size := 0x10000
                  checksum := 0, provenance := { streamType := 2 } }]
    threads := [{ id := 1, registers := jsRegs, stackVa := 0xF000, stackSize := 0x2000
                  tebVa := 0, provenance := {} }]
    annotations := [("ver", "41.0.0"), ("v8_isolate_address", "0x1001C0000"),
                    ("v8_ro_space_firstpage_address", "0x100000000")] }
  check ctx "v8 js frame resolution (synthetic heap)"
    (match (Analyzer.V8.analyzer).run jsDump jsSpace |>.custom with
     | cs =>
       match cs.find? (·.1 == "v8_frames") with
       | some (_, .arr (f0 :: _)) =>
         Json.get f0 "js_function_name" == some (Json.str "myFunc")
           && Json.get f0 "script_name" == some (Json.str "test.js")
       | _ => false)

  -- F6: unwind + CONTEXT decode guards (unwind.rs / arch.rs ports).
  -- Fake PE with one RUNTIME_FUNCTION in .pdata at RVA 0x3000 and the
  -- UNWIND_INFO blob at RVA 0x4000, plus a stack region at 0x8000.
  let uwBase : UInt64 := 0x1_0000_0000
  let mkImg (pdata unwind : List UInt8) : ByteArray :=
    buildBuf 0x5000 [
      (0, [0x4D, 0x5A]),
      (0x3C, le32 0x80),
      (0x80, [0x50, 0x45, 0, 0]),
      (0x98, le16 0x20B),
      (0x120, le32 0x3000),
      (0x124, le32 pdata.length),
      (0x3000, pdata),
      (0x4000, unwind)]
  let uwSpace (img stack : ByteArray) : AddressSpace :=
    let s0 : AddressSpace := .new 4
    let r0 : AddressRegion :=
      { vaStart := uwBase, size := UInt64.ofNat img.size, data := img, protection := 5
        state := .Commit, classification := .Image }
    let s1 := match s0.addRegion r0 with
      | .ok s => s | .error _ => s0
    let r1 : AddressRegion :=
      { vaStart := 0x8000, size := UInt64.ofNat stack.size, data := stack, protection := 3
        state := .Commit, classification := .Stack }
    match s1.addRegion r1 with
      | .ok s => s | .error _ => s1
  let mkRegs (rip rsp rbp : UInt64) : Model.RegisterSet :=
    (Model.RegisterSet.new.set Model.X64.RIP rip).set Model.X64.RSP rsp
      |>.set Model.X64.RBP rbp
  let uwRt : Util.RuntimeFunction := { begin := 0x1000, stop := 0x1100, unwindInfo := 0x4000 }
  let uwMod : Model.Module :=
    { name := "m.exe", baseVa := uwBase, size := 0x5000, checksum := 0, provenance := {} }
  let pdata := le32 0x1000 ++ le32 0x1100 ++ le32 0x4000
  check ctx "unwind pdata lookup finds function"
    (match (Util.UnwindTables.lookup (Util.UnwindTables.new [uwMod])
        (uwSpace (mkImg pdata [1, 4, 1, 0]) (buildBuf 0x100 [])) (uwBase + 0x1050)).1 with
     | some (b, f) => b == uwBase && f.begin == 0x1000
     | none => false)
  check ctx "unwind pdata lookup misses outside module"
    ((Util.UnwindTables.lookup (Util.UnwindTables.new [uwMod])
        (uwSpace (mkImg pdata [1, 4, 1, 0]) (buildBuf 0x100 [])) (uwBase + 0x9999)).1.isNone)
  check ctx "unwind push_nonvol + alloc_small"
    (match Util.unwindStep (mkRegs (uwBase + 0x1080) 0x7FE8 0)
        (uwSpace (mkImg pdata [1, 4, 2, 0, 0x02, 0x22, 0x00, 0x30])
          (buildBuf 0x100 [(0, le64 0xBEEF), (8, le64 0x7ABC)]))
        uwBase uwRt with
     | some r' => r'.get Model.X64.RBX == 0xBEEF && r'.get Model.X64.RSP == 0x8010
         && r'.get Model.X64.RIP == 0x7ABC
     | none => false)
  check ctx "unwind set_fpreg + save_nonvol"
    (match Util.unwindStep (mkRegs (uwBase + 0x1080) 0x8060 0x8100)
        (uwSpace (mkImg pdata [1, 8, 5, 0x05, 0x08, 0x64, 0x02, 0x00, 0x06, 0x52,
                                0x03, 0x03, 0x00, 0x50, 0x00, 0x00])
          (buildBuf 0x200 [(0x70, le64 0x5151), (0x100, le64 0x9000), (0x108, le64 0x9999)]))
        uwBase uwRt with
     | some r' => r'.get Model.X64.RSI == 0x5151 && r'.get Model.X64.RBP == 0x9000
         && r'.get Model.X64.RSP == 0x8110 && r'.get Model.X64.RIP == 0x9999
     | none => false)
  check ctx "unwind push_machframe"
    (match Util.unwindStep (mkRegs (uwBase + 0x1080) 0x8000 0)
        (uwSpace (mkImg pdata [1, 4, 1, 0, 0x00, 0x0A, 0x00, 0x00])
          (buildBuf 0x100 [(0x28, le64 0x1234)]))
        uwBase uwRt with
     | some r' => r'.get Model.X64.RSP == 0x8030 && r'.get Model.X64.RIP == 0x1234
     | none => false)
  check ctx "context full decodes rax+rip"
    (match Model.RegisterSet.decodeContext
        (buildBuf 256 [(0x78, le64 0xDEADBEEFCAFEBABE), (0xF8, le64 0x7FFA1000)]) with
     | .ok rs => rs.get Model.X64.RAX == 0xDEADBEEFCAFEBABE && rs.get Model.X64.RIP == 0x7FFA1000
     | .error _ => false)
  check ctx "context truncated returns error"
    (match Model.RegisterSet.decodeContext (buildBuf 16 []) with
     | .error "truncated CONTEXT" => true | _ => false)
  check ctx "context segment regs"
    (match Model.RegisterSet.decodeContext
        (buildBuf 256 [(0x3A, le16 0x2B), (0x3C, le16 0x33)]) with
     | .ok rs => rs.get Model.X64.DS == 0x2B && rs.get Model.X64.ES == 0x33
     | .error _ => false)
  check ctx "context rflags"
    (match Model.RegisterSet.decodeContext (buildBuf 256 [(0x44, le32 0x246)]) with
     | .ok rs => rs.get Model.X64.RFLAGS == 0x246
     | .error _ => false)
  check ctx "context debug regs"
    (match Model.RegisterSet.decodeContext
        (buildBuf 256 [(0x48, le64 0x7FFA0000), (0x70, le64 0x400)]) with
     | .ok rs => rs.get Model.X64.DR0 == 0x7FFA0000 && rs.get Model.X64.DR7 == 0x400
     | .error _ => false)

  let n ← ctx.failures.get
  IO.println (if n == 0 then "== ALL GUARDS PASSED ==" else s!"== {n} FAILURE(S) ==")
  pure n.toUInt32

end Test.Spec

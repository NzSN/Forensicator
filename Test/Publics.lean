/- Test.Publics — guard checks for the W2 publics parser (design
   docs/analyzers/2026-08-27-crash-analysis-fidelity-design.md §W2.2):
   DBI header, S_PUB32 symbol-record walk, RVA mapping and
   Publics.nearest, plus a lazy MsfHandle round trip over the synthetic
   container (same tmp folder + writeBinFile pattern as the msf
   handle checks in Test/Spec.lean). -/
import Forensicator
import Test.MsfFixture

namespace Test.Publics

open Forensicator Forensicator.Util

structure Ctx where
  failures : IO.Ref Nat

def check (ctx : Ctx) (name : String) (ok : Bool) : IO Unit := do
  if ok then IO.println s!"ok    {name}"
  else do
    ctx.failures.modify (· + 1)
    IO.println s!"FAIL  {name}"

def runAll : IO UInt32 := do
  let ctx : Ctx := ⟨← IO.mkRef 0⟩

  let dbi := Test.MsfFixture.dbiHeader
  check ctx "dbi header parses stream indices"
    (match Util.parseDbiHeader dbi with
     | some h =>
       h.age == 7 && h.globalStream == 0xFFFF && h.publicStream == 9
         && h.symRecordStream == 8
     | none => false)
  check ctx "dbi header rejects bad signature"
    (match Util.parseDbiHeader (dbi.set! 0 0) with
     | none => true | some _ => false)
  check ctx "dbi header truncated fails closed"
    (match Util.parseDbiHeader (dbi.extract 0 60) with
     | none => true | some _ => false)

  let sym := Test.MsfFixture.pubSymStream
  let recs := match Util.walkPublicRecords sym with
    | some r => r | none => #[]
  check ctx "public records walk selects S_PUB32, skips others"
    (recs.size == 5
     && recs[0]!.name == "alpha" && recs[0]!.seg == 1 && recs[0]!.off == 0x1000
     && recs[1]!.name == "builtin" && recs[1]!.off == 0x2024
     && recs[2]!.name == "needsPe" && recs[2]!.seg == 2 && recs[2]!.off == 0x50
     && recs[3]!.name == "aaa" && recs[3]!.off == 0x800
     && recs[4]!.name == "pad" && recs[4]!.off == 0x3000)
  check ctx "public records walk fails closed on truncated record"
    (Util.walkPublicRecords (sym.extract 0 (sym.size - 1)) == none)
  check ctx "public records walk fails closed on zero reclen"
    (Util.walkPublicRecords (ByteArray.mk #[0, 0]) == none)
  check ctx "public records walk accepts minimal non-pub record"
    (Util.walkPublicRecords (ByteArray.mk #[2, 0, 0x0E, 0]) == some #[])
  check ctx "public records walk fails closed on unterminated name"
    (Util.walkPublicRecords (ByteArray.mk (Test.MsfFixture.symRec 0x110E
        (Test.MsfFixture.le32 0 ++ Test.MsfFixture.le32 0x10
          ++ Test.MsfFixture.le16 1 ++ "NONUL".toUTF8.toList)).toArray)
      == none)

  let fallback := Util.Publics.ofRecords recs none
  check ctx "publics fallback: seg-1 off == rva, seg-2 dropped, sorted"
    (fallback.entries == #[(0x800, "aaa"), (0x1000, "alpha"),
                           (0x2024, "builtin"), (0x3000, "pad")])
  check ctx "publics nearest exact hit"
    (Util.Publics.nearest fallback 0x2024 == some ("builtin", 0))
  check ctx "publics nearest below with delta"
    (Util.Publics.nearest fallback 0x1004 == some ("alpha", 4))
  check ctx "publics nearest before first entry is none"
    (Util.Publics.nearest fallback 0x7FF == none)
  check ctx "publics nearest past last entry"
    (Util.Publics.nearest fallback 0x4000 == some ("pad", 0x1000))
  check ctx "publics nearest empty table is none"
    (Util.Publics.nearest { entries := #[] } 0x1000 == none)

  let withPe := Util.Publics.ofRecords recs (some #[0x1000, 0x2000])
  check ctx "publics PE section VAs map seg 1 and seg 2"
    (withPe.entries.contains (0x2050, "needsPe")
     && withPe.entries.contains (0x2000, "alpha")
     && Util.Publics.nearest withPe 0x2054 == some ("needsPe", 4))
  let recsOor := recs.push { off := 7, seg := 3, name := "over" }
  let withPe2 := Util.Publics.ofRecords recsOor (some #[0x1000, 0x2000])
  check ctx "publics PE mapping drops out-of-range segment"
    (withPe2.entries.size == 5 && !withPe2.entries.contains (7, "over"))

  -- Lazy handle round trip over the synthetic container (tmp/ gitignored).
  let path := "tmp/msf-publics-test.pdb"
  IO.FS.writeBinFile path Test.MsfFixture.publicsContainer
  match ← Util.MsfHandle.open path with
  | .error _ => check ctx "publics lazy handle: open" false
  | .ok msf =>
    check ctx "publics lazy handle: open" true
    match ← Util.MsfHandle.stream msf 3 with
    | .error _ => check ctx "publics lazy handle: dbi stream" false
    | .ok dbiBytes =>
      check ctx "publics lazy handle: dbi stream" true
      match Util.parseDbiHeader dbiBytes with
      | none => check ctx "publics lazy handle: dbi parse" false
      | some h =>
        check ctx "publics lazy handle: dbi parse"
          (h.symRecordStream == 8 && h.publicStream == 9)
        match ← Util.MsfHandle.stream msf h.symRecordStream.toNat with
        | .error _ => check ctx "publics lazy handle: symrec stream" false
        | .ok symBytes =>
          check ctx "publics lazy handle: symrec stream"
            (symBytes.size == Test.MsfFixture.pubSymStream.size
             && symBytes == Test.MsfFixture.pubSymStream)
          match Util.walkPublicRecords symBytes with
          | none => check ctx "publics lazy handle: walk" false
          | some recsLazy =>
            let pubs := Util.Publics.ofRecords recsLazy none
            check ctx "publics lazy handle: nearest"
              (Util.Publics.nearest pubs 0x1004 == some ("alpha", 4))
            check ctx "publics lazy handle: entry count"
              (pubs.entries.size == 4)
  IO.FS.removeFile path

  let n ← ctx.failures.get
  IO.println (if n == 0 then "== ALL PUBLICS GUARDS PASSED =="
    else s!"== {n} PUBLICS FAILURE(S) ==")
  pure n.toUInt32

end Test.Publics
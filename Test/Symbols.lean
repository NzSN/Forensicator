/- Test.Symbols — guard checks for the W2.3 symbol-context plumbing
   (design docs/analyzers/2026-08-27-crash-analysis-fidelity-design.md
   §W2.3): SymbolsCtx defaults, runPipeline threading, and the
   `--symbols <dir>` loader — PDB selected by pdb_name basename,
   identity verified (age + GUID via pdbIdentity), fail-closed none —
   over the synthetic MSF fixture. -/
import Forensicator
import Test.MsfFixture

namespace Test.Symbols

open Forensicator

structure Ctx where
  failures : IO.Ref Nat

def check (ctx : Ctx) (name : String) (ok : Bool) : IO Unit := do
  if ok then IO.println s!"ok    {name}"
  else do
    ctx.failures.modify (· + 1)
    IO.println s!"FAIL  {name}"

/-- A ctx-ignoring dummy analyzer for the threading checks. -/
def dummy : Analyzer :=
  { name := "dummy"
    run := fun _ctx _input => AnalyzerOutput.new "dummy" }

def runAll : IO UInt32 := do
  let ctx : Ctx := ⟨← IO.mkRef 0⟩

  -- SymbolsCtx defaults to no publics (analyze without --symbols).
  check ctx "symbols ctx defaults to no publics"
    (match ({ } : SymbolsCtx).publics with | none => true | some _ => false)

  -- runPipeline threads the ctx into every analyzer.
  let dump : Model.Dump := { }
  let space : Spec.AddressSpace := .new 64
  let catalog := runPipeline ({ } : SymbolsCtx) [dummy] (Model.AnalysisInput.ofDump dump space) []
  check ctx "runPipeline threads ctx to analyzers"
    (catalog.outputs.length == 1 && catalog.outputs[0]!.pluginName == "dummy")
  let filtered := runPipeline ({ } : SymbolsCtx) [dummy] (Model.AnalysisInput.ofDump dump space) ["nope"]
  check ctx "runPipeline filter still applies with ctx"
    (filtered.outputs.isEmpty)

  -- Publics.symbol formatting (design §W2.4): NAME+0xHEX no-space.
  let symRecs := match Util.walkPublicRecords Test.MsfFixture.pubSymStream with
    | some r => r | none => #[]
  let symPub := Util.Publics.ofRecords symRecs none
  check ctx "publics symbol formats NAME+0xHEX no-space"
    (Util.Publics.symbol symPub 0 0x1004 == some "alpha+0x4")
  check ctx "publics symbol exact hit (delta 0)"
    (Util.Publics.symbol symPub 0x1000 0x3024 == some "builtin+0x0")
  check ctx "publics symbol below first entry is none"
    (Util.Publics.symbol symPub 0 0x400 == none)
  check ctx "publics symbol va before base is none"
    (Util.Publics.symbol symPub 0x1000 0x900 == none)
  check ctx "publics symbol 64-bit rva is none"
    (Util.Publics.symbol symPub 0 (0x1000 + (0x100000000 : UInt64)) == none)


  -- --symbols loader over the synthetic fixture (tmp/ gitignored): the
  -- container's stream 1 carries age 7 + the DEADBEEF GUID.
  let pdbPath := "tmp/electron.pdb"
  IO.FS.writeBinFile pdbPath Test.MsfFixture.publicsContainer
  let guid := ByteArray.mk (Test.MsfFixture.le64 0xDEADBEEF00112233
    ++ Test.MsfFixture.le64 0x445566778899AABB).toArray
  let crashMod : Model.Module :=
    { name := "C:\\app\\electron.exe", baseVa := 0x140000000
      size := 0x1000, codeviewGuid := some guid, codeviewAge := some 7,
      pdbName := some "electron.pdb", provenance := { } }
  let crashDump : Model.Dump :=
    { modules := [crashMod]
      exception := some { code := 0xC0000005, address := 0x140000800,
                          threadId := 1, provenance := { } } }
  match ← Session.loadSymbolsCtxFor (Model.AnalysisInput.ofDump crashDump space) (some "tmp") with
  | ctx2 =>
    check ctx "symbols ctx loads publics from verified PDB"
      (match ctx2.publics with
       | some pubs => pubs.entries.size == 4
           && Util.Publics.nearest pubs 0x1004 == some ("alpha", 4)
       | none => false)
  let noSymbols ← Session.loadSymbolsCtxFor (Model.AnalysisInput.ofDump crashDump space) none
  check ctx "symbols ctx without dir stays none"
    (match noSymbols.publics with | none => true | some _ => false)
  let badDir ← Session.loadSymbolsCtxFor (Model.AnalysisInput.ofDump crashDump space) (some "tmp2-missing")
  check ctx "symbols ctx missing dir stays none"
    (match badDir.publics with | none => true | some _ => false)
  let mismatched : Model.Module := { crashMod with codeviewAge := some 8 }
  let badDump : Model.Dump := { crashDump with modules := [mismatched] }
  let badCtx ← Session.loadSymbolsCtxFor (Model.AnalysisInput.ofDump badDump space) (some "tmp")
  check ctx "symbols ctx identity mismatch is none"
    (match badCtx.publics with | none => true | some _ => false)
  let noinfo : Model.Module := { crashMod with codeviewGuid := none, codeviewAge := none }
  let infoDump : Model.Dump := { crashDump with modules := [noinfo] }
  let infoCtx ← Session.loadSymbolsCtxFor (Model.AnalysisInput.ofDump infoDump space) (some "tmp")
  check ctx "symbols ctx unverifiable module is none"
    (match infoCtx.publics with | none => true | some _ => false)
  IO.FS.removeFile pdbPath

  let n ← ctx.failures.get
  IO.println (if n == 0 then "== ALL SYMBOLS GUARDS PASSED =="
    else s!"== {n} SYMBOLS FAILURE(S) ==")
  pure n.toUInt32

end Test.Symbols

/- Shared forensic reports for the CLI and MCP. The existing JSON shape and
   artifact matching semantics are preserved; no output is written here. -/
import Forensicator.Parse.Minidump
import Forensicator.Analyzer.Registry
import Forensicator.Session

namespace Forensicator.Report

open Model Parse

def osName : OsPlatform → String
  | .Windows => "Windows" | .Linux => "Linux" | .MacOs => "macOS"

def cpuName : CpuArch → String
  | .X86 => "x86" | .X64 => "x64" | .Arm64 => "ARM64"

/-- CodeView RSDS GUID → standard UUID text (model.rs codeview_guid_to_uuid). -/
def codeviewUuid (guid : ByteArray) : String :=
  let b (i : Nat) := guid.get! i
  let d1 : UInt64 := (b 0).toUInt64 ||| ((b 1).toUInt64 <<< 8)
    ||| ((b 2).toUInt64 <<< 16) ||| ((b 3).toUInt64 <<< 24)
  let d2 : UInt64 := (b 4).toUInt64 ||| ((b 5).toUInt64 <<< 8)
  let d3 : UInt64 := (b 6).toUInt64 ||| ((b 7).toUInt64 <<< 8)
  let hi : UInt64 := ((b 8).toUInt64 <<< 8) ||| (b 9).toUInt64
  let lo : UInt64 := ((b 10).toUInt64 <<< 40) ||| ((b 11).toUInt64 <<< 32)
    ||| ((b 12).toUInt64 <<< 24) ||| ((b 13).toUInt64 <<< 16)
    ||| ((b 14).toUInt64 <<< 8) ||| (b 15).toUInt64
  s!"{hexPadLower d1 8}-{hexPadLower d2 4}-{hexPadLower d3 4}-{hexPadLower hi 4}-{hexPadLower lo 12}"

def moduleJson (m : Module) : Json :=
  .obj [("name", .str m.name),
        ("base_va", .str ("0x" ++ hexPadUpper m.baseVa 16)),
        ("size", .ofUInt64 m.size),
        ("checksum", .str ("0x" ++ hexPadUpper m.checksum.toUInt64 8)),
        ("codeview_guid", match m.codeviewGuid with
          | some g => .str (codeviewUuid g) | none => .null),
        ("pdb_name", match m.pdbName with | some p => .str p | none => .null)]

def diagnosisJson (d : Dump) : Json :=
  match d.exception with
  | none => .null
  | some _ =>
    let space := buildAddressSpace d
    let dg := Analyzer.Cause.diagnose (AnalysisInput.ofDump d space) space
    .obj [("verdict", .str dg.verdict.debug),
          ("confidence", .str dg.confidence.debug),
          ("evidence", .arr (dg.evidence.map .str)),
          ("fault_va", match dg.faultVa with | some v => .str (hexUpper v) | none => .null),
          ("fatal_message", match dg.fatalMessage with | some m => .str m | none => .null)]

def inspectJson (d : Dump) : Json :=
  .obj [
    ("file_size", .ofUInt64 d.fileSize),
    ("system_info", match d.systemInfo with
      | some si => .obj [("os", .str (osName si.os)), ("cpu", .str (cpuName si.cpu)),
          ("version", .str s!"{si.version.1}.{si.version.2.1}.{si.version.2.2.1}.{si.version.2.2.2}")]
      | none => .null),
    ("module_count", .ofNat d.modules.length),
    ("modules", .arr (d.modules.map moduleJson)),
    ("thread_count", .ofNat d.threads.length),
    ("memory_regions", .ofNat d.memoryRegions.length),
    ("exception", .bool d.exception.isSome),
    ("diagnosis", diagnosisJson d),
    ("anomaly_count", .ofNat d.anomalies.length),
    ("annotation_count", .ofNat d.annotations.length),
    ("annotations", .arr (d.annotations.map fun (k, v) => .obj [(k, .str v)]))]

def stringsJson (ss : List StructString) : Json :=
  if ss.isEmpty then .null
  else .arr (ss.map fun s => .obj [("va", .str (hexUpper s.va)),
    ("encoding", .str s.encoding.debug), ("content", .str s.content),
    ("confidence", .ofFloat s.confidence)])

def analyzeJson (outputs : List AnalyzerOutput) : Json :=
  let per (o : AnalyzerOutput) : Json := .obj [
    ("name", .str o.pluginName),
    ("count", .ofNat o.count),
    ("strings", stringsJson o.strings),
    ("vtables", if o.vtables.isEmpty then .null else .arr (o.vtables.map fun v =>
      .obj [("va", .str (hexUpper v.va)), ("method_count", .ofNat v.methodCount),
            ("confidence", .ofFloat v.confidence)])),
    ("linked_lists", if o.linkedLists.isEmpty then .null else .arr (o.linkedLists.map fun l =>
      .obj [("head_va", .str (hexUpper l.headVa)), ("length", .ofNat l.length),
            ("stride", .ofUInt64 l.stride)])),
    ("arrays", if o.arrays.isEmpty then .null else .arr (o.arrays.map fun a =>
      .obj [("start_va", .str (hexUpper a.startVa)), ("element_size", .ofUInt64 a.elementSize),
            ("count", .ofNat a.count), ("confidence", .ofFloat a.confidence)])),
    ("chunks", if o.chunks.isEmpty then .null else .arr (o.chunks.map fun c =>
      .obj [("va_start", .str (hexUpper c.vaStart)), ("size", .ofUInt64 c.size),
            ("is_free", .bool c.isFree), ("confidence", .ofFloat c.confidence)])),
    ("shape_clusters", if o.shapeClusters.isEmpty then .null else .arr (o.shapeClusters.map fun g =>
      .obj [("id", .ofNat g.id), ("member_count", .ofNat g.memberCount)])),
    ("custom", if o.custom.isEmpty then .null else .arr (o.custom.map fun (k, v) => .obj [(k, v)]))]
  .obj [("plugins", .arr (outputs.map per))]

def basenameOf (p : String) : String :=
  let parts := p.splitOn "/" |>.flatMap (·.splitOn "\\")
  (parts.filter (!·.isEmpty)).getLast?.getD p

def supplementImages (space : Spec.AddressSpace) (dump : Dump) (path : String) :
    IO (Spec.AddressSpace × Nat) := do
  let dir := (System.FilePath.parent path).map (·.toString) |>.getD "."
  let names := dump.modules.map (·.name)
  let bases := dump.modules.map (·.baseVa)
  let mut images : Util.ImageSet := ⟨[]⟩
  for (name, base) in names.zip bases do
    let fname := basenameOf name
    if fname.isEmpty then continue
    let candidate := dir ++ "/" ++ fname
    if ← System.FilePath.pathExists candidate then
      let bytes ← IO.FS.readBinFile candidate
      match Util.ImageFile.fromBytes bytes base with
      | .ok img => images := ⟨images.images ++ [img]⟩
      | .error _ => pure ()
  let space := if images.images.isEmpty then space else space.setBacking images
  pure (space, images.images.length)

inductive CheckResult where
  | match_ | mismatch | unknown
  deriving BEq, DecidableEq

def CheckResult.asStr : CheckResult → String
  | .match_ => "match" | .mismatch => "mismatch" | .unknown => "unknown"

def CheckResult.upper (c : CheckResult) : String := c.asStr.toUpper

structure Check where
  field : String
  result : CheckResult
  fileValue : String
  dumpValue : String
  note : Option String

structure MatchItem where
  kind : String
  path : String
  modul : Option String
  checks : List Check

def MatchItem.result (i : MatchItem) : CheckResult :=
  if i.modul.isNone || i.checks.any (·.result == .mismatch) then .mismatch
  else if i.checks.any (·.result == .match_) then .match_
  else .unknown

def compareStr (field : String) (dumpSide fileSide : Option String)
    (absentNote : String) : Check :=
  match dumpSide, fileSide with
  | some d, some f =>
    { field := field
      result := if d == f then .match_ else .mismatch
      fileValue := f, dumpValue := d, note := none }
  | none, f =>
    { field := field, result := .unknown
      fileValue := f.getD "-", dumpValue := "-", note := some absentNote }
  | d, none =>
    { field := field, result := .unknown
      fileValue := "-", dumpValue := d.getD "-", note := some "not present in file" }

def eqIgnoreCase (a b : String) : Bool :=
  a.toLower == b.toLower

structure MatchReport where
  items : List MatchItem
  overall : CheckResult

def MatchReport.toJson (report : MatchReport) (sourceLabel : String := "dump") : Json := Id.run do
  let items := report.items
  let overall := report.overall
  let checkJson (c : Check) : Json :=
    .obj [("field", .str c.field), ("result", .str c.result.asStr),
          ("file", .str c.fileValue), (sourceLabel, .str c.dumpValue),
          ("note", match c.note with | some n => .str n | none => .null)]
  let itemJson (i : MatchItem) : Json :=
    .obj [("kind", .str i.kind),
          ("path", .str i.path),
          ("module", match i.modul with | some m => .str m | none => .null),
          ("result", .str i.result.asStr),
          ("checks", .arr (i.checks.map checkJson))]
  let itemsJson := items.map itemJson
  let top : Json := .obj [("items", .arr itemsJson), ("overall", .str overall.asStr)]
  top

def matchModules (modules : List Module) (exes pdbs : List String)
    (sourceLabel : String := "dump") : IO (Except String MatchReport) := do
    let mut items : List MatchItem := []
    for exe in exes do
      let bytes ← IO.FS.readBinFile exe
      match Util.ImageFile.fromBytes bytes 0 with
      | .error e => return .error s!"{exe}: {e}"
      | .ok img =>
        let rsds := img.rsds
        let peChecksum := img.peChecksum
        let want := basenameOf exe
        match modules.find? fun m => eqIgnoreCase (basenameOf m.name) want with
        | none =>
          items := items ++ [{ kind := "exe", path := exe, modul := none, checks := [] }]
        | some module =>
          let guidCheck := compareStr "guid"
            (module.codeviewGuid.map codeviewUuid)
            (rsds.map fun r => codeviewUuid r.guid)
            "module has no RSDS record"
          let ageCheck := compareStr "age"
            (module.codeviewAge.map toString)
            (rsds.map fun r => toString r.age)
            "module has no RSDS record"
          let checksumCheck :=
            if module.checksum != 0 then
              compareStr "checksum" (some (toString module.checksum))
                (peChecksum.map toString) "module has no RSDS record"
            else
              { field := "checksum", result := .unknown
                fileValue := (peChecksum.map fun c => "0x" ++ hexPadUpper c.toUInt64 8).getD "-"
                dumpValue := "-"
                note := some s!"{sourceLabel} module checksum is 0" }
          items := items ++ [{ kind := "exe", path := exe, modul := some module.name
                               checks := [guidCheck, ageCheck, checksumCheck] }]
    for pdb in pdbs do
      let bytes ← IO.FS.readBinFile pdb
      match Util.pdbIdentity bytes with
      | .error e => return .error s!"{pdb}: {e}"
      | .ok (age, guid) =>
        let want := basenameOf pdb
        match modules.find? fun m =>
            (m.pdbName.map (fun n => eqIgnoreCase (basenameOf n) want)).getD false with
        | none =>
          items := items ++ [{ kind := "pdb", path := pdb, modul := none, checks := [] }]
        | some module =>
          let guidCheck := compareStr "guid"
            (module.codeviewGuid.map codeviewUuid)
            (some (codeviewUuid guid))
            "module has no RSDS record"
          let ageCheck := compareStr "age"
            (module.codeviewAge.map toString)
            (some (toString age))
            "module has no RSDS record"
          items := items ++ [{ kind := "pdb", path := pdb, modul := some module.name
                               checks := [guidCheck, ageCheck] }]
    let failed := items.any fun i => i.result == .mismatch
    let overall :=
      if failed then CheckResult.mismatch
      else if items.all (·.result == .unknown) then .unknown
      else .match_
    pure (.ok { items, overall })

end Forensicator.Report

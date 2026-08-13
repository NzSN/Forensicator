/- forensicator (Lean) — CLI. Lean-only since 2026-08-13: the Rust oracle
   is gone and the eager .ttfx v1 trace path is removed; trace sessions
   (proxy) await the Lean client follow-up plan. -/
import Forensicator

open Forensicator Forensicator.Parse Forensicator.Model

private def byteDebug (bs : ByteArray) : String :=
  "[" ++ String.intercalate ", " (bs.toList.map fun b => hexPadUpper b.toUInt64 2) ++ "]"

-- ── inspect ─────────────────────────────────────────────────────────

private def osName : OsPlatform → String
  | .Windows => "Windows" | .Linux => "Linux" | .MacOs => "macOS"

private def cpuName : CpuArch → String
  | .X86 => "x86" | .X64 => "x64" | .Arm64 => "ARM64"

/-- CodeView RSDS GUID → standard UUID text (model.rs codeview_guid_to_uuid). -/
private def codeviewUuid (guid : ByteArray) : String :=
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

private def moduleJson (m : Module) : Json :=
  .obj [("name", .str m.name),
        ("base_va", .str ("0x" ++ hexPadUpper m.baseVa 16)),
        ("size", .ofUInt64 m.size),
        ("checksum", .str ("0x" ++ hexPadUpper m.checksum.toUInt64 8)),
        ("codeview_guid", match m.codeviewGuid with
          | some g => .str (codeviewUuid g) | none => .null),
        ("pdb_name", match m.pdbName with | some p => .str p | none => .null)]

private def diagnosisJson (d : Dump) : Json :=
  match d.exception with
  | none => .null
  | some _ =>
    let space := buildAddressSpace d
    let dg := Analyzer.Cause.diagnose d space
    .obj [("verdict", .str dg.verdict.debug),
          ("confidence", .str dg.confidence.debug),
          ("evidence", .arr (dg.evidence.map .str)),
          ("fault_va", match dg.faultVa with | some v => .str (hexUpper v) | none => .null),
          ("fatal_message", match dg.fatalMessage with | some m => .str m | none => .null)]

private def inspectJson (d : Dump) : Json :=
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

/-- Rust `{:.1}` of `bytes / 1024.0` (round-half-up on tenths). -/
private def kb1 (bytes : UInt64) : String :=
  let tenths := (bytes.toNat * 10 + 512) / 1024
  s!"{tenths / 10}.{tenths % 10}"

private def inspectText (d : Dump) : IO Unit := do
  IO.println s!"Dump ({kb1 d.fileSize} KB)"
  match d.systemInfo with
  | some si =>
    IO.println s!"├── SystemInfo: {cpuName si.cpu} on {osName si.os} v{si.version.1}.{si.version.2.1}.{si.version.2.2.1}.{si.version.2.2.2}"
  | none => IO.println "├── SystemInfo: <missing>"
  IO.println s!"├── Modules: {d.modules.length} loaded"
  for m in d.modules do
    IO.println s!"│   ├── {m.name} @ 0x{hexPadUpper m.baseVa 16} ({kb1 m.size} KB)"
  IO.println s!"├── Threads: {d.threads.length}"
  for t in d.threads do
    IO.println s!"│   ├── TID {t.id}  stack @ 0x{hexPadUpper t.stackVa 16} ({kb1 t.stackSize} KB)  TEB @ 0x{hexPadUpper t.tebVa 16}  RIP 0x{hexPadUpper t.registers.rip 16}"
  IO.println s!"├── Memory regions: {d.memoryRegions.length}"
  if let some exc := d.exception then
    IO.println s!"├── Exception: code 0x{hexPadUpper exc.code.toUInt64 8} at 0x{hexPadUpper exc.address 16} (thread {exc.threadId})"
    let dg := Analyzer.Cause.diagnose d (buildAddressSpace d)
    let detail := match dg.fatalMessage with
      | some m => m
      | none => dg.evidence.head? |>.getD ""
    IO.println s!"├── Diagnosis: {dg.verdict.debug} ({dg.confidence.debug}){if detail.isEmpty then "" else " — " ++ detail}"
  if !d.anomalies.isEmpty then
    IO.println s!"├── Anomalies: {d.anomalies.length}"
    for a in d.anomalies do
      IO.println s!"│   ├── [stream 0x{hexPadUpper a.streamType.toUInt64 8} @ +{hexUpper a.fileOffset}] {a.description}"
  if !d.annotations.isEmpty then
    IO.println s!"└── Crash annotations: {d.annotations.length}"
    for (k, v) in d.annotations do
      IO.println s!"    ├── {k} = {v}"

private def inspectPrint (dump : Dump) (json quiet : Bool) : IO Unit := do
  if json then IO.println (Json.render (inspectJson dump))
  else if quiet then
    IO.println s!"modules: {dump.modules.length}  threads: {dump.threads.length}  memory_regions: {dump.memoryRegions.length}  anomalies: {dump.anomalies.length}"
  else inspectText dump

private def cmdInspect (path : String) (json quiet : Bool) : IO UInt32 := do
  let data ← IO.FS.readBinFile path
  match Minidump.fromBytes data with
  | .error f => IO.eprintln f.render; pure 1
  | .ok dump =>
    inspectPrint dump json quiet
    pure 0

-- ── analyze ─────────────────────────────────────────────────────────

private def stringsJson (ss : List StructString) : Json :=
  if ss.isEmpty then .null
  else .arr (ss.map fun s => .obj [("va", .str (hexUpper s.va)),
    ("encoding", .str s.encoding.debug), ("content", .str s.content),
    ("confidence", .ofFloat s.confidence)])

private def analyzeJson (outputs : List AnalyzerOutput) : Json :=
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

private def basenameOf (p : String) : String :=
  let parts := p.splitOn "/" |>.flatMap (·.splitOn "\\")
  (parts.filter (!·.isEmpty)).getLast?.getD p

private def supplementImages (space : Spec.AddressSpace) (dump : Dump) (path : String) :
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

private def analyzePrint (dump : Dump) (space : Spec.AddressSpace)
    (plugin : Option String) (json : Bool) : IO Unit := do
    let filter := match plugin with
      | none => []
      | some p => (p.splitOn ",").map (String.trimAscii · |>.toString)
    let catalog := runPipeline defaultPipeline dump space filter
    if json then
      IO.println (Json.render (analyzeJson catalog.outputs))
    else
      IO.println "Analysis results:"
      for o in catalog.outputs do
        IO.println s!"  {o.pluginName}: {o.count} results"
        if o.pluginName == "v8" then
          pure ()  -- v8 frame printing lands in Task 9
        else
          if !o.strings.isEmpty then IO.println s!"    strings: {o.strings.length}"
          if !o.vtables.isEmpty then IO.println s!"    vtables: {o.vtables.length}"
          if !o.linkedLists.isEmpty then IO.println s!"    linked_lists: {o.linkedLists.length}"
          if !o.arrays.isEmpty then IO.println s!"    arrays: {o.arrays.length}"
          if !o.chunks.isEmpty then IO.println s!"    chunks: {o.chunks.length}"
          if !o.shapeClusters.isEmpty then
            IO.println s!"    shape_clusters: {o.shapeClusters.length} groups"
          if !o.custom.isEmpty then IO.println s!"    custom: {o.custom.length} entries"
    pure ()

private def cmdAnalyze (path : String) (plugin : Option String) (json : Bool)
    (_symbols : Option String) : IO UInt32 := do
  let data ← IO.FS.readBinFile path
  match Minidump.fromBytes data with
  | .error f => IO.eprintln f.render; pure 1
  | .ok dump =>
    let (space, imageCount) ← supplementImages (buildAddressSpace dump) dump path
    if !json then
      let kind := match classifyDump dump with
        | .FullMemory => "full-memory" | .StackOnly => "stack-only"
      IO.eprintln s!"dump: {kind}, {imageCount} image(s) supplemented"
    analyzePrint dump space plugin json
    pure 0


private def cmdListPlugins : IO UInt32 := do
  IO.println "Available analyzers:"
  for a in defaultPipeline do
    IO.println s!"  {a.name}: {a.description}"
  pure 0

-- ── match ───────────────────────────────────────────────────────────

private inductive CheckResult where
  | match_ | mismatch | unknown
  deriving BEq, DecidableEq

private def CheckResult.asStr : CheckResult → String
  | .match_ => "match" | .mismatch => "mismatch" | .unknown => "unknown"

private def CheckResult.upper (c : CheckResult) : String := c.asStr.toUpper

private structure Check where
  field : String
  result : CheckResult
  fileValue : String
  dumpValue : String
  note : Option String

private structure MatchItem where
  kind : String
  path : String
  modul : Option String
  checks : List Check

private def MatchItem.result (i : MatchItem) : CheckResult :=
  if i.modul.isNone || i.checks.any (·.result == .mismatch) then .mismatch
  else if i.checks.any (·.result == .match_) then .match_
  else .unknown

private def compareStr (field : String) (dumpSide fileSide : Option String)
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

private def eqIgnoreCase (a b : String) : Bool :=
  a.toLower == b.toLower

private def matchRunDump (dump : Dump) (exes pdbs : List String) (json : Bool) : IO UInt32 := do
    let mut items : List MatchItem := []
    for exe in exes do
      let bytes ← IO.FS.readBinFile exe
      match Util.ImageFile.fromBytes bytes 0 with
      | .error e => IO.eprintln s!"{exe}: {e}"; return 1
      | .ok img =>
        let rsds := img.rsds
        let peChecksum := img.peChecksum
        let want := basenameOf exe
        match dump.modules.find? fun m => eqIgnoreCase (basenameOf m.name) want with
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
                note := some "dump module checksum is 0" }
          items := items ++ [{ kind := "exe", path := exe, modul := some module.name
                               checks := [guidCheck, ageCheck, checksumCheck] }]
    for pdb in pdbs do
      let bytes ← IO.FS.readBinFile pdb
      match Util.pdbIdentity bytes with
      | .error e => IO.eprintln s!"{pdb}: {e}"; return 1
      | .ok (age, guid) =>
        let want := basenameOf pdb
        match dump.modules.find? fun m =>
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
    if json then
      let checkJson (c : Check) : Json :=
        .obj [("field", .str c.field), ("result", .str c.result.asStr),
              ("file", .str c.fileValue), ("dump", .str c.dumpValue),
              ("note", match c.note with | some n => .str n | none => .null)]
      let itemJson (i : MatchItem) : Json :=
        .obj [("kind", .str i.kind),
              ("path", .str i.path),
              ("module", match i.modul with | some m => .str m | none => .null),
              ("result", .str i.result.asStr),
              ("checks", .arr (i.checks.map checkJson))]
      let itemsJson := items.map itemJson
      let top : Json := .obj [("items", .arr itemsJson), ("overall", .str overall.asStr)]
      IO.println (Json.render top)
    else
      for i in items do
        match i.modul with
        | some m =>
          IO.println s!"{i.kind.toUpper} {i.path} ↔ module {m}"
          for c in i.checks do
            let note := (c.note.map ("  (" ++ · ++ ")")).getD ""
            IO.println s!"  {(c.field ++ "         ").take 9} {(c.result.upper ++ "         ").take 9} file={c.fileValue}  dump={c.dumpValue}{note}"
        | none =>
          IO.println s!"{i.kind.toUpper} {i.path} ↔ no matching module in dump"
      IO.println s!"overall: {overall.upper}"
    pure (if failed then 2 else 0)


-- ── shell ───────────────────────────────────────────────────────────


private def cmdMatch (path : String) (exes pdbs : List String) (json : Bool) : IO UInt32 := do
  if exes.isEmpty && pdbs.isEmpty then
    IO.eprintln "nothing to match: pass --exe and/or --pdb"
    return 1
  let data ← IO.FS.readBinFile path
  match Minidump.fromBytes data with
  | .error f => IO.eprintln f.render; pure 1
  | .ok dump => matchRunDump dump exes pdbs json


private def shellDispatch (s : Session) (args : List String) : IO (Session × Bool) := do
  match args with
  | "quit" :: _ => pure (s, false)
  | "inspect" :: rest =>
    match s.current with
    | .error e => IO.eprintln s!"error: {e}"
    | .ok (dump, _) =>
      if (match s.target with | .trace _ _ => true | _ => false) then
        match s.target with
        | .trace t cursor => IO.println s!"position {hexUpper cursor} / frontier {hexUpper t.frontier}"
        | _ => pure ()
      inspectPrint dump ("--json" ∈ rest) ("--quiet" ∈ rest)
    pure (s, true)
  | "analyze" :: rest =>
    match s.current with
    | .error e => IO.eprintln s!"error: {e}"
    | .ok (dump, space) =>
      let plugin := match rest.find? (· == "--plugin") with
        | some _ => (rest.dropWhile (· != "--plugin")).drop 1 |>.head?
        | none => none
      let json := "--json" ∈ rest
      if (match s.target with | .trace _ _ => true | _ => false) && !json then
        match s.target with
        | .trace t cursor =>
          IO.eprintln s!"position {hexUpper cursor} / frontier {hexUpper t.frontier}, dump: stack-only"
        | _ => pure ()
      analyzePrint dump space plugin json
    pure (s, true)
  | "match" :: rest =>
    match s.current with
    | .error e => IO.eprintln s!"error: {e}"
    | .ok (dump, _) =>
      let rec collect (xs : List String) (exes pdbs : List String) : List String × List String :=
        match xs with
        | [] => (exes, pdbs)
        | "--exe" :: e :: r => collect r (exes ++ [e]) pdbs
        | "--pdb" :: p :: r => collect r exes (pdbs ++ [p])
        | _ :: r => collect r exes pdbs
      let (exes, pdbs) := collect rest [] []
      let _ ← matchRunDump dump exes pdbs ("--json" ∈ rest)
    pure (s, true)
  | ["list-plugins"] =>
    let _ ← cmdListPlugins
    pure (s, true)
  | "load" :: path :: _ =>
    let s' ← Session.open path s.symbols
    IO.println s!"loaded {s'.banner}"
    pure (s', true)
  | "symbols" :: rest =>
    match rest with
    | [] =>
      IO.println s!"symbols: {s.symbols.getD "<none>"}"
      pure (s, true)
    | ["off"] =>
      IO.println "symbols cleared"
      pure ({ s with symbols := none }, true)
    | dir :: _ =>
      IO.println s!"symbols: {dir}"
      pure ({ s with symbols := some dir }, true)
  | "seek" :: posStr :: _ =>
    match parseU64 posStr with
    | .error e => IO.eprintln s!"error: {e}"; pure (s, true)
    | .ok pos =>
      match s.target with
      | .dump _ _ => IO.eprintln "error: not a trace session (trace support removed; the proxy-based Lean client is a follow-up)"; pure (s, true)
      | .trace t _ =>
        if pos > t.frontier then
          IO.eprintln s!"error: position {hexUpper pos} beyond frontier {hexUpper t.frontier}"
          pure (s, true)
        else
          pure ({ s with target := .trace t pos }, true)
  | "t+" :: _ | "forward" :: _ =>
    match s.target with
    | .dump _ _ => IO.eprintln "error: not a trace session (trace support removed; the proxy-based Lean client is a follow-up)"; pure (s, true)
    | .trace t cursor =>
      let cursor' := if cursor < t.frontier then cursor + 1 else cursor
      IO.println s!"position {hexUpper cursor'}"
      pure ({ s with target := .trace t cursor' }, true)
  | "t-" :: _ | "back" :: _ =>
    match s.target with
    | .dump _ _ => IO.eprintln "error: not a trace session (trace support removed; the proxy-based Lean client is a follow-up)"; pure (s, true)
    | .trace t cursor =>
      let cursor' := if cursor > 0 then cursor - 1 else cursor
      IO.println s!"position {hexUpper cursor'}"
      pure ({ s with target := .trace t cursor' }, true)
  | ["position"] =>
    match s.target with
    | .dump _ _ => IO.eprintln "error: not a trace session (trace support removed; the proxy-based Lean client is a follow-up)"
    | .trace t cursor =>
      IO.println s!"position {hexUpper cursor} / frontier {hexUpper t.frontier}"
    pure (s, true)
  | "writes" :: vaStr :: lenStr :: _ =>
    match parseU64 vaStr, parseU64 lenStr with
    | .ok va, .ok len =>
      match s.target with
      | .dump _ _ => IO.eprintln "error: not a trace session (trace support removed; the proxy-based Lean client is a follow-up)"
      | .trace t cursor =>
        let last := t.lastWriter va cursor
        let writes := t.writesBetween va len 0 cursor
        if writes.isEmpty then
          IO.println s!"no writes to [{hexUpper va}, {hexUpper (va + len)}) up to cursor"
        for w in writes do
          let marker := match last with
            | some lw => if lw.pos == w.pos && lw.va == w.va && lw.data == w.data
                then "  <-- last writer" else ""
            | none => ""
          IO.println s!"  @{hexUpper w.pos}  [{hexUpper w.va}, {hexUpper (UInt64.ofNat (min w.endVaNat (2^64-1)))})  {byteDebug w.data}{marker}"
    | _, _ => IO.eprintln "error: bad writes arguments"
    pure (s, true)
  | ["intervals"] =>
    match s.target with
    | .dump _ _ => IO.eprintln "error: not a trace session (trace support removed; the proxy-based Lean client is a follow-up)"
    | .trace t cursor =>
      for (id, iv) in t.threads do
        let alive := match iv.stop with
          | none => "alive"
          | some e => s!"ended {hexUpper e}"
        let here := if iv.contains cursor then "*" else " "
        IO.println s!"  {here}thread {id}: start {hexUpper iv.start}, {alive}"
      for c in t.calls do
        let state := match c.interval.stop with
          | none => "open"
          | some e => s!"end {hexUpper e}"
        IO.println s!"   call on {c.threadId}: [{hexUpper c.interval.start}, {state})"
    pure (s, true)
  | "help" :: _ =>
    IO.println "commands: inspect analyze match list-plugins load symbols seek t+ t- position writes intervals quit"
    pure (s, true)
  | [] => pure (s, true)
  | cmd :: _ =>
    IO.eprintln s!"error: unknown command '{cmd}'"
    pure (s, true)

/-- Run the interactive session (session.rs run). -/
private partial def shellLoop (s : Session) (stdin stdout : IO.FS.Stream) : IO Unit := do
  IO.print s.prompt
  stdout.flush
  let line ← stdin.getLine
  if line.isEmpty then
    IO.println ""
  else
    let argv := Session.tokenize line
    if argv.isEmpty then shellLoop s stdin stdout
    else
      let (s', cont) ← shellDispatch s argv
      if cont then shellLoop s' stdin stdout

private def cmdShell (path : String) (symbols : Option String) : IO UInt32 := do
  let s ← Session.open path symbols
  IO.println s!"loaded {s.banner}"
  IO.println "type 'help' for commands, 'quit' to exit"
  shellLoop s (← IO.getStdin) (← IO.getStdout)
  pure 0

private def usage : IO UInt32 := do

  IO.eprintln "usage: forensicator <inspect|analyze|match|list-plugins|shell> <file> [flags]"
  pure 2

def main (args : List String) : IO UInt32 := do
  match args with
  | "inspect" :: rest =>
    let rec parseI (path : Option String) (json quiet : Bool)
        : List String → Except String (Option String × Bool × Bool)
      | [] => .ok (path, json, quiet)
      | "--json" :: rest => parseI path true quiet rest
      | "--quiet" :: rest => parseI path json true rest
      | x :: rest =>
        if x.startsWith "-" then .error s!"unknown flag {x}"
        else parseI (some x) json quiet rest
    match parseI none false false rest with
    | .error e => IO.eprintln e; usage
    | .ok (some path, json, quiet) => cmdInspect path json quiet
    | .ok (none, _, _) => usage
  | "analyze" :: rest =>
    let rec parseA (path : Option String) (plugin : Option String) (json : Bool)
        (symbols : Option String)
        : List String → Except String (Option String × Option String × Bool × Option String)
      | [] => .ok (path, plugin, json, symbols)
      | "--json" :: rest => parseA path plugin true symbols rest
      | "--plugin" :: p :: rest => parseA path (some p) json symbols rest
      | "--symbols" :: sp :: rest => parseA path plugin json (some sp) rest
      | x :: rest =>
        if x.startsWith "-" then .error s!"unknown flag {x}"
        else parseA (some x) plugin json symbols rest
    match parseA none none false none rest with
    | .error e => IO.eprintln e; usage
    | .ok (some path, plugin, json, symbols) => cmdAnalyze path plugin json symbols
    | .ok (none, _, _, _) => usage
  | ["list-plugins"] => cmdListPlugins
  | "shell" :: rest =>
    let path := rest.find? fun x => !x.startsWith "-"
    let symbols := match (rest.zipIdx).find? fun (x, _) => x == "--symbols" with
      | some (_, i) => rest[i+1]?
      | none => none
    match path with
    | some p => cmdShell p symbols
    | none => usage
  | "match" :: rest =>
    let rec parseM (path : Option String) (exes pdbs : List String) (json : Bool)
        : List String → Except String (Option String × List String × List String × Bool)
      | [] => .ok (path, exes, pdbs, json)
      | "--json" :: rest => parseM path exes pdbs true rest
      | "--exe" :: e :: rest => parseM path (exes ++ [e]) pdbs json rest
      | "--pdb" :: p :: rest => parseM path exes (pdbs ++ [p]) json rest
      | x :: rest =>
        if x.startsWith "-" then .error s!"unknown flag {x}"
        else parseM (some x) exes pdbs json rest
    match parseM none [] [] false rest with
    | .error e => IO.eprintln e; usage
    | .ok (some path, exes, pdbs, json) => cmdMatch path exes pdbs json
    | .ok (none, _, _, _) => usage
  | _ => usage

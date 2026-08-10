/- forensicator (Lean) — CLI. Task 4 scope: the `trace` subcommand
   (summary, pos snapshot, writes query, json), Rust-CLI-compatible. -/
import Forensicator

open Forensicator Forensicator.Parse Forensicator.Model

private def byteListJson (bs : ByteArray) : Json :=
  .arr (bs.toList.map fun b => .int b.toNat)

private def writeHitJson (w : WriteRecord) : Json :=
  .obj [("pos", .str (hexUpper w.pos)), ("va", .str (hexUpper w.va)),
        ("end_va", .str (hexUpper (UInt64.ofNat (min w.endVaNat (2^64 - 1))))),
        ("data", byteListJson w.data)]

private def byteDebug (bs : ByteArray) : String :=
  "[" ++ String.intercalate ", " (bs.toList.map fun b => hexPadUpper b.toUInt64 2) ++ "]"

private def traceJson (tr : Trace) (pos : Position) (writes : Option (UInt64 × UInt64)) : Json :=
  let writeHits : Json := match writes with
    | some (va, len) =>
      .arr ((tr.writesBetween va len 0 pos).map writeHitJson)
    | none => .null
  .obj [
    ("frontier", .str (hexUpper tr.frontier)),
    ("position", .str (hexUpper pos)),
    ("init_regions", .ofNat tr.initMem.length),
    ("writes", .ofNat tr.writes.length),
    ("events", .ofNat tr.events.length),
    ("threads", .ofNat tr.threads.length),
    ("calls", .ofNat tr.calls.length),
    ("anomalies", .arr (tr.anomalies.map fun a => .str a.description)),
    ("write_hits", writeHits)]

private def anomalyDisplay (a : Anomaly) : String :=
  s!"[stream 0x{hexPadUpper a.streamType.toUInt64 8} @ +{hexUpper a.fileOffset}] {a.description}"

private def intervalEnd : Option Position → String
  | some e => hexUpper e
  | none => "open"

private def cmdTrace (path : String) (posArg : Option String) (writesArg : List String)
    (json : Bool) : IO UInt32 := do
  let data ← IO.FS.readBinFile path
  match decodeTtfx data with
  | .error a => IO.eprintln a.description; pure 1
  | .ok tr =>
    let pos? ← match posArg with
      | some p =>
        match parseU64 p with
        | .ok v => pure (some v)
        | .error e => IO.eprintln e; pure none
      | none => pure (some tr.frontier)
    let some pos := pos? | return 1
    let writes? ←
      match writesArg with
      | [a, b] =>
        match parseU64 a, parseU64 b with
        | .ok va, .ok len => pure (some (some (va, len)))
        | .error e, _ | _, .error e => IO.eprintln e; pure none
      | [] => pure (some none)
      | _ => pure (some none)  -- json: silently None; text: handled below
    let some writes := writes? | return 1
    if json then
      IO.println (Json.render (traceJson tr pos writes))
      return 0
    -- text output
    IO.println s!"Trace: frontier {hexUpper tr.frontier}, {tr.initMem.length} init region(s), {tr.writes.length} write(s), {tr.events.length} event(s), {tr.threads.length} thread(s), {tr.calls.length} call(s)"
    for a in tr.anomalies do
      IO.println s!"  anomaly: {anomalyDisplay a}"
    for (id, iv) in tr.threads do
      IO.println s!"  thread {id}: [{hexUpper iv.start}, {intervalEnd iv.stop})"
    for c in tr.calls do
      IO.println s!"  call on {c.threadId}: [{hexUpper c.interval.start}, {intervalEnd c.interval.stop})"
    match writesArg with
    | [_, _] =>
      let some (va, len) := writes | unreachable!
      let hits := tr.writesBetween va len 0 pos
      IO.println s!"writes to [{hexUpper va}, {hexUpper (va + len)}) up to {hexUpper pos}: {hits.length}"
      let last := tr.lastWriter va pos
      for w in hits do
        let marker := match last with
          | some lw => if lw.pos == w.pos && lw.va == w.va && lw.data == w.data
              then "  <-- last writer" else ""
          | none => ""
        IO.println s!"  @{hexUpper w.pos}  [{hexUpper w.va}, {hexUpper (UInt64.ofNat (min w.endVaNat (2^64-1)))})  {byteDebug w.data}{marker}"
    | [] => pure ()
    | _ => IO.eprintln "--writes takes exactly two values: <va> <len>"; return 1
    if pos != tr.frontier || writesArg.isEmpty then
      match tr.snapshot pos with
      | none =>
        IO.eprintln s!"position {hexUpper pos} beyond frontier {hexUpper tr.frontier}"
        pure 1
      | some snap =>
        IO.println s!"snapshot @ {hexUpper pos}: {snap.dump.memoryRegions.length} region(s), {snap.dump.modules.length} module(s), exception: {snap.dump.exception.isSome}"
        pure 0
    else pure 0

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

private def cmdInspect (path : String) (json quiet : Bool) : IO UInt32 := do
  let data ← IO.FS.readBinFile path
  match Minidump.fromBytes data with
  | .error f => IO.eprintln f.render; pure 1
  | .ok dump =>
    if json then IO.println (Json.render (inspectJson dump))
    else if quiet then
      IO.println s!"modules: {dump.modules.length}  threads: {dump.threads.length}  memory_regions: {dump.memoryRegions.length}  anomalies: {dump.anomalies.length}"
    else inspectText dump
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
    pure 0

private def cmdListPlugins : IO UInt32 := do
  IO.println "Available analyzers:"
  for a in defaultPipeline do
    IO.println s!"  {a.name}: {a.description}"
  pure 0

private def usage : IO UInt32 := do
  IO.eprintln "usage: forensicator <inspect|analyze|trace|list-plugins> <file> [flags]"
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
  | "trace" :: rest =>
    let rec parseT (path : Option String) (pos : Option String) (writes : List String) (json : Bool)
        : List String → Except String (Option String × Option String × List String × Bool)
      | [] => .ok (path, pos, writes, json)
      | "--json" :: rest => parseT path pos writes true rest
      | "--pos" :: p :: rest => parseT path (some p) writes json rest
      | "--writes" :: a :: b :: rest => parseT path pos [a, b] json rest
      | x :: rest =>
        if x.startsWith "-" then .error s!"unknown flag {x}"
        else parseT (some x) pos writes json rest
    match parseT none none [] false rest with
    | .error e => IO.eprintln e; usage
    | .ok (some path, pos, writes, json) => cmdTrace path pos writes json
    | .ok (none, _, _, _) => usage
  | _ => usage

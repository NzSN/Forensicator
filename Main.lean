/- forensicator — capture inspection and execution analysis. Trace sessions
   expose lazy execution points through the proxy. -/
import Forensicator
import Forensicator.Mcp.Server

open Forensicator Forensicator.Parse Forensicator.Model Forensicator.Report

private def byteDebug (bs : ByteArray) : String :=
  "[" ++ String.intercalate ", " (bs.toList.map fun b => hexPadUpper b.toUInt64 2) ++ "]"

-- ── inspect ─────────────────────────────────────────────────────────

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
    let space := buildAddressSpace d
    let dg := Analyzer.Cause.diagnose (AnalysisInput.ofDump d space) space
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

private def analyzePrint (input : AnalysisInput)
    (plugin : Option String) (json : Bool) (ctx : SymbolsCtx) : IO Unit := do
    let filter := match plugin with
      | none => []
      | some p => (p.splitOn ",").map (String.trimAscii · |>.toString)
    let catalog := runPipeline ctx defaultPipeline input filter
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
    (symbols : Option String) : IO UInt32 := do
  let data ← IO.FS.readBinFile path
  match Minidump.fromBytes data with
  | .error f => IO.eprintln f.render; pure 1
  | .ok dump =>
    let (space, imageCount) ← supplementImages (buildAddressSpace dump) dump path
    let input := AnalysisInput.ofDump dump space path
    let ctx ← Session.loadSymbolsCtxFor input symbols
    if !json then
      let kind := match classifyDump dump with
        | .FullMemory => "full-memory" | .StackOnly => "stack-only"
      IO.eprintln s!"dump: {kind}, {imageCount} image(s) supplemented"
    analyzePrint input plugin json ctx
    pure 0


private def cmdListPlugins : IO UInt32 := do
  IO.println "Available analyzers:"
  for a in defaultPipeline do
    IO.println s!"  {a.name}: {a.description}"
  pure 0

-- ── match ───────────────────────────────────────────────────────────

private def matchRunModules (modules : List Module) (exes pdbs : List String)
    (json : Bool) (sourceLabel : String := "dump") : IO UInt32 := do
    let report ← matchModules modules exes pdbs sourceLabel
    match report with
    | .error e => IO.eprintln e; return 1
    | .ok report =>
      matchPrint report
  where
    matchPrint (report : MatchReport) : IO UInt32 := do
      let items := report.items
      let overall := report.overall
      if json then
        IO.println (Json.render (report.toJson sourceLabel))
      else
        for i in items do
          match i.modul with
          | some m =>
            IO.println s!"{i.kind.toUpper} {i.path} ↔ module {m}"
            for c in i.checks do
              let note := (c.note.map ("  (" ++ · ++ ")")).getD ""
              IO.println s!"  {(c.field ++ "         ").take 9} {(c.result.upper ++ "         ").take 9} file={c.fileValue}  {sourceLabel}={c.dumpValue}{note}"
          | none =>
            IO.println s!"{i.kind.toUpper} {i.path} ↔ no matching module in {sourceLabel}"
        IO.println s!"overall: {overall.upper}"
      pure (if overall == .mismatch then 2 else 0)


-- ── shell ───────────────────────────────────────────────────────────


private def cmdMatch (path : String) (exes pdbs : List String) (json : Bool) : IO UInt32 := do
  if exes.isEmpty && pdbs.isEmpty then
    IO.eprintln "nothing to match: pass --exe and/or --pdb"
    return 1
  let data ← IO.FS.readBinFile path
  match Minidump.fromBytes data with
  | .error f => IO.eprintln f.render; pure 1
  | .ok dump => matchRunModules dump.modules exes pdbs json


private def coverageName : Coverage → String
  | .unknown => "unknown" | .incomplete => "partial" | .complete => "complete"

private def knowledgeJson (k : Knowledge α) (render : α → Json) : Json :=
  match k with
  | .unknown => .obj [("status", .str "unknown")]
  | .unavailable reason => .obj [("status", .str "unavailable"), ("reason", .str reason)]
  | .known value => .obj [("status", .str "known"), ("value", render value)]

private def knowledgeName : Knowledge α → String
  | .unknown => "unknown"
  | .unavailable reason => "unavailable (" ++ reason ++ ")"
  | .known _ => "known"

private def eventKindName : ExecutionEventKind → String
  | .Exception => "exception" | .ModuleLoad => "module_load" | .ModuleUnload => "module_unload"

private def eventJson (e : ExecutionEvent) : Json :=
  .obj [("kind", .str (eventKindName e.kind)), ("code", .str (hexUpper e.code.toUInt64)),
    ("address", .str (hexUpper e.address)), ("thread_id", .ofUInt32 e.threadId),
    ("name", .str e.name), ("size", .ofUInt64 e.size)]

private def frameJson (frame : RecoveredFrame) : Json :=
  .obj [("instruction", .str (hexUpper frame.instruction)),
    ("stack_pointer", .str (hexUpper frame.stackPointer)),
    ("frame_pointer", match frame.framePointer with | some p => .str (hexUpper p) | none => .null),
    ("confidence", .ofFloat frame.confidence)]

private def pointInspectPrint (input : AnalysisInput) (frontier : Option Position)
    (json quiet : Bool) : IO Unit := do
  let point := input.point
  let position := match point.id.position with
    | .capture => "capture"
    | .trace p => hexUpper p
  if json then
    let threadJson (t : ThreadState) : Json :=
      .obj [("id", .ofUInt32 t.id),
        ("lifetime", match t.lifetime with
          | none => .null
          | some iv => .obj [("start", .str (hexUpper iv.start)),
              ("stop", match iv.stop with | none => .null | some e => .str (hexUpper e))]),
        ("registers", knowledgeJson t.registers fun r =>
          .obj [("rip", .str (hexUpper r.rip)), ("rsp", .str (hexUpper r.rsp))]),
        ("stack_range", knowledgeJson t.stackRange fun r =>
          .obj [("va", .str (hexUpper r.va)), ("size", .ofUInt64 r.size)]),
        ("frames", knowledgeJson t.frames fun f =>
          .obj [("count", .ofNat f.frames.length),
            ("frames", .arr (f.frames.map frameJson)),
            ("coverage", .str (coverageName f.coverage)), ("confidence", .ofFloat f.confidence)])]
    IO.println (Json.render (.obj [
      ("source", .str point.id.source), ("position", .str position),
      ("frontier", match frontier with | some p => .str (hexUpper p) | none => .null),
      ("memory", .obj [("known_regions", .ofNat input.space.regions.length),
        ("byte_coverage", .str (coverageName point.memory.byteCoverage)),
        ("mapping_coverage", .str (coverageName point.memory.mappingCoverage)),
        ("known_absent_ranges", .ofNat point.memory.absentRanges.length)]),
      ("events", .arr (point.events.map eventJson)),
      ("event_coverage", .str (coverageName point.eventCoverage)),
      ("threads", .arr (point.threads.map threadJson)),
      ("thread_coverage", .str (coverageName point.threadCoverage)),
      ("context", .obj [("modules", .arr (input.modules.map moduleJson))]),
      ("anomalies", .arr (point.anomalies.map (fun a => .str a.description)))]))
  else if quiet then
    IO.println s!"position: {position}  memory_regions: {input.space.regions.length}  events: {point.events.length}  threads: {point.threads.length}  byte_coverage: {coverageName point.memory.byteCoverage}"
  else
    let suffix := frontier.map (fun p => " / frontier " ++ hexUpper p) |>.getD ""
    IO.println s!"Execution point {position}{suffix}"
    IO.println s!"Memory: {input.space.regions.length} known regions; bytes {coverageName point.memory.byteCoverage}; mappings {coverageName point.memory.mappingCoverage}"
    IO.println s!"Events at this position: {point.events.length}"
    for (e, i) in point.events.zipIdx do
      IO.println s!"  [{i}] {eventKindName e.kind} @ {hexUpper e.address} (thread {e.threadId})"
    IO.println s!"Threads: {point.threads.length}"
    for t in point.threads do
      IO.println s!"  TID {t.id}: registers {knowledgeName t.registers}; stack {knowledgeName t.stackRange}; frames {knowledgeName t.frames}"
    IO.println s!"Active modules: {input.modules.length}"
    for a in point.anomalies do IO.println s!"  anomaly: {a.description}"

private def selectAnalysisEvent (input : AnalysisInput) (args : List String) :
    Except String AnalysisInput := do
  match args.dropWhile (· != "--event") with
  | [] => pure input
  | [_] => .error "--event needs an event index from inspect"
  | _ :: value :: _ =>
    let index ← parseU64 value
    match input.point.events[index.toNat]? with
    | some event =>
      if event.kind == .Exception then pure { input with selectedEvent := some index.toNat }
      else .error "selected event is not an exception"
    | none => .error "event index out of range"

private def stackStopCode : Execution.Stack.StopReason → String
  | .validatedRoot => "validated_root" | .missingThread => "missing_thread"
  | .missingContext => "missing_context" | .missingArchitecture => "missing_architecture"
  | .unsupportedArchitecture => "unsupported_architecture" | .missingStackBounds => "missing_stack_bounds"
  | .missingMemory => "missing_memory" | .absentMemory => "absent_memory"
  | .missingArtifact => "missing_artifact" | .invalidArtifact => "invalid_artifact"
  | .unsupportedUnwind => "unsupported_unwind" | .invalidContext => "invalid_context"
  | .invalidStackTransition => "invalid_stack_transition" | .invalidReturnAddress => "invalid_return_address"
  | .cycle => "cycle" | .frameBudget => "frame_budget" | .byteBudget => "byte_budget"
  | .contextMismatch => "context_mismatch"

private def stackDependencyJson : Execution.Stack.Dependency → Json
  | .registers thread => .obj [("kind", .str "registers"), ("thread_id", .ofUInt32 thread.1)]
  | .stackBounds thread => .obj [("kind", .str "stack_bounds"), ("thread_id", .ofUInt32 thread.1)]
  | .memory range => .obj [("kind", .str "memory"), ("va", .str (hexUpper range.va)),
      ("size", .ofUInt64 range.size)]
  | .unwindArtifact base => .obj [("kind", .str "unwind_artifact"), ("module_base", .str (hexUpper base))]
  | .artifactBytes base range => .obj [("kind", .str "artifact_bytes"),
      ("module_base", .str (hexUpper base)), ("va", .str (hexUpper range.va)),
      ("size", .ofUInt64 range.size)]

private def stackPrint (result : Execution.Stack.StackRecovery) (json : Bool) : IO Unit := do
  let position := match result.evidence.pointId.position with
    | .capture => "capture" | .trace p => hexUpper p
  let origin := match result.evidence.registerOrigin with
    | none => "unavailable" | some .thread => "thread"
    | some (.exceptionEvent i) => s!"exception_event:{i}"
  if json then
    IO.println (Json.render (.obj [
      ("source", .str result.evidence.pointId.source), ("position", .str position),
      ("thread_id", .ofUInt32 result.evidence.thread.1),
      ("frames", .arr (result.stack.frames.map frameJson)),
      ("coverage", .str (coverageName result.stack.coverage)),
      ("confidence", .ofFloat result.stack.confidence),
      ("stop_reason", .str (stackStopCode result.stopReason)),
      ("register_origin", .str origin), ("bytes_read", .ofNat result.bytesRead),
      ("dependencies", .arr (result.dependencies.map stackDependencyJson))]))
  else
    IO.println s!"Stack for thread {result.evidence.thread.1} at {position}: {result.stack.frames.length} frame(s), {coverageName result.stack.coverage}"
    for (frame, i) in result.stack.frames.zipIdx do
      IO.println s!"  #{i}  IP {hexUpper frame.instruction}  SP {hexUpper frame.stackPointer}"
    IO.println s!"Stopped: {(stackStopCode result.stopReason).replace "_" " "}; registers: {origin}"
    if !result.dependencies.isEmpty then
      IO.println s!"Dependencies needed: {Json.render (.arr (result.dependencies.map stackDependencyJson))}"

private def stackBudget (args : List String) (flag : String) (fallback limit : Nat) :
    Except String Nat := do
  match args.dropWhile (· != flag) with
  | [] => pure fallback
  | [_] => .error s!"{flag} needs a number"
  | _ :: value :: _ =>
    let n ← parseU64 value
    if n.toNat > limit then .error s!"{flag} must be at most {limit}" else pure n.toNat

private def shellDispatch (s : Session) (args : List String) : IO (Session × Bool) := do
  match args with
  | "quit" :: _ => do
    s.closeProxy
    pure (s, false)
  | "inspect" :: rest =>
    match s.target with
    | .dump (dump, _, _) _ =>
      if "--point" ∈ rest then
        match ← s.currentIO with
        | .error e => IO.eprintln s!"error: {e}"
        | .ok input => pointInspectPrint input none ("--json" ∈ rest) ("--quiet" ∈ rest)
      else inspectPrint dump ("--json" ∈ rest) ("--quiet" ∈ rest)
    | .trace t _ =>
      match (← s.currentIO) with
      | .error e => IO.eprintln s!"error: {e}"
      | .ok input => pointInspectPrint input (some t.frontier) ("--json" ∈ rest) ("--quiet" ∈ rest)
    pure (s, true)
  | "stack" :: threadStr :: rest =>
    let settings : Except String (UInt32 × Execution.Stack.StackOptions) := do
      let thread ← parseU64 threadStr
      if thread.toNat ≥ 2^32 then .error "thread ID is outside UInt32 range"
      else
        let maxFrames ← stackBudget rest "--max-frames" 128 4096
        let maxReadBytes ← stackBudget rest "--max-bytes" 65536 67108864
        pure (thread.toUInt32, { maxFrames, maxReadBytes })
    match settings with
    | .error e => IO.eprintln s!"error: {e}"; pure (s, true)
    | .ok (thread, options) =>
      match ← s.recoverThreadStack thread options with
      | .error e => IO.eprintln s!"error: {e}"; pure (s, true)
      | .ok (next, result) => stackPrint result ("--json" ∈ rest); pure (next, true)
  | "analyze" :: rest =>
    match (← s.prepareAnalysis) with
    | .error e => IO.eprintln s!"error: {e}"
    | .ok input =>
      let plugin := match rest.find? (· == "--plugin") with
        | some _ => (rest.dropWhile (· != "--plugin")).drop 1 |>.head?
        | none => none
      let json := "--json" ∈ rest
      if (match s.target with | .trace _ _ => true | _ => false) && !json then
        match s.target with
        | .trace t cursor =>
          IO.eprintln s!"position {hexUpper cursor} / frontier {hexUpper t.frontier}, memory coverage: {coverageName input.point.memory.byteCoverage}"
        | _ => pure ()
      match selectAnalysisEvent input rest with
      | .error e => IO.eprintln s!"error: {e}"
      | .ok selected =>
        let ctx ← Session.loadSymbolsCtxFor selected s.symbols
        analyzePrint selected plugin json ctx
    pure (s, true)
  | "match" :: rest =>
    match (← s.currentIO) with
    | .error e => IO.eprintln s!"error: {e}"
    | .ok input =>
      let rec collect (xs : List String) (exes pdbs : List String) : List String × List String :=
        match xs with
        | [] => (exes, pdbs)
        | "--exe" :: e :: r => collect r (exes ++ [e]) pdbs
        | "--pdb" :: p :: r => collect r exes (pdbs ++ [p])
        | _ :: r => collect r exes pdbs
      let (exes, pdbs) := collect rest [] []
      let label := match s.target with | .dump _ _ => "dump" | .trace _ _ => "point"
      let _ ← matchRunModules input.modules exes pdbs ("--json" ∈ rest) label
    pure (s, true)
  | ["list-plugins"] =>
    let _ ← cmdListPlugins
    pure (s, true)
  | "load" :: rest =>
    let proxy := "--proxy" ∈ rest
    match rest.find? fun x => !x.startsWith "-" with
    | none => IO.eprintln "error: load needs a path"; pure (s, true)
    | some path =>
      try
        let s' ← if proxy then Session.openProxy path s.symbols
                 else Session.open path s.symbols
        s.closeProxy
        IO.println s!"loaded {s'.banner}"
        pure (s', true)
      catch e =>
        IO.eprintln s!"error: {e}"
        pure (s, true)
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
      | .dump _ _ => IO.eprintln "error: not a trace session (use shell --proxy or load --proxy)"; pure (s, true)
      | .trace t _ =>
        if pos > t.frontier then
          IO.eprintln s!"error: position {hexUpper pos} beyond frontier {hexUpper t.frontier}"
          pure (s, true)
        else
          pure ({ s with target := .trace t pos }, true)
  | "t+" :: _ | "forward" :: _ =>
    match s.target with
    | .dump _ _ => IO.eprintln "error: not a trace session (use shell --proxy or load --proxy)"; pure (s, true)
    | .trace t cursor =>
      let cursor' := if cursor < t.frontier then cursor + 1 else cursor
      IO.println s!"position {hexUpper cursor'}"
      pure ({ s with target := .trace t cursor' }, true)
  | "t-" :: _ | "back" :: _ =>
    match s.target with
    | .dump _ _ => IO.eprintln "error: not a trace session (use shell --proxy or load --proxy)"; pure (s, true)
    | .trace t cursor =>
      let cursor' := if cursor > 0 then cursor - 1 else cursor
      IO.println s!"position {hexUpper cursor'}"
      pure ({ s with target := .trace t cursor' }, true)
  | ["position"] =>
    match s.target with
    | .dump _ _ => IO.eprintln "error: not a trace session (use shell --proxy or load --proxy)"
    | .trace t cursor =>
      IO.println s!"position {hexUpper cursor} / frontier {hexUpper t.frontier}"
    pure (s, true)
  | "events" :: bounds =>
    match bounds, s.target with
    | [], _ =>
      match ← s.currentIO with
      | .error e => IO.eprintln s!"error: {e}"
      | .ok input =>
        for (event, i) in input.point.events.zipIdx do
          IO.println s!"[{i}] {eventKindName event.kind} @ {hexUpper event.address} (thread {event.threadId})"
        if input.point.events.isEmpty then IO.println "no events recorded at this point"
    | [a, b], .trace t _ =>
      match parseU64 a, parseU64 b with
      | .ok lo, .ok hi =>
        match t.eventsBetween lo hi with
        | .error e => IO.eprintln s!"error: {e}"
        | .ok events =>
          for event in events do
            IO.println s!"@{hexUpper event.pos} {eventKindName event.kind} @ {hexUpper event.address} (thread {event.threadId})"
          if events.isEmpty then IO.println "no events recorded in interval"
      | _, _ => IO.eprintln "error: invalid event interval"
    | [_, _], .dump _ _ => IO.eprintln "error: a capture has no recorded event history"
    | _, _ => IO.eprintln "usage: events [from-position to-position]"
    pure (s, true)
  | ["read", vaStr, lenStr] =>
    match parseU64 vaStr, parseU64 lenStr with
    | .ok va, .ok len =>
      if len > 65536 then IO.eprintln "error: read length must be at most 65536 bytes"
      else
        match ← s.readMemory va len with
        | .error e => IO.eprintln s!"error: {e}"
        | .ok (.known bytes) => IO.println (byteDebug bytes)
        | .ok .absent => IO.println "<known absent>"
        | .ok .unknown => IO.println "<unknown>"
    | _, _ => IO.eprintln "error: invalid address or read length"
    pure (s, true)
  | "writes" :: vaStr :: lenStr :: _ =>
    match parseU64 vaStr, parseU64 lenStr with
    | .ok va, .ok len =>
      match s.target with
      | .dump _ _ => IO.eprintln "error: not a trace session (use shell --proxy or load --proxy)"
      | .trace t cursor =>
        if va.toNat + len.toNat ≥ 2^64 then
          IO.eprintln "error: write-query address range exceeds the supported bounds"
          return (s, true)
        let printWrites (writes : List Model.WriteRecord) (last : Option Model.WriteRecord)
            (payloads : List (Option ByteArray)) : IO Unit := do
          if writes.isEmpty then
            IO.println s!"no writes to [{hexUpper va}, {hexUpper (va + len)}) up to cursor"
          for w in writes.zip payloads do
            let (w, payload) := (w.1, w.2)
            let marker := match last with
              | some lw => if lw.pos == w.pos && lw.va == w.va && lw.len == w.len
                  then "  <-- last writer" else ""
              | none => ""
            let dataStr := match payload with
              | some bs => byteDebug bs
              | none => "<unavailable>"
            IO.println s!"  @{hexUpper w.pos}  [{hexUpper w.va}, {hexUpper (UInt64.ofNat (min w.endVaNat (2^64-1)))})  {dataStr}{marker}"
        match s.proxy with
        | none =>
          let writes := t.writesBetween va len 0 cursor
          printWrites writes (t.lastWriter va cursor) (writes.map (some ·.data))
        | some ps =>
          match (← ps.guarded (do
            let writes ← ps.writesBetween va len 0 cursor
            let payloads ← writes.mapM ps.writeBytes
            pure (writes, payloads))) with
          | .error e => IO.eprintln s!"error: {e}"
          | .ok (writes, payloads) =>
            let last := Model.lastCoveringWrite writes va
            printWrites writes last payloads
    | _, _ => IO.eprintln "error: bad writes arguments"
    pure (s, true)
  | ["intervals"] =>
    match s.target with
    | .dump _ _ => IO.eprintln "error: not a trace session (use shell --proxy or load --proxy)"
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
    IO.println "commands: inspect analyze stack match list-plugins load symbols seek t+ t- position events read writes intervals quit"
    IO.println "events [from to]  |  read <address> <length>  |  analyze [--event <index>]"
    IO.println "stack <thread-id> [--max-frames N] [--max-bytes N] [--json]  |  inspect --point"
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

private def cmdShell (path : String) (symbols : Option String) (proxy : Bool) : IO UInt32 := do
  let s ← if proxy then Session.openProxy path symbols else Session.open path symbols
  IO.println s!"loaded {s.banner}"
  IO.println "type 'help' for commands, 'quit' to exit"
  shellLoop s (← IO.getStdin) (← IO.getStdout)
  (← IO.getStdout).flush
  s.closeProxy
  pure 0

private def usage : IO UInt32 := do

  IO.eprintln "usage: forensicator <inspect|analyze|match|list-plugins|publics|shell> <file> [flags]\n       forensicator mcp"
  pure 2

-- ── publics (design §W2.2 probe: DBI + S_PUB32 + Publics.nearest) ────

/-- Decimal-or-0x-hex UInt32 literal (queries like 0x4E85AE4 or 82311168). -/
private def parseU32Arg (s : String) : Option UInt32 :=
  let hexDigit (c : Char) : Option Nat :=
    let v := c.toNat
    if 48 ≤ v && v ≤ 57 then some (v - 48)
    else if 97 ≤ v && v ≤ 102 then some (v - 97 + 10)
    else if 65 ≤ v && v ≤ 70 then some (v - 65 + 10)
    else none
  if s.startsWith "0x" || s.startsWith "0X" then
    let rec go (acc : Nat) : List Char → Option Nat
      | [] => some acc
      | c :: rest =>
        match hexDigit c with
        | none => none
        | some d => go (acc * 16 + d) rest
    match go 0 (s.toList.drop 2) with
    | some n => if n ≤ 0xFFFFFFFF then some (UInt32.ofNat n) else none
    | none => none
  else
    match s.toNat? with
    | some n => if n ≤ 0xFFFFFFFF then some (UInt32.ofNat n) else none
    | none => none

/-- Load the publics table: the shared S_PUB32 walk (Session) + the
    RVA mapping. With `--exe`, section VAs from the PE drive the mapping
    (rva = sectionVA(seg) + off); without one the segment-1 fallback
    applies (off is already the RVA on MSVC PE PDBs — verified exact on
    the nicholas PDB). IO lives here, Analyzer stays pure. -/
private def loadPublics (pdb : String) (exe : Option String)
    : IO (Except String Util.Publics) := do
  match exe with
  | none => Session.loadPublicsFromPdb pdb
  | some ep =>
    let msecVas : Except String (Array UInt32) ←
      try do
        let bytes ← IO.FS.readBinFile ep
        match Util.ImageFile.fromBytes bytes 0 with
        | .ok img => pure (.ok (img.sections.map (·.vaStart) |>.toArray))
        | .error e => pure (.error e)
      catch _ => pure (.error "publics: cannot read exe")
    match msecVas with
    | .error e => pure (.error e)
    | .ok vas =>
      match ← Session.publicRecordsFromPdb pdb with
      | .error e => pure (.error e)
      | .ok recs => pure (.ok (Util.Publics.ofRecords recs (some vas)))

/-- Probe command: prints the entry count and nearest-below for each
    query RVA as NAME+0xHEX (no space), e.g.
    nearest(0x4E85AE4) = Builtins_TypedArrayPrototypeFindLastIndex+0x24. -/
private def cmdPublics (pdb : String) (queries : List UInt32)
    (greps : List String) (exe : Option String) : IO UInt32 := do
  match ← loadPublics pdb exe with
  | .error e => IO.eprintln s!"publics: {e}"; pure 1
  | .ok pubs =>
    let caveat := if exe.isSome then "PE section VAs" else "segment-1 fallback (off == RVA)"
    IO.println s!"publics {pdb}: {pubs.entries.size} entries ({caveat})"
    for rva in queries do
      match Util.Publics.nearest pubs rva with
      | some (name, delta) =>
        IO.println s!"nearest(0x{hexPadUpper rva.toUInt64 8}) = {name}+0x{hexPadLower delta.toUInt64 0}"
      | none => IO.println s!"nearest(0x{hexPadUpper rva.toUInt64 8}) = <none>"
    for g in greps do
      let mut hits := 0
      for (rva, name) in pubs.entries do
        if name.contains g then
          IO.println s!"0x{hexPadUpper rva.toUInt64 8}  {name}"
          hits := hits + 1
      IO.println s!"grep \"{g}\": {hits} hit(s)"
    pure 0


def main (args : List String) : IO UInt32 := do
  match args with
  | ["mcp"] => Mcp.run
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
    let proxy := "--proxy" ∈ rest
    let symbols := match (rest.zipIdx).find? fun (x, _) => x == "--symbols" with
      | some (_, i) => rest[i+1]?
      | none => none
    match path with
    | some p => cmdShell p symbols proxy
    | none => usage
  | "publics" :: rest =>
    let rec parseP (pdb : Option String) (queries : List UInt32)
        (greps : List String) (exe : Option String) : List String
        → Except String (Option String × List UInt32 × List String × Option String)
      | [] => .ok (pdb, queries, greps, exe)
      | "--nearest" :: r :: rest =>
        (match parseU32Arg r with
         | some v => parseP pdb (queries ++ [v]) greps exe rest
         | none => .error s!"bad rva {r}")
      | "--grep" :: g :: rest => parseP pdb queries (greps ++ [g]) exe rest
      | "--exe" :: e :: rest => parseP pdb queries greps (some e) rest
      | x :: rest =>
        if x.startsWith "-" then .error s!"unknown flag {x}"
        else parseP (some x) queries greps exe rest
    match parseP none [] [] none rest with
    | .error e => IO.eprintln e; usage
    | .ok (some pdb, queries, greps, exe) => cmdPublics pdb queries greps exe
    | .ok (none, _, _, _) => usage
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

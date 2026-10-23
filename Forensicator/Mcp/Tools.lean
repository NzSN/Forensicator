/- Typed, read-only MCP tool surface. All file access uses the caller's local
   filesystem permissions; paths are data, never shell command text. -/
import Forensicator.Report

namespace Forensicator.Mcp

open Model Report

inductive ToolCall where
  | inspect (path : String)
  | analyze (path : String) (plugins : List String) (symbols : Option String)
  | matchArtifacts (path : String) (exes pdbs : List String)
  | listPlugins
  deriving Repr, BEq

private def stringSchema (description : String) : Json :=
  .obj [("type", .str "string"), ("minLength", .ofNat 1),
    ("description", .str description)]

private def stringsSchema (description : String) (item : Json) : Json :=
  .obj [("type", .str "array"), ("description", .str description), ("items", item)]

private def tool (name description : String) (properties : List (String × Json))
    (required : List String) (legacy : Bool) (extra : List (String × Json) := []) : Json :=
  .obj ([("name", .str name), ("description", .str description),
    ("inputSchema", .obj ([("type", .str "object"), ("properties", .obj properties),
      ("required", .arr (required.map .str)), ("additionalProperties", .bool false)] ++ extra))] ++
    if legacy then [] else
      [("annotations", .obj [("readOnlyHint", .bool true), ("destructiveHint", .bool false),
        ("idempotentHint", .bool true), ("openWorldHint", .bool false)])])

def toolNames : List String := ["inspect", "analyze", "match", "list_plugins"]

def toolList (legacy : Bool := false) : Json :=
  let path := stringSchema "Path to a Windows minidump on the server's filesystem."
  let artifact := stringSchema "Local file path."
  let plugins := stringsSchema "Analyzer names; omit or pass [] to run the full pipeline. Full-memory analysis can be expensive; select plugins for focused queries."
    (.obj [("type", .str "string"), ("enum", .arr (defaultPipeline.map fun a => .str a.name))])
  .obj [("tools", .arr [
    tool "inspect" "Inspect minidump modules, system information, annotations, anomalies and crash diagnosis. Results preserve the CLI JSON confidence and evidence fields."
      [("path", path)] ["path"] legacy,
    tool "analyze" "Run Forensicator analyzers on a minidump. Uses captured memory plus adjacent module images and optional identity-checked PDB symbols, as the CLI does."
      [("path", path), ("plugins", plugins),
       ("symbols", stringSchema "Local PDB directory; unmatched or unavailable symbols remain unknown.")]
      ["path"] legacy,
    tool "match" "Compare minidump modules with local PE images and/or PDBs. A mismatch or unknown identity is a successful forensic result, not a tool execution error."
      [("path", path), ("exes", stringsSchema "PE image paths." artifact),
       ("pdbs", stringsSchema "PDB paths." artifact)] ["path"] legacy
      [("anyOf", .arr (["exes", "pdbs"].map fun field =>
        .obj [("required", .arr [.str field]),
          ("properties", .obj [(field, .obj [("minItems", .ofNat 1)])])]))],
    tool "list_plugins" "List registered analyzers and their descriptions in pipeline order."
      [] [] legacy])]

private def fieldsOnly (args : Json) (allowed : List String) : Except String Unit := do
  match args with
  | .obj fields =>
    for (key, _) in fields do
      if !allowed.contains key then throw s!"unknown argument '{key}'"
  | _ => throw "arguments must be an object"

private def asString (value : Json) (field : String) : Except String String := do
  match value with
  | .str s =>
    if s.isEmpty || s.toList.contains (Char.ofNat 0) then
      throw s!"'{field}' must be a nonempty string without NUL characters"
    pure s
  | _ => throw s!"'{field}' must be a string"

private def requiredString (args : Json) (field : String) : Except String String := do
  match args.get field with
  | some v => asString v field
  | none => throw s!"missing required argument '{field}'"

private def optionalString (args : Json) (field : String) : Except String (Option String) := do
  match args.get field with
  | some v => pure (some (← asString v field))
  | none => pure none

private def strings (args : Json) (field : String) : Except String (List String) := do
  match args.get field with
  | none => pure []
  | some (.arr values) => values.mapM (asString · field)
  | _ => throw s!"'{field}' must be an array of strings"

/-- Tool argument validation is pure and precedes every file read. -/
def decodeTool (name : String) (args : Json) : Except String ToolCall := do
  match name with
  | "inspect" =>
    fieldsOnly args ["path"]
    pure (.inspect (← requiredString args "path"))
  | "analyze" =>
    fieldsOnly args ["path", "plugins", "symbols"]
    let path ← requiredString args "path"
    let plugins ← strings args "plugins"
    for plugin in plugins do
      if !defaultPipeline.any (·.name == plugin) then
        throw s!"unknown analyzer '{plugin}'; use list_plugins to discover names"
    pure (.analyze path plugins (← optionalString args "symbols"))
  | "match" =>
    fieldsOnly args ["path", "exes", "pdbs"]
    let path ← requiredString args "path"
    let exes ← strings args "exes"
    let pdbs ← strings args "pdbs"
    if exes.isEmpty && pdbs.isEmpty then throw "provide at least one file in 'exes' or 'pdbs'"
    pure (.matchArtifacts path exes pdbs)
  | "list_plugins" =>
    fieldsOnly args []
    pure .listPlugins
  | _ => throw s!"unknown tool '{name}'"

private def readDump (path : String) : IO (Except String Dump) := do
  let bytes ← IO.FS.readBinFile path
  pure ((Parse.Minidump.fromBytes bytes).mapError (·.render))

/-- Reuse the shipping parser, pipeline, image/symbol support and reports.
    I/O and parse failures stay tool errors; inference uncertainty stays data. -/
def runTool (call : ToolCall) : IO (Except String Json) := do
  try
    match call with
    | .listPlugins =>
      pure (.ok (.obj [("plugins", .arr (defaultPipeline.map fun a =>
        .obj [("name", .str a.name), ("description", .str a.description)]))]))
    | .inspect path =>
      pure ((← readDump path).map inspectJson)
    | .analyze path plugins symbols =>
      match ← readDump path with
      | .error e => pure (.error e)
      | .ok dump =>
        let (space, _) ← supplementImages (buildAddressSpace dump) dump path
        let input := AnalysisInput.ofDump dump space path
        let ctx ← Session.loadSymbolsCtxFor input symbols
        pure (.ok (analyzeJson (runPipeline ctx defaultPipeline input plugins).outputs))
    | .matchArtifacts path exes pdbs =>
      match ← readDump path with
      | .error e => pure (.error e)
      | .ok dump => pure ((← matchModules dump.modules exes pdbs).map (·.toJson))
  catch e => pure (.error e.toString)

def toolResult (result : Except String Json) (legacy : Bool := false) : Json :=
  match result with
  | .ok data =>
    .obj ([("content", .arr [.obj [("type", .str "text"), ("text", .str data.render)]]),
      ("isError", .bool false)] ++ if legacy then [] else [("structuredContent", data)])
  | .error message =>
    .obj [("content", .arr [.obj [("type", .str "text"), ("text", .str message)]]),
      ("isError", .bool true)]

end Forensicator.Mcp

/- Pure MCP 2025-11-25 JSON-RPC dispatch, with 2025-06-18 and 2024-11-05
   compatibility. Only tools are advertised; no hidden shell command route. -/
import Forensicator.Mcp.Tools
import Forensicator.Util.Json.Parser

namespace Forensicator.Mcp

def supportedVersions : List String := ["2025-11-25", "2025-06-18", "2024-11-05"]

structure State where
  version : Option String := none
  ready : Bool := false
  deriving Inhabited, Repr

def State.legacy (s : State) : Bool := s.version == some "2024-11-05"

inductive Action where
  | ignore
  | reply (message : Json)
  | invoke (id : Json) (call : ToolCall)
  deriving Repr

def response (id result : Json) : Json :=
  .obj [("jsonrpc", .str "2.0"), ("id", id), ("result", result)]

def rpcError (id : Json) (code : Int) (message : String) : Json :=
  .obj [("jsonrpc", .str "2.0"), ("id", id),
    ("error", .obj [("code", .int code), ("message", .str message)])]

private def isObject : Json → Bool
  | .obj _ => true | _ => false

private def string? : Json → Option String
  | .str s => some s | _ => none

/-- JSON integers can use decimal/exponent notation. Inspect trailing digits
    without float rounding or expanding a potentially enormous exponent.
    The input is already a syntactically validated JSON number literal. -/
private def integralNumber (literal : String) : Bool := Id.run do
  let parts := literal.toLower.splitOn "e"
  let mantissa := (parts.headD "").splitOn "."
  let digits := (String.intercalate "" mantissa).toList.filter (· != '-')
  let exponentText := (parts[1]?).getD "0"
  let exponentText := if exponentText.startsWith "+" then
    (exponentText.drop 1).toString else exponentText
  let some exponent := exponentText.toInt? | return false
  let needed := (Int.ofNat ((mantissa[1]?).getD "").length - exponent).toNat
  return digits.all (· == '0') || needed ≤ (digits.reverse.takeWhile (· == '0')).length

private def validId : Json → Bool
  | .str _ | .int _ => true
  | .num literal => integralNumber literal
  | _ => false

private def decodeInitialize (params : Json) : Except String String := do
  let some version := (params.get "protocolVersion").bind string?
    | throw "initialize requires a string protocolVersion"
  if version.isEmpty then throw "protocolVersion must not be empty"
  let some caps := params.get "capabilities"
    | throw "initialize requires capabilities"
  if !isObject caps then throw "capabilities must be an object"
  let some info := params.get "clientInfo"
    | throw "initialize requires clientInfo"
  for key in ["name", "version"] do
    let some _ := (info.get key).bind string?
      | throw s!"clientInfo.{key} must be a string"
  pure (if supportedVersions.contains version then version else "2025-11-25")

private def initializeResult (version : String) : Json :=
  .obj [("protocolVersion", .str version),
    ("capabilities", .obj [("tools", .obj [("listChanged", .bool false)])]),
    ("serverInfo", .obj [("name", .str "forensicator"), ("version", .str "0.1.0")]),
    ("instructions", .str "Read-only Windows minidump forensics. Paths refer to this server's filesystem. Use list_plugins before selecting analyzers. Preserve confidence, evidence, and unknown results; a match mismatch is a finding. Calls run sequentially; large dumps may take several minutes.")]

/-- Validate the envelope before dispatch. Notifications never execute tools
    or produce responses. Invalid requests cannot advance initialization. -/
def dispatch (state : State) (message : Json) : State × Action := Id.run do
  let invalid := (state, Action.reply (rpcError .null (-32600) "invalid JSON-RPC request"))
  if !isObject message || message.get "jsonrpc" != some (.str "2.0") then return invalid
  let some method := (message.get "method").bind string? | return invalid
  let params := (message.get "params").getD (.obj [])
  let some id := message.get "id" | do
    if method == "notifications/initialized" && isObject params && state.version.isSome then
      return ({ state with ready := true }, .ignore)
    return (state, .ignore)
  if !validId id then return invalid
  let error (code : Int) (text : String) := (state, Action.reply (rpcError id code text))
  if !isObject params then return error (-32602) "params must be an object"
  if method == "ping" then return (state, .reply (response id (.obj [])))
  if method == "initialize" then
    if state.version.isSome then return error (-32600) "already initialized"
    match decodeInitialize params with
    | .error e => return error (-32602) e
    | .ok version =>
      return ({ version := some version }, .reply (response id (initializeResult version)))
  if method != "tools/list" && method != "tools/call" then
    return error (-32601) s!"method not found: {method}"
  if !state.ready then
    return error (-32600) "send initialize, then notifications/initialized, before using tools"
  if method == "tools/list" then
    if let some cursor := params.get "cursor" then
      if cursor != .str "" then return error (-32602) "invalid cursor: the tool list has one page"
    return (state, .reply (response id (toolList state.legacy)))
  let some name := (params.get "name").bind string?
    | return error (-32602) "tools/call requires a string name"
  if !toolNames.contains name then return error (-32602) s!"unknown tool '{name}'"
  let args := (params.get "arguments").getD (.obj [])
  if !isObject args then return error (-32602) "arguments must be an object"
  -- Tasks are not advertised: do not silently run a requested task inline.
  if (params.get "task").isSome then return error (-32602) "task execution is not supported"
  match decodeTool name args with
  | .error e => return (state, .reply (response id (toolResult (.error e) state.legacy)))
  | .ok call => return (state, .invoke id call)

end Forensicator.Mcp

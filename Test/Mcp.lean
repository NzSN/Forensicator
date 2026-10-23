/- JSON and pure dispatch guards. Transport and real file/result parity are
   covered separately by scripts/test-mcp.py. -/
import Forensicator.Mcp.Protocol

namespace Test.Mcp

open Forensicator Forensicator.Mcp

private def check (failures : IO.Ref Nat) (label : String) (ok : Bool) : IO Unit := do
  if ok then IO.println s!"ok    mcp {label}"
  else
    failures.modify (· + 1)
    IO.eprintln s!"FAIL  mcp {label}"

def runAll : IO UInt32 := do
  let failures ← IO.mkRef 0
  let valid : List Json := [
    .null, .bool true, .bool false, .int 0, .int (-42), .int 18446744073709551615,
    .num "-1.25e+3", .str "quotes: \" \\ \n\r\t", .str "取证 🚀",
    .str (String.ofList ((List.range 32).map Char.ofNat)),
    .arr [.null, .obj [("x", .int 1)]], .obj [("null", .null), ("list", .arr [])]]
  check failures "JSON round-trips exact data" (valid.all fun j => (Json.parse j.render).toOption == some j)
  check failures "Unicode surrogate pair" ((Json.parse "\"\\uD83D\\uDE80\"").toOption == some (.str "🚀"))
  check failures "Unicode NUL and escaped slash"
    ((Json.parse "\"\\u0000\\/\"").toOption == some (.str (String.ofList [Char.ofNat 0, '/'])))
  check failures "JSON whitespace" ((Json.parse " \r\n\t{\"x\": 7}  ").toOption == some (.obj [("x", .int 7)]))
  for bad in ["", " ", "undefined", "NaN", "Infinity", "01", "-01", "+1", "1.",
      "1e", "1e+", ".5", "--1", "null true", "[1,]", "{\"x\":1,}",
      "{\"x\":1,\"x\":2}", "{\"x\":1,\"\\u0078\":2}",
      "\"\\x00\"", "\"\\uD800\"", "\"\\uDC00\"", "\"\\uD800\\u0000\"",
      "\"\\uXYZW\"", "\"raw\nline\"", "\"unterminated", "[", "{", "truex"] do
    check failures s!"reject {repr bad}" (Json.parse bad).toOption.isNone
  let nested (n : Nat) := String.ofList (List.replicate n '[') ++ "0"
    ++ String.ofList (List.replicate n ']')
  check failures "nesting boundary accepted" (Json.parse (nested 63)).isOk
  check failures "nesting budget enforced" (Json.parse (nested 64)).toOption.isNone
  check failures "node budget enforced"
    (Json.parse ("[" ++ String.intercalate "," (List.replicate 8192 "0") ++ "]")).toOption.isNone
  check failures "numeric conversion budget enforced"
    (Json.parse (String.ofList (List.replicate 1025 '9'))).toOption.isNone
  check failures "input budget enforced"
    (Json.parse (String.ofList (List.replicate (Json.maxInputBytes + 1) ' '))).toOption.isNone
  check failures "missing path fails before I/O" (decodeTool "inspect" (.obj [])).toOption.isNone
  check failures "unknown analyzer fails before I/O"
    (decodeTool "analyze" (.obj [("path", .str "missing"), ("plugins", .arr [.str "typo"])] )).toOption.isNone
  check failures "missing artifacts fail before I/O"
    (decodeTool "match" (.obj [("path", .str "missing")])).toOption.isNone
  check failures "NUL path rejected"
    (decodeTool "inspect" (.obj [("path", .str (String.singleton (Char.ofNat 0)))])).toOption.isNone
  let notify : Json := .obj [("jsonrpc", .str "2.0"), ("method", .str "tools/call"),
    ("params", .obj [("name", .str "inspect"), ("arguments", .obj [("path", .str "missing")])])]
  check failures "notifications never invoke tools" (match (dispatch { ready := true } notify).2 with
    | .ignore => true | _ => false)
  let request : Json := .obj [("jsonrpc", .str "2.0"), ("id", .int 0),
    ("method", .str "tools/call"), ("params", .obj [("name", .str "list_plugins")])]
  check failures "tools unavailable before initialization" (match (dispatch {} request).2 with
    | .reply reply => reply.get "error" |>.isSome | _ => false)
  pure (if (← failures.get) == 0 then 0 else 1)

end Test.Mcp

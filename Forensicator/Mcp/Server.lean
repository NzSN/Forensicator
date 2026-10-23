/- stdio transport: bounded UTF-8 newline frames, exactly one JSON-RPC
   response per request, no banner/prompt/progress on stdout. -/
import Forensicator.Mcp.Protocol

namespace Forensicator.Mcp

private def send (stdout : IO.FS.Stream) (message : Json) : IO Unit := do
  stdout.putStrLn message.render
  stdout.flush

private def handleFrame (state : State) (bytes : ByteArray) (overflow : Bool)
    (stdout : IO.FS.Stream) : IO State := do
  let parsed := do
    if overflow then throw "JSON input exceeds 1 MiB"
    let some text := String.fromUTF8? bytes | throw "invalid UTF-8"
    Json.parse text
  match parsed with
  | .error e =>
    send stdout (rpcError .null (-32700) e)
    pure state
  | .ok message =>
    let (next, action) := dispatch state message
    match action with
    | .ignore => pure ()
    | .reply message => send stdout message
    | .invoke id call =>
      send stdout (response id (toolResult (← runTool call) next.legacy))
    pure next

/-- Serial request processing bounds concurrent dump memory use. Input closes
    the server after pending requests complete; no protocol shutdown method.
    Oversized lines are drained without retaining their contents. -/
def serve (stdin stdout : IO.FS.Stream) : IO Unit := do
  let mut state : State := {}
  let mut pending := ByteArray.empty
  let mut overflow := false
  repeat
    -- The core stdio stream may fill the requested read before returning.
    -- Read one byte from its buffered handle so short requests are dispatched
    -- immediately while the client keeps stdin open waiting for the reply.
    let bytes ← stdin.read 1
    if bytes.isEmpty then
      if overflow || !pending.isEmpty then
        let _ ← handleFrame state pending overflow stdout
      break
    for byte in bytes do
      if byte == 10 then
        state ← handleFrame state pending overflow stdout
        pending := ByteArray.empty
        overflow := false
      else if !overflow then
        if pending.size == Json.maxInputBytes then
          pending := ByteArray.empty
          overflow := true
        else pending := pending.push byte

def run : IO UInt32 := do
  try
    serve (← IO.getStdin) (← IO.getStdout)
    pure 0
  catch e =>
    IO.eprintln s!"MCP transport error: {e}"
    pure 1

end Forensicator.Mcp

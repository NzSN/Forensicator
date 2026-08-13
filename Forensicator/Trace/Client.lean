/- Forensicator.Trace.Client — the proxy session (IO side of the trace
   client; plan §C4/C5). Spawns `ttfx-proxy.exe` (local interop or via ssh),
   performs the HELLO handshake, and builds the eager skeleton (threads/
   events/frontier; design D1) that `Target.trace` sessions are built from.

   Everything checkable is pure and lives in `Trace/Proto.lean` (codec),
   `Trace/Index.lean` (write index), `Trace/Jigsaw.lean` (cache); this module
   is the only one that touches `IO.Process`. One outstanding request; no
   read timeout in v1 (plan risk 1: a hung proxy hangs the session, Ctrl-C
   is the remedy).

   Transports:
   * local  — `FORENSICATOR_PROXY_EXE` (default
     `/mnt/d/Codebase/JigsawSpawner/target/release/ttfx-proxy.exe`); trace
     path translated `/mnt/<drive>/…` → `<drive>:/…`.
   * remote — `FORENSICATOR_PROXY_SSH=<host>`: spawns
     `ssh <host> "bash -c '<exe> --stdio <trace>'"`; the stdio protocol rides
     the ssh pipes. `FORENSICATOR_PROXY_EXE` then names the *remote* exe
     (default `D:/Codebase/JigsawSpawner/target/release/ttfx-proxy.exe`). -/
import Forensicator.Model.Trace
import Forensicator.Trace.Proto

namespace Forensicator.Trace

/-- Pseudo stream-type in provenance for proxy-sourced facts ("JGSW" LE). -/
def PROXY_STREAM_TYPE : UInt32 := 0x5753474A

/-- Translate `/mnt/<drive>/…` to `<drive>:/…` for interop/ssh transports;
    anything else passes through unchanged. -/
def windowsPath (p : String) : String :=
  match p.toList with
  | '/' :: 'm' :: 'n' :: 't' :: '/' :: d :: '/' :: rest =>
    String.ofList (d.toUpper :: ':' :: '/' :: rest)
  | _ => p

/-- The child config for a proxy process: stdin/stdout piped (the binary
    protocol), stderr inherited (proxy diagnostics are useful and must not
    fill an undrained pipe). -/
def proxySpawnCfg : IO.Process.StdioConfig :=
  { stdin := .piped, stdout := .piped, stderr := .inherit }

/-- A live proxy: one child process, one outstanding request. -/
structure ProxySession where
  child : IO.Process.Child proxySpawnCfg
  frontier : Position
  skel : Model.Trace

namespace ProxySession

/-- Read exactly `n` bytes (short only at EOF). NOTE: `IO.FS.Handle.read`
    blocks until the full count arrives or EOF (spike-verified), so reads
    must always request exact sizes — never "up to n". -/
private def readExact (h : IO.FS.Handle) (n : Nat) : IO ByteArray := do
  let mut acc : ByteArray := .empty
  while acc.size < n do
    let chunk ← h.read (n - acc.size).toUSize
    if chunk.isEmpty then break
    acc := acc ++ chunk
  pure acc

/-- Receive one frame: exact 4-byte length prefix, then the exact body
    (mirrors the proxy's `read_frame`). EOF and framing violations are
    session-fatal. -/
private def recvFrame (child : IO.Process.Child proxySpawnCfg) :
    IO (UInt32 × ByteArray) := do
  let header ← readExact child.stdout 4
  if header.size < 4 then
    throw (IO.Error.userError "proxy closed the connection (EOF)")
  let bodyLen := (readU32leAt header 0).toNat
  if bodyLen < 4 || bodyLen > maxFrameBody then
    throw (IO.Error.userError s!"proxy framing error: frame body length {bodyLen} out of range")
  let body ← readExact child.stdout bodyLen
  if body.size < bodyLen then
    throw (IO.Error.userError "proxy closed the connection mid-frame (EOF)")
  pure (readU32leAt body 0, body.extract 4 bodyLen)

/-- One round trip: write the request frame, read one response frame. ERROR
    frames, unknown tags and malformed payloads are session-fatal (plan C4:
    fail closed, never fudge). -/
def request (ps : ProxySession) (req : Request) : IO Response := do
  ps.child.stdin.write req.encode
  ps.child.stdin.flush
  let (tag, payload) ← recvFrame ps.child
  match parseResponse tag payload with
  | .ok (.error msg) => throw (IO.Error.userError s!"proxy error: {msg}")
  | .ok r => pure r
  | .error e => throw (IO.Error.userError s!"proxy protocol error: {e}")

/-- Build the eager skeleton (design D1) from the handshake inventory, with
    Timeline-invariant violations recorded as anomalies (degrade, never
    abort — the eager decoder enforced, the client records). -/
def skeleton (frontier : Position) (threads : Array RawThread)
    (events : Array RawEvent) : Model.Trace :=
  let prov : Provenance := { streamType := PROXY_STREAM_TYPE }
  let evs : List Model.TraceEvent := events.toList.map fun
    | .exception pos code address tid =>
      { pos, kind := .Exception, code, address, threadId := tid, provenance := prov }
    | .moduleLoad pos base size name =>
      { pos, kind := .ModuleLoad, address := base, name, size, provenance := prov }
    | .moduleUnload pos base =>
      { pos, kind := .ModuleUnload, address := base, provenance := prov }
  let orderAnoms :=
    if (evs.zip (evs.drop 1)).any fun (a, b) => b.pos < a.pos
    then [Anomaly.ofProv prov "events out of order"] else []
  let evAnoms := (evs.filter (frontier < ·.pos)).map fun _ =>
    Anomaly.ofProv prov "event beyond frontier"
  let threadAnoms := threads.toList.flatMap fun t =>
    (match t.stop with
     | some e => if t.start ≤ e then [] else [Anomaly.ofProv prov "thread interval inverted"]
     | none => [])
      ++ (if frontier < t.start || (t.stop.map (fun e => decide (frontier < e))).getD false
          then [Anomaly.ofProv prov "thread interval beyond frontier"] else [])
  { initMem := [], writes := [], events := evs
    threads := threads.toList.map fun t => (t.id, { start := t.start, stop := t.stop })
    calls := [], frontier := frontier
    anomalies := orderAnoms ++ evAnoms ++ threadAnoms }

/-- Spawn the proxy and run the handshake: HELLO → HELLO_ACK (version
    check + frontier), then the unprompted THREADS/EVENTS inventory
    (exactly those tags, in that order — anything else fails closed). -/
def spawn (tracePath : String) : IO ProxySession := do
  let exe? ← IO.getEnv "FORENSICATOR_PROXY_EXE"
  let (cmd, args) ← match (← IO.getEnv "FORENSICATOR_PROXY_SSH") with
    | some host =>
      let exe := exe?.getD "D:/Codebase/JigsawSpawner/target/release/ttfx-proxy.exe"
      pure ("ssh", #[host, s!"bash -c '{exe} --stdio {windowsPath tracePath}'"])
    | none =>
      pure (exe?.getD "/mnt/d/Codebase/JigsawSpawner/target/release/ttfx-proxy.exe",
        #["--stdio", windowsPath tracePath])
  let child ← IO.Process.spawn { cmd := cmd, args := args
                                 stdin := .piped, stdout := .piped, stderr := .inherit
                                 : IO.Process.SpawnArgs }
  try
    child.stdin.write (Request.hello protoVersion).encode
    child.stdin.flush
    let (t1, p1) ← recvFrame child
    let frontier ← match parseResponse t1 p1 with
      | .ok (.helloAck v f) =>
        if v == protoVersion then pure f
        else throw (IO.Error.userError
          s!"proxy protocol version {v}, client speaks {protoVersion}")
      | .ok (.error msg) => throw (IO.Error.userError s!"proxy refused HELLO: {msg}")
      | .ok _ => throw (IO.Error.userError "proxy handshake: expected HELLO_ACK")
      | .error e => throw (IO.Error.userError s!"proxy protocol error: {e}")
    let (t2, p2) ← recvFrame child
    let threads ← match parseResponse t2 p2 with
      | .ok (.threads ts) => pure ts
      | .ok (.error msg) => throw (IO.Error.userError s!"proxy error: {msg}")
      | _ => throw (IO.Error.userError "proxy handshake: expected THREADS")
    let (t3, p3) ← recvFrame child
    let events ← match parseResponse t3 p3 with
      | .ok (.events es) => pure es
      | .ok (.error msg) => throw (IO.Error.userError s!"proxy error: {msg}")
      | _ => throw (IO.Error.userError "proxy handshake: expected EVENTS")
    pure { child, frontier, skel := skeleton frontier threads events }
  catch e =>
    try child.kill catch _ => pure ()
    throw e

/-- Orderly shutdown: CLOSE frame, then reap (the proxy terminates itself
    on CLOSE). Errors are swallowed — the session is over either way. -/
def close (ps : ProxySession) : IO Unit := do
  try
    ps.child.stdin.write Request.close.encode
    ps.child.stdin.flush
  catch _ => pure ()
  try
    let _ ← ps.child.wait
    pure ()
  catch _ =>
    try ps.child.kill catch _ => pure ()

end ProxySession

end Forensicator.Trace

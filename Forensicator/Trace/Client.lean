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
import Forensicator.Trace.Index
import Forensicator.Trace.Jigsaw

namespace Forensicator.Trace

/--- Translate `/mnt/<drive>/…` to `<drive>:/…` for interop/ssh transports;
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

-- A live proxy: one child process, one outstanding request. `index`
-- accumulates fetched write-index windows (design D1/D9).
structure ProxySession where
  child : IO.Process.Child proxySpawnCfg
  frontier : Position
  skel : Model.Trace
  index : IO.Ref IndexState
  cache : IO.Ref Jigsaw

/-- Above this many outstanding page-index fetches, `ensurePages` collapses
    to one wide window (plan task 3 fan-out limit). -/
def fanoutLimit : Nat := 256

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
  let index ← IO.mkRef ({} : IndexState)
  let cache ← IO.mkRef ({} : Jigsaw)
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
    pure { child, frontier, skel := skeleton frontier threads events, index, cache }
  catch e =>
    try child.kill catch _ => pure ()
    throw e

/-- One `WRITES_INDEX` round trip, merged into the client index. -/
def fetchWindow (ps : ProxySession) (win : IndexWindow) : IO Unit := do
  match ← ps.request (.writesIndex win.vaLo win.vaHi win.t1 win.t2) with
  | .index recs => ps.index.modify fun st => st.mergeWindow win recs ps.frontier
  | _ => throw (IO.Error.userError "proxy protocol error: expected INDEX")

/-- Clamp a VA-range end into u64 (Nat-lifted, documented: a range crossing
    2⁶⁴ loses its top byte — nonsense input, fail-bounded not fail-wild). -/
private def rangeEnd (va : VA) (len : UInt64) : VA :=
  UInt64.ofNat (min (va.toNat + len.toNat) (2^64 - 1))

/-- Fetch write metadata for `[va, va+len)` over `[0, frontier]` (one
    window). Pages already known at the frontier are skipped only when the
    whole range is known; the window merge dedups regardless. -/
def ensureRange (ps : ProxySession) (va : VA) (len : UInt64) : IO Unit := do
  if len == 0 then return
  let st ← ps.index.get
  let lastByte := va + (len - 1)
  let pageCount := (pageBaseOf lastByte - pageBaseOf va).toNat / pageSize.toNat + 1
  let allKnown := pageCount ≤ maxMarkPages.toNat
    && (List.range pageCount).all fun i =>
      st.known (pageBaseOf va + UInt64.ofNat (i * pageSize.toNat)) ps.frontier
  if allKnown then return
  ps.fetchWindow { vaLo := va, vaHi := rangeEnd va len, t1 := 0, t2 := ps.frontier }

/-- Ensure the index knows every page in `pages` (page bases) up to the
    frontier (design D2 dependency rule). Missing pages are fetched as
    consecutive-run windows; beyond `fanoutLimit` pages, one wide window
    `[minBase, maxBase + pageSize)` instead. -/
def ensurePages (ps : ProxySession) (pages : List VA) : IO Unit := do
  let st ← ps.index.get
  let sorted := (pages.filter fun p => !st.known p ps.frontier).mergeSort
    fun a b => decide (a ≤ b)
  let need := (sorted.foldl (init := ([] : List VA)) fun acc p =>
    match acc with
    | last :: _ => if last == p then acc else p :: acc
    | [] => [p]).reverse
  if need.isEmpty then return
  if need.length > fanoutLimit then
    match need.head?, need.getLast? with
    | some lo, some hi =>
      ps.fetchWindow { vaLo := lo, vaHi := hi + pageSize, t1 := 0, t2 := ps.frontier }
    | _, _ => pure ()
  else
    let runs := need.foldl (init := ([] : List (VA × VA))) fun runs p =>
      match runs with
      | (lo, hi) :: rest =>
        if p == hi + pageSize then (lo, p) :: rest
        else (p, p) :: runs
      | [] => [(p, p)]
    for (lo, hi) in runs.reverse do
      ps.fetchWindow { vaLo := lo, vaHi := hi + pageSize, t1 := 0, t2 := ps.frontier }

/-- Raw positioned page read. Short reads are a protocol violation
    (fail closed); `notCommitted` is a fact, not an error (D3). -/
private def readPageRaw (ps : ProxySession) (page : VA) (engPos : Position) :
    IO (Option ByteArray) := do
  match ← ps.request (.readAt engPos page pageSize.toUInt32) with
  | .piece .ok bytes =>
    if bytes.size == pageSize.toNat then pure (some bytes)
    else throw (IO.Error.userError
      s!"proxy protocol error: PIECE size {bytes.size} ≠ {pageSize.toNat}")
  | .piece .notCommitted _ => pure none
  | _ => throw (IO.Error.userError "proxy protocol error: expected PIECE")

/-- Fetch one page into the jigsaw cache for model query `t` (design
    D2/D3 + Implementation notes): dependency rule (index first), READ_AT
    at the p+1-clamped position, P3 next-write fallback (the retried piece
    is cached at the fallback's honest model position), ABSENT point
    otherwise. -/
def fetchPage (ps : ProxySession) (page : VA) (t : Position) : IO Unit := do
  ps.ensurePages [page]
  let st ← ps.index.get
  match ← ps.readPageRaw page (fetchPosition t ps.frontier) with
  | some bytes =>
    ps.cache.modify fun c => c.insertFetched page t ps.frontier (some bytes) st
  | none =>
    if st.lastKnownWrite page t != 0 then
      match fallbackPosition st page t ps.frontier with
      | some e2 =>
        match ← ps.readPageRaw page e2 with
        | some bytes2 =>
          ps.cache.modify fun c => c.insertFetched page (e2 - 1) ps.frontier (some bytes2) st
        | none =>
          ps.cache.modify fun c => c.insertFetched page t ps.frontier none st
      | none =>
        ps.cache.modify fun c => c.insertFetched page t ps.frontier none st
    else
      ps.cache.modify fun c => c.insertFetched page t ps.frontier none st

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

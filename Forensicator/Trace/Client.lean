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
   * remote — `FORENSICATOR_PROXY_SSH=<host>`: spawns ssh with a command
     for a POSIX-compatible remote login shell and `bash` on its PATH.
     Bash receives the exe/trace as literal positional arguments; the
     stdio protocol rides the ssh pipes. `FORENSICATOR_PROXY_EXE` then
     names the *remote* exe (default
     `D:/Codebase/JigsawSpawner/target/release/ttfx-proxy.exe`). -/
import Forensicator.Model.Trace
import Forensicator.Trace.Proto
import Forensicator.Trace.Index
import Forensicator.Trace.Jigsaw
import Std.Data.HashSet

namespace Forensicator.Trace

/--- Translate `/mnt/<drive>/…` to `<drive>:/…` for interop/ssh transports;
    anything else passes through unchanged. -/
def windowsPath (p : String) : String :=
  match p.toList with
  | '/' :: 'm' :: 'n' :: 't' :: '/' :: d :: '/' :: rest =>
    String.ofList (d.toUpper :: ':' :: '/' :: rest)
  | _ => p

/-- One literal argument for the POSIX-compatible remote login shell.
    Apostrophes end the quoted segment, emit an escaped apostrophe, and
    resume it. Whitespace, substitutions, and newlines remain literal. -/
private def shellQuote (arg : String) : String :=
  "'" ++ arg.replace "'" "'\\''" ++ "'"

/-- SSH sends command text through the remote login shell before Bash.
    Only this static script is parsed by Bash: neither path becomes shell
    source at either layer. `--` is Bash's $0, then exe/trace are $1/$2. -/
private def remoteProxyCommand (exe tracePath : String) : String :=
  "bash -c " ++ shellQuote "exec -- \"$1\" --stdio \"$2\"" ++ " -- "
    ++ shellQuote exe ++ " " ++ shellQuote (windowsPath tracePath)

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
  /-- set on a session-fatal transport/protocol error (plan C4: ERROR
      frames, framing violations, EOF are session-fatal — fail closed). -/
  dead : IO.Ref (Option String)
  /-- Evidence identity is the loaded trace path, independent of cursor. -/
  source : String := ""

/-- Above this many outstanding page-index fetches, `ensurePages` collapses
    to one wide window (plan task 3 fan-out limit). -/
def fanoutLimit : Nat := 256

/-- v1 cache intervals need the representable sentinel `frontier + 1`. -/
def validateFrontier (frontier : Position) : Except String Unit :=
  if frontier == 0xFFFFFFFFFFFFFFFF then
    .error "proxy v1 does not support the maximum UInt64 frontier"
  else .ok ()

/-- Validate before IO. A v1 index window cannot express an exclusive end
    of 2^64, so that boundary is unsupported rather than silently wrapped. -/
def validateAddressRange (va : VA) (len : UInt64) : Except String Unit :=
  if va.toNat + len.toNat > 2^64 - 1 then
    .error "proxy address range exceeds the representable exclusive end"
  else .ok ()

def validateWriteQuery (frontier : Position) (va : VA) (len : UInt64)
    (t1 t2 : Position) : Except String Unit := do
  validateFrontier frontier
  if t2 < t1 then throw "reversed timeline interval"
  if frontier < t1 || frontier < t2 then throw "timeline interval beyond frontier"
  validateAddressRange va len

/-- A frontier write has no observable post-write engine position. Its page
    is unknown in execution views, even if the wire cache holds clamped bytes. -/
def unobservableFrontierWrite (st : IndexState) (page : VA)
    (t frontier : Position) : Bool :=
  t == frontier && st.records.any (fun w => w.pos == frontier && w.overlapsPage page)

/-- Pure page knowledge, including positive absence. A future P3 piece cannot
    answer an earlier query and cached bytes never outrun index knowledge. -/
def pageKnowledge (c : Jigsaw) (st : IndexState) (page : VA)
    (t frontier : Position) : Model.MemoryRead :=
  if frontier == 0xFFFFFFFFFFFFFFFF || frontier < t || !st.known page t
      || unobservableFrontierWrite st page t frontier then .unknown
  else match c.bytesAt page t with
    | some bytes => if bytes.size == pageSize.toNat then .known bytes else .unknown
    | none => if c.knownAbsentAt page t then .absent else .unknown

/-- Immutable request result. It owns bytes as each page is obtained, so cache
    capacity changes the cost of later requests rather than this result. -/
structure PageMaterialization where
  pages : List (VA × ByteArray) := []
  absent : List Model.AddressRange := []
  anomalies : List Anomaly := []
  seen : Std.HashSet UInt64 := {}
  deriving Inhabited

def PageMaterialization.hasPage (m : PageMaterialization) (page : VA) : Bool :=
  m.seen.contains page

def PageMaterialization.add (m : PageMaterialization) (page : VA)
    (observation : Model.MemoryRead) : PageMaterialization :=
  if m.hasPage page then m
  else match observation with
    | .known bytes =>
      if pageBaseOf page != page || bytes.size != pageSize.toNat then
        { m with anomalies := (Anomaly.ofProv { streamType := PROXY_STREAM_TYPE }
            "invalid materialized page") :: m.anomalies }
      else { m with pages := (page, bytes) :: m.pages, seen := m.seen.insert page }
    | .absent =>
      { m with
        absent := { va := page, size := pageSize } :: m.absent
        seen := m.seen.insert page }
    | .unknown => m

/-- Controllable acquisition seam used by explicit materialization and tests.
    The accumulator is updated before requesting the next page. -/
def collectPages (pages : List VA) (read : VA → IO Model.MemoryRead)
    (initial : PageMaterialization := {}) : IO PageMaterialization := do
  let mut result := initial
  for page in pages do
    if !result.hasPage page then
      result := result.add page (← read page)
  pure result

def cachedMaterialization (c : Jigsaw) (st : IndexState)
    (t frontier : Position) : PageMaterialization :=
  c.lru.foldl (init := {}) fun result page =>
    result.add page (pageKnowledge c st page t frontier)

/-- Sorted page observations become contiguous regions. Unknown mapping flags
    and classification stay unknown; successful byte reads prove only bytes. -/
def PageMaterialization.memory (m : PageMaterialization) : Model.MemoryState := Id.run do
  let sorted := m.pages.mergeSort fun a b => decide (a.1 ≤ b.1)
  let merged := (sorted.foldl (init := ([] : List (VA × ByteArray))) fun acc (base, data) =>
    match acc with
    | (b0, d0) :: rest =>
      if b0.toNat + d0.size == base.toNat then (b0, d0 ++ data) :: rest
      else (base, data) :: acc
    | [] => [(base, data)]).reverse
  let regions := merged.map fun (base, data) =>
    ({ vaStart := base, size := UInt64.ofNat data.size, data
       protection := 0, classification := .Other } : Spec.AddressRegion)
  return { space := { regions, maxRegions := max 1000000 regions.length }
           absentRanges := m.absent, mappingCoverage := .unknown
           byteCoverage := .incomplete }

/-- Pure assembly shared by cache-only views and prepared results. No capture
    aggregate is constructed and no system or runtime observations are invented. -/
def executionView (skel : Model.Trace) (source : String) (t : Position)
    (st : IndexState) (cache : Jigsaw) (materialized : PageMaterialization) :
    Option Model.AnalysisInput := do
  if skel.frontier == 0xFFFFFFFFFFFFFFFF then none else do
    let input ← skel.analysisAt t source
    let frontierAnomalies :=
      if t == skel.frontier && st.records.any (fun w => w.pos == t) then
        [Anomaly.ofProv { streamType := PROXY_STREAM_TYPE }
          "frontier writes have no observable post-write state; affected pages remain unknown"]
      else []
    let point := { input.point with
      memory := materialized.memory
      anomalies := input.point.anomalies ++ st.anomalies ++ cache.anomalies
        ++ materialized.anomalies ++ frontierAnomalies }
    pure { input with point }

/-- Enumerate only explicitly requested pages. Validate the whole request before
    acquiring anything; huge requests and the unrepresentable last page fail. -/
def requestedPages (ranges : List Model.AddressRange) : Except String (List VA) := do
  let mut pages : List VA := []
  for r in ranges do
    validateAddressRange r.va r.size
    if r.size != 0 then
      let first := pageBaseOf r.va
      let last := pageBaseOf (UInt64.ofNat (r.va.toNat + r.size.toNat - 1))
      if last.toNat + pageSize.toNat > 2^64 - 1 then
        throw "proxy v1 cannot index the final UInt64 address page"
      let count := (last.toNat - first.toNat) / pageSize.toNat + 1
      if count > maxMarkPages.toNat then
        throw s!"requested range exceeds {maxMarkPages} pages"
      pages := pages ++ (List.range count).map (fun i => first + UInt64.ofNat (i * pageSize.toNat))
  let sorted := pages.mergeSort fun a b => decide (a ≤ b)
  pure ((sorted.foldl (init := ([] : List VA)) fun acc p =>
    if acc.head? == some p then acc else p :: acc).reverse)

/-- Fetch/cache with a controllable reader. The returned observation is taken
    before eviction, including when cache capacity is zero. -/
def fetchPageWith (cache : IO.Ref Jigsaw) (st : IndexState) (frontier : Position)
    (page : VA) (t : Position) (read : Position → IO (Option ByteArray)) :
    IO Model.MemoryRead := do
  match validateFrontier frontier with
  | .error e => throw (IO.Error.userError e)
  | .ok () => pure ()
  if frontier < t then throw (IO.Error.userError "position beyond frontier")
  if pageBaseOf page != page || page.toNat + pageSize.toNat > 2^64 - 1 then
    throw (IO.Error.userError "proxy page is unaligned or has an unsupported exclusive end")
  if !st.known page t then throw (IO.Error.userError "page write index is incomplete")
  if unobservableFrontierWrite st page t frontier then return .unknown
  let record (observedAt : Position) (outcome : Option ByteArray) : IO Model.MemoryRead := do
    if let some bytes := outcome then
      if bytes.size != pageSize.toNat then
        throw (IO.Error.userError "proxy protocol error: invalid page size")
    cache.modify fun c => c.insertFetched page observedAt frontier outcome st
    let observation := ({} : Jigsaw).insertFetched page observedAt frontier outcome st
    pure (pageKnowledge observation st page t frontier)
  match ← read (fetchPosition t frontier) with
  | some bytes => record t (some bytes)
  | none =>
    if st.lastKnownWrite page t != 0 then
      match fallbackPosition st page t frontier with
      | some e2 =>
        match ← read e2 with
        | some bytes =>
          let _ ← record (e2 - 1) (some bytes)
          -- The first response established absence at the requested point.
          -- Retain it even though the cache now stores useful future bytes.
          pure .absent
        | none => record t none
      | none => record t none
    else record t none

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
      pure ("ssh", #[host, remoteProxyCommand exe tracePath])
    | none =>
      pure (exe?.getD "/mnt/d/Codebase/JigsawSpawner/target/release/ttfx-proxy.exe",
        #["--stdio", windowsPath tracePath])
  let child ← IO.Process.spawn { cmd := cmd, args := args
                                 stdin := .piped, stdout := .piped, stderr := .inherit
                                 : IO.Process.SpawnArgs }
  let index ← IO.mkRef ({} : IndexState)
  let cache ← IO.mkRef ({} : Jigsaw)
  let dead ← IO.mkRef none
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
    match validateFrontier frontier with
    | .error e => throw (IO.Error.userError e)
    | .ok () => pure ()
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
    pure { child, frontier, skel := skeleton frontier threads events, index, cache, dead
           source := tracePath }
  catch e =>
    try child.kill catch _ => pure ()
    throw e

/-- One `WRITES_INDEX` round trip, merged into the client index. -/
def fetchWindow (ps : ProxySession) (win : IndexWindow) : IO Unit := do
  match ← ps.request (.writesIndex win.vaLo win.vaHi win.t1 win.t2) with
  | .index recs => ps.index.modify fun st => st.mergeWindow win recs ps.frontier
  | _ => throw (IO.Error.userError "proxy protocol error: expected INDEX")

/-- Fetch write metadata for `[va, va+len)` over `[0, frontier]` (one
    window). Pages already known at the frontier are skipped only when the
    whole range is known; the window merge dedups regardless. -/
def ensureRange (ps : ProxySession) (va : VA) (len : UInt64) : IO Unit := do
  match validateAddressRange va len with
  | .error e => throw (IO.Error.userError e)
  | .ok () => pure ()
  if len == 0 then return
  let st ← ps.index.get
  let lastByte := va + (len - 1)
  let pageCount := (pageBaseOf lastByte - pageBaseOf va).toNat / pageSize.toNat + 1
  let allKnown := pageCount ≤ maxMarkPages.toNat
    && (List.range pageCount).all fun i =>
      st.known (pageBaseOf va + UInt64.ofNat (i * pageSize.toNat)) ps.frontier
  if allKnown then return
  ps.fetchWindow { vaLo := va, vaHi := UInt64.ofNat (va.toNat + len.toNat)
                   t1 := 0, t2 := ps.frontier }

/-- Ensure the index knows every page in `pages` (page bases) up to the
    frontier (design D2 dependency rule). Missing pages are fetched as
    consecutive-run windows; beyond `fanoutLimit` pages, one wide window
    `[minBase, maxBase + pageSize)` instead. -/
def ensurePages (ps : ProxySession) (pages : List VA) : IO Unit := do
  for page in pages do
    if pageBaseOf page != page || page.toNat + pageSize.toNat > 2^64 - 1 then
      throw (IO.Error.userError "proxy page is unaligned or has an unsupported exclusive end")
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
  if ps.frontier < t then throw (IO.Error.userError "position beyond frontier")
  ps.ensurePages [page]
  let st ← ps.index.get
  let _ ← fetchPageWith ps.cache st ps.frontier page t (ps.readPageRaw page)
  pure ()

/-- Acquire one page's knowledge, returning fetched evidence independently of
    cache retention. This is the explicit two-phase read used by preparation. -/
def readPageAt (ps : ProxySession) (page : VA) (t : Position) : IO Model.MemoryRead := do
  if ps.frontier < t then throw (IO.Error.userError "position beyond frontier")
  let st ← ps.index.get
  match pageKnowledge (← ps.cache.get) st page t ps.frontier with
  | .known bytes => pure (.known bytes)
  | .absent => pure .absent
  | .unknown =>
    ps.ensurePages [page]
    fetchPageWith ps.cache (← ps.index.get) ps.frontier page t (ps.readPageRaw page)

/-- Run a two-phase action under the session-fatal policy: a dead proxy
    refuses work; a transport/protocol error poisons the session (fail
    closed, never fudge) and surfaces as a command error. -/
def guarded (ps : ProxySession) (k : IO α) : IO (Except String α) := do
  match ← ps.dead.get with
  | some msg => pure (.error s!"proxy session dead: {msg}")
  | none =>
    try
      pure (.ok (← k))
    catch e =>
      ps.dead.set (some (toString e))
      pure (.error s!"proxy error: {e}")

/-- Full-space write index (the fan-out collapse): one window over
    `[0, 2⁶⁴)` × `[0, frontier]`. Merged once; `fullCoverage` makes every
    page known at the frontier without per-page fetches. -/
def ensureFullIndex (ps : ProxySession) : IO Unit := do
  if (← ps.index.get).fullCoverage then return
  ps.fetchWindow { vaLo := 0, vaHi := 0xFFFFFFFFFFFFFFFF, t1 := 0, t2 := ps.frontier }
  ps.index.modify fun st => { st with fullCoverage := true }

/-- Byte at `va` at model position `t` via the jigsaw (two-phase:
    pure gap check → IO fetch → pure answer). -/
def valueAt (ps : ProxySession) (va : VA) (t : Position) : IO (Option UInt8) := do
  if ps.frontier < t then return none
  let page := pageBaseOf va
  match ← ps.readPageAt page t with
  | .known bytes =>
    let off := (va - page).toNat
    pure (if off < bytes.size then some (bytes.get! off) else none)
  | _ => pure none

/-- Writes overlapping `[va, va+len)` in `(t1, t2]` (two-phase: index
    window fetch, then the pure filter). -/
def writesBetween (ps : ProxySession) (va : VA) (len : UInt64) (t1 t2 : Position) :
    IO (List Model.WriteRecord) := do
  match validateWriteQuery ps.frontier va len t1 t2 with
  | .error e => throw (IO.Error.userError e)
  | .ok () => pure ()
  if t1 == t2 || len == 0 then return []
  ps.ensureRange va len
  pure ((← ps.index.get).writesBetween va len t1 t2)

/-- Resolve a write record's payload through the cache (design risk 5:
    lazy records stay metadata-only, one truth source). Payload-backed
    records return their data. Absent pages fail closed (`none`); a
    fallback piece (page state after a later write) is used only when no
    known write in between overlaps the needed bytes (the overlap guard,
    Implementation notes). Capped at 4096 pages per record. -/
def writeBytes (ps : ProxySession) (w : Model.WriteRecord) : IO (Option ByteArray) := do
  if w.len == 0 then return some w.data
  if ps.frontier ≤ w.pos then return none
  let endVa := w.endVaNat
  if endVa ≤ w.va.toNat then return none
  let firstPage := pageBaseOf w.va
  let pageCount := (endVa - 1 - firstPage.toNat) / pageSize.toNat + 1
  if pageCount > 4096 then return none
  let mut out := ByteArray.empty
  for i in [:pageCount] do
    let pbase := firstPage + UInt64.ofNat (i * pageSize.toNat)
    let subLo := max w.va.toNat pbase.toNat
    let subHi := min endVa (pbase.toNat + pageSize.toNat)
    ps.fetchPage pbase w.pos
    -- Fetching this page may have discovered writes needed by the fallback
    -- overlap check; inspect the updated index, never the pre-fetch snapshot.
    let st ← ps.index.get
    match (← ps.cache.get).pieces[pbase]? with
    | none => return none
    | some pc =>
      let sliceFrom (bytes : ByteArray) :=
        bytes.extract (subLo - pbase.toNat) (subHi - pbase.toNat)
      if pc.present && decide (pc.lo ≤ w.pos) && decide (w.pos < pc.hi) then
        out := out ++ sliceFrom pc.bytes
      else if pc.present && decide (w.pos ≤ pc.lo) then
        let conflict := st.records.any fun wr =>
          wr.overlapsPage pbase && decide (w.pos < wr.pos) && decide (wr.pos ≤ pc.lo)
            && decide (wr.va.toNat < subHi) && decide (subLo < wr.endVaNat)
        if conflict then return none
        out := out ++ sliceFrom pc.bytes
      else return none
  pure (some out)

/-- Cache-only point view: reads references and eager metadata, issuing no
    index or page request. Positive absence and unknown bytes remain distinct. -/
def viewAt (ps : ProxySession) (t : Position) : IO (Option Model.AnalysisInput) := do
  if ps.frontier < t then return none
  let st ← ps.index.get
  let cache ← ps.cache.get
  pure (executionView ps.skel ps.source t st cache
    (cachedMaterialization cache st t ps.frontier))

/-- Explicit targeted preparation. All ranges are validated before IO; only
    their page indexes are discovered. Already observed pages are retained in
    the result even if acquiring the request evicts them from the cache. -/
def materializeRanges (ps : ProxySession) (t : Position)
    (ranges : List Model.AddressRange) : IO (Option Model.AnalysisInput) := do
  if ps.frontier < t then return none
  let pages ← match requestedPages ranges with
    | .ok pages => pure pages
    | .error e => throw (IO.Error.userError e)
  let initial := cachedMaterialization (← ps.cache.get) (← ps.index.get) t ps.frontier
  ps.ensurePages pages
  let result ← collectPages pages (fun page => ps.readPageAt page t) initial
  pure (executionView ps.skel ps.source t (← ps.index.get) (← ps.cache.get) result)

/-- Explicit batch-analyzer preparation: discover the write-touched closure
    through `t` and retain already probed evidence. This is a partial discovery
    policy, never a claim that untouched memory is absent. -/
def prepareAnalysisAt (ps : ProxySession) (t : Position) :
    IO (Option Model.AnalysisInput) := do
  if ps.frontier < t then return none
  ps.ensureFullIndex
  let st ← ps.index.get
  let initial := cachedMaterialization (← ps.cache.get) st t ps.frontier
  let result ← collectPages (st.closurePages t) (fun page => ps.readPageAt page t) initial
  pure (executionView ps.skel ps.source t (← ps.index.get) (← ps.cache.get) result)

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

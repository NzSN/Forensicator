/- Forensicator.Session — interactive session REPL (session.rs port).
   Loads a dump or trace once, then dispatches inspect/analyze/match/
   list-plugins/load/symbols/seek/forward/back/position/writes/intervals/quit.

   Known parity boundary: clap's auto-generated `help`/error text is not
   reproduced (our parser prints a simpler usage error).
   Error-path text (F9) is intentionally ungated: `error: …` messages for
   missing files / bad flags are emitted by our CLI in its own wording and
   never diffed against the Rust binary's `error: {e}` output. -/
import Forensicator.Model.Trace
import Forensicator.Model.Capture
import Forensicator.Parse.Minidump
import Forensicator.Pipeline
import Forensicator.Util.Image
import Forensicator.Util.Bytes
import Forensicator.Util.Pdb
import Forensicator.Analyzer.Analyzer
import Forensicator.Trace.Client
import Std.Data.HashSet

namespace Forensicator

open Model Parse Spec

/-- What the session is pointed at. -/
inductive Target where
  | dump (s1 : Dump × AddressSpace × DumpKind) (images : Nat)
  | trace (t : Model.Trace) (cursor : Position)

structure Session where
  path : String
  target : Target
  symbols : Option String
  /-- The live proxy when `target` is a lazy trace (plan §C5). -/
  proxy : Option Trace.ProxySession := none

private def hexDigitsU (v : UInt64) : String :=
  String.ofList ((Nat.toDigits 16 v.toNat).map fun c => if c.isAlpha then c.toUpper else c)

/-- basename for the banner/prompt. -/
def Session.baseName (p : String) : String :=
  let parts := p.splitOn "/" |>.flatMap (·.splitOn "\\")
  (parts.filter (!·.isEmpty)).getLast?.getD p

/-- Discover on-disk images for dump modules (session.rs supplement_images). -/
private def supplement (dump : Dump) (space : AddressSpace) (path : String) :
    IO (AddressSpace × Nat) := do
  let dir := (System.FilePath.parent path).map (·.toString) |>.getD "."
  let mut images : Util.ImageSet := ⟨[]⟩
  for m in dump.modules do
    let fname := Session.baseName m.name
    if fname.isEmpty then continue
    let candidate := dir ++ "/" ++ fname
    if ← System.FilePath.pathExists candidate then
      let bytes ← IO.FS.readBinFile candidate
      match Util.ImageFile.fromBytes bytes m.baseVa with
      | .ok img => images := ⟨images.images ++ [img]⟩
      | .error _ => pure ()
  pure (if images.images.isEmpty then space else space.setBacking images,
        images.images.length)

/-- Open a dump or trace (magic sniff). Trace support is proxy-only since
    the .ttfx v1 format was removed (2026-08-13); a `.ttfx` fails here with
    an explicit error and never falls through to the minidump decoder.
    `openProxy` (below) constructs `.trace` sessions from the proxy. -/
def Session.open (path : String) (symbols : Option String) : IO Session := do
  let head ← IO.FS.withFile path .read fun h => h.read 4
  if head.size ≥ 4 && readU32leAt head 0 == 0x58465454 then
    throw (IO.Error.userError "ttfx removed: trace support is proxy-only (use load --proxy / shell --proxy)")
  else
    let data ← IO.FS.readBinFile path
    match Minidump.fromBytes data with
    | .error f => throw (IO.Error.userError f.render)
    | .ok dump =>
      let (space, images) ← supplement dump (buildAddressSpace dump) path
      pure { path := path
             target := .dump (dump, space, classifyDump dump) images
             symbols := symbols }

/-- Attach to a trace through the lazy proxy (plan §C5): spawn +
    handshake, then a `Target.trace` over the eager skeleton. Memory and
    the write index fill lazily (two-phase commands). -/
def Session.openProxy (path : String) (symbols : Option String) : IO Session := do
  let ps ← Trace.ProxySession.spawn path
  pure { path := path, target := .trace ps.skel 0, symbols := symbols
         proxy := some ps }

/-- Close the proxy if this session holds one. -/
def Session.closeProxy (s : Session) : IO Unit := do
  match s.proxy with
  | some ps => ps.close
  | none => pure ()

private def kindStr : DumpKind → String
  | .FullMemory => "full-memory" | .StackOnly => "stack-only"

def Session.banner (s : Session) : String :=
  match s.target with
  | .dump (_, _, kind) images =>
    s!"{Session.baseName s.path}: {kindStr kind}, {images} image(s) supplemented, symbols: {s.symbols.getD "<none>"}"
  | .trace t _ =>
    match s.proxy with
    | some _ =>
      s!"{Session.baseName s.path}: trace (lazy via proxy), frontier {hexUpper t.frontier}, {t.threads.length} threads, {t.events.length} events, symbols: {s.symbols.getD "<none>"}"
    | none =>
      s!"{Session.baseName s.path}: trace, frontier {hexUpper t.frontier}, {t.writes.length} writes, {t.events.length} events, symbols: {s.symbols.getD "<none>"}"

def Session.prompt (s : Session) : String :=
  match s.target with
  | .dump _ _ => s!"forensicator[{Session.baseName s.path}]> "
  | .trace t cursor =>
    s!"forensicator[{Session.baseName s.path} @ {hexUpper cursor}/{hexUpper t.frontier}]> "

/-- Pure execution input for captures and in-memory traces. Live proxy views
    use `currentIO` so the result reflects current knowledge. -/
def Session.current (s : Session) : Except String AnalysisInput :=
  match s.target with
  | .dump (dump, space, _) _ => .ok (AnalysisInput.ofDump dump space s.path)
  | .trace t cursor =>
    if s.proxy.isSome then .error "lazy trace requires currentIO"
    else match t.analysisAt cursor s.path with
    | none => .error "cursor out of recorded range"
    | some input => .ok input

/-- Obtain currently known execution state without discovering/fetching pages. -/
def Session.currentIO (s : Session) : IO (Except String AnalysisInput) := do
  match s.target, s.proxy with
  | .trace _ cursor, some ps =>
    if cursor > ps.frontier then return .error "cursor out of recorded range"
    match (← ps.guarded (do
        match ← ps.viewAt cursor with
        | some input => pure input
        | none => throw (IO.Error.userError "cursor out of recorded range"))) with
    | .ok r => pure (.ok r)
    | .error e => pure (.error e)
  | _, _ => pure (s.current)

/-- Batch analysis explicitly prepares touched/probed memory. The resulting
    view remains partial; untouched memory is not thereby known absent. -/
def Session.prepareAnalysis (s : Session) : IO (Except String AnalysisInput) := do
  match s.target, s.proxy with
  | .trace _ cursor, some ps =>
    if cursor > ps.frontier then return .error "cursor out of recorded range"
    ps.guarded (do
      match ← ps.prepareAnalysisAt cursor with
      | some input => pure input
      | none => throw (IO.Error.userError "cursor out of recorded range"))
  | _, _ => pure s.current

/-- Explicit targeted acquisition. Validate user bounds before the transport
    guard so an invalid address cannot poison an otherwise usable session. -/
def Session.readMemory (s : Session) (va : VA) (len : UInt64) :
    IO (Except String MemoryRead) := do
  if va.toNat + len.toNat > 2^64 then return .error "address range overflows"
  if len == 0 then return .ok (.known ByteArray.empty)
  match s.target, s.proxy with
  | .trace _ cursor, some ps =>
    if cursor > ps.frontier then return .error "cursor out of recorded range"
    match Trace.requestedPages [⟨va, len⟩] with
    | .error e => return .error e
    | .ok _ => pure ()
    ps.guarded (do
      match ← ps.materializeRanges cursor [⟨va, len⟩] with
      | none => throw (IO.Error.userError "cursor out of recorded range")
      | some input => pure (input.point.memory.read va len.toNat))
  | _, _ => pure (s.current.map fun input => input.point.memory.read va len.toNat)

/-- Split a command line into argv, honoring double quotes. -/
def Session.tokenize (line : String) : List String :=
  let rec go (cs : List Char) (cur : List Char) (inQ : Bool) (acc : List String) : List String :=
    match cs with
    | [] =>
      let acc' := if cur.isEmpty && !inQ then acc else acc ++ [String.ofList cur.reverse]
      acc'
    | c :: rest =>
      if c == '"' then go rest cur (!inQ) acc
      else if c.isWhitespace && !inQ then
        if cur.isEmpty then go rest cur inQ acc
        else go rest [] inQ (acc ++ [String.ofList cur.reverse])
      else go rest (c :: cur) inQ acc
  go line.toList [] false []

-- ── symbol context (design §W2.3) ─────────────────────────────────────

/-- The module owning the exception address (the crashed module); the
    first loaded module when no exception is recorded. -/
def Session.crashModule (input : AnalysisInput) : Option Module :=
  match input.exception with
  | some exc =>
    match input.modules.filter (fun m =>
      decide (m.baseVa.toNat ≤ exc.address.toNat
        ∧ exc.address.toNat < m.baseVa.toNat + m.size.toNat)) with
    | [m] => some m
    | _ => none
  | none =>
    if (input.point.events.filterMap ExecutionEvent.exceptionInfo).length > 1
      then none else input.modules.head?

/-- Candidate PDB paths in `dir` for a module: the module's own
    pdb_name basename first, then its image basename with the `.exe`
    extension swapped for `.pdb`. -/
private def pdbCandidates (dir : String) (m : Module) : List String :=
  (match m.pdbName with
   | some p => [dir ++ "/" ++ Session.baseName p]
   | none => []) ++
  [dir ++ "/" ++ (let n := Session.baseName m.name
                   let stem := if n.endsWith ".exe" then
                     n.toList.reverse.drop 4 |>.reverse |>.asString else n
                   stem ++ ".pdb")]

/-- The raw S_PUB32 walk of a PDB (stream 3 DBI → symbol record stream),
    shared by the publics CLI probe and the symbol context loader. IO
    lives in Main/Session; Analyzer stays pure. -/
def Session.publicRecordsFromPdb (pdb : String)
    : IO (Except String (Array Util.PublicRecord)) := do
  match ← Util.MsfHandle.open pdb with
  | .error e => pure (.error e)
  | .ok msf =>
    match ← Util.MsfHandle.stream msf 3 with
    | .error e => pure (.error e)
    | .ok dbiBytes =>
      match Util.parseDbiHeader dbiBytes with
      | none => pure (.error "PDB: stream 3 is not a DBI stream")
      | some dbi =>
        match ← Util.MsfHandle.stream msf dbi.symRecordStream.toNat with
        | .error e => pure (.error e)
        | .ok symBytes =>
          match Util.walkPublicRecords symBytes with
          | none => pure (.error "PDB: malformed symbol record stream")
          | some recs => pure (.ok recs)

/-- Load the publics table (segment-1 fallback mapping, design §W2.2) for
    a PDB path. -/
def Session.loadPublicsFromPdb (pdb : String) : IO (Except String Util.Publics) := do
  match ← Session.publicRecordsFromPdb pdb with
  | .error e => pure (.error e)
  | .ok recs => pure (.ok (Util.Publics.ofRecords recs none))

/-- Build the symbol context for the current execution input: with
    `--symbols <dir>`, pick the crashed module's PDB — its pdb_name
    basename, else its image basename with the extension swapped to `.pdb`
    — that exists in `dir`, verify the identity (age + GUID via
    pdbIdentity against the module's CodeView record), and load Publics
    once. Any failure — no dir, no module, no candidate, identity
    mismatch, malformed PDB, I/O error — yields `{ publics := none }` and
    analyzers behave exactly as today (fail closed). -/
def Session.loadSymbolsCtxFor (input : AnalysisInput) (dir : Option String) : IO SymbolsCtx := do
  match dir with
  | none => pure { publics := none }
  | some dir =>
    match Session.crashModule input with
    | none => pure { publics := none }
    | some m =>
      let mut out : Option Util.Publics := none
      for cand in pdbCandidates dir m do
        if out.isSome then break
        if ← System.FilePath.pathExists cand then
          try do
            let bytes ← IO.FS.readBinFile cand
            match Util.pdbIdentity bytes with
            | .ok (age, guid) =>
              let ageOk := (m.codeviewAge.map fun a => a == age).getD false
              let guidOk := (m.codeviewGuid.map fun g => g.data == guid.data).getD false
              if ageOk && guidOk then
                match ← Session.loadPublicsFromPdb cand with
                | .ok pubs => out := some pubs
                | .error _ => pure ()
            | .error _ => pure ()
          catch _ => pure ()
      pure { publics := out, moduleBase := if out.isSome then some m.baseVa else none }

end Forensicator

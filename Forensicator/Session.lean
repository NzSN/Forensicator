/- Forensicator.Session — interactive session REPL (session.rs port).
   Loads a dump or trace once, then dispatches inspect/analyze/match/
   list-plugins/load/symbols/seek/forward/back/position/writes/intervals/quit.

   Known parity boundary: clap's auto-generated `help`/error text is not
   reproduced (our parser prints a simpler usage error).
   Error-path text (F9) is intentionally ungated: `error: …` messages for
   missing files / bad flags are emitted by our CLI in its own wording and
   never diffed against the Rust binary's `error: {e}` output. -/
import Forensicator.Model.Trace
import Forensicator.Parse.Minidump
import Forensicator.Parse.Ttfx
import Forensicator.Pipeline
import Forensicator.Util.Image
import Forensicator.Util.Bytes
import Std.Data.HashSet

namespace Forensicator

open Model Parse Spec

/-- What the session is pointed at. -/
inductive Target where
  | dump (s1 : Dump × AddressSpace × DumpKind) (images : Nat)
  | trace (t : Trace) (cursor : Position)

structure Session where
  path : String
  target : Target
  symbols : Option String

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

/-- Open a dump or trace (magic sniff). -/
def Session.open (path : String) (symbols : Option String) : IO Session := do
  let head ← IO.FS.withFile path .read fun h => h.read 4
  if head.size ≥ 4 && readU32leAt head 0 == TTFX_MAGIC then
    let data ← IO.FS.readBinFile path
    match decodeTtfx data with
    | .error a => throw (IO.Error.userError a.description)
    | .ok t =>
      for a in t.anomalies do
        IO.eprintln s!"warning: [stream 0x{hexPadUpper a.streamType.toUInt64 8} @ +{hexUpper a.fileOffset}] {a.description}"
      pure { path := path, target := .trace t t.frontier, symbols := symbols }
  else
    let data ← IO.FS.readBinFile path
    match Minidump.fromBytes data with
    | .error f => throw (IO.Error.userError f.render)
    | .ok dump =>
      let (space, images) ← supplement dump (buildAddressSpace dump) path
      pure { path := path
             target := .dump (dump, space, classifyDump dump) images
             symbols := symbols }

private def kindStr : DumpKind → String
  | .FullMemory => "full-memory" | .StackOnly => "stack-only"

def Session.banner (s : Session) : String :=
  match s.target with
  | .dump (_, _, kind) images =>
    s!"{Session.baseName s.path}: {kindStr kind}, {images} image(s) supplemented, symbols: {s.symbols.getD "<none>"}"
  | .trace t _ =>
    s!"{Session.baseName s.path}: trace, frontier {hexUpper t.frontier}, {t.writes.length} writes, {t.events.length} events, symbols: {s.symbols.getD "<none>"}"

def Session.prompt (s : Session) : String :=
  match s.target with
  | .dump _ _ => s!"forensicator[{Session.baseName s.path}]> "
  | .trace t cursor =>
    s!"forensicator[{Session.baseName s.path} @ {hexUpper cursor}/{hexUpper t.frontier}]> "

/-- The (Dump, AddressSpace) view commands consume. -/
def Session.current (s : Session) : Except String (Dump × AddressSpace) :=
  match s.target with
  | .dump (dump, space, _) _ => .ok (dump, space)
  | .trace t cursor =>
    match t.snapshot cursor with
    | none => .error "cursor out of recorded range"
    | some snap => .ok (snap.dump, snap.space)

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

end Forensicator

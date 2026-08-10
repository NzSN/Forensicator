/- forensicator (Lean) — CLI. Task 4 scope: the `trace` subcommand
   (summary, pos snapshot, writes query, json), Rust-CLI-compatible. -/
import Forensicator

open Forensicator Forensicator.Parse Forensicator.Model

private def byteListJson (bs : ByteArray) : Json :=
  .arr (bs.toList.map fun b => .int b.toNat)

private def writeHitJson (w : WriteRecord) : Json :=
  .obj [("pos", .str (hexUpper w.pos)), ("va", .str (hexUpper w.va)),
        ("end_va", .str (hexUpper (UInt64.ofNat (min w.endVaNat (2^64 - 1))))),
        ("data", byteListJson w.data)]

private def byteDebug (bs : ByteArray) : String :=
  "[" ++ String.intercalate ", " (bs.toList.map fun b => hexPadUpper b.toUInt64 2) ++ "]"

private def traceJson (tr : Trace) (pos : Position) (writes : Option (UInt64 × UInt64)) : Json :=
  let writeHits : Json := match writes with
    | some (va, len) =>
      .arr ((tr.writesBetween va len 0 pos).map writeHitJson)
    | none => .null
  .obj [
    ("frontier", .str (hexUpper tr.frontier)),
    ("position", .str (hexUpper pos)),
    ("init_regions", .ofNat tr.initMem.length),
    ("writes", .ofNat tr.writes.length),
    ("events", .ofNat tr.events.length),
    ("threads", .ofNat tr.threads.length),
    ("calls", .ofNat tr.calls.length),
    ("anomalies", .arr (tr.anomalies.map fun a => .str a.description)),
    ("write_hits", writeHits)]

private def anomalyDisplay (a : Anomaly) : String :=
  s!"[stream 0x{hexPadUpper a.streamType.toUInt64 8} @ +{hexUpper a.fileOffset}] {a.description}"

private def intervalEnd : Option Position → String
  | some e => hexUpper e
  | none => "open"

private def cmdTrace (path : String) (posArg : Option String) (writesArg : List String)
    (json : Bool) : IO UInt32 := do
  let data ← IO.FS.readBinFile path
  match decodeTtfx data with
  | .error a => IO.eprintln a.description; pure 1
  | .ok tr =>
    let pos ← match posArg with
      | some p =>
        match parseU64 p with
        | .ok v => pure v
        | .error e => IO.eprintln e; throw (IO.Error.userError e)
      | none => pure tr.frontier
    let writes ←
      match writesArg with
      | [a, b] =>
        match parseU64 a, parseU64 b with
        | .ok va, .ok len => pure (some (va, len))
        | .error e, _ | _, .error e => IO.eprintln e; throw (IO.Error.userError e)
      | [] => pure none
      | _ => pure none  -- json: silently None; text: handled below
    if json then
      IO.println (Json.render (traceJson tr pos writes))
      return 0
    -- text output
    IO.println s!"Trace: frontier {hexUpper tr.frontier}, {tr.initMem.length} init region(s), {tr.writes.length} write(s), {tr.events.length} event(s), {tr.threads.length} thread(s), {tr.calls.length} call(s)"
    for a in tr.anomalies do
      IO.println s!"  anomaly: {anomalyDisplay a}"
    for (id, iv) in tr.threads do
      IO.println s!"  thread {id}: [{hexUpper iv.start}, {intervalEnd iv.stop})"
    for c in tr.calls do
      IO.println s!"  call on {c.threadId}: [{hexUpper c.interval.start}, {intervalEnd c.interval.stop})"
    match writesArg with
    | [_, _] =>
      let some (va, len) := writes | unreachable!
      let hits := tr.writesBetween va len 0 pos
      IO.println s!"writes to [{hexUpper va}, {hexUpper (va + len)}) up to {hexUpper pos}: {hits.length}"
      let last := tr.lastWriter va pos
      for w in hits do
        let marker := match last with
          | some lw => if lw.pos == w.pos && lw.va == w.va && lw.data == w.data
              then "  <-- last writer" else ""
          | none => ""
        IO.println s!"  @{hexUpper w.pos}  [{hexUpper w.va}, {hexUpper (UInt64.ofNat (min w.endVaNat (2^64-1)))})  {byteDebug w.data}{marker}"
    | [] => pure ()
    | _ => IO.eprintln "--writes takes exactly two values: <va> <len>"; throw (IO.Error.userError "writes arity")
    if pos != tr.frontier || writesArg.isEmpty then
      match tr.snapshot pos with
      | none =>
        IO.eprintln s!"position {hexUpper pos} beyond frontier {hexUpper tr.frontier}"
        pure 1
      | some snap =>
        IO.println s!"snapshot @ {hexUpper pos}: {snap.dump.memoryRegions.length} region(s), {snap.dump.modules.length} module(s), exception: {snap.dump.exception.isSome}"
        pure 0
    else pure 0

private def usage : IO UInt32 := do
  IO.eprintln "usage: forensicator trace <file.ttfx> [--json] [--pos P] [--writes va len]"
  pure 2

def main (args : List String) : IO UInt32 := do
  match args with
  | "trace" :: rest =>
    let rec parse (path : Option String) (pos : Option String) (writes : List String) (json : Bool)
        : List String → Except String (Option String × Option String × List String × Bool)
      | [] => .ok (path, pos, writes, json)
      | "--json" :: rest => parse path pos writes true rest
      | "--pos" :: p :: rest => parse path (some p) writes json rest
      | "--writes" :: a :: b :: rest => parse path pos [a, b] json rest
      | x :: rest =>
        if x.startsWith "-" then .error s!"unknown flag {x}"
        else parse (some x) pos writes json rest
    match parse none none [] false rest with
    | .error e => IO.eprintln e; usage
    | .ok (some path, pos, writes, json) => cmdTrace path pos writes json
    | .ok (none, _, _, _) => usage
  | _ => usage

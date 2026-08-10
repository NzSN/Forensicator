/- Forensicator.Parse.Ttfx — .ttfx v1 decoder (port of parse/ttfx.rs).

   Wire format (little-endian):
     header (32 B): magic "TTFX" u32, version u32, flags u32,
                    section_cnt u32, frontier u64, reserved u64
     per section: kind u32, record_size u32, record_cnt u64, then records
     sections: 1=INITMEM(32B) 2=WRITES(24B) 3=EVENTS(48B) 4=THREADS(24B) 5=CALLS(24B)
     payloads live in a pool after all sections, referenced by absolute u32 offset.

   Hard error only on bad magic / short header / unsupported version;
   everything else degrades into `Trace.anomalies` (fail-closed), with the
   Timeline.tla invariants checked at decode time. -/
import Forensicator.Model.Trace
import Forensicator.Util.Text

namespace Forensicator.Parse

def TTFX_MAGIC : UInt32 := 0x58465454
def TTFX_VERSION : UInt32 := 1

private def HEADER_SIZE : Nat := 32
private def SECTION_HDR_SIZE : Nat := 16

private def SEC_INITMEM : UInt32 := 1
private def SEC_WRITES : UInt32 := 2
private def SEC_EVENTS : UInt32 := 3
private def SEC_THREADS : UInt32 := 4
private def SEC_CALLS : UInt32 := 5

private def OPEN_END : UInt64 := 0xFFFFFFFFFFFFFFFF

open Model (Trace TraceEvent TraceEventKind WriteRecord Interval CallSpan MemoryRegionInfo)

private def prov (fileOffset : Nat) : Provenance :=
  { streamType := Model.TTFX_STREAM_TYPE, fileOffset := UInt64.ofNat fileOffset, rva := 0 }

private def anom (fileOffset : Nat) (description : String) : Anomaly :=
  { streamType := Model.TTFX_STREAM_TYPE, fileOffset := UInt64.ofNat fileOffset
    rva := 0, description := description }

private def u32At (data : ByteArray) (off : Nat) : Option UInt32 :=
  if off + 4 ≤ data.size then
    some ((data.get! off).toUInt32
      ||| ((data.get! (off + 1)).toUInt32 <<< 8)
      ||| ((data.get! (off + 2)).toUInt32 <<< 16)
      ||| ((data.get! (off + 3)).toUInt32 <<< 24))
  else none

private def u64At (data : ByteArray) (off : Nat) : Option UInt64 :=
  if off + 8 ≤ data.size then
    some ((data.get! off).toUInt64
      ||| ((data.get! (off + 1)).toUInt64 <<< 8)
      ||| ((data.get! (off + 2)).toUInt64 <<< 16)
      ||| ((data.get! (off + 3)).toUInt64 <<< 24)
      ||| ((data.get! (off + 4)).toUInt64 <<< 32)
      ||| ((data.get! (off + 5)).toUInt64 <<< 40)
      ||| ((data.get! (off + 6)).toUInt64 <<< 48)
      ||| ((data.get! (off + 7)).toUInt64 <<< 56))
  else none

/-- `data.get(off .. off+len).unwrap_or(&[])` — full slice or empty. -/
private def sliceExact (data : ByteArray) (off len : Nat) : ByteArray :=
  if off + len ≤ data.size then data.extract off (off + len) else ByteArray.empty

private def decodeInitmem (data : ByteArray) (tr : Trace) (off : Nat) : Trace :=
  let va := (u64At data off).getD 0
  let size := (u64At data (off + 8)).getD 0
  let prot := (u32At data (off + 16)).getD 0
  let state := MemState.ofUInt32 ((u32At data (off + 20)).getD 0) |>.getD .Commit
  let memType := MemType.ofUInt32 ((u32At data (off + 24)).getD 0) |>.getD .Private
  let dataOff := ((u32At data (off + 28)).getD 0).toNat
  let payload := sliceExact data dataOff size.toNat
  let payloadAnoms :=
    if payload.size < size.toNat then
      [anom off s!"ttfx: initmem region at {hexUpper va} truncated payload"]
    else []
  let region : MemoryRegionInfo :=
    { vaStart := va, size := size, data := payload, protection := prot
      state := state, memType := memType, provenance := prov off
      regionClass := some .Private }
  { tr with
    initMem := tr.initMem ++ [region]
    anomalies := tr.anomalies ++ payloadAnoms }

private def decodeWrite (data : ByteArray) (frontier : Position) (tr : Trace) (off : Nat) : Trace :=
  let pos := (u64At data off).getD 0
  let va := (u64At data (off + 8)).getD 0
  let len := ((u32At data (off + 16)).getD 0).toNat
  let dataOff := ((u32At data (off + 20)).getD 0).toNat
  let payload := sliceExact data dataOff len
  let a1 :=
    if payload.size < len then [anom off "ttfx: write truncated payload"] else []
  let a2 := match tr.writes.getLast? with
    | some last =>
      if pos < last.pos then
        [anom off s!"ttfx: write out of order (pos {hexUpper pos} < {hexUpper last.pos})"]
      else []
    | none => []
  let a3 :=
    if frontier < pos then [anom off s!"ttfx: write beyond frontier (pos {hexUpper pos})"] else []
  { tr with
    writes := tr.writes ++ [{ pos := pos, va := va, data := payload, provenance := prov off }]
    anomalies := tr.anomalies ++ a1 ++ a2 ++ a3 }

private def decodeEvent (data : ByteArray) (frontier : Position) (tr : Trace) (off : Nat) : Trace :=
  let pos := (u64At data off).getD 0
  let kindRaw := (u32At data (off + 8)).getD 0
  if kindRaw == 0 || kindRaw == 1 || kindRaw == 2 then
    let kind : TraceEventKind :=
      if kindRaw == 0 then .Exception else if kindRaw == 1 then .ModuleLoad else .ModuleUnload
    let code := (u32At data (off + 12)).getD 0
    let address := (u64At data (off + 16)).getD 0
    let threadId := (u32At data (off + 24)).getD 0
    let size := (u64At data (off + 28)).getD 0
    let nameLen := ((u32At data (off + 36)).getD 0).toNat
    let nameOff := ((u32At data (off + 40)).getD 0).toNat
    let name := fromUTF8Lossy (sliceExact data nameOff nameLen)
    let a1 := match tr.events.getLast? with
      | some last =>
        if pos < last.pos then
          [anom off s!"ttfx: event out of order (pos {hexUpper pos} < {hexUpper last.pos})"]
        else []
      | none => []
    let a2 :=
      if frontier < pos then [anom off s!"ttfx: event beyond frontier (pos {hexUpper pos})"] else []
    let ev : TraceEvent :=
      { pos := pos, kind := kind, code := code, address := address
        threadId := threadId, name := name, size := size, provenance := prov off }
    { tr with
      events := tr.events ++ [ev]
      anomalies := tr.anomalies ++ a1 ++ a2 }
  else
    { tr with anomalies := tr.anomalies ++ [anom off s!"ttfx: unknown event kind {kindRaw}"] }

private def decodeInterval (data : ByteArray) (off : Nat) : UInt32 × Interval :=
  let threadId := (u32At data off).getD 0
  let start := (u64At data (off + 8)).getD 0
  let endRaw := (u64At data (off + 16)).getD 0
  (threadId, { start := start, stop := if endRaw == OPEN_END then none else some endRaw })

private def decodeThread (data : ByteArray) (tr : Trace) (off : Nat) : Trace :=
  let (id, iv) := decodeInterval data off
  let a1 := match iv.stop with
    | some e =>
      if e < iv.start then
        [anom off s!"ttfx: thread {id} interval inverted ({hexUpper iv.start} > {hexUpper e})"]
      else []
    | none => []
  { tr with threads := tr.threads ++ [(id, iv)], anomalies := tr.anomalies ++ a1 }

private def decodeCall (data : ByteArray) (tr : Trace) (off : Nat) : Trace :=
  let (threadId, iv) := decodeInterval data off
  { tr with calls := tr.calls ++ [{ threadId := threadId, interval := iv }] }

private def wantSize (kind : UInt32) : Option Nat :=
  if kind == SEC_INITMEM then some 32
  else if kind == SEC_WRITES then some 24
  else if kind == SEC_EVENTS then some 48
  else if kind == SEC_THREADS || kind == SEC_CALLS then some 24
  else none

private def decodeRecord (data : ByteArray) (frontier : Position) (tr : Trace)
    (kind : UInt32) (off : Nat) : Trace :=
  if kind == SEC_INITMEM then decodeInitmem data tr off
  else if kind == SEC_WRITES then decodeWrite data frontier tr off
  else if kind == SEC_EVENTS then decodeEvent data frontier tr off
  else if kind == SEC_THREADS then decodeThread data tr off
  else decodeCall data tr off

private def decodeSection (data : ByteArray) (frontier : Position) (tr : Trace)
    (kind : UInt32) (body recordSize recordCnt : Nat) : Trace :=
  match wantSize kind with
  | none => tr
  | some want =>
    if recordSize != want then
      { tr with anomalies := tr.anomalies ++
          [anom body s!"ttfx: section {kind} record_size {recordSize} != {want}"] }
    else
      let rec loop (tr : Trace) (i : Nat) : Trace :=
        if h : i < recordCnt then
          let off := body + i * recordSize
          if off + recordSize > data.size then
            { tr with anomalies := tr.anomalies ++
                [anom off s!"ttfx: truncated section {kind} at record {i}"] }
          else loop (decodeRecord data frontier tr kind off) (i + 1)
        else tr
      termination_by recordCnt - i
      loop tr 0

/-- Cross-record invariants (CallNesting, CallsWithinThreads). -/
private def validateIntervals (tr : Trace) : Trace :=
  let calls := tr.calls
  calls.zipIdx.foldl (init := tr) fun tr (c, i) =>
    let tr :=
      match tr.threads.find? fun (id, _) => id == c.threadId with
      | none =>
        { tr with anomalies := tr.anomalies ++
            [(anom 0 s!"ttfx: call on unknown thread {c.threadId}") ] }
      | some (_, tiv) =>
        let outside := decide (c.interval.start < tiv.start)
          || (match (c.interval.stop, tiv.stop) with
              | (some ce, some te) => decide (te < ce)
              | _ => false)
        if outside then
          { tr with anomalies := tr.anomalies ++
              [(anom 0 s!"ttfx: call outside thread {c.threadId} lifetime") ] }
        else tr
    calls.zipIdx.foldl (init := tr) fun tr (o, j) =>
      if i == j || o.threadId != c.threadId then tr
      else
        match c.interval.stop, o.interval.stop with
        | some ce, some oe =>
          let cs := c.interval.start
          let os := o.interval.start
          let disjoint := decide (ce ≤ os) || decide (oe ≤ cs)
          let nested := (decide (cs ≤ os) && decide (oe ≤ ce))
            || (decide (os ≤ cs) && decide (ce ≤ oe))
          if !disjoint && !nested then
            { tr with anomalies := tr.anomalies ++
                [(anom 0 s!"ttfx: crossing call spans on thread {c.threadId}") ] }
          else tr
        | _, _ => tr

/-- Decode a .ttfx file into a Trace. Hard error only on truncated header,
    bad magic, or unsupported version; everything else → anomalies. -/
def decodeTtfx (data : ByteArray) : Except Anomaly Trace := do
  if data.size < HEADER_SIZE then throw (anom 0 "ttfx: truncated header")
  if u32At data 0 != some TTFX_MAGIC then throw (anom 0 "ttfx: bad magic")
  let version := (u32At data 4).getD 0
  if version != TTFX_VERSION then throw (anom 4 s!"ttfx: unsupported version {version}")
  let sectionCnt := ((u32At data 12).getD 0).toNat
  let frontier := (u64At data 16).getD 0
  let rec sectionLoop (tr : Trace) (remaining : Nat) (off : Nat) : Trace :=
    match remaining with
    | 0 => tr
    | n + 1 =>
      match u32At data off with
      | none =>
        { tr with anomalies := tr.anomalies ++ [anom off "ttfx: truncated section table"] }
      | some kind =>
        let recordSize := ((u32At data (off + 4)).getD 0).toNat
        let recordCnt := ((u64At data (off + 8)).getD 0).toNat
        let body := off + SECTION_HDR_SIZE
        let tr' := decodeSection data frontier tr kind body recordSize recordCnt
        sectionLoop tr' n (body + recordSize * recordCnt)
  let tr := sectionLoop { frontier := frontier } sectionCnt HEADER_SIZE
  pure (validateIntervals tr)

/-- LE byte emitters for the encoder. -/
private def pushU32le (buf : ByteArray) (v : UInt32) : ByteArray :=
  (((buf.push v.toUInt8).push (v >>> 8).toUInt8).push (v >>> 16).toUInt8).push (v >>> 24).toUInt8

private def pushU64le (buf : ByteArray) (v : UInt64) : ByteArray :=
  (List.range 8).foldl (fun b i => b.push (v >>> (8 * UInt64.ofNat i)).toUInt8) buf

/-- Serialize a Trace to .ttfx bytes (port of encode_ttfx; used by tests and
    fixture regeneration). All five section headers are always emitted. -/
def encodeTtfx (tr : Trace) : ByteArray := Id.run do
  let im := tr.initMem
  let ws := tr.writes
  let es := tr.events
  let ts := tr.threads
  let cs := tr.calls
  let poolStart := HEADER_SIZE + (SECTION_HDR_SIZE + 32 * im.length)
    + (SECTION_HDR_SIZE + 24 * ws.length) + (SECTION_HDR_SIZE + 48 * es.length)
    + (SECTION_HDR_SIZE + 24 * ts.length) + (SECTION_HDR_SIZE + 24 * cs.length)
  -- payloads, in section order; offsets absolute
  let step (poolStart : Nat) (acc : ByteArray × List Nat) (payload : ByteArray) : ByteArray × List Nat :=
    let (p, offs) := acc
    (p ++ payload, offs ++ [poolStart + p.size])
  let (pool1, imOffs) := im.foldl (fun acc r => step poolStart acc r.data) (ByteArray.empty, [])
  let (pool2, wOffs) := ws.foldl (fun acc w => step poolStart acc w.data) (pool1, [])
  let (pool3, eOffs) := es.foldl (fun acc e => step poolStart acc e.name.toUTF8) (pool2, [])

  let imBody := (im.zip imOffs).foldl (init := ByteArray.empty) fun b (r, off) =>
    pushU32le (pushU32le (pushU32le (pushU32le (pushU64le (pushU64le b r.vaStart) r.size)
      r.protection) r.state.toUInt32) r.memType.toUInt32) (UInt32.ofNat off)
  let wBody := (ws.zip wOffs).foldl (init := ByteArray.empty) fun b (w, off) =>
    let b := pushU64le b w.pos
    let b := pushU64le b w.va
    let b := pushU32le b (UInt32.ofNat w.data.size)
    pushU32le b (UInt32.ofNat off)
  let eBody := (es.zip eOffs).foldl (init := ByteArray.empty) fun b (e, off) =>
    let kindU : UInt32 := match e.kind with
      | .Exception => 0 | .ModuleLoad => 1 | .ModuleUnload => 2
    let b := pushU64le b e.pos
    let b := pushU32le b kindU
    let b := pushU32le b e.code
    let b := pushU64le b e.address
    let b := pushU32le b e.threadId
    let b := pushU64le b e.size
    let b := pushU32le b (UInt32.ofNat e.name.toUTF8.size)
    let b := pushU32le b (UInt32.ofNat off)
    pushU32le b 0
  let packIv (b : ByteArray) (threadId : UInt32) (iv : Interval) : ByteArray :=
    let b := pushU32le b threadId
    let b := pushU32le b 0
    let b := pushU64le b iv.start
    pushU64le b (iv.stop.getD OPEN_END)
  let tBody := ts.foldl (init := ByteArray.empty) fun b (id, iv) => packIv b id iv
  let cBody := cs.foldl (init := ByteArray.empty) fun b c => packIv b c.threadId c.interval

  let mut out := ByteArray.empty
  out := pushU32le out TTFX_MAGIC
  out := pushU32le out TTFX_VERSION
  out := pushU32le out 0
  out := pushU32le out 5
  out := pushU64le out tr.frontier
  out := pushU64le out 0
  let sections := [(SEC_INITMEM, 32, imBody), (SEC_WRITES, 24, wBody), (SEC_EVENTS, 48, eBody),
                   (SEC_THREADS, 24, tBody), (SEC_CALLS, 24, cBody)]
  for (kind, recSize, body) in sections do
    out := pushU32le out kind
    out := pushU32le out (UInt32.ofNat recSize)
    out := pushU64le out (UInt64.ofNat (body.size / recSize))
    out := out ++ body
  out ++ pool3

end Forensicator.Parse

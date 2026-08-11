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
import Forensicator.Spec.Timeline

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
    initMem := region :: tr.initMem
    anomalies := tr.anomalies ++ payloadAnoms }

private def decodeWrite (data : ByteArray) (frontier : Position) (tr : Trace) (off : Nat) : Trace :=
  let pos := (u64At data off).getD 0
  let va := (u64At data (off + 8)).getD 0
  let len := ((u32At data (off + 16)).getD 0).toNat
  let dataOff := ((u32At data (off + 20)).getD 0).toNat
  let payload := sliceExact data dataOff len
  let a1 :=
    if payload.size < len then [anom off "ttfx: write truncated payload"] else []
  let a2 := match tr.writes.head? with
    | some last =>
      if pos < last.pos then
        [anom off s!"ttfx: write out of order (pos {hexUpper pos} < {hexUpper last.pos})"]
      else []
    | none => []
  let a3 :=
    if frontier < pos then [anom off s!"ttfx: write beyond frontier (pos {hexUpper pos})"] else []
  { tr with
    writes := { pos := pos, va := va, data := payload, provenance := prov off } :: tr.writes
    anomalies := tr.anomalies ++ (a1 ++ a2 ++ a3) }

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
    let a1 := match tr.events.head? with
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
      events := ev :: tr.events
      anomalies := tr.anomalies ++ (a1 ++ a2) }
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
  { tr with threads := (id, iv) :: tr.threads, anomalies := tr.anomalies ++ a1 }

private def decodeCall (data : ByteArray) (tr : Trace) (off : Nat) : Trace :=
  let (threadId, iv) := decodeInterval data off
  { tr with calls := { threadId := threadId, interval := iv } :: tr.calls }

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

/-- Per-section finalization: the record decoders cons (reversed) for
    O(1) per record; one `List.reverse` per section restores file order
    (F4: linear-time accumulation, observably identical to `++ [x]`). -/
private def finish (kind : UInt32) (tr : Trace) : Trace :=
  if kind == SEC_INITMEM then { tr with initMem := tr.initMem.reverse }
  else if kind == SEC_WRITES then { tr with writes := tr.writes.reverse }
  else if kind == SEC_EVENTS then { tr with events := tr.events.reverse }
  else if kind == SEC_THREADS then { tr with threads := tr.threads.reverse }
  else { tr with calls := tr.calls.reverse }

private def sectionRecordLoop (data : ByteArray) (frontier : Position) (kind : UInt32)
    (body recordSize recordCnt : Nat) (tr : Trace) (i : Nat) : Trace :=
  if h : i < recordCnt then
    let off := body + i * recordSize
    if off + recordSize > data.size then
      finish kind { tr with anomalies := tr.anomalies ++
          [anom off s!"ttfx: truncated section {kind} at record {i}"] }
    else
      sectionRecordLoop data frontier kind body recordSize recordCnt
        (decodeRecord data frontier tr kind off) (i + 1)
  else finish kind tr
termination_by recordCnt - i

/-- Per-section decode (F4): the record loop accumulates its section's
    records cons-reversed (O(1) per record); here the field is swapped out
    (cleared, seeded with a copy of the previous last record so the
    out-of-order check still sees it), the loop runs, and one `reverse`
    restores file order behind the base prefix — linear overall, and
    byte-identical to Rust's `Vec::push` order on every input. -/
private def decodeSection (data : ByteArray) (frontier : Position) (tr : Trace)
    (kind : UInt32) (body recordSize recordCnt : Nat) : Trace :=
  match wantSize kind with
  | none => tr
  | some want =>
    if recordSize != want then
      { tr with anomalies := tr.anomalies ++
          [anom body s!"ttfx: section {kind} record_size {recordSize} != {want}"] }
    else if kind == SEC_WRITES then
      let base := tr.writes
      let seed := match base.getLast? with | some s => [s] | none => []
      let r := sectionRecordLoop data frontier SEC_WRITES body recordSize recordCnt
        { tr with writes := seed } 0
      { r with writes := base ++ r.writes.drop seed.length }
    else if kind == SEC_EVENTS then
      let base := tr.events
      let seed := match base.getLast? with | some s => [s] | none => []
      let r := sectionRecordLoop data frontier SEC_EVENTS body recordSize recordCnt
        { tr with events := seed } 0
      { r with events := base ++ r.events.drop seed.length }
    else if kind == SEC_INITMEM then
      let base := tr.initMem
      let r := sectionRecordLoop data frontier SEC_INITMEM body recordSize recordCnt
        { tr with initMem := [] } 0
      { r with initMem := base ++ r.initMem }
    else if kind == SEC_THREADS then
      let base := tr.threads
      let r := sectionRecordLoop data frontier SEC_THREADS body recordSize recordCnt
        { tr with threads := [] } 0
      { r with threads := base ++ r.threads }
    else
      let base := tr.calls
      let r := sectionRecordLoop data frontier SEC_CALLS body recordSize recordCnt
        { tr with calls := [] } 0
      { r with calls := base ++ r.calls }

private def outsideLifetime (c : CallSpan) (tiv : Interval) : Bool :=
  decide (c.interval.start < tiv.start)
    || (match (c.interval.stop, tiv.stop) with
        | (some ce, some te) => decide (te < ce)
        | _ => false)

private def threadCheck (tr : Trace) (c : CallSpan) : Trace :=
  match tr.threads.find? fun (id, _) => id == c.threadId with
  | none =>
    { tr with anomalies := tr.anomalies ++
        [anom 0 s!"ttfx: call on unknown thread {c.threadId}"] }
  | some (_, tiv) =>
    if outsideLifetime c tiv then
      { tr with anomalies := tr.anomalies ++
          [anom 0 s!"ttfx: call outside thread {c.threadId} lifetime"] }
    else tr

private def crossing (c o : CallSpan) : Bool :=
  match c.interval.stop, o.interval.stop with
  | some ce, some oe =>
    let cs := c.interval.start
    let os := o.interval.start
    let disjoint := decide (ce ≤ os) || decide (oe ≤ cs)
    let nested := (decide (cs ≤ os) && decide (oe ≤ ce))
      || (decide (os ≤ cs) && decide (ce ≤ oe))
    !disjoint && !nested
  | _, _ => false

private def crossingStep (tr : Trace) (c : CallSpan) (i : Nat) (o : CallSpan) (j : Nat) : Trace :=
  if i == j || o.threadId != c.threadId then tr
  else if crossing c o then
    { tr with anomalies := tr.anomalies ++
        [anom 0 s!"ttfx: crossing call spans on thread {c.threadId}"] }
  else tr

private def crossingCheck (calls : List CallSpan) (tr : Trace) (c : CallSpan) (i : Nat) : Trace :=
  calls.zipIdx.foldl (init := tr) fun tr (o, j) => crossingStep tr c i o j

/-- Cross-record invariants (CallNesting, CallsWithinThreads). -/
private def validateIntervals (tr : Trace) : Trace :=
  tr.calls.zipIdx.foldl (init := tr) fun tr (c, i) =>
    crossingCheck tr.calls (threadCheck tr c) c i

private def sectionLoop (data : ByteArray) (frontier : Position)
    : Nat → Nat → Trace → Trace
  | 0, _, tr => tr
  | n + 1, off, tr =>
    match u32At data off with
    | none =>
      { tr with anomalies := tr.anomalies ++ [anom off "ttfx: truncated section table"] }
    | some kind =>
      sectionLoop data frontier n
        (off + SECTION_HDR_SIZE
          + ((u32At data (off + 4)).getD 0).toNat * ((u64At data (off + 8)).getD 0).toNat)
        (decodeSection data frontier tr kind (off + SECTION_HDR_SIZE)
          (((u32At data (off + 4)).getD 0).toNat) (((u64At data (off + 8)).getD 0).toNat))

/-- Decode a .ttfx file into a Trace. Hard error only on truncated header,
    bad magic, or unsupported version; everything else → anomalies. -/
def decodeTtfx (data : ByteArray) : Except Anomaly Trace :=
  if data.size < HEADER_SIZE then .error (anom 0 "ttfx: truncated header")
  else if u32At data 0 != some TTFX_MAGIC then .error (anom 0 "ttfx: bad magic")
  else
    let version := (u32At data 4).getD 0
    if version != TTFX_VERSION then .error (anom 4 s!"ttfx: unsupported version {version}")
    else
      let sectionCnt := ((u32At data 12).getD 0).toNat
      let frontier := (u64At data 16).getD 0
      .ok (validateIntervals (sectionLoop data frontier sectionCnt HEADER_SIZE { frontier := frontier }))

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
  -- payloads, in section order; offsets absolute. Cons-reversed accumulation
  -- (F4: O(1) per record; one reverse per section) — linear-time encode, so
  -- the test runner can synthesize 200k-write fixtures quickly.
  let step (acc : Nat × List ByteArray × List Nat) (payload : ByteArray) :
      Nat × List ByteArray × List Nat :=
    let (len, ps, offs) := acc
    (len + payload.size, payload :: ps, (poolStart + len) :: offs)
  let (imLen, imPs, imOffsR) := im.foldl (fun acc r => step acc r.data) (0, [], [])
  let (wLen, wPs, wOffsR) := ws.foldl (fun acc w => step acc w.data) (imLen, [], [])
  let (_, ePs, eOffsR) := es.foldl (fun acc e => step acc e.name.toUTF8) (wLen, [], [])
  let imOffs := imOffsR.reverse
  let wOffs := wOffsR.reverse
  let eOffs := eOffsR.reverse
  let pool := (imPs.reverse ++ wPs.reverse ++ ePs.reverse).foldl (init := ByteArray.empty) fun acc p =>
    p.data.foldl (fun a b => a.push b) acc

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
  out ++ pool




/- ====================================================================
   Decode postconditions (Timeline.tla TraceOrdered): an anomaly-free
   decode yields position-ordered writes AND events.
   ==================================================================== -/

section Proofs

open Forensicator.Spec (PositionOrdered EventsOrdered)

theorem decodeEvent_anomalies (data : ByteArray) (frontier : Position) (tr : Trace) (off : Nat) :
    ∃ e, (decodeEvent data frontier tr off).anomalies = tr.anomalies ++ e := by
  unfold decodeEvent
  dsimp only
  split <;> exact ⟨_, rfl⟩

theorem decodeEvent_writes (data : ByteArray) (frontier : Position) (tr : Trace) (off : Nat) :
    (decodeEvent data frontier tr off).writes = tr.writes := by
  unfold decodeEvent
  dsimp only
  split <;> rfl

theorem decodeRecord_anomalies (data : ByteArray) (frontier : Position) (tr : Trace)
    (kind : UInt32) (off : Nat) :
    ∃ e, (decodeRecord data frontier tr kind off).anomalies = tr.anomalies ++ e := by
  unfold decodeRecord
  by_cases h1 : (kind == SEC_INITMEM) = true
  · simp only [h1, if_true]; exact ⟨_, rfl⟩
  · by_cases h2 : (kind == SEC_WRITES) = true
    · simp only [h1, h2, if_true]; exact ⟨_, rfl⟩
    · by_cases h3 : (kind == SEC_EVENTS) = true
      · simp only [h1, h2, h3, if_true]; exact decodeEvent_anomalies data frontier tr off
      · by_cases h4 : (kind == SEC_THREADS) = true
        · simp only [h1, h2, h3, h4, if_true]; exact ⟨_, rfl⟩
        · simp only [h1, h2, h3, h4]; exact ⟨[], by simp only [List.append_nil]; rfl⟩

theorem decodeRecord_writes_frame (data : ByteArray) (frontier : Position) (tr : Trace)
    (kind : UInt32) (off : Nat) (h : kind ≠ SEC_WRITES) :
    (decodeRecord data frontier tr kind off).writes = tr.writes := by
  have hns : (kind == SEC_WRITES) = false := by
    cases hkb : kind == SEC_WRITES with
    | false => rfl
    | true => exact absurd (beq_iff_eq.1 hkb) h
  unfold decodeRecord
  by_cases h1 : (kind == SEC_INITMEM) = true
  · simp only [h1, if_true]; rfl
  · by_cases h3 : (kind == SEC_EVENTS) = true
    · simp only [h1, hns, h3, if_true]; exact decodeEvent_writes data frontier tr off
    · by_cases h4 : (kind == SEC_THREADS) = true
      · simp only [h1, hns, h3, h4, if_true]; rfl
      · simp only [h1, hns, h3, h4]; rfl

theorem decodeRecord_eq_decodeWrite (data : ByteArray) (frontier : Position) (tr : Trace)
    (off : Nat) :
    decodeRecord data frontier tr SEC_WRITES off = decodeWrite data frontier tr off := by
  unfold decodeRecord
  simp [SEC_WRITES, SEC_INITMEM]

/-- Content of the write-order check: no anomalies ⇒ previous head write's
    position ≤ the new write's position (head = last decoded under the
    cons-reversed accumulation). -/
theorem decodeWrite_last_le (data : ByteArray) (frontier : Position) (tr : Trace) (off : Nat)
    (hano : (decodeWrite data frontier tr off).anomalies = [])
    (l : WriteRecord) (hl : tr.writes.head? = some l) :
    l.pos ≤ (u64At data off).getD 0 := by
  unfold decodeWrite at hano
  dsimp only at hano
  simp only [List.append_eq_nil_iff] at hano
  obtain ⟨-, ⟨-, ha2⟩, -⟩ := hano
  simp only [hl] at ha2
  by_cases hp : ((u64At data off).getD 0) < l.pos
  · simp [hp] at ha2
  · have hp' : ¬ ((u64At data off).getD 0).toNat < l.pos.toNat := hp
    have hle : l.pos.toNat ≤ ((u64At data off).getD 0).toNat := by omega
    exact hle

theorem decodeWrite_ordered (data : ByteArray) (frontier : Position) (tr : Trace) (off : Nat)
    (hord : PositionOrdered tr.writes.reverse)
    (hano : (decodeWrite data frontier tr off).anomalies = []) :
    PositionOrdered (decodeWrite data frontier tr off).writes.reverse := by
  unfold decodeWrite
  dsimp only
  rw [List.reverse_cons]
  apply PositionOrdered.append_singleton hord
  intro l hl
  exact decodeWrite_last_le data frontier tr off hano l (List.getLast?_reverse ▸ hl)

private theorem finish_anomalies (kind : UInt32) (tr : Trace) :
    (finish kind tr).anomalies = tr.anomalies := by
  unfold finish
  by_cases h1 : kind == SEC_INITMEM
  · simp [h1]
  · by_cases h2 : kind == SEC_WRITES
    · simp [h1, h2]
    · by_cases h3 : kind == SEC_EVENTS
      · simp [h1, h2, h3]
      · by_cases h4 : kind == SEC_THREADS
        · simp [h1, h2, h3, h4]
        · simp [h1, h2, h3, h4]

private theorem finish_writes (kind : UInt32) (tr : Trace) (h : kind ≠ SEC_WRITES) :
    (finish kind tr).writes = tr.writes := by
  unfold finish
  by_cases h1 : kind == SEC_INITMEM
  · simp [h1]
  · by_cases h2 : kind == SEC_WRITES
    · exfalso; exact h (beq_iff_eq.1 h2)
    · by_cases h3 : kind == SEC_EVENTS
      · simp [h1, h2, h3]
      · by_cases h4 : kind == SEC_THREADS
        · simp [h1, h2, h3, h4]
        · simp [h1, h2, h3, h4]

private theorem finish_events (kind : UInt32) (tr : Trace) (h : kind ≠ SEC_EVENTS) :
    (finish kind tr).events = tr.events := by
  unfold finish
  by_cases h1 : kind == SEC_INITMEM
  · simp [h1]
  · by_cases h2 : kind == SEC_WRITES
    · simp [h1, h2]
    · by_cases h3 : kind == SEC_EVENTS
      · exfalso; exact h (beq_iff_eq.1 h3)
      · by_cases h4 : kind == SEC_THREADS
        · simp [h1, h2, h3, h4]
        · simp [h1, h2, h3, h4]

theorem sectionRecordLoop_anomalies_mono (data : ByteArray) (frontier : Position) (kind : UInt32)
    (body recordSize recordCnt : Nat) (tr : Trace) (i : Nat) :
    ∃ e, (sectionRecordLoop data frontier kind body recordSize recordCnt tr i).anomalies
        = tr.anomalies ++ e := by
  fun_induction sectionRecordLoop data frontier kind body recordSize recordCnt tr i
  · rename_i tr i hlt off hfit
    rw [finish_anomalies]
    exact ⟨[anom off s!"ttfx: truncated section {kind} at record {i}"], rfl⟩
  · rename_i tr i hlt off hfit ih
    obtain ⟨e1, h1⟩ := decodeRecord_anomalies data frontier tr kind off
    obtain ⟨e2, h2⟩ := ih
    exact ⟨e1 ++ e2, by rw [h2, h1, List.append_assoc]⟩
  · rw [finish_anomalies]
    exact ⟨[], by simp⟩

theorem sectionRecordLoop_writes_frame (data : ByteArray) (frontier : Position) (kind : UInt32)
    (body recordSize recordCnt : Nat) (tr : Trace) (i : Nat) (h : kind ≠ SEC_WRITES) :
    (sectionRecordLoop data frontier kind body recordSize recordCnt tr i).writes
      = tr.writes := by
  fun_induction sectionRecordLoop data frontier kind body recordSize recordCnt tr i
  · rename_i tr i hlt off hfit
    exact finish_writes kind { tr with anomalies := tr.anomalies ++
      [anom off s!"ttfx: truncated section {kind} at record {i}"] } h
  · rename_i tr i hlt off hfit ih
    rw [ih]
    exact decodeRecord_writes_frame data frontier tr kind off h
  · rename_i tr i hnot
    exact finish_writes kind tr h

/-- Loop postcondition in the cons-reversed world: the accumulated field's
    reverse is position-ordered (the invariant), and after the per-section
    `finish` the field itself is forward-ordered (the conclusion). -/
theorem sectionRecordLoop_writes_ordered (data : ByteArray) (frontier : Position)
    (body recordSize recordCnt : Nat) (tr : Trace) (i : Nat)
    (hord : PositionOrdered tr.writes.reverse)
    (hano : (sectionRecordLoop data frontier SEC_WRITES body recordSize recordCnt tr i).anomalies = [])
    (hano0 : tr.anomalies = []) :
    PositionOrdered
      (sectionRecordLoop data frontier SEC_WRITES body recordSize recordCnt tr i).writes := by
  fun_induction sectionRecordLoop data frontier SEC_WRITES body recordSize recordCnt tr i
  · rename_i tr i hlt off hfit
    simpa [finish, SEC_INITMEM, SEC_WRITES, SEC_EVENTS, SEC_THREADS, SEC_CALLS] using hord
  · rename_i tr i hlt off hfit ih
    obtain ⟨e1, h1⟩ := decodeRecord_anomalies data frontier tr SEC_WRITES off
    obtain ⟨e2, h2⟩ := sectionRecordLoop_anomalies_mono data frontier SEC_WRITES
      body recordSize recordCnt (decodeRecord data frontier tr SEC_WRITES off) (i + 1)
    have hano' := hano
    rw [h2, h1] at hano'
    simp only [List.append_eq_nil_iff] at hano'
    obtain ⟨⟨hano10, hano11⟩, -⟩ := hano'
    have hstep0 : (decodeRecord data frontier tr SEC_WRITES off).anomalies = [] := by
      rw [h1, hano10, hano11]; rfl
    have hstep : (decodeWrite data frontier tr off).anomalies = [] := by
      rw [← decodeRecord_eq_decodeWrite data frontier tr off, h1, hano10, hano11]; rfl
    exact ih ((decodeRecord_eq_decodeWrite data frontier tr off).symm ▸
      decodeWrite_ordered data frontier tr off hord hstep) hano hstep0
  · simpa [finish, SEC_INITMEM, SEC_WRITES, SEC_EVENTS, SEC_THREADS, SEC_CALLS] using hord

/-- The seed survives the loop: a nonempty initial field's last record is
    the result's head (finish puts it at the front of the reversed field). -/
theorem sectionRecordLoop_writes_head (data : ByteArray) (frontier : Position)
    (body recordSize recordCnt : Nat) (tr : Trace) (i : Nat) (hne : tr.writes ≠ []) :
    (sectionRecordLoop data frontier SEC_WRITES body recordSize recordCnt tr i).writes.head?
      = tr.writes.getLast? := by
  fun_induction sectionRecordLoop data frontier SEC_WRITES body recordSize recordCnt tr i
  · rename_i tr i hlt off hfit
    simpa [finish, SEC_INITMEM, SEC_WRITES, SEC_EVENTS, SEC_THREADS, SEC_CALLS, List.head?_reverse]
  · rename_i tr i hlt off hfit ih
    let w : WriteRecord :=
      { pos := (u64At data off).getD 0, va := (u64At data (off + 8)).getD 0,
        data := sliceExact data (((u32At data (off + 20)).getD 0).toNat)
          (((u32At data (off + 16)).getD 0).toNat),
        provenance := prov off }
    have hw : (decodeRecord data frontier tr SEC_WRITES off).writes = w :: tr.writes := by
      rw [decodeRecord_eq_decodeWrite]; rfl
    have hne' : (decodeRecord data frontier tr SEC_WRITES off).writes ≠ [] := by
      intro h; rw [hw] at h; contradiction
    have hlast : (w :: tr.writes).getLast? = tr.writes.getLast? := by
      cases hc : tr.writes with
      | nil => contradiction
      | cons x xs => rfl
    rw [← hlast]
    exact ih hne'
  · rename_i tr i h
    simpa [finish, SEC_INITMEM, SEC_WRITES, SEC_EVENTS, SEC_THREADS, SEC_CALLS, List.head?_reverse]

theorem decodeSection_anomalies (data : ByteArray) (frontier : Position) (tr : Trace)
    (kind : UInt32) (body recordSize recordCnt : Nat) :
    ∃ e, (decodeSection data frontier tr kind body recordSize recordCnt).anomalies
        = tr.anomalies ++ e := by
  unfold decodeSection
  split
  · exact ⟨[], by simp⟩
  · split
    · exact ⟨_, rfl⟩
    · split
      · obtain ⟨e, h⟩ := sectionRecordLoop_anomalies_mono data frontier SEC_WRITES
          body recordSize recordCnt
          { tr with writes := match tr.writes.getLast? with | some s => [s] | none => [] } 0
        exact ⟨e, by simp [h]⟩
      · split
        · obtain ⟨e, h⟩ := sectionRecordLoop_anomalies_mono data frontier SEC_EVENTS
            body recordSize recordCnt
            { tr with events := match tr.events.getLast? with | some s => [s] | none => [] } 0
          exact ⟨e, by simp [h]⟩
        · split
          · obtain ⟨e, h⟩ := sectionRecordLoop_anomalies_mono data frontier SEC_INITMEM
              body recordSize recordCnt { tr with initMem := [] } 0
            exact ⟨e, by simp [h]⟩
          · split
            · obtain ⟨e, h⟩ := sectionRecordLoop_anomalies_mono data frontier SEC_THREADS
                body recordSize recordCnt { tr with threads := [] } 0
              exact ⟨e, by simp [h]⟩
            · obtain ⟨e, h⟩ := sectionRecordLoop_anomalies_mono data frontier SEC_CALLS
                body recordSize recordCnt { tr with calls := [] } 0
              exact ⟨e, by simp [h]⟩

theorem decodeSection_writes_ordered (data : ByteArray) (frontier : Position) (tr : Trace)
    (kind : UInt32) (body recordSize recordCnt : Nat)
    (hord : PositionOrdered tr.writes)
    (hano : (decodeSection data frontier tr kind body recordSize recordCnt).anomalies = [])
    (hano0 : tr.anomalies = []) :
    PositionOrdered (decodeSection data frontier tr kind body recordSize recordCnt).writes := by
  unfold decodeSection at hano ⊢
  cases hw : wantSize kind with
  | none =>
    simp only [hw] at hano ⊢
    exact hord
  | some want =>
    simp only [hw] at hano ⊢
    by_cases hsz : (recordSize != want) = true
    · simp only [hsz, if_true] at hano
      simp at hano
    · simp only [hsz, Bool.false_eq_true, if_false] at hano ⊢
      by_cases hk : kind == SEC_WRITES
      · rw [beq_iff_eq] at hk; subst hk
        cases hb : tr.writes.getLast? with
        | none =>
          cases hc : tr.writes with
          | nil =>
            have hsec : (sectionRecordLoop data frontier SEC_WRITES body recordSize recordCnt
                { tr with writes := [] } 0).anomalies = [] := by
              simpa [hc] using hano
            have hrev : PositionOrdered (sectionRecordLoop data frontier SEC_WRITES body recordSize recordCnt
                { tr with writes := [] } 0).writes :=
              sectionRecordLoop_writes_ordered data frontier body recordSize recordCnt
                { tr with writes := [] } 0 (by simp [PositionOrdered]) hsec (by simpa using hano0)
            simp [hc]
            change PositionOrdered (sectionRecordLoop data frontier SEC_WRITES body recordSize recordCnt
              { tr with writes := [] } 0).writes
            exact hrev
          | cons x xs =>
            rw [hc, List.getLast?_eq_none_iff] at hb
            exact False.elim (List.cons_ne_nil x xs hb)
        | some s =>
          have hsec : (sectionRecordLoop data frontier SEC_WRITES body recordSize recordCnt
              { tr with writes := [s] } 0).anomalies = [] := by
            simpa [hb] using hano
          have hrev : PositionOrdered (sectionRecordLoop data frontier SEC_WRITES body recordSize recordCnt
              { tr with writes := [s] } 0).writes :=
            sectionRecordLoop_writes_ordered data frontier body recordSize recordCnt
              { tr with writes := [s] } 0 (by simp [PositionOrdered]) hsec (by simpa using hano0)
          have hnew : PositionOrdered ((sectionRecordLoop data frontier SEC_WRITES body recordSize recordCnt
              { tr with writes := [s] } 0).writes.tail) := by
            simpa using PositionOrdered.drop 1 hrev
          simp [hb]
          change PositionOrdered (tr.writes ++ (sectionRecordLoop data frontier SEC_WRITES body recordSize recordCnt
            { tr with writes := [s] } 0).writes.tail)
          apply PositionOrdered.append hord hnew
          intro l hl y hy
          have hls : l = s := by
            have hs : s = l := by
              rw [hb] at hl
              exact Option.some.inj hl
            exact hs.symm
          have hframe : (sectionRecordLoop data frontier SEC_WRITES body recordSize recordCnt
              { tr with writes := [s] } 0).writes.head? = some s := by
            simpa using
              sectionRecordLoop_writes_head data frontier body recordSize recordCnt
                { tr with writes := [s] } 0 (by simp)
          cases hd : (sectionRecordLoop data frontier SEC_WRITES body recordSize recordCnt
              { tr with writes := [s] } 0).writes.tail with
          | nil => simp [hd] at hy
          | cons z zs =>
            have hy' : (z :: zs).head? = some y := by simpa [hd] using hy
            have hz : z = y := Option.some.inj (by simpa using hy')
            cases hc : (sectionRecordLoop data frontier SEC_WRITES body recordSize recordCnt
              { tr with writes := [s] } 0).writes with
            | nil => simp [hc] at hframe
            | cons x xs =>
              have hx : x = s := by simpa [hc] using hframe
              have hxs : xs = z :: zs := by simpa [hc] using hd
              have hrev1 : s.pos ≤ z.pos := by
                rw [hc, hx, hxs] at hrev
                exact hrev.1
              rw [hls, ← hz]
              exact hrev1
      · have hk' : kind ≠ SEC_WRITES := fun heq => hk (beq_iff_eq.2 heq)
        by_cases hke : kind == SEC_EVENTS
        · rw [beq_iff_eq] at hke; subst hke
          have hframe := sectionRecordLoop_writes_frame data frontier SEC_EVENTS
            body recordSize recordCnt
            { tr with events := match tr.events.getLast? with | some s => [s] | none => [] } 0
            (by decide)
          change PositionOrdered (sectionRecordLoop data frontier SEC_EVENTS body recordSize recordCnt
            { tr with events := match tr.events.getLast? with | some s => [s] | none => [] } 0).writes
          rw [hframe]
          exact hord
        · by_cases hki : kind == SEC_INITMEM
          · rw [beq_iff_eq] at hki; subst hki
            have hframe := sectionRecordLoop_writes_frame data frontier SEC_INITMEM
              body recordSize recordCnt { tr with initMem := [] } 0
              (by decide)
            change PositionOrdered (sectionRecordLoop data frontier SEC_INITMEM body recordSize recordCnt
              { tr with initMem := [] } 0).writes
            rw [hframe]
            exact hord
          · by_cases hkt : kind == SEC_THREADS
            · rw [beq_iff_eq] at hkt; subst hkt
              have hframe := sectionRecordLoop_writes_frame data frontier SEC_THREADS
                body recordSize recordCnt { tr with threads := [] } 0
                (by decide)
              change PositionOrdered (sectionRecordLoop data frontier SEC_THREADS body recordSize recordCnt
                { tr with threads := [] } 0).writes
              rw [hframe]
              exact hord
            · have hframe := sectionRecordLoop_writes_frame data frontier SEC_CALLS
                body recordSize recordCnt { tr with calls := [] } 0
                (by decide)
              simp [hk, hke, hki, hkt]
              change PositionOrdered (sectionRecordLoop data frontier SEC_CALLS body recordSize recordCnt
                { tr with calls := [] } 0).writes
              rw [hframe]
              exact hord

theorem sectionLoop_anomalies_mono (data : ByteArray) (frontier : Position)
    (remaining : Nat) (off : Nat) (tr : Trace) :
    ∃ e, (sectionLoop data frontier remaining off tr).anomalies = tr.anomalies ++ e := by
  induction remaining generalizing tr off with
  | zero => exact ⟨[], by simp only [sectionLoop]; simp⟩
  | succ n ih =>
    simp only [sectionLoop]
    cases hm : u32At data off with
    | none => exact ⟨_, rfl⟩
    | some kind =>
      obtain ⟨e1, h1⟩ := decodeSection_anomalies data frontier tr kind
        (off + SECTION_HDR_SIZE)
        (((u32At data (off + 4)).getD 0).toNat) (((u64At data (off + 8)).getD 0).toNat)
      obtain ⟨e2, h2⟩ := ih
        (off + SECTION_HDR_SIZE
          + ((u32At data (off + 4)).getD 0).toNat * ((u64At data (off + 8)).getD 0).toNat)
        (decodeSection data frontier tr kind (off + SECTION_HDR_SIZE)
          (((u32At data (off + 4)).getD 0).toNat) (((u64At data (off + 8)).getD 0).toNat))
      exact ⟨e1 ++ e2, by rw [h2, h1, List.append_assoc]⟩

theorem sectionLoop_writes_ordered (data : ByteArray) (frontier : Position)
    (remaining : Nat) (off : Nat) (tr : Trace)
    (hord : PositionOrdered tr.writes)
    (hano : (sectionLoop data frontier remaining off tr).anomalies = [])
    (hano0 : tr.anomalies = []) :
    PositionOrdered (sectionLoop data frontier remaining off tr).writes := by
  induction remaining generalizing tr off with
  | zero => exact hord
  | succ n ih =>
    simp only [sectionLoop] at hano ⊢
    cases hm : u32At data off with
    | none =>
      simp only [hm] at hano
      simp at hano
    | some kind =>
      simp only [hm] at hano ⊢
      obtain ⟨e1, h1⟩ := decodeSection_anomalies data frontier tr kind (off + SECTION_HDR_SIZE)
        (((u32At data (off + 4)).getD 0).toNat) (((u64At data (off + 8)).getD 0).toNat)
      obtain ⟨e2, h2⟩ := sectionLoop_anomalies_mono data frontier n (off + SECTION_HDR_SIZE
        + ((u32At data (off + 4)).getD 0).toNat * ((u64At data (off + 8)).getD 0).toNat)
        (decodeSection data frontier tr kind (off + SECTION_HDR_SIZE)
          (((u32At data (off + 4)).getD 0).toNat) (((u64At data (off + 8)).getD 0).toNat))
      have hano' := hano
      rw [h2, h1] at hano'
      simp only [List.append_eq_nil_iff] at hano'
      obtain ⟨⟨hano10, hano11⟩, -⟩ := hano'
      have hsec : (decodeSection data frontier tr kind (off + SECTION_HDR_SIZE)
          (((u32At data (off + 4)).getD 0).toNat) (((u64At data (off + 8)).getD 0).toNat)).anomalies
          = [] := by
        rw [h1, hano10, hano11]; rfl
      exact ih _ _
        (decodeSection_writes_ordered data frontier tr kind _ _ _ hord hsec hano10) hano hsec

theorem decodeRecord_events_frame (data : ByteArray) (frontier : Position) (tr : Trace)
    (kind : UInt32) (off : Nat) (h : kind ≠ SEC_EVENTS) :
    (decodeRecord data frontier tr kind off).events = tr.events := by
  have hns : (kind == SEC_EVENTS) = false := by
    cases hkb : kind == SEC_EVENTS with
    | false => rfl
    | true => exact absurd (beq_iff_eq.1 hkb) h
  unfold decodeRecord
  by_cases h1 : (kind == SEC_INITMEM) = true
  · simp only [h1, if_true]; rfl
  · by_cases h2 : (kind == SEC_WRITES) = true
    · simp only [h1, h2, hns, if_true]; rfl
    · by_cases h4 : (kind == SEC_THREADS) = true
      · simp only [h1, h2, hns, h4, if_true]; rfl
      · simp only [h1, h2, hns, h4]; rfl

theorem decodeRecord_eq_decodeEvent (data : ByteArray) (frontier : Position) (tr : Trace)
    (off : Nat) :
    decodeRecord data frontier tr SEC_EVENTS off = decodeEvent data frontier tr off := by
  unfold decodeRecord
  simp [SEC_EVENTS, SEC_INITMEM, SEC_WRITES]

/-- Content of the event-order check: no anomalies ⇒ previous head event's
    position ≤ the new event's position. -/
theorem decodeEvent_last_le (data : ByteArray) (frontier : Position) (tr : Trace) (off : Nat)
    (hano : (decodeEvent data frontier tr off).anomalies = [])
    (l : TraceEvent) (hl : tr.events.head? = some l) :
    l.pos ≤ (u64At data off).getD 0 := by
  unfold decodeEvent at hano
  dsimp only at hano
  split at hano
  · simp only [List.append_eq_nil_iff] at hano
    obtain ⟨-, ha1, -⟩ := hano
    simp only [hl] at ha1
    by_cases hp : ((u64At data off).getD 0) < l.pos
    · simp [hp] at ha1
    · have hp' : ¬ ((u64At data off).getD 0).toNat < l.pos.toNat := hp
      have hle : l.pos.toNat ≤ ((u64At data off).getD 0).toNat := by omega
      exact hle
  · simp at hano

theorem decodeEvent_ordered (data : ByteArray) (frontier : Position) (tr : Trace) (off : Nat)
    (hord : EventsOrdered tr.events.reverse)
    (hano : (decodeEvent data frontier tr off).anomalies = []) :
    EventsOrdered (decodeEvent data frontier tr off).events.reverse := by
  unfold decodeEvent
  dsimp only
  split
  · rw [List.reverse_cons]
    apply EventsOrdered.append_singleton hord
    intro l hl
    exact decodeEvent_last_le data frontier tr off hano l (List.getLast?_reverse ▸ hl)
  · exact hord

theorem sectionRecordLoop_events_frame (data : ByteArray) (frontier : Position) (kind : UInt32)
    (body recordSize recordCnt : Nat) (tr : Trace) (i : Nat) (h : kind ≠ SEC_EVENTS) :
    (sectionRecordLoop data frontier kind body recordSize recordCnt tr i).events
      = tr.events := by
  fun_induction sectionRecordLoop data frontier kind body recordSize recordCnt tr i
  · rename_i tr i hlt off hfit
    exact finish_events kind { tr with anomalies := tr.anomalies ++
      [anom off s!"ttfx: truncated section {kind} at record {i}"] } h
  · rename_i tr i hlt off hfit ih
    rw [ih]
    exact decodeRecord_events_frame data frontier tr kind off h
  · rename_i tr i hnot
    exact finish_events kind tr h

/-- Loop postcondition in the cons-reversed world (events half). -/
theorem sectionRecordLoop_events_ordered (data : ByteArray) (frontier : Position)
    (body recordSize recordCnt : Nat) (tr : Trace) (i : Nat)
    (hord : EventsOrdered tr.events.reverse)
    (hano : (sectionRecordLoop data frontier SEC_EVENTS body recordSize recordCnt tr i).anomalies = [])
    (hano0 : tr.anomalies = []) :
    EventsOrdered
      (sectionRecordLoop data frontier SEC_EVENTS body recordSize recordCnt tr i).events := by
  fun_induction sectionRecordLoop data frontier SEC_EVENTS body recordSize recordCnt tr i
  · rename_i tr i hlt off hfit
    simpa [finish, SEC_INITMEM, SEC_WRITES, SEC_EVENTS, SEC_THREADS, SEC_CALLS] using hord
  · rename_i tr i hlt off hfit ih
    have hano' := hano
    obtain ⟨e1, h1⟩ := decodeRecord_anomalies data frontier tr SEC_EVENTS off
    obtain ⟨e2, h2⟩ := sectionRecordLoop_anomalies_mono data frontier SEC_EVENTS
      body recordSize recordCnt (decodeRecord data frontier tr SEC_EVENTS off) (i + 1)
    rw [h2, h1] at hano'
    simp only [List.append_eq_nil_iff] at hano'
    obtain ⟨⟨hano10, hano11⟩, -⟩ := hano'
    have hstep0 : (decodeRecord data frontier tr SEC_EVENTS off).anomalies = [] := by
      rw [h1, hano10, hano11]; rfl
    have hstep : (decodeEvent data frontier tr off).anomalies = [] := by
      rw [← decodeRecord_eq_decodeEvent data frontier tr off, h1, hano10, hano11]; rfl
    exact ih ((decodeRecord_eq_decodeEvent data frontier tr off).symm ▸
      decodeEvent_ordered data frontier tr off hord hstep) hano hstep0
  · simpa [finish, SEC_INITMEM, SEC_WRITES, SEC_EVENTS, SEC_THREADS, SEC_CALLS] using hord

/-- The seed survives the loop (events half). -/
theorem sectionRecordLoop_events_head (data : ByteArray) (frontier : Position)
    (body recordSize recordCnt : Nat) (tr : Trace) (i : Nat) (hne : tr.events ≠ []) :
    (sectionRecordLoop data frontier SEC_EVENTS body recordSize recordCnt tr i).events.head?
      = tr.events.getLast? := by
  fun_induction sectionRecordLoop data frontier SEC_EVENTS body recordSize recordCnt tr i
  · rename_i tr i hlt off hfit
    simpa [finish, SEC_INITMEM, SEC_WRITES, SEC_EVENTS, SEC_THREADS, SEC_CALLS, List.head?_reverse]
  · rename_i tr i hlt off hfit ih
    have hne' : (decodeRecord data frontier tr SEC_EVENTS off).events ≠ [] := by
      intro h
      have h' : (decodeEvent data frontier tr off).events = [] := by
        simpa [decodeRecord_eq_decodeEvent] using h
      unfold decodeEvent at h'
      dsimp only at h'
      split at h'
      · exact List.cons_ne_nil _ _ h'
      · exact hne h'
    have hlast : (decodeEvent data frontier tr off).events.getLast? = tr.events.getLast? := by
      unfold decodeEvent
      dsimp only
      cases hk : (u32At data (off + 8)).getD 0 == 0 || (u32At data (off + 8)).getD 0 == 1
        || (u32At data (off + 8)).getD 0 == 2
      · simp [hk]
      · cases hc : tr.events with
        | nil => contradiction
        | cons x xs => rfl
    rw [← hlast]
    rw [← decodeRecord_eq_decodeEvent data frontier tr off]
    exact ih hne'
  · simpa [finish, SEC_INITMEM, SEC_WRITES, SEC_EVENTS, SEC_THREADS, SEC_CALLS, List.head?_reverse]

theorem decodeSection_events_ordered (data : ByteArray) (frontier : Position) (tr : Trace)
    (kind : UInt32) (body recordSize recordCnt : Nat)
    (hord : EventsOrdered tr.events)
    (hano : (decodeSection data frontier tr kind body recordSize recordCnt).anomalies = [])
    (hano0 : tr.anomalies = []) :
    EventsOrdered (decodeSection data frontier tr kind body recordSize recordCnt).events := by
  unfold decodeSection at hano ⊢
  cases hw : wantSize kind with
  | none =>
    simp only [hw] at hano ⊢
    exact hord
  | some want =>
    simp only [hw] at hano ⊢
    by_cases hsz : (recordSize != want) = true
    · simp only [hsz, if_true] at hano
      simp at hano
    · simp only [hsz, Bool.false_eq_true, if_false] at hano ⊢
      by_cases hk : kind == SEC_EVENTS
      · rw [beq_iff_eq] at hk; subst hk
        cases hb : tr.events.getLast? with
        | none =>
          cases hc : tr.events with
          | nil =>
            have hsec : (sectionRecordLoop data frontier SEC_EVENTS body recordSize recordCnt
                { tr with events := [] } 0).anomalies = [] := by
              simpa [hc, SEC_INITMEM, SEC_WRITES, SEC_EVENTS, SEC_THREADS, SEC_CALLS] using hano
            have hrev : EventsOrdered (sectionRecordLoop data frontier SEC_EVENTS body recordSize recordCnt
                { tr with events := [] } 0).events :=
              sectionRecordLoop_events_ordered data frontier body recordSize recordCnt
                { tr with events := [] } 0 (by simp [EventsOrdered]) hsec (by simpa using hano0)
            simp [hc]
            change EventsOrdered (sectionRecordLoop data frontier SEC_EVENTS body recordSize recordCnt
              { tr with events := [] } 0).events
            exact hrev
          | cons x xs =>
            rw [hc, List.getLast?_eq_none_iff] at hb
            exact False.elim (List.cons_ne_nil x xs hb)
        | some s =>
          have hsec : (sectionRecordLoop data frontier SEC_EVENTS body recordSize recordCnt
              { tr with events := [s] } 0).anomalies = [] := by
            simpa [hb, SEC_INITMEM, SEC_WRITES, SEC_EVENTS, SEC_THREADS, SEC_CALLS] using hano
          have hrev : EventsOrdered (sectionRecordLoop data frontier SEC_EVENTS body recordSize recordCnt
              { tr with events := [s] } 0).events :=
            sectionRecordLoop_events_ordered data frontier body recordSize recordCnt
              { tr with events := [s] } 0 (by simp [EventsOrdered]) hsec (by simpa using hano0)
          have hnew : EventsOrdered ((sectionRecordLoop data frontier SEC_EVENTS body recordSize recordCnt
              { tr with events := [s] } 0).events.tail) := by
            simpa using EventsOrdered.drop 1 hrev
          simp [hb]
          change EventsOrdered (tr.events ++ (sectionRecordLoop data frontier SEC_EVENTS body recordSize recordCnt
            { tr with events := [s] } 0).events.tail)
          apply EventsOrdered.append hord hnew
          intro l hl y hy
          have hls : l = s := by
            have hs : s = l := by
              rw [hb] at hl
              exact Option.some.inj hl
            exact hs.symm
          have hframe : (sectionRecordLoop data frontier SEC_EVENTS body recordSize recordCnt
              { tr with events := [s] } 0).events.head? = some s := by
            simpa using
              sectionRecordLoop_events_head data frontier body recordSize recordCnt
                { tr with events := [s] } 0 (by simp)
          cases hd : (sectionRecordLoop data frontier SEC_EVENTS body recordSize recordCnt
              { tr with events := [s] } 0).events.tail with
          | nil => simp [hd] at hy
          | cons z zs =>
            have hy' : (z :: zs).head? = some y := by simpa [hd] using hy
            have hz : z = y := Option.some.inj (by simpa using hy')
            cases hc : (sectionRecordLoop data frontier SEC_EVENTS body recordSize recordCnt
              { tr with events := [s] } 0).events with
            | nil => simp [hc] at hframe
            | cons x xs =>
              have hx : x = s := by simpa [hc] using hframe
              have hxs : xs = z :: zs := by simpa [hc] using hd
              have hrev1 : s.pos ≤ z.pos := by
                rw [hc, hx, hxs] at hrev
                exact hrev.1
              rw [hls, ← hz]
              exact hrev1
      · have hk' : kind ≠ SEC_EVENTS := fun heq => hk (beq_iff_eq.2 heq)
        by_cases hkw : kind == SEC_WRITES
        · rw [beq_iff_eq] at hkw; subst hkw
          have hframe := sectionRecordLoop_events_frame data frontier SEC_WRITES
            body recordSize recordCnt
            { tr with writes := match tr.writes.getLast? with | some s => [s] | none => [] } 0
            (by decide)
          change EventsOrdered (sectionRecordLoop data frontier SEC_WRITES body recordSize recordCnt
            { tr with writes := match tr.writes.getLast? with | some s => [s] | none => [] } 0).events
          rw [hframe]
          exact hord
        · by_cases hki : kind == SEC_INITMEM
          · rw [beq_iff_eq] at hki; subst hki
            have hframe := sectionRecordLoop_events_frame data frontier SEC_INITMEM
              body recordSize recordCnt { tr with initMem := [] } 0
              (by decide)
            change EventsOrdered (sectionRecordLoop data frontier SEC_INITMEM body recordSize recordCnt
              { tr with initMem := [] } 0).events
            rw [hframe]
            exact hord
          · by_cases hkt : kind == SEC_THREADS
            · rw [beq_iff_eq] at hkt; subst hkt
              have hframe := sectionRecordLoop_events_frame data frontier SEC_THREADS
                body recordSize recordCnt { tr with threads := [] } 0
                (by decide)
              change EventsOrdered (sectionRecordLoop data frontier SEC_THREADS body recordSize recordCnt
                { tr with threads := [] } 0).events
              rw [hframe]
              exact hord
            · have hframe := sectionRecordLoop_events_frame data frontier SEC_CALLS
                body recordSize recordCnt { tr with calls := [] } 0
                (by decide)
              simp [hk, hkw, hki, hkt]
              change EventsOrdered (sectionRecordLoop data frontier SEC_CALLS body recordSize recordCnt
                { tr with calls := [] } 0).events
              rw [hframe]
              exact hord

theorem sectionLoop_events_ordered (data : ByteArray) (frontier : Position)
    (remaining : Nat) (off : Nat) (tr : Trace)
    (hord : EventsOrdered tr.events)
    (hano : (sectionLoop data frontier remaining off tr).anomalies = [])
    (hano0 : tr.anomalies = []) :
    EventsOrdered (sectionLoop data frontier remaining off tr).events := by
  induction remaining generalizing tr off with
  | zero => exact hord
  | succ n ih =>
    simp only [sectionLoop] at hano ⊢
    cases hm : u32At data off with
    | none =>
      simp only [hm] at hano
      simp at hano
    | some kind =>
      simp only [hm] at hano ⊢
      obtain ⟨e1, h1⟩ := decodeSection_anomalies data frontier tr kind (off + SECTION_HDR_SIZE)
        (((u32At data (off + 4)).getD 0).toNat) (((u64At data (off + 8)).getD 0).toNat)
      obtain ⟨e2, h2⟩ := sectionLoop_anomalies_mono data frontier n (off + SECTION_HDR_SIZE
        + ((u32At data (off + 4)).getD 0).toNat * ((u64At data (off + 8)).getD 0).toNat)
        (decodeSection data frontier tr kind (off + SECTION_HDR_SIZE)
          (((u32At data (off + 4)).getD 0).toNat) (((u64At data (off + 8)).getD 0).toNat))
      have hano' := hano
      rw [h2, h1] at hano'
      simp only [List.append_eq_nil_iff] at hano'
      obtain ⟨⟨hano10, hano11⟩, -⟩ := hano'
      have hsec : (decodeSection data frontier tr kind (off + SECTION_HDR_SIZE)
          (((u32At data (off + 4)).getD 0).toNat) (((u64At data (off + 8)).getD 0).toNat)).anomalies
          = [] := by
        rw [h1, hano10, hano11]; rfl
      exact ih _ _
        (decodeSection_events_ordered data frontier tr kind _ _ _ hord hsec hano10) hano hsec

private theorem foldl_writes (f : Trace → α → Trace) (hf : ∀ tr x, (f tr x).writes = tr.writes)
    (xs : List α) (init : Trace) : (xs.foldl f init).writes = init.writes := by
  induction xs generalizing init with
  | nil => rfl
  | cons x xs ih => rw [List.foldl_cons, ih (f init x), hf]

private theorem foldl_anomalies (f : Trace → α → Trace)
    (hf : ∀ tr x, ∃ e, (f tr x).anomalies = tr.anomalies ++ e)
    (xs : List α) (init : Trace) : ∃ e, (xs.foldl f init).anomalies = init.anomalies ++ e := by
  induction xs generalizing init with
  | nil => exact ⟨[], by simp⟩
  | cons x xs ih =>
    rw [List.foldl_cons]
    obtain ⟨e1, h1⟩ := hf init x
    obtain ⟨e2, h2⟩ := ih (f init x)
    exact ⟨e1 ++ e2, by rw [h2, h1, List.append_assoc]⟩

theorem threadCheck_writes (tr : Trace) (c : CallSpan) :
    (threadCheck tr c).writes = tr.writes := by
  unfold threadCheck
  split
  · rfl
  · split <;> rfl

theorem threadCheck_anomalies (tr : Trace) (c : CallSpan) :
    ∃ e, (threadCheck tr c).anomalies = tr.anomalies ++ e := by
  unfold threadCheck
  split
  · exact ⟨_, rfl⟩
  · split <;> first | exact ⟨_, rfl⟩ | exact ⟨[], by simp⟩

theorem crossingStep_writes (tr : Trace) (c : CallSpan) (i : Nat) (o : CallSpan) (j : Nat) :
    (crossingStep tr c i o j).writes = tr.writes := by
  unfold crossingStep
  split
  · rfl
  · split <;> rfl

theorem crossingStep_anomalies (tr : Trace) (c : CallSpan) (i : Nat) (o : CallSpan) (j : Nat) :
    ∃ e, (crossingStep tr c i o j).anomalies = tr.anomalies ++ e := by
  unfold crossingStep
  split
  · exact ⟨[], by simp⟩
  · split <;> first | exact ⟨_, rfl⟩ | exact ⟨[], by simp⟩

theorem crossingCheck_writes (calls : List CallSpan) (tr : Trace) (c : CallSpan) (i : Nat) :
    (crossingCheck calls tr c i).writes = tr.writes := by
  unfold crossingCheck
  apply foldl_writes
  intro tr0 ⟨o, j⟩
  exact crossingStep_writes tr0 c i o j

theorem crossingCheck_anomalies (calls : List CallSpan) (tr : Trace) (c : CallSpan) (i : Nat) :
    ∃ e, (crossingCheck calls tr c i).anomalies = tr.anomalies ++ e := by
  unfold crossingCheck
  apply foldl_anomalies
  intro tr0 ⟨o, j⟩
  exact crossingStep_anomalies tr0 c i o j

theorem validateIntervals_writes (tr : Trace) :
    (validateIntervals tr).writes = tr.writes := by
  unfold validateIntervals
  apply foldl_writes
  intro tr0 ⟨c, i⟩
  rw [crossingCheck_writes, threadCheck_writes]

theorem validateIntervals_anomalies (tr : Trace) :
    ∃ e, (validateIntervals tr).anomalies = tr.anomalies ++ e := by
  unfold validateIntervals
  apply foldl_anomalies
  intro tr0 ⟨c, i⟩
  obtain ⟨e1, h1⟩ := threadCheck_anomalies tr0 c
  obtain ⟨e2, h2⟩ := crossingCheck_anomalies tr0.calls (threadCheck tr0 c) c i
  exact ⟨e1 ++ e2, by rw [h2, h1, List.append_assoc]⟩

/-- Decode postcondition (Timeline.tla TraceOrdered, writes half): an
    anomaly-free decode yields position-ordered writes. -/
theorem decodeTtfx_writes_ordered {data : ByteArray} {tr : Trace}
    (h : decodeTtfx data = .ok tr) (hano : tr.anomalies = []) :
    PositionOrdered tr.writes := by
  unfold decodeTtfx at h
  split at h
  · nomatch h
  · split at h
    · nomatch h
    · try dsimp only at h
      split at h
      · nomatch h
      · try dsimp only at h
        cases h
        rw [validateIntervals_writes]
        obtain ⟨e, he⟩ := validateIntervals_anomalies _
        rw [he] at hano
        rw [List.append_eq_nil_iff] at hano
        exact sectionLoop_writes_ordered _ _ _ _ _ trivial hano.1 rfl

private theorem foldl_events (f : Trace → α → Trace) (hf : ∀ tr x, (f tr x).events = tr.events)
    (xs : List α) (init : Trace) : (xs.foldl f init).events = init.events := by
  induction xs generalizing init with
  | nil => rfl
  | cons x xs ih => rw [List.foldl_cons, ih (f init x), hf]

theorem threadCheck_events (tr : Trace) (c : CallSpan) :
    (threadCheck tr c).events = tr.events := by
  unfold threadCheck
  split
  · rfl
  · split <;> rfl

theorem crossingStep_events (tr : Trace) (c : CallSpan) (i : Nat) (o : CallSpan) (j : Nat) :
    (crossingStep tr c i o j).events = tr.events := by
  unfold crossingStep
  split
  · rfl
  · split <;> rfl

theorem crossingCheck_events (calls : List CallSpan) (tr : Trace) (c : CallSpan) (i : Nat) :
    (crossingCheck calls tr c i).events = tr.events := by
  unfold crossingCheck
  apply foldl_events
  intro tr0 ⟨o, j⟩
  exact crossingStep_events tr0 c i o j

theorem validateIntervals_events (tr : Trace) :
    (validateIntervals tr).events = tr.events := by
  unfold validateIntervals
  apply foldl_events
  intro tr0 ⟨c, i⟩
  rw [crossingCheck_events, threadCheck_events]

/-- Decode postcondition (Timeline.tla TraceOrdered, events half): an
    anomaly-free decode yields position-ordered events. -/
theorem decodeTtfx_events_ordered {data : ByteArray} {tr : Trace}
    (h : decodeTtfx data = .ok tr) (hano : tr.anomalies = []) :
    EventsOrdered tr.events := by
  unfold decodeTtfx at h
  split at h
  · nomatch h
  · split at h
    · nomatch h
    · try dsimp only at h
      split at h
      · nomatch h
      · try dsimp only at h
        cases h
        rw [validateIntervals_events]
        obtain ⟨e, he⟩ := validateIntervals_anomalies _
        rw [he] at hano
        rw [List.append_eq_nil_iff] at hano
        exact sectionLoop_events_ordered _ _ _ _ _ trivial hano.1 rfl

end Proofs

end Forensicator.Parse

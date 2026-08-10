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

private def sectionRecordLoop (data : ByteArray) (frontier : Position) (kind : UInt32)
    (body recordSize recordCnt : Nat) (tr : Trace) (i : Nat) : Trace :=
  if h : i < recordCnt then
    let off := body + i * recordSize
    if off + recordSize > data.size then
      { tr with anomalies := tr.anomalies ++
          [anom off s!"ttfx: truncated section {kind} at record {i}"] }
    else
      sectionRecordLoop data frontier kind body recordSize recordCnt
        (decodeRecord data frontier tr kind off) (i + 1)
  else tr
termination_by recordCnt - i

private def decodeSection (data : ByteArray) (frontier : Position) (tr : Trace)
    (kind : UInt32) (body recordSize recordCnt : Nat) : Trace :=
  match wantSize kind with
  | none => tr
  | some want =>
    if recordSize != want then
      { tr with anomalies := tr.anomalies ++
          [anom body s!"ttfx: section {kind} record_size {recordSize} != {want}"] }
    else sectionRecordLoop data frontier kind body recordSize recordCnt tr 0

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




/- ====================================================================
   Decode postconditions (Timeline.tla TraceOrdered, writes half):
   an anomaly-free decode yields position-ordered writes.
   ==================================================================== -/

section Proofs

open Forensicator.Spec (PositionOrdered)

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

/-- Content of the write-order check: no anomalies ⇒ previous last write's
    position ≤ the new write's position. -/
theorem decodeWrite_last_le (data : ByteArray) (frontier : Position) (tr : Trace) (off : Nat)
    (hano : (decodeWrite data frontier tr off).anomalies = [])
    (l : WriteRecord) (hl : tr.writes.getLast? = some l) :
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
    (hord : PositionOrdered tr.writes)
    (hano : (decodeWrite data frontier tr off).anomalies = []) :
    PositionOrdered (decodeWrite data frontier tr off).writes := by
  have hw : (decodeWrite data frontier tr off).writes
      = tr.writes ++ [{ pos := (u64At data off).getD 0, va := (u64At data (off + 8)).getD 0,
                        data := sliceExact data (((u32At data (off + 20)).getD 0).toNat)
                          (((u32At data (off + 16)).getD 0).toNat),
                        provenance := prov off }] := rfl
  rw [hw]
  exact PositionOrdered.append_singleton hord
    (fun l hl => decodeWrite_last_le data frontier tr off hano l hl)

theorem sectionRecordLoop_anomalies_mono (data : ByteArray) (frontier : Position) (kind : UInt32)
    (body recordSize recordCnt : Nat) (tr : Trace) (i : Nat) :
    ∃ e, (sectionRecordLoop data frontier kind body recordSize recordCnt tr i).anomalies
        = tr.anomalies ++ e := by
  fun_induction sectionRecordLoop data frontier kind body recordSize recordCnt tr i
  · exact ⟨_, rfl⟩
  · rename_i tr i hlt off hfit ih
    obtain ⟨e1, h1⟩ := decodeRecord_anomalies data frontier tr kind off
    obtain ⟨e2, h2⟩ := ih
    exact ⟨e1 ++ e2, by rw [h2, h1, List.append_assoc]⟩
  · exact ⟨[], by simp⟩

theorem sectionRecordLoop_writes_frame (data : ByteArray) (frontier : Position) (kind : UInt32)
    (body recordSize recordCnt : Nat) (tr : Trace) (i : Nat) (h : kind ≠ SEC_WRITES) :
    (sectionRecordLoop data frontier kind body recordSize recordCnt tr i).writes
      = tr.writes := by
  fun_induction sectionRecordLoop data frontier kind body recordSize recordCnt tr i
  · rfl
  · rename_i tr i hlt off hfit ih
    rw [ih]
    exact decodeRecord_writes_frame data frontier tr kind off h
  · rfl

theorem sectionRecordLoop_writes_ordered (data : ByteArray) (frontier : Position)
    (body recordSize recordCnt : Nat) (tr : Trace) (i : Nat)
    (hord : PositionOrdered tr.writes)
    (hano : (sectionRecordLoop data frontier SEC_WRITES body recordSize recordCnt tr i).anomalies = [])
    (hano0 : tr.anomalies = []) :
    PositionOrdered
      (sectionRecordLoop data frontier SEC_WRITES body recordSize recordCnt tr i).writes := by
  fun_induction sectionRecordLoop data frontier SEC_WRITES body recordSize recordCnt tr i
  · rename_i tr i hlt htr
    rw [hano0] at hano
    simp at hano
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
  · exact hord

theorem decodeSection_anomalies (data : ByteArray) (frontier : Position) (tr : Trace)
    (kind : UInt32) (body recordSize recordCnt : Nat) :
    ∃ e, (decodeSection data frontier tr kind body recordSize recordCnt).anomalies
        = tr.anomalies ++ e := by
  unfold decodeSection
  split
  · exact ⟨[], by simp⟩
  · split
    · exact ⟨_, rfl⟩
    · exact sectionRecordLoop_anomalies_mono data frontier kind body recordSize recordCnt tr 0

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
        exact sectionRecordLoop_writes_ordered data frontier body recordSize recordCnt tr 0
          hord hano hano0
      · have hk' : kind ≠ SEC_WRITES := fun heq => hk (beq_iff_eq.2 heq)
        rw [sectionRecordLoop_writes_frame data frontier kind body recordSize recordCnt tr 0 hk']
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

end Proofs

end Forensicator.Parse

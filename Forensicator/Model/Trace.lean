/- TTD trace views: source-scoped execution points and interval queries.
   The pure payload model retains last-write semantics; incomplete payloads
   produce unknown memory. Supporting modules are resolved separately.
   Address arithmetic is Nat-lifted so ranges never wrap at UInt64 max. -/
import Forensicator.Model.Execution

namespace Forensicator.Model

/-- Pseudo stream-type in provenance for facts decoded from a .ttfx file. -/
def TTFX_STREAM_TYPE : UInt32 := 0x54465854

/-- One recorded memory write (Timeline.tla wr_pos/wr_addr/wr_val generalized
    to a byte range). `len = 0` (eager): the record is payload-backed and
    `endVaNat` is `va + data.size`. `len ≠ 0` (lazy index entry): the record
    is metadata-only — `endVaNat` is `va + len`, `data` is empty and
    `byteAt` fails closed (`none`: unknown until fetched). -/
structure WriteRecord where
  pos : Position
  va : VA
  data : ByteArray
  len : UInt64 := 0
  provenance : Provenance := {}
  deriving Inhabited

/-- End VA as Nat (no saturation). -/
def WriteRecord.endVaNat (w : WriteRecord) : Nat :=
  w.va.toNat + if w.len == 0 then w.data.size else w.len.toNat

/-- The write covers `va` (w.va ≤ va < endVa). -/
def WriteRecord.covers (w : WriteRecord) (va : VA) : Prop :=
  w.va.toNat ≤ va.toNat ∧ va.toNat < w.endVaNat

instance (w : WriteRecord) (va : VA) : Decidable (w.covers va) :=
  inferInstanceAs (Decidable (_ ∧ _))

/-- The written byte at `va` (requires coverage for a meaningful result). -/
def WriteRecord.byteAt (w : WriteRecord) (va : VA) : Option UInt8 :=
  let idx := va.toNat - w.va.toNat
  if w.len == 0 && idx < w.data.size then some (w.data.get! idx) else none

abbrev TraceEventKind := ExecutionEventKind

structure TraceEvent extends ExecutionEvent where
  pos : Position
  deriving Inhabited

/-- A call span on a thread (TTD.Calls object). -/
structure CallSpan where
  threadId : UInt32
  interval : Interval
  deriving Repr, Inhabited

/-- The recorded trace (Timeline.tla state). Invariants (ordered logs,
    nesting, intervals within lifetimes) were enforced by the eager decoder
    (removed 2026-08-13); on the proxy path they are enforced client-side
    as index/event windows arrive and recorded in `anomalies`. -/
structure Trace where
  initMem : List MemoryRegionInfo := []
  writes : List WriteRecord := []
  events : List TraceEvent := []
  threads : List (UInt32 × Interval) := []
  calls : List CallSpan := []
  frontier : Position := 0
  anomalies : List Anomaly := []
  deriving Inhabited

/-- The last write in `ws` (list order) covering `va`. -/
def lastCoveringWrite (ws : List WriteRecord) (va : VA) : Option WriteRecord :=
  ws.reverse.find? fun w => decide (w.covers va)

namespace Trace

/-- Index-free last-writer view (Timeline.tla LastWriter): the last write
    covering `va` at or before `t`. Raw-log view; see `valueAt`. -/
def lastWriter (tr : Trace) (va : VA) (t : Position) : Option WriteRecord :=
  lastCoveringWrite (tr.writes.filter fun w => w.pos ≤ t) va

/-- Byte at `va` at position `t` (Timeline.tla ValueAt): last covering write's
    byte, else init_mem contents. No initial backing region means unknown. -/
def valueAt (tr : Trace) (va : VA) (t : Position) : Option UInt8 :=
  match tr.initMem.find? fun r => decide (r.covers va) with
  | none => none
  | some region =>
    match lastCoveringWrite (tr.writes.filter fun w => w.pos ≤ t) va with
    | some w => w.byteAt va
    | none =>
      let idx := va.toNat - region.vaStart.toNat
      if idx < region.data.size then some (region.data.get! idx) else none

/-- All writes overlapping `[va, va+len)` in (t1, t2] (Timeline.tla WritesBetween). -/
def writesBetween (tr : Trace) (va : VA) (len : UInt64) (t1 t2 : Position) : List WriteRecord :=
  tr.writes.filter fun w =>
    decide (t1 < w.pos ∧ w.pos ≤ t2
      ∧ w.va.toNat < va.toNat + len.toNat ∧ va.toNat < w.endVaNat)

/-- Validate a temporal query's domain. Equal bounds denote an empty interval. -/
def validateBounds (tr : Trace) (a b : Position) : Except String Unit :=
  if b < a then .error "reversed timeline interval"
  else if tr.frontier < b then .error "timeline interval exceeds frontier"
  else .ok ()

/-- Events occurring exactly at `t`; earlier exceptions do not carry forward. -/
def eventsAt (tr : Trace) (t : Position) : List TraceEvent :=
  tr.events.filter fun e => e.pos == t

/-- Stable record-order history over `(a,b]`, with explicit invalid-bound errors. -/
def eventsBetween (tr : Trace) (a b : Position) : Except String (List TraceEvent) :=
  match tr.validateBounds a b with
  | .error err => .error err
  | .ok () => .ok (tr.events.filter fun e => decide (a < e.pos ∧ e.pos ≤ b))

/-- Validated temporal and address range query. The raw `writesBetween` remains
    available for internal index calculations. Empty address ranges match nothing. -/
def writesBetweenChecked (tr : Trace) (va : VA) (len : UInt64) (a b : Position) :
    Except String (List WriteRecord) := do
  tr.validateBounds a b
  if va.toNat + len.toNat > 2^64 then .error "write query address range overflows"
  else if len == 0 then pure []
  else pure (tr.writesBetween va len a b)

/-- Historical exception view at or before `t` (Timeline.tla ExceptionsAt).
    Use `eventsAt` when constructing a point or selecting a current exception. -/
def exceptionsAt (tr : Trace) (t : Position) : List TraceEvent :=
  tr.events.filter fun e => e.kind == .Exception && e.pos ≤ t

/-- Thread lifetime containing `t`, if any. -/
def threadAt (tr : Trace) (threadId : UInt32) (t : Position) : Option Interval :=
  (tr.threads.find? fun (id, iv) => id == threadId && iv.contains t).map (·.2)

/-- Write one byte at `va` into the first covering region (fail-closed:
    unmapped or short-data regions drop the byte; search stops at the first
    covering region either way, as in the Rust `iter_mut().find`). -/
def updateRegionByte (regs : List MemoryRegionInfo) (va : Nat) (byte : UInt8) :
    List MemoryRegionInfo :=
  match regs with
  | [] => []
  | r :: rest =>
    if r.vaStart.toNat ≤ va ∧ va < r.vaStart.toNat + r.size.toNat then
      let idx := va - r.vaStart.toNat
      if idx < r.data.size then
        { r with data := r.data.set! idx byte } :: rest
      else r :: rest
    else r :: updateRegionByte rest va byte

/-- Overlay a write onto the region list (fail-closed: bytes outside every
    region are dropped). -/
def applyWrite (regions : List MemoryRegionInfo) (w : WriteRecord) : List MemoryRegionInfo :=
  (List.range w.data.size).foldl (init := regions) fun regs off =>
    updateRegionByte regs (w.va.toNat + off) (w.data.get! off)

/-- Active-module projection with malformed observations preserved as anomalies.
    An ambiguous overlapping load removes the conflicting descriptors and is not
    accepted. Unload followed by load at the same base is valid in record order. -/
def moduleStateAt (tr : Trace) (t : Position) : List Module × List Anomaly :=
  (tr.events.filter fun e => e.pos ≤ t).foldl (init := ([], [])) fun (mods, anomalies) e =>
    match e.kind with
    | .ModuleLoad =>
      let overlaps (m : Module) := decide (m.baseVa.toNat < e.address.toNat + e.size.toNat
        ∧ e.address.toNat < m.baseVa.toNat + m.size.toNat)
      if e.size == 0 || e.address.toNat + e.size.toNat > 2^64 then
        (mods, anomalies ++ [Anomaly.ofProv e.provenance "invalid module range"])
      else if mods.any overlaps then
        (mods.filter (fun m => !overlaps m),
         anomalies ++ [Anomaly.ofProv e.provenance "overlapping module"])
      else
        (mods ++ [{ name := e.name, baseVa := e.address, size := e.size
                    provenance := e.provenance }], anomalies)
    | .ModuleUnload =>
      if mods.any (fun m => m.baseVa == e.address) then
        (mods.filter (fun m => m.baseVa != e.address), anomalies)
      else (mods, anomalies ++ [Anomaly.ofProv e.provenance "unload of unknown module"])
    | .Exception => (mods, anomalies)

def modulesAt (tr : Trace) (t : Position) : List Module := (tr.moduleStateAt t).1

def moduleAnomaliesAt (tr : Trace) (t : Position) : List Anomaly := (tr.moduleStateAt t).2

/-- Malformed lifetimes cannot provide positive thread-state evidence. -/
def validLifetime (tr : Trace) (iv : Interval) : Bool :=
  iv.start ≤ tr.frontier && match iv.stop with
    | none => true
    | some stop => iv.start ≤ stop && stop ≤ tr.frontier

private def activeLifetimes (tr : Trace) (t : Position) : List (UInt32 × Interval) :=
  tr.threads.filter fun (_, iv) => tr.validLifetime iv && iv.contains t

/-- Proxy v1 supplies lifetimes only. Absence of context is explicit and never
    represented by zero registers or an empty recovered stack. -/
def threadsAt (tr : Trace) (t : Position) : List ThreadState :=
  let active := tr.activeLifetimes t
  (active.filter fun (id, _) => (active.filter (fun x => x.1 == id)).length == 1).map
    fun (id, iv) =>
      { id, lifetime := some iv
        registers := .unavailable "trace has no register observation"
        stackRange := .unavailable "trace has no stack-bound observation"
        frames := .unavailable "trace has no recovered frames"
        tebVa := .unavailable "trace has no TEB observation" }

def threadAnomaliesAt (tr : Trace) (t : Position) : List Anomaly :=
  let invalid := (tr.threads.filter (fun (_, iv) => !tr.validLifetime iv)).map
    fun (id, _) => Anomaly.internal s!"invalid lifetime for thread {id}"
  let active := tr.activeLifetimes t
  invalid ++ (active.filter (fun (id, _) =>
    (active.filter (fun x => x.1 == id)).length > 1)).map
      (fun (id, _) => Anomaly.internal s!"overlapping lifetimes for thread {id}")

/-- A metadata-only write invalidates all bytes of each overlapping backing
    region. This is conservative at region granularity: unaffected bytes may
    become unknown too, but stale bytes can never be exposed. Initial mapping
    observations are retained separately. Later short payloads do not manufacture
    full region knowledge; the proxy's page preparation provides that capability. -/
def applyKnownWrite (regions : List MemoryRegionInfo) (w : WriteRecord) :
    List MemoryRegionInfo :=
  if w.len == 0 then applyWrite regions w
  else regions.map fun r =>
    if r.vaStart.toNat < w.endVaNat ∧ w.va.toNat < r.vaStart.toNat + r.size.toNat then
      { r with data := ByteArray.empty }
    else r

/-- Build known backing while retaining rejected-region anomalies. -/
def pointMemory (regions : List MemoryRegionInfo) : MemoryState × List Anomaly :=
  let (space, anomalies) := regions.foldl
    (init := (Spec.AddressSpace.new 1000000, ([] : List Anomaly))) fun (sp, anomalies) r =>
      match sp.addRegion { vaStart := r.vaStart, size := r.size, data := r.data
                           protection := r.protection, state := r.state
                           classification := r.regionClass.getD .Other } with
      | .ok sp' => (sp', anomalies)
      | .error a => (sp, anomalies ++ [a])
  ({ space
     mappings := regions.map fun r =>
       { vaStart := r.vaStart, size := r.size, protection := r.protection
         state := r.state, memType := r.memType }
     mappingCoverage := if regions.isEmpty then .unknown else .incomplete
     byteCoverage := if regions.any (fun r => !r.data.isEmpty) then .incomplete else .unknown },
   anomalies)

/-- A bounded, source-scoped execution point. Memory is a conservative payload
    view; availability says nothing about complete mappings or stacks. -/
def pointAt (tr : Trace) (t : Position) (source : String := "") : Option ExecutionPoint :=
  if tr.frontier < t then none
  else
    let writes := tr.writes.filter fun w => w.pos ≤ t
    let regions := writes.foldl applyKnownWrite tr.initMem
    let (memory, memoryAnomalies) := pointMemory regions
    let unknownWrites := if writes.any (fun w => w.len != 0) then
      [Anomaly.internal "metadata-only writes leave affected backing bytes unknown"] else []
    some {
      id := { source, position := .trace t }
      memory, events := (tr.eventsAt t).map (·.toExecutionEvent)
      threads := tr.threadsAt t
      threadCoverage := .incomplete, eventCoverage := .incomplete
      anomalies := tr.anomalies ++ tr.moduleAnomaliesAt t ++ tr.threadAnomaliesAt t
        ++ memoryAnomalies ++ unknownWrites }

/-- Resolve supporting artifacts for exactly the execution point being analyzed. -/
def analysisAt (tr : Trace) (t : Position) (source : String := "") : Option AnalysisInput := do
  let point ← tr.pointAt t source
  pure { point, context := { pointId := point.id, modules := tr.modulesAt t } }

end Trace

end Forensicator.Model

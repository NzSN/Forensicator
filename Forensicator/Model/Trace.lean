/- Forensicator.Model.Trace — TTD trace model (port of model/trace.rs,
   the Rust realization of specs/Timeline.tla). Views over the write/event
   logs; `snapshot` materializes any position into a Dump + AddressSpace.

   Divergences from Rust (all deliberate, Nat-lifted arithmetic):
   * `end_va` uses `va + size` in Nat — no saturating_add wrap edge.
   * `writes_between` overlap bounds likewise. -/
import Forensicator.Model.Dump
import Forensicator.Spec.AddressSpace

namespace Forensicator.Model

/-- Pseudo stream-type in provenance for facts decoded from a .ttfx file. -/
def TTFX_STREAM_TYPE : UInt32 := 0x54465854

/-- One recorded memory write (Timeline.tla wr_pos/wr_addr/wr_val generalized
    to a byte range). -/
structure WriteRecord where
  pos : Position
  va : VA
  data : ByteArray
  provenance : Provenance := {}
  deriving Inhabited

/-- End VA as Nat (no saturation). -/
def WriteRecord.endVaNat (w : WriteRecord) : Nat := w.va.toNat + w.data.size

/-- The write covers `va` (w.va ≤ va < endVa). -/
def WriteRecord.covers (w : WriteRecord) (va : VA) : Prop :=
  w.va.toNat ≤ va.toNat ∧ va.toNat < w.endVaNat

instance (w : WriteRecord) (va : VA) : Decidable (w.covers va) :=
  inferInstanceAs (Decidable (_ ∧ _))

/-- The written byte at `va` (requires coverage for a meaningful result). -/
def WriteRecord.byteAt (w : WriteRecord) (va : VA) : Option UInt8 :=
  let idx := va.toNat - w.va.toNat
  if idx < w.data.size then some (w.data.get! idx) else none

inductive TraceEventKind where
  | Exception | ModuleLoad | ModuleUnload
  deriving Repr, DecidableEq, BEq, Inhabited

structure TraceEvent where
  pos : Position
  kind : TraceEventKind
  code : UInt32 := 0
  address : VA := 0
  threadId : UInt32 := 0
  name : String := ""
  size : UInt64 := 0
  provenance : Provenance := {}
  deriving Inhabited

/-- [start, end) interval; `end = none` while open (the spec's `end = -1`). -/
structure Interval where
  start : Position
  stop : Option Position
  deriving Repr, DecidableEq, BEq, Inhabited

def Interval.contains (iv : Interval) (t : Position) : Bool :=
  iv.start ≤ t && (match iv.stop with | none => true | some e => t < e)

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

/-- A materialized position: the time-point view analyzers consume. -/
structure Snapshot where
  dump : Dump
  space : Spec.AddressSpace
  pos : Position
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
    byte, else init_mem contents. Snapshot-faithful: no init_mem region → none. -/
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

/-- Exception events at or before `t` (Timeline.tla ExceptionsAt). -/
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

/-- Materialize position `t` (Timeline.tla CursorBounded: none beyond frontier). -/
def snapshot (tr : Trace) (t : Position) : Option Snapshot :=
  if tr.frontier < t then none
  else
    let regions := (tr.writes.filter fun w => w.pos ≤ t).foldl applyWrite tr.initMem
    let modules := (tr.events.filter fun e => e.pos ≤ t).foldl
      (fun (mods : List Module) e =>
        match e.kind with
        | .ModuleLoad => mods ++ [{ name := e.name, baseVa := e.address, size := e.size
                                    provenance := e.provenance }]
        | .ModuleUnload => mods.filter fun m => m.baseVa != e.address
        | .Exception => mods)
      []
    let exception := (tr.exceptionsAt t).getLast?.map fun e =>
      ({ code := e.code, address := e.address, threadId := e.threadId
         provenance := e.provenance } : ExceptionInfo)
    let dump0 : Dump := {
      modules := modules
      memoryRegions := regions
      exception := exception
      anomalies := tr.anomalies
      annotations := [("ttfx_position", hexUpper t)]
    }
    let dump := { dump0 with anomalies := dump0.anomalies ++ dump0.validateModel }
    let space := regions.foldl (init := Spec.AddressSpace.new 1000000) fun sp r =>
      match sp.addRegion { vaStart := r.vaStart, size := r.size, data := r.data
                           protection := r.protection, state := r.state
                           classification := r.regionClass.getD .Other } with
      | .ok sp' => sp'
      | .error _ => sp
    some ⟨dump, space, t⟩

end Trace

end Forensicator.Model

/- Source-neutral execution views. A point contains memory, exact events and
   thread knowledge. Supporting capture/runtime facts are scoped separately. -/
import Forensicator.Model.ExecutionTypes
import Forensicator.Spec.AddressSpace

namespace Forensicator.Model

inductive PointPosition where
  | capture
  | trace (value : Position)
  deriving Repr, DecidableEq, BEq, Inhabited

/-- Source keys are supplied by the adapter/session. A capture does not acquire
    a fictitious TTD coordinate. Evidence is reusable only at the same identity. -/
structure PointId where
  source : String := ""
  position : PointPosition := .capture
  deriving Repr, DecidableEq, BEq, Inhabited

inductive Knowledge (α : Type) where
  | unknown
  | unavailable (reason : String)
  | known (value : α)
  deriving Inhabited

def Knowledge.toOption : Knowledge α → Option α
  | .known value => some value
  | _ => none

inductive Coverage where
  | unknown | incomplete | complete
  deriving Repr, DecidableEq, BEq, Inhabited

structure AddressRange where
  va : VA
  size : UInt64
  deriving Repr, DecidableEq, BEq, Inhabited

def AddressRange.covers (r : AddressRange) (va : VA) (len : Nat := 1) : Bool :=
  decide (r.va.toNat ≤ va.toNat ∧ va.toNat + len ≤ r.va.toNat + r.size.toNat)

inductive MemoryRead where
  | known (bytes : ByteArray)
  | absent
  | unknown
  deriving Inhabited

/-- Known bytes and mapping observations have independent coverage. A sparse
    address space alone is never evidence that its gaps were unmapped. -/
structure MemoryState where
  space : Spec.AddressSpace := Spec.AddressSpace.new 1000000
  mappings : List MemoryInfoEntry := []
  mappingCoverage : Coverage := .unknown
  byteCoverage : Coverage := .unknown
  absentRanges : List AddressRange := []
  deriving Inhabited

def MemoryState.knownAbsent (m : MemoryState) (va : VA) (len : Nat := 1) : Bool :=
  if len == 0 then false
  else m.absentRanges.any (fun r => r.covers va len)
    || m.mappings.any (fun r => r.state != .Commit
      && (AddressRange.mk r.vaStart r.size).covers va len)

def MemoryState.read (m : MemoryState) (va : VA) (len : Nat) : MemoryRead :=
  if va.toNat + len > 2^64 then .unknown
  else if len == 0 then .known ByteArray.empty
  else if m.knownAbsent va len then .absent
  else match m.space.read va len with
    | some bytes => .known bytes
    | none => .unknown

/-- Half-open lifetime; no stop means still open. -/
structure Interval where
  start : Position
  stop : Option Position
  deriving Repr, DecidableEq, BEq, Inhabited

def Interval.contains (iv : Interval) (t : Position) : Bool :=
  iv.start ≤ t && (match iv.stop with | none => true | some e => t < e)

inductive ExecutionEventKind where
  | Exception | ModuleLoad | ModuleUnload
  deriving Repr, DecidableEq, BEq, Inhabited

/-- Payload of an event occurring at the containing point. Trace records add
    a position; captured events need no fabricated trace coordinate. -/
structure ExecutionEvent where
  kind : ExecutionEventKind
  code : UInt32 := 0
  address : VA := 0
  threadId : UInt32 := 0
  name : String := ""
  size : UInt64 := 0
  flags : UInt32 := 0
  parameters : List UInt64 := []
  context : Option RegisterSet := none
  provenance : Provenance := {}
  deriving Inhabited

def ExecutionEvent.exceptionInfo (e : ExecutionEvent) : Option ExceptionInfo :=
  if e.kind == .Exception then
    some { code := e.code, address := e.address, threadId := e.threadId
           flags := e.flags, parameters := e.parameters, context := e.context
           provenance := e.provenance }
  else none

structure RecoveredFrame where
  instruction : VA
  stackPointer : VA
  framePointer : Option VA := none
  confidence : Float := 0
  provenance : Provenance := {}
  deriving Inhabited

structure RecoveredStack where
  frames : List RecoveredFrame := []
  coverage : Coverage := .incomplete
  confidence : Float := 0
  deriving Inhabited

structure ThreadState where
  id : UInt32
  lifetime : Option Interval := none
  registers : Knowledge RegisterSet := .unknown
  stackRange : Knowledge AddressRange := .unknown
  frames : Knowledge RecoveredStack := .unknown
  tebVa : Knowledge VA := .unknown
  provenance : Provenance := {}
  deriving Inhabited

/-- The start distinguishes reused IDs when the source knows a lifetime. -/
def ThreadState.key (t : ThreadState) : UInt32 × Option Position :=
  (t.id, t.lifetime.map (·.start))

/-- Neutral observed-thread record for existing stack walkers. Missing context
    prevents conversion; it never becomes an all-zero register file. -/
def ThreadState.observedThread (t : ThreadState) : Option Thread := do
  let registers ← t.registers.toOption
  let stack ← t.stackRange.toOption
  pure { id := t.id, registers, stackVa := stack.va, stackSize := stack.size
         tebVa := t.tebVa.toOption.getD 0, provenance := t.provenance }

structure ExecutionPoint where
  id : PointId
  memory : MemoryState := {}
  events : List ExecutionEvent := []
  threads : List ThreadState := []
  threadCoverage : Coverage := .unknown
  eventCoverage : Coverage := .unknown
  anomalies : List Anomaly := []
  deriving Inhabited

def ExecutionPoint.space (p : ExecutionPoint) : Spec.AddressSpace := p.memory.space

/-- A lookup is by thread instance, not just a potentially reused OS ID. -/
def ExecutionPoint.threadAt (p : ExecutionPoint)
    (key : UInt32 × Option Position) : Option ThreadState :=
  match p.threads.filter (fun t => t.key == key) with
  | [t] => some t
  | _ => none

structure PositionedEvidence where
  pointId : PointId
  annotations : List (String × String) := []
  v8heapExt : Option V8HeapExt := none
  deriving Inhabited

/-- Supporting context is resolved for one point. `modules` is the active
    projection of shared artifact descriptors; observations carry their own
    point identity and cannot leak when a caller moves the cursor. -/
structure AnalysisContext where
  pointId : PointId
  systemInfo : Option SystemInfo := none
  modules : List Module := []
  observations : List PositionedEvidence := []
  deriving Inhabited

structure AnalysisInput where
  point : ExecutionPoint
  context : AnalysisContext
  /-- Explicit index into point.events. Without selection only a sole exception
      is used; multiple exceptions are not silently collapsed. -/
  selectedEvent : Option Nat := none
  deriving Inhabited

def AnalysisInput.space (a : AnalysisInput) : Spec.AddressSpace := a.point.memory.space

def AnalysisInput.modules (a : AnalysisInput) : List Module :=
  if a.context.pointId == a.point.id then a.context.modules else []

def AnalysisInput.systemInfo (a : AnalysisInput) : Option SystemInfo :=
  if a.context.pointId.source == a.point.id.source then a.context.systemInfo else none

def AnalysisInput.exception (a : AnalysisInput) : Option ExceptionInfo :=
  match a.selectedEvent with
  | some i => a.point.events[i]?.bind ExecutionEvent.exceptionInfo
  | none =>
    match a.point.events.filterMap ExecutionEvent.exceptionInfo with
    | [e] => some e
    | _ => none

def AnalysisInput.threads (a : AnalysisInput) : List Thread :=
  a.point.threads.filterMap ThreadState.observedThread

def AnalysisInput.stackRanges (a : AnalysisInput) : List (UInt32 × VA × UInt64) :=
  a.point.threads.filterMap fun t =>
    t.stackRange.toOption.map fun r => (t.id, r.va, r.size)

def AnalysisInput.memoryInfo (a : AnalysisInput) : List MemoryInfoEntry :=
  a.point.memory.mappings

def AnalysisInput.annotations (a : AnalysisInput) : List (String × String) :=
  (a.context.observations.filter (fun o => o.pointId == a.point.id)).flatMap (·.annotations)

def AnalysisInput.v8heapExt (a : AnalysisInput) : Option V8HeapExt :=
  (a.context.observations.filter (fun o => o.pointId == a.point.id)).findSome? (·.v8heapExt)

def AnalysisInput.anomalies (a : AnalysisInput) : List Anomaly := a.point.anomalies

end Forensicator.Model

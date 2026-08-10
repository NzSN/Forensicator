/- Forensicator.Model.Dump — the assembled dump model (port of model.rs)
   plus `validateModel` (the Model.tla invariant conjuncts that degrade to
   anomalies). The `add_*`/`set_*` transition functions land with the
   minidump decoders (Task 5). -/
import Forensicator.Model.Types

namespace Forensicator.Model

/-- CPU register file. Placeholder until the arch port (Task 5/8): the
    timeline path never materializes registers (snapshot threads = []). -/
structure RegisterSet where
  deriving Inhabited, Repr, DecidableEq

/-- OS platform identifiers. -/
inductive OsPlatform where
  | Windows | Linux | MacOs
  deriving Repr, DecidableEq, BEq, Inhabited

/-- CPU architecture identifiers. -/
inductive CpuArch where
  | X86 | X64 | Arm64
  deriving Repr, DecidableEq, BEq, Inhabited

structure SystemInfo where
  os : OsPlatform
  cpu : CpuArch
  version : UInt32 × UInt32 × UInt32 × UInt32
  provenance : Provenance
  deriving Repr

/-- A loaded module (DLL/EXE). -/
structure Module where
  name : String
  baseVa : VA
  size : UInt64
  checksum : UInt32 := 0
  codeviewGuid : Option ByteArray := none   -- 16 bytes when present
  codeviewAge : Option UInt32 := none
  pdbName : Option String := none
  provenance : Provenance
  deriving Inhabited

/-- A thread in the process. -/
structure Thread where
  id : UInt32
  registers : RegisterSet
  stackVa : VA
  stackSize : UInt64
  tebVa : VA := 0
  provenance : Provenance
  deriving Inhabited

/-- Static description of a memory region from the dump metadata. -/
structure MemoryRegionInfo where
  vaStart : VA
  size : UInt64
  data : ByteArray := ByteArray.empty
  protection : Protection := 0
  state : MemState := .Commit
  memType : MemType := .Private
  provenance : Provenance := {}
  regionClass : Option RegionClass := none
  deriving Inhabited

/-- `va ∈ [vaStart, vaStart + size)` (Nat-lifted, no u64 wrap). -/
def MemoryRegionInfo.covers (r : MemoryRegionInfo) (va : VA) : Prop :=
  r.vaStart.toNat ≤ va.toNat ∧ va.toNat < r.vaStart.toNat + r.size.toNat

instance (r : MemoryRegionInfo) (va : VA) : Decidable (r.covers va) :=
  inferInstanceAs (Decidable (_ ∧ _))

/-- Exception information from the dump. -/
structure ExceptionInfo where
  code : UInt32
  address : VA
  threadId : UInt32
  flags : UInt32 := 0
  parameters : List UInt64 := []
  context : Option RegisterSet := none
  provenance : Provenance
  deriving Inhabited

/-- A MemoryInfoList entry (metadata incl. reserve/free regions). -/
structure MemoryInfoEntry where
  vaStart : VA
  size : UInt64
  protection : UInt32
  state : MemState
  memType : MemType
  deriving Repr

/-- V8HE v2 extension facts captured by the instrumented handler. -/
structure V8HeapExt where
  allocTopVa : VA := 0
  allocLimitVa : VA := 0
  gcState : UInt32 := 0
  lastGcReason : UInt32 := 0
  fatalMessage : Option String := none
  deriving Repr

/-- The assembled dump — the output of the parse pipeline. -/
structure Dump where
  systemInfo : Option SystemInfo := none
  modules : List Module := []
  threads : List Thread := []
  memoryRegions : List MemoryRegionInfo := []
  exception : Option ExceptionInfo := none
  anomalies : List Anomaly := []
  annotations : List (String × String) := []
  memoryInfo : List MemoryInfoEntry := []
  v8heapExt : Option V8HeapExt := none
  fileSize : UInt64 := 0
  deriving Inhabited

namespace Dump

/-- Structural conjuncts of Model.tla ModelInvariant not enforced by types;
    degrades into anomalies, never fails (model.rs:389). -/
def validateModel (d : Dump) : List Anomaly :=
  let moduleOverlaps := d.modules.zipIdx.flatMap fun (a, i) =>
    (d.modules.drop (i + 1)).filterMap fun b =>
      if a.baseVa.toNat < b.baseVa.toNat + b.size.toNat
          && b.baseVa.toNat < a.baseVa.toNat + a.size.toNat then
        some (Anomaly.internal "overlapping module")
      else none
  let provAnomalies :=
    (d.modules.filterMap fun m =>
      if m.provenance.streamType == 0 then some (Anomaly.internal "module without provenance") else none)
    ++ (d.threads.filterMap fun t =>
      if t.provenance.streamType == 0 then some (Anomaly.internal "thread without provenance") else none)
    ++ (d.memoryRegions.filterMap fun r =>
      if r.provenance.streamType == 0 then some (Anomaly.internal "region without provenance") else none)
    ++ (match d.systemInfo with
        | some si => if si.provenance.streamType == 0
            then [Anomaly.internal "system info without provenance"] else []
        | none => [])
    ++ (match d.exception with
        | some e => if e.provenance.streamType == 0
            then [Anomaly.internal "exception without provenance"] else []
        | none => [])
  let stackAnomalies := d.threads.filterMap fun t =>
    if t.stackSize == 0 then some (Anomaly.internal "thread stack size zero") else none
  let annAnomalies := d.annotations.flatMap fun (k, v) =>
    (if k.isEmpty then [Anomaly.internal "annotation key empty"] else [])
    ++ (if v.isEmpty then [Anomaly.internal "annotation value empty"] else [])
  moduleOverlaps ++ provAnomalies ++ stackAnomalies ++ annAnomalies

end Dump

end Forensicator.Model

/- Capture aggregate and its validation; neutral records live in ExecutionTypes. -/
import Forensicator.Model.ExecutionTypes

namespace Forensicator.Model

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

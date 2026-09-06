/- Adapter from a parsed minidump to one source-scoped execution observation. -/
import Forensicator.Model.Dump
import Forensicator.Model.Execution

namespace Forensicator.Model

def ThreadState.ofCaptured (t : Thread) : ThreadState :=
  { id := t.id
    registers := if t.registersKnown then .known t.registers
                 else .unavailable "thread register context is missing or invalid"
    stackRange := .known ⟨t.stackVa, t.stackSize⟩
    frames := .unavailable "stack frames have not been recovered"
    tebVa := if t.tebVa == 0 then .unknown else .known t.tebVa
    provenance := t.provenance }

def ExecutionEvent.ofException (e : ExceptionInfo) : ExecutionEvent :=
  { kind := .Exception, code := e.code, address := e.address, threadId := e.threadId
    flags := e.flags, parameters := e.parameters, context := e.context
    provenance := e.provenance }

/-- This conversion preserves captured facts, not an inferred history. Coverage
    stays partial because the aggregate does not prove stream completeness. -/
def AnalysisInput.ofDump (dump : Dump) (space : Spec.AddressSpace)
    (source : String := "") : AnalysisInput :=
  let id : PointId := { source, position := .capture }
  { point :=
      { id
        memory := { space, mappings := dump.memoryInfo
                    mappingCoverage := if dump.memoryInfo.isEmpty then .unknown else .incomplete
                    byteCoverage := if space.isEmpty then .unknown else .incomplete }
        events := dump.exception.toList.map ExecutionEvent.ofException
        threads := dump.threads.map ThreadState.ofCaptured
        threadCoverage := .incomplete, eventCoverage := .incomplete
        anomalies := dump.anomalies }
    context :=
      { pointId := id, systemInfo := dump.systemInfo, modules := dump.modules
        observations := [{ pointId := id, annotations := dump.annotations
                           v8heapExt := dump.v8heapExt }] } }

end Forensicator.Model

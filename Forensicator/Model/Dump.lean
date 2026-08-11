/- Forensicator.Model.Dump — the assembled dump model (port of model.rs)
   plus `validateModel` (the Model.tla invariant conjuncts that degrade to
   anomalies). The `add_*`/`set_*` transition functions land with the
   minidump decoders (Task 5). -/
import Forensicator.Model.Types

namespace Forensicator.Model

/-- CPU register file: the 32 slots of the x64 CONTEXT layout (arch.rs).
    Index via the `X64` constants below. -/
structure RegisterSet where
  values : Array UInt64
  deriving Inhabited, Repr, DecidableEq

/- x64 register indices (arch.rs x64_indices). -/
namespace X64
def RAX : Nat := 0
def RBX : Nat := 1
def RCX : Nat := 2
def RDX : Nat := 3
def RSI : Nat := 4
def RDI : Nat := 5
def R8 : Nat := 6
def R9 : Nat := 7
def R10 : Nat := 8
def R11 : Nat := 9
def R12 : Nat := 10
def R13 : Nat := 11
def R14 : Nat := 12
def R15 : Nat := 13
def RBP : Nat := 14
def RSP : Nat := 15
def RIP : Nat := 16
def CS : Nat := 17
def DS : Nat := 18
def ES : Nat := 19
def FS : Nat := 20
def GS : Nat := 21
def SS : Nat := 22
def RFLAGS : Nat := 23
def DR0 : Nat := 24
def DR1 : Nat := 25
def DR2 : Nat := 26
def DR3 : Nat := 27
def DR6 : Nat := 28
def DR7 : Nat := 29
end X64

namespace RegisterSet

def new : RegisterSet := ⟨Array.replicate 32 0⟩

def get (r : RegisterSet) (idx : Nat) : UInt64 := r.values.getD idx 0

def set (r : RegisterSet) (idx : Nat) (v : UInt64) : RegisterSet :=
  if idx < 32 then ⟨r.values.set! idx v⟩ else r

def rip (r : RegisterSet) : UInt64 := r.get X64.RIP
def rsp (r : RegisterSet) : UInt64 := r.get X64.RSP
def rbp (r : RegisterSet) : UInt64 := r.get X64.RBP

/-- (offset, register index, size) for the x64 CONTEXT layout. -/
def gprEntries : List (Nat × Nat × Nat) :=
  [(0x78, 0, 8), (0x80, 2, 8), (0x88, 3, 8), (0x90, 1, 8), (0x98, 15, 8),
   (0xA0, 14, 8), (0xA8, 4, 8), (0xB0, 5, 8), (0xB8, 6, 8), (0xC0, 7, 8),
   (0xC8, 8, 8), (0xD0, 9, 8), (0xD8, 10, 8), (0xE0, 11, 8), (0xE8, 12, 8),
   (0xF0, 13, 8), (0xF8, 16, 8)]

def contextLayout : List (Nat × Nat × Nat) :=
  [(0x38, 17, 2), (0x3A, 18, 2), (0x3C, 19, 2), (0x3E, 20, 2), (0x40, 21, 2),
   (0x42, 22, 2), (0x44, 23, 4), (0x48, 24, 8), (0x50, 25, 8), (0x58, 26, 8),
   (0x60, 27, 8), (0x68, 28, 8), (0x70, 29, 8)]
  ++ gprEntries

private def readLe (data : ByteArray) (offset size : Nat) : Option UInt64 :=
  if offset + size ≤ data.size then
    some ((List.range size).foldl
      (fun v i => v ||| ((data.get! (offset + i)).toUInt64 <<< (8 * UInt64.ofNat i))) 0)
  else none

/-- Decode an x64 CONTEXT (Arch.tla DecodeContextSuccess/Truncated).
    Error on < 256 bytes (callers discard partial GPRs, as in Rust). -/
def decodeContext (data : ByteArray) : Except String RegisterSet :=
  if data.size < 256 then
    .error "truncated CONTEXT"
  else
    .ok (contextLayout.foldl (init := RegisterSet.new) fun rs (off, idx, sz) =>
      match readLe data off sz with
      | some v => rs.set idx v
      | none => rs)

end RegisterSet

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

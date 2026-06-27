---- MODULE Model ----
EXTENDS Integers, Sequences, FiniteSets

\* Normalized data types for S1 — what S2-S4 consume.
\* Every fact carries Provenance: which stream + offset it came from.
\* Cross-cutting: no type depends on the minidump parse module.

MaxModules  == 2
MaxThreads  == 2
MaxRegions  == 2
MaxAnomalies == 4

\* ---- Provenance (cross-cutting) ----

\* Provenance is a record, but for Apalache compat we use flat fields.
\* stream_id: 1=SystemInfo, 2=ModuleList, 3=ThreadList, 4=Memory64, 5=MemoryInfo, 6=Exception
\* file_offset: byte offset in .dmp
\* rva: relative virtual address within the stream

\* ---- Anomaly (non-fatal issue) ----

\* Every anomaly records WHERE the problem was found (provenance) + WHAT went wrong.
\* Modeled as <<stream_id, offset, rva, description>> tuples.

\* ---- SystemInfo ----

\* OS platform: 0=Windows, 1=Linux, 2=macOS
\* CPU arch: 0=x86, 1=x64, 2=ARM64
\* Version: (major, minor, build, revision)

\* ---- Module (loaded image) ----

\* Each module: name_hash, base_va, size, checksum, pdb_hash
\* Plus provenance: which stream entry it came from

\* ---- Thread ----

\* Each thread: id, stack_va, stack_size, teb_va
\* Plus provenance

\* ---- MemoryRegion ----

\* va_start, size, protection (bitmask: R=1,W=2,X=4), state (0=commit,1=reserve,2=free)
\* type (0=private,1=mapped,2=image), classification (0=Image,1=Stack,2=Mapped,3=Private,4=Other)
\* Plus provenance

\* ---- ExceptionInfo ----

\* code, address, thread_id, flags
\* Plus provenance

\* ---- Dump (root aggregate) ----

\* system_info, modules, threads, memory (AddressSpace), exception, anomalies
\* The Dump IS the output of the parse pipeline and the input to S2+

\* ---- STATE ----

VARIABLES
    \* @type: Seq(Int);
    sysinfo,              \* [os, cpu, ver_major, ver_minor, ver_build, ver_rev, stream_id, offset, rva]
    \* @type: Seq(Int);
    mod_va,               \* module base VAs
    \* @type: Seq(Int);
    mod_sz,               \* module sizes
    \* @type: Seq(Int);
    mod_prov_sid,         \* module provenance: stream_id
    \* @type: Seq(Int);
    mod_prov_off,         \* module provenance: file_offset
    \* @type: Seq(Int);
    mod_prov_rva,         \* module provenance: rva
    \* @type: Seq(Int);
    thr_id,               \* thread ids
    \* @type: Seq(Int);
    thr_stack_va,         \* thread stack VAs
    \* @type: Seq(Int);
    thr_stack_sz,         \* thread stack sizes
    \* @type: Seq(Int);
    thr_prov_sid,         \* thread provenance: stream_id
    \* @type: Seq(Int);
    thr_prov_off,         \* thread provenance: file_offset
    \* @type: Seq(Int);
    thr_prov_rva,         \* thread provenance: rva
    \* @type: Seq(Int);
    mem_va,               \* memory region VAs
    \* @type: Seq(Int);
    mem_sz,               \* memory region sizes
    \* @type: Seq(Int);
    mem_prot,             \* memory protection flags
    \* @type: Seq(Int);
    mem_state,            \* memory state (commit/reserve/free)
    \* @type: Seq(Int);
    mem_type,             \* memory type (private/mapped/image)
    \* @type: Seq(Int);
    mem_cls,              \* classification (Image/Stack/Mapped/Private/Other)
    \* @type: Seq(Int);
    mem_prov_sid,         \* memory provenance: stream_id
    \* @type: Seq(Int);
    mem_prov_off,         \* memory provenance: file_offset
    \* @type: Seq(Int);
    mem_prov_rva,         \* memory provenance: rva
    \* @type: Seq(Int);
    exc_info,             \* [code, addr, thread_id, flags, stream_id, offset, rva]
    \* @type: Seq([desc: Str]);
    anomalies

\* ---- Helpers ----

HasSysInfo     == Len(sysinfo) = 9
ModuleCount    == Len(mod_va)
ThreadCount    == Len(thr_id)
RegionCount    == Len(mem_va)

\* Provenance present on every entity
SysInfoProv       == HasSysInfo => sysinfo[7] > 0 /\ sysinfo[8] > 0
ModuleProv(i)     == i <= ModuleCount => mod_prov_sid[i] > 0 /\ mod_prov_off[i] >= 0
ThreadProv(i)     == i <= ThreadCount => thr_prov_sid[i] > 0 /\ thr_prov_off[i] >= 0
MemRegionProv(i)  == i <= RegionCount => mem_prov_sid[i] > 0 /\ mem_prov_off[i] >= 0

\* ---- Invariants ----

SysInfoComplete     == HasSysInfo => /\ sysinfo[1] \in {0,1,2}     \* OS
                                    /\ sysinfo[2] \in {1}          \* CPU = x64 (S1 only)
                                    /\ SysInfoProv
ModuleCountBound    == ModuleCount <= MaxModules
ThreadCountBound    == ThreadCount <= MaxThreads
RegionCountBound    == RegionCount <= MaxRegions
AnomalyCountBound   == Len(anomalies) <= MaxAnomalies

\* Modules don't overlap in address space
ModulesDisjoint == \A i \in 1..MaxModules:
                     \A j \in 1..MaxModules:
                       (i <= ModuleCount /\ j <= ModuleCount /\ i # j) =>
                         ~(mod_va[i] < mod_va[j] + mod_sz[j] /\ mod_va[j] < mod_va[i] + mod_sz[i])

\* Every module has provenance
AllModulesHaveProv == \A i \in 1..MaxModules: i <= ModuleCount => ModuleProv(i)

\* Every thread has provenance
AllThreadsHaveProv == \A i \in 1..MaxThreads: i <= ThreadCount => ThreadProv(i)

\* Every memory region has provenance
AllRegionsHaveProv == \A i \in 1..MaxRegions: i <= RegionCount => MemRegionProv(i)

\* Thread stacks are within valid address ranges (bounded for model checking)
ThreadStacksValid == \A i \in 1..MaxThreads:
                       i <= ThreadCount =>
                         thr_stack_va[i] + thr_stack_sz[i] <= 65535

\* Exception info has provenance if present
ExcHasProv == (Len(exc_info) = 7) => exc_info[5] > 0

\* Memory classification values are valid
MemClassValid == \A i \in 1..MaxRegions:
                   i <= RegionCount => mem_cls[i] \in {0,1,2,3,4}

\* Memory state values are valid
MemStateValid == \A i \in 1..MaxRegions:
                   i <= RegionCount => mem_state[i] \in {0,1,2}

\* Memory protection values are in range (0..7 = R|W|X combinations)
MemProtValid == \A i \in 1..MaxRegions:
                   i <= RegionCount => mem_prot[i] <= 7

\* Thread stack sizes > 0
ThreadStacksPositive == \A i \in 1..MaxThreads:
                          i <= ThreadCount => thr_stack_sz[i] > 0

ModelInvariant ==
    /\ ModuleCountBound
    /\ ThreadCountBound
    /\ RegionCountBound
    /\ AnomalyCountBound
    /\ ModulesDisjoint
    /\ AllModulesHaveProv
    /\ AllThreadsHaveProv
    /\ AllRegionsHaveProv
    /\ MemClassValid
    /\ MemStateValid
    /\ MemProtValid
    /\ ThreadStacksPositive

\* ---- Operations ----

\* Set system info (once)
SetSysInfo(os, cpu, maj, min, bld, rev, sid, off, rva) ==
    /\ Len(sysinfo) = 0
    /\ cpu = 1     \* S1: x64 only
    /\ sid > 0
    /\ sysinfo' = <<os, cpu, maj, min, bld, rev, sid, off, rva>>
    /\ UNCHANGED <<mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                   thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                   mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                   mem_prov_sid, mem_prov_off, mem_prov_rva, exc_info, anomalies>>

\* Add a module
AddModule(va, sz, sid, off, rva) ==
    /\ ModuleCount < MaxModules
    /\ sz > 0
    /\ sid > 0
    /\ \/ /\ \A i \in 1..MaxModules:
              i <= ModuleCount => ~(mod_va[i] < va + sz /\ va < mod_va[i] + mod_sz[i])
          /\ mod_va'   = Append(mod_va, va)
          /\ mod_sz'   = Append(mod_sz, sz)
          /\ mod_prov_sid' = Append(mod_prov_sid, sid)
          /\ mod_prov_off' = Append(mod_prov_off, off)
          /\ mod_prov_rva' = Append(mod_prov_rva, rva)
          /\ UNCHANGED <<sysinfo, thr_id, thr_stack_va, thr_stack_sz,
                         thr_prov_sid, thr_prov_off, thr_prov_rva,
                         mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                         mem_prov_sid, mem_prov_off, mem_prov_rva, exc_info, anomalies>>
       \/ /\ Len(anomalies) < MaxAnomalies
          /\ anomalies' = Append(anomalies, [desc |-> "overlapping module"])
          /\ UNCHANGED <<sysinfo, mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                         thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                         mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                         mem_prov_sid, mem_prov_off, mem_prov_rva, exc_info>>

AddThread(id, sva, ssz, sid, off, rva) ==
    /\ ThreadCount < MaxThreads
    /\ ssz > 0
    /\ sid > 0
    /\ thr_id'         = Append(thr_id, id)
    /\ thr_stack_va'   = Append(thr_stack_va, sva)
    /\ thr_stack_sz'   = Append(thr_stack_sz, ssz)
    /\ thr_prov_sid'   = Append(thr_prov_sid, sid)
    /\ thr_prov_off'   = Append(thr_prov_off, off)
    /\ thr_prov_rva'   = Append(thr_prov_rva, rva)
    /\ UNCHANGED <<sysinfo, mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                   mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                   mem_prov_sid, mem_prov_off, mem_prov_rva, exc_info, anomalies>>

AddRegion(va, sz, prot, state, typ, cls, sid, off, rva) ==
    /\ RegionCount < MaxRegions
    /\ sz > 0
    /\ sid > 0
    /\ cls \in {0,1,2,3,4}
    /\ state \in {0,1,2}
    /\ prot <= 7
    /\ mem_va'   = Append(mem_va, va)
    /\ mem_sz'   = Append(mem_sz, sz)
    /\ mem_prot' = Append(mem_prot, prot)
    /\ mem_state'= Append(mem_state, state)
    /\ mem_type' = Append(mem_type, typ)
    /\ mem_cls'  = Append(mem_cls, cls)
    /\ mem_prov_sid' = Append(mem_prov_sid, sid)
    /\ mem_prov_off' = Append(mem_prov_off, off)
    /\ mem_prov_rva' = Append(mem_prov_rva, rva)
    /\ UNCHANGED <<sysinfo, mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                   thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                   exc_info, anomalies>>

SetException(code, addr, tid, flg, sid, off, rva) ==
    /\ Len(exc_info) = 0
    /\ sid > 0
    /\ exc_info' = <<code, addr, tid, flg, sid, off, rva>>
    /\ UNCHANGED <<sysinfo, mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                   thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                   mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                   mem_prov_sid, mem_prov_off, mem_prov_rva, anomalies>>

AddAnomaly(desc) ==
    /\ Len(anomalies) < MaxAnomalies
    /\ anomalies' = Append(anomalies, [desc |-> desc])
    /\ UNCHANGED <<sysinfo, mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                   thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                   mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                   mem_prov_sid, mem_prov_off, mem_prov_rva, exc_info>>

\* ---- Init ----
Init ==
    /\ sysinfo      = <<>>
    /\ mod_va       = <<>>
    /\ mod_sz       = <<>>
    /\ mod_prov_sid = <<>>
    /\ mod_prov_off = <<>>
    /\ mod_prov_rva = <<>>
    /\ thr_id       = <<>>
    /\ thr_stack_va = <<>>
    /\ thr_stack_sz = <<>>
    /\ thr_prov_sid = <<>>
    /\ thr_prov_off = <<>>
    /\ thr_prov_rva = <<>>
    /\ mem_va       = <<>>
    /\ mem_sz       = <<>>
    /\ mem_prot     = <<>>
    /\ mem_state    = <<>>
    /\ mem_type     = <<>>
    /\ mem_cls      = <<>>
    /\ mem_prov_sid = <<>>
    /\ mem_prov_off = <<>>
    /\ mem_prov_rva = <<>>
    /\ exc_info     = <<>>
    /\ anomalies    = <<>>

\* ---- Next ----
Next ==
    \/ \E os \in {0,1}: \E maj,min,bld,rev \in {0,1}:
         \E sid \in {1,2}: \E off,rva \in {0,1}:
           SetSysInfo(os, 1, maj, min, bld, rev, sid, off, rva)
    \/ \E va,sz \in {0,1}: \E sid \in {1,2}: \E off,rva \in {0,1}:
         AddModule(va, sz, sid, off, rva)
    \/ \E id,sva,ssz \in {0,1}: \E sid \in {1,2}: \E off,rva \in {0,1}:
         AddThread(id, sva, ssz, sid, off, rva)
    \/ \E va,sz \in {0,1}: \E prot \in 0..3: \E state \in {0,1}:
         \E typ \in {0,1}: \E cls \in {0,1,2}:
           \E sid \in {1,2}: \E off,rva \in {0,1}:
             AddRegion(va, sz, prot, state, typ, cls, sid, off, rva)
    \/ \E code,addr,tid,flg \in {0,1}: \E sid \in {1,2}: \E off,rva \in {0,1}:
         SetException(code, addr, tid, flg, sid, off, rva)
    \/ \E desc \in {"truncated", "invalid", "missing"}:
         AddAnomaly(desc)

Spec == Init /\ [][Next]_<<sysinfo, mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                           thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                           mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                           mem_prov_sid, mem_prov_off, mem_prov_rva, exc_info, anomalies>>

====

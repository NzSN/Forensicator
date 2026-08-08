---- MODULE Model ----
EXTENDS Integers, Sequences, FiniteSets

\* ── Model — the abstract structure of a decoded minidump (Dump) ─────────
\*
\* WHAT THIS SPEC MODELS
\*   The *content* of a parsed minidump: the normalized collection of facts
\*   that S2 analyzers consume (Rust counterpart: model::Dump). It is a
\*   time-point spec — one frozen instant of one process. It models neither
\*   the file's byte layout nor the parse *process* (that is
\*   ParsePipeline.tla), and memory regions carry metadata only: byte
\*   contents first appear in Timeline.tla (init_mem / wr_*).
\*
\* STATE FORMAT
\*   Entities are stored as flat parallel sequences (Apalache-friendly —
\*   no record-typed tables): the i-th element of each sequence in a group
\*   describes the i-th entity. Every entity group carries a provenance
\*   triple (prov_sid, prov_off, prov_rva): which stream the fact came from,
\*   and where inside the file (sid > 0 = present).
\*
\*   sysinfo    = <<os, cpu, maj, min, bld, rev, sid, off, rva>>  (one-shot)
\*                os ∈ {0=Windows,1=Linux,2=macOS}, cpu = 1 (x64),
\*                sid/off/rva = provenance, stored at slots 7..9.
\*   modules    : mod_va[i] base VA, mod_sz[i] size (+ mod_prov_*[i]).
\*                Invariant: pairwise VA-disjoint; overlap decodes as an
\*                "overlapping module" anomaly instead (degrade, not fail).
\*   threads    : thr_id[i] OS thread id, thr_stack_va[i]/thr_stack_sz[i]
\*                stack range (+ thr_prov_*[i]). Stack size must be > 0.
\*   regions    : mem_va[i]/mem_sz[i] range; mem_prot[i] protection bitmask
\*                (READ=1 WRITE=2 EXECUTE=4, so prot ≤ 7); mem_state[i] ∈
\*                {0=Commit,1=Reserve,2=Free}; mem_type[i] ∈ {0=Private,
\*                1=Mapped,2=Image}; mem_cls[i] ∈ {0..4} (Image/Stack/
\*                Mapped/Private/Other) (+ mem_prov_*[i]).
\*   exc_info   = <<code, addr, tid, flg, sid, off, rva>>  (one-shot)
\*                exception code/address/thread + provenance (slot 5 = sid).
\*   anomalies  : Seq([desc |-> Str]) — non-fatal decode problems.
\*   annotations: ann_key[i] = ann_val[i] — Crashpad CommentStreamA/W
\*                key=value pairs; sequences stay in lockstep, values
\*                non-empty.
\*
\* CONVENTIONS
\*   * Append-only: facts are never updated or removed; the only sequencing
\*     is empty → non-empty (one-shot latches for sysinfo/exc_info).
\*   * Bounds (Max* below) keep the state space tiny for exhaustive
\*     checking; they are verification artifacts, not format limits.
\*   * Timeline.tla re-indexes this state by position t to model TTD
\*     traces; nothing here knows about time.

\* Normalized data types for S1 — what S2+ consume.
\* Every fact carries Provenance: which stream + offset it came from.
\* Crash annotations from CommentStreamA/W are modeled as key-value pairs.

MaxModules    == 3  \* raised from 2 for Snapshot.tla: Timeline admits
                    \* MaxEvents = 3 simultaneous open module loads
MaxThreads    == 2
MaxRegions    == 2
MaxAnomalies  == 4
MaxAnnotations == 4

\* ---- STATE ----

VARIABLES
    \* ── system info (one-shot record, see STATE FORMAT above) ──
    \* @type: Seq(Int);
    sysinfo,        \* <<os, cpu, maj, min, bld, rev, prov_sid, prov_off, prov_rva>>; empty until SetSysInfo

    \* ── module table: i-th module = (mod_va[i], mod_sz[i]) + provenance ──
    \* @type: Seq(Int);
    mod_va,         \* base VA of module i (pairwise VA-disjoint — ModulesDisjoint)
    \* @type: Seq(Int);
    mod_sz,         \* size of module i (> 0)
    \* @type: Seq(Int);
    mod_prov_sid,   \* provenance: stream id the module was decoded from (> 0)
    \* @type: Seq(Int);
    mod_prov_off,   \* provenance: file offset of the module entry
    \* @type: Seq(Int);
    mod_prov_rva,   \* provenance: RVA within the stream

    \* ── thread table: i-th thread = id + stack range + provenance ──
    \* @type: Seq(Int);
    thr_id,         \* OS thread id
    \* @type: Seq(Int);
    thr_stack_va,   \* stack base VA (thr_stack_va + thr_stack_sz ≤ 65535)
    \* @type: Seq(Int);
    thr_stack_sz,   \* stack size (> 0)
    \* @type: Seq(Int);
    thr_prov_sid,
    \* @type: Seq(Int);
    thr_prov_off,
    \* @type: Seq(Int);
    thr_prov_rva,

    \* ── memory-region table: metadata only — no byte contents in this spec ──
    \* @type: Seq(Int);
    mem_va,         \* region start VA
    \* @type: Seq(Int);
    mem_sz,         \* region size (> 0)
    \* @type: Seq(Int);
    mem_prot,       \* protection bitmask: READ=1, WRITE=2, EXECUTE=4 (so ≤ 7)
    \* @type: Seq(Int);
    mem_state,      \* 0=Commit, 1=Reserve, 2=Free
    \* @type: Seq(Int);
    mem_type,       \* 0=Private, 1=Mapped, 2=Image
    \* @type: Seq(Int);
    mem_cls,        \* classification: 0..4 = Image/Stack/Mapped/Private/Other
    \* @type: Seq(Int);
    mem_prov_sid,
    \* @type: Seq(Int);
    mem_prov_off,
    \* @type: Seq(Int);
    mem_prov_rva,

    \* ── exception (one-shot record) ──
    \* @type: Seq(Int);
    exc_info,       \* <<code, addr, tid, flg, prov_sid, prov_off, prov_rva>>; empty until SetException

    \* ── non-fatal decode problems ──
    \* @type: Seq([desc: Str]);
    anomalies,      \* e.g. "overlapping module" recorded instead of failing

    \* ── Crashpad annotations (CommentStreamA/W key=value pairs, lockstep) ──
    \* @type: Seq(Str);
    ann_key,
    \* @type: Seq(Str);
    ann_val         \* non-empty; Len(ann_val) = Len(ann_key) (AnnKeyValMatch)

\* ---- Helpers ----

HasSysInfo   == Len(sysinfo) = 9
ModuleCount  == Len(mod_va)
ThreadCount  == Len(thr_id)
RegionCount  == Len(mem_va)
AnnCount     == Len(ann_key)

SysInfoProv       == HasSysInfo => sysinfo[7] > 0 /\ sysinfo[8] > 0
ModuleProv(i)     == i <= ModuleCount => mod_prov_sid[i] > 0 /\ mod_prov_off[i] >= 0
ThreadProv(i)     == i <= ThreadCount => thr_prov_sid[i] > 0 /\ thr_prov_off[i] >= 0
MemRegionProv(i)  == i <= RegionCount => mem_prov_sid[i] > 0 /\ mem_prov_off[i] >= 0

\* Annotations: key-length matching, values are non-empty strings
AnnKeyValMatch    == Len(ann_val) = AnnCount
AnnValNonEmpty    == \A i \in 1..AnnCount: ann_val[i] # ""

\* ---- Invariants ----

SysInfoComplete     == HasSysInfo => /\ sysinfo[1] \in {0,1,2}
                                    /\ sysinfo[2] \in {1}
                                    /\ SysInfoProv
ModuleCountBound    == ModuleCount <= MaxModules
ThreadCountBound    == ThreadCount <= MaxThreads
RegionCountBound    == RegionCount <= MaxRegions
AnomalyCountBound   == Len(anomalies) <= MaxAnomalies
AnnCountBound       == AnnCount <= MaxAnnotations

ModulesDisjoint == \A i \in 1..MaxModules:
                     \A j \in 1..MaxModules:
                       (i <= ModuleCount /\ j <= ModuleCount /\ i # j) =>
                         ~(mod_va[i] < mod_va[j] + mod_sz[j] /\ mod_va[j] < mod_va[i] + mod_sz[i])

AllModulesHaveProv  == \A i \in 1..MaxModules: i <= ModuleCount => ModuleProv(i)
AllThreadsHaveProv  == \A i \in 1..MaxThreads: i <= ThreadCount => ThreadProv(i)
AllRegionsHaveProv  == \A i \in 1..MaxRegions: i <= RegionCount => MemRegionProv(i)

ThreadStacksValid == \A i \in 1..MaxThreads:
                       i <= ThreadCount => thr_stack_va[i] + thr_stack_sz[i] <= 65535

ExcHasProv == (Len(exc_info) = 7) => exc_info[5] > 0

MemClassValid == \A i \in 1..MaxRegions:
                   i <= RegionCount => mem_cls[i] \in {0,1,2,3,4}
MemStateValid == \A i \in 1..MaxRegions:
                   i <= RegionCount => mem_state[i] \in {0,1,2}
MemProtValid  == \A i \in 1..MaxRegions:
                   i <= RegionCount => mem_prot[i] <= 7

ThreadStacksPositive == \A i \in 1..MaxThreads:
                          i <= ThreadCount => thr_stack_sz[i] > 0

ModelInvariant ==
    /\ ModuleCountBound
    /\ ThreadCountBound
    /\ RegionCountBound
    /\ AnomalyCountBound
    /\ AnnCountBound
    /\ AnnKeyValMatch
    /\ ModulesDisjoint
    /\ AllModulesHaveProv
    /\ AllThreadsHaveProv
    /\ AllRegionsHaveProv
    /\ MemClassValid
    /\ MemStateValid
    /\ MemProtValid
    /\ ThreadStacksPositive

\* ---- Operations ----

SetSysInfo(os, cpu, maj, min, bld, rev, sid, off, rva) ==
    /\ Len(sysinfo) = 0
    /\ cpu = 1
    /\ sid > 0
    /\ sysinfo' = <<os, cpu, maj, min, bld, rev, sid, off, rva>>
    /\ UNCHANGED <<mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                   thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                   mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                   mem_prov_sid, mem_prov_off, mem_prov_rva, exc_info, anomalies,
                   ann_key, ann_val>>

AddModule(va, sz, sid, off, rva) ==
    /\ ModuleCount < MaxModules
    /\ sz > 0
    /\ sid > 0
    /\ LET NoOverlap == \A i \in 1..MaxModules:
                         i <= ModuleCount => ~(mod_va[i] < va + sz /\ va < mod_va[i] + mod_sz[i])
       IN IF NoOverlap
          THEN /\ mod_va'   = Append(mod_va, va)
               /\ mod_sz'   = Append(mod_sz, sz)
               /\ mod_prov_sid' = Append(mod_prov_sid, sid)
               /\ mod_prov_off' = Append(mod_prov_off, off)
               /\ mod_prov_rva' = Append(mod_prov_rva, rva)
               /\ UNCHANGED <<sysinfo, thr_id, thr_stack_va, thr_stack_sz,
                              thr_prov_sid, thr_prov_off, thr_prov_rva,
                              mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                              mem_prov_sid, mem_prov_off, mem_prov_rva, exc_info, anomalies,
                              ann_key, ann_val>>
          ELSE /\ Len(anomalies) < MaxAnomalies
               /\ anomalies' = Append(anomalies, [desc |-> "overlapping module"])
               /\ UNCHANGED <<sysinfo, mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                              thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                              mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                              mem_prov_sid, mem_prov_off, mem_prov_rva, exc_info,
                              ann_key, ann_val>>

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
                   mem_prov_sid, mem_prov_off, mem_prov_rva, exc_info, anomalies,
                   ann_key, ann_val>>

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
                   exc_info, anomalies, ann_key, ann_val>>

SetException(code, addr, tid, flg, sid, off, rva) ==
    /\ Len(exc_info) = 0
    /\ sid > 0
    /\ exc_info' = <<code, addr, tid, flg, sid, off, rva>>
    /\ UNCHANGED <<sysinfo, mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                   thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                   mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                   mem_prov_sid, mem_prov_off, mem_prov_rva, anomalies, ann_key, ann_val>>

AddAnomaly(desc) ==
    /\ Len(anomalies) < MaxAnomalies
    /\ anomalies' = Append(anomalies, [desc |-> desc])
    /\ UNCHANGED <<sysinfo, mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                   thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                   mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                   mem_prov_sid, mem_prov_off, mem_prov_rva, exc_info, ann_key, ann_val>>

\* Crash annotation from CommentStreamA/W: a diagnostic key=value pair.
AddAnnotation(key, val) ==
    /\ AnnCount < MaxAnnotations
    /\ key # ""
    /\ val # ""
    /\ ann_key' = Append(ann_key, key)
    /\ ann_val' = Append(ann_val, val)
    /\ UNCHANGED <<sysinfo, mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                   thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                   mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                   mem_prov_sid, mem_prov_off, mem_prov_rva, exc_info, anomalies>>

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
    /\ ann_key      = <<>>
    /\ ann_val      = <<>>

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
    \/ \E key \in {"app_version", "user_id", "session_id"}:
         \E val \in {"1.0", "42", "abc"}:
           AddAnnotation(key, val)

Spec == Init /\ [][Next]_<<sysinfo, mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                            thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                            mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                            mem_prov_sid, mem_prov_off, mem_prov_rva, exc_info, anomalies,
                            ann_key, ann_val>>

====

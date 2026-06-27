---- MODULE ParsePipeline ----
EXTENDS Integers, Sequences, FiniteSets

\* Full pipeline: raw .dmp bytes → firewalled parse → Model types → Dump.
\* This spec models the BOUNDARY: raw stream data enters, typed facts leave.
\* Consumers (S2-S4) see only Model types, never raw bytes.

MaxFileSize == 256
MaxStreams  == 6

\* ---- Pipeline phases ----
Phase == {"Init","HeaderDone","DirectoryDone","Decoding","Built","Done","Fatal"}

\* ---- Stream type identifiers ----
SysInfoSid == 1
ModListSid == 2
ThrListSid == 3
Mem64Sid   == 4
MemInfoSid == 5
ExcSid     == 6

\* ---- STATE ----

VARIABLES
    \* @type: Str;
    phase,
    \* @type: Str;
    fatal_error,
    \* @type: Seq(Int);
    raw_streams,         \* which stream IDs are present in the dump
    \* typed outputs (NULL = not yet decoded; use 0 as sentinel)
    \* @type: Seq(Int);
    sysinfo_out,         \* [os, cpu, maj, min, bld, rev, sid, off, rva] or <<>> if absent
    \* @type: Seq(Int);
    mod_va,              \* decoded module info
    \* @type: Seq(Int);
    mod_sz,
    \* @type: Seq(Int);
    mod_prov_sid,
    \* @type: Seq(Int);
    mod_prov_off,
    \* @type: Seq(Int);
    mod_prov_rva,
    \* @type: Seq(Int);
    thr_id,
    \* @type: Seq(Int);
    thr_stack_va,
    \* @type: Seq(Int);
    thr_stack_sz,
    \* @type: Seq(Int);
    thr_prov_sid,
    \* @type: Seq(Int);
    thr_prov_off,
    \* @type: Seq(Int);
    thr_prov_rva,
    \* @type: Seq(Int);
    mem_va,              \* decoded memory regions
    \* @type: Seq(Int);
    mem_sz,
    \* @type: Seq(Int);
    mem_prot,
    \* @type: Seq(Int);
    mem_state,
    \* @type: Seq(Int);
    mem_type,
    \* @type: Seq(Int);
    mem_cls,
    \* @type: Seq(Int);
    mem_prov_sid,
    \* @type: Seq(Int);
    mem_prov_off,
    \* @type: Seq(Int);
    mem_prov_rva,
    \* @type: Seq(Int);
    exc_info,            \* [code, addr, tid, flg, sid, off, rva] or <<>> if absent
    \* @type: Seq(Int);
    dump_built,          \* 0=not built, 1=built
    \* @type: Seq([desc: Str]);
    anomalies

\* ---- Helpers ----

StreamPresent(sid) == \E i \in 1..MaxStreams: i <= Len(raw_streams) /\ raw_streams[i] = sid

\* ---- Invariants ----

PhaseValid      == phase \in Phase
FatalHasReason  == (phase = "Fatal") => fatal_error # "NULL"
AnomaliesBounded== Len(anomalies) <= MaxStreams

\* Backend firewall: raw_streams is set before decode; after decode, only typed data used
FirewallInv == (phase \in {"Decoding","Built","Done"}) => Len(raw_streams) > 0

\* If built, all required streams were present (or anomalies recorded)
\* If built, all required streams were present (or anomalies recorded)
\* BuiltRequirement == (phase \in {"Built","Done"} /\ dump_built = <<1>>) =>
\*                       (\/ StreamPresent(SysInfoSid)
\*                        \/ \E a \in 1..MaxStreams: a <= Len(anomalies) /\ anomalies[a].desc = "missing SystemInfo")

\* If sysinfo was decoded, it's well-formed and has provenance
SysInfoValid == (Len(sysinfo_out) = 9) =>
                  /\ sysinfo_out[2] = 1        \* CPU = x64
                  /\ sysinfo_out[7] > 0         \* provenance stream_id > 0
                  /\ sysinfo_out[8] >= 0         \* provenance offset >= 0

\* Every decoded fact carries provenance (stream_id > 0 means provenance present)
ModuleProvOk  == \A i \in 1..MaxStreams: i <= Len(mod_prov_sid) => mod_prov_sid[i] > 0
ThreadProvOk  == \A i \in 1..MaxStreams: i <= Len(thr_prov_sid) => thr_prov_sid[i] > 0
RegionProvOk  == \A i \in 1..MaxStreams: i <= Len(mem_prov_sid) => mem_prov_sid[i] > 0
ExcProvOk     == (Len(exc_info) = 7) => exc_info[5] > 0

PipelineInvariant ==
    /\ PhaseValid
    /\ FatalHasReason
    /\ AnomaliesBounded
    /\ SysInfoValid
    /\ ModuleProvOk
    /\ ThreadProvOk
    /\ RegionProvOk
    /\ ExcProvOk

\* ---- Operations ----

\* @type: () => Bool;
ReadHeader ==
    /\ phase = "Init"
    /\ \/ /\ phase' = "HeaderDone"
          /\ UNCHANGED <<fatal_error, raw_streams, sysinfo_out,
                         mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                         thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                         mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                         mem_prov_sid, mem_prov_off, mem_prov_rva,
                         exc_info, dump_built, anomalies>>
       \/ /\ phase' = "Fatal"
          /\ fatal_error' = "bad header"
          /\ UNCHANGED <<raw_streams, sysinfo_out,
                         mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                         thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                         mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                         mem_prov_sid, mem_prov_off, mem_prov_rva,
                         exc_info, dump_built, anomalies>>

ReadDirectory ==
    /\ phase = "HeaderDone"
    /\ \/ /\ phase' = "DirectoryDone"
          /\ raw_streams' \in {<<1,2,3,4,5>>, <<1,2,3,4,5,6>>}
          /\ UNCHANGED <<fatal_error, sysinfo_out,
                         mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                         thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                         mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                         mem_prov_sid, mem_prov_off, mem_prov_rva,
                         exc_info, dump_built, anomalies>>
       \/ /\ phase' = "Fatal"
          /\ fatal_error' = "directory overflow"
          /\ UNCHANGED <<raw_streams, sysinfo_out,
                         mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                         thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                         mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                         mem_prov_sid, mem_prov_off, mem_prov_rva,
                         exc_info, dump_built, anomalies>>

DecodeSysInfo ==
    /\ phase = "Decoding"
    /\ StreamPresent(SysInfoSid) /\ Len(sysinfo_out) = 0
    /\ \E os \in {0,1}: \E maj,min,bld,rev \in {0,1,2}:
         /\ sysinfo_out' = <<os, 1, maj, min, bld, rev, SysInfoSid, 0, 0>>
         /\ UNCHANGED <<phase, fatal_error, raw_streams,
                        mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                        thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                        mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                        mem_prov_sid, mem_prov_off, mem_prov_rva,
                        exc_info, dump_built, anomalies>>

DecodeModules ==
    /\ phase = "Decoding"
    /\ StreamPresent(ModListSid) /\ Len(mod_va) = 0
    /\ \/ /\ mod_va'   = <<0>>
          /\ mod_sz'   = <<1>>
          /\ mod_prov_sid' = <<ModListSid>>
          /\ mod_prov_off' = <<0>>
          /\ mod_prov_rva' = <<0>>
       \/ /\ mod_va'   = <<0,0>>
          /\ mod_sz'   = <<1,1>>
          /\ mod_prov_sid' = <<ModListSid,ModListSid>>
          /\ mod_prov_off' = <<0,1>>
          /\ mod_prov_rva' = <<0,0>>
    /\ UNCHANGED <<phase, fatal_error, raw_streams, sysinfo_out,
                   thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                   mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                   mem_prov_sid, mem_prov_off, mem_prov_rva,
                   exc_info, dump_built, anomalies>>

DecodeThreads ==
    /\ phase = "Decoding"
    /\ StreamPresent(ThrListSid) /\ Len(thr_id) = 0
    /\ \/ /\ thr_id'       = <<0>>
          /\ thr_stack_va' = <<0>>
          /\ thr_stack_sz' = <<8>>
          /\ thr_prov_sid' = <<ThrListSid>>
          /\ thr_prov_off' = <<0>>
          /\ thr_prov_rva' = <<0>>
       \/ /\ thr_id'       = <<0,1>>
          /\ thr_stack_va' = <<0,0>>
          /\ thr_stack_sz' = <<8,8>>
          /\ thr_prov_sid' = <<ThrListSid,ThrListSid>>
          /\ thr_prov_off' = <<0,1>>
          /\ thr_prov_rva' = <<0,0>>
    /\ UNCHANGED <<phase, fatal_error, raw_streams, sysinfo_out,
                   mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                   mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                   mem_prov_sid, mem_prov_off, mem_prov_rva,
                   exc_info, dump_built, anomalies>>

DecodeMemory ==
    /\ phase = "Decoding"
    /\ StreamPresent(Mem64Sid) /\ Len(mem_va) = 0
    /\ \/ /\ mem_va'   = <<0>>
          /\ mem_sz'   = <<50>>
          /\ mem_prot' = <<3>>
          /\ mem_state' = <<0>>
          /\ mem_type' = <<0>>
          /\ mem_cls'  = <<4>>
          /\ mem_prov_sid' = <<Mem64Sid>>
          /\ mem_prov_off' = <<0>>
          /\ mem_prov_rva' = <<0>>
       \/ /\ mem_va'   = <<0,100>>
          /\ mem_sz'   = <<50,50>>
          /\ mem_prot' = <<3,3>>
          /\ mem_state' = <<0,0>>
          /\ mem_type' = <<0,0>>
          /\ mem_cls'  = <<4,4>>
          /\ mem_prov_sid' = <<Mem64Sid,Mem64Sid>>
          /\ mem_prov_off' = <<0,1>>
          /\ mem_prov_rva' = <<0,0>>
    /\ UNCHANGED <<phase, fatal_error, raw_streams, sysinfo_out,
                   mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                   thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                   exc_info, dump_built, anomalies>>

DecodeException ==
    /\ phase = "Decoding"
    /\ StreamPresent(ExcSid) /\ Len(exc_info) = 0
    /\ exc_info' = <<0, 0, 0, 0, ExcSid, 0, 0>>
    /\ UNCHANGED <<phase, fatal_error, raw_streams, sysinfo_out,
                   mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                   thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                   mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                   mem_prov_sid, mem_prov_off, mem_prov_rva,
                   dump_built, anomalies>>

RecordMissingStreams ==
    /\ phase = "Decoding"
    /\ \/ /\ ~StreamPresent(SysInfoSid) /\ Len(anomalies) < MaxStreams
          /\ anomalies' = Append(anomalies, [desc |-> "missing SystemInfo"])
       \/ /\ ~StreamPresent(ModListSid) /\ Len(anomalies) < MaxStreams
          /\ anomalies' = Append(anomalies, [desc |-> "missing ModuleList"])
       \/ /\ ~StreamPresent(ThrListSid) /\ Len(anomalies) < MaxStreams
          /\ anomalies' = Append(anomalies, [desc |-> "missing ThreadList"])
       \/ /\ ~StreamPresent(Mem64Sid) /\ Len(anomalies) < MaxStreams
          /\ anomalies' = Append(anomalies, [desc |-> "missing Memory64"])
    /\ UNCHANGED <<phase, fatal_error, raw_streams, sysinfo_out,
                   mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                   thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                   mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                   mem_prov_sid, mem_prov_off, mem_prov_rva,
                   exc_info, dump_built>>

BuildDump ==
    /\ phase = "Decoding"
    /\ \/ /\ (StreamPresent(SysInfoSid) => Len(sysinfo_out) = 9)
       /\ (StreamPresent(ModListSid) => Len(mod_va) > 0)
       /\ (StreamPresent(ThrListSid) => Len(thr_id) > 0)
       /\ dump_built' = <<1>>
       /\ phase' = "Built"
       /\ UNCHANGED <<fatal_error, raw_streams, sysinfo_out,
                      mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                      thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                      mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                      mem_prov_sid, mem_prov_off, mem_prov_rva,
                      exc_info, anomalies>>
    \/ /\ dump_built' = <<0>>
       /\ Len(anomalies) < MaxStreams
       /\ anomalies' = Append(anomalies, [desc |-> "incomplete streams"])
       /\ phase' = "Built"
       /\ UNCHANGED <<fatal_error, raw_streams, sysinfo_out,
                      mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                      thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                      mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                      mem_prov_sid, mem_prov_off, mem_prov_rva,
                      exc_info>>

Finish ==
    /\ phase = "Built"
    /\ phase' = "Done"
    /\ UNCHANGED <<fatal_error, raw_streams, sysinfo_out,
                   mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                   thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                   mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                   mem_prov_sid, mem_prov_off, mem_prov_rva,
                   exc_info, dump_built, anomalies>>

\* ---- Init ----
Init ==
    /\ phase        = "Init"
    /\ fatal_error  = "NULL"
    /\ raw_streams  = <<>>
    /\ sysinfo_out  = <<>>
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
    /\ dump_built   = <<>>
    /\ anomalies    = <<>>

\* ---- Next (phases must proceed in order) ----
Next ==
    \/ ReadHeader
    \/ ReadDirectory
    \/ DecodeSysInfo
    \/ DecodeModules
    \/ DecodeThreads
    \/ DecodeMemory
    \/ DecodeException
    \/ RecordMissingStreams
    \/ BuildDump
    \/ Finish

Spec == Init /\ [][Next]_<<phase, fatal_error, raw_streams, sysinfo_out,
                           mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                           thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                           mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                           mem_prov_sid, mem_prov_off, mem_prov_rva,
                           exc_info, dump_built, anomalies>>

====

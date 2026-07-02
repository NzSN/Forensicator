---- MODULE ModelMBT ----
EXTENDS Model

\* Action tracking for Model-Based Testing with MirrorRust.
\* Extends Model.tla to track action names and expose state as a view.

VARIABLES
    \* @type: Str;
    action_taken,
    \* @type: [os: Int, cpu: Int, maj: Int, min: Int, bld: Int, rev: Int, sid: Int, off: Int, rva: Int, va: Int, sz: Int, id: Int, sva: Int, ssz: Int, prot: Int, state: Int, typ: Int, cls: Int, code: Int, addr: Int, tid: Int, flg: Int, desc: Str, key: Str, val: Str];
    parameters

ActionNames ==
    { "SetSysInfo", "AddModule", "AddThread", "AddRegion", "SetException", "AddAnomaly", "AddAnnotation" }

View ==
    [ sysinfo      |-> sysinfo,
      mod_va       |-> mod_va,
      mod_sz       |-> mod_sz,
      mod_prov_sid |-> mod_prov_sid,
      mod_prov_off |-> mod_prov_off,
      mod_prov_rva |-> mod_prov_rva,
      thr_id       |-> thr_id,
      thr_stack_va |-> thr_stack_va,
      thr_stack_sz |-> thr_stack_sz,
      thr_prov_sid |-> thr_prov_sid,
      thr_prov_off |-> thr_prov_off,
      thr_prov_rva |-> thr_prov_rva,
      mem_va       |-> mem_va,
      mem_sz       |-> mem_sz,
      mem_prot     |-> mem_prot,
      mem_state    |-> mem_state,
      mem_type     |-> mem_type,
      mem_cls      |-> mem_cls,
      mem_prov_sid |-> mem_prov_sid,
      mem_prov_off |-> mem_prov_off,
      mem_prov_rva |-> mem_prov_rva,
      exc_info     |-> exc_info,
      anomalies    |-> anomalies,
      ann_key      |-> ann_key,
      ann_val      |-> ann_val ]

MBTInit ==
    /\ Init
    /\ action_taken = "Init"
    /\ parameters = [desc |-> "", key |-> "", val |-> ""]

MBTSetSysInfo ==
    /\ \E os \in {0,1}: \E maj,min,bld,rev \in {0,1}:
         \E sid \in {1,2}: \E off,rva \in {0,1}:
           /\ SetSysInfo(os, 1, maj, min, bld, rev, sid, off, rva)
           /\ action_taken' = "SetSysInfo"
           /\ parameters' = [ os  |-> os,  cpu |-> 1,
                              maj |-> maj, min |-> min,
                              bld |-> bld, rev |-> rev,
                              sid |-> sid, off |-> off, rva |-> rva,
                              key |-> "", val |-> "" ]

MBTAddModule ==
    /\ \E va,sz \in {0,1}: \E sid \in {1,2}: \E off,rva \in {0,1}:
         /\ AddModule(va, sz, sid, off, rva)
         /\ action_taken' = "AddModule"
         /\ parameters' = [ va |-> va, sz |-> sz, sid |-> sid, off |-> off, rva |-> rva,
                            key |-> "", val |-> "" ]

MBTAddThread ==
    /\ \E id,sva,ssz \in {0,1}: \E sid \in {1,2}: \E off,rva \in {0,1}:
         /\ AddThread(id, sva, ssz, sid, off, rva)
         /\ action_taken' = "AddThread"
         /\ parameters' = [ id |-> id, sva |-> sva, ssz |-> ssz,
                            sid |-> sid, off |-> off, rva |-> rva,
                            key |-> "", val |-> "" ]

MBTAddRegion ==
    /\ \E va,sz \in {0,1}: \E prot \in 0..3: \E state \in {0,1}:
         \E typ \in {0,1}: \E cls \in {0,1,2}:
           \E sid \in {1,2}: \E off,rva \in {0,1}:
             /\ AddRegion(va, sz, prot, state, typ, cls, sid, off, rva)
             /\ action_taken' = "AddRegion"
             /\ parameters' = [ va |-> va, sz |-> sz, prot |-> prot,
                                state |-> state, typ |-> typ, cls |-> cls,
                                sid |-> sid, off |-> off, rva |-> rva,
                                key |-> "", val |-> "" ]

MBTSetException ==
    /\ \E code,addr,tid,flg \in {0,1}: \E sid \in {1,2}: \E off,rva \in {0,1}:
         /\ SetException(code, addr, tid, flg, sid, off, rva)
         /\ action_taken' = "SetException"
         /\ parameters' = [ code |-> code, addr |-> addr, tid |-> tid,
                            flg |-> flg, sid |-> sid, off |-> off, rva |-> rva,
                            key |-> "", val |-> "" ]

MBTAddAnomaly ==
    /\ \E desc \in {"truncated", "invalid", "missing"}:
         /\ AddAnomaly(desc)
         /\ action_taken' = "AddAnomaly"
         /\ parameters' = [desc |-> desc, key |-> "", val |-> ""]

MBTAddAnnotation ==
    /\ \E key \in {"app_version", "user_id", "session_id"}:
         \E val \in {"1.0", "42", "abc"}:
           /\ AddAnnotation(key, val)
           /\ action_taken' = "AddAnnotation"
           /\ parameters' = [key |-> key, val |-> val]

MBTNext ==
    \/ MBTSetSysInfo
    \/ MBTAddModule
    \/ MBTAddThread
    \/ MBTAddRegion
    \/ MBTSetException
    \/ MBTAddAnomaly
    \/ MBTAddAnnotation

MBTSpec == MBTInit /\ [][MBTNext]_<<sysinfo, mod_va, mod_sz, mod_prov_sid, mod_prov_off, mod_prov_rva,
                                    thr_id, thr_stack_va, thr_stack_sz, thr_prov_sid, thr_prov_off, thr_prov_rva,
                                    mem_va, mem_sz, mem_prot, mem_state, mem_type, mem_cls,
                                    mem_prov_sid, mem_prov_off, mem_prov_rva,
                                    exc_info, anomalies, ann_key, ann_val, action_taken, parameters>>

TraceComplete == TRUE
====

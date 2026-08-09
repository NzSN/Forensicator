---- MODULE SnapshotMBT ----
EXTENDS Snapshot

\* Action tracking for Model-Based Testing with MirrorRust.
\* Extends Snapshot.tla (which extends Timeline.tla) with the mirrorrust
\* envelope; the verified specs stay untouched. Rust counterpart:
\* forensicator-core/tests/mbt_snapshot.rs (SnapshotComputer).
\*
\* The mirror compares the computer's reported state against the spec's
\* raw VARIABLES exactly (--view only deduplicates traces with
\* --max-error > 1; it does not project trace states). The snapshot
\* projection therefore travels in a real variable: `snapshot` holds
\* ModelAt(cursor)'s fields plus cell_values, re-assigned by every MBT
\* wrapper from the primed constituents. SnapshotOf/EvUptoOf/... are
\* Snapshot.tla's ModelAt/ValueAt machinery parameterized over the log
\* variables, because TLA+ cannot evaluate an operator in the next state.
\*
\* Sentinel discipline in `parameters` (both are format constants, pinned
\* here): a = 0 <=> the RecordStep stored no cell (Timeline cells live in
\* 1..MaxAddr, so cell 0 is forever free); k = "NONE" <=> the RecordStep
\* raised no event ("NONE" \notin EventKinds).

VARIABLES
    \* @type: Str;
    action_taken,
    \* @type: [a: Int, v: Int, k: Str, p: Int, thr: Int];
    parameters,
    \* @type: [sysinfo: Seq(Int), mod_va: Seq(Int), mod_sz: Seq(Int), mod_prov_sid: Seq(Int), mod_prov_off: Seq(Int), mod_prov_rva: Seq(Int), thr_id: Seq(Int), thr_stack_va: Seq(Int), thr_stack_sz: Seq(Int), thr_prov_sid: Seq(Int), thr_prov_off: Seq(Int), thr_prov_rva: Seq(Int), mem_va: Seq(Int), mem_sz: Seq(Int), mem_prot: Seq(Int), mem_state: Seq(Int), mem_type: Seq(Int), mem_cls: Seq(Int), mem_prov_sid: Seq(Int), mem_prov_off: Seq(Int), mem_prov_rva: Seq(Int), exc_info: Seq(Int), anomalies: Seq([desc: Str]), ann_key: Seq(Str), ann_val: Seq(Str), cell_values: Seq(Int)];
    snapshot

\* ---- Parameterized re-derivations (log variables passed explicitly) ----

\* @type: (Seq(Str), Int, Int) => Int;
LoadsInOf(ek, a, b) ==
    Cardinality({j \in 1..MaxEvents : a <= j /\ j <= b /\ j <= Len(ek)
                                      /\ ek[j] = "MODULE_LOAD"})
\* @type: (Seq(Str), Int, Int) => Int;
UnloadsInOf(ek, a, b) ==
    Cardinality({j \in 1..MaxEvents : a <= j /\ j <= b /\ j <= Len(ek)
                                      /\ ek[j] = "MODULE_UNLOAD"})
\* @type: (Seq(Int), Int) => Int;
EvUptoOf(ep, t) ==
    Cardinality({i \in 1..MaxEvents : i <= Len(ep) /\ ep[i] <= t})
\* @type: (Seq(Int), Seq(Str), Int) => Int;
ExcUptoOf(ep, ek, t) ==
    Cardinality({i \in 1..MaxEvents : i <= Len(ep) /\ ep[i] <= t
                                      /\ ek[i] = "EXCEPTION"})
\* @type: (Seq(Str), Int, Int) => Bool;
LoadAliveAtOf(ek, i, n) ==
    /\ i <= n /\ i <= Len(ek) /\ ek[i] = "MODULE_LOAD"
    /\ \A k \in 1..MaxEvents :
         (i <= k /\ k <= n) => LoadsInOf(ek, i, k) > UnloadsInOf(ek, i, k)

\* @type: (Seq(Str), Int) => Seq(Int);
OpenModsOf(ek, n) ==
    LET open == {i \in 1..MaxEvents : i <= n /\ LoadAliveAtOf(ek, i, n)}
    IN IF open = {} THEN <<>>
       ELSE LET m1 == CHOOSE x \in open : \A y \in open : x <= y
                r1 == open \ {m1}
            IN IF r1 = {} THEN <<m1>>
               ELSE LET m2 == CHOOSE x \in r1 : \A y \in r1 : x <= y
                        r2 == r1 \ {m2}
                    IN IF r2 = {} THEN <<m1, m2>>
                       ELSE LET m3 == CHOOSE x \in r2 : \A y \in r2 : x <= y
                            IN <<m1, m2, m3>>

\* ModelAt with the event log passed explicitly (Snapshot.tla:154).
\* @type: (Seq(Int), Seq(Str), Int) => [sysinfo: Seq(Int), mod_va: Seq(Int), mod_sz: Seq(Int), mod_prov_sid: Seq(Int), mod_prov_off: Seq(Int), mod_prov_rva: Seq(Int), thr_id: Seq(Int), thr_stack_va: Seq(Int), thr_stack_sz: Seq(Int), thr_prov_sid: Seq(Int), thr_prov_off: Seq(Int), thr_prov_rva: Seq(Int), mem_va: Seq(Int), mem_sz: Seq(Int), mem_prot: Seq(Int), mem_state: Seq(Int), mem_type: Seq(Int), mem_cls: Seq(Int), mem_prov_sid: Seq(Int), mem_prov_off: Seq(Int), mem_prov_rva: Seq(Int), exc_info: Seq(Int), anomalies: Seq([desc: Str]), ann_key: Seq(Str), ann_val: Seq(Str)];
ModelAtOf(ep, ek, t) ==
    LET mods == OpenModsOf(ek, EvUptoOf(ep, t))
    IN [ sysinfo      |-> SnapEmptyInts,
         mod_va       |-> mods,
         mod_sz       |-> ConstSeq(Len(mods), 1),
         mod_prov_sid |-> ConstSeq(Len(mods), 1),
         mod_prov_off |-> ConstSeq(Len(mods), 0),
         mod_prov_rva |-> ConstSeq(Len(mods), 0),
         thr_id       |-> SnapEmptyInts,
         thr_stack_va |-> SnapEmptyInts,
         thr_stack_sz |-> SnapEmptyInts,
         thr_prov_sid |-> SnapEmptyInts,
         thr_prov_off |-> SnapEmptyInts,
         thr_prov_rva |-> SnapEmptyInts,
         mem_va       |-> SnapMemVa,
         mem_sz       |-> SnapMemSz,
         mem_prot     |-> SnapMemProt,
         mem_state    |-> SnapMemState,
         mem_type     |-> SnapMemType,
         mem_cls      |-> SnapMemCls,
         mem_prov_sid |-> SnapMemProvSid,
         mem_prov_off |-> SnapMemProvOff,
         mem_prov_rva |-> SnapMemProvRva,
         exc_info     |-> IF ExcUptoOf(ep, ek, t) > 0
                          THEN <<0, 0, 0, 0, 1, 0, 0>>
                          ELSE SnapEmptyInts,
         anomalies    |-> SnapEmptyAnomalies,
         ann_key      |-> SnapAnnKey,
         ann_val      |-> SnapAnnVal ]

\* @type: (Seq(Int), Seq(Int), Int, Int) => Int;
LastWriterOf(wp, wa, a, t) ==
    LET idxs == {i \in 1..MaxPos : i <= Len(wp) /\ wa[i] = a /\ wp[i] <= t}
    IN IF idxs = {} THEN 0
       ELSE CHOOSE i \in idxs : \A j \in idxs : j <= i

\* @type: (Int -> Int, Seq(Int), Seq(Int), Seq(Int), Int, Int) => Int;
ValueAtOf(im, wp, wa, wv, a, t) ==
    LET i == LastWriterOf(wp, wa, a, t)
    IN IF i = 0 THEN im[a] ELSE wv[i]

\* Byte contents at position t — the Rust echo of SnapshotConsistent,
\* checked cell-by-cell against Trace::value_at (metadata-only Model
\* regions cannot carry this). A 2-cell literal: MaxAddr = 2, and
\* [c \in S |-> e] is function-typed to Snowcat, not a Seq.
\* @type: (Int -> Int, Seq(Int), Seq(Int), Seq(Int), Int) => Seq(Int);
CellValuesOf(im, wp, wa, wv, t) ==
    <<ValueAtOf(im, wp, wa, wv, 1, t), ValueAtOf(im, wp, wa, wv, 2, t)>>

\* The `snapshot` variable's value: ModelAt(t)'s fields plus cell_values.
\* @type: (Seq(Int), Seq(Str), Int -> Int, Seq(Int), Seq(Int), Seq(Int), Int) => [sysinfo: Seq(Int), mod_va: Seq(Int), mod_sz: Seq(Int), mod_prov_sid: Seq(Int), mod_prov_off: Seq(Int), mod_prov_rva: Seq(Int), thr_id: Seq(Int), thr_stack_va: Seq(Int), thr_stack_sz: Seq(Int), thr_prov_sid: Seq(Int), thr_prov_off: Seq(Int), thr_prov_rva: Seq(Int), mem_va: Seq(Int), mem_sz: Seq(Int), mem_prot: Seq(Int), mem_state: Seq(Int), mem_type: Seq(Int), mem_cls: Seq(Int), mem_prov_sid: Seq(Int), mem_prov_off: Seq(Int), mem_prov_rva: Seq(Int), exc_info: Seq(Int), anomalies: Seq([desc: Str]), ann_key: Seq(Str), ann_val: Seq(Str), cell_values: Seq(Int)];
SnapshotOf(ep, ek, im, wp, wa, wv, t) ==
    LET m == ModelAtOf(ep, ek, t)
    IN [ sysinfo      |-> m.sysinfo,
         mod_va       |-> m.mod_va,
         mod_sz       |-> m.mod_sz,
         mod_prov_sid |-> m.mod_prov_sid,
         mod_prov_off |-> m.mod_prov_off,
         mod_prov_rva |-> m.mod_prov_rva,
         thr_id       |-> m.thr_id,
         thr_stack_va |-> m.thr_stack_va,
         thr_stack_sz |-> m.thr_stack_sz,
         thr_prov_sid |-> m.thr_prov_sid,
         thr_prov_off |-> m.thr_prov_off,
         thr_prov_rva |-> m.thr_prov_rva,
         mem_va       |-> m.mem_va,
         mem_sz       |-> m.mem_sz,
         mem_prot     |-> m.mem_prot,
         mem_state    |-> m.mem_state,
         mem_type     |-> m.mem_type,
         mem_cls      |-> m.mem_cls,
         mem_prov_sid |-> m.mem_prov_sid,
         mem_prov_off |-> m.mem_prov_off,
         mem_prov_rva |-> m.mem_prov_rva,
         exc_info     |-> m.exc_info,
         anomalies    |-> m.anomalies,
         ann_key      |-> m.ann_key,
         ann_val      |-> m.ann_val,
         cell_values  |-> CellValuesOf(im, wp, wa, wv, t) ]

\* ---- View (trace deduplication for --max-error = 100) ----

\* The chosen initial memory as a sequence. A 2-cell literal suffices
\* because MaxAddr = 2 (extend the chain if MaxAddr grows).
\* @type: (Int -> Int) => Seq(Int);
CellsOf(f) == <<f[1], f[2]>>

View ==
    [ cells      |-> CellsOf(init_mem),
      wr_pos     |-> wr_pos,
      wr_addr    |-> wr_addr,
      wr_val     |-> wr_val,
      ev_pos     |-> ev_pos,
      ev_kind    |-> ev_kind,
      frontier   |-> frontier,
      cursor     |-> cursor,
      threads    |-> threads,
      calls      |-> calls,
      snapshot   |-> snapshot ]

NoParams == [a |-> 0, v |-> 0, k |-> "NONE", p |-> 0, thr |-> 0]

MBTInit ==
    /\ Init
    /\ action_taken = "Init"
    /\ parameters = NoParams
    /\ snapshot = SnapshotOf(ev_pos, ev_kind, init_mem,
                             wr_pos, wr_addr, wr_val, cursor)

\* RecordStep's three disjuncts (no-op / write / event) inlined so the
\* choices land in `parameters`; a write and an event may co-fire in one
\* step, so the wrapper carries both independently (sentinels above).
MBTRecordStep ==
    /\ frontier < MaxPos
    /\ frontier' = frontier + 1
    /\ \E a \in 0..MaxAddr :
        \E v \in 0..MaxVal - 1 :
          \E k \in EventKinds \cup {"NONE"} :
            /\ IF a = 0
               THEN UNCHANGED <<wr_pos, wr_addr, wr_val>>
               ELSE /\ wr_pos'  = Append(wr_pos, frontier + 1)
                    /\ wr_addr' = Append(wr_addr, a)
                    /\ wr_val'  = Append(wr_val, v)
            /\ IF k = "NONE"
               THEN UNCHANGED <<ev_pos, ev_kind>>
               ELSE /\ Len(ev_pos) < MaxEvents
                    /\ ev_pos'  = Append(ev_pos, frontier + 1)
                    /\ ev_kind' = Append(ev_kind, k)
            /\ parameters' = [a |-> a, v |-> v, k |-> k, p |-> 0, thr |-> 0]
    /\ action_taken' = "RecordStep"
    /\ UNCHANGED <<init_mem, cursor, threads, calls>>
    /\ snapshot' = SnapshotOf(ev_pos', ev_kind', init_mem',
                              wr_pos', wr_addr', wr_val', cursor')

MBTStartThread ==
    /\ StartThread
    /\ action_taken' = "StartThread"
    /\ parameters' = NoParams
    /\ snapshot' = SnapshotOf(ev_pos', ev_kind', init_mem',
                              wr_pos', wr_addr', wr_val', cursor')

MBTEndThread ==
    /\ \E t \in 1..MaxThreads :
        /\ EndThread(t)
        /\ parameters' = [a |-> 0, v |-> 0, k |-> "NONE", p |-> 0, thr |-> t]
    /\ action_taken' = "EndThread"
    /\ snapshot' = SnapshotOf(ev_pos', ev_kind', init_mem',
                              wr_pos', wr_addr', wr_val', cursor')

MBTOpenCall ==
    /\ \E t \in 1..MaxThreads :
        /\ OpenCall(t)
        /\ parameters' = [a |-> 0, v |-> 0, k |-> "NONE", p |-> 0, thr |-> t]
    /\ action_taken' = "OpenCall"
    /\ snapshot' = SnapshotOf(ev_pos', ev_kind', init_mem',
                              wr_pos', wr_addr', wr_val', cursor')

MBTCloseCall ==
    /\ \E t \in 1..MaxThreads :
        /\ CloseCall(t)
        /\ parameters' = [a |-> 0, v |-> 0, k |-> "NONE", p |-> 0, thr |-> t]
    /\ action_taken' = "CloseCall"
    /\ snapshot' = SnapshotOf(ev_pos', ev_kind', init_mem',
                              wr_pos', wr_addr', wr_val', cursor')

MBTAdvance ==
    /\ Advance
    /\ action_taken' = "Advance"
    /\ parameters' = NoParams
    /\ snapshot' = SnapshotOf(ev_pos', ev_kind', init_mem',
                              wr_pos', wr_addr', wr_val', cursor')

MBTRetreat ==
    /\ Retreat
    /\ action_taken' = "Retreat"
    /\ parameters' = NoParams
    /\ snapshot' = SnapshotOf(ev_pos', ev_kind', init_mem',
                              wr_pos', wr_addr', wr_val', cursor')

MBTSeek ==
    /\ \E p \in 0..MaxPos :
        /\ Seek(p)
        /\ parameters' = [a |-> 0, v |-> 0, k |-> "NONE", p |-> p, thr |-> 0]
    /\ action_taken' = "Seek"
    /\ snapshot' = SnapshotOf(ev_pos', ev_kind', init_mem',
                              wr_pos', wr_addr', wr_val', cursor')

MBTNext ==
    \/ MBTRecordStep
    \/ MBTStartThread
    \/ MBTEndThread
    \/ MBTOpenCall
    \/ MBTCloseCall
    \/ MBTAdvance
    \/ MBTRetreat
    \/ MBTSeek

MBTSpec == MBTInit /\ [][MBTNext]_<<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                                     frontier, cursor, threads, calls,
                                     action_taken, parameters, snapshot>>

TraceComplete == TRUE
====

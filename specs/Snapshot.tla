---- MODULE Snapshot ----
EXTENDS Timeline

\* ── Snapshot — the formal Timeline → Model link ──────────────────────────
\*
\* Model.tla declares itself "a time-point spec — one frozen instant" that
\* "Timeline.tla re-indexes by position t" (Model.tla:9,46), and Timeline.tla
\* says "a time-point spec re-indexed by t would read through ValueAt"
\* (Timeline.tla:83). This module makes that informal link *syntactic*:
\*
\*   * Behaviors are Timeline's — EXTENDS Timeline adds no variables and no
\*     actions; recording and navigation proceed exactly as in Timeline.tla.
\*   * ModelAt(t) is the explicit re-indexing: a function from a timeline
\*     position to a Model-shaped state — the spec-level counterpart of
\*     Trace::snapshot (model/trace.rs). The index-to-Model connection is
\*     a first-class operator, not an encoding side effect.
\*   * M == INSTANCE Model WITH <every Model variable> <- ModelAt(cursor).f
\*     anchors the mapping to Model.tla itself: SnapshotValid checks the
\*     *actual* M!ModelInvariant on the materialized view at the cursor.
\*   * SnapshotsAreModels checks the same claim for every recorded index
\*     explicitly: \A t <= frontier, ValidModelAt(t) — ModelInvariant
\*     restated over ModelAt(t), since TLA+ cannot parameterize INSTANCE
\*     by t. LinkAtCursor guards against drift between the restatement
\*     and the real invariant.
\*
\* Mapping discipline (mirrors Trace::snapshot, model/trace.rs:178):
\*   * modules     — MODULE_LOAD minus MODULE_UNLOAD events at <= t,
\*                   event-ordered. Timeline events carry no address payload,
\*                   so a module's identity/base VA is its load event index
\*                   and an unload pops the most recent open load (LIFO);
\*                   the Rust extractor matches unloads by base VA. Every
\*                   snapshot fact carries provenance sid = 1 (the Rust side
\*                   uses TTFX_STREAM_TYPE).
\*   * threads     — empty: register files are per-position and out of scope
\*                   for v1 (Rust sets Snapshot.dump.threads = vec![]).
\*   * regions     — one region covering the abstract memory 1..MaxAddr,
\*                   R/W, Committed, Private. Model regions carry metadata
\*                   only; byte-level faithfulness is Timeline's
\*                   SnapshotConsistent.
\*   * sysinfo     — absent (Rust: system_info: None).
\*   * exception   — present once an EXCEPTION event exists at <= t;
\*                   payload abstracted to 0 because Timeline's event log is
\*                   kind-only (Rust maps exceptions_at(t).last()).
\*   * anomalies   — empty: Timeline invariants are enforced at decode time,
\*                   not degraded into anomalies.
\*   * annotations — the single ("ttfx_position", ...) pair Rust adds.
\*
\* NOTE on bounds: Timeline admits MaxEvents = 3 simultaneously open loads,
\* which exceeded Model's original MaxModules = 2. Composing the specs
\* surfaced that mismatch, and MaxModules was raised to 3 (bounds are
\* verification artifacts — Model.tla:44). That was the first property the
\* formal link checked.

\* ---- Event-log prefix views ----

\* Number of recorded events at or before position t. Log order agrees with
\* position order (TraceOrdered), so the prefix 1..EvUpto(t) is exactly the
\* events with ev_pos[i] <= t.
\* @type: (Int) => Int;
EvUpto(t) ==
    Cardinality({i \in 1..MaxEvents : i <= Len(ev_pos) /\ ev_pos[i] <= t})

\* Number of EXCEPTION events at or before position t.
\* @type: (Int) => Int;
ExcUpto(t) ==
    Cardinality({i \in 1..MaxEvents : i <= Len(ev_pos) /\ ev_pos[i] <= t
                                      /\ ev_kind[i] = "EXCEPTION"})

\* ---- Snapshot components ----

\* Loads/unloads among events a..b (constant quantifier domain with guards,
\* the same Apalache-friendly discipline as Timeline.tla).
\* @type: (Int, Int) => Int;
LoadsIn(a, b) ==
    Cardinality({j \in 1..MaxEvents : a <= j /\ j <= b /\ j <= Len(ev_pos)
                                     /\ ev_kind[j] = "MODULE_LOAD"})
\* @type: (Int, Int) => Int;
UnloadsIn(a, b) ==
    Cardinality({j \in 1..MaxEvents : a <= j /\ j <= b /\ j <= Len(ev_pos)
                                     /\ ev_kind[j] = "MODULE_UNLOAD"})

\* Load event i is still open after the first n events. LIFO matching makes
\* loads/unloads behave as parentheses (a no-op unload on an empty table can
\* only occur once i is already closed, so it never corrupts the count):
\* i survives iff every prefix of i..n holds more loads than unloads.
\* @type: (Int, Int) => Bool;
LoadAliveAt(i, n) ==
    /\ i <= n /\ i <= Len(ev_pos) /\ ev_kind[i] = "MODULE_LOAD"
    /\ \A k \in 1..MaxEvents :
         (i <= k /\ k <= n) => LoadsIn(i, k) > UnloadsIn(i, k)

\* Still-loaded module ids (= load event indices) after the first n events,
\* in increasing index order. Apalache has no recursive operators, so the
\* sorted set is materialized by repeated minimum; MaxEvents = 3 bounds the
\* unroll (extend the chain if MaxEvents grows).
\* @type: (Int) => Seq(Int);
OpenMods(n) ==
    LET open == {i \in 1..MaxEvents : i <= n /\ LoadAliveAt(i, n)}
    IN IF open = {} THEN <<>>
       ELSE LET m1 == CHOOSE x \in open : \A y \in open : x <= y
                r1 == open \ {m1}
            IN IF r1 = {} THEN <<m1>>
               ELSE LET m2 == CHOOSE x \in r1 : \A y \in r1 : x <= y
                        r2 == r1 \ {m2}
                    IN IF r2 = {} THEN <<m1, m2>>
                       ELSE LET m3 == CHOOSE x \in r2 : \A y \in r2 : x <= y
                            IN <<m1, m2, m3>>

\* A length-n sequence with every cell = x. n <= MaxEvents = 3 at the call
\* sites, so a 3-cell literal suffices (extend if MaxEvents grows).
\* @type: (Int, Int) => Seq(Int);
ConstSeq(n, x) == SubSeq(<<x, x, x>>, 1, n)

\* The single memory region covering the abstract cells 1..MaxAddr
\* (annotated: bare <<..>> literals are tuple/sequence ambiguous to Snowcat).
\* @type: Seq(Int);
SnapMemVa      == <<1>>
\* @type: Seq(Int);
SnapMemSz      == <<MaxAddr>>
\* @type: Seq(Int);
SnapMemProt    == <<3>>              \* READ|WRITE
\* @type: Seq(Int);
SnapMemState   == <<0>>              \* Commit
\* @type: Seq(Int);
SnapMemType    == <<0>>              \* Private
\* @type: Seq(Int);
SnapMemCls     == <<3>>              \* Private
\* @type: Seq(Int);
SnapMemProvSid == <<1>>
\* @type: Seq(Int);
SnapMemProvOff == <<0>>
\* @type: Seq(Int);
SnapMemProvRva == <<0>>

\* The position annotation Rust adds to every snapshot Dump.
\* @type: Seq(Str);
SnapAnnKey == <<"ttfx_position">>
\* @type: Seq(Str);
SnapAnnVal == <<"pos">>

\* Empty tables, annotated: bare <<>> literals are polymorphic and poison
\* Len(...) sites downstream (Snowcat).
\* @type: Seq(Int);
SnapEmptyInts == <<>>
\* @type: Seq([desc: Str]);
SnapEmptyAnomalies == <<>>

\* ---- The explicit re-indexing: position t |-> Model state ----

\* The Model-shaped state materialized at timeline position t. Field names
\* match Model.tla's variables one-to-one; this is the formal statement of
\* "timeline index t corresponds to *this* Model".
\* @type: (Int) => [sysinfo: Seq(Int), mod_va: Seq(Int), mod_sz: Seq(Int), mod_prov_sid: Seq(Int), mod_prov_off: Seq(Int), mod_prov_rva: Seq(Int), thr_id: Seq(Int), thr_stack_va: Seq(Int), thr_stack_sz: Seq(Int), thr_prov_sid: Seq(Int), thr_prov_off: Seq(Int), thr_prov_rva: Seq(Int), mem_va: Seq(Int), mem_sz: Seq(Int), mem_prot: Seq(Int), mem_state: Seq(Int), mem_type: Seq(Int), mem_cls: Seq(Int), mem_prov_sid: Seq(Int), mem_prov_off: Seq(Int), mem_prov_rva: Seq(Int), exc_info: Seq(Int), anomalies: Seq([desc: Str]), ann_key: Seq(Str), ann_val: Seq(Str)];
ModelAt(t) ==
    LET mods == OpenMods(EvUpto(t))
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
         exc_info     |-> IF ExcUpto(t) > 0
                          THEN <<0, 0, 0, 0, 1, 0, 0>> \* payload abstracted; sid = 1
                          ELSE SnapEmptyInts,
         anomalies    |-> SnapEmptyAnomalies,
         ann_key      |-> SnapAnnKey,
         ann_val      |-> SnapAnnVal ]

\* ---- Anchor: Model.tla instantiated at the cursor position ----

M == INSTANCE Model WITH
    sysinfo      <- ModelAt(cursor).sysinfo,
    mod_va       <- ModelAt(cursor).mod_va,
    mod_sz       <- ModelAt(cursor).mod_sz,
    mod_prov_sid <- ModelAt(cursor).mod_prov_sid,
    mod_prov_off <- ModelAt(cursor).mod_prov_off,
    mod_prov_rva <- ModelAt(cursor).mod_prov_rva,
    thr_id       <- ModelAt(cursor).thr_id,
    thr_stack_va <- ModelAt(cursor).thr_stack_va,
    thr_stack_sz <- ModelAt(cursor).thr_stack_sz,
    thr_prov_sid <- ModelAt(cursor).thr_prov_sid,
    thr_prov_off <- ModelAt(cursor).thr_prov_off,
    thr_prov_rva <- ModelAt(cursor).thr_prov_rva,
    mem_va       <- ModelAt(cursor).mem_va,
    mem_sz       <- ModelAt(cursor).mem_sz,
    mem_prot     <- ModelAt(cursor).mem_prot,
    mem_state    <- ModelAt(cursor).mem_state,
    mem_type     <- ModelAt(cursor).mem_type,
    mem_cls      <- ModelAt(cursor).mem_cls,
    mem_prov_sid <- ModelAt(cursor).mem_prov_sid,
    mem_prov_off <- ModelAt(cursor).mem_prov_off,
    mem_prov_rva <- ModelAt(cursor).mem_prov_rva,
    exc_info     <- ModelAt(cursor).exc_info,
    anomalies    <- ModelAt(cursor).anomalies,
    ann_key      <- ModelAt(cursor).ann_key,
    ann_val      <- ModelAt(cursor).ann_val

\* ---- The linked properties ----

\* Anchor property: the snapshot at the cursor satisfies Model.tla's own
\* invariant. Seek makes every position in 0..frontier reachable as a cursor
\* value, so across behaviors this already covers all recorded positions.
SnapshotValid == M!ModelInvariant

\* ModelInvariant restated pointwise over ModelAt(t) — same conjuncts in
\* the same form (Model.tla:178), because INSTANCE cannot be parameterized
\* by the position index. ValidModelAt is what SnapshotValid would be if
\* the instance could be re-bound per t.
\* @type: (Int) => Bool;
ValidModelAt(t) ==
    LET m == ModelAt(t)
    IN /\ Len(m.mod_va) <= M!MaxModules
       /\ Len(m.thr_id) <= M!MaxThreads
       /\ Len(m.mem_va) <= M!MaxRegions
       /\ Len(m.anomalies) <= M!MaxAnomalies
       /\ Len(m.ann_key) <= M!MaxAnnotations
       /\ Len(m.ann_val) = Len(m.ann_key)
       /\ \A i \in 1..M!MaxModules :
            \A j \in 1..M!MaxModules :
              (i <= Len(m.mod_va) /\ j <= Len(m.mod_va) /\ i # j) =>
                ~(m.mod_va[i] < m.mod_va[j] + m.mod_sz[j]
                  /\ m.mod_va[j] < m.mod_va[i] + m.mod_sz[i])
       /\ \A i \in 1..M!MaxModules :
            i <= Len(m.mod_va) =>
              m.mod_prov_sid[i] > 0 /\ m.mod_prov_off[i] >= 0
       /\ \A i \in 1..M!MaxThreads :
            i <= Len(m.thr_id) =>
              m.thr_prov_sid[i] > 0 /\ m.thr_prov_off[i] >= 0
       /\ \A i \in 1..M!MaxRegions :
            i <= Len(m.mem_va) =>
              m.mem_prov_sid[i] > 0 /\ m.mem_prov_off[i] >= 0
       /\ \A i \in 1..M!MaxRegions :
            i <= Len(m.mem_va) => m.mem_cls[i] \in {0,1,2,3,4}
       /\ \A i \in 1..M!MaxRegions :
            i <= Len(m.mem_va) => m.mem_state[i] \in {0,1,2}
       /\ \A i \in 1..M!MaxRegions :
            i <= Len(m.mem_va) => m.mem_prot[i] <= 7
       /\ \A i \in 1..M!MaxThreads :
            i <= Len(m.thr_id) => m.thr_stack_sz[i] > 0

\* The explicit link: every recorded index materializes into a valid Model.
\* This is "Trace::snapshot(t) yields a valid Dump at every recorded
\* position t" stated over indices, not over cursor reachability.
SnapshotsAreModels ==
    \A t \in 0..MaxPos : t <= frontier => ValidModelAt(t)

\* Drift guard: the pointwise restatement and the real M!ModelInvariant
\* agree at the cursor, so ValidModelAt cannot silently diverge from
\* Model.tla's actual invariant.
LinkAtCursor == ValidModelAt(cursor) <=> M!ModelInvariant

=============================================================================

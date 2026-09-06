---- MODULE Snapshot ----
EXTENDS ExecutionState

\* Immutable execution-point materialization (2026-09-06).
\* Replaces the historical Timeline -> Model/Dump projection at this filename.
\* A request fixes source/point identity, accumulates each observation before
\* another page can replace it in the one-cell cache, and then publishes a point.
\* Pure point inspection/navigation does not fetch. Acquisition is an explicit
\* action. A completed result remains valid after cache replacement or eviction.
\* No modules, system information, file size or capture aggregate enters a point.
\* Completion means all requested cells were attempted, not that all resolved.
\* The model projects requested cells; implementation may include other cached
\* pages too. The last published result survives the next request's acquisition
\* until that request publishes its replacement; multiple caller-held results
\* are outside this bounded state machine.

VARIABLES
    \* @type: Str;
    mat_phase,
    \* @type: Int;
    mat_source,
    \* @type: Int;
    mat_pos,
    \* @type: Set(Int);
    mat_requested,
    \* @type: Set(Int);
    mat_seen,
    \* @type: Set(Int);
    mat_observed,
    \* @type: Int -> [knowledge: Str, value: Int];
    mat_values,
    \* @type: Bool;
    snapshot_live,
    \* @type: [source: Int, kind: Str, position: Int];
    published_id,
    \* @type: Set(Int);
    published_requested,
    \* @type: Set(Int);
    published_observed,
    \* @type: [id: [source: Int, kind: Str, position: Int],
    \*   addressSpace: Int -> [knowledge: Str, value: Int], events: Seq(Int),
    \*   threads: Int -> [present: Bool, instance: Int, lifetime_known: Bool,
    \*     start: Int, stop: Int, registers: [knowledge: Str, value: Int],
    \*     stack_range: [knowledge: Str, base: Int, size: Int],
    \*     frames: [knowledge: Str, values: Seq(Int), complete: Bool]]];
    snapshot

mvars == <<mat_phase, mat_source, mat_pos, mat_requested, mat_seen, mat_observed,
           mat_values, snapshot_live, published_id, published_requested,
           published_observed, snapshot>>
materializationVars == <<executionVars, mvars>>

MaterializationInit ==
    /\ ExecutionInit
    /\ mat_phase = "IDLE"
    /\ mat_source = TraceSource /\ mat_pos = 0
    /\ mat_requested = {} /\ mat_seen = {} /\ mat_observed = {}
    /\ mat_values = [a \in 1..MaxAddr |-> [knowledge |-> "unknown", value |-> 0]]
    /\ snapshot_live = FALSE
    /\ published_id = PointId(CaptureSource, 0)
    /\ published_requested = {}
    /\ published_observed = {}
    /\ snapshot = ExecutionPointAt(CaptureSource, 0)

\* Starting a request captures its identity independently of the moving cursor.
BeginMaterialization(source, t, requested) ==
    /\ trace_sealed /\ ValidPoint(source, t)
    /\ requested \subseteq 1..MaxAddr
    /\ mat_phase # "RUNNING"
    /\ mat_phase' = "RUNNING"
    /\ mat_source' = source /\ mat_pos' = t
    /\ mat_requested' = requested /\ mat_seen' = {} /\ mat_observed' = {}
    /\ mat_values' = [a \in 1..MaxAddr |-> [knowledge |-> "unknown", value |-> 0]]
    /\ UNCHANGED <<executionVars, snapshot_live, published_id, published_requested,
                   published_observed, snapshot>>

CollectCached(a) ==
    /\ mat_phase = "RUNNING"
    /\ a \in mat_requested \ mat_seen
    /\ ReadAt(mat_source, mat_pos, a).knowledge \in {"known", "absent"}
    /\ mat_seen' = mat_seen \cup {a}
    /\ mat_observed' = mat_observed \cup {a}
    /\ mat_values' = [mat_values EXCEPT ![a] = ReadAt(mat_source, mat_pos, a)]
    /\ UNCHANGED <<executionVars, mat_phase, mat_source, mat_pos,
                   mat_requested, snapshot_live, published_id, published_requested,
                   published_observed, snapshot>>

\* Acquire and retain in the same transition, before a later ObserveMemory
\* replaces the shared cache. This models collectPages / PageMaterialization.
CollectFetched(a) ==
    /\ mat_phase = "RUNNING"
    /\ a \in mat_requested \ mat_seen
    /\ ReadAt(mat_source, mat_pos, a).knowledge = "unknown"
    /\ ObserveMemory(mat_source, mat_pos, a)
    /\ mat_seen' = mat_seen \cup {a}
    /\ mat_observed' = mat_observed \cup {a}
    /\ LET key == CellKey(mat_source, mat_pos, a)
       IN mat_values' = [mat_values EXCEPT ![a] =
            IF key \in known_absence'
            THEN [knowledge |-> "absent", value |-> 0]
            ELSE [knowledge |-> "known", value |-> observed_values'[key]]]
    /\ UNCHANGED <<mat_phase, mat_source, mat_pos, mat_requested,
                   snapshot_live, published_id, published_requested, published_observed, snapshot>>

\* An unavailable/frontier/P3 read may complete without new memory knowledge.
\* Record the attempt; it must not become a known zero or a proof of absence.
CollectUnresolved(a) ==
    /\ mat_phase = "RUNNING"
    /\ a \in mat_requested \ mat_seen
    /\ ReadAt(mat_source, mat_pos, a).knowledge = "unknown"
    /\ mat_seen' = mat_seen \cup {a}
    /\ UNCHANGED <<executionVars, mat_phase, mat_source, mat_pos, mat_requested,
                   mat_observed, mat_values, snapshot_live, published_id,
                   published_requested, published_observed, snapshot>>

FinishMaterialization ==
    /\ mat_phase = "RUNNING" /\ mat_seen = mat_requested
    /\ mat_phase' = "DONE" /\ snapshot_live' = TRUE
    /\ published_id' = PointId(mat_source, mat_pos)
    /\ published_requested' = mat_requested
    /\ published_observed' = mat_observed
    /\ snapshot' = [ExecutionPointAt(mat_source, mat_pos) EXCEPT !.addressSpace = mat_values]
    /\ UNCHANGED <<executionVars, mat_source, mat_pos, mat_requested,
                   mat_seen, mat_observed, mat_values>>

\* Other point queries, navigation and cache operations cannot alter a result.
MaterializationEnvironment ==
    ExecutionNext /\ UNCHANGED mvars

MaterializationNext ==
    \/ MaterializationEnvironment
    \/ \E source \in Sources, t \in 0..MaxPos, requested \in SUBSET (1..MaxAddr) :
         BeginMaterialization(source, t, requested)
    \/ \E a \in 1..MaxAddr : CollectCached(a)
    \/ \E a \in 1..MaxAddr : CollectFetched(a)
    \/ \E a \in 1..MaxAddr : CollectUnresolved(a)
    \/ FinishMaterialization

MaterializationTypes ==
    /\ mat_phase \in {"IDLE", "RUNNING", "DONE"}
    /\ mat_source \in Sources /\ mat_pos \in 0..MaxPos
    /\ mat_seen \subseteq mat_requested /\ mat_requested \subseteq 1..MaxAddr
    /\ mat_observed \subseteq mat_seen
    /\ (mat_phase # "IDLE" => trace_sealed /\ ValidPoint(mat_source, mat_pos))
    /\ published_requested \subseteq 1..MaxAddr
    /\ published_observed \subseteq published_requested
    /\ (mat_phase = "DONE" => snapshot_live)
    /\ (snapshot_live => ValidPoint(published_id.source, published_id.position))

RetainedObservationsSound ==
    \A a \in 1..MaxAddr :
      LET key == CellKey(mat_source, mat_pos, a)
      IN /\ (a \in mat_observed <=> mat_values[a].knowledge \in {"known", "absent"})
         /\ (a \in mat_seen =>
               \/ /\ mat_values[a].knowledge = "known"
                  /\ mapped_truth[key]
                  /\ mat_values[a].value = TruthAt(mat_source, mat_pos, a)
               \/ /\ mat_values[a].knowledge = "absent"
                  /\ ~mapped_truth[key]
               \/ mat_values[a].knowledge = "unknown")
         /\ (a \notin mat_seen => mat_values[a].knowledge = "unknown")

SnapshotIdentity ==
    snapshot_live =>
      /\ snapshot.id = published_id
      /\ DOMAIN snapshot = {"id", "addressSpace", "events", "threads"}
      /\ snapshot.events = OrderedPointEvents(published_id.source, published_id.position)
      /\ \A thr \in 1..MaxThreads :
           snapshot.threads[thr] =
             ThreadStateAt(published_id.source, published_id.position, thr)

SnapshotComplete ==
    /\ (mat_phase = "DONE" =>
          /\ mat_seen = mat_requested
          /\ snapshot.addressSpace = mat_values
          /\ published_requested = mat_requested
          /\ published_observed = mat_observed
          /\ published_id = PointId(mat_source, mat_pos))
    /\ (snapshot_live =>
          \A a \in 1..MaxAddr :
            snapshot.addressSpace[a].knowledge \in {"known", "absent", "unknown"})

\* The result is accurate even if no part of it remains cached. The request
\* can contain two cells whereas KnowledgeSound bounds the cache to one.
IndependentOfCache ==
    snapshot_live =>
      \A a \in 1..MaxAddr :
        a \in published_requested =>
          LET key == CellKey(published_id.source, published_id.position, a)
              result == snapshot.addressSpace[a]
          IN /\ (a \in published_observed <=> result.knowledge \in {"known", "absent"})
             /\ (result.knowledge = "known" =>
                    /\ mapped_truth[key]
                    /\ result.value = TruthAt(published_id.source, published_id.position, a))
             /\ (result.knowledge = "absent" => ~mapped_truth[key])

SnapshotInvariant ==
    /\ ExecutionInvariant
    /\ MaterializationTypes /\ RetainedObservationsSound
    /\ SnapshotIdentity /\ SnapshotComplete /\ IndependentOfCache

MaterializationSpec == MaterializationInit /\ [][MaterializationNext]_materializationVars
=============================================================================

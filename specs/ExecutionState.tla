---- MODULE ExecutionState ----
EXTENDS Timeline

\* Execution views for traces and single-point captures (2026-09-06).
\* Timeline supplies recorded truth; this module stores observations separately.
\* A point has address space, exact events and per-thread execution knowledge.
\* Context/artifact data is separate; no Model.tla/Dump aggregate is constructed.
\*
\* Bounds/abstractions: source 1 is a trace, source 2 a capture. Capture coordinate
\* 0 is a tagged observation token, not a fictitious TTD coordinate. One cell is
\* one page/byte; the cache retains one observation so Snapshot.tla can exercise
\* materialization larger than cache capacity. Mapping truth is chosen for every
\* source/point/cell. Adapter truth is assumed here; ReplayApi/JigSaw model the
\* engine and index. Registers/ranges are abstract values, and thread sequence
\* indices identify lifetime instances. Proxy v1 supplies no stack contexts.
\* Capture contexts can be unavailable or valid (including valid zero registers).
\* Histories are sealed before acquisition, like loading an immutable .run.

Sources == 1..2
TraceSource == 1
CaptureSource == 2
CellKeys == Sources \X (0..MaxPos) \X (1..MaxAddr)

\* @type: (Int, Int, Int) => <<Int, Int, Int>>;
CellKey(source, t, addr) == <<source, t, addr>>

VARIABLES
    \* @type: Bool;
    trace_sealed,
    \* @type: <<Int, Int, Int>> -> Bool;
    mapped_truth,
    \* @type: Int -> Int;
    capture_memory,
    \* @type: Set(Int);
    capture_threads,
    \* @type: Int -> Bool;
    capture_regs_valid,
    \* @type: Int -> Int;
    capture_regs,
    \* @type: Int -> Bool;
    capture_stack_valid,
    \* @type: Bool;
    capture_exception,
    \* @type: Set(<<Int, Int, Int>>);
    known_bytes,
    \* @type: Set(<<Int, Int, Int>>);
    known_absence,
    \* @type: <<Int, Int, Int>> -> Int;
    observed_values

evars == <<trace_sealed, mapped_truth, capture_memory, capture_threads,
           capture_regs_valid, capture_regs, capture_stack_valid,
           capture_exception, known_bytes, known_absence, observed_values>>
executionVars == <<vars, evars>>

\* @type: (Int, Int) => Bool;
ValidPoint(source, t) ==
    \/ source = TraceSource /\ t \in 0..MaxPos /\ t <= frontier
    \/ source = CaptureSource /\ t = 0

\* @type: (Int, Int) => Bool;
PointQueryOk(source, t) == ValidPoint(source, t)

\* @type: (Int, Int) => [source: Int, kind: Str, position: Int];
PointId(source, t) ==
    [source |-> source,
     kind |-> IF source = CaptureSource THEN "capture" ELSE "trace",
     position |-> t]

\* @type: (Int, Int, Int) => Int;
TruthAt(source, t, addr) ==
    IF source = TraceSource THEN ValueAt(addr, t) ELSE capture_memory[addr]

\* Reads return stored observations; unknown placeholders are never known zeros.
\* @type: (Int, Int, Int) => [knowledge: Str, value: Int];
ReadAt(source, t, addr) ==
    IF ~PointQueryOk(source, t) \/ addr \notin 1..MaxAddr
    THEN [knowledge |-> "invalid", value |-> 0]
    ELSE LET key == CellKey(source, t, addr)
         IN IF key \in known_absence THEN [knowledge |-> "absent", value |-> 0]
            ELSE IF key \in known_bytes
                 THEN [knowledge |-> "known", value |-> observed_values[key]]
                 ELSE [knowledge |-> "unknown", value |-> 0]

\* @type: (Int, Int) => Set(Int);
PointEvents(source, t) ==
    IF source = TraceSource THEN EventsAt(t)
    ELSE IF source = CaptureSource /\ t = 0 /\ capture_exception THEN {1}
    ELSE {}

\* @type: (Int, Int) => Str;
EventKind(source, event) ==
    IF source = TraceSource
    THEN IF event \in 1..MaxEvents /\ event <= Len(ev_kind)
         THEN ev_kind[event] ELSE "NONE"
    ELSE IF source = CaptureSource /\ event = 1 /\ capture_exception
         THEN "EXCEPTION" ELSE "NONE"

\* Bounded sequence of event IDs (keep in sync with MaxEvents; invariant below).
\* @type: Seq(Int);
EventIds == <<1, 2, 3>>

\* Ascending log indices retain occurrence order, including ties in position.
\* @type: (Int, Int) => Seq(Int);
OrderedPointEvents(source, t) ==
    SelectSeq(EventIds,
              LAMBDA i : i \in PointEvents(source, t))

\* @type: (Int, Int) => Set(Int);
PointThreads(source, t) ==
    IF source = TraceSource THEN LiveThreads(t)
    ELSE IF source = CaptureSource /\ t = 0 THEN capture_threads ELSE {}

\* A constant thread domain is used for bounded checking. present=FALSE means
\* the slot is omitted from the public collection. No zero register placeholder
\* is treated as an observed context, and no unavailable frame list is complete.
\* @type: (Int, Int, Int) => [present: Bool, instance: Int,
\*   lifetime_known: Bool, start: Int, stop: Int,
\*   registers: [knowledge: Str, value: Int],
\*   stack_range: [knowledge: Str, base: Int, size: Int],
\*   frames: [knowledge: Str, values: Seq(Int), complete: Bool]];
ThreadStateAt(source, t, thr) ==
    LET live == thr \in PointThreads(source, t)
        captured == source = CaptureSource /\ live
        traceLive == source = TraceSource /\ live
    IN [present |-> live, instance |-> thr,
        lifetime_known |-> traceLive,
        start |-> IF traceLive THEN threads[thr].start ELSE 0,
        stop |-> IF traceLive THEN threads[thr].end ELSE 0,
        registers |->
          [knowledge |-> IF captured /\ capture_regs_valid[thr]
                         THEN "known" ELSE "unavailable",
           value |-> IF captured /\ capture_regs_valid[thr]
                     THEN capture_regs[thr] ELSE 0],
        stack_range |->
          [knowledge |-> IF captured /\ capture_stack_valid[thr]
                         THEN "known" ELSE "unavailable",
           base |-> IF captured /\ capture_stack_valid[thr] THEN thr ELSE 0,
           size |-> IF captured /\ capture_stack_valid[thr] THEN 1 ELSE 0],
        frames |-> [knowledge |-> "unavailable", values |-> <<>>, complete |-> FALSE]]

\* @type: (Int, Int) => [id: [source: Int, kind: Str, position: Int],
\*   addressSpace: Int -> [knowledge: Str, value: Int], events: Seq(Int),
\*   threads: Int -> [present: Bool, instance: Int, lifetime_known: Bool,
\*     start: Int, stop: Int, registers: [knowledge: Str, value: Int],
\*     stack_range: [knowledge: Str, base: Int, size: Int],
\*     frames: [knowledge: Str, values: Seq(Int), complete: Bool]]];
ExecutionPointAt(source, t) ==
    [id |-> PointId(source, t),
     addressSpace |-> [a \in 1..MaxAddr |-> ReadAt(source, t, a)],
     events |-> OrderedPointEvents(source, t),
     threads |-> [thr \in 1..MaxThreads |-> ThreadStateAt(source, t, thr)]]

\* A single-point capture cannot assert intervening history, even at equal bounds.
\* @type: (Int, Int, Int) => [ok: Bool, events: Set(Int)];
SourceEventsBetween(source, a, b) ==
    [ok |-> source = TraceSource /\ ValidInterval(a, b),
     events |-> IF source = TraceSource /\ ValidInterval(a, b)
                THEN EventsIn(a, b) ELSE {}]

\* @type: (Int, Int) => Set(Int);
PointExceptions(source, t) ==
    {i \in 1..MaxEvents :
       i \in PointEvents(source, t) /\ EventKind(source, i) = "EXCEPTION"}

\* 0 is automatic selection; positive choices index the point's event sequence.
\* Lean's explicit zero-based index n corresponds to choice n+1 here.
\* @type: (Int, Int, Int) => Int;
SelectedException(source, t, choice) ==
    LET exceptions == PointExceptions(source, t)
        es == OrderedPointEvents(source, t)
    IN IF ~PointQueryOk(source, t) THEN 0
       ELSE IF choice # 0
            THEN IF choice >= 1 /\ choice <= Len(es)
                 THEN IF es[choice] \in exceptions THEN es[choice] ELSE 0
                 ELSE 0
       ELSE IF Cardinality(exceptions) = 1
            THEN CHOOSE i \in exceptions : TRUE ELSE 0

\* @type: (Int, Int, Int, Int) => Bool;
EvidenceApplies(eSource, ePos, qSource, qPos) ==
    eSource = qSource /\ ePos = qPos

\* Context observations are consumed separately from the execution point.
\* Payload truth is an adapter obligation; this checks scope and value retention.
\* @type: (Int, Int, Int, Int, Int) => [knowledge: Str, value: Int];
ContextEvidenceAt(source, t, eSource, ePos, value) ==
    IF PointQueryOk(source, t) /\ EvidenceApplies(eSource, ePos, source, t)
    THEN [knowledge |-> "known", value |-> value]
    ELSE [knowledge |-> "unknown", value |-> 0]

RecordTrace == ~trace_sealed /\ Next /\ UNCHANGED evars

\* Additional occurrences at the current head exercise multiple exact events;
\* this does not alter Timeline's recording actions inherited by ReplayApi.
RecordAdditionalEvent ==
    /\ ~trace_sealed
    /\ Len(ev_pos) < MaxEvents
    /\ \E kind \in EventKinds :
         /\ ev_pos' = Append(ev_pos, frontier)
         /\ ev_kind' = Append(ev_kind, kind)
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, frontier, cursor,
                   threads, calls, evars>>

SealTrace ==
    /\ ~trace_sealed
    /\ trace_sealed' = TRUE
    /\ UNCHANGED <<vars, mapped_truth, capture_memory, capture_threads,
                   capture_regs_valid, capture_regs, capture_stack_valid,
                   capture_exception, known_bytes, known_absence, observed_values>>

NavigateTrace ==
    /\ trace_sealed
    /\ (Advance \/ Retreat \/ \E p \in 0..MaxPos : Seek(p))
    /\ UNCHANGED evars

\* Acquisition replaces the single reusable cache cell with tagged evidence.
ObserveMemory(source, t, addr) ==
    /\ trace_sealed /\ ValidPoint(source, t) /\ addr \in 1..MaxAddr
    /\ LET key == CellKey(source, t, addr)
       IN /\ known_bytes' = IF mapped_truth[key] THEN {key} ELSE {}
          /\ known_absence' = IF mapped_truth[key] THEN {} ELSE {key}
          /\ observed_values' =
               IF mapped_truth[key]
               THEN [observed_values EXCEPT ![key] = TruthAt(source, t, addr)]
               ELSE observed_values
    /\ UNCHANGED <<vars, trace_sealed, mapped_truth, capture_memory,
                   capture_threads, capture_regs_valid, capture_regs,
                   capture_stack_valid, capture_exception>>

EvictKnowledge ==
    /\ known_bytes \cup known_absence # {}
    /\ known_bytes' = {} /\ known_absence' = {}
    /\ UNCHANGED <<vars, trace_sealed, mapped_truth, capture_memory,
                   capture_threads, capture_regs_valid, capture_regs,
                   capture_stack_valid, capture_exception, observed_values>>

ExecutionInit ==
    /\ Init
    /\ trace_sealed = FALSE
    /\ mapped_truth \in [CellKeys -> BOOLEAN]
    /\ capture_memory \in [1..MaxAddr -> 0..MaxVal - 1]
    /\ capture_threads \in SUBSET (1..MaxThreads)
    /\ capture_regs_valid \in [1..MaxThreads -> BOOLEAN]
    /\ capture_regs \in [1..MaxThreads -> 0..MaxVal - 1]
    /\ capture_stack_valid \in [1..MaxThreads -> BOOLEAN]
    /\ capture_exception \in BOOLEAN
    /\ known_bytes = {} /\ known_absence = {}
    /\ observed_values = [key \in CellKeys |-> 0]

ExecutionNext ==
    \/ RecordTrace \/ RecordAdditionalEvent \/ SealTrace \/ NavigateTrace
    \/ \E source \in Sources, t \in 0..MaxPos, addr \in 1..MaxAddr :
         ObserveMemory(source, t, addr)
    \/ EvictKnowledge

KnowledgeSound ==
    /\ known_bytes \subseteq CellKeys /\ known_absence \subseteq CellKeys
    /\ known_bytes \cap known_absence = {}
    /\ Cardinality(known_bytes \cup known_absence) <= 1
    /\ \A source \in Sources, t \in 0..MaxPos, addr \in 1..MaxAddr :
         LET key == CellKey(source, t, addr)
         IN /\ key \in known_bytes =>
                 /\ trace_sealed /\ ValidPoint(source, t) /\ mapped_truth[key]
                 /\ observed_values[key] = TruthAt(source, t, addr)
                 /\ ReadAt(source, t, addr).knowledge = "known"
                 /\ ReadAt(source, t, addr).value = observed_values[key]
            /\ key \in known_absence =>
                 /\ trace_sealed /\ ValidPoint(source, t) /\ ~mapped_truth[key]
                 /\ ReadAt(source, t, addr).knowledge = "absent"

UnknownIsNotZero ==
    \A source \in Sources, t \in 0..MaxPos, addr \in 1..MaxAddr :
      (ValidPoint(source, t) /\ CellKey(source, t, addr) \notin known_bytes \cup known_absence)
        => ReadAt(source, t, addr).knowledge = "unknown"

PointIdentity ==
    \A source \in Sources, t \in 0..MaxPos :
      ValidPoint(source, t) =>
        /\ ExecutionPointAt(source, t).id = PointId(source, t)
        /\ DOMAIN ExecutionPointAt(source, t) = {"id", "addressSpace", "events", "threads"}
        /\ (source = CaptureSource => ExecutionPointAt(source, t).id.kind = "capture")

ExactEvents ==
    \A t \in 0..MaxPos, i \in 1..MaxEvents :
      (t <= frontier /\ i <= Len(ev_pos)) =>
        (i \in PointEvents(TraceSource, t) <=> ev_pos[i] = t)

ReturnedEventsComplete ==
    \A source \in Sources, t \in 0..MaxPos, event \in 1..MaxEvents :
      PointQueryOk(source, t) =>
        LET es == ExecutionPointAt(source, t).events
        IN (event \in PointEvents(source, t) <=>
              \E i \in 1..MaxEvents : i <= Len(es) /\ es[i] = event)

PointQueryBounds ==
    \A source \in 0..3, t \in -1..(MaxPos + 1) :
      /\ (PointQueryOk(source, t) <=>
            (source = TraceSource /\ 0 <= t /\ t <= frontier)
              \/ (source = CaptureSource /\ t = 0))
      /\ (~PointQueryOk(source, t) =>
            \A a \in 1..MaxAddr : ReadAt(source, t, a).knowledge = "invalid")

EventOrder ==
    \A source \in Sources, t \in 0..MaxPos, i \in 1..MaxEvents, j \in 1..MaxEvents :
      LET es == OrderedPointEvents(source, t)
      IN (i <= Len(es) /\ j <= Len(es) /\ i < j) => es[i] < es[j]

ThreadKnowledgeSound ==
    \A source \in Sources, t \in 0..MaxPos, thr \in 1..MaxThreads :
      ValidPoint(source, t) =>
        LET th == ThreadStateAt(source, t, thr)
        IN /\ (th.present <=> thr \in PointThreads(source, t))
           /\ (source = TraceSource =>
                 /\ th.registers.knowledge = "unavailable"
                 /\ th.stack_range.knowledge = "unavailable")
           /\ (th.registers.knowledge = "known" =>
                 /\ source = CaptureSource /\ th.present /\ capture_regs_valid[thr]
                 /\ th.registers.value = capture_regs[thr])
           /\ (th.stack_range.knowledge = "known" =>
                 /\ source = CaptureSource /\ th.present /\ capture_stack_valid[thr])
           /\ th.frames.knowledge = "unavailable" /\ ~th.frames.complete
           /\ (source = CaptureSource => ~th.lifetime_known)

SelectionSound ==
    \A source \in Sources, t \in 0..MaxPos, choice \in -1..(MaxEvents + 1) :
      /\ (SelectedException(source, t, choice) # 0 =>
            SelectedException(source, t, choice) \in PointExceptions(source, t))
      /\ (Cardinality(PointExceptions(source, t)) # 1 =>
            SelectedException(source, t, 0) = 0)
      /\ (choice < 0 \/ choice > Len(OrderedPointEvents(source, t)) =>
            SelectedException(source, t, choice) = 0)

SelectionComplete ==
    \A source \in Sources, t \in 0..MaxPos : PointQueryOk(source, t) =>
      LET exceptions == PointExceptions(source, t)
          es == OrderedPointEvents(source, t)
      IN /\ (Cardinality(exceptions) = 1 =>
               SelectedException(source, t, 0) \in exceptions)
         /\ \A i \in 1..MaxEvents :
              (i <= Len(es) /\ es[i] \in exceptions) =>
                SelectedException(source, t, i) = es[i]

CaptureHasNoHistory ==
    \A a \in 0..MaxPos, b \in 0..MaxPos :
      ~SourceEventsBetween(CaptureSource, a, b).ok

EvidenceScoped ==
    \A source \in Sources, eSource \in Sources,
       t \in 0..MaxPos, ePos \in 0..MaxPos, value \in 0..MaxVal - 1 :
      LET result == ContextEvidenceAt(source, t, eSource, ePos, value)
      IN /\ (result.knowledge = "known" <=>
               PointQueryOk(source, t) /\ source = eSource /\ t = ePos)
         /\ (result.knowledge = "known" => result.value = value)

ExecutionInvariant ==
    /\ Len(EventIds) = MaxEvents
    /\ TimelineInvariant /\ KnowledgeSound /\ UnknownIsNotZero /\ PointIdentity
    /\ ExactEvents /\ ReturnedEventsComplete /\ EventOrder /\ PointQueryBounds
    /\ ThreadKnowledgeSound /\ SelectionSound /\ SelectionComplete
    /\ CaptureHasNoHistory /\ EvidenceScoped

ExecutionSpec == ExecutionInit /\ [][ExecutionNext]_executionVars
=============================================================================

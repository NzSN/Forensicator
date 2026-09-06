---- MODULE Timeline ----
EXTENDS Integers, Sequences, FiniteSets

\* Timeline -- recorded memory, events, and thread/call lifetime foundation.
\*
\* The append-only trace records initial payload memory, writes, and events;
\* frontier bounds its positions, while cursor selects an investigation point.
\* ValueAt supplies the recorded memory semantics. EventsAt is exact-position;
\* checked interval queries use (a,b], and thread lifetimes use [start,end).
\* Sequence indices identify event records and lifetime instances. They retain
\* recorded order without conflating potentially reused operating-system IDs.
\*
\* ExecutionState.tla layers source-scoped memory knowledge and thread execution
\* views on this foundation. A timeline point does not construct a Model.tla
\* capture aggregate. Model.tla describes decoded minidump facts separately.
\*
\* Abstraction limits: positions are ordered integers rather than packed TTD
\* Major:Minor keys; cells 1..MaxAddr stand for payload bytes. RecordStep emits
\* at most one write and one event at each new position. Query definitions
\* preserve log indices and support equal-position records, but this transition
\* generator does not explore multiple events at the same position. Lean tests
\* cover that case, module descriptors/reuse, and malformed source observations.
\*
\* ---- Model-checking bounds ----

MaxPos     == 4     \* positions 0..MaxPos
MaxAddr    == 2     \* memory cells 1..MaxAddr
MaxVal     == 2     \* cell values 0..MaxVal-1
MaxCalls   == 2
MaxThreads == 2
MaxEvents  == 3

EventKinds == {"EXCEPTION", "MODULE_LOAD", "MODULE_UNLOAD"}

\* ---- State ----

VARIABLES
    \* ── recorded trace (append-only — the immutable trace file) ──
    \* @type: Int -> Int;
    init_mem,     \* memory contents at position 0, chosen in Init
    \* @type: Seq(Int);
    wr_pos,       \* write log: position of the i-th write
    \* @type: Seq(Int);
    wr_addr,      \*          target cell of the i-th write
    \* @type: Seq(Int);
    wr_val,       \*          value stored by the i-th write
    \* @type: Seq(Int);
    ev_pos,       \* event log: position of the i-th event
    \* @type: Seq(Str);
    ev_kind,      \*           kind of the i-th event
    \* ── navigation ──
    \* @type: Int;
    frontier,     \* record head: positions 0..frontier exist in the trace
    \* @type: Int;
    cursor,       \* view position: the debugger's "now"
    \* ── intervals (TTD.Threads / TTD.Calls) ──
    \* @type: Seq([start: Int, end: Int]);
    threads,      \* lifetimes; end = -1 while the thread is alive
    \* @type: Seq([start: Int, end: Int, thr: Int]);
    calls         \* call spans; end = -1 while open, thr ∈ 1..Len(threads)

vars == <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
          frontier, cursor, threads, calls>>

\* ---- Recorded-memory and temporal queries ----

\* Index of the last write to cell a at or before position t, or 0.
\* WritesOrdered makes "last" the greatest log index.
\* (Constant quantifier domains with Len guards — Apalache-friendly.)
LastWriter(a, t) ==
    LET idxs == {i \in 1..MaxPos : i <= Len(wr_pos) /\ wr_addr[i] = a /\ wr_pos[i] <= t}
    IN IF idxs = {} THEN 0
       ELSE CHOOSE i \in idxs : \A j \in idxs : j <= i

\* Recorded payload byte at t. ExecutionState exposes only acquired evidence
\* about this value; this operator makes no claim about complete live mappings.
ValueAt(a, t) ==
    LET i == LastWriter(a, t)
    IN IF i = 0 THEN init_mem[a] ELSE wr_val[i]

\* Recorded writes to cell a in (t1,t2]. The current proxy write metadata
\* does not identify the responsible thread. Checked callers validate bounds.
WritesBetween(a, t1, t2) ==
    {i \in 1..MaxPos : i <= Len(wr_pos) /\ wr_addr[i] = a /\ t1 < wr_pos[i] /\ wr_pos[i] <= t2}

\* Exact-position events and historical exceptions are separate queries.
\* @type: Int => Set(Int);
EventsAt(t) ==
    {i \in 1..MaxEvents : i <= Len(ev_pos) /\ ev_pos[i] = t}

\* @type: Int => Set(Int);
ExceptionsAt(t) ==
    {i \in 1..MaxEvents : i <= Len(ev_pos) /\ ev_kind[i] = "EXCEPTION" /\ ev_pos[i] = t}

\* @type: Int => Set(Int);
ExceptionsThrough(t) ==
    {i \in 1..MaxEvents : i <= Len(ev_pos) /\ ev_kind[i] = "EXCEPTION" /\ ev_pos[i] <= t}

\* @type: (Int, Int) => Bool;
ValidInterval(a, b) == 0 <= a /\ a <= b /\ b <= frontier

\* Log indices retain identity and recorded order in the selected interval.
\* @type: (Int, Int) => Set(Int);
EventsIn(a, b) ==
    {i \in 1..MaxEvents : i <= Len(ev_pos) /\ a < ev_pos[i] /\ ev_pos[i] <= b}

\* Invalid bounds report an error, distinct from a valid empty interval.
\* @type: (Int, Int) => [ok: Bool, events: Set(Int)];
EventsBetweenChecked(a, b) ==
    [ok |-> ValidInterval(a, b),
     events |-> IF ValidInterval(a, b) THEN EventsIn(a, b) ELSE {}]

\* A cell models a nonempty address range; address 0 and MaxAddr+1 are invalid.
\* Byte-range overflow/empty-range checks are exercised by the Lean tests.
\* @type: (Int, Int, Int) => [ok: Bool, writes: Set(Int)];
WritesBetweenChecked(addr, a, b) ==
    [ok |-> ValidInterval(a, b) /\ addr \in 1..MaxAddr,
     writes |-> IF ValidInterval(a, b) /\ addr \in 1..MaxAddr
                THEN WritesBetween(addr, a, b) ELSE {}]

\* Half-open lifetimes; -1 denotes an open end. Empty lifetimes are not live.
\* @type: Int => Set(Int);
LiveThreads(t) ==
    {i \in 1..MaxThreads : i <= Len(threads)
       /\ threads[i].start <= t
       /\ (threads[i].end = -1 \/ t < threads[i].end)}

\* Indices of open calls on thread thr.
OpenCallIdx(thr) ==
    {i \in 1..MaxCalls : i <= Len(calls) /\ calls[i].thr = thr /\ calls[i].end = -1}

\* ---- Actions: recording (frontier only) ----

\* One recorded step. A step may store at most one cell and raise at most
\* one event; the trace grows strictly at the record head.
RecordStep ==
    /\ frontier < MaxPos
    /\ frontier' = frontier + 1
    /\ \/ UNCHANGED <<wr_pos, wr_addr, wr_val>>
       \/ \E a \in 1..MaxAddr, v \in 0..MaxVal - 1 :
            /\ wr_pos'  = Append(wr_pos, frontier + 1)
            /\ wr_addr' = Append(wr_addr, a)
            /\ wr_val'  = Append(wr_val, v)
    /\ \/ UNCHANGED <<ev_pos, ev_kind>>
       \/ \E k \in EventKinds :
            /\ Len(ev_pos) < MaxEvents
            /\ ev_pos'  = Append(ev_pos, frontier + 1)
            /\ ev_kind' = Append(ev_kind, k)
    /\ UNCHANGED <<init_mem, cursor, threads, calls>>

StartThread ==
    /\ Len(threads) < MaxThreads
    /\ threads' = Append(threads, [start |-> frontier, end |-> -1])
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, calls>>

\* A thread exits only with an empty call stack (TTD materializes no
\* frames for a dead thread).
EndThread(thr) ==
    /\ thr \in 1..Len(threads)
    /\ threads[thr].end = -1
    /\ OpenCallIdx(thr) = {}
    /\ threads' = [threads EXCEPT ![thr].end = frontier]
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, calls>>

OpenCall(thr) ==
    /\ thr \in 1..Len(threads)
    /\ threads[thr].end = -1
    /\ Len(calls) < MaxCalls
    /\ calls' = Append(calls, [start |-> frontier, end |-> -1, thr |-> thr])
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads>>

\* Stack discipline: only the most recent open call on a thread can close.
CloseCall(thr) ==
    /\ thr \in 1..Len(threads)
    /\ LET open == OpenCallIdx(thr)
       IN /\ open # {}
          /\ LET i == CHOOSE k \in open : \A j \in open : calls[j].start <= calls[k].start
             IN calls' = [calls EXCEPT ![i].end = frontier]
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads>>

\* ---- Actions: navigation (cursor only, trace untouched) ----

Advance ==
    /\ cursor < frontier
    /\ cursor' = cursor + 1
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, threads, calls>>

Retreat ==
    /\ cursor > 0
    /\ cursor' = cursor - 1
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, threads, calls>>

\* !tt <pos>: direct jump anywhere inside the recorded range.
Seek(p) ==
    /\ p \in 0..frontier
    /\ cursor' = p
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, threads, calls>>

\* ---- Invariants ----

\* The trace is append-only and position-ordered; nothing is recorded
\* beyond the head.
TraceOrdered ==
    /\ Len(wr_pos) = Len(wr_addr) /\ Len(wr_addr) = Len(wr_val)
    /\ Len(wr_pos) <= MaxPos
    /\ \A i \in 1..MaxPos :
         i <= Len(wr_pos) =>
           /\ wr_pos[i] <= frontier
           /\ wr_addr[i] \in 1..MaxAddr
           /\ wr_val[i] \in 0..MaxVal - 1
           /\ i > 1 => wr_pos[i - 1] <= wr_pos[i]
    /\ Len(ev_pos) = Len(ev_kind)
    /\ Len(ev_pos) <= MaxEvents
    /\ \A i \in 1..MaxEvents :
         i <= Len(ev_pos) =>
           /\ ev_pos[i] <= frontier
           /\ ev_kind[i] \in EventKinds
           /\ i > 1 => ev_pos[i - 1] <= ev_pos[i]

\* The cursor never leaves the recorded trace: no travel to positions
\* that have not been recorded.
CursorBounded ==
    /\ 0 <= cursor /\ cursor <= frontier /\ frontier <= MaxPos

\* The recorded-memory view agrees with the last covering payload write,
\* falling back to the initial value only when there is no covering write.
\* This is a byte-value property, not complete execution-state recovery.
MemoryViewConsistent ==
    \A a \in 1..MaxAddr :
      \A t \in 0..MaxPos :
        t <= frontier =>
          /\ LastWriter(a, t) = 0  => ValueAt(a, t) = init_mem[a]
          /\ LastWriter(a, t) # 0  => ValueAt(a, t) = wr_val[LastWriter(a, t)]

\* Thread lifetimes lie inside the recorded range.
ThreadIntervals ==
    \A i \in 1..MaxThreads :
      i <= Len(threads) =>
        /\ threads[i].start <= frontier
        /\ threads[i].end # -1 =>
             /\ threads[i].start <= threads[i].end
             /\ threads[i].end <= frontier

\* Call spans on one thread are disjoint or nested — never crossing.
CallNesting ==
    \A i \in 1..MaxCalls :
      \A j \in 1..MaxCalls :
        (i <= Len(calls) /\ j <= Len(calls)
         /\ i # j /\ calls[i].thr = calls[j].thr
         /\ calls[i].end # -1 /\ calls[j].end # -1) =>
          \/ calls[i].end <= calls[j].start
          \/ calls[j].end <= calls[i].start
          \/ calls[i].start <= calls[j].start /\ calls[j].end <= calls[i].end
          \/ calls[j].start <= calls[i].start /\ calls[i].end <= calls[j].end

\* Calls live on valid threads, inside the trace and inside their
\* thread's lifetime.
CallsWithinThreads ==
    \A i \in 1..MaxCalls :
      i <= Len(calls) =>
        /\ calls[i].thr \in 1..Len(threads)
        /\ calls[i].start <= frontier
        /\ threads[calls[i].thr].start <= calls[i].start
        /\ calls[i].end # -1 =>
             /\ calls[i].end <= frontier
             /\ threads[calls[i].thr].end = -1
                  \/ calls[i].end <= threads[calls[i].thr].end

\* Exact exceptions cannot persist at later positions merely because no newer
\* exception exists. Historical queries retain those records explicitly.
ExactEventQueries ==
    \A t \in 0..MaxPos, i \in 1..MaxEvents :
      (t <= frontier /\ i <= Len(ev_pos)) =>
        /\ (i \in EventsAt(t) <=> ev_pos[i] = t)
        /\ (i \in ExceptionsAt(t) <=>
              ev_pos[i] = t /\ ev_kind[i] = "EXCEPTION")
        /\ (i \in ExceptionsThrough(t) <=>
              ev_pos[i] <= t /\ ev_kind[i] = "EXCEPTION")
        /\ (i \in ExceptionsAt(t) => i \in ExceptionsThrough(t))

\* Constant domains include both sides of the valid temporal/address domain,
\* so this checks rejection as well as valid and equal-endpoint intervals.
QueryBounds ==
    \A a \in (-1)..(MaxPos + 1), b \in (-1)..(MaxPos + 1) :
      /\ (EventsBetweenChecked(a, b).ok <=> ValidInterval(a, b))
      /\ (~ValidInterval(a, b) => EventsBetweenChecked(a, b).events = {})
      /\ \A addr \in 0..(MaxAddr + 1) :
           /\ (WritesBetweenChecked(addr, a, b).ok <=>
                 ValidInterval(a, b) /\ addr \in 1..MaxAddr)
           /\ (~WritesBetweenChecked(addr, a, b).ok =>
                 WritesBetweenChecked(addr, a, b).writes = {})

QueryIntervalEndpoints ==
    /\ \A t \in 0..MaxPos : t <= frontier =>
         /\ EventsBetweenChecked(t, t).ok
         /\ EventsBetweenChecked(t, t).events = {}
         /\ \A addr \in 1..MaxAddr :
              /\ WritesBetweenChecked(addr, t, t).ok
              /\ WritesBetweenChecked(addr, t, t).writes = {}
    /\ \A a \in 0..MaxPos, b \in 0..MaxPos : ValidInterval(a, b) =>
         /\ EventsBetweenChecked(a, b).events \cap EventsAt(a) = {}
         /\ (a < b => EventsAt(b) \subseteq EventsBetweenChecked(a, b).events)

ThreadViewEndpoints ==
    \A i \in 1..MaxThreads : i <= Len(threads) =>
      /\ (i \in LiveThreads(threads[i].start) <=>
            threads[i].end = -1 \/ threads[i].start < threads[i].end)
      /\ (threads[i].end # -1 => i \notin LiveThreads(threads[i].end))
      /\ \A t \in 0..MaxPos : t <= frontier =>
           (i \in LiveThreads(t) <=>
             threads[i].start <= t /\ (threads[i].end = -1 \/ t < threads[i].end))

TimelineInvariant ==
    /\ TraceOrdered
    /\ CursorBounded
    /\ MemoryViewConsistent
    /\ ThreadIntervals
    /\ CallNesting
    /\ CallsWithinThreads
    /\ ExactEventQueries
    /\ QueryBounds
    /\ QueryIntervalEndpoints
    /\ ThreadViewEndpoints

\* ---- Specification ----

Init ==
    /\ init_mem \in [1..MaxAddr -> 0..MaxVal - 1]
    /\ wr_pos = <<>> /\ wr_addr = <<>> /\ wr_val = <<>>
    /\ ev_pos = <<>> /\ ev_kind = <<>>
    /\ frontier = 0
    /\ cursor = 0
    /\ threads = <<>>
    /\ calls = <<>>

Next ==
    \/ RecordStep
    \/ StartThread
    \/ \E t \in 1..MaxThreads : EndThread(t)
    \/ \E t \in 1..MaxThreads : OpenCall(t)
    \/ \E t \in 1..MaxThreads : CloseCall(t)
    \/ Advance
    \/ Retreat
    \/ \E p \in 0..MaxPos : Seek(p)

Spec == Init /\ [][Next]_vars

=============================================================================

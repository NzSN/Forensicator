---- MODULE Timeline ----
EXTENDS Integers, Sequences, FiniteSets

\* ── Timeline — TTD-style time-travel extension of the time-point specs ──
\*
\* The existing specs (Model, AddressSpace, Arch, CrashCause) describe one
\* frozen snapshot of the target process. This module adds the time-line
\* dimension they can be re-indexed by, modelling the public structure of a
\* time-travel trace (WinDbg TTD ".run" data model):
\*
\*   * recorded trace   — initial memory + append-only write log
\*                        (position, address, value) + event log; the
\*                        abstract trace file. Grows only at the frontier.
\*   * frontier/cursor  — record head vs. view position. Navigation
\*                        (Advance/Retreat/Seek) is !tt / t- / g-.
\*   * intervals        — thread lifetimes and call spans [start, end]:
\*                        the TTD.Threads / TTD.Calls objects.
\*   * snapshot views   — ValueAt(a, t) reconstructs memory at any position
\*                        from the delta chain: timeline[t] is a *view*,
\*                        not N stored copies.
\*
\* TTD positions (Major:Minor pairs) are abstracted to a single monotone
\* Int: only the total order matters for these properties.
\*
\* Memory cells are 1..MaxAddr so they double as Seq indices.

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

\* ---- Derived views (what a position materializes to) ----

\* Index of the last write to cell a at or before position t, or 0.
\* WritesOrdered makes "last" the greatest log index.
\* (Constant quantifier domains with Len guards — Apalache-friendly.)
LastWriter(a, t) ==
    LET idxs == {i \in 1..MaxPos : i <= Len(wr_pos) /\ wr_addr[i] = a /\ wr_pos[i] <= t}
    IN IF idxs = {} THEN 0
       ELSE CHOOSE i \in idxs : \A j \in idxs : j <= i

\* Memory contents at position t — the snapshot view. A time-point spec
\* (Model/AddressSpace/Arch) re-indexed by t would read through this.
ValueAt(a, t) ==
    LET i == LastWriter(a, t)
    IN IF i = 0 THEN init_mem[a] ELSE wr_val[i]

\* All writes to cell a in (t1, t2]: "who wrote this VA between t1 and t2"
\* (TTD.Memory(addr, addr+1, "w")).
WritesBetween(a, t1, t2) ==
    {i \in 1..MaxPos : i <= Len(wr_pos) /\ wr_addr[i] = a /\ t1 < wr_pos[i] /\ wr_pos[i] <= t2}

\* Exception events at or before t — CrashCause's input, time-indexed.
ExceptionsAt(t) ==
    {i \in 1..MaxEvents : i <= Len(ev_pos) /\ ev_kind[i] = "EXCEPTION" /\ ev_pos[i] <= t}

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

\* Snapshot views are faithful: an unwritten cell shows its initial
\* contents at every position; a written cell shows its last write.
\* This is what licenses treating timeline[t] as a time-point snapshot.
SnapshotConsistent ==
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

TimelineInvariant ==
    /\ TraceOrdered
    /\ CursorBounded
    /\ SnapshotConsistent
    /\ ThreadIntervals
    /\ CallNesting
    /\ CallsWithinThreads

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

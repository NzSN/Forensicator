---- MODULE ReplayApi ----
EXTENDS Timeline

\* ── ReplayApi — the public TTD Replay API as a formal engine surface ─────
\*
\* Formal counterpart of the Microsoft.TimeTravelDebugging.Apis surface
\* (TTD/IReplayEngine.h, NuGet) exercised by microsoft/WinDbg-Samples
\* TTD/ReplayApi (TraceDebugger/TraceAnalysis + inc/ReplayHelpers.h) and
\* summarized in docs/trace/2026-08-12-lazy-trace-proxy-design.md §"P0′".
\*
\* Timeline.tla models the recorded trace (append-only write log, frontier).
\* This module models what the *Replay API* exposes over it:
\*
\*   * engine view (IReplayEngineView) — lifetime [0, frontier], threads,
\*     modules, events: read-only projections of Timeline's logs, so there
\*     is nothing to specify beyond TimelineInvariant. Omitted.
\*   * cursors (ICursorView) — INDEPENDENT position holders: "many cursors
\*     can be created for a single engine object" (P0′), unlike the dbgeng
\*     channel's one global `!tt` position (cf. JigSawSpawner). Per cursor:
\*     position, previous position (GetPreviousPosition), last stop reason.
\*   * memory queries (QueryMemoryBuffer / QueryMemoryRange) with
\*     QueryMemoryPolicy — ThreadLocal / GloballyConservative answer
\*     exactly at the cursor; GloballyAggressive / InFragmentAggressive
\*     may return the value at ANOTHER position, but always with honest
\*     provenance (the returned position's truth). QueryMemoryRange
\*     additionally returns the position the range was recorded at — the
\*     jigsaw-validity hook (RangeFresh below).
\*   * memory watchpoints (AddMemoryWatchpoint + ReplayForward/Backward) —
\*     replay runs to the destination, to a boundary, or stops at the
\*     FIRST (forward) / LAST (backward) watched write inside the bounds.
\*
\* Abstractions (all deliberate):
\*   * Positions collapse TTD's (Sequence, Steps) pair to Timeline's single
\*     monotone Int (only the total order matters). Lifetime.Min = 0.
\*   * Watchpoint access masks R/W/E/C collapse to W: the trace model has
\*     no read/exec logs (Timeline records writes only).
\*   * Replay is one atomic step to its stop position; InterruptReplay and
\*     the progress/thread-continuity callbacks are UI-level concerns —
\*     every observable outcome of an interrupted replay equals a replay
\*     stopped at an intermediate destination, already covered by the
\*     nondeterministic destination choice.
\*   * GetCrossPlatformContext (per-position register file, P0′) is out of
\*     scope: the trace model has no register contents.
\*   * QueryMemoryBufferWithRanges is the per-cell loop of QueryMemoryRange
\*     — no new semantics.
\*
\* Commit truth is needed because memory queries FAIL on uncommitted cells
\* (the API's read failure is a fact, cf. JigSawSpawner's D3): a commit log
\* recorded at the moving frontier, same shape as JigSawSpawner's.

\* ---- Model-checking bounds (Timeline's, reused) ----
\* MaxPos, MaxAddr, MaxVal, MaxCalls, MaxThreads, MaxEvents come from
\* Timeline. Commit changes are recorded steps, so at most MaxPos exist.

MaxCursors == 2
MaxWatch   == 2

Policies == {"THREAD_LOCAL", "CONSERVATIVE", "AGGRESSIVE", "IN_FRAGMENT"}
StopReasons == {"NONE", "POSITION", "PROCESS", "MEMORY_WATCHPOINT", "INTERRUPTED"}

\* ---- State ----

VARIABLES
    \* ── commit truth (engine side; append-only, frontier-recorded) ──
    \* @type: Int -> Bool;
    init_committed, \* cells committed at position 0, chosen in RInit
    \* @type: Seq(Int);
    cm_pos,         \* commit-change log: position of the i-th change
    \* @type: Seq(Int);
    cm_page,        \*                 cell of the i-th change
    \* @type: Seq(Bool);
    cm_on,          \*                 committed flag after the i-th change
    \* ── cursors (ICursorView; independent objects) ──
    \* @type: Int -> Bool;
    cur_on,         \* cursor c has been created
    \* @type: Int -> Int;
    cur_pos,        \* cursor c's position (GetPosition)
    \* @type: Int -> Int;
    cur_prev,       \* cursor c's previous position (GetPreviousPosition)
    \* @type: Int -> Str;
    cur_stop,       \* cursor c's last replay stop reason
    \* ── memory watchpoints (AddMemoryWatchpoint) ──
    \* @type: Int -> Bool;
    wp_on,
    \* @type: Int -> Int;
    wp_addr,        \* watched cell (one cell per watchpoint slot)
    \* ── last memory query (for the honesty invariants) ──
    \* @type: Bool;
    q_ok,           \* the query succeeded (cell committed at the answer's position)
    \* @type: Int;
    q_addr,         \* queried cell
    \* @type: Int;
    q_val,          \* returned value
    \* @type: Int;
    q_pos,          \* returned provenance position
    \* @type: Int;
    q_cursor,       \* cursor position the query was issued at
    \* @type: Str;
    q_pol           \* policy used ("RANGE" for QueryMemoryRange)

rvars == <<init_committed, cm_pos, cm_page, cm_on,
           cur_on, cur_pos, cur_prev, cur_stop, wp_on, wp_addr,
           q_ok, q_addr, q_val, q_pos, q_cursor, q_pol>>

allVars == <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
              frontier, cursor, threads, calls,
              init_committed, cm_pos, cm_page, cm_on,
              cur_on, cur_pos, cur_prev, cur_stop, wp_on, wp_addr,
              q_ok, q_addr, q_val, q_pos, q_cursor, q_pol>>

\* ---- Commit truth (what the engine knows; as JigSawSpawner) ----

\* Index of the last commit change to cell p at or before t, or 0.
\* @type: (Int, Int) => Int;
LastCmChange(p, t) ==
    LET idxs == {i \in 1..MaxPos : i <= Len(cm_pos) /\ cm_page[i] = p /\ cm_pos[i] <= t}
    IN IF idxs = {} THEN 0
       ELSE CHOOSE i \in idxs : \A j \in idxs : j <= i

\* Is cell p committed at position t (engine truth).
\* @type: (Int, Int) => Bool;
CmAt(p, t) ==
    LET i == LastCmChange(p, t)
    IN IF i = 0 THEN init_committed[p] ELSE cm_on[i]

\* Position of the last commit-ON to cell p at or before t, or 0.
\* @type: (Int, Int) => Int;
LastCommitOnPos(p, t) ==
    LET idxs == {i \in 1..MaxPos : i <= Len(cm_pos) /\ cm_page[i] = p
                                   /\ cm_on[i] /\ cm_pos[i] <= t}
    IN IF idxs = {} THEN 0
       ELSE cm_pos[CHOOSE i \in idxs : \A j \in idxs : j <= i]

\* The position cell a's current-at-t content was recorded at: the later
\* of its last write and its last commit-ON (0 = the initial memory). A
\* commit re-captures content (first materialization; in this model
\* commits do not change content — the NoRecommitWithin assumption of
\* JigSawSpawner). This is the provenance QueryMemoryRange returns.
\* @type: (Int, Int) => Int;
RecordedAt(a, t) ==
    LET i  == LastWriter(a, t)
        wp == IF i = 0 THEN 0 ELSE wr_pos[i]
        cp == LastCommitOnPos(a, t)
    IN IF wp >= cp THEN wp ELSE cp

\* Cells currently watched.
WatchedCells == {a \in 1..MaxAddr : \E w \in 1..MaxWatch : wp_on[w] /\ wp_addr[w] = a}

\* Positions of watched writes in (lo, hi].
\* @type: (Int, Int) => Set(Int);
WatchHitsFwd(c, dest) ==
    {p \in 0..MaxPos :
      \E i \in 1..MaxPos :
        i <= Len(wr_pos) /\ wr_pos[i] = p /\ wr_addr[i] \in WatchedCells
          /\ cur_pos[c] < p /\ p <= dest}

\* Positions of watched writes in [lo, hi).
\* @type: (Int, Int) => Set(Int);
WatchHitsBwd(c, dest) ==
    {p \in 0..MaxPos :
      \E i \in 1..MaxPos :
        i <= Len(wr_pos) /\ wr_pos[i] = p /\ wr_addr[i] \in WatchedCells
          /\ dest <= p /\ p < cur_pos[c]}

\* ---- Actions: recording (Timeline's + commit changes; API untouched) ----

\* Timeline's recording/navigation, gated to engine-consistent traces: a
\* write is recorded only on a cell committed at the pre-state (the engine
\* cannot execute a store on an uncommitted page). Navigation and
\* non-write steps are unaffected.
RecordOrNav ==
    /\ Next
    /\ Len(wr_pos') > Len(wr_pos) =>
         CmAt(wr_addr'[Len(wr_pos')], frontier)
    /\ UNCHANGED rvars

\* A commit change is a recorded step at the moving head (no cell write).
CommitStep ==
    /\ frontier < MaxPos
    /\ \E p \in 1..MaxAddr, on \in BOOLEAN :
         /\ cm_pos'  = Append(cm_pos, frontier + 1)
         /\ cm_page' = Append(cm_page, p)
         /\ cm_on'   = Append(cm_on, on)
    /\ frontier' = frontier + 1
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   cursor, threads, calls,
                   init_committed,
                   cur_on, cur_pos, cur_prev, cur_stop, wp_on, wp_addr,
                   q_ok, q_addr, q_val, q_pos, q_cursor, q_pol>>

\* ---- Actions: cursor lifecycle ----

CreateCursor(c) ==
    /\ c \in 1..MaxCursors
    /\ ~cur_on[c]
    /\ cur_on'   = [cur_on EXCEPT ![c] = TRUE]
    /\ cur_pos'  = [cur_pos EXCEPT ![c] = 0]
    /\ cur_prev' = [cur_prev EXCEPT ![c] = 0]
    /\ cur_stop' = [cur_stop EXCEPT ![c] = "NONE"]
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on,
                   wp_on, wp_addr,
                   q_ok, q_addr, q_val, q_pos, q_cursor, q_pol>>

\* SetPosition: a direct jump anywhere inside the recorded range.
SetPos(c, t) ==
    /\ c \in 1..MaxCursors
    /\ cur_on[c]
    /\ t \in 0..MaxPos /\ t <= frontier
    /\ cur_pos'  = [cur_pos EXCEPT ![c] = t]
    /\ cur_prev' = [cur_prev EXCEPT ![c] = cur_pos[c]]
    /\ cur_stop' = [cur_stop EXCEPT ![c] = "NONE"]
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on,
                   cur_on, wp_on, wp_addr,
                   q_ok, q_addr, q_val, q_pos, q_cursor, q_pol>>

\* ---- Actions: memory queries (QueryMemoryBuffer/Range + policies) ----

\* ThreadLocal / GloballyConservative: the answer is exact at the cursor —
\* the engine does not search. Fails iff the cell is uncommitted there.
QueryExact(c, a, pol) ==
    /\ c \in 1..MaxCursors /\ a \in 1..MaxAddr
    /\ cur_on[c] /\ pol \in {"THREAD_LOCAL", "CONSERVATIVE"}
    /\ IF CmAt(a, cur_pos[c])
       THEN /\ q_ok'   = TRUE
            /\ q_val'  = ValueAt(a, cur_pos[c])
            /\ q_pos'  = cur_pos[c]
       ELSE /\ q_ok' = FALSE
            /\ UNCHANGED <<q_val, q_pos>>
    /\ q_addr' = a /\ q_cursor' = cur_pos[c] /\ q_pol' = pol
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on,
                   cur_on, cur_pos, cur_prev, cur_stop, wp_on, wp_addr>>

\* GloballyAggressive / InFragmentAggressive: the engine may return the
\* value from ANOTHER position (searching past/future) — but the returned
\* provenance position is honest: the value is exactly the trace truth
\* there, and the cell is committed there.
QuerySearch(c, a, pol) ==
    /\ c \in 1..MaxCursors /\ a \in 1..MaxAddr
    /\ cur_on[c] /\ pol \in {"AGGRESSIVE", "IN_FRAGMENT"}
    /\ LET committed == {s \in 0..MaxPos : s <= frontier /\ CmAt(a, s)}
       IN \/ /\ committed # {}
             /\ \E s \in committed :
                  /\ q_ok'  = TRUE
                  /\ q_val' = ValueAt(a, s)
                  /\ q_pos' = s
          \/ /\ committed = {}
             /\ q_ok' = FALSE
             /\ UNCHANGED <<q_val, q_pos>>
    /\ q_addr' = a /\ q_cursor' = cur_pos[c] /\ q_pol' = pol
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on,
                   cur_on, cur_pos, cur_prev, cur_stop, wp_on, wp_addr>>

\* QueryMemoryRange: the contiguous recorded range containing the address
\* plus the position it was recorded at (modeled per cell). Exact at the
\* cursor; provenance = RecordedAt.
QueryRangeMem(c, a) ==
    /\ c \in 1..MaxCursors /\ a \in 1..MaxAddr
    /\ cur_on[c]
    /\ IF CmAt(a, cur_pos[c])
       THEN /\ q_ok'   = TRUE
            /\ q_val'  = ValueAt(a, cur_pos[c])
            /\ q_pos'  = RecordedAt(a, cur_pos[c])
       ELSE /\ q_ok' = FALSE
            /\ UNCHANGED <<q_val, q_pos>>
    /\ q_addr' = a /\ q_cursor' = cur_pos[c] /\ q_pol' = "RANGE"
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on,
                   cur_on, cur_pos, cur_prev, cur_stop, wp_on, wp_addr>>

\* ---- Actions: watchpoints + replay scan ----

AddWatchpoint(w, a) ==
    /\ w \in 1..MaxWatch /\ a \in 1..MaxAddr
    /\ wp_on'   = [wp_on EXCEPT ![w] = TRUE]
    /\ wp_addr' = [wp_addr EXCEPT ![w] = a]
    \* stop reasons are meaningful only against a fixed watchpoint set
    /\ cur_stop' = [c \in 1..MaxCursors |-> "NONE"]
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on,
                   cur_on, cur_pos, cur_prev,
                   q_ok, q_addr, q_val, q_pos, q_cursor, q_pol>>

RemoveWatchpoint(w) ==
    /\ w \in 1..MaxWatch
    /\ wp_on' = [wp_on EXCEPT ![w] = FALSE]
    /\ cur_stop' = [c \in 1..MaxCursors |-> "NONE"]
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on,
                   cur_on, cur_pos, cur_prev, wp_addr,
                   q_ok, q_addr, q_val, q_pos, q_cursor, q_pol>>

\* ReplayForward(dest): run forward from the cursor; stop at the first
\* watched write in (pos, dest], else at dest. "PROCESS" at the frontier
\* (end of the recorded lifetime), "POSITION" otherwise.
ReplayFwd(c, dest) ==
    /\ c \in 1..MaxCursors
    /\ cur_on[c]
    /\ dest \in 0..MaxPos /\ cur_pos[c] < dest /\ dest <= frontier
    /\ LET hits == WatchHitsFwd(c, dest)
           firstHit == CHOOSE p \in hits : \A q \in hits : p <= q
       IN IF hits # {} /\ firstHit <= dest
          THEN /\ cur_pos'  = [cur_pos EXCEPT ![c] = firstHit]
               /\ cur_stop' = [cur_stop EXCEPT ![c] = "MEMORY_WATCHPOINT"]
          ELSE /\ cur_pos'  = [cur_pos EXCEPT ![c] = dest]
               /\ cur_stop' = [cur_stop EXCEPT ![c] =
                    IF dest = frontier THEN "PROCESS" ELSE "POSITION"]
    /\ cur_prev' = [cur_prev EXCEPT ![c] = cur_pos[c]]
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on,
                   cur_on, wp_on, wp_addr,
                   q_ok, q_addr, q_val, q_pos, q_cursor, q_pol>>

\* ReplayBackward(dest): run backward; stop at the last watched write in
\* [dest, pos), else at dest. "PROCESS" at position 0 (lifetime start).
ReplayBwd(c, dest) ==
    /\ c \in 1..MaxCursors
    /\ cur_on[c]
    /\ dest \in 0..MaxPos /\ dest < cur_pos[c]
    /\ LET hits == WatchHitsBwd(c, dest)
           lastHit == CHOOSE p \in hits : \A q \in hits : q <= p
       IN IF hits # {} /\ lastHit >= dest
          THEN /\ cur_pos'  = [cur_pos EXCEPT ![c] = lastHit]
               /\ cur_stop' = [cur_stop EXCEPT ![c] = "MEMORY_WATCHPOINT"]
          ELSE /\ cur_pos'  = [cur_pos EXCEPT ![c] = dest]
               /\ cur_stop' = [cur_stop EXCEPT ![c] =
                    IF dest = 0 THEN "PROCESS" ELSE "POSITION"]
    /\ cur_prev' = [cur_prev EXCEPT ![c] = cur_pos[c]]
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on,
                   cur_on, wp_on, wp_addr,
                   q_ok, q_addr, q_val, q_pos, q_cursor, q_pol>>

\* ---- Invariants ----

ReplayTypes ==
    /\ \A c \in 1..MaxCursors :
         /\ 0 <= cur_pos[c] /\ cur_pos[c] <= MaxPos
         /\ 0 <= cur_prev[c] /\ cur_prev[c] <= MaxPos
         /\ cur_stop[c] \in StopReasons
    /\ \A w \in 1..MaxWatch : wp_on[w] => wp_addr[w] \in 1..MaxAddr
    /\ q_pol \in Policies \cup {"RANGE", "NONE"}
    /\ 0 <= q_pos /\ q_pos <= MaxPos
    /\ Len(cm_pos) = Len(cm_page) /\ Len(cm_page) = Len(cm_on)
    /\ \A i \in 1..MaxPos :
         i <= Len(cm_pos) =>
           /\ cm_pos[i] <= frontier
           /\ cm_page[i] \in 1..MaxAddr
           /\ i > 1 => cm_pos[i - 1] <= cm_pos[i]

\* API cursors never leave the recorded trace.
ReplayCursorBounded ==
    \A c \in 1..MaxCursors :
      cur_on[c] => /\ cur_pos[c] <= frontier
                   /\ cur_prev[c] <= frontier

\* The money property for memory queries: whatever the policy, a
\* successful answer carries honest provenance — the returned value is
\* exactly the trace truth at the returned position, and the cell is
\* committed there.
QueryHonest ==
    q_ok =>
      /\ q_pos <= frontier
      /\ q_val = ValueAt(q_addr, q_pos)
      /\ CmAt(q_addr, q_pos)

\* ThreadLocal / GloballyConservative answers are exact: provenance is
\* the position the query was issued at.
ExactAtCursor ==
    (q_ok /\ q_pol \in {"THREAD_LOCAL", "CONSERVATIVE"}) => q_pos = q_cursor

\* The jigsaw-validity hook (QueryMemoryRange): the returned content was
\* recorded at q_pos and no write to the cell lands in (q_pos, q_cursor] —
\* so the range truthfully serves every position in between (the engine
\* side of JigSawSpawner's CacheSound).
RangeFresh ==
    (q_ok /\ q_pol = "RANGE") =>
      (\A i \in 1..MaxPos :
        (i <= Len(wr_pos) /\ wr_addr[i] = q_addr) =>
          ~(q_pos < wr_pos[i] /\ wr_pos[i] <= q_cursor))

\* Watchpoint scans stop at the FIRST hit in the replay direction:
\* a MEMORY_WATCHPOINT stop means a watched write happens exactly at the
\* stop position, and none lies strictly between the previous position
\* and it.
WatchStopsFirst ==
    \A c \in 1..MaxCursors :
      cur_stop[c] = "MEMORY_WATCHPOINT" =>
        /\ \E i \in 1..MaxPos :
             i <= Len(wr_pos) /\ wr_pos[i] = cur_pos[c]
               /\ wr_addr[i] \in WatchedCells
        /\ (cur_prev[c] < cur_pos[c]) =>
             (\A i \in 1..MaxPos :
               (i <= Len(wr_pos) /\ wr_addr[i] \in WatchedCells) =>
                 ~(cur_prev[c] < wr_pos[i] /\ wr_pos[i] < cur_pos[c]))
        /\ (cur_pos[c] < cur_prev[c]) =>
             (\A i \in 1..MaxPos :
               (i <= Len(wr_pos) /\ wr_addr[i] \in WatchedCells) =>
                 ~(cur_pos[c] < wr_pos[i] /\ wr_pos[i] < cur_prev[c]))

ReplayApiInvariant ==
    /\ ReplayTypes
    /\ ReplayCursorBounded
    /\ QueryHonest
    /\ ExactAtCursor
    /\ RangeFresh
    /\ WatchStopsFirst

\* ---- Specification ----

RInit ==
    /\ Init
    /\ init_committed \in [1..MaxAddr -> BOOLEAN]
    /\ cm_pos = <<>> /\ cm_page = <<>> /\ cm_on = <<>>
    /\ cur_on   = [c \in 1..MaxCursors |-> FALSE]
    /\ cur_pos  = [c \in 1..MaxCursors |-> 0]
    /\ cur_prev = [c \in 1..MaxCursors |-> 0]
    /\ cur_stop = [c \in 1..MaxCursors |-> "NONE"]
    /\ wp_on    = [w \in 1..MaxWatch |-> FALSE]
    /\ wp_addr  = [w \in 1..MaxWatch |-> 1]
    /\ q_ok = FALSE
    /\ q_addr = 1 /\ q_val = 0 /\ q_pos = 0 /\ q_cursor = 0
    /\ q_pol = "NONE"

RNext ==
    \/ RecordOrNav
    \/ CommitStep
    \/ \E c \in 1..MaxCursors : CreateCursor(c)
    \/ \E c \in 1..MaxCursors, t \in 0..MaxPos : SetPos(c, t)
    \/ \E c \in 1..MaxCursors, a \in 1..MaxAddr, p \in Policies :
         QueryExact(c, a, p)
    \/ \E c \in 1..MaxCursors, a \in 1..MaxAddr, p \in Policies :
         QuerySearch(c, a, p)
    \/ \E c \in 1..MaxCursors, a \in 1..MaxAddr : QueryRangeMem(c, a)
    \/ \E w \in 1..MaxWatch, a \in 1..MaxAddr : AddWatchpoint(w, a)
    \/ \E w \in 1..MaxWatch : RemoveWatchpoint(w)
    \/ \E c \in 1..MaxCursors, d \in 0..MaxPos : ReplayFwd(c, d)
    \/ \E c \in 1..MaxCursors, d \in 0..MaxPos : ReplayBwd(c, d)

RSpec == RInit /\ [][RNext]_allVars

=============================================================================

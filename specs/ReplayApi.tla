---- MODULE ReplayApi ----
EXTENDS Timeline

\* ── ReplayApi — the public TTD Replay API as a formal engine surface ─────
\*
\* Formal counterpart of the Microsoft.TimeTravelDebugging.Apis surface,
\* pinned to the v0.9.5 NuGet header (sdk/include/TTD/IReplayEngine.h in
\* Microsoft.TimeTravelDebugging.Apis.0.9.5.nupkg — the latest published
\* version; verified symbol-for-symbol against the package itself). The
\* WinDbg-Samples TTD/docs tree is a secondary cross-check only — its
\* divergences from the header are listed below.
\* Timeline.tla models the recorded trace (append-only write log, frontier).
\* This module models what the *Replay API* exposes over it:
\*
\*   * engine view (IReplayEngineView) — lifetime [0, frontier], threads,
\*     modules, events: read-only projections of Timeline's logs; nothing to
\*     specify beyond TimelineInvariant. Omitted.
\*   * cursors (ICursorView) — INDEPENDENT position holders ("many cursors
\*     can be created for a single engine object", unlike the dbgeng
\*     channel's one global `!tt` position, cf. JigSawSpawner). Per cursor:
\*     position, previous position, event mask (v0.9.5 EventMask flags),
\*     last stop reason.
\*   * memory queries (QueryMemoryBuffer / QueryMemoryRange) with
\*     QueryMemoryPolicy (v0.9.5: Default, ThreadLocal, GloballyConservative,
\*     GloballyAggressive, InFragmentAggressive). Only GloballyConservative
\*     is exact at the cursor; ThreadLocal CONCENTRATES on the current
\*     position/thread but may return past/future memory observed by the
\*     current thread (header comment) — it is a bounded search, modeled
\*     with the search family. Aggressive variants search anywhere.
\*   * replay scans (ReplayForward/ReplayBackward(limit, stepCount)) —
\*     stop at the FIRST (forward) / LAST (backward) of: a masked
\*     memory-watchpoint write, a masked position-watchpoint range entry,
\*     a masked exception (all three gated on the cursor's EventMask),
\*     the destination ("Position"), or the lifetime boundary ("Process").
\*
\* Engine position convention (v0.9.5 callback docs: "the current position
\* points to the call or ret instruction"): positions are PRE-instruction
\* states — a write at p materializes at engine position p+1 (the proxy
\* design's Implementation-note off-by-one, here made explicit as
\* EngineValueAt; the jigsaw client's fetch-at-(t+1) clamp implements it).
\*
\* Abstractions and known simplifications (deliberate):
\*   * Positions collapse TTD's (Sequence, Steps) pair to Timeline's single
\*     monotone Int (only the total order matters). Lifetime.Min = 0.
\*   * Watchpoint access masks R/W/E/C collapse to W: the trace model has
\*     no read/exec logs (Timeline records writes only).
\*   * Replay is one atomic step to its stop position; InterruptReplay,
\*     StepCount-bounded replay, progress/continuity/fallback/call-return/
\*     indirect-jump callbacks are UI/scheduler-level concerns — every
\*     observable outcome equals a replay stopped at an intermediate
\*     destination, covered by the nondeterministic destination choice.
\*     EventType Gap/Thread/StepCount/Interrupted/Error are therefore
\*     unmodeled stop reasons (gaps: the trace here is fully recorded).
\*   * Partial reads: QueryMemoryBuffer "fills as much of the buffer as
\*     possible" — with one-cell queries, reads are binary (ok/fail). Range
\*     composition is out of scope (QueryMemoryBufferWithRanges is the
\*     per-cell loop of QueryMemoryRange).
\*   * Provenance observability: only MemoryRange/WithRanges carry the
\*     recording Sequence; MemoryBuffer does NOT. q_pos/q_val honesty for
\*     buffer queries is model instrumentation, not an API-observable fact.
\*   * GetCrossPlatformContext (per-position register file) is out of scope:
\*     the trace model has no register contents. SetPositionOnThread
\*     (thread-scoped seek), ReplayResult payloads (steps/instructions/
\*     event data), and the query-buffer lifetime rule ("valid until the
\*     next memory query on this cursor") are unmodeled.
\*   * Thread scoping is unmodeled throughout (Timeline has no schedule):
\*     per-thread GetPosition/GetPreviousPosition(ThreadId), the
\*     watchpoints' UniqueThreadId filters, ThreadLocal's current-thread
\*     concentration. A cursor's modeled position is the header's
\*     ThreadId::Invalid (current thread) projection.
\*     SetDefaultMemoryPolicy/GetDefaultMemoryPolicy is a stored default
\*     for the queries' policy argument — passing the policy per query,
\*     as here, is the same observable surface. GapKindMask filters gap
\*     stops, which this model never produces.
\*   * Scope is the replay interfaces' SEMANTICS only. The STL veneer
\*     (IReplayEngineStl.h: Unique* smart-pointer aliases, the Create*/
\*     Make* factories with their GUID/HRESULT plumbing, ITraceList
\*     multi-trace management) has no replay semantics and is out of
\*     scope — RInit starts with one trace already loaded and engine
\*     creation cannot fail.
\*   * Docs-tree divergences from the pinned v0.9.5 header, found while
\*     cross-checking (docs-tree bugs or later-API drift; the header in
\*     the NuGet package stays the authority). enum-EventMask.md IS
\*     faithful to the header: the mask genuinely gates watchpoint
\*     stops, which an earlier revision of this module got wrong.
\*     - enum-QueryMemoryPolicy.md lists RequireContiguous/AllowPartial
\*       (do not exist); interface-ICursorView.md's example uses
\*       QueryMemoryPolicy::MostAccurate (does not exist either).
\*     - the EventType doc over-lists ModuleLoad/ModuleUnload/Custom
\*       (the header enum has none of them).
\*     - interface-ICursorView.md names the scans ExecuteForward/
\*       ExecuteBackward with no destination limit (v0.9.5: ReplayForward/
\*       ReplayBackward(limit, stepCount) plus no-limit convenience
\*       overloads); behaviorally the dest = frontier/0 special case.
\*     - interface-ICursorView.md gives SetPosition a bool result
\*       (the header returns void).
\*     - type-UniqueCursor.md's examples contradict the interface pages
\*       (NewCursor's signature — the header returns ICursor* — and
\*       QueryMemory/GetCurrentThreadId calls ICursorView does not have).
\*
\* Commit truth is needed because memory queries FAIL on uncommitted cells
\* (the API's read failure is a fact, cf. JigSawSpawner's D3): a commit log
\* recorded at the moving frontier, same shape as JigSawSpawner's. Commit
\* positions are engine-visible at their recorded position (post-state
\* convention — the commit log is this module's own abstraction).

\* ---- Model-checking bounds (Timeline's, reused) ----
\* MaxPos, MaxAddr, MaxVal, MaxCalls, MaxThreads, MaxEvents come from
\* Timeline. Commit changes are recorded steps, so at most MaxPos exist.

MaxCursors == 2
MaxWatch   == 2

\* QueryMemoryPolicy v0.9.5 (Default/ThreadLocal/GloballyConservative/
\* GloballyAggressive/InFragmentAggressive), renamed to fit the grammar.
Policies == {"DEFAULT", "THREAD_LOCAL", "CONSERVATIVE", "AGGRESSIVE", "IN_FRAGMENT"}
\* EventType v0.9.5 + this model's "NONE" (no stop yet). GAP, THREAD,
\* STEP_COUNT, INTERRUPTED, ERROR are enumerated for fidelity but never
\* produced (see abstractions above).
StopReasons == {"NONE", "MEMORY_WATCHPOINT", "POSITION_WATCHPOINT", "EXCEPTION",
                "GAP", "THREAD", "STEP_COUNT", "POSITION", "PROCESS",
                "INTERRUPTED", "ERROR"}

\* EventMask v0.9.5: the maskable stop kinds are MemoryWatchpoint,
\* PositionWatchpoint, Exception, Gap, Thread (StepCount/Position/
\* Process/Interrupted/Error are NON-maskable per the header's EventType
\* comments). GAP/THREAD are absent here: Timeline records exceptions
\* only, so those bits could never gate anything in this model.
Maskable == {"MEMORY_WATCHPOINT", "POSITION_WATCHPOINT", "EXCEPTION"}

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
    \* @type: Int -> Set(Str);
    cur_mask,       \* cursor c's event mask (SetEventMask): SUBSET Maskable
    \* ── memory watchpoints (AddMemoryWatchpoint) ──
    \* @type: Int -> Bool;
    wp_on,
    \* @type: Int -> Int;
    wp_addr,        \* watched cell (one cell per watchpoint slot)
    \* ── position watchpoints (AddPositionWatchpoint) ──
    \* @type: Int -> Bool;
    pwp_on,
    \* @type: Int -> Int;
    pwp_lo,         \* armed position range [lo, hi]
    \* @type: Int -> Int;
    pwp_hi,
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
           cur_on, cur_pos, cur_prev, cur_stop, cur_mask,
           wp_on, wp_addr, pwp_on, pwp_lo, pwp_hi,
           q_ok, q_addr, q_val, q_pos, q_cursor, q_pol>>

allVars == <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
              frontier, cursor, threads, calls,
              init_committed, cm_pos, cm_page, cm_on,
              cur_on, cur_pos, cur_prev, cur_stop, cur_mask,
              wp_on, wp_addr, pwp_on, pwp_lo, pwp_hi,
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

\* ---- Engine truth (pre-instruction positions; the p+1 rule) ----

\* Memory contents at ENGINE position t: writes at p materialize at p+1,
\* so the engine sees ValueAt(t-1). Position 0 is the initial memory
\* (Timeline's first write is at position 1).
\* @type: (Int, Int) => Int;
EngineValueAt(a, t) ==
    IF t = 0 THEN init_mem[a] ELSE ValueAt(a, t - 1)

\* The engine position cell a's current-at-t content was recorded at: the
\* later of its last materialized write (write instruction at p is visible
\* at p+1) and its last commit-ON. This is the Sequence QueryMemoryRange
\* returns as provenance.
\* @type: (Int, Int) => Int;
RecordedAtE(a, t) ==
    LET i  == IF t = 0 THEN 0 ELSE LastWriter(a, t - 1)
        wp == IF i = 0 THEN 0 ELSE wr_pos[i] + 1
        cp == LastCommitOnPos(a, t)
    IN IF wp >= cp THEN wp ELSE cp

\* Cells currently memory-watched.
WatchedCells == {a \in 1..MaxAddr : \E w \in 1..MaxWatch : wp_on[w] /\ wp_addr[w] = a}

\* Watched-write positions in (cur, dest], when the mask allows them.
\* @type: (Int, Int) => Set(Int);
WatchHitsFwd(c, dest) ==
    IF "MEMORY_WATCHPOINT" \in cur_mask[c]
    THEN {p \in 0..MaxPos :
           \E i \in 1..MaxPos :
             i <= Len(wr_pos) /\ wr_pos[i] = p /\ wr_addr[i] \in WatchedCells
               /\ cur_pos[c] < p /\ p <= dest}
    ELSE {}

\* Watched-write positions in [dest, cur), when the mask allows them.
\* @type: (Int, Int) => Set(Int);
WatchHitsBwd(c, dest) ==
    IF "MEMORY_WATCHPOINT" \in cur_mask[c]
    THEN {p \in 0..MaxPos :
           \E i \in 1..MaxPos :
             i <= Len(wr_pos) /\ wr_pos[i] = p /\ wr_addr[i] \in WatchedCells
               /\ dest <= p /\ p < cur_pos[c]}
    ELSE {}

\* Exception-event positions in (cur, dest], when the mask allows them.
\* @type: (Int, Int) => Set(Int);
ExcHitsFwd(c, dest) ==
    IF "EXCEPTION" \in cur_mask[c]
    THEN {p \in 0..MaxPos :
           \E i \in 1..MaxEvents :
             i <= Len(ev_pos) /\ ev_kind[i] = "EXCEPTION" /\ ev_pos[i] = p
               /\ cur_pos[c] < p /\ p <= dest}
    ELSE {}

\* Exception-event positions in [dest, cur).
\* @type: (Int, Int) => Set(Int);
ExcHitsBwd(c, dest) ==
    IF "EXCEPTION" \in cur_mask[c]
    THEN {p \in 0..MaxPos :
           \E i \in 1..MaxEvents :
             i <= Len(ev_pos) /\ ev_kind[i] = "EXCEPTION" /\ ev_pos[i] = p
               /\ dest <= p /\ p < cur_pos[c]}
    ELSE {}

\* Positions in (cur, dest] inside an added position-watchpoint range,
\* when the mask allows them.
\* @type: (Int, Int) => Set(Int);
PwpHitsFwd(c, dest) ==
    IF "POSITION_WATCHPOINT" \in cur_mask[c]
    THEN {p \in 0..MaxPos :
           cur_pos[c] < p /\ p <= dest
             /\ \E w \in 1..MaxWatch : pwp_on[w] /\ pwp_lo[w] <= p /\ p <= pwp_hi[w]}
    ELSE {}

\* Positions in [dest, cur) inside an added position-watchpoint range,
\* when the mask allows them.
\* @type: (Int, Int) => Set(Int);
PwpHitsBwd(c, dest) ==
    IF "POSITION_WATCHPOINT" \in cur_mask[c]
    THEN {p \in 0..MaxPos :
           dest <= p /\ p < cur_pos[c]
             /\ \E w \in 1..MaxWatch : pwp_on[w] /\ pwp_lo[w] <= p /\ p <= pwp_hi[w]}
    ELSE {}

\* Smallest/largest element of a position set, with a "none" sentinel.
\* @type: Set(Int) => Int;
MinPos(s) == IF s = {} THEN MaxPos + 1 ELSE CHOOSE p \in s : \A q \in s : p <= q
\* @type: Set(Int) => Int;
MaxPosOf(s) == IF s = {} THEN 0 ELSE CHOOSE p \in s : \A q \in s : q <= p

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
                   cur_on, cur_pos, cur_prev, cur_stop, cur_mask,
                   wp_on, wp_addr, pwp_on, pwp_lo, pwp_hi,
                   q_ok, q_addr, q_val, q_pos, q_cursor, q_pol>>

\* ---- Actions: cursor lifecycle ----

CreateCursor(c) ==
    /\ c \in 1..MaxCursors
    /\ ~cur_on[c]
    /\ cur_on'   = [cur_on EXCEPT ![c] = TRUE]
    /\ cur_pos'  = [cur_pos EXCEPT ![c] = 0]
    /\ cur_prev' = [cur_prev EXCEPT ![c] = 0]
    /\ cur_stop' = [cur_stop EXCEPT ![c] = "NONE"]
    /\ cur_mask' = [cur_mask EXCEPT ![c] = {}]
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on,
                   wp_on, wp_addr, pwp_on, pwp_lo, pwp_hi,
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
                   cur_on, cur_mask, wp_on, wp_addr, pwp_on, pwp_lo, pwp_hi,
                   q_ok, q_addr, q_val, q_pos, q_cursor, q_pol>>

\* SetEventMask: arm the maskable stop kinds (v0.9.5 EventMask flags
\* MemoryWatchpoint/PositionWatchpoint/Exception/Gap/Thread — of which
\* only the three in Maskable can ever fire in this model).
SetMask(c, m) ==
    /\ c \in 1..MaxCursors
    /\ cur_on[c]
    /\ m \in SUBSET Maskable
    /\ cur_mask' = [cur_mask EXCEPT ![c] = m]
    /\ cur_stop' = [cur_stop EXCEPT ![c] = "NONE"]
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on,
                   cur_on, cur_pos, cur_prev,
                   wp_on, wp_addr, pwp_on, pwp_lo, pwp_hi,
                   q_ok, q_addr, q_val, q_pos, q_cursor, q_pol>>

\* ---- Actions: memory queries (QueryMemoryBuffer/Range + policies) ----

\* GloballyConservative ("high confidence of being correct, efficient to
\* find"): the answer is exact at the cursor. Fails iff uncommitted there.
QueryExact(c, a, pol) ==
    /\ c \in 1..MaxCursors /\ a \in 1..MaxAddr
    /\ cur_on[c] /\ pol = "CONSERVATIVE"
    /\ IF CmAt(a, cur_pos[c])
       THEN /\ q_ok'   = TRUE
            /\ q_val'  = EngineValueAt(a, cur_pos[c])
            /\ q_pos'  = cur_pos[c]
       ELSE /\ q_ok' = FALSE
            /\ UNCHANGED <<q_val, q_pos>>
    /\ q_addr' = a /\ q_cursor' = cur_pos[c] /\ q_pol' = pol
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on,
                   cur_on, cur_pos, cur_prev, cur_stop, cur_mask,
                   wp_on, wp_addr, pwp_on, pwp_lo, pwp_hi>>

\* ThreadLocal / GloballyAggressive / InFragmentAggressive / Default: the
\* engine may return the value from ANOTHER position (ThreadLocal
\* concentrates on the current thread's past/future — thread scoping is
\* unmodeled, Timeline has no schedule; the aggressive variants search
\* globally / in-fragment incl. the future). Provenance is honest: the
\* value is exactly the engine truth at the returned, committed position.
QuerySearch(c, a, pol) ==
    /\ c \in 1..MaxCursors /\ a \in 1..MaxAddr
    /\ cur_on[c] /\ pol \in {"DEFAULT", "THREAD_LOCAL", "AGGRESSIVE", "IN_FRAGMENT"}
    /\ LET committed == {s \in 0..MaxPos : s <= frontier /\ CmAt(a, s)}
       IN \/ /\ committed # {}
             /\ \E s \in committed :
                  /\ q_ok'  = TRUE
                  /\ q_val' = EngineValueAt(a, s)
                  /\ q_pos' = s
          \/ /\ committed = {}
             /\ q_ok' = FALSE
             /\ UNCHANGED <<q_val, q_pos>>
    /\ q_addr' = a /\ q_cursor' = cur_pos[c] /\ q_pol' = pol
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on,
                   cur_on, cur_pos, cur_prev, cur_stop, cur_mask,
                   wp_on, wp_addr, pwp_on, pwp_lo, pwp_hi>>

\* QueryMemoryRange: the contiguous recorded range containing the address
\* plus the position it was recorded at (modeled per cell). Exact at the
\* cursor; provenance = RecordedAtE.
QueryRangeMem(c, a) ==
    /\ c \in 1..MaxCursors /\ a \in 1..MaxAddr
    /\ cur_on[c]
    /\ IF CmAt(a, cur_pos[c])
       THEN /\ q_ok'   = TRUE
            /\ q_val'  = EngineValueAt(a, cur_pos[c])
            /\ q_pos'  = RecordedAtE(a, cur_pos[c])
       ELSE /\ q_ok' = FALSE
            /\ UNCHANGED <<q_val, q_pos>>
    /\ q_addr' = a /\ q_cursor' = cur_pos[c] /\ q_pol' = "RANGE"
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on,
                   cur_on, cur_pos, cur_prev, cur_stop, cur_mask,
                   wp_on, wp_addr, pwp_on, pwp_lo, pwp_hi>>

\* ---- Actions: watchpoints ----

AddMemWatchpoint(w, a) ==
    /\ w \in 1..MaxWatch /\ a \in 1..MaxAddr
    /\ wp_on'   = [wp_on EXCEPT ![w] = TRUE]
    /\ wp_addr' = [wp_addr EXCEPT ![w] = a]
    \* stop reasons are meaningful only against a fixed watchpoint set
    /\ cur_stop' = [c \in 1..MaxCursors |-> "NONE"]
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on,
                   cur_on, cur_pos, cur_prev, cur_mask,
                   pwp_on, pwp_lo, pwp_hi,
                   q_ok, q_addr, q_val, q_pos, q_cursor, q_pol>>

RemoveMemWatchpoint(w) ==
    /\ w \in 1..MaxWatch
    /\ wp_on' = [wp_on EXCEPT ![w] = FALSE]
    /\ cur_stop' = [c \in 1..MaxCursors |-> "NONE"]
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on,
                   cur_on, cur_pos, cur_prev, cur_mask, wp_addr,
                   pwp_on, pwp_lo, pwp_hi,
                   q_ok, q_addr, q_val, q_pos, q_cursor, q_pol>>

AddPosWatchpoint(w, lo, hi) ==
    /\ w \in 1..MaxWatch
    /\ lo \in 0..MaxPos /\ hi \in 0..MaxPos /\ lo <= hi
    /\ pwp_on' = [pwp_on EXCEPT ![w] = TRUE]
    /\ pwp_lo' = [pwp_lo EXCEPT ![w] = lo]
    /\ pwp_hi' = [pwp_hi EXCEPT ![w] = hi]
    /\ cur_stop' = [c \in 1..MaxCursors |-> "NONE"]
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on,
                   cur_on, cur_pos, cur_prev, cur_mask, wp_on, wp_addr,
                   q_ok, q_addr, q_val, q_pos, q_cursor, q_pol>>

RemovePosWatchpoint(w) ==
    /\ w \in 1..MaxWatch
    /\ pwp_on' = [pwp_on EXCEPT ![w] = FALSE]
    /\ cur_stop' = [c \in 1..MaxCursors |-> "NONE"]
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on,
                   cur_on, cur_pos, cur_prev, cur_mask, wp_on, wp_addr,
                   pwp_lo, pwp_hi,
                   q_ok, q_addr, q_val, q_pos, q_cursor, q_pol>>

\* ---- Actions: replay scans ----

\* ReplayForward(limit): run forward from the cursor; stop at the FIRST
\* of {masked memory-watchpoint write, masked position-watchpoint entry,
\* masked exception} in (pos, limit], else at the limit. "PROCESS" at the
\* frontier (end of lifetime), "POSITION" otherwise. Ties between event
\* kinds at the same position are resolved nondeterministically (the
\* engine's priority is undocumented).
ReplayFwd(c, dest) ==
    /\ c \in 1..MaxCursors
    /\ cur_on[c]
    /\ dest \in 0..MaxPos /\ cur_pos[c] < dest /\ dest <= frontier
    /\ LET wHit == MinPos(WatchHitsFwd(c, dest))
           eHit == MinPos(ExcHitsFwd(c, dest))
           pHit == MinPos(PwpHitsFwd(c, dest))
           target == IF wHit <= eHit /\ wHit <= pHit THEN wHit
                     ELSE IF eHit <= pHit THEN eHit ELSE pHit
       IN IF target <= dest
          THEN /\ cur_pos' = [cur_pos EXCEPT ![c] = target]
               \* reason must name a kind that genuinely hit at the stop
               \* position: set membership, not extremal-value equality
               \* (MinPos({}) = MaxPos+1 is unreachable here, so equality
               \* was sentinel-safe in this direction; membership is the
               \* honest form and the only safe one backward — see ReplayBwd).
               /\ \E reason \in {r \in {"MEMORY_WATCHPOINT", "EXCEPTION",
                                        "POSITION_WATCHPOINT"} :
                      (r = "MEMORY_WATCHPOINT" => target \in WatchHitsFwd(c, dest))
                      /\ (r = "EXCEPTION" => target \in ExcHitsFwd(c, dest))
                      /\ (r = "POSITION_WATCHPOINT" => target \in PwpHitsFwd(c, dest))} :
                    cur_stop' = [cur_stop EXCEPT ![c] = reason]
          ELSE /\ cur_pos' = [cur_pos EXCEPT ![c] = dest]
               /\ cur_stop' = [cur_stop EXCEPT ![c] =
                    IF dest = frontier THEN "PROCESS" ELSE "POSITION"]
    /\ cur_prev' = [cur_prev EXCEPT ![c] = cur_pos[c]]
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on,
                   cur_on, cur_mask, wp_on, wp_addr, pwp_on, pwp_lo, pwp_hi,
                   q_ok, q_addr, q_val, q_pos, q_cursor, q_pol>>

\* ReplayBackward(limit): run backward; stop at the LAST of {masked
\* watched write, masked position-watchpoint position, masked exception}
\* in [limit, pos), else at the limit. "PROCESS" at position 0 (start).
ReplayBwd(c, dest) ==
    /\ c \in 1..MaxCursors
    /\ cur_on[c]
    /\ dest \in 0..MaxPos /\ dest < cur_pos[c]
    /\ LET wHit == MaxPosOf(WatchHitsBwd(c, dest))
           eHit == MaxPosOf(ExcHitsBwd(c, dest))
           pHit == MaxPosOf(PwpHitsBwd(c, dest))
           target == IF wHit >= eHit /\ wHit >= pHit THEN wHit
                     ELSE IF eHit >= pHit THEN eHit ELSE pHit
       IN IF target >= dest /\ (WatchHitsBwd(c, dest) \cup ExcHitsBwd(c, dest)
                                \cup PwpHitsBwd(c, dest)) # {}
          THEN /\ cur_pos' = [cur_pos EXCEPT ![c] = target]
               \* reason must name a kind that genuinely hit at the stop
               \* position: set membership, NOT extremal-value equality.
               \* MaxPosOf({}) = 0 collides with real position 0 — the
               \* 2026-08-18 length-6 counterexample: a genuine
               \* POSITION_WATCHPOINT hit at 0 made wHit = eHit = pHit = 0,
               \* and "target = wHit" held spuriously, licensing a bogus
               \* MEMORY_WATCHPOINT stop with no memory watchpoint armed.
               /\ \E reason \in {r \in {"MEMORY_WATCHPOINT", "EXCEPTION",
                                        "POSITION_WATCHPOINT"} :
                      (r = "MEMORY_WATCHPOINT" => target \in WatchHitsBwd(c, dest))
                      /\ (r = "EXCEPTION" => target \in ExcHitsBwd(c, dest))
                      /\ (r = "POSITION_WATCHPOINT" => target \in PwpHitsBwd(c, dest))} :
                    cur_stop' = [cur_stop EXCEPT ![c] = reason]
          ELSE /\ cur_pos' = [cur_pos EXCEPT ![c] = dest]
               /\ cur_stop' = [cur_stop EXCEPT ![c] =
                    IF dest = 0 THEN "PROCESS" ELSE "POSITION"]
    /\ cur_prev' = [cur_prev EXCEPT ![c] = cur_pos[c]]
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on,
                   cur_on, cur_mask, wp_on, wp_addr, pwp_on, pwp_lo, pwp_hi,
                   q_ok, q_addr, q_val, q_pos, q_cursor, q_pol>>

\* ---- Invariants ----

ReplayTypes ==
    /\ \A c \in 1..MaxCursors :
         /\ 0 <= cur_pos[c] /\ cur_pos[c] <= MaxPos
         /\ 0 <= cur_prev[c] /\ cur_prev[c] <= MaxPos
         /\ cur_stop[c] \in StopReasons
         /\ cur_mask[c] \subseteq Maskable
    /\ \A w \in 1..MaxWatch :
         /\ wp_on[w] => wp_addr[w] \in 1..MaxAddr
         /\ pwp_on[w] => (pwp_lo[w] <= pwp_hi[w] /\ pwp_hi[w] <= MaxPos)
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
\* exactly the engine truth (pre-instruction convention) at the returned
\* position, and the cell is committed there.
QueryHonest ==
    q_ok =>
      /\ q_pos <= frontier
      /\ q_val = EngineValueAt(q_addr, q_pos)
      /\ CmAt(q_addr, q_pos)

\* GloballyConservative answers are exact: provenance is the position the
\* query was issued at.
ExactAtCursor ==
    (q_ok /\ q_pol = "CONSERVATIVE") => q_pos = q_cursor

\* The jigsaw-validity hook (QueryMemoryRange): the returned content was
\* recorded at q_pos and no write to the cell MATERIALIZES in
\* (q_pos, q_cursor] — so the range truthfully serves every engine
\* position in between (the engine side of JigSawSpawner's CacheSound).
RangeFresh ==
    (q_ok /\ q_pol = "RANGE") =>
      (\A i \in 1..MaxPos :
        (i <= Len(wr_pos) /\ wr_addr[i] = q_addr) =>
          ~(q_pos < wr_pos[i] + 1 /\ wr_pos[i] + 1 <= q_cursor))

\* Watchpoint scans stop at the FIRST hit in the replay direction, and
\* only with the mask bit set: a MEMORY_WATCHPOINT stop means a watched
\* write happens exactly at the stop position, and none lies strictly
\* between the previous position and it.
WatchStopsFirst ==
    \A c \in 1..MaxCursors :
      cur_stop[c] = "MEMORY_WATCHPOINT" =>
        /\ "MEMORY_WATCHPOINT" \in cur_mask[c]
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

\* Masked-exception stops are first in the replay direction likewise.
EventStopsFirst ==
    \A c \in 1..MaxCursors :
      cur_stop[c] = "EXCEPTION" =>
        /\ "EXCEPTION" \in cur_mask[c]
        /\ \E i \in 1..MaxEvents :
             i <= Len(ev_pos) /\ ev_kind[i] = "EXCEPTION"
               /\ ev_pos[i] = cur_pos[c]
        /\ (cur_prev[c] < cur_pos[c]) =>
             (\A i \in 1..MaxEvents :
               (i <= Len(ev_pos) /\ ev_kind[i] = "EXCEPTION") =>
                 ~(cur_prev[c] < ev_pos[i] /\ ev_pos[i] < cur_pos[c]))
        /\ (cur_pos[c] < cur_prev[c]) =>
             (\A i \in 1..MaxEvents :
               (i <= Len(ev_pos) /\ ev_kind[i] = "EXCEPTION") =>
                 ~(cur_pos[c] < ev_pos[i] /\ ev_pos[i] < cur_prev[c]))

\* Position-watchpoint stops land on the FIRST armed-range position in
\* the replay direction.
PwpStopsFirst ==
    \A c \in 1..MaxCursors :
      cur_stop[c] = "POSITION_WATCHPOINT" =>
        /\ "POSITION_WATCHPOINT" \in cur_mask[c]
        /\ \E w \in 1..MaxWatch :
             pwp_on[w] /\ pwp_lo[w] <= cur_pos[c] /\ cur_pos[c] <= pwp_hi[w]
        /\ (cur_prev[c] < cur_pos[c]) =>
             \A p \in 0..MaxPos :
               (cur_prev[c] < p /\ p < cur_pos[c]) =>
                 ~(\E w \in 1..MaxWatch :
                     pwp_on[w] /\ pwp_lo[w] <= p /\ p <= pwp_hi[w])
        /\ (cur_pos[c] < cur_prev[c]) =>
             \A p \in 0..MaxPos :
               (cur_pos[c] < p /\ p < cur_prev[c]) =>
                 ~(\E w \in 1..MaxWatch :
                     pwp_on[w] /\ pwp_lo[w] <= p /\ p <= pwp_hi[w])

ReplayApiInvariant ==
    /\ ReplayTypes
    /\ ReplayCursorBounded
    /\ QueryHonest
    /\ ExactAtCursor
    /\ RangeFresh
    /\ WatchStopsFirst
    /\ EventStopsFirst
    /\ PwpStopsFirst

\* ---- Specification ----

RInit ==
    /\ Init
    /\ init_committed \in [1..MaxAddr -> BOOLEAN]
    /\ cm_pos = <<>> /\ cm_page = <<>> /\ cm_on = <<>>
    /\ cur_on   = [c \in 1..MaxCursors |-> FALSE]
    /\ cur_pos  = [c \in 1..MaxCursors |-> 0]
    /\ cur_prev = [c \in 1..MaxCursors |-> 0]
    /\ cur_stop = [c \in 1..MaxCursors |-> "NONE"]
    /\ cur_mask = [c \in 1..MaxCursors |-> {}]
    /\ wp_on    = [w \in 1..MaxWatch |-> FALSE]
    /\ wp_addr  = [w \in 1..MaxWatch |-> 1]
    /\ pwp_on   = [w \in 1..MaxWatch |-> FALSE]
    /\ pwp_lo   = [w \in 1..MaxWatch |-> 0]
    /\ pwp_hi   = [w \in 1..MaxWatch |-> 0]
    /\ q_ok = FALSE
    /\ q_addr = 1 /\ q_val = 0 /\ q_pos = 0 /\ q_cursor = 0
    /\ q_pol = "NONE"

RNext ==
    \/ RecordOrNav
    \/ CommitStep
    \/ \E c \in 1..MaxCursors : CreateCursor(c)
    \/ \E c \in 1..MaxCursors, t \in 0..MaxPos : SetPos(c, t)
    \/ \E c \in 1..MaxCursors, m \in SUBSET Maskable : SetMask(c, m)
    \/ \E c \in 1..MaxCursors, a \in 1..MaxAddr, p \in Policies :
         QueryExact(c, a, p)
    \/ \E c \in 1..MaxCursors, a \in 1..MaxAddr, p \in Policies :
         QuerySearch(c, a, p)
    \/ \E c \in 1..MaxCursors, a \in 1..MaxAddr : QueryRangeMem(c, a)
    \/ \E w \in 1..MaxWatch, a \in 1..MaxAddr : AddMemWatchpoint(w, a)
    \/ \E w \in 1..MaxWatch : RemoveMemWatchpoint(w)
    \/ \E w \in 1..MaxWatch, lo \in 0..MaxPos, hi \in 0..MaxPos :
         AddPosWatchpoint(w, lo, hi)
    \/ \E w \in 1..MaxWatch : RemovePosWatchpoint(w)
    \/ \E c \in 1..MaxCursors, d \in 0..MaxPos : ReplayFwd(c, d)
    \/ \E c \in 1..MaxCursors, d \in 0..MaxPos : ReplayBwd(c, d)

RSpec == RInit /\ [][RNext]_allVars

=============================================================================

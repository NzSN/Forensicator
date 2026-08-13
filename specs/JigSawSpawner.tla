---- MODULE JigSawSpawner ----
EXTENDS Timeline

\* ── JigSawSpawner — the lazy trace proxy's client core ───────────────────
\*
\* Formal counterpart of docs/superpowers/specs/2026-08-12-lazy-trace-proxy
\* -design.md. Timeline.tla models the recorded trace (append-only write
\* log, frontier, cursor). This module models what the *analysis host* knows
\* and caches when memory is served lazily by a Windows-side proxy instead
\* of extracted eagerly into .ttfx INITMEM:
\*
\*   * write index (D1)   — the client's partial copy of the write log:
\*                          metadata only, fetched per page ("windowed";
\*                          a VA-range window is abstracted to one page).
\*                          idx_known[p] / idx_F[p] = the horizon: index for
\*                          page p is complete up to position idx_F[p].
\*   * commit state       — whether page p is committed at position t. The
\*                          engine answers reads truthfully (bytes if
\*                          committed, ABSENT if not); there is NO region
\*                          enumeration (P3 / P0′ findings), so commitment
\*                          is observable only by probing.
\*   * jigsaw cache (D2)  — per page, at most one piece: the bytes plus a
\*                          validity interval [lo, hi-1] derived from the
\*                          write index. ABSENT pieces are point-interval
\*                          pieces (D3: absent is a fact, not an error).
\*   * eviction           — cache correctness never depends on retention
\*                          (D2: eviction may be pure LRU).
\*
\* Abstractions (all deliberate):
\*   * One page = one Timeline memory cell (1..MaxAddr). Validity logic
\*     lives in the position domain, not the address domain.
\*   * The proxy/engine is not a process here — it is the *truth oracle*
\*     defined by the Timeline state: a read of page p at cursor t answers
\*     ValueAt(p, t) if CmAt(p, t), else ABSENT. Protocol serialization
\*     (D6) and the cursor pool (P0′) are concurrency concerns outside
\*     this spec; the per-cursor register file (P0′) is out of scope.
\*   * Commit changes are recorded steps at the moving frontier (TTD
\*     records VirtualAlloc/Free effects as trace activity), so the commit
\*     log is append-only like the write log.
\*
\* KNOWN GAP (documented, not modeled): a decommit→recommit cycle can
\* replace a page's contents (kernel zero-fill) without any write-log
\* entry, so a PRESENT piece's write-index validity interval is sound only
\* if no recommit happens inside it. The client cannot see recommits from
\* the index; the engineered mitigation is proxy-side — an N-mask
\* (NewData) watchpoint pass surfaces first-materialization positions and
\* clips intervals. Here, CacheSound is guarded by CmAt and the residual
\* risk is stated as the NoRecommitWithin assumption (not checked).

\* ---- Model-checking bounds (Timeline's, reused) ----
\* MaxPos, MaxAddr, MaxVal, MaxCalls, MaxThreads, MaxEvents come from
\* Timeline. Commit changes are recorded steps, so at most MaxPos exist.

PieceStates == {"EMPTY", "PRESENT", "ABSENT"}

\* ---- State ----

VARIABLES
    \* ── commit truth (engine side; append-only, frontier-recorded) ──
    \* @type: Int -> Bool;
    init_committed, \* pages committed at position 0, chosen in JInit
    \* @type: Seq(Int);
    cm_pos,         \* commit-change log: position of the i-th change
    \* @type: Seq(Int);
    cm_page,        \*                 page of the i-th change
    \* @type: Seq(Bool);
    cm_on,          \*                 committed flag after the i-th change
    \* ── client write index (D1; per-page horizon) ──
    \* @type: Int -> Bool;
    idx_known,      \* page's index has been fetched
    \* @type: Int -> Int;
    idx_F,          \* horizon: index of p complete for positions ≤ idx_F[p]
    \* ── jigsaw cache (D2/D3) ──
    \* @type: Int -> Str;
    cache_state,    \* EMPTY | PRESENT | ABSENT per page
    \* @type: Int -> Int;
    cache_val,      \* PRESENT: the page's byte (cell value)
    \* @type: Int -> Int;
    cache_lo,       \* validity interval [cache_lo, cache_hi - 1]
    \* @type: Int -> Int;
    cache_hi        \* (uniform: ABSENT is the point interval [t, t])

jvars == <<init_committed, cm_pos, cm_page, cm_on,
           idx_known, idx_F, cache_state, cache_val, cache_lo, cache_hi>>

allVars == <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
             frontier, cursor, threads, calls,
             init_committed, cm_pos, cm_page, cm_on,
             idx_known, idx_F, cache_state, cache_val, cache_lo, cache_hi>>

\* ---- Commit truth (what the engine knows) ----

\* Index of the last commit change to page p at or before t, or 0.
\* @type: (Int, Int) => Int;
LastCmChange(p, t) ==
    LET idxs == {i \in 1..MaxPos : i <= Len(cm_pos) /\ cm_page[i] = p /\ cm_pos[i] <= t}
    IN IF idxs = {} THEN 0
       ELSE CHOOSE i \in idxs : \A j \in idxs : j <= i

\* Is page p committed at position t (engine truth).
\* @type: (Int, Int) => Bool;
CmAt(p, t) ==
    LET i == LastCmChange(p, t)
    IN IF i = 0 THEN init_committed[p] ELSE cm_on[i]

\* ---- Client knowledge (write-index horizons; D1/D2 dependency rule) ----

\* Indices of writes to p at or before t that the client's index knows.
\* Sound only for t ≤ idx_F[p] — every use is guarded by FetchPage's
\* cursor ≤ idx_F[p] (queries beyond the horizon are refused; the client
\* must RefreshIndex first — the design's dependency rule).
\* @type: (Int, Int) => Int;
LastKnownWrite(p, t) ==
    LET idxs == {i \in 1..MaxPos : i <= Len(wr_pos) /\ wr_addr[i] = p
                                   /\ wr_pos[i] <= idx_F[p] /\ wr_pos[i] <= t}
    IN IF idxs = {} THEN 0 ELSE wr_pos[CHOOSE i \in idxs : \A j \in idxs : j <= i]

\* First known write to p strictly after t, or idx_F[p] + 1 when none is
\* known. The sentinel is the *horizon*, not MaxPos + 1: append-only growth
\* can add writes beyond idx_F[p], and validity must never claim positions
\* the index cannot see. (This is what makes staleness harmless: facts
\* about positions ≤ idx_F[p] never invalidate — IndexMonotone.)
\* @type: (Int, Int) => Int;
NextKnownWrite(p, t) ==
    LET idxs == {i \in 1..MaxPos : i <= Len(wr_pos) /\ wr_addr[i] = p
                                   /\ wr_pos[i] <= idx_F[p] /\ t < wr_pos[i]}
    IN IF idxs = {} THEN idx_F[p] + 1
       ELSE wr_pos[CHOOSE i \in idxs : \A j \in idxs : i <= j]

\* ---- Host-side position knowledge (views; D9) ----

\* Position knowledge lives on the analysis host, not in the proxy: the
\* proxy is a fetcher/truth-oracle, and every fact it returns becomes
\* host-side state (index horizons, pieces, ABSENT points). These views
\* compute locally what the host can answer about (p, t) and what it must
\* fetch next — the host drives the proxy, never the reverse. This is the
\* "state empty initially, filled lazily by query" of docs/timeline.md made
\* precise.

\* The host can serve the byte at (p, t) locally: a PRESENT piece whose
\* validity interval covers t. (Meaningful where committed — CacheSound.)
\* @type: (Int, Int) => Bool;
KnownAt(p, t) ==
    /\ cache_state[p] = "PRESENT"
    /\ cache_lo[p] <= t /\ t <= cache_hi[p] - 1

\* The host knows (p, t) is unreadable: an ABSENT point covers t.
\* @type: (Int, Int) => Bool;
KnownAbsentAt(p, t) ==
    /\ cache_state[p] = "ABSENT"
    /\ cache_lo[p] <= t /\ t <= cache_hi[p] - 1

\* The host lacks page p's index at t (the D2 dependency rule fires first:
\* fetch/refresh the index before the page).
\* @type: (Int, Int) => Bool;
NeedsIndex(p, t) ==
    \/ ~idx_known[p]
    \/ t > idx_F[p]

\* A hole in the jigsaw: the host can say nothing about (p, t) — this is
\* what the next FetchPage closes.
\* @type: (Int, Int) => Bool;
GapAt(p, t) ==
    /\ ~KnownAt(p, t)
    /\ ~KnownAbsentAt(p, t)

\* ---- Actions: recording (Timeline's, unchanged; jigsaw untouched) ----

TraceStep == Next /\ UNCHANGED jvars

\* A commit change is a recorded step at the moving head (no cell write).
CommitStep ==
    /\ frontier < MaxPos
    /\ \E p \in 1..MaxAddr, on \in BOOLEAN :
         /\ cm_pos'  = Append(cm_pos, frontier + 1)
         /\ cm_page' = Append(cm_page, p)
         /\ cm_on'   = Append(cm_on, on)
    /\ frontier' = frontier + 1
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   cursor, threads, calls, init_committed,
                   idx_known, idx_F, cache_state, cache_val, cache_lo, cache_hi>>

\* ---- Actions: client/proxy interaction ----

\* Fetch (or refresh) the write index for page p: the horizon advances to
\* the current frontier. Append-only ⇒ already-known facts stay true.
FetchIndex(p) ==
    /\ p \in 1..MaxAddr
    /\ (~idx_known[p] \/ idx_F[p] < frontier)
    /\ idx_known' = [idx_known EXCEPT ![p] = TRUE]
    /\ idx_F'     = [idx_F EXCEPT ![p] = frontier]
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on,
                   cache_state, cache_val, cache_lo, cache_hi>>

\* Proxy read of page p at the cursor (D2/D3). The engine answers
\* truthfully; the client caches the piece with its validity interval.
\* Guard: index known and cursor within the horizon (dependency rule).
\*   PRESENT: interval [W_last, W_next - 1] — exactly the positions whose
\*            write history (≤ that position) equals the fetch position's,
\*            so ValueAt agrees there by SnapshotConsistent.
\*   ABSENT:  point interval [t, t] — commitment can change invisibly
\*            (no region enumeration), so absence claims nothing beyond
\*            the probed position.
FetchPage(p) ==
    /\ p \in 1..MaxAddr
    /\ idx_known[p]
    /\ cursor <= idx_F[p]
    /\ IF CmAt(p, cursor)
       THEN /\ cache_state' = [cache_state EXCEPT ![p] = "PRESENT"]
            /\ cache_val'   = [cache_val EXCEPT ![p] = ValueAt(p, cursor)]
            /\ cache_lo'    = [cache_lo EXCEPT ![p] = LastKnownWrite(p, cursor)]
            /\ cache_hi'    = [cache_hi EXCEPT ![p] = NextKnownWrite(p, cursor)]
       ELSE /\ cache_state' = [cache_state EXCEPT ![p] = "ABSENT"]
            /\ cache_lo'    = [cache_lo EXCEPT ![p] = cursor]
            /\ cache_hi'    = [cache_hi EXCEPT ![p] = cursor + 1]
            /\ UNCHANGED cache_val
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on, idx_known, idx_F>>

\* Eviction is always safe (D2: retention never affects correctness).
Evict(p) ==
    /\ p \in 1..MaxAddr
    /\ cache_state[p] # "EMPTY"
    /\ cache_state' = [cache_state EXCEPT ![p] = "EMPTY"]
    /\ UNCHANGED <<init_mem, wr_pos, wr_addr, wr_val, ev_pos, ev_kind,
                   frontier, cursor, threads, calls,
                   init_committed, cm_pos, cm_page, cm_on, idx_known, idx_F,
                   cache_val, cache_lo, cache_hi>>

\* ---- Invariants ----

JigSawTypes ==
    /\ \A p \in 1..MaxAddr :
         /\ cache_state[p] \in PieceStates
         /\ 0 <= cache_lo[p] /\ cache_lo[p] <= MaxPos
         /\ 1 <= cache_hi[p] /\ cache_hi[p] <= MaxPos + 1
         /\ 0 <= idx_F[p] /\ idx_F[p] <= frontier
         /\ cache_state[p] # "EMPTY" => idx_known[p]
    /\ Len(cm_pos) = Len(cm_page) /\ Len(cm_page) = Len(cm_on)
    /\ \A i \in 1..MaxPos :
         i <= Len(cm_pos) =>
           /\ cm_pos[i] <= frontier
           /\ cm_page[i] \in 1..MaxAddr
           /\ i > 1 => cm_pos[i - 1] <= cm_pos[i]

\* The money property (D2/D5): any byte the cache can serve is the true
\* byte at that position — a cached PRESENT piece agrees with ValueAt at
\* every committed position inside its validity interval. Together with
\* SnapshotConsistent this licenses Trace::valueAt / snapshot over the
\* jigsaw instead of eager init_mem.
CacheSound ==
    \A p \in 1..MaxAddr :
      \A t \in 0..MaxPos :
        (cache_state[p] = "PRESENT" /\ cache_lo[p] <= t /\ t <= cache_hi[p] - 1
         /\ CmAt(p, t)) =>
          cache_val[p] = ValueAt(p, t)

\* Absent is a fact, not an error (D3): a cached ABSENT piece correctly
\* witnesses uncommittedness at its (point) interval.
AbsentSound ==
    \A p \in 1..MaxAddr :
      \A t \in 0..MaxPos :
        (cache_state[p] = "ABSENT" /\ cache_lo[p] <= t /\ t <= cache_hi[p] - 1) =>
          ~CmAt(p, t)

\* Validity never outruns knowledge: a PRESENT piece's interval stays
\* inside the page's index horizon, so append-only trace growth cannot
\* invalidate a cached interval (IndexMonotone made structural).
HorizonBounded ==
    \A p \in 1..MaxAddr :
      cache_state[p] = "PRESENT" =>
        /\ idx_known[p]
        /\ cache_hi[p] <= idx_F[p] + 1
        /\ cache_lo[p] <= cache_hi[p] - 1

\* Residual assumption, stated but NOT conjoined into JigSawInvariant and
\* NOT checked (see KNOWN GAP): if no commit change to p happens inside
\* (cache_lo[p], cache_hi[p] - 1], the cached byte is the true byte at
\* every position of the interval, committed or recomitted.
NoRecommitWithin ==
    \A p \in 1..MaxAddr :
      cache_state[p] = "PRESENT" =>
        \A i \in 1..MaxPos :
          (i <= Len(cm_pos) /\ cm_page[i] = p) =>
            ~(cache_lo[p] < cm_pos[i] /\ cm_pos[i] <= cache_hi[p] - 1)

JigSawInvariant ==
    /\ JigSawTypes
    /\ CacheSound
    /\ AbsentSound
    /\ HorizonBounded

\* ---- Specification ----

JInit ==
    /\ Init
    /\ init_committed \in [1..MaxAddr -> BOOLEAN]
    /\ cm_pos = <<>> /\ cm_page = <<>> /\ cm_on = <<>>
    /\ idx_known = [p \in 1..MaxAddr |-> FALSE]
    /\ idx_F     = [p \in 1..MaxAddr |-> 0]
    /\ cache_state = [p \in 1..MaxAddr |-> "EMPTY"]
    /\ cache_val   = [p \in 1..MaxAddr |-> 0]
    /\ cache_lo    = [p \in 1..MaxAddr |-> 0]
    /\ cache_hi    = [p \in 1..MaxAddr |-> 1]

JNext ==
    \/ TraceStep
    \/ CommitStep
    \/ \E p \in 1..MaxAddr : FetchIndex(p)
    \/ \E p \in 1..MaxAddr : FetchPage(p)
    \/ \E p \in 1..MaxAddr : Evict(p)

JSpec == JInit /\ [][JNext]_allVars

=============================================================================

---- MODULE JigSawSpawner ----
EXTENDS ReplayApi

\* ── JigSawSpawner — the lazy trace proxy's client core ───────────────────
\*
\* Formal counterpart of docs/trace/2026-08-12-lazy-trace-proxy-design.md.
\*
\* 2026-08-18 refactor: the engine surface is now ReplayApi (the public
\* TTD Replay API, pinned to the v0.9.5 NuGet header) instead of the
\* dbgeng-channel truth oracle of the 2026-08-13 revision (in git history;
\* that revision was Apalache-verified, full run green). What changes:
\*
\*   * Commit truth is inherited from ReplayApi (init_committed, the cm_*
\*     log, CmAt) — one model, no local copy.
\*   * Recording steps are ReplayApi's RecordOrNav: writes land only on
\*     committed cells (engine-consistency PIN 1). The previous revision
\*     let Timeline record writes anywhere.
\*   * Page fetch (READ_AT on the wire) has the semantics of SetPos(e)
\*     followed by a GloballyConservative QueryMemoryBuffer — QueryExact's
\*     contract, folded into one atomic step: succeeds iff CmAt(p, e), the
\*     value is EngineValueAt(p, e). The p+1 write-visibility clamp is now
\*     explicit: e = min(t+1, frontier) (Trace/Jigsaw.lean fetchPosition).
\*   * Write-index acquisition (WRITES_INDEX on the wire) is the watchpoint
\*     route (the proxy's Replay-API backend, design P0′): arm a memory
\*     watchpoint on the page, then iterate ReplayFwd to the frontier.
\*     Every stop is a masked watched write — ReplayApi's WatchStopsFirst
\*     is the completeness argument. The index itself stays implicit
\*     (per-page horizon only): the scan is the honest mechanism behind the
\*     old atomic FetchIndex's postcondition.
\*   * The P3 fallback (pages with write records but never readable)
\*     retries at the next known write's materialization position
\*     e2 = min(nw+1, frontier) and caches the piece at the honest model
\*     position e2−1 — mirroring Trace/Client.lean fetchPage.
\*   * Every piece records its probe: cache_req (model position requested)
\*     and cache_e (engine position probed). The one position-level
\*     divergence — a write exactly AT the frontier never materializes in
\*     any engine state — is explicit in CacheSound's guard.
\*
\* Abstractions (all deliberate):
\*   * One page = one Timeline memory cell (1..MaxAddr). Validity logic
\*     lives in the position domain, not the address domain.
\*   * One client cursor (Client = 1); one outstanding client op (D6): a
\*     scan and a fetch never overlap. The cursor's seek is folded into
\*     the atomic fetch — READ_AT carries its position on the wire.
\*   * Scans stop at watched writes of ANY armed page (watchpoints are
\*     engine-global); the walk simply continues. The implicit index
\*     stores no per-scan records — the horizon is the deliverable.
\*   * QueryMemoryRange provenance (RecordedAtE) refining the index-based
\*     intervals — the D2 revision — is NOT modeled yet; noted as future.
\*
\* KNOWN GAP (unchanged): a decommit→recommit cycle can replace a page's
\* contents (kernel zero-fill) without any write-log entry. The client
\* cannot see recommits from the index; the engineered mitigation is
\* proxy-side (an N-mask/NewData watchpoint pass clips intervals). Here
\* CacheSound is guarded by CmAt and the residual risk is stated as the
\* NoRecommitWithin assumption (not checked).

PieceStates == {"EMPTY", "PRESENT", "ABSENT"}

\* The client's one API cursor (ICursorView; D6 serialization).
Client == 1

\* ---- State (client side; engine/commit/API state comes from ReplayApi) ----

VARIABLES
    \* ── client write index (D1; per-page horizon) ──
    \* @type: Int -> Bool;
    idx_known,      \* page's index has been enumerated by a completed scan
    \* @type: Int -> Int;
    idx_F,          \* horizon: page's writes complete for positions ≤ idx_F[p]
    \* ── jigsaw cache (D2/D3) ──
    \* @type: Int -> Str;
    cache_state,    \* EMPTY | PRESENT | ABSENT per page
    \* @type: Int -> Int;
    cache_val,      \* PRESENT: the page's byte (cell value)
    \* @type: Int -> Int;
    cache_lo,       \* validity interval [cache_lo, cache_hi - 1]
    \* @type: Int -> Int;
    cache_hi,       \* (uniform: ABSENT is the point interval [t, t])
    \* ── per-piece probe provenance ──
    \* @type: Int -> Int;
    cache_req,      \* model position the piece was fetched for
    \* @type: Int -> Int;
    cache_e,        \* engine position actually probed (p+1-clamped)
    \* ── index-acquisition scan state ──
    \* @type: Bool;
    scan_on,        \* a watchpoint scan is walking the trace
    \* @type: Int;
    scan_page       \* the page being indexed

jvars == <<idx_known, idx_F, cache_state, cache_val, cache_lo, cache_hi,
           cache_req, cache_e, scan_on, scan_page>>

allJVars == <<allVars, jvars>>

\* ---- Client knowledge (write-index horizons; D1/D2 dependency rule) ----

\* Position of the last write to p at or before t that the client's index
\* knows, or 0. Sound only for t ≤ idx_F[p] — every use is guarded by the
\* dependency rule (queries beyond the horizon are refused; scan again).
\* @type: (Int, Int) => Int;
LastKnownWrite(p, t) ==
    LET idxs == {i \in 1..MaxPos : i <= Len(wr_pos) /\ wr_addr[i] = p
                                   /\ wr_pos[i] <= idx_F[p] /\ wr_pos[i] <= t}
    IN IF idxs = {} THEN 0 ELSE wr_pos[CHOOSE i \in idxs : \A j \in idxs : j <= i]

\* First known write position on p strictly after t, or idx_F[p] + 1 when
\* none is known. The sentinel is the *horizon*, not MaxPos + 1: append-only
\* growth can add writes beyond idx_F[p], and validity must never claim
\* positions the index cannot see (staleness is harmless — facts about
\* positions ≤ idx_F[p] never invalidate).
\* @type: (Int, Int) => Int;
NextKnownWrite(p, t) ==
    LET idxs == {i \in 1..MaxPos : i <= Len(wr_pos) /\ wr_addr[i] = p
                                   /\ wr_pos[i] <= idx_F[p] /\ t < wr_pos[i]}
    IN IF idxs = {} THEN idx_F[p] + 1
       ELSE wr_pos[CHOOSE i \in idxs : \A j \in idxs : i <= j]

\* Engine read position for a model query at t: a write at q materializes
\* at engine position q+1 (pre-instruction convention; ReplayApi's
\* EngineValueAt), clamped at the frontier (Trace/Jigsaw.lean
\* fetchPosition). A write exactly AT the frontier never materializes in
\* any engine state — the one documented position-level divergence.
\* @type: Int => Int;
FetchPos(t) == IF t + 1 <= frontier THEN t + 1 ELSE frontier

\* ---- Host-side position knowledge (views; D9) ----

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
\* scan the page before fetching it).
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

\* ---- Environment: recording & commit changes (ReplayApi's; client state
\*      untouched). RecordOrNav carries PIN 1: writes only on committed
\*      cells — the previous revision recorded writes anywhere. ----

TraceStep == RecordOrNav /\ UNCHANGED jvars

CommitStepJ == CommitStep /\ UNCHANGED jvars

\* ---- Client setup over the API surface ----

\* The client cursor comes up (NewCursor; mask starts empty, v0.9.5
\* default).
ClientSetup ==
    /\ CreateCursor(Client)
    /\ UNCHANGED jvars

\* Arm the memory-watchpoint stop kind for scans (SetEventMask).
ClientMaskOn ==
    /\ SetMask(Client, {"MEMORY_WATCHPOINT"})
    /\ UNCHANGED jvars

\* Arm/disarm the index watchpoint on a page (AddMemoryWatchpoint;
\* R/W/E/C collapses to W — Timeline records writes only).
ArmIndexWatch(w, p) ==
    /\ w \in 1..MaxWatch /\ p \in 1..MaxAddr
    /\ AddMemWatchpoint(w, p)
    /\ UNCHANGED jvars

DisarmIndexWatch(w) ==
    /\ w \in 1..MaxWatch
    /\ RemoveMemWatchpoint(w)
    /\ UNCHANGED jvars

\* ---- Index acquisition: the watchpoint scan (WRITES_INDEX via the API) ----

\* Begin enumerating page p's writes: position the client cursor at 0
\* (Lifetime.Min) and start walking masked watched-write stops toward the
\* frontier. Requires the watchpoint armed and the mask bit — else
\* ReplayFwd never stops for the page (v0.9.5 EventMask gating).
ScanStart(p) ==
    /\ p \in 1..MaxAddr
    /\ ~scan_on
    /\ cur_on[Client]
    /\ "MEMORY_WATCHPOINT" \in cur_mask[Client]
    /\ \E w \in 1..MaxWatch : wp_on[w] /\ wp_addr[w] = p
    /\ (~idx_known[p] \/ idx_F[p] < frontier)
    /\ SetPos(Client, 0)
    /\ scan_on' = TRUE
    /\ scan_page' = p
    /\ UNCHANGED <<idx_known, idx_F, cache_state, cache_val, cache_lo, cache_hi,
                   cache_req, cache_e>>

\* A genuine masked hit before the frontier (WatchStopsFirst: a watched
\* write AT the stop position, none strictly between) — the walk
\* continues. Stops may also name other armed pages' writes; harmless.
ScanStep ==
    /\ scan_on
    /\ cur_pos[Client] < frontier
    /\ ReplayFwd(Client, frontier)
    /\ cur_pos'[Client] < frontier
    /\ UNCHANGED jvars

\* The walk reached the frontier (dest; PROCESS stop): scan_page's writes
\* are complete for positions ≤ frontier — the horizon postcondition.
ScanFinish ==
    /\ scan_on
    /\ cur_pos[Client] < frontier
    /\ ReplayFwd(Client, frontier)
    /\ cur_pos'[Client] = frontier
    /\ idx_known' = [idx_known EXCEPT ![scan_page] = TRUE]
    /\ idx_F'     = [idx_F     EXCEPT ![scan_page] = frontier]
    /\ scan_on' = FALSE
    /\ UNCHANGED <<cache_state, cache_val, cache_lo, cache_hi, cache_req, cache_e,
                   scan_page>>

\* Degenerate completion: positioned at the frontier already (empty trace
\* at scan start, or the last watched write landed exactly on the
\* frontier — the walk saw it and cannot step past the head).
ScanFinishEmpty ==
    /\ scan_on
    /\ cur_pos[Client] = frontier
    /\ idx_known' = [idx_known EXCEPT ![scan_page] = TRUE]
    /\ idx_F'     = [idx_F     EXCEPT ![scan_page] = frontier]
    /\ scan_on' = FALSE
    /\ UNCHANGED <<vars, rvars,
                   cache_state, cache_val, cache_lo, cache_hi, cache_req, cache_e,
                   scan_page>>

\* ---- Page fetch: READ_AT = SetPos(e) ∘ GloballyConservative query ----

\* Fetch one page for model query position t (D2/D3 + Implementation
\* notes). Dependency rule: the page's index first, and t within the
\* horizon. The probe is a GloballyConservative query at the p+1-clamped
\* engine position e (the QueryExact contract): succeeds iff the page is
\* committed there, the value is the engine truth at e. On failure, the P3
\* fallback probes the next known write's materialization position e2 and
\* caches at the honest model position e2−1; otherwise the piece is ABSENT
\* at the point [t, t]. (Trace/Client.lean fetchPage.)
FetchPage(p, t) ==
    /\ p \in 1..MaxAddr
    /\ t \in 0..MaxPos
    /\ ~scan_on                    \* one outstanding client op (D6)
    /\ idx_known[p]
    /\ t <= idx_F[p]               \* queries beyond the horizon are refused
    /\ t <= frontier
    /\ LET e  == FetchPos(t)
           nw == NextKnownWrite(p, t)
           e2 == IF nw <= frontier THEN FetchPos(nw) ELSE 0
       IN
       IF CmAt(p, e)
       THEN \* PRESENT: value is engine truth at e; validity from the index
            /\ cache_state' = [cache_state EXCEPT ![p] = "PRESENT"]
            /\ cache_val'   = [cache_val   EXCEPT ![p] = EngineValueAt(p, e)]
            /\ cache_lo'    = [cache_lo    EXCEPT ![p] = LastKnownWrite(p, t)]
            /\ cache_hi'    = [cache_hi    EXCEPT ![p] = NextKnownWrite(p, t)]
            /\ cache_req'   = [cache_req   EXCEPT ![p] = t]
            /\ cache_e'     = [cache_e     EXCEPT ![p] = e]
       ELSE IF LastKnownWrite(p, t) # 0 /\ e2 # 0
            THEN \* P3 fallback: probe at the next write's materialization
                 IF CmAt(p, e2)
                 THEN /\ cache_state' = [cache_state EXCEPT ![p] = "PRESENT"]
                      /\ cache_val'   = [cache_val   EXCEPT ![p] = EngineValueAt(p, e2)]
                      \* cached at the fallback's honest model position e2−1
                      /\ cache_lo'    = [cache_lo  EXCEPT ![p] = LastKnownWrite(p, e2 - 1)]
                      /\ cache_hi'    = [cache_hi  EXCEPT ![p] = NextKnownWrite(p, e2 - 1)]
                      /\ cache_req'   = [cache_req EXCEPT ![p] = e2 - 1]
                      /\ cache_e'     = [cache_e   EXCEPT ![p] = e2]
                 ELSE \* ABSENT point at t (both probes failed)
                      /\ cache_state' = [cache_state EXCEPT ![p] = "ABSENT"]
                      /\ cache_lo'    = [cache_lo    EXCEPT ![p] = t]
                      /\ cache_hi'    = [cache_hi    EXCEPT ![p] = t + 1]
                      /\ cache_req'   = [cache_req   EXCEPT ![p] = t]
                      /\ cache_e'     = [cache_e     EXCEPT ![p] = e]
                      /\ UNCHANGED cache_val
            ELSE \* ABSENT point at t (no fallback applicable)
                 /\ cache_state' = [cache_state EXCEPT ![p] = "ABSENT"]
                 /\ cache_lo'    = [cache_lo    EXCEPT ![p] = t]
                 /\ cache_hi'    = [cache_hi    EXCEPT ![p] = t + 1]
                 /\ cache_req'   = [cache_req   EXCEPT ![p] = t]
                 /\ cache_e'     = [cache_e     EXCEPT ![p] = e]
                 /\ UNCHANGED cache_val
    /\ UNCHANGED <<vars, rvars, idx_known, idx_F, scan_on, scan_page>>

\* Eviction is always safe (D2: retention never affects correctness).
Evict(p) ==
    /\ p \in 1..MaxAddr
    /\ cache_state[p] # "EMPTY"
    /\ cache_state' = [cache_state EXCEPT ![p] = "EMPTY"]
    /\ UNCHANGED <<vars, rvars, idx_known, idx_F, cache_val, cache_lo,
                   cache_hi, cache_req, cache_e, scan_on, scan_page>>

\* ---- Invariants ----

JigSawTypes ==
    /\ \A p \in 1..MaxAddr :
         /\ cache_state[p] \in PieceStates
         /\ 0 <= cache_lo[p] /\ cache_lo[p] <= MaxPos
         /\ 1 <= cache_hi[p] /\ cache_hi[p] <= MaxPos + 1
         /\ 0 <= cache_req[p] /\ cache_req[p] <= MaxPos
         /\ 0 <= cache_e[p] /\ cache_e[p] <= MaxPos
         /\ 0 <= idx_F[p] /\ idx_F[p] <= frontier
         /\ cache_state[p] # "EMPTY" => idx_known[p]
    /\ scan_on \in BOOLEAN
    /\ scan_page \in 1..MaxAddr
    \* commit-log shape and cursor typing now live in ReplayApi's
    \* ReplayTypes (checked alongside — see JigSawSpawner.cfg).

\* The money property (D2/D5), now against the API probe semantics: a
\* cached PRESENT piece agrees with ValueAt at every committed model
\* position inside its validity interval — EXCEPT the one documented
\* position-level divergence: a write exactly AT the frontier never
\* materializes in any engine state, so a piece fetched at the clamped
\* head (recognizable by cache_req = cache_e with a write recorded at
\* cache_req) can lag that one write (design Implementation notes
\* 2026-08-12: the eager model applies it, the proxy cannot).
CacheSound ==
    \A p \in 1..MaxAddr :
      \A t \in 0..MaxPos :
        (cache_state[p] = "PRESENT" /\ cache_lo[p] <= t /\ t <= cache_hi[p] - 1
         /\ CmAt(p, t)
         /\ ~(cache_req[p] = cache_e[p]
              /\ \E i \in 1..MaxPos :
                   i <= Len(wr_pos) /\ wr_pos[i] = cache_req[p]
                     /\ wr_addr[i] = p)) =>
          cache_val[p] = ValueAt(p, t)

\* Absent is a fact, not an error (D3): an ABSENT piece witnesses that the
\* probed engine position was uncommitted. cache_e records WHICH position
\* was probed (the p+1-clamped position of the first, failing probe) —
\* commitment at the model position t itself is not claimed: commits are
\* engine-visible at their recorded position, and a flip exactly between
\* t and e is the probe boundary's business.
AbsentSound ==
    \A p \in 1..MaxAddr :
      \A t \in 0..MaxPos :
        (cache_state[p] = "ABSENT" /\ cache_lo[p] <= t /\ t <= cache_hi[p] - 1) =>
          ~CmAt(p, cache_e[p])

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
\* every position of the interval, committed or recommitted.
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
    /\ RInit
    /\ idx_known = [p \in 1..MaxAddr |-> FALSE]
    /\ idx_F     = [p \in 1..MaxAddr |-> 0]
    /\ cache_state = [p \in 1..MaxAddr |-> "EMPTY"]
    /\ cache_val   = [p \in 1..MaxAddr |-> 0]
    /\ cache_lo    = [p \in 1..MaxAddr |-> 0]
    /\ cache_hi    = [p \in 1..MaxAddr |-> 1]
    /\ cache_req   = [p \in 1..MaxAddr |-> 0]
    /\ cache_e     = [p \in 1..MaxAddr |-> 0]
    /\ scan_on = FALSE
    /\ scan_page = 1

JNext ==
    \/ TraceStep
    \/ CommitStepJ
    \/ ClientSetup
    \/ ClientMaskOn
    \/ \E w \in 1..MaxWatch, p \in 1..MaxAddr : ArmIndexWatch(w, p)
    \/ \E w \in 1..MaxWatch : DisarmIndexWatch(w)
    \/ \E p \in 1..MaxAddr : ScanStart(p)
    \/ ScanStep
    \/ ScanFinish
    \/ ScanFinishEmpty
    \/ \E p \in 1..MaxAddr, t \in 0..MaxPos : FetchPage(p, t)
    \/ \E p \in 1..MaxAddr : Evict(p)

JSpec == JInit /\ [][JNext]_allJVars

=============================================================================

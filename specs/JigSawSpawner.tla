---- MODULE JigSawSpawner ----
EXTENDS ReplayApi

\* ── JigSawSpawner — the lazy trace proxy's client core ───────────────────
\*
\* Formal counterpart of docs/trace/2026-08-12-lazy-trace-proxy-design.md
\* and docs/trace/2026-09-06-execution-timeline-design.md (execution views).
\* Assumption correction (2026-09-06 R0): ReplayApi.QueryExact is an idealized
\* certified oracle, not a guarantee of SDK GloballyConservative. The pinned
\* header promises high confidence, not strict exactness. Existing actions and
\* BMC invariants below are unchanged and conditional on that oracle, complete
\* absence classification, the integer p+1 phase rule and honest index coverage.
\* No native replay certification follows from a successful model check.
\* Evidence: Drafts/2026-09-06-timeline-native-prerequisites.md.
\*
\* 2026-08-18 refactor: the engine surface is now ReplayApi (the public
\* TTD adapter abstraction, using v0.9.5 NuGet header names) instead of the
\* dbgeng-channel truth oracle of the 2026-08-13 revision (in git history;
\* that revision was Apalache-verified, full run green). What changes:
\*
\*   * Commit truth is inherited from ReplayApi (init_committed, the cm_*
\*     log, CmAt) — one model, no local copy.
\*   * Recording steps are ReplayApi's RecordOrNav: writes land only on
\*     committed cells (engine-consistency PIN 1). The previous revision
\*     let Timeline record writes anywhere.
\*   * Page fetch (READ_AT on the wire) ASSUMES SetPos(e) followed by the
\*     certified QueryExact oracle, folded into one atomic step. A successful
\*     GloballyConservative query alone is insufficient. In the model the
\*     query succeeds iff CmAt(p, e), the
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
\*     only when nw < frontier, at e2 = nw+1, and caches at model nw.
\*     A write at the frontier has no post-write state to retry. This
\*     strict guard mirrors Trace/Jigsaw.lean fallbackPosition.
\*   * Probe instrumentation distinguishes the original request, initial
\*     engine probe, observed model position and final engine probe. A
\*     successful future fallback returns ABSENT for the original point.
\*     Public page knowledge suppresses writes exactly at the frontier;
\*     they cannot be fetched as faithful post-write observations.
\*
\* Abstractions (all deliberate):
\*   * One page = one Timeline memory cell (1..MaxAddr). Validity logic
\*     lives in the position domain, not the address domain.
\*   * Bounded integer positions assume the supported client domain. The
\*     UInt64 maximum frontier is rejected before attachment in Lean,
\*     since the half-open cache sentinel frontier+1 must be representable.
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
\* cannot see recommits from the index. A proposed proxy-side NewData pass
\* requires native validation; SDK NewData is not a certified allocation or
\* lifecycle event and cannot alone close this gap. Here
\* byte equality below is against ReplayApi's write-log ValueAt oracle,
\* which does not model kernel zero-fill. It proves neither complete
\* mapping knowledge nor lifecycle coverage. NoRecommitWithin remains
\* an external assumption (not checked or silently conjoined).

PieceStates == {"EMPTY", "PRESENT", "ABSENT"}
KnowledgeStates == {"UNKNOWN", "KNOWN", "ABSENT"}

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
    cache_req,      \* ORIGINAL requested model position
    \* @type: Int -> Int;
    cache_obs,      \* model position used to establish the stored piece
    \* @type: Int -> Int;
    cache_first_e,  \* initial engine probe for the original request
    \* @type: Int -> Int;
    cache_e,        \* final engine probe (may be a future fallback)
    \* @type: Int -> Str;
    cache_reply,    \* original request result; fallback success returns ABSENT
    \* ── index-acquisition scan state ──
    \* @type: Bool;
    scan_on,        \* a watchpoint scan is walking the trace
    \* @type: Int;
    scan_page       \* the page being indexed

jvars == <<idx_known, idx_F, cache_state, cache_val, cache_lo, cache_hi,
           cache_req, cache_obs, cache_first_e, cache_e, cache_reply, scan_on, scan_page>>

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

\* Raw bounded cache predicates. A piece alone is not a public answer:
\* pageKnowledge additionally checks position bounds, index knowledge and
\* the unobservable frontier write (Trace/Client.lean).
\* @type: (Int, Int) => Bool;
CachedPresentAt(p, t) ==
    /\ cache_state[p] = "PRESENT"
    /\ cache_lo[p] <= t /\ t < cache_hi[p]

\* @type: (Int, Int) => Bool;
CachedAbsentAt(p, t) ==
    /\ cache_state[p] = "ABSENT"
    /\ cache_lo[p] <= t /\ t < cache_hi[p]

\* @type: (Int, Int) => Bool;
NeedsIndex(p, t) == ~idx_known[p] \/ t > idx_F[p]

\* @type: (Int, Int) => Bool;
UnobservableFrontierWrite(p, t) ==
    /\ t = frontier
    /\ \E i \in 1..MaxPos :
         i <= Len(wr_pos) /\ wr_addr[i] = p /\ wr_pos[i] = frontier

\* @type: (Int, Int) => Bool;
KnowledgeDomain(p, t) ==
    /\ 0 <= t /\ t <= frontier
    /\ ~NeedsIndex(p, t)
    /\ ~UnobservableFrontierWrite(p, t)

\* @type: (Int, Int) => Bool;
KnownAt(p, t) == KnowledgeDomain(p, t) /\ CachedPresentAt(p, t)

\* @type: (Int, Int) => Bool;
KnownAbsentAt(p, t) == KnowledgeDomain(p, t) /\ CachedAbsentAt(p, t)

\* @type: (Int, Int) => Str;
PageKnowledge(p, t) ==
    IF KnownAt(p, t) THEN "KNOWN"
    ELSE IF KnownAbsentAt(p, t) THEN "ABSENT" ELSE "UNKNOWN"

\* A gap may need an index scan before a read. An unobservable frontier
\* write stays UNKNOWN: a read cannot make its post-write value available.
\* @type: (Int, Int) => Bool;
GapAt(p, t) == PageKnowledge(p, t) = "UNKNOWN"

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
                   cache_req, cache_obs, cache_first_e, cache_e, cache_reply>>

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
    /\ UNCHANGED <<cache_state, cache_val, cache_lo, cache_hi, cache_req, cache_obs, cache_first_e, cache_e, cache_reply,
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
                   cache_state, cache_val, cache_lo, cache_hi, cache_req, cache_obs, cache_first_e, cache_e, cache_reply,
                   scan_page>>

\* ---- Page fetch: READ_AT = SetPos(e) ∘ assumed certified oracle ----

\* Fetch one page for model query position t (D2/D3 + Implementation
\* notes). Dependency rule: the page's index first, and t within the
\* full static frontier. The probe assumes QueryExact at the p+1-clamped
\* engine position e: succeeds iff the page is
\* committed there, the value is the engine truth at e. On failure, the P3
\* fallback probes a next known write strictly below the frontier at e2 and
\* caches at the honest model position e2−1; otherwise the piece is ABSENT
\* at the point [t, t]. (Trace/Client.lean fetchPage.)
FetchPage(p, t) ==
    /\ p \in 1..MaxAddr
    /\ t \in 0..MaxPos
    /\ ~scan_on                    \* one outstanding client op (D6)
    /\ idx_known[p]
    /\ idx_F[p] = frontier         \* ensurePages fetches the full static horizon
    /\ t <= frontier
    /\ ~UnobservableFrontierWrite(p, t) \* return UNKNOWN without cache mutation
    /\ LET e  == FetchPos(t)
           nw == NextKnownWrite(p, t)
           e2 == IF nw < frontier THEN FetchPos(nw) ELSE 0
       IN
       IF CmAt(p, e)
       THEN \* PRESENT: value is engine truth at e; validity from the index
            /\ cache_state' = [cache_state EXCEPT ![p] = "PRESENT"]
            /\ cache_val'   = [cache_val   EXCEPT ![p] = EngineValueAt(p, e)]
            /\ cache_lo'    = [cache_lo    EXCEPT ![p] = LastKnownWrite(p, t)]
            /\ cache_hi'    = [cache_hi    EXCEPT ![p] = NextKnownWrite(p, t)]
            /\ cache_req'   = [cache_req   EXCEPT ![p] = t]
            /\ cache_obs'   = [cache_obs   EXCEPT ![p] = t]
            /\ cache_first_e' = [cache_first_e EXCEPT ![p] = e]
            /\ cache_e'     = [cache_e     EXCEPT ![p] = e]
            /\ cache_reply' = [cache_reply EXCEPT ![p] = "KNOWN"]
       ELSE IF LastKnownWrite(p, t) # 0 /\ e2 # 0
            THEN \* P3 fallback: probe at the next write's materialization
                 IF CmAt(p, e2)
                 THEN /\ cache_state' = [cache_state EXCEPT ![p] = "PRESENT"]
                      /\ cache_val'   = [cache_val   EXCEPT ![p] = EngineValueAt(p, e2)]
                      \* cached at the fallback's honest model position e2−1
                      /\ cache_lo'    = [cache_lo  EXCEPT ![p] = LastKnownWrite(p, e2 - 1)]
                      /\ cache_hi'    = [cache_hi  EXCEPT ![p] = NextKnownWrite(p, e2 - 1)]
                      /\ cache_req'   = [cache_req EXCEPT ![p] = t]
                      /\ cache_obs'   = [cache_obs EXCEPT ![p] = e2 - 1]
                      /\ cache_first_e' = [cache_first_e EXCEPT ![p] = e]
                      /\ cache_e'     = [cache_e   EXCEPT ![p] = e2]
                      /\ cache_reply' = [cache_reply EXCEPT ![p] = "ABSENT"]
                 ELSE \* ABSENT point at t (both probes failed)
                      /\ cache_state' = [cache_state EXCEPT ![p] = "ABSENT"]
                      /\ cache_lo'    = [cache_lo    EXCEPT ![p] = t]
                      /\ cache_hi'    = [cache_hi    EXCEPT ![p] = t + 1]
                      /\ cache_req'   = [cache_req   EXCEPT ![p] = t]
                      /\ cache_obs'   = [cache_obs   EXCEPT ![p] = t]
                      /\ cache_first_e' = [cache_first_e EXCEPT ![p] = e]
                      /\ cache_e'     = [cache_e     EXCEPT ![p] = e]
                      /\ cache_reply' = [cache_reply EXCEPT ![p] = "ABSENT"]
                      /\ UNCHANGED cache_val
            ELSE \* ABSENT point at t (no fallback applicable)
                 /\ cache_state' = [cache_state EXCEPT ![p] = "ABSENT"]
                 /\ cache_lo'    = [cache_lo    EXCEPT ![p] = t]
                 /\ cache_hi'    = [cache_hi    EXCEPT ![p] = t + 1]
                 /\ cache_req'   = [cache_req   EXCEPT ![p] = t]
                 /\ cache_obs'   = [cache_obs   EXCEPT ![p] = t]
                 /\ cache_first_e' = [cache_first_e EXCEPT ![p] = e]
                 /\ cache_e'     = [cache_e     EXCEPT ![p] = e]
                 /\ cache_reply' = [cache_reply EXCEPT ![p] = "ABSENT"]
                 /\ UNCHANGED cache_val
    /\ UNCHANGED <<vars, rvars, idx_known, idx_F, scan_on, scan_page>>

\* Eviction is always safe (D2: retention never affects correctness).
Evict(p) ==
    /\ p \in 1..MaxAddr
    /\ cache_state[p] # "EMPTY"
    /\ cache_state' = [cache_state EXCEPT ![p] = "EMPTY"]
    /\ UNCHANGED <<vars, rvars, idx_known, idx_F, cache_val, cache_lo,
                   cache_hi, cache_req, cache_obs, cache_first_e, cache_e, cache_reply, scan_on, scan_page>>

\* ---- Invariants ----

JigSawTypes ==
    /\ \A p \in 1..MaxAddr :
         /\ cache_state[p] \in PieceStates
         /\ 0 <= cache_lo[p] /\ cache_lo[p] <= MaxPos
         /\ 1 <= cache_hi[p] /\ cache_hi[p] <= MaxPos + 1
         /\ 0 <= cache_req[p] /\ cache_req[p] <= MaxPos
         /\ 0 <= cache_obs[p] /\ cache_obs[p] <= MaxPos
         /\ 0 <= cache_first_e[p] /\ cache_first_e[p] <= MaxPos
         /\ cache_reply[p] \in KnowledgeStates
         /\ 0 <= cache_e[p] /\ cache_e[p] <= MaxPos
         /\ 0 <= idx_F[p] /\ idx_F[p] <= frontier
         /\ cache_state[p] # "EMPTY" => idx_known[p]
    /\ scan_on \in BOOLEAN
    /\ scan_page \in 1..MaxAddr
    \* commit-log shape and cursor typing now live in ReplayApi's
    \* ReplayTypes (checked alongside — see JigSawSpawner.cfg).

\* Public known values agree with Timeline's write-log value at every
\* queried position, with no exemption for stale clamped bytes. Frontier
\* writes are UNKNOWN in PageKnowledge and FetchPage never stores them.
\* This is byte equality within ReplayApi's oracle, not a verification of
\* lifecycle/zero-fill behavior; see the external NoRecommitWithin gap.
CacheSound ==
    \A p \in 1..MaxAddr :
      \A t \in 0..MaxPos :
        KnownAt(p, t) => cache_val[p] = ValueAt(p, t)

KnowledgeSound ==
    \A p \in 1..MaxAddr :
      \A t \in 0..MaxPos + 1 :
        /\ PageKnowledge(p, t) \in KnowledgeStates
        /\ (NeedsIndex(p, t) \/ t > frontier \/ UnobservableFrontierWrite(p, t))
             => PageKnowledge(p, t) = "UNKNOWN"
        /\ ~(KnownAt(p, t) /\ KnownAbsentAt(p, t))

\* The probe fields are specification instrumentation, not new protocol
\* fields or an unbounded client-side knowledge ledger.
ProbeSound ==
    \A p \in 1..MaxAddr :
      cache_state[p] # "EMPTY" =>
        /\ cache_req[p] <= cache_obs[p]
        /\ cache_obs[p] <= idx_F[p]
        /\ cache_req[p] <= cache_first_e[p]
        /\ cache_first_e[p] <= cache_req[p] + 1
        /\ cache_first_e[p] <= cache_e[p]
        /\ cache_obs[p] <= cache_e[p]
        /\ cache_e[p] <= cache_obs[p] + 1
        /\ cache_e[p] <= frontier
        /\ (cache_state[p] = "PRESENT" =>
              /\ CmAt(p, cache_e[p])
              /\ cache_val[p] = EngineValueAt(p, cache_e[p]))
        /\ (cache_reply[p] = "ABSENT" => ~CmAt(p, cache_first_e[p]))
        /\ (cache_reply[p] = "KNOWN" =>
              /\ cache_req[p] = cache_obs[p]
              /\ cache_state[p] = "PRESENT")

\* A P3 piece is useful only from the later write onward. In particular,
\* neither a clamped frontier retry nor a wide inferred interval may make
\* the original NOT_COMMITTED point appear PRESENT. The per-request
\* result retains ABSENT even though the bounded cache retains future bytes.
FallbackIsolation ==
    \A p \in 1..MaxAddr :
      (cache_state[p] = "PRESENT" /\ cache_req[p] < cache_obs[p]) =>
        /\ cache_reply[p] = "ABSENT"
        /\ cache_first_e[p] = cache_req[p] + 1
        /\ cache_e[p] = cache_obs[p] + 1
        /\ cache_req[p] < cache_lo[p]
        /\ ~CachedPresentAt(p, cache_req[p])
        /\ PageKnowledge(p, cache_req[p]) = "UNKNOWN"

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
    /\ KnowledgeSound
    /\ ProbeSound
    /\ FallbackIsolation

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
    /\ cache_obs   = [p \in 1..MaxAddr |-> 0]
    /\ cache_first_e = [p \in 1..MaxAddr |-> 0]
    /\ cache_reply = [p \in 1..MaxAddr |-> "UNKNOWN"]
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

---- MODULE JigSawSpawnerRegression ----
EXTENDS JigSawSpawner

\* Focused loaded-trace regression for the two P3 paths. The normal model
\* checks recording, watchpoint scanning and cache operations together;
\* this seed starts after a valid scan, so both retry paths are reached
\* without spending the bound on cursor/watchpoint setup.
\*
\* Cell 1: write at 1, decommit at 2, recommit at 3, second write at 4
\* (ordinary fallback) or 5 (unobservable frontier write). The frontier
\* is 5. Both writes occur on committed memory at their pre-instruction
\* positions, as ReplayApi.RecordOrNav requires. Query 1 probes engine 2
\* and observes NOT_COMMITTED. QueryMemory uses actual CmAt/EngineValueAt;
\* this is not an arbitrary successful/failed-read oracle.
\*
\* The configuration overrides Timeline's bounded MaxPos operator to 5.
\* NoRecommitWithin is deliberately NOT assumed: these fixtures exercise
\* commitment changes. The byte oracle still omits kernel zero-fill, as
\* documented in ReplayApi/JigSawSpawner; lifecycle coverage is not proved.

RegressionMaxPos == 5

RegressionInit ==
    /\ init_mem = [p \in 1..MaxAddr |-> 0]
    /\ wr_pos \in {<<1, 4>>, <<1, 5>>}
    /\ wr_addr = <<1, 1>>
    /\ wr_val = <<1, 0>>
    /\ ev_pos = <<>> /\ ev_kind = <<>>
    /\ frontier = 5 /\ cursor = 0
    /\ threads = <<>> /\ calls = <<>>
    /\ init_committed = [p \in 1..MaxAddr |-> TRUE]
    /\ cm_pos = <<2, 3>> /\ cm_page = <<1, 1>> /\ cm_on = <<FALSE, TRUE>>
    /\ cur_on = [c \in 1..MaxCursors |-> FALSE]
    /\ cur_pos = [c \in 1..MaxCursors |-> 0]
    /\ cur_prev = [c \in 1..MaxCursors |-> 0]
    /\ cur_stop = [c \in 1..MaxCursors |-> "NONE"]
    /\ cur_mask = [c \in 1..MaxCursors |-> {}]
    /\ wp_on = [w \in 1..MaxWatch |-> FALSE]
    /\ wp_addr = [w \in 1..MaxWatch |-> 1]
    /\ pwp_on = [w \in 1..MaxWatch |-> FALSE]
    /\ pwp_lo = [w \in 1..MaxWatch |-> 0]
    /\ pwp_hi = [w \in 1..MaxWatch |-> 0]
    /\ q_ok = FALSE
    /\ q_addr = 1 /\ q_val = 0 /\ q_pos = 0 /\ q_cursor = 0 /\ q_pol = "NONE"
    /\ idx_known = [p \in 1..MaxAddr |-> p = 1]
    /\ idx_F = [p \in 1..MaxAddr |-> IF p = 1 THEN frontier ELSE 0]
    /\ cache_state = [p \in 1..MaxAddr |-> "EMPTY"]
    /\ cache_val = [p \in 1..MaxAddr |-> 0]
    /\ cache_lo = [p \in 1..MaxAddr |-> 0]
    /\ cache_hi = [p \in 1..MaxAddr |-> 1]
    /\ cache_req = [p \in 1..MaxAddr |-> 0]
    /\ cache_obs = [p \in 1..MaxAddr |-> 0]
    /\ cache_first_e = [p \in 1..MaxAddr |-> 0]
    /\ cache_e = [p \in 1..MaxAddr |-> 0]
    /\ cache_reply = [p \in 1..MaxAddr |-> "UNKNOWN"]
    /\ scan_on = FALSE /\ scan_page = 1

RegressionNext ==
    \/ \E p \in 1..MaxAddr, t \in 0..MaxPos : FetchPage(p, t)
    \/ \E p \in 1..MaxAddr : Evict(p)

RegressionInvariant ==
    /\ TimelineInvariant
    /\ ReplayApiInvariant
    /\ JigSawInvariant
    /\ \A i \in 1..2 : CmAt(wr_addr[i], wr_pos[i] - 1)
    /\ \A t \in 0..MaxPos : PageKnowledge(2, t) = "UNKNOWN"
    /\ (cache_state[1] # "EMPTY" /\ cache_req[1] = 1) =>
         /\ cache_reply[1] = "ABSENT"
         /\ PageKnowledge(1, 1) # "KNOWN"
         /\ (wr_pos[2] = frontier =>
               /\ cache_state[1] = "ABSENT"
               /\ cache_obs[1] = 1 /\ cache_e[1] = 2)
         /\ (wr_pos[2] < frontier =>
               /\ cache_state[1] = "PRESENT"
               /\ cache_obs[1] = 4 /\ cache_lo[1] = 4
               /\ cache_e[1] = 5)

=============================================================================

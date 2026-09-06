---- MODULE SnapshotRegression ----
EXTENDS Snapshot

\* Loaded-source materialization profile. Timeline.cfg separately explores
\* recording; this profile starts with an immutable trace, like proxy attach.
\* Two writes restore the original byte (0 -> 1 -> 0), event shapes exercise
\* simultaneous exceptions and local-vs-global selection indices, and thread
\* instances have distinct half-open lifetimes. Capture contexts and every
\* source/position's mapping truth remain nondeterministic.
\*
\* All normal materialization/observation/navigation/eviction actions run.
\* The eight-step bound reaches a two-cell result from a one-cell cache and
\* acquisition for a following request while that result is still published.
\* Requested reads may remain unknown: finishing does not assert full recovery.

RegressionInit ==
    /\ init_mem = [a \in 1..MaxAddr |-> 0]
    /\ wr_pos = <<1, 2>> /\ wr_addr = <<1, 1>> /\ wr_val = <<1, 0>>
    /\ ev_pos \in {<<1, 1, 2>>, <<0, 1, 2>>}
    /\ ev_kind = <<"EXCEPTION", "EXCEPTION", "MODULE_LOAD">>
    /\ frontier = MaxPos /\ cursor = 0
    /\ threads = <<[start |-> 0, end |-> 3], [start |-> 2, end |-> -1]>>
    /\ calls = <<>>
    /\ trace_sealed = TRUE
    /\ mapped_truth \in [CellKeys -> BOOLEAN]
    /\ capture_memory \in [1..MaxAddr -> 0..MaxVal - 1]
    /\ capture_threads \in SUBSET (1..MaxThreads)
    /\ capture_regs_valid \in [1..MaxThreads -> BOOLEAN]
    /\ capture_regs \in [1..MaxThreads -> 0..MaxVal - 1]
    /\ capture_stack_valid \in [1..MaxThreads -> BOOLEAN]
    /\ capture_exception \in BOOLEAN
    /\ known_bytes = {} /\ known_absence = {}
    /\ observed_values = [key \in CellKeys |-> 0]
    /\ mat_phase = "IDLE"
    /\ mat_source = TraceSource /\ mat_pos = 0
    /\ mat_requested = {} /\ mat_seen = {} /\ mat_observed = {}
    /\ mat_values = [a \in 1..MaxAddr |-> [knowledge |-> "unknown", value |-> 0]]
    /\ snapshot_live = FALSE
    /\ published_id = PointId(CaptureSource, 0)
    /\ published_requested = {} /\ published_observed = {}
    /\ snapshot = ExecutionPointAt(CaptureSource, 0)

RegressionNext == MaterializationNext

RegressionInvariant ==
    /\ SnapshotInvariant
    /\ ValueAt(1, 0) = ValueAt(1, 2)
    /\ WritesBetweenChecked(1, 0, 2).writes = {1, 2}
    /\ ExecutionPointAt(TraceSource, 3).threads[1].present = FALSE
    /\ ExecutionPointAt(TraceSource, 2).threads[2].present = TRUE

=============================================================================

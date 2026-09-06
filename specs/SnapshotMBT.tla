---- MODULE SnapshotMBT ----
EXTENDS Snapshot

\* Compatibility module name for existing model-check commands. The deleted
\* Rust echo/driver state is gone: this entry checks the same execution-point
\* materialization as Snapshot.tla and constructs no Dump-shaped projection.
MBTSpec == MaterializationSpec

=============================================================================

---- MODULE SymbolizerMBT ----
EXTENDS Symbolizer

\* Action tracking for Model-Based Testing with MirrorRust.
\* Extends Symbolizer.tla to expose action names and parameters.
\* View captures module state and anomalies for trace replay.

VARIABLES
    \* @type: Str;
    action_taken,
    \* @type: [name: Str, base_va: Int, size: Int, va: Int, count: Int];
    parameters

SymbolizerActionNames ==
    { "Init", "LoadPdb", "LoadPdbEmpty", "ResolveAddress" }

\* View is used only for trace deduplication under --max-error > 1 (the
\* mirror compares raw variables, so no record projection here; a
\* dynamic-range set-map is also a known unsupported Apalache construct).
View ==
    [ sym_modules   |-> sym_modules,
      sym_anomalies |-> sym_anomalies ]

MBTInit ==
    /\ Init
    /\ action_taken = "Init"
    /\ parameters = [name |-> "", base_va |-> 0, size |-> 0, va |-> 0, count |-> 0]

MBTLoadPdb ==
    \E name \in {"module_a", "module_b"}:
      \E base_va \in {0, 4096, 8192}:
        \E size \in {4096, 8192}:
          \E count \in 1..MaxSymbols:
            /\ LoadPdb(name, base_va, size, count)
            /\ action_taken' = "LoadPdb"
            /\ parameters' = [name |-> name, base_va |-> base_va, size |-> size, va |-> 0,
                              count |-> count]

MBTLoadPdbEmpty ==
    \E name \in {"module_a", "module_b"}:
      \E base_va \in {0, 4096, 8192}:
        \E size \in {4096, 8192}:
          /\ LoadPdbEmpty(name, base_va, size)
          /\ action_taken' = "LoadPdbEmpty"
          /\ parameters' = [name |-> name, base_va |-> base_va, size |-> size, va |-> 0,
                            count |-> 0]

MBTResolveAddress ==
    \E va \in 0..12288:
      /\ ResolveAddress(va)
      /\ action_taken' = "ResolveAddress"
      /\ parameters' = [name |-> "", base_va |-> 0, size |-> 0, va |-> va, count |-> 0]

MBTNext ==
    \/ MBTLoadPdb
    \/ MBTLoadPdbEmpty
    \/ MBTResolveAddress

MBTSpec == MBTInit /\ [][MBTNext]_<<sym_modules, sym_tables, sym_anomalies, action_taken, parameters>>

TraceComplete == TRUE
====

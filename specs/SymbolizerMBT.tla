---- MODULE SymbolizerMBT ----
EXTENDS Symbolizer

\* Action tracking for Model-Based Testing with MirrorRust.
\* Extends Symbolizer.tla to expose action names and parameters.

VARIABLES
    \* @type: Str;
    action_taken,
    \* @type: [name: Str, va: Int];
    parameters

SymbolizerActionNames ==
    { "Init", "LoadPdb", "LoadPdbEmpty", "ResolveAddress" }

\* View operator exposed to MirrorRust for state comparison.
View ==
    [ sym_loaded    |-> sym_loaded,
      sym_entries   |-> sym_entries,
      sym_anomalies |-> sym_anomalies ]

MBTInit ==
    /\ Init
    /\ action_taken = "Init"
    /\ parameters = [name |-> "", va |-> 0]

MBTLoadPdb ==
    \E name \in {"module_a", "module_b"}:
      /\ LoadPdb(name, TRUE)
      /\ action_taken' = "LoadPdb"
      /\ parameters' = [name |-> name, va |-> 0]

MBTLoadPdbEmpty ==
    \E name \in {"module_a", "module_b"}:
      /\ LoadPdbEmpty(name)
      /\ action_taken' = "LoadPdbEmpty"
      /\ parameters' = [name |-> name, va |-> 0]

MBTResolveAddress ==
    \E va \in 0..1024:
      /\ ResolveAddress(va)
      /\ action_taken' = "ResolveAddress"
      /\ parameters' = [name |-> "", va |-> va]

MBTNext ==
    \/ MBTLoadPdb
    \/ MBTLoadPdbEmpty
    \/ MBTResolveAddress

MBTSpec == MBTInit /\ [][MBTNext]_<<sym_loaded, sym_entries, sym_anomalies, action_taken, parameters>>

TraceComplete == TRUE
====

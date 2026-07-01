---- MODULE SymbolizerMBT ----
EXTENDS Symbolizer

\* Action tracking for Model-Based Testing with MirrorRust.
\* Extends Symbolizer.tla to expose action names and parameters.
\* View captures module state and anomalies for trace replay.

VARIABLES
    \* @type: Str;
    action_taken,
    \* @type: [name: Str, base_va: Int, size: Int, va: Int];
    parameters

SymbolizerActionNames ==
    { "Init", "LoadPdb", "LoadPdbEmpty", "ResolveAddress" }

View ==
    [ sym_modules   |-> { [name |-> ModuleName(i), base_va |-> ModuleBase(i), size |-> ModuleSize(i)] : i \in 1..Len(sym_modules) },
      sym_anomalies |-> sym_anomalies ]

MBTInit ==
    /\ Init
    /\ action_taken = "Init"
    /\ parameters = [name |-> "", base_va |-> 0, size |-> 0, va |-> 0]

MBTLoadPdb ==
    \E name \in {"module_a", "module_b"}:
      \E base_va \in {0, 4096, 8192}:
        \E size \in {4096, 8192}:
          /\ LoadPdb(name, base_va, size)
          /\ action_taken' = "LoadPdb"
          /\ parameters' = [name |-> name, base_va |-> base_va, size |-> size, va |-> 0]

MBTLoadPdbEmpty ==
    \E name \in {"module_a", "module_b"}:
      \E base_va \in {0, 4096, 8192}:
        \E size \in {4096, 8192}:
          /\ LoadPdbEmpty(name, base_va, size)
          /\ action_taken' = "LoadPdbEmpty"
          /\ parameters' = [name |-> name, base_va |-> base_va, size |-> size, va |-> 0]

MBTResolveAddress ==
    \E va \in 0..12288:
      /\ ResolveAddress(va)
      /\ action_taken' = "ResolveAddress"
      /\ parameters' = [name |-> "", base_va |-> 0, size |-> 0, va |-> va]

MBTNext ==
    \/ MBTLoadPdb
    \/ MBTLoadPdbEmpty
    \/ MBTResolveAddress

MBTSpec == MBTInit /\ [][MBTNext]_<<sym_modules, sym_tables, sym_anomalies, action_taken, parameters>>

TraceComplete == TRUE
====

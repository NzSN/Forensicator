---- MODULE Symbolizer ----
EXTENDS Integers, Sequences, FiniteSets

\* ── Symbolizer — PDB-based address-to-symbol resolution ──
\*
\* Each loaded module has a base_va, a size, and a sorted symbol table.
\* ResolveAddress(va) finds the module containing va, then binary-searches
\* its symbol table for the nearest function ≤ va.

\* Model-checking bounds (verification artifacts, not format limits).
MaxModules  == 2
MaxSymbols  == 4
MaxAnomalies == 4

\* ---- State ----

VARIABLES
    \* @type: Seq(<<Str, Int, Int>>);
    sym_modules,       \* loaded modules: Seq of <<name, base_va, size>>
    \* @type: Seq(Seq(<<Int, Str, Str, Int>>));
    sym_tables,        \* per-module sorted symbol table: Seq of <<va, name, file, line>>
    \* @type: Seq([desc: Str]);
    sym_anomalies

\* ---- Helpers ----

LoadedCount == Len(sym_modules)

ModuleName(i) == sym_modules[i][1]
ModuleBase(i)  == sym_modules[i][2]
ModuleSize(i)  == sym_modules[i][3]

ModuleContains(i, va) ==
    i <= Len(sym_modules) /\ ModuleBase(i) <= va /\ va < ModuleBase(i) + ModuleSize(i)

FindModule(va) ==
    \* ModuleContains(i, va) already Len-guards; the constant domain is
    \* the Apalache discipline (no dynamic ranges in set/quantifier bounds).
    CHOOSE i \in 1..MaxModules : ModuleContains(i, va)

\* Nearest function ≤ va in module i's symbol table: the last table
\* entry whose va is ≤ va (tables are sorted). Returns
\* <<va, name, file, line>> or <<0, "", "", 0>> if none.
\* (Constant quantifier domain with a Len guard — Apalache-friendly;
\* Apalache admits no recursive LET definitions.)
NearestSymbol(i, va) ==
    LET tbl == sym_tables[i]
        idxs == {j \in 1..MaxSymbols : j <= Len(tbl) /\ tbl[j][1] <= va}
    IN  IF idxs = {}
        THEN <<0, "", "", 0>>
        ELSE LET m == CHOOSE j \in idxs : \A k \in idxs : k <= j
             IN tbl[m]

\* ---- Invariants ----

TablesSorted ==
    \A i \in 1..MaxModules:
      i <= Len(sym_modules) =>
        LET tbl == sym_tables[i]
        IN  \A j \in 1..MaxSymbols:
              j <= Len(tbl) - 1 => tbl[j][1] <= tbl[j+1][1]

ModulesNonOverlapping ==
    \A i \in 1..MaxModules:
      \A j \in 1..MaxModules:
        (i <= Len(sym_modules) /\ j <= Len(sym_modules) /\ i # j) =>
          ~(ModuleBase(i) < ModuleBase(j) + ModuleSize(j)
            /\ ModuleBase(j) < ModuleBase(i) + ModuleSize(i))

AnomaliesBounded == Len(sym_anomalies) <= MaxAnomalies

SymbolizerInvariant ==
    /\ TablesSorted
    /\ ModulesNonOverlapping
    /\ AnomaliesBounded

\* ---- Operations ----

\* Fabricated per-k names (4 literals suffice because MaxSymbols = 4;
\* extend the chains if MaxSymbols grows — string concatenation is not
\* typeable as \o over Str for Snowcat, and TLC!ToString is deprecated).
\* @type: (Int) => Str;
SymName(k) == SubSeq(<<"func1", "func2", "func3", "func4">>, 1, 4)[k]
\* @type: (Int) => Str;
SymFile(k) == SubSeq(<<"src1.cpp", "src2.cpp", "src3.cpp", "src4.cpp">>, 1, 4)[k]

\* Load a PDB for a module at base_va with size, producing a sorted
\* symbol table of public functions. Module base+VAs are used so resolve
\* works with absolute addresses. count is a parameter (not an internal
\* choice) so SymbolizerMBT can export it to the Rust mirror.
LoadPdb(name, base_va, size, count) ==
    /\ Len(sym_modules) < MaxModules
    /\ size > 0
    /\ count \in 1..MaxSymbols
    /\ LET Build(k) == <<base_va + (k * 256), SymName(k), SymFile(k), k * 10>>
           \* 4 literals suffice because MaxSymbols = 4 (extend if it
           \* grows); [j \in 1..count |-> ...] is function-typed to
           \* Snowcat, so the table is materialized as a Seq literal.
           \* @type: Seq(<<Int, Str, Str, Int>>);
           All == <<Build(1), Build(2), Build(3), Build(4)>>
           entries == SubSeq(All, 1, count)
       IN  /\ sym_modules' = Append(sym_modules, <<name, base_va, size>>)
           /\ sym_tables'  = Append(sym_tables, entries)
           /\ UNCHANGED sym_anomalies

LoadPdbEmpty(name, base_va, size) ==
    /\ Len(sym_modules) < MaxModules
    /\ size > 0
    /\ sym_modules' = Append(sym_modules, <<name, base_va, size>>)
    /\ sym_tables'  = Append(sym_tables, <<>>)
    /\ Len(sym_anomalies) < MaxAnomalies
    /\ sym_anomalies' = Append(sym_anomalies, [desc |-> "no_publics"])

\* Resolve a VA to a symbol. Finds the module containing the VA,
\* then binary-searches its symbol table for the nearest function.
\* Records an anomaly if the VA is not in any loaded module.
ResolveAddress(va) ==
    IF \E i \in 1..MaxModules: ModuleContains(i, va)
    THEN LET i == FindModule(va)
             entry == NearestSymbol(i, va)
         IN  IF entry[1] > 0
             THEN /\ UNCHANGED <<sym_modules, sym_tables, sym_anomalies>>
             ELSE /\ Len(sym_anomalies) < MaxAnomalies
                  /\ sym_anomalies' = Append(sym_anomalies, [desc |-> "va_not_found"])
                  /\ UNCHANGED <<sym_modules, sym_tables>>
    ELSE /\ Len(sym_anomalies) < MaxAnomalies
         /\ sym_anomalies' = Append(sym_anomalies, [desc |-> "va_not_found"])
         /\ UNCHANGED <<sym_modules, sym_tables>>

\* ── Init ──

Init ==
    /\ sym_modules   = <<>>
    /\ sym_tables    = <<>>
    /\ sym_anomalies = <<>>

\* ── Next ──

Next ==
    \/ \E name \in {"module_a", "module_b"}:
         \E base_va \in {0, 4096, 8192}:
           \E size \in {4096, 8192}:
             \E count \in 1..MaxSymbols:
               LoadPdb(name, base_va, size, count)
    \/ \E name \in {"module_a", "module_b"}:
         \E base_va \in {0, 4096, 8192}:
           \E size \in {4096, 8192}:
             LoadPdbEmpty(name, base_va, size)
    \/ \E va \in 0..12288:
         ResolveAddress(va)

Spec == Init /\ [][Next]_<<sym_modules, sym_tables, sym_anomalies>>

====

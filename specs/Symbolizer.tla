---- MODULE Symbolizer ----
EXTENDS Integers, Sequences, FiniteSets

\* ── Symbolizer — PDB-based address-to-symbol resolution ──
\*
\* Each loaded module has a base_va, a size, and a sorted symbol table.
\* ResolveAddress(va) finds the module containing va, then binary-searches
\* its symbol table for the nearest function ≤ va.

CONSTANTS MaxModules, MaxSymbols

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
    CHOOSE i \in 1..Len(sym_modules) : ModuleContains(i, va)

\* Nearest function ≤ va in module i's symbol table.
\* Returns <<va, name, file, line>> or <<0, "", "", 0>> if none.
NearestSymbol(i, va) ==
    LET tbl == sym_tables[i]
    IN  IF tbl = <<>>
        THEN <<0, "", "", 0>>
        ELSE LET
            Find(t, idx, best) ==
                IF idx > Len(t)
                THEN best
                ELSE IF t[idx][1] <= va
                     THEN Find(t, idx+1, t[idx])
                     ELSE Find(t, idx+1, best)
        IN Find(tbl, 1, <<0, "", "", 0>>)

\* ---- Invariants ----

TablesSorted ==
    \A i \in 1..Len(sym_modules):
      LET tbl == sym_tables[i]
      IN  \A j \in 1..(Len(tbl)-1):
            j > 0 => tbl[j][1] <= tbl[j+1][1]

ModulesNonOverlapping ==
    \A i \in 1..Len(sym_modules):
      \A j \in 1..Len(sym_modules):
        (i # j) => ~(ModuleBase(i) < ModuleBase(j) + ModuleSize(j)
                     /\ ModuleBase(j) < ModuleBase(i) + ModuleSize(i))

AnomaliesBounded == Len(sym_anomalies) <= MaxAnomalies

SymbolizerInvariant ==
    /\ TablesSorted
    /\ ModulesNonOverlapping
    /\ AnomaliesBounded

\* ---- Operations ----

\* Load a PDB for a module at base_va with size, producing a sorted
\* symbol table of public functions. Module base+VAs are used so resolve
\* works with absolute addresses.
LoadPdb(name, base_va, size) ==
    /\ Len(sym_modules) < MaxModules
    /\ size > 0
    /\ \E count \in 1..MaxSymbols:
         LET Build(k) ==
             IF k = 0 THEN <<>>
             ELSE LET va   == base_va + (k * 256)
                      fn   == "func" \o ToString(k)
                      file == "src" \o ToString(k) \o ".cpp"
                      line == k * 10
                  IN  <<va, fn, file, line>>
         IN  LET entries == [j \in 1..count |-> Build(j)]
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
    IF \E i \in 1..Len(sym_modules): ModuleContains(i, va)
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
             LoadPdb(name, base_va, size)
    \/ \E name \in {"module_a", "module_b"}:
         \E base_va \in {0, 4096, 8192}:
           \E size \in {4096, 8192}:
             LoadPdbEmpty(name, base_va, size)
    \/ \E va \in 0..12288:
         ResolveAddress(va)

Spec == Init /\ [][Next]_<<sym_modules, sym_tables, sym_anomalies>>

====

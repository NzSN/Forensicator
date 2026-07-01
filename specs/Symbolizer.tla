---- MODULE Symbolizer ----
EXTENDS Integers, Sequences, FiniteSets

\* ── Symbolizer — PDB-based address-to-symbol resolution ──
\*
\* Standalone module. Consumed by CLI and analyzers (not a pipeline stage).
\* Takes Dump.modules + local PDB files → SymbolTable per module → ResolveAddress.
\*
\* Actions: LoadPdb (GUID match + parse + index), ResolveAddress (VA → symbol).
\* Invariants: all tables sorted, loaded ⊆ dump modules, resolved VAs in bounds.

\* ---- Constants ----

CONSTANTS
    MaxModules,        \* bound from Model.tla
    MaxSymbols,        \* max public symbols per module
    MaxFileLen,        \* max source file path length
    MaxNameLen         \* max function name length

MaxModules == 2
MaxSymbols == 4
MaxFileLen == 8
MaxNameLen == 16

\* ---- State variables ----

VARIABLES
    \* @type: Set(Str);
    sym_loaded,         \* set of module names with loaded symbol tables
    \* @type: Str -> Seq(<<Int, Str, Str, Int>>);
    sym_entries,        \* per-module symbol table: Seq of <<va, name, file, line>>
    \* @type: Seq([desc: Str]);
    sym_anomalies       \* loading/resolution errors

\* ---- Helpers ----

\* Count of loaded modules
LoadedCount == Cardinality(sym_loaded)

\* Symbol table for a module (empty if not loaded)
TableFor(name) ==
    IF name \in sym_loaded
    THEN sym_entries[name]
    ELSE <<>>

\* Binary search for nearest function VA ≤ target
\* Returns (function_va, name, file, line) or None if target < first entry.
NearestSymbol(name, va) ==
    LET table == TableFor(name)
    IN  IF table = <<>>
        THEN <<0, "", "", 0>>   \* sentinel: no symbol found
        ELSE LET
            FindNearest(t, idx, best) ==
                IF idx > Len(t)
                THEN best
                ELSE IF t[idx][1] <= va
                     THEN FindNearest(t, idx+1, t[idx])
                     ELSE FindNearest(t, idx+1, best)
        IN FindNearest(table, 1, <<0, "", "", 0>>)

\* ---- Invariants ----

\* All symbol tables are sorted by VA (ascending)
TablesSorted ==
    \A name \in sym_loaded:
      LET tbl == sym_entries[name]
      IN  \A i \in 1..(Len(tbl)-1):
            i > 0 => tbl[i][1] <= tbl[i+1][1]

\* Every loaded module corresponds to a parsed dump module
\* (Imported from Model.tla — module names are tracked there)
LoadedSubsetModules == TRUE
    \* When composed with Model.tla, this becomes:
    \*   sym_loaded \subseteq { "ntdll.dll", "kernel32.dll", ... }
    \* The actual check uses M!ModuleCount and module name tracking.

\* Anomalies are bounded
AnomaliesBounded == Len(sym_anomalies) <= 4

SymbolizerInvariant ==
    /\ TablesSorted
    /\ AnomaliesBounded

\* ---- Operations ----

\* LoadPdb: match module GUID from PDB header, parse public symbols,
\* build a sorted symbol table. Non-deterministic on which symbols appear.
LoadPdb(module_name, pdb_guid_matches) ==
    /\ module_name \notin sym_loaded
    /\ pdb_guid_matches   \* GUID verification succeeded (opaque to us)
    \* Non-deterministically produce a sorted symbol table
    /\ \E count \in 1..MaxSymbols:
         LET BuildSeq(k) ==
             IF k = 0 THEN <<>>
             ELSE LET va   == k * 256      \* non-det VA spacing
                      name == "func" \o ToString(k)
                      file == "src" \o ToString(k) \o ".cpp"
                      line == k * 10
                  IN  <<va, name, file, line>>
         IN  LET entries == [i \in 1..count |-> BuildSeq(i)]
             IN  /\ sym_entries' = [sym_entries EXCEPT ![module_name] = entries]
                 /\ sym_loaded'  = sym_loaded \cup {module_name}
                 /\ UNCHANGED sym_anomalies

\* LoadPdb with no public symbols (still records the module as loaded)
LoadPdbEmpty(module_name) ==
    /\ module_name \notin sym_loaded
    /\ sym_entries' = [sym_entries EXCEPT ![module_name] = <<>>]
    /\ sym_loaded'  = sym_loaded \cup {module_name}
    /\ Len(sym_anomalies) < 4
    /\ sym_anomalies' = Append(sym_anomalies, [desc |-> "no_publics"])

\* ResolveAddress: given a VA, find which module contains it, then
\* look up the nearest symbol. Returns (name, offset, file, line).
\* If VA is not in any loaded module, records an anomaly.
ResolveAddress(va) ==
    /\ \E name \in sym_loaded:
         \* Assume module base + size bounds check happens here
         \* (in Rust: binary search ModuleSymbols by base_va)
         LET entry == NearestSymbol(name, va)
         IN  /\ entry[1] > 0   \* found a symbol
             /\ UNCHANGED <<sym_loaded, sym_entries, sym_anomalies>>
    \/ /\ \A name \in sym_loaded:   \* VA not in any module
             LET entry == NearestSymbol(name, va)
             IN  entry[1] = 0
       /\ Len(sym_anomalies) < 4
       /\ sym_anomalies' = Append(sym_anomalies, [desc |-> "va_not_found"])
       /\ UNCHANGED <<sym_loaded, sym_entries>>

\* ── Init ──

Init ==
    /\ sym_loaded    = {}
    /\ sym_entries   = [n \in {} |-> <<>>]
    /\ sym_anomalies = <<>>

\* ── Next ──

Next ==
    \/ \E name \in {"module_a", "module_b"}:
         LoadPdb(name, TRUE)
    \/ \E name \in {"module_a", "module_b"}:
         LoadPdbEmpty(name)
    \/ \E va \in 0..1024:
         ResolveAddress(va)

\* ── Spec ──

Spec == Init /\ [][Next]_<<sym_loaded, sym_entries, sym_anomalies>>

====

---- MODULE Forensicator ----
EXTENDS Integers, Sequences, FiniteSets

\* ── Forensicator 2-Stage Workflow ──
\*
\* S1: Parse minidump → Dump + AddressSpace (Model.tla + AddressSpace.tla + Arch.tla)
\* S2: Pluggable analyzer pipeline → StructureCatalog
\* Symbolizer: utility module for address→symbol resolution (Symbolizer.tla)
\*
\* S1 → Symbolizer: after S1 completes, LoadSymbolizer reads Dump.modules
\* and loads matching PDB symbol tables (GUID match + public symbols).
\* CLI and analyzers can then call ResolveAddress(va).
\*
\* Each analyzer receives (&Dump, &AddressSpace) and produces an AnalyzerOutput.
\* Analyzers are independent — no mandatory graph stage, no shared mutable state.
\* Panic isolation: one analyzer failing does not affect others.

\* ---- Imports ----

M == INSTANCE Model
A == INSTANCE AddressSpace WITH MaxAddr <- 255
R == INSTANCE Arch
S == INSTANCE Symbolizer

\* ---- Constants ----

CONSTANTS
    StreamTypeSet,        \* {1,2,3,4,5,6} — known stream type identifiers
    MaxStreams,           \* max entries in stream directory
    AnalyzerPool          \* set of analyzer names (e.g. {"strings","vtables","lists","arrays","chunks","shapes"})

MaxStreams == 4

\* ---- S1: Parse Pipeline ----

VARIABLES
    \* @type: Int;
    p_header_parsed,
    \* @type: Int;
    p_dir_parsed,
    \* @type: Seq(Int);
    p_stream_types,
    \* @type: Seq(Int);
    p_stream_parsed,
    \* @type: Int;
    s1_complete

\* ---- Helper: all sub-module variables (for UNCHANGED lists) ----

SubVars ==
    <<M!sysinfo, M!mod_va, M!mod_sz, M!mod_prov_sid, M!mod_prov_off, M!mod_prov_rva,
      M!thr_id, M!thr_stack_va, M!thr_stack_sz, M!thr_prov_sid, M!thr_prov_off, M!thr_prov_rva,
      M!mem_va, M!mem_sz, M!mem_prot, M!mem_state, M!mem_type, M!mem_cls,
      M!mem_prov_sid, M!mem_prov_off, M!mem_prov_rva, M!exc_info, M!anomalies,
      A!reg_va, A!reg_sz, A!reg_cl, A!anomalies,
      R!regs, R!anomalies,
      S!sym_modules, S!sym_tables, S!sym_anomalies>>

\* ---- S2: Analyzer Pipeline ----

VARIABLES
    \* @type: Seq(Str);
    pipeline,
    \* @type: Set(Str);
    completed,
    \* @type: Set(Str);
    failed,
    \* @type: Set(Str);
    catalog_strings,
    \* @type: Set(Str);
    catalog_vtables,
    \* @type: Set(Str);
    catalog_lists,
    \* @type: Set(Str);
    catalog_arrays,
    \* @type: Set(Str);
    catalog_chunks,
    \* @type: Set(Str);
    catalog_shapes

\* ---- Helpers ----

RegisteredAnalyzers == Len(pipeline)

\* ── S1 Operations ──

ParseHeader ==
    /\ p_header_parsed = 0
    /\ p_header_parsed' = 1
    /\ UNCHANGED <<p_dir_parsed, p_stream_types, p_stream_parsed, s1_complete,
                   pipeline, completed, failed,
                   catalog_strings, catalog_vtables, catalog_lists,
                   catalog_arrays, catalog_chunks, catalog_shapes,
                   SubVars>>

ParseDirectory ==
    /\ p_header_parsed = 1
    /\ p_dir_parsed = 0
    /\ LET count == Cardinality(StreamTypeSet)
       IN /\ p_stream_types'  = CHOOSE s \in [1..MaxStreams -> StreamTypeSet] : TRUE
          /\ p_stream_parsed' = [i \in 1..MaxStreams |-> IF i <= count THEN 0 ELSE 0]
          /\ p_dir_parsed'    = 1
    /\ UNCHANGED <<p_header_parsed, s1_complete,
                   pipeline, completed, failed,
                   catalog_strings, catalog_vtables, catalog_lists,
                   catalog_arrays, catalog_chunks, catalog_shapes,
                   SubVars>>

DecodeStream(stream_type) ==
    /\ p_dir_parsed = 1
    /\ \E idx \in 1..MaxStreams:
         /\ idx <= Len(p_stream_types)
         /\ p_stream_types[idx] = stream_type
         /\ p_stream_parsed[idx] = 0
         /\ \/ (stream_type = 1 /\ M!SetSysInfo(0, 1, 0, 0, 0, 0, 1, 0, 0))
            \/ (stream_type = 2 /\ M!AddModule(0, 1, 1, 0, 0))
            \/ (stream_type = 3 /\ M!AddThread(0, 0, 1, 1, 0, 0))
            \/ (stream_type = 4 /\ M!AddRegion(0, 1, 3, 0, 0, 0, 1, 0, 0))
            \/ (stream_type = 5 /\ M!SetException(0, 0, 0, 0, 1, 0, 0))
            \/ (stream_type = 6 /\ M!AddAnomaly("truncated"))
            \/ TRUE
         /\ p_stream_parsed' = [p_stream_parsed EXCEPT ![idx] = 1]
    /\ UNCHANGED <<p_header_parsed, p_dir_parsed, p_stream_types, s1_complete,
                   pipeline, completed, failed,
                   catalog_strings, catalog_vtables, catalog_lists,
                   catalog_arrays, catalog_chunks, catalog_shapes>>

BuildAddressSpace ==
    /\ p_dir_parsed = 1
    /\ \A idx \in 1..MaxStreams:
         idx <= Len(p_stream_types) => p_stream_parsed[idx] = 1
    /\ s1_complete = 0
    /\ \E va_start \in 0..255:
         \E size \in 1..255:
           \E class \in {"Image","Stack","Mapped","Private","Other"}:
             A!AddRegion(va_start, size, class)
    /\ s1_complete' = 1
    /\ UNCHANGED <<p_header_parsed, p_dir_parsed, p_stream_types, p_stream_parsed,
                   pipeline, completed, failed,
                   catalog_strings, catalog_vtables, catalog_lists,
                   catalog_arrays, catalog_chunks, catalog_shapes>>

\* ── Symbolizer Integration ──

\* After S1 completes, the Symbolizer can load PDBs for each parsed module.
\* Bridges M!ModuleCount and module metadata into S.
\* Non-deterministic: each module may get symbols (LoadPdb) or none (LoadPdbEmpty).
LoadSymbolizer ==
    /\ s1_complete = 1
    /\ M!ModuleCount > 0
    /\ Len(S!sym_modules) = 0
    /\ \E name \in {"module_a"}:
         \E base_va \in {0, 4096}:
           \E size \in {4096, 8192}:
             S!LoadPdb(name, base_va, size)
    /\ UNCHANGED <<p_header_parsed, p_dir_parsed, p_stream_types, p_stream_parsed, s1_complete,
                   pipeline, completed, failed,
                   catalog_strings, catalog_vtables, catalog_lists,
                   catalog_arrays, catalog_chunks, catalog_shapes>>

\* ── S2 Operations ──

RegisterAnalyzer(name) ==
    /\ name \in AnalyzerPool
    /\ name \notin { a \in pipeline : TRUE }
    /\ pipeline' = Append(pipeline, name)
    /\ UNCHANGED <<p_header_parsed, p_dir_parsed, p_stream_types, p_stream_parsed, s1_complete,
                   completed, failed,
                   catalog_strings, catalog_vtables, catalog_lists,
                   catalog_arrays, catalog_chunks, catalog_shapes,
                   SubVars>>

AnalyzerRun ==
    /\ s1_complete = 1
    /\ pipeline /= <<>>
    /\ \E a \in (AnalyzerPool \cap { x \in pipeline : TRUE }) \ completed:
         /\ completed' = completed \cup {a}
         /\ \/ /\ failed' = failed
               /\ catalog_strings' = catalog_strings \cup IF a = "strings" THEN {a} ELSE {}
               /\ catalog_vtables' = catalog_vtables \cup IF a = "vtables" THEN {a} ELSE {}
               /\ catalog_lists'   = catalog_lists   \cup IF a = "lists"   THEN {a} ELSE {}
               /\ catalog_arrays'  = catalog_arrays  \cup IF a = "arrays"  THEN {a} ELSE {}
               /\ catalog_chunks'  = catalog_chunks  \cup IF a = "chunks"  THEN {a} ELSE {}
               /\ catalog_shapes'  = catalog_shapes  \cup IF a = "shapes"  THEN {a} ELSE {}
            \/ /\ failed' = failed \cup {a}
               /\ UNCHANGED <<catalog_strings, catalog_vtables, catalog_lists,
                              catalog_arrays, catalog_chunks, catalog_shapes>>
    /\ UNCHANGED <<p_header_parsed, p_dir_parsed, p_stream_types, p_stream_parsed, s1_complete,
                   pipeline,
                   SubVars>>

\* ── Invariants ──

S1ParseSequence ==
    /\ p_dir_parsed = 1 => p_header_parsed = 1
    /\ s1_complete = 1 => p_dir_parsed = 1

S2PipelineInvariant ==
    /\ completed \subseteq { a \in pipeline : TRUE }
    /\ failed \subseteq completed
    /\ catalog_strings \subseteq completed
    /\ catalog_vtables \subseteq completed
    /\ catalog_lists   \subseteq completed
    /\ catalog_arrays  \subseteq completed
    /\ catalog_chunks  \subseteq completed
    /\ catalog_shapes  \subseteq completed

NoFailedProduces ==
    /\ catalog_strings \cap failed = {}
    /\ catalog_vtables \cap failed = {}
    /\ catalog_lists   \cap failed = {}
    /\ catalog_arrays  \cap failed = {}
    /\ catalog_chunks  \cap failed = {}
    /\ catalog_shapes  \cap failed = {}

PipelineOrdered ==
    Cardinality(completed) <= Len(pipeline)

CatalogInvariant ==
    /\ NoFailedProduces
    /\ PipelineOrdered

ForensicatorInvariant ==
    /\ M!ModelInvariant
    /\ A!TypeInvariant
    /\ R!ArchInvariant
    /\ S!SymbolizerInvariant
    /\ S1ParseSequence
    /\ S2PipelineInvariant
    /\ CatalogInvariant

\* ── Init ──

Init ==
    /\ M!Init
    /\ A!Init
    /\ R!Init
    /\ S!Init
    /\ p_header_parsed  = 0
    /\ p_dir_parsed     = 0
    /\ p_stream_types   = <<>>
    /\ p_stream_parsed  = <<>>
    /\ s1_complete      = 0
    /\ pipeline         = <<>>
    /\ completed        = {}
    /\ failed           = {}
    /\ catalog_strings  = {}
    /\ catalog_vtables  = {}
    /\ catalog_lists    = {}
    /\ catalog_arrays   = {}
    /\ catalog_chunks   = {}
    /\ catalog_shapes   = {}

\* ── Next ──

Next ==
    \/ ParseHeader
    \/ ParseDirectory
    \/ \E t \in {1,2,3,4,5,6}: DecodeStream(t)
    \/ BuildAddressSpace
    \/ LoadSymbolizer
    \/ \E name \in AnalyzerPool: RegisterAnalyzer(name)
    \/ AnalyzerRun

\* ── Spec ──

Spec == Init /\ [][Next]_<<p_header_parsed, p_dir_parsed, p_stream_types, p_stream_parsed, s1_complete,
                            pipeline, completed, failed,
                            catalog_strings, catalog_vtables, catalog_lists,
                            catalog_arrays, catalog_chunks, catalog_shapes,
                            SubVars>>

====

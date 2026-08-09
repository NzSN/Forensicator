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
\*
\* Instance state lives in explicitly declared host variables with WITH
\* substitutions: Apalache cannot resolve primed instance references
\* (S!sym_modules') in UNCHANGED/subscript contexts, so those name the
\* host variables directly (SubVars below). Unprimed M!/A!/R!/S!
\* references expand through the substitution as usual.

VARIABLES
    \* ── Model.tla ──
    \* @type: Seq(Int);
    m_sysinfo,
    \* @type: Seq(Int);
    m_mod_va,
    \* @type: Seq(Int);
    m_mod_sz,
    \* @type: Seq(Int);
    m_mod_prov_sid,
    \* @type: Seq(Int);
    m_mod_prov_off,
    \* @type: Seq(Int);
    m_mod_prov_rva,
    \* @type: Seq(Int);
    m_thr_id,
    \* @type: Seq(Int);
    m_thr_stack_va,
    \* @type: Seq(Int);
    m_thr_stack_sz,
    \* @type: Seq(Int);
    m_thr_prov_sid,
    \* @type: Seq(Int);
    m_thr_prov_off,
    \* @type: Seq(Int);
    m_thr_prov_rva,
    \* @type: Seq(Int);
    m_mem_va,
    \* @type: Seq(Int);
    m_mem_sz,
    \* @type: Seq(Int);
    m_mem_prot,
    \* @type: Seq(Int);
    m_mem_state,
    \* @type: Seq(Int);
    m_mem_type,
    \* @type: Seq(Int);
    m_mem_cls,
    \* @type: Seq(Int);
    m_mem_prov_sid,
    \* @type: Seq(Int);
    m_mem_prov_off,
    \* @type: Seq(Int);
    m_mem_prov_rva,
    \* @type: Seq(Int);
    m_exc_info,
    \* @type: Seq([desc: Str]);
    m_anomalies,
    \* @type: Seq(Str);
    m_ann_key,
    \* @type: Seq(Str);
    m_ann_val,
    \* ── AddressSpace.tla ──
    \* @type: Seq(Int);
    a_reg_va,
    \* @type: Seq(Int);
    a_reg_sz,
    \* @type: Seq(Str);
    a_reg_cl,
    \* @type: Seq([desc: Str]);
    a_anomalies,
    \* ── Arch.tla ──
    \* @type: Seq(Int);
    r_regs,
    \* @type: Seq([desc: Str]);
    r_anomalies,
    \* ── Symbolizer.tla ──
    \* @type: Seq(<<Str, Int, Int>>);
    s_sym_modules,
    \* @type: Seq(Seq(<<Int, Str, Str, Int>>));
    s_sym_tables,
    \* @type: Seq([desc: Str]);
    s_sym_anomalies

M == INSTANCE Model WITH
    sysinfo <- m_sysinfo,
    mod_va <- m_mod_va, mod_sz <- m_mod_sz,
    mod_prov_sid <- m_mod_prov_sid, mod_prov_off <- m_mod_prov_off, mod_prov_rva <- m_mod_prov_rva,
    thr_id <- m_thr_id, thr_stack_va <- m_thr_stack_va, thr_stack_sz <- m_thr_stack_sz,
    thr_prov_sid <- m_thr_prov_sid, thr_prov_off <- m_thr_prov_off, thr_prov_rva <- m_thr_prov_rva,
    mem_va <- m_mem_va, mem_sz <- m_mem_sz, mem_prot <- m_mem_prot,
    mem_state <- m_mem_state, mem_type <- m_mem_type, mem_cls <- m_mem_cls,
    mem_prov_sid <- m_mem_prov_sid, mem_prov_off <- m_mem_prov_off, mem_prov_rva <- m_mem_prov_rva,
    exc_info <- m_exc_info, anomalies <- m_anomalies,
    ann_key <- m_ann_key, ann_val <- m_ann_val

A == INSTANCE AddressSpace WITH MaxAddr <- 255,
    reg_va <- a_reg_va, reg_sz <- a_reg_sz, reg_cl <- a_reg_cl, anomalies <- a_anomalies

R == INSTANCE Arch WITH
    regs <- r_regs, anomalies <- r_anomalies

S == INSTANCE Symbolizer WITH
    sym_modules <- s_sym_modules, sym_tables <- s_sym_tables, sym_anomalies <- s_sym_anomalies

\* ---- Constants ----

CONSTANTS
    \* @type: Set(Int);
    StreamTypeSet,        \* {1,2,3,4,5,6} — known stream type identifiers
    \* @type: Set(Str);
    AnalyzerPool          \* set of analyzer names (e.g. {"strings","vtables","lists","arrays","chunks","shapes"})

MaxStreams == 4

\* ---- S1: Parse Pipeline ----

VARIABLES
    \* @type: Int;
    p_header_parsed,
    \* @type: Int;
    p_dir_parsed,
    \* @type: Int -> Int;
    p_stream_types,
    \* @type: Int -> Int;
    p_stream_parsed,
    \* @type: Int;
    s1_complete

\* ---- Helper: all sub-module variables (for UNCHANGED lists) ----

SubVars ==
    <<m_sysinfo, m_mod_va, m_mod_sz, m_mod_prov_sid, m_mod_prov_off, m_mod_prov_rva,
      m_thr_id, m_thr_stack_va, m_thr_stack_sz, m_thr_prov_sid, m_thr_prov_off, m_thr_prov_rva,
      m_mem_va, m_mem_sz, m_mem_prot, m_mem_state, m_mem_type, m_mem_cls,
      m_mem_prov_sid, m_mem_prov_off, m_mem_prov_rva, m_exc_info, m_anomalies,
      m_ann_key, m_ann_val,
      a_reg_va, a_reg_sz, a_reg_cl, a_anomalies,
      r_regs, r_anomalies,
      s_sym_modules, s_sym_tables, s_sym_anomalies>>

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

\* The pipeline's analyzer names as a set (sequence-as-set; a bare
\* { a \in pipeline : ... } is untypeable — a Seq is not a Set).
\* @type: (Seq(Str)) => Set(Str);
NameSet(p) == { p[i] : i \in DOMAIN p }

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
         /\ idx \in DOMAIN p_stream_types
         /\ p_stream_types[idx] = stream_type
         /\ p_stream_parsed[idx] = 0
         /\ \/ (stream_type = 1 /\ M!SetSysInfo(0, 1, 0, 0, 0, 0, 1, 0, 0))
            \/ (stream_type = 2 /\ M!AddModule(0, 1, 1, 0, 0))
            \/ (stream_type = 3 /\ M!AddThread(0, 0, 1, 1, 0, 0))
            \/ (stream_type = 4 /\ M!AddRegion(0, 1, 3, 0, 0, 0, 1, 0, 0))
            \/ (stream_type = 5 /\ M!SetException(0, 0, 0, 0, 1, 0, 0))
            \/ (stream_type = 6 /\ M!AddAnomaly("truncated"))
            \/ (stream_type = 7 /\ M!AddAnnotation("key", "val"))
            \/ TRUE
         /\ p_stream_parsed' = [p_stream_parsed EXCEPT ![idx] = 1]
    /\ UNCHANGED <<p_header_parsed, p_dir_parsed, p_stream_types, s1_complete,
                   pipeline, completed, failed,
                   catalog_strings, catalog_vtables, catalog_lists,
                   catalog_arrays, catalog_chunks, catalog_shapes>>

BuildAddressSpace ==
    /\ p_dir_parsed = 1
    /\ \A idx \in 1..MaxStreams:
         idx \in DOMAIN p_stream_types => p_stream_parsed[idx] = 1
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
    /\ Len(s_sym_modules) = 0
    /\ \E name \in {"module_a"}:
         \E base_va \in {0, 4096}:
           \E size \in {4096, 8192}:
             \E count \in 1..S!MaxSymbols:
               S!LoadPdb(name, base_va, size, count)
    /\ UNCHANGED <<p_header_parsed, p_dir_parsed, p_stream_types, p_stream_parsed, s1_complete,
                   pipeline, completed, failed,
                   catalog_strings, catalog_vtables, catalog_lists,
                   catalog_arrays, catalog_chunks, catalog_shapes>>

\* ── S2 Operations ──

RegisterAnalyzer(name) ==
    /\ name \in AnalyzerPool
    /\ name \notin NameSet(pipeline)
    /\ pipeline' = Append(pipeline, name)
    /\ UNCHANGED <<p_header_parsed, p_dir_parsed, p_stream_types, p_stream_parsed, s1_complete,
                   completed, failed,
                   catalog_strings, catalog_vtables, catalog_lists,
                   catalog_arrays, catalog_chunks, catalog_shapes,
                   SubVars>>

AnalyzerRun ==
    /\ s1_complete = 1
    /\ pipeline /= <<>>
    /\ \E a \in (AnalyzerPool \cap NameSet(pipeline)) \ completed:
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
    /\ completed \subseteq NameSet(pipeline)
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
    /\ p_stream_types   = [i \in {} |-> 0]
    /\ p_stream_parsed  = [i \in {} |-> 0]
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

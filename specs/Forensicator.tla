---- MODULE Forensicator ----
EXTENDS Integers, Sequences, FiniteSets

\* ── Forensicator 2-Stage Workflow ──
\*
\* S1: Parse minidump → Dump + AddressSpace (Model.tla + AddressSpace.tla + Arch.tla)
\* S2: Pluggable analyzer pipeline → StructureCatalog
\*
\* Each analyzer receives (&Dump, &AddressSpace) and produces an AnalyzerOutput.
\* Analyzers are independent — no mandatory graph stage, no shared mutable state.
\* Panic isolation: one analyzer failing does not affect others.

\* ---- Imports ----

M == INSTANCE Model
A == INSTANCE AddressSpace WITH MaxAddr <- 255
R == INSTANCE Arch

\* ---- S1: Parse Pipeline (mirrors Rust pipeline.rs::Forensicator::s1) ----

\* P_* variables track the parse stream state (header → directory → per-stream decoders).
\* Once all streams are parsed, S1 output is assembled from M + A + R.

CONSTANTS
    StreamTypeSet,        \* {1,2,3,4,5,6} — known stream type identifiers
    MaxStreams            \* max entries in stream directory

MaxStreams == 4

VARIABLES
    \* @type: Int;
    p_header_parsed,      \* 0=not yet, 1=parsed
    \* @type: Int;
    p_dir_parsed,         \* 0=not yet, 1=parsed
    \* @type: Seq(Int);
    p_stream_types,       \* stream types found in directory
    \* @type: Seq(Int);
    p_stream_parsed,      \* per-stream: 0=pending, 1=parsed

    \* ── S1 output: assembled from M + A + R ──
    \* @type: Int;
    s1_complete           \* 0=not yet, 1=S1 output ready

\* ---- S2: Analyzer Pipeline ----

\* Each analyzer is identified by a name (string literal).
\* Pipeline holds an ordered set of registered analyzers.
\* Each analyzer produces output independent of others.

CONSTANTS
    AnalyzerPool          \* set of analyzer names (e.g. {"strings","vtables","lists","arrays","chunks","shapes"})

VARIABLES
    \* @type: Seq(Str);
    pipeline,             \* ordered list: registered analyzer names
    \* @type: Set(Str);
    completed,            \* analyzers that have finished (success or failure)
    \* @type: Set(Str);
    failed,               \* analyzers that panicked
    \* @type: Set(Str);
    catalog_strings,      \* analyzers that produced string results
    \* @type: Set(Str);
    catalog_vtables,      \* analyzers that produced vtable results
    \* @type: Set(Str);
    catalog_lists,        \* analyzers that produced linked-list results
    \* @type: Set(Str);
    catalog_arrays,       \* analyzers that produced array results
    \* @type: Set(Str);
    catalog_chunks,       \* analyzers that produced chunk results
    \* @type: Set(Str);
    catalog_shapes        \* analyzers that produced shape-cluster results

\* ---- Helpers ----

RegisteredAnalyzers == Len(pipeline)

Filtered(analyzers, filter) ==
    IF filter = {}
    THEN analyzers
    ELSE { a \in analyzers : a \in filter }

RunNext(analyzers) ==
    LET candidates == { a \in AnalyzerPool :
                          a \in pipeline /\ a \notin completed }
    IN IF candidates = {}
       THEN TRUE                        \* nothing left to run
       ELSE \E a \in candidates:
              LET ran_panic == a \in failed
              IN  /\ completed'  = completed \cup {a}
                  /\ IF ran_panic
                     THEN failed' = failed \cup {a}
                     ELSE failed' = failed
                  /\ UNCHANGED <<catalog_strings, catalog_vtables, catalog_lists,
                                 catalog_arrays, catalog_chunks, catalog_shapes>>

\* ── S1 Operations ──

ParseHeader ==
    /\ p_header_parsed = 0
    /\ p_header_parsed' = 1
    /\ UNCHANGED <<p_dir_parsed, p_stream_types, p_stream_parsed, s1_complete,
                   pipeline, completed, failed,
                   catalog_strings, catalog_vtables, catalog_lists,
                   catalog_arrays, catalog_chunks, catalog_shapes,
                   M!sysinfo, M!mod_va, M!mod_sz, M!mod_prov_sid, M!mod_prov_off, M!mod_prov_rva,
                   M!thr_id, M!thr_stack_va, M!thr_stack_sz, M!thr_prov_sid, M!thr_prov_off, M!thr_prov_rva,
                   M!mem_va, M!mem_sz, M!mem_prot, M!mem_state, M!mem_type, M!mem_cls,
                   M!mem_prov_sid, M!mem_prov_off, M!mem_prov_rva, M!exc_info, M!anomalies,
                   A!reg_va, A!reg_sz, A!reg_cl, A!anomalies,
                   R!regs, R!anomalies>>

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
                   M!sysinfo, M!mod_va, M!mod_sz, M!mod_prov_sid, M!mod_prov_off, M!mod_prov_rva,
                   M!thr_id, M!thr_stack_va, M!thr_stack_sz, M!thr_prov_sid, M!thr_prov_off, M!thr_prov_rva,
                   M!mem_va, M!mem_sz, M!mem_prot, M!mem_state, M!mem_type, M!mem_cls,
                   M!mem_prov_sid, M!mem_prov_off, M!mem_prov_rva, M!exc_info, M!anomalies,
                   A!reg_va, A!reg_sz, A!reg_cl, A!anomalies,
                   R!regs, R!anomalies>>

\* Decode one pending stream. Types: 1=SystemInfo, 2=Module, 3=Thread, 4=Memory, 5=Exception, 6=Anomaly
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

\* All streams parsed → build AddressSpace → S1 complete.
\* Transfers Model memory regions into AddressSpace non-deterministically.
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

\* ── S2 Operations ──

\* Register an analyzer into the pipeline. Must happen before running.
RegisterAnalyzer(name) ==
    /\ name \in AnalyzerPool
    /\ name \notin { a \in pipeline : TRUE }
    /\ pipeline' = Append(pipeline, name)
    /\ UNCHANGED <<p_header_parsed, p_dir_parsed, p_stream_types, p_stream_parsed, s1_complete,
                   completed, failed,
                   catalog_strings, catalog_vtables, catalog_lists,
                   catalog_arrays, catalog_chunks, catalog_shapes,
                   M!sysinfo, M!mod_va, M!mod_sz, M!mod_prov_sid, M!mod_prov_off, M!mod_prov_rva,
                   M!thr_id, M!thr_stack_va, M!thr_stack_sz, M!thr_prov_sid, M!thr_prov_off, M!thr_prov_rva,
                   M!mem_va, M!mem_sz, M!mem_prot, M!mem_state, M!mem_type, M!mem_cls,
                   M!mem_prov_sid, M!mem_prov_off, M!mem_prov_rva, M!exc_info, M!anomalies,
                   A!reg_va, A!reg_sz, A!reg_cl, A!anomalies,
                   R!regs, R!anomalies>>

\* Run all registered analyzers (no filter — runs everything). Each analyzer can produce typed output.
AnalyzerRun ==
    /\ s1_complete = 1
    /\ pipeline /= <<>>
    /\ \E a \in (AnalyzerPool \cap { x \in pipeline : TRUE }) \ completed:
         /\ completed' = completed \cup {a}
         \* Non-deterministically: analyzer may produce results of any type, or panic
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
                   M!sysinfo, M!mod_va, M!mod_sz, M!mod_prov_sid, M!mod_prov_off, M!mod_prov_rva,
                   M!thr_id, M!thr_stack_va, M!thr_stack_sz, M!thr_prov_sid, M!thr_prov_off, M!thr_prov_rva,
                   M!mem_va, M!mem_sz, M!mem_prot, M!mem_state, M!mem_type, M!mem_cls,
                   M!mem_prov_sid, M!mem_prov_off, M!mem_prov_rva, M!exc_info, M!anomalies,
                   A!reg_va, A!reg_sz, A!reg_cl, A!anomalies,
                   R!regs, R!anomalies>>

\* ── Invariants ──

\* S1 invariants
S1ParseSequence ==
    /\ p_dir_parsed = 1 => p_header_parsed = 1
    /\ s1_complete = 1 => p_dir_parsed = 1

\* S2 invariants
S2PipelineInvariant ==
    /\ completed \subseteq { a \in pipeline : TRUE }
    /\ failed \subseteq completed
    /\ catalog_strings \subseteq completed
    /\ catalog_vtables \subseteq completed
    /\ catalog_lists   \subseteq completed
    /\ catalog_arrays  \subseteq completed
    /\ catalog_chunks  \subseteq completed
    /\ catalog_shapes  \subseteq completed

\* An analyzer cannot both fail and produce output
NoFailedProduces ==
    /\ catalog_strings \cap failed = {}
    /\ catalog_vtables \cap failed = {}
    /\ catalog_lists   \cap failed = {}
    /\ catalog_arrays  \cap failed = {}
    /\ catalog_chunks  \cap failed = {}
    /\ catalog_shapes  \cap failed = {}

\* Pipeline ordering: analyzers complete <= registration count
PipelineOrdered ==
    Cardinality(completed) <= Len(pipeline)

\* ── Structural catalog integrity ──

\* Each analyzer produces at most 1 entry per output type
\* (Since each analyzer runs exactly once in completed, and each
\*  catalog_* set records which analyzers contributed that type)

CatalogInvariant ==
    /\ NoFailedProduces
    /\ PipelineOrdered

ForensicatorInvariant ==
    /\ M!ModelInvariant
    /\ A!TypeInvariant
    /\ R!ArchInvariant
    /\ S1ParseSequence
    /\ S2PipelineInvariant
    /\ CatalogInvariant

\* ── Init ──

Init ==
    /\ M!Init
    /\ A!Init
    /\ R!Init
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
    \/ \E name \in AnalyzerPool: RegisterAnalyzer(name)
    \/ AnalyzerRun

\* ── Spec ──

Spec == Init /\ [][Next]_<<p_header_parsed, p_dir_parsed, p_stream_types, p_stream_parsed, s1_complete,
                            pipeline, completed, failed,
                            catalog_strings, catalog_vtables, catalog_lists,
                            catalog_arrays, catalog_chunks, catalog_shapes,
                            M!sysinfo, M!mod_va, M!mod_sz, M!mod_prov_sid, M!mod_prov_off, M!mod_prov_rva,
                            M!thr_id, M!thr_stack_va, M!thr_stack_sz, M!thr_prov_sid, M!thr_prov_off, M!thr_prov_rva,
                            M!mem_va, M!mem_sz, M!mem_prot, M!mem_state, M!mem_type, M!mem_cls,
                            M!mem_prov_sid, M!mem_prov_off, M!mem_prov_rva, M!exc_info, M!anomalies,
                            A!reg_va, A!reg_sz, A!reg_cl, A!anomalies,
                            R!regs, R!anomalies>>

====

---- MODULE Root ----
EXTENDS Integers, Sequences, FiniteSets

VARIABLES
    \* @type: Seq(Int);
    a_regs,
    \* @type: Seq([desc: Str]);
    a_anomalies,
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
    \* @type: Seq(Int);
    s_reg_va,
    \* @type: Seq(Int);
    s_reg_sz,
    \* @type: Seq(Str);
    s_reg_cl,
    \* @type: Seq([desc: Str]);
    s_anomalies,
    \* @type: Str;
    p_phase,
    \* @type: Str;
    p_fatal_error,
    \* @type: Seq(Int);
    p_raw_streams,
    \* @type: Seq(Int);
    p_sysinfo_out,
    \* @type: Seq(Int);
    p_mod_va,
    \* @type: Seq(Int);
    p_mod_sz,
    \* @type: Seq(Int);
    p_mod_prov_sid,
    \* @type: Seq(Int);
    p_mod_prov_off,
    \* @type: Seq(Int);
    p_mod_prov_rva,
    \* @type: Seq(Int);
    p_thr_id,
    \* @type: Seq(Int);
    p_thr_stack_va,
    \* @type: Seq(Int);
    p_thr_stack_sz,
    \* @type: Seq(Int);
    p_thr_prov_sid,
    \* @type: Seq(Int);
    p_thr_prov_off,
    \* @type: Seq(Int);
    p_thr_prov_rva,
    \* @type: Seq(Int);
    p_mem_va,
    \* @type: Seq(Int);
    p_mem_sz,
    \* @type: Seq(Int);
    p_mem_prot,
    \* @type: Seq(Int);
    p_mem_state,
    \* @type: Seq(Int);
    p_mem_type,
    \* @type: Seq(Int);
    p_mem_cls,
    \* @type: Seq(Int);
    p_mem_prov_sid,
    \* @type: Seq(Int);
    p_mem_prov_off,
    \* @type: Seq(Int);
    p_mem_prov_rva,
    \* @type: Seq(Int);
    p_exc_info,
    \* @type: Seq(Int);
    p_dump_built,
    \* @type: Seq([desc: Str]);
    p_anomalies

A == INSTANCE Arch WITH regs <- a_regs, anomalies <- a_anomalies
S == INSTANCE AddressSpace WITH reg_va <- s_reg_va, reg_sz <- s_reg_sz, reg_cl <- s_reg_cl, anomalies <- s_anomalies
\* ParsePipeline carries Model via internal INSTANCE — no separate M needed.
P == INSTANCE ParsePipeline WITH
    phase <- p_phase, fatal_error <- p_fatal_error, raw_streams <- p_raw_streams,
    sysinfo_out <- p_sysinfo_out,
    mod_va <- p_mod_va, mod_sz <- p_mod_sz,
    mod_prov_sid <- p_mod_prov_sid, mod_prov_off <- p_mod_prov_off, mod_prov_rva <- p_mod_prov_rva,
    thr_id <- p_thr_id, thr_stack_va <- p_thr_stack_va, thr_stack_sz <- p_thr_stack_sz,
    thr_prov_sid <- p_thr_prov_sid, thr_prov_off <- p_thr_prov_off, thr_prov_rva <- p_thr_prov_rva,
    mem_va <- p_mem_va, mem_sz <- p_mem_sz,
    mem_prot <- p_mem_prot, mem_state <- p_mem_state, mem_type <- p_mem_type, mem_cls <- p_mem_cls,
    mem_prov_sid <- p_mem_prov_sid, mem_prov_off <- p_mem_prov_off, mem_prov_rva <- p_mem_prov_rva,
    exc_info <- p_exc_info, dump_built <- p_dump_built, anomalies <- p_anomalies

Init == A!Init /\ S!Init /\ P!Init

Next == \/ A!Next /\ UNCHANGED <<s_reg_va, s_reg_sz, s_reg_cl, s_anomalies, p_phase, p_fatal_error, p_raw_streams, p_sysinfo_out, p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva, p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva, p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls, p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva, p_exc_info, p_dump_built, p_anomalies>>
        \/ S!Next /\ UNCHANGED <<a_regs, a_anomalies, p_phase, p_fatal_error, p_raw_streams, p_sysinfo_out, p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva, p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva, p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls, p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva, p_exc_info, p_dump_built, p_anomalies>>
        \/ P!Next /\ UNCHANGED <<a_regs, a_anomalies, s_reg_va, s_reg_sz, s_reg_cl, s_anomalies>>

Vars == <<a_regs, a_anomalies, s_reg_va, s_reg_sz, s_reg_cl, s_anomalies, p_phase, p_fatal_error, p_raw_streams, p_sysinfo_out, p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva, p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva, p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls, p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva, p_exc_info, p_dump_built, p_anomalies>>

Spec == Init /\ [][Next]_Vars

RootInvariant ==
    /\ A!ArchInvariant
    /\ S!TypeInvariant
    /\ S!ClassifyTotal
    /\ P!PipelineInvariant

====

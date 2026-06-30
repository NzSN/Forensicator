---- MODULE Forensicator ----
EXTENDS Integers, Sequences, FiniteSets

VARIABLES
    \* @type: Seq(Int);
    a_regs,
    \* @type: Seq([desc: Str]);
    a_anomalies,
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
    p_anomalies,
    \* @type: Seq(Int);
    g_node_va,
    \* @type: Seq(Int);
    g_node_cls,
    \* @type: Seq(Int);
    g_node_root,
    \* @type: Seq(Int);
    g_edge_from,
    \* @type: Seq(Int);
    g_edge_to,
    \* @type: Seq(Int);
    g_edge_conf,
    \* @type: Str;
    g_phase,
    \* @type: Seq(Int);
    r_str_va,
    \* @type: Seq(Int);
    r_str_enc,
    \* @type: Seq(Int);
    r_str_conf,
    \* @type: Seq(Int);
    r_vtable_va,
    \* @type: Seq(Int);
    r_vtable_cnt,
    \* @type: Seq(Int);
    r_vtable_conf,
    \* @type: Seq(Int);
    r_list_head,
    \* @type: Seq(Int);
    r_list_len,
    \* @type: Seq(Int);
    r_list_conf,
    \* @type: Seq(Int);
    r_arr_start,
    \* @type: Seq(Int);
    r_arr_esz,
    \* @type: Seq(Int);
    r_arr_cnt,
    \* @type: Seq(Int);
    r_arr_conf,
    \* @type: Seq(Int);
    r_chunk_va,
    \* @type: Seq(Int);
    r_chunk_sz,
    \* @type: Seq(Int);
    r_chunk_free,
    \* @type: Seq(Int);
    r_chunk_conf,
    \* @type: Seq(Int);
    r_shape_id,
    \* @type: Seq(Int);
    r_shape_cnt

R == INSTANCE Recover WITH
    r_str_va <- r_str_va, r_str_enc <- r_str_enc, r_str_conf <- r_str_conf,
    r_vtable_va <- r_vtable_va, r_vtable_cnt <- r_vtable_cnt, r_vtable_conf <- r_vtable_conf,
    r_list_head <- r_list_head, r_list_len <- r_list_len, r_list_conf <- r_list_conf,
    r_arr_start <- r_arr_start, r_arr_esz <- r_arr_esz, r_arr_cnt <- r_arr_cnt, r_arr_conf <- r_arr_conf,
    r_chunk_va <- r_chunk_va, r_chunk_sz <- r_chunk_sz, r_chunk_free <- r_chunk_free, r_chunk_conf <- r_chunk_conf,
    r_shape_id <- r_shape_id, r_shape_cnt <- r_shape_cnt

G == INSTANCE PointerGraph WITH
    node_va <- g_node_va, node_cls <- g_node_cls, node_root <- g_node_root,
    edge_from <- g_edge_from, edge_to <- g_edge_to, edge_conf <- g_edge_conf

A == INSTANCE Arch WITH regs <- a_regs, anomalies <- a_anomalies
S == INSTANCE AddressSpace WITH reg_va <- s_reg_va, reg_sz <- s_reg_sz, reg_cl <- s_reg_cl, anomalies <- s_anomalies, MaxAddr <- 256
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

\* ---- Helpers ----

\* Map Model.tla classification integer (0=Image..4=Other) to AddressSpace string.
ClassToStr(cls) ==
    CASE cls = 0 -> "Image"
      [] cls = 1 -> "Stack"
      [] cls = 2 -> "Mapped"
      [] cls = 3 -> "Private"
      [] OTHER  -> "Other"

\* ---- Address Space construction from parsed dump ----
\* Adds memory regions one at a time from ParsePipeline output (p_mem_*)
\* into AddressSpace (s_reg_*) via S!AddRegion. Once all are transferred,
\* sets p_phase to "Done".

BuildAddressSpace ==
    \/ /\ p_phase = "Built"
       /\ Len(s_reg_va) < Len(p_mem_va)
       /\ LET i == Len(s_reg_va) + 1
           IN S!AddRegion(p_mem_va[i], p_mem_sz[i], ClassToStr(p_mem_cls[i]))
       /\ UNCHANGED <<p_phase,
                      a_regs, a_anomalies,
                      p_fatal_error, p_raw_streams, p_sysinfo_out,
                      p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva,
                      p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva,
                      p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls,
                      p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva,
                      p_exc_info, p_dump_built, p_anomalies,
                      g_node_va, g_node_cls, g_node_root, g_edge_from, g_edge_to, g_edge_conf,
                      g_phase,
                      r_str_va, r_str_enc, r_str_conf, r_vtable_va, r_vtable_cnt, r_vtable_conf, r_list_head, r_list_len, r_list_conf, r_arr_start, r_arr_esz, r_arr_cnt, r_arr_conf, r_chunk_va, r_chunk_sz, r_chunk_free, r_chunk_conf, r_shape_id, r_shape_cnt>>
    \/ /\ p_phase = "Built"
       /\ Len(s_reg_va) = Len(p_mem_va)
       /\ p_phase' = "Done"
       /\ UNCHANGED <<s_reg_va, s_reg_sz, s_reg_cl, s_anomalies,
                      a_regs, a_anomalies,
                      p_fatal_error, p_raw_streams, p_sysinfo_out,
                      p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva,
                      p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva,
                      p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls,
                      p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva,
                      p_exc_info, p_dump_built, p_anomalies,
                       g_node_va, g_node_cls, g_node_root, g_edge_from, g_edge_to, g_edge_conf,
                      g_phase,
                      r_str_va, r_str_enc, r_str_conf, r_vtable_va, r_vtable_cnt, r_vtable_conf, r_list_head, r_list_len, r_list_conf, r_arr_start, r_arr_esz, r_arr_cnt, r_arr_conf, r_chunk_va, r_chunk_sz, r_chunk_free, r_chunk_conf, r_shape_id, r_shape_cnt>>

\* ---- Pointer Graph construction from parsed dump ----
\* Transfers nodes from model (p_mem_*) into the pointer graph one at a
\* time via G!AddNode, then non-deterministically adds edges between nodes
\* via G!AddEdge, then finalizes by marking g_phase = "Done".

BuildPointerGraph ==
    \/ /\ p_phase = "Done"
       /\ g_phase = "Idle"
       /\ Len(g_node_va) < Len(p_mem_va)
       /\ LET i == Len(g_node_va) + 1
           IN G!AddNode(p_mem_va[i], p_mem_cls[i], 0)
       /\ UNCHANGED <<g_phase,
                      a_regs, a_anomalies,
                      s_reg_va, s_reg_sz, s_reg_cl, s_anomalies,
                      p_phase, p_fatal_error, p_raw_streams, p_sysinfo_out,
                      p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva,
                      p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva,
                      p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls,
                      p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva,
                      p_exc_info, p_dump_built, p_anomalies,
                      r_str_va, r_str_enc, r_str_conf, r_vtable_va, r_vtable_cnt, r_vtable_conf, r_list_head, r_list_len, r_list_conf, r_arr_start, r_arr_esz, r_arr_cnt, r_arr_conf, r_chunk_va, r_chunk_sz, r_chunk_free, r_chunk_conf, r_shape_id, r_shape_cnt>>
    \/ /\ p_phase = "Done"
       /\ g_phase = "Idle"
       /\ Len(g_node_va) = Len(p_mem_va)
       /\ g_phase' = "Edges"
       /\ UNCHANGED <<g_node_va, g_node_cls, g_node_root, g_edge_from, g_edge_to, g_edge_conf,
                      a_regs, a_anomalies,
                      s_reg_va, s_reg_sz, s_reg_cl, s_anomalies,
                      p_phase, p_fatal_error, p_raw_streams, p_sysinfo_out,
                      p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva,
                      p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva,
                      p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls,
                      p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva,
                      p_exc_info, p_dump_built, p_anomalies,
                      r_str_va, r_str_enc, r_str_conf, r_vtable_va, r_vtable_cnt, r_vtable_conf, r_list_head, r_list_len, r_list_conf, r_arr_start, r_arr_esz, r_arr_cnt, r_arr_conf, r_chunk_va, r_chunk_sz, r_chunk_free, r_chunk_conf, r_shape_id, r_shape_cnt>>
    \/ /\ p_phase = "Done"
       /\ g_phase = "Edges"
       /\ Len(g_node_va) = Len(p_mem_va) /\ Len(g_node_va) > 0
        /\ Len(g_edge_from) < G!MaxEdges
       /\ \E src \in 1..Len(g_node_va):
          \E tgt \in 1..Len(g_node_va):
          \E conf \in 0..10:
            G!AddEdge(src, tgt, conf)
       /\ UNCHANGED <<g_phase,
                      a_regs, a_anomalies,
                      s_reg_va, s_reg_sz, s_reg_cl, s_anomalies,
                      p_phase, p_fatal_error, p_raw_streams, p_sysinfo_out,
                      p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva,
                      p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva,
                      p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls,
                      p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva,
                      p_exc_info, p_dump_built, p_anomalies,
                      r_str_va, r_str_enc, r_str_conf, r_vtable_va, r_vtable_cnt, r_vtable_conf, r_list_head, r_list_len, r_list_conf, r_arr_start, r_arr_esz, r_arr_cnt, r_arr_conf, r_chunk_va, r_chunk_sz, r_chunk_free, r_chunk_conf, r_shape_id, r_shape_cnt>>
    \/ /\ p_phase = "Done"
       /\ g_phase = "Edges"
       /\ g_phase' = "Done"
       /\ UNCHANGED <<g_node_va, g_node_cls, g_node_root, g_edge_from, g_edge_to, g_edge_conf,
                      a_regs, a_anomalies,
                      s_reg_va, s_reg_sz, s_reg_cl, s_anomalies,
                      p_phase, p_fatal_error, p_raw_streams, p_sysinfo_out,
                      p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva,
                      p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva,
                      p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls,
                      p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva,
                       p_exc_info, p_dump_built, p_anomalies,
                       r_str_va, r_str_enc, r_str_conf, r_vtable_va, r_vtable_cnt, r_vtable_conf, r_list_head, r_list_len, r_list_conf, r_arr_start, r_arr_esz, r_arr_cnt, r_arr_conf, r_chunk_va, r_chunk_sz, r_chunk_free, r_chunk_conf, r_shape_id, r_shape_cnt>>

\* ---- Structure Recovery from pointer graph ----
\* Feeds S1 (AddressSpace) and S2 (PointerGraph) data into S3 detectors.
\* Runs after the pointer graph is built (g_phase = "Done").

BuildRecoverCatalog ==
    \/ /\ g_phase = "Done"
       /\ Len(r_vtable_va) < R!MaxVTbls
       /\ \E i \in 1..Len(g_node_va):
            /\ g_node_cls[i] = 0
            /\ g_node_root[i] = 0
            /\ R!AddVTable(g_node_va[i], 3, 5)
       /\ UNCHANGED <<g_phase,
                      a_regs, a_anomalies,
                      s_reg_va, s_reg_sz, s_reg_cl, s_anomalies,
                      p_phase, p_fatal_error, p_raw_streams, p_sysinfo_out,
                      p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva,
                      p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva,
                      p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls,
                      p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva,
                      p_exc_info, p_dump_built, p_anomalies,
                      g_node_va, g_node_cls, g_node_root, g_edge_from, g_edge_to, g_edge_conf>>
    \/ /\ g_phase = "Done"
       /\ Len(g_edge_from) > 0
       /\ Len(r_list_head) < R!MaxLists
       /\ \E i \in 1..Len(g_node_va):
            /\ g_node_root[i] = 1
            /\ \E tgt \in 1..Len(g_node_va):
                 G!HasEdge(i, tgt)
            /\ R!AddList(g_node_va[i], 3, 5)
       /\ UNCHANGED <<g_phase,
                      a_regs, a_anomalies,
                      s_reg_va, s_reg_sz, s_reg_cl, s_anomalies,
                      p_phase, p_fatal_error, p_raw_streams, p_sysinfo_out,
                      p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva,
                      p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva,
                      p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls,
                      p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva,
                      p_exc_info, p_dump_built, p_anomalies,
                      g_node_va, g_node_cls, g_node_root, g_edge_from, g_edge_to, g_edge_conf>>
    \/ /\ g_phase = "Done"
       /\ Len(s_reg_va) > 0
       /\ Len(r_str_va) < R!MaxStrs
       /\ \E i \in 1..Len(s_reg_va):
            /\ R!AddString(s_reg_va[i], 0, 5)
       /\ UNCHANGED <<g_phase,
                      a_regs, a_anomalies,
                      s_reg_va, s_reg_sz, s_reg_cl, s_anomalies,
                      p_phase, p_fatal_error, p_raw_streams, p_sysinfo_out,
                      p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva,
                      p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva,
                      p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls,
                      p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva,
                      p_exc_info, p_dump_built, p_anomalies,
                      g_node_va, g_node_cls, g_node_root, g_edge_from, g_edge_to, g_edge_conf>>
    \/ /\ g_phase = "Done"
       /\ Len(g_node_va) >= 2
       /\ Len(r_arr_start) < R!MaxArrs
       /\ \E i \in 1..Len(g_node_va)-1:
            /\ g_node_va[i] < g_node_va[i+1]
            /\ g_node_cls[i] = g_node_cls[i+1]
            /\ R!AddArray(g_node_va[i], g_node_va[i+1] - g_node_va[i], 3, 5)
       /\ UNCHANGED <<g_phase,
                      a_regs, a_anomalies,
                      s_reg_va, s_reg_sz, s_reg_cl, s_anomalies,
                      p_phase, p_fatal_error, p_raw_streams, p_sysinfo_out,
                      p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva,
                      p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva,
                      p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls,
                      p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva,
                      p_exc_info, p_dump_built, p_anomalies,
                      g_node_va, g_node_cls, g_node_root, g_edge_from, g_edge_to, g_edge_conf>>

Init == A!Init /\ S!Init /\ P!Init /\ G!Init /\ R!Init /\ g_phase = "Idle"

Next == \/ A!Next /\ UNCHANGED <<s_reg_va, s_reg_sz, s_reg_cl, s_anomalies, p_phase, p_fatal_error, p_raw_streams, p_sysinfo_out, p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva, p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva, p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls, p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva, p_exc_info, p_dump_built, p_anomalies, g_node_va, g_node_cls, g_node_root, g_edge_from, g_edge_to, g_edge_conf, g_phase, r_str_va, r_str_enc, r_str_conf, r_vtable_va, r_vtable_cnt, r_vtable_conf, r_list_head, r_list_len, r_list_conf, r_arr_start, r_arr_esz, r_arr_cnt, r_arr_conf, r_chunk_va, r_chunk_sz, r_chunk_free, r_chunk_conf, r_shape_id, r_shape_cnt>>
        \/ S!Next /\ UNCHANGED <<a_regs, a_anomalies, p_phase, p_fatal_error, p_raw_streams, p_sysinfo_out, p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva, p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva, p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls, p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva, p_exc_info, p_dump_built, p_anomalies, g_node_va, g_node_cls, g_node_root, g_edge_from, g_edge_to, g_edge_conf, g_phase, r_str_va, r_str_enc, r_str_conf, r_vtable_va, r_vtable_cnt, r_vtable_conf, r_list_head, r_list_len, r_list_conf, r_arr_start, r_arr_esz, r_arr_cnt, r_arr_conf, r_chunk_va, r_chunk_sz, r_chunk_free, r_chunk_conf, r_shape_id, r_shape_cnt>>
        \/ P!Next /\ UNCHANGED <<a_regs, a_anomalies, s_reg_va, s_reg_sz, s_reg_cl, s_anomalies, g_node_va, g_node_cls, g_node_root, g_edge_from, g_edge_to, g_edge_conf, g_phase, r_str_va, r_str_enc, r_str_conf, r_vtable_va, r_vtable_cnt, r_vtable_conf, r_list_head, r_list_len, r_list_conf, r_arr_start, r_arr_esz, r_arr_cnt, r_arr_conf, r_chunk_va, r_chunk_sz, r_chunk_free, r_chunk_conf, r_shape_id, r_shape_cnt>>
        \/ G!Next /\ UNCHANGED <<a_regs, a_anomalies, s_reg_va, s_reg_sz, s_reg_cl, s_anomalies, p_phase, p_fatal_error, p_raw_streams, p_sysinfo_out, p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva, p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva, p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls, p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva, p_exc_info, p_dump_built, p_anomalies, g_phase, r_str_va, r_str_enc, r_str_conf, r_vtable_va, r_vtable_cnt, r_vtable_conf, r_list_head, r_list_len, r_list_conf, r_arr_start, r_arr_esz, r_arr_cnt, r_arr_conf, r_chunk_va, r_chunk_sz, r_chunk_free, r_chunk_conf, r_shape_id, r_shape_cnt>>
        \/ R!Next /\ UNCHANGED <<a_regs, a_anomalies, s_reg_va, s_reg_sz, s_reg_cl, s_anomalies, p_phase, p_fatal_error, p_raw_streams, p_sysinfo_out, p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva, p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva, p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls, p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva, p_exc_info, p_dump_built, p_anomalies, g_node_va, g_node_cls, g_node_root, g_edge_from, g_edge_to, g_edge_conf, g_phase>>
        \/ BuildAddressSpace
        \/ BuildPointerGraph
        \/ BuildRecoverCatalog

Vars == <<a_regs, a_anomalies, s_reg_va, s_reg_sz, s_reg_cl, s_anomalies, p_phase, p_fatal_error, p_raw_streams, p_sysinfo_out, p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva, p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva, p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls, p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva, p_exc_info, p_dump_built, p_anomalies, g_node_va, g_node_cls, g_node_root, g_edge_from, g_edge_to, g_edge_conf, g_phase, r_str_va, r_str_enc, r_str_conf, r_vtable_va, r_vtable_cnt, r_vtable_conf, r_list_head, r_list_len, r_list_conf, r_arr_start, r_arr_esz, r_arr_cnt, r_arr_conf, r_chunk_va, r_chunk_sz, r_chunk_free, r_chunk_conf, r_shape_id, r_shape_cnt>>

Spec == Init /\ [][Next]_Vars

RootInvariant ==
    /\ A!ArchInvariant
    /\ S!TypeInvariant
    /\ S!ClassifyTotal
    /\ P!PipelineInvariant
    /\ G!PointerGraphInvariant
    /\ R!RecoverInvariant

====

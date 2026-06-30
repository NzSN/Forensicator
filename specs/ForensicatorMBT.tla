---- MODULE ForensicatorMBT ----
EXTENDS Forensicator

\* MBT trace for the pipeline stages: S1 (parse) → S2 (graph) → S3 (recover).
\* Traces a deterministic sequential pipeline execution, not the full
\* concurrent interleaving of Forensicator.tla.

VARIABLES
    \* @type: Str;
    action_taken,
    \* @type: [va: Int, sz: Int, cls: Int, src: Int, tgt: Int, conf: Int, desc: Str];
    parameters

ActionNames ==
    { "Init", "AddSpaceRegion", "SpaceDone", "AddGraphNode", "EdgesPhase",
      "AddGraphEdge", "GraphDone" }

\* ---- View exposed to MirrorRust for state comparison ----

View ==
    [ s_reg_va    |-> s_reg_va,
      s_reg_sz    |-> s_reg_sz,
      s_reg_cl    |-> s_reg_cl,
      s_anomalies |-> s_anomalies,
      g_node_va   |-> g_node_va,
      g_node_cls  |-> g_node_cls,
      g_node_root |-> g_node_root,
      g_edge_from |-> g_edge_from,
      g_edge_to   |-> g_edge_to,
      g_edge_conf |-> g_edge_conf,
      g_phase     |-> g_phase,
      a_regs      |-> a_regs,
      a_anomalies |-> a_anomalies,
      p_phase     |-> p_phase,
      p_mem_va    |-> p_mem_va,
      p_mem_sz    |-> p_mem_sz,
      p_mem_cls   |-> p_mem_cls,
      p_thr_id    |-> p_thr_id,
      p_thr_stack_va |-> p_thr_stack_va,
      p_thr_stack_sz |-> p_thr_stack_sz,
      p_mod_va    |-> p_mod_va,
      p_mod_sz    |-> p_mod_sz,
      p_exc_info  |-> p_exc_info,
      p_anomalies |-> p_anomalies ]

\* ---- MBT Initial state: dump already parsed, everything empty ----

MBTInit ==
    /\ a_regs      = <<>>
    /\ a_anomalies = <<>>
    /\ s_reg_va    = <<>>
    /\ s_reg_sz    = <<>>
    /\ s_reg_cl    = <<>>
    /\ s_anomalies = <<>>
    /\ p_phase     = "Done"
    /\ p_fatal_error = "NULL"
    /\ p_raw_streams = <<>>
    /\ p_sysinfo_out = <<>>
    /\ p_mod_va    = <<>>
    /\ p_mod_sz    = <<>>
    /\ p_mod_prov_sid = <<>>
    /\ p_mod_prov_off = <<>>
    /\ p_mod_prov_rva = <<>>
    /\ p_thr_id    = <<>>
    /\ p_thr_stack_va = <<>>
    /\ p_thr_stack_sz = <<>>
    /\ p_thr_prov_sid = <<>>
    /\ p_thr_prov_off = <<>>
    /\ p_thr_prov_rva = <<>>
    /\ p_mem_va    = <<0, 128>>
    /\ p_mem_sz    = <<64, 64>>
    /\ p_mem_prot  = <<3, 3>>
    /\ p_mem_state = <<0, 0>>
    /\ p_mem_type  = <<0, 0>>
    /\ p_mem_cls   = <<1, 3>>
    /\ p_mem_prov_sid = <<1, 1>>
    /\ p_mem_prov_off = <<0, 0>>
    /\ p_mem_prov_rva = <<0, 0>>
    /\ p_exc_info  = <<>>
    /\ p_dump_built = <<>>
    /\ p_anomalies = <<>>
    /\ g_node_va   = <<>>
    /\ g_node_cls  = <<>>
    /\ g_node_root = <<>>
    /\ g_edge_from = <<>>
    /\ g_edge_to   = <<>>
    /\ g_edge_conf = <<>>
    /\ g_phase     = "Idle"
    /\ action_taken = "Init"
    /\ parameters = [desc |-> ""]

\* ---- MBT Trace: sequential pipeline execution ----
\* Wraps each Forensicator action with action_taken tracking.

MBTAddSpaceRegion ==
    /\ p_phase = "Done"
    /\ g_phase = "Idle"
    /\ Len(s_reg_va) < Len(p_mem_va)
    /\ LET i == Len(s_reg_va) + 1
        IN /\ S!AddRegion(p_mem_va[i], p_mem_sz[i], ClassToStr(p_mem_cls[i]))
           /\ action_taken' = "AddSpaceRegion"
           /\ parameters' = [ va |-> p_mem_va[i], sz |-> p_mem_sz[i],
                              cls |-> p_mem_cls[i], src |-> 0, tgt |-> 0, conf |-> 0,
                              desc |-> "region" ]
           /\ UNCHANGED <<g_phase, g_node_va, g_node_cls, g_node_root,
                           g_edge_from, g_edge_to, g_edge_conf,
                           a_regs, a_anomalies, p_phase,
                           p_fatal_error, p_raw_streams, p_sysinfo_out,
                           p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva,
                           p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva,
                           p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls,
                           p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva,
                           p_exc_info, p_dump_built, p_anomalies>>

MBTSpaceDone ==
    /\ p_phase = "Done"
    /\ Len(s_reg_va) = Len(p_mem_va)
    /\ action_taken' = "SpaceDone"
    /\ UNCHANGED <<s_reg_va, s_reg_sz, s_reg_cl, s_anomalies,
                   g_node_va, g_node_cls, g_node_root, g_edge_from, g_edge_to, g_edge_conf,
                   g_phase, a_regs, a_anomalies, p_phase,
                   p_fatal_error, p_raw_streams, p_sysinfo_out,
                   p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva,
                   p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva,
                   p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls,
                   p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva,
                   p_exc_info, p_dump_built, p_anomalies>>
    /\ parameters' = [ desc |-> "space_done" ]

MBTAddGraphNode ==
    /\ p_phase = "Done"
    /\ g_phase = "Idle"
    /\ Len(g_node_va) < Len(p_mem_va)
    /\ LET i == Len(g_node_va) + 1
        IN /\ G!AddNode(p_mem_va[i], p_mem_cls[i], 0)
           /\ action_taken' = "AddGraphNode"
           /\ parameters' = [ va |-> p_mem_va[i], sz |-> 0,
                              cls |-> p_mem_cls[i], src |-> 0, tgt |-> 0, conf |-> 0,
                              desc |-> "node" ]
           /\ UNCHANGED <<g_phase,
                          s_reg_va, s_reg_sz, s_reg_cl, s_anomalies,
                          a_regs, a_anomalies, p_phase,
                          p_fatal_error, p_raw_streams, p_sysinfo_out,
                          p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva,
                          p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva,
                          p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls,
                          p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva,
                          p_exc_info, p_dump_built, p_anomalies>>

MBTEdgesPhase ==
    /\ p_phase = "Done"
    /\ Len(g_node_va) = Len(p_mem_va)
    /\ g_phase' = "Edges"
    /\ action_taken' = "EdgesPhase"
    /\ parameters' = [ desc |-> "edges_phase" ]
    /\ UNCHANGED <<s_reg_va, s_reg_sz, s_reg_cl, s_anomalies,
                   g_node_va, g_node_cls, g_node_root, g_edge_from, g_edge_to, g_edge_conf,
                   a_regs, a_anomalies, p_phase,
                   p_fatal_error, p_raw_streams, p_sysinfo_out,
                   p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva,
                   p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva,
                   p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls,
                   p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva,
                   p_exc_info, p_dump_built, p_anomalies>>

MBTAddGraphEdge ==
    /\ p_phase = "Done"
    /\ g_phase = "Edges"
    /\ Len(g_node_va) > 0
    /\ Len(g_edge_from) < G!MaxEdges
    /\ \E src \in 1..Len(g_node_va):
       \E tgt \in 1..Len(g_node_va):
       \E conf \in 0..10:
         /\ G!AddEdge(src, tgt, conf)
         /\ action_taken' = "AddGraphEdge"
         /\ parameters' = [ src |-> src, tgt |-> tgt, conf |-> conf,
                            va |-> 0, sz |-> 0, cls |-> 0, desc |-> "edge" ]
    /\ UNCHANGED <<g_phase,
                   s_reg_va, s_reg_sz, s_reg_cl, s_anomalies,
                   a_regs, a_anomalies, p_phase,
                   p_fatal_error, p_raw_streams, p_sysinfo_out,
                   p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva,
                   p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva,
                   p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls,
                   p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva,
                   p_exc_info, p_dump_built, p_anomalies>>

MBTGraphDone ==
    /\ p_phase = "Done"
    /\ g_phase = "Edges"
    /\ g_phase' = "Done"
    /\ action_taken' = "GraphDone"
    /\ parameters' = [ desc |-> "graph_done" ]
    /\ UNCHANGED <<s_reg_va, s_reg_sz, s_reg_cl, s_anomalies,
                   g_node_va, g_node_cls, g_node_root, g_edge_from, g_edge_to, g_edge_conf,
                   a_regs, a_anomalies, p_phase,
                   p_fatal_error, p_raw_streams, p_sysinfo_out,
                   p_mod_va, p_mod_sz, p_mod_prov_sid, p_mod_prov_off, p_mod_prov_rva,
                   p_thr_id, p_thr_stack_va, p_thr_stack_sz, p_thr_prov_sid, p_thr_prov_off, p_thr_prov_rva,
                   p_mem_va, p_mem_sz, p_mem_prot, p_mem_state, p_mem_type, p_mem_cls,
                   p_mem_prov_sid, p_mem_prov_off, p_mem_prov_rva,
                   p_exc_info, p_dump_built, p_anomalies>>

MBTNext ==
    \/ MBTAddSpaceRegion
    \/ MBTSpaceDone
    \/ MBTAddGraphNode
    \/ MBTEdgesPhase
    \/ MBTAddGraphEdge
    \/ MBTGraphDone

====

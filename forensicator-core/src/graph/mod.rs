use crate::error::Anomaly;
use crate::model::{
    EdgeIndex, GraphEdge, GraphNode, NodeIndex, PointerGraph,
    RegionClass, ScanResult, SourceContext, TargetContext,
};

pub fn build_graph(scan_result: &ScanResult) -> Result<PointerGraph, Anomaly> {
    let mut graph = PointerGraph::new();

    for c in &scan_result.candidates {
        insert_or_get_node(&mut graph, c.source_va, RegionClass::Other)?;
        insert_or_get_node(&mut graph, c.target_va, RegionClass::Other)?;
    }
    for root in &scan_result.roots {
        let va = root.va();
        insert_or_get_node(&mut graph, va, RegionClass::Other)?;
    }

    for c in &scan_result.candidates {
        let class = match c.target_ctx {
            TargetContext::Image => RegionClass::Image,
            TargetContext::Stack => RegionClass::Stack,
            TargetContext::Heap => RegionClass::Private,
            TargetContext::Mapped => RegionClass::Mapped,
            TargetContext::AnyReadable => RegionClass::Other,
        };
        if let Some(&idx) = graph.va_to_node.get(&c.target_va) {
            graph.nodes[idx.0].region_class = class;
        }
    }

    for c in &scan_result.candidates {
        let class = match c.source_ctx {
            SourceContext::Stack { .. } => RegionClass::Stack,
            SourceContext::Heap { .. } => RegionClass::Private,
            SourceContext::ModuleData { .. } => RegionClass::Image,
            SourceContext::Register { .. } | SourceContext::AnyCommitted => RegionClass::Other,
        };
        if let Some(&idx) = graph.va_to_node.get(&c.source_va) {
            if graph.nodes[idx.0].region_class == RegionClass::Other {
                graph.nodes[idx.0].region_class = class;
            }
        }
    }

    for c in &scan_result.candidates {
        let from = graph.va_to_node[&c.source_va];
        let to = graph.va_to_node[&c.target_va];

        if let Some(existing) = find_edge(&graph, from, to) {
            let edge = &mut graph.edges[existing.0];
            if c.confidence > edge.confidence {
                edge.confidence = c.confidence;
            }
            merge_string_vecs(&mut edge.evidence, &c.evidence);
            merge_string_vecs(&mut edge.matched_by, &c.matched_by);
        } else {
            if graph.edge_count() >= graph.max_edges() {
                return Err(Anomaly {
                    provenance: crate::error::Provenance {
                        stream_type: 0,
                        file_offset: 0,
                        rva: 0,
                    },
                    description: "edge capacity exceeded".into(),
                });
            }
            let edge_idx = EdgeIndex(graph.edges.len());
            graph.edges.push(GraphEdge {
                from,
                to,
                confidence: c.confidence,
                evidence: c.evidence.clone(),
                matched_by: c.matched_by.clone(),
            });
            graph.adj_out[from.0].push(edge_idx);
            graph.adj_in[to.0].push(edge_idx);
            graph.nodes[from.0].out_degree += 1;
            graph.nodes[to.0].in_degree += 1;
        }
    }

    for root in &scan_result.roots {
        let va = root.va();
        if let Some(&idx) = graph.va_to_node.get(&va) {
            if !graph.nodes[idx.0].is_root {
                graph.nodes[idx.0].is_root = true;
                graph.roots.push(idx);
            }
        }
    }

    Ok(graph)
}

fn insert_or_get_node(
    graph: &mut PointerGraph,
    va: u64,
    default_class: RegionClass,
) -> Result<NodeIndex, Anomaly> {
    if let Some(&idx) = graph.va_to_node.get(&va) {
        return Ok(idx);
    }
    if graph.node_count() >= graph.max_nodes() {
        return Err(Anomaly {
            provenance: crate::error::Provenance {
                stream_type: 0,
                file_offset: 0,
                rva: 0,
            },
            description: "node capacity exceeded".into(),
        });
    }
    let idx = NodeIndex(graph.nodes.len());
    graph.va_to_node.insert(va, idx);
    graph.nodes.push(GraphNode {
        va,
        region_class: default_class,
        out_degree: 0,
        in_degree: 0,
        is_root: false,
    });
    graph.adj_out.push(Vec::new());
    graph.adj_in.push(Vec::new());
    Ok(idx)
}

fn find_edge(graph: &PointerGraph, from: NodeIndex, to: NodeIndex) -> Option<EdgeIndex> {
    for &ei in &graph.adj_out[from.0] {
        if graph.edges[ei.0].to == to {
            return Some(ei);
        }
    }
    None
}

fn merge_string_vecs(target: &mut Vec<String>, source: &[String]) {
    for s in source {
        if !target.contains(s) {
            target.push(s.clone());
        }
    }
}

impl PointerGraph {
    pub fn edges_from(&self, node: NodeIndex) -> Vec<&GraphEdge> {
        if node.0 >= self.adj_out.len() {
            return vec![];
        }
        self.adj_out[node.0]
            .iter()
            .map(|&ei| &self.edges[ei.0])
            .collect()
    }

    pub fn edges_to(&self, node: NodeIndex) -> Vec<&GraphEdge> {
        if node.0 >= self.adj_in.len() {
            return vec![];
        }
        self.adj_in[node.0]
            .iter()
            .map(|&ei| &self.edges[ei.0])
            .collect()
    }

    pub fn iter_nodes(&self) -> impl Iterator<Item = &GraphNode> {
        self.nodes.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CandidatePointer, Root, SourceContext, TargetContext};

    fn make_candidate(source: u64, target: u64, conf: f64) -> CandidatePointer {
        CandidatePointer {
            source_va: source,
            value: target,
            target_va: target,
            source_ctx: SourceContext::AnyCommitted,
            target_ctx: TargetContext::AnyReadable,
            confidence: conf,
            matched_by: vec!["test".into()],
            evidence: vec!["aligned".into()],
        }
    }

    #[test]
    fn build_empty_scan_result() {
        let sr = ScanResult {
            candidates: vec![],
            roots: vec![],
        };
        let g = build_graph(&sr).unwrap();
        assert_eq!(g.node_count(), 0);
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn build_single_edge() {
        let c = make_candidate(0x1000, 0x2000, 0.8);
        let sr = ScanResult {
            candidates: vec![c],
            roots: vec![],
        };
        let g = build_graph(&sr).unwrap();
        assert_eq!(g.node_count(), 2);
        assert_eq!(g.edge_count(), 1);
        assert_eq!(g.nodes[0].va, 0x1000);
        assert_eq!(g.nodes[1].va, 0x2000);
        assert_eq!(g.nodes[0].out_degree, 1);
        assert_eq!(g.nodes[1].in_degree, 1);
    }

    #[test]
    fn node_deduplication() {
        let c1 = make_candidate(0x1000, 0x3000, 0.8);
        let c2 = make_candidate(0x2000, 0x3000, 0.9);
        let sr = ScanResult {
            candidates: vec![c1, c2],
            roots: vec![],
        };
        let g = build_graph(&sr).unwrap();
        assert_eq!(g.node_count(), 3);
        assert_eq!(g.edge_count(), 2);
    }

    #[test]
    fn edge_merge_on_duplicate() {
        let c1 = make_candidate(0x1000, 0x2000, 0.3);
        let c2 = {
            let mut c = make_candidate(0x1000, 0x2000, 0.7);
            c.evidence.push("canonical".into());
            c.matched_by.push("other".into());
            c
        };
        let sr = ScanResult {
            candidates: vec![c1, c2],
            roots: vec![],
        };
        let g = build_graph(&sr).unwrap();
        assert_eq!(g.edge_count(), 1);
        assert_eq!(g.edges[0].confidence, 0.7);
        assert!(g.edges[0].evidence.contains(&"aligned".to_string()));
        assert!(g.edges[0].evidence.contains(&"canonical".to_string()));
        assert!(g.edges[0].matched_by.contains(&"test".to_string()));
        assert!(g.edges[0].matched_by.contains(&"other".to_string()));
    }

    #[test]
    fn root_marking() {
        let c = make_candidate(0x1000, 0x2000, 0.8);
        let r = Root::Register {
            thread_id: 1,
            reg_name: "RIP".into(),
            va: 0x1000,
        };
        let sr = ScanResult {
            candidates: vec![c],
            roots: vec![r],
        };
        let g = build_graph(&sr).unwrap();
        assert_eq!(g.roots.len(), 1);
        assert!(g.nodes[g.roots[0].0].is_root);
        assert_eq!(g.nodes[g.roots[0].0].va, 0x1000);
    }

    #[test]
    fn root_inserted_even_without_candidates() {
        let sr = ScanResult {
            candidates: vec![],
            roots: vec![Root::Register {
                thread_id: 1,
                reg_name: "RIP".into(),
                va: 0x9999,
            }],
        };
        let g = build_graph(&sr).unwrap();
        assert_eq!(g.roots.len(), 1);
        assert_eq!(g.nodes[g.roots[0].0].va, 0x9999);
    }

    #[test]
    fn edges_from_and_edges_to() {
        let c = make_candidate(0x1000, 0x2000, 0.8);
        let sr = ScanResult {
            candidates: vec![c],
            roots: vec![],
        };
        let g = build_graph(&sr).unwrap();
        let n0 = g.va_to_node[&0x1000];
        let n1 = g.va_to_node[&0x2000];
        assert_eq!(g.edges_from(n0).len(), 1);
        assert_eq!(g.edges_to(n0).len(), 0);
        assert_eq!(g.edges_from(n1).len(), 0);
        assert_eq!(g.edges_to(n1).len(), 1);
    }

    #[test]
    fn iter_nodes_yields_all() {
        let c1 = make_candidate(0x1000, 0x2000, 0.8);
        let c2 = make_candidate(0x3000, 0x4000, 0.6);
        let sr = ScanResult {
            candidates: vec![c1, c2],
            roots: vec![],
        };
        let g = build_graph(&sr).unwrap();
        let vas: Vec<u64> = g.iter_nodes().map(|n| n.va).collect();
        assert!(vas.contains(&0x1000));
        assert!(vas.contains(&0x2000));
        assert!(vas.contains(&0x3000));
        assert!(vas.contains(&0x4000));
    }

    #[test]
    fn target_region_class_populated() {
        let c = CandidatePointer {
            source_va: 0x1000,
            value: 0x2000,
            target_va: 0x2000,
            source_ctx: SourceContext::AnyCommitted,
            target_ctx: TargetContext::Image,
            confidence: 0.5,
            matched_by: vec![],
            evidence: vec![],
        };
        let sr = ScanResult {
            candidates: vec![c],
            roots: vec![],
        };
        let g = build_graph(&sr).unwrap();
        let n1 = g.va_to_node[&0x2000];
        assert_eq!(g.nodes[n1.0].region_class, RegionClass::Image);
    }
}

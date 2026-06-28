use std::collections::HashMap;
use crate::model::{PointerGraph, RegionClass, ShapeClusters, ShapeGroup, ShapeSignature};
use crate::query::GraphQuery;
use crate::space::AddressSpace;

pub struct ShapeClusterer;

impl ShapeClusterer {
    pub fn cluster(_space: &AddressSpace, graph: &PointerGraph, _query: &GraphQuery) -> ShapeClusters {
        let mut sig_to_nodes: HashMap<ShapeSignature, Vec<u64>> = HashMap::new();
        for node in &graph.nodes {
            if node.region_class != RegionClass::Private || node.out_degree == 0 { continue; }
            let idx = graph.va_to_node[&node.va];
            let edges = graph.edges_from(idx);
            let mut sig_edges: Vec<(u64, RegionClass)> = edges.iter().map(|e| {
                let source_va = graph.nodes[e.from.0].va;
                let offset = source_va.wrapping_sub(node.va);
                let target_class = graph.nodes[e.to.0].region_class;
                (offset, target_class)
            }).collect();
            sig_edges.sort_by_key(|&(off, _)| off);
            sig_to_nodes.entry(ShapeSignature { edges: sig_edges }).or_default().push(node.va);
        }
        let mut groups: Vec<ShapeGroup> = sig_to_nodes.into_iter().enumerate().map(|(id, (sig, members))| {
            let count = members.len();
            ShapeGroup { id, signature: sig, member_count: count, members }
        }).collect();
        groups.sort_by(|a, b| b.member_count.cmp(&a.member_count));
        ShapeClusters { groups }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CandidatePointer, ScanResult, SourceContext, TargetContext};
    use crate::graph::build_graph;

    #[test]
    fn clusters_by_shape() {
        let c1 = CandidatePointer { source_va: 0x1000, value: 0x2000, target_va: 0x2000, source_ctx: SourceContext::Heap { region_va: None }, target_ctx: TargetContext::Heap, confidence: 0.8, matched_by: vec![], evidence: vec![] };
        let c2 = CandidatePointer { source_va: 0x1100, value: 0x3000, target_va: 0x3000, source_ctx: SourceContext::Heap { region_va: None }, target_ctx: TargetContext::Heap, confidence: 0.8, matched_by: vec![], evidence: vec![] };
        let t1 = CandidatePointer { source_va: 0x2000, value: 0, target_va: 0, source_ctx: SourceContext::Heap { region_va: None }, target_ctx: TargetContext::Heap, confidence: 0.5, matched_by: vec![], evidence: vec![] };
        let t2 = CandidatePointer { source_va: 0x3000, value: 0, target_va: 0, source_ctx: SourceContext::Heap { region_va: None }, target_ctx: TargetContext::Heap, confidence: 0.5, matched_by: vec![], evidence: vec![] };
        let g = build_graph(&ScanResult { candidates: vec![c1, c2, t1, t2], roots: vec![] }).unwrap();
        let clusters = ShapeClusterer::cluster(&AddressSpace::new(4), &g, &GraphQuery::new(&g));
        assert!(clusters.groups.iter().any(|g| g.member_count >= 2));
    }

    #[test]
    fn empty_graph() { assert!(ShapeClusterer::cluster(&AddressSpace::new(4), &PointerGraph::new(), &GraphQuery::new(&PointerGraph::new())).groups.is_empty()); }

    #[test]
    fn nodes_without_edges_excluded() {
        let c = CandidatePointer { source_va: 0x1000, value: 0, target_va: 0, source_ctx: SourceContext::Heap { region_va: None }, target_ctx: TargetContext::Heap, confidence: 0.5, matched_by: vec![], evidence: vec![] };
        let g = build_graph(&ScanResult { candidates: vec![c], roots: vec![] }).unwrap();
        assert!(ShapeClusterer::cluster(&AddressSpace::new(4), &g, &GraphQuery::new(&g)).groups.is_empty());
    }
}

use std::collections::HashSet;
use crate::model::{NodeIndex, PointerGraph, StructLinkedList};
use crate::query::GraphQuery;
use crate::recover::StructureDetector;
use crate::space::AddressSpace;

pub struct ListDetector {
    pub min_length: usize,
    pub min_confidence: f64,
    pub max_chain_length: usize,
}

impl Default for ListDetector {
    fn default() -> Self { ListDetector { min_length: 3, min_confidence: 0.4, max_chain_length: 10000 } }
}

impl StructureDetector for ListDetector {
    type Item = StructLinkedList;
    fn name(&self) -> &str { "lists" }
    fn detect(&self, _space: &AddressSpace, graph: &PointerGraph, _query: &GraphQuery) -> Vec<StructLinkedList> {
        let mut visited: HashSet<NodeIndex> = HashSet::new();
        let mut results = Vec::new();
        for (i, node) in graph.nodes.iter().enumerate() {
            let idx = NodeIndex(i);
            if visited.contains(&idx) || node.out_degree == 0 { continue; }
            let mut chain = vec![node.va];
            let mut current = idx;
            loop {
                let out = graph.edges_from(current);
                if out.is_empty() { break; }
                let best = out.iter().max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap());
                let Some(best_edge) = best else { break; };
                if best_edge.confidence < self.min_confidence { break; }
                if visited.contains(&best_edge.to) { break; }
                visited.insert(best_edge.to);
                chain.push(graph.nodes[best_edge.to.0].va);
                current = best_edge.to;
                if chain.len() >= self.max_chain_length { break; }
            }
            if chain.len() >= self.min_length {
                let stride = if chain.len() >= 2 { chain[1].wrapping_sub(chain[0]) } else { 0 };
                results.push(StructLinkedList { head_va: chain[0], length: chain.len(), stride, next_offset: 0, is_circular: false, nodes: chain, avg_confidence: 0.5 });
            }
            visited.insert(idx);
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CandidatePointer, ScanResult, SourceContext, TargetContext};
    use crate::graph::build_graph;

    fn make_list_graph() -> PointerGraph {
        let c1 = CandidatePointer { source_va: 0x1000, value: 0x1020, target_va: 0x1020, source_ctx: SourceContext::Heap { region_va: None }, target_ctx: TargetContext::Heap, confidence: 0.8, matched_by: vec![], evidence: vec![] };
        let c2 = CandidatePointer { source_va: 0x1020, value: 0x1040, target_va: 0x1040, source_ctx: SourceContext::Heap { region_va: None }, target_ctx: TargetContext::Heap, confidence: 0.8, matched_by: vec![], evidence: vec![] };
        build_graph(&ScanResult { candidates: vec![c1, c2], roots: vec![] }).unwrap()
    }

    #[test]
    fn detects_linked_list() {
        let g = make_list_graph();
        let query = GraphQuery::new(&g);
        let d = ListDetector::default();
        let lists = d.detect(&AddressSpace::new(4), &g, &query);
        assert!(!lists.is_empty());
    }

    #[test]
    fn empty_graph() {
        let g = PointerGraph::new();
        let query = GraphQuery::new(&g);
        assert!(ListDetector::default().detect(&AddressSpace::new(4), &g, &query).is_empty());
    }

    #[test]
    fn singleton_rejected() {
        let c = CandidatePointer { source_va: 0x1000, value: 0, target_va: 0, source_ctx: SourceContext::Heap { region_va: None }, target_ctx: TargetContext::Heap, confidence: 0.5, matched_by: vec![], evidence: vec![] };
        let g = build_graph(&ScanResult { candidates: vec![c], roots: vec![] }).unwrap();
        let query = GraphQuery::new(&g);
        assert!(ListDetector::default().detect(&AddressSpace::new(4), &g, &query).is_empty());
    }
}

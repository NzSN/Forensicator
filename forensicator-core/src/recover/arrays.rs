use crate::model::{PointerGraph, StructArray};
use crate::query::GraphQuery;
use crate::recover::StructureDetector;
use crate::space::AddressSpace;

pub struct ArrayDetector { pub min_count: usize, pub max_stride: u64 }
impl Default for ArrayDetector { fn default() -> Self { ArrayDetector { min_count: 3, max_stride: 4096 } } }

impl StructureDetector for ArrayDetector {
    type Item = StructArray;
    fn name(&self) -> &str { "arrays" }
    fn detect(&self, _space: &AddressSpace, graph: &PointerGraph, _query: &GraphQuery) -> Vec<StructArray> {
        if graph.node_count() < self.min_count { return vec![]; }
        let mut indices: Vec<usize> = (0..graph.node_count()).collect();
        indices.sort_by_key(|&i| graph.nodes[i].va);
        let mut results = Vec::new();
        let mut i = 0;
        while i + self.min_count <= indices.len() {
            let a = &graph.nodes[indices[i]];
            let b = &graph.nodes[indices[i+1]];
            if a.va >= b.va { i += 1; continue; }
            let stride = b.va - a.va;
            if stride > self.max_stride || stride == 0 { i += 1; continue; }
            if a.out_degree != b.out_degree || a.region_class != b.region_class { i += 1; continue; }
            let mut elements = vec![a.va, b.va];
            let mut j = i + 2;
            while j < indices.len() {
                let cur = &graph.nodes[indices[j]];
                if cur.va != *elements.last().unwrap() + stride { break; }
                if cur.out_degree != a.out_degree || cur.region_class != a.region_class { break; }
                elements.push(cur.va);
                j += 1;
            }
            if elements.len() >= self.min_count {
                let conf = if elements.len() >= 5 { 0.85 } else { 0.6 };
                results.push(StructArray { start_va: a.va, element_size: stride, count: elements.len(), out_degree: a.out_degree, region_class: a.region_class, elements, confidence: conf });
                i = j;
                continue;
            }
            i += 1;
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CandidatePointer, ScanResult, SourceContext, TargetContext};
    use crate::graph::build_graph;

    fn make_graph(stride: u64, count: usize) -> PointerGraph {
        let mut candidates = Vec::new();
        for i in 0..count {
            let va = 0x1000 + i as u64 * stride;
            candidates.push(CandidatePointer { source_va: va, value: va + stride, target_va: va + stride, source_ctx: SourceContext::Heap { region_va: None }, target_ctx: TargetContext::Heap, confidence: 0.7, matched_by: vec![], evidence: vec![] });
        }
        build_graph(&ScanResult { candidates, roots: vec![] }).unwrap()
    }

    #[test]
    fn detects_array() {
        let g = make_graph(0x20, 4);
        let a = ArrayDetector::default().detect(&AddressSpace::new(4), &g, &GraphQuery::new(&g));
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].count, 4);
    }

    #[test]
    fn too_few_rejected() { assert!(ArrayDetector::default().detect(&AddressSpace::new(4), &make_graph(0x10, 2), &GraphQuery::new(&make_graph(0x10,2))).is_empty()); }

    #[test]
    fn empty_graph() { assert!(ArrayDetector::default().detect(&AddressSpace::new(4), &PointerGraph::new(), &GraphQuery::new(&PointerGraph::new())).is_empty()); }
}

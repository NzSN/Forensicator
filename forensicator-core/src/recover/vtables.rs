use crate::model::{PointerGraph, RegionClass, StructVTable};
use crate::query::GraphQuery;
use crate::recover::StructureDetector;
use crate::space::AddressSpace;

pub struct VTableDetector {
    pub min_methods: usize,
    pub max_methods: usize,
}

impl Default for VTableDetector {
    fn default() -> Self { VTableDetector { min_methods: 3, max_methods: 256 } }
}

impl StructureDetector for VTableDetector {
    type Item = StructVTable;
    fn name(&self) -> &str { "vtables" }
    fn detect(&self, space: &AddressSpace, graph: &PointerGraph, _query: &GraphQuery) -> Vec<StructVTable> {
        let mut results = Vec::new();
        for region in space.regions() {
            if region.classification != RegionClass::Image { continue; }
            let data = &region.data;
            let mut offset = 0usize;
            'outer: while offset + 8 <= data.len() {
                let bytes: [u8; 8] = data[offset..offset+8].try_into().unwrap();
                let value = u64::from_le_bytes(bytes);
                if value == 0 { offset += 8; continue; }
                let is_code_ptr = graph.node(value).map(|n| n.region_class == RegionClass::Image).unwrap_or(false);
                if !is_code_ptr { offset += 8; continue; }
                let va = region.va_start + offset as u64;
                let mut methods: Vec<u64> = vec![value];
                let mut run_offset = offset + 8;
                while run_offset + 8 <= data.len() && methods.len() < self.max_methods {
                    let b: [u8; 8] = data[run_offset..run_offset+8].try_into().unwrap();
                    let v = u64::from_le_bytes(b);
                    if v == 0 { break; }
                    let is_ptr = graph.node(v).map(|n| n.region_class == RegionClass::Image).unwrap_or(false);
                    if !is_ptr { break; }
                    methods.push(v);
                    run_offset += 8;
                }
                if methods.len() >= self.min_methods {
                    results.push(StructVTable { va, method_count: methods.len(), methods, module_name: None, confidence: 0.8 });
                    offset = run_offset;
                    continue 'outer;
                }
                offset += 8;
            }
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CandidatePointer, MemState, ScanResult, SourceContext, TargetContext};
    use crate::graph::build_graph;
    use crate::space::{AddressRegion, AddressSpace};

    #[test]
    fn detects_vtable() {
        let mut space = AddressSpace::new(4);
        let mut data: Vec<u8> = Vec::new();
        for &ptr in &[0x401000u64, 0x402000, 0x403000, 0u64] { data.extend_from_slice(&ptr.to_le_bytes()); }
        space.add_region(AddressRegion { va_start: 0x400000, size: data.len() as u64, data, protection: 3, state: MemState::Commit, classification: RegionClass::Image }).unwrap();
        let candidates: Vec<CandidatePointer> = [0x401000u64, 0x402000, 0x403000].iter().map(|&va| CandidatePointer { source_va: 0x400000, value: va, target_va: va, source_ctx: SourceContext::ModuleData { module_name: None }, target_ctx: TargetContext::Image, confidence: 0.9, matched_by: vec![], evidence: vec![] }).collect();
        let sr = ScanResult { candidates, roots: vec![] };
        let graph = build_graph(&sr).unwrap();
        let query = GraphQuery::new(&graph);
        let d = VTableDetector::default();
        let vt = d.detect(&space, &graph, &query);
        assert_eq!(vt.len(), 1);
        assert_eq!(vt[0].method_count, 3);
    }

    #[test]
    fn empty_returns_empty() {
        let space = AddressSpace::new(4);
        let graph = PointerGraph::new();
        let query = GraphQuery::new(&graph);
        let d = VTableDetector::default();
        assert!(d.detect(&space, &graph, &query).is_empty());
    }

    #[test]
    fn too_few_methods_filtered() {
        let mut space = AddressSpace::new(4);
        let mut data: Vec<u8> = Vec::new();
        for &ptr in &[0x401000u64, 0u64] { data.extend_from_slice(&ptr.to_le_bytes()); }
        space.add_region(AddressRegion { va_start: 0, size: data.len() as u64, data, protection: 3, state: MemState::Commit, classification: RegionClass::Image }).unwrap();
        let candidates = vec![CandidatePointer { source_va: 0, value: 0x401000, target_va: 0x401000, source_ctx: SourceContext::ModuleData { module_name: None }, target_ctx: TargetContext::Image, confidence: 0.9, matched_by: vec![], evidence: vec![] }];
        let sr = ScanResult { candidates, roots: vec![] };
        let graph = build_graph(&sr).unwrap();
        let query = GraphQuery::new(&graph);
        let d = VTableDetector::default();
        assert!(d.detect(&space, &graph, &query).is_empty());
    }
}

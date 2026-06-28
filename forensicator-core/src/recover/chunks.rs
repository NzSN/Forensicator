use crate::model::{PointerGraph, RegionClass, StructChunk};
use crate::query::GraphQuery;
use crate::recover::StructureDetector;
use crate::space::AddressSpace;

pub struct ChunkDetector { pub min_chunk_size: u64, pub alignment: u64, pub density_gap_threshold: u64, pub zero_run_for_free: usize }
impl Default for ChunkDetector { fn default() -> Self { ChunkDetector { min_chunk_size: 16, alignment: 16, density_gap_threshold: 64, zero_run_for_free: 32 } } }

impl StructureDetector for ChunkDetector {
    type Item = StructChunk;
    fn name(&self) -> &str { "chunks" }
    fn detect(&self, space: &AddressSpace, graph: &PointerGraph, _query: &GraphQuery) -> Vec<StructChunk> {
        let mut results = Vec::new();
        for region in space.regions() {
            if region.classification != RegionClass::Private || region.size < self.min_chunk_size { continue; }
            let mut nodes_in_region: Vec<u64> = graph.nodes.iter().filter(|n| n.va >= region.va_start && n.va < region.va_start + region.size).map(|n| n.va).collect();
            nodes_in_region.sort();
            if nodes_in_region.is_empty() {
                let is_free = region.data.iter().take(self.zero_run_for_free).all(|&b| b == 0);
                results.push(StructChunk { va_start: region.va_start, size: region.size, is_free, node_count: 0, pointer_density: 0.0, confidence: if is_free { 0.8 } else { 0.3 } });
                continue;
            }
            let mut chunk_start = region.va_start;
            let mut prev_va = nodes_in_region[0];
            if prev_va > chunk_start + self.density_gap_threshold {
                results.push(StructChunk { va_start: chunk_start, size: prev_va - chunk_start, is_free: true, node_count: 0, pointer_density: 0.0, confidence: 0.7 });
                chunk_start = prev_va;
            }
            for &va in &nodes_in_region[1..] {
                if va - prev_va > self.density_gap_threshold {
                    let sz = (prev_va - chunk_start + 16).min(region.va_start + region.size - chunk_start);
                    results.push(StructChunk { va_start: chunk_start, size: sz, is_free: false, node_count: 1, pointer_density: 1.0 / sz as f64 * 1024.0, confidence: 0.6 });
                    chunk_start = va;
                }
                prev_va = va;
            }
            let sz = (prev_va - chunk_start + 16).min(region.va_start + region.size - chunk_start);
            results.push(StructChunk { va_start: chunk_start, size: sz, is_free: false, node_count: 1, pointer_density: 0.0, confidence: 0.5 });
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::MemState;
    use crate::space::{AddressRegion, AddressSpace};

    #[test]
    fn empty_heap_is_free() {
        let mut space = AddressSpace::new(4);
        space.add_region(AddressRegion { va_start: 0x10000, size: 64, data: vec![0u8; 64], protection: 3, state: MemState::Commit, classification: RegionClass::Private }).unwrap();
        let g = PointerGraph::new(); let q = GraphQuery::new(&g);
        let chunks = ChunkDetector::default().detect(&space, &g, &q);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].is_free);
    }

    #[test]
    fn skips_non_heap() {
        let mut space = AddressSpace::new(4);
        space.add_region(AddressRegion { va_start: 0, size: 64, data: vec![1u8; 64], protection: 3, state: MemState::Commit, classification: RegionClass::Image }).unwrap();
        let g = PointerGraph::new(); let q = GraphQuery::new(&g);
        assert!(ChunkDetector::default().detect(&space, &g, &q).is_empty());
    }

    #[test]
    fn empty_space() {
        let g = PointerGraph::new(); let q = GraphQuery::new(&g);
        assert!(ChunkDetector::default().detect(&AddressSpace::new(4), &g, &q).is_empty());
    }
}

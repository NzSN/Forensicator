use crate::analyzer::{Analyzer, AnalyzerOutput};
use crate::analyzer::scan::pointer_scan;
use crate::model::{CandidatePointer, Dump, RegionClass, StructChunk};
use crate::pattern::PointerPattern;
use crate::space::AddressSpace;

pub struct ChunkAnalyzer {
    pub min_chunk_size: u64,
    pub alignment: u64,
    pub density_gap_threshold: u64,
    pub zero_run_for_free: usize,
}

impl Default for ChunkAnalyzer {
    fn default() -> Self {
        ChunkAnalyzer {
            min_chunk_size: 16,
            alignment: 16,
            density_gap_threshold: 64,
            zero_run_for_free: 32,
        }
    }
}

impl Analyzer for ChunkAnalyzer {
    fn name(&self) -> &str { "chunks" }
    fn description(&self) -> &str { "Identifies heap allocation chunks by pointer density in Private regions" }

    fn analyze(&self, dump: &Dump, space: &AddressSpace) -> AnalyzerOutput {
        let mut out = AnalyzerOutput::new("chunks");
        let candidates = pointer_scan(space, dump, &[PointerPattern::heap_references()]);
        out.chunks = self.detect(space, &candidates);
        out
    }
}

impl ChunkAnalyzer {
    fn detect(&self, space: &AddressSpace, candidates: &[CandidatePointer]) -> Vec<StructChunk> {
        let mut results = Vec::new();
        for region in space.regions() {
            if region.classification != RegionClass::Private || region.size < self.min_chunk_size {
                continue;
            }
            let mut nodes_in_region: Vec<u64> = candidates
                .iter()
                .filter(|c| c.source_va >= region.va_start && c.source_va < region.va_start + region.size)
                .map(|c| c.source_va)
                .collect();
            nodes_in_region.sort();
            nodes_in_region.dedup();

            if nodes_in_region.is_empty() {
                let is_free = region.data.iter().take(self.zero_run_for_free).all(|&b| b == 0);
                results.push(StructChunk {
                    va_start: region.va_start,
                    size: region.size,
                    is_free,
                    node_count: 0,
                    pointer_density: 0.0,
                    confidence: if is_free { 0.8 } else { 0.3 },
                });
                continue;
            }

            let mut chunk_start = region.va_start;
            let mut prev_va = nodes_in_region[0];
            if prev_va > chunk_start + self.density_gap_threshold {
                results.push(StructChunk {
                    va_start: chunk_start,
                    size: prev_va - chunk_start,
                    is_free: true,
                    node_count: 0,
                    pointer_density: 0.0,
                    confidence: 0.7,
                });
                chunk_start = prev_va;
            }
            for &va in &nodes_in_region[1..] {
                if va - prev_va > self.density_gap_threshold {
                    let sz = (prev_va - chunk_start + 16)
                        .min(region.va_start + region.size - chunk_start);
                    results.push(StructChunk {
                        va_start: chunk_start,
                        size: sz,
                        is_free: false,
                        node_count: 1,
                        pointer_density: if sz > 0 { 1.0 / sz as f64 * 1024.0 } else { 0.0 },
                        confidence: 0.6,
                    });
                    chunk_start = va;
                }
                prev_va = va;
            }
            let sz = (prev_va - chunk_start + 16)
                .min(region.va_start + region.size - chunk_start);
            results.push(StructChunk {
                va_start: chunk_start,
                size: sz,
                is_free: false,
                node_count: 1,
                pointer_density: 0.0,
                confidence: 0.5,
            });
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
        space
            .add_region(AddressRegion {
                va_start: 0x10000,
                size: 64,
                data: vec![0u8; 64],
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Private,
            })
            .unwrap();
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            file_size: 0,
        };
        let a = ChunkAnalyzer::default();
        let out = a.analyze(&dump, &space);
        assert_eq!(out.chunks.len(), 1);
        assert!(out.chunks[0].is_free);
    }

    #[test]
    fn skips_non_heap() {
        let mut space = AddressSpace::new(4);
        space
            .add_region(AddressRegion {
                va_start: 0,
                size: 64,
                data: vec![1u8; 64],
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Image,
            })
            .unwrap();
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            file_size: 0,
        };
        let a = ChunkAnalyzer::default();
        let out = a.analyze(&dump, &space);
        assert!(out.chunks.is_empty());
    }

    #[test]
    fn empty_space() {
        let space = AddressSpace::new(4);
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            file_size: 0,
        };
        let a = ChunkAnalyzer::default();
        let out = a.analyze(&dump, &space);
        assert!(out.chunks.is_empty());
    }
}

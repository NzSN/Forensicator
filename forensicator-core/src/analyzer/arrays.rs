use crate::analyzer::scan::pointer_scan;
use crate::analyzer::{Analyzer, AnalyzerOutput};
use crate::model::{CandidatePointer, Dump, RegionClass, StructArray};
use crate::pattern::PointerPattern;
use crate::space::AddressSpace;

pub struct ArrayAnalyzer {
    pub min_count: usize,
    pub max_stride: u64,
}

impl Default for ArrayAnalyzer {
    fn default() -> Self {
        ArrayAnalyzer {
            min_count: 3,
            max_stride: 4096,
        }
    }
}

impl Analyzer for ArrayAnalyzer {
    fn name(&self) -> &str {
        "arrays"
    }
    fn description(&self) -> &str {
        "Groups pointer targets with regular stride into arrays"
    }

    fn analyze(&self, dump: &Dump, space: &AddressSpace) -> AnalyzerOutput {
        let mut out = AnalyzerOutput::new("arrays");
        let candidates = pointer_scan(space, dump, &[PointerPattern::heap_references()]);
        out.arrays = self.detect(space, &candidates);
        out
    }
}

impl ArrayAnalyzer {
    fn detect(&self, space: &AddressSpace, candidates: &[CandidatePointer]) -> Vec<StructArray> {
        let mut vas: Vec<u64> = candidates.iter().map(|c| c.source_va).collect();
        vas.sort();
        vas.dedup();

        if vas.len() < self.min_count {
            return vec![];
        }

        let mut results = Vec::new();
        let mut i = 0;
        while i + self.min_count <= vas.len() {
            let a = vas[i];
            let b = vas[i + 1];
            if a >= b {
                i += 1;
                continue;
            }
            let stride = b - a;
            if stride > self.max_stride || stride == 0 {
                i += 1;
                continue;
            }

            let a_class = space.classify(a);
            let b_class = space.classify(b);
            if a_class != b_class {
                i += 1;
                continue;
            }

            let a_out_deg = self.count_out(candidates, a);
            let b_out_deg = self.count_out(candidates, b);
            if a_out_deg != b_out_deg {
                i += 1;
                continue;
            }

            let mut elements = vec![a, b];
            let mut j = i + 2;
            while j < vas.len() {
                let cur = vas[j];
                if cur != elements.last().unwrap().wrapping_add(stride) {
                    break;
                }
                if space.classify(cur) != a_class {
                    break;
                }
                if self.count_out(candidates, cur) != a_out_deg {
                    break;
                }
                elements.push(cur);
                j += 1;
            }
            if elements.len() >= self.min_count {
                let conf = if elements.len() >= 5 { 0.85 } else { 0.6 };
                results.push(StructArray {
                    start_va: a,
                    element_size: stride,
                    count: elements.len(),
                    out_degree: a_out_deg,
                    region_class: a_class,
                    elements,
                    confidence: conf,
                });
                i = j;
                continue;
            }
            i += 1;
        }
        results
    }

    fn count_out(&self, candidates: &[CandidatePointer], va: u64) -> usize {
        candidates.iter().filter(|c| c.source_va == va).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MemState, SourceContext, TargetContext};
    use crate::space::{AddressRegion, AddressSpace};

    #[test]
    fn detects_array() {
        let mut space = AddressSpace::new(4);
        space
            .add_region(AddressRegion {
                va_start: 0x1000,
                size: 0x100,
                data: vec![0u8; 0x100],
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Private,
            })
            .unwrap();
        let candidates: Vec<CandidatePointer> = (0..4)
            .map(|i| {
                let va = 0x1000 + i as u64 * 0x20;
                CandidatePointer {
                    source_va: va,
                    target_va: va + 0x20,
                    source_ctx: SourceContext::Heap { region_va: None },
                    target_ctx: TargetContext::Heap,
                    confidence: 0.7,
                }
            })
            .collect();
        let d = ArrayAnalyzer::default();
        let arrays = d.detect(&space, &candidates);
        assert_eq!(arrays.len(), 1);
        assert_eq!(arrays[0].count, 4);
    }

    #[test]
    fn too_few_rejected() {
        let space = AddressSpace::new(4);
        let candidates = vec![
            CandidatePointer {
                source_va: 0x1000,
                target_va: 0x1010,
                source_ctx: SourceContext::Heap { region_va: None },
                target_ctx: TargetContext::Heap,
                confidence: 0.7,
            },
            CandidatePointer {
                source_va: 0x1010,
                target_va: 0x1020,
                source_ctx: SourceContext::Heap { region_va: None },
                target_ctx: TargetContext::Heap,
                confidence: 0.7,
            },
        ];
        let d = ArrayAnalyzer::default();
        assert!(d.detect(&space, &candidates).is_empty());
    }

    #[test]
    fn empty_candidates() {
        let space = AddressSpace::new(4);
        let d = ArrayAnalyzer::default();
        assert!(d.detect(&space, &[]).is_empty());
    }
}

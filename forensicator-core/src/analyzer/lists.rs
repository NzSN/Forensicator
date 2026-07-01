use std::collections::{HashMap, HashSet};
use crate::analyzer::{Analyzer, AnalyzerOutput};
use crate::analyzer::scan::pointer_scan;
use crate::model::{CandidatePointer, Dump, StructLinkedList};
use crate::pattern::PointerPattern;
use crate::space::AddressSpace;

pub struct ListAnalyzer {
    pub min_length: usize,
    pub min_confidence: f64,
    pub max_chain_length: usize,
}

impl Default for ListAnalyzer {
    fn default() -> Self {
        ListAnalyzer { min_length: 3, min_confidence: 0.4, max_chain_length: 10000 }
    }
}

impl Analyzer for ListAnalyzer {
    fn name(&self) -> &str { "lists" }
    fn description(&self) -> &str { "Chases pointer chains to find linked lists in heap memory" }

    fn analyze(&self, dump: &Dump, space: &AddressSpace) -> AnalyzerOutput {
        let mut out = AnalyzerOutput::new("lists");
        let candidates = pointer_scan(space, dump, &[PointerPattern::heap_references()]);
        out.linked_lists = self.detect(&candidates);
        out
    }
}

impl ListAnalyzer {
    fn detect(&self, candidates: &[CandidatePointer]) -> Vec<StructLinkedList> {
        let mut adj: HashMap<u64, Vec<(u64, f64)>> = HashMap::new();
        for c in candidates {
            adj.entry(c.source_va).or_default().push((c.target_va, c.confidence));
        }

        let mut visited: HashSet<u64> = HashSet::new();
        let mut results = Vec::new();

        for (&start_va, edges) in &adj {
            if edges.is_empty() || visited.contains(&start_va) {
                continue;
            }
            let mut chain = vec![start_va];
            let mut current = start_va;
            visited.insert(current);
            loop {
                let Some(out_edges) = adj.get(&current) else { break };
                let best = out_edges.iter()
                    .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
                let Some(&(next, conf)) = best else { break };
                if conf < self.min_confidence { break; }
                if visited.contains(&next) { break; }
                if chain.len() >= self.max_chain_length { break; }
                visited.insert(next);
                chain.push(next);
                current = next;
            }
            if chain.len() >= self.min_length {
                let stride = if chain.len() >= 2 { chain[1].wrapping_sub(chain[0]) } else { 0 };
                results.push(StructLinkedList {
                    head_va: chain[0],
                    length: chain.len(),
                    stride,
                    next_offset: 0,
                    is_circular: false,
                    nodes: chain,
                    avg_confidence: 0.5,
                });
            }
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{SourceContext, TargetContext};

    #[test]
    fn detects_linked_list() {
        let candidates = vec![
            CandidatePointer {
                source_va: 0x1000, target_va: 0x1020,
                source_ctx: SourceContext::Heap { region_va: None },
                target_ctx: TargetContext::Heap, confidence: 0.8,
            },
            CandidatePointer {
                source_va: 0x1020, target_va: 0x1040,
                source_ctx: SourceContext::Heap { region_va: None },
                target_ctx: TargetContext::Heap, confidence: 0.8,
            },
            CandidatePointer {
                source_va: 0x1040, target_va: 0x1060,
                source_ctx: SourceContext::Heap { region_va: None },
                target_ctx: TargetContext::Heap, confidence: 0.8,
            },
        ];
        let d = ListAnalyzer::default();
        let lists = d.detect(&candidates);
        assert!(!lists.is_empty());
        assert_eq!(lists[0].length, 3);
    }

    #[test]
    fn empty_candidates() {
        let d = ListAnalyzer::default();
        assert!(d.detect(&[]).is_empty());
    }

    #[test]
    fn singleton_rejected() {
        let candidates = vec![
            CandidatePointer {
                source_va: 0x1000, target_va: 0x1020,
                source_ctx: SourceContext::Heap { region_va: None },
                target_ctx: TargetContext::Heap, confidence: 0.5,
            },
        ];
        let d = ListAnalyzer::default();
        assert!(d.detect(&candidates).is_empty());
    }
}

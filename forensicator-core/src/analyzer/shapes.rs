use crate::analyzer::scan::pointer_scan;
use crate::analyzer::{Analyzer, AnalyzerOutput};
use crate::model::{CandidatePointer, Dump, RegionClass, ShapeGroup, ShapeSignature};
use crate::pattern::PointerPattern;
use crate::space::AddressSpace;
use std::collections::HashMap;

pub struct ShapeAnalyzer;

impl Analyzer for ShapeAnalyzer {
    fn name(&self) -> &str {
        "shapes"
    }
    fn description(&self) -> &str {
        "Clusters heap nodes by structural signature (offset→target_class edges)"
    }

    fn analyze(&self, dump: &Dump, space: &AddressSpace) -> AnalyzerOutput {
        let mut out = AnalyzerOutput::new("shapes");
        let candidates = pointer_scan(space, dump, &[PointerPattern::heap_references()]);
        out.shape_clusters = self.detect(&candidates);
        out
    }
}

impl ShapeAnalyzer {
    fn detect(&self, candidates: &[CandidatePointer]) -> Vec<ShapeGroup> {
        let mut adj: HashMap<u64, Vec<(u64, RegionClass)>> = HashMap::new();
        for c in candidates {
            adj.entry(c.source_va)
                .or_default()
                .push((c.target_va, region_class_from_target(c.target_ctx)));
        }

        let mut sig_to_nodes: HashMap<ShapeSignature, Vec<u64>> = HashMap::new();
        for (&node_va, edges) in &adj {
            let meaningful: Vec<_> = edges
                .iter()
                .filter(|(target_va, _)| *target_va != 0)
                .collect();
            if meaningful.is_empty() {
                continue;
            }
            let mut sig_edges: Vec<(u64, RegionClass)> = meaningful
                .iter()
                .map(|(target_va, target_class)| {
                    let offset = target_va.wrapping_sub(node_va);
                    (offset, *target_class)
                })
                .collect();
            sig_edges.sort_by_key(|&(off, _)| off);
            sig_to_nodes
                .entry(ShapeSignature { edges: sig_edges })
                .or_default()
                .push(node_va);
        }

        let mut groups: Vec<ShapeGroup> = sig_to_nodes
            .into_iter()
            .enumerate()
            .map(|(id, (sig, members))| {
                let count = members.len();
                ShapeGroup {
                    id,
                    signature: sig,
                    member_count: count,
                    members,
                }
            })
            .collect();
        groups.sort_by(|a, b| b.member_count.cmp(&a.member_count));
        groups
    }
}

fn region_class_from_target(tc: crate::model::TargetContext) -> RegionClass {
    match tc {
        crate::model::TargetContext::Image => RegionClass::Image,
        crate::model::TargetContext::Stack => RegionClass::Stack,
        crate::model::TargetContext::Heap => RegionClass::Private,
        crate::model::TargetContext::Mapped => RegionClass::Mapped,
        crate::model::TargetContext::AnyReadable => RegionClass::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{SourceContext, TargetContext};

    #[test]
    fn clusters_by_shape() {
        let candidates = vec![
            CandidatePointer {
                source_va: 0x1000,
                target_va: 0x2000,
                source_ctx: SourceContext::Heap { region_va: None },
                target_ctx: TargetContext::Heap,
                confidence: 0.8,
            },
            CandidatePointer {
                source_va: 0x1500,
                target_va: 0x2500,
                source_ctx: SourceContext::Heap { region_va: None },
                target_ctx: TargetContext::Heap,
                confidence: 0.8,
            },
            CandidatePointer {
                source_va: 0x2000,
                target_va: 0,
                source_ctx: SourceContext::Heap { region_va: None },
                target_ctx: TargetContext::Heap,
                confidence: 0.5,
            },
            CandidatePointer {
                source_va: 0x3000,
                target_va: 0,
                source_ctx: SourceContext::Heap { region_va: None },
                target_ctx: TargetContext::Heap,
                confidence: 0.5,
            },
        ];
        let a = ShapeAnalyzer;
        let groups = a.detect(&candidates);
        assert!(groups.iter().any(|g| g.member_count >= 2));
    }

    #[test]
    fn empty_candidates() {
        let a = ShapeAnalyzer;
        let groups = a.detect(&[]);
        assert!(groups.is_empty());
    }

    #[test]
    fn nodes_without_edges_excluded() {
        let candidates = vec![CandidatePointer {
            source_va: 0x1000,
            target_va: 0,
            source_ctx: SourceContext::Heap { region_va: None },
            target_ctx: TargetContext::Heap,
            confidence: 0.5,
        }];
        let a = ShapeAnalyzer;
        let groups = a.detect(&candidates);
        assert!(groups.is_empty());
    }
}

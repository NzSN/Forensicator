use crate::model::{CandidatePointer, Dump, RegionClass, SourceContext, TargetContext};
use crate::pattern::PointerPattern;
use crate::space::AddressSpace;

pub fn pointer_scan(
    space: &AddressSpace,
    dump: &Dump,
    patterns: &[PointerPattern],
) -> Vec<CandidatePointer> {
    if patterns.is_empty() {
        return vec![];
    }

    let stack_ranges: Vec<(u32, u64, u64)> = dump
        .threads
        .iter()
        .map(|t| (t.id, t.stack_va, t.stack_size))
        .collect();

    let mut candidates: Vec<CandidatePointer> = Vec::new();

    for region in space.regions() {
        if region.classification == RegionClass::Other {
            continue;
        }
        let data = &region.data;
        let mut offset = 0usize;
        while offset + 8 <= data.len() {
            let bytes: [u8; 8] = data[offset..offset + 8].try_into().unwrap();
            let value = u64::from_le_bytes(bytes);
            if value == 0 {
                offset += 8;
                continue;
            }
            let source_va = region.va_start + offset as u64;

            let mut matched = false;
            let mut best_confidence = 0.0f64;

            for pat in patterns {
                if !pat.value_matches(value) {
                    continue;
                }
                let mut conf = 0.0;
                if value & 7 == 0 {
                    conf += 0.15;
                }
                let bit47 = (value >> 47) & 1;
                let upper = value >> 48;
                if upper == (if bit47 == 1 { 0xFFFF } else { 0x0000 }) {
                    conf += 0.20;
                }
                if space.region_at(value).is_some() {
                    conf += 0.25;
                }
                let target_class = space.classify(value);
                if target_class == RegionClass::Image {
                    conf += 0.15;
                }

                if conf >= pat.min_confidence {
                    matched = true;
                    if conf > best_confidence {
                        best_confidence = conf;
                    }
                }
            }

            if matched {
                let source_ctx = classify_source(region, source_va, &stack_ranges);
                let target_ctx = classify_target(space, value);
                candidates.push(CandidatePointer {
                    source_va,
                    target_va: value,
                    source_ctx,
                    target_ctx,
                    confidence: best_confidence.min(1.0),
                });
            }

            offset += 8;
        }
    }

    candidates
}

fn classify_source(
    region: &crate::space::AddressRegion,
    source_va: u64,
    stack_ranges: &[(u32, u64, u64)],
) -> SourceContext {
    match region.classification {
        RegionClass::Stack => {
            let tid = stack_ranges
                .iter()
                .find(|&&(_, sva, sz)| source_va >= sva && source_va < sva + sz)
                .map(|&(tid, _, _)| tid);
            SourceContext::Stack { thread_id: tid }
        }
        RegionClass::Private => SourceContext::Heap {
            region_va: Some(region.va_start),
        },
        RegionClass::Image => SourceContext::ModuleData { module_name: None },
        RegionClass::Mapped => SourceContext::AnyCommitted,
        RegionClass::Other => SourceContext::AnyCommitted,
    }
}

fn classify_target(space: &AddressSpace, va: u64) -> TargetContext {
    match space.classify(va) {
        RegionClass::Image => TargetContext::Image,
        RegionClass::Stack => TargetContext::Stack,
        RegionClass::Private => TargetContext::Heap,
        RegionClass::Mapped => TargetContext::Mapped,
        RegionClass::Other => TargetContext::AnyReadable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MemState, ValueMatcher};
    use crate::space::{AddressRegion, AddressSpace};

    fn make_space_with_pointer() -> AddressSpace {
        let mut space = AddressSpace::new(4);
        let mut data = vec![0u8; 24];
        let ptr: u64 = 0x00007FFA_00001000;
        data[0..8].copy_from_slice(&ptr.to_le_bytes());
        space
            .add_region(AddressRegion {
                va_start: 0x1000,
                size: 24,
                data,
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Private,
            })
            .unwrap();
        space
    }

    #[test]
    fn empty_space_returns_empty() {
        let space = AddressSpace::new(4);
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            annotations: vec![],
            file_size: 0,
        };
        let patterns = PointerPattern::presets();
        let result = pointer_scan(&space, &dump, &patterns);
        assert!(result.is_empty());
    }

    #[test]
    fn finds_known_pointer() {
        let space = make_space_with_pointer();
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            annotations: vec![],
            file_size: 0,
        };
        let pat = PointerPattern::new("test")
            .with_matcher(ValueMatcher::AlignedTo(8))
            .with_matcher(ValueMatcher::CanonicalX64)
            .with_min_confidence(0.0);
        let result = pointer_scan(&space, &dump, &[pat]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].source_va, 0x1000);
        assert_eq!(result[0].target_va, 0x00007FFA_00001000);
    }

    #[test]
    fn empty_patterns_returns_empty() {
        let space = make_space_with_pointer();
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            annotations: vec![],
            file_size: 0,
        };
        let result = pointer_scan(&space, &dump, &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn skips_other_regions() {
        let mut space = AddressSpace::new(4);
        let mut data = vec![0u8; 24];
        let ptr: u64 = 0x00007FFA_00001000;
        data[0..8].copy_from_slice(&ptr.to_le_bytes());
        space
            .add_region(AddressRegion {
                va_start: 0,
                size: 24,
                data,
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Other,
            })
            .unwrap();
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            annotations: vec![],
            file_size: 0,
        };
        let pat = PointerPattern::new("test")
            .with_matcher(ValueMatcher::AlignedTo(8))
            .with_min_confidence(0.0);
        assert!(pointer_scan(&space, &dump, &[pat]).is_empty());
    }

    #[test]
    fn zero_values_are_skipped() {
        let mut space = AddressSpace::new(4);
        space
            .add_region(AddressRegion {
                va_start: 0,
                size: 16,
                data: vec![0u8; 16],
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
            annotations: vec![],
            file_size: 0,
        };
        let pat = PointerPattern::new("test").with_min_confidence(0.0);
        assert!(pointer_scan(&space, &dump, &[pat]).is_empty());
    }
}

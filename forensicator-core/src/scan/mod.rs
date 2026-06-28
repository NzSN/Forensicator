use crate::error::Anomaly;
use crate::model::{
    CandidatePointer, RegionClass, Root, ScanResult,
    SourceContext, TargetContext,
};
use crate::pattern::PointerPattern;
use crate::space::AddressSpace;

/// Scan an AddressSpace for pointer candidates matching the given patterns.
/// Also extracts roots from registers and module data.
pub fn scan(
    space: &AddressSpace,
    registers: &[(u32, &[(String, u64)])],        // (thread_id, &[(reg_name, va)])
    stack_ranges: &[(u32, u64, u64)],              // (thread_id, stack_va, stack_size)
    patterns: &[PointerPattern],
) -> Result<ScanResult, Anomaly> {
    let mut candidates: Vec<CandidatePointer> = Vec::new();
    let mut roots: Vec<Root> = Vec::new();

    // Phase 1: Walk committed regions, apply value matchers
    for region in space.regions() {
        if region.classification == RegionClass::Other {
            continue;
        }
        let data = &region.data;
        // Step at 8-byte boundaries
        let mut offset = 0usize;
        while offset + 8 <= data.len() {
            let bytes: [u8; 8] = data[offset..offset+8].try_into().unwrap();
            let value = u64::from_le_bytes(bytes);
            if value == 0 {
                offset += 8;
                continue;
            }
            let source_va = region.va_start + offset as u64;

            let mut matched = false;
            let mut all_evidence: Vec<String> = Vec::new();
            let mut all_matched_by: Vec<String> = Vec::new();
            let mut best_confidence = 0.0f64;

            for pat in patterns {
                if !pat.value_matches(value) {
                    continue;
                }
                let mut evidence: Vec<String> = Vec::new();
                let mut conf = 0.0;

                if value & 7 == 0 { evidence.push("aligned".into()); conf += 0.15; }
                // Canonical check
                let bit47 = (value >> 47) & 1;
                let upper = value >> 48;
                if upper == (if bit47 == 1 { 0xFFFF } else { 0x0000 }) {
                    evidence.push("canonical".into()); conf += 0.20;
                }
                if space.region_at(value).is_some() {
                    evidence.push("readable_target".into()); conf += 0.25;
                }
                let target_class = space.classify(value);
                if target_class == RegionClass::Image {
                    evidence.push("target_is_module".into()); conf += 0.15;
                }

                if conf >= pat.min_confidence {
                    matched = true;
                    if conf > best_confidence { best_confidence = conf; }
                    all_evidence.extend(evidence);
                    all_matched_by.push(pat.name.clone());
                }
            }

            if matched {
                let source_ctx = classify_source(region, source_va, registers, stack_ranges);
                let target_ctx = classify_target(space, value);
                candidates.push(CandidatePointer {
                    source_va,
                    value,
                    target_va: value,
                    source_ctx,
                    target_ctx,
                    confidence: best_confidence.min(1.0),
                    matched_by: all_matched_by,
                    evidence: all_evidence,
                });
            }

            offset += 8;
        }
    }

    // Extract roots from registers
    for &(tid, ref regs) in registers {
        for &(ref name, va) in *regs {
            if va != 0 {
                roots.push(Root::Register { thread_id: tid, reg_name: name.clone(), va });
            }
        }
    }

    // Extract roots from stack ranges
    for &(tid, stack_va, stack_size) in stack_ranges {
        let end = stack_va.saturating_add(stack_size);
        let mut va = stack_va;
        while va + 8 <= end {
            if let Some(bytes) = space.read(va, 8) {
                let raw: [u8; 8] = bytes.try_into().unwrap();
                let value = u64::from_le_bytes(raw);
                if value != 0 {
                    roots.push(Root::Stack { thread_id: tid, source_va: va, va: value });
                }
            }
            va += 8;
        }
    }

    Ok(ScanResult { candidates, roots })
}

fn classify_source(
    region: &crate::space::AddressRegion,
    source_va: u64,
    _registers: &[(u32, &[(String, u64)])],
    stack_ranges: &[(u32, u64, u64)],
) -> SourceContext {
    match region.classification {
        RegionClass::Stack => {
            let tid = stack_ranges.iter()
                .find(|&&(_, sva, sz)| source_va >= sva && source_va < sva + sz)
                .map(|&(tid, _, _)| tid);
            SourceContext::Stack { thread_id: tid }
        }
        RegionClass::Private => SourceContext::Heap { region_va: Some(region.va_start) },
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
    use crate::model::{MemState, RegionClass, ValueMatcher};
    use crate::space::{AddressRegion, AddressSpace};

    fn make_space() -> AddressSpace {
        let mut space = AddressSpace::new(4);
        let data = vec![0u8; 256];
        space.add_region(AddressRegion {
            va_start: 0x1000, size: 256, data,
            protection: 3, state: MemState::Commit, classification: RegionClass::Private,
        }).unwrap();
        space
    }

    fn make_space_with_known_pointer() -> AddressSpace {
        let mut space = AddressSpace::new(4);
        let mut data = vec![0u8; 24];
        // Put a pointer-like value at offset 0: 0x7FFA_1000
        let ptr: u64 = 0x00007FFA_00001000;
        data[0..8].copy_from_slice(&ptr.to_le_bytes());
        space.add_region(AddressRegion {
            va_start: 0x1000, size: 24, data,
            protection: 3, state: MemState::Commit, classification: RegionClass::Private,
        }).unwrap();
        space
    }

    #[test]
    fn scan_empty_space() {
        let space = AddressSpace::new(4);
        let patterns = PointerPattern::presets();
        let result = scan(&space, &[], &[], &patterns).unwrap();
        assert!(result.candidates.is_empty());
        assert!(result.roots.is_empty());
    }

    #[test]
    fn scan_all_zeros_produces_no_candidates() {
        let space = make_space();
        let patterns = PointerPattern::presets();
        let result = scan(&space, &[], &[], &patterns).unwrap();
        assert!(result.candidates.is_empty());
    }

    #[test]
    fn scan_finds_known_pointer() {
        let space = make_space_with_known_pointer();
        let alo = PointerPattern::new("test")
            .with_matcher(ValueMatcher::AlignedTo(8))
            .with_matcher(ValueMatcher::CanonicalX64)
            .with_min_confidence(0.0);
        let result = scan(&space, &[], &[], &[alo]).unwrap();
        assert_eq!(result.candidates.len(), 1);
        let c = &result.candidates[0];
        assert_eq!(c.source_va, 0x1000);
        assert_eq!(c.value, 0x00007FFA_00001000);
        assert!(c.confidence > 0.0);
    }

    #[test]
    fn scan_steps_by_8_bytes() {
        let mut space = AddressSpace::new(4);
        // Region with 24 bytes = 3 candidates scanned at offsets 0, 8, 16
        let data = vec![0u8; 24];
        space.add_region(AddressRegion {
            va_start: 0, size: 24, data,
            protection: 3, state: MemState::Commit, classification: RegionClass::Private,
        }).unwrap();
        let result = scan(&space, &[], &[], &[]).unwrap();
        assert!(result.candidates.is_empty());
    }

    #[test]
    fn root_extraction_from_registers() {
        let space = make_space_with_known_pointer();
        let regs = vec![("RIP".to_string(), 0x00007FFA_00001000u64)];
        let result = scan(&space, &[(1u32, &regs)], &[], &[]).unwrap();
        assert_eq!(result.roots.len(), 1);
        match &result.roots[0] {
            Root::Register { thread_id, reg_name, va } => {
                assert_eq!(*thread_id, 1);
                assert_eq!(reg_name, "RIP");
                assert_eq!(*va, 0x00007FFA_00001000);
            }
            _ => panic!("expected Register root"),
        }
    }

    #[test]
    fn root_extraction_ignores_zero_registers() {
        let space = make_space();
        let regs = vec![("RAX".to_string(), 0u64)];
        let result = scan(&space, &[(1u32, &regs)], &[], &[]).unwrap();
        assert!(result.roots.is_empty());
    }

    #[test]
    fn root_extraction_from_stack() {
        let space = make_space_with_known_pointer();
        let stack_ranges = &[(1u32, 0x1000u64, 16u64)];
        let result = scan(&space, &[], stack_ranges, &[]).unwrap();
        assert_eq!(result.roots.len(), 1);
        match &result.roots[0] {
            Root::Stack { thread_id, source_va, va } => {
                assert_eq!(*thread_id, 1);
                assert_eq!(*source_va, 0x1000);
                assert_eq!(*va, 0x00007FFA_00001000);
            }
            _ => panic!("expected Stack root"),
        }
    }

    #[test]
    fn scan_skips_other_regions() {
        let mut space = AddressSpace::new(4);
        let mut data = vec![0u8; 24];
        let ptr: u64 = 0x00007FFA_00001000;
        data[0..8].copy_from_slice(&ptr.to_le_bytes());
        space.add_region(AddressRegion {
            va_start: 0, size: 24, data,
            protection: 3, state: MemState::Commit, classification: RegionClass::Other,
        }).unwrap();
        let alo = PointerPattern::new("test")
            .with_matcher(ValueMatcher::AlignedTo(8))
            .with_min_confidence(0.0);
        let result = scan(&space, &[], &[], &[alo]).unwrap();
        assert!(result.candidates.is_empty());
    }

    #[test]
    fn confidence_bounded_at_1() {
        let space = make_space_with_known_pointer();
        // Use a pattern with min_confidence 0 so everything matches
        let alo = PointerPattern::new("test")
            .with_matcher(ValueMatcher::AlignedTo(8))
            .with_min_confidence(0.0);
        let result = scan(&space, &[], &[], &[alo]).unwrap();
        assert_eq!(result.candidates.len(), 1);
        assert!(result.candidates[0].confidence <= 1.0);
    }
}

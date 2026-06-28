use crate::model::{ValueMatcher, SourceContext, TargetContext};

/// A user-definable pointer pattern: value matchers + source + target constraints.
#[derive(Debug, Clone, PartialEq)]
pub struct PointerPattern {
    pub name: String,
    pub value_matchers: Vec<ValueMatcher>,
    pub source: SourceContext,
    pub target: TargetContext,
    pub min_confidence: f64,
    pub max_depth_from_root: Option<usize>,
}

impl PointerPattern {
    pub fn new(name: &str) -> Self {
        PointerPattern {
            name: name.into(),
            value_matchers: Vec::new(),
            source: SourceContext::AnyCommitted,
            target: TargetContext::AnyReadable,
            min_confidence: 0.0,
            max_depth_from_root: None,
        }
    }

    pub fn with_matcher(mut self, m: ValueMatcher) -> Self {
        self.value_matchers.push(m);
        self
    }

    pub fn with_source(mut self, s: SourceContext) -> Self {
        self.source = s;
        self
    }

    pub fn with_target(mut self, t: TargetContext) -> Self {
        self.target = t;
        self
    }

    pub fn with_min_confidence(mut self, c: f64) -> Self {
        self.min_confidence = 0.0_f64.max(c).min(1.0);
        self
    }

    pub fn with_max_depth_from_root(mut self, d: usize) -> Self {
        self.max_depth_from_root = Some(d);
        self
    }

    /// Test whether a single raw value passes all value matchers.
    pub fn value_matches(&self, value: u64) -> bool {
        self.value_matchers.iter().all(|m| m.eval(value))
    }

    /// Built-in presets.
    pub fn presets() -> Vec<PointerPattern> {
        vec![
            Self::all_strict(),
            Self::all_loose(),
            Self::saved_frame_pointers(),
            Self::vtables(),
            Self::heap_references(),
        ]
    }

    pub fn all_strict() -> Self {
        PointerPattern::new("all_strict")
            .with_matcher(ValueMatcher::AlignedTo(8))
            .with_matcher(ValueMatcher::CanonicalX64)
            .with_min_confidence(0.5)
    }

    pub fn all_loose() -> Self {
        PointerPattern::new("all_loose")
            .with_matcher(ValueMatcher::AlignedTo(4))
            .with_min_confidence(0.3)
    }

    pub fn saved_frame_pointers() -> Self {
        PointerPattern::new("saved_frame_pointers")
            .with_matcher(ValueMatcher::AlignedTo(8))
            .with_source(SourceContext::Stack { thread_id: None })
            .with_target(TargetContext::Stack)
            .with_min_confidence(0.6)
    }

    pub fn vtables() -> Self {
        PointerPattern::new("vtables")
            .with_matcher(ValueMatcher::AlignedTo(8))
            .with_matcher(ValueMatcher::CanonicalX64)
            .with_source(SourceContext::ModuleData { module_name: None })
            .with_target(TargetContext::Image)
            .with_min_confidence(0.4)
    }

    pub fn heap_references() -> Self {
        PointerPattern::new("heap_references")
            .with_matcher(ValueMatcher::AlignedTo(8))
            .with_matcher(ValueMatcher::CanonicalX64)
            .with_source(SourceContext::Heap { region_va: None })
            .with_target(TargetContext::Heap)
            .with_min_confidence(0.35)
    }
}

impl Default for PointerPattern {
    fn default() -> Self { Self::new("default") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_with_aligned_matcher_passes_aligned_value() {
        let p = PointerPattern::new("test")
            .with_matcher(ValueMatcher::AlignedTo(8));
        assert!(p.value_matches(0x7FFA_1000));
        assert!(!p.value_matches(0x7FFA_1001));
        assert!(!p.value_matches(0x7FFA_1007));
    }

    #[test]
    fn pattern_with_multiple_matchers_ands_them() {
        let p = PointerPattern::new("test")
            .with_matcher(ValueMatcher::AlignedTo(8))
            .with_matcher(ValueMatcher::CanonicalX64);
        assert!(p.value_matches(0x00007FFA_00001000));
        assert!(!p.value_matches(0x00007FFA_00001001));
        assert!(!p.value_matches(0x00018000_00001000));
    }

    #[test]
    fn pattern_default_has_no_matchers_passes_all() {
        let p = PointerPattern::new("test");
        assert!(p.value_matches(0));
        assert!(p.value_matches(1));
        assert!(p.value_matches(u64::MAX));
    }

    #[test]
    fn preset_all_strict() {
        let p = PointerPattern::all_strict();
        assert_eq!(p.name, "all_strict");
        assert!(p.min_confidence >= 0.5);
        assert!(p.value_matches(0x00007FFA_00001000));
        assert!(!p.value_matches(0x00007FFA_00001001));
    }

    #[test]
    fn preset_all_loose() {
        let p = PointerPattern::all_loose();
        assert_eq!(p.name, "all_loose");
        assert!(p.min_confidence <= 0.3);
        assert!(p.value_matches(0x00007FFA_00001000));
        assert!(!p.value_matches(0x00007FFA_00001003));
    }

    #[test]
    fn preset_saved_frame_pointers() {
        let p = PointerPattern::saved_frame_pointers();
        assert!(p.value_matches(0x7FFE_1000));
    }

    #[test]
    fn preset_count_is_five() {
        assert_eq!(PointerPattern::presets().len(), 5);
    }

    #[test]
    fn builder_fluent_api() {
        let p = PointerPattern::new("custom")
            .with_matcher(ValueMatcher::InRange { lo: 0x1000, hi: 0x2000 })
            .with_source(SourceContext::Register { register_name: Some("RIP".into()) })
            .with_target(TargetContext::Image)
            .with_min_confidence(0.9);
        assert_eq!(p.name, "custom");
        assert_eq!(p.min_confidence, 0.9);
        assert!(p.value_matches(0x1500));
        assert!(!p.value_matches(0x3000));
    }

    #[test]
    fn with_source_stores_correctly() {
        let p = PointerPattern::new("test")
            .with_source(SourceContext::Heap { region_va: Some(0x1000) });
        assert_eq!(p.source, SourceContext::Heap { region_va: Some(0x1000) });
    }

    #[test]
    fn with_target_stores_correctly() {
        let p = PointerPattern::new("test")
            .with_target(TargetContext::Stack);
        assert_eq!(p.target, TargetContext::Stack);
    }

    #[test]
    fn preset_vtables() {
        let p = PointerPattern::vtables();
        assert_eq!(p.name, "vtables");
        assert_eq!(p.source, SourceContext::ModuleData { module_name: None });
        assert_eq!(p.target, TargetContext::Image);
    }

    #[test]
    fn preset_heap_references() {
        let p = PointerPattern::heap_references();
        assert_eq!(p.name, "heap_references");
        assert_eq!(p.source, SourceContext::Heap { region_va: None });
        assert_eq!(p.target, TargetContext::Heap);
    }

    #[test]
    fn with_max_depth_from_root_stores_correctly() {
        let p = PointerPattern::new("test")
            .with_max_depth_from_root(5);
        assert_eq!(p.max_depth_from_root, Some(5));
    }

    #[test]
    fn default_produces_expected_values() {
        let p = PointerPattern::default();
        assert_eq!(p.name, "default");
        assert!(p.value_matchers.is_empty());
        assert_eq!(p.source, SourceContext::AnyCommitted);
        assert_eq!(p.target, TargetContext::AnyReadable);
        assert_eq!(p.min_confidence, 0.0);
        assert_eq!(p.max_depth_from_root, None);
    }

    #[test]
    fn min_confidence_clamped() {
        let p = PointerPattern::new("test")
            .with_min_confidence(-0.5);
        assert_eq!(p.min_confidence, 0.0);
        let p = PointerPattern::new("test")
            .with_min_confidence(1.5);
        assert_eq!(p.min_confidence, 1.0);
        let p = PointerPattern::new("test")
            .with_min_confidence(0.7);
        assert_eq!(p.min_confidence, 0.7);
    }
}

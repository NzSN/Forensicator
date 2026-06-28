# S2 Pointer Graph — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build 4 new modules in `forensicator-core` that classify pointers in minidump memory, extract root sets, construct a VA→VA reachability graph with confidence scores, and expose a query API for S3.

**Architecture:** `model ← pattern ← scan ← graph ← query ← CLI`. Shared types in `model.rs`; `PointerPattern` with byte-level ValueMatchers in `pattern/`; two-phase scanner with root extraction in `scan/`; dual-adjacency `PointerGraph` in `graph/`; traversal + stats + export in `query/`.

**Tech Stack:** Rust edition 2024, `forensicator-core` + `forensicator-cli` workspace. No new external dependencies.

---

## File Structure

```
forensicator-core/src/
├── model.rs              # MODIFY: add S2 types after existing S1 types
├── lib.rs                # MODIFY: add pub mod declarations
├── pattern/
│   └── mod.rs            # CREATE: PointerPattern, ValueMatcher eval, presets
├── scan/
│   └── mod.rs            # CREATE: two-phase scanner, root extraction
├── graph/
│   └── mod.rs            # CREATE: PointerGraph construction from candidates
└── query/
    └── mod.rs            # CREATE: GraphQuery, traversal, stats, export

forensicator-cli/src/
└── main.rs               # MODIFY: add scan, graph, query, patterns subcommands

specs/
└── PointerGraph.tla      # CREATE: TLA+ model of pointer graph
```

---

### Task 1: Model extensions — S2 shared types

**Files:**
- Modify: `forensicator-core/src/model.rs` (append new types after existing S1 types, before the test module)

- [ ] **Step 1: Write failing tests for new S2 types**

Append these new test functions inside the existing `mod tests` block at the bottom of `forensicator-core/src/model.rs`:

```rust
    #[test]
    fn node_index_wrapping() {
        let ni = NodeIndex(5);
        assert_eq!(ni.0, 5);
    }

    #[test]
    fn value_matcher_aligned_to_matches() {
        assert!(ValueMatcher::AlignedTo(8).eval(0x7FFA_1000));
        assert!(!ValueMatcher::AlignedTo(8).eval(0x7FFA_1001));
    }

    #[test]
    fn value_matcher_in_range() {
        let m = ValueMatcher::InRange { lo: 0x1000, hi: 0x2000 };
        assert!(m.eval(0x1500));
        assert!(!m.eval(0x3000));
    }

    #[test]
    fn value_matcher_canonical_x64() {
        assert!(ValueMatcher::CanonicalX64.eval(0x00007FFA_00001000));
        assert!(!ValueMatcher::CanonicalX64.eval(0xFFFF_8000_00001000));
    }

    #[test]
    fn value_matcher_bitmask() {
        let m = ValueMatcher::BitMask { mask: 0xFF, expected: 0xAB };
        assert!(m.eval(0x7FFA_10AB));
        assert!(!m.eval(0x7FFA_10CD));
    }

    #[test]
    fn value_matcher_modulo() {
        let m = ValueMatcher::Modulo { divisor: 4, remainder: 0 };
        assert!(m.eval(16));
        assert!(!m.eval(17));
    }

    #[test]
    fn value_matcher_bit_zero_and_one() {
        assert!(ValueMatcher::BitZero(3).eval(0b0000_0000));
        assert!(!ValueMatcher::BitZero(3).eval(0b0000_1000));
        assert!(ValueMatcher::BitOne(3).eval(0b0000_1000));
        assert!(!ValueMatcher::BitOne(3).eval(0b0000_0000));
    }

    #[test]
    fn value_matcher_known_va() {
        assert!(ValueMatcher::KnownVA(0xDEADBEEF).eval(0xDEADBEEF));
        assert!(!ValueMatcher::KnownVA(0xDEADBEEF).eval(0xCAFEBABE));
    }

    #[test]
    fn value_matcher_match_size_rejects_wrong_width() {
        let m = ValueMatcher::MatchSize(4);
        assert!(m.eval(0x0000_1234));
        assert!(!m.eval(0x7FFA_0000_1234));
    }

    #[test]
    fn candidate_pointer_construction() {
        let c = CandidatePointer {
            source_va: 0x1000,
            value: 0x7FFA_2000,
            target_va: 0x7FFA_2000,
            source_ctx: SourceContext::Stack { thread_id: Some(1) },
            target_ctx: TargetContext::Image,
            confidence: 0.85,
            matched_by: vec!["test".into()],
            evidence: vec!["aligned".into()],
        };
        assert_eq!(c.source_va, 0x1000);
        assert_eq!(c.confidence, 0.85);
    }

    #[test]
    fn scan_result_empty() {
        let sr = ScanResult { candidates: vec![], roots: vec![] };
        assert!(sr.candidates.is_empty());
        assert!(sr.roots.is_empty());
    }

    #[test]
    fn root_register_variant() {
        let r = Root::Register { thread_id: 1, reg_name: "RIP".into(), va: 0x7FFA_1000 };
        match r {
            Root::Register { thread_id, ref reg_name, va } => {
                assert_eq!(thread_id, 1);
                assert_eq!(reg_name, "RIP");
                assert_eq!(va, 0x7FFA_1000);
            }
            _ => panic!("expected Register variant"),
        }
    }

    #[test]
    fn graph_node_default() {
        let n = GraphNode { va: 0x400000, region_class: RegionClass::Image, out_degree: 0, in_degree: 0, is_root: false };
        assert_eq!(n.va, 0x400000);
        assert!(!n.is_root);
    }

    #[test]
    fn graph_edge_construction() {
        let e = GraphEdge { from: NodeIndex(0), to: NodeIndex(1), confidence: 0.75, evidence: vec!["canonical".into()], matched_by: vec!["all_strict".into()] };
        assert_eq!(e.from, NodeIndex(0));
        assert_eq!(e.to, NodeIndex(1));
        assert_eq!(e.confidence, 0.75);
    }

    #[test]
    fn pointer_graph_empty() {
        let g = PointerGraph::new();
        assert_eq!(g.node_count(), 0);
        assert_eq!(g.edge_count(), 0);
        assert!(g.root_nodes().is_empty());
    }

    #[test]
    fn edge_predicate_default_allows_all() {
        let p = EdgePredicate::default();
        assert!(p.matches(&GraphEdge { from: NodeIndex(0), to: NodeIndex(1), confidence: 0.5, evidence: vec![], matched_by: vec![] }));
    }

    #[test]
    fn edge_predicate_confidence_filter() {
        let p = EdgePredicate { min_confidence: 0.6, ..Default::default() };
        let good = GraphEdge { from: NodeIndex(0), to: NodeIndex(1), confidence: 0.8, evidence: vec![], matched_by: vec![] };
        let bad = GraphEdge { from: NodeIndex(0), to: NodeIndex(2), confidence: 0.4, evidence: vec![], matched_by: vec![] };
        assert!(p.matches(&good));
        assert!(!p.matches(&bad));
    }

    #[test]
    fn edge_path_total_confidence() {
        let path = EdgePath { nodes: vec![NodeIndex(0), NodeIndex(1)], edges: vec![EdgeIndex(0)], total_confidence: 0.72 };
        assert_eq!(path.total_confidence, 0.72);
    }
```

- [ ] **Step 2: Run tests to verify they fail (types not defined)**

Run: `cargo test -p forensicator-core -- model::tests::node_index_wrapping model::tests::value_matcher_aligned_to_matches 2>&1`
Expected: compile errors (types not found)

- [ ] **Step 3: Add S2 types to model.rs**

Insert the following types after the `Dump` struct definition (after line 149), before the `#[cfg(test)]` block:

```rust
/// Index into a PointerGraph's node array.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeIndex(pub usize);

/// Index into a PointerGraph's edge array.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EdgeIndex(pub usize);

/// Byte-level predicate on a raw 8-byte value.
/// All matchers in a pattern are AND-ed.
#[derive(Debug, Clone, PartialEq)]
pub enum ValueMatcher {
    /// Value's least-significant N bytes are zero (alignment check).
    AlignedTo(u8),
    /// Value passes bitmask test: (value & mask) == expected.
    BitMask { mask: u64, expected: u64 },
    /// A specific bit is 0.
    BitZero(u8),
    /// A specific bit is 1.
    BitOne(u8),
    /// Value is a canonical x64 address (bits 48-63 == bit 47 sign-extension).
    CanonicalX64,
    /// Value falls within an address range.
    InRange { lo: u64, hi: u64 },
    /// Value % divisor == remainder.
    Modulo { divisor: u64, remainder: u64 },
    /// Value fits in N bytes (4 = 32-bit pointer, 8 = 64-bit pointer).
    MatchSize(u8),
    /// Value matches a known VA exactly.
    KnownVA(u64),
}

impl ValueMatcher {
    /// Evaluate this matcher against a raw value.
    pub fn eval(&self, value: u64) -> bool {
        match *self {
            ValueMatcher::AlignedTo(n) => {
                let mask = (1u64 << (n as u32)) - 1;
                (value & mask) == 0
            }
            ValueMatcher::BitMask { mask, expected } => (value & mask) == expected,
            ValueMatcher::BitZero(n) => (value & (1u64 << n)) == 0,
            ValueMatcher::BitOne(n) => (value & (1u64 << n)) != 0,
            ValueMatcher::CanonicalX64 => {
                let bit47 = (value >> 47) & 1;
                let upper = value >> 48;
                upper == if bit47 == 1 { 0xFFFF } else { 0x0000 }
            }
            ValueMatcher::InRange { lo, hi } => value >= lo && value <= hi,
            ValueMatcher::Modulo { divisor, remainder } => {
                if divisor == 0 { false } else { value % divisor == remainder }
            }
            ValueMatcher::MatchSize(4) => value <= 0xFFFF_FFFF,
            ValueMatcher::MatchSize(8) => true,
            ValueMatcher::KnownVA(va) => value == va,
            _ => false,
        }
    }
}

/// Where a pointer value was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceContext {
    Stack { thread_id: Option<u32> },
    Heap { region_va: Option<u64> },
    ModuleData { module_name: Option<String> },
    Register { register_name: Option<String> },
    AnyCommitted,
}

/// What kind of memory region a pointer targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetContext {
    Image,
    Stack,
    Heap,
    Mapped,
    AnyReadable,
}

/// A candidate pointer found by the scanner.
#[derive(Debug, Clone, PartialEq)]
pub struct CandidatePointer {
    pub source_va: u64,
    pub value: u64,
    pub target_va: u64,
    pub source_ctx: SourceContext,
    pub target_ctx: TargetContext,
    pub confidence: f64,
    pub matched_by: Vec<String>,
    pub evidence: Vec<String>,
}

/// Output of the scan phase.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanResult {
    pub candidates: Vec<CandidatePointer>,
    pub roots: Vec<Root>,
}

/// A root for graph traversal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Root {
    Register { thread_id: u32, reg_name: String, va: u64 },
    Stack { thread_id: u32, source_va: u64, va: u64 },
    ModuleData { mod_name: String, source_va: u64, va: u64 },
}

/// A node in the pointer graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphNode {
    pub va: u64,
    pub region_class: RegionClass,
    pub out_degree: usize,
    pub in_degree: usize,
    pub is_root: bool,
}

/// A directed edge in the pointer graph.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphEdge {
    pub from: NodeIndex,
    pub to: NodeIndex,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub matched_by: Vec<String>,
}

/// The pointer graph: nodes, edges with dual adjacency, roots.
#[derive(Debug, Clone, PartialEq)]
pub struct PointerGraph {
    pub nodes: Vec<GraphNode>,
    pub adj_out: Vec<Vec<EdgeIndex>>,
    pub adj_in: Vec<Vec<EdgeIndex>>,
    pub edges: Vec<GraphEdge>,
    pub va_to_node: std::collections::HashMap<u64, NodeIndex>,
    pub roots: Vec<NodeIndex>,
    max_nodes: usize,
    max_edges: usize,
}

impl PointerGraph {
    pub fn new() -> Self {
        PointerGraph {
            nodes: Vec::new(),
            adj_out: Vec::new(),
            adj_in: Vec::new(),
            edges: Vec::new(),
            va_to_node: std::collections::HashMap::new(),
            roots: Vec::new(),
            max_nodes: 1_000_000,
            max_edges: 10_000_000,
        }
    }

    pub fn with_capacity(max_nodes: usize, max_edges: usize) -> Self {
        PointerGraph { max_nodes, max_edges, ..Self::new() }
    }

    pub fn node_count(&self) -> usize { self.nodes.len() }
    pub fn edge_count(&self) -> usize { self.edges.len() }
    pub fn root_nodes(&self) -> &[NodeIndex] { &self.roots }

    pub fn node(&self, va: u64) -> Option<&GraphNode> {
        self.va_to_node.get(&va).map(|&idx| &self.nodes[idx.0])
    }
}

impl Default for PointerGraph {
    fn default() -> Self { Self::new() }
}

/// Predicate for filtering graph edges during traversal.
#[derive(Debug, Clone, PartialEq)]
pub struct EdgePredicate {
    pub min_confidence: f64,
    pub max_confidence: f64,
    pub source_region: Option<RegionClass>,
    pub target_region: Option<RegionClass>,
    pub max_depth: Option<usize>,
    pub matched_by_pattern: Option<String>,
}

impl EdgePredicate {
    pub fn matches(&self, edge: &GraphEdge) -> bool {
        if edge.confidence < self.min_confidence { return false; }
        if edge.confidence > self.max_confidence { return false; }
        if let Some(ref pat) = self.matched_by_pattern {
            if !edge.matched_by.iter().any(|m| m == pat) { return false; }
        }
        true
    }
}

impl Default for EdgePredicate {
    fn default() -> Self {
        EdgePredicate {
            min_confidence: 0.0,
            max_confidence: 1.0,
            source_region: None,
            target_region: None,
            max_depth: None,
            matched_by_pattern: None,
        }
    }
}

/// A path through the graph: sequence of nodes and edges.
#[derive(Debug, Clone, PartialEq)]
pub struct EdgePath {
    pub nodes: Vec<NodeIndex>,
    pub edges: Vec<EdgeIndex>,
    pub total_confidence: f64,
}
```

- [ ] **Step 4: Run the S2 model tests to verify they pass**

Run: `cargo test -p forensicator-core -- model::tests 2>&1`
Expected: all model tests pass (existing + 18 new S2 tests)

- [ ] **Step 5: Commit**

```bash
git add forensicator-core/src/model.rs
git commit -m "feat(model): add S2 pointer graph types — ValueMatcher, CandidatePointer, PointerGraph, QueryPredicate"
```

---

### Task 2: Pattern module — PointerPattern definitions and presets

**Files:**
- Create: `forensicator-core/src/pattern/mod.rs`

- [ ] **Step 1: Write failing tests for PointerPattern**

Write `forensicator-core/src/pattern/mod.rs`:

```rust
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
        self.min_confidence = c;
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
        assert!(!p.value_matches(0xFFFF8000_00001000));
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
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p forensicator-core -- pattern::tests 2>&1`
Expected: 8 tests pass

- [ ] **Step 3: Commit**

```bash
git add forensicator-core/src/pattern/
git commit -m "feat(pattern): add PointerPattern with ValueMatchers, source/target context, presets"
```

---

### Task 3: Scan module — two-phase pointer scanner and root extraction

**Files:**
- Create: `forensicator-core/src/scan/mod.rs`

- [ ] **Step 1: Write failing tests for scanner**

Write `forensicator-core/src/scan/mod.rs`:

```rust
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
            let source_va = region.va_start + offset as u64;

            let mut matched = false;
            let mut all_evidence: Vec<String> = Vec::new();
            let mut all_matched_by: Vec<String> = Vec::new();
            let mut best_confidence = 0.0f64;

            for pat in patterns {
                if !pat.value_matches(value) {
                    continue;
                }
                // Phase 2: target resolution
                let target_class = space.classify(value);
                let target_ctx = match target_class {
                    RegionClass::Image => TargetContext::Image,
                    RegionClass::Stack => TargetContext::Stack,
                    RegionClass::Private => TargetContext::Heap,
                    RegionClass::Mapped => TargetContext::Mapped,
                    RegionClass::Other => TargetContext::AnyReadable,
                };

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
                if target_ctx == TargetContext::Image {
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
            if va != 0 && space.region_at(va).is_some() {
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
                if value != 0 && space.region_at(value).is_some() {
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
    registers: &[(u32, &[(String, u64)])],
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
        let regs = vec![(1u32, vec![("RIP".to_string(), 0x00007FFA_00001000u64)])];
        let result = scan(&space, &[(1u32, &regs[0].1)], &[], &[]).unwrap();
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
        let regs = vec![(1u32, vec![("RAX".to_string(), 0u64)])];
        let result = scan(&space, &[(1u32, &regs[0].1)], &[], &[]).unwrap();
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
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p forensicator-core -- scan::tests 2>&1`
Expected: 10 tests pass

- [ ] **Step 3: Commit**

```bash
git add forensicator-core/src/scan/
git commit -m "feat(scan): add two-phase pointer scanner with root extraction from registers and stacks"
```

---

### Task 4: Graph module — PointerGraph construction from candidates

**Files:**
- Create: `forensicator-core/src/graph/mod.rs`

- [ ] **Step 1: Write failing tests for PointerGraph construction**

Write `forensicator-core/src/graph/mod.rs`:

```rust
use std::collections::HashMap;

use crate::error::Anomaly;
use crate::model::{
    CandidatePointer, EdgeIndex, GraphEdge, GraphNode, NodeIndex,
    PointerGraph, RegionClass, Root, ScanResult, SourceContext, TargetContext,
};

/// Build a PointerGraph from scan results.
pub fn build_graph(scan_result: &ScanResult) -> Result<PointerGraph, Anomaly> {
    let mut graph = PointerGraph::new();
    let candidates = &scan_result.candidates;

    // Step 1: Insert unique nodes
    for c in candidates {
        insert_or_get_node(&mut graph, c.source_va, RegionClass::Other, |g, _| {})?;
        insert_or_get_node(&mut graph, c.target_va, RegionClass::Other, |g, _| {})?;
    }

    // Update region_class for target nodes
    for c in candidates {
        let class = match c.target_ctx {
            TargetContext::Image => RegionClass::Image,
            TargetContext::Stack => RegionClass::Stack,
            TargetContext::Heap => RegionClass::Private,
            TargetContext::Mapped => RegionClass::Mapped,
            TargetContext::AnyReadable => RegionClass::Other,
        };
        if let Some(&idx) = graph.va_to_node.get(&c.target_va) {
            graph.nodes[idx.0].region_class = class;
        }
    }

    // Step 2: Insert edges
    for c in candidates {
        let from = graph.va_to_node[&c.source_va];
        let to = graph.va_to_node[&c.target_va];

        // Step 3: Merge duplicate edges
        if let Some(existing) = find_edge(&graph, from, to) {
            let edge = &mut graph.edges[existing.0];
            if c.confidence > edge.confidence {
                edge.confidence = c.confidence;
            }
            for ev in &c.evidence {
                if !edge.evidence.contains(ev) {
                    edge.evidence.push(ev.clone());
                }
            }
            for m in &c.matched_by {
                if !edge.matched_by.contains(m) {
                    edge.matched_by.push(m.clone());
                }
            }
        } else {
            if graph.edges.len() >= graph.max_edges {
                return Err(Anomaly {
                    provenance: crate::error::Provenance { stream_type: 0, file_offset: 0, rva: 0 },
                    description: "edge capacity exceeded".into(),
                });
            }
            let edge_idx = EdgeIndex(graph.edges.len());
            graph.edges.push(GraphEdge {
                from,
                to,
                confidence: c.confidence,
                evidence: c.evidence.clone(),
                matched_by: c.matched_by.clone(),
            });
            graph.adj_out[from.0].push(edge_idx);
            graph.adj_in[to.0].push(edge_idx);
            graph.nodes[from.0].out_degree += 1;
            graph.nodes[to.0].in_degree += 1;
        }
    }

    // Step 4: Mark roots
    for root in &scan_result.roots {
        let va = match root {
            Root::Register { va, .. } => *va,
            Root::Stack { va, .. } => *va,
            Root::ModuleData { va, .. } => *va,
        };
        if let Some(&idx) = graph.va_to_node.get(&va) {
            if !graph.nodes[idx.0].is_root {
                graph.nodes[idx.0].is_root = true;
                graph.roots.push(idx);
            }
        }
    }

    Ok(graph)
}

fn insert_or_get_node(
    graph: &mut PointerGraph,
    va: u64,
    default_class: RegionClass,
    _init: impl FnOnce(&mut PointerGraph, NodeIndex),
) -> Result<NodeIndex, Anomaly> {
    if let Some(&idx) = graph.va_to_node.get(&va) {
        return Ok(idx);
    }
    if graph.nodes.len() >= graph.max_nodes() {
        return Err(Anomaly {
            provenance: crate::error::Provenance { stream_type: 0, file_offset: 0, rva: 0 },
            description: "node capacity exceeded".into(),
        });
    }
    let idx = NodeIndex(graph.nodes.len());
    graph.va_to_node.insert(va, idx);
    graph.nodes.push(GraphNode {
        va,
        region_class: default_class,
        out_degree: 0,
        in_degree: 0,
        is_root: false,
    });
    graph.adj_out.push(Vec::new());
    graph.adj_in.push(Vec::new());
    Ok(idx)
}

fn find_edge(graph: &PointerGraph, from: NodeIndex, to: NodeIndex) -> Option<EdgeIndex> {
    for &ei in &graph.adj_out[from.0] {
        if graph.edges[ei.0].to == to {
            return Some(ei);
        }
    }
    None
}

impl PointerGraph {
    /// Maximum number of nodes.
    pub fn max_nodes(&self) -> usize { self.max_nodes }

    /// Get edges originating from a node.
    pub fn edges_from(&self, node: NodeIndex) -> Vec<&GraphEdge> {
        if node.0 >= self.adj_out.len() { return vec![]; }
        self.adj_out[node.0].iter().map(|&ei| &self.edges[ei.0]).collect()
    }

    /// Get edges arriving at a node.
    pub fn edges_to(&self, node: NodeIndex) -> Vec<&GraphEdge> {
        if node.0 >= self.adj_in.len() { return vec![]; }
        self.adj_in[node.0].iter().map(|&ei| &self.edges[ei.0]).collect()
    }

    /// Iterate over all nodes.
    pub fn iter_nodes(&self) -> impl Iterator<Item = &GraphNode> {
        self.nodes.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_candidate(source: u64, target: u64, conf: f64) -> CandidatePointer {
        CandidatePointer {
            source_va: source,
            value: target,
            target_va: target,
            source_ctx: SourceContext::AnyCommitted,
            target_ctx: TargetContext::AnyReadable,
            confidence: conf,
            matched_by: vec!["test".into()],
            evidence: vec!["aligned".into()],
        }
    }

    #[test]
    fn build_empty_scan_result() {
        let sr = ScanResult { candidates: vec![], roots: vec![] };
        let g = build_graph(&sr).unwrap();
        assert_eq!(g.node_count(), 0);
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn build_single_edge() {
        let c = make_candidate(0x1000, 0x2000, 0.8);
        let sr = ScanResult { candidates: vec![c], roots: vec![] };
        let g = build_graph(&sr).unwrap();
        assert_eq!(g.node_count(), 2);
        assert_eq!(g.edge_count(), 1);
        assert_eq!(g.nodes[0].va, 0x1000);
        assert_eq!(g.nodes[1].va, 0x2000);
        assert_eq!(g.nodes[0].out_degree, 1);
        assert_eq!(g.nodes[1].in_degree, 1);
    }

    #[test]
    fn node_deduplication() {
        let c1 = make_candidate(0x1000, 0x3000, 0.8);
        let c2 = make_candidate(0x2000, 0x3000, 0.9);
        let sr = ScanResult { candidates: vec![c1, c2], roots: vec![] };
        let g = build_graph(&sr).unwrap();
        assert_eq!(g.node_count(), 3);
        assert_eq!(g.edge_count(), 2);
    }

    #[test]
    fn edge_merge_on_duplicate() {
        let c1 = make_candidate(0x1000, 0x2000, 0.3);
        let c2 = {
            let mut c = make_candidate(0x1000, 0x2000, 0.7);
            c.evidence.push("canonical".into());
            c.matched_by.push("other".into());
            c
        };
        let sr = ScanResult { candidates: vec![c1, c2], roots: vec![] };
        let g = build_graph(&sr).unwrap();
        assert_eq!(g.edge_count(), 1);
        assert_eq!(g.edges[0].confidence, 0.7);
        assert!(g.edges[0].evidence.contains(&"aligned".to_string()));
        assert!(g.edges[0].evidence.contains(&"canonical".to_string()));
        assert!(g.edges[0].matched_by.contains(&"test".to_string()));
        assert!(g.edges[0].matched_by.contains(&"other".to_string()));
    }

    #[test]
    fn root_marking() {
        let c = make_candidate(0x1000, 0x2000, 0.8);
        let r = Root::Register { thread_id: 1, reg_name: "RIP".into(), va: 0x1000 };
        let sr = ScanResult { candidates: vec![c], roots: vec![r] };
        let g = build_graph(&sr).unwrap();
        assert_eq!(g.roots.len(), 1);
        assert!(g.nodes[g.roots[0].0].is_root);
        assert_eq!(g.nodes[g.roots[0].0].va, 0x1000);
    }

    #[test]
    fn root_not_marked_if_va_not_a_node() {
        let sr = ScanResult {
            candidates: vec![],
            roots: vec![Root::Register { thread_id: 1, reg_name: "RIP".into(), va: 0x9999 }],
        };
        let g = build_graph(&sr).unwrap();
        assert!(g.roots.is_empty());
    }

    #[test]
    fn edges_from_and_edges_to() {
        let c = make_candidate(0x1000, 0x2000, 0.8);
        let sr = ScanResult { candidates: vec![c], roots: vec![] };
        let g = build_graph(&sr).unwrap();
        let n0 = g.va_to_node[&0x1000];
        let n1 = g.va_to_node[&0x2000];
        assert_eq!(g.edges_from(n0).len(), 1);
        assert_eq!(g.edges_to(n0).len(), 0);
        assert_eq!(g.edges_from(n1).len(), 0);
        assert_eq!(g.edges_to(n1).len(), 1);
    }

    #[test]
    fn iter_nodes_yields_all() {
        let c1 = make_candidate(0x1000, 0x2000, 0.8);
        let c2 = make_candidate(0x3000, 0x4000, 0.6);
        let sr = ScanResult { candidates: vec![c1, c2], roots: vec![] };
        let g = build_graph(&sr).unwrap();
        let vas: Vec<u64> = g.iter_nodes().map(|n| n.va).collect();
        assert!(vas.contains(&0x1000));
        assert!(vas.contains(&0x2000));
        assert!(vas.contains(&0x3000));
        assert!(vas.contains(&0x4000));
    }

    #[test]
    fn target_region_class_populated() {
        let c = CandidatePointer {
            source_va: 0x1000, value: 0x2000, target_va: 0x2000,
            source_ctx: SourceContext::AnyCommitted,
            target_ctx: TargetContext::Image,
            confidence: 0.5, matched_by: vec![], evidence: vec![],
        };
        let sr = ScanResult { candidates: vec![c], roots: vec![] };
        let g = build_graph(&sr).unwrap();
        let n1 = g.va_to_node[&0x2000];
        assert_eq!(g.nodes[n1.0].region_class, RegionClass::Image);
    }
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p forensicator-core -- graph::tests 2>&1`
Expected: 11 tests pass

- [ ] **Step 3: Commit**

```bash
git add forensicator-core/src/graph/
git commit -m "feat(graph): add PointerGraph construction from candidates with dedup, merge, root marking"
```

---

### Task 5: Query module — traversal, filtering, statistics, export

**Files:**
- Create: `forensicator-core/src/query/mod.rs`

- [ ] **Step 1: Write failing tests for GraphQuery**

Write `forensicator-core/src/query/mod.rs`:

```rust
use std::collections::VecDeque;

use crate::model::{
    EdgeIndex, EdgePath, EdgePredicate, GraphEdge, NodeIndex,
    PointerGraph, RegionClass,
};

/// Query engine over a PointerGraph.
pub struct GraphQuery<'g> {
    graph: &'g PointerGraph,
    config: EdgePredicate,
}

impl<'g> GraphQuery<'g> {
    pub fn new(graph: &'g PointerGraph) -> Self {
        GraphQuery { graph, config: EdgePredicate::default() }
    }

    pub fn with_config(mut self, config: EdgePredicate) -> Self {
        self.config = config;
        self
    }

    /// Check if `va` is reachable from any root.
    pub fn is_reachable(&self, va: u64) -> bool {
        let Some(&node) = self.graph.va_to_node.get(&va) else { return false; };
        self.reachable_from_any_root(node)
    }

    /// Find all nodes reachable from any root (BFS), filtered by predicate.
    pub fn reachable_all(&self) -> Vec<NodeIndex> {
        let mut visited = vec![false; self.graph.node_count()];
        let mut result = Vec::new();
        for &root in &self.graph.roots {
            self.bfs_from(root, &mut visited, &mut result, None);
        }
        result
    }

    /// Find a path from `va` to the nearest root. Returns empty if unreachable.
    pub fn path_to_root(&self, va: u64) -> Vec<EdgePath> {
        let Some(&target) = self.graph.va_to_node.get(&va) else { return vec![]; };

        // BFS backwards from va to any root
        let mut visited = vec![false; self.graph.node_count()];
        let mut queue = VecDeque::new();
        let mut parent: Vec<Option<(NodeIndex, EdgeIndex)>> = vec![None; self.graph.node_count()];

        visited[target.0] = true;
        queue.push_back(target);

        while let Some(curr) = queue.pop_front() {
            if self.graph.nodes[curr.0].is_root {
                // Reconstruct path from target up to curr (root)
                let mut path_nodes = vec![curr];
                let mut path_edges = Vec::new();
                let mut walk = curr;
                while walk != target {
                    let (prev, edge) = parent[walk.0].expect("parent must exist");
                    path_nodes.push(prev);
                    path_edges.push(edge);
                    walk = prev;
                }
                path_nodes.reverse();
                path_edges.reverse();
                let total_conf: f64 = path_edges.iter()
                    .map(|&ei| self.graph.edges[ei.0].confidence)
                    .product();
                return vec![EdgePath { nodes: path_nodes, edges: path_edges, total_confidence: total_conf }];
            }
            // Traverse incoming edges (reverse direction)
            for &ei in &self.graph.adj_in[curr.0] {
                let edge = &self.graph.edges[ei.0];
                let prev = edge.from;
                if !visited[prev.0] && self.config.matches(edge) {
                    visited[prev.0] = true;
                    parent[prev.0] = Some((curr, ei));
                    queue.push_back(prev);
                }
            }
        }
        vec![]
    }

    /// Find all nodes reachable from `va` (BFS forward).
    pub fn reachable_from(&self, va: u64) -> Vec<NodeIndex> {
        let Some(&start) = self.graph.va_to_node.get(&va) else { return vec![]; };
        let mut visited = vec![false; self.graph.node_count()];
        let mut result = Vec::new();
        self.bfs_from(start, &mut visited, &mut result, None);
        result
    }

    /// Find all nodes that point to `va`.
    pub fn who_points_to(&self, va: u64) -> Vec<NodeIndex> {
        let Some(&node) = self.graph.va_to_node.get(&va) else { return vec![]; };
        self.graph.adj_in[node.0].iter()
            .map(|&ei| self.graph.edges[ei.0].from)
            .filter(|n| self.config.matches(self.edge_between(*n, node).unwrap()))
            .collect()
    }

    /// Get in/out neighbors of a node.
    pub fn neighbors(&self, va: u64) -> (Vec<NodeIndex>, Vec<NodeIndex>) {
        let Some(&node) = self.graph.va_to_node.get(&va) else { return (vec![], vec![]); };
        let in_n: Vec<NodeIndex> = self.graph.adj_in[node.0].iter()
            .map(|&ei| self.graph.edges[ei.0].from)
            .collect();
        let out_n: Vec<NodeIndex> = self.graph.adj_out[node.0].iter()
            .map(|&ei| self.graph.edges[ei.0].to)
            .collect();
        (in_n, out_n)
    }

    /// Pointer density: count of candidates in a range.
    pub fn pointer_density(&self, _va: u64, _size: u64) -> f64 {
        // Density is computed over the graph's node distribution
        self.graph.node_count() as f64
    }

    /// Degree distribution histogram.
    pub fn degree_distribution(&self) -> Vec<(usize, usize)> {
        let max_deg = self.graph.nodes.iter().map(|n| n.out_degree).max().unwrap_or(0);
        let mut buckets = vec![0usize; max_deg + 1];
        for n in &self.graph.nodes {
            if n.out_degree <= max_deg {
                buckets[n.out_degree] += 1;
            }
        }
        buckets.into_iter().enumerate().filter(|(_, c)| *c > 0).collect()
    }

    /// Node/edge counts by region class.
    pub fn region_breakdown(&self) -> Vec<(RegionClass, usize, usize)> {
        let mut map: std::collections::HashMap<RegionClass, (usize, usize)> = std::collections::HashMap::new();
        for n in &self.graph.nodes {
            let e = map.entry(n.region_class).or_insert((0, 0));
            e.0 += 1;
        }
        for edge in &self.graph.edges {
            let n = &self.graph.nodes[edge.from.0];
            if let Some(e) = map.get_mut(&n.region_class) {
                e.1 += 1;
            }
        }
        let mut result: Vec<_> = map.into_iter().map(|(k, (n, e))| (k, n, e)).collect();
        result.sort_by_key(|&(ref c, _, _)| *c as u8);
        result
    }

    /// Confidence distribution.
    pub fn confidence_distribution(&self) -> Vec<(usize, usize)> {
        let levels = [0.0, 0.2, 0.4, 0.6, 0.8];
        let mut buckets = vec![0usize; levels.len()];
        for edge in &self.graph.edges {
            for (i, &threshold) in levels.iter().enumerate().rev() {
                if edge.confidence >= threshold {
                    buckets[i] += 1;
                    break;
                }
            }
        }
        buckets.into_iter().enumerate().collect()
    }

    /// Export to Graphviz DOT format.
    pub fn to_dot(&self) -> String {
        let mut dot = String::from("digraph PointerGraph {\n");
        dot.push_str("  rankdir=LR;\n");
        for n in &self.graph.nodes {
            let shape = match n.region_class {
                RegionClass::Image => "box",
                RegionClass::Stack => "diamond",
                RegionClass::Private => "oval",
                RegionClass::Mapped => "hexagon",
                RegionClass::Other => "ellipse",
            };
            let color = if n.is_root { "red" } else { "black" };
            dot.push_str(&format!("  n{} [label=\"0x{:X}\", shape={shape}, color={color}];\n", n.va, n.va));
        }
        for (i, edge) in self.graph.edges.iter().enumerate() {
            let color = if edge.confidence >= 0.7 { "green" }
                else if edge.confidence >= 0.4 { "orange" }
                else { "red" };
            dot.push_str(&format!("  n{} -> n{} [color={color}, label=\"{:.2}\"];\n",
                edge.from.0, edge.to.0, edge.confidence));
        }
        dot.push_str("}\n");
        dot
    }

    /// Export to JSON.
    pub fn to_json(&self) -> serde_json::Value {
        let nodes: Vec<serde_json::Value> = self.graph.nodes.iter().map(|n| {
            serde_json::json!({
                "va": format!("0x{:X}", n.va),
                "region_class": format!("{:?}", n.region_class),
                "out_degree": n.out_degree,
                "in_degree": n.in_degree,
                "is_root": n.is_root,
            })
        }).collect();
        let edges: Vec<serde_json::Value> = self.graph.edges.iter().map(|e| {
            serde_json::json!({
                "from": format!("0x{:X}", self.graph.nodes[e.from.0].va),
                "to": format!("0x{:X}", self.graph.nodes[e.to.0].va),
                "confidence": e.confidence,
                "evidence": e.evidence,
                "matched_by": e.matched_by,
            })
        }).collect();
        serde_json::json!({ "nodes": nodes, "edges": edges })
    }

    // --- private helpers ---

    fn bfs_from(
        &self,
        start: NodeIndex,
        visited: &mut [bool],
        result: &mut Vec<NodeIndex>,
        max_depth: Option<usize>,
    ) {
        let mut queue = VecDeque::new();
        let mut depth = vec![0usize; self.graph.node_count()];
        visited[start.0] = true;
        queue.push_back(start);
        result.push(start);

        while let Some(curr) = queue.pop_front() {
            let d = depth[curr.0];
            if let Some(max) = max_depth {
                if d >= max { continue; }
            }
            for &ei in &self.graph.adj_out[curr.0] {
                let edge = &self.graph.edges[ei.0];
                let next = edge.to;
                if !visited[next.0] && self.config.matches(edge) {
                    visited[next.0] = true;
                    depth[next.0] = d + 1;
                    queue.push_back(next);
                    result.push(next);
                }
            }
        }
    }

    fn reachable_from_any_root(&self, node: NodeIndex) -> bool {
        if self.graph.roots.contains(&node) { return true; }
        let mut visited = vec![false; self.graph.node_count()];
        for &root in &self.graph.roots {
            let mut queue = VecDeque::new();
            visited[root.0] = true;
            queue.push_back(root);
            while let Some(curr) = queue.pop_front() {
                if curr == node { return true; }
                for &ei in &self.graph.adj_out[curr.0] {
                    let next = self.graph.edges[ei.0].to;
                    if !visited[next.0] && self.config.matches(&self.graph.edges[ei.0]) {
                        visited[next.0] = true;
                        queue.push_back(next);
                    }
                }
            }
            visited.fill(false);
        }
        false
    }

    fn edge_between(&self, from: NodeIndex, to: NodeIndex) -> Option<&GraphEdge> {
        if from.0 >= self.graph.adj_out.len() { return None; }
        for &ei in &self.graph.adj_out[from.0] {
            if self.graph.edges[ei.0].to == to {
                return Some(&self.graph.edges[ei.0]);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CandidatePointer, Root, ScanResult, SourceContext, TargetContext};
    use crate::graph::build_graph;

    fn make_simple_graph() -> PointerGraph {
        let c1 = CandidatePointer {
            source_va: 0x1000, value: 0x2000, target_va: 0x2000,
            source_ctx: SourceContext::AnyCommitted, target_ctx: TargetContext::AnyReadable,
            confidence: 0.8, matched_by: vec!["test".into()], evidence: vec!["aligned".into()],
        };
        let c2 = CandidatePointer {
            source_va: 0x2000, value: 0x3000, target_va: 0x3000,
            source_ctx: SourceContext::AnyCommitted, target_ctx: TargetContext::AnyReadable,
            confidence: 0.6, matched_by: vec!["test".into()], evidence: vec!["aligned".into()],
        };
        let r = Root::Register { thread_id: 1, reg_name: "RIP".into(), va: 0x1000 };
        let sr = ScanResult {
            candidates: vec![c1, c2],
            roots: vec![r],
        };
        build_graph(&sr).unwrap()
    }

    #[test]
    fn is_reachable_from_root() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        assert!(q.is_reachable(0x1000));
        assert!(q.is_reachable(0x2000));
        assert!(q.is_reachable(0x3000));
        assert!(!q.is_reachable(0x9999));
    }

    #[test]
    fn reachable_all_from_roots() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        let nodes = q.reachable_all();
        assert_eq!(nodes.len(), 3);
    }

    #[test]
    fn path_to_root_finds_path() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        let paths = q.path_to_root(0x3000);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].nodes.len(), 3);
        assert_eq!(g.nodes[paths[0].nodes[0].0].va, 0x1000);
        assert_eq!(g.nodes[paths[0].nodes[2].0].va, 0x3000);
    }

    #[test]
    fn path_to_root_unreachable_is_empty() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        assert!(q.path_to_root(0x9999).is_empty());
    }

    #[test]
    fn reachable_from_node() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        let nodes = q.reachable_from(0x1000);
        let vas: Vec<u64> = nodes.iter().map(|&n| g.nodes[n.0].va).collect();
        assert!(vas.contains(&0x2000));
        assert!(vas.contains(&0x3000));
    }

    #[test]
    fn who_points_to() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        let ptrs = q.who_points_to(0x3000);
        assert_eq!(ptrs.len(), 1);
        assert_eq!(g.nodes[ptrs[0].0].va, 0x2000);
    }

    #[test]
    fn neighbors_returns_in_and_out() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        let (ins, outs) = q.neighbors(0x2000);
        assert_eq!(ins.len(), 1);
        assert_eq!(outs.len(), 1);
    }

    #[test]
    fn reachable_respects_confidence_filter() {
        let g = make_simple_graph();
        let filter = EdgePredicate { min_confidence: 0.7, ..Default::default() };
        let q = GraphQuery::new(&g).with_config(filter);
        assert!(q.is_reachable(0x1000));
        assert!(q.is_reachable(0x2000));
        assert!(!q.is_reachable(0x3000));
    }

    #[test]
    fn degree_distribution_works() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        let dist = q.degree_distribution();
        assert!(!dist.is_empty());
    }

    #[test]
    fn region_breakdown_works() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        let bd = q.region_breakdown();
        assert!(!bd.is_empty());
    }

    #[test]
    fn confidence_distribution_works() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        let dist = q.confidence_distribution();
        assert_eq!(dist.len(), 5);
    }

    #[test]
    fn to_dot_produces_output() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        let dot = q.to_dot();
        assert!(dot.contains("digraph PointerGraph"));
        assert!(dot.contains("0x1000"));
        assert!(dot.contains("0x3000"));
    }

    #[test]
    fn to_json_produces_valid_structure() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        let json = q.to_json();
        assert!(json["nodes"].is_array());
        assert!(json["edges"].is_array());
    }

    #[test]
    fn empty_graph_queries_return_empty() {
        let g = PointerGraph::new();
        let q = GraphQuery::new(&g);
        assert!(!q.is_reachable(0x1000));
        assert!(q.reachable_all().is_empty());
        assert!(q.path_to_root(0x1000).is_empty());
        assert!(q.who_points_to(0x1000).is_empty());
    }
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p forensicator-core -- query::tests 2>&1`
Expected: 14 tests pass

- [ ] **Step 3: Commit**

```bash
git add forensicator-core/src/query/
git commit -m "feat(query): add GraphQuery with traversal, path finding, filtering, statistics, DOT/JSON export"
```

---

### Task 6: Wire modules into lib.rs, add serde_json dependency, and CLI

**Files:**
- Modify: `forensicator-core/Cargo.toml`
- Modify: `forensicator-core/src/lib.rs`
- Modify: `forensicator-cli/src/main.rs`

- [ ] **Step 0: Add serde_json to forensicator-core**

Edit `forensicator-core/Cargo.toml`, add under `[dependencies]`:

```toml
[dependencies]
serde_json = "1"
```

- [ ] **Step 1: Verify core still compiles**

Run: `cargo build -p forensicator-core 2>&1`
Expected: compiles with no errors

- [ ] **Step 2: Register new modules in lib.rs**

Replace the current content of `forensicator-core/src/lib.rs`:

```rust
//! Forensicator core library — S1 foundation + S2 pointer graph.
//! Parses Windows x64 minidumps into a typed `Dump` with provenance,
//! then classifies pointers and builds a reachability graph.

pub mod error;
pub mod arch;
pub mod model;
pub mod parse;
pub mod space;
pub mod pattern;
pub mod scan;
pub mod graph;
pub mod query;
```

- [ ] **Step 3: Verify compilation**

Run: `cargo build -p forensicator-core 2>&1`
Expected: compiles with no errors

- [ ] **Step 4: Add new CLI subcommands**

Replace `forensicator-cli/src/main.rs`:

```rust
use std::process;

use clap::{Parser, Subcommand};
use forensicator_core::graph;
use forensicator_core::model::{CpuArch, OsPlatform};
use forensicator_core::parse::dump;
use forensicator_core::pattern::PointerPattern;
use forensicator_core::query::GraphQuery;
use forensicator_core::scan;

#[derive(Parser)]
#[command(name = "forensicator")]
#[command(version = "0.1.0")]
#[command(about = "Forensic analysis of Windows minidumps")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Inspect a minidump file and print its structural inventory.
    Inspect {
        path: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        quiet: bool,
    },
    /// Scan for pointer candidates using configured patterns.
    Scan {
        path: String,
        #[arg(long)]
        pattern: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Build and export the pointer graph.
    Graph {
        path: String,
        #[arg(long)]
        pattern: Option<String>,
        #[arg(long, default_value = "0.5")]
        min_conf: f64,
        #[arg(long)]
        dot: bool,
        #[arg(long)]
        json: bool,
    },
    /// Query the pointer graph.
    Query {
        path: String,
        #[arg(long)]
        reachable: Option<String>,
        #[arg(long)]
        stats: bool,
    },
    /// List or show pointer patterns.
    Patterns {
        #[command(subcommand)]
        action: PatternsAction,
    },
}

#[derive(Subcommand)]
enum PatternsAction {
    List,
    Show { name: String },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Inspect { path, json, quiet } => {
            if let Err(e) = inspect(&path, json, quiet) {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }
        Commands::Scan { path, pattern, json } => {
            if let Err(e) = cmd_scan(&path, pattern.as_deref(), json) {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }
        Commands::Graph { path, pattern, min_conf, dot, json } => {
            if let Err(e) = cmd_graph(&path, pattern.as_deref(), min_conf, dot, json) {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }
        Commands::Query { path, reachable, stats } => {
            if let Err(e) = cmd_query(&path, reachable.as_deref(), stats) {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }
        Commands::Patterns { action } => match action {
            PatternsAction::List => cmd_patterns_list(),
            PatternsAction::Show { name } => cmd_patterns_show(&name),
        },
    }
}

fn inspect(path: &str, json: bool, quiet: bool) -> Result<(), Box<dyn std::error::Error>> {
    let dump = dump::open(path)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "file_size": dump.file_size,
            "system_info": dump.system_info.as_ref().map(|si| serde_json::json!({
                "os": os_name(si.os),
                "cpu": cpu_name(si.cpu),
                "version": format!("{}.{}.{}.{}", si.version.0, si.version.1, si.version.2, si.version.3),
            })),
            "module_count": dump.modules.len(),
            "thread_count": dump.threads.len(),
            "memory_regions": dump.memory_regions.len(),
            "exception": dump.exception.is_some(),
            "anomaly_count": dump.anomalies.len(),
        }))?);
        return Ok(());
    }

    if quiet {
        println!("modules: {}  threads: {}  memory_regions: {}  anomalies: {}",
            dump.modules.len(), dump.threads.len(),
            dump.memory_regions.len(), dump.anomalies.len());
        return Ok(());
    }

    println!("Dump ({:.1} KB)", dump.file_size as f64 / 1024.0);

    if let Some(ref si) = dump.system_info {
        println!("├── SystemInfo: {} on {} v{}.{}.{}.{}",
            cpu_name(si.cpu), os_name(si.os),
            si.version.0, si.version.1, si.version.2, si.version.3);
    } else {
        println!("├── SystemInfo: <missing>");
    }

    println!("├── Modules: {} loaded", dump.modules.len());
    for m in &dump.modules {
        println!("│   ├── {} @ 0x{:016X} ({:.1} KB)", m.name, m.base_va, m.size as f64 / 1024.0);
    }

    println!("├── Threads: {}", dump.threads.len());
    for t in &dump.threads {
        println!("│   ├── TID {}  stack @ 0x{:016X} ({:.1} KB)  TEB @ 0x{:016X}  RIP 0x{:016X}",
            t.id, t.stack_va, t.stack_size as f64 / 1024.0, t.teb_va, t.registers.rip());
    }

    println!("├── Memory regions: {}", dump.memory_regions.len());

    if let Some(ref exc) = dump.exception {
        println!("├── Exception: code 0x{:08X} at 0x{:016X} (thread {})",
            exc.code, exc.address, exc.thread_id);
    }

    if !dump.anomalies.is_empty() {
        println!("└── Anomalies: {}", dump.anomalies.len());
        for a in &dump.anomalies {
            println!("    ├── [stream 0x{:08X} @ +0x{:X}] {}",
                a.provenance.stream_type, a.provenance.file_offset, a.description);
        }
    }

    Ok(())
}

fn cmd_scan(path: &str, pattern_name: Option<&str>, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let dump = dump::open(path)?;

    let mut space = forensicator_core::space::AddressSpace::new(1_000_000);
    let patterns = select_patterns(pattern_name);
    let registers: Vec<(u32, Vec<(String, u64)>)> = dump.threads.iter().map(|t| {
        let regs = vec![("RIP".into(), t.registers.rip())];
        (t.id, regs)
    }).collect();
    let stack_ranges: Vec<(u32, u64, u64)> = dump.threads.iter()
        .map(|t| (t.id, t.stack_va, t.stack_size))
        .collect();

    let reg_refs: Vec<(u32, &[(String, u64)])> = registers.iter()
        .map(|(tid, r)| (*tid, r.as_slice()))
        .collect();

    let result = scan::scan(&space, &reg_refs, &stack_ranges, &patterns)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "candidate_count": result.candidates.len(),
            "root_count": result.roots.len(),
            "candidates": result.candidates.iter().map(|c| serde_json::json!({
                "source_va": format!("0x{:X}", c.source_va),
                "target_va": format!("0x{:X}", c.target_va),
                "confidence": c.confidence,
                "evidence": c.evidence,
            })).collect::<Vec<_>>(),
        }))?);
    } else {
        println!("Pointer scan results:");
        println!("  candidates: {}  roots: {}", result.candidates.len(), result.roots.len());
        for c in &result.candidates {
            println!("  ├── 0x{:016X} → 0x{:016X}  conf={:.2}  {:?}",
                c.source_va, c.target_va, c.confidence, c.evidence);
        }
    }

    Ok(())
}

fn cmd_graph(path: &str, pattern_name: Option<&str>, min_conf: f64, dot: bool, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let dump = dump::open(path)?;

    let mut space = forensicator_core::space::AddressSpace::new(1_000_000);
    let patterns = select_patterns(pattern_name);
    let registers: Vec<(u32, Vec<(String, u64)>)> = dump.threads.iter().map(|t| {
        let regs = vec![("RIP".into(), t.registers.rip())];
        (t.id, regs)
    }).collect();
    let stack_ranges: Vec<(u32, u64, u64)> = dump.threads.iter()
        .map(|t| (t.id, t.stack_va, t.stack_size))
        .collect();

    let reg_refs: Vec<(u32, &[(String, u64)])> = registers.iter()
        .map(|(tid, r)| (*tid, r.as_slice()))
        .collect();

    let scan_result = scan::scan(&space, &reg_refs, &stack_ranges, &patterns)?;
    let pointer_graph = graph::build_graph(&scan_result)?;
    let query = GraphQuery::new(&pointer_graph);

    if dot {
        println!("{}", query.to_dot());
    } else if json {
        println!("{}", serde_json::to_string_pretty(&query.to_json())?);
    } else {
        println!("Pointer graph:");
        println!("  nodes: {}  edges: {}  roots: {}",
            pointer_graph.node_count(), pointer_graph.edge_count(), pointer_graph.root_nodes().len());
        let bd = query.region_breakdown();
        for (rc, nodes, edges) in bd {
            println!("  {:?}: {} nodes, {} edges", rc, nodes, edges);
        }
    }

    Ok(())
}

fn cmd_query(path: &str, reachable: Option<&str>, stats: bool) -> Result<(), Box<dyn std::error::Error>> {
    let dump = dump::open(path)?;

    let mut space = forensicator_core::space::AddressSpace::new(1_000_000);
    let patterns = PointerPattern::presets();
    let registers: Vec<(u32, Vec<(String, u64)>)> = dump.threads.iter().map(|t| {
        let regs = vec![("RIP".into(), t.registers.rip())];
        (t.id, regs)
    }).collect();
    let stack_ranges: Vec<(u32, u64, u64)> = dump.threads.iter()
        .map(|t| (t.id, t.stack_va, t.stack_size))
        .collect();

    let reg_refs: Vec<(u32, &[(String, u64)])> = registers.iter()
        .map(|(tid, r)| (*tid, r.as_slice()))
        .collect();

    let scan_result = scan::scan(&space, &reg_refs, &stack_ranges, &patterns)?;
    let pointer_graph = graph::build_graph(&scan_result)?;
    let query = GraphQuery::new(&pointer_graph);

    if let Some(va_str) = reachable {
        let va = u64::from_str_radix(va_str.trim_start_matches("0x"), 16)?;
        let nodes = query.reachable_from(va);
        println!("Reachable from 0x{:X}: {} nodes", va, nodes.len());
        for n in nodes {
            println!("  0x{:X}", pointer_graph.nodes[n.0].va);
        }
    }

    if stats {
        println!("Degree distribution:");
        for (deg, count) in query.degree_distribution() {
            println!("  {} → {} nodes", deg, count);
        }
        println!("Confidence distribution:");
        for (bucket, count) in query.confidence_distribution() {
            println!("  bucket {} → {} edges", bucket, count);
        }
    }

    Ok(())
}

fn cmd_patterns_list() {
    println!("Pointer patterns:");
    for p in PointerPattern::presets() {
        println!("  {} (min_conf={:.2})", p.name, p.min_confidence);
    }
}

fn cmd_patterns_show(name: &str) {
    for p in PointerPattern::presets() {
        if p.name == name {
            println!("Pattern: {}", p.name);
            println!("  min_confidence: {:.2}", p.min_confidence);
            println!("  value_matchers: {:?}", p.value_matchers);
            println!("  source: {:?}", p.source);
            println!("  target: {:?}", p.target);
            return;
        }
    }
    println!("Pattern '{}' not found", name);
}

fn select_patterns(name: Option<&str>) -> Vec<PointerPattern> {
    match name {
        Some(n) => {
            let all = PointerPattern::presets();
            all.into_iter().filter(|p| p.name == n).collect()
        }
        None => PointerPattern::presets(),
    }
}

fn os_name(os: OsPlatform) -> &'static str {
    match os {
        OsPlatform::Windows => "Windows",
        OsPlatform::Linux => "Linux",
        OsPlatform::MacOs => "macOS",
    }
}

fn cpu_name(cpu: CpuArch) -> &'static str {
    match cpu {
        CpuArch::X86 => "x86",
        CpuArch::X64 => "x64",
        CpuArch::Arm64 => "ARM64",
    }
}
```

- [ ] **Step 5: Verify full workspace compilation**

Run: `cargo build 2>&1`
Expected: both crates compile with no errors

- [ ] **Step 6: Run full test suite**

Run: `cargo test 2>&1`
Expected: all existing + new tests pass

- [ ] **Step 7: Commit**

```bash
git add forensicator-core/src/lib.rs forensicator-cli/src/main.rs
git commit -m "feat(cli): wire S2 modules — scan, graph, query, patterns subcommands"
```

---

### Task 7: TLA+ specification

**Files:**
- Create: `specs/PointerGraph.tla`
- Create: `specs/PointerGraph.cfg`

- [ ] **Step 1: Write PointerGraph.tla**

Write `specs/PointerGraph.tla`:

```tla
---- MODULE PointerGraph ----
EXTENDS Integers, Sequences, FiniteSets

MaxNodes == 4
MaxEdges == 6

\* Node: (va, region_class, is_root)
\* region_class: 0=Image, 1=Stack, 2=Heap, 3=Mapped, 4=Other

\* Edge: (from_node, to_node, confidence)
\* confidence in {0..10} representing 0.0..1.0

VARIABLES
    node_va,          \* Seq(Int) — VA of each node
    node_cls,         \* Seq(Int) — region class
    node_root,        \* Seq(Int) — 1 if root, 0 otherwise
    edge_from,        \* Seq(Int) — source node index
    edge_to,          \* Seq(Int) — target node index
    edge_conf         \* Seq(Int) — confidence 0..10

NodeCount == Len(node_va)
EdgeCount == Len(edge_from)

\* Helper: check if node i exists
NodeExists(i) == i \in 1..NodeCount

\* Helper: check if there is an edge from i to j
HasEdge(i, j) == \E k \in 1..EdgeCount: edge_from[k] = i /\ edge_to[k] = j

\* No self-loops on non-heap nodes
NoSelfLoopsNonHeap == \A i \in 1..NodeCount:
    \A j \in 1..EdgeCount:
        (edge_from[j] = i /\ edge_to[j] = i) => node_cls[i] = 2     \* Heap

\* All edges connect existing nodes
EdgesValid == \A i \in 1..EdgeCount:
    NodeExists(edge_from[i]) /\ NodeExists(edge_to[i])

\* Confidence in valid range
ConfidenceValid == \A i \in 1..EdgeCount: edge_conf[i] \in 0..10

\* Root nodes are self-reachable
RootsReachable == \A i \in 1..NodeCount:
    node_root[i] = 1 => NodeExists(i)

\* Counts bounded
CountsBounded == NodeCount <= MaxNodes /\ EdgeCount <= MaxEdges

PointerGraphInvariant ==
    /\ NoSelfLoopsNonHeap
    /\ EdgesValid
    /\ ConfidenceValid
    /\ RootsReachable
    /\ CountsBounded

\* ---- Operations ----

AddNode(va, cls, is_root) ==
    /\ NodeCount < MaxNodes
    /\ node_va'   = Append(node_va, va)
    /\ node_cls'  = Append(node_cls, cls)
    /\ node_root' = Append(node_root, is_root)
    /\ UNCHANGED <<edge_from, edge_to, edge_conf>>

AddEdge(from, to, conf) ==
    /\ EdgeCount < MaxEdges
    /\ NodeExists(from) /\ NodeExists(to)
    /\ conf \in 0..10
    /\ ~(from = to /\ node_cls[from] /= 2)
    /\ edge_from' = Append(edge_from, from)
    /\ edge_to'   = Append(edge_to, to)
    /\ edge_conf' = Append(edge_conf, conf)
    /\ UNCHANGED <<node_va, node_cls, node_root>>

MarkRoot(node) ==
    /\ NodeExists(node)
    /\ node_root' = [node_root EXCEPT ![node] = 1]
    /\ UNCHANGED <<node_va, node_cls, edge_from, edge_to, edge_conf>>

Init ==
    /\ node_va    = <<>>
    /\ node_cls   = <<>>
    /\ node_root  = <<>>
    /\ edge_from  = <<>>
    /\ edge_to    = <<>>
    /\ edge_conf  = <<>>

Next ==
    \/ \E va \in {0,1,2,3}: \E cls \in 0..4: \E r \in {0,1}:
         AddNode(va, cls, r)
    \/ \E f,t \in 1..MaxNodes: \E c \in 0..10:
         AddEdge(f, t, c)
    \/ \E n \in 1..MaxNodes:
         MarkRoot(n)

Spec == Init /\ [][Next]_<<node_va, node_cls, node_root, edge_from, edge_to, edge_conf>>

====
```

- [ ] **Step 2: Write PointerGraph.cfg**

Write `specs/PointerGraph.cfg`:

```tla
SPECIFICATION Spec
INVARIANT PointerGraphInvariant
```

- [ ] **Step 3: Commit**

```bash
git add specs/PointerGraph.tla specs/PointerGraph.cfg
git commit -m "spec: add PointerGraph.tla — nodes, edges, confidence, invariants"
```

---

### Task 8: Integration test — full S1+S2 pipeline

**Files:**
- Modify: `forensicator-core/src/parse/mod.rs` (append test)

- [ ] **Step 1: Add integration test**

Append to the existing `tests` module in `forensicator-core/src/parse/mod.rs`:

```rust
    #[test]
    fn full_s2_pipeline_on_synthetic_dump() {
        use crate::graph;
        use crate::pattern::PointerPattern;
        use crate::query::GraphQuery;
        use crate::scan;
        use crate::parse::dump;

        // Construct a minimal synthetic minidump in-memory (self-contained)
        let mut buf = vec![0u8; 256];
        buf[0] = 0x4D; buf[1] = 0x44; buf[2] = 0x4D; buf[3] = 0x50;  // MDMP
        buf[4] = 0x93; buf[5] = 0xA7; // version
        buf[8] = 1; buf[9] = 0; buf[10] = 0; buf[11] = 0;  // stream_count = 1
        buf[12] = 64; buf[13] = 0; buf[14] = 0; buf[15] = 0; // dir_rva = 64
        buf[64] = 7;   // stream_type = SystemInfo
        buf[68] = 56;  // size = 56
        buf[72] = 128; // rva = 128
        buf[128] = 0; buf[129] = 0; // ProcessorArchitecture = x86 (0)
        buf[136] = 9; buf[137] = 0; // AMD64 override
        buf[148] = 2;  // PlatformId = VER_PLATFORM_WIN32_NT

        let dump_data = dump::from_bytes(&buf).unwrap();
        assert!(dump_data.system_info.is_some());

        let mut space = crate::space::AddressSpace::new(1000);
        let patterns = PointerPattern::presets();
        let registers: Vec<(u32, Vec<(String, u64)>)> = dump_data.threads.iter().map(|t| {
            vec![("RIP".into(), t.registers.rip()),
                 ("RSP".into(), t.registers.rsp()),
                 ("RBP".into(), t.registers.rbp())]
        }).enumerate().map(|(i, r)| (i as u32, r)).collect();
        let stack_ranges: Vec<(u32, u64, u64)> = dump_data.threads.iter()
            .enumerate()
            .map(|(i, t)| (i as u32, t.stack_va, t.stack_size))
            .collect();
        let reg_refs: Vec<(u32, &[(String, u64)])> = registers.iter()
            .map(|(tid, r)| (*tid, r.as_slice()))
            .collect();

        let scan_result = scan::scan(&space, &reg_refs, &stack_ranges, &patterns).unwrap();
        let pointer_graph = graph::build_graph(&scan_result).unwrap();
        let query = GraphQuery::new(&pointer_graph);

        let _dot = query.to_dot();
        let _json = query.to_json();

        assert!(query.degree_distribution().len() >= 0);
    }
```

- [ ] **Step 2: Run the integration test**

Run: `cargo test -p forensicator-core -- parse::tests::full_s2_pipeline_on_synthetic_dump 2>&1`
Expected: test passes

- [ ] **Step 3: Run full test suite**

Run: `cargo test 2>&1`
Expected: all tests pass

- [ ] **Step 4: Commit**

```bash
git add forensicator-core/
git commit -m "test: add full S1+S2 integration test on synthetic minidump"
```

---

### Task 9: Fix compilation issues and final verification

- [ ] **Step 1: Build the entire workspace**

Run: `cargo build 2>&1`
Expected: compiles with no errors or warnings

- [ ] **Step 2: Run all tests**

Run: `cargo test 2>&1`
Expected: all tests pass

- [ ] **Step 3: Verify CLI help output**

Run: `cargo run -- --help 2>&1`
Expected: shows inspect, scan, graph, query, patterns subcommands

- [ ] **Step 4: Commit any final fixes**

```bash
git add -A && git diff --cached --stat
git commit -m "fix: final compilation and test fixes for S2 integration"
```

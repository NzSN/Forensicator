use crate::arch::RegisterSet;
use crate::error::{Anomaly, Provenance};

/// OS platform identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsPlatform {
    Windows = 0,
    Linux = 1,
    MacOs = 2,
}

/// CPU architecture identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuArch {
    X86 = 0,
    X64 = 1,
    Arm64 = 2,
}

/// System information extracted from the minidump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemInfo {
    pub os: OsPlatform,
    pub cpu: CpuArch,
    pub version: (u32, u32, u32, u32),
    pub provenance: Provenance,
}

/// A loaded module (DLL/EXE) found in the process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Module {
    pub name: String,
    pub base_va: u64,
    pub size: u64,
    pub checksum: u32,
    pub codeview_guid: Option<[u8; 16]>,
    pub pdb_name: Option<String>,
    pub provenance: Provenance,
}

/// A thread in the process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thread {
    pub id: u32,
    pub registers: RegisterSet,
    pub stack_va: u64,
    pub stack_size: u64,
    pub teb_va: u64,
    pub provenance: Provenance,
}

/// Memory protection flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protection(u32);

impl Protection {
    pub const READ: u32 = 1;
    pub const WRITE: u32 = 2;
    pub const EXECUTE: u32 = 4;
    pub const GUARD: u32 = 8;
    pub const NO_CACHE: u32 = 16;

    pub fn new(flags: u32) -> Self { Protection(flags) }
    pub fn is_readable(&self) -> bool { self.0 & Self::READ != 0 }
    pub fn is_writable(&self) -> bool { self.0 & Self::WRITE != 0 }
    pub fn is_executable(&self) -> bool { self.0 & Self::EXECUTE != 0 }
}

/// Memory state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemState {
    Commit = 0,
    Reserve = 1,
    Free = 2,
}

impl MemState {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(MemState::Commit),
            1 => Some(MemState::Reserve),
            2 => Some(MemState::Free),
            _ => None,
        }
    }
}

/// Memory type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemType {
    Private = 0,
    Mapped = 1,
    Image = 2,
}

impl MemType {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(MemType::Private),
            1 => Some(MemType::Mapped),
            2 => Some(MemType::Image),
            _ => None,
        }
    }
}

/// High-level classification of a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegionClass {
    Image,
    Stack,
    Mapped,
    Private,
    Other,
}

/// Static description of a memory region from the dump metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegionInfo {
    pub va_start: u64,
    pub size: u64,
    pub protection: Protection,
    pub state: MemState,
    pub mem_type: MemType,
    pub provenance: Provenance,
}

/// Exception information from the dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionInfo {
    pub code: u32,
    pub address: u64,
    pub thread_id: u32,
    pub flags: u32,
    pub context: Option<RegisterSet>,
    pub provenance: Provenance,
}

/// The assembled dump — the output of the parse pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dump {
    pub system_info: Option<SystemInfo>,
    pub modules: Vec<Module>,
    pub threads: Vec<Thread>,
    pub memory_regions: Vec<MemoryRegionInfo>,
    pub exception: Option<ExceptionInfo>,
    pub anomalies: Vec<Anomaly>,
    pub file_size: u64,
}

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
    /// Value is aligned to N bytes (N must be a power of 2).
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
                let mask = (n as u64).wrapping_sub(1);
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

impl Root {
    pub fn va(&self) -> u64 {
        match *self {
            Root::Register { va, .. } => va,
            Root::Stack { va, .. } => va,
            Root::ModuleData { va, .. } => va,
        }
    }
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
#[derive(Debug, Clone)]
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
    pub fn max_nodes(&self) -> usize { self.max_nodes }
    pub fn max_edges(&self) -> usize { self.max_edges }

    pub fn node(&self, va: u64) -> Option<&GraphNode> {
        self.va_to_node.get(&va).map(|&idx| &self.nodes[idx.0])
    }
}

impl Default for PointerGraph {
    fn default() -> Self { Self::new() }
}

/// Predicate for filtering graph edges during traversal.
///
/// `source_region`, `target_region`, and `max_depth` are checked by
/// `matches_with_nodes()` (or by the query module's BFS logic) — they
/// require access to `GraphNode` data that the basic `matches()` does
/// not have.
#[derive(Debug, Clone, PartialEq)]
pub struct EdgePredicate {
    pub min_confidence: f64,
    pub max_confidence: f64,
    /// Checked by `matches_with_nodes()` / GraphQuery — requires source node ref.
    pub source_region: Option<RegionClass>,
    /// Checked by `matches_with_nodes()` / GraphQuery — requires target node ref.
    pub target_region: Option<RegionClass>,
    /// Checked by the query module's BFS traversal, not by `matches()`.
    pub max_depth: Option<usize>,
    pub matched_by_pattern: Option<String>,
}

impl EdgePredicate {
    /// Check edge-level fields (confidence, matched_by_pattern) only.
    pub fn matches(&self, edge: &GraphEdge) -> bool {
        if edge.confidence < self.min_confidence { return false; }
        if edge.confidence > self.max_confidence { return false; }
        if let Some(ref pat) = self.matched_by_pattern {
            if !edge.matched_by.iter().any(|m| m == pat) { return false; }
        }
        true
    }

    /// Full check including region and depth filters that require node references.
    pub fn matches_with_nodes(
        &self,
        edge: &GraphEdge,
        source_node: &GraphNode,
        target_node: &GraphNode,
        current_depth: usize,
    ) -> bool {
        if !self.matches(edge) { return false; }
        if let Some(ref region) = self.source_region {
            if source_node.region_class != *region { return false; }
        }
        if let Some(ref region) = self.target_region {
            if target_node.region_class != *region { return false; }
        }
        if let Some(max) = self.max_depth {
            if current_depth > max { return false; }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Provenance;

    fn dummy_prov() -> Provenance {
        Provenance { stream_type: 0, file_offset: 0, rva: 0 }
    }

    #[test]
    fn protection_flags() {
        let p = Protection::new(Protection::READ | Protection::WRITE);
        assert!(p.is_readable());
        assert!(p.is_writable());
        assert!(!p.is_executable());
    }

    #[test]
    fn mem_state_from_u32() {
        assert_eq!(MemState::from_u32(0), Some(MemState::Commit));
        assert_eq!(MemState::from_u32(3), None);
    }

    #[test]
    fn mem_type_from_u32() {
        assert_eq!(MemType::from_u32(1), Some(MemType::Mapped));
        assert_eq!(MemType::from_u32(5), None);
    }

    #[test]
    fn dump_empty() {
        let d = Dump {
            system_info: None, modules: vec![], threads: vec![],
            memory_regions: vec![], exception: None, anomalies: vec![],
            file_size: 0,
        };
        assert_eq!(d.modules.len(), 0);
    }

    #[test]
    fn system_info_with_provenance() {
        let si = SystemInfo {
            os: OsPlatform::Windows, cpu: CpuArch::X64,
            version: (10, 0, 19041, 0), provenance: dummy_prov(),
        };
        assert_eq!(si.cpu, CpuArch::X64);
    }

    #[test]
    fn protection_execute_only() {
        let p = Protection::new(Protection::EXECUTE);
        assert!(!p.is_readable());
        assert!(!p.is_writable());
        assert!(p.is_executable());
    }

    #[test]
    fn protection_guard_and_nocache() {
        let p = Protection::new(Protection::GUARD | Protection::NO_CACHE);
        assert!(!p.is_readable());
    }

    #[test]
    fn mem_state_all_variants() {
        assert_eq!(MemState::from_u32(0), Some(MemState::Commit));
        assert_eq!(MemState::from_u32(1), Some(MemState::Reserve));
        assert_eq!(MemState::from_u32(2), Some(MemState::Free));
        assert_eq!(MemState::from_u32(99), None);
    }

    #[test]
    fn mem_type_all_variants() {
        assert_eq!(MemType::from_u32(0), Some(MemType::Private));
        assert_eq!(MemType::from_u32(1), Some(MemType::Mapped));
        assert_eq!(MemType::from_u32(2), Some(MemType::Image));
        assert_eq!(MemType::from_u32(99), None);
    }

    #[test]
    fn thread_construction() {
        let registers = RegisterSet::new();
        let t = Thread {
            id: 1234,
            registers,
            stack_va: 0x7FFE_0000,
            stack_size: 0x10000,
            teb_va: 0x7FFD_E000,
            provenance: dummy_prov(),
        };
        assert_eq!(t.id, 1234);
        assert_eq!(t.stack_va, 0x7FFE_0000);
        assert_eq!(t.stack_size, 0x10000);
        assert_eq!(t.teb_va, 0x7FFD_E000);
    }

    #[test]
    fn module_with_pdb() {
        let mut guid = [0u8; 16];
        guid[0] = 0xAB; guid[1] = 0xCD;
        let m = Module {
            name: "ntdll.dll".into(),
            base_va: 0x7FFA_0000,
            size: 0x200000,
            checksum: 0x12345678,
            codeview_guid: Some(guid),
            pdb_name: Some("ntdll.pdb".into()),
            provenance: dummy_prov(),
        };
        assert_eq!(m.name, "ntdll.dll");
        assert!(m.codeview_guid.is_some());
        assert_eq!(m.pdb_name.as_deref(), Some("ntdll.pdb"));
    }

    #[test]
    fn module_without_pdb() {
        let m = Module {
            name: "unknown.dll".into(),
            base_va: 0x10000000,
            size: 0x5000,
            checksum: 0,
            codeview_guid: None,
            pdb_name: None,
            provenance: dummy_prov(),
        };
        assert!(m.codeview_guid.is_none());
        assert!(m.pdb_name.is_none());
    }

    #[test]
    fn exception_info_with_context() {
        let ctx = RegisterSet::new();
        let exc = ExceptionInfo {
            code: 0xC0000005,
            address: 0x7FFA_1234,
            thread_id: 42,
            flags: 0,
            context: Some(ctx.clone()),
            provenance: dummy_prov(),
        };
        assert_eq!(exc.code, 0xC0000005);
        assert_eq!(exc.address, 0x7FFA_1234);
        assert!(exc.context.is_some());
    }

    #[test]
    fn exception_info_without_context() {
        let exc = ExceptionInfo {
            code: 0x80000003,
            address: 0x1000,
            thread_id: 1,
            flags: 1,
            context: None,
            provenance: dummy_prov(),
        };
        assert!(exc.context.is_none());
    }

    #[test]
    fn memory_region_info_construction() {
        let mri = MemoryRegionInfo {
            va_start: 0x400000,
            size: 0x1000,
            protection: Protection::new(Protection::READ),
            state: MemState::Commit,
            mem_type: MemType::Image,
            provenance: dummy_prov(),
        };
        assert_eq!(mri.va_start, 0x400000);
        assert_eq!(mri.size, 0x1000);
        assert_eq!(mri.state, MemState::Commit);
        assert_eq!(mri.mem_type, MemType::Image);
        assert!(mri.protection.is_readable());
    }

    #[test]
    fn dump_with_all_fields() {
        let si = SystemInfo {
            os: OsPlatform::Windows, cpu: CpuArch::X64,
            version: (10, 0, 22000, 0), provenance: dummy_prov(),
        };
        let m = Module {
            name: "test.exe".into(), base_va: 0x140000000, size: 0x1000,
            checksum: 0, codeview_guid: None, pdb_name: None,
            provenance: dummy_prov(),
        };
        let t = Thread {
            id: 1, registers: RegisterSet::new(),
            stack_va: 0x7FFE_0000, stack_size: 0x10000, teb_va: 0x7FFD_E000,
            provenance: dummy_prov(),
        };
        let exc = ExceptionInfo {
            code: 0xC0000005, address: 0, thread_id: 1, flags: 0,
            context: None, provenance: dummy_prov(),
        };
        let d = Dump {
            system_info: Some(si),
            modules: vec![m],
            threads: vec![t],
            memory_regions: vec![],
            exception: Some(exc),
            anomalies: vec![],
            file_size: 1024,
        };
        assert_eq!(d.modules.len(), 1);
        assert_eq!(d.threads.len(), 1);
        assert!(d.system_info.is_some());
        assert!(d.exception.is_some());
        assert_eq!(d.file_size, 1024);
    }

    #[test]
    fn os_platform_discriminants() {
        assert_eq!(OsPlatform::Windows as u32, 0);
        assert_eq!(OsPlatform::Linux as u32, 1);
        assert_eq!(OsPlatform::MacOs as u32, 2);
    }

    #[test]
    fn cpu_arch_discriminants() {
        assert_eq!(CpuArch::X86 as u32, 0);
        assert_eq!(CpuArch::X64 as u32, 1);
        assert_eq!(CpuArch::Arm64 as u32, 2);
    }

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
        assert!(!ValueMatcher::CanonicalX64.eval(0x0000_8000_00001000));
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
}

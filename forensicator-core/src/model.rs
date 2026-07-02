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
    pub fn bits(&self) -> u32 {
        self.0
    }
    pub const READ: u32 = 1;
    pub const WRITE: u32 = 2;
    pub const EXECUTE: u32 = 4;
    pub const GUARD: u32 = 8;
    pub const NO_CACHE: u32 = 16;

    pub fn new(flags: u32) -> Self {
        Protection(flags)
    }
    pub fn is_readable(&self) -> bool {
        self.0 & Self::READ != 0
    }
    pub fn is_writable(&self) -> bool {
        self.0 & Self::WRITE != 0
    }
    pub fn is_executable(&self) -> bool {
        self.0 & Self::EXECUTE != 0
    }
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
    pub data: Vec<u8>,
    pub protection: Protection,
    pub state: MemState,
    pub mem_type: MemType,
    pub provenance: Provenance,
    pub region_class: Option<RegionClass>,
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
    pub annotations: Vec<(String, String)>,
    pub file_size: u64,
}

/// State‑transition constants mirroring Model.tla.
impl Dump {
    pub const MAX_MODULES: usize = 2;
    pub const MAX_THREADS: usize = 2;
    pub const MAX_REGIONS: usize = 2;
    pub const MAX_ANOMALIES: usize = 4;

    /// Set system information — once‑only, requires provenance.
    pub fn set_sys_info(
        &mut self,
        os: OsPlatform,
        cpu: CpuArch,
        version: (u32, u32, u32, u32),
        provenance: Provenance,
    ) {
        if self.system_info.is_some() {
            return;
        }
        if provenance.stream_type == 0 {
            return;
        }
        self.system_info = Some(SystemInfo {
            os,
            cpu,
            version,
            provenance,
        });
    }

    /// Add a module.  If the new module overlaps an existing one, records an
    /// "overlapping module" anomaly instead (matching Model.tla).
    pub fn add_module(&mut self, base_va: u64, size: u64, provenance: Provenance) {
        if self.modules.len() >= Self::MAX_MODULES {
            return;
        }
        if size == 0 || provenance.stream_type == 0 {
            return;
        }
        if self.has_module_overlap(base_va, size) {
            if self.anomalies.len() < Self::MAX_ANOMALIES {
                self.anomalies.push(Anomaly {
                    provenance: Provenance {
                        stream_type: 0,
                        file_offset: 0,
                        rva: 0,
                    },
                    description: "overlapping module".into(),
                });
            }
            return;
        }
        self.modules.push(Module {
            name: String::new(),
            base_va,
            size,
            checksum: 0,
            codeview_guid: None,
            pdb_name: None,
            provenance,
        });
    }

    fn has_module_overlap(&self, va: u64, sz: u64) -> bool {
        for m in &self.modules {
            let mva = m.base_va;
            let msz = m.size;
            if mva < va + sz && va < mva + msz {
                return true;
            }
        }
        false
    }

    /// Add a thread.
    pub fn add_thread(&mut self, id: u32, stack_va: u64, stack_size: u64, provenance: Provenance) {
        if self.threads.len() >= Self::MAX_THREADS {
            return;
        }
        if stack_size == 0 || provenance.stream_type == 0 {
            return;
        }
        self.threads.push(Thread {
            id,
            registers: RegisterSet::new(),
            stack_va,
            stack_size,
            teb_va: 0,
            provenance,
        });
    }

    /// Add a memory region with its classification.
    pub fn add_region(
        &mut self,
        va_start: u64,
        size: u64,
        protection: Protection,
        state: MemState,
        mem_type: MemType,
        class: RegionClass,
        provenance: Provenance,
    ) {
        if self.memory_regions.len() >= Self::MAX_REGIONS {
            return;
        }
        if size == 0 || provenance.stream_type == 0 {
            return;
        }
        self.memory_regions.push(MemoryRegionInfo {
            va_start,
            size,
            data: vec![],
            protection,
            state,
            mem_type,
            provenance,
            region_class: Some(class),
        });
    }

    /// Set exception information — once‑only, requires provenance.
    pub fn set_exception(
        &mut self,
        code: u32,
        address: u64,
        thread_id: u32,
        flags: u32,
        provenance: Provenance,
    ) {
        if self.exception.is_some() {
            return;
        }
        if provenance.stream_type == 0 {
            return;
        }
        self.exception = Some(ExceptionInfo {
            code,
            address,
            thread_id,
            flags,
            context: None,
            provenance,
        });
    }

    /// Record a non‑fatal anomaly.
    pub fn add_anomaly(&mut self, description: &str) {
        if self.anomalies.len() >= Self::MAX_ANOMALIES {
            return;
        }
        self.anomalies.push(Anomaly {
            provenance: Provenance {
                stream_type: 0,
                file_offset: 0,
                rva: 0,
            },
            description: description.to_string(),
        });
    }
}

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
                if divisor == 0 {
                    false
                } else {
                    value % divisor == remainder
                }
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
    pub target_va: u64,
    pub source_ctx: SourceContext,
    pub target_ctx: TargetContext,
    pub confidence: f64,
}

/// String encoding detected by the string scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
    Utf16Be,
}

/// A null-terminated string found in memory.
#[derive(Debug, Clone, PartialEq)]
pub struct StructString {
    pub va: u64,
    pub byte_len: usize,
    pub encoding: StringEncoding,
    pub content: String,
    pub confidence: f64,
}

/// A virtual method table found in module data.
#[derive(Debug, Clone, PartialEq)]
pub struct StructVTable {
    pub va: u64,
    pub method_count: usize,
    pub methods: Vec<u64>,
    pub module_name: Option<String>,
    pub confidence: f64,
}

/// A linked list detected in the pointer graph.
#[derive(Debug, Clone, PartialEq)]
pub struct StructLinkedList {
    pub head_va: u64,
    pub length: usize,
    pub stride: u64,
    pub next_offset: u64,
    pub is_circular: bool,
    pub nodes: Vec<u64>,
    pub avg_confidence: f64,
}

/// An array of structurally identical objects.
#[derive(Debug, Clone, PartialEq)]
pub struct StructArray {
    pub start_va: u64,
    pub element_size: u64,
    pub count: usize,
    pub out_degree: usize,
    pub region_class: RegionClass,
    pub elements: Vec<u64>,
    pub confidence: f64,
}

/// An inferred heap allocation chunk.
#[derive(Debug, Clone, PartialEq)]
pub struct StructChunk {
    pub va_start: u64,
    pub size: u64,
    pub is_free: bool,
    pub node_count: usize,
    pub pointer_density: f64,
    pub confidence: f64,
}

/// A structural signature: ordered list of (offset, target_class) edges.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ShapeSignature {
    pub edges: Vec<(u64, RegionClass)>,
}

/// A group of heap nodes sharing the same shape.
#[derive(Debug, Clone, PartialEq)]
pub struct ShapeGroup {
    pub id: usize,
    pub signature: ShapeSignature,
    pub member_count: usize,
    pub members: Vec<u64>,
}

/// Result of a pointer scan pass.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanResult {
    pub candidates: Vec<CandidatePointer>,
}

/// A node in the pointer graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphNode {
    pub va: u64,
    pub size: u64,
    pub region_class: RegionClass,
}

/// An edge in the pointer graph.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphEdge {
    pub source: usize,
    pub target: usize,
    pub offset: u64,
    pub confidence: f64,
}

/// The pointer graph: dual adjacency, va→node map, capacity caps.
#[derive(Debug, Clone)]
pub struct PointerGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub va_to_node: std::collections::HashMap<u64, usize>,
    pub max_nodes: usize,
    pub max_edges: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Provenance;

    fn dummy_prov() -> Provenance {
        Provenance {
            stream_type: 0,
            file_offset: 0,
            rva: 0,
        }
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
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            annotations: vec![],
            file_size: 0,
        };
        assert_eq!(d.modules.len(), 0);
    }

    #[test]
    fn system_info_with_provenance() {
        let si = SystemInfo {
            os: OsPlatform::Windows,
            cpu: CpuArch::X64,
            version: (10, 0, 19041, 0),
            provenance: dummy_prov(),
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
        guid[0] = 0xAB;
        guid[1] = 0xCD;
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
            data: vec![],
            protection: Protection::new(Protection::READ),
            state: MemState::Commit,
            mem_type: MemType::Image,
            provenance: dummy_prov(),
            region_class: None,
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
            os: OsPlatform::Windows,
            cpu: CpuArch::X64,
            version: (10, 0, 22000, 0),
            provenance: dummy_prov(),
        };
        let m = Module {
            name: "test.exe".into(),
            base_va: 0x140000000,
            size: 0x1000,
            checksum: 0,
            codeview_guid: None,
            pdb_name: None,
            provenance: dummy_prov(),
        };
        let t = Thread {
            id: 1,
            registers: RegisterSet::new(),
            stack_va: 0x7FFE_0000,
            stack_size: 0x10000,
            teb_va: 0x7FFD_E000,
            provenance: dummy_prov(),
        };
        let exc = ExceptionInfo {
            code: 0xC0000005,
            address: 0,
            thread_id: 1,
            flags: 0,
            context: None,
            provenance: dummy_prov(),
        };
        let d = Dump {
            system_info: Some(si),
            modules: vec![m],
            threads: vec![t],
            memory_regions: vec![],
            exception: Some(exc),
            anomalies: vec![],
            annotations: vec![],
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
    fn value_matcher_aligned_to_matches() {
        assert!(ValueMatcher::AlignedTo(8).eval(0x7FFA_1000));
        assert!(!ValueMatcher::AlignedTo(8).eval(0x7FFA_1001));
    }

    #[test]
    fn value_matcher_in_range() {
        let m = ValueMatcher::InRange {
            lo: 0x1000,
            hi: 0x2000,
        };
        assert!(m.eval(0x1500));
        assert!(!m.eval(0x3000));
    }

    #[test]
    fn value_matcher_canonical_x64() {
        assert!(ValueMatcher::CanonicalX64.eval(0x00007FFA_00001000));
        assert!(!ValueMatcher::CanonicalX64.eval(0x0000_8000_0000_1000));
    }

    #[test]
    fn value_matcher_bitmask() {
        let m = ValueMatcher::BitMask {
            mask: 0xFF,
            expected: 0xAB,
        };
        assert!(m.eval(0x7FFA_10AB));
        assert!(!m.eval(0x7FFA_10CD));
    }

    #[test]
    fn value_matcher_modulo() {
        let m = ValueMatcher::Modulo {
            divisor: 4,
            remainder: 0,
        };
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
            target_va: 0x7FFA_2000,
            source_ctx: SourceContext::Stack { thread_id: Some(1) },
            target_ctx: TargetContext::Image,
            confidence: 0.85,
        };
        assert_eq!(c.source_va, 0x1000);
        assert_eq!(c.confidence, 0.85);
    }

    #[test]
    fn string_encoding_variants() {
        assert!(matches!(StringEncoding::Ascii, StringEncoding::Ascii));
        assert!(matches!(StringEncoding::Utf16Le, StringEncoding::Utf16Le));
        assert!(matches!(StringEncoding::Utf16Be, StringEncoding::Utf16Be));
    }

    #[test]
    fn struct_string_construction() {
        let s = StructString {
            va: 0x1000,
            byte_len: 12,
            encoding: StringEncoding::Ascii,
            content: "hello".into(),
            confidence: 0.95,
        };
        assert_eq!(s.va, 0x1000);
        assert_eq!(s.byte_len, 12);
        assert_eq!(s.content, "hello");
        assert!(s.confidence <= 1.0);
    }

    #[test]
    fn struct_vtable_construction() {
        let v = StructVTable {
            va: 0x400000,
            method_count: 3,
            methods: vec![0x401000, 0x402000, 0x403000],
            module_name: Some("test.dll".into()),
            confidence: 0.9,
        };
        assert_eq!(v.method_count, 3);
        assert_eq!(v.methods.len(), 3);
    }

    #[test]
    fn struct_linked_list_construction() {
        let l = StructLinkedList {
            head_va: 0x1000,
            length: 5,
            stride: 0x20,
            next_offset: 0x08,
            is_circular: false,
            nodes: vec![0x1000, 0x1020],
            avg_confidence: 0.8,
        };
        assert_eq!(l.length, 5);
        assert!(!l.is_circular);
    }

    #[test]
    fn struct_array_construction() {
        let a = StructArray {
            start_va: 0x2000,
            element_size: 0x10,
            count: 4,
            out_degree: 1,
            region_class: RegionClass::Private,
            elements: vec![0x2000, 0x2010, 0x2020, 0x2030],
            confidence: 0.85,
        };
        assert_eq!(a.count, 4);
        assert_eq!(a.element_size, 0x10);
    }

    #[test]
    fn struct_chunk_construction() {
        let c = StructChunk {
            va_start: 0x10000,
            size: 0x1000,
            is_free: false,
            node_count: 12,
            pointer_density: 0.75,
            confidence: 0.6,
        };
        assert_eq!(c.size, 0x1000);
        assert!(!c.is_free);
    }

    #[test]
    fn shape_signature_construction() {
        let sig = ShapeSignature {
            edges: vec![(0x00, RegionClass::Image), (0x08, RegionClass::Private)],
        };
        assert_eq!(sig.edges.len(), 2);
    }

    #[test]
    fn shape_group_construction() {
        let sig = ShapeSignature {
            edges: vec![(0x00, RegionClass::Private)],
        };
        let g = ShapeGroup {
            id: 0,
            signature: sig,
            member_count: 5,
            members: vec![],
        };
        assert_eq!(g.member_count, 5);
    }
}

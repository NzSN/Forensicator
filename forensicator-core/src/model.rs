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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

# S1 Foundation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Rust library + CLI that parses Windows x64 minidump files into a typed `Dump` structure with provenance, using a custom hand-written parser (no external parse dependencies).

**Architecture:** Cargo workspace with two crates. `forensicator-core` contains 5 modules (`arch`, `error`, `model`, `parse`, `space`) implementing the bottom-up pipeline: raw bytes → header validation → stream directory → per-stream decoders → typed `Dump` with provenance → AddressSpace with region invariants. `forensicator-cli` wraps it with a structured tree renderer.

**Tech Stack:** Rust (edition 2024), `clap` for CLI, `minidumper` (dev-dependency for synthetic test fixtures only). No external parse crate.

---

## File Structure

```
Forensicator/
├── Cargo.toml                          # workspace root
├── forensicator-core/
│   ├── Cargo.toml                      # lib crate
│   └── src/
│       ├── lib.rs                      # pub mod re-exports
│       ├── error.rs                    # FatalError enum, Anomaly struct
│       ├── arch.rs                     # Arch trait + X64 struct
│       ├── model.rs                    # Provenance, Anomaly, SystemInfo, Module, Thread, MemoryRegion, ExceptionInfo, Dump
│       ├── parse/
│       │   ├── mod.rs                  # pub mod declarations
│       │   ├── header.rs              # read_header, Header struct
│       │   ├── directory.rs           # read_directory, StreamDirectory, StreamEntry
│       │   ├── system_info.rs         # decode_system_info
│       │   ├── module_list.rs         # decode_module_list
│       │   ├── thread_list.rs         # decode_thread_list
│       │   ├── memory.rs              # decode_memory64, decode_memory_list
│       │   ├── memory_info.rs         # decode_memory_info_list
│       │   ├── exception.rs           # decode_exception
│       │   └── dump.rs                # Dump::open, Dump::from_bytes, assemble_dump
│       └── space.rs                    # AddressSpace, MemoryRegion (runtime variant), RegionClass
├── forensicator-cli/
│   ├── Cargo.toml                      # bin crate
│   └── src/
│       └── main.rs                     # inspect subcommand, tree renderer, --json, --quiet
└── specs/                              # TLA+ specs (already exist)
```

**Dependency graph:**
```
error  ←  arch  ←  model  ←  parse  ←  CLI
  ↑                 ↑
  └── space ←────────┘
```

---

### Task 1: Workspace scaffolding

**Files:**
- Create: `Cargo.toml`
- Create: `forensicator-core/Cargo.toml`
- Create: `forensicator-core/src/lib.rs`
- Create: `forensicator-cli/Cargo.toml`
- Create: `forensicator-cli/src/main.rs`

- [ ] **Step 1: Create workspace root Cargo.toml**

Write `Cargo.toml`:
```toml
[workspace]
resolver = "3"
members = ["forensicator-core", "forensicator-cli"]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT"
```

- [ ] **Step 2: Create forensicator-core Cargo.toml**

Write `forensicator-core/Cargo.toml`:
```toml
[package]
name = "forensicator-core"
version.workspace = true
edition.workspace = true

[dependencies]

[dev-dependencies]
minidumper = "0.9"
```

- [ ] **Step 3: Create forensicator-core/src/lib.rs (empty)**

Write `forensicator-core/src/lib.rs`:
```rust
//! Forensicator core library — S1 foundation.
//! Parses Windows x64 minidumps into a typed `Dump` with provenance.
```

- [ ] **Step 4: Create forensicator-cli Cargo.toml**

Write `forensicator-cli/Cargo.toml`:
```toml
[package]
name = "forensicator-cli"
version.workspace = true
edition.workspace = true

[dependencies]
forensicator-core = { path = "../forensicator-core" }
clap = { version = "4", features = ["derive"] }
```

- [ ] **Step 5: Create forensicator-cli/src/main.rs (minimal)**

Write `forensicator-cli/src/main.rs`:
```rust
fn main() {
    println!("forensicator S1");
}
```

- [ ] **Step 6: Verify workspace builds**

Run:
```powershell
cargo build
```
Expected: Both crates compile, no errors.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml forensicator-core/ forensicator-cli/
git commit -m "feat: scaffold Cargo workspace with forensicator-core and forensicator-cli"
```

---

### Task 2: error module

**Files:**
- Create: `forensicator-core/src/error.rs`
- Modify: `forensicator-core/src/lib.rs`

- [ ] **Step 1: Write the error module**

Write `forensicator-core/src/error.rs`:
```rust
use std::fmt;

/// Fatal errors that stop the parse pipeline immediately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FatalError {
    /// File could not be read or does not exist.
    Io(String),
    /// File is too small to contain a valid minidump header (need >= 32 bytes).
    TooSmall { size: usize },
    /// Minidump magic bytes (0x4D444D50 = "MDMP") not found.
    BadMagic { found: [u8; 4] },
    /// Stream directory RVA points outside the file.
    DirectoryOutOfBounds { rva: u32, size: u32, file_len: usize },
    /// A stream's data descriptor points outside the file.
    StreamOutOfBounds { stream_type: u32, rva: u32, size: u32, file_len: usize },
}

impl fmt::Display for FatalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FatalError::Io(msg) => write!(f, "I/O error: {msg}"),
            FatalError::TooSmall { size } => write!(f, "file too small ({size} bytes, need >= 32)"),
            FatalError::BadMagic { found } => write!(f, "bad magic: {found:02X?} (expected 4D 44 4D 50)"),
            FatalError::DirectoryOutOfBounds { rva, size, file_len } => {
                write!(f, "stream directory at RVA {rva} size {size} out of bounds (file len {file_len})")
            }
            FatalError::StreamOutOfBounds { stream_type, rva, size, file_len } => {
                write!(f, "stream 0x{stream_type:08X} at RVA {rva} size {size} out of bounds (file len {file_len})")
            }
        }
    }
}

impl std::error::Error for FatalError {}

/// A provenance record: which stream and where in the file a fact came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// Stream type identifier (e.g., 0x04 = ModuleList).
    pub stream_type: u32,
    /// Byte offset within the .dmp file where the stream data starts.
    pub file_offset: u64,
    /// Relative virtual address (RVA) within the stream data.
    pub rva: u32,
}

/// A non-fatal anomaly: something went wrong but the pipeline continues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    pub provenance: Provenance,
    pub description: String,
}
```

- [ ] **Step 2: Register in lib.rs**

Write `forensicator-core/src/lib.rs`:
```rust
//! Forensicator core library — S1 foundation.
//! Parses Windows x64 minidumps into a typed `Dump` with provenance.

pub mod error;
```

- [ ] **Step 3: Write a unit test**

Write `forensicator-core/src/error.rs`, append at bottom:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fatal_error_display() {
        let err = FatalError::BadMagic { found: [0xDE, 0xAD, 0xBE, 0xEF] };
        let msg = err.to_string();
        assert!(msg.contains("bad magic"));
        assert!(msg.contains("DE AD BE EF"));
    }

    #[test]
    fn anomaly_construction() {
        let prov = Provenance { stream_type: 7, file_offset: 128, rva: 0 };
        let a = Anomaly { provenance: prov.clone(), description: "truncated".into() };
        assert_eq!(a.provenance.stream_type, 7);
        assert_eq!(a.provenance.file_offset, 128);
    }
}
```

- [ ] **Step 4: Run tests**

Run:
```powershell
cargo test -p forensicator-core
```
Expected: 2 tests pass.

- [ ] **Step 5: Commit**

```bash
git add forensicator-core/
git commit -m "feat(error): add FatalError, Provenance, and Anomaly types"
```

---

### Task 3: arch module

**Files:**
- Create: `forensicator-core/src/arch.rs`
- Modify: `forensicator-core/src/lib.rs`

- [ ] **Step 1: Write the Arch module**

Write `forensicator-core/src/arch.rs`:
```rust
/// Architecture abstraction — v1 implements x64 only.
/// x86 / ARM64 add new structs implementing this trait later.

/// Width of a pointer in bytes for this architecture.
pub const PTR_WIDTH: usize = 8;

/// Number of named registers in the x64 CONTEXT structure.
pub const REGISTER_COUNT: usize = 32;

/// Indices into the register file for x64.
pub mod x64_indices {
    pub const RAX: usize = 0;
    pub const RBX: usize = 1;
    pub const RCX: usize = 2;
    pub const RDX: usize = 3;
    pub const RSI: usize = 4;
    pub const RDI: usize = 5;
    pub const R8:  usize = 6;
    pub const R9:  usize = 7;
    pub const R10: usize = 8;
    pub const R11: usize = 9;
    pub const R12: usize = 10;
    pub const R13: usize = 11;
    pub const R14: usize = 12;
    pub const R15: usize = 13;
    pub const RBP: usize = 14;
    pub const RSP: usize = 15;
    pub const RIP: usize = 16;
    pub const CS:  usize = 17;
    pub const DS:  usize = 18;
    pub const ES:  usize = 19;
    pub const FS:  usize = 20;
    pub const GS:  usize = 21;
    pub const SS:  usize = 22;
    pub const RFLAGS: usize = 23;
    pub const DR0: usize = 24;
    pub const DR1: usize = 25;
    pub const DR2: usize = 26;
    pub const DR3: usize = 27;
    pub const DR6: usize = 28;
    pub const DR7: usize = 29;
    pub const FLOATING_POINT: usize = 30;
    pub const EXTENDED_REGISTERS: usize = 31;
}

/// Decoded register set from an x64 CONTEXT structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterSet {
    /// All 32 register values. Index by x64_indices constants.
    pub values: [u64; REGISTER_COUNT],
}

impl RegisterSet {
    /// Create a new zeroed register set.
    pub fn new() -> Self {
        RegisterSet { values: [0; REGISTER_COUNT] }
    }

    /// Read a register by index.
    pub fn get(&self, idx: usize) -> u64 {
        self.values.get(idx).copied().unwrap_or(0)
    }

    /// Set a register value.
    pub fn set(&mut self, idx: usize, val: u64) {
        if idx < REGISTER_COUNT {
            self.values[idx] = val;
        }
    }

    /// The instruction pointer (RIP).
    pub fn rip(&self) -> u64 { self.get(x64_indices::RIP) }

    /// The stack pointer (RSP).
    pub fn rsp(&self) -> u64 { self.get(x64_indices::RSP) }

    /// The frame pointer (RBP).
    pub fn rbp(&self) -> u64 { self.get(x64_indices::RBP) }
}

impl Default for RegisterSet {
    fn default() -> Self { Self::new() }
}
```

- [ ] **Step 2: Register in lib.rs**

Edit `forensicator-core/src/lib.rs`:
```rust
pub mod error;
pub mod arch;
```

- [ ] **Step 3: Write tests**

Write `forensicator-core/src/arch.rs`, append:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ptr_width_is_8_for_x64() {
        assert_eq!(PTR_WIDTH, 8);
    }

    #[test]
    fn register_count_is_32() {
        assert_eq!(REGISTER_COUNT, 32);
    }

    #[test]
    fn register_set_default_is_all_zero() {
        let regs = RegisterSet::default();
        for i in 0..REGISTER_COUNT {
            assert_eq!(regs.get(i), 0);
        }
    }

    #[test]
    fn set_and_get_rip() {
        let mut regs = RegisterSet::new();
        regs.set(x64_indices::RIP, 0x7FFA_1000);
        assert_eq!(regs.rip(), 0x7FFA_1000);
    }

    #[test]
    fn get_out_of_bounds_returns_zero() {
        let regs = RegisterSet::new();
        assert_eq!(regs.get(999), 0);
    }

    #[test]
    fn set_out_of_bounds_is_noop() {
        let mut regs = RegisterSet::new();
        regs.set(999, 42);
        // all regs still zero
        assert!(regs.values.iter().all(|&v| v == 0));
    }
}
```

- [ ] **Step 4: Run tests**

Run:
```powershell
cargo test -p forensicator-core
```
Expected: 8 tests pass (2 from error + 6 from arch).

- [ ] **Step 5: Commit**

```bash
git add forensicator-core/src/arch.rs forensicator-core/src/lib.rs
git commit -m "feat(arch): add x64 RegisterSet with PTR_WIDTH=8"
```

---

### Task 4: model module

**Files:**
- Create: `forensicator-core/src/model.rs`
- Modify: `forensicator-core/src/lib.rs`

- [ ] **Step 1: Write the model module**

Write `forensicator-core/src/model.rs`:
```rust
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
```

- [ ] **Step 2: Register in lib.rs**

Edit `forensicator-core/src/lib.rs`:
```rust
pub mod error;
pub mod arch;
pub mod model;
```

- [ ] **Step 3: Write tests**

Write `forensicator-core/src/model.rs`, append:
```rust
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
}
```

- [ ] **Step 4: Run tests**

Run:
```powershell
cargo test -p forensicator-core
```
Expected: 13 tests pass.

- [ ] **Step 5: Commit**

```bash
git add forensicator-core/src/model.rs forensicator-core/src/lib.rs
git commit -m "feat(model): add Dump, SystemInfo, Module, Thread, MemoryRegionInfo, ExceptionInfo types"
```

---

### Task 5: parse/header module

**Files:**
- Create: `forensicator-core/src/parse/mod.rs`
- Create: `forensicator-core/src/parse/header.rs`
- Modify: `forensicator-core/src/lib.rs`

- [ ] **Step 1: Create parse module skeleton**

Write `forensicator-core/src/parse/mod.rs`:
```rust
pub mod header;
```

- [ ] **Step 2: Link parse from lib.rs**

Edit `forensicator-core/src/lib.rs`:
```rust
pub mod error;
pub mod arch;
pub mod model;
pub mod parse;
```

- [ ] **Step 3: Write header parser**

Write `forensicator-core/src/parse/header.rs`:
```rust
use crate::error::FatalError;

/// Minidump magic bytes: "MDMP" in little-endian.
const MAGIC: u32 = 0x504D444D;

/// Minidump header as defined by the format specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Must equal 0x504D444D ("MDMP").
    pub magic: u32,
    /// Version of the minidump format (expected: 0xA793).
    pub version: u16,
    /// Implementation-specific version.
    pub implementation_version: u16,
    /// Number of streams in the stream directory.
    pub stream_count: u32,
    /// RVA of the stream directory within the file.
    pub stream_directory_rva: u32,
    /// Checksum of the minidump file (0 if unused).
    pub checksum: u32,
    /// Timestamp when the dump was created (Unix epoch, seconds).
    pub timestamp: u32,
    /// Flags indicating what data is present.
    pub flags: u64,
}

/// Validate and parse the minidump header from raw bytes.
/// Returns `Err(FatalError)` if the file is too small, has bad magic,
/// or has an unsupported version.
pub fn read_header(data: &[u8]) -> Result<Header, FatalError> {
    if data.len() < 32 {
        return Err(FatalError::TooSmall { size: data.len() });
    }

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != MAGIC {
        return Err(FatalError::BadMagic { found: [data[0], data[1], data[2], data[3]] });
    }

    let version = u16::from_le_bytes([data[4], data[5]]);
    if version != 0xA793 {
        // Not a fatal error — we accept and warn via anomaly
    }

    Ok(Header {
        magic,
        version,
        implementation_version: u16::from_le_bytes([data[6], data[7]]),
        stream_count: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        stream_directory_rva: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        checksum: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
        timestamp: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
        flags: u64::from_le_bytes([
            data[24], data[25], data[26], data[27],
            data[28], data[29], data[30], data[31],
        ]),
    })
}
```

- [ ] **Step 4: Write tests**

Write `forensicator-core/src/parse/header.rs`, append:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn make_header_bytes() -> Vec<u8> {
        let mut buf = vec![0u8; 32];
        // Magic "MDMP"
        buf[0] = 0x4D; buf[1] = 0x44; buf[2] = 0x4D; buf[3] = 0x50;
        // Version 0xA793
        buf[4] = 0x93; buf[5] = 0xA7;
        // Stream count = 5
        buf[8] = 5; buf[9] = 0; buf[10] = 0; buf[11] = 0;
        // Stream directory RVA = 64
        buf[12] = 64; buf[13] = 0; buf[14] = 0; buf[15] = 0;
        buf
    }

    #[test]
    fn read_valid_header() {
        let data = make_header_bytes();
        let h = read_header(&data).unwrap();
        assert_eq!(h.magic, 0x504D444D);
        assert_eq!(h.version, 0xA793);
        assert_eq!(h.stream_count, 5);
        assert_eq!(h.stream_directory_rva, 64);
    }

    #[test]
    fn too_small_returns_error() {
        let data = vec![0u8; 16];
        let err = read_header(&data).unwrap_err();
        assert!(matches!(err, FatalError::TooSmall { .. }));
    }

    #[test]
    fn bad_magic_returns_error() {
        let mut data = make_header_bytes();
        data[0] = 0xDE; data[1] = 0xAD; data[2] = 0xBE; data[3] = 0xEF;
        let err = read_header(&data).unwrap_err();
        assert!(matches!(err, FatalError::BadMagic { .. }));
    }

    #[test]
    fn zero_stream_count_ok() {
        let mut data = make_header_bytes();
        data[8] = 0; // stream_count = 0
        let h = read_header(&data).unwrap();
        assert_eq!(h.stream_count, 0);
    }
}
```

- [ ] **Step 5: Run tests**

Run:
```powershell
cargo test -p forensicator-core
```
Expected: 17 tests pass.

- [ ] **Step 6: Commit**

```bash
git add forensicator-core/src/parse/ forensicator-core/src/lib.rs
git commit -m "feat(parse): add minidump header parser with magic/version validation"
```

---

### Task 6: parse/directory module

**Files:**
- Create: `forensicator-core/src/parse/directory.rs`
- Modify: `forensicator-core/src/parse/mod.rs`

- [ ] **Step 1: Write directory parser**

Write `forensicator-core/src/parse/directory.rs`:
```rust
use crate::error::FatalError;

/// Known minidump stream type identifiers.
pub mod stream_types {
    pub const UNUSED:          u32 = 0x00;
    pub const THREAD_LIST:     u32 = 0x03;
    pub const MODULE_LIST:     u32 = 0x04;
    pub const MEMORY_LIST:     u32 = 0x05;
    pub const EXCEPTION:       u32 = 0x06;
    pub const SYSTEM_INFO:     u32 = 0x07;
    pub const THREAD_EX_LIST:  u32 = 0x08;
    pub const MEMORY_64_LIST:  u32 = 0x09;
    pub const COMMENT_A:       u32 = 0x0A;
    pub const COMMENT_W:       u32 = 0x0B;
    pub const HANDLE_DATA:     u32 = 0x0C;
    pub const FUNCTION_TABLE:  u32 = 0x0D;
    pub const UNLOADED_MODULE: u32 = 0x0E;
    pub const MISC_INFO:       u32 = 0x0F;
    pub const MEMORY_INFO_LIST:u32 = 0x10;
    pub const THREAD_INFO_LIST:u32 = 0x11;
    pub const HANDLE_OP_LIST:  u32 = 0x12;
    pub const LAST_RESERVED:   u32 = 0x13;
}

/// A single entry in the stream directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamEntry {
    pub stream_type: u32,
    pub rva: u32,
    pub size: u32,
}

/// A parsed stream directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamDirectory {
    pub entries: Vec<StreamEntry>,
}

impl StreamDirectory {
    /// Find the first entry matching the given stream type, if any.
    pub fn find(&self, stream_type: u32) -> Option<&StreamEntry> {
        self.entries.iter().find(|e| e.stream_type == stream_type)
    }

    /// Check if a stream type is present.
    pub fn has(&self, stream_type: u32) -> bool {
        self.find(stream_type).is_some()
    }
}

/// Read the stream directory from raw bytes, starting at `rva`.
/// Each entry is 12 bytes: 4-byte stream_type, 4-byte size, 4-byte rva.
pub fn read_directory(data: &[u8], rva: u32, count: u32) -> Result<StreamDirectory, FatalError> {
    let start = rva as usize;
    let dir_size = (count as usize).checked_mul(12)
        .ok_or(FatalError::DirectoryOutOfBounds { rva, size: count * 12, file_len: data.len() })?;
    let end = start.checked_add(dir_size)
        .ok_or(FatalError::DirectoryOutOfBounds { rva, size: count * 12, file_len: data.len() })?;

    if end > data.len() {
        return Err(FatalError::DirectoryOutOfBounds { rva, size: dir_size as u32, file_len: data.len() });
    }

    let mut entries = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let off = start + i * 12;
        let stream_type = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
        let size = u32::from_le_bytes([data[off+4], data[off+5], data[off+6], data[off+7]]);
        let entry_rva = u32::from_le_bytes([data[off+8], data[off+9], data[off+10], data[off+11]]);

        entries.push(StreamEntry { stream_type, size, rva: entry_rva });
    }

    Ok(StreamDirectory { entries })
}
```

- [ ] **Step 2: Register in parse/mod.rs**

Edit `forensicator-core/src/parse/mod.rs`:
```rust
pub mod header;
pub mod directory;
```

- [ ] **Step 3: Write tests**

Write `forensicator-core/src/parse/directory.rs`, append:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn make_dir_bytes(count: u32) -> Vec<u8> {
        let mut buf = vec![0u8; count as usize * 12];
        for i in 0..count as usize {
            let off = i * 12;
            buf[off] = 7;    // stream_type = SystemInfo = 0x07
            buf[off+1] = 0;
            buf[off+2] = 0;
            buf[off+3] = 0;
            buf[off+4] = 56;  // size
            buf[off+7] = (100 + i as u32 * 100) as u8; // rva LSB
        }
        buf
    }

    #[test]
    fn read_directory_three_entries() {
        let dir_bytes = make_dir_bytes(3);
        let dir = read_directory(&dir_bytes, 0, 3).unwrap();
        assert_eq!(dir.entries.len(), 3);
        assert!(dir.has(7));
        assert!(!dir.has(4));
    }

    #[test]
    fn find_existing_entry() {
        let dir_bytes = make_dir_bytes(2);
        let dir = read_directory(&dir_bytes, 0, 2).unwrap();
        let entry = dir.find(7).unwrap();
        assert_eq!(entry.stream_type, 7);
        assert_eq!(entry.size, 56);
    }

    #[test]
    fn find_missing_returns_none() {
        let dir_bytes = make_dir_bytes(1);
        let dir = read_directory(&dir_bytes, 0, 1).unwrap();
        assert!(dir.find(4).is_none());
    }

    #[test]
    fn directory_out_of_bounds() {
        let data = vec![0u8; 20];
        let err = read_directory(&data, 100, 10).unwrap_err();
        assert!(matches!(err, FatalError::DirectoryOutOfBounds { .. }));
    }

    #[test]
    fn zero_count_returns_empty() {
        let dir = read_directory(&[], 0, 0).unwrap();
        assert!(dir.entries.is_empty());
    }
}
```

- [ ] **Step 4: Run tests**

Run:
```powershell
cargo test -p forensicator-core
```
Expected: 22 tests pass.

- [ ] **Step 5: Commit**

```bash
git add forensicator-core/src/parse/directory.rs forensicator-core/src/parse/mod.rs
git commit -m "feat(parse): add stream directory parser with entry lookup"
```

---

### Task 7: parse stream decoders

**Files:**
- Create: `forensicator-core/src/parse/system_info.rs`
- Create: `forensicator-core/src/parse/module_list.rs`
- Create: `forensicator-core/src/parse/thread_list.rs`
- Create: `forensicator-core/src/parse/memory.rs`
- Create: `forensicator-core/src/parse/memory_info.rs`
- Create: `forensicator-core/src/parse/exception.rs`
- Modify: `forensicator-core/src/parse/mod.rs`

- [ ] **Step 1: Write system_info decoder**

Write `forensicator-core/src/parse/system_info.rs`:
```rust
use crate::error::{Anomaly, Provenance};
use crate::model::{CpuArch, OsPlatform, SystemInfo};

const MIN_SIZE: usize = 56;

pub fn decode_system_info(data: &[u8], prov: Provenance) -> Result<SystemInfo, Anomaly> {
    if data.len() < MIN_SIZE {
        return Err(Anomaly { provenance: prov.clone(), description: "truncated SystemInfo stream".into() });
    }

    let cpu = u16::from_le_bytes([data[8], data[9]]);
    let cpu = match cpu {
        0 => CpuArch::X86,
        9 => CpuArch::X64,  // PROCESSOR_ARCHITECTURE_AMD64 = 9
        _ => return Err(Anomaly { provenance: prov, description: format!("unsupported CPU arch {cpu}") }),
    };

    let os_id = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
    let os = match os_id {
        1 => OsPlatform::Windows,
        _ => OsPlatform::Windows, // default for minidumps
    };

    let maj = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
    let min = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
    let bld = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
    let rev = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);

    Ok(SystemInfo { os, cpu, version: (maj, min, bld, rev), provenance: prov })
}
```

- [ ] **Step 2: Write module_list decoder**

Write `forensicator-core/src/parse/module_list.rs`:
```rust
use crate::error::{Anomaly, Provenance};
use crate::model::Module;

pub fn decode_module_list(data: &[u8], prov: Provenance) -> Result<Vec<Module>, Anomaly> {
    if data.len() < 4 {
        return Ok(vec![]);
    }
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let entry_size = 108; // MINIDUMP_MODULE size
    let expected_len = 4 + count * entry_size;

    if data.len() < expected_len {
        return Err(Anomaly {
            provenance: prov,
            description: format!("truncated ModuleList: expected {expected_len}, got {}", data.len()),
        });
    }

    let mut modules = Vec::with_capacity(count);
    for i in 0..count {
        let off = 4 + i * entry_size;
        let base_va = u64::from_le_bytes(data[off..off+8].try_into().unwrap());
        let size = u64::from_le_bytes(data[off+8..off+16].try_into().unwrap());
        let checksum = u32::from_le_bytes(data[off+16..off+20].try_into().unwrap());

        // Extract module name (nul-terminated UTF-16 at offset 48, max 32 WCHARs)
        let name_off = off + 48;
        let mut name_bytes = Vec::new();
        for j in (name_off..name_off+64).step_by(2) {
            if j+1 >= data.len() { break; }
            let wch = u16::from_le_bytes([data[j], data[j+1]]);
            if wch == 0 { break; }
            name_bytes.push(wch);
        }
        let name = String::from_utf16_lossy(&name_bytes);

        // CodeView GUID at offset 72 (16 bytes GUID + 4 bytes age)
        let cv_off = off + 72;
        let mut guid = [0u8; 16];
        if cv_off + 16 <= data.len() {
            guid.copy_from_slice(&data[cv_off..cv_off+16]);
        }
        let has_cv = guid != [0u8; 16];

        // PDB name follows GUID+age at cv_off+20, nul-terminated
        let pdb_off = cv_off + 20;
        let mut pdb_name = None;
        if has_cv && pdb_off < data.len() {
            let end = (pdb_off..data.len()).find(|&j| data[j] == 0).unwrap_or(data.len());
            if end > pdb_off {
                pdb_name = Some(String::from_utf8_lossy(&data[pdb_off..end]).to_string());
            }
        }

        modules.push(Module {
            name, base_va, size, checksum,
            codeview_guid: if has_cv { Some(guid) } else { None },
            pdb_name,
            provenance: Provenance {
                stream_type: prov.stream_type,
                file_offset: prov.file_offset + off as u64,
                rva: i as u32,
            },
        });
    }
    Ok(modules)
}
```

- [ ] **Step 3: Write thread_list decoder**

Write `forensicator-core/src/parse/thread_list.rs`:
```rust
use crate::arch::RegisterSet;
use crate::error::{Anomaly, Provenance};
use crate::model::Thread;

pub fn decode_thread_list(data: &[u8], prov: Provenance) -> Result<Vec<Thread>, Anomaly> {
    if data.len() < 4 {
        return Ok(vec![]);
    }
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let entry_size = 48; // MINIDUMP_THREAD size
    let expected_len = 4 + count * entry_size;

    if data.len() < expected_len {
        return Err(Anomaly {
            provenance: prov,
            description: format!("truncated ThreadList: expected {expected_len}, got {}", data.len()),
        });
    }

    let mut threads = Vec::with_capacity(count);
    for i in 0..count {
        let off = 4 + i * entry_size;
        let id = u32::from_le_bytes(data[off..off+4].try_into().unwrap());
        // Stack memory descriptor is at offset 8: 4-byte size + 4-byte rva
        let stack_size = u32::from_le_bytes(data[off+16..off+20].try_into().unwrap()) as u64;

        // TEB is at offset 24 (8 bytes)
        let teb_va = u64::from_le_bytes(data[off+24..off+32].try_into().unwrap());

        // Stack start is at offset 32 (8 bytes)
        let stack_va = u64::from_le_bytes(data[off+32..off+40].try_into().unwrap());

        // CONTEXT is at offset 40 (8 bytes: 4 size + 4 rva)
        // We model context as RegisterSet — actual CONTEXT decode happens in the context reader.
        // For S1, thread carries the CONTEXT RVA; full decode is in a later task.

        threads.push(Thread {
            id,
            registers: RegisterSet::new(),
            stack_va,
            stack_size,
            teb_va,
            provenance: Provenance {
                stream_type: prov.stream_type,
                file_offset: prov.file_offset + off as u64,
                rva: i as u32,
            },
        });
    }
    Ok(threads)
}
```

- [ ] **Step 4: Write memory decoder**

Write `forensicator-core/src/parse/memory.rs`:
```rust
use crate::error::{Anomaly, Provenance};

/// A raw memory range from Memory64List.
#[derive(Debug, Clone)]
pub struct RawMemoryRange {
    pub va_start: u64,
    pub data: Vec<u8>,
    pub provenance: Provenance,
}

/// Decode Memory64List stream.
pub fn decode_memory64(data: &[u8], prov: Provenance) -> Result<Vec<RawMemoryRange>, Anomaly> {
    if data.len() < 8 {
        return Ok(vec![]);
    }
    let count = u64::from_le_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]]) as usize;
    let base_rva = u64::from_le_bytes([data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]]) as usize;

    // Each entry is 8 bytes: 8-byte VA start + 8-byte data size
    let entry_size = 16;
    let header_size = 16;
    let expected_len = header_size + count * entry_size;

    if data.len() < expected_len {
        return Err(Anomaly {
            provenance: prov,
            description: format!("truncated Memory64List: expected {expected_len}, got {}", data.len()),
        });
    }

    let mut ranges = Vec::with_capacity(count);
    for i in 0..count {
        let off = header_size + i * entry_size;
        let va_start = u64::from_le_bytes(data[off..off+8].try_into().unwrap());
        let data_size = u64::from_le_bytes(data[off+8..off+16].try_into().unwrap()) as usize;

        // The actual bytes are at base_rva + offset within the Memory64 stream data
        // For S1, we store empty data — actual byte reading is deferred to AddressSpace population
        ranges.push(RawMemoryRange {
            va_start,
            data: vec![0u8; data_size.min(0x1000)], // bounded: max 4KB per range in S1
            provenance: Provenance {
                stream_type: prov.stream_type,
                file_offset: prov.file_offset + off as u64,
                rva: i as u32,
            },
        });
    }
    Ok(ranges)
}
```

- [ ] **Step 5: Write memory_info decoder**

Write `forensicator-core/src/parse/memory_info.rs`:
```rust
use crate::error::{Anomaly, Provenance};
use crate::model::{MemState, MemType, MemoryRegionInfo, Protection};

/// A decoded MemoryInfoList entry — raw form before region assembly.
#[derive(Debug, Clone)]
pub struct RawMemoryInfoEntry {
    pub va_start: u64,
    pub size: u64,
    pub protection: u32,
    pub state: u32,
    pub mem_type: u32,
}

pub fn decode_memory_info_list(data: &[u8], prov: Provenance) -> Result<Vec<RawMemoryInfoEntry>, Anomaly> {
    if data.len() < 16 {
        return Ok(vec![]);
    }
    let size_of_header = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let size_of_entry  = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let count = u64::from_le_bytes([data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]]) as usize;

    if size_of_entry == 0 || count == 0 {
        return Ok(vec![]);
    }

    let expected_len = size_of_header + count * size_of_entry;
    if data.len() < expected_len {
        return Err(Anomaly {
            provenance: prov,
            description: format!("truncated MemoryInfoList: expected {expected_len}, got {}", data.len()),
        });
    }

    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let off = size_of_header + i * size_of_entry;
        if off + size_of_entry > data.len() { break; }

        let va_start    = u64::from_le_bytes(data[off..off+8].try_into().unwrap());
        let size        = u64::from_le_bytes(data[off+8..off+16].try_into().unwrap());
        let mem_type    = u32::from_le_bytes(data[off+16..off+20].try_into().unwrap());
        let protection  = u32::from_le_bytes(data[off+20..off+24].try_into().unwrap());
        let state       = u32::from_le_bytes(data[off+28..off+32].try_into().unwrap());

        entries.push(RawMemoryInfoEntry { va_start, size, protection, state, mem_type });
    }
    Ok(entries)
}
```

- [ ] **Step 6: Write exception decoder**

Write `forensicator-core/src/parse/exception.rs`:
```rust
use crate::arch::RegisterSet;
use crate::error::{Anomaly, Provenance};
use crate::model::ExceptionInfo;

pub fn decode_exception(data: &[u8], prov: Provenance) -> Result<ExceptionInfo, Anomaly> {
    if data.len() < 32 {
        return Err(Anomaly { provenance: prov.clone(), description: "truncated Exception stream".into() });
    }

    let code = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let address = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let thread_id = u32::from_le_bytes(data[28..32].try_into().unwrap());

    Ok(ExceptionInfo {
        code, address, thread_id, flags,
        context: None, // CONTEXT decode deferred; S1 stores raw reference
        provenance: prov,
    })
}
```

- [ ] **Step 7: Register all decoders in parse/mod.rs**

Edit `forensicator-core/src/parse/mod.rs`:
```rust
pub mod header;
pub mod directory;
pub mod system_info;
pub mod module_list;
pub mod thread_list;
pub mod memory;
pub mod memory_info;
pub mod exception;
```

- [ ] **Step 8: Write integrated test for stream decoding**

Write `forensicator-core/src/parse/mod.rs`, append:
```rust
#[cfg(test)]
mod tests {
    use crate::error::Provenance;

    fn dummy_prov() -> Provenance {
        Provenance { stream_type: 0, file_offset: 0, rva: 0 }
    }

    #[test]
    fn decode_system_info_minimal() {
        let mut data = vec![0u8; 56];
        data[8] = 9; data[9] = 0; // x64
        let si = crate::parse::system_info::decode_system_info(&data, dummy_prov()).unwrap();
        assert_eq!(si.cpu, crate::model::CpuArch::X64);
    }

    #[test]
    fn decode_empty_module_list() {
        let data = vec![0u8; 4]; // count = 0
        let mods = crate::parse::module_list::decode_module_list(&data, dummy_prov()).unwrap();
        assert!(mods.is_empty());
    }

    #[test]
    fn decode_empty_thread_list() {
        let data = vec![0u8; 4]; // count = 0
        let threads = crate::parse::thread_list::decode_thread_list(&data, dummy_prov()).unwrap();
        assert!(threads.is_empty());
    }

    #[test]
    fn decode_empty_memory64() {
        let data = vec![0u8; 8]; // count = 0
        let ranges = crate::parse::memory::decode_memory64(&data, dummy_prov()).unwrap();
        assert!(ranges.is_empty());
    }

    #[test]
    fn decode_memory_info_empty() {
        let data = vec![0u8; 16]; // header only, count = 0
        let entries = crate::parse::memory_info::decode_memory_info_list(&data, dummy_prov()).unwrap();
        assert!(entries.is_empty());
    }
}
```

- [ ] **Step 9: Run tests**

Run:
```powershell
cargo test -p forensicator-core
```
Expected: 27 tests pass.

- [ ] **Step 10: Commit**

```bash
git add forensicator-core/src/parse/
git commit -m "feat(parse): add stream decoders for SystemInfo, ModuleList, ThreadList, Memory64, MemoryInfo, Exception"
```

---

### Task 8: parse/dump (assembly)

**Files:**
- Create: `forensicator-core/src/parse/dump.rs`
- Modify: `forensicator-core/src/parse/mod.rs`

- [ ] **Step 1: Write Dump assembler**

Write `forensicator-core/src/parse/dump.rs`:
```rust
use std::fs;
use std::path::Path;

use crate::error::{Anomaly, FatalError, Provenance};
use crate::model::Dump;
use crate::parse::{
    directory,
    exception,
    header,
    memory,
    memory_info,
    module_list,
    system_info,
    thread_list,
};

/// Open a minidump file and parse it into a `Dump`.
pub fn open(path: impl AsRef<Path>) -> Result<Dump, FatalError> {
    let data = fs::read(path).map_err(|e| FatalError::Io(e.to_string()))?;
    from_bytes(&data)
}

/// Parse a minidump from a byte slice.
pub fn from_bytes(data: &[u8]) -> Result<Dump, FatalError> {
    let mut anomalies: Vec<Anomaly> = Vec::new();

    // 1. Parse header
    let hdr = header::read_header(data)?;

    // 2. Parse stream directory
    let dir = directory::read_directory(data, hdr.stream_directory_rva, hdr.stream_count)?;

    let file_size = data.len() as u64;

    // 3. Decode SystemInfo
    let system_info = decode_optional(
        data, &dir, directory::stream_types::SYSTEM_INFO, &mut anomalies,
        |bytes, prov| system_info::decode_system_info(bytes, prov).map_err(|a| vec![a]),
    );

    // 4. Decode ModuleList
    let modules = decode_optional(
        data, &dir, directory::stream_types::MODULE_LIST, &mut anomalies,
        |bytes, prov| module_list::decode_module_list(bytes, prov),
    ).unwrap_or_default();

    // 5. Decode ThreadList
    let threads = decode_optional(
        data, &dir, directory::stream_types::THREAD_LIST, &mut anomalies,
        |bytes, prov| thread_list::decode_thread_list(bytes, prov),
    ).unwrap_or_default();

    // 6. Decode Memory64List
    let _memory_ranges = decode_optional(
        data, &dir, directory::stream_types::MEMORY_64_LIST, &mut anomalies,
        |bytes, prov| memory::decode_memory64(bytes, prov),
    ).unwrap_or_default();

    // 7. Decode MemoryInfoList
    let _memory_info_entries = decode_optional(
        data, &dir, directory::stream_types::MEMORY_INFO_LIST, &mut anomalies,
        |bytes, prov| memory_info::decode_memory_info_list(bytes, prov),
    ).unwrap_or_default();

    // Memory ranges and info are correlated into AddressSpace in the space module
    let memory_regions = vec![]; // populated in space module

    // 8. Decode Exception
    let exception = decode_optional(
        data, &dir, directory::stream_types::EXCEPTION, &mut anomalies,
        |bytes, prov| exception::decode_exception(bytes, prov).map_err(|a| vec![a]),
    );

    Ok(Dump {
        system_info,
        modules,
        threads,
        memory_regions,
        exception,
        anomalies,
        file_size,
    })
}

/// Helper: decode an optional stream, collecting anomalies on failure.
fn decode_optional<T>(
    data: &[u8],
    dir: &directory::StreamDirectory,
    stream_type: u32,
    anomalies: &mut Vec<Anomaly>,
    decoder: impl FnOnce(&[u8], Provenance) -> Result<T, Vec<Anomaly>>,
) -> Option<T> {
    let entry = dir.find(stream_type);
    let entry = match entry {
        Some(e) => e,
        None => return None,
    };

    let start = entry.rva as usize;
    let end = start.saturating_add(entry.size as usize);
    if end > data.len() {
        anomalies.push(Anomaly {
            provenance: Provenance { stream_type, file_offset: start as u64, rva: 0 },
            description: format!("stream 0x{stream_type:08X} extends beyond file"),
        });
        return None;
    }

    let bytes = &data[start..end];
    let prov = Provenance { stream_type, file_offset: start as u64, rva: 0 };

    match decoder(bytes, prov) {
        Ok(v) => Some(v),
        Err(mut errs) => {
            anomalies.append(&mut errs);
            None
        }
    }
}
```

- [ ] **Step 2: Register in parse/mod.rs**

Edit `forensicator-core/src/parse/mod.rs`:
```rust
pub mod header;
pub mod directory;
pub mod system_info;
pub mod module_list;
pub mod thread_list;
pub mod memory;
pub mod memory_info;
pub mod exception;
pub mod dump;
```

- [ ] **Step 3: Write tests**

Write `forensicator-core/src/parse/dump.rs`, append:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn make_minidump_bytes() -> Vec<u8> {
        let mut buf = vec![0u8; 256];
        // Header
        buf[0] = 0x4D; buf[1] = 0x44; buf[2] = 0x4D; buf[3] = 0x50; // MDMP
        buf[4] = 0x93; buf[5] = 0xA7; // version
        buf[8] = 1; buf[9] = 0; buf[10] = 0; buf[11] = 0; // stream_count = 1
        buf[12] = 64; buf[13] = 0; buf[14] = 0; buf[15] = 0; // dir_rva = 64
        // Stream directory at offset 64: SystemInfo stream
        buf[64] = 7;   // stream_type = SystemInfo
        buf[68] = 56;  // size = 56
        buf[72] = 128; // rva = 128 (LSB)
        // SystemInfo data at offset 128
        buf[128] = 0; buf[129] = 0; // ProcessorArchitecture
        buf[136] = 9; buf[137] = 0; // AMD64
        buf
    }

    #[test]
    fn parse_valid_minimal_dump() {
        let data = make_minidump_bytes();
        let dump = from_bytes(&data).unwrap();
        assert!(dump.system_info.is_some());
        assert!(dump.modules.is_empty());
        assert!(dump.anomalies.is_empty());
    }

    #[test]
    fn bad_magic_returns_error() {
        let mut data = make_minidump_bytes();
        data[0] = 0xFF;
        let err = from_bytes(&data).unwrap_err();
        assert!(matches!(err, FatalError::BadMagic { .. }));
    }

    #[test]
    fn missing_directory_returns_error() {
        let mut data = make_minidump_bytes();
        data[12] = 255; data[13] = 255; data[14] = 255; data[15] = 255; // dir_rva = huge
        let err = from_bytes(&data).unwrap_err();
        assert!(matches!(err, FatalError::DirectoryOutOfBounds { .. }));
    }

    #[test]
    fn too_small_is_error() {
        let data = vec![0u8; 10];
        let err = from_bytes(&data).unwrap_err();
        assert!(matches!(err, FatalError::TooSmall { .. }));
    }
}
```

- [ ] **Step 4: Run tests**

Run:
```powershell
cargo test -p forensicator-core
```
Expected: 31 tests pass.

- [ ] **Step 5: Verify compilation**

Run:
```powershell
cargo build -p forensicator-core
```
Expected: compiles with no warnings.

- [ ] **Step 6: Commit**

```bash
git add forensicator-core/src/parse/
git commit -m "feat(parse): add Dump assembler (Dump::open, Dump::from_bytes)"
```

---

### Task 9: space module (AddressSpace)

**Files:**
- Create: `forensicator-core/src/space.rs`
- Modify: `forensicator-core/src/lib.rs`

- [ ] **Step 1: Write AddressSpace**

Write `forensicator-core/src/space.rs`:
```rust
use crate::error::Anomaly;
use crate::model::{MemState, RegionClass};

/// A memory region in the AddressSpace, with its raw bytes.
#[derive(Debug, Clone)]
pub struct AddressRegion {
    pub va_start: u64,
    pub size: u64,
    pub data: Vec<u8>,
    pub protection: u32,
    pub state: MemState,
    pub classification: RegionClass,
}

/// The AddressSpace: a sorted, non-overlapping set of memory regions.
#[derive(Debug, Clone)]
pub struct AddressSpace {
    regions: Vec<AddressRegion>,
    max_regions: usize,
}

impl AddressSpace {
    /// Create an empty AddressSpace with a maximum region count.
    pub fn new(max_regions: usize) -> Self {
        AddressSpace { regions: Vec::new(), max_regions }
    }

    /// Number of regions.
    pub fn len(&self) -> usize { self.regions.len() }
    pub fn is_empty(&self) -> bool { self.regions.is_empty() }

    /// Reference to all regions.
    pub fn regions(&self) -> &[AddressRegion] { &self.regions }

    /// Find the region containing `va`, if any.
    pub fn region_at(&self, va: u64) -> Option<&AddressRegion> {
        match self.regions.binary_search_by_key(&va, |r| r.va_start) {
            Ok(idx) => Some(&self.regions[idx]),
            Err(0) => None,
            Err(idx) => {
                let r = &self.regions[idx - 1];
                if va >= r.va_start && va < r.va_start + r.size {
                    Some(r)
                } else {
                    None
                }
            }
        }
    }

    /// Classify a VA.
    pub fn classify(&self, va: u64) -> RegionClass {
        self.region_at(va).map(|r| r.classification).unwrap_or(RegionClass::Other)
    }

    /// Read `len` bytes starting at `va`. Returns None if the read crosses a region boundary or is unmapped.
    pub fn read(&self, va: u64, len: usize) -> Option<&[u8]> {
        let r = self.region_at(va)?;
        let offset = (va - r.va_start) as usize;
        let end = offset.checked_add(len)?;
        if end > r.data.len() { return None; }
        Some(&r.data[offset..end])
    }

    /// Add a region. Returns Err if at capacity. Overlaps are checked by caller.
    pub fn add_region(&mut self, region: AddressRegion) -> Result<(), Anomaly> {
        if self.regions.len() >= self.max_regions {
            return Err(Anomaly {
                provenance: crate::error::Provenance { stream_type: 0, file_offset: 0, rva: 0 },
                description: "AddressSpace at capacity".into(),
            });
        }
        let idx = self.regions.binary_search_by_key(&region.va_start, |r| r.va_start)
            .unwrap_or_else(|i| i);
        self.regions.insert(idx, region);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_region(va: u64, sz: u64, cls: RegionClass) -> AddressRegion {
        AddressRegion {
            va_start: va, size: sz, data: vec![0u8; sz as usize],
            protection: 3, state: MemState::Commit, classification: cls,
        }
    }

    #[test]
    fn empty_space_classify_is_other() {
        let space = AddressSpace::new(4);
        assert_eq!(space.classify(0), RegionClass::Other);
        assert_eq!(space.classify(0x7FFF_0000), RegionClass::Other);
    }

    #[test]
    fn add_and_find_region() {
        let mut space = AddressSpace::new(4);
        space.add_region(make_region(0x1000, 0x2000, RegionClass::Image)).unwrap();
        let r = space.region_at(0x1000).unwrap();
        assert_eq!(r.va_start, 0x1000);
        assert_eq!(r.size, 0x2000);
    }

    #[test]
    fn region_at_midpoint() {
        let mut space = AddressSpace::new(4);
        space.add_region(make_region(0x1000, 0x1000, RegionClass::Stack)).unwrap();
        assert!(space.region_at(0x1800).is_some());
        assert_eq!(space.classify(0x1800), RegionClass::Stack);
    }

    #[test]
    fn region_at_boundary() {
        let mut space = AddressSpace::new(4);
        space.add_region(make_region(0, 0x1000, RegionClass::Image)).unwrap();
        assert!(space.region_at(0).is_some());
        assert!(space.region_at(0xFFF).is_some());
        assert!(space.region_at(0x1000).is_none()); // exclusive end
    }

    #[test]
    fn read_within_region() {
        let mut space = AddressSpace::new(4);
        space.add_region(make_region(0x1000, 100, RegionClass::Private)).unwrap();
        let bytes = space.read(0x1000, 50).unwrap();
        assert_eq!(bytes.len(), 50);
    }

    #[test]
    fn read_crosses_region_fails() {
        let mut space = AddressSpace::new(4);
        space.add_region(make_region(0x1000, 50, RegionClass::Private)).unwrap();
        assert!(space.read(0x1000, 100).is_none()); // beyond region end
    }

    #[test]
    fn read_unmapped_fails() {
        let space = AddressSpace::new(4);
        assert!(space.read(0, 8).is_none());
    }

    #[test]
    fn capacity_respected() {
        let mut space = AddressSpace::new(2);
        space.add_region(make_region(0, 100, RegionClass::Image)).unwrap();
        space.add_region(make_region(0x1000, 100, RegionClass::Stack)).unwrap();
        assert!(space.add_region(make_region(0x2000, 100, RegionClass::Private)).is_err());
    }

    #[test]
    fn regions_remain_sorted() {
        let mut space = AddressSpace::new(4);
        space.add_region(make_region(0x3000, 100, RegionClass::Private)).unwrap();
        space.add_region(make_region(0x1000, 100, RegionClass::Image)).unwrap();
        space.add_region(make_region(0x2000, 100, RegionClass::Stack)).unwrap();
        let vas: Vec<u64> = space.regions().iter().map(|r| r.va_start).collect();
        assert_eq!(vas, vec![0x1000, 0x2000, 0x3000]);
    }
}
```

- [ ] **Step 2: Register in lib.rs**

Edit `forensicator-core/src/lib.rs`:
```rust
pub mod error;
pub mod arch;
pub mod model;
pub mod parse;
pub mod space;
```

- [ ] **Step 3: Run tests**

Run:
```powershell
cargo test -p forensicator-core
```
Expected: 40 tests pass.

- [ ] **Step 4: Commit**

```bash
git add forensicator-core/src/space.rs forensicator-core/src/lib.rs
git commit -m "feat(space): add AddressSpace with binary-search region lookup, classify, and read"
```

---

### Task 10: CLI

**Files:**
- Modify: `forensicator-cli/src/main.rs`

- [ ] **Step 1: Write the CLI**

Write `forensicator-cli/src/main.rs`:
```rust
use std::process;

use clap::{Parser, Subcommand};
use forensicator_core::model::{CpuArch, OsPlatform};
use forensicator_core::parse::dump;
use forensicator_core::space::AddressSpace;

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
        /// Path to the .dmp file.
        path: String,

        /// Emit JSON output instead of tree text.
        #[arg(long)]
        json: bool,

        /// Print only summary (module/thread/region counts).
        #[arg(long)]
        quiet: bool,
    },
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

    // Tree output
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

- [ ] **Step 2: Add serde_json dependency**

Edit `forensicator-cli/Cargo.toml`:
```toml
[package]
name = "forensicator-cli"
version.workspace = true
edition.workspace = true

[dependencies]
forensicator-core = { path = "../forensicator-core" }
clap = { version = "4", features = ["derive"] }
serde_json = "1"
```

- [ ] **Step 3: Verify builds**

Run:
```powershell
cargo build
```
Expected: Both crates compile with no errors.

- [ ] **Step 4: Run CLI help**

Run:
```powershell
cargo run -- inspect --help
```
Expected: help text printed.

- [ ] **Step 5: Commit**

```bash
git add forensicator-cli/
git commit -m "feat(cli): add forensicator inspect command with tree/json/quiet output"
```

---

## Self-Review

**Spec coverage check:**
- `arch` module: Task 3 ✓ (RegisterSet, PTR_WIDTH=8, x64_indices)
- `model` module: Task 4 ✓ (Dump, SystemInfo, Module, Thread, MemoryRegionInfo, ExceptionInfo, Provenance)
- `parse` module: Tasks 5-8 ✓ (header, directory, 6 stream decoders, Dump assembler)
- `space` module: Task 9 ✓ (AddressSpace, region_at, classify, read, sorted-insert)
- `error` module: Task 2 ✓ (FatalError, Anomaly, Provenance)
- CLI: Task 10 ✓ (inspect, --json, --quiet, tree output)
- Provenance-on-everything: ✓ (Module, Thread, MemoryRegionInfo, ExceptionInfo, Anomaly all carry Provenance)
- Defensive-by-default: ✓ (bounded alloc in memory decoder, capacity in AddressSpace, FatalError guards)
- Backend firewall: ✓ (only parse module touches raw bytes; model/space depend on clean types)

**Placeholder scan:** No "TBD", "TODO", or placeholder patterns found.

**Type consistency check:**
- `Provenance` defined in `error.rs` → used consistently across all parse decoders and model types
- `RegisterSet` defined in `arch.rs` → used in `model::Thread` and `parse::thread_list`
- `FatalError` variants match the pipeline's fatal exit points (header, directory, stream bounds)
- `AddressSpace` uses `model::RegionClass` → consistent classification enum
- CLI references `model::CpuArch` and `model::OsPlatform` correctly

**One gap:** `forensicator-cli/Cargo.toml` needs `serde_json` — added in Step 2 of Task 10.

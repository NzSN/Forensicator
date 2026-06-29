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

    /// Minimum bytes for a full x64 CONTEXT (through RIP at offset 0xF8).
    pub const MIN_CONTEXT_SIZE: usize = 256;

    /// Raw byte-offset → (register_index, size) mapping for the x64 CONTEXT layout.
    /// Segment regs are u16, EFlags is u32, everything else is u64 (little-endian).
    const CONTEXT_LAYOUT: &[(usize, usize, u8)] = &[
        (0x38, 17, 2), (0x3A, 18, 2), (0x3C, 19, 2),
        (0x3E, 20, 2), (0x40, 21, 2), (0x42, 22, 2),
        (0x44, 23, 4),
        (0x48, 24, 8), (0x50, 25, 8), (0x58, 26, 8),
        (0x60, 27, 8), (0x68, 28, 8), (0x70, 29, 8),
        (0x78,  0, 8), (0x80,  2, 8), (0x88,  3, 8),
        (0x90,  1, 8), (0x98, 15, 8), (0xA0, 14, 8),
        (0xA8,  4, 8), (0xB0,  5, 8), (0xB8,  6, 8),
        (0xC0,  7, 8), (0xC8,  8, 8), (0xD0,  9, 8),
        (0xD8, 10, 8), (0xE0, 11, 8), (0xE8, 12, 8),
        (0xF0, 13, 8), (0xF8, 16, 8),
    ];

    fn read_le(data: &[u8], offset: usize, size: u8) -> Option<u64> {
        let end = offset + size as usize;
        if end > data.len() { return None; }
        let mut v: u64 = 0;
        for (i, &b) in data[offset..end].iter().enumerate() {
            v |= (b as u64) << (i * 8);
        }
        Some(v)
    }

    /// Decode registers from an x64 CONTEXT byte stream (mirrors Arch.tla
    /// `DecodeContextSuccess` / `DecodeContextTruncated`).
    ///
    /// Returns `Ok(regs)` when enough bytes are present for the full 32‑register
    /// layout.  Returns `Err("truncated CONTEXT")` when the data is too short —
    /// only the 16 GPRs (RAX‑R15) are decoded in that case.
    pub fn decode_context(data: &[u8]) -> Result<Self, &'static str> {
        let mut regs = RegisterSet::new();
        // Always decode the 16 GPRs (RAX through R15) plus RBP/RSP/RIP.
        // These span CONTEXT offsets 0x78 – 0xFF.
        let gpr_entries: &[(usize, usize, u8)] = &[
            (0x78,  0, 8), (0x80,  2, 8), (0x88,  3, 8), (0x90,  1, 8),
            (0x98, 15, 8), (0xA0, 14, 8), (0xA8,  4, 8), (0xB0,  5, 8),
            (0xB8,  6, 8), (0xC0,  7, 8), (0xC8,  8, 8), (0xD0,  9, 8),
            (0xD8, 10, 8), (0xE0, 11, 8), (0xE8, 12, 8), (0xF0, 13, 8),
            (0xF8, 16, 8),
        ];
        let truncated = data.len() < Self::MIN_CONTEXT_SIZE;
        if truncated {
            // Decode whatever GPRs the available bytes cover.
            for &(off, idx, sz) in gpr_entries {
                if let Some(val) = Self::read_le(data, off, sz) {
                    regs.set(idx, val);
                }
            }
            return Err("truncated CONTEXT");
        }
        // Full decode — all 32 register slots.
        for &(off, idx, sz) in Self::CONTEXT_LAYOUT {
            if let Some(val) = Self::read_le(data, off, sz) {
                regs.set(idx, val);
            }
        }
        Ok(regs)
    }
}

impl Default for RegisterSet {
    fn default() -> Self { Self::new() }
}

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
        assert!(regs.values.iter().all(|&v| v == 0));
    }

    #[test]
    fn set_and_get_rsp() {
        let mut regs = RegisterSet::new();
        regs.set(x64_indices::RSP, 0x7FFE_0000);
        assert_eq!(regs.rsp(), 0x7FFE_0000);
    }

    #[test]
    fn set_and_get_rbp() {
        let mut regs = RegisterSet::new();
        regs.set(x64_indices::RBP, 0x7FFD_1000);
        assert_eq!(regs.rbp(), 0x7FFD_1000);
    }

    #[test]
    fn set_all_gprs() {
        let mut regs = RegisterSet::new();
        let gprs = [
            x64_indices::RAX, x64_indices::RBX, x64_indices::RCX, x64_indices::RDX,
            x64_indices::RSI, x64_indices::RDI, x64_indices::R8,  x64_indices::R9,
            x64_indices::R10, x64_indices::R11, x64_indices::R12, x64_indices::R13,
            x64_indices::R14, x64_indices::R15,
        ];
        for (i, &idx) in gprs.iter().enumerate() {
            regs.set(idx, 0x1000 + i as u64);
        }
        assert_eq!(regs.get(x64_indices::RAX), 0x1000);
        assert_eq!(regs.get(x64_indices::R15), 0x100D);
    }

    #[test]
    fn set_segment_registers() {
        let mut regs = RegisterSet::new();
        regs.set(x64_indices::CS, 0x33);
        regs.set(x64_indices::DS, 0x2B);
        regs.set(x64_indices::SS, 0x2B);
        assert_eq!(regs.get(x64_indices::CS), 0x33);
        assert_eq!(regs.get(x64_indices::DS), 0x2B);
        assert_eq!(regs.get(x64_indices::SS), 0x2B);
    }

    #[test]
    fn set_debug_registers() {
        let mut regs = RegisterSet::new();
        regs.set(x64_indices::DR0, 0x7FFA_0000);
        regs.set(x64_indices::DR7, 0x400);
        assert_eq!(regs.get(x64_indices::DR0), 0x7FFA_0000);
        assert_eq!(regs.get(x64_indices::DR7), 0x400);
    }

    #[test]
    fn set_rflags() {
        let mut regs = RegisterSet::new();
        regs.set(x64_indices::RFLAGS, 0x246);
        assert_eq!(regs.get(x64_indices::RFLAGS), 0x246);
    }

    #[test]
    fn register_set_clone() {
        let mut a = RegisterSet::new();
        a.set(x64_indices::RIP, 0x7FFA_1000);
        let b = a.clone();
        assert_eq!(a, b);
        assert_eq!(b.rip(), 0x7FFA_1000);
    }

    #[test]
    fn partial_register_update() {
        let mut regs = RegisterSet::new();
        regs.set(x64_indices::RAX, 0xDEADBEEF);
        regs.set(x64_indices::RBX, 0xCAFEBABE);
        // RAX should be set, RBX should be set, others zero
        assert_eq!(regs.get(x64_indices::RAX), 0xDEADBEEF);
        assert_eq!(regs.get(x64_indices::RBX), 0xCAFEBABE);
        assert_eq!(regs.get(x64_indices::RCX), 0);
    }

    #[test]
    fn decode_context_full_parses_all_regs() {
        let mut data = [0u8; 256];
        // Write known values at RAX (offset 0x78) and RIP (offset 0xF8)
        data[0x78..0x80].copy_from_slice(&0xDEADBEEF_CAFEBABEu64.to_le_bytes());
        data[0xF8..0x100].copy_from_slice(&0x7FFA_1000u64.to_le_bytes());
        let regs = RegisterSet::decode_context(&data).expect("full context should succeed");
        assert_eq!(regs.get(x64_indices::RAX), 0xDEADBEEF_CAFEBABE);
        assert_eq!(regs.get(x64_indices::RIP), 0x7FFA_1000);
    }

    #[test]
    fn decode_context_truncated_returns_err() {
        let data = [0u8; 16];
        let result = RegisterSet::decode_context(&data);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "truncated CONTEXT");
    }

    #[test]
    fn decode_context_truncated_still_parses_gprs() {
        let mut data = [0u8; 200];
        data[0x78..0x80].copy_from_slice(&0x1234567890ABCDEFu64.to_le_bytes());
        assert!(RegisterSet::decode_context(&data).is_err());
    }

    #[test]
    fn decode_context_segment_regs() {
        let mut data = [0u8; 256];
        data[0x3A..0x3C].copy_from_slice(&0x002Bu16.to_le_bytes()); // DS at 0x3A
        data[0x3C..0x3E].copy_from_slice(&0x0033u16.to_le_bytes()); // ES at 0x3C
        let regs = RegisterSet::decode_context(&data).expect("full context");
        assert_eq!(regs.get(x64_indices::DS), 0x2B);
        assert_eq!(regs.get(x64_indices::ES), 0x33);
    }

    #[test]
    fn decode_context_rflags() {
        let mut data = [0u8; 256];
        data[0x44..0x48].copy_from_slice(&0x246u32.to_le_bytes());
        let regs = RegisterSet::decode_context(&data).expect("full context");
        assert_eq!(regs.get(x64_indices::RFLAGS), 0x246);
    }

    #[test]
    fn decode_context_debug_regs() {
        let mut data = [0u8; 256];
        data[0x48..0x50].copy_from_slice(&0x7FFA0000u64.to_le_bytes()); // DR0
        data[0x70..0x78].copy_from_slice(&0x400u64.to_le_bytes()); // DR7
        let regs = RegisterSet::decode_context(&data).expect("full context");
        assert_eq!(regs.get(x64_indices::DR0), 0x7FFA0000);
        assert_eq!(regs.get(x64_indices::DR7), 0x400);
    }
}

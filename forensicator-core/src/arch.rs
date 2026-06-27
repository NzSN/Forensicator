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
}

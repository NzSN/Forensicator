//! Minimal iced-x86 wrapper: decode a window of instructions at a VA and
//! classify the forms crash-cause rules care about.

use crate::space::AddressSpace;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstrKind {
    Int3,
    Ud2,
    /// base = RegisterSet index when the memory operand is [reg + disp]
    /// (None for RIP-relative or absolute forms).
    MemRead { base: Option<usize>, disp: i64 },
    MemWrite { base: Option<usize>, disp: i64 },
    IndirectCall,
    IndirectJump,
    Other,
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub va: u64,
    pub text: String,
    pub kind: InstrKind,
}

/// Decode up to `max` instructions starting at `ip`. Empty when the bytes
/// are not captured. Never fails — garbage bytes classify as `Other`.
pub fn decode_window(space: &AddressSpace, ip: u64, max: usize) -> Vec<Instruction> {
    let bytes = match space.read(ip, 64) {
        Some(b) => b,
        // Near a region end: decode whatever tail bytes are captured.
        None => {
            let Some(r) = space.region_at(ip) else {
                return Vec::new();
            };
            let off = (ip - r.va_start) as usize;
            let Some(tail) = r.data.get(off..) else {
                return Vec::new();
            };
            tail
        }
    };
    let mut decoder = iced_x86::Decoder::with_ip(64, bytes, ip, iced_x86::DecoderOptions::NONE);
    let mut out = Vec::new();
    let mut instr = iced_x86::Instruction::default();
    let mut sink = FmtSink(String::new());
    let mut formatter = iced_x86::IntelFormatter::new();
    while out.len() < max && decoder.can_decode() {
        decoder.decode_out(&mut instr);
        sink.0.clear();
        iced_x86::Formatter::format(&mut formatter, &instr, &mut sink);
        let kind = classify(&instr);
        out.push(Instruction {
            va: instr.ip(),
            text: sink.0.clone(),
            kind,
        });
    }
    out
}

fn classify(i: &iced_x86::Instruction) -> InstrKind {
    use iced_x86::Mnemonic::*;
    match i.mnemonic() {
        Int3 => return InstrKind::Int3,
        Ud2 => return InstrKind::Ud2,
        Call => {
            if matches!(
                i.op0_kind(),
                iced_x86::OpKind::Memory | iced_x86::OpKind::Register
            ) {
                return InstrKind::IndirectCall;
            }
            return InstrKind::Other;
        }
        Jmp => {
            return match i.op0_kind() {
                iced_x86::OpKind::NearBranch16
                | iced_x86::OpKind::NearBranch32
                | iced_x86::OpKind::NearBranch64 => InstrKind::Other,
                _ => InstrKind::IndirectJump,
            };
        }
        Lea => return InstrKind::Other, // memory operand but no memory access
        _ => {}
    }

    // Find the memory operand; decide read vs write from the mnemonic.
    for op in 0..i.op_count() {
        if i.op_kind(op) != iced_x86::OpKind::Memory {
            continue;
        }
        let base = reg_index(i.memory_base());
        // For register-based operands this is the raw displacement; for
        // RIP-relative forms iced-x86 reports the absolute target address,
        // which is what crash-cause rules want anyway.
        let disp = i.memory_displacement64() as i64;
        let is_write = op == 0 && !is_read_only_op0_mem(i.mnemonic());
        return if is_write {
            InstrKind::MemWrite { base, disp }
        } else {
            InstrKind::MemRead { base, disp }
        };
    }
    InstrKind::Other
}

/// Mnemonics whose op0 memory operand is read, not written.
fn is_read_only_op0_mem(m: iced_x86::Mnemonic) -> bool {
    use iced_x86::Mnemonic::*;
    matches!(
        m,
        Cmp | Test | Bt | Btr | Bts | Cmpxchg | Cmpxchg8b | Cmpxchg16b | Xadd
    )
}

fn reg_index(r: iced_x86::Register) -> Option<usize> {
    use crate::arch::x64_indices as x;
    use iced_x86::Register::*;
    Some(match r {
        RAX => x::RAX,
        RBX => x::RBX,
        RCX => x::RCX,
        RDX => x::RDX,
        RSI => x::RSI,
        RDI => x::RDI,
        RBP => x::RBP,
        RSP => x::RSP,
        R8 => x::R8,
        R9 => x::R9,
        R10 => x::R10,
        R11 => x::R11,
        R12 => x::R12,
        R13 => x::R13,
        R14 => x::R14,
        R15 => x::R15,
        _ => return Option::None, // RIP-relative, segment, etc.
    })
}

struct FmtSink(String);

impl iced_x86::FormatterOutput for FmtSink {
    fn write(&mut self, text: &str, _kind: iced_x86::FormatterTextKind) {
        self.0.push_str(text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MemState, RegionClass};
    use crate::space::{AddressRegion, AddressSpace};

    fn space_with(ip: u64, code: &[u8]) -> AddressSpace {
        let mut space = AddressSpace::new(2);
        space
            .add_region(AddressRegion {
                va_start: ip,
                size: code.len() as u64,
                data: code.to_vec(),
                protection: 5,
                state: MemState::Commit,
                classification: RegionClass::Image,
            })
            .unwrap();
        space
    }

    #[test]
    fn classifies_int3() {
        let s = space_with(0x1000, &[0xCC, 0x90]);
        assert_eq!(decode_window(&s, 0x1000, 4)[0].kind, InstrKind::Int3);
    }

    #[test]
    fn classifies_ud2() {
        let s = space_with(0x1000, &[0x0F, 0x0B]);
        assert_eq!(decode_window(&s, 0x1000, 4)[0].kind, InstrKind::Ud2);
    }

    #[test]
    fn classifies_mem_read_with_disp() {
        // mov rax, [rcx+0x1B]
        let s = space_with(0x1000, &[0x48, 0x8B, 0x41, 0x1B]);
        let ins = &decode_window(&s, 0x1000, 4)[0];
        assert_eq!(
            ins.kind,
            InstrKind::MemRead {
                base: Some(crate::arch::x64_indices::RCX),
                disp: 0x1B
            }
        );
    }

    #[test]
    fn classifies_mem_write() {
        // mov [rdx+0x10], rax
        let s = space_with(0x1000, &[0x48, 0x89, 0x42, 0x10]);
        let ins = &decode_window(&s, 0x1000, 4)[0];
        assert_eq!(
            ins.kind,
            InstrKind::MemWrite {
                base: Some(crate::arch::x64_indices::RDX),
                disp: 0x10
            }
        );
    }

    #[test]
    fn cmp_op0_mem_is_read() {
        // cmp [rcx], rax
        let s = space_with(0x1000, &[0x48, 0x39, 0x01]);
        let ins = &decode_window(&s, 0x1000, 4)[0];
        assert!(matches!(ins.kind, InstrKind::MemRead { .. }));
    }

    #[test]
    fn call_through_register_is_indirect() {
        // call rax
        let s = space_with(0x1000, &[0xFF, 0xD0]);
        assert_eq!(decode_window(&s, 0x1000, 4)[0].kind, InstrKind::IndirectCall);
    }

    #[test]
    fn rip_relative_has_no_base() {
        // mov rax, [rip+0x10] at 0x1000 (7 bytes) → absolute target 0x1017
        let s = space_with(0x1000, &[0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00]);
        let ins = &decode_window(&s, 0x1000, 4)[0];
        assert_eq!(
            ins.kind,
            InstrKind::MemRead {
                base: None,
                disp: 0x1017
            }
        );
    }

    #[test]
    fn uncaptured_va_decodes_nothing() {
        let s = AddressSpace::new(2);
        assert!(decode_window(&s, 0x1000, 4).is_empty());
    }
}

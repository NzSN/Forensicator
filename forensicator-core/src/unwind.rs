//! x64 unwind-info stack walking via `.pdata` RUNTIME_FUNCTION records.
//!
//! The unwind table is read through the (possibly image-backed) AddressSpace,
//! so it works identically for full dumps (module image captured) and
//! stack-only minidumps (image supplemented from disk).

use std::collections::HashMap;

use crate::arch::{RegisterSet, x64_indices};
use crate::model::Module;
use crate::space::AddressSpace;

const UNW_FLAG_CHAININFO: u8 = 4;

/// UNWIND_INFO register numbers → our x64_indices.
const UWREG_MAP: [usize; 16] = [
    x64_indices::RAX, // 0
    x64_indices::RCX, // 1
    x64_indices::RDX, // 2
    x64_indices::RBX, // 3
    x64_indices::RSP, // 4
    x64_indices::RBP, // 5
    x64_indices::RSI, // 6
    x64_indices::RDI, // 7
    x64_indices::R8,  // 8
    x64_indices::R9,  // 9
    x64_indices::R10, // 10
    x64_indices::R11, // 11
    x64_indices::R12, // 12
    x64_indices::R13, // 13
    x64_indices::R14, // 14
    x64_indices::R15, // 15
];

#[derive(Debug, Clone, Copy)]
pub struct RuntimeFunction {
    pub begin: u32,
    pub end: u32,
    pub unwind_info: u32,
}

/// Parsed `.pdata` for one module (empty when the module has none).
struct ModuleUnwind {
    funcs: Vec<RuntimeFunction>,
}

/// Lazily parses and caches `.pdata` for each module it is asked about.
pub struct UnwindTables {
    modules: HashMap<u64, Option<ModuleUnwind>>,
    ranges: Vec<(u64, u64)>,
}

impl UnwindTables {
    pub fn new(modules: &[Module]) -> Self {
        UnwindTables {
            modules: HashMap::new(),
            ranges: modules.iter().map(|m| (m.base_va, m.size)).collect(),
        }
    }

    fn module_of(&self, va: u64) -> Option<(u64, u64)> {
        self.ranges
            .iter()
            .find(|&&(b, s)| va >= b && va < b + s)
            .copied()
    }

    /// Find the RUNTIME_FUNCTION covering `va`, parsing the module's `.pdata`
    /// on first use.
    pub fn lookup(&mut self, space: &AddressSpace, va: u64) -> Option<(u64, RuntimeFunction)> {
        let (base, size) = self.module_of(va)?;

        let mu = self
            .modules
            .entry(base)
            .or_insert_with(|| parse_pdata(space, base, size))
            .as_ref()?;
        let rva = (va - base) as u32;
        // .pdata is sorted by begin address.
        let idx = mu
            .funcs
            .binary_search_by(|f| {
                if rva < f.begin {
                    std::cmp::Ordering::Greater
                } else if rva >= f.end {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .ok()?;
        Some((base, mu.funcs[idx]))
    }
}

/// Parse a module's exception data directory through the AddressSpace.
fn parse_pdata(space: &AddressSpace, base: u64, _size: u64) -> Option<ModuleUnwind> {
    let read32 = |va: u64| -> Option<u32> {
        let b = space.read(va, 4)?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
    };
    let read16 = |va: u64| -> Option<u16> {
        let b = space.read(va, 2)?;
        Some(u16::from_le_bytes(b.try_into().ok()?))
    };

    if space.read(base, 2)? != b"MZ" {
        return None;
    }
    let pe_off = read32(base + 0x3C)? as u64;
    if space.read(base + pe_off, 4)? != b"PE\0\0" {
        return None;
    }
    let opt = base + pe_off + 24;
    if read16(opt)? != 0x20B {
        return None;
    }
    // Data directory #3 (exception): PE32+ directories start at opt + 112.
    let dir = opt + 112 + 24;
    let pdata_rva = read32(dir)?;
    let pdata_size = read32(dir + 4)?;
    if pdata_rva == 0 || pdata_size == 0 {
        return None;
    }
    let count = pdata_size as usize / 12;
    let pdata_va = base + pdata_rva as u64;
    // Read in chunks: a single giant read may span beyond the image backing.
    let mut funcs = Vec::with_capacity(count);
    let mut done = 0usize;
    while done < count {
        let n = (count - done).min(4096);
        let Some(bytes) = space.read(pdata_va + 12 * done as u64, 12 * n) else {
            break;
        };
        for chunk in bytes.chunks_exact(12) {
            funcs.push(RuntimeFunction {
                begin: u32::from_le_bytes(chunk[0..4].try_into().ok()?),
                end: u32::from_le_bytes(chunk[4..8].try_into().ok()?),
                unwind_info: u32::from_le_bytes(chunk[8..12].try_into().ok()?),
            });
        }
        done += n;
    }
    Some(ModuleUnwind { funcs })
}

fn read_mem(space: &AddressSpace, va: u64) -> Option<u64> {
    let b = space.read(va, 8)?;
    Some(u64::from_le_bytes(b.try_into().ok()?))
}

/// Apply one unwind step: simulate the function's prolog unwind codes plus
/// the final return-address pop, updating `regs`. Returns false on failure.
pub fn unwind_step(
    regs: &mut RegisterSet,
    space: &AddressSpace,
    module_base: u64,
    rt: RuntimeFunction,
) -> bool {
    let mut cur = rt;
    let rip_off_in_func = regs.rip().wrapping_sub(module_base) as u32;

    loop {
        let Some(hdr) = space.read(module_base + cur.unwind_info as u64, 4) else {
            return false;
        };
        let version_flags = hdr[0];
        let flags = version_flags >> 3;
        let size_of_prolog = hdr[1] as u32;
        let count = hdr[2] as usize;
        let frame_reg = hdr[3] & 0xF;
        let frame_off_scaled = hdr[3] >> 4;

        // Effective prolog position of the current PC: PCs before the prolog
        // end must skip unwind codes that haven't executed yet.
        let pc_in_prolog = rip_off_in_func
            .checked_sub(cur.begin)
            .map(|o| o < size_of_prolog)
            .unwrap_or(false);
        let pc_offset = rip_off_in_func.wrapping_sub(cur.begin);

        let codes_va = module_base + cur.unwind_info as u64 + 4;
        let mut consumed = 0usize; // 2-byte slots consumed (ops + extra slots)
        while consumed < count {
            let Some(cb) = space.read(codes_va + 2 * consumed as u64, 2) else {
                return false;
            };
            consumed += 1;
            let code_off = cb[0] as u32;
            // UNWIND_CODE: op in low nibble, opinfo in high nibble.
            let op = cb[1] & 0xF;
            let info = cb[1] >> 4;

            // Skip codes whose prolog instruction hasn't been reached yet.
            if pc_in_prolog && code_off > pc_offset {
                continue;
            }

            let slot = |space: &AddressSpace, at: usize| -> Option<u32> {
                let b = space.read(codes_va + 2 * at as u64, 2)?;
                Some(u16::from_le_bytes(b.try_into().ok()?) as u32)
            };

            let rsp = regs.rsp();
            match op {
                0 => {
                    // UWOP_PUSH_NONVOL
                    let Some(v) = read_mem(space, rsp) else {
                        return false;
                    };
                    regs.set(UWREG_MAP[info as usize], v);
                    regs.set(x64_indices::RSP, rsp + 8);
                }
                1 => {
                    // UWOP_ALLOC_LARGE
                    if info == 0 {
                        let Some(n) = slot(space, consumed) else {
                            return false;
                        };
                        consumed += 1;
                        regs.set(x64_indices::RSP, rsp + 8 * n as u64);
                    } else {
                        let Some(lo) = slot(space, consumed) else {
                            return false;
                        };
                        let Some(hi) = slot(space, consumed + 1) else {
                            return false;
                        };
                        consumed += 2;
                        regs.set(x64_indices::RSP, rsp + (lo | (hi << 16)) as u64);
                    }
                }
                2 => {
                    // UWOP_ALLOC_SMALL
                    regs.set(x64_indices::RSP, rsp + 8 * (info as u64 + 1));
                }
                3 => {
                    // UWOP_SET_FPREG
                    let frame = regs.get(UWREG_MAP[frame_reg as usize]);
                    regs.set(
                        x64_indices::RSP,
                        frame.wrapping_sub(16 * frame_off_scaled as u64),
                    );
                }
                4 => {
                    // UWOP_SAVE_NONVOL
                    let Some(n) = slot(space, consumed) else {
                        return false;
                    };
                    consumed += 1;
                    let Some(v) = read_mem(space, rsp + 8 * n as u64) else {
                        return false;
                    };
                    regs.set(UWREG_MAP[info as usize], v);
                }
                5 => {
                    // UWOP_SAVE_NONVOL_FAR
                    let Some(lo) = slot(space, consumed) else {
                        return false;
                    };
                    let Some(hi) = slot(space, consumed + 1) else {
                        return false;
                    };
                    consumed += 2;
                    let Some(v) = read_mem(space, rsp + (lo | (hi << 16)) as u64) else {
                        return false;
                    };
                    regs.set(UWREG_MAP[info as usize], v);
                }
                6 | 7 => {
                    // UWOP_EPILOG / SPARE (v2) — skip payload slots.
                    consumed += if op == 6 { 1 } else { 0 };
                }
                8 => {
                    // UWOP_SAVE_XMM128 — no GPR effect.
                    consumed += 1;
                }
                9 => {
                    // UWOP_SAVE_XMM128_FAR — no GPR effect.
                    consumed += 2;
                }
                10 => {
                    // UWOP_PUSH_MACHFRAME
                    regs.set(x64_indices::RSP, rsp + if info == 1 { 0x30 } else { 0x28 });
                }
                _ => return false,
            }
        }

        if flags & UNW_FLAG_CHAININFO != 0 {
            // A chained RUNTIME_FUNCTION follows the (aligned) unwind codes.
            let slot_count = (count + 1) & !1;
            let chained_va = codes_va + 2 * slot_count as u64;
            let Some(b) = space.read(chained_va, 12) else {
                return false;
            };
            cur = RuntimeFunction {
                begin: u32::from_le_bytes(b[0..4].try_into().unwrap()),
                end: u32::from_le_bytes(b[4..8].try_into().unwrap()),
                unwind_info: u32::from_le_bytes(b[8..12].try_into().unwrap()),
            };
            continue;
        }
        break;
    }

    // Standard return address pop.
    let Some(ret) = read_mem(space, regs.rsp()) else {
        return false;
    };
    regs.set(x64_indices::RIP, ret);
    regs.set(x64_indices::RSP, regs.rsp() + 8);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MemState, RegionClass};
    use crate::space::{AddressRegion, AddressSpace};

    const BASE: u64 = 0x1_0000_0000;

    /// Module region with a fake PE header + one RUNTIME_FUNCTION, plus a
    /// stack region. `pdata` holds the exception directory payload,
    /// `unwind` the UNWIND_INFO blob at RVA 0x4000.
    fn make_space(pdata: &[u8], unwind: &[u8], stack: Vec<u8>) -> AddressSpace {
        let mut img = vec![0u8; 0x5000];
        img[0..2].copy_from_slice(b"MZ");
        img[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        img[0x80..0x84].copy_from_slice(b"PE\0\0");
        let opt = 0x80 + 24;
        img[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        let dir = opt + 112 + 24;
        img[dir..dir + 4].copy_from_slice(&0x3000u32.to_le_bytes()); // .pdata RVA
        img[dir + 4..dir + 8].copy_from_slice(&(pdata.len() as u32).to_le_bytes());
        img[0x3000..0x3000 + pdata.len()].copy_from_slice(pdata);
        img[0x4000..0x4000 + unwind.len()].copy_from_slice(unwind);

        let mut space = AddressSpace::new(4);
        space
            .add_region(AddressRegion {
                va_start: BASE,
                size: img.len() as u64,
                data: img,
                protection: 5,
                state: MemState::Commit,
                classification: RegionClass::Image,
            })
            .unwrap();
        space
            .add_region(AddressRegion {
                va_start: 0x8000,
                size: stack.len() as u64,
                data: stack,
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Stack,
            })
            .unwrap();
        space
    }

    fn rt(unwind_rva: u32) -> RuntimeFunction {
        RuntimeFunction {
            begin: 0x1000,
            end: 0x1100,
            unwind_info: unwind_rva,
        }
    }

    fn make_pdata(unwind_rva: u32) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&0x1000u32.to_le_bytes());
        p.extend_from_slice(&0x1100u32.to_le_bytes());
        p.extend_from_slice(&unwind_rva.to_le_bytes());
        p
    }

    fn regs(rip: u64, rsp: u64, rbp: u64) -> RegisterSet {
        let mut r = RegisterSet::new();
        r.set(x64_indices::RIP, rip);
        r.set(x64_indices::RSP, rsp);
        r.set(x64_indices::RBP, rbp);
        r
    }

    #[test]
    fn pdata_lookup_finds_function() {
        let space = make_space(&make_pdata(0x4000), &[1, 4, 1, 0], vec![0; 0x100]);
        let mut tables = UnwindTables::new(&[Module {
            name: "m.exe".into(),
            base_va: BASE,
            size: 0x5000,
            checksum: 0,
            codeview_guid: None,
            codeview_age: None,
            pdb_name: None,
            provenance: crate::error::Provenance {
                stream_type: 0,
                file_offset: 0,
                rva: 0,
            },
        }]);
        let (base, f) = tables.lookup(&space, BASE + 0x1050).unwrap();
        assert_eq!(base, BASE);
        assert_eq!(f.begin, 0x1000);
        assert!(tables.lookup(&space, BASE + 0x9999).is_none());
    }

    #[test]
    fn push_nonvol_and_alloc_small() {
        // Prolog: push rbx; sub rsp,24 → unwind codes (reverse):
        // [ALLOC_SMALL n=3], [PUSH_NONVOL rbx]
        let unwind = [1u8, 4, 2, 0, 0x02, 0x22, 0x00, 0x30]; // ver1,prolog4,2 slots
        let mut stack = vec![0u8; 0x100];
        // after alloc-undo rsp=0x8000: pushed rbx, then return address
        stack[0..8].copy_from_slice(&0xBEEFu64.to_le_bytes());
        stack[8..16].copy_from_slice(&0x7ABCu64.to_le_bytes());
        let space = make_space(&make_pdata(0x4000), &unwind, stack);
        let mut r = regs(BASE + 0x1080, 0x7FE8, 0);
        assert!(unwind_step(&mut r, &space, BASE, rt(0x4000)));
        assert_eq!(r.get(x64_indices::RBX), 0xBEEF);
        assert_eq!(r.rsp(), 0x8010);
        assert_eq!(r.rip(), 0x7ABC);
    }

    #[test]
    fn set_fpreg_and_save_nonvol() {
        // Prolog: push rbp; mov rbp,rsp; sub rsp,0x30; mov [rsp+16],rsi
        // Unwind codes (reverse): SAVE_NONVOL rsi@+16, ALLOC_SMALL 6,
        // SET_FPREG (frame=rbp), PUSH_NONVOL rbp → 5 slots.
        let unwind = [
            1u8, 8, 5, 0x05, // hdr
            0x08, 0x64, 0x02, 0x00, // SAVE_NONVOL rsi, slot 2 (16/8)
            0x06, 0x52, // ALLOC_SMALL 6
            0x03, 0x03, // SET_FPREG
            0x00, 0x50, // PUSH_NONVOL rbp
            0x00, 0x00, // align
        ];
        let mut stack = vec![0u8; 0x200];
        stack[0x70..0x78].copy_from_slice(&0x5151u64.to_le_bytes()); // rsi @rsp+16
        stack[0x100..0x108].copy_from_slice(&0x9000u64.to_le_bytes()); // saved rbp
        stack[0x108..0x110].copy_from_slice(&0x9999u64.to_le_bytes()); // ret
        let space = make_space(&make_pdata(0x4000), &unwind, stack);
        let mut r = regs(BASE + 0x1080, 0x8060, 0x8100);
        assert!(unwind_step(&mut r, &space, BASE, rt(0x4000)));
        assert_eq!(r.get(x64_indices::RSI), 0x5151);
        assert_eq!(r.get(x64_indices::RBP), 0x9000);
        assert_eq!(r.rsp(), 0x8110);
        assert_eq!(r.rip(), 0x9999);
    }

    #[test]
    fn push_machframe() {
        let unwind = [1u8, 4, 1, 0, 0x00, 0x0A, 0x00, 0x00];
        let mut stack = vec![0u8; 0x100];
        stack[0x28..0x30].copy_from_slice(&0x1234u64.to_le_bytes()); // ret after frame
        let space = make_space(&make_pdata(0x4000), &unwind, stack);
        let mut r = regs(BASE + 0x1080, 0x8000, 0);
        assert!(unwind_step(&mut r, &space, BASE, rt(0x4000)));
        assert_eq!(r.rsp(), 0x8030);
        assert_eq!(r.rip(), 0x1234);
    }
}

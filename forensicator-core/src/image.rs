//! PE image backing: supplements dump memory with bytes read from an on-disk
//! module image (.exe/.dll). Used when a minidump captures only thread
//! stacks — .pdata/.text/.rdata are then still reachable by VA.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
struct Section {
    va_start: u32,
    va_size: u32,
    raw_ptr: u32,
    raw_size: u32,
}

/// A single module image mapped at `base_va` in the dumped process.
#[derive(Debug, Clone)]
pub struct ImageFile {
    pub base_va: u64,
    pub size_of_image: u64,
    data: Vec<u8>,
    header_size: u32,
    sections: Vec<Section>,
}

impl ImageFile {
    /// Parse a PE file and associate it with the load base recorded in the dump.
    pub fn open(path: impl AsRef<Path>, base_va: u64) -> Result<Self, String> {
        let data = std::fs::read(path.as_ref()).map_err(|e| e.to_string())?;
        Self::from_bytes(data, base_va)
    }

    pub fn from_bytes(data: Vec<u8>, base_va: u64) -> Result<Self, String> {
        let r16 = |off: usize| -> Result<u16, String> {
            data.get(off..off + 2)
                .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
                .ok_or_else(|| "truncated PE".to_string())
        };
        let r32 = |off: usize| -> Result<u32, String> {
            data.get(off..off + 4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                .ok_or_else(|| "truncated PE".to_string())
        };

        if data.len() < 0x40 || &data[0..2] != b"MZ" {
            return Err("not a PE (MZ missing)".into());
        }
        let pe_off = r32(0x3C)? as usize;
        if data.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
            return Err("not a PE (signature missing)".into());
        }
        let coff = pe_off + 4;
        let num_sections = r16(coff + 2)? as usize;
        let opt_size = r16(coff + 16)? as usize;
        let opt = coff + 20;
        let magic = r16(opt)?;
        if magic != 0x20B {
            return Err(format!("not a PE32+ image (magic {magic:#x})"));
        }
        let size_of_image = r32(opt + 56)?;
        let header_size = r32(opt + 60)?;

        let sec_off = opt + opt_size;
        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let s = sec_off + i * 40;
            if s + 40 > data.len() {
                return Err("truncated section table".into());
            }
            sections.push(Section {
                va_size: r32(s + 8)?,
                va_start: r32(s + 12)?,
                raw_size: r32(s + 16)?,
                raw_ptr: r32(s + 20)?,
            });
        }

        Ok(ImageFile {
            base_va,
            size_of_image: size_of_image as u64,
            data,
            header_size,
            sections,
        })
    }

    /// Read `len` bytes at virtual address `va`, mapping through the section
    /// table. Returns None when outside the image or unmapped file bytes.
    pub fn read(&self, va: u64, len: usize) -> Option<&[u8]> {
        if va < self.base_va {
            return None;
        }
        let rva = (va - self.base_va) as u32;
        let file_off = if (rva as u64) < self.header_size as u64 {
            rva as usize
        } else {
            let sec = self.sections.iter().find(|s| {
                let span = s.va_size.max(s.raw_size);
                rva >= s.va_start && rva < s.va_start + span
            })?;
            (sec.raw_ptr + (rva - sec.va_start)) as usize
        };
        self.data.get(file_off..file_off.checked_add(len)?)
    }
}

/// All discovered module images, keyed by load base.
#[derive(Debug, Clone, Default)]
pub struct ImageSet {
    images: Vec<ImageFile>,
}

impl ImageSet {
    pub fn new() -> Self {
        ImageSet { images: vec![] }
    }

    pub fn push(&mut self, img: ImageFile) {
        self.images.push(img);
    }

    pub fn len(&self) -> usize {
        self.images.len()
    }
    pub fn is_empty(&self) -> bool {
        self.images.is_empty()
    }

    pub fn read(&self, va: u64, len: usize) -> Option<&[u8]> {
        self.images.iter().find_map(|i| i.read(va, len))
    }

    /// Discover images for dump modules by basename in `dir`.
    /// `module_paths` are the paths recorded in the dump's module list.
    pub fn discover(dir: &Path, module_paths: &[String], base_vas: &[u64]) -> ImageSet {
        let mut set = ImageSet::new();
        for (path, base) in module_paths.iter().zip(base_vas.iter()) {
            // Module paths are Windows paths; split on both separators.
            let Some(name) = path.rsplit(['/', '\\']).next().filter(|n| !n.is_empty()) else {
                continue;
            };
            let candidate: PathBuf = dir.join(name);
            if !candidate.exists() {
                continue;
            }
            if let Ok(img) = ImageFile::open(&candidate, *base) {
                set.push(img);
            }
        }
        set
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal PE32+ with two sections: .text RVA 0x1000 (raw 0x200),
    /// .pdata RVA 0x2000 (raw 0x400).
    fn make_pe() -> Vec<u8> {
        let mut d = vec![0u8; 0x600];
        d[0..2].copy_from_slice(b"MZ");
        d[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        d[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes()); // sections
        d[coff + 16..coff + 18].copy_from_slice(&0xF0u16.to_le_bytes()); // opt size
        let opt = coff + 20;
        d[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        d[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
        d[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
        let s0 = opt + 0xF0;
        d[s0..s0 + 5].copy_from_slice(b".text");
        d[s0 + 8..s0 + 12].copy_from_slice(&0x100u32.to_le_bytes());
        d[s0 + 12..s0 + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        d[s0 + 16..s0 + 20].copy_from_slice(&0x200u32.to_le_bytes());
        d[s0 + 20..s0 + 24].copy_from_slice(&0x200u32.to_le_bytes());
        let s1 = s0 + 40;
        d[s1..s1 + 6].copy_from_slice(b".pdata");
        d[s1 + 8..s1 + 12].copy_from_slice(&0x100u32.to_le_bytes());
        d[s1 + 12..s1 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        d[s1 + 16..s1 + 20].copy_from_slice(&0x100u32.to_le_bytes());
        d[s1 + 20..s1 + 24].copy_from_slice(&0x400u32.to_le_bytes());
        d[0x200] = 0xCC;
        d[0x400] = 0x90;
        d
    }

    #[test]
    fn reads_sections_by_va() {
        let img = ImageFile::from_bytes(make_pe(), 0x1_0000_0000).unwrap();
        assert_eq!(img.size_of_image, 0x3000);
        assert_eq!(img.read(0x1_0000_0000, 2), Some(b"MZ".as_slice())); // headers
        assert_eq!(img.read(0x1_0000_1000, 1), Some(&[0xCC][..]));
        assert_eq!(img.read(0x1_0000_2000, 1), Some(&[0x90][..]));
        assert!(img.read(0x1_0000_3000, 1).is_none());
        assert!(img.read(0x9999, 1).is_none());
    }

    #[test]
    fn rejects_non_pe() {
        assert!(ImageFile::from_bytes(vec![0u8; 16], 0x1000).is_err());
    }
}

use crate::analyzer::{Analyzer, AnalyzerOutput};
use crate::model::{Dump, StringEncoding, StructString};
use crate::space::AddressSpace;

pub struct StringAnalyzer {
    pub min_len: usize,
    pub max_len: usize,
    pub max_nonprintable_ratio: f64,
    pub max_scan_per_region: usize,
}

impl Default for StringAnalyzer {
    fn default() -> Self {
        StringAnalyzer {
            min_len: 4,
            max_len: 1024,
            max_nonprintable_ratio: 0.2,
            max_scan_per_region: 4096,
        }
    }
}

impl Analyzer for StringAnalyzer {
    fn name(&self) -> &str {
        "strings"
    }
    fn description(&self) -> &str {
        "Scans committed memory for null-terminated strings (ASCII, UTF-16LE)"
    }

    fn analyze(&self, _dump: &Dump, space: &AddressSpace) -> AnalyzerOutput {
        let mut out = AnalyzerOutput::new("strings");
        out.strings = self.detect(space);
        out
    }
}

impl StringAnalyzer {
    fn detect(&self, space: &AddressSpace) -> Vec<StructString> {
        let mut results = Vec::new();
        for region in space.regions() {
            if matches!(region.classification, crate::model::RegionClass::Other) {
                continue;
            }
            let data = &region.data;
            let scan_len = data.len().min(self.max_scan_per_region);
            let mut i = 0usize;
            while i < scan_len {
                if let Some(s) = self.try_ascii(data, region.va_start, i) {
                    let blen = s.byte_len;
                    if blen >= self.min_len {
                        results.push(s);
                        i += blen + 1;
                    } else {
                        i += 1;
                    }
                    continue;
                }
                if i + 2 <= data.len() {
                    if let Some(s) = self.try_utf16le(data, region.va_start, i) {
                        let blen = s.byte_len;
                        if blen >= self.min_len {
                            results.push(s);
                            i += blen + 2;
                        } else {
                            i += 2;
                        }
                        continue;
                    }
                }
                i += 1;
            }
        }
        results
    }

    fn try_ascii(&self, data: &[u8], base_va: u64, start: usize) -> Option<StructString> {
        let mut buf: Vec<u8> = Vec::new();
        let mut nonprint = 0usize;
        let mut i = start;
        while i < data.len() && buf.len() < self.max_len {
            let b = data[i];
            if b == 0 {
                break;
            }
            if b < 0x20 || b > 0x7E {
                if b != b'\t' && b != b'\n' && b != b'\r' {
                    nonprint += 1;
                }
            }
            buf.push(b);
            i += 1;
        }
        if i >= data.len() || data[i] != 0 {
            return None;
        }
        if buf.len() < self.min_len {
            return None;
        }
        let ratio = nonprint as f64 / buf.len().max(1) as f64;
        if ratio > self.max_nonprintable_ratio {
            return None;
        }
        let content = String::from_utf8_lossy(&buf).to_string();
        Some(StructString {
            va: base_va + start as u64,
            byte_len: buf.len(),
            encoding: StringEncoding::Ascii,
            content,
            confidence: 1.0 - ratio,
        })
    }

    fn try_utf16le(&self, data: &[u8], base_va: u64, start: usize) -> Option<StructString> {
        let mut units: Vec<u16> = Vec::new();
        let mut nonprint = 0usize;
        let mut i = start;
        while i + 1 < data.len() && units.len() * 2 < self.max_len {
            let w = u16::from_le_bytes([data[i], data[i + 1]]);
            if w == 0 {
                break;
            }
            if w < 0x20 && w != b'\t' as u16 && w != b'\n' as u16 && w != b'\r' as u16 {
                nonprint += 1;
            }
            units.push(w);
            i += 2;
        }
        if i + 1 >= data.len() || u16::from_le_bytes([data[i], data[i + 1]]) != 0 {
            return None;
        }
        if units.len() < self.min_len {
            return None;
        }
        let ratio = nonprint as f64 / units.len().max(1) as f64;
        if ratio > self.max_nonprintable_ratio {
            return None;
        }
        let content = String::from_utf16_lossy(&units);
        Some(StructString {
            va: base_va + start as u64,
            byte_len: units.len() * 2,
            encoding: StringEncoding::Utf16Le,
            content,
            confidence: 1.0 - ratio,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::MemState;
    use crate::space::{AddressRegion, AddressSpace};

    #[test]
    fn detects_ascii_string() {
        let mut space = AddressSpace::new(4);
        space
            .add_region(AddressRegion {
                va_start: 0x1000,
                size: 16,
                data: b"hello\0world\0".to_vec(),
                protection: 3,
                state: MemState::Commit,
                classification: crate::model::RegionClass::Private,
            })
            .unwrap();
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            file_size: 0,
        };
        let a = StringAnalyzer::default();
        let out = a.analyze(&dump, &space);
        assert_eq!(out.strings.len(), 2);
        assert_eq!(out.strings[0].content, "hello");
        assert_eq!(out.strings[0].va, 0x1000);
    }

    #[test]
    fn ignores_short_strings() {
        let mut space = AddressSpace::new(4);
        space
            .add_region(AddressRegion {
                va_start: 0,
                size: 4,
                data: b"ab\0".to_vec(),
                protection: 3,
                state: MemState::Commit,
                classification: crate::model::RegionClass::Private,
            })
            .unwrap();
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            file_size: 0,
        };
        let a = StringAnalyzer::default();
        let out = a.analyze(&dump, &space);
        assert!(out.strings.is_empty());
    }

    #[test]
    fn empty_space_returns_empty() {
        let space = AddressSpace::new(4);
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            file_size: 0,
        };
        let a = StringAnalyzer::default();
        let out = a.analyze(&dump, &space);
        assert!(out.strings.is_empty());
    }
}

use crate::analyzer::{Analyzer, AnalyzerOutput};
use crate::model::{Dump, RegionClass, StructVTable};
use crate::space::AddressSpace;

pub struct VTableAnalyzer {
    pub min_methods: usize,
    pub max_methods: usize,
}

impl Default for VTableAnalyzer {
    fn default() -> Self {
        VTableAnalyzer {
            min_methods: 3,
            max_methods: 256,
        }
    }
}

impl Analyzer for VTableAnalyzer {
    fn name(&self) -> &str {
        "vtables"
    }
    fn description(&self) -> &str {
        "Scans Image-region data for aligned function pointers forming vtables"
    }

    fn analyze(&self, _dump: &Dump, space: &AddressSpace) -> AnalyzerOutput {
        let mut out = AnalyzerOutput::new("vtables");
        out.vtables = self.detect(space);
        out
    }
}

impl VTableAnalyzer {
    fn detect(&self, space: &AddressSpace) -> Vec<StructVTable> {
        let mut results = Vec::new();
        for region in space.regions() {
            if region.classification != RegionClass::Image {
                continue;
            }
            let data = &region.data;
            let mut offset = 0usize;
            'outer: while offset + 8 <= data.len() {
                let bytes: [u8; 8] = data[offset..offset + 8].try_into().unwrap();
                let value = u64::from_le_bytes(bytes);
                if value == 0 {
                    offset += 8;
                    continue;
                }
                let is_code_ptr = space.classify(value) == RegionClass::Image;
                if !is_code_ptr {
                    offset += 8;
                    continue;
                }
                let va = region.va_start + offset as u64;
                let mut methods: Vec<u64> = vec![value];
                let mut run_offset = offset + 8;
                while run_offset + 8 <= data.len() && methods.len() < self.max_methods {
                    let b: [u8; 8] = data[run_offset..run_offset + 8].try_into().unwrap();
                    let v = u64::from_le_bytes(b);
                    if v == 0 {
                        break;
                    }
                    let is_ptr = space.classify(v) == RegionClass::Image;
                    if !is_ptr {
                        break;
                    }
                    methods.push(v);
                    run_offset += 8;
                }
                if methods.len() >= self.min_methods {
                    results.push(StructVTable {
                        va,
                        method_count: methods.len(),
                        methods,
                        module_name: None,
                        confidence: 0.8,
                    });
                    offset = run_offset;
                    continue 'outer;
                }
                offset += 8;
            }
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::MemState;
    use crate::space::{AddressRegion, AddressSpace};

    #[test]
    fn detects_vtable() {
        let mut space = AddressSpace::new(8);
        let mut data: Vec<u8> = Vec::new();
        for &ptr in &[0x401000u64, 0x402000, 0x403000, 0u64] {
            data.extend_from_slice(&ptr.to_le_bytes());
        }
        space
            .add_region(AddressRegion {
                va_start: 0x400000,
                size: data.len() as u64,
                data,
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Image,
            })
            .unwrap();
        let target_data = vec![0u8; 16];
        space
            .add_region(AddressRegion {
                va_start: 0x401000,
                size: 16,
                data: target_data.clone(),
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Image,
            })
            .unwrap();
        space
            .add_region(AddressRegion {
                va_start: 0x402000,
                size: 16,
                data: target_data.clone(),
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Image,
            })
            .unwrap();
        space
            .add_region(AddressRegion {
                va_start: 0x403000,
                size: 16,
                data: target_data,
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Image,
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
        let a = VTableAnalyzer::default();
        let out = a.analyze(&dump, &space);
        assert_eq!(out.vtables.len(), 1);
        assert_eq!(out.vtables[0].method_count, 3);
    }

    #[test]
    fn empty_returns_empty() {
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
        let a = VTableAnalyzer::default();
        let out = a.analyze(&dump, &space);
        assert!(out.vtables.is_empty());
    }

    #[test]
    fn too_few_methods_filtered() {
        let mut space = AddressSpace::new(4);
        let mut data: Vec<u8> = Vec::new();
        for &ptr in &[0x401000u64, 0u64] {
            data.extend_from_slice(&ptr.to_le_bytes());
        }
        space
            .add_region(AddressRegion {
                va_start: 0,
                size: data.len() as u64,
                data,
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Image,
            })
            .unwrap();
        space
            .add_region(AddressRegion {
                va_start: 0x401000,
                size: 8,
                data: vec![0u8; 8],
                protection: 3,
                state: MemState::Commit,
                classification: RegionClass::Image,
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
        let a = VTableAnalyzer::default();
        let out = a.analyze(&dump, &space);
        assert!(out.vtables.is_empty());
    }
}

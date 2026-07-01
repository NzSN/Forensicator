use std::path::Path;

use crate::analyzer::{Pipeline, StructureCatalog};
use crate::error::FatalError;
use crate::model::Dump;
use crate::parse::dump;
use crate::space::AddressSpace;

pub struct Forensicator;

pub struct S1Output {
    pub dump: Dump,
    pub space: AddressSpace,
}

impl Forensicator {
    pub fn s1(path: impl AsRef<Path>) -> Result<S1Output, FatalError> {
        let dump = dump::open(&path)?;
        let space = Self::build_address_space(&dump);
        Ok(S1Output { dump, space })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<S1Output, FatalError> {
        Self::s1(path)
    }

    pub fn analyze(s1: &S1Output, pipeline: &Pipeline, filter: &[&str]) -> StructureCatalog {
        pipeline.run(&s1.dump, &s1.space, filter)
    }

    pub fn run_full(
        path: impl AsRef<Path>,
        pipeline: &Pipeline,
        filter: &[&str],
    ) -> Result<(S1Output, StructureCatalog), Box<dyn std::error::Error>> {
        let s1 = Self::s1(path)?;
        let cat = Self::analyze(&s1, pipeline, filter);
        Ok((s1, cat))
    }

    pub fn build_address_space(dump: &Dump) -> AddressSpace {
        let mut space = AddressSpace::new(1_000_000);
        for region in &dump.memory_regions {
            let ar = crate::space::AddressRegion {
                va_start: region.va_start,
                size: region.size,
                data: region.data.clone(),
                protection: region.protection.bits(),
                state: region.state,
                classification: region
                    .region_class
                    .unwrap_or(crate::model::RegionClass::Other),
            };
            let _ = space.add_region(ar);
        }
        space
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s1output_construction() {
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            file_size: 0,
        };
        let space = AddressSpace::new(4);
        let out = S1Output { dump, space };
        assert_eq!(out.dump.file_size, 0);
        assert_eq!(out.space.len(), 0);
    }

    #[test]
    fn analyze_with_empty_pipeline() {
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            file_size: 0,
        };
        let space = AddressSpace::new(4);
        let s1 = S1Output { dump, space };
        let pipeline = Pipeline::new();
        let cat = Forensicator::analyze(&s1, &pipeline, &[]);
        assert!(cat.outputs.is_empty());
    }

    #[test]
    fn build_address_space_from_empty_dump() {
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            file_size: 0,
        };
        let space = Forensicator::build_address_space(&dump);
        assert_eq!(space.len(), 0);
    }
}

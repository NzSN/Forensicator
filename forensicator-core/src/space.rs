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
        AddressSpace {
            regions: Vec::new(),
            max_regions,
        }
    }

    /// Number of regions.
    pub fn len(&self) -> usize {
        self.regions.len()
    }
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Reference to all regions.
    pub fn regions(&self) -> &[AddressRegion] {
        &self.regions
    }

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
        self.region_at(va)
            .map(|r| r.classification)
            .unwrap_or(RegionClass::Other)
    }

    /// Read `len` bytes starting at `va`. Returns None if the read crosses a region boundary or is unmapped.
    pub fn read(&self, va: u64, len: usize) -> Option<&[u8]> {
        let r = self.region_at(va)?;
        let offset = (va - r.va_start) as usize;
        let end = offset.checked_add(len)?;
        if end > r.data.len() {
            return None;
        }
        Some(&r.data[offset..end])
    }

    /// Add a region. Returns Err on zero size, capacity exceeded, or overlap.
    /// Mirrors AddressSpace.tla `AddRegion`.
    pub fn add_region(&mut self, region: AddressRegion) -> Result<(), Anomaly> {
        if region.size == 0 {
            return Err(Anomaly {
                provenance: crate::error::Provenance {
                    stream_type: 0,
                    file_offset: 0,
                    rva: 0,
                },
                description: "zero-sized region".into(),
            });
        }
        if self.regions.len() >= self.max_regions {
            return Err(Anomaly {
                provenance: crate::error::Provenance {
                    stream_type: 0,
                    file_offset: 0,
                    rva: 0,
                },
                description: "AddressSpace at capacity".into(),
            });
        }
        let va = region.va_start;
        let end = va.saturating_add(region.size);
        for r in &self.regions {
            if va < r.va_start + r.size && r.va_start < end {
                return Err(Anomaly {
                    provenance: crate::error::Provenance {
                        stream_type: 0,
                        file_offset: 0,
                        rva: 0,
                    },
                    description: "overlap".into(),
                });
            }
        }
        let idx = self
            .regions
            .binary_search_by_key(&region.va_start, |r| r.va_start)
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
            va_start: va,
            size: sz,
            data: vec![0u8; sz as usize],
            protection: 3,
            state: MemState::Commit,
            classification: cls,
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
        space
            .add_region(make_region(0x1000, 0x2000, RegionClass::Image))
            .unwrap();
        let r = space.region_at(0x1000).unwrap();
        assert_eq!(r.va_start, 0x1000);
        assert_eq!(r.size, 0x2000);
    }

    #[test]
    fn region_at_midpoint() {
        let mut space = AddressSpace::new(4);
        space
            .add_region(make_region(0x1000, 0x1000, RegionClass::Stack))
            .unwrap();
        assert!(space.region_at(0x1800).is_some());
        assert_eq!(space.classify(0x1800), RegionClass::Stack);
    }

    #[test]
    fn region_at_boundary() {
        let mut space = AddressSpace::new(4);
        space
            .add_region(make_region(0, 0x1000, RegionClass::Image))
            .unwrap();
        assert!(space.region_at(0).is_some());
        assert!(space.region_at(0xFFF).is_some());
        assert!(space.region_at(0x1000).is_none());
    }

    #[test]
    fn read_within_region() {
        let mut space = AddressSpace::new(4);
        space
            .add_region(make_region(0x1000, 100, RegionClass::Private))
            .unwrap();
        let bytes = space.read(0x1000, 50).unwrap();
        assert_eq!(bytes.len(), 50);
    }

    #[test]
    fn read_crosses_region_fails() {
        let mut space = AddressSpace::new(4);
        space
            .add_region(make_region(0x1000, 50, RegionClass::Private))
            .unwrap();
        assert!(space.read(0x1000, 100).is_none());
    }

    #[test]
    fn read_unmapped_fails() {
        let space = AddressSpace::new(4);
        assert!(space.read(0, 8).is_none());
    }

    #[test]
    fn capacity_respected() {
        let mut space = AddressSpace::new(2);
        space
            .add_region(make_region(0, 100, RegionClass::Image))
            .unwrap();
        space
            .add_region(make_region(0x1000, 100, RegionClass::Stack))
            .unwrap();
        assert!(
            space
                .add_region(make_region(0x2000, 100, RegionClass::Private))
                .is_err()
        );
    }

    #[test]
    fn regions_remain_sorted() {
        let mut space = AddressSpace::new(4);
        space
            .add_region(make_region(0x3000, 100, RegionClass::Private))
            .unwrap();
        space
            .add_region(make_region(0x1000, 100, RegionClass::Image))
            .unwrap();
        space
            .add_region(make_region(0x2000, 100, RegionClass::Stack))
            .unwrap();
        let vas: Vec<u64> = space.regions().iter().map(|r| r.va_start).collect();
        assert_eq!(vas, vec![0x1000, 0x2000, 0x3000]);
    }

    #[test]
    fn is_empty_and_len() {
        let space = AddressSpace::new(4);
        assert!(space.is_empty());
        assert_eq!(space.len(), 0);
    }

    #[test]
    fn len_after_insertion() {
        let mut space = AddressSpace::new(4);
        space
            .add_region(make_region(0, 100, RegionClass::Image))
            .unwrap();
        assert!(!space.is_empty());
        assert_eq!(space.len(), 1);
    }

    #[test]
    fn gap_between_regions_returns_none() {
        let mut space = AddressSpace::new(4);
        space
            .add_region(make_region(0, 100, RegionClass::Image))
            .unwrap();
        space
            .add_region(make_region(0x2000, 100, RegionClass::Stack))
            .unwrap();
        assert!(space.region_at(0x1000).is_none());
        assert_eq!(space.classify(0x1000), RegionClass::Other);
    }

    #[test]
    fn exact_va_match() {
        let mut space = AddressSpace::new(4);
        space
            .add_region(make_region(0x400000, 0x1000, RegionClass::Image))
            .unwrap();
        assert!(space.region_at(0x400000).is_some());
        assert_eq!(space.classify(0x400000), RegionClass::Image);
    }

    #[test]
    fn one_past_end_returns_none() {
        let mut space = AddressSpace::new(4);
        space
            .add_region(make_region(0x1000, 0x1000, RegionClass::Private))
            .unwrap();
        assert!(space.region_at(0x2000).is_none());
    }

    #[test]
    fn multiple_classifications() {
        let mut space = AddressSpace::new(4);
        space
            .add_region(make_region(0, 100, RegionClass::Image))
            .unwrap();
        space
            .add_region(make_region(0x1000, 100, RegionClass::Stack))
            .unwrap();
        space
            .add_region(make_region(0x2000, 100, RegionClass::Mapped))
            .unwrap();
        space
            .add_region(make_region(0x3000, 100, RegionClass::Private))
            .unwrap();
        assert_eq!(space.classify(0), RegionClass::Image);
        assert_eq!(space.classify(0x1000), RegionClass::Stack);
        assert_eq!(space.classify(0x2000), RegionClass::Mapped);
        assert_eq!(space.classify(0x3000), RegionClass::Private);
        assert_eq!(space.classify(0x4000), RegionClass::Other);
    }

    #[test]
    fn read_at_region_start() {
        let mut space = AddressSpace::new(4);
        let mut data = vec![0u8; 100];
        data[0] = 0xAB;
        data[1] = 0xCD;
        let region = AddressRegion {
            va_start: 0x1000,
            size: 100,
            data,
            protection: 3,
            state: MemState::Commit,
            classification: RegionClass::Image,
        };
        space.add_region(region).unwrap();
        let bytes = space.read(0x1000, 2).unwrap();
        assert_eq!(bytes, &[0xAB, 0xCD]);
    }

    #[test]
    fn add_region_returns_err_message() {
        let mut space = AddressSpace::new(1);
        space
            .add_region(make_region(0, 100, RegionClass::Image))
            .unwrap();
        let err = space
            .add_region(make_region(0x2000, 100, RegionClass::Stack))
            .unwrap_err();
        assert!(err.description.contains("capacity"));
    }
}

use crate::error::Anomaly;
use crate::model::ScanResult;
use crate::pattern::PointerPattern;
use crate::space::AddressSpace;

pub fn scan(
    _space: &AddressSpace,
    _reg_refs: &[(u32, &[(String, u64)])],
    _stack_ranges: &[(u32, u64, u64)],
    _patterns: &[PointerPattern],
) -> Result<ScanResult, Anomaly> {
    Ok(ScanResult { candidates: vec![] })
}

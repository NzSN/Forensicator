use crate::model::{PointerGraph, StructVTable};
use crate::query::GraphQuery;
use crate::recover::StructureDetector;
use crate::space::AddressSpace;

#[derive(Default)]
pub struct VTableDetector;

impl StructureDetector for VTableDetector {
    type Item = StructVTable;
    fn name(&self) -> &str { "vtables" }
    fn detect(&self, _space: &AddressSpace, _graph: &PointerGraph, _query: &GraphQuery) -> Vec<StructVTable> {
        vec![]
    }
}

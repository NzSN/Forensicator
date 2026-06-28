use crate::model::{PointerGraph, StructArray};
use crate::query::GraphQuery;
use crate::recover::StructureDetector;
use crate::space::AddressSpace;

#[derive(Default)]
pub struct ArrayDetector;

impl StructureDetector for ArrayDetector {
    type Item = StructArray;
    fn name(&self) -> &str { "arrays" }
    fn detect(&self, _space: &AddressSpace, _graph: &PointerGraph, _query: &GraphQuery) -> Vec<StructArray> {
        vec![]
    }
}

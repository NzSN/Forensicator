use crate::model::{PointerGraph, StructString};
use crate::query::GraphQuery;
use crate::recover::StructureDetector;
use crate::space::AddressSpace;

#[derive(Default)]
pub struct StringDetector;

impl StructureDetector for StringDetector {
    type Item = StructString;
    fn name(&self) -> &str { "strings" }
    fn detect(&self, _space: &AddressSpace, _graph: &PointerGraph, _query: &GraphQuery) -> Vec<StructString> {
        vec![]
    }
}

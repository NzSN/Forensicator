use crate::model::{PointerGraph, StructLinkedList};
use crate::query::GraphQuery;
use crate::recover::StructureDetector;
use crate::space::AddressSpace;

#[derive(Default)]
pub struct ListDetector;

impl StructureDetector for ListDetector {
    type Item = StructLinkedList;
    fn name(&self) -> &str { "lists" }
    fn detect(&self, _space: &AddressSpace, _graph: &PointerGraph, _query: &GraphQuery) -> Vec<StructLinkedList> {
        vec![]
    }
}

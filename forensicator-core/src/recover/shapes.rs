use crate::model::{PointerGraph, ShapeClusters};
use crate::query::GraphQuery;
use crate::space::AddressSpace;

pub struct ShapeClusterer;

impl ShapeClusterer {
    pub fn cluster(_space: &AddressSpace, _graph: &PointerGraph, _query: &GraphQuery) -> ShapeClusters {
        ShapeClusters { groups: vec![] }
    }
}

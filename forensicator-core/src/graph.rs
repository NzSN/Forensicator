use crate::error::Anomaly;
use crate::model::{PointerGraph, ScanResult};

pub fn build_graph(_scan_result: &ScanResult) -> Result<PointerGraph, Anomaly> {
    Ok(PointerGraph {
        nodes: vec![],
        edges: vec![],
        va_to_node: std::collections::HashMap::new(),
        max_nodes: 0,
        max_edges: 0,
    })
}

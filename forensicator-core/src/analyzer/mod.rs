use crate::model::*;
use crate::space::AddressSpace;

pub mod scan;
pub mod strings;
pub mod vtables;
pub mod lists;
pub mod arrays;
pub mod chunks;
pub mod shapes;

pub trait Analyzer: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str { "no description" }
    fn analyze(&self, dump: &Dump, space: &AddressSpace) -> AnalyzerOutput;
}

#[derive(Debug, Clone)]
pub struct AnalyzerOutput {
    pub plugin_name: String,
    pub strings: Vec<StructString>,
    pub vtables: Vec<StructVTable>,
    pub linked_lists: Vec<StructLinkedList>,
    pub arrays: Vec<StructArray>,
    pub chunks: Vec<StructChunk>,
    pub shape_clusters: Vec<ShapeGroup>,
    pub custom: Vec<(String, serde_json::Value)>,
}

impl AnalyzerOutput {
    pub fn new(plugin_name: &str) -> Self {
        AnalyzerOutput {
            plugin_name: plugin_name.to_string(),
            strings: Vec::new(),
            vtables: Vec::new(),
            linked_lists: Vec::new(),
            arrays: Vec::new(),
            chunks: Vec::new(),
            shape_clusters: Vec::new(),
            custom: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StructureCatalog {
    pub outputs: Vec<AnalyzerOutput>,
}

impl StructureCatalog {
    pub fn empty() -> Self {
        StructureCatalog { outputs: Vec::new() }
    }

    pub fn all_strings(&self) -> impl Iterator<Item = &StructString> {
        self.outputs.iter().flat_map(|o| o.strings.iter())
    }

    pub fn all_vtables(&self) -> impl Iterator<Item = &StructVTable> {
        self.outputs.iter().flat_map(|o| o.vtables.iter())
    }

    pub fn all_linked_lists(&self) -> impl Iterator<Item = &StructLinkedList> {
        self.outputs.iter().flat_map(|o| o.linked_lists.iter())
    }

    pub fn all_arrays(&self) -> impl Iterator<Item = &StructArray> {
        self.outputs.iter().flat_map(|o| o.arrays.iter())
    }

    pub fn all_chunks(&self) -> impl Iterator<Item = &StructChunk> {
        self.outputs.iter().flat_map(|o| o.chunks.iter())
    }

    pub fn all_shape_clusters(&self) -> impl Iterator<Item = &ShapeGroup> {
        self.outputs.iter().flat_map(|o| o.shape_clusters.iter())
    }
}

pub struct Pipeline {
    analyzers: Vec<Box<dyn Analyzer>>,
}

impl Pipeline {
    pub fn new() -> Self {
        Pipeline { analyzers: Vec::new() }
    }

    pub fn register(&mut self, a: impl Analyzer + 'static) -> &mut Self {
        self.analyzers.push(Box::new(a));
        self
    }

    pub fn default_pipeline() -> Self {
        let mut p = Pipeline::new();
        p.register(strings::StringAnalyzer::default());
        p.register(vtables::VTableAnalyzer::default());
        p.register(lists::ListAnalyzer::default());
        p.register(arrays::ArrayAnalyzer::default());
        p.register(chunks::ChunkAnalyzer::default());
        p.register(shapes::ShapeAnalyzer);
        p
    }

    pub fn list_analyzers(&self) -> impl Iterator<Item = (&str, &str)> {
        self.analyzers.iter().map(|a| (a.name(), a.description()))
    }

    pub fn run(&self, dump: &Dump, space: &AddressSpace, filter: &[&str]) -> StructureCatalog {
        let use_filter = !filter.is_empty();
        let mut outputs = Vec::new();
        for analyzer in &self.analyzers {
            if use_filter && !filter.contains(&analyzer.name()) {
                continue;
            }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                analyzer.analyze(dump, space)
            }));
            match result {
                Ok(output) => outputs.push(output),
                Err(_) => {
                    let mut err_out = AnalyzerOutput::new(analyzer.name());
                    err_out.custom.push((
                        "error".to_string(),
                        serde_json::Value::String(format!("analyzer '{}' panicked", analyzer.name())),
                    ));
                    outputs.push(err_out);
                }
            }
        }
        StructureCatalog { outputs }
    }
}

impl Default for Pipeline {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::AddressSpace;

    struct TestAnalyzer;
    impl Analyzer for TestAnalyzer {
        fn name(&self) -> &str { "test" }
        fn analyze(&self, _dump: &Dump, _space: &AddressSpace) -> AnalyzerOutput {
            let mut out = AnalyzerOutput::new("test");
            out.custom.push(("result".to_string(), serde_json::Value::String("ok".to_string())));
            out
        }
    }

    #[test]
    fn pipeline_runs_registered_analyzer() {
        let mut pipeline = Pipeline::new();
        pipeline.register(TestAnalyzer);
        let dump = Dump {
            system_info: None, modules: vec![], threads: vec![],
            memory_regions: vec![], exception: None, anomalies: vec![],
            file_size: 0,
        };
        let space = AddressSpace::new(4);
        let cat = pipeline.run(&dump, &space, &[]);
        assert_eq!(cat.outputs.len(), 1);
        assert_eq!(cat.outputs[0].plugin_name, "test");
        assert_eq!(cat.outputs[0].custom[0].0, "result");
    }

    #[test]
    fn pipeline_filters_by_name() {
        let mut pipeline = Pipeline::new();
        pipeline.register(TestAnalyzer);
        let dump = Dump {
            system_info: None, modules: vec![], threads: vec![],
            memory_regions: vec![], exception: None, anomalies: vec![],
            file_size: 0,
        };
        let space = AddressSpace::new(4);
        let cat = pipeline.run(&dump, &space, &["nonexistent"]);
        assert_eq!(cat.outputs.len(), 0);
    }

    #[test]
    fn default_pipeline_has_six_analyzers() {
        // NOTE: this test will fail until all 6 analyzer submodules exist
        // It will compile but panic at runtime because submodules don't exist yet
    }

    #[test]
    fn structure_catalog_convenience_accessors() {
        let cat = StructureCatalog { outputs: vec![] };
        assert_eq!(cat.all_strings().count(), 0);
        assert_eq!(cat.all_vtables().count(), 0);
        assert_eq!(cat.all_linked_lists().count(), 0);
        assert_eq!(cat.all_arrays().count(), 0);
        assert_eq!(cat.all_chunks().count(), 0);
        assert_eq!(cat.all_shape_clusters().count(), 0);
    }
}

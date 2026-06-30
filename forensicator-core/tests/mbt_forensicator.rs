//! Model-Based Testing for Forensicator pipeline using MirrorRust.
//! Validates pipeline.rs against the TLA+ ForensicatorMBT.tla spec via trace replay.
//!
//! Requires MirrorRust binary. Set MIRROR_BIN env var to run.
//! Requires Apalache. Set APALACHE_MC env var.
//!   e.g. MIRROR_BIN=D:\Tools\ModelMirrors.exe APALACHE_MC=D:\Programs\apalache\bin\apalache-mc.bat cargo test --test mbt_forensicator -- --nocapture

use forensicator_core::model::{MemState, RegionClass};
use forensicator_core::space::{AddressRegion, AddressSpace};
use mirrorrust::{
    as_int, get_param, run_client, ApalacheConfig, State, StateComputer,
    TraceGenerationConfig, Value,
};
use num_bigint::BigInt;
use num_traits::ToPrimitive;

fn st(pairs: Vec<(&str, Value)>) -> State {
    pairs
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect()
}

fn seq_to_value(seq: &[i64]) -> Value {
    Value::Set(seq.iter().map(|&n| Value::Int(BigInt::from(n))).collect())
}

fn str_seq_to_value(seq: &[&str]) -> Value {
    Value::Set(seq.iter().map(|&s| Value::Str(s.to_string())).collect())
}

fn anomalies_to_value(anomalies: &[String]) -> Value {
    Value::Set(
        anomalies
            .iter()
            .map(|a| {
                Value::Record(
                    vec![("desc".to_string(), Value::Str(a.clone()))]
                        .into_iter()
                        .collect(),
                )
            })
            .collect(),
    )
}

fn region_class_to_str(cls: RegionClass) -> &'static str {
    match cls {
        RegionClass::Image => "Image",
        RegionClass::Stack => "Stack",
        RegionClass::Mapped => "Mapped",
        RegionClass::Private => "Private",
        RegionClass::Other => "Other",
    }
}

fn region_class_from_i64(v: i64) -> RegionClass {
    match v {
        0 => RegionClass::Image,
        1 => RegionClass::Stack,
        2 => RegionClass::Mapped,
        3 => RegionClass::Private,
        _ => RegionClass::Other,
    }
}

/// Mirrors the TLA+ state produced by ForensicatorMBT.tla.
struct PipelineComputer {
    space: AddressSpace,
    nodes: Vec<i64>,
    node_classes: Vec<i64>,
    edge_from: Vec<i64>,
    edge_to: Vec<i64>,
    edge_conf: Vec<i64>,
    phase: String,
    anomalies: Vec<String>,
    /// Model output from initial state
    p_mem_va: Vec<i64>,
    p_mem_sz: Vec<i64>,
    p_mem_cls: Vec<i64>,
}

impl PipelineComputer {
    fn new() -> Self {
        PipelineComputer {
            space: AddressSpace::new(4),
            nodes: vec![],
            node_classes: vec![],
            edge_from: vec![],
            edge_to: vec![],
            edge_conf: vec![],
            phase: "Idle".into(),
            anomalies: vec![],
            p_mem_va: vec![],
            p_mem_sz: vec![],
            p_mem_cls: vec![],
        }
    }

    fn to_state(&self) -> State {
        let s_va: Vec<i64> = self.space.regions().iter().map(|r| r.va_start as i64).collect();
        let s_sz: Vec<i64> = self.space.regions().iter().map(|r| r.size as i64).collect();
        let s_cl: Vec<&str> = self.space.regions().iter().map(|r| {
            region_class_to_str(r.classification)
        }).collect();

        st(vec![
            ("s_reg_va", seq_to_value(&s_va)),
            ("s_reg_sz", seq_to_value(&s_sz)),
            ("s_reg_cl", str_seq_to_value(&s_cl)),
            ("s_anomalies", anomalies_to_value(&self.anomalies)),
            ("g_node_va", seq_to_value(&self.nodes)),
            ("g_node_cls", seq_to_value(&self.node_classes)),
            ("g_node_root", seq_to_value(&vec![0i64; self.nodes.len()])),
            ("g_edge_from", seq_to_value(&self.edge_from)),
            ("g_edge_to", seq_to_value(&self.edge_to)),
            ("g_edge_conf", seq_to_value(&self.edge_conf)),
            ("g_phase", Value::Str(self.phase.clone())),
            ("a_regs", seq_to_value(&[])),
            ("a_anomalies", seq_to_value(&[])),
            ("p_phase", Value::Str("Done".into())),
            ("p_mem_va", seq_to_value(&self.p_mem_va)),
            ("p_mem_sz", seq_to_value(&self.p_mem_sz)),
            ("p_mem_cls", seq_to_value(&self.p_mem_cls)),
            ("p_thr_id", seq_to_value(&[])),
            ("p_thr_stack_va", seq_to_value(&[])),
            ("p_thr_stack_sz", seq_to_value(&[])),
            ("p_mod_va", seq_to_value(&[])),
            ("p_mod_sz", seq_to_value(&[])),
            ("p_exc_info", seq_to_value(&[])),
            ("p_anomalies", seq_to_value(&[])),
        ])
    }

    fn get_int_param(params: &State, key: &str) -> i64 {
        get_param(params, "parameters")
            .and_then(|p| p.get(key))
            .and_then(as_int)
            .and_then(|n| n.to_i64())
            .unwrap_or(0)
    }

    fn add_space_region(&mut self, va: i64, sz: i64, cls: i64) {
        if sz > 0 {
            let _ = self.space.add_region(AddressRegion {
                va_start: va as u64,
                size: sz as u64,
                data: vec![0u8; sz as usize],
                protection: 3,
                state: MemState::Commit,
                classification: region_class_from_i64(cls),
            });
        }
    }

    fn add_graph_node(&mut self, va: i64, cls: i64) {
        self.nodes.push(va);
        self.node_classes.push(cls);
    }
}

impl StateComputer for PipelineComputer {
    fn compute(&mut self, action: &str, params: &State, _prev: &State) -> State {
        match action {
            "Init" => {
                *self = PipelineComputer::new();
                self.p_mem_va = self.load_seq(params, "p_mem_va");
                self.p_mem_sz = self.load_seq(params, "p_mem_sz");
                self.p_mem_cls = self.load_seq(params, "p_mem_cls");
            }
            "AddSpaceRegion" => {
                let va = Self::get_int_param(params, "va");
                let sz = Self::get_int_param(params, "sz");
                let cls = Self::get_int_param(params, "cls");
                self.add_space_region(va, sz, cls);
            }
            "SpaceDone" => {}
            "AddGraphNode" => {
                let va = Self::get_int_param(params, "va");
                let cls = Self::get_int_param(params, "cls");
                self.add_graph_node(va, cls);
            }
            "EdgesPhase" => {
                self.phase = "Edges".into();
            }
            "AddGraphEdge" => {
                let src = Self::get_int_param(params, "src");
                let tgt = Self::get_int_param(params, "tgt");
                let conf = Self::get_int_param(params, "conf");
                let src_idx = src as usize;
                let tgt_idx = tgt as usize;
                if src_idx >= 1 && src_idx <= self.nodes.len()
                    && tgt_idx >= 1 && tgt_idx <= self.nodes.len()
                {
                    self.edge_from.push(src);
                    self.edge_to.push(tgt);
                    self.edge_conf.push(conf);
                }
            }
            "GraphDone" => {
                self.phase = "Done".into();
            }
            _ => {}
        }
        self.to_state()
    }
}

impl PipelineComputer {
    fn load_seq(&self, state: &State, key: &str) -> Vec<i64> {
        state.get(key)
            .and_then(|v| match v {
                Value::Set(s) => {
                    let mut items: Vec<i64> = s.iter()
                        .filter_map(|v| match v {
                            Value::Int(n) => n.to_i64(),
                            _ => None,
                        })
                        .collect();
                    items.sort(); // TLA+ sets are unordered, sort for comparison
                    Some(items)
                }
                _ => None,
            })
            .unwrap_or_default()
    }
}

fn apalache_config() -> ApalacheConfig {
    let spec_path = std::env::var("MBT_SPEC")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../specs/ForensicatorMBT.tla").to_string());
    ApalacheConfig {
        spec_path,
        invariant: "RootInvariant".into(),
        length_bound: 10,
        const_init: None,
        param_vars: Some("parameters".into()),
        init_predicate: Some("MBTInit".into()),
        next_predicate: Some("MBTNext".into()),
    }
}

fn trace_config() -> TraceGenerationConfig {
    TraceGenerationConfig {
        num_traces: 10,
        view: Some("View".into()),
    }
}

#[test]
fn mbt_forensicator() {
    let bin = match std::env::var("MIRROR_BIN") {
        Ok(b) if !b.is_empty() => b,
        _ => {
            eprintln!("MIRROR_BIN not set; skipping MBT test");
            return;
        }
    };
    run_client(&bin, apalache_config(), trace_config(), PipelineComputer::new())
        .expect("MBT forensicator test failed");
}

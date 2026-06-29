//! Model-Based Testing for Forensicator S1 using MirrorRust.
//! Validates the Rust Dump model against the TLA+ Model.tla spec via trace replay.
//!
//! Requires ModelMirros binary. Set MIRROR_BIN env var to run.
//!   e.g. MIRROR_BIN=/path/to/ModelMirros cargo test --test mbt_model -- --nocapture

use mirrorrust::{
    as_int, as_str, get_param, run_client, ApalacheConfig, State, StateComputer,
    TraceGenerationConfig, Value,
};
use num_bigint::BigInt;
use num_traits::ToPrimitive;

fn st(pairs: Vec<(&str, Value)>) -> State {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

fn seq_to_value(seq: &[i64]) -> Value {
    Value::Set(seq.iter().map(|&n| Value::Int(BigInt::from(n))).collect())
}

/// State computer mirroring Model.tla's state machine.
struct ModelComputer {
    sysinfo: Vec<i64>,
    mod_va: Vec<i64>,
    mod_sz: Vec<i64>,
    mod_prov_sid: Vec<i64>,
    mod_prov_off: Vec<i64>,
    mod_prov_rva: Vec<i64>,
    thr_id: Vec<i64>,
    thr_stack_va: Vec<i64>,
    thr_stack_sz: Vec<i64>,
    thr_prov_sid: Vec<i64>,
    thr_prov_off: Vec<i64>,
    thr_prov_rva: Vec<i64>,
    mem_va: Vec<i64>,
    mem_sz: Vec<i64>,
    mem_prot: Vec<i64>,
    mem_state: Vec<i64>,
    mem_type: Vec<i64>,
    mem_cls: Vec<i64>,
    mem_prov_sid: Vec<i64>,
    mem_prov_off: Vec<i64>,
    mem_prov_rva: Vec<i64>,
    exc_info: Vec<i64>,
    anomalies: Vec<String>,
}

const MAX_MODULES: usize = 2;
const MAX_THREADS: usize = 2;
const MAX_REGIONS: usize = 2;
const MAX_ANOMALIES: usize = 4;

impl ModelComputer {
    fn new() -> Self {
        ModelComputer {
            sysinfo: vec![],
            mod_va: vec![], mod_sz: vec![],
            mod_prov_sid: vec![], mod_prov_off: vec![], mod_prov_rva: vec![],
            thr_id: vec![], thr_stack_va: vec![], thr_stack_sz: vec![],
            thr_prov_sid: vec![], thr_prov_off: vec![], thr_prov_rva: vec![],
            mem_va: vec![], mem_sz: vec![], mem_prot: vec![],
            mem_state: vec![], mem_type: vec![], mem_cls: vec![],
            mem_prov_sid: vec![], mem_prov_off: vec![], mem_prov_rva: vec![],
            exc_info: vec![],
            anomalies: vec![],
        }
    }

    fn to_state(&self) -> State {
        st(vec![
            ("sysinfo", seq_to_value(&self.sysinfo)),
            ("mod_va", seq_to_value(&self.mod_va)),
            ("mod_sz", seq_to_value(&self.mod_sz)),
            ("mod_prov_sid", seq_to_value(&self.mod_prov_sid)),
            ("mod_prov_off", seq_to_value(&self.mod_prov_off)),
            ("mod_prov_rva", seq_to_value(&self.mod_prov_rva)),
            ("thr_id", seq_to_value(&self.thr_id)),
            ("thr_stack_va", seq_to_value(&self.thr_stack_va)),
            ("thr_stack_sz", seq_to_value(&self.thr_stack_sz)),
            ("thr_prov_sid", seq_to_value(&self.thr_prov_sid)),
            ("thr_prov_off", seq_to_value(&self.thr_prov_off)),
            ("thr_prov_rva", seq_to_value(&self.thr_prov_rva)),
            ("mem_va", seq_to_value(&self.mem_va)),
            ("mem_sz", seq_to_value(&self.mem_sz)),
            ("mem_prot", seq_to_value(&self.mem_prot)),
            ("mem_state", seq_to_value(&self.mem_state)),
            ("mem_type", seq_to_value(&self.mem_type)),
            ("mem_cls", seq_to_value(&self.mem_cls)),
            ("mem_prov_sid", seq_to_value(&self.mem_prov_sid)),
            ("mem_prov_off", seq_to_value(&self.mem_prov_off)),
            ("mem_prov_rva", seq_to_value(&self.mem_prov_rva)),
            ("exc_info", seq_to_value(&self.exc_info)),
            ("anomalies", Value::Set(
                self.anomalies.iter().map(|s| {
                    Value::Record(
                        vec![("desc".to_string(), Value::Str(s.clone()))].into_iter().collect()
                    )
                }).collect()
            )),
        ])
    }

    fn get_int_param(params: &State, key: &str) -> i64 {
        get_param(params, "parameters")
            .and_then(|p| p.get(key))
            .and_then(as_int)
            .and_then(|n| {
                n.to_i64()
            })
            .unwrap_or(0)
    }

    fn has_module_overlap(&self, va: i64, sz: i64) -> bool {
        for i in 0..self.mod_va.len() {
            let mva = self.mod_va[i];
            let msz = self.mod_sz[i];
            if mva < va + sz && va < mva + msz {
                return true;
            }
        }
        false
    }
}

impl StateComputer for ModelComputer {
    fn compute(&mut self, action: &str, params: &State, _prev: &State) -> State {
        match action {
            "Init" => {
                *self = ModelComputer::new();
            }
            "SetSysInfo" => {
                if self.sysinfo.is_empty() {
                    let os = Self::get_int_param(params, "os");
                    let cpu = 1i64; // x64 only
                    let maj = Self::get_int_param(params, "maj");
                    let min = Self::get_int_param(params, "min");
                    let bld = Self::get_int_param(params, "bld");
                    let rev = Self::get_int_param(params, "rev");
                    let sid = Self::get_int_param(params, "sid");
                    let off = Self::get_int_param(params, "off");
                    let rva = Self::get_int_param(params, "rva");
                    self.sysinfo = vec![os, cpu, maj, min, bld, rev, sid, off, rva];
                }
            }
            "AddModule" => {
                let va = Self::get_int_param(params, "va");
                let sz = Self::get_int_param(params, "sz");
                let sid = Self::get_int_param(params, "sid");
                let off = Self::get_int_param(params, "off");
                let rva = Self::get_int_param(params, "rva");
                if self.mod_va.len() < MAX_MODULES && sz > 0 && sid > 0 {
                    if !self.has_module_overlap(va, sz) {
                        self.mod_va.push(va);
                        self.mod_sz.push(sz);
                        self.mod_prov_sid.push(sid);
                        self.mod_prov_off.push(off);
                        self.mod_prov_rva.push(rva);
                    } else if self.anomalies.len() < MAX_ANOMALIES {
                        self.anomalies.push("overlapping module".to_string());
                    }
                }
            }
            "AddThread" => {
                let id = Self::get_int_param(params, "id");
                let sva = Self::get_int_param(params, "sva");
                let ssz = Self::get_int_param(params, "ssz");
                let sid = Self::get_int_param(params, "sid");
                let off = Self::get_int_param(params, "off");
                let rva = Self::get_int_param(params, "rva");
                if self.thr_id.len() < MAX_THREADS && ssz > 0 && sid > 0 {
                    self.thr_id.push(id);
                    self.thr_stack_va.push(sva);
                    self.thr_stack_sz.push(ssz);
                    self.thr_prov_sid.push(sid);
                    self.thr_prov_off.push(off);
                    self.thr_prov_rva.push(rva);
                }
            }
            "AddRegion" => {
                let va = Self::get_int_param(params, "va");
                let sz = Self::get_int_param(params, "sz");
                let prot = Self::get_int_param(params, "prot");
                let state = Self::get_int_param(params, "state");
                let typ = Self::get_int_param(params, "typ");
                let cls = Self::get_int_param(params, "cls");
                let sid = Self::get_int_param(params, "sid");
                let off = Self::get_int_param(params, "off");
                let rva = Self::get_int_param(params, "rva");
                if self.mem_va.len() < MAX_REGIONS && sz > 0 && sid > 0
                    && (0..=4).contains(&cls) && (0..=2).contains(&state) && prot <= 7
                {
                    self.mem_va.push(va);
                    self.mem_sz.push(sz);
                    self.mem_prot.push(prot);
                    self.mem_state.push(state);
                    self.mem_type.push(typ);
                    self.mem_cls.push(cls);
                    self.mem_prov_sid.push(sid);
                    self.mem_prov_off.push(off);
                    self.mem_prov_rva.push(rva);
                }
            }
            "SetException" => {
                if self.exc_info.is_empty() {
                    let code = Self::get_int_param(params, "code");
                    let addr = Self::get_int_param(params, "addr");
                    let tid = Self::get_int_param(params, "tid");
                    let flg = Self::get_int_param(params, "flg");
                    let sid = Self::get_int_param(params, "sid");
                    let off = Self::get_int_param(params, "off");
                    let rva = Self::get_int_param(params, "rva");
                    if sid > 0 {
                        self.exc_info = vec![code, addr, tid, flg, sid, off, rva];
                    }
                }
            }
            "AddAnomaly" => {
                if let Some(desc) = get_param(params, "parameters")
                    .and_then(|p| p.get("desc"))
                    .and_then(as_str)
                {
                    self.anomalies.push(desc.to_string());
                }
            }
            _ => {}
        }
        self.to_state()
    }
}

fn apalache_config() -> ApalacheConfig {
    let spec_path = std::env::var("MBT_SPEC")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../specs/ModelMBT.tla").to_string());
    ApalacheConfig {
        spec_path,
        invariant: "ModelInvariant".into(),
        length_bound: 6,
        const_init: None,
        param_vars: Some("parameters".into()),
        init_predicate: Some("MBTInit".into()),
        next_predicate: Some("MBTNext".into()),
    }
}

fn trace_config() -> TraceGenerationConfig {
    TraceGenerationConfig { num_traces: 100, view: Some("View".into()) }
}

#[test]
fn mbt_model_s1() {
    let bin = match std::env::var("MIRROR_BIN") {
        Ok(b) if !b.is_empty() => b,
        _ => {
            eprintln!("MIRROR_BIN not set; skipping MBT test");
            return;
        }
    };
    run_client(&bin, apalache_config(), trace_config(), ModelComputer::new())
        .expect("MBT model test failed");
}

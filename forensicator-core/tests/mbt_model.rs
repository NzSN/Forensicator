//! Model-Based Testing for Forensicator S1 using MirrorRust.
//! Validates the Rust Dump model (model.rs) against the TLA+ Model.tla spec via trace replay.
//!
//! Requires ModelMirros binary. Set MIRROR_BIN env var to run.
//! Requires apalache. Set APALACHE_MC env var. Use wrapper with --features=no-rows.
//!   e.g. MIRROR_BIN=D:\Tools\ModelMirrors.exe APALACHE_MC=...\wrapper.bat cargo test --test mbt_model -- --nocapture

use forensicator_core::error::Provenance;
use forensicator_core::model::{
    CpuArch, Dump, MemState, MemType, OsPlatform, Protection, RegionClass,
};
use mirrorrust::{
    ApalacheConfig, State, StateComputer, TraceGenerationConfig, Value, as_int, as_str, get_param,
    run_client,
};
use num_bigint::BigInt;
use num_traits::ToPrimitive;

fn st(pairs: Vec<(&str, Value)>) -> State {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

fn seq_to_value(seq: &[i64]) -> Value {
    Value::Set(seq.iter().map(|&n| Value::Int(BigInt::from(n))).collect())
}

fn anomalies_to_value(dump: &Dump) -> Value {
    Value::Set(
        dump.anomalies
            .iter()
            .map(|a| {
                Value::Record(
                    vec![("desc".to_string(), Value::Str(a.description.clone()))]
                        .into_iter()
                        .collect(),
                )
            })
            .collect(),
    )
}

fn str_seq_to_value(seq: &[&str]) -> Value {
    Value::Set(seq.iter().map(|&s| Value::Str(s.to_string())).collect())
}

/// Mirrors the TLA+ `State` produced by Model.tla.
struct ModelComputer {
    dump: Dump,
    annotations: Vec<(String, String)>,
}

impl ModelComputer {
    fn new() -> Self {
        ModelComputer {
            dump: Dump {
                system_info: None,
                modules: vec![],
                threads: vec![],
                memory_regions: vec![],
                exception: None,
                anomalies: vec![],
                file_size: 0,
            },
            annotations: vec![],
        }
    }

    fn to_state(&self) -> State {
        let sysinfo: Vec<i64> = self
            .dump
            .system_info
            .as_ref()
            .map(|si| {
                vec![
                    si.os as i64,
                    si.cpu as i64,
                    si.version.0 as i64,
                    si.version.1 as i64,
                    si.version.2 as i64,
                    si.version.3 as i64,
                    si.provenance.stream_type as i64,
                    si.provenance.file_offset as i64,
                    si.provenance.rva as i64,
                ]
            })
            .unwrap_or_default();

        let mod_va: Vec<i64> = self.dump.modules.iter().map(|m| m.base_va as i64).collect();
        let mod_sz: Vec<i64> = self.dump.modules.iter().map(|m| m.size as i64).collect();
        let mod_prov_sid: Vec<i64> = self
            .dump
            .modules
            .iter()
            .map(|m| m.provenance.stream_type as i64)
            .collect();
        let mod_prov_off: Vec<i64> = self
            .dump
            .modules
            .iter()
            .map(|m| m.provenance.file_offset as i64)
            .collect();
        let mod_prov_rva: Vec<i64> = self
            .dump
            .modules
            .iter()
            .map(|m| m.provenance.rva as i64)
            .collect();

        let thr_id: Vec<i64> = self.dump.threads.iter().map(|t| t.id as i64).collect();
        let thr_stack_va: Vec<i64> = self
            .dump
            .threads
            .iter()
            .map(|t| t.stack_va as i64)
            .collect();
        let thr_stack_sz: Vec<i64> = self
            .dump
            .threads
            .iter()
            .map(|t| t.stack_size as i64)
            .collect();
        let thr_prov_sid: Vec<i64> = self
            .dump
            .threads
            .iter()
            .map(|t| t.provenance.stream_type as i64)
            .collect();
        let thr_prov_off: Vec<i64> = self
            .dump
            .threads
            .iter()
            .map(|t| t.provenance.file_offset as i64)
            .collect();
        let thr_prov_rva: Vec<i64> = self
            .dump
            .threads
            .iter()
            .map(|t| t.provenance.rva as i64)
            .collect();

        let mem_va: Vec<i64> = self
            .dump
            .memory_regions
            .iter()
            .map(|mr| mr.va_start as i64)
            .collect();
        let mem_sz: Vec<i64> = self
            .dump
            .memory_regions
            .iter()
            .map(|mr| mr.size as i64)
            .collect();
        let mem_prot: Vec<i64> = self
            .dump
            .memory_regions
            .iter()
            .map(|mr| mr.protection.bits() as i64)
            .collect();
        let mem_state: Vec<i64> = self
            .dump
            .memory_regions
            .iter()
            .map(|mr| mr.state as i64)
            .collect();
        let mem_type: Vec<i64> = self
            .dump
            .memory_regions
            .iter()
            .map(|mr| mr.mem_type as i64)
            .collect();
        let mem_cls: Vec<i64> = self
            .dump
            .memory_regions
            .iter()
            .map(|mr| mr.region_class.map(|rc| rc as i64).unwrap_or(0))
            .collect();
        let mem_prov_sid: Vec<i64> = self
            .dump
            .memory_regions
            .iter()
            .map(|mr| mr.provenance.stream_type as i64)
            .collect();
        let mem_prov_off: Vec<i64> = self
            .dump
            .memory_regions
            .iter()
            .map(|mr| mr.provenance.file_offset as i64)
            .collect();
        let mem_prov_rva: Vec<i64> = self
            .dump
            .memory_regions
            .iter()
            .map(|mr| mr.provenance.rva as i64)
            .collect();

        let exc_info: Vec<i64> = self
            .dump
            .exception
            .as_ref()
            .map(|exc| {
                vec![
                    exc.code as i64,
                    exc.address as i64,
                    exc.thread_id as i64,
                    exc.flags as i64,
                    exc.provenance.stream_type as i64,
                    exc.provenance.file_offset as i64,
                    exc.provenance.rva as i64,
                ]
            })
            .unwrap_or_default();

        let ann_keys: Vec<&str> = self.annotations.iter().map(|(k, _)| k.as_str()).collect();
        let ann_vals: Vec<&str> = self.annotations.iter().map(|(_, v)| v.as_str()).collect();

        st(vec![
            ("sysinfo", seq_to_value(&sysinfo)),
            ("mod_va", seq_to_value(&mod_va)),
            ("mod_sz", seq_to_value(&mod_sz)),
            ("mod_prov_sid", seq_to_value(&mod_prov_sid)),
            ("mod_prov_off", seq_to_value(&mod_prov_off)),
            ("mod_prov_rva", seq_to_value(&mod_prov_rva)),
            ("thr_id", seq_to_value(&thr_id)),
            ("thr_stack_va", seq_to_value(&thr_stack_va)),
            ("thr_stack_sz", seq_to_value(&thr_stack_sz)),
            ("thr_prov_sid", seq_to_value(&thr_prov_sid)),
            ("thr_prov_off", seq_to_value(&thr_prov_off)),
            ("thr_prov_rva", seq_to_value(&thr_prov_rva)),
            ("mem_va", seq_to_value(&mem_va)),
            ("mem_sz", seq_to_value(&mem_sz)),
            ("mem_prot", seq_to_value(&mem_prot)),
            ("mem_state", seq_to_value(&mem_state)),
            ("mem_type", seq_to_value(&mem_type)),
            ("mem_cls", seq_to_value(&mem_cls)),
            ("mem_prov_sid", seq_to_value(&mem_prov_sid)),
            ("mem_prov_off", seq_to_value(&mem_prov_off)),
            ("mem_prov_rva", seq_to_value(&mem_prov_rva)),
            ("exc_info", seq_to_value(&exc_info)),
            ("anomalies", anomalies_to_value(&self.dump)),
            ("ann_key", str_seq_to_value(&ann_keys)),
            ("ann_val", str_seq_to_value(&ann_vals)),
        ])
    }

    fn get_int_param(params: &State, key: &str) -> i64 {
        get_param(params, "parameters")
            .and_then(|p| p.get(key))
            .and_then(as_int)
            .and_then(|n| n.to_i64())
            .unwrap_or(0)
    }

    fn get_str_param(params: &State, key: &str) -> String {
        get_param(params, "parameters")
            .and_then(|p| p.get(key))
            .and_then(as_str)
            .map(|s| s.to_string())
            .unwrap_or_default()
    }
}

fn os_from_i64(v: i64) -> OsPlatform {
    match v {
        1 => OsPlatform::Linux,
        2 => OsPlatform::MacOs,
        _ => OsPlatform::Windows,
    }
}

fn mem_state_from_i64(v: i64) -> MemState {
    match v {
        1 => MemState::Reserve,
        2 => MemState::Free,
        _ => MemState::Commit,
    }
}

fn mem_type_from_i64(v: i64) -> MemType {
    match v {
        1 => MemType::Mapped,
        2 => MemType::Image,
        _ => MemType::Private,
    }
}

fn region_class_from_i64(v: i64) -> RegionClass {
    match v {
        1 => RegionClass::Stack,
        2 => RegionClass::Mapped,
        3 => RegionClass::Private,
        4 => RegionClass::Other,
        _ => RegionClass::Image,
    }
}

impl StateComputer for ModelComputer {
    fn compute(&mut self, action: &str, params: &State, _prev: &State) -> State {
        match action {
            "Init" => {
                *self = ModelComputer::new();
            }
            "SetSysInfo" => {
                let os = Self::get_int_param(params, "os");
                let maj = Self::get_int_param(params, "maj");
                let min = Self::get_int_param(params, "min");
                let bld = Self::get_int_param(params, "bld");
                let rev = Self::get_int_param(params, "rev");
                let sid = Self::get_int_param(params, "sid");
                let off = Self::get_int_param(params, "off");
                let rva = Self::get_int_param(params, "rva");
                self.dump.set_sys_info(
                    os_from_i64(os),
                    CpuArch::X64,
                    (maj as u32, min as u32, bld as u32, rev as u32),
                    Provenance {
                        stream_type: sid as u32,
                        file_offset: off as u64,
                        rva: rva as u32,
                    },
                );
            }
            "AddModule" => {
                let va = Self::get_int_param(params, "va");
                let sz = Self::get_int_param(params, "sz");
                let sid = Self::get_int_param(params, "sid");
                let off = Self::get_int_param(params, "off");
                let rva = Self::get_int_param(params, "rva");
                self.dump.add_module(
                    va as u64,
                    sz as u64,
                    Provenance {
                        stream_type: sid as u32,
                        file_offset: off as u64,
                        rva: rva as u32,
                    },
                );
            }
            "AddThread" => {
                let id = Self::get_int_param(params, "id");
                let sva = Self::get_int_param(params, "sva");
                let ssz = Self::get_int_param(params, "ssz");
                let sid = Self::get_int_param(params, "sid");
                let off = Self::get_int_param(params, "off");
                let rva = Self::get_int_param(params, "rva");
                self.dump.add_thread(
                    id as u32,
                    sva as u64,
                    ssz as u64,
                    Provenance {
                        stream_type: sid as u32,
                        file_offset: off as u64,
                        rva: rva as u32,
                    },
                );
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
                self.dump.add_region(
                    va as u64,
                    sz as u64,
                    Protection::new(prot as u32),
                    mem_state_from_i64(state),
                    mem_type_from_i64(typ),
                    region_class_from_i64(cls),
                    Provenance {
                        stream_type: sid as u32,
                        file_offset: off as u64,
                        rva: rva as u32,
                    },
                );
            }
            "SetException" => {
                let code = Self::get_int_param(params, "code");
                let addr = Self::get_int_param(params, "addr");
                let tid = Self::get_int_param(params, "tid");
                let flg = Self::get_int_param(params, "flg");
                let sid = Self::get_int_param(params, "sid");
                let off = Self::get_int_param(params, "off");
                let rva = Self::get_int_param(params, "rva");
                self.dump.set_exception(
                    code as u32,
                    addr as u64,
                    tid as u32,
                    flg as u32,
                    Provenance {
                        stream_type: sid as u32,
                        file_offset: off as u64,
                        rva: rva as u32,
                    },
                );
            }
            "AddAnomaly" => {
                if let Some(desc) = get_param(params, "parameters")
                    .and_then(|p| p.get("desc"))
                    .and_then(as_str)
                {
                    self.dump.add_anomaly(desc);
                }
            }
            "AddAnnotation" => {
                let key = Self::get_str_param(params, "key");
                let val = Self::get_str_param(params, "val");
                if !key.is_empty() && !val.is_empty() {
                    self.annotations.push((key, val));
                }
            }
            _ => {}
        }
        self.to_state()
    }
}

fn apalache_config() -> ApalacheConfig {
    let spec_path = std::env::var("MBT_SPEC").unwrap_or_else(|_| {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../specs/ModelMBT.tla").to_string()
    });
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
    TraceGenerationConfig {
        num_traces: 100,
        view: Some("View".into()),
    }
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
    run_client(
        &bin,
        apalache_config(),
        trace_config(),
        ModelComputer::new(),
    )
    .expect("MBT model test failed");
}

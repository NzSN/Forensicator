//! Model-Based Testing for Forensicator AddressSpace using MirrorRust.
//! Validates the Rust AddressSpace (space.rs) against the TLA+ AddressSpace.tla spec
//! via trace replay.
//!
//! Requires ModelMirros binary. Set MIRROR_BIN env var to run.
//!   e.g. MIRROR_BIN=D:\Tools\ModelMirrors.exe APALACHE_MC=...\wrapper.bat cargo test --test mbt_address_space -- --nocapture

use forensicator_core::model::{MemState, RegionClass};
use forensicator_core::space::{AddressRegion, AddressSpace};
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

fn str_to_region_class(s: &str) -> RegionClass {
    match s {
        "Stack" => RegionClass::Stack,
        "Mapped" => RegionClass::Mapped,
        "Private" => RegionClass::Private,
        "Other" => RegionClass::Other,
        _ => RegionClass::Image,
    }
}

/// Mirrors AddressSpace.tla state with an internal `AddressSpace` and a
/// separate anomaly list (the spec tracks anomalies independently).
struct SpaceComputer {
    space: AddressSpace,
    anomalies: Vec<String>,
}

const MAX_REGIONS: usize = 2;
const MAX_ANOMALIES: usize = 2;

impl SpaceComputer {
    fn new() -> Self {
        SpaceComputer {
            space: AddressSpace::new(MAX_REGIONS),
            anomalies: vec![],
        }
    }

    fn to_state(&self) -> State {
        let reg_va: Vec<i64> = self
            .space
            .regions()
            .iter()
            .map(|r| r.va_start as i64)
            .collect();
        let reg_sz: Vec<i64> = self.space.regions().iter().map(|r| r.size as i64).collect();
        let reg_cl: Vec<&str> = self
            .space
            .regions()
            .iter()
            .map(|r| region_class_to_str(r.classification))
            .collect();

        st(vec![
            ("reg_va", seq_to_value(&reg_va)),
            ("reg_sz", seq_to_value(&reg_sz)),
            ("reg_cl", str_seq_to_value(&reg_cl)),
            ("anomalies", anomalies_to_value(&self.anomalies)),
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

impl StateComputer for SpaceComputer {
    fn compute(&mut self, action: &str, params: &State, _prev: &State) -> State {
        match action {
            "Init" => {
                *self = SpaceComputer::new();
            }
            "AddRegion" => {
                let va = Self::get_int_param(params, "va") as u64;
                let sz = Self::get_int_param(params, "sz") as u64;
                let cls = str_to_region_class(&Self::get_str_param(params, "cls"));
                let region = AddressRegion {
                    va_start: va,
                    size: sz,
                    data: vec![0u8; sz as usize],
                    protection: 3,
                    state: MemState::Commit,
                    classification: cls,
                };
                match self.space.add_region(region) {
                    Ok(()) => {}
                    Err(a)
                        if a.description == "overlap" && self.anomalies.len() < MAX_ANOMALIES =>
                    {
                        self.anomalies.push(a.description);
                    }
                    _ => {}
                }
            }
            "Read" => {
                let va = Self::get_int_param(params, "va") as u64;
                let len = Self::get_int_param(params, "len") as usize;
                if self.space.read(va, len).is_none() && self.anomalies.len() < MAX_ANOMALIES {
                    self.anomalies.push("read_beyond_region".to_string());
                }
            }
            _ => {}
        }
        self.to_state()
    }
}

fn apalache_config() -> ApalacheConfig {
    let spec_path = std::env::var("MBT_SPEC").unwrap_or_else(|_| {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../specs/AddressSpaceMBT.tla").to_string()
    });
    ApalacheConfig {
        spec_path,
        invariant: "TypeInvariant".into(),
        length_bound: 4,
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
fn mbt_address_space() {
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
        SpaceComputer::new(),
    )
    .expect("MBT address space test failed");
}

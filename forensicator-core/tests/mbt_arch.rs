//! Model-Based Testing for Forensicator Arch using MirrorRust.
//! Validates the Rust RegisterSet (arch.rs) against the TLA+ Arch.tla spec via trace replay.
//!
//! Requires ModelMirros binary. Set MIRROR_BIN env var to run.
//!   e.g. MIRROR_BIN=D:\Tools\ModelMirrors.exe APALACHE_MC=...\wrapper.bat cargo test --test mbt_arch -- --nocapture

use forensicator_core::arch::RegisterSet;
use mirrorrust::{
    run_client, ApalacheConfig, State, StateComputer, TraceGenerationConfig, Value,
};
use num_bigint::BigInt;

fn st(pairs: Vec<(&str, Value)>) -> State {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

fn seq_to_value(seq: &[i64]) -> Value {
    Value::Set(seq.iter().map(|&n| Value::Int(BigInt::from(n))).collect())
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

enum DecodeState {
    NotDecoded,
    Success(RegisterSet),
    Truncated(RegisterSet),
}

struct ArchComputer {
    decode: DecodeState,
    anomalies: Vec<String>,
}

const MAX_ANOMALIES: usize = 4;

impl ArchComputer {
    fn new() -> Self {
        ArchComputer {
            decode: DecodeState::NotDecoded,
            anomalies: vec![],
        }
    }

    fn to_state(&self) -> State {
        let regs: Vec<i64> = match &self.decode {
            DecodeState::NotDecoded => vec![],
            DecodeState::Success(rs) => {
                (0..32).map(|i| rs.get(i) as i64).collect()
            }
            DecodeState::Truncated(rs) => {
                (0..16).map(|i| rs.get(i) as i64).collect()
            }
        };

        st(vec![
            ("regs", seq_to_value(&regs)),
            ("anomalies", anomalies_to_value(&self.anomalies)),
        ])
    }
}

impl StateComputer for ArchComputer {
    fn compute(&mut self, action: &str, _params: &State, _prev: &State) -> State {
        match action {
            "Init" => {
                *self = ArchComputer::new();
            }
            "DecodeContextSuccess" => {
                if matches!(self.decode, DecodeState::NotDecoded) {
                    let data = [0u8; RegisterSet::MIN_CONTEXT_SIZE];
                    if let Ok(regs) = RegisterSet::decode_context(&data) {
                        self.decode = DecodeState::Success(regs);
                    }
                }
            }
            "DecodeContextTruncated" => {
                if matches!(self.decode, DecodeState::NotDecoded)
                    && self.anomalies.len() < MAX_ANOMALIES
                {
                    let data = [0u8; 16];
                    if let Err(_) = RegisterSet::decode_context(&data) {
                        self.decode = DecodeState::Truncated(RegisterSet::new());
                        self.anomalies.push("truncated CONTEXT".to_string());
                    }
                }
            }
            _ => {}
        }
        self.to_state()
    }
}

fn apalache_config() -> ApalacheConfig {
    let spec_path = std::env::var("MBT_SPEC")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../specs/ArchMBT.tla").to_string());
    ApalacheConfig {
        spec_path,
        invariant: "ArchInvariant".into(),
        length_bound: 2,
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
fn mbt_arch() {
    let bin = match std::env::var("MIRROR_BIN") {
        Ok(b) if !b.is_empty() => b,
        _ => {
            eprintln!("MIRROR_BIN not set; skipping MBT test");
            return;
        }
    };
    run_client(&bin, apalache_config(), trace_config(), ArchComputer::new())
        .expect("MBT arch test failed");
}

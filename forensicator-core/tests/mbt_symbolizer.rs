//! Model-Based Testing for Forensicator Symbolizer using MirrorRust.
//! Validates symbolizer.rs against the TLA+ Symbolizer.tla spec via trace replay.
//!
//! Requires MirrorRust binary. Set MIRROR_BIN env var to run.
//! Requires Apalache. Set APALACHE_MC env var.
//!   e.g. MIRROR_BIN=D:\Tools\ModelMirrors.exe APALACHE_MC=...\wrapper.bat cargo test --test mbt_symbolizer -- --nocapture

use std::collections::BTreeMap;

use forensicator_core::symbolizer::{ModuleSymbols, SymbolEntry, Symbolizer};
use mirrorrust::{
    ApalacheConfig, State, StateComputer, TraceGenerationConfig, Value, as_int, as_str, get_param,
    run_client,
};
use num_bigint::BigInt;
use num_traits::ToPrimitive;

fn st(pairs: Vec<(&str, Value)>) -> State {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
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

fn symbol_entry(va: u64, k: usize) -> SymbolEntry {
    SymbolEntry {
        va,
        function_name: format!("func{k}"),
        source_file: Some(format!("src{k}.cpp")),
        source_line: Some((k * 10) as u32),
    }
}

/// Mirrors the TLA+ state produced by SymbolizerMBT.tla.
/// Exercises real Symbolizer::resolve() for each ResolveAddress action.
struct SymbolizerComputer {
    symbolizer: Symbolizer,
    modules: Vec<(String, u64, u64)>,
    tables: Vec<Vec<SymbolEntry>>,
    anomalies: Vec<String>,
}

const MAX_SYMBOLS: usize = 4;
const MAX_ANOMALIES: usize = 4;

impl SymbolizerComputer {
    fn new() -> Self {
        SymbolizerComputer {
            symbolizer: Symbolizer::from_modules(vec![]),
            modules: vec![],
            tables: vec![],
            anomalies: vec![],
        }
    }

    fn to_state(&self) -> State {
        let mods: Vec<Value> = self
            .modules
            .iter()
            .map(|(name, base, sz)| {
                Value::Record(
                    vec![
                        ("name".to_string(), Value::Str(name.clone())),
                        ("base_va".to_string(), Value::Int(BigInt::from(*base as i64))),
                        ("size".to_string(), Value::Int(BigInt::from(*sz as i64))),
                    ]
                    .into_iter()
                    .collect::<BTreeMap<_, _>>(),
                )
            })
            .collect();

        st(vec![
            ("sym_modules", Value::Set(mods)),
            ("sym_anomalies", anomalies_to_value(&self.anomalies)),
        ])
    }

    fn rebuild_symbolizer(&mut self) {
        let mut ms: Vec<ModuleSymbols> = Vec::new();
        for (i, (name, base, sz)) in self.modules.iter().enumerate() {
            let syms = self.tables.get(i).cloned().unwrap_or_default();
            ms.push(ModuleSymbols::new(name.clone(), *base, *sz, syms));
        }
        self.symbolizer = Symbolizer::from_modules(ms);
    }
}

impl StateComputer for SymbolizerComputer {
    fn compute(&mut self, action: &str, params: &State, _prev: &State) -> State {
        let get_str = |key: &str| -> String {
            get_param(params, "parameters")
                .and_then(|p| p.get(key))
                .and_then(as_str)
                .map(|s| s.to_string())
                .unwrap_or_default()
        };
        let get_int = |key: &str| -> u64 {
            get_param(params, "parameters")
                .and_then(|p| p.get(key))
                .and_then(as_int)
                .and_then(|n| n.to_u64())
                .unwrap_or(0)
        };

        match action {
            "Init" => {
                *self = SymbolizerComputer::new();
            }
            "LoadPdb" => {
                let name = get_str("name");
                let base_va = get_int("base_va");
                let size = get_int("size");

                if !name.is_empty() && !self.modules.iter().any(|(n, _, _)| n == &name) {
                    let count = (self.modules.len() % MAX_SYMBOLS) + 1;
                    let mut entries: Vec<SymbolEntry> = (1..=count)
                        .map(|k| symbol_entry(base_va + (k * 256) as u64, k))
                        .collect();
                    entries.sort_by_key(|e| e.va);
                    self.tables.push(entries);
                    self.modules.push((name, base_va, size));
                    self.rebuild_symbolizer();
                }
            }
            "LoadPdbEmpty" => {
                let name = get_str("name");
                let base_va = get_int("base_va");
                let size = get_int("size");

                if !name.is_empty() && !self.modules.iter().any(|(n, _, _)| n == &name) {
                    self.tables.push(vec![]);
                    self.modules.push((name.clone(), base_va, size));
                    self.rebuild_symbolizer();
                    if self.anomalies.len() < MAX_ANOMALIES {
                        self.anomalies.push("no_publics".to_string());
                    }
                }
            }
            "ResolveAddress" => {
                let va = get_int("va");
                let found = self.symbolizer.resolve(va).is_some();
                if !found && self.anomalies.len() < MAX_ANOMALIES {
                    self.anomalies.push("va_not_found".to_string());
                }
            }
            _ => {}
        }
        self.to_state()
    }
}

fn apalache_config() -> ApalacheConfig {
    let spec_path = std::env::var("MBT_SPEC").unwrap_or_else(|_| {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../specs/SymbolizerMBT.tla").to_string()
    });
    ApalacheConfig {
        spec_path,
        invariant: "SymbolizerInvariant".into(),
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
fn mbt_symbolizer() {
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
        SymbolizerComputer::new(),
    )
    .expect("MBT symbolizer test failed");
}

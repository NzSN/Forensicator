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

fn str_set_to_value(set: &[String]) -> Value {
    Value::Set(set.iter().map(|s| Value::Str(s.clone())).collect())
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

fn entries_to_value(entries: &[SymbolEntry]) -> Value {
    Value::Set(
        entries
            .iter()
            .map(|e| {
                Value::Record(
                    vec![
                        ("va".to_string(), Value::Int(BigInt::from(e.va as i64))),
                        ("name".to_string(), Value::Str(e.function_name.clone())),
                        (
                            "file".to_string(),
                            Value::Str(e.source_file.clone().unwrap_or_default()),
                        ),
                        (
                            "line".to_string(),
                            Value::Int(BigInt::from(e.source_line.unwrap_or(0) as i64)),
                        ),
                    ]
                    .into_iter()
                    .collect::<BTreeMap<_, _>>(),
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

/// Mirrors the TLA+ state and exercises the real Symbolizer::resolve().
struct SymbolizerComputer {
    symbolizer: Symbolizer,
    module_names: Vec<String>,        // ordered list (mirrors sym_loaded)
    entries: Vec<Vec<SymbolEntry>>,   // per-module symbol entries (mirrors sym_entries)
    anomalies: Vec<String>,
}

const MAX_SYMBOLS: usize = 4;
const MAX_ANOMALIES: usize = 4;

impl SymbolizerComputer {
    fn new() -> Self {
        SymbolizerComputer {
            symbolizer: Symbolizer::from_modules(vec![]),
            module_names: vec![],
            entries: vec![],
            anomalies: vec![],
        }
    }

    fn to_state(&self) -> State {
        let mut entries_map: BTreeMap<String, Value> = BTreeMap::new();
        for (i, name) in self.module_names.iter().enumerate() {
            let ents = self.entries.get(i).map(|e| e.as_slice()).unwrap_or(&[]);
            entries_map.insert(name.clone(), entries_to_value(ents));
        }

        st(vec![
            ("sym_loaded", str_set_to_value(&self.module_names)),
            ("sym_entries", Value::Record(entries_map)),
            ("sym_anomalies", anomalies_to_value(&self.anomalies)),
        ])
    }

    fn rebuild_symbolizer(&mut self) {
        let mut modules: Vec<ModuleSymbols> = Vec::new();
        for (i, name) in self.module_names.iter().enumerate() {
            let syms = self.entries.get(i).cloned().unwrap_or_default();
            let size = syms.last().map(|s| s.va + 256).unwrap_or(4096);
            modules.push(ModuleSymbols::new(name.clone(), 0, size, syms));
        }
        self.symbolizer = Symbolizer::from_modules(modules);
    }
}

impl StateComputer for SymbolizerComputer {
    fn compute(&mut self, action: &str, params: &State, _prev: &State) -> State {
        match action {
            "Init" => {
                *self = SymbolizerComputer::new();
            }
            "LoadPdb" => {
                let name = get_param(params, "parameters")
                    .and_then(|p| p.get("name"))
                    .and_then(as_str)
                    .map(|s| s.to_string())
                    .unwrap_or_default();

                if !name.is_empty() && !self.module_names.contains(&name) {
                    let count = (self.module_names.len() % MAX_SYMBOLS) + 1;
                    let mut entries: Vec<SymbolEntry> =
                        (1..=count).map(|k| symbol_entry((k * 256) as u64, k)).collect();
                    entries.sort_by_key(|e| e.va);
                    self.entries.push(entries);
                    self.module_names.push(name);
                    self.rebuild_symbolizer();
                }
            }
            "LoadPdbEmpty" => {
                let name = get_param(params, "parameters")
                    .and_then(|p| p.get("name"))
                    .and_then(as_str)
                    .map(|s| s.to_string())
                    .unwrap_or_default();

                if !name.is_empty() && !self.module_names.contains(&name) {
                    self.entries.push(vec![]);
                    self.module_names.push(name.clone());
                    self.rebuild_symbolizer();
                    if self.anomalies.len() < MAX_ANOMALIES {
                        self.anomalies.push("no_publics".to_string());
                    }
                }
            }
            "ResolveAddress" => {
                let va = get_param(params, "parameters")
                    .and_then(|p| p.get("va"))
                    .and_then(as_int)
                    .and_then(|n| n.to_u64())
                    .unwrap_or(0);

                // Exercise real Symbolizer::resolve()
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

//! Model-Based Testing for the Timeline → Model snapshot link using
//! MirrorRust. Validates model::trace::Trace::snapshot against the TLA+
//! Snapshot.tla spec (specs/Snapshot.tla: Trace::snapshot's formal
//! counterpart — every cursor position materializes into a valid Model)
//! via trace replay through specs/SnapshotMBT.tla.
//!
//! Requires MirrorRust binary. Set MIRROR_BIN env var to run.
//! Requires Apalache. Set APALACHE_MC env var. Use wrapper with --features=no-rows.
//!   e.g. MIRROR_BIN=D:\Tools\ModelMirrors.exe APALACHE_MC=...\wrapper.bat cargo test --test mbt_snapshot -- --nocapture
//!
//! The mirror compares the computer's reported state against the spec's
//! raw variables exactly (the --view operator only deduplicates traces),
//! so SnapshotMBT carries the ModelAt(cursor) projection in a `snapshot`
//! variable and this computer emits the raw trace variables plus a
//! matching "snapshot" record. InitialState delivers the spec's initial
//! variables (never `parameters`), so Init reads init_mem from the state.
//!
//! Spec↔Rust divergences reconciled here (design doc C.3):
//!   * module VA = load event index; unload = LIFO pop — the computer
//!     synthesizes TraceEvent.address = event index and tracks open_loads,
//!     so LIFO pop and snapshot's retain-by-VA coincide by construction.
//!   * exception payload abstracted to 0 — the computer zeroes code/
//!     address/thread_id; the projection emits <<0,0,0,0,1,0,0>>.
//!   * ann_val = "pos" — Rust formats 0x{t:X}; the projection normalizes
//!     to "pos" (the "ttfx_position" key is compared literally).
//!   * single-cell write (a,v) — MBT drives 1-byte WriteRecords only.
//!   * end = -1 open interval — projection maps None ↔ -1.
//!   * threads/calls carry no OS id — the computer assigns id = table
//!     index (1-based, matching the spec's thr ∈ 1..Len(threads)).
//!   * provenance sid = 1 — the computer uses 1 (the spec's abstraction);
//!     real decode keeps TTFX_STREAM_TYPE.

use forensicator_core::error::Provenance;
use forensicator_core::model::trace::{
    CallSpan, Interval, Position, Trace, TraceEvent, TraceEventKind, WriteRecord,
};
use forensicator_core::model::{
    Dump, MemState, MemType, MemoryRegionInfo, Protection, RegionClass,
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
    Value::Seq(seq.iter().map(|&n| Value::Int(BigInt::from(n))).collect())
}

fn str_seq_to_value(seq: &[&str]) -> Value {
    Value::Seq(seq.iter().map(|&s| Value::Str(s.to_string())).collect())
}

/// The spec's provenance abstraction: every snapshot fact carries sid = 1.
fn prov1() -> Provenance {
    Provenance {
        stream_type: 1,
        file_offset: 0,
        rva: 0,
    }
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

/// init_mem arrives as an ITF function. New-protocol servers (VMap) deliver
/// Value::Map of (Str key, Int value) pairs; canonical (pre-VSeq) servers
/// re-encode it as a plain record {"1": v, "2": v}. Handle both shapes.
fn parse_init_mem(v: &Value) -> Vec<u8> {
    let mut cells: Vec<(i64, u8)> = Vec::new();
    match v {
        Value::Map(pairs) => {
            for (k, v) in pairs {
                let key = match k {
                    Value::Str(s) => s.parse::<i64>().ok(),
                    Value::Int(n) => n.to_i64(),
                    _ => None,
                };
                if let (Some(i), Some(b)) = (key, n_to_u8(v)) {
                    cells.push((i, b));
                }
            }
        }
        Value::Record(rec) => {
            for (k, v) in rec {
                if let (Ok(i), Some(b)) = (k.parse::<i64>(), n_to_u8(v)) {
                    cells.push((i, b));
                }
            }
        }
        _ => {}
    }
    cells.sort_by_key(|(k, _)| *k);
    cells.into_iter().map(|(_, v)| v).collect()
}

fn n_to_u8(v: &Value) -> Option<u8> {
    as_int(v).and_then(|n| n.to_u64()).map(|b| b as u8)
}

/// init_mem as an ITF function ({"#map": [[k,v]]}): string keys match the
/// server's VMap key canonicalization (valueToText) for Int domains.
fn init_mem_to_value(data: &[u8]) -> Value {
    Value::Map(
        data.iter()
            .enumerate()
            .map(|(i, &b)| {
                (
                    Value::Str((i + 1).to_string()),
                    Value::Int(BigInt::from(b as i64)),
                )
            })
            .collect(),
    )
}

/// Mirrors the TLA+ state produced by SnapshotMBT.tla: a model::trace::Trace
/// driven by Timeline actions plus a cursor, re-materialized per step.
struct SnapshotComputer {
    trace: Trace,
    cursor: Position,
    open_loads: Vec<u64>, // load event indices (1-based), LIFO
}

impl SnapshotComputer {
    fn new() -> Self {
        SnapshotComputer {
            trace: Trace {
                init_mem: vec![],
                writes: vec![],
                events: vec![],
                threads: vec![],
                calls: vec![],
                frontier: 0,
                anomalies: vec![],
            },
            cursor: 0,
            open_loads: vec![],
        }
    }

    /// The one canonical memory region: va 1..=MaxAddr, R/W, Committed,
    /// Private (Snapshot.tla SnapMem*).
    fn canonical_region(data: Vec<u8>) -> MemoryRegionInfo {
        MemoryRegionInfo {
            va_start: 1,
            size: data.len() as u64,
            data,
            protection: Protection::new(Protection::READ | Protection::WRITE),
            state: MemState::Commit,
            mem_type: MemType::Private,
            provenance: prov1(),
            region_class: Some(RegionClass::Private),
        }
    }

    fn cell_count(&self) -> u64 {
        self.trace.init_mem.first().map(|r| r.size).unwrap_or(0)
    }

    /// The `snapshot` variable's fields: ModelAt(cursor) plus cell_values.
    /// Mirrors mbt_model.rs's Dump projection; ann_val is normalized to
    /// the spec's constant "pos".
    fn snapshot_fields(&self, dump: &Dump) -> Vec<(&'static str, Value)> {
        let sysinfo: Vec<i64> = dump
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

        let mod_va: Vec<i64> = dump.modules.iter().map(|m| m.base_va as i64).collect();
        let mod_sz: Vec<i64> = dump.modules.iter().map(|m| m.size as i64).collect();
        let mod_prov_sid: Vec<i64> = dump
            .modules
            .iter()
            .map(|m| m.provenance.stream_type as i64)
            .collect();
        let mod_prov_off: Vec<i64> = dump
            .modules
            .iter()
            .map(|m| m.provenance.file_offset as i64)
            .collect();
        let mod_prov_rva: Vec<i64> = dump
            .modules
            .iter()
            .map(|m| m.provenance.rva as i64)
            .collect();

        let thr_id: Vec<i64> = dump.threads.iter().map(|t| t.id as i64).collect();
        let thr_stack_va: Vec<i64> = dump.threads.iter().map(|t| t.stack_va as i64).collect();
        let thr_stack_sz: Vec<i64> = dump.threads.iter().map(|t| t.stack_size as i64).collect();
        let thr_prov_sid: Vec<i64> = dump
            .threads
            .iter()
            .map(|t| t.provenance.stream_type as i64)
            .collect();
        let thr_prov_off: Vec<i64> = dump
            .threads
            .iter()
            .map(|t| t.provenance.file_offset as i64)
            .collect();
        let thr_prov_rva: Vec<i64> = dump
            .threads
            .iter()
            .map(|t| t.provenance.rva as i64)
            .collect();

        let mem_va: Vec<i64> = dump
            .memory_regions
            .iter()
            .map(|mr| mr.va_start as i64)
            .collect();
        let mem_sz: Vec<i64> = dump
            .memory_regions
            .iter()
            .map(|mr| mr.size as i64)
            .collect();
        let mem_prot: Vec<i64> = dump
            .memory_regions
            .iter()
            .map(|mr| mr.protection.bits() as i64)
            .collect();
        let mem_state: Vec<i64> = dump
            .memory_regions
            .iter()
            .map(|mr| mr.state as i64)
            .collect();
        let mem_type: Vec<i64> = dump
            .memory_regions
            .iter()
            .map(|mr| mr.mem_type as i64)
            .collect();
        let mem_cls: Vec<i64> = dump
            .memory_regions
            .iter()
            .map(|mr| mr.region_class.map(|rc| rc as i64).unwrap_or(0))
            .collect();
        let mem_prov_sid: Vec<i64> = dump
            .memory_regions
            .iter()
            .map(|mr| mr.provenance.stream_type as i64)
            .collect();
        let mem_prov_off: Vec<i64> = dump
            .memory_regions
            .iter()
            .map(|mr| mr.provenance.file_offset as i64)
            .collect();
        let mem_prov_rva: Vec<i64> = dump
            .memory_regions
            .iter()
            .map(|mr| mr.provenance.rva as i64)
            .collect();

        let exc_info: Vec<i64> = dump
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

        let ann_keys: Vec<&str> = dump.annotations.iter().map(|(k, _)| k.as_str()).collect();
        let ann_vals: Vec<&str> = dump.annotations.iter().map(|_| "pos").collect();

        // SnapshotConsistent echo: total because the canonical region
        // covers every cell 1..=MaxAddr.
        let cell_values: Vec<i64> = (1..=self.cell_count())
            .map(|c| {
                self.trace
                    .value_at(c, self.cursor)
                    .expect("canonical region covers every cell") as i64
            })
            .collect();

        vec![
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
            (
                "anomalies",
                Value::Seq(
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
                ),
            ),
            ("ann_key", str_seq_to_value(&ann_keys)),
            ("ann_val", str_seq_to_value(&ann_vals)),
            ("cell_values", seq_to_value(&cell_values)),
        ]
    }

    fn to_state(&self) -> State {
        let init_mem_data: Vec<u8> = self
            .trace
            .init_mem
            .first()
            .map(|r| r.data.clone())
            .unwrap_or_default();

        let wr_pos: Vec<i64> = self.trace.writes.iter().map(|w| w.pos as i64).collect();
        let wr_addr: Vec<i64> = self.trace.writes.iter().map(|w| w.va as i64).collect();
        let wr_val: Vec<i64> = self
            .trace
            .writes
            .iter()
            .map(|w| w.data.first().copied().unwrap_or(0) as i64)
            .collect();

        let ev_pos: Vec<i64> = self.trace.events.iter().map(|e| e.pos as i64).collect();
        let ev_kind: Vec<&str> = self
            .trace
            .events
            .iter()
            .map(|e| match e.kind {
                TraceEventKind::Exception => "EXCEPTION",
                TraceEventKind::ModuleLoad => "MODULE_LOAD",
                TraceEventKind::ModuleUnload => "MODULE_UNLOAD",
            })
            .collect();

        let interval_end = |iv: &Interval| iv.end.map(|e| e as i64).unwrap_or(-1);
        let threads = Value::Seq(
            self.trace
                .threads
                .iter()
                .map(|(_, iv)| {
                    Value::Record(
                        vec![
                            (
                                "start".to_string(),
                                Value::Int(BigInt::from(iv.start as i64)),
                            ),
                            (
                                "end".to_string(),
                                Value::Int(BigInt::from(interval_end(iv))),
                            ),
                        ]
                        .into_iter()
                        .collect(),
                    )
                })
                .collect(),
        );
        let calls = Value::Seq(
            self.trace
                .calls
                .iter()
                .map(|c| {
                    Value::Record(
                        vec![
                            (
                                "start".to_string(),
                                Value::Int(BigInt::from(c.interval.start as i64)),
                            ),
                            (
                                "end".to_string(),
                                Value::Int(BigInt::from(interval_end(&c.interval))),
                            ),
                            (
                                "thr".to_string(),
                                Value::Int(BigInt::from(c.thread_id as i64)),
                            ),
                        ]
                        .into_iter()
                        .collect(),
                    )
                })
                .collect(),
        );

        let snap = self
            .trace
            .snapshot(self.cursor)
            .expect("cursor is bounded by frontier");

        st(vec![
            ("init_mem", init_mem_to_value(&init_mem_data)),
            ("wr_pos", seq_to_value(&wr_pos)),
            ("wr_addr", seq_to_value(&wr_addr)),
            ("wr_val", seq_to_value(&wr_val)),
            ("ev_pos", seq_to_value(&ev_pos)),
            ("ev_kind", str_seq_to_value(&ev_kind)),
            (
                "frontier",
                Value::Int(BigInt::from(self.trace.frontier as i64)),
            ),
            ("cursor", Value::Int(BigInt::from(self.cursor as i64))),
            ("threads", threads),
            ("calls", calls),
            (
                "snapshot",
                Value::Record(
                    self.snapshot_fields(&snap.dump)
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v))
                        .collect(),
                ),
            ),
        ])
    }
}

impl StateComputer for SnapshotComputer {
    fn compute(&mut self, action: &str, params: &State, _prev: &State) -> State {
        match action {
            "Init" => {
                let data = params
                    .get("init_mem")
                    .map(parse_init_mem)
                    .unwrap_or_default();
                *self = SnapshotComputer {
                    trace: Trace {
                        init_mem: vec![Self::canonical_region(data)],
                        writes: vec![],
                        events: vec![],
                        threads: vec![],
                        calls: vec![],
                        frontier: 0,
                        anomalies: vec![],
                    },
                    cursor: 0,
                    open_loads: vec![],
                };
            }
            "RecordStep" => {
                self.trace.frontier += 1;
                let a = get_int_param(params, "a");
                let v = get_int_param(params, "v");
                let k = get_str_param(params, "k");
                if a > 0 {
                    self.trace.writes.push(WriteRecord {
                        pos: self.trace.frontier,
                        va: a as u64,
                        data: vec![v as u8],
                        provenance: prov1(),
                    });
                }
                if k != "NONE" {
                    let kind = match k.as_str() {
                        "EXCEPTION" => TraceEventKind::Exception,
                        "MODULE_LOAD" => TraceEventKind::ModuleLoad,
                        "MODULE_UNLOAD" => TraceEventKind::ModuleUnload,
                        other => panic!("unknown event kind {other}"),
                    };
                    // The event's 1-based log index is the spec's module VA.
                    let index = self.trace.events.len() as u64 + 1;
                    let (address, name, size) = match kind {
                        TraceEventKind::ModuleLoad => {
                            self.open_loads.push(index);
                            (index, format!("m{index}"), 1)
                        }
                        TraceEventKind::ModuleUnload => {
                            // LIFO pop of the most recent open load; 0 matches
                            // nothing when the stack is empty (spec's no-op).
                            (self.open_loads.pop().unwrap_or(0), String::new(), 0)
                        }
                        TraceEventKind::Exception => (0, String::new(), 0),
                    };
                    self.trace.events.push(TraceEvent {
                        pos: self.trace.frontier,
                        kind,
                        code: 0,
                        address,
                        thread_id: 0,
                        name,
                        size,
                        provenance: prov1(),
                    });
                }
            }
            "StartThread" => {
                let id = self.trace.threads.len() as u32 + 1;
                self.trace.threads.push((
                    id,
                    Interval {
                        start: self.trace.frontier,
                        end: None,
                    },
                ));
            }
            "EndThread" => {
                let thr = get_int_param(params, "thr") as usize;
                if let Some((_, iv)) = self.trace.threads.get_mut(thr.saturating_sub(1)) {
                    iv.end = Some(self.trace.frontier);
                }
            }
            "OpenCall" => {
                let thr = get_int_param(params, "thr") as u32;
                self.trace.calls.push(CallSpan {
                    thread_id: thr,
                    interval: Interval {
                        start: self.trace.frontier,
                        end: None,
                    },
                });
            }
            "CloseCall" => {
                let thr = get_int_param(params, "thr") as u32;
                // Stack discipline: close the most recent open call on thr.
                if let Some(c) = self
                    .trace
                    .calls
                    .iter_mut()
                    .rev()
                    .find(|c| c.thread_id == thr && c.interval.end.is_none())
                {
                    c.interval.end = Some(self.trace.frontier);
                }
            }
            "Advance" => self.cursor += 1,
            "Retreat" => self.cursor -= 1,
            "Seek" => self.cursor = get_int_param(params, "p") as u64,
            _ => {}
        }
        self.to_state()
    }
}

fn apalache_config() -> ApalacheConfig {
    let spec_path = std::env::var("MBT_SPEC").unwrap_or_else(|_| {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../specs/SnapshotMBT.tla").to_string()
    });
    ApalacheConfig {
        spec_path,
        invariant: "SnapshotValid".into(),
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
fn mbt_snapshot() {
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
        SnapshotComputer::new(),
    )
    .expect("MBT snapshot test failed");
}

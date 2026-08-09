//! TTD-style trace model — the Rust realization of specs/Timeline.tla.
//!
//! A `Trace` is initial memory + an append-only, position-ordered write
//! log + an event log + thread/call intervals. Any position materializes
//! into a `Snapshot` (Dump + AddressSpace) so the existing analyzer
//! pipeline runs unchanged at any recorded instant.
//!
//! Spec mapping (see docs/superpowers/specs/2026-08-07-timeline-design.md):
//!   init_mem/wr_*/ev_*  → Trace.init_mem/writes/events
//!   end = -1            → Interval.end = None
//!   frontier            → Trace.frontier
//!   CursorBounded       → Trace::snapshot returns None for t > frontier
//!
//! Snapshot.tla mapping (see docs/superpowers/specs/2026-08-08-snapshot-rust-design.md):
//!   ModelAt(t)                       → Trace::snapshot(t)
//!   EvUpto / ExcUpto                 → event-log prefix scans in snapshot/exceptions_at
//!   OpenMods (LIFO load−unload)      → module push/retain loop in snapshot
//!   SnapshotValid/SnapshotsAreModels → Dump::validate_model + tests/mbt_snapshot.rs
//!   LinkAtCursor                     → MBT-only drift guard; no Rust counterpart (by design)

use crate::error::{Anomaly, Provenance};
use crate::model::{Dump, ExceptionInfo, MemoryRegionInfo, Module, RegionClass};
use crate::space::{AddressRegion, AddressSpace};

/// A position on the trace — TTD's Major:Minor pair packed into one u64
/// (major in the high half). Only the total order matters to the model.
pub type Position = u64;

/// Pseudo stream-type used in provenance for facts decoded from a .ttfx file.
pub const TTFX_STREAM_TYPE: u32 = 0x5446_5854; // "TTFX"

/// One recorded memory write (Timeline.tla wr_pos/wr_addr/wr_val, generalized
/// from a single cell to a byte range — real TTD accesses are 1–16 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRecord {
    pub pos: Position,
    pub va: u64,
    pub data: Vec<u8>,
    pub provenance: Provenance,
}

impl WriteRecord {
    pub fn end_va(&self) -> u64 {
        self.va.saturating_add(self.data.len() as u64)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceEventKind {
    Exception,
    ModuleLoad,
    ModuleUnload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEvent {
    pub pos: Position,
    pub kind: TraceEventKind,
    /// Exception: raw exception code. Module events: 0.
    pub code: u32,
    /// Exception: exception address. ModuleLoad: module base VA. ModuleUnload: base VA.
    pub address: u64,
    pub thread_id: u32,
    /// ModuleLoad: module name. Otherwise empty.
    pub name: String,
    /// ModuleLoad: module size. Otherwise 0.
    pub size: u64,
    pub provenance: Provenance,
}

/// [start, end) interval; `end: None` while open (the spec's `end = -1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interval {
    pub start: Position,
    pub end: Option<Position>,
}

impl Interval {
    pub fn contains(&self, t: Position) -> bool {
        self.start <= t && self.end.is_none_or(|e| t < e)
    }
}

/// A call span on a thread (TTD.Calls object).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallSpan {
    pub thread_id: u32,
    pub interval: Interval,
}

/// The recorded trace. Invariants of Timeline.tla (ordered logs, nesting,
/// intervals within lifetimes) are validated at decode time in parse/ttfx.rs
/// and recorded in `anomalies`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trace {
    /// Memory contents at position 0 (Timeline.tla init_mem).
    pub init_mem: Vec<MemoryRegionInfo>,
    /// Append-only, position-ordered write log.
    pub writes: Vec<WriteRecord>,
    /// Position-ordered event log.
    pub events: Vec<TraceEvent>,
    /// Thread lifetimes.
    pub threads: Vec<(u32, Interval)>,
    /// Call spans.
    pub calls: Vec<CallSpan>,
    /// Record head: positions 0..=frontier exist in the trace.
    pub frontier: Position,
    pub anomalies: Vec<Anomaly>,
}

/// A materialized position: the time-point view analyzers consume.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub dump: Dump,
    pub space: AddressSpace,
    pub pos: Position,
}

impl Trace {
    /// Index of the last write covering `va` at or before position `t`
    /// (Timeline.tla LastWriter). Raw-log view: reports writes even when
    /// they target memory absent from init_mem (a decode anomaly); use
    /// `value_at` for the snapshot-faithful view.
    pub fn last_writer(&self, va: u64, t: Position) -> Option<usize> {
        let upto = self.writes.partition_point(|w| w.pos <= t);
        (0..upto).rev().find(|&i| {
            let w = &self.writes[i];
            w.va <= va && va < w.end_va()
        })
    }

    /// Byte at `va` at position `t` (Timeline.tla ValueAt): the last write's
    /// byte, else init_mem contents. Snapshot-faithful: bytes outside every
    /// init_mem region are not observable (apply_write drops them too), so
    /// out-of-region writes never mask earlier valid ones.
    pub fn value_at(&self, va: u64, t: Position) -> Option<u8> {
        let region = self
            .init_mem
            .iter()
            .find(|r| r.va_start <= va && va < r.va_start + r.size)?;
        let upto = self.writes.partition_point(|w| w.pos <= t);
        for i in (0..upto).rev() {
            let w = &self.writes[i];
            if w.va <= va && va < w.end_va() {
                return w.data.get((va - w.va) as usize).copied();
            }
        }
        region.data.get((va - region.va_start) as usize).copied()
    }

    /// All writes overlapping `[va, va+len)` in (t1, t2]
    /// (Timeline.tla WritesBetween).
    pub fn writes_between(
        &self,
        va: u64,
        len: u64,
        t1: Position,
        t2: Position,
    ) -> Vec<&WriteRecord> {
        let end = va.saturating_add(len);
        self.writes
            .iter()
            .filter(|w| t1 < w.pos && w.pos <= t2 && w.va < end && va < w.end_va())
            .collect()
    }

    /// Exception events at or before `t` (Timeline.tla ExceptionsAt).
    pub fn exceptions_at(&self, t: Position) -> Vec<&TraceEvent> {
        self.events
            .iter()
            .filter(|e| e.kind == TraceEventKind::Exception && e.pos <= t)
            .collect()
    }

    /// Thread lifetime containing `t`, if any.
    pub fn thread_at(&self, thread_id: u32, t: Position) -> Option<Interval> {
        self.threads
            .iter()
            .find(|(id, iv)| *id == thread_id && iv.contains(t))
            .map(|(_, iv)| *iv)
    }

    /// Materialize position `t` as a time-point snapshot. Returns None when
    /// `t > frontier` (Timeline.tla CursorBounded — fail closed).
    pub fn snapshot(&self, t: Position) -> Option<Snapshot> {
        if t > self.frontier {
            return None;
        }

        // Memory: init_mem overlaid with writes ≤ t.
        let mut regions: Vec<MemoryRegionInfo> = self.init_mem.clone();
        for w in self.writes.iter().filter(|w| w.pos <= t) {
            apply_write(&mut regions, w);
        }

        // Modules: loads minus unloads ≤ t (event-ordered).
        let mut modules: Vec<Module> = Vec::new();
        for e in self.events.iter().filter(|e| e.pos <= t) {
            match e.kind {
                TraceEventKind::ModuleLoad => modules.push(Module {
                    name: e.name.clone(),
                    base_va: e.address,
                    size: e.size,
                    checksum: 0,
                    codeview_guid: None,
                    codeview_age: None,
                    pdb_name: None,
                    provenance: e.provenance.clone(),
                }),
                TraceEventKind::ModuleUnload => modules.retain(|m| m.base_va != e.address),
                TraceEventKind::Exception => {}
            }
        }

        // Exception: the most recent one at or before t.
        let exception = self.exceptions_at(t).last().map(|e| ExceptionInfo {
            code: e.code,
            address: e.address,
            thread_id: e.thread_id,
            flags: 0,
            parameters: Vec::new(),
            context: None,
            provenance: e.provenance.clone(),
        });

        let prov = Provenance {
            stream_type: TTFX_STREAM_TYPE,
            file_offset: 0,
            rva: 0,
        };
        let mut dump = Dump {
            system_info: None,
            modules,
            threads: Vec::new(), // register files are per-position; out of scope for v1
            memory_regions: regions,
            exception,
            anomalies: self.anomalies.clone(),
            annotations: vec![("ttfx_position".to_string(), format!("0x{t:X}"))],
            memory_info: Vec::new(),
            v8heap_ext: None,
            file_size: 0,
        };
        // Snapshot.tla SnapshotValid: degrade Model-invariant violations of the
        // materialized view into anomalies (never fail — CursorBounded above
        // remains the only hard failure).
        let mut validation = dump.validate_model();
        dump.anomalies.append(&mut validation);

        let mut space = AddressSpace::new(1_000_000);
        for region in &dump.memory_regions {
            let _ = space.add_region(AddressRegion {
                va_start: region.va_start,
                size: region.size,
                data: region.data.clone(),
                protection: region.protection.bits(),
                state: region.state,
                classification: region.region_class.unwrap_or(RegionClass::Other),
            });
        }
        let _ = prov;

        Some(Snapshot {
            dump,
            space,
            pos: t,
        })
    }
}

/// Overlay a write onto the region list: bytes land in the containing
/// region; bytes outside every region are dropped (fail-closed).
fn apply_write(regions: &mut [MemoryRegionInfo], w: &WriteRecord) {
    for (off, byte) in w.data.iter().enumerate() {
        let va = w.va.saturating_add(off as u64);
        if let Some(r) = regions
            .iter_mut()
            .find(|r| r.va_start <= va && va < r.va_start + r.size)
        {
            let idx = (va - r.va_start) as usize;
            if idx < r.data.len() {
                r.data[idx] = *byte;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MemState, MemType, Protection};

    fn prov() -> Provenance {
        Provenance {
            stream_type: TTFX_STREAM_TYPE,
            file_offset: 0,
            rva: 0,
        }
    }

    fn region(va: u64, data: &[u8]) -> MemoryRegionInfo {
        MemoryRegionInfo {
            va_start: va,
            size: data.len() as u64,
            data: data.to_vec(),
            protection: Protection::new(Protection::READ | Protection::WRITE),
            state: MemState::Commit,
            mem_type: MemType::Private,
            provenance: prov(),
            region_class: Some(RegionClass::Private),
        }
    }

    fn write(pos: Position, va: u64, data: &[u8]) -> WriteRecord {
        WriteRecord {
            pos,
            va,
            data: data.to_vec(),
            provenance: prov(),
        }
    }

    fn fixture() -> Trace {
        Trace {
            init_mem: vec![region(0x1000, &[0xAA; 16]), region(0x2000, &[0xBB; 16])],
            writes: vec![
                write(1, 0x1004, &[0x11, 0x22]),
                write(2, 0x1004, &[0x33]),
                write(3, 0x2FF0, &[0xCC]), // outside all regions: dropped
            ],
            events: vec![],
            threads: vec![(
                7,
                Interval {
                    start: 0,
                    end: None,
                },
            )],
            calls: vec![],
            frontier: 3,
            anomalies: vec![],
        }
    }

    #[test]
    fn value_at_initial() {
        let tr = fixture();
        assert_eq!(tr.value_at(0x1000, 0), Some(0xAA));
        assert_eq!(tr.value_at(0x1004, 0), Some(0xAA));
    }

    #[test]
    fn value_at_applies_writes_in_order() {
        let tr = fixture();
        assert_eq!(tr.value_at(0x1004, 1), Some(0x11));
        assert_eq!(tr.value_at(0x1005, 1), Some(0x22));
        assert_eq!(tr.value_at(0x1004, 2), Some(0x33)); // later write wins
        assert_eq!(tr.value_at(0x1005, 2), Some(0x22)); // untouched by second write
    }

    #[test]
    fn value_at_unmapped_and_out_of_region_write() {
        let tr = fixture();
        assert_eq!(tr.value_at(0x9000, 3), None);
        assert_eq!(tr.value_at(0x2FF0, 3), None); // write dropped: no region there
    }

    #[test]
    fn snapshot_consistent_with_brute_force() {
        // SnapshotConsistent: value_at == naive fold of init_mem + writes ≤ t.
        let tr = fixture();
        for t in 0..=tr.frontier {
            for va in 0x1000..0x1010u64 {
                let mut expect = tr
                    .init_mem
                    .iter()
                    .find(|r| r.va_start <= va && va < r.va_start + r.size)
                    .and_then(|r| r.data.get((va - r.va_start) as usize).copied());
                for w in tr.writes.iter().filter(|w| w.pos <= t) {
                    if w.va <= va && va < w.end_va() {
                        expect = w.data.get((va - w.va) as usize).copied();
                    }
                }
                assert_eq!(tr.value_at(va, t), expect, "va={va:#X} t={t}");
            }
        }
    }

    #[test]
    fn writes_between_window() {
        let tr = fixture();
        let all = tr.writes_between(0x1004, 1, 0, 3);
        assert_eq!(all.len(), 2);
        let only_first = tr.writes_between(0x1004, 1, 0, 1);
        assert_eq!(only_first.len(), 1);
        assert_eq!(only_first[0].data, vec![0x11, 0x22]);
        // Overlap by range, not just start address.
        let touching = tr.writes_between(0x1005, 1, 0, 1);
        assert_eq!(touching.len(), 1);
    }

    #[test]
    fn snapshot_cursor_bounded() {
        let tr = fixture();
        assert!(tr.snapshot(4).is_none()); // beyond frontier
        assert!(tr.snapshot(3).is_some());
    }

    #[test]
    fn snapshot_materializes_memory_and_modules() {
        let mut tr = fixture();
        tr.events = vec![
            TraceEvent {
                pos: 1,
                kind: TraceEventKind::ModuleLoad,
                code: 0,
                address: 0x7000_0000,
                thread_id: 0,
                name: "app.exe".to_string(),
                size: 0x1000,
                provenance: prov(),
            },
            TraceEvent {
                pos: 2,
                kind: TraceEventKind::Exception,
                code: 0xC000_0005,
                address: 0xDEAD,
                thread_id: 7,
                name: String::new(),
                size: 0,
                provenance: prov(),
            },
        ];
        let snap = tr.snapshot(2).unwrap();
        assert_eq!(snap.dump.modules.len(), 1);
        assert_eq!(snap.dump.modules[0].name, "app.exe");
        let exc = snap.dump.exception.unwrap();
        assert_eq!(exc.code, 0xC000_0005);
        assert_eq!(exc.thread_id, 7);
        // Region bytes reflect writes ≤ t.
        let r = &snap.dump.memory_regions[0];
        assert_eq!(r.data[4], 0x33);
        assert_eq!(r.data[5], 0x22);
        // AddressSpace agrees.
        assert_eq!(snap.space.read(0x1004, 1), Some(&[0x33][..]));
        // Exception absent before it happened.
        let snap0 = tr.snapshot(0).unwrap();
        assert!(snap0.dump.exception.is_none());
        assert!(snap0.dump.modules.is_empty());
    }

    #[test]
    fn module_unload_removes() {
        let mut tr = fixture();
        for (pos, kind) in [
            (1, TraceEventKind::ModuleLoad),
            (2, TraceEventKind::ModuleUnload),
        ] {
            tr.events.push(TraceEvent {
                pos,
                kind,
                code: 0,
                address: 0x7000_0000,
                thread_id: 0,
                name: "app.exe".to_string(),
                size: 0x1000,
                provenance: prov(),
            });
        }
        assert_eq!(tr.snapshot(1).unwrap().dump.modules.len(), 1);
        assert_eq!(tr.snapshot(2).unwrap().dump.modules.len(), 0);
    }

    #[test]
    fn snapshot_clean_dump_has_no_validation_anomalies() {
        let tr = fixture();
        let snap = tr.snapshot(3).unwrap();
        assert!(snap.dump.anomalies.is_empty());
    }

    #[test]
    fn snapshot_surfaces_overlapping_module_anomaly() {
        // Snapshot.tla SnapshotValid: ModuleLoads with overlapping VAs
        // materialize into a Dump whose ModulesDisjoint violation degrades
        // into an "overlapping module" anomaly (Model.tla:225).
        let mut tr = fixture();
        for (pos, address) in [(1, 0x7000_0000u64), (2, 0x7000_0800)] {
            tr.events.push(TraceEvent {
                pos,
                kind: TraceEventKind::ModuleLoad,
                code: 0,
                address,
                thread_id: 0,
                name: format!("m{pos}"),
                size: 0x1000,
                provenance: prov(),
            });
        }
        let snap = tr.snapshot(2).unwrap();
        assert_eq!(snap.dump.modules.len(), 2);
        let overlapping: Vec<_> = snap
            .dump
            .anomalies
            .iter()
            .filter(|a| a.description == "overlapping module")
            .collect();
        assert_eq!(overlapping.len(), 1);
        // Before the second load the snapshot is clean.
        let snap1 = tr.snapshot(1).unwrap();
        assert!(snap1.dump.anomalies.is_empty());
    }
}

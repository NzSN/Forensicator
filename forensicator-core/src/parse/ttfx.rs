//! .ttfx trace container — the wire format carrying Timeline.tla's abstract
//! trace between the Windows extractor (TTDReplay → TTFX) and forensicator.
//!
//! Wire format (little-endian):
//!   header (32 B): magic "TTFX" (4) version u32 (4) flags u32 (4)
//!                  section_cnt u32 (4) frontier u64 (8) reserved (8)
//!   per section: kind u32 (4) record_size u32 (4) record_cnt u64 (8)
//!                then record_cnt * record_size bytes
//!   sections: 1=INITMEM 2=WRITES 3=EVENTS 4=THREADS 5=CALLS
//!   byte payloads (region bytes, write bytes, module names) live inline
//!   after all sections, referenced by absolute file offset.
//!
//! Records:
//!   INITMEM (32 B): va u64, size u64, prot u32, state u32, mem_type u32, data_off u32
//!   WRITES  (24 B): pos u64, va u64, len u32, data_off u32
//!   EVENTS  (48 B): pos u64, kind u32, code u32, address u64, thread_id u32,
//!                   size u64, name_len u32, name_off u32, pad u32
//!   THREADS (24 B): thread_id u32, pad u32, start u64, end u64   (u64::MAX = open)
//!   CALLS   (24 B): thread_id u32, pad u32, start u64, end u64   (u64::MAX = open)
//!
//! Same discipline as V8HE: versioned, truncation-tolerant, decode-time
//! validation of the Timeline.tla invariants (ordered logs, call nesting,
//! intervals within lifetimes) into `Trace.anomalies`.

use crate::error::{Anomaly, Provenance};
use crate::model::trace::{
    CallSpan, Interval, Position, TTFX_STREAM_TYPE, Trace, TraceEvent, TraceEventKind, WriteRecord,
};
use crate::model::{MemState, MemType, MemoryRegionInfo, Protection, RegionClass};

/// 'TTFX' packed little-endian as a u32 (on-disk bytes: 'T','T','F','X'),
/// same convention as V8HE_STREAM_TYPE.
pub const TTFX_MAGIC: u32 = 0x5846_5454; // "TTFX"
pub const TTFX_VERSION: u32 = 1;

const HEADER_SIZE: usize = 32;
const SECTION_HDR_SIZE: usize = 16;

const SEC_INITMEM: u32 = 1;
const SEC_WRITES: u32 = 2;
const SEC_EVENTS: u32 = 3;
const SEC_THREADS: u32 = 4;
const SEC_CALLS: u32 = 5;

const INITMEM_SIZE: usize = 32;
const WRITES_SIZE: usize = 24;
const EVENTS_SIZE: usize = 48;
const INTERVAL_SIZE: usize = 24; // THREADS and CALLS share the layout

const OPEN_END: u64 = u64::MAX;

fn prov(file_offset: u64) -> Provenance {
    Provenance {
        stream_type: TTFX_STREAM_TYPE,
        file_offset,
        rva: 0,
    }
}

fn anomaly(file_offset: u64, description: String) -> Anomaly {
    Anomaly {
        provenance: prov(file_offset),
        description,
    }
}

fn u32_at(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

fn u64_at(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

/// Decode a .ttfx file into a Trace. Hard error only on bad magic or a
/// header shorter than 32 bytes; everything else degrades into anomalies.
pub fn decode_ttfx(data: &[u8]) -> Result<Trace, Anomaly> {
    if data.len() < HEADER_SIZE {
        return Err(anomaly(0, "ttfx: truncated header".into()));
    }
    if u32_at(data, 0) != Some(TTFX_MAGIC) {
        return Err(anomaly(0, "ttfx: bad magic".into()));
    }
    let version = u32_at(data, 4).unwrap_or(0);
    if version != TTFX_VERSION {
        return Err(anomaly(4, format!("ttfx: unsupported version {version}")));
    }
    let section_cnt = u32_at(data, 12).unwrap_or(0) as usize;
    let frontier = u64_at(data, 16).unwrap_or(0);

    let mut trace = Trace {
        init_mem: Vec::new(),
        writes: Vec::new(),
        events: Vec::new(),
        threads: Vec::new(),
        calls: Vec::new(),
        frontier,
        anomalies: Vec::new(),
    };

    let mut off = HEADER_SIZE;
    for _ in 0..section_cnt {
        let Some(kind) = u32_at(data, off) else {
            trace
                .anomalies
                .push(anomaly(off as u64, "ttfx: truncated section table".into()));
            break;
        };
        let record_size = u32_at(data, off + 4).unwrap_or(0) as usize;
        let record_cnt = u64_at(data, off + 8).unwrap_or(0) as usize;
        let body = off + SECTION_HDR_SIZE;
        decode_section(
            &mut trace,
            kind,
            data,
            body,
            record_size,
            record_cnt,
            frontier,
        );
        off = body.saturating_add(record_size.saturating_mul(record_cnt));
    }

    validate_intervals(&mut trace);
    Ok(trace)
}

fn decode_section(
    trace: &mut Trace,
    kind: u32,
    data: &[u8],
    body: usize,
    record_size: usize,
    record_cnt: usize,
    frontier: Position,
) {
    let want = match kind {
        SEC_INITMEM => INITMEM_SIZE,
        SEC_WRITES => WRITES_SIZE,
        SEC_EVENTS => EVENTS_SIZE,
        SEC_THREADS | SEC_CALLS => INTERVAL_SIZE,
        _ => return, // unknown section kind: skip (forward compatibility)
    };
    if record_size != want {
        trace.anomalies.push(anomaly(
            body as u64,
            format!("ttfx: section {kind} record_size {record_size} != {want}"),
        ));
        return;
    }
    for i in 0..record_cnt {
        let off = body + i * record_size;
        if off + record_size > data.len() {
            trace.anomalies.push(anomaly(
                off as u64,
                format!("ttfx: truncated section {kind} at record {i}"),
            ));
            break;
        }
        match kind {
            SEC_INITMEM => decode_initmem(trace, data, off),
            SEC_WRITES => decode_write(trace, data, off, frontier),
            SEC_EVENTS => decode_event(trace, data, off, frontier),
            SEC_THREADS => decode_thread(trace, data, off),
            SEC_CALLS => decode_call(trace, data, off),
            _ => {}
        }
    }
}

fn decode_initmem(trace: &mut Trace, data: &[u8], off: usize) {
    let va = u64_at(data, off).unwrap_or(0);
    let size = u64_at(data, off + 8).unwrap_or(0);
    let prot = u32_at(data, off + 16).unwrap_or(0);
    let state = MemState::from_u32(u32_at(data, off + 20).unwrap_or(0)).unwrap_or(MemState::Commit);
    let mem_type =
        MemType::from_u32(u32_at(data, off + 24).unwrap_or(0)).unwrap_or(MemType::Private);
    let data_off = u32_at(data, off + 28).unwrap_or(0) as usize;
    let payload = data
        .get(data_off..data_off.saturating_add(size as usize))
        .unwrap_or(&[]);
    if payload.len() < size as usize {
        trace.anomalies.push(anomaly(
            off as u64,
            format!("ttfx: initmem region at 0x{va:X} truncated payload"),
        ));
    }
    trace.init_mem.push(MemoryRegionInfo {
        va_start: va,
        size,
        data: payload.to_vec(),
        protection: Protection::new(prot),
        state,
        mem_type,
        provenance: prov(off as u64),
        region_class: Some(RegionClass::Private),
    });
}

fn decode_write(trace: &mut Trace, data: &[u8], off: usize, frontier: Position) {
    let pos = u64_at(data, off).unwrap_or(0);
    let va = u64_at(data, off + 8).unwrap_or(0);
    let len = u32_at(data, off + 16).unwrap_or(0) as usize;
    let data_off = u32_at(data, off + 20).unwrap_or(0) as usize;
    let payload = data
        .get(data_off..data_off.saturating_add(len))
        .unwrap_or(&[]);
    if payload.len() < len {
        trace
            .anomalies
            .push(anomaly(off as u64, "ttfx: write truncated payload".into()));
    }
    // TraceOrdered: positions non-decreasing and within the recorded range.
    if let Some(last) = trace.writes.last()
        && pos < last.pos
    {
        trace.anomalies.push(anomaly(
            off as u64,
            format!("ttfx: write out of order (pos {pos:#X} < {:#X})", last.pos),
        ));
    }
    if pos > frontier {
        trace.anomalies.push(anomaly(
            off as u64,
            format!("ttfx: write beyond frontier (pos {pos:#X})"),
        ));
    }
    trace.writes.push(WriteRecord {
        pos,
        va,
        data: payload.to_vec(),
        provenance: prov(off as u64),
    });
}

fn decode_event(trace: &mut Trace, data: &[u8], off: usize, frontier: Position) {
    let pos = u64_at(data, off).unwrap_or(0);
    let kind = match u32_at(data, off + 8).unwrap_or(0) {
        0 => TraceEventKind::Exception,
        1 => TraceEventKind::ModuleLoad,
        2 => TraceEventKind::ModuleUnload,
        other => {
            trace.anomalies.push(anomaly(
                off as u64,
                format!("ttfx: unknown event kind {other}"),
            ));
            return;
        }
    };
    let code = u32_at(data, off + 12).unwrap_or(0);
    let address = u64_at(data, off + 16).unwrap_or(0);
    let thread_id = u32_at(data, off + 24).unwrap_or(0);
    let size = u64_at(data, off + 28).unwrap_or(0);
    let name_len = u32_at(data, off + 36).unwrap_or(0) as usize;
    let name_off = u32_at(data, off + 40).unwrap_or(0) as usize;
    let name = data
        .get(name_off..name_off.saturating_add(name_len))
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    if let Some(last) = trace.events.last()
        && pos < last.pos
    {
        trace.anomalies.push(anomaly(
            off as u64,
            format!("ttfx: event out of order (pos {pos:#X} < {:#X})", last.pos),
        ));
    }
    if pos > frontier {
        trace.anomalies.push(anomaly(
            off as u64,
            format!("ttfx: event beyond frontier (pos {pos:#X})"),
        ));
    }
    trace.events.push(TraceEvent {
        pos,
        kind,
        code,
        address,
        thread_id,
        name,
        size,
        provenance: prov(off as u64),
    });
}

fn decode_interval(data: &[u8], off: usize) -> (u32, Interval) {
    let thread_id = u32_at(data, off).unwrap_or(0);
    let start = u64_at(data, off + 8).unwrap_or(0);
    let end_raw = u64_at(data, off + 16).unwrap_or(0);
    let end = if end_raw == OPEN_END {
        None
    } else {
        Some(end_raw)
    };
    (thread_id, Interval { start, end })
}

fn decode_thread(trace: &mut Trace, data: &[u8], off: usize) {
    let (id, iv) = decode_interval(data, off);
    // ThreadIntervals: start <= end.
    if let Some(e) = iv.end
        && iv.start > e
    {
        trace.anomalies.push(anomaly(
            off as u64,
            format!(
                "ttfx: thread {id} interval inverted ({:#X} > {:#X})",
                iv.start, e
            ),
        ));
    }
    trace.threads.push((id, iv));
}

fn decode_call(trace: &mut Trace, data: &[u8], off: usize) {
    let (thread_id, iv) = decode_interval(data, off);
    trace.calls.push(CallSpan {
        thread_id,
        interval: iv,
    });
}

/// Cross-record invariants (CallNesting, CallsWithinThreads) — checked
/// after all sections, since THREADS/CALLS order is not guaranteed.
fn validate_intervals(trace: &mut Trace) {
    for (i, c) in trace.calls.iter().enumerate() {
        // CallsWithinThreads.
        match trace.threads.iter().find(|(id, _)| *id == c.thread_id) {
            None => trace.anomalies.push(anomaly(
                0,
                format!("ttfx: call on unknown thread {}", c.thread_id),
            )),
            Some((_, tiv)) => {
                let outside = c.interval.start < tiv.start
                    || matches!((c.interval.end, tiv.end), (Some(ce), Some(te)) if ce > te);
                if outside {
                    trace.anomalies.push(anomaly(
                        0,
                        format!("ttfx: call outside thread {} lifetime", c.thread_id),
                    ));
                }
            }
        }
        // CallNesting: same-thread closed spans are disjoint or nested.
        for (j, o) in trace.calls.iter().enumerate() {
            if i == j || o.thread_id != c.thread_id {
                continue;
            }
            let (Some(ce), Some(oe)) = (c.interval.end, o.interval.end) else {
                continue;
            };
            let (cs, os) = (c.interval.start, o.interval.start);
            let disjoint = ce <= os || oe <= cs;
            let nested = (cs <= os && oe <= ce) || (os <= cs && ce <= oe);
            if !disjoint && !nested {
                trace.anomalies.push(anomaly(
                    0,
                    format!("ttfx: crossing call spans on thread {}", c.thread_id),
                ));
            }
        }
    }
}

/// Serialize a Trace to .ttfx bytes. Used by tests/fixtures and by the
/// Windows extractor (which links this crate or reimplements the format).
pub fn encode_ttfx(trace: &Trace) -> Vec<u8> {
    let mut pool: Vec<u8> = Vec::new();
    let mut sections: Vec<(u32, usize, Vec<u8>)> = Vec::new(); // (kind, record_size, body)

    // Record payload offsets are absolute file offsets; the pool start is
    // known only after all sections are laid out, so emit placeholders and
    // patch at the end.
    let mut patch: Vec<(usize, usize)> = Vec::new(); // (section_idx, field_off_in_body) → pool_off

    let mut initmem = Vec::new();
    for r in &trace.init_mem {
        let mut rec = [0u8; INITMEM_SIZE];
        rec[0..8].copy_from_slice(&r.va_start.to_le_bytes());
        rec[8..16].copy_from_slice(&r.size.to_le_bytes());
        rec[16..20].copy_from_slice(&r.protection.bits().to_le_bytes());
        rec[20..24].copy_from_slice(&(r.state as u32).to_le_bytes());
        rec[24..28].copy_from_slice(&(r.mem_type as u32).to_le_bytes());
        patch.push((sections.len(), initmem.len() + 28));
        pool.extend_from_slice(&r.data);
        initmem.extend_from_slice(&rec);
    }
    sections.push((SEC_INITMEM, INITMEM_SIZE, initmem));

    let mut writes = Vec::new();
    for w in &trace.writes {
        let mut rec = [0u8; WRITES_SIZE];
        rec[0..8].copy_from_slice(&w.pos.to_le_bytes());
        rec[8..16].copy_from_slice(&w.va.to_le_bytes());
        rec[16..20].copy_from_slice(&(w.data.len() as u32).to_le_bytes());
        patch.push((sections.len(), writes.len() + 20));
        pool.extend_from_slice(&w.data);
        writes.extend_from_slice(&rec);
    }
    sections.push((SEC_WRITES, WRITES_SIZE, writes));

    let mut events = Vec::new();
    for e in &trace.events {
        let mut rec = [0u8; EVENTS_SIZE];
        rec[0..8].copy_from_slice(&e.pos.to_le_bytes());
        rec[8..12].copy_from_slice(
            &(match e.kind {
                TraceEventKind::Exception => 0u32,
                TraceEventKind::ModuleLoad => 1,
                TraceEventKind::ModuleUnload => 2,
            })
            .to_le_bytes(),
        );
        rec[12..16].copy_from_slice(&e.code.to_le_bytes());
        rec[16..24].copy_from_slice(&e.address.to_le_bytes());
        rec[24..28].copy_from_slice(&e.thread_id.to_le_bytes());
        rec[28..36].copy_from_slice(&e.size.to_le_bytes());
        rec[36..40].copy_from_slice(&(e.name.len() as u32).to_le_bytes());
        patch.push((sections.len(), events.len() + 40));
        pool.extend_from_slice(e.name.as_bytes());
        events.extend_from_slice(&rec);
    }
    sections.push((SEC_EVENTS, EVENTS_SIZE, events));

    let pack_interval = |thread_id: u32, iv: &Interval| {
        let mut rec = [0u8; INTERVAL_SIZE];
        rec[0..4].copy_from_slice(&thread_id.to_le_bytes());
        rec[8..16].copy_from_slice(&iv.start.to_le_bytes());
        rec[16..24].copy_from_slice(&iv.end.unwrap_or(OPEN_END).to_le_bytes());
        rec
    };
    let mut threads = Vec::new();
    for (id, iv) in &trace.threads {
        threads.extend_from_slice(&pack_interval(*id, iv));
    }
    sections.push((SEC_THREADS, INTERVAL_SIZE, threads));

    let mut calls = Vec::new();
    for c in &trace.calls {
        calls.extend_from_slice(&pack_interval(c.thread_id, &c.interval));
    }
    sections.push((SEC_CALLS, INTERVAL_SIZE, calls));

    // Layout: header, section headers+bodies, pool. Patch payload offsets.
    let sections_total: usize = sections
        .iter()
        .map(|(_, _, body)| SECTION_HDR_SIZE + body.len())
        .sum();
    let pool_start = HEADER_SIZE + sections_total;

    let mut out = Vec::with_capacity(pool_start + pool.len());
    out.extend_from_slice(&TTFX_MAGIC.to_le_bytes());
    out.extend_from_slice(&TTFX_VERSION.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // flags
    out.extend_from_slice(&(sections.len() as u32).to_le_bytes());
    out.extend_from_slice(&trace.frontier.to_le_bytes());
    out.extend_from_slice(&[0u8; 8]); // reserved

    // Pool offsets accumulated per record in patch-push order; patch the
    // section bodies directly.
    let mut running = pool_start;
    for (sec_idx, field_off) in patch {
        let body = &mut sections[sec_idx].2;
        body[field_off..field_off + 4].copy_from_slice(&(running as u32).to_le_bytes());
        // Advance by the payload length of this record.
        let payload_len = match sections[sec_idx].0 {
            SEC_INITMEM => {
                let rec = &sections[sec_idx].2[field_off - 28..field_off + 4];
                u64::from_le_bytes(rec[8..16].try_into().unwrap()) as usize
            }
            SEC_WRITES => {
                let rec = &sections[sec_idx].2[field_off - 20..field_off + 4];
                u32::from_le_bytes(rec[16..20].try_into().unwrap()) as usize
            }
            SEC_EVENTS => {
                let rec = &sections[sec_idx].2[field_off - 40..field_off + 4];
                u32::from_le_bytes(rec[36..40].try_into().unwrap()) as usize
            }
            _ => 0,
        };
        running += payload_len;
    }

    for (kind, rec_size, body) in &sections {
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&(*rec_size as u32).to_le_bytes());
        let cnt = body.len() / rec_size;
        out.extend_from_slice(&(cnt as u64).to_le_bytes());
        out.extend_from_slice(body);
    }
    out.extend_from_slice(&pool);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Protection, RegionClass};

    fn region(va: u64, data: &[u8]) -> MemoryRegionInfo {
        MemoryRegionInfo {
            va_start: va,
            size: data.len() as u64,
            data: data.to_vec(),
            protection: Protection::new(Protection::READ | Protection::WRITE),
            state: MemState::Commit,
            mem_type: MemType::Private,
            provenance: prov(0),
            region_class: Some(RegionClass::Private),
        }
    }

    pub fn minimal_trace() -> Trace {
        Trace {
            init_mem: vec![region(0x1000, &[0xAA; 16]), region(0x2000, &[0xBB; 16])],
            writes: vec![
                WriteRecord {
                    pos: 1,
                    va: 0x1004,
                    data: vec![0x11, 0x22],
                    provenance: prov(0),
                },
                WriteRecord {
                    pos: 2,
                    va: 0x1004,
                    data: vec![0x33],
                    provenance: prov(0),
                },
            ],
            events: vec![
                TraceEvent {
                    pos: 1,
                    kind: TraceEventKind::ModuleLoad,
                    code: 0,
                    address: 0x7000_0000,
                    thread_id: 0,
                    name: "app.exe".into(),
                    size: 0x1000,
                    provenance: prov(0),
                },
                TraceEvent {
                    pos: 2,
                    kind: TraceEventKind::Exception,
                    code: 0xC000_0005,
                    address: 0x1004,
                    thread_id: 7,
                    name: String::new(),
                    size: 0,
                    provenance: prov(0),
                },
            ],
            threads: vec![(
                7,
                Interval {
                    start: 0,
                    end: None,
                },
            )],
            calls: vec![
                CallSpan {
                    thread_id: 7,
                    interval: Interval {
                        start: 0,
                        end: Some(2),
                    },
                },
                CallSpan {
                    thread_id: 7,
                    interval: Interval {
                        start: 0,
                        end: Some(1),
                    },
                },
            ],
            frontier: 2,
            anomalies: vec![],
        }
    }

    #[test]
    fn round_trip() {
        let trace = minimal_trace();
        let bytes = encode_ttfx(&trace);
        let back = decode_ttfx(&bytes).unwrap();
        assert!(back.anomalies.is_empty(), "anomalies: {:?}", back.anomalies);
        assert_eq!(back.frontier, 2);
        assert_eq!(back.init_mem.len(), 2);
        assert_eq!(back.init_mem[0].data, vec![0xAA; 16]);
        assert_eq!(back.writes.len(), 2);
        assert_eq!(back.writes[0].data, vec![0x11, 0x22]);
        assert_eq!(back.events.len(), 2);
        assert_eq!(back.events[0].name, "app.exe");
        assert_eq!(back.threads, trace.threads);
        assert_eq!(back.calls, trace.calls);
        // Views survive the round trip.
        assert_eq!(back.value_at(0x1004, 2), Some(0x33));
    }

    #[test]
    fn bad_magic_rejected() {
        let mut bytes = encode_ttfx(&minimal_trace());
        bytes[0] = b'X';
        assert!(decode_ttfx(&bytes).is_err());
    }

    #[test]
    fn truncated_header_rejected() {
        assert!(decode_ttfx(&[0u8; 16]).is_err());
    }

    #[test]
    fn truncated_section_tolerated() {
        let bytes = encode_ttfx(&minimal_trace());
        let cut = bytes.len() - 20; // chop inside the pool/last records
        let back = decode_ttfx(&bytes[..cut]).unwrap();
        assert!(!back.anomalies.is_empty());
    }

    #[test]
    fn out_of_order_write_flagged() {
        let mut trace = minimal_trace();
        trace.writes[1].pos = 0; // earlier than writes[0].pos = 1
        let bytes = encode_ttfx(&trace);
        let back = decode_ttfx(&bytes).unwrap();
        assert!(
            back.anomalies
                .iter()
                .any(|a| a.description.contains("out of order"))
        );
    }

    #[test]
    fn write_beyond_frontier_flagged() {
        let mut trace = minimal_trace();
        trace.writes[1].pos = 99;
        let bytes = encode_ttfx(&trace);
        let back = decode_ttfx(&bytes).unwrap();
        assert!(
            back.anomalies
                .iter()
                .any(|a| a.description.contains("beyond frontier"))
        );
    }

    #[test]
    fn crossing_calls_flagged() {
        let mut trace = minimal_trace();
        trace.calls[1].interval = Interval {
            start: 1,
            end: Some(2),
        };
        trace.calls[0].interval = Interval {
            start: 0,
            end: Some(2),
        };
        // now: [0,2) and [1,2) — nested, fine; make them cross instead:
        trace.calls[1].interval = Interval {
            start: 1,
            end: Some(3),
        };
        trace.frontier = 3;
        let bytes = encode_ttfx(&trace);
        let back = decode_ttfx(&bytes).unwrap();
        assert!(
            back.anomalies
                .iter()
                .any(|a| a.description.contains("crossing call spans"))
        );
    }

    #[test]
    fn call_on_unknown_thread_flagged() {
        let mut trace = minimal_trace();
        trace.calls[0].thread_id = 99;
        let bytes = encode_ttfx(&trace);
        let back = decode_ttfx(&bytes).unwrap();
        assert!(
            back.anomalies
                .iter()
                .any(|a| a.description.contains("unknown thread"))
        );
    }

    #[test]
    fn inverted_thread_interval_flagged() {
        let mut trace = minimal_trace();
        trace.threads[0].1 = Interval {
            start: 5,
            end: Some(2),
        };
        trace.frontier = 5;
        let bytes = encode_ttfx(&trace);
        let back = decode_ttfx(&bytes).unwrap();
        assert!(
            back.anomalies
                .iter()
                .any(|a| a.description.contains("interval inverted"))
        );
    }

    /// Regenerate the committed golden fixture:
    ///   cargo test -p forensicator-core --lib -- parse::ttfx --ignored
    #[test]
    #[ignore]
    fn write_minimal_fixture() {
        let bytes = encode_ttfx(&minimal_trace());
        std::fs::create_dir_all("../Case/ttfx").unwrap();
        std::fs::write("../Case/ttfx/minimal.ttfx", &bytes).unwrap();
        let back = decode_ttfx(&bytes).unwrap();
        assert!(back.anomalies.is_empty());
    }
}

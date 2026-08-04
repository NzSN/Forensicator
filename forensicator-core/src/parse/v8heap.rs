use crate::error::{Anomaly, Provenance};
use crate::model::V8HeapExt;
use crate::parse::memory::RawMemoryRange;

/// The V8 heap snapshot user-extension stream type.
///
/// 'V8HE' packed little-endian as a u32 (in-memory bytes: 'V','8','H','E').
/// Must match `kMinidumpStreamTypeV8Heap` in the handler's
/// `v8_heap_format.h`. Above the 0x0000..0xffff reserved range and outside
/// Crashpad's own 0x43500001..0x4350ffff block.
pub const V8HE_STREAM_TYPE: u32 = 0x45483856;

const HEADER_SIZE: usize = 32; // stream_type(4) version(4) cage_base(8)
// isolate_va(8) region_count(4) flags(4)
const REGION_ENTRY_SIZE: usize = 24; // va(8) size(8) file_offset(8)
const V2_EXT_SIZE: usize = 32; // alloc_top(8) alloc_limit(8) gc_state(4)
// last_gc_reason(4) fatal_msg_len(4) reserved(4)
const MAX_FATAL_MSG_LEN: usize = 4096;

/// Decode the V8HE user-extension stream into memory ranges, plus the
/// optional v2 extension facts (allocation top/limit, GC state, fatal
/// message).
///
/// Wire format (little-endian), emitted by the handler's `V8HeapCapture`:
///   v1: V8HeapExtensionHeader (32 B) → V8HeapRegion[count] (24 B) → bytes
///   v2: header (32 B) → V8HeapExt (32 B) → fatal message bytes
///       → V8HeapRegion[count] (24 B) → bytes
///
/// Each region's `file_offset` is relative to the start of the stream. The
/// returned ranges are ingested into the address space just like ordinary
/// memory ranges, after which the existing V8 JIT-frame decoder works
/// unmodified.
pub fn decode_v8heap(
    data: &[u8],
    prov: Provenance,
) -> Result<(Vec<RawMemoryRange>, Option<V8HeapExt>), Anomaly> {
    if data.len() < HEADER_SIZE {
        return Ok((vec![], None));
    }
    let stream_type = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if stream_type != V8HE_STREAM_TYPE {
        return Err(Anomaly {
            provenance: prov,
            description: format!("V8HE stream has unexpected stream_type 0x{stream_type:08X}"),
        });
    }
    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let region_count = u32::from_le_bytes(data[24..28].try_into().unwrap()) as usize;

    // v2: extension block, then fatal message bytes, then the region table.
    let mut ext = None;
    let mut table_off = HEADER_SIZE;
    if version >= 2 {
        if data.len() < HEADER_SIZE + V2_EXT_SIZE {
            return Ok((vec![], None)); // truncated ext — nothing trustworthy
        }
        let b = &data[HEADER_SIZE..HEADER_SIZE + V2_EXT_SIZE];
        let msg_len = u32::from_le_bytes(b[24..28].try_into().unwrap()) as usize;
        let msg_len = msg_len.min(MAX_FATAL_MSG_LEN);
        let msg_start = HEADER_SIZE + V2_EXT_SIZE;
        let msg_end = msg_start.saturating_add(msg_len);
        let fatal_message = if msg_len > 0 && msg_end <= data.len() {
            Some(String::from_utf8_lossy(&data[msg_start..msg_end]).into_owned())
        } else {
            None
        };
        ext = Some(V8HeapExt {
            alloc_top_va: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            alloc_limit_va: u64::from_le_bytes(b[8..16].try_into().unwrap()),
            gc_state: u32::from_le_bytes(b[16..20].try_into().unwrap()),
            last_gc_reason: u32::from_le_bytes(b[20..24].try_into().unwrap()),
            fatal_message,
        });
        table_off = msg_end;
        if table_off > data.len() {
            return Ok((vec![], ext)); // region table unreachable
        }
    }

    let mut ranges = Vec::with_capacity(region_count.min(4096));
    for i in 0..region_count {
        let off = table_off + i * REGION_ENTRY_SIZE;
        if off + REGION_ENTRY_SIZE > data.len() {
            break; // truncated region table — decode what we have
        }
        let va = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        let size = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap()) as usize;
        let file_offset = u64::from_le_bytes(data[off + 16..off + 24].try_into().unwrap()) as usize;

        let fend = match file_offset.checked_add(size) {
            Some(e) => e,
            None => continue,
        };
        if size == 0 || fend > data.len() {
            continue; // empty or out-of-bounds region — skip, never fail the dump
        }
        ranges.push(RawMemoryRange {
            va_start: va,
            data: data[file_offset..fend].to_vec(),
            provenance: Provenance {
                stream_type: V8HE_STREAM_TYPE,
                file_offset: prov.file_offset + off as u64,
                rva: i as u32,
            },
        });
    }
    Ok((ranges, ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_prov() -> Provenance {
        Provenance {
            stream_type: 0,
            file_offset: 0,
            rva: 0,
        }
    }

    /// Build a minimal V8HE stream: 2 regions of 16 and 8 bytes.
    /// `version` 1 = v1 layout, 2 = v2 layout (ext + message before table).
    fn make_v8he(version: u32) -> Vec<u8> {
        let region_count: u32 = 2;
        let cage_base: u64 = 0x0000_0100_0000_0000;
        let isolate_va: u64 = 0x0000_0200_0000_0000;
        let r0_va: u64 = cage_base;
        let r1_va: u64 = cage_base + 0x1000_0000;
        let r0_size: u64 = 16;
        let r1_size: u64 = 8;

        let msg = b"Check failed: !ptr->IsSmi().";
        let ext_size = if version >= 2 {
            V2_EXT_SIZE + msg.len()
        } else {
            0
        };
        let data_start = (HEADER_SIZE + ext_size + 2 * REGION_ENTRY_SIZE) as u64;
        let r0_off = data_start;
        let r1_off = data_start + r0_size;

        let mut buf = Vec::new();
        // header
        buf.extend_from_slice(&V8HE_STREAM_TYPE.to_le_bytes());
        buf.extend_from_slice(&version.to_le_bytes());
        buf.extend_from_slice(&cage_base.to_le_bytes());
        buf.extend_from_slice(&isolate_va.to_le_bytes());
        buf.extend_from_slice(&region_count.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        if version >= 2 {
            buf.extend_from_slice(&0xAAAAu64.to_le_bytes()); // alloc_top
            buf.extend_from_slice(&0xBBBBu64.to_le_bytes()); // alloc_limit
            buf.extend_from_slice(&3u32.to_le_bytes()); // gc_state
            buf.extend_from_slice(&7u32.to_le_bytes()); // last_gc_reason
            buf.extend_from_slice(&(msg.len() as u32).to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
            buf.extend_from_slice(msg);
        }
        // region table
        buf.extend_from_slice(&r0_va.to_le_bytes());
        buf.extend_from_slice(&r0_size.to_le_bytes());
        buf.extend_from_slice(&r0_off.to_le_bytes());
        buf.extend_from_slice(&r1_va.to_le_bytes());
        buf.extend_from_slice(&r1_size.to_le_bytes());
        buf.extend_from_slice(&r1_off.to_le_bytes());
        // region bytes
        buf.extend_from_slice(&[0xAA; 16]);
        buf.extend_from_slice(&[0xBB; 8]);
        buf
    }

    #[test]
    fn decode_two_regions() {
        let data = make_v8he(1);
        let (ranges, ext) = decode_v8heap(&data, dummy_prov()).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].va_start, 0x0000_0100_0000_0000);
        assert_eq!(ranges[0].data.len(), 16);
        assert_eq!(&ranges[0].data, &[0xAA; 16]);
        assert_eq!(ranges[1].va_start, 0x0000_0100_1000_0000);
        assert_eq!(ranges[1].data.len(), 8);
        assert_eq!(&ranges[1].data, &[0xBB; 8]);
        // provenance tagged with the V8HE stream type
        assert_eq!(ranges[0].provenance.stream_type, V8HE_STREAM_TYPE);
        assert!(ext.is_none());
    }

    #[test]
    fn v2_decodes_ext_and_message() {
        let data = make_v8he(2);
        let (ranges, ext) = decode_v8heap(&data, dummy_prov()).unwrap();
        let ext = ext.expect("v2 ext present");
        assert_eq!(ext.alloc_top_va, 0xAAAA);
        assert_eq!(ext.alloc_limit_va, 0xBBBB);
        assert_eq!(ext.gc_state, 3);
        assert_eq!(ext.last_gc_reason, 7);
        assert_eq!(
            ext.fatal_message.as_deref(),
            Some("Check failed: !ptr->IsSmi().")
        );
        // regions still decode after the variable-length message
        assert_eq!(ranges.len(), 2);
        assert_eq!(&ranges[0].data, &[0xAA; 16]);
    }

    #[test]
    fn v2_truncated_ext_yields_nothing() {
        let data = make_v8he(2);
        let truncated = &data[..HEADER_SIZE + 10];
        let (ranges, ext) = decode_v8heap(truncated, dummy_prov()).unwrap();
        assert!(ranges.is_empty());
        assert!(ext.is_none());
    }

    #[test]
    fn wrong_stream_type_is_error() {
        let mut data = make_v8he(1);
        data[0..4].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
        let err = decode_v8heap(&data, dummy_prov()).unwrap_err();
        assert!(err.description.contains("unexpected stream_type"));
    }

    #[test]
    fn truncated_header_is_empty() {
        let data = vec![0u8; 8];
        let (ranges, ext) = decode_v8heap(&data, dummy_prov()).unwrap();
        assert!(ranges.is_empty());
        assert!(ext.is_none());
    }

    #[test]
    fn out_of_bounds_region_is_skipped() {
        let mut data = make_v8he(1);
        // point region 1 past end-of-stream
        let r1_off_field = HEADER_SIZE + REGION_ENTRY_SIZE + 16;
        let huge: u64 = 0xFFFF_FFFF;
        data[r1_off_field..r1_off_field + 8].copy_from_slice(&huge.to_le_bytes());
        let (ranges, _) = decode_v8heap(&data, dummy_prov()).unwrap();
        assert_eq!(ranges.len(), 1); // only the valid region survives
    }
}

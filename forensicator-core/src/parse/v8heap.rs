use crate::error::{Anomaly, Provenance};
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

/// Decode the V8HE user-extension stream into memory ranges.
///
/// Wire format (little-endian), emitted by the handler's `V8HeapCapture`:
///   V8HeapExtensionHeader (32 B)
///   V8HeapRegion[region_count] (24 B each)
///   region bytes (concatenated, in region order)
///
/// Each region's `file_offset` is relative to the start of the stream. The
/// returned ranges are ingested into the address space just like ordinary
/// memory ranges, after which the existing V8 JIT-frame decoder works
/// unmodified.
pub fn decode_v8heap(data: &[u8], prov: Provenance) -> Result<Vec<RawMemoryRange>, Anomaly> {
    if data.len() < HEADER_SIZE {
        return Ok(vec![]);
    }
    let stream_type = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if stream_type != V8HE_STREAM_TYPE {
        return Err(Anomaly {
            provenance: prov,
            description: format!(
                "V8HE stream has unexpected stream_type 0x{stream_type:08X}"
            ),
        });
    }
    let region_count = u32::from_le_bytes(data[24..28].try_into().unwrap()) as usize;

    let mut ranges = Vec::with_capacity(region_count.min(4096));
    for i in 0..region_count {
        let off = HEADER_SIZE + i * REGION_ENTRY_SIZE;
        if off + REGION_ENTRY_SIZE > data.len() {
            break; // truncated region table — decode what we have
        }
        let va = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        let size = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap()) as usize;
        let file_offset =
            u64::from_le_bytes(data[off + 16..off + 24].try_into().unwrap()) as usize;

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
    Ok(ranges)
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
    fn make_v8he() -> Vec<u8> {
        let region_count: u32 = 2;
        let cage_base: u64 = 0x0000_0100_0000_0000;
        let isolate_va: u64 = 0x0000_0200_0000_0000;
        let r0_va: u64 = cage_base;
        let r1_va: u64 = cage_base + 0x1000_0000;
        let r0_size: u64 = 16;
        let r1_size: u64 = 8;

        let data_start = (HEADER_SIZE + 2 * REGION_ENTRY_SIZE) as u64;
        let r0_off = data_start;
        let r1_off = data_start + r0_size;

        let mut buf = Vec::new();
        // header
        buf.extend_from_slice(&V8HE_STREAM_TYPE.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes()); // version
        buf.extend_from_slice(&cage_base.to_le_bytes());
        buf.extend_from_slice(&isolate_va.to_le_bytes());
        buf.extend_from_slice(&region_count.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
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
        let data = make_v8he();
        let ranges = decode_v8heap(&data, dummy_prov()).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].va_start, 0x0000_0100_0000_0000);
        assert_eq!(ranges[0].data.len(), 16);
        assert_eq!(&ranges[0].data, &[0xAA; 16]);
        assert_eq!(ranges[1].va_start, 0x0000_0100_1000_0000);
        assert_eq!(ranges[1].data.len(), 8);
        assert_eq!(&ranges[1].data, &[0xBB; 8]);
        // provenance tagged with the V8HE stream type
        assert_eq!(ranges[0].provenance.stream_type, V8HE_STREAM_TYPE);
    }

    #[test]
    fn wrong_stream_type_is_error() {
        let mut data = make_v8he();
        data[0..4].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
        let err = decode_v8heap(&data, dummy_prov()).unwrap_err();
        assert!(err.description.contains("unexpected stream_type"));
    }

    #[test]
    fn truncated_header_is_empty() {
        let data = vec![0u8; 8];
        let ranges = decode_v8heap(&data, dummy_prov()).unwrap();
        assert!(ranges.is_empty());
    }

    #[test]
    fn out_of_bounds_region_is_skipped() {
        let mut data = make_v8he();
        // point region 1 past end-of-stream
        let r1_off_field = HEADER_SIZE + REGION_ENTRY_SIZE + 16;
        let huge: u64 = 0xFFFF_FFFF;
        data[r1_off_field..r1_off_field + 8].copy_from_slice(&huge.to_le_bytes());
        let ranges = decode_v8heap(&data, dummy_prov()).unwrap();
        assert_eq!(ranges.len(), 1); // only the valid region survives
    }
}

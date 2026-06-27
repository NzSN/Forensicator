use crate::error::{Anomaly, Provenance};

#[derive(Debug, Clone)]
pub struct RawMemoryRange {
    pub va_start: u64,
    pub data: Vec<u8>,
    pub provenance: Provenance,
}

pub fn decode_memory64(data: &[u8], prov: Provenance) -> Result<Vec<RawMemoryRange>, Anomaly> {
    if data.len() < 16 {
        return Ok(vec![]);
    }
    let count = u64::from_le_bytes(data[0..8].try_into().unwrap()) as usize;
    let _base_rva = u64::from_le_bytes(data[8..16].try_into().unwrap()) as usize;

    let entry_size = 16;
    let header_size = 16;
    let expected_len = header_size + count * entry_size;

    if data.len() < expected_len {
        return Err(Anomaly {
            provenance: prov,
            description: format!("truncated Memory64List: expected {expected_len}, got {}", data.len()),
        });
    }

    let mut ranges = Vec::with_capacity(count);
    for i in 0..count {
        let off = header_size + i * entry_size;
        let va_start = u64::from_le_bytes(data[off..off+8].try_into().unwrap());
        let data_size = u64::from_le_bytes(data[off+8..off+16].try_into().unwrap()) as usize;

        ranges.push(RawMemoryRange {
            va_start,
            data: vec![0u8; data_size.min(0x1000)],
            provenance: Provenance {
                stream_type: prov.stream_type,
                file_offset: prov.file_offset + off as u64,
                rva: i as u32,
            },
        });
    }
    Ok(ranges)
}

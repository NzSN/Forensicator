use crate::error::{Anomaly, Provenance};

#[derive(Debug, Clone)]
pub struct RawMemoryRange {
    pub va_start: u64,
    pub data: Vec<u8>,
    pub provenance: Provenance,
}

pub fn decode_memory_list(
    full_data: &[u8],
    data: &[u8],
    prov: Provenance,
) -> Result<Vec<RawMemoryRange>, Anomaly> {
    if data.len() < 4 {
        return Ok(vec![]);
    }
    let count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;

    let entry_size = 16;
    let header_size = 4;
    let expected_len = header_size + count * entry_size;

    if data.len() < expected_len {
        return Err(Anomaly {
            provenance: prov,
            description: format!(
                "truncated MemoryList: expected {expected_len}, got {}",
                data.len()
            ),
        });
    }

    let mut ranges = Vec::with_capacity(count);
    for i in 0..count {
        let off = header_size + i * entry_size;
        let va_start = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        let data_size = u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap()) as usize;
        let data_rva = u32::from_le_bytes(data[off + 12..off + 16].try_into().unwrap()) as usize;

        let memory_data = if data_rva + data_size <= full_data.len() {
            full_data[data_rva..data_rva + data_size].to_vec()
        } else if data_rva < full_data.len() {
            let mut d = vec![0u8; data_size];
            let available = full_data.len() - data_rva;
            d[..available].copy_from_slice(&full_data[data_rva..data_rva + available]);
            d
        } else {
            vec![0u8; data_size.min(0x1000)]
        };

        ranges.push(RawMemoryRange {
            va_start,
            data: memory_data,
            provenance: Provenance {
                stream_type: prov.stream_type,
                file_offset: prov.file_offset + off as u64,
                rva: i as u32,
            },
        });
    }
    Ok(ranges)
}
pub fn decode_memory64(data: &[u8], prov: Provenance) -> Result<Vec<RawMemoryRange>, Anomaly> {
    if data.len() < 16 {
        return Ok(vec![]);
    }
    let count = u64::from_le_bytes(data[0..8].try_into().unwrap()) as usize;
    let base_rva = u64::from_le_bytes(data[8..16].try_into().unwrap()) as usize;

    let entry_size = 16;
    let header_size = 16;
    let expected_len = header_size + count * entry_size;

    if data.len() < expected_len {
        return Err(Anomaly {
            provenance: prov,
            description: format!(
                "truncated Memory64List: expected {expected_len}, got {}",
                data.len()
            ),
        });
    }

    let mut ranges = Vec::with_capacity(count);
    let mut data_offset = base_rva;
    for i in 0..count {
        let off = header_size + i * entry_size;
        let va_start = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        let data_size = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap()) as usize;

        let memory_data = if data_offset + data_size <= data.len() {
            data[data_offset..data_offset + data_size].to_vec()
        } else if data_offset < data.len() {
            let mut d = vec![0u8; data_size];
            let available = data.len() - data_offset;
            d[..available].copy_from_slice(&data[data_offset..data_offset + available]);
            d
        } else {
            vec![0u8; data_size.min(0x1000)]
        };

        ranges.push(RawMemoryRange {
            va_start,
            data: memory_data,
            provenance: Provenance {
                stream_type: prov.stream_type,
                file_offset: prov.file_offset + off as u64,
                rva: i as u32,
            },
        });
        data_offset = data_offset.saturating_add(data_size);
    }
    Ok(ranges)
}

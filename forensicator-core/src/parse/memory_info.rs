use crate::error::{Anomaly, Provenance};

#[derive(Debug, Clone)]
pub struct RawMemoryInfoEntry {
    pub va_start: u64,
    pub size: u64,
    pub protection: u32,
    pub state: u32,
    pub mem_type: u32,
}

pub fn decode_memory_info_list(data: &[u8], prov: Provenance) -> Result<Vec<RawMemoryInfoEntry>, Anomaly> {
    if data.len() < 16 {
        return Ok(vec![]);
    }
    let size_of_header = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let size_of_entry  = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let count = u64::from_le_bytes(data[8..16].try_into().unwrap()) as usize;

    if size_of_entry == 0 || count == 0 {
        return Ok(vec![]);
    }

    let expected_len = size_of_header + count * size_of_entry;
    if data.len() < expected_len {
        return Err(Anomaly {
            provenance: prov,
            description: format!("truncated MemoryInfoList: expected {expected_len}, got {}", data.len()),
        });
    }

    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let off = size_of_header + i * size_of_entry;
        if off + size_of_entry > data.len() { break; }

        let va_start    = u64::from_le_bytes(data[off..off+8].try_into().unwrap());
        let size        = u64::from_le_bytes(data[off+8..off+16].try_into().unwrap());
        let mem_type    = u32::from_le_bytes(data[off+16..off+20].try_into().unwrap());
        let protection  = u32::from_le_bytes(data[off+20..off+24].try_into().unwrap());
        let state       = u32::from_le_bytes(data[off+28..off+32].try_into().unwrap());

        entries.push(RawMemoryInfoEntry { va_start, size, protection, state, mem_type });
    }
    Ok(entries)
}

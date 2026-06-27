use crate::arch::RegisterSet;
use crate::error::{Anomaly, Provenance};
use crate::model::Thread;

pub fn decode_thread_list(data: &[u8], prov: Provenance) -> Result<Vec<Thread>, Anomaly> {
    if data.len() < 4 {
        return Ok(vec![]);
    }
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let entry_size = 48;
    let expected_len = 4 + count * entry_size;

    if data.len() < expected_len {
        return Err(Anomaly {
            provenance: prov,
            description: format!("truncated ThreadList: expected {expected_len}, got {}", data.len()),
        });
    }

    let mut threads = Vec::with_capacity(count);
    for i in 0..count {
        let off = 4 + i * entry_size;
        let id = u32::from_le_bytes(data[off..off+4].try_into().unwrap());
        let stack_size = u32::from_le_bytes(data[off+16..off+20].try_into().unwrap()) as u64;
        let teb_va = u64::from_le_bytes(data[off+24..off+32].try_into().unwrap());
        let stack_va = u64::from_le_bytes(data[off+32..off+40].try_into().unwrap());

        threads.push(Thread {
            id,
            registers: RegisterSet::new(),
            stack_va,
            stack_size,
            teb_va,
            provenance: Provenance {
                stream_type: prov.stream_type,
                file_offset: prov.file_offset + off as u64,
                rva: i as u32,
            },
        });
    }
    Ok(threads)
}

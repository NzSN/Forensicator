use crate::arch::RegisterSet;
use crate::error::{Anomaly, Provenance};
use crate::model::Thread;

/// MINIDUMP_THREAD layout (48 bytes):
///   +0:  ThreadId (u32)
///   +4:  SuspendCount (u32)
///   +8:  PriorityClass (u32)
///  +12:  Priority (u32)
///  +16:  Teb (u64)
///  +24:  Stack.StartOfMemoryRange (u64)   — stack_va
///  +32:  Stack.Memory.DataSize (u32)       — stack allocation size
///  +36:  Stack.Memory.Rva (u32)            — stack data RVA in dump
///  +40:  ThreadContext.DataSize (u32)
///  +44:  ThreadContext.Rva (u32)
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
            description: format!(
                "truncated ThreadList: expected {expected_len}, got {}",
                data.len()
            ),
        });
    }

    let mut threads = Vec::with_capacity(count);
    for i in 0..count {
        let off = 4 + i * entry_size;
        let id = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let teb_va = u64::from_le_bytes(data[off + 16..off + 24].try_into().unwrap());
        let stack_va = u64::from_le_bytes(data[off + 24..off + 32].try_into().unwrap());
        let stack_size = u32::from_le_bytes(data[off + 32..off + 36].try_into().unwrap()) as u64;

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

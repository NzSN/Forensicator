use crate::error::{Anomaly, Provenance};
use crate::model::Module;

pub fn decode_module_list(data: &[u8], prov: Provenance) -> Result<Vec<Module>, Anomaly> {
    if data.len() < 4 {
        return Ok(vec![]);
    }
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let entry_size = 108;
    let expected_len = 4 + count * entry_size;

    if data.len() < expected_len {
        return Err(Anomaly {
            provenance: prov,
            description: format!("truncated ModuleList: expected {expected_len}, got {}", data.len()),
        });
    }

    let mut modules = Vec::with_capacity(count);
    for i in 0..count {
        let off = 4 + i * entry_size;
        let base_va = u64::from_le_bytes(data[off..off+8].try_into().unwrap());
        let size = u64::from_le_bytes(data[off+8..off+16].try_into().unwrap());
        let checksum = u32::from_le_bytes(data[off+16..off+20].try_into().unwrap());

        let name_off = off + 48;
        let mut name_bytes = Vec::new();
        for j in (name_off..name_off+64).step_by(2) {
            if j+1 >= data.len() { break; }
            let wch = u16::from_le_bytes([data[j], data[j+1]]);
            if wch == 0 { break; }
            name_bytes.push(wch);
        }
        let name = String::from_utf16_lossy(&name_bytes);

        let cv_off = off + 72;
        let mut guid = [0u8; 16];
        if cv_off + 16 <= data.len() {
            guid.copy_from_slice(&data[cv_off..cv_off+16]);
        }
        let has_cv = guid != [0u8; 16];

        let pdb_off = cv_off + 20;
        let mut pdb_name = None;
        if has_cv && pdb_off < data.len() {
            let end = (pdb_off..data.len()).find(|&j| data[j] == 0).unwrap_or(data.len());
            if end > pdb_off {
                pdb_name = Some(String::from_utf8_lossy(&data[pdb_off..end]).to_string());
            }
        }

        modules.push(Module {
            name, base_va, size, checksum,
            codeview_guid: if has_cv { Some(guid) } else { None },
            pdb_name,
            provenance: Provenance {
                stream_type: prov.stream_type,
                file_offset: prov.file_offset + off as u64,
                rva: i as u32,
            },
        });
    }
    Ok(modules)
}

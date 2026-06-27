use crate::error::{Anomaly, Provenance};
use crate::model::Module;

/// MINIDUMP_MODULE layout (x64, 108 bytes):
///   +0:  BaseOfImage (u64)
///   +8:  SizeOfImage (u32)
///  +12:  CheckSum (u32)
///  +16:  TimeDateStamp (u32)
///  +20:  ModuleNameRva (u32)  — RVA to nul-terminated UTF-16 name
///  +24:  VersionInfo (VS_FIXEDFILEINFO, 52 bytes)
///  +76:  CvRecord { u32 DataSize, u32 Rva }
///  +84:  MiscRecord { u32 DataSize, u32 Rva }
///  +92:  Reserved0 (u64)
/// +100:  Reserved1 (u64)
///
/// `full_data` is the complete dump file bytes for RVA resolution.
pub fn decode_module_list(
    data: &[u8],
    full_data: &[u8],
    prov: Provenance,
) -> Result<Vec<Module>, Anomaly> {
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
        let mod_size = u32::from_le_bytes(data[off+8..off+12].try_into().unwrap()) as u64;
        let checksum = u32::from_le_bytes(data[off+12..off+16].try_into().unwrap());

        // Module name via ModuleNameRva (UTF-16, nul-terminated)
        let name_rva = u32::from_le_bytes([data[off+20], data[off+21], data[off+22], data[off+23]]);
        let name = read_utf16_at_rva(full_data, name_rva).unwrap_or_default();

        // CV record (RSDS at +76: { DataSize u32, Rva u32 })
        let cv_size = u32::from_le_bytes(data[off+76..off+80].try_into().unwrap());
        let cv_rva  = u32::from_le_bytes(data[off+80..off+84].try_into().unwrap());

        let (codeview_guid, pdb_name) = if cv_size >= 24 {
            let cv_start = cv_rva as usize;
            let cv_end = cv_start.saturating_add(cv_size as usize);
            if cv_end <= full_data.len() {
                let cv_bytes = &full_data[cv_start..cv_end];
                let sig = u32::from_le_bytes([cv_bytes[0], cv_bytes[1], cv_bytes[2], cv_bytes[3]]);
                // RSDS signature = 0x53445352 ("SDSR" in LE)
                if sig == 0x53445352 && cv_bytes.len() >= 24 {
                    let mut guid = [0u8; 16];
                    guid.copy_from_slice(&cv_bytes[4..20]);
                    let pdb = if cv_bytes.len() > 24 {
                        let pdb_end = cv_bytes[24..].iter().position(|&b| b == 0).unwrap_or(cv_bytes.len() - 24);
                        Some(String::from_utf8_lossy(&cv_bytes[24..24+pdb_end]).to_string())
                    } else {
                        None
                    };
                    (Some(guid), pdb)
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        modules.push(Module {
            name,
            base_va,
            size: mod_size,
            checksum,
            codeview_guid,
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

fn read_utf16_at_rva(full_data: &[u8], rva: u32) -> Option<String> {
    let start = rva as usize;
    if start + 4 >= full_data.len() {
        return None;
    }
    // MINIDUMP_STRING: 4-byte Length (in bytes), then UTF-16 buffer
    let _len = u32::from_le_bytes([full_data[start], full_data[start+1], full_data[start+2], full_data[start+3]]);
    let buf_start = start + 4;
    let mut units = Vec::new();
    let mut j = buf_start;
    while j + 1 < full_data.len() {
        let w = u16::from_le_bytes([full_data[j], full_data[j+1]]);
        if w == 0 { break; }
        units.push(w);
        j += 2;
    }
    if units.is_empty() {
        None
    } else {
        Some(String::from_utf16_lossy(&units))
    }
}

use crate::error::{Anomaly, Provenance};
use crate::model::{CpuArch, OsPlatform, SystemInfo};

const MIN_SIZE: usize = 56;

pub fn decode_system_info(data: &[u8], prov: Provenance) -> Result<SystemInfo, Anomaly> {
    if data.len() < MIN_SIZE {
        return Err(Anomaly { provenance: prov.clone(), description: "truncated SystemInfo stream".into() });
    }

    let cpu = u16::from_le_bytes([data[8], data[9]]);
    let cpu = match cpu {
        0 => CpuArch::X86,
        9 => CpuArch::X64,
        _ => return Err(Anomaly { provenance: prov, description: format!("unsupported CPU arch {cpu}") }),
    };

    let os_id = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
    let os = match os_id {
        1 => OsPlatform::Windows,
        _ => OsPlatform::Windows,
    };

    let maj = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
    let min = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
    let bld = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
    let rev = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);

    Ok(SystemInfo { os, cpu, version: (maj, min, bld, rev), provenance: prov })
}

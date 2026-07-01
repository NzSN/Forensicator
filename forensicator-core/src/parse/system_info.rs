use crate::error::{Anomaly, Provenance};
use crate::model::{CpuArch, OsPlatform, SystemInfo};

const MIN_SIZE: usize = 56;

/// MINIDUMP_SYSTEM_INFO layout (x64 build):
///   +0: ProcessorArchitecture (u16)   — 0=x86, 5=ARM, 9=AMD64, 12=ARM64
///   +2: ProcessorLevel (u16)
///   +4: ProcessorRevision (u16)
///   +6: NumberOfProcessors (u8) / ProductType (u8)
///   +8: MajorVersion (u32)
///  +12: MinorVersion (u32)
///  +16: BuildNumber (u32)
///  +20: PlatformId (u32)   — VER_PLATFORM_WIN32_NT = 2
///  +24: CSDVersionRva (u32)
///  +28: SuiteMask (u16) / Reserved2 (u16)
///  +32: ProcessorFeatures[2] (u64[2])
pub fn decode_system_info(data: &[u8], prov: Provenance) -> Result<SystemInfo, Anomaly> {
    if data.len() < MIN_SIZE {
        return Err(Anomaly {
            provenance: prov.clone(),
            description: "truncated SystemInfo stream".into(),
        });
    }

    let cpu_arch = u16::from_le_bytes([data[0], data[1]]);
    let cpu = match cpu_arch {
        0 => CpuArch::X86,
        9 => CpuArch::X64,
        12 => CpuArch::Arm64,
        _ => {
            return Err(Anomaly {
                provenance: prov,
                description: format!("unsupported CPU arch {cpu_arch}"),
            });
        }
    };

    let platform_id = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
    let os = match platform_id {
        2 => OsPlatform::Windows, // VER_PLATFORM_WIN32_NT
        _ => OsPlatform::Windows,
    };

    let maj = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let min = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let bld = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
    let rev = 0; // UBR not available in minidump — CDB reads it from live registry

    Ok(SystemInfo {
        os,
        cpu,
        version: (maj, min, bld, rev),
        provenance: prov,
    })
}

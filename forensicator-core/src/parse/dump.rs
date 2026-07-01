use std::fs;
use std::path::Path;

use crate::error::{Anomaly, FatalError, Provenance};
use crate::model::{Dump, MemState, MemType, MemoryRegionInfo, Protection, RegionClass};
use crate::parse::{
    directory, exception, header, memory, memory_info, module_list, system_info, thread_list,
};

/// Open a minidump file and parse it into a `Dump`.
pub fn open(path: impl AsRef<Path>) -> Result<Dump, FatalError> {
    let data = fs::read(path).map_err(|e| FatalError::Io(e.to_string()))?;
    from_bytes(&data)
}

/// Parse a minidump from a byte slice.
pub fn from_bytes(data: &[u8]) -> Result<Dump, FatalError> {
    let mut anomalies: Vec<Anomaly> = Vec::new();

    let hdr = header::read_header(data)?;

    let dir = directory::read_directory(data, hdr.stream_directory_rva, hdr.stream_count)?;

    let file_size = data.len() as u64;

    let system_info = decode_optional(
        data,
        &dir,
        directory::stream_types::SYSTEM_INFO,
        &mut anomalies,
        |bytes, prov| system_info::decode_system_info(bytes, prov).map_err(|a| vec![a]),
    );

    let modules = {
        let entry = dir.find(directory::stream_types::MODULE_LIST);
        match entry {
            Some(e) => {
                let start = e.rva as usize;
                let end = start.saturating_add(e.size as usize);
                if end > data.len() {
                    anomalies.push(Anomaly {
                        provenance: Provenance {
                            stream_type: directory::stream_types::MODULE_LIST,
                            file_offset: start as u64,
                            rva: 0,
                        },
                        description: "ModuleList extends beyond file".into(),
                    });
                    vec![]
                } else {
                    let stream_bytes = &data[start..end];
                    let prov = Provenance {
                        stream_type: directory::stream_types::MODULE_LIST,
                        file_offset: start as u64,
                        rva: 0,
                    };
                    module_list::decode_module_list(stream_bytes, data, prov).unwrap_or_else(
                        |err| {
                            anomalies.push(err);
                            vec![]
                        },
                    )
                }
            }
            None => vec![],
        }
    };

    let threads = decode_optional(
        data,
        &dir,
        directory::stream_types::THREAD_LIST,
        &mut anomalies,
        |bytes, prov| thread_list::decode_thread_list(bytes, prov).map_err(|a| vec![a]),
    )
    .unwrap_or_default();

    let memory_ranges: Vec<memory::RawMemoryRange> = {
        let mut ranges = decode_optional(
            data,
            &dir,
            directory::stream_types::MEMORY_64_LIST,
            &mut anomalies,
            |bytes, prov| memory::decode_memory64(bytes, prov).map_err(|a| vec![a]),
        )
        .unwrap_or_default();
        if ranges.is_empty() {
            let entry = dir.find(directory::stream_types::MEMORY_LIST);
            if let Some(e) = entry {
                let start = e.rva as usize;
                let end = start.saturating_add(e.size as usize);
                if end <= data.len() {
                    let stream_bytes = &data[start..end];
                    let prov = Provenance {
                        stream_type: directory::stream_types::MEMORY_LIST,
                        file_offset: start as u64,
                        rva: 0,
                    };
                    ranges = memory::decode_memory_list(data, stream_bytes, prov).unwrap_or_else(
                        |err| {
                            anomalies.push(err);
                            vec![]
                        },
                    );
                }
            }
        }
        ranges
    };

    let memory_info_entries: Vec<memory_info::RawMemoryInfoEntry> = decode_optional(
        data,
        &dir,
        directory::stream_types::MEMORY_INFO_LIST,
        &mut anomalies,
        |bytes, prov| memory_info::decode_memory_info_list(bytes, prov).map_err(|a| vec![a]),
    )
    .unwrap_or_default();

    let memory_regions: Vec<MemoryRegionInfo> = memory_ranges
        .into_iter()
        .map(|mr| {
            let info = memory_info_entries
                .iter()
                .find(|mi| mi.va_start == mr.va_start);
            MemoryRegionInfo {
                va_start: mr.va_start,
                size: mr.data.len() as u64,
                data: mr.data,
                protection: Protection::new(info.map(|i| i.protection).unwrap_or(0)),
                state: info
                    .and_then(|i| MemState::from_u32(i.state))
                    .unwrap_or(MemState::Commit),
                mem_type: info
                    .and_then(|i| MemType::from_u32(i.mem_type))
                    .unwrap_or(MemType::Private),
                provenance: mr.provenance,
                region_class: info.and_then(|i| classify_region(i.state, i.mem_type, i.protection)),
            }
        })
        .collect();

    let exception = decode_optional(
        data,
        &dir,
        directory::stream_types::EXCEPTION,
        &mut anomalies,
        |bytes, prov| exception::decode_exception(bytes, prov).map_err(|a| vec![a]),
    );

    Ok(Dump {
        system_info,
        modules,
        threads,
        memory_regions,
        exception,
        anomalies,
        file_size,
    })
}

fn classify_region(state: u32, mem_type: u32, _protection: u32) -> Option<RegionClass> {
    if state == 2 {
        return None;
    }
    match mem_type {
        2 => Some(RegionClass::Image),
        1 => Some(RegionClass::Mapped),
        0 => Some(RegionClass::Private),
        _ => Some(RegionClass::Other),
    }
}

fn decode_optional<T>(
    data: &[u8],
    dir: &directory::StreamDirectory,
    stream_type: u32,
    anomalies: &mut Vec<Anomaly>,
    decoder: impl FnOnce(&[u8], Provenance) -> Result<T, Vec<Anomaly>>,
) -> Option<T> {
    let entry = dir.find(stream_type);
    let entry = entry?;

    let start = entry.rva as usize;
    let end = start.saturating_add(entry.size as usize);
    if end > data.len() {
        anomalies.push(Anomaly {
            provenance: Provenance {
                stream_type,
                file_offset: start as u64,
                rva: 0,
            },
            description: format!("stream 0x{stream_type:08X} extends beyond file"),
        });
        return None;
    }

    let bytes = &data[start..end];
    let prov = Provenance {
        stream_type,
        file_offset: start as u64,
        rva: 0,
    };

    match decoder(bytes, prov) {
        Ok(v) => Some(v),
        Err(mut errs) => {
            anomalies.append(&mut errs);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minidump_bytes() -> Vec<u8> {
        let mut buf = vec![0u8; 256];
        buf[0] = 0x4D;
        buf[1] = 0x44;
        buf[2] = 0x4D;
        buf[3] = 0x50;
        buf[4] = 0x93;
        buf[5] = 0xA7;
        buf[8] = 1;
        buf[9] = 0;
        buf[10] = 0;
        buf[11] = 0;
        buf[12] = 64;
        buf[13] = 0;
        buf[14] = 0;
        buf[15] = 0;
        buf[64] = 7; // stream_type = SystemInfo
        buf[68] = 56; // size = 56
        buf[72] = 128; // rva = 128
        buf[128] = 0;
        buf[129] = 0;
        buf[136] = 9;
        buf[137] = 0; // AMD64
        buf
    }

    #[test]
    fn parse_valid_minimal_dump() {
        let data = make_minidump_bytes();
        let dump = from_bytes(&data).unwrap();
        assert!(dump.system_info.is_some());
        assert!(dump.modules.is_empty());
        assert!(dump.anomalies.is_empty());
    }

    #[test]
    fn bad_magic_returns_error() {
        let mut data = make_minidump_bytes();
        data[0] = 0xFF;
        let err = from_bytes(&data).unwrap_err();
        assert!(matches!(err, FatalError::BadMagic { .. }));
    }

    #[test]
    fn missing_directory_returns_error() {
        let mut data = make_minidump_bytes();
        data[12] = 255;
        data[13] = 255;
        data[14] = 255;
        data[15] = 255;
        let err = from_bytes(&data).unwrap_err();
        assert!(matches!(err, FatalError::DirectoryOutOfBounds { .. }));
    }

    #[test]
    fn too_small_is_error() {
        let data = vec![0u8; 10];
        let err = from_bytes(&data).unwrap_err();
        assert!(matches!(err, FatalError::TooSmall { .. }));
    }
}

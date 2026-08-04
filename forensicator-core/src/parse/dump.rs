use std::fs;
use std::path::Path;

use crate::error::{Anomaly, FatalError, Provenance};
use crate::model::{Dump, MemState, MemType, MemoryRegionInfo, Protection, RegionClass};
use crate::parse::{
    comment_a, crashpad, directory, exception, header, memory, memory_info, module_list,
    system_info, thread_list, v8heap,
};

/// Open a minidump file and parse it into a `Dump`.
pub fn open(path: impl AsRef<Path>) -> Result<Dump, FatalError> {
    let data = fs::read(path).map_err(|e| FatalError::Io(e.to_string()))?;
    from_bytes(&data)
}

/// Parse stream data from a byte slice with a pre-parsed directory and header.
/// This is the DecodeStream step: called once the header and directory are validated.
/// Mirrors Forensicator.tla `DecodeStream(stream_type)` — called once per stream type.
pub fn parse_streams(
    data: &[u8],
    dir: &directory::StreamDirectory,
    file_size: u64,
) -> Result<Dump, FatalError> {
    from_bytes_inner(data, dir, file_size)
}

/// Parse a minidump from a byte slice.
pub fn from_bytes(data: &[u8]) -> Result<Dump, FatalError> {
    let hdr = header::read_header(data)?;
    let dir = directory::read_directory(data, hdr.stream_directory_rva, hdr.stream_count)?;
    let file_size = data.len() as u64;
    from_bytes_inner(data, &dir, file_size)
}

fn from_bytes_inner(
    data: &[u8],
    dir: &directory::StreamDirectory,
    file_size: u64,
) -> Result<Dump, FatalError> {
    let mut anomalies: Vec<Anomaly> = Vec::new();

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

    let threads = decode_optional_with_dump(
        data,
        &dir,
        directory::stream_types::THREAD_LIST,
        data,
        &mut anomalies,
        |bytes, dump_bytes, prov| {
            thread_list::decode_thread_list_with_dump(bytes, prov, dump_bytes).map_err(|a| vec![a])
        },
    )
    .unwrap_or_default();

    let mut memory_ranges: Vec<memory::RawMemoryRange> = {
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

    // V8 heap snapshot (V8HE user stream): additional heap regions that let a
    // stack-only dump resolve JIT frames. Ingested into the address space just
    // like ordinary memory ranges. Absent on dumps not produced with the
    // instrumented handler.
    let mut v8heap_ext = None;
    if let Some(entry) = dir.find(v8heap::V8HE_STREAM_TYPE) {
        let start = entry.rva as usize;
        let end = start.saturating_add(entry.size as usize).min(data.len());
        if end > start {
            let stream_bytes = &data[start..end];
            let prov = Provenance {
                stream_type: v8heap::V8HE_STREAM_TYPE,
                file_offset: start as u64,
                rva: 0,
            };
            match v8heap::decode_v8heap(stream_bytes, prov) {
                // Prepend V8HE regions BEFORE standard MemoryList ranges so they
                // take priority: build_address_space's add_region rejects overlaps,
                // and MemoryList fragments (small heap captures) would otherwise
                // mask the larger V8HE pages that contain the decoder's objects.
                Ok((v8_ranges, ext)) => {
                    v8heap_ext = ext;
                    let mut combined = v8_ranges;
                    combined.append(&mut memory_ranges);
                    memory_ranges = combined;
                }
                Err(anom) => anomalies.push(anom),
            }
        }
    }

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

    let memory_info: Vec<crate::model::MemoryInfoEntry> = memory_info_entries
        .iter()
        .map(|mi| crate::model::MemoryInfoEntry {
            va_start: mi.va_start,
            size: mi.size,
            protection: mi.protection,
            state: MemState::from_u32(mi.state).unwrap_or(MemState::Free),
            mem_type: MemType::from_u32(mi.mem_type).unwrap_or(MemType::Private),
        })
        .collect();

    let exception = decode_optional_with_dump(
        data,
        &dir,
        directory::stream_types::EXCEPTION,
        data, // pass full dump for context RVA resolution
        &mut anomalies,
        |bytes, dump_bytes, prov| {
            exception::decode_exception_with_dump(bytes, prov, dump_bytes).map_err(|a| vec![a])
        },
    );

    let mut annotations: Vec<(String, String)> = decode_optional(
        data,
        &dir,
        directory::stream_types::COMMENT_A,
        &mut anomalies,
        |bytes, prov| comment_a::decode_comment_a(bytes, prov).map_err(|a| vec![a]),
    )
    .unwrap_or_default()
    .into_iter()
    .map(|a| (a.key, a.value))
    .collect();

    // Crashpad annotations (stream 0x43500001): header with annotation RVA pointer
    if let Some(entry) = dir.find(0x43500001) {
        let start = entry.rva as usize;
        let end = (start + entry.size as usize).min(data.len());
        let stream_bytes = &data[start..end];

        if let Some(ann_rva) = crashpad::extract_annotation_rva(stream_bytes) {
            let ann_start = ann_rva as usize;
            if ann_start < data.len() {
                let prov = Provenance {
                    stream_type: 0x43500001,
                    file_offset: start as u64,
                    rva: ann_rva,
                };
                if let Ok(mut crashpad_anns) =
                    crashpad::decode_crashpad_annotations(data, ann_start, prov)
                {
                    for a in crashpad_anns.drain(..) {
                        annotations.push((a.key, a.value));
                    }

                    if let Some(obj_rva) = crashpad::extract_annotation_objects_rva(stream_bytes) {
                        let obj_start = obj_rva as usize;
                        if obj_start < data.len() {
                            let prov = Provenance {
                                stream_type: 0x43500001,
                                file_offset: start as u64,
                                rva: obj_rva,
                            };
                            if let Ok(mut objs) =
                                crashpad::decode_crashpad_annotation_objects(data, obj_start, prov)
                            {
                                for a in objs.drain(..) {
                                    annotations.push((a.key, a.value));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(Dump {
        system_info,
        modules,
        threads,
        memory_regions,
        exception,
        anomalies,
        annotations,
        memory_info,
        v8heap_ext,
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

fn decode_optional_with_dump<T>(
    data: &[u8],
    dir: &directory::StreamDirectory,
    stream_type: u32,
    dump_data: &[u8],
    anomalies: &mut Vec<Anomaly>,
    decoder: impl FnOnce(&[u8], &[u8], Provenance) -> Result<T, Vec<Anomaly>>,
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

    match decoder(bytes, dump_data, prov) {
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

    /// A minimal V8HE stream: 2 regions (16 and 8 bytes). Mirrors the handler's
    /// V8HeapCapture serialization.
    fn make_v8he_stream() -> Vec<u8> {
        const HEADER_SIZE: usize = 32;
        const REGION_ENTRY_SIZE: usize = 24;
        let cage_base: u64 = 0x0000_0100_0000_0000;
        let isolate_va: u64 = 0x0000_0200_0000_0000;
        let r0_va: u64 = cage_base;
        let r1_va: u64 = cage_base + 0x1000_0000;
        let data_start = (HEADER_SIZE + 2 * REGION_ENTRY_SIZE) as u64;

        let mut buf = Vec::new();
        buf.extend_from_slice(&0x45483856u32.to_le_bytes()); // stream_type 'V8HE'
        buf.extend_from_slice(&1u32.to_le_bytes()); // version
        buf.extend_from_slice(&cage_base.to_le_bytes());
        buf.extend_from_slice(&isolate_va.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes()); // region_count
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        // region table
        buf.extend_from_slice(&r0_va.to_le_bytes());
        buf.extend_from_slice(&16u64.to_le_bytes());
        buf.extend_from_slice(&data_start.to_le_bytes());
        buf.extend_from_slice(&r1_va.to_le_bytes());
        buf.extend_from_slice(&8u64.to_le_bytes());
        buf.extend_from_slice(&(data_start + 16).to_le_bytes());
        // region bytes
        buf.extend_from_slice(&[0xAA; 16]);
        buf.extend_from_slice(&[0xBB; 8]);
        buf
    }

    #[test]
    fn v8heap_stream_lands_in_memory_regions() {
        let v8he = make_v8he_stream();
        let dir_rva: u32 = 32;
        let stream_rva: u32 = dir_rva + 12;
        let mut buf = vec![0u8; stream_rva as usize + v8he.len()];
        buf[0..4].copy_from_slice(b"MDMP");
        buf[4] = 0x93;
        buf[5] = 0xA7; // version 0xA793
        buf[8..12].copy_from_slice(&1u32.to_le_bytes()); // stream_count
        buf[12..16].copy_from_slice(&dir_rva.to_le_bytes());
        // directory entry: V8HE
        let d = dir_rva as usize;
        buf[d..d + 4].copy_from_slice(&0x45483856u32.to_le_bytes());
        buf[d + 4..d + 8].copy_from_slice(&(v8he.len() as u32).to_le_bytes());
        buf[d + 8..d + 12].copy_from_slice(&stream_rva.to_le_bytes());
        // stream bytes
        buf[stream_rva as usize..stream_rva as usize + v8he.len()].copy_from_slice(&v8he);

        let dump = from_bytes(&buf).unwrap();
        assert_eq!(dump.memory_regions.len(), 2, "V8HE regions not ingested");
        assert_eq!(dump.memory_regions[0].va_start, 0x0000_0100_0000_0000);
        assert_eq!(dump.memory_regions[0].data.len(), 16);
        assert_eq!(dump.memory_regions[1].va_start, 0x0000_0100_1000_0000);
        assert_eq!(dump.memory_regions[1].data, &[0xBB; 8]);
    }
}

pub mod directory;
pub mod dump;
pub mod exception;
pub mod header;
pub mod memory;
pub mod memory_info;
pub mod module_list;
pub mod system_info;
pub mod thread_list;

#[cfg(test)]
mod tests {
    use crate::error::Provenance;

    fn dummy_prov() -> Provenance {
        Provenance {
            stream_type: 0,
            file_offset: 0,
            rva: 0,
        }
    }

    #[test]
    fn decode_system_info_minimal() {
        let mut data = vec![0u8; 56];
        data[0] = 9;
        data[1] = 0; // x64 (offset 0)
        data[20] = 2; // PlatformId = VER_PLATFORM_WIN32_NT
        let si = crate::parse::system_info::decode_system_info(&data, dummy_prov()).unwrap();
        assert_eq!(si.cpu, crate::model::CpuArch::X64);
    }

    #[test]
    fn decode_system_info_truncated() {
        let data = vec![0u8; 20];
        let err = crate::parse::system_info::decode_system_info(&data, dummy_prov()).unwrap_err();
        assert!(err.description.contains("truncated"));
    }

    #[test]
    fn decode_system_info_unsupported_cpu() {
        let mut data = vec![0u8; 56];
        data[0] = 5;
        data[1] = 0; // ARM (offset 0)
        let err = crate::parse::system_info::decode_system_info(&data, dummy_prov()).unwrap_err();
        assert!(err.description.contains("unsupported CPU"));
    }

    #[test]
    fn decode_system_info_windows_x64() {
        let mut data = vec![0u8; 56];
        data[0] = 9;
        data[1] = 0; // x64 (offset 0)
        data[8] = 10; // MajorVersion
        data[16] = 0x41;
        data[17] = 0x4A; // BuildNumber 19041
        data[20] = 2;
        data[21] = 0;
        data[22] = 0;
        data[23] = 0; // PlatformId = 2
        let si = crate::parse::system_info::decode_system_info(&data, dummy_prov()).unwrap();
        assert_eq!(si.os, crate::model::OsPlatform::Windows);
        assert_eq!(si.cpu, crate::model::CpuArch::X64);
    }

    #[test]
    fn decode_thread_list_with_data() {
        let mut data = vec![0u8; 4 + 48]; // count=1, one thread
        let count: u32 = 1;
        data[0..4].copy_from_slice(&count.to_le_bytes());
        let tid: u32 = 5678;
        data[4..8].copy_from_slice(&tid.to_le_bytes()); // ThreadId at +0
        let ssz: u32 = 0x10000;
        data[4 + 32..4 + 36].copy_from_slice(&ssz.to_le_bytes()); // Stack.Memory.DataSize at +32
        let threads = crate::parse::thread_list::decode_thread_list(&data, dummy_prov()).unwrap();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].id, 5678);
        assert_eq!(threads[0].stack_size, 0x10000);
    }

    #[test]
    fn decode_empty_module_list() {
        let data = vec![0u8; 4];
        let mods =
            crate::parse::module_list::decode_module_list(&data, &data, dummy_prov()).unwrap();
        assert!(mods.is_empty());
    }

    #[test]
    fn decode_empty_thread_list() {
        let data = vec![0u8; 4];
        let threads = crate::parse::thread_list::decode_thread_list(&data, dummy_prov()).unwrap();
        assert!(threads.is_empty());
    }

    #[test]
    fn decode_empty_memory64() {
        let data = vec![0u8; 16];
        let ranges = crate::parse::memory::decode_memory64(&data, dummy_prov()).unwrap();
        assert!(ranges.is_empty());
    }

    #[test]
    fn decode_memory_info_empty() {
        let data = vec![0u8; 16];
        let entries =
            crate::parse::memory_info::decode_memory_info_list(&data, dummy_prov()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn decode_exception_access_violation() {
        let mut data = vec![0u8; 168];
        let code: u32 = 0xC0000005;
        data[8..12].copy_from_slice(&code.to_le_bytes()); // ExceptionCode at +8
        let addr: u64 = 0x7FFA_1234;
        data[24..32].copy_from_slice(&addr.to_le_bytes()); // ExceptionAddress at +24
        let tid: u32 = 42;
        data[0..4].copy_from_slice(&tid.to_le_bytes()); // ThreadId at +0
        let exc = crate::parse::exception::decode_exception(&data, dummy_prov()).unwrap();
        assert_eq!(exc.code, 0xC0000005);
        assert_eq!(exc.address, 0x7FFA_1234);
        assert_eq!(exc.thread_id, 42);
    }

    #[test]
    fn decode_exception_truncated() {
        let data = vec![0u8; 16];
        let err = crate::parse::exception::decode_exception(&data, dummy_prov()).unwrap_err();
        assert!(err.description.contains("truncated"));
    }

    #[test]
    fn decode_memory64_single_range() {
        let mut data = vec![0u8; 16 + 16]; // header + 1 entry
        let count: u64 = 1;
        data[0..8].copy_from_slice(&count.to_le_bytes());
        let va: u64 = 0x400000;
        data[16..24].copy_from_slice(&va.to_le_bytes());
        let sz: u64 = 0x1000;
        data[24..32].copy_from_slice(&sz.to_le_bytes());
        let ranges = crate::parse::memory::decode_memory64(&data, dummy_prov()).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].va_start, 0x400000);
        assert_eq!(ranges[0].data.len(), 0x1000);
    }

    #[test]
    fn full_s2_pipeline_on_synthetic_dump() {
        use crate::graph;
        use crate::parse::dump;
        use crate::pattern::PointerPattern;
        use crate::query::GraphQuery;
        use crate::scan;

        // Construct a minimal synthetic minidump in-memory
        let mut buf = vec![0u8; 256];
        buf[0] = 0x4D;
        buf[1] = 0x44;
        buf[2] = 0x4D;
        buf[3] = 0x50; // MDMP
        buf[4] = 0x93;
        buf[5] = 0xA7; // version
        buf[8] = 1;
        buf[9] = 0;
        buf[10] = 0;
        buf[11] = 0; // stream_count = 1
        buf[12] = 64;
        buf[13] = 0;
        buf[14] = 0;
        buf[15] = 0; // dir_rva = 64
        buf[64] = 7; // stream_type = SystemInfo
        buf[68] = 56; // size = 56
        buf[72] = 128; // rva = 128
        buf[128] = 0;
        buf[129] = 0; // ProcessorArchitecture = x86 (0)
        buf[136] = 9;
        buf[137] = 0; // AMD64 override
        buf[148] = 2; // PlatformId = VER_PLATFORM_WIN32_NT

        let dump_data = dump::from_bytes(&buf).unwrap();
        assert!(dump_data.system_info.is_some());

        let space = crate::space::AddressSpace::new(1000);
        let patterns = PointerPattern::presets();
        let registers: Vec<(u32, Vec<(String, u64)>)> = dump_data
            .threads
            .iter()
            .map(|t| {
                vec![
                    ("RIP".into(), t.registers.rip()),
                    ("RSP".into(), t.registers.rsp()),
                    ("RBP".into(), t.registers.rbp()),
                ]
            })
            .enumerate()
            .map(|(i, r)| (i as u32, r))
            .collect();
        let stack_ranges: Vec<(u32, u64, u64)> = dump_data
            .threads
            .iter()
            .enumerate()
            .map(|(i, t)| (i as u32, t.stack_va, t.stack_size))
            .collect();
        let reg_refs: Vec<(u32, &[(String, u64)])> = registers
            .iter()
            .map(|(tid, r)| (*tid, r.as_slice()))
            .collect();

        let scan_result = scan::scan(&space, &reg_refs, &stack_ranges, &patterns).unwrap();
        let pointer_graph = graph::build_graph(&scan_result).unwrap();
        let query = GraphQuery::new(&pointer_graph);

        // Pipeline ran end-to-end without panics
    }

    #[test]
    fn full_s3_pipeline_on_synthetic_dump() {
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
        buf[64] = 7;
        buf[68] = 56;
        buf[72] = 128;
        buf[128] = 0;
        buf[129] = 0;
        buf[136] = 9;
        buf[137] = 0;
        buf[148] = 2;

        let dump = crate::parse::dump::from_bytes(&buf).unwrap();
        assert!(dump.system_info.is_some());

        let space = crate::space::AddressSpace::new(1000);
        let patterns = crate::pattern::PointerPattern::presets();
        let reg_refs: Vec<(u32, &[(String, u64)])> = vec![];
        let stack_ranges: Vec<(u32, u64, u64)> = vec![];

        let scan_result = crate::scan::scan(&space, &reg_refs, &stack_ranges, &patterns).unwrap();
        let graph = crate::graph::build_graph(&scan_result).unwrap();
        let query = crate::query::GraphQuery::new(&graph);

        let catalog = crate::recover::recover_all(&space, &graph, &query);
        assert_eq!(catalog.all_strings().count(), 0);
        assert_eq!(catalog.all_vtables().count(), 0);
        assert_eq!(catalog.all_linked_lists().count(), 0);
        assert_eq!(catalog.all_arrays().count(), 0);
    }
}

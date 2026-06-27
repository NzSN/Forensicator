pub mod header;
pub mod directory;
pub mod system_info;
pub mod module_list;
pub mod thread_list;
pub mod memory;
pub mod memory_info;
pub mod exception;
pub mod dump;

#[cfg(test)]
mod tests {
    use crate::error::Provenance;

    fn dummy_prov() -> Provenance {
        Provenance { stream_type: 0, file_offset: 0, rva: 0 }
    }

    #[test]
    fn decode_system_info_minimal() {
        let mut data = vec![0u8; 56];
        data[8] = 9; data[9] = 0; // x64
        let si = crate::parse::system_info::decode_system_info(&data, dummy_prov()).unwrap();
        assert_eq!(si.cpu, crate::model::CpuArch::X64);
    }

    #[test]
    fn decode_empty_module_list() {
        let data = vec![0u8; 4];
        let mods = crate::parse::module_list::decode_module_list(&data, dummy_prov()).unwrap();
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
        let entries = crate::parse::memory_info::decode_memory_info_list(&data, dummy_prov()).unwrap();
        assert!(entries.is_empty());
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
        data[8] = 5; data[9] = 0; // ARM = 5
        let err = crate::parse::system_info::decode_system_info(&data, dummy_prov()).unwrap_err();
        assert!(err.description.contains("unsupported CPU"));
    }

    #[test]
    fn decode_system_info_windows_x64() {
        let mut data = vec![0u8; 56];
        data[8] = 9; data[9] = 0; // x64
        data[16] = 1; data[17] = 0; data[18] = 0; data[19] = 0; // Windows
        data[20] = 10; // major
        data[28] = 0x41; data[29] = 0x4A; // build 19041
        let si = crate::parse::system_info::decode_system_info(&data, dummy_prov()).unwrap();
        assert_eq!(si.os, crate::model::OsPlatform::Windows);
        assert_eq!(si.cpu, crate::model::CpuArch::X64);
    }

    #[test]
    fn decode_thread_list_with_data() {
        let mut data = vec![0u8; 4 + 48]; // count=1, one thread
        let count: u32 = 1;
        data[0..4].copy_from_slice(&count.to_le_bytes());
        // Thread ID at entry offset 0 = offset 4 in data
        let tid: u32 = 5678;
        data[4..8].copy_from_slice(&tid.to_le_bytes());
        // Stack size at entry offset 16
        let ssz: u32 = 0x10000;
        data[20..24].copy_from_slice(&ssz.to_le_bytes());
        let threads = crate::parse::thread_list::decode_thread_list(&data, dummy_prov()).unwrap();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].id, 5678);
        assert_eq!(threads[0].stack_size, 0x10000);
    }

    #[test]
    fn decode_exception_access_violation() {
        let mut data = vec![0u8; 32];
        let code: u32 = 0xC0000005;
        data[0..4].copy_from_slice(&code.to_le_bytes());
        let addr: u64 = 0x7FFA_1234;
        data[16..24].copy_from_slice(&addr.to_le_bytes());
        let tid: u32 = 42;
        data[28..32].copy_from_slice(&tid.to_le_bytes());
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
}

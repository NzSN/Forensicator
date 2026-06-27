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
}

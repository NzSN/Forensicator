use crate::error::FatalError;

/// Known minidump stream type identifiers.
pub mod stream_types {
    pub const UNUSED:          u32 = 0x00;
    pub const THREAD_LIST:     u32 = 0x03;
    pub const MODULE_LIST:     u32 = 0x04;
    pub const MEMORY_LIST:     u32 = 0x05;
    pub const EXCEPTION:       u32 = 0x06;
    pub const SYSTEM_INFO:     u32 = 0x07;
    pub const THREAD_EX_LIST:  u32 = 0x08;
    pub const MEMORY_64_LIST:  u32 = 0x09;
    pub const COMMENT_A:       u32 = 0x0A;
    pub const COMMENT_W:       u32 = 0x0B;
    pub const HANDLE_DATA:     u32 = 0x0C;
    pub const FUNCTION_TABLE:  u32 = 0x0D;
    pub const UNLOADED_MODULE: u32 = 0x0E;
    pub const MISC_INFO:       u32 = 0x0F;
    pub const MEMORY_INFO_LIST:u32 = 0x10;
    pub const THREAD_INFO_LIST:u32 = 0x11;
    pub const HANDLE_OP_LIST:  u32 = 0x12;
    pub const LAST_RESERVED:   u32 = 0x13;
}

/// A single entry in the stream directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamEntry {
    pub stream_type: u32,
    pub rva: u32,
    pub size: u32,
}

/// A parsed stream directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamDirectory {
    pub entries: Vec<StreamEntry>,
}

impl StreamDirectory {
    /// Find the first entry matching the given stream type, if any.
    pub fn find(&self, stream_type: u32) -> Option<&StreamEntry> {
        self.entries.iter().find(|e| e.stream_type == stream_type)
    }

    /// Check if a stream type is present.
    pub fn has(&self, stream_type: u32) -> bool {
        self.find(stream_type).is_some()
    }
}

/// Read the stream directory from raw bytes, starting at `rva`.
/// Each entry is 12 bytes: 4-byte stream_type, 4-byte size, 4-byte rva.
pub fn read_directory(data: &[u8], rva: u32, count: u32) -> Result<StreamDirectory, FatalError> {
    let start = rva as usize;
    let dir_size = (count as usize).checked_mul(12)
        .ok_or(FatalError::DirectoryOutOfBounds { rva, size: count * 12, file_len: data.len() })?;
    let end = start.checked_add(dir_size)
        .ok_or(FatalError::DirectoryOutOfBounds { rva, size: count * 12, file_len: data.len() })?;

    if end > data.len() {
        return Err(FatalError::DirectoryOutOfBounds { rva, size: dir_size as u32, file_len: data.len() });
    }

    let mut entries = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let off = start + i * 12;
        let stream_type = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
        let size = u32::from_le_bytes([data[off+4], data[off+5], data[off+6], data[off+7]]);
        let entry_rva = u32::from_le_bytes([data[off+8], data[off+9], data[off+10], data[off+11]]);

        entries.push(StreamEntry { stream_type, size, rva: entry_rva });
    }

    Ok(StreamDirectory { entries })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dir_bytes(count: u32) -> Vec<u8> {
        let mut buf = vec![0u8; count as usize * 12];
        for i in 0..count as usize {
            let off = i * 12;
            buf[off] = 7;    // stream_type = SystemInfo = 0x07
            buf[off+1] = 0;
            buf[off+2] = 0;
            buf[off+3] = 0;
            buf[off+4] = 56;  // size
            buf[off+8] = (100 + i as u32 * 100) as u8; // rva LSB
        }
        buf
    }

    #[test]
    fn read_directory_three_entries() {
        let dir_bytes = make_dir_bytes(3);
        let dir = read_directory(&dir_bytes, 0, 3).unwrap();
        assert_eq!(dir.entries.len(), 3);
        assert!(dir.has(7));
        assert!(!dir.has(4));
    }

    #[test]
    fn find_existing_entry() {
        let dir_bytes = make_dir_bytes(2);
        let dir = read_directory(&dir_bytes, 0, 2).unwrap();
        let entry = dir.find(7).unwrap();
        assert_eq!(entry.stream_type, 7);
        assert_eq!(entry.size, 56);
    }

    #[test]
    fn find_missing_returns_none() {
        let dir_bytes = make_dir_bytes(1);
        let dir = read_directory(&dir_bytes, 0, 1).unwrap();
        assert!(dir.find(4).is_none());
    }

    #[test]
    fn directory_out_of_bounds() {
        let data = vec![0u8; 20];
        let err = read_directory(&data, 100, 10).unwrap_err();
        assert!(matches!(err, FatalError::DirectoryOutOfBounds { .. }));
    }

    #[test]
    fn zero_count_returns_empty() {
        let dir = read_directory(&[], 0, 0).unwrap();
        assert!(dir.entries.is_empty());
    }
}

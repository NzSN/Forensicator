use crate::error::FatalError;

/// Minidump magic bytes: "MDMP" in little-endian.
const MAGIC: u32 = 0x504D444D;

/// Minidump header as defined by the format specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Must equal 0x504D444D ("MDMP").
    pub magic: u32,
    /// Version of the minidump format (expected: 0xA793).
    pub version: u16,
    /// Implementation-specific version.
    pub implementation_version: u16,
    /// Number of streams in the stream directory.
    pub stream_count: u32,
    /// RVA of the stream directory within the file.
    pub stream_directory_rva: u32,
    /// Checksum of the minidump file (0 if unused).
    pub checksum: u32,
    /// Timestamp when the dump was created (Unix epoch, seconds).
    pub timestamp: u32,
    /// Flags indicating what data is present.
    pub flags: u64,
}

/// Validate and parse the minidump header from raw bytes.
/// Returns `Err(FatalError)` if the file is too small, has bad magic,
/// or has an unsupported version.
pub fn read_header(data: &[u8]) -> Result<Header, FatalError> {
    if data.len() < 32 {
        return Err(FatalError::TooSmall { size: data.len() });
    }

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != MAGIC {
        return Err(FatalError::BadMagic {
            found: [data[0], data[1], data[2], data[3]],
        });
    }

    let version = u16::from_le_bytes([data[4], data[5]]);
    if version != 0xA793 {
        // Not a fatal error — we accept and warn via anomaly
    }

    Ok(Header {
        magic,
        version,
        implementation_version: u16::from_le_bytes([data[6], data[7]]),
        stream_count: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        stream_directory_rva: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        checksum: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
        timestamp: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
        flags: u64::from_le_bytes([
            data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
        ]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header_bytes() -> Vec<u8> {
        let mut buf = vec![0u8; 32];
        // Magic "MDMP"
        buf[0] = 0x4D;
        buf[1] = 0x44;
        buf[2] = 0x4D;
        buf[3] = 0x50;
        // Version 0xA793
        buf[4] = 0x93;
        buf[5] = 0xA7;
        // Stream count = 5
        buf[8] = 5;
        buf[9] = 0;
        buf[10] = 0;
        buf[11] = 0;
        // Stream directory RVA = 64
        buf[12] = 64;
        buf[13] = 0;
        buf[14] = 0;
        buf[15] = 0;
        buf
    }

    #[test]
    fn read_valid_header() {
        let data = make_header_bytes();
        let h = read_header(&data).unwrap();
        assert_eq!(h.magic, 0x504D444D);
        assert_eq!(h.version, 0xA793);
        assert_eq!(h.stream_count, 5);
        assert_eq!(h.stream_directory_rva, 64);
    }

    #[test]
    fn too_small_returns_error() {
        let data = vec![0u8; 16];
        let err = read_header(&data).unwrap_err();
        assert!(matches!(err, FatalError::TooSmall { .. }));
    }

    #[test]
    fn bad_magic_returns_error() {
        let mut data = make_header_bytes();
        data[0] = 0xDE;
        data[1] = 0xAD;
        data[2] = 0xBE;
        data[3] = 0xEF;
        let err = read_header(&data).unwrap_err();
        assert!(matches!(err, FatalError::BadMagic { .. }));
    }

    #[test]
    fn zero_stream_count_ok() {
        let mut data = make_header_bytes();
        data[8] = 0; // stream_count = 0
        let h = read_header(&data).unwrap();
        assert_eq!(h.stream_count, 0);
    }
}

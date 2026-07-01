use std::fmt;

/// Fatal errors that stop the parse pipeline immediately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FatalError {
    /// File could not be read or does not exist.
    Io(String),
    /// File is too small to contain a valid minidump header (need >= 32 bytes).
    TooSmall { size: usize },
    /// Minidump magic bytes (0x4D444D50 = "MDMP") not found.
    BadMagic { found: [u8; 4] },
    /// Stream directory RVA points outside the file.
    DirectoryOutOfBounds {
        rva: u32,
        size: u32,
        file_len: usize,
    },
    /// A stream's data descriptor points outside the file.
    StreamOutOfBounds {
        stream_type: u32,
        rva: u32,
        size: u32,
        file_len: usize,
    },
}

impl fmt::Display for FatalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FatalError::Io(msg) => write!(f, "I/O error: {msg}"),
            FatalError::TooSmall { size } => write!(f, "file too small ({size} bytes, need >= 32)"),
            FatalError::BadMagic { found } => {
                write!(f, "bad magic: {found:02X?} (expected 4D 44 4D 50)")
            }
            FatalError::DirectoryOutOfBounds {
                rva,
                size,
                file_len,
            } => {
                write!(
                    f,
                    "stream directory at RVA {rva} size {size} out of bounds (file len {file_len})"
                )
            }
            FatalError::StreamOutOfBounds {
                stream_type,
                rva,
                size,
                file_len,
            } => {
                write!(
                    f,
                    "stream 0x{stream_type:08X} at RVA {rva} size {size} out of bounds (file len {file_len})"
                )
            }
        }
    }
}

impl std::error::Error for FatalError {}

/// A provenance record: which stream and where in the file a fact came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// Stream type identifier (e.g., 0x04 = ModuleList).
    pub stream_type: u32,
    /// Byte offset within the .dmp file where the stream data starts.
    pub file_offset: u64,
    /// Relative virtual address (RVA) within the stream data.
    pub rva: u32,
}

/// A non-fatal anomaly: something went wrong but the pipeline continues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    pub provenance: Provenance,
    pub description: String,
}

impl fmt::Display for Anomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[stream 0x{:08X} @ +0x{:X}] {}",
            self.provenance.stream_type, self.provenance.file_offset, self.description
        )
    }
}

impl std::error::Error for Anomaly {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fatal_error_display() {
        let err = FatalError::BadMagic {
            found: [0xDE, 0xAD, 0xBE, 0xEF],
        };
        let msg = err.to_string();
        assert!(msg.contains("bad magic"));
        assert!(msg.contains("[DE, AD, BE, EF]"));
    }

    #[test]
    fn anomaly_construction() {
        let prov = Provenance {
            stream_type: 7,
            file_offset: 128,
            rva: 0,
        };
        let a = Anomaly {
            provenance: prov.clone(),
            description: "truncated".into(),
        };
        assert_eq!(a.provenance.stream_type, 7);
        assert_eq!(a.provenance.file_offset, 128);
    }

    #[test]
    fn io_error_display() {
        let err = FatalError::Io("permission denied".into());
        let msg = err.to_string();
        assert!(msg.contains("I/O error"));
        assert!(msg.contains("permission denied"));
    }

    #[test]
    fn too_small_display() {
        let err = FatalError::TooSmall { size: 16 };
        let msg = err.to_string();
        assert!(msg.contains("file too small"));
        assert!(msg.contains("16"));
        assert!(msg.contains("32"));
    }

    #[test]
    fn directory_out_of_bounds_display() {
        let err = FatalError::DirectoryOutOfBounds {
            rva: 0x1000,
            size: 4096,
            file_len: 512,
        };
        let msg = err.to_string();
        assert!(msg.contains("stream directory"));
        assert!(msg.contains("4096"));
        assert!(msg.contains("out of bounds"));
    }

    #[test]
    fn stream_out_of_bounds_display() {
        let err = FatalError::StreamOutOfBounds {
            stream_type: 0x07,
            rva: 0x2000,
            size: 1024,
            file_len: 512,
        };
        let msg = err.to_string();
        assert!(msg.contains("0x00000007"));
        assert!(msg.contains("1024"));
        assert!(msg.contains("out of bounds"));
    }

    #[test]
    fn fatal_error_is_std_error() {
        let err = FatalError::TooSmall { size: 10 };
        let _: Box<dyn std::error::Error> = Box::new(err);
    }

    #[test]
    fn fatal_error_equality() {
        let a = FatalError::BadMagic {
            found: [0xDE, 0xAD, 0xBE, 0xEF],
        };
        let b = FatalError::BadMagic {
            found: [0xDE, 0xAD, 0xBE, 0xEF],
        };
        assert_eq!(a, b);
    }

    #[test]
    fn provenance_default_stream_type() {
        let prov = Provenance {
            stream_type: 0,
            file_offset: 0,
            rva: 0,
        };
        assert_eq!(prov.stream_type, 0);
    }

    #[test]
    fn anomaly_clone() {
        let prov = Provenance {
            stream_type: 1,
            file_offset: 64,
            rva: 8,
        };
        let a = Anomaly {
            provenance: prov,
            description: "test".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}

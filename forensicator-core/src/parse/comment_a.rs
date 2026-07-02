use crate::error::{Anomaly, Provenance};

/// A single crash annotation: a diagnostic key=value pair from CommentStreamA/W.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Annotation {
    pub key: String,
    pub value: String,
}

/// Decode CommentStreamA (stream type 0x0A): a buffer of null-terminated
/// key=value pairs. Chromium-derived dumps use a single key=value;
/// other implementations may concatenate multiple pairs.
pub fn decode_comment_a(
    data: &[u8],
    provenance: Provenance,
) -> Result<Vec<Annotation>, Anomaly> {
    let mut annotations = Vec::new();
    let s = String::from_utf8_lossy(data);
    for pair in s.split('\0') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        if let Some((key, value)) = pair.split_once('=') {
            annotations.push(Annotation {
                key: key.trim().to_string(),
                value: value.trim().to_string(),
            });
        }
    }
    if annotations.is_empty() {
        return Err(Anomaly {
            provenance,
            description: "no annotations in CommentStreamA".into(),
        });
    }
    Ok(annotations)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_prov() -> Provenance {
        Provenance { stream_type: 0x0A, file_offset: 0, rva: 0 }
    }

    #[test]
    fn decodes_single_annotation() {
        let data = b"app_version=1.2.3\0";
        let anns = decode_comment_a(data, dummy_prov()).unwrap();
        assert_eq!(anns.len(), 1);
        assert_eq!(anns[0].key, "app_version");
        assert_eq!(anns[0].value, "1.2.3");
    }

    #[test]
    fn decodes_multiple_annotations() {
        let data = b"app_version=1.0\0user_id=42\0session_id=abc\0";
        let anns = decode_comment_a(data, dummy_prov()).unwrap();
        assert_eq!(anns.len(), 3);
        assert_eq!(anns[0].key, "app_version");
        assert_eq!(anns[1].key, "user_id");
        assert_eq!(anns[2].key, "session_id");
    }

    #[test]
    fn ignores_empty_entries() {
        let data = b"\0app_version=1.0\0\0";
        let anns = decode_comment_a(data, dummy_prov()).unwrap();
        assert_eq!(anns.len(), 1);
    }

    #[test]
    fn trims_whitespace() {
        let data = b" key = value \0";
        let anns = decode_comment_a(data, dummy_prov()).unwrap();
        assert_eq!(anns[0].key, "key");
        assert_eq!(anns[0].value, "value");
    }

    #[test]
    fn no_equals_skipped() {
        let data = b"just_a_string\0";
        let result = decode_comment_a(data, dummy_prov());
        assert!(result.is_err());
    }

    #[test]
    fn empty_buffer_is_error() {
        let result = decode_comment_a(b"", dummy_prov());
        assert!(result.is_err());
    }
}

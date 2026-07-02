use crate::error::{Anomaly, Provenance};
use crate::parse::comment_a::Annotation;

/// Extract the annotation blob RVA from a crashpad extension stream header.
/// The stream layout (after version 1 GUID):
///   ... 28 bytes of fixed fields ...
///   offset 36: annotation_size (u32)
///   offset 40: annotation_rva  (u32)
pub fn extract_annotation_rva(stream_data: &[u8]) -> Option<u32> {
    if stream_data.len() < 44 {
        return None;
    }
    let version = u32::from_le_bytes([stream_data[0], stream_data[1], stream_data[2], stream_data[3]]);
    if version != 1 {
        return None;
    }
    let ann_size = u32::from_le_bytes([
        stream_data[36], stream_data[37], stream_data[38], stream_data[39],
    ]);
    let ann_rva = u32::from_le_bytes([
        stream_data[40], stream_data[41], stream_data[42], stream_data[43],
    ]);
    if ann_size == 0 || ann_rva == 0 {
        return None;
    }
    Some(ann_rva)
}

/// Decode Crashpad annotations from a dump byte slice at the given RVA.
/// The annotation blob contains length-prefixed key=value pairs interleaved
/// in a flat buffer. Pairs are parsed sequentially until a zero-length key
/// is encountered or the buffer is exhausted.
///
/// Each pair:
///   u32 key_len
///   char[key_len] key  (padded to ceil((len+1)/4)*4)
///   u32 val_len
///   char[val_len] val  (padded to ceil((len+1)/4)*4)
pub fn decode_crashpad_annotations(
    dump_data: &[u8],
    ann_rva: usize,
    provenance: Provenance,
) -> Result<Vec<Annotation>, Anomaly> {
    let mut annotations = Vec::new();

    // Skip the directory (count + count × u32 RVAs → find where data starts)
    if ann_rva + 4 > dump_data.len() {
        return Err(Anomaly { provenance, description: "crashpad blob too short".into() });
    }
    let count = u32::from_le_bytes([
        dump_data[ann_rva], dump_data[ann_rva+1], dump_data[ann_rva+2], dump_data[ann_rva+3],
    ]) as usize;
    if count == 0 || count > 256 {
        return Err(Anomaly { provenance, description: format!("bad crashpad annotation count: {count}") });
    }

    // Scan for the first key-value start. The directory RVAs point to individual
    // entries within the blob. The data starts at the lowest directory RVA.
    let mut min_rva = usize::MAX;
    for i in 0..count {
        let off = ann_rva + 4 + i * 4;
        if off + 4 <= dump_data.len() {
            let rva = u32::from_le_bytes([
                dump_data[off], dump_data[off+1], dump_data[off+2], dump_data[off+3],
            ]) as usize;
            if rva > 0 && rva < min_rva { min_rva = rva; }
        }
    }

    let mut pos = if min_rva < usize::MAX { min_rva } else { ann_rva + 4 + count * 4 };
    let max_pos = (pos + 8192).min(dump_data.len());

    while pos + 4 <= max_pos {
        let key_len = u32::from_le_bytes([
            dump_data[pos], dump_data[pos+1], dump_data[pos+2], dump_data[pos+3],
        ]) as usize;
        if key_len == 0 || key_len > 256 { break; }
        pos += 4;

        let key = String::from_utf8_lossy(&dump_data[pos..pos + key_len])
            .trim_end_matches('\0')
            .to_string();
        pos += ((key_len + 4) / 4) * 4;

        if pos + 4 > max_pos { break; }
        let val_len = u32::from_le_bytes([
            dump_data[pos], dump_data[pos+1], dump_data[pos+2], dump_data[pos+3],
        ]) as usize;
        if val_len == 0 || val_len > 10240 { break; }
        pos += 4;

        let value = String::from_utf8_lossy(&dump_data[pos..pos + val_len])
            .trim_end_matches('\0')
            .to_string();
        pos += ((val_len + 4) / 4) * 4;

        annotations.push(Annotation { key, value });
    }

    if annotations.is_empty() {
        return Err(Anomaly {
            provenance,
            description: "no annotations found in crashpad stream".into(),
        });
    }

    Ok(annotations)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_crashpad_stream(entries: &[(&str, &str)]) -> Vec<u8> {
        let count = entries.len() as u32;
        let dir_size = 4 + count as usize * 4;
        let mut stream = vec![0u8; dir_size];
        stream[0..4].copy_from_slice(&count.to_le_bytes());

        let mut blob_rvas = Vec::new();

        for (k, v) in entries {
            let rva = dir_size + (stream.len() - dir_size); // offset from stream start
            blob_rvas.push(rva as u32);

            // key
            stream.extend_from_slice(&(k.len() as u32).to_le_bytes());
            stream.extend_from_slice(k.as_bytes());
            let kpad = ((k.len() + 4) / 4) * 4 - k.len();
            stream.extend(std::iter::repeat(0u8).take(kpad));

            // value
            stream.extend_from_slice(&(v.len() as u32).to_le_bytes());
            stream.extend_from_slice(v.as_bytes());
            let vpad = ((v.len() + 4) / 4) * 4 - v.len();
            stream.extend(std::iter::repeat(0u8).take(vpad));
        }

        for (i, rva) in blob_rvas.iter().enumerate() {
            stream[4 + i * 4..8 + i * 4].copy_from_slice(&rva.to_le_bytes());
        }

        stream
    }

    #[test]
    fn decodes_crashpad_annotations() {
        let stream = make_crashpad_stream(&[
            ("prod", "Electron"),
            ("ver", "41.8.0"),
            ("plat", "Win64"),
        ]);
        let result =
            decode_crashpad_annotations(&stream, 0, Provenance { stream_type: 0x43500001, file_offset: 0, rva: 0 })
                .unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].key, "prod");
        assert_eq!(result[1].key, "ver");
        assert_eq!(result[2].key, "plat");
    }

    #[test]
    fn empty_crashpad_stream() {
        let result =
            decode_crashpad_annotations(&[0u8; 4], 0, Provenance { stream_type: 0, file_offset: 0, rva: 0 });
        assert!(result.is_err());
    }

    #[test]
    fn zero_count_returns_error() {
        let result = decode_crashpad_annotations(
            &[0, 0, 0, 0],
            0,
            Provenance { stream_type: 0, file_offset: 0, rva: 0 },
        );
        assert!(result.is_err());
    }
}

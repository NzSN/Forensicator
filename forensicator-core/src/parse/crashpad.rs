use crate::error::{Anomaly, Provenance};
use crate::parse::comment_a::Annotation;

/// Extract the snapshot annotation blob RVA from a crashpad extension
/// stream header (stream type 0x43500001).
/// The stream header layout (version 1):
///   offset 0:  u32 version   (= 1)
///   offset 4:  u8[16] guid
///   offset 20: u32 padding
///   offset 24: u32 padding
///   offset 28: u32 padding
///   offset 32: u32 padding
///   offset 36: u32 ann_size
///   offset 40: u32 ann_rva
pub fn extract_annotation_rva(stream_data: &[u8]) -> Option<u32> {
    if stream_data.len() < 44 {
        return None;
    }
    let version =
        u32::from_le_bytes([stream_data[0], stream_data[1], stream_data[2], stream_data[3]]);
    if version != 1 {
        return None;
    }
    let ann_size = u32::from_le_bytes([
        stream_data[36],
        stream_data[37],
        stream_data[38],
        stream_data[39],
    ]);
    let ann_rva = u32::from_le_bytes([
        stream_data[40],
        stream_data[41],
        stream_data[42],
        stream_data[43],
    ]);
    if ann_size == 0 || ann_rva == 0 {
        return None;
    }
    Some(ann_rva)
}

/// Extract the annotation objects blob RVA from the crashpad extension stream.
/// The second pointer is at offset 48 (annotation objects, per-module data).
pub fn extract_annotation_objects_rva(stream_data: &[u8]) -> Option<u32> {
    if stream_data.len() < 52 { return None; }
    let version = u32::from_le_bytes([stream_data[0], stream_data[1], stream_data[2], stream_data[3]]);
    if version != 1 { return None; }
    let rva = u32::from_le_bytes([stream_data[48], stream_data[49], stream_data[50], stream_data[51]]);
    if rva == 0 { None } else { Some(rva) }
}

/// Decode crashpad snapshot annotations from a dump byte slice at the given RVA.
/// The blob contains a directory (count + count × u32 RVAs) followed by
/// length-prefixed key=value pairs with 4-byte padding.
pub fn decode_crashpad_annotations(
    dump_data: &[u8],
    ann_rva: usize,
    provenance: Provenance,
) -> Result<Vec<Annotation>, Anomaly> {
    if ann_rva + 4 > dump_data.len() {
        return Err(Anomaly {
            provenance,
            description: "crashpad blob too short".into(),
        });
    }
    let count = u32::from_le_bytes([
        dump_data[ann_rva],
        dump_data[ann_rva + 1],
        dump_data[ann_rva + 2],
        dump_data[ann_rva + 3],
    ]) as usize;
    if count == 0 || count > 256 {
        return Err(Anomaly {
            provenance,
            description: "bad crashpad annotation count".into(),
        });
    }

    // Find the minimal entry RVA to locate the start of key-value data
    let mut min_rva = usize::MAX;
    for i in 0..count {
        let off = ann_rva + 4 + i * 4;
        if off + 4 <= dump_data.len() {
            let rva = u32::from_le_bytes([
                dump_data[off],
                dump_data[off + 1],
                dump_data[off + 2],
                dump_data[off + 3],
            ]) as usize;
            if rva > 0 && rva < min_rva {
                min_rva = rva;
            }
        }
    }

    let mut pos = if min_rva < usize::MAX {
        min_rva
    } else {
        ann_rva + 4 + count * 4
    };
    let max_pos = (pos + 8192).min(dump_data.len());

    // Parse length-prefixed key=value pairs sequentially (up to count entries)
    let mut annotations = Vec::new();
    for _ in 0..count {
        if pos + 4 > max_pos {
            break;
        }
        let key_len = u32::from_le_bytes([
            dump_data[pos],
            dump_data[pos + 1],
            dump_data[pos + 2],
            dump_data[pos + 3],
        ]) as usize;
        if key_len == 0 || key_len > 256 {
            break;
        }
        pos += 4;

        let key = String::from_utf8_lossy(&dump_data[pos..pos + key_len])
            .trim_end_matches('\0')
            .to_string();
        pos += ((key_len + 4) / 4) * 4;

        if pos + 4 > max_pos {
            break;
        }
        let val_len = u32::from_le_bytes([
            dump_data[pos],
            dump_data[pos + 1],
            dump_data[pos + 2],
            dump_data[pos + 3],
        ]) as usize;
        if val_len == 0 || val_len > 10240 {
            break;
        }
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

/// Scan the annotation objects region for length-prefixed key=value pairs.
/// Unlike snapshot annotations (which have a count+directory), annotation
/// objects are stored in a nested tree. We scan linearly for any plausible
/// 4-byte-aligned key-length + value-length pairs in the blob region.
pub fn decode_crashpad_annotation_objects(
    dump_data: &[u8],
    objects_rva: usize,
    provenance: Provenance,
) -> Result<Vec<Annotation>, Anomaly> {
    // Scan a window of 4096 bytes around the objects RVA
    let start = objects_rva;
    let end = (start + 4096).min(dump_data.len());
    let mut seen_keys = std::collections::HashSet::new();
    let mut seen_vals = std::collections::HashSet::new();
    let mut annotations = Vec::new();

    let mut pos = start;
    while pos + 8 <= end {
        let klen = u32::from_le_bytes([dump_data[pos], dump_data[pos+1], dump_data[pos+2], dump_data[pos+3]]) as usize;
        // Plausible key length: 2-128 characters, printable ASCII
        if klen >= 2 && klen <= 128 && pos + 4 + klen + 4 <= end {
            let key_bytes = &dump_data[pos+4..pos+4+klen];
            let is_ascii = key_bytes.iter().all(|&b| (b >= 0x20 && b <= 0x7E) || b == b'_' || b == b'-' || b == b'.');
            let has_alpha = key_bytes.iter().any(|&b| b.is_ascii_alphabetic());
            let not_numeric = !key_bytes.iter().all(|&b| b.is_ascii_digit() || b == b'x' || b == b'0');
            if is_ascii && has_alpha && not_numeric {
                let key = String::from_utf8_lossy(key_bytes).to_string();
                if !seen_keys.contains(&key) && !seen_vals.contains(&key) {
                    seen_keys.insert(key.clone());
                    let vpos = pos + 4 + ((klen + 4) / 4) * 4;
                    if vpos + 4 <= end {
                        let vlen = u32::from_le_bytes([dump_data[vpos], dump_data[vpos+1], dump_data[vpos+2], dump_data[vpos+3]]) as usize;
                        if vlen > 0 && vlen <= 1024 && vpos + 4 + vlen <= end {
                            let val = String::from_utf8_lossy(&dump_data[vpos+4..vpos+4+vlen])
                                .trim_end_matches('\0')
                                .to_string();
                            seen_vals.insert(val.clone());
                            annotations.push(Annotation { key, value: val });
                        }
                    }
                }
            }
        }
        pos += 4;
    }

    if annotations.is_empty() {
        return Err(Anomaly { provenance, description: "no annotation objects found".into() });
    }
    Ok(annotations)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_annotation_blob(entries: &[(&str, &str)]) -> Vec<u8> {
        let count = entries.len() as u32;
        let dir_size = 4 + count as usize * 4;
        let mut blob = vec![0u8; dir_size];
        blob[0..4].copy_from_slice(&count.to_le_bytes());

        let mut rvas = Vec::new();
        for (k, v) in entries {
            rvas.push(blob.len() as u32);

            blob.extend_from_slice(&(k.len() as u32).to_le_bytes());
            blob.extend_from_slice(k.as_bytes());
            let pad = ((k.len() + 4) / 4) * 4 - k.len();
            blob.extend(std::iter::repeat(0u8).take(pad));

            blob.extend_from_slice(&(v.len() as u32).to_le_bytes());
            blob.extend_from_slice(v.as_bytes());
            let pad = ((v.len() + 4) / 4) * 4 - v.len();
            blob.extend(std::iter::repeat(0u8).take(pad));
        }

        for (i, rva) in rvas.iter().enumerate() {
            blob[4 + i * 4..8 + i * 4].copy_from_slice(&rva.to_le_bytes());
        }
        blob
    }

    #[test]
    fn decodes_annotations() {
        let blob = make_annotation_blob(&[("prod", "Electron"), ("ver", "41.8.0")]);
        let result = decode_crashpad_annotations(&blob, 0, Provenance {
            stream_type: 0x43500001,
            file_offset: 0,
            rva: 0,
        })
        .unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].key, "prod");
        assert_eq!(result[0].value, "Electron");
    }

    #[test]
    fn empty_blob_errors() {
        let result = decode_crashpad_annotations(&[0u8; 4], 0, Provenance {
            stream_type: 0,
            file_offset: 0,
            rva: 0,
        });
        assert!(result.is_err());
    }
}

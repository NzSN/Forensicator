use crate::arch::RegisterSet;
use crate::error::{Anomaly, Provenance};
use crate::model::ExceptionInfo;

/// MINIDUMP_EXCEPTION_STREAM layout:
///   +0:   ThreadId (u32)
///   +4:   __alignment (u32)
///   +8:   ExceptionCode (u32)
///  +12:   ExceptionFlags (u32)
///  +16:   ExceptionRecord (u64)
///  +24:   ExceptionAddress (u64)
///  +32:   NumberParameters (u32)
///  +36:   __unusedAlignment (u32)
///  +40:   ExceptionInformation[15] (u64[15])
/// +160:   ThreadContext.DataSize (u32)
/// +164:   ThreadContext.Rva (u32)
pub fn decode_exception(data: &[u8], prov: Provenance) -> Result<ExceptionInfo, Anomaly> {
    decode_exception_with_dump(data, prov, &[])
}

/// Decode exception info with access to the full dump data for resolving
/// the thread context RVA.
pub fn decode_exception_with_dump(
    data: &[u8],
    prov: Provenance,
    dump_data: &[u8],
) -> Result<ExceptionInfo, Anomaly> {
    if data.len() < 32 {
        return Err(Anomaly {
            provenance: prov.clone(),
            description: "truncated Exception stream".into(),
        });
    }

    let thread_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let code = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let flags = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let address = u64::from_le_bytes(data[24..32].try_into().unwrap());

    // NumberParameters @ +32, ExceptionInformation[15] @ +40.
    let parameters = if data.len() >= 40 {
        let n = u32::from_le_bytes([data[32], data[33], data[34], data[35]]).min(15) as usize;
        let avail = (data.len() - 40) / 8;
        (0..n.min(avail))
            .map(|i| u64::from_le_bytes(data[40 + 8 * i..48 + 8 * i].try_into().unwrap()))
            .collect()
    } else {
        Vec::new()
    };

    // Read thread context
    let context = if data.len() >= 168 {
        let ctx_size = u32::from_le_bytes([data[160], data[161], data[162], data[163]]) as usize;
        let ctx_rva = u32::from_le_bytes([data[164], data[165], data[166], data[167]]) as usize;
        if ctx_size > 0 && ctx_rva > 0 && ctx_rva + ctx_size <= dump_data.len() {
            let ctx_bytes = &dump_data[ctx_rva..ctx_rva + ctx_size];
            RegisterSet::decode_context(ctx_bytes).ok()
        } else {
            None
        }
    } else {
        None
    };

    Ok(ExceptionInfo {
        code,
        address,
        thread_id,
        flags,
        parameters,
        context,
        provenance: prov,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Provenance;

    fn dummy_prov() -> Provenance {
        Provenance {
            stream_type: 0,
            file_offset: 0,
            rva: 0,
        }
    }

    #[test]
    fn decodes_av_parameters() {
        let mut data = vec![0u8; 168];
        data[8..12].copy_from_slice(&0xC0000005u32.to_le_bytes());
        data[32..36].copy_from_slice(&2u32.to_le_bytes()); // NumberParameters
        data[40..48].copy_from_slice(&1u64.to_le_bytes()); // write
        data[48..56].copy_from_slice(&0xDEADu64.to_le_bytes()); // fault VA
        let exc = decode_exception(&data, dummy_prov()).unwrap();
        assert_eq!(exc.parameters, vec![1, 0xDEAD]);
    }

    #[test]
    fn clamps_parameters_to_stream_length() {
        let mut data = vec![0u8; 48]; // room for only 1 param
        data[32..36].copy_from_slice(&15u32.to_le_bytes());
        let exc = decode_exception(&data, dummy_prov()).unwrap();
        assert_eq!(exc.parameters.len(), 1);
    }

    #[test]
    fn short_stream_yields_no_parameters() {
        let data = vec![0u8; 32];
        let exc = decode_exception(&data, dummy_prov()).unwrap();
        assert!(exc.parameters.is_empty());
    }
}

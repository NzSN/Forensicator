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
        context,
        provenance: prov,
    })
}

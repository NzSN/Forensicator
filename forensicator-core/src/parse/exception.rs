use crate::error::{Anomaly, Provenance};
use crate::model::ExceptionInfo;

/// MINIDUMP_EXCEPTION_STREAM layout (168 bytes):
///   +0:   ThreadId (u32)
///   +4:   __alignment (u32)
///   +8:   ExceptionRecord.ExceptionCode (u32)
///  +12:   ExceptionRecord.ExceptionFlags (u32)
///  +16:   ExceptionRecord.ExceptionRecord (u64)  — nested, usually 0
///  +24:   ExceptionRecord.ExceptionAddress (u64)
///  +32:   ExceptionRecord.NumberParameters (u32)
///  +36:   ExceptionRecord.__unusedAlignment (u32)
///  +40:   ExceptionRecord.ExceptionInformation[15] (u64[15])
/// +160:   ThreadContext.DataSize (u32)
/// +164:   ThreadContext.Rva (u32)
pub fn decode_exception(data: &[u8], prov: Provenance) -> Result<ExceptionInfo, Anomaly> {
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

    Ok(ExceptionInfo {
        code,
        address,
        thread_id,
        flags,
        context: None,
        provenance: prov,
    })
}

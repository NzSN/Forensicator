use crate::error::{Anomaly, Provenance};
use crate::model::ExceptionInfo;

pub fn decode_exception(data: &[u8], prov: Provenance) -> Result<ExceptionInfo, Anomaly> {
    if data.len() < 32 {
        return Err(Anomaly { provenance: prov.clone(), description: "truncated Exception stream".into() });
    }

    let code = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let address = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let thread_id = u32::from_le_bytes(data[28..32].try_into().unwrap());

    Ok(ExceptionInfo {
        code, address, thread_id, flags,
        context: None,
        provenance: prov,
    })
}

use clave_proto::transport::DeviceLink;

use crate::{DeviceId, Gateway, IdentityProvider, Store};

pub async fn serve_device_audit<I: IdentityProvider, S: Store>(
    mut link: DeviceLink,
    device: DeviceId,
    gateway: &Gateway<I, S>,
) -> usize {
    let mut ingested = 0;
    while let Some(batch) = link.recv_audit().await {
        match gateway.ingest_device_audit(device, &batch).await {
            Ok(events) => ingested += events.len(),
            Err(e) => eprintln!("clave-gateway: device {:x} audit rejected: {e}", device.0),
        }
    }
    ingested
}

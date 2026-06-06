use configuration::{addresses::get_addresses, logging::init_logging, settings::get_settings};
use log::{error, info};
use nightfall_attestor::{routes, AttestorContext};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let settings = get_settings();

    init_logging(
        settings.nightfall_attestor.log_level.as_str(),
        settings.log_app_only,
    );

    let addresses = get_addresses();
    let ctx = AttestorContext {
        chain_id: addresses.chain_id,
        verifier: addresses.nova_verifier,
    };

    if settings.nova_verifier.attestor_key.trim().is_empty() {
        error!(
            "[attestor] No nova_verifier.attestor_key configured; the service \
             will reject all attestation requests with 503 until a key is set."
        );
    }

    let bind = settings.nightfall_attestor.bind.trim();
    let addr: SocketAddr = bind.parse().unwrap_or_else(|_| {
        error!("[attestor] invalid bind '{bind}', falling back to 0.0.0.0:3001");
        SocketAddr::from(([0, 0, 0, 0], 3001))
    });

    info!(
        "[attestor] Nova attestation service listening on {addr} \
         (chain_id={}, verifier={})",
        ctx.chain_id, ctx.verifier
    );

    warp::serve(routes(ctx)).run(addr).await;
}

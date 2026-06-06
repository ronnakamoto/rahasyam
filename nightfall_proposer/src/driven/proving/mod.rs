use configuration::settings::{Settings, ProvingSystemIdConfig};
use lib::proving::{ProofSystemId, ProofSystemRegistry, ProvingError, plonk_v1::PlonkV1System};

#[cfg(feature = "nova-v1")]
use lib::proving::nova_v1::NovaV1System;

pub fn build_registry_from_config(settings: &Settings) -> Result<ProofSystemRegistry, ProvingError> {
    let mut registry = ProofSystemRegistry::new();
    let ps_config = &settings.nightfall_proposer.proving_system;

    if ps_config.enabled.is_empty() {
        registry.register::<PlonkV1System>()?;
        return Ok(registry);
    }

    for system in &ps_config.enabled {
        match system {
            ProvingSystemIdConfig::PlonkV1 => {
                registry.register::<PlonkV1System>()?;
            }
            ProvingSystemIdConfig::NovaV1 => {
                #[cfg(feature = "nova-v1")]
                {
                    registry.register::<NovaV1System>()?;
                    log::info!("Registered NovaV1 proving system");
                }
                #[cfg(not(feature = "nova-v1"))]
                {
                    log::warn!("NovaV1 is configured but nova-v1 feature is not enabled; skipping registration");
                }
            }
            ProvingSystemIdConfig::NovaBlsV1 => {
                // The committee is an on-chain verifier gate (router id 3), not a
                // prover; committee blocks are produced by the Nova prover. Ensure
                // it is registered (idempotent if nova-v1 is also enabled).
                #[cfg(feature = "nova-v1")]
                {
                    if !registry.is_registered(ProofSystemId::NovaV1) {
                        registry.register::<NovaV1System>()?;
                    }
                    log::info!("nova-bls-v1 committee gate enabled (uses the Nova prover)");
                }
                #[cfg(not(feature = "nova-v1"))]
                {
                    log::warn!("nova-bls-v1 is configured but nova-v1 feature is not enabled; skipping");
                }
            }
        }
    }

    let active_id = match &ps_config.active {
        ProvingSystemIdConfig::PlonkV1 => ProofSystemId::PlonkV1,
        ProvingSystemIdConfig::NovaV1 => ProofSystemId::NovaV1,
        // `active` selects the prover; the committee proves with Nova.
        ProvingSystemIdConfig::NovaBlsV1 => ProofSystemId::NovaV1,
    };

    if registry.is_registered(active_id) {
        registry.set_active(active_id)?;
    }

    Ok(registry)
}

pub fn map_config_to_id(config: &ProvingSystemIdConfig) -> ProofSystemId {
    match config {
        ProvingSystemIdConfig::PlonkV1 => ProofSystemId::PlonkV1,
        ProvingSystemIdConfig::NovaV1 => ProofSystemId::NovaV1,
        // Applied to the active prover; the committee proves with Nova.
        ProvingSystemIdConfig::NovaBlsV1 => ProofSystemId::NovaV1,
    }
}

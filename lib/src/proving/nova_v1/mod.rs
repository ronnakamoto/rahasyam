//! Nova-SNARK v1 Proving System
//!
//! This module implements the Nova proof system for Nightfall's rollup aggregation.
//! Nova is Microsoft's implementation of a high-speed recursive SNARK using folding schemes.
//!
//! ## Architecture
//!
//! - `step_circuit.rs` - IVC step circuit for rollup verification
//! - `client_engine.rs` - Client proof generation/verification
//! - `rollup_engine.rs` - Rollup block proof generation via IVC
//! - `keys.rs` - Key generation and management
//! - `proof.rs` - Proof serialization types
//!
//! ## References
//!
//! - [Nova-SNARK Documentation](https://docs.rs/nova-snark/0.71.1/)
//! - [Nova GitHub](https://github.com/Microsoft/Nova)
//! - [Nova Paper (CRYPTO 2022)](https://eprint.iacr.org/2021/370)

pub mod client_engine;
#[cfg(feature = "nova-v1")]
pub mod commitment_tree;
#[cfg(feature = "nova-v1")]
pub mod hash;
#[cfg(all(test, feature = "nova-v1"))]
pub mod ivc_integration_tests;
pub mod keys;
#[cfg(feature = "nova-v1")]
pub mod merkle;
pub mod proof;
#[cfg(all(test, feature = "nova-v1"))]
pub mod proposer_repro_tests;
pub mod r1cs_export;
pub mod rollup_engine;
pub mod step_circuit;
#[cfg(feature = "nova-v1")]
pub mod witness;

use alloy::primitives::Address;

use super::{ProofSystemId, ProvingSystem};
use crate::proving::nova_v1::client_engine::NovaClientEngine;
use crate::proving::nova_v1::keys::NovaVerifyingKey;
use crate::proving::nova_v1::proof::NovaClientProof;
use crate::proving::nova_v1::rollup_engine::NovaRollupEngine;

fn get_nova_verifier_address() -> Address {
    // Try to load from configuration addresses first
    if let Ok(addr) = std::env::var("NF4_NOVA_VERIFIER_ADDRESS") {
        if let Ok(parsed) = addr.parse::<Address>() {
            if parsed != Address::ZERO {
                return parsed;
            }
        }
    }

    // Fall back to reading from the addresses.toml file
    let paths = [
        "/app/configuration/toml/addresses.toml",
        "./configuration/toml/addresses.toml",
    ];
    for path in &paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(table) = content.parse::<toml::Table>() {
                if let Some(val) = table.get("nova_verifier").and_then(|v| v.as_str()) {
                    if let Ok(parsed) = val.parse::<Address>() {
                        if parsed != Address::ZERO {
                            return parsed;
                        }
                    }
                }
            }
        }
    }

    // Final fallback: deterministic zero-addr with the low bit set so
    // it is distinguishable from `Address::ZERO` (the PlonkV1 sentinel).
    // A production deployment MUST override this with
    // `NF4_NOVA_VERIFIER_ADDRESS` (or `nova_verifier` in
    // `addresses.toml`); the value below is intentionally a
    // well-known, non-zero placeholder that causes a loud
    // misconfiguration to be observable on-chain (any call to the
    // verifier at this address will revert).
    alloy::primitives::address!("0x0000000000000000000000000000000000000001")
}

pub struct NovaV1System;

impl ProvingSystem for NovaV1System {
    type ClientProof = NovaClientProof;
    type ClientEngine = NovaClientEngine;
    type RollupEngine = NovaRollupEngine;
    type VerifyingKey = NovaVerifyingKey;

    fn id() -> ProofSystemId {
        ProofSystemId::NovaV1
    }

    fn name() -> &'static str {
        "nova-v1"
    }

    fn verifying_key() -> &'static Self::VerifyingKey {
        static VK: NovaVerifyingKey = NovaVerifyingKey::new(1);
        &VK
    }

    fn onchain_verifier() -> Address {
        get_nova_verifier_address()
    }
}

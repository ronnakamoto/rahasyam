use configuration::settings::{self, Settings};
#[cfg(not(feature = "nova-v1"))]
use ark_bn254::{Bn254, Fq as Fq254};
#[cfg(not(feature = "nova-v1"))]
use ark_serialize::{CanonicalSerialize, Write};
#[cfg(not(feature = "nova-v1"))]
use ark_std::rand;
#[cfg(not(feature = "nova-v1"))]
use jf_plonk::{
    errors::PlonkError,
    nightfall::{ipa_structs::VerificationKeyId, FFTPlonk},
    proof_system::UniversalSNARK,
};
#[cfg(feature = "nova-v1")]
use jf_plonk::errors::PlonkError;
#[cfg(not(feature = "nova-v1"))]
use jf_primitives::{pcs::prelude::*, rescue::sponge::RescueCRHF};
#[cfg(not(feature = "nova-v1"))]
use jf_relation::Arithmetization;
#[cfg(not(feature = "nova-v1"))]
use lib::{
    build_transfer_inputs::build_valid_transfer_inputs,
    circuit_key_generation::{generate_rollup_keys_for_production, universal_setup_for_production},
    constants::MAX_KZG_DEGREE,
    nf_client_proof::{PrivateInputs, PublicInputs},
    plonk_prover::circuits::unified_circuit::unified_circuit_builder,
    shared_entities::DepositData,
};
#[cfg(not(feature = "nova-v1"))]
use std::fs::File;
fn main() {
    let settings: Settings = settings::Settings::new().unwrap();
    if settings.mock_prover {
        println!("Generating keys for MOCK rollup prover");
    } else {
        println!("Generating keys for REAL rollup prover");
    }
    let path = std::env::current_dir()
        .expect("Failed to get current path")
        .as_path()
        .join("configuration");
    std::fs::create_dir_all(path.join("bin/keys"))
        .expect("Failed to create directory for proving keys");
    generate_proving_keys(&settings).unwrap();
    println!("Generating keys for rollup prover finished.");
}

/// Generates the proving key and writes it to file.
pub fn generate_proving_keys(settings: &Settings) -> Result<(), PlonkError> {
    // ── Nova-only key generation ──────────────────────────────────────────
    // When the nova-v1 feature is active, the proposer uses NovaRollupEngine
    // exclusively for block proving. The entire Plonk pipeline (circuit
    // building, Powers-of-Tau SRS download, KZG preprocessing, recursive
    // rollup key generation) is not needed and is skipped entirely.
    #[cfg(feature = "nova-v1")]
    {
        if !settings.mock_prover {
            println!("Generating keys for Nova rollup prover");
            lib::proving::nova_v1::keys::pregenerate_nova_keys()
                .expect("Failed to pregenerate Nova keys");
        } else {
            println!("Mock prover mode: skipping Nova key generation");
        }
        return Ok(());
    }

    // ── Plonk key generation (original pipeline) ──────────────────────────
    #[cfg(not(feature = "nova-v1"))]
    {
        // Generate a dummy circuit.
        let (mut public_inputs, mut private_inputs) =
            build_valid_transfer_inputs(&mut ark_std::rand::thread_rng());
        let mut circuit = unified_circuit_builder(&mut public_inputs, &mut private_inputs)?;

        circuit.finalize_for_recursive_arithmetization::<RescueCRHF<Fq254>>()?;

        let deposit_data = [DepositData::default(); 4];
        let mut deposit_public_inputs = PublicInputs::for_deposit();
        let mut deposit_private_inputs = PrivateInputs::for_deposit(&deposit_data);
        let mut deposit_base_circuit =
            unified_circuit_builder(&mut deposit_public_inputs, &mut deposit_private_inputs)?;
        deposit_base_circuit.finalize_for_recursive_arithmetization::<RescueCRHF<Fq254>>()?;
        let mut rng = rand::thread_rng();

        // locate the configuration directory
        let path = std::env::current_dir()?.as_path().join("configuration");

        // if we're using a mock prover, we won't waste time downloading a real Perpetual Powers of Tau file
        // and generating a structured reference string
        let kzg_srs = if settings.mock_prover {
            // The client/deposit circuit is far smaller than 2^MAX_KZG_DEGREE.
            // Sizing the test SRS to the actual circuit (rather than the rollup's
            // 2^MAX_KZG_DEGREE) avoids generating tens of millions of needless
            // SRS elements, which otherwise exhausts memory on modest machines.
            let srs_size = circuit
                .srs_size(true)
                .expect("Failed to compute client circuit SRS size")
                .max(
                    deposit_base_circuit
                        .srs_size(true)
                        .expect("Failed to compute deposit circuit SRS size"),
                );
            FFTPlonk::<UnivariateKzgPCS<Bn254>>::universal_setup_for_testing(srs_size, &mut rng)
                .unwrap()
        } else {
            // Unless we already have a local copy, read a remote perpetual powers of Tau file and save, then extract a KZG structured reference string
            universal_setup_for_production(MAX_KZG_DEGREE)
                .expect("Failed to perform universal trusted setup for production.")
        };
        // transfer/withdraw pk vk
        let (pk, _) = FFTPlonk::<UnivariateKzgPCS<Bn254>>::preprocess(
            &kzg_srs,
            Some(VerificationKeyId::Client),
            &circuit,
            true,
        )?;
        // deposit pk vk
        let pk_path = path.join("bin/keys/proving_key");
        let mut file = File::create(pk_path).map_err(PlonkError::IoError)?;
        let mut compressed_bytes = Vec::new();
        pk.serialize_compressed(&mut compressed_bytes)?;
        file.write_all(&compressed_bytes)
            .map_err(PlonkError::IoError)?;

        // if we're using a mock prover, we don't need an IPA proof at all, if we are using a real prover then we'll generate a real IPA SRS
        if !settings.mock_prover {
            // this part will generate base_grumpkin_pk, base_bn254_pk, merge_grumpkin_pk, merge_bn254_pk, decider_vk, decider_pk in fn preprocess() located in nightfall_proposer/src/driven/rollup_prover.rs
            generate_rollup_keys_for_production(
                deposit_base_circuit,
                deposit_public_inputs,
                path.join("bin/keys/proving_key"),
                &kzg_srs,
            )?;
        }

        Ok(())
    }
}

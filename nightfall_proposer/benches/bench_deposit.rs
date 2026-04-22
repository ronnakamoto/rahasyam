use ark_bn254::Bn254;
use ark_ff::Zero;
use ark_std::UniformRand;
use criterion::{criterion_group, criterion_main, Criterion};
use jf_plonk::{
    nightfall::{ipa_structs::VerificationKeyId, FFTPlonk},
    proof_system::UniversalSNARK,
    transcript::StandardTranscript,
};
use jf_primitives::pcs::prelude::UnivariateKzgPCS;
use jf_relation::{Arithmetization, Circuit};
use jf_utils::test_rng;
use lib::{
    nf_client_proof::{PrivateInputs, PublicInputs},
    nf_token_id::to_nf_token_id_from_fr254,
    plonk_prover::circuits::unified_circuit::unified_circuit_builder,
    shared_entities::DepositData,
};
use nf_curves::ed_on_bn254::Fq as Fr254;
use std::time::{Duration, Instant};

fn benchmark_unified_deposit(c: &mut Criterion) {
    let rng = &mut test_rng();
    let token_id = Fr254::rand(rng);
    let erc_address = Fr254::rand(rng);
    let nf_token_id = to_nf_token_id_from_fr254(erc_address, token_id);

    let deposit_data: [DepositData; 4] = (0..4)
        .map(|i| {
            if i.is_zero() {
                DepositData::default()
            } else {
                let nf_slot_id = Fr254::rand(rng);
                let value = Fr254::rand(rng);
                let secret_hash = Fr254::rand(rng);
                DepositData {
                    nf_token_id,
                    nf_slot_id,
                    value,
                    secret_hash,
                }
            }
        })
        .collect::<Vec<DepositData>>()
        .try_into()
        .unwrap();

    let mut public_input = PublicInputs::for_deposit();
    let mut private_inputs = PrivateInputs::for_deposit(&deposit_data);
    let mut circuit = unified_circuit_builder(&mut public_input, &mut private_inputs).unwrap();

    println!(
        "Deposit: {} constraints before padding",
        circuit.num_gates()
    );
    let mut rng = ark_std::rand::thread_rng();

    circuit.finalize_for_arithmetization().unwrap();

    let srs_size = circuit.srs_size(true).unwrap();

    let srs = FFTPlonk::<UnivariateKzgPCS<Bn254>>::universal_setup_for_testing(srs_size, &mut rng)
        .unwrap();
    let (pk, vk) = FFTPlonk::<UnivariateKzgPCS<Bn254>>::preprocess(
        &srs,
        Some(VerificationKeyId::Client),
        &circuit,
        true,
    )
    .unwrap();
    let start = Instant::now();
    let proof = FFTPlonk::<UnivariateKzgPCS<Bn254>>::prove::<_, _, StandardTranscript>(
        &mut rng, &circuit, &pk, None, true,
    )
    .unwrap();
    println!(
        "Deposit Circuit Proving time:{} ms",
        start.elapsed().as_millis()
    );
    c.bench_function("Deposit Circuit Proving time:", |b| {
        b.iter(|| {
            FFTPlonk::<UnivariateKzgPCS<Bn254>>::prove::<_, _, StandardTranscript>(
                &mut rng, &circuit, &pk, None, true,
            )
            .unwrap();
        })
    });
    let mut inputs = Vec::new();
    inputs.push(public_input.fee);
    inputs.push(public_input.root);
    inputs.extend_from_slice(&public_input.commitments);
    inputs.extend_from_slice(&public_input.nullifiers);
    inputs.extend_from_slice(&public_input.compressed_secrets);
    let start = Instant::now();
    FFTPlonk::<UnivariateKzgPCS<Bn254>>::verify::<StandardTranscript>(
        &vk, &inputs, &proof, None, true,
    )
    .unwrap();
    println!(
        "Deposit Circuit Verifying time:{} ms",
        start.elapsed().as_millis()
    );
    c.bench_function("Deposit Circuit Verifying time:", |b| {
        b.iter(|| {
            FFTPlonk::<UnivariateKzgPCS<Bn254>>::verify::<StandardTranscript>(
                &vk, &inputs, &proof, None, true,
            )
            .unwrap();
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(2)).warm_up_time(Duration::from_secs(1));
    targets = benchmark_unified_deposit
}
criterion_main!(benches);

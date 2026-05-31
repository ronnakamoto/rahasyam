use crate::{
    domain::entities::ClientTransactionWithMetaData,
    driven::rollup_prover::RollupProofError,
    ports::proving::RecursiveProvingEngine,
};
use ark_bn254::{Fq as Fq254, Fr as Fr254};
use ark_std::Zero;
use lib::{
    nf_client_proof::PublicInputs,
    shared_entities::DepositData,
};

// Implement the Proposer's RecursiveProvingEngine for NovaRollupEngine
impl RecursiveProvingEngine<lib::proving::nova_v1::proof::NovaClientProof> for lib::proving::nova_v1::rollup_engine::NovaRollupEngine {
    type PreppedInfo = Vec<lib::proving::nova_v1::rollup_engine::RollupCircuit>;
    type Error = RollupProofError;
    type RecursiveProof = Vec<Fq254>;

    async fn prepare_state_transition(
        deposit_transactions: &[(lib::proving::nova_v1::proof::NovaClientProof, PublicInputs)],
        transactions: &[ClientTransactionWithMetaData<lib::proving::nova_v1::proof::NovaClientProof>],
    ) -> Result<(Self::PreppedInfo, [Fr254; 3]), Self::Error> {
        use crate::initialisation::get_db_connection;
        use crate::ports::trees::{CommitmentTree, NullifierTree, HistoricRootTree};
        use lib::merkle_trees::trees::MutableTree;
        use lib::proving::nova_v1::merkle::{MerklePathHop, ImtNonInclusionWitness};
        use lib::proving::nova_v1::rollup_engine::{RollupCircuit, F1};
        use jf_primitives::trees::Directions;
        use ark_ff::{PrimeField as ArkPrimeField, BigInteger};
        use ff::PrimeField as FfPrimeField;

        fn fr254_to_f1(fr: Fr254) -> F1 {
            let bytes = fr.into_bigint().to_bytes_le();
            let mut repr = <F1 as FfPrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(&bytes[..32]);
            <F1 as FfPrimeField>::from_repr(repr).unwrap()
        }

        let db_conn = get_db_connection().await;
        let mut db = db_conn.clone();

        let mut new_commitments = vec![];
        let mut insert_nullifiers = vec![];

        for (_, pi) in deposit_transactions {
            new_commitments.extend_from_slice(&pi.commitments);
            insert_nullifiers.extend_from_slice(&pi.nullifiers);
        }

        for tx in transactions {
            new_commitments.extend_from_slice(&tx.client_transaction.commitments);
            insert_nullifiers.extend_from_slice(&tx.client_transaction.nullifiers);
        }

        let max_steps = std::cmp::max(new_commitments.len(), insert_nullifiers.len());
        new_commitments.resize(max_steps, Fr254::zero());
        insert_nullifiers.resize(max_steps, Fr254::zero());

        let current_historic_root_fr = <mongodb::Client as MutableTree<Fr254>>::get_root(
            db_conn,
            <mongodb::Client as HistoricRootTree<Fr254>>::TREE_NAME
        ).await.map_err(|e| {
            RollupProofError::ParameterError(format!("DB error getting historic root: {:?}", e))
        })?;
        let current_historic_root = fr254_to_f1(current_historic_root_fr);

        fn path_to_hops(path: &[jf_primitives::trees::PathElement<Fr254>]) -> Vec<MerklePathHop<F1>> {
            path.iter().map(|p| MerklePathHop {
                sibling: fr254_to_f1(p.value),
                is_right: matches!(p.direction, Directions::HashWithThisNodeOnRight),
            }).collect()
        }

        let mut rollup_circuits = Vec::with_capacity(max_steps);

        for i in 0..max_steps {
            let commitment_fr = new_commitments[i];
            let nullifier_fr = insert_nullifiers[i];

            let comm_info = <mongodb::Client as CommitmentTree<Fr254>>::insert_for_circuit(&mut db, &[commitment_fr])
                .await
                .map_err(|e| RollupProofError::ParameterError(format!("DB error inserting commitment: {:?}", e)))?;

            let null_info = <mongodb::Client as NullifierTree<Fr254>>::insert_for_circuit(&mut db, &[nullifier_fr])
                .await
                .map_err(|e| RollupProofError::ParameterError(format!("DB error inserting nullifier: {:?}", e)))?;

            let commitment_path = path_to_hops(&comm_info.proof.sibling_path);

            let low_leaf = &null_info.low_nullifiers[0].0;
            let low_proof = &null_info.low_nullifiers[0].1;

            let nullifier_witness = ImtNonInclusionWitness {
                nullifier: fr254_to_f1(nullifier_fr),
                low_value: fr254_to_f1(low_leaf.value),
                low_next_index: fr254_to_f1(low_leaf.next_index),
                low_next_value: fr254_to_f1(low_leaf.next_value),
                path: path_to_hops(&low_proof.sibling_path),
            };

            let circuit = RollupCircuit::new_real(
                32, // merkle_depth
                fr254_to_f1(comm_info.new_root),
                fr254_to_f1(null_info.circuit_info.new_root),
                current_historic_root,
                fr254_to_f1(commitment_fr),
                commitment_path,
                nullifier_witness,
            );

            rollup_circuits.push(circuit);
        }

        let final_commitments_root = <mongodb::Client as MutableTree<Fr254>>::get_root(
            db_conn,
            <mongodb::Client as CommitmentTree<Fr254>>::TREE_NAME
        ).await.map_err(|e| {
            RollupProofError::ParameterError(format!("DB error getting commitment root: {:?}", e))
        })?;
        let final_nullifiers_root = <mongodb::Client as MutableTree<Fr254>>::get_root(
            db_conn,
            <mongodb::Client as NullifierTree<Fr254>>::TREE_NAME
        ).await.map_err(|e| {
            RollupProofError::ParameterError(format!("DB error getting nullifier root: {:?}", e))
        })?;

        let updated_historic_root_fr =
            <mongodb::Client as HistoricRootTree<Fr254>>::append_historic_commitment_root(
                &mut db,
                &final_commitments_root,
                false,
            )
            .await.map_err(|e| {
                RollupProofError::ParameterError(format!("DB error appending historic root: {:?}", e))
            })?;

        Ok((rollup_circuits, [final_commitments_root, final_nullifiers_root, updated_historic_root_fr]))
    }

    fn recursive_prove(info: Self::PreppedInfo) -> Result<Vec<Fq254>, Self::Error> {
        use ark_ff::PrimeField;

        let engine = lib::proving::nova_v1::rollup_engine::NovaRollupEngine::new();
        let proof = engine.prove_circuits(info).map_err(|e| RollupProofError::ParameterError(format!("Nova prove error: {}", e)))?;
        
        // Serialize the real NovaProof to bytes
        let proof_bytes = bincode::serialize(&proof)
            .map_err(|e| RollupProofError::ParameterError(format!("Nova proof serialization error: {}", e)))?;

        // Convert the raw proof bytes into a Vec<Fq254> in a loss-free manner.
        // We pack 31 bytes per field element to ensure no modulo reduction.
        let mut fq_vec = Vec::new();
        for chunk in proof_bytes.chunks(31) {
            let mut padded = [0u8; 32];
            padded[1..chunk.len() + 1].copy_from_slice(chunk);
            let element = Fq254::from_be_bytes_mod_order(&padded);
            fq_vec.push(element);
        }

        // To ensure the Solidity verifier's length checks pass (which requires at least 320 bytes, i.e., 10 Fq254 elements),
        // we pad the vector to at least 10 elements if needed.
        while fq_vec.len() < 10 {
            fq_vec.push(Fq254::zero());
        }

        Ok(fq_vec)
    }

    fn create_deposit_proof(
        deposit_data: &[DepositData; 4],
        public_inputs: &mut PublicInputs,
    ) -> Result<lib::proving::nova_v1::proof::NovaClientProof, Self::Error> {
        use lib::nf_client_proof::ProvingEngine;
        use lib::proving::nova_v1::client_engine::NovaClientEngine;
        use lib::nf_client_proof::PrivateInputs;

        let mut private_inputs = PrivateInputs::for_deposit(deposit_data);
        *public_inputs = PublicInputs::for_deposit();

        NovaClientEngine::prove(&mut private_inputs, public_inputs)
            .map_err(|e| RollupProofError::ParameterError(format!("Nova deposit proof error: {}", e)))
    }
}

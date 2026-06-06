use std::{error::Error, fmt::Display};
use log::info;
use tokio::time::Instant;

use crate::{
    domain::entities::{Block, ClientTransactionWithMetaData},
    drivers::blockchain::block_assembly::BlockAssemblyError,
};
use ark_bn254::{Fq as Fq254, Fr as Fr254};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::SerializationError;
use lib::error::ConversionError;
use lib::{
    nf_client_proof::{Proof, ProvingEngine, PublicInputs},
    shared_entities::DepositData,
    shared_entities::OnChainTransaction,
};

/// A trait for a proving engine that can recursively prove multiple transactions are valid.
#[allow(async_fn_in_trait)]
pub trait RecursiveProvingEngine<P: Proof> {
    /// This type is defined by the implementation based on how the proving engine proves state transitions.
    type PreppedInfo: std::fmt::Debug + Send + 'static;
    /// The error type returned if unable to prove.
    type Error: Error
        + Display
        + Into<BlockAssemblyError>
        + From<SerializationError>
        + From<ConversionError>
        + Send
        + 'static;
    /// The type of proof output by this recursive proving engine
    type RecursiveProof: Into<Vec<Fq254>> + Send + 'static;

    /// This function takes in the list of client transactions to be proved and outputs the formed [`Block`]
    async fn prove_block(
        deposit_transactions: &[(P, PublicInputs)],
        client_transactions: &[ClientTransactionWithMetaData<P>],
    ) -> Result<Block, Self::Error> {
        let prove_block_start = Instant::now();

        info!("[prove_block] Starting prepare_state_transition ({} deposits, {} client txs)...",
            deposit_transactions.len(), client_transactions.len());
        let prep_start = Instant::now();
        // Snapshot the authoritative JF trees before `prepare_state_transition`
        // mutates them speculatively, so the block can be rolled back if it
        // fails to land on-chain. On a prepare failure we restore immediately so
        // partial inserts never leak into the trees; on success the snapshot is
        // retained (keyed to this block) for the finality/event paths. The
        // tree-mutation lock serialises this against a concurrent rollback on
        // the finality task.
        let db = crate::initialisation::get_db_connection().await;
        let (info, [commitments_root, nullifiers_root, commitments_root_root]) = {
            let _tree_guard = crate::driven::speculative_state::tree_mutation_lock().await;
            crate::driven::speculative_state::begin(db).await;
            match Self::prepare_state_transition(deposit_transactions, client_transactions).await {
                Ok(v) => {
                    crate::driven::speculative_state::confirm_prepare(v.1[0]).await;
                    v
                }
                Err(e) => {
                    crate::driven::speculative_state::abort_prepare(db).await;
                    return Err(e);
                }
            }
        };
        info!("[prove_block] prepare_state_transition completed in {:.2}s", prep_start.elapsed().as_secs_f64());

        info!("[prove_block] Starting recursive_prove (offloaded to blocking thread pool)...");
        let prove_start = Instant::now();
        let proof = tokio::task::spawn_blocking(move || {
            Self::recursive_prove(info)
        })
        .await
        .map_err(|_e| {
            // JoinError → convert to our Error type via ConversionError
            ConversionError::ParseFailed
        })??;
        info!("[prove_block] recursive_prove completed in {:.2}s", prove_start.elapsed().as_secs_f64());

        let serialize_start = Instant::now();
        let proof_vec: Vec<Fq254> = proof.into();
        let proof_bytes = proof_vec
            .into_iter()
            .flat_map(|x| {
                let mut bytes: Vec<u8> = x.into_bigint().to_bytes_le();
                bytes.resize(32, 0u8);
                bytes.reverse();
                bytes
            })
            .collect::<Vec<u8>>();
        info!("[prove_block] Proof serialization completed in {:.2}s ({} bytes)",
            serialize_start.elapsed().as_secs_f64(), proof_bytes.len());

        let result = Ok(Block {
            commitments_root,
            nullifiers_root,
            commitments_root_root,
            transactions: deposit_transactions
                .iter()
                .map(|(_, pi)| OnChainTransaction::from(pi))
                .chain(
                    client_transactions
                        .iter()
                        .map(|t| (&t.client_transaction).into()),
                )
                .collect::<_>(),
            rollup_proof: proof_bytes,
            block_number: 0,
            // The proof-system ID is taken from the proof type's
            // associated `system_id()` (see `lib::nf_client_proof::Proof`)
            // so that the on-chain verifier receives a proof_system_id
            // field that matches the leading byte the proposer writes
            // via `Block::tagged_rollup_proof`.
            proof_system_id: P::system_id(),
            // Plonk blocks leave the Nova-specific IVC state at the
            // default. The Nova proposer populates these fields after
            // the IVC fold completes; this path doesn't have access to
            // them yet.
            nova_ivc_state: Default::default(),
        });
        info!("[prove_block] Total prove_block completed in {:.2}s", prove_block_start.elapsed().as_secs_f64());
        result
    }
    /// The proving engine decides how it handles proving state transition so we make it define how it needs the
    /// commitment and nullifier information structured. This method returns the prepped info ready to be passed to the proving function as well as
    /// the new commitment, nullifier and historic root root in that order.
    async fn prepare_state_transition(
        deposit_transactions: &[(P, PublicInputs)],
        transactions: &[ClientTransactionWithMetaData<P>],
    ) -> Result<(Self::PreppedInfo, [Fr254; 3]), Self::Error>;
    /// This function performs the recursive proving based on the prepped information
    fn recursive_prove(info: Self::PreppedInfo) -> Result<Self::RecursiveProof, Self::Error>;
    fn verify_client_proof<E: ProvingEngine<P>>(
        &self,
        proof: &P,
        public_inputs: &PublicInputs,
    ) -> Result<bool, Self::Error> {
        E::verify(proof, public_inputs).map_err(|_| Self::Error::from(ConversionError::ParseFailed))
    }
    /// Function to create a deposit proof
    fn create_deposit_proof(
        deposit_data: &[DepositData; 4],
        public_inputs: &mut PublicInputs,
    ) -> Result<P, Self::Error>;

    /// Whether the engine requires every block to contain exactly `block_size`
    /// transactions. Fixed-arity SNARKs (Plonk) must return `true`. IVC schemes
    /// (Nova) may return `false` to allow blocks with a dynamic number of
    /// transactions in `[1, block_size]`.
    ///
    /// The default is `true` so existing engines (Plonk, mock) keep their
    /// current padding behaviour without changes.
    fn requires_padding() -> bool {
        true
    }
}

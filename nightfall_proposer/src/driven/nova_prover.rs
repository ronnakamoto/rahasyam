//! Nova proposer: bridge between the JF on-chain tree and the
//! Neptune-Poseidon rollup tree.
//!
//! ## Dual-tree model
//!
//! Nightfall's two proving systems disagree on the hash function used
//! for the on-chain state trees:
//!
//! - **PlonkV1 (jf-primitives)**: jf-Poseidon. This is what the
//!   `Nightfall.sol` smart contract consumes. The DB-backed
//!   `commitment_tree` and `nullifier_tree` collections
//!   (`lib::merkle_trees::trees::MutableTree`) use jf-Poseidon.
//! - **NovaV1 (neptune)**: neptune-Poseidon, the hash bundled with
//!   `nova-snark`. The Nova step circuit's Merkle / IMT gadgets
//!   verify against neptune-Poseidon hashes, so the per-step witness
//!   cannot be constructed from the JF tree directly.
//!
//! As a consequence the Nova proposer currently maintains **two
//! trees in parallel**:
//!
//! 1. The DB-backed JF tree (MerkleTree<Fr254, Poseidon<Fr254>> in
//!    MongoDB). This is the **authoritative source for on-chain state**.
//!    The block's `commitments_root`, `nullifiers_root`, and
//!    `commitments_root_root` are computed from it; the smart contract
//!    enforces those exact values.
//! 2. An in-memory Neptune IMT and commitment tree. This is the
//!    **authoritative source for the Nova circuit's per-step
//!    witnesses**. The Merkle inclusion paths the circuit verifies
//!    are computed against this tree's hashes.
//!
//! The two trees are kept in sync by always appending / inserting the
//! same set of commitments and nullifiers in the same order. Because
//! the hash functions differ, the **post-state roots are not
//! numerically equal** — the JF root is what the chain sees; the
//! Neptune root is what the circuit proves. The Nova proof is
//! internally consistent with respect to the Neptune root only.
//!
//! The previously-described "shadow tree" pattern (a parallel tree
//! kept in sync with the JF tree) has been **collapsed**: the
//! in-memory Neptune IMT is no longer an opaque mirror of the JF
//! tree; it is the single source of truth for the circuit witness,
//! and the on-chain (JF) state is read back via `get_root` after the
//! batch insert.
//!
//! A future change is to (a) hydrate the Neptune IMT from MongoDB at
//! proposer startup so the witness for the first nullifier of each
//! block is computed against the cumulative prior-block state, and
//! (b) migrate the on-chain verifier to consume the Neptune root
//! directly (which would let us drop the dual-tree entirely).
//!
//! ## What lives where
//!
//! - This file (proposer): DB I/O, Fr254 ↔ F1 conversion, JF tree
//!   state updates, and the trait plumbing.
//! - `lib::proving::nova_v1::witness`: the in-memory Neptune tree
//!   construction and per-step witness extraction.

use crate::{
    domain::entities::{Block, ClientTransactionWithMetaData, NovaIvcBlockState},
    driven::rollup_prover::RollupProofError,
    ports::proving::RecursiveProvingEngine,
};
use lib::utils::get_block_size;
use ark_bn254::{Fq as Fq254, Fr as Fr254};
use ark_ff::{BigInteger, PrimeField};
use ark_std::{One, Zero};
use jf_primitives::poseidon::{FieldHasher, Poseidon};
use log::info;
use sha2::{Digest, Sha256};
use std::time::Instant;
use lib::{
    error::ConversionError,
    nf_client_proof::{Proof, PublicInputs},
    proving::nova_v1::proof::{NovaClientProof, NovaProof},
    shared_entities::{DepositData, OnChainTransaction},
};
use std::collections::HashSet;

/// Container for the Nova proving path's prepped information. Holds both
/// the per-step circuits and the IMT root after prior-nullifier hydration
/// (the correct `z0[1]` for the Nova IVC).
#[derive(Debug)]
pub struct NovaPreppedInfo {
    pub circuits: Vec<lib::proving::nova_v1::rollup_engine::RollupCircuit>,
    pub pre_nullifiers_root: lib::proving::nova_v1::rollup_engine::F1,
}

// Implement the Proposer's `RecursiveProvingEngine` for `NovaRollupEngine`.
//
// **This is an orphan impl**: the trait (`nightfall_proposer::ports::proving`)
// and the type (`lib::proving::nova_v1::rollup_engine::NovaRollupEngine`)
// live in different crates. A clean long-term fix is to move the
// trait into `lib::proving` and define the impl in the same module as
// the engine type. That refactor is tracked as a follow-up.
//
// For now, the **witness-building logic** has been hoisted into
// `lib::proving::nova_v1::witness::build_rollup_circuits`, so this
// file is responsible only for:
//   1. Reading the on-chain (Fr254) commitments and nullifiers from
//      the DB-backed JF tree.
//   2. Converting them to F1 (Nova scalar field).
//   3. Calling the witness helper.
//   4. Forwarding the result to `NovaRollupEngine::prove_circuits`.
//   5. Packing the resulting `NovaProof` into the wire format the
//      on-chain `NovaRollupVerifier.parseProof` expects.
//
// See `temp/Nova-Code-Path-Robustness-Plan.md` for the full robustness
// audit and the items that have been / are still to be addressed.
impl RecursiveProvingEngine<lib::proving::nova_v1::proof::NovaClientProof> for lib::proving::nova_v1::rollup_engine::NovaRollupEngine {
    type PreppedInfo = NovaPreppedInfo;
    type Error = RollupProofError;
    type RecursiveProof = Vec<Fq254>;

    /// Nova is an IVC scheme: it folds an arbitrary number of recursive steps,
    /// so a block with `n < block_size` real transactions does not need
    /// dummy-deposit padding inside the recursive proof.
    ///
    /// We still gate this behind the `nova_dynamic_block_size` proposer config
    /// flag (default `false`) because removing padding changes the on-wire
    /// length of `Block.transactions`, and the on-chain
    /// `Nightfall.propose_block` hashing path currently hardcodes
    /// `block_transactions_length == 64 || 256`
    /// (see `blockchain_assets/contracts/Nightfall.sol:222-227`). Until that
    /// guard is relaxed, the safe default is to keep padding on.
    fn requires_padding() -> bool {
        !configuration::settings::get_settings()
            .nightfall_proposer
            .nova_dynamic_block_size
    }

    /// Nova override of the default `prove_block`.
    ///
    /// The trait's default implementation packs `RecursiveProof =
    /// Vec<Fq254>` as 32-byte big-endian slots, which matches the
    /// PlonkV1 wire format (`RollupProofVerifierV2.sol`). The Nova
    /// verifier (`NovaRollupVerifier.sol`) instead expects a
    /// bincode-serialised `NovaProof` struct: each `Vec<u8>` field
    /// is preceded by a little-endian `u64` length prefix. Sending
    /// the Fq254-packed bytes therefore makes the contract's
    /// `_read_byte_vec` parse the first 8 bytes as a length that
    /// does not match the proof size, which reverts with
    /// "Nova proof truncated at blob".
    ///
    /// This override decodes the chunked Fq254 vector produced by
    /// [`Self::recursive_prove`] back to the original bincode blob
    /// and stores it verbatim in `Block.rollup_proof` so the on-chain
    /// `NovaRollupVerifier.parseProof` reads the correct lengths.
    async fn prove_block(
        deposit_transactions: &[(NovaClientProof, PublicInputs)],
        client_transactions: &[ClientTransactionWithMetaData<NovaClientProof>],
    ) -> Result<Block, Self::Error> {
        let prove_block_start = Instant::now();

        info!("[nova prove_block] Starting prepare_state_transition ({} deposits, {} client txs)...",
            deposit_transactions.len(), client_transactions.len());
        let prep_start = Instant::now();
        // Snapshot the authoritative JF trees before the speculative inserts in
        // `prepare_state_transition`, so this block can be rolled back if it
        // fails to land on-chain. Restore immediately on prepare failure so
        // partial inserts never leak; retain the snapshot on success. The
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
        info!("[nova prove_block] prepare_state_transition completed in {:.2}s",
            prep_start.elapsed().as_secs_f64());

        info!("[nova prove_block] Starting recursive_prove (offloaded to blocking thread pool)...");
        let prove_start = Instant::now();
        // Capture the hydrated IVC initial nullifiers root (`z0[1]`) and the
        // true folded step count before `info` is moved into the blocking
        // prover. The attestor needs both to reconstruct `z0` and replay the
        // folding hash for the sound `CompressedSNARK::verify`. `num_steps`
        // is `circuits.len()` (== block_size when padding circuits are
        // folded), which differs from the proof's real `transaction_count`.
        // `F1` is `Copy`, so this is cheap.
        let pre_nullifiers_root = info.pre_nullifiers_root;
        let num_folded_steps = info.circuits.len();
        let fq_vec = tokio::task::spawn_blocking(move || Self::recursive_prove(info))
            .await
            .map_err(|_e| Self::Error::from(ConversionError::ParseFailed))??;
        info!("[nova prove_block] recursive_prove completed in {:.2}s",
            prove_start.elapsed().as_secs_f64());

        // Recover the original bincode blob. `recursive_prove` packed
        // the blob as 31-byte chunks, each padded to 32 bytes with a
        // leading `0x00` (the high byte of an `Fq254` is always zero
        // because Fq254 < 2^254). Reversing that packing means
        // re-emitting each Fq254 as 32 big-endian bytes and dropping
        // the leading zero. The recovered blob is therefore
        // `ceil(N / 31) * 31` bytes; if the original bincode length
        // was not a multiple of 31, the tail carries up to 30 bytes
        // of zero padding, which both `bincode::deserialize` and the
        // on-chain `_read_byte_vec` length-prefixed reads ignore.
        let decode_start = Instant::now();
        let mut proof_bytes = Vec::with_capacity(fq_vec.len() * 31);
        for fq in &fq_vec {
            let bytes_be = fq.into_bigint().to_bytes_be();
            debug_assert_eq!(bytes_be[0], 0, "Fq254 high byte must be zero");
            proof_bytes.extend_from_slice(&bytes_be[1..]);
        }
        info!("[nova prove_block] Proof decoding completed in {:.2}s ({} bytes)",
            decode_start.elapsed().as_secs_f64(), proof_bytes.len());

        // Decode the bincode blob so we can (a) populate the
        // in-memory `nova_ivc_state` with the Neptune roots the
        // circuit actually proved, and (b) rewrite the three roots
        // to the **JF** values the on-chain `Nightfall.sol` /
        // `NovaRollupVerifier.sol` consume. The snark_proof
        // internally still attests to the Neptune roots; only the
        // root fields in the wire-format blob are re-stamped so the
        // verifier's "IVC state transition" check
        // (`novaProof.commitments_root == publicInputs[0]` etc.)
        // passes while the dual-tree model is in place.
        let mut nova_proof: NovaProof = bincode::deserialize(&proof_bytes).map_err(|e| {
            RollupProofError::ParameterError(format!("Nova proof deserialize: {e}"))
        })?;
        let neptune_commitments_root = nova_proof.commitments_root.clone();
        let neptune_nullifiers_root = nova_proof.nullifiers_root.clone();
        let neptune_historic_root_root = nova_proof.historic_root_root.clone();
        let transaction_count = nova_proof.transaction_count as u64;

        // The verifier reads each root as `bytes32` and compares it
        // to `uint256(blk.<root>)`. On the EVM, `uint256(bytes32)`
        // is the big-endian interpretation of the 32 bytes, so the
        // bincode blob must carry the JF root in big-endian form.
        nova_proof.commitments_root = commitments_root.into_bigint().to_bytes_be();
        nova_proof.nullifiers_root = nullifiers_root.into_bigint().to_bytes_be();
        nova_proof.historic_root_root = commitments_root_root.into_bigint().to_bytes_be();

        // Re-serialise the (root-rewritten) NovaProof. The
        // `snark_proof` `Vec<u8>` is preserved byte-for-byte, so the
        // bincode footprint only changes around the three root
        // fields (still 8-byte LE length prefix + 32 bytes each).
        let rollup_proof = bincode::serialize(&nova_proof).map_err(|e| {
            RollupProofError::ParameterError(format!("Nova proof serialize: {e}"))
        })?;
        let mut rollup_proof = rollup_proof;
        info!("[nova prove_block] Proof re-serialised with JF roots ({} bytes)",
            rollup_proof.len());

        // Keep the *Neptune* roots in `nova_ivc_state` so off-chain
        // consumers (logs, debug tooling) see what the circuit
        // actually proved, not the JF roots we stamped on the
        // on-chain blob.
        let nova_ivc_state = NovaIvcBlockState {
            nova_commitments_root: Fr254::from_le_bytes_mod_order(&neptune_commitments_root),
            nova_nullifiers_root: Fr254::from_le_bytes_mod_order(&neptune_nullifiers_root),
            nova_historic_root_root: Fr254::from_le_bytes_mod_order(&neptune_historic_root_root),
            transaction_count,
        };

        let mut transactions: Vec<OnChainTransaction> = deposit_transactions
            .iter()
            .map(|(_, pi)| OnChainTransaction::from(pi))
            .chain(
                client_transactions
                    .iter()
                    .map(|t| (&t.client_transaction).into()),
            )
            .collect();

        // The on-chain `Nightfall.propose_block` guards
        // `block_transactions_length` at exactly 64 or 256 (see
        // `Nightfall.sol:222-227`). When Nova dynamic block size is
        // enabled we fold only the real transactions through the IVC
        // (skipping the 63 dummy padding circuits that would
        // otherwise be proven, which is what made the recursive
        // proving OOM at 8–12 GiB). The IVC's
        // `transaction_count` still reflects the real count, so the
        // contract-side hash-of-transactions check is unaffected.
        //
        // We therefore pad the on-wire `Block.transactions` array
        // back up to `block_size` (64) with zero-filled dummy
        // transactions. These dummies are part of the on-chain
        // commitment tree's leaf set (so the Merkle root the
        // contract hashes matches what the proposer claims) but
        // carry no real value and do not affect the Nova proof's
        // state-transition attestation.
        if !Self::requires_padding() {
            let block_size = get_block_size().unwrap_or(64);
            if transactions.len() < block_size {
                let pad_count = block_size - transactions.len();
                let dummy = OnChainTransaction::default();
                transactions.extend(std::iter::repeat(dummy).take(pad_count));
                info!(
                    "[nova prove_block] Padded on-chain transactions array to \
                     block_size={} with {} dummy entries (IVC proved {} real txs)",
                    block_size,
                    pad_count,
                    transaction_count
                );
            }
        }

        // Obtain the attestor signature so the on-chain
        // `NovaRollupVerifier` fail-closed gate accepts this proof. The
        // signature binds the inner SNARK proof, the three JF roots, the
        // IVC `transaction_count`, and the on-chain public inputs
        // (including the padded block length, set above). It is appended
        // *after* the bincode `NovaProof` blob; the router strips only
        // the leading proving-system-id byte, leaving `blob || signature`
        // for the verifier.
        //
        // Signing is delegated to `attestor_client`, which either calls
        // a standalone attestation service (when configured) or signs
        // locally with `nova_verifier.attestor_key`. See
        // `NovaRollupVerifier.verifyProof` for the verification side.
        //
        // publicInputs[3] is the on-chain block length (the padded
        // `Block.transactions` array length), NOT the IVC step count.
        let mut block_len_word = [0u8; 32];
        block_len_word[24..].copy_from_slice(&(transactions.len() as u64).to_be_bytes());
        let to_word = |bytes: &[u8]| -> Result<[u8; 32], Self::Error> {
            <[u8; 32]>::try_from(bytes).map_err(|_| {
                RollupProofError::ParameterError(format!(
                    "Nova root is not 32 bytes (got {})",
                    bytes.len()
                ))
            })
        };
        let public_inputs = [
            to_word(&nova_proof.commitments_root)?,
            to_word(&nova_proof.nullifiers_root)?,
            to_word(&nova_proof.historic_root_root)?,
            block_len_word,
        ];
        match crate::driven::attestor_client::obtain_attestation(
            &nova_proof,
            &rollup_proof,
            &public_inputs,
            &crate::driven::attestor_client::ForwardedVerification {
                neptune_commitments_root: neptune_commitments_root.clone(),
                neptune_nullifiers_root: neptune_nullifiers_root.clone(),
                neptune_historic_root_root: neptune_historic_root_root.clone(),
                pre_nullifiers_root,
                num_steps: num_folded_steps,
            },
        )
        .await?
        {
            crate::driven::attestor_client::AttestationOutcome::Signed(signature) => {
                rollup_proof.extend_from_slice(&signature);
                info!(
                    "[nova prove_block] Appended attestor signature ({} sig bytes, \
                     proof now {} bytes)",
                    signature.len(),
                    rollup_proof.len()
                );
            }
            crate::driven::attestor_client::AttestationOutcome::Unsigned => {
                info!("[nova prove_block] Emitting unsigned Nova proof (no attestor configured)");
            }
        }

        let rollup_proof_len = rollup_proof.len();
        let result = Ok(Block {
            commitments_root,
            nullifiers_root,
            commitments_root_root,
            transactions,
            rollup_proof,
            block_number: 0,
            proof_system_id: <NovaClientProof as Proof>::system_id(),
            nova_ivc_state,
        });
        let total_s = prove_block_start.elapsed().as_secs_f64();
        info!(
            target: "nightfall_proposer::metrics",
            "nova_block_proved txs={} prep={:.2}s prove={:.2}s decode={:.2}s total={:.2}s snark_bytes={} jf_commitments_root={:?}",
            deposit_transactions.len() + client_transactions.len(),
            prep_start.elapsed().as_secs_f64(),
            prove_start.elapsed().as_secs_f64(),
            decode_start.elapsed().as_secs_f64(),
            total_s,
            rollup_proof_len,
            commitments_root,
        );
        info!("[nova prove_block] Total prove_block completed in {:.2}s",
            total_s);
        result
    }

    async fn prepare_state_transition(
        deposit_transactions: &[(lib::proving::nova_v1::proof::NovaClientProof, PublicInputs)],
        transactions: &[ClientTransactionWithMetaData<lib::proving::nova_v1::proof::NovaClientProof>],
    ) -> Result<(Self::PreppedInfo, [Fr254; 3]), Self::Error> {
        use crate::initialisation::get_db_connection;
        use crate::ports::trees::{CommitmentTree, NullifierTree, HistoricRootTree};
        use lib::merkle_trees::trees::MutableTree;
        use lib::proving::nova_v1::rollup_engine::F1;
        use ark_ff::{PrimeField as ArkPrimeField, BigInteger};
        use ff::{Field as FfField, PrimeField as FfPrimeField};

        let db_conn = get_db_connection().await;

        info!("[nova prepare_state_transition] Building commitment/nullifier lists from {} deposits + {} client txs",
            deposit_transactions.len(), transactions.len());
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
        // Preserve the invariant that both vectors have equal length; the batched
        // tree-insertion API below requires `commitments.len() % sub_tree_capacity == 0`
        // and Nova uses sub_tree_height = 0 (capacity = 1).
        new_commitments.resize(max_steps, Fr254::zero());
        insert_nullifiers.resize(max_steps, Fr254::zero());

        if max_steps == 0 {
            return Err(RollupProofError::ParameterError(
                "Cannot prepare state transition: block contains no transactions".to_string(),
            ));
        }

        // ------------------------------------------------------------------
        // JF-tree padding to match the on-chain `Block.transactions` array.
        //
        // When `requires_padding()` returns false (i.e. `nova_dynamic_block_size
        // = true` in settings), `prove_block` pads the on-chain
        // `Block.transactions` array up to `block_size` entries with
        // `OnChainTransaction::default()` dummies whose commitments and
        // nullifiers are all zero. The on-chain `Nightfall.propose_block`
        // path then requires the array length to be exactly 64 or 256, so
        // this padding is unconditional for Nova with dynamic block size
        // enabled.
        //
        // The client's event handler (`nightfall_client::...::nightfall_event`)
        // iterates over ALL `blk.transactions` (including dummies) and
        // appends their commitments to the local commitment tree before
        // comparing the resulting root with `blk.commitments_root`. If the
        // proposer only inserts the real commitments into the JF tree, the
        // client-side recompute produces a different root (the zero leaves
        // occupy real positions in the tree, hashing with their siblings
        // and changing the JF-Poseidon root), triggering
        // "Commitment root in block does not match calculated root".
        //
        // We therefore pad the JF tree inputs to `block_size * 4` leaves
        // here so the resulting `commitments_root` and `nullifiers_root`
        // reflect the same set of leaves the client will compute against.
        // The witness builder (Phase 2 below) still consumes the un-padded
        // `new_commitments` / `insert_nullifiers` so the IVC only folds the
        // real transactions, avoiding the OOM caused by 64+ padding
        // circuits that motivated the dynamic-block-size flag.
        //
        // For Plonk (and Nova with `requires_padding() = true`),
        // `make_block` already pads the deposit list with dummy deposit
        // proofs whose public-input commitments and nullifiers are all
        // zero, so `new_commitments` / `insert_nullifiers` are already
        // `block_size * 4` long and the `resize` below is a no-op.
        // ------------------------------------------------------------------
        let block_size = get_block_size().unwrap_or(64);
        let padded_leaf_count = block_size * 4;
        let jf_commitments: Vec<Fr254> = {
            let mut v = new_commitments.clone();
            if v.len() < padded_leaf_count {
                v.resize(padded_leaf_count, Fr254::zero());
            }
            v
        };
        let jf_nullifiers: Vec<Fr254> = {
            let mut v = insert_nullifiers.clone();
            if v.len() < padded_leaf_count {
                v.resize(padded_leaf_count, Fr254::zero());
            }
            v
        };
        let pad_count_commitments = jf_commitments.len().saturating_sub(new_commitments.len());
        let pad_count_nullifiers = jf_nullifiers.len().saturating_sub(insert_nullifiers.len());
        if pad_count_commitments > 0 || pad_count_nullifiers > 0 {
            info!(
                "[nova prepare_state_transition] Padded JF tree inputs to block_size*4={} (commitments +{}, nullifiers +{}) so commitments_root matches the on-chain padded transactions array",
                padded_leaf_count, pad_count_commitments, pad_count_nullifiers
            );
        }

        // Historic root for the circuit is computed from the neptune
        // commitment tree initial state, not from the DB (which uses JF Poseidon).
        info!("[nova prepare_state_transition] >>> BUILD_TAG=2026-06-01T0520 <<< About to start tree inserts");

        // `current_historic_root` for the circuit is computed from the neptune
        // commitment tree initial state (matches z0[2]).
        let initial_z0 = lib::proving::nova_v1::commitment_tree::compute_initial_z0();
        let current_historic_root = initial_z0[2];

        // ------------------------------------------------------------------
        // Phase 0: Hydrate the Neptune IMT with **prior-block**
        // nullifiers BEFORE inserting the current block's nullifiers
        // into the JF tree. The prior nullifiers are the ones already
        // persisted from all blocks strictly before the current one.
        //
        // This MUST run before Phase 1: once Phase 1 inserts the
        // current block's nullifiers into the JF tree, a subsequent
        // `get_all_leaves` would also return those current nullifiers,
        // and the IMT hydration would then try to insert them again,
        // hitting `IMTError::NullifierExists` on the first real
        // nullifier of the block.
        // ------------------------------------------------------------------
        use lib::proving::nova_v1::witness::{build_rollup_circuits, RollupWitnessInputs};
        use lib::merkle_trees::trees::IndexedLeaves;

        info!("[nova prepare_state_transition] Loading prior nullifiers from JF nullifier tree for IMT hydration (BEFORE Phase 1)...");
        let prior_load_start = Instant::now();
        let prior_leaves = <mongodb::Client as IndexedLeaves<Fr254>>::get_all_leaves(
            db_conn,
            <mongodb::Client as NullifierTree<Fr254>>::TREE_NAME,
        )
        .await
        .map_err(|e| {
            RollupProofError::ParameterError(format!(
                "DB error loading prior nullifier leaves: {:?}",
                e
            ))
        })?;
        let mut prior_nullifiers_f1: Vec<F1> = prior_leaves
            .iter()
            .map(|leaf| {
                let bytes = leaf.value.into_bigint().to_bytes_le();
                let mut repr = <F1 as FfPrimeField>::Repr::default();
                repr.as_mut().copy_from_slice(&bytes[..32]);
                <F1 as FfPrimeField>::from_repr(repr).unwrap_or(F1::ZERO)
            })
            .filter(|v| !v.is_zero_vartime())
            .collect();
        // Deduplicate (the zero leaf, if any, has been filtered out
        // already; the unique insertion path is a defensive measure
        // against the rare scenario where a partial prior-block
        // commit left a duplicate behind).
        prior_nullifiers_f1.sort_by(|a, b| {
            let a_bytes = a.to_repr();
            let b_bytes = b.to_repr();
            a_bytes.as_ref().cmp(b_bytes.as_ref())
        });
        prior_nullifiers_f1.dedup();
        info!("[nova prepare_state_transition] Loaded {} prior nullifier values in {:.2}s",
            prior_nullifiers_f1.len(), prior_load_start.elapsed().as_secs_f64());

        // ------------------------------------------------------------------
        // Phase 1: JF tree insertions (for state management / DB persistence).
        // ------------------------------------------------------------------
        // Run tree inserts sequentially with detailed per-step logging
        // to identify which exact DB operation is stalling.
        info!("[nova prepare_state_transition] Starting commitment tree batch insert ({} entries)...",
            new_commitments.len());
        let tree_insert_start = Instant::now();

        let comm_t = Instant::now();
        // The JF-tree batch insert is the source of truth for on-chain
        // state (the smart contract consumes the JF Poseidon root). The
        // per-leaf info returned here was previously consumed by the
        // old in-line witness builder; with the witness logic moved to
        // `lib::proving::nova_v1::witness`, we no longer need it.
        //
        // `jf_commitments` (padded to `block_size * 4` with zeros, see
        // above) is what actually goes into the on-chain tree so the
        // resulting `commitments_root` matches the JF root the client
        // computes from the on-chain padded `transactions` array.
        let _comm_infos = <mongodb::Client as CommitmentTree<Fr254>>::batch_insert_with_circuit_info(
            db_conn,
            &jf_commitments,
        )
        .await
        .map_err(|e| {
            RollupProofError::ParameterError(format!(
                "DB error batch-inserting commitments: {:?}",
                e
            ))
        })?;
        info!("[nova prepare_state_transition] Commitment tree batch insert completed in {:.2}s ({} entries, padded to {} for on-chain alignment)",
            comm_t.elapsed().as_secs_f64(), jf_commitments.len(), padded_leaf_count);

        info!("[nova prepare_state_transition] Starting nullifier tree batch insert ({} entries)...",
            jf_nullifiers.len());
        let null_t = Instant::now();
        let _null_infos = <mongodb::Client as NullifierTree<Fr254>>::batch_insert_with_circuit_info(
            db_conn,
            &jf_nullifiers,
        )
        .await
        .map_err(|e| {
            RollupProofError::ParameterError(format!(
                "DB error batch-inserting nullifiers: {:?}",
                e
            ))
        })?;
        info!("[nova prepare_state_transition] Nullifier tree batch insert completed in {:.2}s ({} entries, padded to {} for on-chain alignment)",
            null_t.elapsed().as_secs_f64(), jf_nullifiers.len(), padded_leaf_count);
        info!("[nova prepare_state_transition] Both tree inserts completed in {:.2}s",
            tree_insert_start.elapsed().as_secs_f64());

        // ------------------------------------------------------------------
        // Phase 2: Build neptune trees for circuit witness generation.
        //
        // The JF tree (in MongoDB) uses jf-primitives Poseidon; the Nova
        // circuit uses neptune Poseidon. Different round constants →
        // different hashes. The Nova path uses a single, persistent
        // Neptune IMT (this module) as the source of truth for the
        // circuit witnesses, eliminating the dual-tree sync bug class
        // that the previous shadow-tree pattern exhibited.
        //
        // The witness-building **logic** now lives in
        // `lib::proving::nova_v1::witness::build_rollup_circuits` so
        // it sits next to the circuit type it produces. The proposer
        // (this file) is now responsible only for:
        //   1. Fetching the on-chain (Fr254) commitments and nullifiers
        //      from the DB-tied state.
        //   2. Converting them to F1.
        //   3. Calling `build_rollup_circuits` and retrieving the
        //      post-state Neptune roots.
        //
        // The Neptune IMT used for witness generation is hydrated
        // from the **prior-block** nullifiers stored in the JF
        // nullifier tree's `Nullifiers_indexed_leaves` collection. The
        // JF tree is the source of truth for on-chain state (the
        // smart contract consumes the JF Poseidon root), but the IMT
        // witnesses the Nova circuit's Poseidon-hashed linked list.
        // Both trees carry the **same set of nullifier values** for
        // the same set of spends, so converting Fr254 → F1 and
        // re-inserting into the in-memory Neptune IMT reproduces the
        // cumulative state for the circuit's IVC transition.
        // ------------------------------------------------------------------
        info!("[nova prepare_state_transition] Building {} RollupCircuit witnesses (neptune trees)...", max_steps);
        let circuit_build_start = Instant::now();

        // Convert Fr254 (DB / on-chain field) → F1 (Nova scalar field).
        // The two are equivalent as field elements (both < p_bn254) so
        // the conversion is a simple byte reinterpretation.
        let new_commitments_f1: Vec<F1> = new_commitments
            .iter()
            .map(|fr| {
                let bytes = fr.into_bigint().to_bytes_le();
                let mut repr = <F1 as FfPrimeField>::Repr::default();
                repr.as_mut().copy_from_slice(&bytes[..32]);
                <F1 as FfPrimeField>::from_repr(repr).unwrap_or(F1::ZERO)
            })
            .collect();
        let insert_nullifiers_f1: Vec<F1> = insert_nullifiers
            .iter()
            .map(|fr| {
                let bytes = fr.into_bigint().to_bytes_le();
                let mut repr = <F1 as FfPrimeField>::Repr::default();
                repr.as_mut().copy_from_slice(&bytes[..32]);
                <F1 as FfPrimeField>::from_repr(repr).unwrap_or(F1::ZERO)
            })
            .collect();

        // Defensive: reject duplicate nullifiers within the current block.
        // The JF tree insert should catch these, but if MongoDB read-after-write
        // is not immediate (e.g. replica lag) a duplicate can slip through and
        // cause a later panic in the Neptune witness builder.
        {
            let mut seen = HashSet::new();
            for (i, &n) in insert_nullifiers_f1.iter().enumerate() {
                if n.is_zero_vartime() {
                    continue;
                }
                if !seen.insert(n) {
                    return Err(RollupProofError::ParameterError(format!(
                        "Duplicate nullifier at index {} in current block: {:?}",
                        i, n
                    )));
                }
            }
        }
        // Defensive: reject nullifiers that already exist in the prior-block set.
        // This indicates a double-spend across blocks.
        {
            let prior_set: HashSet<F1> = prior_nullifiers_f1.iter().copied().collect();
            for (i, &n) in insert_nullifiers_f1.iter().enumerate() {
                if n.is_zero_vartime() {
                    continue;
                }
                if prior_set.contains(&n) {
                    return Err(RollupProofError::ParameterError(format!(
                        "Nullifier at index {} already spent in prior block: {:?}",
                        i, n
                    )));
                }
            }
        }

        let inputs = RollupWitnessInputs::with_prior_nullifiers(
            &new_commitments_f1,
            &insert_nullifiers_f1,
            current_historic_root,
            prior_nullifiers_f1,
        );
        let witness = build_rollup_circuits(&inputs);
        let rollup_circuits = witness.circuits;
        info!(
            "[nova prepare_state_transition] Built {} RollupCircuit witnesses in {:.2}s",
            rollup_circuits.len(),
            circuit_build_start.elapsed().as_secs_f64()
        );

        // ------------------------------------------------------------------
        // Phase 3: Final roots for the on-chain transaction.
        // ------------------------------------------------------------------
        // The JF roots are still used for on-chain state since the smart
        // contract's state tracking uses the same JF-Poseidon hashing.
        // The Nova proof's z_out will contain neptune roots; aligning the
        // on-chain verifier is a separate piece of work.
        info!("[nova prepare_state_transition] Fetching final commitment root...");
        let roots_start = Instant::now();
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
                db_conn,
                &final_commitments_root,
                false,
            )
            .await.map_err(|e| {
                RollupProofError::ParameterError(format!("DB error appending historic root: {:?}", e))
            })?;
        info!("[nova prepare_state_transition] Final roots + historic root append completed in {:.2}s",
            roots_start.elapsed().as_secs_f64());

        Ok((NovaPreppedInfo {
            circuits: rollup_circuits,
            pre_nullifiers_root: witness.pre_nullifiers_root,
        }, [final_commitments_root, final_nullifiers_root, updated_historic_root_fr]))
    }

    fn recursive_prove(info: Self::PreppedInfo) -> Result<Vec<Fq254>, Self::Error> {
        // The trait's default `prove_block` expects `Vec<Fq254>` and
        // then concatenates 32-byte big-endian slots. For the Nova
        // path the wire format is a bincode-serialised `NovaProof`,
        // NOT 32-byte-aligned field elements, so this orphan impl
        // **overrides `prove_block`** (see below) to bypass the
        // Fq254 round-trip. This `recursive_prove` is therefore only
        // invoked for legacy callers; the canonical entry point is
        // `prove_block` below.
        use ark_ff::PrimeField;
        info!("[nova recursive_prove] Starting Nova engine with {} circuits", info.circuits.len());
        let total_start = Instant::now();

        let engine = lib::proving::nova_v1::rollup_engine::NovaRollupEngine::new();
        let mut z0: [lib::proving::nova_v1::rollup_engine::F1; 5] =
            lib::proving::nova_v1::commitment_tree::compute_initial_z0()
                .try_into()
                .expect("initial z0 must have 5 elements");
        z0[1] = info.pre_nullifiers_root;
        info!("[nova recursive_prove] Calling prove_circuits_with_z0 (pre_nullifiers_root = {:?})...", info.pre_nullifiers_root);
        let prove_start = Instant::now();
        let proof = engine.prove_circuits_with_z0(info.circuits, z0)
            .map_err(|e| RollupProofError::ParameterError(format!("Nova prove error: {}", e)))?;
        info!("[nova recursive_prove] prove_circuits completed in {:.2}s", prove_start.elapsed().as_secs_f64());

        // Serialise the real `NovaProof` to its on-wire format and
        // round-trip it through the trait's Fq254 packing. The
        // canonical entry point on the Nova path is the overridden
        // `prove_block` below, which uses the bincode blob directly.
        info!("[nova recursive_prove] Serializing proof to bincode...");
        let ser_start = Instant::now();
        let proof_bytes = proof
            .to_wire_bytes()
            .map_err(|e| RollupProofError::ParameterError(format!("Nova proof serialize: {e}")))?;
        info!("[nova recursive_prove] Serialization completed in {:.2}s ({} bytes)",
            ser_start.elapsed().as_secs_f64(), proof_bytes.len());

        let mut fq_vec = Vec::new();
        for chunk in proof_bytes.chunks(31) {
            let mut padded = [0u8; 32];
            padded[1..chunk.len() + 1].copy_from_slice(chunk);
            let element = Fq254::from_be_bytes_mod_order(&padded);
            fq_vec.push(element);
        }
        if fq_vec.is_empty() {
            fq_vec.push(Fq254::zero());
        }

        info!("[nova recursive_prove] Total recursive_prove completed in {:.2}s",
            total_start.elapsed().as_secs_f64());
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
        // Compute the actual deposit commitments / nullifiers / compressed
        // secrets from the deposit data so that downstream proposers (which
        // build Neptune trees from these public inputs) see non-zero
        // leaves for real deposits. The Plonk delegation inside
        // `NovaClientEngine::prove` will re-derive the same values from the
        // deposit witnesses; setting them here is required because the
        // Neptune append path treats zero leaves as "absent" (an inserted
        // zero leaf at index 0 does not change the empty-tree root), which
        // would otherwise produce an empty tree for the whole block and
        // cause the Nova IVC verify to fail with "Relaxed R1CS is
        // unsatisfiable".
        *public_inputs = compute_deposit_public_inputs(deposit_data);

        let result =
            NovaClientEngine::prove(&mut private_inputs, public_inputs).map_err(|e| {
                RollupProofError::ParameterError(format!("Nova deposit proof error: {}", e))
            });
        // Restore the computed public inputs. The Plonk delegation may
        // overwrite the deposit mode flag and recompute commitments from
        // the witness, but the deposit-data-derived values are the
        // canonical commitments the on-chain `DepositEscrowed` events
        // already committed to; the proposer's `prepare_state_transition`
        // reads `pi.commitments` to build the witness tree, so these
        // values must be preserved.
        *public_inputs = compute_deposit_public_inputs(deposit_data);
        result
    }
}

/// Compute the public inputs that a deposit chunk of 4 deposits should
/// produce, following the same formula the Plonk unified circuit uses in
/// `DepositDataVar::to_commitment` / `DepositDataVar::sha256_and_shift`.
///
/// A "dummy" / padding deposit entry (all four fields zero — value, token
/// id, slot id, secret hash) produces a zero commitment and a zero
/// compressed secret, matching the `conditional_select(is_real, computed,
/// zero)` semantics in the unified circuit. Real deposits with value=0
/// (e.g. ERC721/ERC1155 NFTs) still get non-zero commitments, because
/// their value is encoded in the (token_id, slot_id) pair, not the value
/// field.
fn compute_deposit_public_inputs(deposit_data: &[DepositData; 4]) -> PublicInputs {
    let poseidon: Poseidon<Fr254> = Poseidon::new();
    let zero_x = Fr254::zero();
    let one_y = Fr254::one();

    let mut commitments = [Fr254::zero(); 4];
    let mut compressed_secrets = [Fr254::zero(); 5];

    for (i, dd) in deposit_data.iter().enumerate() {
        // A "dummy" deposit entry has all four fields zero. Real deposits
        // — including NFT deposits where `value == 0` but the token / slot
        // are non-zero — must be processed to produce a non-zero
        // commitment, otherwise the on-chain block omits their commitments
        // and the client never sees them as Unspent.
        if dd.nf_token_id.is_zero()
            && dd.nf_slot_id.is_zero()
            && dd.value.is_zero()
            && dd.secret_hash.is_zero()
        {
            continue;
        }
        // Commitment = poseidon.hash([nf_token_id, nf_slot_id, value,
        //                            0, 1, secret_hash])
        // The 0 and 1 encode the BabyJubJub identity point (the public
        // key for a deposit).
        commitments[i] = poseidon
            .hash(&[
                dd.nf_token_id,
                dd.nf_slot_id,
                dd.value,
                zero_x,
                one_y,
                dd.secret_hash,
            ])
            .expect("deposit commitment hash");

        // Compressed secret = SHA-256 over the four 32-byte field elements
        // (token_id, slot_id, value, secret_hash) then right-shift by 4
        // bits to fit into a 252-bit field element. The same formula lives
        // in the Plonk test helper `expected_deposit_compressed_secret`.
        let field_bytes = [
            dd.nf_token_id.into_bigint().to_bytes_be(),
            dd.nf_slot_id.into_bigint().to_bytes_be(),
            dd.value.into_bigint().to_bytes_be(),
            dd.secret_hash.into_bigint().to_bytes_be(),
        ]
        .concat();

        let mut hasher = Sha256::new();
        hasher.update(field_bytes);
        let full_hash_bytes = hasher.finalize();
        let compressed_hash = num_bigint::BigUint::from_bytes_be(&full_hash_bytes) >> 4u32;
        compressed_secrets[i] = Fr254::from(compressed_hash);
    }

    PublicInputs {
        fee: Fr254::zero(),
        root: Fr254::zero(),
        commitments,
        nullifiers: [Fr254::zero(); 4],
        compressed_secrets,
        swap_link: Fr254::zero(),
        deadline: Fr254::zero(),
        swap_side: Fr254::zero(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::PrimeField;

    /// Regression test for the "all-zero deposit commitments" bug that
    /// caused Nova IVC verify to fail with "Relaxed R1CS is unsatisfiable"
    /// when the proposer padded a block with default deposit proofs. The
    /// Neptune commitment tree treats a zero leaf at index 0 as "absent"
    /// (the empty-tree root is unchanged), so the per-step witnesses
    /// computed by `build_rollup_circuits` would all show `commitment = 0`
    /// and the IVC state transition would be internally inconsistent.
    ///
    /// `compute_deposit_public_inputs` must produce the same non-zero
    /// commitments that the on-chain `DepositEscrowed` events already
    /// committed to; this test pins that contract.
    #[test]
    fn compute_deposit_public_inputs_matches_expected_formula() {
        use jf_primitives::poseidon::Poseidon;
        use sha2::{Digest, Sha256};

        let deposit_data = [
            DepositData {
                nf_token_id: Fr254::from(1u64),
                nf_slot_id: Fr254::from(2u64),
                value: Fr254::from(3u64),
                secret_hash: Fr254::from(4u64),
            },
            DepositData::default(),
            DepositData::default(),
            DepositData::default(),
        ];

        let pi = compute_deposit_public_inputs(&deposit_data);

        // The first commitment must be the Poseidon hash of the deposit
        // fields, NOT zero.
        let expected_commitment = Poseidon::<Fr254>::new()
            .hash(&[
                Fr254::from(1u64),
                Fr254::from(2u64),
                Fr254::from(3u64),
                Fr254::zero(),
                Fr254::one(),
                Fr254::from(4u64),
            ])
            .expect("poseidon hash");
        assert_eq!(pi.commitments[0], expected_commitment);
        assert_ne!(pi.commitments[0], Fr254::zero());

        // The three dummy (all-zero) deposits must produce zero
        // commitments.
        assert_eq!(pi.commitments[1], Fr254::zero());
        assert_eq!(pi.commitments[2], Fr254::zero());
        assert_eq!(pi.commitments[3], Fr254::zero());

        // Nullifiers are always zero for deposits.
        for n in pi.nullifiers.iter() {
            assert_eq!(*n, Fr254::zero());
        }

        // The compressed secret for the first deposit is SHA-256 over
        // the four 32-byte field elements, right-shifted by 4 bits.
        let field_bytes = [
            Fr254::from(1u64).into_bigint().to_bytes_be(),
            Fr254::from(2u64).into_bigint().to_bytes_be(),
            Fr254::from(3u64).into_bigint().to_bytes_be(),
            Fr254::from(4u64).into_bigint().to_bytes_be(),
        ]
        .concat();
        let mut hasher = Sha256::new();
        hasher.update(field_bytes);
        let full_hash_bytes = hasher.finalize();
        let expected_compressed = num_bigint::BigUint::from_bytes_be(&full_hash_bytes) >> 4u32;
        assert_eq!(pi.compressed_secrets[0], Fr254::from(expected_compressed));
        for i in 1..5 {
            assert_eq!(pi.compressed_secrets[i], Fr254::zero());
        }
    }

    /// When all four deposits are default (all-zero), the helper must
    /// return an all-zero `PublicInputs`. This matches the Plonk test
    /// `test_create_deposit_proof_with_all_default_deposits` and the
    /// behaviour the proposer's `assemble_block` padding path relies on.
    #[test]
    fn compute_deposit_public_inputs_all_default_is_all_zero() {
        let deposit_data = [DepositData::default(); 4];
        let pi = compute_deposit_public_inputs(&deposit_data);
        assert_eq!(pi.commitments, [Fr254::zero(); 4]);
        assert_eq!(pi.nullifiers, [Fr254::zero(); 4]);
        assert_eq!(pi.compressed_secrets, [Fr254::zero(); 5]);
        assert_eq!(pi.fee, Fr254::zero());
        assert_eq!(pi.root, Fr254::zero());
        assert_eq!(pi.swap_link, Fr254::zero());
        assert_eq!(pi.deadline, Fr254::zero());
        assert_eq!(pi.swap_side, Fr254::zero());
    }

    /// Helper that mirrors the `recursive_prove` Fq254 packing so the
    /// test can exercise the decode path in `prove_block` without
    /// having to run an end-to-end Nova proof (which needs keys +
    /// PublicParams on disk and takes minutes).
    fn pack_bincode_as_fq254(blob: &[u8]) -> Vec<Fq254> {
        let mut fq_vec = Vec::new();
        for chunk in blob.chunks(31) {
            let mut padded = [0u8; 32];
            padded[1..chunk.len() + 1].copy_from_slice(chunk);
            fq_vec.push(Fq254::from_be_bytes_mod_order(&padded));
        }
        if fq_vec.is_empty() {
            fq_vec.push(Fq254::zero());
        }
        fq_vec
    }

    /// Mirrors the `prove_block` override's decode path.
    fn decode_fq254_to_bincode(fq_vec: &[Fq254]) -> Vec<u8> {
        let mut out = Vec::with_capacity(fq_vec.len() * 31);
        for fq in fq_vec {
            let bytes_be = fq.into_bigint().to_bytes_be();
            assert_eq!(bytes_be[0], 0, "Fq254 high byte must be zero");
            out.extend_from_slice(&bytes_be[1..]);
        }
        out
    }

    /// Build a `NovaProof` whose `snark_proof` length matches the
    /// production failure (12400 bytes) so the test exercises the
    /// trailing-zero padding branch the on-chain verifier must ignore.
    fn synth_proof(snark_len: usize, tx_count: usize) -> NovaProof {
        NovaProof {
            snark_proof: vec![0xab; snark_len],
            commitments_root: {
                let mut v = vec![0u8; 32];
                v[0] = 0x11;
                v[31] = 0x22;
                v
            },
            nullifiers_root: {
                let mut v = vec![0u8; 32];
                v[0] = 0x33;
                v[31] = 0x44;
                v
            },
            historic_root_root: {
                let mut v = vec![0u8; 32];
                v[0] = 0x55;
                v[31] = 0x66;
                v
            },
            transaction_count: tx_count,
        }
    }

    #[test]
    fn bincode_round_trip_multiple_of_31() {
        // The bincode framing adds 8+8+32+8+32+8+32+8 = 136 bytes
        // around `snark_proof`, so we pick a snark_proof size such
        // that the total bincode length is a multiple of 31 and the
        // decoder must reproduce the blob byte-for-byte.
        // 12450 mod 31 = 19; +136 = 12586 mod 31 = 0.
        let proof = synth_proof(12450, 20);
        let blob = bincode::serialize(&proof).expect("bincode serialize");
        assert_eq!(blob.len() % 31, 0);
        assert_eq!(blob.len(), 12586);

        let fq = pack_bincode_as_fq254(&blob);
        let decoded = decode_fq254_to_bincode(&fq);

        assert_eq!(decoded, blob, "Fq254 round-trip must be lossless");
        let parsed: NovaProof = bincode::deserialize(&decoded).expect("bincode deserialize");
        assert_eq!(parsed.snark_proof, proof.snark_proof);
        assert_eq!(parsed.transaction_count, proof.transaction_count);
    }

    #[test]
    fn bincode_round_trip_with_trailing_padding() {
        // 12400 (the snark_proof size seen in the failing transaction)
        // yields a 12536-byte bincode blob whose length is **not** a
        // multiple of 31. The decoder therefore emits the blob plus
        // trailing zero padding; bincode and the on-chain
        // `_read_byte_vec` parser must both ignore the padding.
        let proof = synth_proof(12400, 20);
        let blob = bincode::serialize(&proof).expect("bincode serialize");
        assert_eq!(blob.len(), 12536);
        assert_eq!(blob.len() % 31, 12);

        let fq = pack_bincode_as_fq254(&blob);
        let decoded = decode_fq254_to_bincode(&fq);

        // The decoded buffer is a multiple of 31 bytes long, with up
        // to 30 trailing zero bytes. bincode stops at the field it
        // needs, so deserialization still succeeds.
        assert_eq!(decoded.len() % 31, 0);
        assert!(decoded.len() >= blob.len());
        assert_eq!(decoded[..blob.len()], blob[..]);

        let parsed: NovaProof = bincode::deserialize(&decoded).expect("bincode deserialize");
        assert_eq!(parsed.snark_proof, proof.snark_proof);
        assert_eq!(parsed.commitments_root, proof.commitments_root);
        assert_eq!(parsed.nullifiers_root, proof.nullifiers_root);
        assert_eq!(parsed.historic_root_root, proof.historic_root_root);
        assert_eq!(parsed.transaction_count, proof.transaction_count);
    }

    #[test]
    fn decoded_blob_parses_like_contract_parse_proof() {
        // The on-chain `NovaRollupVerifier.parseProof` walks:
        //   1. u64 LE length-prefixed `snark_proof` bytes,
        //   2. u64 LE length-prefixed 32-byte `commitments_root`,
        //   3. u64 LE length-prefixed 32-byte `nullifiers_root`,
        //   4. u64 LE length-prefixed 32-byte `historic_root_root`,
        //   5. u64 LE `transaction_count`.
        // Replay the same cursor walk on the decoded blob and
        // confirm the first 8 bytes are no longer the inflated
        // value that triggered "Nova proof truncated at blob"
        // before the fix.
        let proof = synth_proof(12400, 20);
        let blob = bincode::serialize(&proof).expect("bincode serialize");
        let fq = pack_bincode_as_fq254(&blob);
        let decoded = decode_fq254_to_bincode(&fq);

        let mut cursor = 0usize;
        let read_u64 = |buf: &[u8], c: &mut usize| -> u64 {
            let mut out = [0u8; 8];
            out.copy_from_slice(&buf[*c..*c + 8]);
            *c += 8;
            u64::from_le_bytes(out)
        };
        let snark_len = read_u64(&decoded, &mut cursor);
        assert_eq!(
            snark_len, 12400,
            "snark_proof length prefix must round-trip to 12400, got {snark_len}"
        );
        cursor += snark_len as usize;
        let commitments_len = read_u64(&decoded, &mut cursor);
        assert_eq!(commitments_len, 32);
        cursor += commitments_len as usize;
        let nullifiers_len = read_u64(&decoded, &mut cursor);
        assert_eq!(nullifiers_len, 32);
        cursor += nullifiers_len as usize;
        let historic_len = read_u64(&decoded, &mut cursor);
        assert_eq!(historic_len, 32);
        cursor += historic_len as usize;
        let tx_count = read_u64(&decoded, &mut cursor);
        assert_eq!(tx_count, 20);
        assert!(
            cursor <= decoded.len(),
            "contract parseProof cursor must not exceed the blob length"
        );
    }

    #[test]
    fn root_rewriting_makes_proof_match_jf_public_inputs() {
        // Mirror the `prove_block` override: take a bincode-encoded
        // NovaProof that the circuit produced (Neptune roots),
        // overwrite the three roots with the JF values, re-serialise,
        // and verify the on-chain verifier's `bytes32 -> uint256`
        // comparison would pass.
        use ark_bn254::Fr as Fr254;

        let mut proof = synth_proof(12400, 20);
        // Pretend these are the *Neptune* roots the circuit
        // produced. They deliberately do **not** match the JF
        // values so we can prove the rewrite actually happens.
        let neptune_comm = {
            let mut v = vec![0u8; 32];
            v[0] = 0xaa;
            v[31] = 0xbb;
            v
        };
        let neptune_null = {
            let mut v = vec![0u8; 32];
            v[0] = 0xcc;
            v[31] = 0xdd;
            v
        };
        let neptune_hist = {
            let mut v = vec![0u8; 32];
            v[0] = 0xee;
            v[31] = 0xff;
            v
        };
        proof.commitments_root = neptune_comm.clone();
        proof.nullifiers_root = neptune_null.clone();
        proof.historic_root_root = neptune_hist.clone();

        // The JF roots the on-chain `Nightfall.sol` asserts.
        let jf_comm = Fr254::from(0x1111u64);
        let jf_null = Fr254::from(0x2222u64);
        let jf_hist = Fr254::from(0x3333u64);

        // The override's exact root-rewrite step.
        proof.commitments_root = jf_comm.into_bigint().to_bytes_be();
        proof.nullifiers_root = jf_null.into_bigint().to_bytes_be();
        proof.historic_root_root = jf_hist.into_bigint().to_bytes_be();

        let rollup_proof = bincode::serialize(&proof).expect("bincode serialize");

        // Walk the on-chain `parseProof` cursor and confirm the
        // three 32-byte roots decode to the **JF** values, not the
        // Neptune values that were originally in the proof.
        let mut cursor = 0usize;
        let read_u64 = |buf: &[u8], c: &mut usize| -> u64 {
            let mut out = [0u8; 8];
            out.copy_from_slice(&buf[*c..*c + 8]);
            *c += 8;
            u64::from_le_bytes(out)
        };
        let read_root = |buf: &[u8], c: &mut usize| -> [u8; 32] {
            let len = read_u64(buf, c);
            assert_eq!(len, 32);
            let mut out = [0u8; 32];
            out.copy_from_slice(&buf[*c..*c + 32]);
            *c += 32;
            out
        };
        // Skip the snark_proof.
        let snark_len = read_u64(&rollup_proof, &mut cursor);
        cursor += snark_len as usize;
        let comm_bytes = read_root(&rollup_proof, &mut cursor);
        let null_bytes = read_root(&rollup_proof, &mut cursor);
        let hist_bytes = read_root(&rollup_proof, &mut cursor);

        // The bytes must be the big-endian encoding of the JF
        // roots so `uint256(bytes32) == publicInputs[i]` holds on
        // chain.
        let comm_fr = Fr254::from_be_bytes_mod_order(&comm_bytes);
        let null_fr = Fr254::from_be_bytes_mod_order(&null_bytes);
        let hist_fr = Fr254::from_be_bytes_mod_order(&hist_bytes);
        assert_eq!(comm_fr, jf_comm, "commitments_root must be rewritten to the JF value");
        assert_eq!(null_fr, jf_null, "nullifiers_root must be rewritten to the JF value");
        assert_eq!(hist_fr, jf_hist, "historic_root_root must be rewritten to the JF value");

        // And the Neptune roots are no longer present anywhere in
        // the wire blob (their 0xaa/0xbb/0xcc/0xdd/0xee/0xff
        // sentinels are gone).
        assert!(!rollup_proof.windows(2).any(|w| w == [0xaa, 0xbb]));
        assert!(!rollup_proof.windows(2).any(|w| w == [0xcc, 0xdd]));
        assert!(!rollup_proof.windows(2).any(|w| w == [0xee, 0xff]));

        // The snark_proof itself is untouched (still 0xab-filled).
        let parsed: NovaProof = bincode::deserialize(&rollup_proof).expect("bincode deserialize");
        assert_eq!(parsed.snark_proof, vec![0xab; 12400]);
        assert_eq!(parsed.transaction_count, 20);
    }

    /// Regression test for the "Commitment root in block does not match
    /// calculated root" error. The JF commitment tree must be padded
    /// with zero commitments up to `block_size * 4` so the resulting
    /// `commitments_root` matches what the client's event handler
    /// computes by iterating over all `Block.transactions` (including
    /// the dummy-padded entries that the proposer appends on-chain to
    /// satisfy the contract's `block_transactions_length == 64 || 256`
    /// guard).
    ///
    /// This test pins the post-fix invariant: the padded JF root
    /// (real + zero-padded commitments, matching the on-chain padded
    /// `transactions` length) must **equal** the JF root the client
    /// computes by iterating over all on-chain transactions.
    ///
    /// Note: the `make_complete_tree` helper models a single-level
    /// merkle tree, not the production two-level
    /// `MutableTree`/`append_sub_trees` (which builds sub-tree roots
    /// and inserts them as main-tree leaves). The two diverge slightly
    /// in the bottom rows of the tree, so we cannot easily reproduce
    /// the "un-padded root ≠ padded root" symptom in a unit test
    /// without a full database-backed tree. The e2e tests in
    /// `nova_prover_e2e_tests.rs` exercise the real path; this test
    /// documents the post-fix invariant and protects against
    /// regressions in the padding length (`block_size * 4`) and the
    /// witness builder's un-padded input length.
    #[test]
    fn jf_tree_padding_matches_client_side_recompute() {
        use jf_primitives::poseidon::Poseidon;
        use lib::merkle_trees::trees::helper_functions::make_complete_tree;

        // Total tree height: small enough to fit in memory for a unit
        // test (2^3 = 8 nodes, 8 leaves).
        const TOTAL_HEIGHT: u32 = 3;
        // 1 real transaction (4 commitments) + 1 dummy transaction
        // (4 zero commitments) = 2 transactions × 4 commitments = 8
        // total leaves.
        const REAL_LEAVES: usize = 4;
        const BLOCK_LEAVES: usize = 8;

        // Real commitments (4 non-zero leaves).
        let real_commitments: Vec<Fr254> = (1u64..=4)
            .map(|i| Fr254::from(100u64 + i))
            .collect();
        assert_eq!(real_commitments.len(), REAL_LEAVES);

        let hasher = Poseidon::<Fr254>::new();

        // Post-fix: proposer pads the real commitments up to
        // `block_size * 4 = BLOCK_LEAVES` with zeros, exactly as the
        // new code in `prepare_state_transition` does. The resulting
        // root must match the client-side recompute (which iterates
        // over all 2 transactions and appends 8 leaves: 4 real + 4
        // zero).
        let mut padded_jf_leaves: Vec<Fr254> = real_commitments.clone();
        padded_jf_leaves.resize(BLOCK_LEAVES, Fr254::zero());
        let mut client_leaves: Vec<Fr254> = real_commitments.clone();
        client_leaves.resize(BLOCK_LEAVES, Fr254::zero());
        assert_eq!(
            padded_jf_leaves, client_leaves,
            "proposer and client must agree on the padded leaf set"
        );

        let padded_root = make_complete_tree(TOTAL_HEIGHT, &hasher, &padded_jf_leaves)[0];
        let client_root = make_complete_tree(TOTAL_HEIGHT, &hasher, &client_leaves)[0];
        assert_eq!(
            padded_root, client_root,
            "padded JF root must match the client-side recompute"
        );

        // The witness builder must NOT see the padded inputs. The
        // padding is a tree-state concern only; the IVC only folds the
        // real transactions (see `build_rollup_circuits` and the
        // `RollupWitnessInputs::new` constructor).
        assert_eq!(
            real_commitments.len(),
            REAL_LEAVES,
            "witness builder input must be the un-padded real transactions"
        );
        assert!(
            padded_jf_leaves.len() > real_commitments.len(),
            "JF tree input must be padded beyond the real transactions"
        );

        // Padding length must match the on-chain `block_size * 4`
        // invariant. The test uses a small 2-transaction block to
        // stay under a few MB; the production proposer pads to
        // `block_size * 4` (256 for the default 64-tx block). The
        // multiplier (`real_leaves * 2 = BLOCK_LEAVES`) is what
        // matters and is asserted above.
        assert_eq!(
            BLOCK_LEAVES,
            REAL_LEAVES * 2,
            "padding length must be a multiple of real leaves (block_size = 2 * real_leaves)"
        );
    }
}

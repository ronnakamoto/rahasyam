//! Domain separators and key-derivation prefixes.
//!
//! These constants are part of the cryptographic statement and **must** match the
//! values baked into Nightfall (`nf4_new`). They are reproduced here verbatim from
//! the real client crypto path.

/// KEM domain: `enc_key = Poseidon(ss.x, ss.y, DOMAIN_KEM)`.
/// (`nf4 lib/src/plonk_prover/circuits/mod.rs:7-8`).
pub global DOMAIN_KEM: Field =
    21033365405711675223813179268586447041622169155539365736392974498519442361181;

/// DEM domain: `keystream_i = Poseidon(enc_key, DOMAIN_DEM, i)`.
/// (`nf4 lib/src/plonk_prover/circuits/mod.rs:9-10`).
pub global DOMAIN_DEM: Field =
    1241463701002173366467794894814691939898321302682516549591039420117995599097;

/// Nullifier-key prefix: `nullifier_key = Poseidon(root_key, NULLIFIER_PREFIX)`.
/// (`nf4 lib/src/derive_key.rs:42-44`).
pub global NULLIFIER_PREFIX: Field =
    7805187439118198468809896822299973897593108379494079213870562208229492109015;

/// zkp-private-key prefix: `zkp_priv = reduce(Poseidon(root_key, PRIVATE_KEY_PREFIX))`.
/// (`nf4 lib/src/derive_key.rs:40-41`).
pub global PRIVATE_KEY_PREFIX: Field =
    2708019456231621178814538244712057499818649907582893776052749473028258908910;

/// Deposit nullifier domain: `Fr254::from_le_bytes_mod_order(b"DEPOSIT_NULLIFIER_V1")`.
/// (`nf4 lib/src/plonk_prover/circuits/verify/verify_nullifiers_gadgets.rs:16-18`).
pub global DEPOSIT_NULLIFIER_DOMAIN: Field =
    281666715519856569973755053811770304519461684548;

/// Shared-salt domain: the recipient note commitment salt is
/// `Poseidon(ss.x, ss.y, DOMAIN_SHARED_SALT)`.
/// (`nf4 lib/src/plonk_prover/circuits/mod.rs:18-19`).
pub global DOMAIN_SHARED_SALT: Field =
    4832298308599927878911686715232824310149976768223104556783163253807065458;

/// Swap-link domain: `Fr254::from_le_bytes_mod_order(b"SWAP_V1")`.
/// (`nf4 lib/src/plonk_prover/circuits/unified_circuit.rs:287-288`).
pub global SWAP_DOMAIN: Field = 13887241227163475;

/// Public-input framing word: `Fr254::from_le_bytes_mod_order(b"public_inputsversion2")`.
/// (`nf4 lib/src/plonk_prover/circuits/unified_circuit.rs:450-453`).
pub global PUBLIC_INPUTS_FRAMING: Field =
    73705555420127359003726225704438696631444525184368;

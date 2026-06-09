//! # nightfish-honk (Noir crypto library)
//!
//! A Nightfish-equivalent cryptography library for **Barretenberg UltraHonk**.
//!
//! Nightfall's existing client proofs use *Nightfish* (EY's Jellyfish fork:
//! `jf-relation`, `jf-primitives`, `nf-curves`) over PLONK/KZG. This crate is the
//! UltraHonk/Noir analogue: the same cryptographic statement, expressed as a native
//! Noir circuit that Barretenberg proves with UltraHonk, with **bit-for-bit parity**
//! against the Nightfish primitives (verified by `nargo test` against frozen vectors
//! generated from the real `nf-curves` + `jf_primitives` in `../rust`).
//!
//! ## Modules
//! - [`domains`]  domain separators / prefixes (must match Nightfall constants)
//! - [`hash`]     Poseidon (= circomlib/iden3 = `jf_primitives::Poseidon`) wrappers
//! - [`bjj`]      Baby JubJub (`a = 1`, `ed_on_bn254`): add / double / scalar-mul
//! - [`keys`]     root-key derivation (zkp private key + nullifier key)
//! - [`kemdem`]   Poseidon KEM + DEM stream cipher
//! - [`note`]     note commitment + nullifier
//! - [`merkle`]   binary Poseidon Merkle membership (NF4 `MembershipProof` shape)
//! - [`client`]   the high-level client-transaction statement
//! - [`script`]   bounded predicate-VM mirror
//! - [`notev2`]   programmable-note v2 commitment and stealth helpers
//! - [`statement_v2`] fixed programmable-note transfer statement//!
//! Everything is fail-closed: invalid scalars, off-curve points, and unsatisfied
//! constraints abort witness generation before any proving work happens.

pub mod domains;
pub mod hash;
pub mod bjj;
pub mod keys;
pub mod kemdem;
pub mod note;
pub mod merkle;
pub mod sponge;
pub mod deposit;
pub mod client;
pub mod statement;
pub mod script;
pub mod notev2;
pub mod statement_v2;

mod vectors;
mod statement_vectors;
mod statement_v2_vectors;
mod tests;

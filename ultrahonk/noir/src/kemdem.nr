//! Poseidon KEM-DEM hybrid encryption.
//!
//! Matches Nightfall's client encryption path:
//! - **KEM**: derive a symmetric key from a Baby JubJub shared secret point
//!   `enc_key = Poseidon(ss.x, ss.y, DOMAIN_KEM)`.
//! - **DEM**: a Poseidon stream cipher; the `i`-th keystream field is
//!   `Poseidon(enc_key, DOMAIN_DEM, i)` and `cipher_i = keystream_i + plain_i`.

use crate::bjj::Point;
use crate::domains::{DOMAIN_DEM, DOMAIN_KEM};
use crate::hash;

/// KEM: derive the symmetric encryption key from a shared-secret point.
pub fn derive_enc_key(ss: Point) -> Field {
    hash::hash3(ss.x, ss.y, DOMAIN_KEM)
}

/// DEM keystream field for a given counter.
pub fn dem_keystream(enc_key: Field, counter: Field) -> Field {
    hash::hash3(enc_key, DOMAIN_DEM, counter)
}

/// Encrypt a single field: `cipher = keystream(counter) + plain`.
pub fn dem_encrypt_field(enc_key: Field, counter: Field, plain: Field) -> Field {
    dem_keystream(enc_key, counter) + plain
}

/// Decrypt a single field: `plain = cipher - keystream(counter)`.
pub fn dem_decrypt_field(enc_key: Field, counter: Field, cipher: Field) -> Field {
    cipher - dem_keystream(enc_key, counter)
}

/// Encrypt `N` plaintext fields with counters `0..N`.
pub fn dem_encrypt<let N: u32>(enc_key: Field, plains: [Field; N]) -> [Field; N] {
    let mut out: [Field; N] = [0; N];
    for i in 0..N {
        out[i] = dem_encrypt_field(enc_key, i as Field, plains[i]);
    }
    out
}

/// Decrypt `N` ciphertext fields with counters `0..N`.
pub fn dem_decrypt<let N: u32>(enc_key: Field, ciphers: [Field; N]) -> [Field; N] {
    let mut out: [Field; N] = [0; N];
    for i in 0..N {
        out[i] = dem_decrypt_field(enc_key, i as Field, ciphers[i]);
    }
    out
}

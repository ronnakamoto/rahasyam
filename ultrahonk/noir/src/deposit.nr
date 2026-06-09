//! Deposit-mode public-data hashing (nf4 `deposit_witness.rs` +
//! jf `full_shifted_sha256_hash`).
//!
//! A deposit slot's public-data word is
//!   `SHA256(be32(token) || be32(slot) || be32(value) || be32(secret_hash)) >> 4`
//! — the 256-bit big-endian digest with its low 4 bits dropped (jf's gadget
//! splits off `digest & 0xF` and keeps the top 252 bits). Each field element is
//! serialized as 32 big-endian bytes, matching jf's `preprocess` (8 big-endian
//! 32-bit words per input). Anchored bit-for-bit against nf4's real in-circuit
//! gadget by `rust/examples/anchor_sha256.rs`.

/// `SHA256(be32(inputs[0]) || … ) >> 4` over four field inputs.
pub fn sha256_shift(inputs: [Field; 4]) -> Field {
    // Serialize the 4 inputs as 4 × 32 big-endian bytes = 128-byte message.
    let mut msg: [u8; 128] = [0; 128];
    for i in 0..4 {
        let be: [u8; 32] = inputs[i].to_be_bytes();
        for j in 0..32 {
            msg[i * 32 + j] = be[j];
        }
    }
    let digest: [u8; 32] = sha256::digest(msg);

    // digest >> 4 = (top 31 bytes as integer) * 16 + (digest[31] >> 4).
    // (digest = T*256 + digest[31], and T*256 is divisible by 16.)
    let mut top: Field = 0;
    for i in 0..31 {
        top = top * 256 + digest[i] as Field;
    }
    let high_nibble = (digest[31] / 16) as Field;
    top * 16 + high_nibble
}

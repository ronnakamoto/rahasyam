# ultrahonk

A **cryptography library for Barretenberg UltraHonk**, providing the client-side
zero-knowledge primitives used by Nightfall 4.

`ultrahonk` expresses the full Nightfall 4 client transaction statement as a native
**Noir** circuit proved by **Barretenberg UltraHonk**, with bit-for-bit parity against
the reference Rust implementation. It enables browser proving via `bb.js` and recursive
verification inside the rollup.

## Why native Noir

The existing `nf4_new/lib/src/proving/ultrahonk_circuit.rs` lowers a JF `PlonkCircuit`
to ACIR gate-by-gate, but **rejects JF lookup gates** — so it cannot express the full
statement (range checks, etc.). The correct path is a native Noir circuit whose
primitives are validated by frozen vectors against the canonical Rust implementation.
This library is the clean, tested consolidation of that path.

## The statement

All keys are derived from `root_key` (nf4 parity); the in-circuit reduction of the
zkp private key is enforced with a witnessed quotient `lambda`.

```text
zkp_priv   = reduce(Poseidon(root_key, PRIVATE_KEY_PREFIX)) mod l   (witness + check)
pk         = zkp_priv · G                         (Baby JubJub, a = 1)
ss         = ephemeral · pk
epk        = ephemeral · G
enc_key    = Poseidon(ss.x, ss.y, DOMAIN_KEM)     (KEM)
cipher_i   = Poseidon(enc_key, DOMAIN_DEM, i) + plain_i    (DEM, i = 0..2)
plain      = [nf_token_id, nf_slot_id, value]
secrets    = [cipher0, cipher1, cipher2, epk.y, x_parity]
salt       = ss.y
commitment = Poseidon(nf_token_id, nf_slot_id, value, pk.x, pk.y, salt)   (arity-6)
nullifier  = Poseidon(Poseidon(root_key, NULLIFIER_PREFIX), commitment)
```

Public outputs (7 fields): `[commitment, nullifier, compressed_secrets[0..5]]`.
These formulas match nf4's `derive_key.rs`, `verify_commitments_gadgets.rs`,
`kemdem_gadgets.rs`, and `verify_nullifiers_gadgets.rs`.

## The full client statement (transfer / withdraw / swap)

The provable circuit `circuits/client_tx` proves nf4's **complete** per-transaction
statement — the UltraHonk analogue of `unified_circuit.rs` — built on the primitives
above. `noir/src/statement.nr` (native oracle: `rust/src/statement.rs`) enforces, all
**fail-closed**:

- **4 commitments + 4 nullifiers** — recipient note, transfer change, fee, fee change,
  with conditional zeroing per mode; nullifier slots 0/1 spend the note tokens, slots 2/3
  the fee token; neutral→`nullifier_key` vs deposit key, plus salt-from-preimage.
- **Merkle membership** of each spent note against the **public `root`** (binary Poseidon
  tree; depth configurable, vectors use 32).
- **Value/fee conservation** + **range checks** (160-bit addresses, 96-bit values/fees/
  changes, 64-bit nonce/deadline) and **duplicate checks**.
- **Modes** transfer / withdraw / swap / **deposit** — role and value/token/recipient
  selection, the withdraw KEM-DEM override, the **`swap_link` Poseidon sponge** (width-4
  rate-3, matching `SpongePoseidonHashGadget`), and deposit's arity-6 commitment +
  **SHA256>>4** public-data words (`DepositDataVar::sha256_and_shift`).
- **`commitment[0]` shared salt** `Poseidon(ss.x, ss.y, DOMAIN_SHARED_SALT)`.

Public output is the framed **27-word** vector
`[framing, fee, root, commitments[4], nullifiers[4], compressed_secrets[5], swap_link,
deadline, swap_side]`, matching nf4's `From<&PublicInputs> for Vec<Fr254>`. The transfer,
withdraw, and swap scenarios are proven and verified by `bb` and `bb.js`; the deposit
scenario is parity-verified Rust↔Noir (`statement_deposit_matches_reference`).

**Deposit SHA256 anchored.** The deposit public-data hash
`SHA256(be32(token)||be32(slot)||be32(value)||be32(secret_hash)) >> 4` is anchored
**bit-for-bit** to nf4's real in-circuit `full_shifted_sha256_hash` gadget by
`rust/examples/anchor_sha256.rs` (run in `verify-all.sh`). All four modes are covered;
see `REVIEW.md §0` for the full status and the remaining nf4 wiring backlog.

## Parity strategy (fail-closed; no silent fallbacks)

Two frozen vector sets — `vectors/client_ref.json` (single-note primitives) and
`vectors/statement.json` (full transfer/withdraw/swap statement), both produced by the
**real** `nf_curves` + `jf_primitives` — drive three independent checks:

1. **Rust** (`cargo test`) — native primitives + full statement reproduce the vectors.
2. **Noir** (`nargo test`) — in-circuit gadgets + statement reproduce the same vectors.
3. **e2e** (`bb` / `bb.js`) — the compiled circuit proves & verifies; the 27 public
   outputs equal the vectors.

Invalid scalars, off-curve points, and unsatisfied constraints abort witness generation
before any proving work — matching the existing `ultrahonk_v1.rs` "no Plonk fallback" stance.

## Production hardening over the prototypes

- Full **251-bit** scalar multiplication (prototypes used 64-bit for small scalars).
- Tight **subgroup-order** scalar check `scalar < l`, not just a bit-length bound.
- On-curve assertions for derived points.
- Generalised **multi-field DEM** (`dem_encrypt`/`dem_decrypt` over `N` fields).

## Toolchain

- `nargo` 1.0.0-beta.22 (`noirup`)
- `bb` 5.0.0-nightly.20260522 (`bbup`)
- Rust stable + `cargo`
- Node ≥ 18 with `@noir-lang/noir_js` 1.0.0-beta.22 + `@aztec/bb.js` 5.0.0-nightly.20260522

## Quick start

```sh
# 1. Noir gadget + parity tests
cd noir && nargo test

# 2. Rust reference parity
cd ../rust && cargo test
cargo run --example gen_vectors      # regenerate vectors/client_ref.json (single-note)
cargo run --example gen_statement    # regenerate vectors/statement.json + Noir fixtures + Prover.toml

# 3. Compile + prove + verify (UltraHonk)
cd ../circuits/client_tx
nargo compile && nargo execute witness
bb write_vk -b target/nightfish_honk_client_tx.json -o target -t noir-recursive
bb prove    -b target/nightfish_honk_client_tx.json -w target/witness.gz -o target -t noir-recursive
bb verify   -k target/vk -p target/proof -i target/public_inputs -t noir-recursive

# 4. Browser/Node bb.js end-to-end
cd ../../ts && npm install && node verify_e2e.mjs

# …or everything at once:
./scripts/verify-all.sh
```
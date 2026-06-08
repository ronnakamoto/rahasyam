/**
 * End-to-end verification of the standalone client circuit (full statement).
 *
 * Loads the nargo-compiled circuit + the frozen full-statement vectors, solves
 * the witness with noir_js, proves & verifies with Barretenberg UltraHonk
 * (bb.js WASM), and asserts the 27 framed public outputs equal the real nf4
 * reference vectors for the transfer scenario.
 *
 *   node verify_e2e.mjs
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Noir } from '@noir-lang/noir_js';
import { Barretenberg, BackendType, UltraHonkBackend } from '@aztec/bb.js';

const here = dirname(fileURLToPath(import.meta.url));
const circuit = JSON.parse(
  readFileSync(join(here, '../circuits/client_tx/target/nightfish_honk_client_tx.json'), 'utf8'),
);
const doc = JSON.parse(readFileSync(join(here, '../vectors/statement.json'), 'utf8'));
const scenario = doc.scenarios.find((s) => s.name === 'transfer');
if (!scenario) throw new Error('transfer scenario missing from statement.json');
const { inputs, outputs } = scenario;

const toHex = (d) => '0x' + BigInt(d).toString(16);
const point = (p) => ({ x: toHex(p.x), y: toHex(p.y) });
const pathElem = (e) => ({ sibling: toHex(e.sibling), sibling_on_left: e.sibling_on_left });

// Mirror the Noir `StatementInputs` struct field-for-field.
const input = {
  root: toHex(inputs.root),
  root_key: toHex(inputs.root_key),
  zkp_priv: toHex(outputs.zkp_priv),
  zkp_priv_lambda: toHex(outputs.zkp_priv_lambda),
  ephemeral_key: toHex(inputs.ephemeral_key),
  fee_token_id: toHex(inputs.fee_token_id),
  fee: toHex(inputs.fee),
  nf_address: toHex(inputs.nf_address),
  nf_slot_id: toHex(inputs.nf_slot_id),
  nullifiers_values: inputs.nullifiers_values.map(toHex),
  nullifiers_salts: inputs.nullifiers_salts.map(toHex),
  public_keys: inputs.public_keys.map(point),
  membership_proofs: inputs.membership_proofs.map((path) => path.map(pathElem)),
  secret_preimages: inputs.secret_preimages.map((sp) => sp.map(toHex)),
  commitments_values: inputs.commitments_values.map(toHex),
  sender_commitment_salts: inputs.sender_commitment_salts.map(toHex),
  deposit_token_ids: inputs.deposit_token_ids.map(toHex),
  deposit_slot_ids: inputs.deposit_slot_ids.map(toHex),
  deposit_values: inputs.deposit_values.map(toHex),
  deposit_secret_hashes: inputs.deposit_secret_hashes.map(toHex),
  withdraw_address: toHex(inputs.withdraw_address),
  party_a_public_key: point(inputs.party_a_public_key),
  party_b_public_key: point(inputs.party_b_public_key),
  nf_token_a_id: toHex(inputs.nf_token_a_id),
  value_a: toHex(inputs.value_a),
  nf_token_b_id: toHex(inputs.nf_token_b_id),
  value_b: toHex(inputs.value_b),
  swap_nonce: toHex(inputs.swap_nonce),
  deadline: toHex(inputs.deadline),
};

const noir = new Noir(circuit);
const api = await Barretenberg.new({ backend: BackendType.Wasm, threads: 1 });
const backend = new UltraHonkBackend(circuit.bytecode, api);

console.log('executing witness...');
const { witness } = await noir.execute({ input });
console.log('proving (UltraHonk, bb.js WASM)...');
const { proof, publicInputs } = await backend.generateProof(witness);
console.log('verifying...');
const ok = await backend.verifyProof({ proof, publicInputs });
await api.destroy();

const expect = outputs.public_inputs;
if (publicInputs.length !== expect.length) {
  console.error(`public input count ${publicInputs.length} != expected ${expect.length}`);
  process.exit(1);
}
let parity = true;
publicInputs.forEach((pi, i) => {
  const match = BigInt(pi) === BigInt(expect[i]);
  parity &&= match;
  if (!match) console.log(`output[${i}]: MISMATCH ${pi} != ${expect[i]}`);
});

console.log(`public outputs: ${publicInputs.length} words, ${parity ? 'all MATCH' : 'MISMATCH'}`);
console.log(`proof bytes : ${proof.length}`);
console.log(`verifyProof : ${ok}`);
if (!ok || !parity) {
  console.error('E2E FAILED');
  process.exit(1);
}
console.log('E2E OK: UltraHonk proof verified; 27 public outputs match nf4 transfer vector');

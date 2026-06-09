import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Noir } from '@noir-lang/noir_js';
import { Barretenberg, BackendType, UltraHonkBackend } from '@aztec/bb.js';

export const NUM_PUBLIC_INPUTS = 27;
export const EXPECTED_CIRCUIT_BYTECODE_SHA256 =
  'aa844f9aa7115f9065098733296c48fb4c142ae534e667de2c31989d3eda0db5';

const here = dirname(fileURLToPath(import.meta.url));
const circuitPath = join(here, 'nightfish_honk_client_tx.json');

export function circuitBytecodeHash(circuit) {
  if (!circuit || typeof circuit.bytecode !== 'string') {
    throw new Error('sidecar circuit is missing string bytecode');
  }
  return createHash('sha256').update(circuit.bytecode, 'utf8').digest('hex');
}

export function assertPinnedCircuit(circuit, path = circuitPath) {
  const actual = circuitBytecodeHash(circuit);
  if (actual !== EXPECTED_CIRCUIT_BYTECODE_SHA256) {
    throw new Error(
      `UltraHonk circuit bytecode SHA-256 mismatch at ${path}: expected ${EXPECTED_CIRCUIT_BYTECODE_SHA256}, got ${actual}`,
    );
  }
}

export function loadCircuit() {
  const circuit = JSON.parse(readFileSync(circuitPath, 'utf8'));
  assertPinnedCircuit(circuit);
  return circuit;
}

export function readJsonFromArgOrStdin(argvPath = process.argv[2]) {
  const text = argvPath ? readFileSync(argvPath, 'utf8') : readFileSync(0, 'utf8');
  if (!text.trim()) throw new Error('expected JSON input from argv[1] path or stdin');
  return JSON.parse(text);
}

export function toHexField(value, name = 'field') {
  if (value === undefined || value === null) throw new Error(`missing ${name}`);
  return `0x${BigInt(value).toString(16)}`;
}

function pointAbi(point, name) {
  if (!point || typeof point !== 'object') throw new Error(`missing ${name}`);
  return {
    x: toHexField(point.x, `${name}.x`),
    y: toHexField(point.y, `${name}.y`),
  };
}

function pathAbi(element, name) {
  if (!element || typeof element !== 'object') throw new Error(`missing ${name}`);
  const siblingOnLeft = element.sibling_on_left ?? element.siblingOnLeft;
  if (typeof siblingOnLeft !== 'boolean') throw new Error(`missing boolean ${name}.sibling_on_left`);
  return {
    sibling: toHexField(element.sibling, `${name}.sibling`),
    sibling_on_left: siblingOnLeft,
  };
}

function arrayFieldAbi(values, name) {
  if (!Array.isArray(values)) throw new Error(`missing array ${name}`);
  return values.map((value, i) => toHexField(value, `${name}[${i}]`));
}

function arrayPointAbi(values, name) {
  if (!Array.isArray(values)) throw new Error(`missing array ${name}`);
  return values.map((value, i) => pointAbi(value, `${name}[${i}]`));
}

function arrayPathAbi(paths, name) {
  if (!Array.isArray(paths)) throw new Error(`missing array ${name}`);
  return paths.map((path, i) => {
    if (!Array.isArray(path)) throw new Error(`missing array ${name}[${i}]`);
    return path.map((element, j) => pathAbi(element, `${name}[${i}][${j}]`));
  });
}

function nestedFieldAbi(values, name) {
  if (!Array.isArray(values)) throw new Error(`missing array ${name}`);
  return values.map((row, i) => {
    if (!Array.isArray(row)) throw new Error(`missing array ${name}[${i}]`);
    return row.map((value, j) => toHexField(value, `${name}[${i}][${j}]`));
  });
}

function snakeInputToAbi(input) {
  return {
    input: {
      root: toHexField(input.root, 'input.root'),
      root_key: toHexField(input.root_key, 'input.root_key'),
      zkp_priv: toHexField(input.zkp_priv, 'input.zkp_priv'),
      zkp_priv_lambda: toHexField(input.zkp_priv_lambda, 'input.zkp_priv_lambda'),
      ephemeral_key: toHexField(input.ephemeral_key, 'input.ephemeral_key'),
      fee_token_id: toHexField(input.fee_token_id, 'input.fee_token_id'),
      fee: toHexField(input.fee, 'input.fee'),
      nf_address: toHexField(input.nf_address, 'input.nf_address'),
      nf_slot_id: toHexField(input.nf_slot_id, 'input.nf_slot_id'),
      nullifiers_values: arrayFieldAbi(input.nullifiers_values, 'input.nullifiers_values'),
      nullifiers_salts: arrayFieldAbi(input.nullifiers_salts, 'input.nullifiers_salts'),
      public_keys: arrayPointAbi(input.public_keys, 'input.public_keys'),
      membership_proofs: arrayPathAbi(input.membership_proofs, 'input.membership_proofs'),
      secret_preimages: nestedFieldAbi(input.secret_preimages, 'input.secret_preimages'),
      commitments_values: arrayFieldAbi(input.commitments_values, 'input.commitments_values'),
      sender_commitment_salts: arrayFieldAbi(input.sender_commitment_salts, 'input.sender_commitment_salts'),
      deposit_token_ids: arrayFieldAbi(input.deposit_token_ids, 'input.deposit_token_ids'),
      deposit_slot_ids: arrayFieldAbi(input.deposit_slot_ids, 'input.deposit_slot_ids'),
      deposit_values: arrayFieldAbi(input.deposit_values, 'input.deposit_values'),
      deposit_secret_hashes: arrayFieldAbi(input.deposit_secret_hashes, 'input.deposit_secret_hashes'),
      withdraw_address: toHexField(input.withdraw_address, 'input.withdraw_address'),
      party_a_public_key: pointAbi(input.party_a_public_key, 'input.party_a_public_key'),
      party_b_public_key: pointAbi(input.party_b_public_key, 'input.party_b_public_key'),
      nf_token_a_id: toHexField(input.nf_token_a_id, 'input.nf_token_a_id'),
      value_a: toHexField(input.value_a, 'input.value_a'),
      nf_token_b_id: toHexField(input.nf_token_b_id, 'input.nf_token_b_id'),
      value_b: toHexField(input.value_b, 'input.value_b'),
      swap_nonce: toHexField(input.swap_nonce, 'input.swap_nonce'),
      deadline: toHexField(input.deadline, 'input.deadline'),
    },
  };
}

function camelInputToAbi(input) {
  return {
    input: {
      root: toHexField(input.root, 'root'),
      root_key: toHexField(input.rootKey, 'rootKey'),
      zkp_priv: toHexField(input.zkpPriv, 'zkpPriv'),
      zkp_priv_lambda: toHexField(input.zkpPrivLambda, 'zkpPrivLambda'),
      ephemeral_key: toHexField(input.ephemeralKey, 'ephemeralKey'),
      fee_token_id: toHexField(input.feeTokenId, 'feeTokenId'),
      fee: toHexField(input.fee, 'fee'),
      nf_address: toHexField(input.nfAddress, 'nfAddress'),
      nf_slot_id: toHexField(input.nfSlotId, 'nfSlotId'),
      nullifiers_values: arrayFieldAbi(input.nullifiersValues, 'nullifiersValues'),
      nullifiers_salts: arrayFieldAbi(input.nullifiersSalts, 'nullifiersSalts'),
      public_keys: arrayPointAbi(input.publicKeys, 'publicKeys'),
      membership_proofs: arrayPathAbi(input.membershipProofs, 'membershipProofs'),
      secret_preimages: nestedFieldAbi(input.secretPreimages, 'secretPreimages'),
      commitments_values: arrayFieldAbi(input.commitmentsValues, 'commitmentsValues'),
      sender_commitment_salts: arrayFieldAbi(input.senderCommitmentSalts, 'senderCommitmentSalts'),
      deposit_token_ids: arrayFieldAbi(input.depositTokenIds, 'depositTokenIds'),
      deposit_slot_ids: arrayFieldAbi(input.depositSlotIds, 'depositSlotIds'),
      deposit_values: arrayFieldAbi(input.depositValues, 'depositValues'),
      deposit_secret_hashes: arrayFieldAbi(input.depositSecretHashes, 'depositSecretHashes'),
      withdraw_address: toHexField(input.withdrawAddress, 'withdrawAddress'),
      party_a_public_key: pointAbi(input.partyAPublicKey, 'partyAPublicKey'),
      party_b_public_key: pointAbi(input.partyBPublicKey, 'partyBPublicKey'),
      nf_token_a_id: toHexField(input.nfTokenAId, 'nfTokenAId'),
      value_a: toHexField(input.valueA, 'valueA'),
      nf_token_b_id: toHexField(input.nfTokenBId, 'nfTokenBId'),
      value_b: toHexField(input.valueB, 'valueB'),
      swap_nonce: toHexField(input.swapNonce, 'swapNonce'),
      deadline: toHexField(input.deadline, 'deadline'),
    },
  };
}

export function toAbi(payload) {
  if (!payload || typeof payload !== 'object') throw new Error('expected JSON object');
  if (payload.input && typeof payload.input === 'object') return snakeInputToAbi(payload.input);
  if (payload.root_key !== undefined) return snakeInputToAbi(payload);
  return camelInputToAbi(payload);
}

export async function createBackend() {
  const circuit = loadCircuit();
  const api = await Barretenberg.new({ backend: BackendType.Wasm, threads: 1 });
  const backend = new UltraHonkBackend(circuit.bytecode, api);
  return { circuit, api, backend };
}

export async function proveStatement(payload) {
  const abi = toAbi(payload);
  const { circuit, api, backend } = await createBackend();
  try {
    const noir = new Noir(circuit);
    const { witness } = await noir.execute(abi);
    const { proof, publicInputs } = await backend.generateProof(witness);
    if (publicInputs.length !== NUM_PUBLIC_INPUTS) {
      throw new Error(`expected ${NUM_PUBLIC_INPUTS} public inputs, got ${publicInputs.length}`);
    }
    return { proof, publicInputs };
  } finally {
    await api.destroy();
  }
}

export async function verifyProofPayload(payload) {
  if (!payload || typeof payload !== 'object') throw new Error('expected JSON object');
  if (!Array.isArray(payload.publicInputs)) throw new Error('expected publicInputs array');
  const proof = proofHexToBytes(payload.proofHex);
  const { api, backend } = await createBackend();
  try {
    return await backend.verifyProof({ proof, publicInputs: payload.publicInputs });
  } finally {
    await api.destroy();
  }
}

export function proofToHex(proof) {
  return `0x${Buffer.from(proof).toString('hex')}`;
}

export function proofHexToBytes(proofHex) {
  if (typeof proofHex !== 'string') throw new Error('expected proofHex string');
  const hex = proofHex.startsWith('0x') || proofHex.startsWith('0X') ? proofHex.slice(2) : proofHex;
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) throw new Error('invalid proofHex');
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

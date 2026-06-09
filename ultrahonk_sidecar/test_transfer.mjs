#!/usr/bin/env node
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { proofHexToBytes } from './sidecar_lib.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, 'vectors/statement.json'), 'utf8'));
const scenario = vectors.scenarios.find((entry) => entry.name === 'transfer');
assert(scenario, 'transfer scenario missing from vectors/statement.json');

const input = {
  input: {
    ...scenario.inputs,
    zkp_priv: scenario.outputs.zkp_priv,
    zkp_priv_lambda: scenario.outputs.zkp_priv_lambda,
  },
};

const started = Date.now();
const prove = spawnSync(process.execPath, ['prove.mjs'], {
  cwd: here,
  input: `${JSON.stringify(input)}\n`,
  encoding: 'utf8',
  maxBuffer: 128 * 1024 * 1024,
});
const proveSeconds = (Date.now() - started) / 1000;
if (prove.status !== 0) {
  process.stderr.write(prove.stderr);
  process.stderr.write(prove.stdout);
  throw new Error(`prove.mjs exited ${prove.status}`);
}
const proofPayload = JSON.parse(prove.stdout.trim());
assert.match(proofPayload.proofHex, /^0x[0-9a-f]+$/i);
assert.equal(proofPayload.publicInputs.length, 27);

const expected = scenario.outputs.public_inputs;
assert.equal(proofPayload.publicInputs.length, expected.length);
let parity = true;
for (let i = 0; i < expected.length; i += 1) {
  const matches = BigInt(proofPayload.publicInputs[i]) === BigInt(expected[i]);
  parity &&= matches;
  if (!matches) {
    console.log(`output[${i}]: MISMATCH ${proofPayload.publicInputs[i]} != ${expected[i]}`);
  }
}
assert(parity, 'public inputs differ from frozen transfer vector');

const verify = spawnSync(process.execPath, ['verify.mjs'], {
  cwd: here,
  input: `${JSON.stringify(proofPayload)}\n`,
  encoding: 'utf8',
  maxBuffer: 128 * 1024 * 1024,
});
if (verify.status !== 0) {
  process.stderr.write(verify.stderr);
  process.stderr.write(verify.stdout);
  throw new Error(`verify.mjs exited ${verify.status}`);
}
const verifyPayload = JSON.parse(verify.stdout.trim());
assert.equal(verifyPayload.valid, true);

console.log(`prove.mjs exit: ${prove.status}`);
console.log(`verify.mjs exit: ${verify.status}`);
console.log(`proving time: ${proveSeconds.toFixed(3)}s`);
console.log(`proof bytes : ${proofHexToBytes(proofPayload.proofHex).length}`);
console.log(`verifyProof : ${verifyPayload.valid}`);
console.log(`public outputs: ${proofPayload.publicInputs.length} words, all MATCH`);
console.log('E2E OK: UltraHonk proof verified; 27 public outputs match nf4 transfer vector');

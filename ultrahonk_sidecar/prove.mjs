#!/usr/bin/env node
import { proofToHex, proveStatement, readJsonFromArgOrStdin } from './sidecar_lib.mjs';

function redirectStdoutToStderr() {
  const stdoutWrite = process.stdout.write.bind(process.stdout);
  process.stdout.write = (chunk, encoding, callback) => process.stderr.write(chunk, encoding, callback);
  return () => {
    process.stdout.write = stdoutWrite;
  };
}

try {
  const started = Date.now();
  const input = readJsonFromArgOrStdin();
  console.error('executing witness and proving (UltraHonk, bb.js WASM, threads=1)...');
  const restoreStdout = redirectStdoutToStderr();
  let proof;
  let publicInputs;
  try {
    ({ proof, publicInputs } = await proveStatement(input));
  } finally {
    restoreStdout();
  }
  console.error(`proof generated in ${((Date.now() - started) / 1000).toFixed(3)}s (${proof.length} bytes, ${publicInputs.length} public inputs)`);
  process.stdout.write(`${JSON.stringify({ proofHex: proofToHex(proof), publicInputs })}\n`);
} catch (error) {
  console.error(error?.stack || error?.message || String(error));
  process.exit(1);
}

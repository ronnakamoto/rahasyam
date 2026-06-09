#!/usr/bin/env node
import { readJsonFromArgOrStdin, verifyProofPayload } from './sidecar_lib.mjs';

function redirectStdoutToStderr() {
  const stdoutWrite = process.stdout.write.bind(process.stdout);
  process.stdout.write = (chunk, encoding, callback) => process.stderr.write(chunk, encoding, callback);
  return () => {
    process.stdout.write = stdoutWrite;
  };
}

try {
  const input = readJsonFromArgOrStdin();
  const restoreStdout = redirectStdoutToStderr();
  let valid;
  try {
    valid = await verifyProofPayload(input);
  } finally {
    restoreStdout();
  }
  process.stdout.write(`${JSON.stringify({ valid })}\n`);
  process.exit(valid ? 0 : 1);
} catch (error) {
  console.error(error?.stack || error?.message || String(error));
  process.exit(1);
}

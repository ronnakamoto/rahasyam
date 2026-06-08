# NF4 UltraHonk sidecar

Node/bb.js sidecar for proving and verifying the prebuilt `nightfish_honk_client_tx` Noir circuit with `@noir-lang/noir_js` and `@aztec/bb.js` UltraHonk WASM (`threads: 1`).

## Install

```sh
cd ultrahonk_sidecar
npm install
```

If the registry is unavailable, copy `node_modules` from the matching nightfish-honk TypeScript workspace that already has `@aztec/bb.js@5.0.0-nightly.20260522` and `@noir-lang/noir_js@1.0.0-beta.22` installed.

## `prove.mjs`

```sh
node prove.mjs input.json
cat input.json | node prove.mjs
```

Input is JSON from `argv[1]` or stdin. It may be either:

1. ABI-shaped snake_case Noir input:

```json
{"input":{"root":"0x...","root_key":"0x...","zkp_priv":"0x...","zkp_priv_lambda":"0x..."}}
```

with all remaining `StatementInputs` fields present; or

2. camelCase `StatementInputs`:

```json
{"root":"0x...","rootKey":"0x...","zkpPriv":"0x...","zkpPrivLambda":"0x..."}
```

with all remaining fields present. Decimal strings and `0x` strings are accepted and normalized to Noir hex fields.

Stdout is exactly one JSON line on success:

```json
{"proofHex":"0x...","publicInputs":["0x...", "..."]}
```

`publicInputs` must contain 27 entries. Witness/proving errors are written to stderr and the process exits non-zero.

## `verify.mjs`

```sh
node verify.mjs proof.json
cat proof.json | node verify.mjs
```

Input JSON shape:

```json
{"proofHex":"0x...","publicInputs":["0x...", "..."]}
```

Stdout is one JSON line: `{"valid":true}` or `{"valid":false}`. Exit code is `0` only when valid; invalid proofs or malformed input exit `1`.

## Feasibility test

```sh
npm test
```

The test builds the frozen transfer ABI from `vectors/statement.json`, runs `prove.mjs`, runs `verify.mjs`, and asserts all 27 public outputs match the vector.

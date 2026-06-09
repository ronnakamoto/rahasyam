#!/usr/bin/env bash
#
# Run every nightfish-honk parity/proof check, fail-closed.
#
#   scripts/verify-all.sh
#
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$HOME/.nargo/bin:$HOME/.bb:$HOME/.cargo/bin:$PATH"

echo "== [1/4] Noir gadget + parity tests (nargo test) =="
( cd "$ROOT/noir" && nargo test )

echo "== [2/4] Rust reference parity (cargo test) =="
( cd "$ROOT/rust" && cargo test )

echo "== [2b/4] Deposit SHA256 anchored to nf4's real gadget (cargo run) =="
( cd "$ROOT/rust" && cargo run --quiet --example anchor_sha256 )

echo "== [2c/4] swap_link sponge anchored to nf4's real gadget (cargo run) =="
( cd "$ROOT/rust" && cargo run --quiet --example anchor_sponge )

echo "== [3/4] Compile client circuit + solve witness (nargo) =="
( cd "$ROOT/circuits/client_tx" && nargo compile && nargo execute witness )

echo "== [4/4] UltraHonk prove + verify (bb, noir-recursive) =="
cd "$ROOT/circuits/client_tx"
B="target/nightfish_honk_client_tx.json"
bb write_vk -b "$B" -o target -t noir-recursive
bb prove   -b "$B" -w target/witness.gz -o target -t noir-recursive
bb verify  -k target/vk -p target/proof -i target/public_inputs -t noir-recursive

# Optional: browser/Node bb.js end-to-end (only if ts deps are installed).
if [ -d "$ROOT/ts/node_modules" ]; then
  echo "== [extra] bb.js WASM end-to-end (ts/verify_e2e.mjs) =="
  ( cd "$ROOT/ts" && node verify_e2e.mjs )
fi

echo
echo "All nightfish-honk checks passed."

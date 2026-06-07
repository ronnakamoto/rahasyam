#!/bin/sh
set -e

# Start anvil.
# `--hardfork prague` enables the EIP-2537 BLS12-381 precompiles required by the
# Nova BLS attestor committee verifier (NovaCommitteeVerifier / router id 3).
# Prague is a superset of Cancun for existing contracts, so this is safe for the
# Plonk / Nova-ECDSA paths too.
anvil --base-fee 58000000000 --block-time 5 --gas-limit 500000000 --hardfork prague &
ANVIL_PID=$!

# Wait for anvil to be ready (JSON-RPC POST)
for i in $(seq 1 30); do
    if curl -s -X POST --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
        -H "Content-Type: application/json" http://localhost:8545 | grep -q '"result"'; then
        break
    fi
    echo "Waiting for anvil to be ready... ($i)"
    sleep 1
done

# Run the deployment script with Foundry
forge script MockDeployer \
    --fork-url ws://localhost:8545 \
    --broadcast \
    --force

wait $ANVIL_PID

exec "$@"

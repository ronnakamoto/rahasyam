// SPDX-License-Identifier: CC0
pragma solidity >=0.8.20;

import "./IRollupVerifier.sol";

// Mock verifier contract that just returns `true`.
contract MockVerifier is IRollupVerifier {
    bool private defaultResult = true;

    function verifyProof(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view override returns (bool result) {
        proof;
        publicInputs;
        result = defaultResult;
        return result;
    }
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title IRollupVerifier
/// @notice Interface for rollup proof verification that all verifier implementations must follow
interface IRollupVerifier {
    /// @notice Verify a rollup proof
    /// @param proof The serialized proof bytes (without the proof system ID prefix)
    /// @param publicInputs The public inputs for the proof
    /// @return True if the proof is valid, false otherwise
    function verifyProof(bytes calldata proof, uint256[] calldata publicInputs) external view returns (bool);
}

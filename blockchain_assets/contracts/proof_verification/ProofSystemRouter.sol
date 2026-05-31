// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IRollupVerifier} from "./IRollupVerifier.sol";

/// @title ProofSystemRouter
/// @notice Routes proof verification to the appropriate verifier based on proof system ID
/// @dev The first byte of the proof blob is the proof system ID
contract ProofSystemRouter is Ownable {
    mapping(uint8 => IRollupVerifier) public verifiers;
    mapping(uint8 => bool) public disabled;

    event VerifierRegistered(uint8 id, address verifier);
    event VerifierDisabled(uint8 id);
    event VerifierEnabled(uint8 id, address verifier);

    error UnknownProofSystem(uint8 id);
    error ProofSystemDisabled(uint8 id);
    error InvalidVerifierAddress();
    error ProofTooShort();

    constructor(address initialOwner) Ownable(initialOwner) {}

    /// @notice Register a new verifier for a proof system ID
    /// @param id The proof system ID
    /// @param verifier The address of the verifier contract
    function register(uint8 id, IRollupVerifier verifier) external onlyOwner {
        if (address(verifier) == address(0)) {
            revert InvalidVerifierAddress();
        }
        verifiers[id] = verifier;
        disabled[id] = false;
        emit VerifierRegistered(id, address(verifier));
    }

    /// @notice Disable a proof system
    /// @param id The proof system ID to disable
    function disable(uint8 id) external onlyOwner {
        disabled[id] = true;
        emit VerifierDisabled(id);
    }

    /// @notice Enable a previously disabled proof system
    /// @param id The proof system ID to enable
    function enable(uint8 id) external onlyOwner {
        if (address(verifiers[id]) == address(0)) {
            revert UnknownProofSystem(id);
        }
        disabled[id] = false;
        emit VerifierEnabled(id, address(verifiers[id]));
    }

    /// @notice Verify a proof by routing to the appropriate verifier
    /// @param blob The full proof blob (first byte is the proof system ID)
    /// @param pi The public inputs
    /// @return True if the proof is valid
    function verify(bytes calldata blob, uint256[] calldata pi) external view returns (bool) {
        if (blob.length == 0) {
            revert ProofTooShort();
        }

        uint8 id = uint8(blob[0]);

        if (disabled[id]) {
            revert ProofSystemDisabled(id);
        }

        IRollupVerifier verifier = verifiers[id];
        if (address(verifier) == address(0)) {
            revert UnknownProofSystem(id);
        }

        // Skip the first byte (proof system ID) when passing to the verifier
        bytes calldata proof = blob[1:];
        return verifier.verifyProof(proof, pi);
    }

    /// @notice Get the verifier address for a proof system ID
    /// @param id The proof system ID
    /// @return The verifier address
    function getVerifier(uint8 id) external view returns (address) {
        return address(verifiers[id]);
    }
}

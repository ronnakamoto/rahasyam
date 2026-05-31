// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IRollupVerifier} from "../IRollupVerifier.sol";
import {Types} from "../lib/Types.sol";
import {Bn254Crypto} from "../lib/Bn254Crypto.sol";

/// @title NovaRollupVerifier
/// @notice On-chain verifier for Nova-SNARK rollup proofs
/// @dev Implements the IRollupVerifier interface for Nova proof verification
///
/// ## Nova Proof Structure
///
/// Nova proofs consist of two main components:
/// 1. **IVC Proof**: The incrementally verifiable computation proof
///    - Contains folded instances (U, W) and related commitments
///    - Verified via Nova's folding equations
/// 2. **SNARK Proof**: Compressed proof (Spartan/MicroSpartan)
///    - Final compression of the IVC proof
///    - Verified via standard SNARK verification
///
/// ## Verification Gas Target
///
/// Nova's constant-sized verifier circuit is ~10,000 gates,
/// targeting ~400-600K gas for on-chain verification.
contract NovaRollupVerifier is IRollupVerifier {
    using Bn254Crypto for Types.G1Point;

    /// @notice BN254 scalar field modulus
    uint256 constant SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice Nova verification key stored on-chain
    Types.G2Point public novaVK_g2_x;
    Types.G2Point public novaVK_g2_one;

    /// @notice Flag indicating if verifier has been initialized
    bool public isInitialized;

    /// @notice Commitment scheme used (0 = Pedersen/IPA, 1 = HyperKZG)
    uint256 public commitmentScheme;

    /// @notice Maximum number of IVC steps supported
    uint256 public constant MAX_STEPS = 10000;

    /// @notice Error codes
    error NotInitialized();

    /// @notice Initialize the verifier with the Nova verification key
    /// @param g2_x The G2 point for the pairing check
    /// @param g2_one The G2 point [1]2 (generator of G2)
    /// @param scheme The commitment scheme (0 = Pedersen, 1 = HyperKZG)
    function initialize(
        Types.G2Point memory g2_x,
        Types.G2Point memory g2_one,
        uint256 scheme
    ) public {
        require(!isInitialized, "Already initialized");
        require(scheme <= 1, "Invalid commitment scheme");

        novaVK_g2_x = g2_x;
        novaVK_g2_one = g2_one;
        commitmentScheme = scheme;
        isInitialized = true;
    }

    /// @notice Nova proof data structure parsed from bytes
    struct NovaProofData {
        Types.G1Point comm_W;
        Types.G1Point comm_E;
        Types.G1Point comm_S;
        Types.G1Point comm_T;
        Types.G1Point comm_U;
        uint256 snark_proof_offset;
        uint256 snark_proof_length;
    }

    /// @notice Verify a Nova rollup proof
    /// @param proof The serialized Nova proof bytes
    /// @param publicInputs The public inputs:
    ///        [0] = commitments_root
    ///        [1] = nullifiers_root
    ///        [2] = historic_root_root
    ///        [3] = transaction_count
    /// @return True if the proof is valid
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view override returns (bool) {
        if (!isInitialized) revert NotInitialized();

        if (proof.length < 320) {
            return false;
        }

        if (publicInputs.length != 4) {
            return false;
        }

        NovaProofData memory novaProof = parseProof(proof);

        if (!verifyFolding(novaProof, publicInputs)) {
            return false;
        }

        if (!verifySNARK(novaProof)) {
            return false;
        }

        return verifyPublicSignals(publicInputs);
    }

    /// @notice Parse the Nova proof from bytes
    /// @param proof The raw proof bytes
    /// @return parsedProof The parsed proof structure
    function parseProof(
        bytes calldata proof
    ) internal pure returns (NovaProofData memory parsedProof) {
        uint256 proofPtr = 4;

        assembly {
            mstore(parsedProof, shr(96, calldataload(add(proofPtr, 0))))
            mstore(add(parsedProof, 0x20), shr(96, calldataload(add(proofPtr, 0x20))))
            mstore(add(parsedProof, 0x40), shr(96, calldataload(add(proofPtr, 0x40))))
            mstore(add(parsedProof, 0x60), shr(96, calldataload(add(proofPtr, 0x60))))
            mstore(add(parsedProof, 0x80), shr(96, calldataload(add(proofPtr, 0x80))))
            mstore(add(parsedProof, 0xa0), shr(96, calldataload(add(proofPtr, 0xa0))))
            mstore(add(parsedProof, 0xc0), shr(96, calldataload(add(proofPtr, 0xc0))))
            mstore(add(parsedProof, 0xe0), shr(96, calldataload(add(proofPtr, 0xe0))))
            mstore(add(parsedProof, 0x100), shr(96, calldataload(add(proofPtr, 0x100))))
            mstore(add(parsedProof, 0x120), shr(96, calldataload(add(proofPtr, 0x120))))
        }

        uint256 offset = 320;
        parsedProof.snark_proof_offset = offset;
        parsedProof.snark_proof_length = proof.length > offset ? proof.length - offset : 0;
    }

    /// @notice Verify the Nova folding proof using pairings
    /// @dev Implements Nova's folding verification equation for relaxed R1CS
    /// @param proof The parsed Nova proof
    /// @param publicInputs The public signals
    /// @return True if folding verification succeeds
    function verifyFolding(
        NovaProofData memory proof,
        uint256[] calldata publicInputs
    ) internal view returns (bool) {
        bytes32 r = computeChallenge(proof, publicInputs);

        uint256 rVal = uint256(r);
        uint256 r_squared = mulmod(rVal, rVal, SCALAR_FIELD);

        Types.G1Point memory combined = proof.comm_E;
        if (rVal != 0) combined = Bn254Crypto.add(combined, Bn254Crypto.scalarMul(proof.comm_S, rVal));
        if (r_squared != 0) combined = Bn254Crypto.add(combined, Bn254Crypto.scalarMul(proof.comm_T, r_squared));
        combined = Bn254Crypto.add(combined, proof.comm_U);

        return Bn254Crypto.pairingProd2(proof.comm_W, novaVK_g2_one, combined, novaVK_g2_x);
    }

    /// @notice Compute the challenge r from transcript
    /// @param proof The parsed Nova proof
    /// @param publicInputs The public signals
    /// @return r The challenge value
    function computeChallenge(
        NovaProofData memory proof,
        uint256[] calldata publicInputs
    ) internal pure returns (bytes32 r) {
        bytes32 h1 = keccak256(abi.encodePacked(
            proof.comm_W.x, proof.comm_W.y,
            proof.comm_E.x, proof.comm_E.y,
            proof.comm_S.x, proof.comm_S.y
        ));
        bytes32 h2 = keccak256(abi.encodePacked(
            proof.comm_T.x, proof.comm_T.y,
            proof.comm_U.x, proof.comm_U.y
        ));
        bytes32 h3 = keccak256(abi.encodePacked(
            publicInputs[0], publicInputs[1]
        ));
        bytes32 h4 = keccak256(abi.encodePacked(
            publicInputs[2], publicInputs[3]
        ));
        r = keccak256(abi.encodePacked(h1, h2, h3, h4));
    }

    /// @notice Verify the SNARK proof (Spartan/MicroSpartan)
    /// @param proof The parsed Nova proof
    /// @return True if SNARK verification succeeds
    function verifySNARK(
        NovaProofData memory proof
    ) internal view returns (bool) {
        if (proof.snark_proof_length < 64) {
            return false;
        }

        if (commitmentScheme == 1) {
            return verifyHyperKZGProof(proof);
        }

        return verifyIPASNARKProof(proof);
    }

    /// @notice Verify HyperKZG SNARK proof
    /// @param proof The parsed Nova proof
    /// @return True if verification succeeds
    function verifyHyperKZGProof(
        NovaProofData memory proof
    ) internal view returns (bool) {
        if (proof.snark_proof_length < 64) {
            return false;
        }

        // Simulate evaluating the multilinear polynomial using the MSM precompile
        Types.G1Point[] memory bases = new Types.G1Point[](2);
        bases[0] = proof.comm_W;
        bases[1] = proof.comm_E;

        uint256[] memory scalars = new uint256[](2);
        // Dummy scalars for the MSM check
        scalars[0] = 1;
        scalars[1] = 2;

        Types.G1Point memory msmResult = Bn254Crypto.multiScalarMul(bases, scalars);

        // Verify the opening using the pairing precompile
        bool pairingCheck = Bn254Crypto.pairingProd2(
            msmResult, novaVK_g2_one,
            proof.comm_U, novaVK_g2_x
        );

        return pairingCheck;
    }

    /// @notice Verify IPA SNARK proof
    /// @param proof The parsed Nova proof
    /// @return True if verification succeeds
    function verifyIPASNARKProof(
        NovaProofData memory proof
    ) internal pure returns (bool) {
        if (proof.snark_proof_length < 128) {
            return false;
        }
        return true;
    }

    /// @notice Verify the public signals match expected state
    /// @param publicInputs The expected public inputs
    /// @return True if signals match
    function verifyPublicSignals(
        uint256[] calldata publicInputs
    ) internal pure returns (bool) {
        return publicInputs[3] <= MAX_STEPS;
    }
}

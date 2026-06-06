// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../contracts/proof_verification/nova_v1/NovaRollupVerifier.sol";
import "../contracts/proof_verification/lib/Types.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract NovaRollupVerifierTest is Test {
    NovaRollupVerifier verifier;

    // Deterministic attestor key used across the signed-path tests.
    uint256 constant ATTESTOR_PK = 0xA11CE;
    address attestorAddr;

    bytes32 constant COMMITMENTS_ROOT = bytes32(uint256(0x1111));
    bytes32 constant NULLIFIERS_ROOT = bytes32(uint256(0x2222));
    bytes32 constant HISTORIC_ROOT_ROOT = bytes32(uint256(0x3333));
    uint64 constant TX_COUNT = 20;

    function setUp() public {
        verifier = new NovaRollupVerifier();

        // Initialize with dummy reserved VK values. msg.sender (this
        // test contract) becomes the owner.
        Types.G2Point memory dummyG2;
        verifier.initialize(dummyG2, dummyG2, 1);

        attestorAddr = vm.addr(ATTESTOR_PK);
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    /// Build a bincode-shaped NovaProof blob with a 64-byte snark_proof.
    function _proofBlob() internal pure returns (bytes memory) {
        return abi.encodePacked(
            // snark_proof: len = 64, bytes = 64 zeros
            hex"4000000000000000",
            new bytes(64),
            // commitments_root: len = 32
            hex"2000000000000000",
            COMMITMENTS_ROOT,
            // nullifiers_root: len = 32
            hex"2000000000000000",
            NULLIFIERS_ROOT,
            // historic_root_root: len = 32
            hex"2000000000000000",
            HISTORIC_ROOT_ROOT,
            // transaction_count: 20 (u64 LE)
            hex"1400000000000000"
        );
    }

    function _publicInputs() internal pure returns (uint256[] memory pi) {
        pi = new uint256[](4);
        pi[0] = uint256(COMMITMENTS_ROOT);
        pi[1] = uint256(NULLIFIERS_ROOT);
        pi[2] = uint256(HISTORIC_ROOT_ROOT);
        pi[3] = uint256(TX_COUNT);
    }

    /// Sign the canonical attestation preimage with `pk` and return the
    /// 65-byte `(r || s || v)` signature.
    function _sign(uint256 pk, bytes memory snarkProof, uint256[] memory pi)
        internal
        view
        returns (bytes memory)
    {
        bytes32 preimage = verifier.attestationPreimage(
            snarkProof,
            COMMITMENTS_ROOT,
            NULLIFIERS_ROOT,
            HISTORIC_ROOT_ROOT,
            TX_COUNT,
            pi
        );
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(preimage);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    // ----------------------------------------------------------------
    // Fail-closed behaviour
    // ----------------------------------------------------------------

    /// With no attestor configured, even a structurally-valid proof is
    /// REJECTED. This is the core fix: structural checks alone are no
    /// longer sufficient.
    function test_failClosed_rejectsWhenNoAttestor() public view {
        bytes memory proof = _proofBlob();
        assertFalse(verifier.verifyProof(proof, _publicInputs()));
    }

    /// A structurally-valid proof WITHOUT an appended signature is
    /// rejected once an attestor is configured.
    function test_rejectsMissingSignature() public {
        verifier.setAttestor(attestorAddr);
        bytes memory proof = _proofBlob();
        assertFalse(verifier.verifyProof(proof, _publicInputs()));
    }

    // ----------------------------------------------------------------
    // Signed (accepted) path
    // ----------------------------------------------------------------

    /// A structurally-valid proof carrying a valid attestor signature
    /// is ACCEPTED.
    function test_acceptsValidlySignedProof() public {
        verifier.setAttestor(attestorAddr);
        uint256[] memory pi = _publicInputs();
        bytes memory sig = _sign(ATTESTOR_PK, new bytes(64), pi);
        bytes memory proof = abi.encodePacked(_proofBlob(), sig);
        assertTrue(verifier.verifyProof(proof, pi));
    }

    /// A signature from a key that is NOT the configured attestor is
    /// rejected.
    function test_rejectsWrongSigner() public {
        verifier.setAttestor(attestorAddr);
        uint256[] memory pi = _publicInputs();
        // Sign with a different key.
        bytes memory sig = _sign(0xB0B, new bytes(64), pi);
        bytes memory proof = abi.encodePacked(_proofBlob(), sig);
        assertFalse(verifier.verifyProof(proof, pi));
    }

    /// Tampering with the public inputs after signing breaks the
    /// signature binding (replay/substitution protection).
    function test_rejectsTamperedPublicInputs() public {
        verifier.setAttestor(attestorAddr);
        uint256[] memory pi = _publicInputs();
        bytes memory sig = _sign(ATTESTOR_PK, new bytes(64), pi);
        bytes memory proof = abi.encodePacked(_proofBlob(), sig);

        // Present different public inputs: the structural root check
        // diverges first, and the signature would not bind these either.
        uint256[] memory tampered = _publicInputs();
        tampered[0] = uint256(bytes32(uint256(0xDEAD)));
        assertFalse(verifier.verifyProof(proof, tampered));
    }

    /// A garbage 65-byte signature is rejected without reverting.
    function test_rejectsGarbageSignature() public {
        verifier.setAttestor(attestorAddr);
        uint256[] memory pi = _publicInputs();
        bytes memory sig = new bytes(65); // all zeros -> invalid
        bytes memory proof = abi.encodePacked(_proofBlob(), sig);
        assertFalse(verifier.verifyProof(proof, pi));
    }

    /// `snark_proof` shorter than 64 bytes is rejected even when signed.
    function test_rejectsShortSnarkProof() public {
        verifier.setAttestor(attestorAddr);

        // Build a blob with a 32-byte snark_proof.
        bytes memory shortBlob = abi.encodePacked(
            hex"2000000000000000",
            new bytes(32),
            hex"2000000000000000",
            COMMITMENTS_ROOT,
            hex"2000000000000000",
            NULLIFIERS_ROOT,
            hex"2000000000000000",
            HISTORIC_ROOT_ROOT,
            hex"1400000000000000"
        );
        uint256[] memory pi = _publicInputs();

        bytes32 preimage = verifier.attestationPreimage(
            new bytes(32),
            COMMITMENTS_ROOT,
            NULLIFIERS_ROOT,
            HISTORIC_ROOT_ROOT,
            TX_COUNT,
            pi
        );
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(preimage);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ATTESTOR_PK, digest);
        bytes memory proof = abi.encodePacked(shortBlob, abi.encodePacked(r, s, v));

        assertFalse(verifier.verifyProof(proof, pi));
    }

    // ----------------------------------------------------------------
    // Access control
    // ----------------------------------------------------------------

    function test_onlyOwnerCanSetAttestor() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert(NovaRollupVerifier.NotOwner.selector);
        verifier.setAttestor(attestorAddr);
    }

    function test_attestorCanBeRotatedAndCleared() public {
        verifier.setAttestor(attestorAddr);
        assertEq(verifier.attestor(), attestorAddr);

        // Clearing re-arms fail-closed.
        verifier.setAttestor(address(0));
        assertEq(verifier.attestor(), address(0));

        uint256[] memory pi = _publicInputs();
        bytes memory sig = _sign(ATTESTOR_PK, new bytes(64), pi);
        bytes memory proof = abi.encodePacked(_proofBlob(), sig);
        assertFalse(verifier.verifyProof(proof, pi));
    }
}

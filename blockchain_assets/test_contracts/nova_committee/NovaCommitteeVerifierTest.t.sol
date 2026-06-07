// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../../contracts/proof_verification/nova_v1/NovaCommitteeVerifier.sol";
import {NovaCommitteeVectors as V} from "./NovaCommitteeVectors.sol";

/// @notice Repo integration tests for the BLS12-381 t-of-N committee verifier.
/// Requires the Prague hardfork (EIP-2537); `foundry.toml` pins
/// `evm_version = "prague"`. Vectors are produced by the `blst` generator in
/// `temp/bls_parity_spike/rustgen`.
contract NovaCommitteeVerifierTest is Test {
    NovaCommitteeVerifier verifier;

    bytes32 constant COMMITMENTS_ROOT = bytes32(uint256(0x1111));
    bytes32 constant NULLIFIERS_ROOT = bytes32(uint256(0x2222));
    bytes32 constant HISTORIC_ROOT_ROOT = bytes32(uint256(0x3333));
    uint64 constant TX_COUNT = 20;

    function setUp() public {
        verifier = new NovaCommitteeVerifier(address(this));
    }

    function _register2of3() internal {
        verifier.addAttestor(V.PK0, V.POP0);
        verifier.addAttestor(V.PK1, V.POP1);
        verifier.addAttestor(V.PK2, V.POP2);
        verifier.setThreshold(2);
    }

    function _proofBlob() internal pure returns (bytes memory) {
        return abi.encodePacked(
            hex"4000000000000000", new bytes(64), // snark_proof: len 64
            hex"2000000000000000", COMMITMENTS_ROOT,
            hex"2000000000000000", NULLIFIERS_ROOT,
            hex"2000000000000000", HISTORIC_ROOT_ROOT,
            hex"1400000000000000" // transaction_count = 20 (u64 LE)
        );
    }

    function _publicInputs() internal pure returns (uint256[] memory pi) {
        pi = new uint256[](4);
        pi[0] = uint256(COMMITMENTS_ROOT);
        pi[1] = uint256(NULLIFIERS_ROOT);
        pi[2] = uint256(HISTORIC_ROOT_ROOT);
        pi[3] = uint256(TX_COUNT);
    }

    // ----------------------------------------------------------------
    // Committee core: verifyDigest over a fixed digest (static vectors)
    // ----------------------------------------------------------------

    function test_verifyDigest_accepts_2of3() public {
        _register2of3();
        assertEq(verifier.attestorCount(), 3);
        assertTrue(verifier.verifyDigest(V.DIGEST, V.SIGMA, V.BITMAP_01));
    }

    function test_verifyDigest_rejects_subThreshold() public {
        _register2of3();
        // Only attestor 0 (bitmap 0x01): count 1 < threshold 2.
        assertFalse(verifier.verifyDigest(V.DIGEST, V.SIGMA, 0x01));
    }

    function test_verifyDigest_rejects_lyingBitmap() public {
        _register2of3();
        // Claim all three signed (0x07) but sigma aggregates only {0,1}.
        assertFalse(verifier.verifyDigest(V.DIGEST, V.SIGMA, 0x07));
    }

    function test_verifyDigest_rejects_outOfRangeBitmap() public {
        _register2of3();
        // Bit 3 set but only 3 attestors registered.
        assertFalse(verifier.verifyDigest(V.DIGEST, V.SIGMA, 0x0B));
    }

    function test_verifyDigest_failClosed_withoutThreshold() public {
        verifier.addAttestor(V.PK0, V.POP0);
        // threshold still 0 => reject all.
        assertFalse(verifier.verifyDigest(V.DIGEST, V.SIGMA, 0x01));
    }

    // ----------------------------------------------------------------
    // Registration / proof-of-possession
    // ----------------------------------------------------------------

    function test_addAttestor_rejectsRogueKey() public {
        // PoP for attestor 0 presented for pubkey 1 must revert.
        vm.expectRevert(NovaCommitteeVerifier.BadPoP.selector);
        verifier.addAttestor(V.PK1, V.POP0);
    }

    function test_addAttestor_onlyOwner() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert(NovaCommitteeVerifier.NotOwner.selector);
        verifier.addAttestor(V.PK0, V.POP0);
    }

    // ----------------------------------------------------------------
    // IRollupVerifier.verifyProof wire path
    // ----------------------------------------------------------------

    function test_verifyProof_failClosed_noCommittee() public view {
        // No attestors / threshold 0 => reject even a structurally valid proof.
        bytes memory proof = abi.encodePacked(_proofBlob(), V.SIGMA, bytes32(uint256(0x03)));
        assertFalse(verifier.verifyProof(proof, _publicInputs()));
    }

    function test_verifyProof_rejectsShortSnarkProof() public {
        _register2of3();
        bytes memory shortBlob = abi.encodePacked(
            hex"2000000000000000", new bytes(32), // snark_proof: len 32 (< 64)
            hex"2000000000000000", COMMITMENTS_ROOT,
            hex"2000000000000000", NULLIFIERS_ROOT,
            hex"2000000000000000", HISTORIC_ROOT_ROOT,
            hex"1400000000000000"
        );
        bytes memory proof = abi.encodePacked(shortBlob, V.SIGMA, bytes32(uint256(0x03)));
        assertFalse(verifier.verifyProof(proof, _publicInputs()));
    }

    function test_verifyProof_rejectsTamperedPublicInputs() public {
        _register2of3();
        bytes memory proof = abi.encodePacked(_proofBlob(), V.SIGMA, bytes32(uint256(0x03)));
        uint256[] memory tampered = _publicInputs();
        tampered[0] = uint256(bytes32(uint256(0xDEAD)));
        assertFalse(verifier.verifyProof(proof, tampered));
    }

    /// Routing + never-revert: the digest verifyProof computes binds
    /// `address(this)`/`chainid`, so a signature over a different message is
    /// cleanly rejected (returns false, no revert) rather than accepted.
    function test_verifyProof_rejectsSignatureOverWrongMessage() public {
        _register2of3();
        bytes memory proof = abi.encodePacked(_proofBlob(), V.SIGMA, bytes32(uint256(0x03)));
        assertFalse(verifier.verifyProof(proof, _publicInputs()));
    }

    /// Truncated signature region => reject, never revert.
    function test_verifyProof_rejectsTruncatedSignature() public {
        _register2of3();
        bytes memory proof = abi.encodePacked(_proofBlob(), V.SIGMA); // missing 32-byte bitmap
        assertFalse(verifier.verifyProof(proof, _publicInputs()));
    }

    /// The digest `verifyProof` signs/verifies is the canonical attestation
    /// preimage (domain || chainid || verifier || proof || roots || count || pi)
    /// — byte-identical to off-chain `attestation::attestation_preimage`. Proven
    /// here so that, together with {test_verifyDigest_accepts_2of3}, a valid
    /// committee signature over a well-formed proof verifies end-to-end.
    function test_verifyProof_digestIsCanonicalPreimage() public {
        _register2of3();
        uint256[] memory pi = _publicInputs();
        bytes memory snarkProof = new bytes(64);
        bytes32 fromContract = verifier.attestationPreimage(
            snarkProof, COMMITMENTS_ROOT, NULLIFIERS_ROOT, HISTORIC_ROOT_ROOT, TX_COUNT, pi
        );
        bytes32 expected = keccak256(
            abi.encodePacked(
                "NF4_NOVA_ATTEST_V1",
                block.chainid,
                address(verifier),
                snarkProof,
                COMMITMENTS_ROOT,
                NULLIFIERS_ROOT,
                HISTORIC_ROOT_ROOT,
                TX_COUNT,
                pi[0],
                pi[1],
                pi[2],
                pi[3]
            )
        );
        assertEq(fromContract, expected, "non-canonical attestation preimage");
    }

    /// End-to-end accept: a real 2-of-3 BLS aggregate (produced by the `blst`
    /// generator over the runtime canonical digest) is accepted through the full
    /// `verifyProof` wire path. Opt-in (needs the generator binary built — see
    /// `temp/bls_parity_spike/README.md`): run with `RUN_BLS_FFI=1 forge test`.
    function test_e2e_verifyProof_acceptsRealAggregate() public {
        if (!vm.envOr("RUN_BLS_FFI", false)) return;
        _register2of3();
        uint256[] memory pi = _publicInputs();
        bytes memory snarkProof = new bytes(64);
        bytes32 digest = verifier.attestationPreimage(
            snarkProof, COMMITMENTS_ROOT, NULLIFIERS_ROOT, HISTORIC_ROOT_ROOT, TX_COUNT, pi
        );
        string[] memory cmd = new string[](3);
        cmd[0] = "temp/bls_parity_spike/rustgen/target/release/blsgen";
        cmd[1] = "sign";
        cmd[2] = vm.toString(digest);
        bytes memory sigma = vm.ffi(cmd);
        bytes memory proof = abi.encodePacked(_proofBlob(), sigma, bytes32(uint256(0x03)));
        assertTrue(verifier.verifyProof(proof, pi), "valid committee aggregate rejected");
    }
}

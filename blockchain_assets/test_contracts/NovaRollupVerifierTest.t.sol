// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../contracts/proof_verification/nova_v1/NovaRollupVerifier.sol";
import "../contracts/proof_verification/lib/Types.sol";

contract NovaRollupVerifierTest is Test {
    NovaRollupVerifier verifier;

    function setUp() public {
        verifier = new NovaRollupVerifier();
        
        // Initialize with dummy values
        Types.G2Point memory dummyG2;
        verifier.initialize(dummyG2, dummyG2, 1);
    }

    function test_parse_and_verify_valid_proof() public {
        // Construct valid bincode proof serialization bytes:
        // 1. snark_proof: Vec<u8> of length 64
        //    Length prefix: uint64 LE 64 -> 0x4000000000000000
        //    Bytes: 64 bytes of zeros (or values)
        // 2. commitments_root: Vec<u8> of length 32
        //    Length prefix: uint64 LE 32 -> 0x2000000000000000
        //    Bytes: 32 bytes commitments root
        // 3. nullifiers_root: Vec<u8> of length 32
        //    Length prefix: uint64 LE 32 -> 0x2000000000000000
        //    Bytes: 32 bytes nullifiers root
        // 4. historic_root_root: Vec<u8> of length 32
        //    Length prefix: uint64 LE 32 -> 0x2000000000000000
        //    Bytes: 32 bytes historic root root
        // 5. transaction_count: uint64 LE 20 -> 0x1400000000000000

        bytes32 commitmentsRoot = bytes32(uint256(0x1111));
        bytes32 nullifiersRoot = bytes32(uint256(0x2222));
        bytes32 historicRootRoot = bytes32(uint256(0x3333));
        uint64 transactionCount = 20;

        bytes memory proofBytes = abi.encodePacked(
            // snark_proof: len = 64, bytes = 64 zeros
            hex"4000000000000000",
            new bytes(64),
            // commitments_root: len = 32, bytes = commitmentsRoot
            hex"2000000000000000",
            commitmentsRoot,
            // nullifiers_root: len = 32, bytes = nullifiersRoot
            hex"2000000000000000",
            nullifiersRoot,
            // historic_root_root: len = 32, bytes = historicRootRoot
            hex"2000000000000000",
            historicRootRoot,
            // transaction_count: 20
            hex"1400000000000000"
        );

        uint256[] memory publicInputs = new uint256[](4);
        publicInputs[0] = uint256(commitmentsRoot);
        publicInputs[1] = uint256(nullifiersRoot);
        publicInputs[2] = uint256(historicRootRoot);
        publicInputs[3] = uint256(transactionCount);

        assertTrue(verifier.verifyProof(proofBytes, publicInputs));
    }
}

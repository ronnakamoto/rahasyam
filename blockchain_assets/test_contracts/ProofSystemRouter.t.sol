// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../contracts/proof_verification/ProofSystemRouter.sol";
import "../contracts/proof_verification/IRollupVerifier.sol";

contract DummyVerifier is IRollupVerifier {
    bool public shouldPass;
    constructor(bool _shouldPass) {
        shouldPass = _shouldPass;
    }
    function verifyProof(bytes calldata proof, uint256[] calldata publicInputs) external view override returns (bool) {
        return shouldPass;
    }
}

contract ProofSystemRouterTest is Test {
    ProofSystemRouter router;
    DummyVerifier verifierPass;
    DummyVerifier verifierFail;

    function setUp() public {
        router = new ProofSystemRouter(address(this));
        verifierPass = new DummyVerifier(true);
        verifierFail = new DummyVerifier(false);
    }

    function testRegister() public {
        router.register(1, verifierPass);
        assertEq(address(router.getVerifier(1)), address(verifierPass));
    }

    function testVerifyPass() public {
        router.register(1, verifierPass);
        bytes memory blob = abi.encodePacked(uint8(1), "some_proof_bytes");
        uint256[] memory pi = new uint256[](0);
        assertTrue(router.verify(blob, pi));
    }

    function testVerifyFail() public {
        router.register(1, verifierFail);
        bytes memory blob = abi.encodePacked(uint8(1), "some_proof_bytes");
        uint256[] memory pi = new uint256[](0);
        assertFalse(router.verify(blob, pi));
    }

    function testVerifyUnknownSystem() public {
        bytes memory blob = abi.encodePacked(uint8(2), "some_proof_bytes");
        uint256[] memory pi = new uint256[](0);
        vm.expectRevert(abi.encodeWithSelector(ProofSystemRouter.UnknownProofSystem.selector, 2));
        router.verify(blob, pi);
    }

    function testVerifyDisabledSystem() public {
        router.register(1, verifierPass);
        router.disable(1);
        bytes memory blob = abi.encodePacked(uint8(1), "some_proof_bytes");
        uint256[] memory pi = new uint256[](0);
        vm.expectRevert(abi.encodeWithSelector(ProofSystemRouter.ProofSystemDisabled.selector, 1));
        router.verify(blob, pi);
    }

    function testDisableAndEnable() public {
        router.register(1, verifierPass);
        router.disable(1);
        assertTrue(router.disabled(1));
        router.enable(1);
        assertFalse(router.disabled(1));
    }
}
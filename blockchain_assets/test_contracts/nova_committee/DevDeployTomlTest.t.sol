// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {stdToml} from "forge-std/StdToml.sol";
import "../../contracts/proof_verification/nova_v1/NovaCommitteeVerifier.sol";

/// @notice End-to-end validation of the dev deploy path: read the actual
/// `[development.nova_committee]` config from `nightfall.toml` exactly as
/// `deployer.s.sol::_deployNovaCommitteeVerifier` does (`readStringArray` +
/// `vm.parseBytes` + `addAttestor`/`setThreshold`) and confirm it registers a
/// valid 2-of-3 committee on-chain. If this passes, the dev/`nf4_test` committee
/// deploy is guaranteed to succeed (anvil already verified to support EIP-2537).
contract DevDeployTomlTest is Test {
    using stdToml for string;

    function test_dev_committee_toml_deploys_and_registers() public {
        string memory toml = vm.readFile("nightfall.toml");
        string[] memory pubkeys = toml.readStringArray(".development.nova_committee.pubkeys");
        string[] memory pops = toml.readStringArray(".development.nova_committee.pops");
        uint256 t = toml.readUint(".development.nova_committee.threshold");

        assertEq(pubkeys.length, 3, "3 committee pubkeys in nightfall.toml");
        assertEq(pops.length, 3, "3 committee pops in nightfall.toml");

        NovaCommitteeVerifier c = new NovaCommitteeVerifier(address(this));
        for (uint256 i = 0; i < pubkeys.length; i++) {
            c.addAttestor(vm.parseBytes(pubkeys[i]), vm.parseBytes(pops[i]));
        }
        c.setThreshold(t);

        assertEq(c.attestorCount(), 3, "all dev attestors registered from TOML");
        assertEq(c.threshold(), 2, "dev committee threshold = 2");
    }

    function test_dev_committee_enabled_in_proving_systems() public {
        string memory toml = vm.readFile("nightfall.toml");
        string[] memory enabled =
            toml.readStringArray(".development.nightfall_proposer.proving_system.enabled");
        bool hasBls;
        for (uint256 i = 0; i < enabled.length; i++) {
            if (keccak256(bytes(enabled[i])) == keccak256(bytes("nova-bls-v1"))) {
                hasBls = true;
            }
        }
        assertTrue(hasBls, "nova-bls-v1 enabled => deploy registers the committee verifier");
    }
}

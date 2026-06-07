// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../../contracts/proof_verification/nova_v1/NovaCommitteeVerifier.sol";
import {DevCommitteeVectors as D} from "./DevCommitteeVectors.sol";

/// @notice Validates that the committed dev committee keyset
/// (`nightfall.toml [development.nova_committee]`) registers on-chain exactly as
/// the deploy script's `addAttestor(pubkey, pop)` + `setThreshold` calls do — so
/// a dev/`nf4_test` committee deploy is guaranteed to succeed. Requires Prague
/// (verified supported by the dev `foundry:v1.1.0` anvil image).
contract DevCommitteeKeysetTest is Test {
    function test_dev_keyset_registers_2of3() public {
        NovaCommitteeVerifier c = new NovaCommitteeVerifier(address(this));
        // Same calls (and order) the deploy script makes.
        c.addAttestor(D.PK0, D.POP0);
        c.addAttestor(D.PK1, D.POP1);
        c.addAttestor(D.PK2, D.POP2);
        c.setThreshold(2);
        assertEq(c.attestorCount(), 3, "all 3 dev attestors registered");
    }

    function test_dev_keyset_rejects_swapped_pop() public {
        NovaCommitteeVerifier c = new NovaCommitteeVerifier(address(this));
        // A mismatched PoP must be rejected (rogue-key defence).
        vm.expectRevert(NovaCommitteeVerifier.BadPoP.selector);
        c.addAttestor(D.PK0, D.POP1);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { Test } from "forge-std/Test.sol";
import { console2 } from "forge-std/console2.sol";
import { SelfDestructTarget } from "../src/SelfDestructTarget.sol";

/// @notice Tests whether FPValidator's extcodesize-based "is this a real
/// contract" check is a stable guarantee, or just a snapshot that can go
/// stale - reproducing the EXACT real logic verbatim (confirmed correct
/// offset from the prior test), targeting a REAL contract we can
/// actually self-destruct mid-test to observe the real before/after.
contract RealFPValidatorExtcodesizeSnapshot is Test {
    function test_INJECTION_ExtcodesizeSnapshotGoesStale() public {
        SelfDestructTarget target = new SelfDestructTarget();
        address targetAddr = address(target);

        uint256 sizeBefore;
        assembly { sizeBefore := extcodesize(targetAddr) }
        console2.log("extcodesize BEFORE selfdestruct:", sizeBefore);

        bool wouldBeSecuredBefore = (sizeBefore == 0);
        console2.log("Real FPValidator logic BEFORE: would this get 'secured' (payload wiped)?", wouldBeSecuredBefore);

        // Trigger selfdestruct - real, actual contract destruction.
        target.die();

        uint256 sizeAfter;
        assembly { sizeAfter := extcodesize(targetAddr) }
        console2.log("extcodesize AFTER selfdestruct:", sizeAfter);

        bool wouldBeSecuredAfter = (sizeAfter == 0);
        console2.log("Real FPValidator logic AFTER: would this get 'secured' (payload wiped)?", wouldBeSecuredAfter);

        console2.log("=== GROUND TRUTH ===");
        if (!wouldBeSecuredBefore && wouldBeSecuredAfter) {
            console2.log("!!!!! CONFIRMED: extcodesize check result CHANGES within the same test lifecycle !!!!!");
            console2.log("!!!!! A single validateProof call gets ONE snapshot - if delivery ever happens");
            console2.log("!!!!! in a call where the target's code state differs from validation time, the");
            console2.log("!!!!! safety substitution logic is checking a DIFFERENT reality than delivery time. !!!!!");
        } else {
            console2.log("No observable state change in this scenario.");
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { Test } from "forge-std/Test.sol";
import { console2 } from "forge-std/console2.sol";
import { MessagingContextHarness } from "../src/MessagingContextHarness.sol";

contract RealMessagingContextStuckTest is Test {
    MessagingContextHarness harness;

    function setUp() public {
        harness = new MessagingContextHarness();
    }

    function test_REAL_RevertingCall_LeavesContextStuckOrNot() public {
        console2.log("isSendingMessage BEFORE any call:", harness.isSendingMessage());
        assertFalse(harness.isSendingMessage(), "sanity: must start false");

        vm.expectRevert("deliberate revert inside guarded call");
        harness.guardedRevert(2, address(0xDEAD));

        bool stuckAfterRevert = harness.isSendingMessage();
        console2.log("isSendingMessage AFTER the reverting call:", stuckAfterRevert);

        if (stuckAfterRevert) {
            console2.log("!!!!! CONFIRMED: a reverting call LEAVES the context permanently stuck !!!!!");
        } else {
            console2.log("CONFIRMED: the context correctly reset despite the revert.");
        }

        assertFalse(stuckAfterRevert, "REAL TEST: context must NOT be stuck after a reverting guarded call");

        // Now confirm a SUCCESSFUL call also resets correctly, as a control.
        harness.guardedSuccess(2, address(0xBEEF));
        console2.log("isSendingMessage AFTER a successful call:", harness.isSendingMessage());
        assertFalse(harness.isSendingMessage(), "context must reset after successful call too");
    }
}

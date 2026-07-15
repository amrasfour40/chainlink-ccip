// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MyComposingOApp } from "../src/MyComposingOApp.sol";
import { ComposeOnlyHandler, ITestHelper } from "../src/ComposeOnlyHandler.sol";
import { console2 } from "forge-std/console2.sol";

contract RealComposeOnlyIsolatedInvariant is TestHelperOz5 {
    MyComposingOApp composeA;
    MyComposingOApp composeB;
    ComposeOnlyHandler handler;
    uint32 aEid = 1;
    uint32 bEid = 2;
    address OWNER = address(0x1111);

    function setUp() public override {
        super.setUp();
        setUpEndpoints(2, LibraryType.UltraLightNode);
        vm.deal(OWNER, 1000 ether);

        composeA = new MyComposingOApp(address(endpoints[aEid]), OWNER);
        composeB = new MyComposingOApp(address(endpoints[bEid]), OWNER);
        vm.prank(OWNER); composeA.setPeer(bEid, bytes32(uint256(uint160(address(composeB)))));
        vm.prank(OWNER); composeB.setPeer(aEid, bytes32(uint256(uint160(address(composeA)))));

        handler = new ComposeOnlyHandler(composeA, composeB, ITestHelper(address(this)), bEid, OWNER);
        targetContract(address(handler));
    }

    function invariant_ComposeExecutionsNeverExceedSends() public view {
        assertLe(composeB.composedCount(), handler.sendSuccesses(), "COMPOSE INVARIANT BROKEN: more executions than sends");
    }

    function invariant_Summary() public view {
        console2.log("=== ISOLATED COMPOSE SUMMARY ===");
        console2.log("Send attempts:", handler.sendAttempts(), " successes:", handler.sendSuccesses());
        console2.log("Deliver attempts:", handler.deliverAttempts(), " successes:", handler.deliverSuccesses());
        console2.log("Compose execute attempts:", handler.composeExecuteAttempts(), " successes:", handler.composeExecuteSuccesses());
        console2.log("Real composedCount on-chain:", composeB.composedCount());
    }
}

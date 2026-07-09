// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MyOrderedOApp } from "../src/MyOrderedOApp.sol";
import { OptionsBuilder } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";

contract RealOrderingTest is TestHelperOz5 {
    using OptionsBuilder for bytes;

    MyOrderedOApp aApp;
    MyOrderedOApp bApp;
    uint32 aEid = 1;
    uint32 bEid = 2;
    address OWNER = address(0x1111);

    function setUp() public override {
        super.setUp();
        setUpEndpoints(2, LibraryType.UltraLightNode);
        vm.deal(OWNER, 100 ether);

        aApp = new MyOrderedOApp(address(endpoints[aEid]), OWNER);
        bApp = new MyOrderedOApp(address(endpoints[bEid]), OWNER);

        vm.prank(OWNER);
        aApp.setPeer(bEid, bytes32(uint256(uint160(address(bApp)))));
        vm.prank(OWNER);
        bApp.setPeer(aEid, bytes32(uint256(uint160(address(aApp)))));
    }

    function test_ASSERT_ExplicitOrderedEnforcement_HOLDS_DIRECT() public {
        // Contrast with Code 2 (default unordered - both messages delivered
        // fine). Here the OApp explicitly enforces strict nonce sequencing
        // via receivedNonce tracking. Sending and verifying two messages
        // should still allow delivery of BOTH in order - real test is
        // whether the SAME executor-style unordered delivery attempt from
        // verifyPackets respects this, or whether the OApp's own check
        // catches any mismatch. Ground truth: receivedCount after both
        // attempts, and lastMessage reflecting the correct final state.
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);

        vm.prank(OWNER);
        aApp.sendString{value: 1 ether}(bEid, "ordered first", options);
        vm.prank(OWNER);
        aApp.sendString{value: 1 ether}(bEid, "ordered second", options);

        verifyPackets(bEid, address(bApp));

        assertEq(bApp.receivedCount(), 2, "both messages delivered in correct order");
        assertEq(bApp.lastMessage(), "ordered second", "final message should be the second one, delivered in order");
    }
}

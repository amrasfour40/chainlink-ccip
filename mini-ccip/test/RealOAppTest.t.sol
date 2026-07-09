// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MyRealOApp } from "../src/MyRealOApp.sol";
import { OptionsBuilder } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";

contract RealOAppTest is TestHelperOz5 {
    using OptionsBuilder for bytes;

    MyRealOApp aApp;
    MyRealOApp bApp;
    uint32 aEid = 1;
    uint32 bEid = 2;

    address OWNER = address(0x1111);
    address ATTACKER = address(0xDEAD);

    function setUp() public override {
        super.setUp();
        setUpEndpoints(2, LibraryType.UltraLightNode);

        vm.deal(OWNER, 100 ether);

        aApp = new MyRealOApp(address(endpoints[aEid]), OWNER);
        bApp = new MyRealOApp(address(endpoints[bEid]), OWNER);

        vm.prank(OWNER);
        aApp.setPeer(bEid, bytes32(uint256(uint160(address(bApp)))));
        vm.prank(OWNER);
        bApp.setPeer(aEid, bytes32(uint256(uint160(address(aApp)))));
    }

    function test_HonestDeliverySucceeds() public {
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);

        vm.prank(OWNER);
        aApp.sendString{value: 1 ether}(bEid, "hello real layerzero", options);

        verifyPackets(bEid, address(bApp));

        assertEq(bApp.lastMessage(), "hello real layerzero", "honest delivery must actually deliver the real message");
        assertEq(bApp.receivedCount(), 1, "honest delivery must increment exactly once");
    }

    function test_ASSERT_RealPeerValidation_HOLDS_DIRECT() public {
        // fakeSender CAN send (it has ITS OWN peer set on the send side),
        // but bApp was NEVER told to trust fakeSender as its peer for
        // aEid. Ground truth check instead of expectRevert (which fired
        // on the wrong internal call frame last attempt): did the
        // spoofed message actually get delivered, or not?
        MyRealOApp fakeSender = new MyRealOApp(address(endpoints[aEid]), OWNER);
        vm.prank(OWNER);
        fakeSender.setPeer(bEid, bytes32(uint256(uint160(address(bApp)))));

        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);

        vm.prank(OWNER);
        fakeSender.sendString{value: 1 ether}(bEid, "spoofed message", options);

        uint256 receivedBefore = bApp.receivedCount();

        // Call verifyPackets in a try/catch - if the real OnlyPeer check
        // fires anywhere in the delivery chain, this whole call reverts.
        // Either way, we check GROUND TRUTH state afterward, not whether
        // a specific call frame reverted.
        try this.verifyPackets(bEid, address(bApp)) {
            // did not revert at the top level - but did it ACTUALLY deliver?
        } catch {
            // reverted somewhere in the chain - expected, real OnlyPeer check
        }

        assertEq(bApp.receivedCount(), receivedBefore, "SPOOFED MESSAGE WAS DELIVERED: bApp accepted a message from a sender it never configured as its peer");
        assertEq(bApp.lastMessage(), "", "SPOOFED MESSAGE CONTENT WAS ACCEPTED: bApp.lastMessage should remain empty");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MyOrderedOApp } from "../src/MyOrderedOApp.sol";
import { OptionsBuilder } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";
import { console2 } from "forge-std/console2.sol";

/// @notice Deterministic reproduction attempt: send N messages, deliver
/// them ALL via repeated verifyPackets calls, count exactly how many
/// actually land vs how many were sent - matching the exact 24-sent
/// pattern observed, to see if a real, reproducible off-by-one exists
/// or if it was a one-off artifact of shared fuzzing state.
contract RealOrderedGapInvestigation is TestHelperOz5 {
    using OptionsBuilder for bytes;

    MyOrderedOApp orderedA;
    MyOrderedOApp orderedB;
    uint32 aEid = 1;
    uint32 bEid = 2;
    address OWNER = address(0x1111);

    function setUp() public override {
        super.setUp();
        setUpEndpoints(2, LibraryType.UltraLightNode);
        vm.deal(OWNER, 100 ether);

        orderedA = new MyOrderedOApp(address(endpoints[aEid]), OWNER);
        orderedB = new MyOrderedOApp(address(endpoints[bEid]), OWNER);
        vm.prank(OWNER); orderedA.setPeer(bEid, bytes32(uint256(uint160(address(orderedB)))));
        vm.prank(OWNER); orderedB.setPeer(aEid, bytes32(uint256(uint160(address(orderedA)))));
    }

    function test_INVESTIGATE_24SentDeliverAllRepeatedly() public {
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);

        for (uint256 i = 0; i < 24; i++) {
            vm.prank(OWNER);
            orderedA.sendString{value: 1 ether}(bEid, "msg", options);
        }

        console2.log("Sent 24 real messages. Attempting delivery via REPEATED verifyPackets calls...");

        for (uint256 attempt = 0; attempt < 30; attempt++) {
            try this.verifyPackets(bEid, address(orderedB)) {
                console2.log("Attempt", attempt, "- receivedCount now:", orderedB.receivedCount());
            } catch {
                console2.log("Attempt", attempt, "- verifyPackets REVERTED");
            }
            if (orderedB.receivedCount() == 24) {
                console2.log("All 24 delivered after", attempt + 1, "verifyPackets calls.");
                break;
            }
        }

        console2.log("=== FINAL ===");
        console2.log("Sent: 24  Delivered:", orderedB.receivedCount());
        if (orderedB.receivedCount() < 24) {
            console2.log("!!!!! REAL GAP CONFIRMED: some messages are permanently undeliverable via repeated verifyPackets alone !!!!!");
        } else {
            console2.log("All 24 eventually delivered - the earlier gap was likely a mid-campaign snapshot artifact, not a permanent loss.");
        }
    }
}

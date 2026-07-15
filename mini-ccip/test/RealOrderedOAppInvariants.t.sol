// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MyOrderedOApp } from "../src/MyOrderedOApp.sol";
import { OrderedOAppHandler } from "../src/OrderedOAppHandler.sol";
import { console2 } from "forge-std/console2.sol";
import { ITestDeliver } from "../src/OrderedOAppHandler.sol";
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";

contract RealOrderedOAppInvariants is TestHelperOz5 {
    MyOrderedOApp aApp;
    MyOrderedOApp bApp;
    OrderedOAppHandler handler;
    uint32 aEid = 1;
    uint32 bEid = 2;
    address OWNER = address(0x1111);

    function setUp() public override {
        super.setUp();
        setUpEndpoints(2, LibraryType.UltraLightNode);
        vm.deal(OWNER, 1000 ether);

        aApp = new MyOrderedOApp(address(endpoints[aEid]), OWNER);
        bApp = new MyOrderedOApp(address(endpoints[bEid]), OWNER);

        vm.prank(OWNER);
        aApp.setPeer(bEid, bytes32(uint256(uint160(address(bApp)))));
        vm.prank(OWNER);
        bApp.setPeer(aEid, bytes32(uint256(uint160(address(aApp)))));

        handler = new OrderedOAppHandler(aApp, bApp, ITestDeliver(address(this)), address(endpoints[bEid]), aEid, bEid, OWNER);
        targetContract(address(handler));
    }

    /// INVARIANT 1: real delivered count can never exceed real successful
    /// sends. If this breaks, messages are being delivered from nothing.
    function invariant_NeverMoreReceivedThanSent() public view {
        assertLe(bApp.receivedCount(), handler.totalSendSuccesses(), "INVARIANT BROKEN: more real deliveries than real sends");
    }

    /// INVARIANT 2: content integrity. Whatever bApp's lastMessage
    /// currently holds, if ANY delivery has ever happened, that exact
    /// content must have genuinely been sent by the handler at some point.
    /// If this breaks, delivered content was fabricated/corrupted.
    function invariant_DeliveredContentWasGenuinelySent() public view {
        if (bApp.receivedCount() > 0) {
            bytes32 currentMsgHash = keccak256(bytes(bApp.lastMessage()));
            assertTrue(handler.wasEverSent(currentMsgHash), "INVARIANT BROKEN: delivered content does not match anything ever actually sent");
        }
    }

    function invariant_CallSummary() public view {
        console2.log("--- REAL fuzz run summary ---");
        console2.log("Send attempts:", handler.totalSendAttempts(), "  successes:", handler.totalSendSuccesses());
        console2.log("Delivery attempts:", handler.totalDeliveryAttempts(), "  successes:", handler.totalDeliverySuccesses());
        console2.log("Skip attempts:", handler.totalSkipAttempts(), "  successes:", handler.totalSkipSuccesses());
        console2.log("bApp receivedCount (real, on-chain):", bApp.receivedCount());

        bytes32 senderKey = bytes32(uint256(uint160(address(aApp))));
        uint64 lazyNonce = ILayerZeroEndpointV2(address(endpoints[bEid])).lazyInboundNonce(address(bApp), aEid, senderKey);
        uint64 realInboundNonce = ILayerZeroEndpointV2(address(endpoints[bEid])).inboundNonce(address(bApp), aEid, senderKey);
        console2.log("Final lazyInboundNonce (real protocol state):", lazyNonce);
        console2.log("Final inboundNonce (real protocol state):", realInboundNonce);
        console2.log("DIAGNOSIS: if lazyInboundNonce > 1 but receivedCount == 1, skip() orphaned the rest.");
    }
}

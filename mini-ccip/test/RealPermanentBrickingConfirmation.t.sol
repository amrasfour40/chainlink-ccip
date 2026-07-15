// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MyOrderedOApp } from "../src/MyOrderedOApp.sol";
import { OptionsBuilder } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { console2 } from "forge-std/console2.sol";

contract RealPermanentBrickingConfirmation is TestHelperOz5 {
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

    function test_CONFIRM_OneEarlySkipPermanentlyBricksOrderedOApp() public {
        bytes32 senderKey = bytes32(uint256(uint160(address(aApp))));
        ILayerZeroEndpointV2 bEndpoint = ILayerZeroEndpointV2(address(endpoints[bEid]));
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);

        // Step 1: skip nonce 1 on a completely fresh pathway - matches
        // our earlier-confirmed orphaning finding exactly.
        console2.log("Skipping nonce 1 on a fresh pathway (before any message exists)...");
        vm.prank(OWNER);
        bEndpoint.skip(address(bApp), aEid, senderKey, 1);

        // Step 2: send THREE separate, genuine, honest messages (nonces 2,3,4).
        vm.prank(OWNER);
        aApp.sendString{value: 1 ether}(bEid, "message A - nonce 2", options);
        vm.prank(OWNER);
        aApp.sendString{value: 1 ether}(bEid, "message B - nonce 3", options);
        vm.prank(OWNER);
        aApp.sendString{value: 1 ether}(bEid, "message C - nonce 4", options);

        console2.log("Sent 3 genuine, honest messages after the skip. Attempting delivery of ALL...");

        try this.verifyPackets(bEid, address(bApp)) {
            console2.log("verifyPackets did not revert at top level.");
        } catch {
            console2.log("verifyPackets reverted.");
        }

        console2.log("=== GROUND TRUTH ===");
        console2.log("bApp.receivedCount() (should be 0 if PERMANENTLY bricked, not just missing nonce 1):", bApp.receivedCount());
        console2.log("bApp.lastMessage():", bApp.lastMessage());

        if (bApp.receivedCount() == 0) {
            console2.log("!!!!! CONFIRMED: ALL 3 subsequent genuine messages were ALSO rejected !!!!!");
            console2.log("!!!!! One early skip() PERMANENTLY BRICKED the entire pathway, not just nonce 1 !!!!!");
            console2.log("!!!!! There is no recovery mechanism - MyOrderedOApp's internal counter can NEVER resync !!!!!");
        } else if (bApp.receivedCount() < 3) {
            console2.log("Partial delivery - some but not all messages got through. Investigate further.");
        } else {
            console2.log("All messages delivered despite the early skip - bricking hypothesis does NOT hold.");
        }
    }
}

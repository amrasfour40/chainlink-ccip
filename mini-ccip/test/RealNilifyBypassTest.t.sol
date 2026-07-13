// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MyRealOApp } from "../src/MyRealOApp.sol";
import { OptionsBuilder } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { console2 } from "forge-std/console2.sol";

interface INilify {
    function nilify(address _oapp, uint32 _srcEid, bytes32 _sender, uint64 _nonce, bytes32 _payloadHash) external;
}

contract RealNilifyBypassTest is TestHelperOz5 {
    using OptionsBuilder for bytes;

    MyRealOApp aApp;
    MyRealOApp bApp;
    uint32 aEid = 1;
    uint32 bEid = 2;
    address OWNER = address(0x1111);

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

    function test_ATTACK_NilifyThenRealCommitOverwrites() public {
        bytes32 senderKey = bytes32(uint256(uint160(address(aApp))));
        ILayerZeroEndpointV2 bEndpoint = ILayerZeroEndpointV2(address(endpoints[bEid]));

        console2.log("Step 1: OWNER nilifies future nonce=1, BEFORE any message exists...");
        vm.prank(OWNER);
        try INilify(address(bEndpoint)).nilify(address(bApp), aEid, senderKey, 1, bytes32(0)) {
            console2.log("nilify() SUCCEEDED on a future, never-verified nonce.");
        } catch Error(string memory reason) {
            console2.log("nilify() REVERTED with reason:", reason);
        } catch (bytes memory data) {
            console2.log("nilify() REVERTED, data length:", data.length);
        }

        console2.log("Step 2: now attempt a REAL, honest cross-chain message for that SAME nonce=1...");
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);

        vm.prank(OWNER);
        aApp.sendString{value: 1 ether}(bEid, "does this bypass the nilify?", options);

        uint256 receivedBefore = bApp.receivedCount();
        try this.verifyPackets(bEid, address(bApp)) {
            console2.log("verifyPackets did NOT revert.");
        } catch {
            console2.log("verifyPackets REVERTED - nilify protection held.");
        }

        console2.log("=== GROUND TRUTH ===");
        console2.log("receivedCount before:", receivedBefore);
        console2.log("receivedCount after: ", bApp.receivedCount());
        console2.log("lastMessage:          ", bApp.lastMessage());

        if (bApp.receivedCount() > receivedBefore) {
            console2.log("!!!!! CONFIRMED: real commit/delivery OVERWROTE the nilified slot and delivered anyway !!!!!");
        } else {
            console2.log("Delivery did NOT happen - nilify() protection held against a real, honest message too.");
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MyOrderedOApp } from "../src/MyOrderedOApp.sol";
import { OptionsBuilder } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { console2 } from "forge-std/console2.sol";

contract RealNonceSkipTest is TestHelperOz5 {
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

    function test_ASSERT_SkipDesyncsLocalNonceTracking_HOLDS_DIRECT() public {
        // Real documented risk: EndpointV2.skip() advances the PROTOCOL's
        // nonce floor without ever calling lzReceive. An OApp that tracks
        // its OWN nonce counter (like MyOrderedOApp) never finds out about
        // this - its local counter stays at 0. Testing directly: does this
        // desync cause a legitimate LATER message to be permanently
        // rejected by the OApp's own logic, even though the protocol
        // itself delivered it correctly?
        bytes32 senderKey = bytes32(uint256(uint160(address(aApp))));
        ILayerZeroEndpointV2 bEndpoint = ILayerZeroEndpointV2(address(endpoints[bEid]));

        // Skip nonce 1 on a completely fresh pathway - nothing sent yet,
        // so inboundNonce is 0, and 1 is the expected next value.
        vm.prank(OWNER);
        bEndpoint.skip(address(bApp), aEid, senderKey, 1);
        console2.log("Protocol floor after skip: nonce 1 marked handled, bApp.receivedCount still:", bApp.receivedCount());

        // Now send a REAL message. Because aApp has never sent before,
        // ITS outbound nonce also starts at 1 - but that nonce was already
        // consumed by skip() on the protocol side, so this message will
        // actually be assigned nonce 1 by the SEND side... real question:
        // does the endpoint even allow this, or does the mismatch matter?
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);
        vm.prank(OWNER);
        aApp.sendString{value: 1 ether}(bEid, "message after skip", options);

        uint256 receivedBefore = bApp.receivedCount();
        try this.verifyPackets(bEid, address(bApp)) {
            console2.log("verifyPackets did not revert");
        } catch Error(string memory reason) {
            console2.log("verifyPackets reverted with reason:", reason);
        } catch {
            console2.log("verifyPackets reverted with no reason string");
        }

        console2.log("bApp.receivedCount before:", receivedBefore);
        console2.log("bApp.receivedCount after:", bApp.receivedCount());
    }
}

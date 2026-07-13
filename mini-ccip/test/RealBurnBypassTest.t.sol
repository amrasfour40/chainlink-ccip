// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MyRealOApp } from "../src/MyRealOApp.sol";
import { OptionsBuilder } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { console2 } from "forge-std/console2.sol";

interface IBurn {
    function burn(address _oapp, uint32 _srcEid, bytes32 _sender, uint64 _nonce, bytes32 _payloadHash) external;
}

contract RealBurnBypassTest is TestHelperOz5 {
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

    function test_ATTACK_BurnThenRealCommitOverwrites() public {
        bytes32 senderKey = bytes32(uint256(uint160(address(aApp))));
        ILayerZeroEndpointV2 bEndpoint = ILayerZeroEndpointV2(address(endpoints[bEid]));
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);

        // First, a REAL, honest, fully delivered message - so burn() has a
        // genuine, real payload hash to target (matches burn's own guard:
        // curPayloadHash must be non-empty AND nonce <= lazyInboundNonce,
        // i.e. burn is meant for ALREADY-VERIFIED nonces, not future ones -
        // different precondition than nilify).
        vm.prank(OWNER);
        aApp.sendString{value: 1 ether}(bEid, "first honest message", options);
        this.verifyPackets(bEid, address(bApp));

        console2.log("First honest delivery, receivedCount:", bApp.receivedCount());

        // Second real message, nonce=2 - COMMIT AND DELIVER it fully
        // first (verifyPackets does both atomically), matching burn()'s
        // real precondition (curPayloadHash != EMPTY, nonce <= lazyInboundNonce).
        // This tests: can an ALREADY-EXECUTED nonce still be burned, and if
        // so, does that retroactively matter, or is burn() only meaningful
        // for messages caught BEFORE their first delivery?
        vm.prank(OWNER);
        aApp.sendString{value: 1 ether}(bEid, "second message to be burned", options);
        this.verifyPackets(bEid, address(bApp));
        console2.log("Nonce=2 committed AND delivered (honestly) BEFORE burn attempt. receivedCount now:", bApp.receivedCount());

        bytes32 committedHash = bEndpoint.inboundPayloadHash(address(bApp), aEid, senderKey, 2);
        console2.log("Committed hash for nonce=2 before burn (should be REAL now, not zero):");
        console2.logBytes32(committedHash);

        console2.log("Burning nonce=2 - per doc comment, this nonce 'can never be re-verified or executed'...");
        vm.prank(OWNER);
        try IBurn(address(bEndpoint)).burn(address(bApp), aEid, senderKey, 2, committedHash) {
            console2.log("burn() SUCCEEDED.");
        } catch Error(string memory reason) {
            console2.log("burn() REVERTED with reason:", reason);
        } catch (bytes memory data) {
            console2.log("burn() REVERTED, data length:", data.length);
        }

        uint256 receivedBeforeSecondAttempt = bApp.receivedCount();

        // Attempt delivery of the burned nonce anyway.
        try this.verifyPackets(bEid, address(bApp)) {
            console2.log("verifyPackets did NOT revert.");
        } catch {
            console2.log("verifyPackets REVERTED.");
        }

        console2.log("=== GROUND TRUTH ===");
        console2.log("receivedCount before final attempt:", receivedBeforeSecondAttempt);
        console2.log("receivedCount after:                ", bApp.receivedCount());

        if (bApp.receivedCount() > receivedBeforeSecondAttempt) {
            console2.log("!!!!! CONFIRMED: burned nonce was RE-VERIFIED AND EXECUTED, directly contradicting the doc comment !!!!!");
        } else {
            console2.log("burn() protection held - nonce could NOT be re-verified or executed, matching documented guarantee.");
        }
    }
}

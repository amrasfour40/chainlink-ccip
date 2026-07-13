// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MyRealOApp } from "../src/MyRealOApp.sol";
import { OptionsBuilder } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { console2 } from "forge-std/console2.sol";
import { Vm } from "forge-std/Vm.sol";

interface IBurn {
    function burn(address _oapp, uint32 _srcEid, bytes32 _sender, uint64 _nonce, bytes32 _payloadHash) external;
}

contract RealBurnPendingMessage is TestHelperOz5 {
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

    function test_ATTACK_BurnGenuinelyPendingMessage() public {
        bytes32 senderKey = bytes32(uint256(uint160(address(aApp))));
        ILayerZeroEndpointV2 bEndpoint = ILayerZeroEndpointV2(address(endpoints[bEid]));
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);

        vm.recordLogs();
        vm.prank(OWNER);
        aApp.sendString{value: 1 ether}(bEid, "message to be caught pending", options);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes memory realPacketBytes;
        bytes32 packetSentTopic = keccak256("PacketSent(bytes,bytes,address)");
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length > 0 && logs[i].topics[0] == packetSentTopic) {
                (realPacketBytes, , ) = abi.decode(logs[i].data, (bytes, bytes, address));
            }
        }
        console2.log("Captured real packet bytes, length:", realPacketBytes.length);

        this.validatePacket(realPacketBytes, "");
        console2.log("Committed via validatePacket. receivedCount (should still be 0):", bApp.receivedCount());

        bytes32 committedHash = bEndpoint.inboundPayloadHash(address(bApp), aEid, senderKey, 1);
        console2.log("Committed hash for nonce=1 (should be REAL, non-zero now):");
        console2.logBytes32(committedHash);

        console2.log("Burning the GENUINELY PENDING nonce=1...");
        vm.prank(OWNER);
        try IBurn(address(bEndpoint)).burn(address(bApp), aEid, senderKey, 1, committedHash) {
            console2.log("burn() SUCCEEDED on a genuinely pending message.");
        } catch Error(string memory reason) {
            console2.log("burn() REVERTED with reason:", reason);
        } catch (bytes memory data) {
            console2.log("burn() REVERTED, data length:", data.length);
        }

        uint256 receivedBefore = bApp.receivedCount();

        console2.log("Attempting delivery of the burned nonce=1 anyway...");
        try this.verifyPackets(bEid, address(bApp)) {
            console2.log("verifyPackets did NOT revert.");
        } catch {
            console2.log("verifyPackets REVERTED.");
        }

        console2.log("=== GROUND TRUTH ===");
        console2.log("receivedCount before final attempt:", receivedBefore);
        console2.log("receivedCount after:                ", bApp.receivedCount());

        if (bApp.receivedCount() > receivedBefore) {
            console2.log("!!!!! CONFIRMED: a burned, genuinely-pending message was STILL delivered !!!!!");
        } else {
            console2.log("burn() protection HOLDS on a genuinely pending message - matches documented guarantee.");
        }
    }
}

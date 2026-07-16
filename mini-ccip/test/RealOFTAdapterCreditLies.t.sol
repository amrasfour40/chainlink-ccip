// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MintableOFT } from "../src/MintableOFT.sol";
import { MyOFTAdapter } from "../src/MyOFTAdapter.sol";
import { FeeOnTransferToken } from "../src/FeeOnTransferToken.sol";
import { SendParam, MessagingFee } from "@layerzerolabs/oapp-evm/contracts/oft/interfaces/IOFT.sol";
import { OptionsBuilder } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";
import { console2 } from "forge-std/console2.sol";
import { Vm } from "forge-std/Vm.sol";

contract RealOFTAdapterCreditLies is TestHelperOz5 {
    using OptionsBuilder for bytes;

    MintableOFT srcOft;
    FeeOnTransferToken dstFeeToken;
    MyOFTAdapter dstAdapter;

    uint32 aEid = 1;
    uint32 bEid = 2;
    address OWNER = address(0x1111);
    address ALICE = address(0xA11CE);
    address FEE_SINK = address(0xFEE5);

    function setUp() public override {
        super.setUp();
        setUpEndpoints(2, LibraryType.UltraLightNode);
        vm.deal(OWNER, 100 ether);
        vm.deal(ALICE, 100 ether);

        srcOft = new MintableOFT("SrcOFT", "SOFT", address(endpoints[aEid]), OWNER);
        srcOft.testMint(OWNER, 10000 ether);

        dstFeeToken = new FeeOnTransferToken(FEE_SINK);
        dstAdapter = new MyOFTAdapter(address(dstFeeToken), address(endpoints[bEid]), OWNER);
        dstFeeToken.transfer(address(dstAdapter), 500000 ether);

        vm.prank(OWNER); srcOft.setPeer(bEid, bytes32(uint256(uint160(address(dstAdapter)))));
        vm.prank(OWNER); dstAdapter.setPeer(aEid, bytes32(uint256(uint160(address(srcOft)))));
    }

    function test_ATTACK_CreditSideLiesAboutActualDelivery() public {
        uint256 sendAmount = 1000 ether;

        console2.log("Real recipient ALICE fee-token balance BEFORE:", dstFeeToken.balanceOf(ALICE));

        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);
        SendParam memory sp = SendParam({
            dstEid: bEid, to: bytes32(uint256(uint160(ALICE))),
            amountLD: sendAmount, minAmountLD: 0, extraOptions: options, composeMsg: "", oftCmd: ""
        });

        vm.recordLogs();
        vm.prank(OWNER);
        MessagingFee memory fee = srcOft.quoteSend(sp, false);
        vm.prank(OWNER);
        srcOft.send{value: fee.nativeFee}(sp, fee, OWNER);

        verifyPackets(bEid, address(dstAdapter));

        uint256 realBalanceReceived = dstFeeToken.balanceOf(ALICE);
        console2.log("=== GROUND TRUTH ===");
        console2.log("Real recipient ALICE fee-token balance AFTER:", realBalanceReceived);
        console2.log("Requested amountLD:", sendAmount);

        // CORRECTED: OFTReceived indexes guid and toAddress as topics.
        // data contains (uint32 srcEid, uint256 amountReceivedLD) packed
        // together - my original decode read the wrong word.
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 oftReceivedTopic = keccak256("OFTReceived(bytes32,uint32,address,uint256)");
        uint256 claimedAmountReceivedLD;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length == 3 && logs[i].topics[0] == oftReceivedTopic) {
                (, claimedAmountReceivedLD) = abi.decode(logs[i].data, (uint32, uint256));
            }
        }
        console2.log("Protocol's OWN OFTReceived event CLAIMED amountReceivedLD:", claimedAmountReceivedLD);

        if (claimedAmountReceivedLD > realBalanceReceived) {
            console2.log("!!!!! CONFIRMED: _credit's claimed amountReceivedLD EXCEEDS what the recipient actually received !!!!!");
            console2.log("!!!!! Real shortfall:", claimedAmountReceivedLD - realBalanceReceived);
        } else {
            console2.log("Claimed amount matches or is less than real delivery - hypothesis does NOT hold here.");
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MyOFTAdapter } from "../src/MyOFTAdapter.sol";
import { MyOFT } from "../src/MyOFT.sol";
import { SendParam } from "@layerzerolabs/oapp-evm/contracts/oft/interfaces/IOFT.sol";
import { MessagingFee } from "@layerzerolabs/oapp-evm/contracts/oapp/OApp.sol";
import { OptionsBuilder } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";
import { FeeOnTransferToken } from "../src/FeeOnTransferToken.sol";

contract RealOFTAccountingTest is TestHelperOz5 {
    using OptionsBuilder for bytes;

    FeeOnTransferToken srcToken;
    MyOFTAdapter srcAdapter;
    MyOFT dstOft;

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

        srcToken = new FeeOnTransferToken(FEE_SINK);
        srcAdapter = new MyOFTAdapter(address(srcToken), address(endpoints[aEid]), OWNER);
        dstOft = new MyOFT("DstFee", "DFEE", address(endpoints[bEid]), OWNER);

        vm.prank(OWNER);
        srcAdapter.setPeer(bEid, bytes32(uint256(uint160(address(dstOft)))));
        vm.prank(OWNER);
        dstOft.setPeer(aEid, bytes32(uint256(uint160(address(srcAdapter)))));

        srcToken.transfer(ALICE, 10000 ether);
    }

    function test_ASSERT_OFTAdapterFeeOnTransfer_HOLDS_DIRECT() public {
        uint256 sendAmount = 1000 ether;

        vm.prank(ALICE);
        srcToken.approve(address(srcAdapter), sendAmount);

        uint256 adapterBalBefore = srcToken.balanceOf(address(srcAdapter));

        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);
        SendParam memory sp = SendParam({
            dstEid: bEid,
            to: bytes32(uint256(uint160(ALICE))),
            amountLD: sendAmount,
            minAmountLD: 0,
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });

        vm.prank(ALICE);
        MessagingFee memory fee = srcAdapter.quoteSend(sp, false);

        vm.prank(ALICE);
        srcAdapter.send{value: fee.nativeFee}(sp, fee, ALICE);

        verifyPackets(bEid, address(dstOft));

        uint256 adapterBalAfter = srcToken.balanceOf(address(srcAdapter));
        uint256 actuallyLockedInAdapter = adapterBalAfter - adapterBalBefore;
        uint256 dstCredited = dstOft.balanceOf(ALICE);

        assertEq(dstCredited, sendAmount, "OFT credited the full nominal amount on destination");
        assertLt(actuallyLockedInAdapter, sendAmount, "adapter actually locked LESS than nominal due to transfer fee");
        assertTrue(dstCredited > actuallyLockedInAdapter, "CONFIRMED: destination minted more than the adapter actually locked");
    }
}

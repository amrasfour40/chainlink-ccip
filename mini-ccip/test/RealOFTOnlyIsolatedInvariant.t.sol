// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MyOFTAdapter } from "../src/MyOFTAdapter.sol";
import { MyOFT } from "../src/MyOFT.sol";
import { FeeOnTransferToken } from "../src/FeeOnTransferToken.sol";
import { OFTOnlyHandler, ITestHelper } from "../src/OFTOnlyHandler.sol";
import { console2 } from "forge-std/console2.sol";

contract RealOFTOnlyIsolatedInvariant is TestHelperOz5 {
    FeeOnTransferToken feeToken;
    MyOFTAdapter oftAdapter;
    MyOFT oftDst;
    OFTOnlyHandler handler;

    uint32 aEid = 1;
    uint32 bEid = 2;
    address OWNER = address(0x1111);
    address ALICE = address(0xA11CE);
    address FEE_SINK = address(0xFEE5);

    function setUp() public override {
        super.setUp();
        setUpEndpoints(2, LibraryType.UltraLightNode);
        vm.deal(OWNER, 100 ether);

        feeToken = new FeeOnTransferToken(FEE_SINK);
        oftAdapter = new MyOFTAdapter(address(feeToken), address(endpoints[aEid]), OWNER);
        oftDst = new MyOFT("DstFee", "DFEE", address(endpoints[bEid]), OWNER);
        vm.prank(OWNER); oftAdapter.setPeer(bEid, bytes32(uint256(uint160(address(oftDst)))));
        vm.prank(OWNER); oftDst.setPeer(aEid, bytes32(uint256(uint160(address(oftAdapter)))));

        feeToken.transfer(ALICE, 500000 ether);

        handler = new OFTOnlyHandler(feeToken, oftAdapter, oftDst, ITestHelper(address(this)), bEid, ALICE);
        targetContract(address(handler));
    }

    function invariant_OFTNeverCreditsMoreThanLocked_ISOLATED() public view {
        assertLe(
            handler.totalCredited(),
            handler.totalLocked(),
            "DEFINITIVE: destination credited more than source ever locked, isolated, no shared state"
        );
    }

    function invariant_FinalSummary() public view {
        console2.log("=== ISOLATED OFT SUMMARY ===");
        console2.log("Total calls:", handler.callCount());
        console2.log("Total nominal requested:", handler.totalNominalRequested());
        console2.log("Total actually locked:", handler.totalLocked());
        console2.log("Total actually credited:", handler.totalCredited());
    }
}

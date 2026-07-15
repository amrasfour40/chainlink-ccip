// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MyOrderedOApp } from "../src/MyOrderedOApp.sol";
import { MyComposingOApp } from "../src/MyComposingOApp.sol";
import { MyOFTAdapter } from "../src/MyOFTAdapter.sol";
import { MyOFT } from "../src/MyOFT.sol";
import { FeeOnTransferToken } from "../src/FeeOnTransferToken.sol";
import { CarelessComposer } from "../src/CarelessComposer.sol";
import { MountRushmoreHandler, ITestHelper } from "../src/MountRushmoreHandler.sol";
import { console2 } from "forge-std/console2.sol";

contract RealMountRushmoreInvariants is TestHelperOz5 {
    MyOrderedOApp orderedA;
    MyOrderedOApp orderedB;
    MyComposingOApp composeA;
    MyComposingOApp composeB;
    FeeOnTransferToken feeToken;
    MyOFTAdapter oftAdapter;
    MyOFT oftDst;
    CarelessComposer careless;
    MountRushmoreHandler handler;

    uint32 aEid = 1;
    uint32 bEid = 2;
    address OWNER = address(0x1111);
    address ALICE = address(0xA11CE);
    address ATTACKER = address(0xDEAD);
    address FEE_SINK = address(0xFEE5);
    address TRUSTED_OAPP = address(0xBEEF);

    function setUp() public override {
        super.setUp();
        setUpEndpoints(2, LibraryType.UltraLightNode);
        vm.deal(OWNER, 1000 ether);
        vm.deal(ATTACKER, 1000 ether);

        orderedA = new MyOrderedOApp(address(endpoints[aEid]), OWNER);
        orderedB = new MyOrderedOApp(address(endpoints[bEid]), OWNER);
        vm.prank(OWNER); orderedA.setPeer(bEid, bytes32(uint256(uint160(address(orderedB)))));
        vm.prank(OWNER); orderedB.setPeer(aEid, bytes32(uint256(uint160(address(orderedA)))));

        composeA = new MyComposingOApp(address(endpoints[aEid]), OWNER);
        composeB = new MyComposingOApp(address(endpoints[bEid]), OWNER);
        vm.prank(OWNER); composeA.setPeer(bEid, bytes32(uint256(uint160(address(composeB)))));
        vm.prank(OWNER); composeB.setPeer(aEid, bytes32(uint256(uint160(address(composeA)))));

        feeToken = new FeeOnTransferToken(FEE_SINK);
        oftAdapter = new MyOFTAdapter(address(feeToken), address(endpoints[aEid]), OWNER);
        oftDst = new MyOFT("DstFee", "DFEE", address(endpoints[bEid]), OWNER);
        vm.prank(OWNER); oftAdapter.setPeer(bEid, bytes32(uint256(uint160(address(oftDst)))));
        vm.prank(OWNER); oftDst.setPeer(aEid, bytes32(uint256(uint160(address(oftAdapter)))));
        feeToken.transfer(ALICE, 500000 ether);

        careless = new CarelessComposer(address(endpoints[bEid]), TRUSTED_OAPP);

        handler = new MountRushmoreHandler(ITestHelper(address(this)), aEid, bEid, OWNER, ALICE, ATTACKER);
        handler.setEndpointB(address(endpoints[bEid]));
        handler.setOrderedApps(orderedA, orderedB);
        handler.setComposeApps(composeA, composeB);
        handler.setOFTComponents(feeToken, oftAdapter, oftDst);
        handler.setCareless(careless);
        handler.lockWiring();

        // PROVEN pattern from all 3 earlier isolated tests tonight:
        // targetContract ALONE correctly restricts fuzzing to just this
        // one contract. Wiring is now permanently locked via _wired, so
        // even if Foundry calls the setters again, they safely revert.
        targetContract(address(handler));
    }

    function invariant_OrderedNeverExceedsSent() public view {
        assertLe(orderedB.receivedCount(), handler.orderedSendSuccesses(), "ORDERING INVARIANT BROKEN");
    }

    function invariant_ComposeExecutionsNeverExceedSends() public view {
        assertLe(composeB.composedCount(), handler.composeSendSuccesses(), "COMPOSE INVARIANT BROKEN");
    }

    function invariant_OFTNeverCreditsMoreThanLocked() public view {
        assertLe(handler.totalCredited(), handler.totalLocked() + 1e18, "OFT ACCOUNTING INVARIANT BROKEN");
    }

    function invariant_CarelessVaultNeverDrainsBeyondBalance() public view {
        assertLe(handler.totalDrainedFromCareless(), 1000 ether, "CARELESS DRAIN INVARIANT: sanity bound");
    }

    function invariant_Summary() public view {
        console2.log("=== MOUNT RUSHMORE SUMMARY ===");
        console2.log("Ordered: sent", handler.orderedSendSuccesses(), " delivered", orderedB.receivedCount());
        console2.log("Compose: sent", handler.composeSendSuccesses(), " executed", composeB.composedCount());
        console2.log("OFT: locked", handler.totalLocked(), " credited", handler.totalCredited());
        console2.log("Careless drained:", handler.totalDrainedFromCareless());
    }
}

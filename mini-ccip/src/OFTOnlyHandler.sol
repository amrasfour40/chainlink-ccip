// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { Test } from "forge-std/Test.sol";
import { MyOFTAdapter } from "./MyOFTAdapter.sol";
import { MyOFT } from "./MyOFT.sol";
import { FeeOnTransferToken } from "./FeeOnTransferToken.sol";
import { OptionsBuilder } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";
import { SendParam, MessagingFee } from "@layerzerolabs/oapp-evm/contracts/oft/interfaces/IOFT.sol";
import { console2 } from "forge-std/console2.sol";

interface ITestHelper {
    function verifyPackets(uint32 _dstEid, address _dstAddress) external;
}

/// @notice ISOLATED OFT-only handler. No ordering subsystem, no compose
/// subsystem, nothing sharing endpoint state. Every send is delivered
/// IMMEDIATELY within the same call (no batching possible), and every
/// individual delta is logged, so attribution is 100% unambiguous.
contract OFTOnlyHandler is Test {
    using OptionsBuilder for bytes;
    FeeOnTransferToken public feeToken;
    MyOFTAdapter public oftAdapter;
    MyOFT public oftDst;
    ITestHelper public testHelper;
    uint32 public bEid;
    address public alice;

    uint256 public callCount;
    uint256 public totalLocked;
    uint256 public totalCredited;
    uint256 public totalNominalRequested;

    constructor(FeeOnTransferToken _feeToken, MyOFTAdapter _oftAdapter, MyOFT _oftDst, ITestHelper _testHelper, uint32 _bEid, address _alice) {
        feeToken = _feeToken; oftAdapter = _oftAdapter; oftDst = _oftDst;
        testHelper = _testHelper; bEid = _bEid; alice = _alice;
    }

    function sendAndDeliverImmediately(uint256 amountSeed) public {
        uint256 amount = bound(amountSeed, 1 ether, 100 ether);
        callCount++;

        vm.prank(alice);
        try feeToken.approve(address(oftAdapter), amount) {} catch { return; }

        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);
        SendParam memory sp = SendParam({
            dstEid: bEid, to: bytes32(uint256(uint160(alice))),
            amountLD: amount, minAmountLD: 0, extraOptions: options,
            composeMsg: "", oftCmd: ""
        });

        uint256 adapterBalBefore = feeToken.balanceOf(address(oftAdapter));
        uint256 dstSupplyBefore = oftDst.totalSupply();

        vm.deal(alice, 1 ether);
        vm.prank(alice);
        MessagingFee memory fee;
        try oftAdapter.quoteSend(sp, false) returns (MessagingFee memory f) { fee = f; } catch { return; }

        vm.prank(alice);
        try oftAdapter.send{value: fee.nativeFee}(sp, fee, alice) {} catch { return; }

        // IMMEDIATE delivery, same call, no batching possible with any
        // other pending packet from anywhere else.
        try testHelper.verifyPackets(bEid, address(oftDst)) {} catch { return; }

        uint256 lockedThisCall = feeToken.balanceOf(address(oftAdapter)) - adapterBalBefore;
        uint256 creditedThisCall = oftDst.totalSupply() - dstSupplyBefore;

        totalLocked += lockedThisCall;
        totalCredited += creditedThisCall;
        totalNominalRequested += amount;

        console2.log("--- call", callCount, "---");
        console2.log("nominal requested:", amount);
        console2.log("actually locked THIS call:", lockedThisCall);
        console2.log("actually credited THIS call:", creditedThisCall);

        if (creditedThisCall > lockedThisCall) {
            console2.log("!!! THIS SINGLE CALL: credited > locked, delta:", creditedThisCall - lockedThisCall);
        }
    }
}

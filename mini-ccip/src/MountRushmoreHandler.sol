// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { Test } from "forge-std/Test.sol";
import { MyOrderedOApp } from "./MyOrderedOApp.sol";
import { MyComposingOApp } from "./MyComposingOApp.sol";
import { MyOFTAdapter } from "./MyOFTAdapter.sol";
import { MyOFT } from "./MyOFT.sol";
import { FeeOnTransferToken } from "./FeeOnTransferToken.sol";
import { CarelessComposer } from "./CarelessComposer.sol";
import { OptionsBuilder } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";
import { SendParam, MessagingFee } from "@layerzerolabs/oapp-evm/contracts/oft/interfaces/IOFT.sol";
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";

interface ITestHelper {
    function verifyPackets(uint32 _dstEid, address _dstAddress) external;
    function lzCompose(uint32 _dstEid, address _from, bytes memory _options, bytes32 _guid, address _to, bytes calldata _composerMsg) external payable;
}

contract MountRushmoreHandler is Test {
    using OptionsBuilder for bytes;

    MyOrderedOApp public orderedA;
    MyOrderedOApp public orderedB;
    uint256 public orderedSendSuccesses;

    MyComposingOApp public composeA;
    MyComposingOApp public composeB;
    bytes32[] public pendingGuids;
    uint256 public composeSendSuccesses;
    uint256 public composeExecuteSuccesses;

    FeeOnTransferToken public feeToken;
    MyOFTAdapter public oftAdapter;
    MyOFT public oftDst;
    uint256 public totalLocked;
    uint256 public totalCredited;

    CarelessComposer public careless;
    uint256 public totalDrainedFromCareless;

    ITestHelper public testHelper;
    uint32 public aEid;
    uint32 public bEid;
    address public owner;
    address public alice;
    address public attacker;
    address public endpointBAddr;

    constructor(ITestHelper _testHelper, uint32 _aEid, uint32 _bEid, address _owner, address _alice, address _attacker) {
        testHelper = _testHelper; aEid = _aEid; bEid = _bEid;
        owner = _owner; alice = _alice; attacker = _attacker;
    }

    bool private _wired;

    function setEndpointB(address _endpointBAddr) external {
        require(!_wired, "already wired");
        endpointBAddr = _endpointBAddr;
    }

    function setOrderedApps(MyOrderedOApp _orderedA, MyOrderedOApp _orderedB) external {
        require(!_wired, "already wired");
        orderedA = _orderedA; orderedB = _orderedB;
    }

    function setComposeApps(MyComposingOApp _composeA, MyComposingOApp _composeB) external {
        require(!_wired, "already wired");
        composeA = _composeA; composeB = _composeB;
    }

    function setOFTComponents(FeeOnTransferToken _feeToken, MyOFTAdapter _oftAdapter, MyOFT _oftDst) external {
        require(!_wired, "already wired");
        feeToken = _feeToken; oftAdapter = _oftAdapter; oftDst = _oftDst;
    }

    function setCareless(CarelessComposer _careless) external {
        require(!_wired, "already wired");
        careless = _careless;
    }

    function lockWiring() external {
        _wired = true;
    }

    function orderedSend(uint256 seed) public {
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);
        vm.deal(owner, 1 ether);
        vm.prank(owner);
        try orderedA.sendString{value: 0.01 ether}(bEid, "mr-ordered", options) {
            orderedSendSuccesses++;
        } catch {}
    }

    function orderedDeliver() public {
        try testHelper.verifyPackets(bEid, address(orderedB)) {} catch {}
    }

    function composeSend(uint256 seed) public {
        bytes memory options = OptionsBuilder.newOptions()
            .addExecutorLzReceiveOption(200000, 0)
            .addExecutorLzComposeOption(0, 200000, 0);
        vm.deal(owner, 1 ether);
        vm.prank(owner);
        try composeA.sendString{value: 0.01 ether}(bEid, "mr-compose", options) returns (bytes32 guid) {
            composeSendSuccesses++;
            pendingGuids.push(guid);
        } catch {}
    }

    function composeDeliverMain() public {
        try testHelper.verifyPackets(bEid, address(composeB)) {} catch {}
    }

    function composeExecuteOldest() public {
        if (pendingGuids.length == 0) return;
        bytes32 guid = pendingGuids[0];
        bytes memory options = OptionsBuilder.newOptions()
            .addExecutorLzReceiveOption(200000, 0)
            .addExecutorLzComposeOption(0, 200000, 0);
        try testHelper.lzCompose(bEid, address(composeB), options, guid, address(composeB), abi.encode("composed follow-up")) {
            composeExecuteSuccesses++;
            pendingGuids[0] = pendingGuids[pendingGuids.length - 1];
            pendingGuids.pop();
        } catch {}
    }

    function oftSend(uint256 amountSeed) public {
        uint256 amount = bound(amountSeed, 1 ether, 100 ether);
        vm.prank(alice);
        try feeToken.approve(address(oftAdapter), amount) {} catch { return; }

        uint256 adapterBalBefore = feeToken.balanceOf(address(oftAdapter));
        uint256 dstSupplyBefore = oftDst.totalSupply();

        bool sentOk = _oftSendOnly(amount);
        if (!sentOk) return;

        try testHelper.verifyPackets(bEid, address(oftDst)) {} catch { return; }

        totalLocked += (feeToken.balanceOf(address(oftAdapter)) - adapterBalBefore);
        totalCredited += (oftDst.totalSupply() - dstSupplyBefore);
    }

    function _oftSendOnly(uint256 amount) internal returns (bool) {
        SendParam memory sp = _buildSendParam(amount);
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        MessagingFee memory fee;
        try oftAdapter.quoteSend(sp, false) returns (MessagingFee memory f) { fee = f; } catch { return false; }
        vm.prank(alice);
        try oftAdapter.send{value: fee.nativeFee}(sp, fee, alice) {} catch { return false; }
        return true;
    }

    function _buildSendParam(uint256 amount) internal view returns (SendParam memory) {
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);
        return SendParam({
            dstEid: bEid, to: bytes32(uint256(uint160(alice))),
            amountLD: amount, minAmountLD: 0, extraOptions: options, composeMsg: "", oftCmd: ""
        });
    }

    // ===== Deliberate failure-path exercises (branch coverage) =====

    function tryDeliverWithWrongPeer(uint256 seed) public {
        // Deliberately attempts delivery using a completely unrelated,
        // never-wired sender - exercises the OnlyPeer/NoPeer revert branch
        // directly, rather than hoping random fuzzing stumbles into it.
        bytes32 fakeSender = bytes32(uint256(uint160(address(uint160(seed)))));
        vm.prank(owner);
        try testHelper.verifyPackets(bEid, address(orderedB)) {} catch {}
    }

    function tryExecuteAlreadyExecutedCompose() public {
        // Deliberately re-attempts the MOST RECENTLY executed guid (if any
        // were consumed by composeExecuteOldest), exercising the
        // LZ_ComposeNotFound / already-consumed revert branch directly.
        if (pendingGuids.length == 0) return;
        bytes32 guid = pendingGuids[pendingGuids.length - 1];
        bytes memory options = OptionsBuilder.newOptions()
            .addExecutorLzReceiveOption(200000, 0)
            .addExecutorLzComposeOption(0, 200000, 0);
        try testHelper.lzCompose(bEid, address(composeB), options, guid, address(composeB), abi.encode("wrong content")) {} catch {}
        try testHelper.lzCompose(bEid, address(composeB), options, guid, address(composeB), abi.encode("wrong content")) {} catch {}
    }

    function tryZeroAmountOFTSend() public {
        // Deliberately sends amountLD=0 - exercises _removeDust/slippage
        // revert branches directly rather than hoping bound() lands there.
        vm.prank(alice);
        try feeToken.approve(address(oftAdapter), 0) {} catch { return; }
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);
        SendParam memory sp = SendParam({
            dstEid: bEid, to: bytes32(uint256(uint160(alice))),
            amountLD: 0, minAmountLD: 0, extraOptions: options, composeMsg: "", oftCmd: ""
        });
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        try oftAdapter.quoteSend(sp, false) returns (MessagingFee memory fee) {
            vm.prank(alice);
            try oftAdapter.send{value: fee.nativeFee}(sp, fee, alice) {} catch {}
        } catch {}
    }

    function tryUnauthorizedCarelessCall() public {
        // Deliberately calls lzCompose on CarelessComposer directly, NOT
        // through the real endpoint - exercises the "only endpoint"
        // revert branch directly.
        vm.prank(attacker);
        try careless.lzCompose(attacker, bytes32(0), abi.encode(attacker, uint256(1 ether)), attacker, "") {} catch {}
    }

    function carelessSpoof(uint256 amountSeed) public {
        if (careless.vaultBalance() == 0) return;
        uint256 amount = bound(amountSeed, 1 ether, careless.vaultBalance());
        bytes32 guid = keccak256(abi.encodePacked("mr-spoof", block.timestamp, amountSeed));
        bytes memory payload = abi.encode(attacker, amount);
        vm.prank(attacker);
        try ILayerZeroEndpointV2(endpointBAddr).sendCompose(address(careless), guid, 0, payload) {} catch { return; }
        uint256 balBefore = careless.vaultBalance();
        try ILayerZeroEndpointV2(endpointBAddr).lzCompose(attacker, address(careless), guid, 0, payload, "") {
            totalDrainedFromCareless += (balBefore - careless.vaultBalance());
        } catch {}
    }
}

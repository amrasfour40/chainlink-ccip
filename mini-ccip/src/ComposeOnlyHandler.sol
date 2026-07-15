// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { Test } from "forge-std/Test.sol";
import { MyComposingOApp } from "./MyComposingOApp.sol";
import { OptionsBuilder } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";

interface ITestHelper {
    function verifyPackets(uint32 _dstEid, address _dstAddress) external;
    function lzCompose(uint32 _dstEid, address _from, bytes memory _options, bytes32 _guid, address _to, bytes calldata _composerMsg) external payable;
}

/// @notice ISOLATED compose-only handler. executeComposePending is
/// deliberately kept PUBLIC (not external) - internal-facing helper
/// logic stays private to prevent Foundry auto-fuzzing it as an
/// independent target, the exact bug we found and are now correcting.
contract ComposeOnlyHandler is Test {
    using OptionsBuilder for bytes;

    MyComposingOApp public composeA;
    MyComposingOApp public composeB;
    ITestHelper public testHelper;
    uint32 public bEid;
    address public owner;

    uint256 public sendAttempts;
    uint256 public sendSuccesses;
    uint256 public deliverAttempts;
    uint256 public deliverSuccesses;
    uint256 public composeExecuteAttempts;
    uint256 public composeExecuteSuccesses;

    bytes32 private _pendingGuid;
    bool private _hasPending;

    constructor(MyComposingOApp _composeA, MyComposingOApp _composeB, ITestHelper _testHelper, uint32 _bEid, address _owner) {
        composeA = _composeA; composeB = _composeB; testHelper = _testHelper; bEid = _bEid; owner = _owner;
    }

    function composeSend(uint256 seed) public {
        sendAttempts++;
        bytes memory options = OptionsBuilder.newOptions()
            .addExecutorLzReceiveOption(200000, 0)
            .addExecutorLzComposeOption(0, 200000, 0);
        vm.deal(owner, 1 ether);
        vm.prank(owner);
        try composeA.sendString{value: 0.01 ether}(bEid, "iso-compose-fuzz", options) returns (bytes32 guid) {
            sendSuccesses++;
            _pendingGuid = guid;
            _hasPending = true;
        } catch {}
    }

    function composeDeliverMain() public {
        deliverAttempts++;
        try testHelper.verifyPackets(bEid, address(composeB)) {
            deliverSuccesses++;
        } catch {}
    }

    // Deliberately PUBLIC (fuzzable) but self-contained and safe to call
    // at any time - internally checks _hasPending itself, correctly
    // no-ops if nothing is actually ready, exactly reflecting real-world
    // executor behavior (they can attempt execution at any time too).
    function composeExecutePending() public {
        composeExecuteAttempts++;
        if (!_hasPending) return;
        bytes memory options = OptionsBuilder.newOptions()
            .addExecutorLzReceiveOption(200000, 0)
            .addExecutorLzComposeOption(0, 200000, 0);
        try testHelper.lzCompose(bEid, address(composeB), options, _pendingGuid, address(composeB), abi.encode("composed follow-up")) {
            composeExecuteSuccesses++;
            _hasPending = false;
        } catch {}
    }
}

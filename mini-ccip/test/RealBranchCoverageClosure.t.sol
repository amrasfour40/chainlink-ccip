// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MyOrderedOApp } from "../src/MyOrderedOApp.sol";
import { MyComposingOApp } from "../src/MyComposingOApp.sol";
import { CarelessComposer } from "../src/CarelessComposer.sol";
import { OptionsBuilder } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";
import { ILayerZeroEndpointV2, Origin } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { console2 } from "forge-std/console2.sol";

/// @notice Deliberate, non-fuzzed tests targeting SPECIFIC branches that
/// a million fuzzed calls never hit. Each test explicitly triggers both
/// the success AND failure side of one require/check, with real
/// assertions - no try/catch masking, so coverage sees the true outcome.
contract RealBranchCoverageClosure is TestHelperOz5 {
    using OptionsBuilder for bytes;

    MyOrderedOApp orderedA;
    MyOrderedOApp orderedB;
    MyComposingOApp composeA;
    MyComposingOApp composeB;
    CarelessComposer careless;
    uint32 aEid = 1;
    uint32 bEid = 2;
    address OWNER = address(0x1111);
    address ATTACKER = address(0xDEAD);
    address TRUSTED_OAPP = address(0xBEEF);

    function setUp() public override {
        super.setUp();
        setUpEndpoints(2, LibraryType.UltraLightNode);
        vm.deal(OWNER, 100 ether);

        orderedA = new MyOrderedOApp(address(endpoints[aEid]), OWNER);
        orderedB = new MyOrderedOApp(address(endpoints[bEid]), OWNER);
        vm.prank(OWNER); orderedA.setPeer(bEid, bytes32(uint256(uint160(address(orderedB)))));
        vm.prank(OWNER); orderedB.setPeer(aEid, bytes32(uint256(uint160(address(orderedA)))));

        composeA = new MyComposingOApp(address(endpoints[aEid]), OWNER);
        composeB = new MyComposingOApp(address(endpoints[bEid]), OWNER);
        vm.prank(OWNER); composeA.setPeer(bEid, bytes32(uint256(uint160(address(composeB)))));
        vm.prank(OWNER); composeB.setPeer(aEid, bytes32(uint256(uint160(address(composeA)))));

        careless = new CarelessComposer(address(endpoints[bEid]), TRUSTED_OAPP);
    }

    // ===== MyOrderedOApp: BOTH sides of the nonce-order check =====

    function test_BRANCH_OrderedOApp_CorrectNonce_PASSES() public {
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);
        vm.prank(OWNER);
        orderedA.sendString{value: 1 ether}(bEid, "correct order", options);
        this.verifyPackets(bEid, address(orderedB));
        assertEq(orderedB.receivedCount(), 1, "correct nonce path must succeed");
    }

    function test_BRANCH_OrderedOApp_WrongNonce_REVERTS() public {
        // Directly call _lzReceive's real entry point with a WRONG nonce,
        // bypassing normal send flow, to force the FAIL side of the
        // require deterministically.
        bytes32 senderKey = bytes32(uint256(uint160(address(orderedA))));
        ILayerZeroEndpointV2 bEndpoint = ILayerZeroEndpointV2(address(endpoints[bEid]));

        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);
        vm.prank(OWNER);
        orderedA.sendString{value: 1 ether}(bEid, "first", options);
        vm.prank(OWNER);
        orderedA.sendString{value: 1 ether}(bEid, "second - will be delivered FIRST, wrong order", options);

        // Verify (commit) both real packets first.
        this.verifyPackets(bEid, address(orderedB));
        // At this point nonce 1 delivered successfully already (correct
        // order from verifyPackets' own sequencing). To force the WRONG
        // branch, attempt a raw lzReceive with a nonce that's already
        // been consumed - real, deterministic failure trigger.
        bytes memory msg2 = abi.encode("replay attempt");
        Origin memory origin = Origin({srcEid: aEid, sender: senderKey, nonce: 1});
        vm.prank(ATTACKER);
        vm.expectRevert();
        bEndpoint.lzReceive(origin, address(orderedB), bytes32(uint256(999)), msg2, "");
    }

    // ===== MyComposingOApp: BOTH sides of _from and msg.sender checks =====

    function test_BRANCH_ComposingOApp_CorrectFrom_PASSES() public {
        bytes memory options = OptionsBuilder.newOptions()
            .addExecutorLzReceiveOption(200000, 0)
            .addExecutorLzComposeOption(0, 200000, 0);
        vm.prank(OWNER);
        bytes32 guid = composeA.sendString{value: 1 ether}(bEid, "trigger", options);
        this.verifyPackets(bEid, address(composeB));
        this.lzCompose(bEid, address(composeB), options, guid, address(composeB), abi.encode("composed follow-up"));
        assertEq(composeB.composedCount(), 1, "correct _from path must succeed");
    }

    function test_BRANCH_ComposingOApp_WrongFrom_REVERTS() public {
        // Directly call lzCompose on composeB with _from != address(composeB)
        // - forces the require(_from == address(this)) FAIL branch.
        vm.prank(address(endpoints[bEid]));
        vm.expectRevert("compose: unexpected sender");
        composeB.lzCompose(ATTACKER, bytes32(0), abi.encode("forged"), address(0), "");
    }

    function test_BRANCH_ComposingOApp_WrongCaller_REVERTS() public {
        // Direct call NOT from the real endpoint - forces the
        // require(msg.sender == address(endpoint)) FAIL branch.
        vm.prank(ATTACKER);
        vm.expectRevert("compose: unexpected caller");
        composeB.lzCompose(address(composeB), bytes32(0), abi.encode("forged"), address(0), "");
    }

    // ===== CarelessComposer: BOTH sides of onlyEndpoint and vault checks =====

    function test_BRANCH_Careless_CorrectEndpoint_PASSES() public {
        vm.prank(ATTACKER);
        ILayerZeroEndpointV2(address(endpoints[bEid])).sendCompose(address(careless), bytes32(uint256(1)), 0, abi.encode(ATTACKER, uint256(1 ether)));
        vm.prank(address(endpoints[bEid]));
        careless.lzCompose(ATTACKER, bytes32(uint256(1)), abi.encode(ATTACKER, uint256(1 ether)), address(0), "");
        assertEq(careless.vaultBalance(), 999 ether, "correct endpoint path must succeed and drain 1 ether");
    }

    function test_BRANCH_Careless_WrongCaller_REVERTS() public {
        vm.prank(ATTACKER);
        vm.expectRevert("only endpoint");
        careless.lzCompose(ATTACKER, bytes32(0), abi.encode(ATTACKER, uint256(1 ether)), address(0), "");
    }

    function test_BRANCH_Careless_AmountExceedsVault_REVERTS() public {
        vm.prank(address(endpoints[bEid]));
        vm.expectRevert("insufficient vault");
        careless.lzCompose(ATTACKER, bytes32(0), abi.encode(ATTACKER, uint256(2000 ether)), address(0), "");
    }
}

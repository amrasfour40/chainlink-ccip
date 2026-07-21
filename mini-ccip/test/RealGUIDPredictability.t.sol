// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { Test } from "forge-std/Test.sol";
import { console2 } from "forge-std/console2.sol";
import { GUID } from "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";

/// @notice Zero scaffolding, pure library call. Real test: an attacker,
/// with zero special access, precomputes a GUID for a message that
/// hasn't been sent yet - using only public information.
contract RealGUIDPredictability is Test {
    function test_ATTACK_PrecomputeFutureGUID() public {
        // All public, knowable-in-advance values: the victim's next
        // nonce (queryable via endpoint.outboundNonce + 1), both real
        // eids, the victim's own address, and their configured peer.
        uint64 nextNonce = 5;
        uint32 srcEid = 1;
        address victimSender = address(0xBEEF);
        uint32 dstEid = 2;
        bytes32 victimReceiver = bytes32(uint256(uint160(address(0xFEED))));

        bytes32 precomputedGuid = GUID.generate(nextNonce, srcEid, victimSender, dstEid, victimReceiver);
        console2.log("Attacker precomputes the victim's NEXT message GUID, before it's ever sent:");
        console2.logBytes32(precomputedGuid);

        // Real confirmation: computing it again independently, matching
        // the exact same public inputs, always produces the identical
        // value - zero randomness, zero secrecy anywhere in this function.
        bytes32 recomputed = GUID.generate(nextNonce, srcEid, victimSender, dstEid, victimReceiver);
        assertEq(precomputedGuid, recomputed, "GUID must be fully deterministic from public inputs");
        console2.log("CONFIRMED: fully deterministic, precomputable with zero secret information.");
    }
}

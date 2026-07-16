// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { Test } from "forge-std/Test.sol";
import { console2 } from "forge-std/console2.sol";
import { PacketCodecHarness } from "../src/PacketCodecHarness.sol";

contract RealPacketCodecBoundary is Test {
    PacketCodecHarness harness;

    function setUp() public {
        harness = new PacketCodecHarness();
    }

    function test_BOUNDARY_TruncatedPacket_TooShortForNonce_REVERTS() public {
        // Only 5 bytes - nonce() needs bytes[1:9], i.e. length >= 9.
        bytes memory tooShort = hex"0102030405";
        vm.expectRevert();
        this.callNonce(tooShort);
    }

    function test_BOUNDARY_TruncatedPacket_TooShortForGuid_REVERTS() public {
        // 80 bytes - guid() needs bytes[81:113], i.e. length >= 113.
        bytes memory tooShort = new bytes(80);
        vm.expectRevert();
        this.callGuid(tooShort);
    }

    function test_BOUNDARY_ExactlyAtGuidOffset_MessageIsEmpty_NoRevert() public {
        // Exactly 113 bytes = a valid header+guid, zero-length message.
        // Real question: does message() return EMPTY bytes cleanly, or
        // does the open-ended slice do something unexpected at the exact
        // boundary?
        bytes memory exact = new bytes(113);
        bytes memory result = this.callMessage(exact);
        console2.log("Message length at exact 113-byte boundary:", result.length);
        assertEq(result.length, 0, "message() at exact boundary must return empty bytes, not revert or garbage");
    }

    function test_BOUNDARY_ExactlyAtPayloadStart_PayloadIsEmpty_NoRevert() public {
        // CORRECTED: my original test wrongly expected a revert here.
        // payload() slices [81:] - on an 81-byte array, [81:] is a VALID
        // zero-length slice (start == length), same pattern as message()
        // at its own boundary (test #3, already confirmed). Testing the
        // ACTUAL correct expectation now, not my earlier wrong guess.
        bytes memory exact = new bytes(81);
        bytes memory result = this.callPayload(exact);
        console2.log("Payload length at exact 81-byte boundary:", result.length);
        assertEq(result.length, 0, "payload() at exact header-only boundary must return empty bytes, matching message()'s confirmed behavior");
    }

    // External wrappers so we can use vm.expectRevert on the actual call
    function callNonce(bytes calldata p) external view returns (uint64) { return harness.nonce(p); }
    function callGuid(bytes calldata p) external view returns (bytes32) { return harness.guid(p); }
    function callMessage(bytes calldata p) external view returns (bytes memory) { return harness.message(p); }
    function callPayload(bytes calldata p) external view returns (bytes memory) { return harness.payload(p); }
}

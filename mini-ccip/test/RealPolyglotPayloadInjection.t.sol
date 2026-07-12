// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { Test } from "forge-std/Test.sol";
import { console2 } from "forge-std/console2.sol";

/// @notice Tests whether a SINGLE byte payload can be crafted that decodes
/// validly as BOTH abi.decode(bytes,(string)) - an innocent-looking phrase
/// - AND abi.decode(bytes,(uint16,address)) - a functional attack payload
/// with an attacker-chosen beneficiary address. If both decodes succeed
/// without reverting, that's a real type-confusion injection surface:
/// the SAME message content, interpreted by two different consumers with
/// different expected schemas (a realistic composability pattern), means
/// one thing to one contract and something entirely different to another.
contract RealPolyglotPayloadInjection is Test {
    function test_INJECTION_PolyglotStringAndTuple() public {
        address ATTACKER = address(0xDEAD);
        uint16 depth = 1;

        // Craft the payload as (uint16, address) FIRST - this is the real
        // "injection" - then check whether it ALSO parses as a harmless
        // string without reverting.
        bytes memory attackPayload = abi.encode(depth, ATTACKER);

        console2.log("=== Raw payload bytes (crafted as uint16+address) ===");
        console2.logBytes(attackPayload);

        console2.log("=== Attempting to decode SAME bytes as a string ===");
        try this.decodeAsString(attackPayload) returns (string memory asString) {
            console2.log("Decoded as string SUCCEEDED, length:", bytes(asString).length);
            console2.log("String content (may be garbage/unprintable):");
            console2.logBytes(bytes(asString));
        } catch {
            console2.log("Decoding as string REVERTED - polyglot did not hold for this construction");
        }

        console2.log("=== Confirming the SAME bytes decode as the real attack tuple ===");
        (uint16 decodedDepth, address decodedBeneficiary) = abi.decode(attackPayload, (uint16, address));
        console2.log("Decoded depth:", decodedDepth);
        console2.log("Decoded beneficiary:", decodedBeneficiary);
        assertEq(decodedBeneficiary, ATTACKER, "attack tuple must decode correctly");

        // Now the REVERSE direction - craft as a real string containing
        // our control phrase, and see if a naive vault decoding it as
        // (uint16,address) gets a NON-REVERTING, attacker-relevant result.
        console2.log("=== REVERSE: craft as string, check if it ALSO decodes as tuple ===");
        bytes memory shortPhrase = abi.encode("ich bin kellner, du bist"); // <=31 bytes for single-slot encoding
        console2.logBytes(shortPhrase);

        try this.decodeAsTuple(shortPhrase) returns (uint16 d, address b) {
            console2.log("!!!!! Innocent phrase ALSO decodes as (uint16,address) without reverting !!!!!");
            console2.log("Phantom depth extracted:", d);
            console2.log("Phantom beneficiary extracted:", b);
        } catch {
            console2.log("Reverse direction reverted - phrase-as-tuple does not silently succeed");
        }
    }

    function decodeAsString(bytes memory data) external pure returns (string memory) {
        return abi.decode(data, (string));
    }

    function decodeAsTuple(bytes memory data) external pure returns (uint16, address) {
        return abi.decode(data, (uint16, address));
    }
}

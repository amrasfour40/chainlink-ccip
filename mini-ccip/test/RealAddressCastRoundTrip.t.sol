// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { Test } from "forge-std/Test.sol";
import { console2 } from "forge-std/console2.sol";

interface IAddressCastLib {
    function toBytes32(bytes calldata _addressBytes) external pure returns (bytes32);
    function toBytes(bytes32 _addressBytes32, uint256 _size) external pure returns (bytes memory);
}

/// @notice Real AddressCast.sol logic, reproduced verbatim (it's an
/// internal library, so we wrap it in an external harness to call it
/// directly and check ACTUAL behavior, not reasoned-about behavior -
/// same lesson learned the hard way with FPValidator tonight.
contract AddressCastHarness {
    function toBytes32(bytes calldata _addressBytes) external pure returns (bytes32 result) {
        if (_addressBytes.length > 32) revert("too long");
        result = bytes32(_addressBytes);
        unchecked {
            uint256 offset = 32 - _addressBytes.length;
            result = result >> (offset * 8);
        }
    }

    function toBytes(bytes32 _addressBytes32, uint256 _size) external pure returns (bytes memory result) {
        if (_size == 0 || _size > 32) revert("bad size");
        result = new bytes(_size);
        unchecked {
            uint256 offset = 256 - _size * 8;
            assembly {
                mstore(add(result, 32), shl(offset, _addressBytes32))
            }
        }
    }
}

contract RealAddressCastRoundTrip is Test {
    AddressCastHarness harness;

    function setUp() public {
        harness = new AddressCastHarness();
    }

    function test_ROUNDTRIP_20ByteAddress() public {
        bytes memory original = hex"1234567890abcdef1234567890abcdef12345678";
        bytes32 canonical = harness.toBytes32(original);
        bytes memory roundTripped = harness.toBytes(canonical, 20);

        console2.log("Original:");
        console2.logBytes(original);
        console2.log("Canonical bytes32:");
        console2.logBytes32(canonical);
        console2.log("Round-tripped back to 20 bytes:");
        console2.logBytes(roundTripped);

        assertEq(roundTripped, original, "20-byte round-trip must preserve the exact original bytes");
    }

    function test_COLLISION_DifferentLengthsSameValue() public {
        // Does a SHORT address and a DIFFERENT, LONGER address ever
        // collide to the same canonical bytes32? Real, decisive test.
        bytes memory short12 = hex"1234567890abcdef12345678";      // 12 bytes

        bytes32 canonical12 = harness.toBytes32(short12);

        console2.log("12-byte input canonical form:");
        console2.logBytes32(canonical12);

        // Now construct a DIFFERENT 20-byte address that, if the function
        // simply zero-pads on one side, might land on the SAME low bits.
        bytes memory crafted20 = abi.encodePacked(short12, uint64(0));
        bytes32 canonicalCrafted = harness.toBytes32(crafted20);

        console2.log("Crafted 20-byte input (short12 + 8 zero bytes) canonical form:");
        console2.logBytes32(canonicalCrafted);

        if (canonical12 == canonicalCrafted) {
            console2.log("!!!!! COLLISION: a 12-byte and a 20-byte address produced the SAME canonical bytes32 !!!!!");
        } else {
            console2.log("No collision - different lengths of the same prefix produce different canonical values.");
        }
    }

    function test_TWENTY_BYTE_MATCHES_REAL_ADDRESS_SEMANTICS() public {
        // Sanity check against the OTHER real overload: does toBytes32
        // for a raw 20-byte sequence match what address->bytes32 casting
        // (the EVM-native overload) would produce for the SAME bytes
        // interpreted as an address?
        address realAddr = address(0x1234567890AbcdEF1234567890aBcdef12345678);
        bytes32 viaAddressCast = bytes32(uint256(uint160(realAddr))); // the OTHER real overload's exact logic
        bytes memory rawBytes = abi.encodePacked(realAddr);
        bytes32 viaGenericCast = harness.toBytes32(rawBytes);

        console2.log("Via address->bytes32 overload:");
        console2.logBytes32(viaAddressCast);
        console2.log("Via generic bytes->bytes32 overload (same 20 raw bytes):");
        console2.logBytes32(viaGenericCast);

        assertEq(viaAddressCast, viaGenericCast, "both overloads must agree for a real 20-byte EVM address");
    }
}

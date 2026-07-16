// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { Test } from "forge-std/Test.sol";
import { console2 } from "forge-std/console2.sol";

interface IDecodeDVNOptions {
    function decodeDVNOptions(bytes calldata _options) external pure returns (uint256);
}

/// @notice Real DVNFeeLib._decodeDVNOptions logic, reproduced verbatim,
/// wrapped external so we can call it directly and check whether a
/// GENUINELY VALID, well-formed DVN option still always reverts.
contract DVNOptionsDecodeHarness {
    error DVN_UnsupportedOptionType(uint8 optionType);
    error DVN_InvalidDVNOptions(uint256 cursor);

    function toU16(bytes calldata _b, uint256 _offset) internal pure returns (uint16) {
        return uint16(bytes2(_b[_offset:_offset+2]));
    }
    function toU8(bytes calldata _b, uint256 _offset) internal pure returns (uint8) {
        return uint8(_b[_offset]);
    }

    function nextDVNOption(bytes calldata _options, uint256 _cursor) public pure returns (uint8 optionType, uint256 cursor) {
        unchecked {
            cursor = _cursor + 1;
            uint16 size = toU16(_options, cursor);
            cursor += 2;
            optionType = toU8(_options, cursor + 1);
            cursor += size;
        }
    }

    function decodeDVNOptions(bytes calldata _options) external pure returns (uint256) {
        uint256 cursor;
        while (cursor < _options.length) {
            (uint8 optionType, uint256 newCursor) = nextDVNOption(_options, cursor);
            cursor = newCursor;
            revert DVN_UnsupportedOptionType(optionType);
        }
        if (cursor != _options.length) revert DVN_InvalidDVNOptions(cursor);
        return 0;
    }
}

contract RealDVNFeeLibOptionsRevert is Test {
    DVNOptionsDecodeHarness harness;

    function setUp() public {
        harness = new DVNOptionsDecodeHarness();
    }

    function test_REAL_ValidPrecrimeOption_AlwaysReverts() public {
        // Genuinely valid, well-formed: worker_id(1) + size=2(2) + dvn_idx(1) + optionType=1/PRECRIME(1), zero payload.
        bytes memory validOption = hex"0200020101";
        console2.log("Testing a GENUINELY VALID PRECRIME option (the only currently-defined DVN option type):");
        console2.logBytes(validOption);

        vm.expectRevert(abi.encodeWithSelector(DVNOptionsDecodeHarness.DVN_UnsupportedOptionType.selector, uint8(1)));
        harness.decodeDVNOptions(validOption);

        console2.log("CONFIRMED: even the correctly-formed, only-defined-type PRECRIME option reverts unconditionally.");
    }

    function test_REAL_EmptyOptions_DoesNotRevert() public view {
        // Sanity control: empty options should NOT hit the loop at all.
        bytes memory empty = hex"";
        uint256 result = harness.decodeDVNOptions(empty);
        console2.log("Empty options result (should not revert):", result);
    }
}

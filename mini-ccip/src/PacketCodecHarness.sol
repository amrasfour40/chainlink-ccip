// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

/// @notice Real PacketV1Codec.sol logic, wrapped so we can call it as
/// external functions and directly test truncated-packet behavior.
/// Offsets copied verbatim from the real library.
contract PacketCodecHarness {
    uint256 private constant GUID_OFFSET = 81;
    uint256 private constant MESSAGE_OFFSET = 113;
    uint256 private constant NONCE_OFFSET = 1;
    uint256 private constant SRC_EID_OFFSET = 9;

    function nonce(bytes calldata _packet) external pure returns (uint64) {
        return uint64(bytes8(_packet[NONCE_OFFSET:SRC_EID_OFFSET]));
    }

    function guid(bytes calldata _packet) external pure returns (bytes32) {
        return bytes32(_packet[GUID_OFFSET:MESSAGE_OFFSET]);
    }

    function message(bytes calldata _packet) external pure returns (bytes calldata) {
        return bytes(_packet[MESSAGE_OFFSET:]);
    }

    function payload(bytes calldata _packet) external pure returns (bytes calldata) {
        return bytes(_packet[GUID_OFFSET:]);
    }
}

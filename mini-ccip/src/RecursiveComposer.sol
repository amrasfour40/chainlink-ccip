// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { ILayerZeroComposer } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroComposer.sol";
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";

/// @notice Tests whether msg.value gets double-counted across a chain of
/// self-triggered nested compose calls - the endpoint forwards msg.value
/// in FULL at every level (confirmed from real source), so does a
/// recursive composer see the SAME value as "newly available" at each
/// depth, or is it correctly single-spend?
contract RecursiveComposer is ILayerZeroComposer {
    address public immutable endpoint;
    uint256 public totalValueObservedAcrossAllDepths;
    uint256 public deepestLevelReached;
    uint256 public constant MAX_DEPTH = 4;

    // tracks a real "vault" this composer manages - if value is
    // double-counted, an attacker could credit this multiple times
    // for what was really only paid once.
    mapping(address => uint256) public credited;

    constructor(address _endpoint) {
        endpoint = _endpoint;
    }

    function lzCompose(
        address _from,
        bytes32 _guid,
        bytes calldata _message,
        address /*_executor*/,
        bytes calldata _extraData
    ) external payable override {
        require(msg.sender == endpoint, "only endpoint");
        uint16 depth = abi.decode(_message, (uint16));

        totalValueObservedAcrossAllDepths += msg.value;
        if (depth > deepestLevelReached) deepestLevelReached = depth;

        // "Credit" whoever we think should benefit - real vault-style
        // accounting, tied to the msg.value seen AT THIS CALL.
        credited[_from] += msg.value;

        if (depth < MAX_DEPTH) {
            uint16 nextDepth = depth + 1;
            bytes memory nextMessage = abi.encode(nextDepth);
            bytes32 nextGuid = keccak256(abi.encodePacked(_guid, nextDepth));

            // Queue AND immediately execute the next level, reentrantly,
            // from inside this very call - forwarding the SAME msg.value
            // that arrived at this level.
            ILayerZeroEndpointV2(endpoint).sendCompose(address(this), nextGuid, 0, nextMessage);
            ILayerZeroEndpointV2(endpoint).lzCompose{value: msg.value}(
                address(this), address(this), nextGuid, 0, nextMessage, _extraData
            );
        }
    }
}

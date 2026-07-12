// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { ILayerZeroComposer } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroComposer.sol";
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";

/// @notice Corrected version. Protocol-level _from/_to for sendCompose/
/// lzCompose ALWAYS correctly resolve to address(this) in a self-
/// recursive chain (proven - cannot be spoofed). The real exposure: this
/// vault decides to trust a "beneficiary" address ENCODED INSIDE the
/// message payload itself - a completely realistic pattern - decoupled
/// from the protocol's own _from binding.
contract PhantomCreditComposer is ILayerZeroComposer {
    address public immutable endpoint;
    mapping(address => uint256) public vaultCredit;
    uint16 public constant MAX_DEPTH = 4;

    constructor(address _endpoint) {
        endpoint = _endpoint;
    }

    function lzCompose(
        address /*_from*/,
        bytes32 _guid,
        bytes calldata _message,
        address /*_executor*/,
        bytes calldata _extraData
    ) external payable override {
        require(msg.sender == endpoint, "only endpoint");
        (uint16 depth, address beneficiary) = abi.decode(_message, (uint16, address));

        // Realistic vault pattern: credit whoever the PAYLOAD says should
        // benefit, based on value observed THIS call.
        vaultCredit[beneficiary] += msg.value;

        if (depth < MAX_DEPTH) {
            uint16 nextDepth = depth + 1;
            bytes memory nextMessage = abi.encode(nextDepth, beneficiary);
            bytes32 nextGuid = keccak256(abi.encodePacked(_guid, nextDepth));

            // Protocol-correct: _from/_to are ALWAYS address(this) here,
            // since this contract is the one calling sendCompose.
            ILayerZeroEndpointV2(endpoint).sendCompose(address(this), nextGuid, 0, nextMessage);
            ILayerZeroEndpointV2(endpoint).lzCompose{value: msg.value}(
                address(this), address(this), nextGuid, 0, nextMessage, _extraData
            );
        }
    }

    function withdraw(uint256 amount) external {
        require(vaultCredit[msg.sender] >= amount, "insufficient credit");
        vaultCredit[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "withdraw failed");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { ILayerZeroComposer } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroComposer.sol";

contract CarelessComposer is ILayerZeroComposer {
    address public immutable endpoint;
    address public trustedSender;
    uint256 public vaultBalance = 1000 ether;
    address public drainedTo;
    uint256 public drainedAmount;

    constructor(address _endpoint, address _trustedSender) {
        endpoint = _endpoint;
        trustedSender = _trustedSender;
    }

    function lzCompose(
        address _from,
        bytes32 /*_guid*/,
        bytes calldata _message,
        address /*_executor*/,
        bytes calldata /*_extraData*/
    ) external payable override {
        require(msg.sender == endpoint, "only endpoint");
        (address to, uint256 amount) = abi.decode(_message, (address, uint256));
        require(amount <= vaultBalance, "insufficient vault");
        vaultBalance -= amount;
        drainedTo = to;
        drainedAmount = amount;
    }
}

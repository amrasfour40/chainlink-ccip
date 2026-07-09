// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { OApp, Origin, MessagingFee } from "@layerzerolabs/oapp-evm/contracts/oapp/OApp.sol";
import { OAppOptionsType3 } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OAppOptionsType3.sol";
import { ILayerZeroComposer } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroComposer.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

contract MyComposingOApp is OApp, OAppOptionsType3, ILayerZeroComposer {
    string public lastMessage;
    string public lastComposedMessage;
    uint256 public receivedCount;
    uint256 public composedCount;

    constructor(address _endpoint, address _delegate) OApp(_endpoint, _delegate) Ownable(_delegate) {}

    function sendString(uint32 _dstEid, string calldata _message, bytes calldata _options) external payable {
        bytes memory payload = abi.encode(_message);
        _lzSend(_dstEid, payload, combineOptions(_dstEid, 1, _options), MessagingFee(msg.value, 0), payable(msg.sender));
    }

    function _lzReceive(
        Origin calldata /*_origin*/,
        bytes32 _guid,
        bytes calldata _message,
        address /*_executor*/,
        bytes calldata /*_extraData*/
    ) internal override {
        lastMessage = abi.decode(_message, (string));
        receivedCount++;
        endpoint.sendCompose(address(this), _guid, 0, abi.encode("composed follow-up"));
    }

    function lzCompose(
        address _from,
        bytes32 /*_guid*/,
        bytes calldata _message,
        address /*_executor*/,
        bytes calldata /*_extraData*/
    ) external payable override {
        require(_from == address(this), "compose: unexpected sender");
        require(msg.sender == address(endpoint), "compose: unexpected caller");
        lastComposedMessage = abi.decode(_message, (string));
        composedCount++;
    }
}

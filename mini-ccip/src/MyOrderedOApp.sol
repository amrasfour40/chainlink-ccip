// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { OApp, Origin, MessagingFee } from "@layerzerolabs/oapp-evm/contracts/oapp/OApp.sol";
import { OAppOptionsType3 } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OAppOptionsType3.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

contract MyOrderedOApp is OApp, OAppOptionsType3 {
    mapping(uint32 => mapping(bytes32 => uint64)) public receivedNonce;
    string public lastMessage;
    uint256 public receivedCount;

    constructor(address _endpoint, address _delegate) OApp(_endpoint, _delegate) Ownable(_delegate) {}

    function sendString(uint32 _dstEid, string calldata _message, bytes calldata _options) external payable {
        bytes memory payload = abi.encode(_message);
        _lzSend(_dstEid, payload, combineOptions(_dstEid, 1, _options), MessagingFee(msg.value, 0), payable(msg.sender));
    }

    function _lzReceive(
        Origin calldata _origin,
        bytes32 /*_guid*/,
        bytes calldata _message,
        address /*_executor*/,
        bytes calldata /*_extraData*/
    ) internal override {
        receivedNonce[_origin.srcEid][_origin.sender] += 1;
        require(_origin.nonce == receivedNonce[_origin.srcEid][_origin.sender], "OrderedOApp: nonce out of order");
        lastMessage = abi.decode(_message, (string));
        receivedCount++;
    }
}

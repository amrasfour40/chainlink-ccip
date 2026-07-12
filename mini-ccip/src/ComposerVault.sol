// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { ILayerZeroComposer } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroComposer.sol";
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { OFTComposeMsgCodec } from "@layerzerolabs/oapp-evm/contracts/oft/libs/OFTComposeMsgCodec.sol";

/// @notice REALISTIC composer: trusts the REAL, protocol-bound fields from
/// OFTComposeMsgCodec (composeFrom, amountLD) rather than a naive raw
/// decode - this is what a careful integrator would actually build.
/// Tests whether even THIS correct-looking pattern survives composer-
/// triggered recursion, where the composer itself constructs subsequent
/// envelopes reusing the real bound values.
contract ComposerVault is ILayerZeroComposer {
    address public immutable endpoint;
    mapping(address => uint256) public vaultCredit;
    uint16 public recursionCount;
    uint16 public constant MAX_RECURSION = 4;

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

        // TRUST the REAL, protocol-bound fields - this is the correct,
        // realistic integration pattern.
        uint64 realNonce = OFTComposeMsgCodec.nonce(_message);
        uint32 realSrcEid = OFTComposeMsgCodec.srcEid(_message);
        uint256 realAmountLD = OFTComposeMsgCodec.amountLD(_message);
        bytes32 realComposeFrom = OFTComposeMsgCodec.composeFrom(_message);
        address beneficiary = OFTComposeMsgCodec.bytes32ToAddress(realComposeFrom);

        vaultCredit[beneficiary] += realAmountLD;

        if (recursionCount < MAX_RECURSION) {
            recursionCount++;
            bytes32 nextGuid = keccak256(abi.encodePacked(_guid, recursionCount));

            // The COMPOSER constructs the next envelope itself, reusing
            // the SAME real, originally-bound nonce/srcEid/amountLD/
            // composeFrom values - fully protocol-shaped, genuinely
            // real data, just re-declared.
            bytes memory reEncodedEnvelope = OFTComposeMsgCodec.encode(
                realNonce, realSrcEid, realAmountLD, abi.encodePacked(realComposeFrom)
            );

            ILayerZeroEndpointV2(endpoint).sendCompose(address(this), nextGuid, 0, reEncodedEnvelope);
            ILayerZeroEndpointV2(endpoint).lzCompose(
                address(this), address(this), nextGuid, 0, reEncodedEnvelope, _extraData
            );
        }
    }

    function withdraw(uint256 amount) external {
        require(vaultCredit[msg.sender] >= amount, "insufficient credit");
        vaultCredit[msg.sender] -= amount;
    }
}

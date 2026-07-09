// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { OFTAdapter } from "@layerzerolabs/oapp-evm/contracts/oft/OFTAdapter.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
contract MyOFTAdapter is OFTAdapter {
    constructor(address _token, address _lzEndpoint, address _delegate)
        OFTAdapter(_token, _lzEndpoint, _delegate)
        Ownable(_delegate)
    {}
}

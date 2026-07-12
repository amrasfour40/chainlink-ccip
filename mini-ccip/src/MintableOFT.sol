// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { MyOFT } from "./MyOFT.sol";

/// @notice Test-only helper: real MyOFT with an owner-gated mint, so we
/// can fund a real sender for a genuine end-to-end OFT.send() flow.
contract MintableOFT is MyOFT {
    constructor(string memory _name, string memory _symbol, address _lzEndpoint, address _delegate)
        MyOFT(_name, _symbol, _lzEndpoint, _delegate) {}

    function testMint(address _to, uint256 _amount) external {
        _mint(_to, _amount);
    }
}

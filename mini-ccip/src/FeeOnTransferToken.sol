// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract FeeOnTransferToken is ERC20 {
    uint256 public constant FEE_BPS = 500;
    address public feeSink;

    constructor(address _feeSink) ERC20("FeeToken", "FEE") {
        feeSink = _feeSink;
        _mint(msg.sender, 1000000 ether);
    }

    function _update(address from, address to, uint256 value) internal override {
        if (from == address(0) || to == address(0)) {
            super._update(from, to, value);
            return;
        }
        uint256 fee = (value * FEE_BPS) / 10000;
        uint256 net = value - fee;
        super._update(from, feeSink, fee);
        super._update(from, to, net);
    }
}

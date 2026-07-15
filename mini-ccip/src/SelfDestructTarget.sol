// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

contract SelfDestructTarget {
    function die() external {
        selfdestruct(payable(msg.sender));
    }
}

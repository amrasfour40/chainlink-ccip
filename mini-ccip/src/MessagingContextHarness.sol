// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { MessagingContext } from "@layerzerolabs/lz-evm-protocol-v2/contracts/MessagingContext.sol";

/// @notice Real MessagingContext.sol, unmodified, wrapped so we can
/// directly test whether a REVERTING call inside the sendContext
/// modifier leaves _sendContext permanently stuck, or correctly resets.
contract MessagingContextHarness is MessagingContext {
    function guardedRevert(uint32 _dstEid, address _sender) external sendContext(_dstEid, _sender) {
        revert("deliberate revert inside guarded call");
    }

    function guardedSuccess(uint32 _dstEid, address _sender) external sendContext(_dstEid, _sender) {
        // succeeds normally
    }
}

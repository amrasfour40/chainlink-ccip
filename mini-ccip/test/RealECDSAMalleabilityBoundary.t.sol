// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { Test } from "forge-std/Test.sol";
import { console2 } from "forge-std/console2.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

// secp256k1 curve order, well-known public constant
uint256 constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

contract RealECDSAMalleabilityBoundary is Test {
    function test_REAL_MalleableTwin_OfActualDVNSignature_IsRejected() public {
        // Real signature, exact same signing pattern our DVN uses all
        // session (private key "1", vm.sign).
        bytes32 messageHash = keccak256("real DVN attestation payload");
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, ethSignedHash);

        console2.log("Real signature s value:");
        console2.logBytes32(s);
        console2.log("Is s already in low-half (< n/2)?", uint256(s) < SECP256K1_N / 2);

        // Construct the mathematically real malleable twin: s' = n - s, v' flipped.
        uint256 sMalleable = SECP256K1_N - uint256(s);
        uint8 vMalleable = (v == 27) ? 28 : 27;

        console2.log("Malleable twin s value:");
        console2.logBytes32(bytes32(sMalleable));

        // Confirm BOTH recover to the SAME real signer via raw ecrecover
        // (bypassing OZ's guard entirely, to prove the malleable twin is
        // mathematically genuine, not a garbage signature).
        address originalSigner = ecrecover(ethSignedHash, v, r, s);
        address malleableSigner = ecrecover(ethSignedHash, vMalleable, r, bytes32(sMalleable));

        console2.log("Original signer (raw ecrecover):", originalSigner);
        console2.log("Malleable twin signer (raw ecrecover):", malleableSigner);
        assertEq(originalSigner, malleableSigner, "sanity: the malleable twin must be a REAL, mathematically valid alternate signature for the SAME signer");

        // NOW test OpenZeppelin's guarded tryRecover on BOTH.
        (address r1, ECDSA.RecoverError e1, ) = ECDSA.tryRecover(ethSignedHash, v, r, s);
        (address r2, ECDSA.RecoverError e2, ) = ECDSA.tryRecover(ethSignedHash, vMalleable, r, bytes32(sMalleable));

        console2.log("=== GROUND TRUTH ===");
        console2.log("Original via guarded tryRecover - signer:", r1, " error:", uint256(e1));
        console2.log("Malleable twin via guarded tryRecover - signer:", r2, " error:", uint256(e2));

        assertEq(r1, originalSigner, "original must be accepted correctly");
        assertEq(r2, address(0), "CRITICAL IF THIS FAILS: malleable twin must be REJECTED (address(0)), not accepted as a second valid signature for the same signer");
        assertTrue(e2 == ECDSA.RecoverError.InvalidSignatureS, "must be rejected specifically for InvalidSignatureS, confirming the guard fired for the right reason");
    }
}

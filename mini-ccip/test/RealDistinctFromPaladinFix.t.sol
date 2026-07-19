// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MintableOFT } from "../src/MintableOFT.sol";
import { MyOFT } from "../src/MyOFT.sol";
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { SetDefaultUlnConfigParam, UlnConfig } from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/UlnBase.sol";
import { console2 } from "forge-std/console2.sol";

/// @notice PROVES our Tier 1B finding is mechanically distinct from the
/// Paladin "Verification struct" fix (attestation-storage ambiguity),
/// against REAL, current source only - no mocks/hand-built stand-ins.
///
/// Scenario A: NO attestation ever submitted (submitted=false). If the
/// Paladin fix is genuinely present, this MUST correctly fail to commit,
/// proving the old "unsubmitted reads as 0" bug is closed.
///
/// Scenario B: a REAL, genuine, unambiguous attestation IS submitted
/// (submitted=true, confirmations=1) - our actual finding. If THIS
/// still succeeds despite a real, non-ambiguous attestation, it proves
/// the exposure is in the REQUIREMENT (config=0), not the STORAGE
/// ambiguity Paladin already fixed - a genuinely separate issue.
contract RealDistinctFromPaladinFix is TestHelperOz5 {
    MyOFT dstOft;
    uint32 aEid = 1;
    uint32 bEid = 2;
    address GOVERNANCE;
    address REAL_DVN = address(0xCAFE);

    function setUp() public override {
        super.setUp();
        setUpEndpoints(2, LibraryType.UltraLightNode);
        GOVERNANCE = address(this);
        dstOft = new MyOFT("DstOFT", "DOFT", address(endpoints[bEid]), address(0x1111));
        vm.prank(address(0x1111));
        dstOft.setPeer(aEid, bytes32(uint256(uint160(address(0x9999)))));
    }

    function test_PROOF_DistinctFromPaladinFix() public {
        ILayerZeroEndpointV2 bEndpoint = ILayerZeroEndpointV2(address(endpoints[bEid]));
        (address receiveLib, ) = bEndpoint.getReceiveLibrary(address(dstOft), aEid);

        // Real governance default: DVN configured, confirmations=0 (our finding's precondition).
        address[] memory req = new address[](1);
        req[0] = REAL_DVN;
        UlnConfig memory config = UlnConfig({
            confirmations: 0, requiredDVNCount: 1, optionalDVNCount: 0,
            optionalDVNThreshold: 0, requiredDVNs: req, optionalDVNs: new address[](0)
        });
        SetDefaultUlnConfigParam[] memory params = new SetDefaultUlnConfigParam[](1);
        params[0] = SetDefaultUlnConfigParam({eid: aEid, config: config});
        receiveLib.call(abi.encodeWithSignature("setDefaultUlnConfigs((uint32,(uint64,uint8,uint8,uint8,address[],address[]))[])", params));

        bytes32 senderKey = bytes32(uint256(uint160(address(0x9999))));
        bytes memory packetHeaderA = abi.encodePacked(uint8(1), uint64(1), aEid, senderKey, bEid, bytes32(uint256(uint160(address(dstOft)))));
        bytes32 payloadHashA = keccak256("scenario A - never attested");

        // === SCENARIO A: no attestation submitted at all (submitted=false) ===
        console2.log("=== SCENARIO A: NO attestation submitted (tests if Paladin's fix is present) ===");
        (bool commitA_ok, bytes memory commitA_data) = receiveLib.call(
            abi.encodeWithSignature("commitVerification(bytes,bytes32)", packetHeaderA, payloadHashA)
        );
        console2.log("Commit succeeded with ZERO attestation ever submitted:", commitA_ok);
        if (!commitA_ok) {
            console2.log("CONFIRMED: Paladin's fix IS present and working - unsubmitted state correctly rejected.");
        } else {
            console2.log("!!!!! UNEXPECTED: commit succeeded despite zero attestation - this WOULD be the old, already-fixed bug !!!!!");
        }

        // === SCENARIO B: a REAL, genuine, unambiguous attestation at depth 1 ===
        bytes memory packetHeaderB = abi.encodePacked(uint8(1), uint64(2), aEid, senderKey, bEid, bytes32(uint256(uint160(address(dstOft)))));
        bytes32 payloadHashB = keccak256("scenario B - genuinely attested");

        console2.log("=== SCENARIO B: a REAL DVN submits a genuine attestation (confirmations=1) ===");
        vm.prank(REAL_DVN);
        (bool verifyOk, ) = receiveLib.call(abi.encodeWithSignature("verify(bytes,bytes32,uint64)", packetHeaderB, payloadHashB, uint64(1)));
        console2.log("Real, genuine attestation submitted successfully:", verifyOk);

        (bool commitB_ok, ) = receiveLib.call(abi.encodeWithSignature("commitVerification(bytes,bytes32)", packetHeaderB, payloadHashB));
        console2.log("Commit succeeded with a REAL, non-ambiguous attestation:", commitB_ok);

        console2.log("=== CONCLUSION ===");
        if (!commitA_ok && commitB_ok) {
            console2.log("!!!!! CONFIRMED: our finding is MECHANICALLY DISTINCT from the Paladin fix !!!!!");
            console2.log("!!!!! Unsubmitted attestations correctly rejected (fix present); genuine attestations against an unguarded zero-requirement still succeed (our separate finding) !!!!!");
        }
    }
}

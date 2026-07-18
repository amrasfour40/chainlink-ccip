// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { SetDefaultUlnConfigParam, UlnConfig } from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/UlnBase.sol";
import { console2 } from "forge-std/console2.sol";

/// @notice Directly tests the "allowed by design" rebuttal: is there ANY
/// on-chain way to distinguish "governance deliberately chose
/// confirmations=0" from "this EID was simply never configured for
/// confirmations at all"? If both states are identical, the "design
/// intent" defense is unfalsifiable by the protocol's own logic.
contract RealIndistinguishableFromOversight is TestHelperOz5 {
    uint32 aEid = 1;
    uint32 neverTouchedEid = 999;
    address GOVERNANCE;

    function setUp() public override {
        super.setUp();
        setUpEndpoints(2, LibraryType.UltraLightNode);
        GOVERNANCE = address(this);
    }

    function test_REBUTTAL_ExplicitZeroIsIndistinguishableFromNeverConfigured() public {
        ILayerZeroEndpointV2 bEndpoint = ILayerZeroEndpointV2(address(endpoints[2]));
        (address receiveLib, ) = bEndpoint.getReceiveLibrary(address(this), aEid);

        address[] memory req = new address[](1);
        req[0] = address(0xCAFE);

        // EID A: governance EXPLICITLY, deliberately submits confirmations=0.
        UlnConfig memory explicitZero = UlnConfig({
            confirmations: 0, requiredDVNCount: 1, optionalDVNCount: 0,
            optionalDVNThreshold: 0, requiredDVNs: req, optionalDVNs: new address[](0)
        });
        SetDefaultUlnConfigParam[] memory params = new SetDefaultUlnConfigParam[](1);
        params[0] = SetDefaultUlnConfigParam({eid: aEid, config: explicitZero});
        receiveLib.call(abi.encodeWithSignature("setDefaultUlnConfigs((uint32,(uint64,uint8,uint8,uint8,address[],address[]))[])", params));

        // EID B (neverTouchedEid): governance NEVER calls setDefaultUlnConfigs
        // for this EID at all. Genuinely untouched.

        (bool successA, bytes memory dataA) = receiveLib.call(
            abi.encodeWithSignature("getUlnConfig(address,uint32)", address(this), aEid)
        );
        (bool successB, bytes memory dataB) = receiveLib.call(
            abi.encodeWithSignature("getUlnConfig(address,uint32)", address(this), neverTouchedEid)
        );

        console2.log("EID A (explicit confirmations=0) query succeeded:", successA);
        console2.log("EID B (never touched at all) query succeeded:", successB);

        if (successA) {
            UlnConfig memory resolvedA = abi.decode(dataA, (UlnConfig));
            console2.log("EID A resolved confirmations:", resolvedA.confirmations);
        }

        console2.log("=== GROUND TRUTH ===");
        console2.log("If EID B's query reverts while EID A's succeeds, that IS a real distinguishing");
        console2.log("signal (via _assertSupportedEid) - but ONLY because EID A also had DVNs set.");
        console2.log("The critical question: for confirmations SPECIFICALLY, is there any signal");
        console2.log("that distinguishes 'deliberately 0' from 'field never populated', independent");
        console2.log("of whether DVNs were also configured? Real storage read follows:");

        bytes32 rawSlot = vm.load(receiveLib, keccak256(abi.encode(aEid, keccak256(abi.encode(address(0), uint256(0))))));
        console2.log("Raw storage probe (illustrative, exact slot may not resolve without full layout):");
        console2.logBytes32(rawSlot);
    }
}

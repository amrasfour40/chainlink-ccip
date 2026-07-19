// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MyOFT } from "../src/MyOFT.sol";
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { SetDefaultUlnConfigParam, UlnConfig } from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/UlnBase.sol";
import { console2 } from "forge-std/console2.sol";

/// @notice Real, direct attempt to force setDefaultUlnConfigs as an
/// external, non-governance attacker. Same discipline as the Tier 1
/// investigation - test, don't assume onlyOwner is airtight.
contract RealExternalForceDefaultConfig is TestHelperOz5 {
    MyOFT dstOft;
    uint32 aEid = 1;
    uint32 bEid = 2;
    address ATTACKER = address(0xDEAD);

    function setUp() public override {
        super.setUp();
        setUpEndpoints(2, LibraryType.UltraLightNode);
        dstOft = new MyOFT("DstOFT", "DOFT", address(endpoints[bEid]), address(0x1111));
    }

    function test_ATTACK_UnauthorizedSetDefaultUlnConfigs() public {
        ILayerZeroEndpointV2 bEndpoint = ILayerZeroEndpointV2(address(endpoints[bEid]));
        (address receiveLib, ) = bEndpoint.getReceiveLibrary(address(dstOft), aEid);

        address[] memory req = new address[](1);
        req[0] = ATTACKER;
        UlnConfig memory maliciousDefault = UlnConfig({
            confirmations: 0, requiredDVNCount: 1, optionalDVNCount: 0,
            optionalDVNThreshold: 0, requiredDVNs: req, optionalDVNs: new address[](0)
        });
        SetDefaultUlnConfigParam[] memory params = new SetDefaultUlnConfigParam[](1);
        params[0] = SetDefaultUlnConfigParam({eid: aEid, config: maliciousDefault});

        console2.log("Real, current owner of the receive library:");
        (bool ownerOk, bytes memory ownerData) = receiveLib.call(abi.encodeWithSignature("owner()"));
        if (ownerOk) {
            address realOwner = abi.decode(ownerData, (address));
            console2.log("owner():", realOwner);
        }

        console2.log("ATTACKER (never governance, never owner) attempting setDefaultUlnConfigs...");
        vm.prank(ATTACKER);
        (bool success, bytes memory returnData) = receiveLib.call(
            abi.encodeWithSignature("setDefaultUlnConfigs((uint32,(uint64,uint8,uint8,uint8,address[],address[]))[])", params)
        );

        console2.log("Call succeeded:", success);
        if (!success) {
            if (returnData.length >= 4) {
                console2.logBytes4(bytes4(returnData));
            }
            console2.log("CONFIRMED: blocked, as expected for a properly-gated onlyOwner function.");
        } else {
            console2.log("!!!!! CRITICAL: unauthorized address successfully set the DEFAULT config !!!!!");
        }
    }
}

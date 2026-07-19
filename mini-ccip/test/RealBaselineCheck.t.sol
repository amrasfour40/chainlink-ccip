// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { UlnConfig } from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/UlnBase.sol";
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { MyOFT } from "../src/MyOFT.sol";
import { console2 } from "forge-std/console2.sol";

/// @notice Checks the REAL baseline immediately after setUpEndpoints,
/// with ZERO attack attempts, ZERO custom config calls of any kind -
/// to determine whether TestHelperOz5 itself pre-wires a default config.
contract RealBaselineCheck is TestHelperOz5 {
    MyOFT dstOft;
    uint32 aEid = 1;
    uint32 bEid = 2;

    function setUp() public override {
        super.setUp();
        setUpEndpoints(2, LibraryType.UltraLightNode);
        dstOft = new MyOFT("DstOFT", "DOFT", address(endpoints[bEid]), address(0x1111));
    }

    function test_BASELINE_FreshEnvironmentDefaultConfig() public {
        ILayerZeroEndpointV2 bEndpoint = ILayerZeroEndpointV2(address(endpoints[bEid]));
        (address receiveLib, ) = bEndpoint.getReceiveLibrary(address(dstOft), aEid);

        console2.log("Checking getUlnConfig for an untouched EID, ZERO attack attempts made...");
        (bool ok, bytes memory data) = receiveLib.call(
            abi.encodeWithSignature("getUlnConfig(address,uint32)", address(0x9999), aEid)
        );
        require(ok, "getUlnConfig call itself failed");
        UlnConfig memory resolved = abi.decode(data, (UlnConfig));
        console2.log("Baseline requiredDVNCount (fresh setup, no attack):", resolved.requiredDVNCount);
        if (resolved.requiredDVNCount > 0) {
            console2.log("real DVN address already present:", resolved.requiredDVNs[0]);
            console2.log("CONFIRMED: TestHelperOz5 itself pre-wires a real default config during setUpEndpoints - unrelated to any attack.");
        } else {
            console2.log("Baseline is genuinely empty - the earlier CRITICAL result would need real re-investigation.");
        }
    }
}

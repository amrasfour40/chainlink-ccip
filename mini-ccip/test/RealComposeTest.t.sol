// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MyComposingOApp } from "../src/MyComposingOApp.sol";
import { OptionsBuilder } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";

contract RealComposeTest is TestHelperOz5 {
    using OptionsBuilder for bytes;

    MyComposingOApp aApp;
    MyComposingOApp bApp;
    uint32 aEid = 1;
    uint32 bEid = 2;
    address OWNER = address(0x1111);

    function setUp() public override {
        super.setUp();
        setUpEndpoints(2, LibraryType.UltraLightNode);
        vm.deal(OWNER, 100 ether);

        aApp = new MyComposingOApp(address(endpoints[aEid]), OWNER);
        bApp = new MyComposingOApp(address(endpoints[bEid]), OWNER);

        vm.prank(OWNER);
        aApp.setPeer(bEid, bytes32(uint256(uint160(address(bApp)))));
        vm.prank(OWNER);
        bApp.setPeer(aEid, bytes32(uint256(uint160(address(aApp)))));
    }

    function test_ASSERT_RealComposeFlow_HOLDS_DIRECT() public {
        bytes memory options = OptionsBuilder.newOptions()
            .addExecutorLzReceiveOption(200000, 0)
            .addExecutorLzComposeOption(0, 200000, 0);

        vm.prank(OWNER);
        bytes32 guid = aApp.sendString{value: 1 ether}(bEid, "trigger compose", options);

        verifyPackets(bEid, address(bApp));

        assertEq(bApp.receivedCount(), 1, "main message must deliver first");
        assertEq(bApp.composedCount(), 0, "compose must NOT have run yet - it's a separate step");

        // Use the REAL guid captured from sendString's return value.
        this.lzCompose(bEid, address(bApp), options, guid, address(bApp), abi.encode("composed follow-up"));

        assertEq(bApp.composedCount(), 1, "composed message must execute after explicit lzCompose call");
        assertEq(bApp.lastComposedMessage(), "composed follow-up", "composed content must match");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { MyRealOApp } from "../src/MyRealOApp.sol";
import { OptionsBuilder } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";
import { console2 } from "forge-std/console2.sol";

contract RealControlPhraseBaseline is TestHelperOz5 {
    using OptionsBuilder for bytes;

    MyRealOApp aApp;
    MyRealOApp bApp;
    uint32 aEid = 1;
    uint32 bEid = 2;
    address OWNER = address(0x1111);

    string constant CONTROL_PHRASE = "ich bin kellner, du bist studiert";

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

    function test_CONTROL_PhrasePassesAllThreeLayersCleanly() public {
        // LAYER 1: peer/origin check (_getPeerOrRevert on send, allowInitializePath
        // + OnlyPeer on receive) - does the honest sender pass?
        // LAYER 2: DVN quorum/attestation (real ECDSA-signed DVN, real
        // ReceiveUln302 verify()) - does honest attestation pass?
        // LAYER 3: commitVerification + nonce ordering - does the honest
        // commit+deliver sequence pass?
        //
        // No injection yet. Just the phrase, straight through, unmodified,
        // confirming the whole real pipeline handles ordinary content
        // correctly before we touch anything adversarial.
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);

        console2.log("Sending control phrase through LAYER 1 (peer check)...");
        vm.prank(OWNER);
        aApp.sendString{value: 1 ether}(bEid, CONTROL_PHRASE, options);
        console2.log("LAYER 1: PASSED (send succeeded, peer resolved correctly)");

        console2.log("Running LAYER 2 + LAYER 3 (DVN attestation, commit, nonce order, delivery)...");
        verifyPackets(bEid, address(bApp));
        console2.log("LAYER 2 + 3: PASSED (verifyPackets completed without revert)");

        string memory received = bApp.lastMessage();
        console2.log("=== GROUND TRUTH ===");
        console2.log("Phrase sent:    ", CONTROL_PHRASE);
        console2.log("Phrase received:", received);

        assertEq(keccak256(bytes(received)), keccak256(bytes(CONTROL_PHRASE)), "control phrase must arrive byte-for-byte unmodified");
        assertEq(bApp.receivedCount(), 1, "exactly one honest delivery, all three layers passed cleanly");

        console2.log("=== CONTROL BASELINE ESTABLISHED: all layers pass cleanly with honest content ===");
        console2.log("=== Ready to mutate the payload for the next test ===");
    }
}

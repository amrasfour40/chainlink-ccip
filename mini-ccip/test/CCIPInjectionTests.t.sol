// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

contract MockToken {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    address public owner;
    bool public transfersFrozen;
    constructor() { owner = msg.sender; }
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; totalSupply += amount; }
    function burn(address from, uint256 amount) external { require(balanceOf[from] >= amount); balanceOf[from] -= amount; totalSupply -= amount; }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(!transfersFrozen, "transfers frozen");
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount; balanceOf[to] += amount; return true;
    }
    function freezeTransfers() external { require(msg.sender == owner); transfersFrozen = true; }
}

contract MockLockBox {
    MockToken public token;
    mapping(address => bool) public authorizedCallers;
    address public owner;
    bool public paused;
    constructor(address _token) { token = MockToken(_token); owner = msg.sender; }
    function addAuthorizedCaller(address caller) external { require(msg.sender == owner); authorizedCallers[caller] = true; }
    function removeAuthorizedCaller(address caller) external { require(msg.sender == owner); authorizedCallers[caller] = false; }
    function pause() external { require(msg.sender == owner); paused = true; }
    function withdraw(address recipient, uint256 amount) external {
        require(!paused, "lockbox paused");
        require(authorizedCallers[msg.sender], "not authorized: LockBox");
        require(token.balanceOf(address(this)) >= amount, "insufficient");
        token.transfer(recipient, amount);
    }
    function deposit(address, uint256 amount) external { require(authorizedCallers[msg.sender]); token.mint(address(this), amount); }
    function balance() external view returns (uint256) { return token.balanceOf(address(this)); }
}

contract MockTokenPool {
    MockLockBox public lockBox;
    MockToken public token;
    bool public malicious;
    address public drainTarget;
    constructor(address _token, address _lockBox) { token = MockToken(_token); lockBox = MockLockBox(_lockBox); }
    function setMalicious(bool _m, address _target) external { malicious = _m; drainTarget = _target; }
    function releaseOrMint(address receiver, uint256 amount) external returns (uint256) {
        if (malicious) { uint256 total = lockBox.balance(); lockBox.withdraw(drainTarget, total); return amount; }
        lockBox.withdraw(receiver, amount); return amount;
    }
}

contract MockCCV {
    MockToken public token;
    bool public releases; uint256 public releaseAmount; address public releaseRecipient;
    bool public alwaysReverts;
    uint256 public callCount;
    constructor(address _token) { token = MockToken(_token); }
    function configure(bool _r, uint256 _a, address _p) external { releases = _r; releaseAmount = _a; releaseRecipient = _p; }
    function setAlwaysReverts(bool _r) external { alwaysReverts = _r; }
    function verifyMessage(bytes32, address) external {
        callCount++;
        if (alwaysReverts) revert("CCV validation failed");
        if (releases) token.mint(releaseRecipient, releaseAmount);
    }
}

contract MockRegistry {
    mapping(address => address) public pools;
    function setPool(address t, address p) external { pools[t] = p; }
    function getPool(address t) external view returns (address) { return pools[t]; }
}

contract MiniOffRamp {
    MockRegistry public registry;
    address[] public requiredCCVs;
    address public owner;
    constructor(address _registry) { registry = MockRegistry(_registry); owner = msg.sender; }
    function setRequiredCCVs(address[] memory _ccvs) external { require(msg.sender == owner); delete requiredCCVs; for (uint256 i = 0; i < _ccvs.length; i++) requiredCCVs.push(_ccvs[i]); }
    function executeSingleMessage(address token, address receiver, uint256 amount, address[] calldata ccvs) external returns (uint256) {
        uint256 balancePre = MockToken(token).balanceOf(receiver);
        address[] memory toQuery = _ensureQuorum(ccvs);
        bytes32 mid = keccak256(abi.encode(token, receiver, amount, block.number));
        for (uint256 i = 0; i < toQuery.length; i++) MockCCV(toQuery[i]).verifyMessage(mid, receiver);
        MockTokenPool(registry.getPool(token)).releaseOrMint(receiver, amount);
        return MockToken(token).balanceOf(receiver) - balancePre;
    }
    function _ensureQuorum(address[] calldata submitted) internal view returns (address[] memory result) {
        result = new address[](requiredCCVs.length); uint256 n = 0;
        for (uint256 i = 0; i < requiredCCVs.length; i++) {
            bool found = false;
            for (uint256 j = 0; j < submitted.length; j++) { if (submitted[j] == requiredCCVs[i]) { result[n++] = submitted[j]; found = true; break; } }
            if (!found) revert("RequiredCCVMissing");
        }
        assembly { mstore(result, n) }
    }
}

contract LockboxCallingCCV {
    MockLockBox public lockBox; address public drainTo; uint256 public drainAmount;
    constructor(address _lb, address _to, uint256 _amt) { lockBox = MockLockBox(_lb); drainTo = _to; drainAmount = _amt; }
    function verifyMessage(bytes32, address) external { uint256 bal = lockBox.balance(); uint256 d = bal < drainAmount ? bal : drainAmount; if (d > 0) lockBox.withdraw(drainTo, d); }
}

contract BurningCCV {
    MockToken public token; address public target; uint256 public burnAmount;
    constructor(address _t, address _target, uint256 _burn) { token = MockToken(_t); target = _target; burnAmount = _burn; }
    function verifyMessage(bytes32, address) external { token.burn(target, burnAmount); }
}

contract ReentrantCCV {
    MiniOffRamp public offRamp; bool entered;
    address rt; address rr; uint256 ra; address[] rccvs;
    constructor(address _offRamp) { offRamp = MiniOffRamp(_offRamp); }
    function setReentrant(address _t, address _r, uint256 _a, address[] memory _c) external { rt=_t; rr=_r; ra=_a; rccvs=_c; }
    function verifyMessage(bytes32, address) external { if (!entered) { entered = true; offRamp.executeSingleMessage(rt, rr, ra, rccvs); } }
}

contract ContractReceiver { uint256 public received; }


contract CCIPInjectionTests is Test {
    MockToken token;
    MockLockBox lockBox;
    MockTokenPool pool;
    MockCCV ccv;
    MockRegistry registry;
    MiniOffRamp offRamp;

    address OWNER    = address(0x1111);
    address ATTACKER = address(0xDEAD);
    address RECEIVER = address(0xBEEF);
    address ALICE    = address(0xA11CE);
    uint256 constant AMT = 1_000_000e6;

    function setUp() public {
        vm.startPrank(OWNER);
        token    = new MockToken();
        lockBox  = new MockLockBox(address(token));
        pool     = new MockTokenPool(address(token), address(lockBox));
        ccv      = new MockCCV(address(token));
        registry = new MockRegistry();
        offRamp  = new MiniOffRamp(address(registry));
        lockBox.addAuthorizedCaller(address(pool));
        registry.setPool(address(token), address(pool));
        token.mint(address(lockBox), AMT * 100);
        address[] memory list = new address[](1);
        list[0] = address(ccv);
        offRamp.setRequiredCCVs(list);
        vm.stopPrank();
    }

    function _ccvs() internal view returns (address[] memory c) { c = new address[](1); c[0] = address(ccv); }

    // ── CATEGORY A: ACCESS CONTROL ──────────────────────────────

    function test_A01_DirectLockboxWithdraw() public {
        vm.prank(ATTACKER);
        vm.expectRevert("not authorized: LockBox");
        lockBox.withdraw(ATTACKER, AMT);
        console2.log("A-01 DEFENDED: Direct lockbox withdrawal blocked");
    }

    function test_A02_AttackerAddsAuthorizedCaller() public {
        vm.prank(ATTACKER);
        vm.expectRevert();
        lockBox.addAuthorizedCaller(ATTACKER);
        console2.log("A-02 DEFENDED: Attacker cannot add themselves");
    }

    function test_A03_RegistryHasNoAccessControl() public {
        MockTokenPool evil = new MockTokenPool(address(token), address(lockBox));
        vm.prank(ATTACKER);
        registry.setPool(address(token), address(evil));
        assertTrue(registry.getPool(address(token)) == address(evil));
        console2.log("A-03 FINDING: Registry.setPool has no access control");
    }

    function test_A04_AttackerSetsRequiredCCVs() public {
        address[] memory e = new address[](0);
        vm.prank(ATTACKER);
        vm.expectRevert();
        offRamp.setRequiredCCVs(e);
        console2.log("A-04 DEFENDED: setRequiredCCVs is onlyOwner");
    }

    function test_A05_RemovePoolAuth() public {
        vm.prank(ATTACKER);
        vm.expectRevert();
        lockBox.removeAuthorizedCaller(address(pool));
        console2.log("A-05 DEFENDED: removeAuthorizedCaller is onlyOwner");
    }

    function test_A06_EvilPoolDrainAfterAuth() public {
        MockTokenPool evil = new MockTokenPool(address(token), address(lockBox));
        evil.setMalicious(true, ATTACKER);
        vm.prank(OWNER);
        lockBox.addAuthorizedCaller(address(evil));
        uint256 before = token.balanceOf(ATTACKER);
        evil.releaseOrMint(RECEIVER, AMT);
        console2.log("A-06 FINDING: Authorized evil pool drained lockbox. Attacker gained:", token.balanceOf(ATTACKER) - before);
    }

    function test_A07_AttackerPausesLockbox() public {
        vm.prank(ATTACKER);
        vm.expectRevert();
        lockBox.pause();
        console2.log("A-07 DEFENDED: pause is onlyOwner");
    }

    function test_A08_FreezeTokenTransfers() public {
        vm.prank(OWNER);
        token.freezeTransfers();
        ccv.configure(false, 0, RECEIVER);
        vm.expectRevert("transfers frozen");
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        console2.log("A-08 FINDING: Token freeze causes permanent DoS");
    }

    function test_A09_ExecuteWithNoCCVsWhenNoneRequired() public {
        vm.prank(OWNER);
        address[] memory empty = new address[](0);
        offRamp.setRequiredCCVs(empty);
        address[] memory submitted = new address[](0);
        uint256 received = offRamp.executeSingleMessage(address(token), RECEIVER, AMT, submitted);
        console2.log("A-09 FINDING: Zero required CCVs -- unverified execution succeeded:", received);
    }

    function test_A10_MessageReplay() public {
        ccv.configure(false, 0, RECEIVER);
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        console2.log("A-10 FINDING: Replay succeeded -- receiver balance:", token.balanceOf(RECEIVER));
    }

    function test_A11_NullPoolAddress() public {
        vm.prank(OWNER);
        registry.setPool(address(token), address(0));
        vm.expectRevert();
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        console2.log("A-11 DEFENDED: Null pool reverts");
    }

    function test_A12_DuplicateCCVSubmission() public {
        address[] memory ccvs = new address[](3);
        ccvs[0] = address(ccv); ccvs[1] = address(ccv); ccvs[2] = address(ccv);
        ccv.configure(false, 0, RECEIVER);
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, ccvs);
        assertEq(ccv.callCount(), 1);
        console2.log("A-12 DEFENDED: Duplicate CCVs -- called only once:", ccv.callCount());
    }

    function test_A13_ZeroAmountExecution() public {
        ccv.configure(false, 0, RECEIVER);
        uint256 received = offRamp.executeSingleMessage(address(token), RECEIVER, 0, _ccvs());
        assertEq(received, 0);
        console2.log("A-13 NOTE: Zero amount executes -- potential spam vector");
    }

    function test_A14_MaxUintAmount() public {
        ccv.configure(false, 0, RECEIVER);
        vm.expectRevert();
        offRamp.executeSingleMessage(address(token), RECEIVER, type(uint256).max, _ccvs());
        console2.log("A-14 DEFENDED: Max uint reverts on insufficient lockbox");
    }

    function test_A15_ReceiverRedirection() public {
        ccv.configure(false, 0, ATTACKER);
        uint256 before = token.balanceOf(ATTACKER);
        offRamp.executeSingleMessage(address(token), ATTACKER, AMT, _ccvs());
        console2.log("A-15 NOTE: Receiver is caller-supplied in mini system. Attacker got:", token.balanceOf(ATTACKER) - before);
    }

    function test_A16_RegistryOwnershipTakeover() public {
        vm.prank(ATTACKER);
        registry.setPool(address(token), ATTACKER);
        assertTrue(registry.getPool(address(token)) == ATTACKER);
        console2.log("A-16 FINDING: Registry has no ownership -- anyone can redirect pools");
    }

    function test_A17_MissingRequiredCCV() public {
        address[] memory empty = new address[](0);
        vm.expectRevert("RequiredCCVMissing");
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, empty);
        console2.log("A-17 DEFENDED: Missing required CCV reverts");
    }

    function test_A18_ExtraCCVIgnored() public {
        MockCCV evil = new MockCCV(address(token));
        evil.configure(true, AMT * 100, ATTACKER);
        ccv.configure(false, 0, RECEIVER);
        address[] memory ccvs = new address[](2);
        ccvs[0] = address(ccv); ccvs[1] = address(evil);
        uint256 received = offRamp.executeSingleMessage(address(token), RECEIVER, AMT, ccvs);
        assertEq(received, AMT);
        console2.log("A-18 DEFENDED: Extra evil CCV ignored -- received:", received);
    }

    function test_A19_UnauthorizedLockboxWithdrawal() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert("not authorized: LockBox");
        lockBox.withdraw(address(0xDEAD), AMT);
        console2.log("A-19 DEFENDED: Unauthorized withdrawal reverts");
    }

    function test_A20_ExecutionToContractReceiver() public {
        ContractReceiver cr = new ContractReceiver();
        ccv.configure(false, 0, address(cr));
        uint256 received = offRamp.executeSingleMessage(address(token), address(cr), AMT, _ccvs());
        assertEq(received, AMT);
        console2.log("A-20 PASS: Contract receiver works:", received);
    }

    // ── CATEGORY B: REENTRANCY ───────────────────────────────────

    function test_B01_ReentrantCCV() public {
        ReentrantCCV rCCV = new ReentrantCCV(address(offRamp));
        vm.prank(OWNER);
        address[] memory list = new address[](1);
        list[0] = address(rCCV);
        offRamp.setRequiredCCVs(list);
        address[] memory ccvs = new address[](1);
        ccvs[0] = address(rCCV);
        rCCV.setReentrant(address(token), RECEIVER, AMT / 2, ccvs);
        uint256 before = lockBox.balance();
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, ccvs);
        console2.log("B-01 FINDING: Reentrant CCV -- lockbox drained extra:", before - lockBox.balance() - AMT);
        console2.log("B-01 NOTE: Real OffRamp has reentrancy guard -- mini system does not");
    }

    function test_B02_CCVCallsLockboxDirectly() public {
        LockboxCallingCCV lbCCV = new LockboxCallingCCV(address(lockBox), ATTACKER, AMT * 5);
        vm.startPrank(OWNER);
        lockBox.addAuthorizedCaller(address(lbCCV));
        address[] memory list = new address[](1);
        list[0] = address(lbCCV);
        offRamp.setRequiredCCVs(list);
        vm.stopPrank();
        address[] memory ccvs = new address[](1);
        ccvs[0] = address(lbCCV);
        uint256 before = token.balanceOf(ATTACKER);
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, ccvs);
        console2.log("B-02 FINDING: Malicious CCV drained lockbox. Attacker got:", token.balanceOf(ATTACKER) - before);
    }

    function test_B03_DoubleRelease() public {
        ccv.configure(true, AMT, RECEIVER);
        uint256 received = offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        assertEq(received, AMT * 2);
        console2.log("B-03 CONFIRMED: Double release -- verifier+pool both released:", received);
    }

    function test_B04_BalanceManipulationDuringExecution() public {
        token.mint(RECEIVER, AMT);
        BurningCCV bCCV = new BurningCCV(address(token), RECEIVER, AMT / 2);
        vm.prank(OWNER);
        address[] memory list = new address[](1);
        list[0] = address(bCCV);
        offRamp.setRequiredCCVs(list);
        address[] memory ccvs = new address[](1);
        ccvs[0] = address(bCCV);
        uint256 reported = offRamp.executeSingleMessage(address(token), RECEIVER, AMT, ccvs);
        console2.log("B-04: CCV burned AMT/2 from receiver during verify");
        console2.log("B-04: Reported received:", reported, "(pool released AMT, CCV burned AMT/2)");
        assertEq(reported, AMT / 2);
    }

    function test_B05_NegativeBalanceDiff() public {
        token.mint(RECEIVER, AMT);
        BurningCCV bCCV = new BurningCCV(address(token), RECEIVER, AMT * 3);
        vm.prank(OWNER);
        address[] memory list = new address[](1);
        list[0] = address(bCCV);
        offRamp.setRequiredCCVs(list);
        address[] memory ccvs = new address[](1);
        ccvs[0] = address(bCCV);
        vm.expectRevert();
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, ccvs);
        console2.log("B-05 DEFENDED: Negative balance diff causes underflow revert");
    }

    function test_B06_StateChangeAfterExternalCall() public {
        ccv.configure(false, 0, RECEIVER);
        uint256 received = offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        assertEq(received, AMT);
        console2.log("B-06 DEFENDED: balancePre captured before external calls");
    }

    function test_B07_MultipleSequentialExecutions() public {
        ccv.configure(false, 0, RECEIVER);
        for (uint256 i = 0; i < 5; i++) {
            offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        }
        assertEq(token.balanceOf(RECEIVER), AMT * 5);
        console2.log("B-07 DEFENDED: Sequential executions accurate -- no drift");
    }

    function test_B08_CCVReleasesToDifferentAddress() public {
        ccv.configure(true, AMT, ALICE);
        uint256 aliceBefore = token.balanceOf(ALICE);
        uint256 receiverBefore = token.balanceOf(RECEIVER);
        uint256 reported = offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        console2.log("B-08 FINDING: CCV released to Alice, pool released to RECEIVER");
        console2.log("B-08: Reported:", reported, "Alice got:", token.balanceOf(ALICE) - aliceBefore);
        console2.log("B-08 NOTE: balancePre/Post only tracks RECEIVER -- Alice's tokens invisible");
    }

    function test_B09_ZeroAmountReplay() public {
        ccv.configure(false, 0, RECEIVER);
        for (uint256 i = 0; i < 10; i++) {
            offRamp.executeSingleMessage(address(token), RECEIVER, 0, _ccvs());
        }
        console2.log("B-09 NOTE: Zero amount replay -- spam with no value but costs gas");
    }

    function test_B10_DoubleExecutionNoStateTracking() public {
        ccv.configure(false, 0, RECEIVER);
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        console2.log("B-10 FINDING: No execution state -- double execution drained 2x AMT from lockbox");
        assertEq(token.balanceOf(RECEIVER), AMT * 2);
    }

    // ── CATEGORY C: ARITHMETIC ──────────────────────────────────

    function test_C01_Overflow() public {
        vm.expectRevert();
        token.mint(RECEIVER, type(uint256).max);
        token.mint(RECEIVER, 1);
        console2.log("C-01 DEFENDED: Overflow causes revert");
    }

    function test_C02_LockboxUnderflow() public {
        ccv.configure(false, 0, RECEIVER);
        uint256 bal = lockBox.balance();
        vm.expectRevert("insufficient");
        offRamp.executeSingleMessage(address(token), RECEIVER, bal + 1, _ccvs());
        console2.log("C-02 DEFENDED: Lockbox underflow reverts");
    }

    function test_C03_PartialVerifierRelease() public {
        ccv.configure(true, AMT / 4, RECEIVER);
        uint256 received = offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        assertEq(received, AMT + AMT / 4);
        console2.log("C-03 FINDING: Partial verifier release adds to pool release:", received);
    }

    function test_C04_OnlyVerifierRelease() public {
        vm.prank(OWNER);
        address[] memory empty = new address[](0);
        offRamp.setRequiredCCVs(empty);
        address[] memory submitted = new address[](0);
        uint256 before = lockBox.balance();
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, submitted);
        console2.log("C-04: Lockbox drained:", before - lockBox.balance());
    }

    function test_C05_TotalSupplyInflation() public {
        uint256 supplyBefore = token.totalSupply();
        ccv.configure(true, AMT, RECEIVER);
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        uint256 supplyAfter = token.totalSupply();
        console2.log("C-05 FINDING: Supply inflated by CCV mint:", supplyAfter - supplyBefore - AMT);
    }

    function test_C06_DecimalMismatch18vs6() public {
        uint256 sourceAmt = 1e18;
        ccv.configure(false, 0, RECEIVER);
        vm.expectRevert("insufficient");
        offRamp.executeSingleMessage(address(token), RECEIVER, sourceAmt, _ccvs());
        console2.log("C-06 NOTE: 18-decimal source amount reverts -- no decimal conversion in mini system");
    }

    function test_C07_OneWeiPrecision() public {
        ccv.configure(false, 0, RECEIVER);
        uint256 received = offRamp.executeSingleMessage(address(token), RECEIVER, 1, _ccvs());
        assertEq(received, 1);
        console2.log("C-07 DEFENDED: 1 wei precision -- no loss");
    }

    function test_C08_LargeAmount() public {
        uint256 large = 1_000_000_000e6;
        token.mint(address(lockBox), large);
        ccv.configure(false, 0, RECEIVER);
        uint256 received = offRamp.executeSingleMessage(address(token), RECEIVER, large, _ccvs());
        assertEq(received, large);
        console2.log("C-08 DEFENDED: 1 trillion USDC -- no arithmetic issues");
    }

    function test_C09_ExistingReceiverBalance() public {
        token.mint(RECEIVER, AMT * 5);
        ccv.configure(false, 0, RECEIVER);
        uint256 received = offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        assertEq(received, AMT);
        console2.log("C-09 DEFENDED: Existing balance does not distort accounting");
    }

    function test_C10_InsolvencyViaDoubleRelease() public {
        uint256 lockboxStart = lockBox.balance();
        ccv.configure(true, AMT, RECEIVER);
        uint256 executions = 0;
        while (lockBox.balance() >= AMT) {
            offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
            executions++;
        }
        console2.log("C-10: Executions before insolvency:", executions);
        console2.log("C-10: Lockbox start:", lockboxStart, "end:", lockBox.balance());
        console2.log("C-10: Receiver balance:", token.balanceOf(RECEIVER));
        console2.log("C-10 FINDING: Double release reaches insolvency in half the expected messages");
    }

    // ── CATEGORY D: LOGIC / FLOW ─────────────────────────────────

    function test_D01_CCVPermanentRevert() public {
        ccv.setAlwaysReverts(true);
        vm.expectRevert("CCV validation failed");
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        console2.log("D-01 FINDING: Reverting CCV permanently freezes all messages");
    }

    function test_D02_MultipleRequiredCCVs() public {
        MockCCV ccv2 = new MockCCV(address(token));
        vm.prank(OWNER);
        address[] memory list = new address[](2);
        list[0] = address(ccv); list[1] = address(ccv2);
        offRamp.setRequiredCCVs(list);
        ccv.configure(false, 0, RECEIVER);
        ccv2.configure(false, 0, RECEIVER);
        address[] memory ccvs = new address[](2);
        ccvs[0] = address(ccv); ccvs[1] = address(ccv2);
        uint256 received = offRamp.executeSingleMessage(address(token), RECEIVER, AMT, ccvs);
        assertEq(ccv.callCount(), 1); assertEq(ccv2.callCount(), 1);
        console2.log("D-02 DEFENDED: Both CCVs called exactly once, received:", received);
    }

    function test_D03_PartialCCVSubmission() public {
        MockCCV ccv2 = new MockCCV(address(token));
        vm.prank(OWNER);
        address[] memory list = new address[](2);
        list[0] = address(ccv); list[1] = address(ccv2);
        offRamp.setRequiredCCVs(list);
        address[] memory ccvs = new address[](1);
        ccvs[0] = address(ccv);
        vm.expectRevert("RequiredCCVMissing");
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, ccvs);
        console2.log("D-03 DEFENDED: Partial CCV submission reverts");
    }

    function test_D04_CCVOrderIndependence() public {
        MockCCV ccv2 = new MockCCV(address(token));
        vm.prank(OWNER);
        address[] memory list = new address[](2);
        list[0] = address(ccv); list[1] = address(ccv2);
        offRamp.setRequiredCCVs(list);
        ccv.configure(false, 0, RECEIVER); ccv2.configure(false, 0, RECEIVER);
        address[] memory ccvs = new address[](2);
        ccvs[0] = address(ccv2); ccvs[1] = address(ccv);
        uint256 received = offRamp.executeSingleMessage(address(token), RECEIVER, AMT, ccvs);
        assertEq(received, AMT);
        console2.log("D-04 DEFENDED: CCV order in submitted array does not matter");
    }

    function test_D05_ExecutionAfterPoolRemoval() public {
        vm.prank(OWNER);
        registry.setPool(address(token), address(0));
        vm.expectRevert();
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        console2.log("D-05 DEFENDED: Execution after pool removal reverts");
    }

    function test_D06_DoubleExecution() public {
        ccv.configure(false, 0, RECEIVER);
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        assertEq(token.balanceOf(RECEIVER), AMT * 2);
        console2.log("D-06 FINDING: No replay protection -- 2x drain from lockbox");
    }

    function test_D07_EmptyLockboxExecution() public {
        uint256 bal = lockBox.balance();
        ccv.configure(false, 0, RECEIVER);
        offRamp.executeSingleMessage(address(token), RECEIVER, bal, _ccvs());
        vm.expectRevert("insufficient");
        offRamp.executeSingleMessage(address(token), RECEIVER, 1, _ccvs());
        console2.log("D-07 DEFENDED: Empty lockbox causes revert");
    }

    function test_D08_GasGriefingCCV() public {
        console2.log("D-08: Infinite loop CCV would OOG -- message stays in FAILURE");
        console2.log("D-08 NOTE: Real OffRamp uses callWithGasBuffer to prevent full drain");
    }

    function test_D09_FrozenTokenExecution() public {
        vm.prank(OWNER);
        token.freezeTransfers();
        ccv.configure(false, 0, RECEIVER);
        vm.expectRevert("transfers frozen");
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        console2.log("D-09 FINDING: Frozen token = permanent message freeze");
    }

    function test_D10_PausedLockboxExecution() public {
        vm.prank(OWNER);
        lockBox.pause();
        ccv.configure(false, 0, RECEIVER);
        vm.expectRevert("lockbox paused");
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        console2.log("D-10 FINDING: Paused lockbox = permanent message freeze");
    }

    // ── CATEGORY E: ECONOMIC / GRIEFING ─────────────────────────

    function test_E01_FullLockboxDrain() public {
        uint256 total = lockBox.balance();
        ccv.configure(false, 0, RECEIVER);
        offRamp.executeSingleMessage(address(token), RECEIVER, total, _ccvs());
        assertEq(lockBox.balance(), 0);
        console2.log("E-01: Full lockbox drained legitimately:", total);
    }

    function test_E02_GriefingViaSmallMessages() public {
        ccv.configure(false, 0, RECEIVER);
        for (uint256 i = 0; i < 20; i++) {
            offRamp.executeSingleMessage(address(token), RECEIVER, 1, _ccvs());
        }
        console2.log("E-02 NOTE: 20x 1-wei messages executed -- spam/griefing possible");
    }

    function test_E03_MaliciousPoolDrain() public {
        MockTokenPool evil = new MockTokenPool(address(token), address(lockBox));
        evil.setMalicious(true, ATTACKER);
        vm.startPrank(OWNER);
        registry.setPool(address(token), address(evil));
        lockBox.addAuthorizedCaller(address(evil));
        vm.stopPrank();
        uint256 before = token.balanceOf(ATTACKER);
        ccv.configure(false, 0, RECEIVER);
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        console2.log("E-03 FINDING: Malicious pool drained entire lockbox. Attacker got:", token.balanceOf(ATTACKER) - before);
    }

    function test_E04_SupplyInflationAttack() public {
        uint256 s0 = token.totalSupply();
        ccv.configure(true, AMT * 10, RECEIVER);
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        console2.log("E-04 FINDING: Supply inflated by:", token.totalSupply() - s0 - AMT);
    }

    function test_E05_CCVGriefingAllMessages() public {
        ccv.setAlwaysReverts(true);
        vm.expectRevert("CCV validation failed");
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        console2.log("E-05 FINDING: Single CCV reverting freezes ALL messages on this lane");
    }

    function test_E06_InsolventBridge() public {
        uint256 backed = lockBox.balance();
        ccv.configure(true, AMT, RECEIVER);
        uint256 count = 0;
        while (lockBox.balance() >= AMT) {
            offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
            count++;
        }
        uint256 receiverBal = token.balanceOf(RECEIVER);
        uint256 unbacked = receiverBal - backed;
        console2.log("E-06: Messages before insolvency:", count);
        console2.log("E-06 FINDING: Unbacked tokens in circulation:", unbacked);
    }

    function test_E07_ReceiverSelfGriefing() public {
        ccv.configure(false, 0, RECEIVER);
        offRamp.executeSingleMessage(address(token), RECEIVER, AMT, _ccvs());
        console2.log("E-07 NOTE: Receiver cannot block their own transfer -- tokens sent regardless");
    }

    function test_E08_LockboxBalanceManipulation() public {
        token.mint(address(lockBox), AMT * 1000);
        console2.log("E-08 NOTE: Lockbox balance can be inflated by anyone minting in test");
        console2.log("E-08 NOTE: Real USDC restricts minting to authorized roles");
    }

    function test_E09_ChainedDoubleRelease() public {
        MockCCV ccv2 = new MockCCV(address(token));
        ccv.configure(true, AMT, RECEIVER);
        ccv2.configure(true, AMT, RECEIVER);
        vm.prank(OWNER);
        address[] memory list = new address[](2);
        list[0] = address(ccv); list[1] = address(ccv2);
        offRamp.setRequiredCCVs(list);
        address[] memory ccvs = new address[](2);
        ccvs[0] = address(ccv); ccvs[1] = address(ccv2);
        uint256 received = offRamp.executeSingleMessage(address(token), RECEIVER, AMT, ccvs);
        console2.log("E-09 FINDING: 2 minting CCVs + pool = 3x release:", received);
    }

    function test_E10_EconomicSummary() public {
        console2.log("=== ECONOMIC SUMMARY ===");
        console2.log("FINDINGS:");
        console2.log("  A-03/A-16: Registry has no access control -- pool redirection");
        console2.log("  A-10/B-10/D-06: No replay protection -- double drain");
        console2.log("  B-03/C-10/E-06: Double release = bridge insolvency");
        console2.log("  B-02/E-03: Malicious authorized CCV/pool = full drain");
        console2.log("  D-01/E-05: Reverting CCV = permanent message freeze");
        console2.log("DEFENDED:");
        console2.log("  A-01: Direct lockbox withdrawal blocked");
        console2.log("  A-04: setRequiredCCVs is onlyOwner");
        console2.log("  A-12: Duplicate CCVs called only once");
        console2.log("  A-18: Extra injected CCV ignored by intersection logic");
        console2.log("  C-02: Lockbox underflow reverts");
    }
}

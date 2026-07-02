// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

contract Token {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    address public owner;
    mapping(address => bool) public minters;
    uint8 public decimals;
    constructor(uint8 _d) { owner = msg.sender; minters[msg.sender] = true; decimals = _d; }
    function addMinter(address m) external { require(msg.sender == owner); minters[m] = true; }
    function mint(address to, uint256 amt) external { require(minters[msg.sender],"not minter"); require(to != address(0),"zero"); balanceOf[to] += amt; totalSupply += amt; }
    function burn(address from, uint256 amt) external { require(minters[msg.sender],"not minter"); require(balanceOf[from] >= amt,"insuf"); balanceOf[from] -= amt; totalSupply -= amt; }
    function transfer(address to, uint256 amt) external returns (bool) { require(to != address(0),"zero"); require(balanceOf[msg.sender] >= amt,"insuf"); balanceOf[msg.sender] -= amt; balanceOf[to] += amt; return true; }
}

contract LockBox {
    Token public token;
    mapping(address => bool) public auth;
    address public owner;
    bool public paused;
    constructor(address _t) { token = Token(_t); owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    modifier onlyAuth() { require(auth[msg.sender],"not auth: LockBox"); _; }
    modifier notPaused() { require(!paused,"lockbox paused"); _; }
    function authorize(address a) external onlyOwner { auth[a] = true; }
    function deauthorize(address a) external onlyOwner { auth[a] = false; }
    function pause() external onlyOwner { paused = true; }
    function unpause() external onlyOwner { paused = false; }
    function deposit(uint256 amt) external onlyAuth notPaused { require(amt > 0,"zero"); token.mint(address(this), amt); }
    function withdraw(address to, uint256 amt) external onlyAuth notPaused { require(to != address(0),"zero"); require(amt > 0,"zero"); require(token.balanceOf(address(this)) >= amt,"insufficient"); token.transfer(to, amt); }
    function balance() external view returns (uint256) { return token.balanceOf(address(this)); }
}

contract Pool {
    LockBox public lockBox;
    address public owner;
    bool public paused;
    uint256 public feePercent;
    constructor(address _lb) { lockBox = LockBox(_lb); owner = msg.sender; }
    function setFee(uint256 bps) external { require(msg.sender == owner); feePercent = bps; }
    function pause() external { require(msg.sender == owner); paused = true; }
    function unpause() external { require(msg.sender == owner); paused = false; }
    function releaseOrMint(address receiver, uint256 amt) external returns (uint256) {
        require(!paused,"pool paused");
        require(amt > 0,"zero");
        uint256 fee = (amt * feePercent) / 10000;
        uint256 net = amt - fee;
        lockBox.withdraw(receiver, net);
        if (fee > 0) lockBox.withdraw(owner, fee);
        return net;
    }
}

contract CCV {
    Token public token;
    bool public releases; uint256 public releaseAmt; address public releaseTarget;
    bool public reverts;
    address public lockboxToDrain; address public drainTarget; uint256 public drainAmt;
    bool public modifiesRegistry; address public registryAddr; address public newPool;
    uint256 public callCount;
    constructor(address _t) { token = Token(_t); }
    function configRelease(bool _r, uint256 _a, address _t) external { releases=_r; releaseAmt=_a; releaseTarget=_t; }
    function configRevert(bool _r) external { reverts=_r; }
    function configDrain(address _lb, address _to, uint256 _a) external { lockboxToDrain=_lb; drainTarget=_to; drainAmt=_a; }
    function configRegistryPoison(address _reg, address _np) external { modifiesRegistry=true; registryAddr=_reg; newPool=_np; }
    function reset() external { releases=false; reverts=false; lockboxToDrain=address(0); modifiesRegistry=false; callCount=0; releaseTarget=address(0); }
    function verifyMessage(bytes32, address) external {
        callCount++;
        if (reverts) revert("CCV: validation failed");
        if (releases && releaseTarget != address(0)) token.mint(releaseTarget, releaseAmt);
        if (lockboxToDrain != address(0)) { LockBox lb = LockBox(lockboxToDrain); uint256 b=lb.balance(); uint256 d=b<drainAmt?b:drainAmt; if(d>0) lb.withdraw(drainTarget, d); }
        if (modifiesRegistry && registryAddr != address(0)) { Registry(registryAddr).setPool(address(token), newPool); }
    }
}

contract Registry {
    mapping(address => address) public pools;
    function setPool(address t, address p) external { pools[t] = p; }
    function getPool(address t) external view returns (address) { return pools[t]; }
}

contract OffRamp {
    Registry public registry;
    address[] public requiredCCVs;
    address public owner;
    mapping(bytes32 => uint8) public msgState;
    bool public reentryGuard;
    uint256 public executionCount;
    constructor(address _reg) { registry = Registry(_reg); owner = msg.sender; }
    function setRequiredCCVs(address[] memory _c) external { require(msg.sender == owner); delete requiredCCVs; for(uint256 i=0;i<_c.length;i++) requiredCCVs.push(_c[i]); }
    function execute(address token, address receiver, uint256 amt, address[] calldata ccvs, bytes calldata extraData) external returns (uint256) {
        require(!reentryGuard,"reentrancy");
        reentryGuard = true;
        bytes32 mid = keccak256(abi.encode(token, receiver, amt, extraData));
        require(msgState[mid] != 1,"already executed");
        uint256 balPre = Token(token).balanceOf(receiver);
        address[] memory toQuery = _quorum(ccvs);
        for(uint256 i=0;i<toQuery.length;i++) CCV(toQuery[i]).verifyMessage(mid, receiver);
        address pool = registry.getPool(token);
        require(pool != address(0),"no pool");
        Pool(pool).releaseOrMint(receiver, amt);
        uint256 received = Token(token).balanceOf(receiver) - balPre;
        msgState[mid] = 1;
        executionCount++;
        reentryGuard = false;
        return received;
    }
    function _quorum(address[] calldata s) internal view returns (address[] memory r) {
        r = new address[](requiredCCVs.length); uint256 n=0;
        for(uint256 i=0;i<requiredCCVs.length;i++) {
            bool found=false;
            for(uint256 j=0;j<s.length;j++) { if(s[j]==requiredCCVs[i]) { r[n++]=s[j]; found=true; break; } }
            if(!found) revert("RequiredCCVMissing");
        }
        assembly { mstore(r,n) }
    }
}

contract IceBall is Test {
    Token token;
    LockBox lockBox;
    Pool pool;
    CCV ccv;
    Registry registry;
    OffRamp offRamp;

    address OWNER    = address(0x1111);
    address ATTACKER = address(0xDEAD);
    address RECEIVER = address(0xBEEF);
    uint256 constant AMT = 1_000_000e6;
    uint256 constant LOCKBOX_INITIAL = AMT * 100;

    uint256 constant NUM_INJ = 20;
    uint256 constant INJ_NONE                = 0;
    uint256 constant INJ_CCV_MINT_ATTACKER   = 1;
    uint256 constant INJ_CCV_MINT_RECEIVER   = 2;
    uint256 constant INJ_CCV_MINT_LOCKBOX    = 3;
    uint256 constant INJ_CCV_REVERT          = 4;
    uint256 constant INJ_CCV_DRAIN           = 5;
    uint256 constant INJ_CCV_POISON_REG      = 6;
    uint256 constant INJ_POOL_PAUSED         = 7;
    uint256 constant INJ_POOL_MAX_FEE        = 8;
    uint256 constant INJ_POOL_ZERO_FEE       = 9;
    uint256 constant INJ_LOCKBOX_PAUSED      = 10;
    uint256 constant INJ_ZERO_AMOUNT         = 11;
    uint256 constant INJ_REPLAY              = 12;
    uint256 constant INJ_RECEIVER_ZERO       = 13;
    uint256 constant INJ_RECEIVER_POOL       = 14;
    uint256 constant INJ_RECEIVER_OFFRAMP    = 15;
    uint256 constant INJ_RECEIVER_REGISTRY   = 16;
    uint256 constant INJ_CCV_MINT_HUGE       = 17;
    uint256 constant INJ_DOUBLE_EXECUTE      = 18;
    uint256 constant INJ_CCV_MINT_BOTH       = 19;

    struct BugReport {
        bool found;
        uint8 severity;
        string description;
        uint256 injA;
        uint256 injB;
        uint256 injC;
        uint256 layer;
    }

    BugReport public lastBug;
    uint256 public totalTests;
    uint256 public criticalFound;
    uint256 public highFound;
    uint256 public mediumFound;
    uint256 public lowFound;

    function setUp() public {
        vm.startPrank(OWNER);
        token    = new Token(6);
        lockBox  = new LockBox(address(token));
        pool     = new Pool(address(lockBox));
        ccv      = new CCV(address(token));
        registry = new Registry();
        offRamp  = new OffRamp(address(registry));
        token.addMinter(address(lockBox));
        token.addMinter(address(ccv));
        lockBox.authorize(address(pool));
        registry.setPool(address(token), address(pool));
        lockBox.authorize(address(this));
        token.mint(address(lockBox), LOCKBOX_INITIAL);
        address[] memory list = new address[](1);
        list[0] = address(ccv);
        offRamp.setRequiredCCVs(list);
        vm.stopPrank();
    }

    struct Snap {
        uint256 lb;
        uint256 supply;
        uint256 attacker;
        uint256 receiver;
        uint256 execCount;
    }

    function _snap() internal view returns (Snap memory s) {
        s.lb = lockBox.balance();
        s.supply = token.totalSupply();
        s.attacker = token.balanceOf(ATTACKER);
        s.receiver = token.balanceOf(RECEIVER);
        s.execCount = offRamp.executionCount();
    }

    function _apply(uint256 id) internal {
        if (id == INJ_CCV_MINT_ATTACKER) ccv.configRelease(true, AMT, ATTACKER);
        if (id == INJ_CCV_MINT_RECEIVER) ccv.configRelease(true, AMT, RECEIVER);
        if (id == INJ_CCV_MINT_LOCKBOX)  ccv.configRelease(true, AMT, address(lockBox));
        if (id == INJ_CCV_MINT_HUGE)     ccv.configRelease(true, AMT * 50, ATTACKER);
        if (id == INJ_CCV_MINT_BOTH)     ccv.configRelease(true, AMT, RECEIVER);
        if (id == INJ_CCV_REVERT)        ccv.configRevert(true);
        if (id == INJ_CCV_DRAIN)         ccv.configDrain(address(lockBox), ATTACKER, lockBox.balance());
        if (id == INJ_CCV_POISON_REG)    ccv.configRegistryPoison(address(registry), ATTACKER);
        if (id == INJ_POOL_PAUSED)       { vm.prank(OWNER); pool.pause(); }
        if (id == INJ_POOL_MAX_FEE)      { vm.prank(OWNER); pool.setFee(10000); }
        if (id == INJ_POOL_ZERO_FEE)     { vm.prank(OWNER); pool.setFee(0); }
        if (id == INJ_LOCKBOX_PAUSED)    { vm.prank(OWNER); lockBox.pause(); }
    }

    function _reset() internal {
        ccv.reset();
        vm.startPrank(OWNER);
        if (pool.paused()) pool.unpause();
        if (lockBox.paused()) lockBox.unpause();
        pool.setFee(0);
        registry.setPool(address(token), address(pool));
        uint256 lb = lockBox.balance();
        if (lb < AMT * 10) lockBox.deposit(LOCKBOX_INITIAL - lb);
        vm.stopPrank();
    }

    function _injName(uint256 id) internal pure returns (string memory) {
        if (id == INJ_NONE)             return "NONE";
        if (id == INJ_CCV_MINT_ATTACKER)return "CCV_MINT->ATTACKER";
        if (id == INJ_CCV_MINT_RECEIVER)return "CCV_MINT->RECEIVER";
        if (id == INJ_CCV_MINT_LOCKBOX) return "CCV_MINT->LOCKBOX";
        if (id == INJ_CCV_REVERT)       return "CCV_REVERT";
        if (id == INJ_CCV_DRAIN)        return "CCV_DRAIN_LOCKBOX";
        if (id == INJ_CCV_POISON_REG)   return "CCV_POISON_REGISTRY";
        if (id == INJ_POOL_PAUSED)      return "POOL_PAUSED";
        if (id == INJ_POOL_MAX_FEE)     return "POOL_100%_FEE";
        if (id == INJ_POOL_ZERO_FEE)    return "POOL_ZERO_FEE";
        if (id == INJ_LOCKBOX_PAUSED)   return "LOCKBOX_PAUSED";
        if (id == INJ_ZERO_AMOUNT)      return "ZERO_AMOUNT";
        if (id == INJ_REPLAY)           return "REPLAY_ATTACK";
        if (id == INJ_RECEIVER_ZERO)    return "RECEIVER=ZERO";
        if (id == INJ_RECEIVER_POOL)    return "RECEIVER=POOL";
        if (id == INJ_RECEIVER_OFFRAMP) return "RECEIVER=OFFRAMP";
        if (id == INJ_RECEIVER_REGISTRY)return "RECEIVER=REGISTRY";
        if (id == INJ_CCV_MINT_HUGE)    return "CCV_MINT_50x->ATTACKER";
        if (id == INJ_DOUBLE_EXECUTE)   return "DOUBLE_EXECUTE";
        if (id == INJ_CCV_MINT_BOTH)    return "CCV_MINT+POOL->RECEIVER";
        return "UNKNOWN";
    }

    function _recordBug(uint8 sev, string memory desc, uint256 a, uint256 b, uint256 c, uint256 layer) internal {
        lastBug = BugReport(true, sev, desc, a, b, c, layer);
        if (sev == 1) criticalFound++;
        else if (sev == 2) highFound++;
        else if (sev == 3) mediumFound++;
        else lowFound++;
    }

    function _detect(Snap memory before, bool success, uint256 a, uint256 b, uint256 c, uint256 layer) internal returns (bool) {
        Snap memory after_ = _snap();

        // CRITICAL: attacker stole significant funds
        if (after_.attacker > before.attacker + AMT / 10) {
            _recordBug(1, "CRITICAL: Attacker gained funds", a, b, c, layer);
            return true;
        }

        // CRITICAL: supply inflated beyond lockbox drain
        uint256 supplyUp = after_.supply > before.supply ? after_.supply - before.supply : 0;
        uint256 lbDown = before.lb > after_.lb ? before.lb - after_.lb : 0;
        if (supplyUp > lbDown + AMT * 2) {
            _recordBug(1, "CRITICAL: Unbacked supply inflation", a, b, c, layer);
            return true;
        }

        // HIGH: receiver got more than 1.5x expected
        uint256 rxGain = after_.receiver > before.receiver ? after_.receiver - before.receiver : 0;
        if (rxGain > AMT * 15 / 10) {
            _recordBug(2, "HIGH: Receiver over-funded (double release)", a, b, c, layer);
            return true;
        }

        // HIGH: lockbox drained more than 2x expected
        if (lbDown > AMT * 2 && success) {
            _recordBug(2, "HIGH: Lockbox over-drained", a, b, c, layer);
            return true;
        }

        // MEDIUM: execution succeeded but receiver got nothing
        if (success && rxGain == 0 && after_.execCount > before.execCount) {
            _recordBug(3, "MEDIUM: Execution succeeded, receiver got nothing", a, b, c, layer);
            return true;
        }

        // LOW: double execute succeeded
        if (after_.execCount > before.execCount + 1) {
            _recordBug(4, "LOW: Double execution", a, b, c, layer);
            return true;
        }

        return false;
    }

    function _runTest(uint256 a, uint256 b, uint256 c) internal returns (bool) {
        totalTests++;
        _apply(a); _apply(b); _apply(c);
        Snap memory before = _snap();

        uint256 testAmt = AMT;
        address testRx = RECEIVER;
        bytes memory testData = abi.encode(totalTests);

        if (a == INJ_ZERO_AMOUNT || b == INJ_ZERO_AMOUNT || c == INJ_ZERO_AMOUNT) testAmt = 0;
        if (a == INJ_RECEIVER_ZERO || b == INJ_RECEIVER_ZERO || c == INJ_RECEIVER_ZERO) testRx = address(0);
        if (a == INJ_RECEIVER_POOL || b == INJ_RECEIVER_POOL || c == INJ_RECEIVER_POOL) testRx = address(pool);
        if (a == INJ_RECEIVER_OFFRAMP || b == INJ_RECEIVER_OFFRAMP || c == INJ_RECEIVER_OFFRAMP) testRx = address(offRamp);
        if (a == INJ_RECEIVER_REGISTRY || b == INJ_RECEIVER_REGISTRY || c == INJ_RECEIVER_REGISTRY) testRx = address(registry);
        if (a == INJ_REPLAY || b == INJ_REPLAY || c == INJ_REPLAY) testData = abi.encode(uint256(0));

        address[] memory ccvs = new address[](1);
        ccvs[0] = address(ccv);

        bool success = false;
        try offRamp.execute(address(token), testRx, testAmt, ccvs, testData) { success = true; } catch {}

        // Handle DOUBLE_EXECUTE
        if (a == INJ_DOUBLE_EXECUTE || b == INJ_DOUBLE_EXECUTE || c == INJ_DOUBLE_EXECUTE) {
            try offRamp.execute(address(token), testRx, testAmt, ccvs, testData) {} catch {}
        }

        bool bug = _detect(before, success, a, b, c, a == INJ_NONE && b == INJ_NONE ? 1 : b == INJ_NONE ? 1 : c == INJ_NONE ? 2 : 3);
        _reset();
        return bug;
    }

    function _report() internal view {
        console2.log("===========================================");
        console2.log("ICEBALL FINAL REPORT");
        console2.log("Total tests:", totalTests);
        console2.log("Critical:", criticalFound);
        console2.log("High:", highFound);
        console2.log("Medium:", mediumFound);
        console2.log("Low:", lowFound);
        if (lastBug.found) {
            string memory sev = lastBug.severity == 1 ? "CRITICAL" :
                                lastBug.severity == 2 ? "HIGH" :
                                lastBug.severity == 3 ? "MEDIUM" : "LOW";
            console2.log("LAST BUG:", sev);
            console2.log("Layer:", lastBug.layer);
            console2.log("Description:", lastBug.description);
            console2.log("Injection A:", _injName(lastBug.injA));
            if (lastBug.injB != INJ_NONE) console2.log("Injection B:", _injName(lastBug.injB));
            if (lastBug.injC != INJ_NONE) console2.log("Injection C:", _injName(lastBug.injC));
        }
        console2.log("===========================================");
    }

    // LAYER 1: Single injections
    function test_IceBall_Layer1() public {
        console2.log("=== ICEBALL LAYER 1: 20 single injections ===");
        for (uint256 i = 0; i < NUM_INJ; i++) {
            bool bug = _runTest(i, INJ_NONE, INJ_NONE);
            if (bug && lastBug.severity <= 2) { _report(); return; }
        }
        console2.log("Layer 1 complete:", totalTests, "tests");
        _report();
    }

    // LAYER 2: Double injections
    function test_IceBall_Layer2() public {
        console2.log("=== ICEBALL LAYER 2: double injections ===");
        for (uint256 i = 0; i < NUM_INJ; i++) {
            for (uint256 j = i+1; j < NUM_INJ; j++) {
                bool bug = _runTest(i, j, INJ_NONE);
                if (bug && lastBug.severity <= 2) { _report(); return; }
            }
        }
        console2.log("Layer 2 complete:", totalTests, "tests");
        _report();
    }

    // LAYER 3: Triple injections (high-risk combos)
    function test_IceBall_Layer3() public {
        console2.log("=== ICEBALL LAYER 3: triple injections ===");
        uint256[10] memory hr = [
            INJ_CCV_MINT_ATTACKER, INJ_CCV_DRAIN, INJ_CCV_POISON_REG,
            INJ_POOL_MAX_FEE, INJ_REPLAY, INJ_CCV_MINT_RECEIVER,
            INJ_RECEIVER_OFFRAMP, INJ_CCV_MINT_HUGE, INJ_DOUBLE_EXECUTE, INJ_CCV_MINT_BOTH
        ];
        for (uint256 i = 0; i < hr.length; i++) {
            for (uint256 j = i+1; j < hr.length; j++) {
                for (uint256 k = j+1; k < hr.length; k++) {
                    bool bug = _runTest(hr[i], hr[j], hr[k]);
                    if (bug && lastBug.severity <= 2) { _report(); return; }
                }
            }
        }
        console2.log("Layer 3 complete:", totalTests, "tests");
        _report();
    }

    // FULL ICEBALL: All layers
    function test_IceBall_FullRun() public {
        console2.log("=== ICEBALL FULL RUN ===");
        console2.log("Layer 1: 20 tests | Layer 2: 190 tests | Layer 3: 120 tests");

        // Layer 1
        for (uint256 i = 0; i < NUM_INJ; i++) {
            if (_runTest(i, INJ_NONE, INJ_NONE) && lastBug.severity <= 2) { _report(); return; }
        }

        // Layer 2
        for (uint256 i = 0; i < NUM_INJ; i++) {
            for (uint256 j = i+1; j < NUM_INJ; j++) {
                if (_runTest(i, j, INJ_NONE) && lastBug.severity <= 2) { _report(); return; }
            }
        }

        // Layer 3
        uint256[10] memory hr = [
            INJ_CCV_MINT_ATTACKER, INJ_CCV_DRAIN, INJ_CCV_POISON_REG,
            INJ_POOL_MAX_FEE, INJ_REPLAY, INJ_CCV_MINT_RECEIVER,
            INJ_RECEIVER_OFFRAMP, INJ_CCV_MINT_HUGE, INJ_DOUBLE_EXECUTE, INJ_CCV_MINT_BOTH
        ];
        for (uint256 i = 0; i < hr.length; i++) {
            for (uint256 j = i+1; j < hr.length; j++) {
                for (uint256 k = j+1; k < hr.length; k++) {
                    if (_runTest(hr[i], hr[j], hr[k]) && lastBug.severity <= 2) { _report(); return; }
                }
            }
        }

        _report();
    }
}

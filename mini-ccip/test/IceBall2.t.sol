// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

// ICEBALL v2 — 110 Injections, Deduplication, Conflict Detection, False-Positive Fixes

contract Token {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    address public owner;
    mapping(address => bool) public minters;
    uint8 public decimals;
    bool public transfersFrozen;
    constructor(uint8 _d) { owner=msg.sender; minters[msg.sender]=true; decimals=_d; }
    function addMinter(address m) external { require(msg.sender==owner); minters[m]=true; }
    function removeMinter(address m) external { require(msg.sender==owner); minters[m]=false; }
    function freeze() external { require(msg.sender==owner); transfersFrozen=true; }
    function unfreeze() external { require(msg.sender==owner); transfersFrozen=false; }
    function mint(address to, uint256 amt) external { require(minters[msg.sender],"not minter"); require(to!=address(0),"zero"); balanceOf[to]+=amt; totalSupply+=amt; }
    function burn(address from, uint256 amt) external { require(minters[msg.sender],"not minter"); require(balanceOf[from]>=amt,"insuf"); balanceOf[from]-=amt; totalSupply-=amt; }
    function transfer(address to, uint256 amt) external returns (bool) { require(!transfersFrozen,"frozen"); require(to!=address(0),"zero"); require(balanceOf[msg.sender]>=amt,"insuf"); balanceOf[msg.sender]-=amt; balanceOf[to]+=amt; return true; }
}

contract LockBox {
    Token public token;
    mapping(address => bool) public auth;
    address public owner;
    bool public paused;
    constructor(address _t) { token=Token(_t); owner=msg.sender; }
    modifier onlyOwner() { require(msg.sender==owner); _; }
    modifier onlyAuth() { require(auth[msg.sender],"not auth: LockBox"); _; }
    modifier notPaused() { require(!paused,"lockbox paused"); _; }
    function authorize(address a) external onlyOwner { auth[a]=true; }
    function deauthorize(address a) external onlyOwner { auth[a]=false; }
    function pause() external onlyOwner { paused=true; }
    function unpause() external onlyOwner { paused=false; }
    function deposit(uint256 amt) external onlyAuth notPaused { require(amt>0,"zero"); token.mint(address(this),amt); }
    function withdraw(address to, uint256 amt) external onlyAuth notPaused { require(to!=address(0),"zero"); require(amt>0,"zero"); require(token.balanceOf(address(this))>=amt,"insufficient"); token.transfer(to,amt); }
    function balance() external view returns (uint256) { return token.balanceOf(address(this)); }
}

contract Pool {
    LockBox public lockBox;
    address public owner;
    bool public paused;
    uint256 public feePercent;
    uint8 public localDecimals;
    uint8 public remoteDecimals;
    constructor(address _lb, uint8 _ld, uint8 _rd) { lockBox=LockBox(_lb); owner=msg.sender; localDecimals=_ld; remoteDecimals=_rd; }
    function setFee(uint256 bps) external { require(msg.sender==owner); feePercent=bps; }
    function pause() external { require(msg.sender==owner); paused=true; }
    function unpause() external { require(msg.sender==owner); paused=false; }
    function setDecimals(uint8 ld, uint8 rd) external { require(msg.sender==owner); localDecimals=ld; remoteDecimals=rd; }
    function calculateLocalAmount(uint256 remoteAmt) public view returns (uint256) {
        if (localDecimals==remoteDecimals) return remoteAmt;
        if (localDecimals>remoteDecimals) return remoteAmt*(10**(localDecimals-remoteDecimals));
        return remoteAmt/(10**(remoteDecimals-localDecimals));
    }
    function releaseOrMint(address receiver, uint256 amt) external returns (uint256) {
        require(!paused,"pool paused"); require(amt>0,"zero");
        uint256 localAmt=calculateLocalAmount(amt); require(localAmt>0,"zero local");
        uint256 fee=(localAmt*feePercent)/10000; uint256 net=localAmt-fee;
        lockBox.withdraw(receiver,net); if(fee>0) lockBox.withdraw(owner,fee); return net;
    }
}

contract CCV {
    Token public token;
    bool public releases; uint256 public releaseAmt; address public releaseTarget;
    bool public reverts; string public revertMsg;
    address public lbToDrain; address public drainTo; uint256 public drainAmt;
    bool public poisonsRegistry; address public registryAddr; address public newPool;
    bool public burns; address public burnFrom; uint256 public burnAmt;
    bool public releases2; uint256 public releaseAmt2; address public releaseTarget2;
    uint256 public callCount;
    constructor(address _t) { token=Token(_t); }
    function configRelease(bool _r, uint256 _a, address _t) external { releases=_r; releaseAmt=_a; releaseTarget=_t; }
    function configRelease2(bool _r, uint256 _a, address _t) external { releases2=_r; releaseAmt2=_a; releaseTarget2=_t; }
    function configRevert(bool _r, string calldata _m) external { reverts=_r; revertMsg=_m; }
    function configDrain(address _lb, address _to, uint256 _a) external { lbToDrain=_lb; drainTo=_to; drainAmt=_a; }
    function configRegistryPoison(address _reg, address _np) external { poisonsRegistry=true; registryAddr=_reg; newPool=_np; }
    function configBurn(bool _b, address _from, uint256 _a) external { burns=_b; burnFrom=_from; burnAmt=_a; }
    function reset() external { releases=false; reverts=false; burns=false; releases2=false; lbToDrain=address(0); poisonsRegistry=false; callCount=0; releaseTarget=address(0); releaseTarget2=address(0); burnFrom=address(0); }
    function verifyMessage(bytes32, address) external {
        callCount++;
        if (reverts) revert(revertMsg);
        if (releases && releaseTarget!=address(0)) token.mint(releaseTarget,releaseAmt);
        if (releases2 && releaseTarget2!=address(0)) token.mint(releaseTarget2,releaseAmt2);
        if (burns && burnFrom!=address(0)) token.burn(burnFrom,burnAmt);
        if (lbToDrain!=address(0)) { LockBox lb=LockBox(lbToDrain); uint256 b=lb.balance(); uint256 d=b<drainAmt?b:drainAmt; if(d>0) lb.withdraw(drainTo,d); }
        if (poisonsRegistry && registryAddr!=address(0)) { Registry(registryAddr).setPool(address(token),newPool); }
    }
}

contract Registry {
    mapping(address => address) public pools;
    bool public locked;
    address public owner;
    constructor() { owner=msg.sender; }
    function setPool(address t, address p) external { require(!locked,"locked"); pools[t]=p; }
    function lock() external { require(msg.sender==owner); locked=true; }
    function unlock() external { require(msg.sender==owner); locked=false; }
    function getPool(address t) external view returns (address) { return pools[t]; }
}

contract OffRamp {
    Registry public registry;
    address[] public requiredCCVs;
    address public owner;
    mapping(bytes32 => uint8) public msgState;
    bool public reentryGuard;
    uint256 public executionCount;
    constructor(address _reg) { registry=Registry(_reg); owner=msg.sender; }
    function setRequiredCCVs(address[] memory _c) external { require(msg.sender==owner); delete requiredCCVs; for(uint256 i=0;i<_c.length;i++) requiredCCVs.push(_c[i]); }
    function execute(address token, address receiver, uint256 amt, address[] calldata ccvs, bytes calldata extraData) external returns (uint256) {
        require(!reentryGuard,"reentrancy"); reentryGuard=true;
        bytes32 mid=keccak256(abi.encode(token,receiver,amt,extraData));
        require(msgState[mid]!=1,"already executed");
        uint256 balPre=Token(token).balanceOf(receiver);
        address[] memory toQuery=_quorum(ccvs);
        for(uint256 i=0;i<toQuery.length;i++) CCV(toQuery[i]).verifyMessage(mid,receiver);
        address pool=registry.getPool(token); require(pool!=address(0),"no pool");
        Pool(pool).releaseOrMint(receiver,amt);
        uint256 received=Token(token).balanceOf(receiver)-balPre;
        msgState[mid]=1; executionCount++; reentryGuard=false; return received;
    }
    function _quorum(address[] calldata s) internal view returns (address[] memory r) {
        r=new address[](requiredCCVs.length); uint256 n=0;
        for(uint256 i=0;i<requiredCCVs.length;i++) {
            bool found=false;
            for(uint256 j=0;j<s.length;j++) { if(s[j]==requiredCCVs[i]) { r[n++]=s[j]; found=true; break; } }
            if(!found) revert("RequiredCCVMissing");
        }
        assembly { mstore(r,n) }
    }
}

contract IceBall2 is Test {
    Token token; LockBox lockBox; Pool pool; CCV ccv; Registry registry; OffRamp offRamp;
    address OWNER=address(0x1111); address ATTACKER=address(0xDEAD); address RECEIVER=address(0xBEEF); address ALICE=address(0xA11CE);
    uint256 constant AMT=1_000_000e6; uint256 constant LB_INIT=AMT*500;

    uint256 constant NUM_INJ=110;
    uint256 constant A00_NONE=0;
    uint256 constant A01_CCV_MINT_ATTACKER_1X=1; uint256 constant A02_CCV_MINT_ATTACKER_10X=2;
    uint256 constant A03_CCV_MINT_ATTACKER_50X=3; uint256 constant A04_CCV_MINT_RECEIVER_1X=4;
    uint256 constant A05_CCV_MINT_RECEIVER_2X=5; uint256 constant A06_CCV_MINT_ALICE=6;
    uint256 constant A07_CCV_MINT_LOCKBOX=7; uint256 constant A08_CCV_MINT_OFFRAMP=8;
    uint256 constant A09_CCV_MINT_REGISTRY=9; uint256 constant A10_CCV_MINT_POOL=10;
    uint256 constant A11_CCV_MINT_ZERO_ADDR=11; uint256 constant A12_CCV_MINT_SELF=12;
    uint256 constant A13_CCV_DUAL_MINT_ATK_RX=13; uint256 constant A14_CCV_DUAL_MINT_RX_ALICE=14;
    uint256 constant A15_CCV_MINT_TINY=15; uint256 constant A16_CCV_MINT_MAX_HALF=16;
    uint256 constant A17_CCV_BURN_RECEIVER=17; uint256 constant A18_CCV_BURN_LOCKBOX=18;
    uint256 constant A19_CCV_MINT_THEN_BURN=19;
    uint256 constant B20_CCV_REVERT=20; uint256 constant B21_CCV_REVERT_CUSTOM_MSG=21;
    uint256 constant B22_CCV_DRAIN_ALL=22; uint256 constant B23_CCV_DRAIN_HALF=23;
    uint256 constant B24_CCV_DRAIN_1WEI=24; uint256 constant B25_CCV_POISON_REGISTRY=25;
    uint256 constant B26_CCV_POISON_ZERO_POOL=26; uint256 constant B27_UNUSED=27;
    uint256 constant B28_CCV_NO_OP=28; uint256 constant B29_UNUSED=29;
    uint256 constant B30_UNUSED=30; uint256 constant B31_CCV_INFLATE_SUPPLY=31;
    uint256 constant B32_CCV_DRAIN_TO_ALICE=32; uint256 constant B33_CCV_DRAIN_TO_REGISTRY=33;
    uint256 constant B34_CCV_MINT_EXACT_LOCKBOX=34; uint256 constant B35_CCV_BURN_ATTACKER=35;
    uint256 constant B36_CCV_MINT_OWNER=36; uint256 constant B37_CCV_DRAIN_TO_OFFRAMP=37;
    uint256 constant B38_CCV_MINT_999X=38; uint256 constant B39_CCV_DRAIN_TO_ZERO=39;
    uint256 constant C40_POOL_PAUSED=40; uint256 constant C41_POOL_FEE_100PCT=41;
    uint256 constant C42_POOL_FEE_50PCT=42; uint256 constant C43_POOL_FEE_1PCT=43;
    uint256 constant C44_POOL_FEE_ZERO=44; uint256 constant C45_POOL_FEE_9999BPS=45;
    uint256 constant C46_POOL_DECIMAL_18_6=46; uint256 constant C47_POOL_DECIMAL_6_18=47;
    uint256 constant C48_POOL_DECIMAL_SAME=48; uint256 constant C49_LOCKBOX_PAUSED=49;
    uint256 constant C50_LOCKBOX_DEAUTH_POOL=50; uint256 constant C51_UNUSED=51;
    uint256 constant C52_UNUSED=52; uint256 constant C53_LOCKBOX_EMPTY=53;
    uint256 constant C54_LOCKBOX_1WEI=54; uint256 constant C55_UNUSED=55;
    uint256 constant C56_TOKEN_FROZEN=56; uint256 constant C57_UNUSED=57;
    uint256 constant C58_UNUSED=58; uint256 constant C59_UNUSED=59;
    uint256 constant D60_ZERO_AMOUNT=60; uint256 constant D61_TINY_AMOUNT_1WEI=61;
    uint256 constant D62_LARGE_AMOUNT_100X=62; uint256 constant D63_MAX_UINT64=63;
    uint256 constant D64_REPLAY_FIXED_DATA=64; uint256 constant D65_REPLAY_ZERO_DATA=65;
    uint256 constant D66_RECEIVER_ZERO_ADDR=66; uint256 constant D67_RECEIVER_IS_POOL=67;
    uint256 constant D68_RECEIVER_IS_OFFRAMP=68; uint256 constant D69_RECEIVER_IS_REGISTRY=69;
    uint256 constant D70_RECEIVER_IS_LOCKBOX=70; uint256 constant D71_RECEIVER_IS_TOKEN=71;
    uint256 constant D72_RECEIVER_IS_CCV=72; uint256 constant D73_RECEIVER_IS_ATTACKER=73;
    uint256 constant D74_RECEIVER_IS_ALICE=74; uint256 constant D75_DOUBLE_EXECUTE=75;
    uint256 constant D76_UNUSED=76; uint256 constant D77_EMPTY_CALLDATA=77;
    uint256 constant D78_LARGE_CALLDATA=78; uint256 constant D79_NO_CCVS_REQUIRED=79;
    uint256 constant E80_REGISTRY_LOCK=80; uint256 constant E81_REGISTRY_ZERO_POOL=81;
    uint256 constant E82_UNUSED=82; uint256 constant E83_UNUSED=83;
    uint256 constant E84_REGISTRY_ATTACKER=84; uint256 constant E85_UNUSED=85;
    uint256 constant E86_UNUSED=86; uint256 constant E87_UNUSED=87;
    uint256 constant E88_UNUSED=88; uint256 constant E89_UNUSED=89;
    uint256 constant E90_ZERO_CCV_REQUIRED=90; uint256 constant E91_UNUSED=91;
    uint256 constant E92_UNUSED=92; uint256 constant E93_TOKEN_MINTER_REMOVED=93;
    uint256 constant E94_UNUSED=94; uint256 constant E95_UNUSED=95;
    uint256 constant E96_UNUSED=96; uint256 constant E97_UNUSED=97;
    uint256 constant E98_UNUSED=98; uint256 constant E99_UNUSED=99;
    uint256 constant F100_FEE_ROUNDS_ZERO=100; uint256 constant F101_UNUSED=101;
    uint256 constant F102_DECIMAL_LOSS=102; uint256 constant F103_UNUSED=103;
    uint256 constant F104_LOCKBOX_FULL_DRAIN=104; uint256 constant F105_UNUSED=105;
    uint256 constant F106_DUST_GRIEFING=106; uint256 constant F107_LOCKBOX_INFLATE=107;
    uint256 constant F108_UNUSED=108; uint256 constant F109_UNUSED=109;

    struct BugReport { bool found; uint8 severity; string description; uint256 injA; uint256 injB; uint256 injC; uint256 layer; uint256 testNumber; }
    BugReport[] public bugLog;
    mapping(bytes32 => bool) public reportedBugs;
    uint256 public totalTests; uint256 public criticalFound; uint256 public highFound;
    uint256 public mediumFound; uint256 public lowFound;
    uint256 public skippedConflicts; uint256 public skippedDuplicates;

    function setUp() public {
        vm.startPrank(OWNER);
        token=new Token(6); lockBox=new LockBox(address(token));
        pool=new Pool(address(lockBox),6,6); ccv=new CCV(address(token));
        registry=new Registry(); offRamp=new OffRamp(address(registry));
        token.addMinter(address(lockBox)); token.addMinter(address(ccv)); token.addMinter(address(this));
        lockBox.authorize(address(pool)); lockBox.authorize(address(this));
        registry.setPool(address(token),address(pool));
        token.mint(address(lockBox),LB_INIT);
        address[] memory list=new address[](1); list[0]=address(ccv);
        offRamp.setRequiredCCVs(list);
        vm.stopPrank();
    }

    function _inGroup(uint256 id, uint256 gs, uint256 ge) internal pure returns (bool) { return id>=gs && id<=ge; }

    function _conflicts(uint256 a, uint256 b) internal pure returns (bool) {
        bool aCCVMint=_inGroup(a,1,16)||a==A13_CCV_DUAL_MINT_ATK_RX||a==A14_CCV_DUAL_MINT_RX_ALICE||a==B31_CCV_INFLATE_SUPPLY||a==B34_CCV_MINT_EXACT_LOCKBOX||a==B36_CCV_MINT_OWNER||a==B38_CCV_MINT_999X;
        bool bCCVMint=_inGroup(b,1,16)||b==A13_CCV_DUAL_MINT_ATK_RX||b==A14_CCV_DUAL_MINT_RX_ALICE||b==B31_CCV_INFLATE_SUPPLY||b==B34_CCV_MINT_EXACT_LOCKBOX||b==B36_CCV_MINT_OWNER||b==B38_CCV_MINT_999X;
        if (aCCVMint&&bCCVMint) return true;
        if ((a==B20_CCV_REVERT||a==B21_CCV_REVERT_CUSTOM_MSG)&&(b==B20_CCV_REVERT||b==B21_CCV_REVERT_CUSTOM_MSG)) return true;
        if (a==C40_POOL_PAUSED&&b==C40_POOL_PAUSED) return true;
        bool aFee=_inGroup(a,41,45); bool bFee=_inGroup(b,41,45);
        if (aFee&&bFee) return true;
        bool aRx=_inGroup(a,66,74); bool bRx=_inGroup(b,66,74);
        if (aRx&&bRx) return true;
        return false;
    }

    function _intentionalAttackerGain(uint256 a, uint256 b, uint256 c) internal pure returns (bool) {
        uint256[10] memory atkInjs=[A01_CCV_MINT_ATTACKER_1X,A02_CCV_MINT_ATTACKER_10X,A03_CCV_MINT_ATTACKER_50X,A13_CCV_DUAL_MINT_ATK_RX,B22_CCV_DRAIN_ALL,B23_CCV_DRAIN_HALF,D73_RECEIVER_IS_ATTACKER,E84_REGISTRY_ATTACKER,B38_CCV_MINT_999X,A16_CCV_MINT_MAX_HALF];
        for (uint256 i=0;i<10;i++) { if(a==atkInjs[i]||b==atkInjs[i]||c==atkInjs[i]) return true; }
        return false;
    }

    function _intentionalOverFund(uint256 a, uint256 b, uint256 c) internal pure returns (bool) {
        uint256[5] memory ovInjs=[A04_CCV_MINT_RECEIVER_1X,A05_CCV_MINT_RECEIVER_2X,A13_CCV_DUAL_MINT_ATK_RX,A14_CCV_DUAL_MINT_RX_ALICE,B31_CCV_INFLATE_SUPPLY];
        for (uint256 i=0;i<5;i++) { if(a==ovInjs[i]||b==ovInjs[i]||c==ovInjs[i]) return true; }
        return false;
    }

    function _apply(uint256 id) internal {
        if (id==A01_CCV_MINT_ATTACKER_1X) ccv.configRelease(true,AMT,ATTACKER);
        if (id==A02_CCV_MINT_ATTACKER_10X) ccv.configRelease(true,AMT*10,ATTACKER);
        if (id==A03_CCV_MINT_ATTACKER_50X) ccv.configRelease(true,AMT*50,ATTACKER);
        if (id==A04_CCV_MINT_RECEIVER_1X) ccv.configRelease(true,AMT,RECEIVER);
        if (id==A05_CCV_MINT_RECEIVER_2X) ccv.configRelease(true,AMT*2,RECEIVER);
        if (id==A06_CCV_MINT_ALICE) ccv.configRelease(true,AMT,ALICE);
        if (id==A07_CCV_MINT_LOCKBOX) ccv.configRelease(true,AMT,address(lockBox));
        if (id==A08_CCV_MINT_OFFRAMP) ccv.configRelease(true,AMT,address(offRamp));
        if (id==A09_CCV_MINT_REGISTRY) ccv.configRelease(true,AMT,address(registry));
        if (id==A10_CCV_MINT_POOL) ccv.configRelease(true,AMT,address(pool));
        if (id==A12_CCV_MINT_SELF) ccv.configRelease(true,AMT,address(ccv));
        if (id==A13_CCV_DUAL_MINT_ATK_RX) { ccv.configRelease(true,AMT,ATTACKER); ccv.configRelease2(true,AMT,RECEIVER); }
        if (id==A14_CCV_DUAL_MINT_RX_ALICE) { ccv.configRelease(true,AMT,RECEIVER); ccv.configRelease2(true,AMT,ALICE); }
        if (id==A15_CCV_MINT_TINY) ccv.configRelease(true,1,RECEIVER);
        if (id==A16_CCV_MINT_MAX_HALF) ccv.configRelease(true,type(uint128).max,ATTACKER);
        if (id==A17_CCV_BURN_RECEIVER) ccv.configBurn(true,RECEIVER,AMT/2);
        if (id==A18_CCV_BURN_LOCKBOX) ccv.configBurn(true,address(lockBox),AMT);
        if (id==A19_CCV_MINT_THEN_BURN) { ccv.configRelease(true,AMT*2,RECEIVER); ccv.configBurn(true,RECEIVER,AMT); }
        if (id==B20_CCV_REVERT) ccv.configRevert(true,"CCV: validation failed");
        if (id==B21_CCV_REVERT_CUSTOM_MSG) ccv.configRevert(true,"custom revert");
        if (id==B22_CCV_DRAIN_ALL) ccv.configDrain(address(lockBox),ATTACKER,lockBox.balance());
        if (id==B23_CCV_DRAIN_HALF) ccv.configDrain(address(lockBox),ATTACKER,lockBox.balance()/2);
        if (id==B24_CCV_DRAIN_1WEI) ccv.configDrain(address(lockBox),ATTACKER,1);
        if (id==B25_CCV_POISON_REGISTRY) ccv.configRegistryPoison(address(registry),ATTACKER);
        if (id==B26_CCV_POISON_ZERO_POOL) ccv.configRegistryPoison(address(registry),address(0));
        if (id==B31_CCV_INFLATE_SUPPLY) ccv.configRelease(true,AMT*100,RECEIVER);
        if (id==B32_CCV_DRAIN_TO_ALICE) ccv.configDrain(address(lockBox),ALICE,lockBox.balance());
        if (id==B33_CCV_DRAIN_TO_REGISTRY) ccv.configDrain(address(lockBox),address(registry),lockBox.balance());
        if (id==B34_CCV_MINT_EXACT_LOCKBOX) ccv.configRelease(true,lockBox.balance(),ATTACKER);
        if (id==B35_CCV_BURN_ATTACKER) ccv.configBurn(true,ATTACKER,AMT);
        if (id==B36_CCV_MINT_OWNER) ccv.configRelease(true,AMT,OWNER);
        if (id==B37_CCV_DRAIN_TO_OFFRAMP) ccv.configDrain(address(lockBox),address(offRamp),lockBox.balance());
        if (id==B38_CCV_MINT_999X) ccv.configRelease(true,AMT*999,ATTACKER);
        if (id==B39_CCV_DRAIN_TO_ZERO) ccv.configDrain(address(lockBox),address(1),lockBox.balance());
        if (id==C40_POOL_PAUSED) { vm.prank(OWNER); pool.pause(); }
        if (id==C41_POOL_FEE_100PCT) { vm.prank(OWNER); pool.setFee(10000); }
        if (id==C42_POOL_FEE_50PCT) { vm.prank(OWNER); pool.setFee(5000); }
        if (id==C43_POOL_FEE_1PCT) { vm.prank(OWNER); pool.setFee(100); }
        if (id==C44_POOL_FEE_ZERO) { vm.prank(OWNER); pool.setFee(0); }
        if (id==C45_POOL_FEE_9999BPS) { vm.prank(OWNER); pool.setFee(9999); }
        if (id==C46_POOL_DECIMAL_18_6) { vm.prank(OWNER); pool.setDecimals(18,6); }
        if (id==C47_POOL_DECIMAL_6_18) { vm.prank(OWNER); pool.setDecimals(6,18); }
        if (id==C48_POOL_DECIMAL_SAME) { vm.prank(OWNER); pool.setDecimals(6,6); }
        if (id==C49_LOCKBOX_PAUSED) { vm.prank(OWNER); lockBox.pause(); }
        if (id==C50_LOCKBOX_DEAUTH_POOL) { vm.prank(OWNER); lockBox.deauthorize(address(pool)); }
        if (id==C53_LOCKBOX_EMPTY) { uint256 b=lockBox.balance(); if(b>0) lockBox.withdraw(ATTACKER,b); }
        if (id==C54_LOCKBOX_1WEI) { uint256 b=lockBox.balance(); if(b>1) lockBox.withdraw(ATTACKER,b-1); }
        if (id==C56_TOKEN_FROZEN) { vm.prank(OWNER); token.freeze(); }
        if (id==E80_REGISTRY_LOCK) { vm.prank(OWNER); registry.lock(); }
        if (id==E81_REGISTRY_ZERO_POOL) registry.setPool(address(token),address(0));
        if (id==E84_REGISTRY_ATTACKER) registry.setPool(address(token),ATTACKER);
        if (id==E90_ZERO_CCV_REQUIRED) { vm.prank(OWNER); offRamp.setRequiredCCVs(new address[](0)); }
        if (id==E93_TOKEN_MINTER_REMOVED) { vm.prank(OWNER); token.removeMinter(address(ccv)); }
        if (id==F104_LOCKBOX_FULL_DRAIN) { uint256 b=lockBox.balance(); if(b>0) lockBox.withdraw(ATTACKER,b); }
        if (id==F107_LOCKBOX_INFLATE) token.mint(address(lockBox),AMT*1000);
    }

    function _getParams(uint256 a, uint256 b, uint256 c) internal view returns (uint256 amt, address rx, bytes memory data) {
        amt=AMT; rx=RECEIVER; data=abi.encode(totalTests);
        uint256[3] memory ids=[a,b,c];
        for (uint256 i=0;i<3;i++) {
            uint256 id=ids[i];
            if (id==D60_ZERO_AMOUNT) amt=0;
            if (id==D61_TINY_AMOUNT_1WEI) amt=1;
            if (id==D62_LARGE_AMOUNT_100X) amt=AMT*100;
            if (id==D63_MAX_UINT64) amt=type(uint64).max;
            if (id==D64_REPLAY_FIXED_DATA) data=abi.encode(uint256(42));
            if (id==D65_REPLAY_ZERO_DATA) data=abi.encode(uint256(0));
            if (id==D66_RECEIVER_ZERO_ADDR) rx=address(0);
            if (id==D67_RECEIVER_IS_POOL) rx=address(pool);
            if (id==D68_RECEIVER_IS_OFFRAMP) rx=address(offRamp);
            if (id==D69_RECEIVER_IS_REGISTRY) rx=address(registry);
            if (id==D70_RECEIVER_IS_LOCKBOX) rx=address(lockBox);
            if (id==D71_RECEIVER_IS_TOKEN) rx=address(token);
            if (id==D72_RECEIVER_IS_CCV) rx=address(ccv);
            if (id==D73_RECEIVER_IS_ATTACKER) rx=ATTACKER;
            if (id==D74_RECEIVER_IS_ALICE) rx=ALICE;
            if (id==D77_EMPTY_CALLDATA) data="";
            if (id==D78_LARGE_CALLDATA) data=new bytes(256);
            if (id==F100_FEE_ROUNDS_ZERO||id==F102_DECIMAL_LOSS||id==F106_DUST_GRIEFING) amt=1;
        }
    }

    function _reset() internal {
        vm.stopPrank(); // clear any lingering prank
        ccv.reset();
        vm.startPrank(OWNER);
        if (pool.paused()) pool.unpause();
        if (lockBox.paused()) lockBox.unpause();
        pool.setFee(0);
        pool.setDecimals(6,6);
        if (registry.locked()) registry.unlock();
        registry.setPool(address(token),address(pool));
        uint256 lb=lockBox.balance();
        if (lb<AMT*50) {
            if (!lockBox.auth(address(this))) lockBox.authorize(address(this));
            token.mint(address(lockBox),LB_INIT-lb);
        }
        if (!lockBox.auth(address(pool))) lockBox.authorize(address(pool));
        token.addMinter(address(ccv));
        if (token.transfersFrozen()) token.unfreeze();
        address[] memory list=new address[](1); list[0]=address(ccv);
        offRamp.setRequiredCCVs(list);
        vm.stopPrank();
    }

    struct Snap { uint256 lb; uint256 supply; uint256 attacker; uint256 receiver; uint256 execCount; uint256 ownerBal; }

    function _snap() internal view returns (Snap memory s) {
        s.lb=lockBox.balance(); s.supply=token.totalSupply();
        s.attacker=token.balanceOf(ATTACKER); s.receiver=token.balanceOf(RECEIVER);
        s.execCount=offRamp.executionCount(); s.ownerBal=token.balanceOf(OWNER);
    }

    function _bugSig(uint8 sev, string memory desc) internal pure returns (bytes32) { return keccak256(abi.encodePacked(sev,desc)); }

    function _report(uint8 sev, string memory desc, uint256 a, uint256 b, uint256 c) internal returns (bool) {
        bytes32 sig=_bugSig(sev,desc);
        if (reportedBugs[sig]) { skippedDuplicates++; return false; }
        reportedBugs[sig]=true;
        uint256 layer=(b==A00_NONE&&c==A00_NONE)?1:(c==A00_NONE)?2:3;
        bugLog.push(BugReport(true,sev,desc,a,b,c,layer,totalTests));
        if (sev==1) criticalFound++;
        else if (sev==2) highFound++;
        else if (sev==3) mediumFound++;
        else lowFound++;
        string memory sevStr=sev==1?"CRITICAL":sev==2?"HIGH":sev==3?"MEDIUM":"LOW";
        console2.log("BUG FOUND:",sevStr);
        console2.log("  Desc:",desc);
        console2.log("  Layer:",layer,"Test#:",totalTests);
        console2.log("  InjA:",_name(a));
        if (b!=A00_NONE) console2.log("  InjB:",_name(b));
        if (c!=A00_NONE) console2.log("  InjC:",_name(c));
        return true;
    }

    function _detect(Snap memory before, Snap memory after_, bool success, uint256 testAmt, uint256 a, uint256 b, uint256 c) internal returns (bool) {
        bool intentionalAtk=_intentionalAttackerGain(a,b,c);
        bool intentionalOver=_intentionalOverFund(a,b,c);
        uint256 atkGain=after_.attacker>before.attacker?after_.attacker-before.attacker:0;
        uint256 rxGain=after_.receiver>before.receiver?after_.receiver-before.receiver:0;
        uint256 supplyUp=after_.supply>before.supply?after_.supply-before.supply:0;
        uint256 lbDown=before.lb>after_.lb?before.lb-after_.lb:0;

        // CRITICAL: unexpected attacker gain
        if (!intentionalAtk&&atkGain>AMT/100) return _report(1,"CRITICAL: Unexpected attacker fund gain",a,b,c);

        // CRITICAL: unbacked supply inflation
        if (supplyUp>lbDown+testAmt*2&&supplyUp>AMT&&!intentionalOver) return _report(1,"CRITICAL: Unbacked supply inflation",a,b,c);

        // CRITICAL: replay succeeded (requires both REPLAY + DOUBLE_EXECUTE injections)
        bool isReplay=(a==D64_REPLAY_FIXED_DATA||b==D64_REPLAY_FIXED_DATA||c==D64_REPLAY_FIXED_DATA||a==D65_REPLAY_ZERO_DATA||b==D65_REPLAY_ZERO_DATA||c==D65_REPLAY_ZERO_DATA);
        bool hasDoubleExec=(a==D75_DOUBLE_EXECUTE||b==D75_DOUBLE_EXECUTE||c==D75_DOUBLE_EXECUTE);
        if (isReplay&&hasDoubleExec&&success&&after_.execCount>before.execCount+1) return _report(1,"CRITICAL: Replay attack succeeded",a,b,c);

        // HIGH: unexpected over-fund
        if (!intentionalOver&&rxGain>testAmt*15/10&&rxGain>AMT/10) return _report(2,"HIGH: Receiver unexpectedly over-funded",a,b,c);

        // HIGH: lockbox over-drained
        if (lbDown>testAmt*3&&success) return _report(2,"HIGH: Lockbox over-drained",a,b,c);

        // HIGH: execution succeeded but no tokens moved
        if (success&&rxGain==0&&lbDown==0&&testAmt>0) return _report(2,"HIGH: Execution succeeded, no tokens moved",a,b,c);

        // MEDIUM: tokens stuck in unexpected contract
        if (token.balanceOf(address(offRamp))>AMT/10||token.balanceOf(address(registry))>AMT/10) return _report(3,"MEDIUM: Tokens stuck in unexpected contract",a,b,c);

        // MEDIUM: owner extracted excessive fee
        uint256 ownerGain=after_.ownerBal>before.ownerBal?after_.ownerBal-before.ownerBal:0;
        if (ownerGain>testAmt&&success) return _report(3,"MEDIUM: Owner extracted excessive fee",a,b,c);

        // LOW: supply increased despite failed execution
        if (!success&&supplyUp>0&&!intentionalOver&&!intentionalAtk) return _report(4,"LOW: Supply increased despite failed execution",a,b,c);

        return false;
    }

    function _runTest(uint256 a, uint256 b, uint256 c) internal returns (bool) {
        if (_conflicts(a,b)||_conflicts(b,c)||_conflicts(a,c)) { skippedConflicts++; return false; }
        totalTests++;
        _apply(a); _apply(b); _apply(c);
        Snap memory before=_snap();
        (uint256 testAmt, address testRx, bytes memory testData)=_getParams(a,b,c);
        address[] memory ccvs=new address[](1); ccvs[0]=address(ccv);
        bool success=false;
        try offRamp.execute(address(token),testRx,testAmt,ccvs,testData) { success=true; } catch {}
        if (a==D75_DOUBLE_EXECUTE||b==D75_DOUBLE_EXECUTE||c==D75_DOUBLE_EXECUTE) {
            try offRamp.execute(address(token),testRx,testAmt,ccvs,testData) {} catch {}
        }
        Snap memory after_=_snap();
        bool bug=_detect(before,after_,success,testAmt,a,b,c);
        _reset();
        return bug;
    }

    function _name(uint256 id) internal pure returns (string memory) {
        if (id==A00_NONE) return "NONE";
        if (id==A01_CCV_MINT_ATTACKER_1X) return "CCV_MINT_ATK_1x";
        if (id==A02_CCV_MINT_ATTACKER_10X) return "CCV_MINT_ATK_10x";
        if (id==A03_CCV_MINT_ATTACKER_50X) return "CCV_MINT_ATK_50x";
        if (id==A04_CCV_MINT_RECEIVER_1X) return "CCV_MINT_RX_1x";
        if (id==A05_CCV_MINT_RECEIVER_2X) return "CCV_MINT_RX_2x";
        if (id==A06_CCV_MINT_ALICE) return "CCV_MINT_ALICE";
        if (id==A07_CCV_MINT_LOCKBOX) return "CCV_MINT_LOCKBOX";
        if (id==A08_CCV_MINT_OFFRAMP) return "CCV_MINT_OFFRAMP";
        if (id==A09_CCV_MINT_REGISTRY) return "CCV_MINT_REGISTRY";
        if (id==A10_CCV_MINT_POOL) return "CCV_MINT_POOL";
        if (id==A12_CCV_MINT_SELF) return "CCV_MINT_SELF";
        if (id==A13_CCV_DUAL_MINT_ATK_RX) return "CCV_DUAL_ATK+RX";
        if (id==A14_CCV_DUAL_MINT_RX_ALICE) return "CCV_DUAL_RX+ALICE";
        if (id==A15_CCV_MINT_TINY) return "CCV_MINT_1WEI";
        if (id==A16_CCV_MINT_MAX_HALF) return "CCV_MINT_MAX/2";
        if (id==A17_CCV_BURN_RECEIVER) return "CCV_BURN_RX";
        if (id==A18_CCV_BURN_LOCKBOX) return "CCV_BURN_LB";
        if (id==A19_CCV_MINT_THEN_BURN) return "CCV_MINT_THEN_BURN";
        if (id==B20_CCV_REVERT) return "CCV_REVERT";
        if (id==B21_CCV_REVERT_CUSTOM_MSG) return "CCV_REVERT_CUSTOM";
        if (id==B22_CCV_DRAIN_ALL) return "CCV_DRAIN_ALL";
        if (id==B23_CCV_DRAIN_HALF) return "CCV_DRAIN_HALF";
        if (id==B24_CCV_DRAIN_1WEI) return "CCV_DRAIN_1WEI";
        if (id==B25_CCV_POISON_REGISTRY) return "CCV_POISON_REG";
        if (id==B26_CCV_POISON_ZERO_POOL) return "CCV_POISON_ZERO";
        if (id==B31_CCV_INFLATE_SUPPLY) return "CCV_INFLATE_100x";
        if (id==B32_CCV_DRAIN_TO_ALICE) return "CCV_DRAIN_ALICE";
        if (id==B33_CCV_DRAIN_TO_REGISTRY) return "CCV_DRAIN_REG";
        if (id==B34_CCV_MINT_EXACT_LOCKBOX) return "CCV_MINT_EXACT_LB";
        if (id==B35_CCV_BURN_ATTACKER) return "CCV_BURN_ATK";
        if (id==B36_CCV_MINT_OWNER) return "CCV_MINT_OWNER";
        if (id==B37_CCV_DRAIN_TO_OFFRAMP) return "CCV_DRAIN_OFFRAMP";
        if (id==B38_CCV_MINT_999X) return "CCV_MINT_999x";
        if (id==B39_CCV_DRAIN_TO_ZERO) return "CCV_DRAIN_ZERO";
        if (id==C40_POOL_PAUSED) return "POOL_PAUSED";
        if (id==C41_POOL_FEE_100PCT) return "POOL_FEE_100%";
        if (id==C42_POOL_FEE_50PCT) return "POOL_FEE_50%";
        if (id==C43_POOL_FEE_1PCT) return "POOL_FEE_1%";
        if (id==C44_POOL_FEE_ZERO) return "POOL_FEE_0%";
        if (id==C45_POOL_FEE_9999BPS) return "POOL_FEE_99.99%";
        if (id==C46_POOL_DECIMAL_18_6) return "POOL_DEC_18->6";
        if (id==C47_POOL_DECIMAL_6_18) return "POOL_DEC_6->18";
        if (id==C48_POOL_DECIMAL_SAME) return "POOL_DEC_6->6";
        if (id==C49_LOCKBOX_PAUSED) return "LOCKBOX_PAUSED";
        if (id==C50_LOCKBOX_DEAUTH_POOL) return "LB_DEAUTH_POOL";
        if (id==C53_LOCKBOX_EMPTY) return "LOCKBOX_EMPTY";
        if (id==C54_LOCKBOX_1WEI) return "LOCKBOX_1WEI";
        if (id==C56_TOKEN_FROZEN) return "TOKEN_FROZEN";
        if (id==D60_ZERO_AMOUNT) return "AMT=ZERO";
        if (id==D61_TINY_AMOUNT_1WEI) return "AMT=1WEI";
        if (id==D62_LARGE_AMOUNT_100X) return "AMT=100x";
        if (id==D63_MAX_UINT64) return "AMT=MAX64";
        if (id==D64_REPLAY_FIXED_DATA) return "REPLAY_42";
        if (id==D65_REPLAY_ZERO_DATA) return "REPLAY_0";
        if (id==D66_RECEIVER_ZERO_ADDR) return "RX=ZERO";
        if (id==D67_RECEIVER_IS_POOL) return "RX=POOL";
        if (id==D68_RECEIVER_IS_OFFRAMP) return "RX=OFFRAMP";
        if (id==D69_RECEIVER_IS_REGISTRY) return "RX=REGISTRY";
        if (id==D70_RECEIVER_IS_LOCKBOX) return "RX=LOCKBOX";
        if (id==D71_RECEIVER_IS_TOKEN) return "RX=TOKEN";
        if (id==D72_RECEIVER_IS_CCV) return "RX=CCV";
        if (id==D73_RECEIVER_IS_ATTACKER) return "RX=ATTACKER";
        if (id==D74_RECEIVER_IS_ALICE) return "RX=ALICE";
        if (id==D75_DOUBLE_EXECUTE) return "DOUBLE_EXEC";
        if (id==D77_EMPTY_CALLDATA) return "DATA=EMPTY";
        if (id==D78_LARGE_CALLDATA) return "DATA=256BYTES";
        if (id==D79_NO_CCVS_REQUIRED) return "NO_CCVS";
        if (id==E80_REGISTRY_LOCK) return "REG_LOCKED";
        if (id==E81_REGISTRY_ZERO_POOL) return "REG_ZERO_POOL";
        if (id==E84_REGISTRY_ATTACKER) return "REG_ATK_POOL";
        if (id==E90_ZERO_CCV_REQUIRED) return "ZERO_CCV_REQ";
        if (id==E93_TOKEN_MINTER_REMOVED) return "MINTER_REMOVED";
        if (id==F100_FEE_ROUNDS_ZERO) return "FEE_ROUNDS_0";
        if (id==F102_DECIMAL_LOSS) return "DECIMAL_LOSS";
        if (id==F104_LOCKBOX_FULL_DRAIN) return "LB_FULL_DRAIN";
        if (id==F106_DUST_GRIEFING) return "DUST_GRIEF";
        if (id==F107_LOCKBOX_INFLATE) return "LB_INFLATE";
        return "UNKNOWN";
    }

    function _printReport() internal view {
        console2.log("==========================================");
        console2.log("ICEBALL v2 REPORT");
        console2.log("Total tests:", totalTests);
        console2.log("Skipped conflicts:", skippedConflicts);
        console2.log("Skipped duplicates:", skippedDuplicates);
        console2.log("Unique bugs - Critical:", criticalFound);
        console2.log("Unique bugs - High:", highFound);
        console2.log("Unique bugs - Medium:", mediumFound);
        console2.log("Unique bugs - Low:", lowFound);
        console2.log("==========================================");
    }

    function test_IceBall2_Layer1() public {
        console2.log("=== ICEBALL v2 LAYER 1: 110 single injections ===");
        for (uint256 i=0;i<NUM_INJ;i++) {
            bool bug=_runTest(i,A00_NONE,A00_NONE);
            if (bug&&criticalFound>0&&bugLog[bugLog.length-1].severity==1) { _printReport(); return; }
        }
        console2.log("Layer 1 complete:",totalTests,"tests run");
        _printReport();
    }

    function test_IceBall2_Layer2() public {
        console2.log("=== ICEBALL v2 LAYER 2: double injections ===");
        for (uint256 i=0;i<NUM_INJ;i++) {
            for (uint256 j=i+1;j<NUM_INJ;j++) {
                bool bug=_runTest(i,j,A00_NONE);
                if (bug&&criticalFound>0&&bugLog[bugLog.length-1].severity==1) { _printReport(); return; }
            }
        }
        console2.log("Layer 2 complete:",totalTests,"tests");
        _printReport();
    }

    function test_IceBall2_Layer3() public {
        console2.log("=== ICEBALL v2 LAYER 3: high-risk triples ===");
        uint256[15] memory hr=[A01_CCV_MINT_ATTACKER_1X,B22_CCV_DRAIN_ALL,B25_CCV_POISON_REGISTRY,C41_POOL_FEE_100PCT,D64_REPLAY_FIXED_DATA,A04_CCV_MINT_RECEIVER_1X,D68_RECEIVER_IS_OFFRAMP,A03_CCV_MINT_ATTACKER_50X,D75_DOUBLE_EXECUTE,A13_CCV_DUAL_MINT_ATK_RX,B31_CCV_INFLATE_SUPPLY,C46_POOL_DECIMAL_18_6,E90_ZERO_CCV_REQUIRED,F104_LOCKBOX_FULL_DRAIN,B38_CCV_MINT_999X];
        for (uint256 i=0;i<hr.length;i++) {
            for (uint256 j=i+1;j<hr.length;j++) {
                for (uint256 k=j+1;k<hr.length;k++) {
                    bool bug=_runTest(hr[i],hr[j],hr[k]);
                    if (bug&&criticalFound>0&&bugLog[bugLog.length-1].severity==1) { _printReport(); return; }
                }
            }
        }
        console2.log("Layer 3 complete:",totalTests,"tests");
        _printReport();
    }

    function test_IceBall2_FullRun() public {
        console2.log("=== ICEBALL v2 FULL RUN: 110 injections ===");
        console2.log("Deduplication + Conflict Detection + False-Positive Fixes");
        for (uint256 i=0;i<NUM_INJ;i++) _runTest(i,A00_NONE,A00_NONE);
        console2.log("Layer 1 done:",totalTests,"tests");
        uint256 l2limit=totalTests+500;
        bool l2stop=false;
        for (uint256 i=0;i<NUM_INJ&&!l2stop;i++) {
            for (uint256 j=i+1;j<NUM_INJ&&!l2stop;j++) {
                _runTest(i,j,A00_NONE);
                if (totalTests>=l2limit) l2stop=true;
            }
        }
        console2.log("Layer 2 done:",totalTests,"tests");
        uint256[15] memory hr=[A01_CCV_MINT_ATTACKER_1X,B22_CCV_DRAIN_ALL,B25_CCV_POISON_REGISTRY,C41_POOL_FEE_100PCT,D64_REPLAY_FIXED_DATA,A04_CCV_MINT_RECEIVER_1X,D68_RECEIVER_IS_OFFRAMP,A03_CCV_MINT_ATTACKER_50X,D75_DOUBLE_EXECUTE,A13_CCV_DUAL_MINT_ATK_RX,B31_CCV_INFLATE_SUPPLY,C46_POOL_DECIMAL_18_6,E90_ZERO_CCV_REQUIRED,F104_LOCKBOX_FULL_DRAIN,B38_CCV_MINT_999X];
        for (uint256 i=0;i<hr.length;i++) for (uint256 j=i+1;j<hr.length;j++) for (uint256 k=j+1;k<hr.length;k++) _runTest(hr[i],hr[j],hr[k]);
        console2.log("Layer 3 done:",totalTests,"tests");
        _printReport();
    }
}

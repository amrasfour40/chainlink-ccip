// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

contract MockToken {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract MockLockBox {
    MockToken public token;
    mapping(address => bool) public authorizedCallers;
    address public owner;
    constructor(address _token) { token = MockToken(_token); owner = msg.sender; }
    function addAuthorizedCaller(address caller) external { require(msg.sender == owner); authorizedCallers[caller] = true; }
    function withdraw(address recipient, uint256 amount) external {
        require(authorizedCallers[msg.sender], "not authorized: LockBox");
        require(token.balanceOf(address(this)) >= amount, "insufficient");
        token.transfer(recipient, amount);
    }
}

contract MockTokenPool {
    MockLockBox public lockBox;
    constructor(address _lockBox) { lockBox = MockLockBox(_lockBox); }
    function releaseOrMint(address receiver, uint256 amount) external returns (uint256) {
        lockBox.withdraw(receiver, amount);
        return amount;
    }
}

contract MockCCV {
    MockToken public token;
    bool public releases;
    uint256 public releaseAmount;
    address public releaseRecipient;
    constructor(address _token) { token = MockToken(_token); }
    function configure(bool _releases, uint256 _amount, address _recipient) external {
        releases = _releases; releaseAmount = _amount; releaseRecipient = _recipient;
    }
    function verifyMessage(bytes32, address) external {
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
    constructor(address _registry) { registry = MockRegistry(_registry); }
    function setRequiredCCVs(address[] memory _ccvs) external {
        delete requiredCCVs;
        for (uint256 i = 0; i < _ccvs.length; i++) requiredCCVs.push(_ccvs[i]);
    }
    function executeSingleMessage(address token, address receiver, uint256 amount, address[] calldata ccvs) external returns (uint256) {
        uint256 balancePre = MockToken(token).balanceOf(receiver);
        address[] memory toQuery = _ensureQuorum(ccvs);
        bytes32 mid = keccak256(abi.encode(token, receiver, amount));
        for (uint256 i = 0; i < toQuery.length; i++) MockCCV(toQuery[i]).verifyMessage(mid, receiver);
        MockTokenPool(registry.getPool(token)).releaseOrMint(receiver, amount);
        return MockToken(token).balanceOf(receiver) - balancePre;
    }
    function _ensureQuorum(address[] calldata submitted) internal view returns (address[] memory result) {
        result = new address[](requiredCCVs.length);
        uint256 n = 0;
        for (uint256 i = 0; i < requiredCCVs.length; i++) {
            bool found = false;
            for (uint256 j = 0; j < submitted.length; j++) {
                if (submitted[j] == requiredCCVs[i]) { result[n++] = submitted[j]; found = true; break; }
            }
            if (!found) revert("RequiredCCVMissing");
        }
        assembly { mstore(result, n) }
    }
}

contract CCIPMiniSystemTest is Test {
    MockToken token;
    MockLockBox lockBox;
    MockTokenPool pool;
    MockCCV ccv;
    MockRegistry registry;
    MiniOffRamp offRamp;
    address receiver = address(0xBEEF);
    uint256 constant AMT = 1_000_000e6;

    function setUp() public {
        token = new MockToken();
        lockBox = new MockLockBox(address(token));
        pool = new MockTokenPool(address(lockBox));
        ccv = new MockCCV(address(token));
        registry = new MockRegistry();
        offRamp = new MiniOffRamp(address(registry));
        lockBox.addAuthorizedCaller(address(pool));
        registry.setPool(address(token), address(pool));
        token.mint(address(lockBox), AMT * 10);
        address[] memory list = new address[](1);
        list[0] = address(ccv);
        offRamp.setRequiredCCVs(list);
    }

    function test_NormalFlow_SingleRelease() public {
        ccv.configure(false, 0, receiver);
        address[] memory ccvs = new address[](1);
        ccvs[0] = address(ccv);
        uint256 received = offRamp.executeSingleMessage(address(token), receiver, AMT, ccvs);
        console2.log("Normal flow - received:", received);
        assertEq(received, AMT, "should receive exactly AMT");
    }

    function test_DoubleRelease_VerifierAndPool() public {
        ccv.configure(true, AMT, receiver);
        address[] memory ccvs = new address[](1);
        ccvs[0] = address(ccv);
        uint256 received = offRamp.executeSingleMessage(address(token), receiver, AMT, ccvs);
        console2.log("Double release test - received:", received);
        console2.log("Expected if double:", AMT * 2);
        assertEq(received, AMT * 2, "double release: verifier + pool both released");
    }

    function test_ExtraCCV_IsIgnored() public {
        MockCCV evil = new MockCCV(address(token));
        evil.configure(true, AMT * 100, receiver);
        ccv.configure(false, 0, receiver);
        address[] memory ccvs = new address[](2);
        ccvs[0] = address(ccv);
        ccvs[1] = address(evil);
        uint256 received = offRamp.executeSingleMessage(address(token), receiver, AMT, ccvs);
        console2.log("Extra CCV test - received:", received);
        assertEq(received, AMT, "evil CCV must be ignored");
    }

    function test_MissingRequiredCCV_Reverts() public {
        address[] memory ccvs = new address[](0);
        vm.expectRevert("RequiredCCVMissing");
        offRamp.executeSingleMessage(address(token), receiver, AMT, ccvs);
    }

    function test_UnauthorizedLockboxWithdrawal_Reverts() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert("not authorized: LockBox");
        lockBox.withdraw(address(0xDEAD), AMT);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

// ================================================================
// ICEBALL ZILLION - LayerZero V2 "safe zone"
// Structurally grounded in real LZ V2 architecture (not a guess):
//   - Lossless channel: nonce-ordered packets, Sent -> Verified -> Received
//   - ReceiveUln302-style X-of-Y-of-N DVN quorum (required + optional + threshold)
//   - Lazy inbound nonce (skip-execution) per (receiver, srcEid, sender) pathway
//   - Packet = {nonce, srcEid, sender, dstEid, receiver, guid, message}
//   - commitVerification requires prior nonces committed (censorship-resistance rule)
// This is NOT a copy of LayerZero's source. It reimplements the *behavior*
// described in their public docs/whitepaper/interfaces so we can fuzz the
// same failure classes without touching live or testnet infra.
// Honesty note: this is a first pass. Real ULN/Endpoint has more edge cases
// (compose messages, alt-token endpoints, native OZ upgradeability) that we
// have not modeled yet. Extend together as agreed.
// ================================================================

library GUID {
    function gen(uint64 nonce, uint32 srcEid, address sender, uint32 dstEid, address receiver) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(nonce, srcEid, sender, dstEid, receiver));
    }
}

// -- Mock OApp: OFT-style burn/mint token with decimal conversion --
contract OAppToken {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    address public owner;
    address public endpoint;
    address public delegate; // real LZ: near-full config power, not full ownership
    mapping(uint32 => bytes32) public peers; // dstEid => peer (as bytes32, LZ style)
    uint8 public localDecimals = 18;
    uint8 public sharedDecimals = 6; // amountSD conversion, like real OFT
    bool public reenterOnReceive; // #10: trigger a reentrant send() from inside lzReceive
    uint32 public reenterDstEid;

    // #NFT01: ONFT-style uniqueness check. Real ONFT721/ONFT1155 (LayerZero's
    // NFT standard) requires the destination tokenId to NOT already exist -
    // unlike fungible OFT where re-delivery just adds more balance. Toggled
    // per-run by the harness.
    bool public nftMode;
    mapping(uint256 => bool) public nftOwned;

    // #USDC01: real USDC-style blacklist. If the destination token can
    // blacklist a recipient, a credit() call reverts - and per real LZ docs,
    // `clear(oapp, origin, guid, message)` lets the OApp itself explicitly
    // discard a permanently-stuck verified message ("oapp can burn messages
    // partially by calling this function with its own business logic").
    mapping(address => bool) public blacklisted;
    function setBlacklisted(address who, bool val) external onlyOwner { blacklisted[who] = val; }
    function setNftMode(bool on) external onlyOwner { nftMode = on; }

    // Security stack per this OApp (single-remote-simplified for the harness)
    address[] public requiredDVNs;
    address[] public optionalDVNs;
    uint8 public optionalThreshold;
    uint64 public confirmations;

    event Received(address indexed to, uint256 amt);

    constructor(address _endpoint) { owner = msg.sender; endpoint = _endpoint; }
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    modifier onlyEndpoint() { require(msg.sender == endpoint, "not endpoint"); _; }

    function setPeer(uint32 eid, bytes32 peer) external onlyOwner { peers[eid] = peer; }
    function setDelegate(address d) external onlyOwner { delegate = d; }
    function setReentrancy(bool on, uint32 dstEid) external onlyOwner { reenterOnReceive = on; reenterDstEid = dstEid; }
    // Real LZ: delegate can call setConfig on the OApp's behalf (near-owner power for config, not for mint/ownership).
    modifier onlyOwnerOrDelegate() { require(msg.sender == owner || msg.sender == delegate, "not owner or delegate"); _; }
    function setConfig(address[] calldata req, address[] calldata opt, uint8 thresh, uint64 conf) external onlyOwnerOrDelegate {
        requiredDVNs = req; optionalDVNs = opt; optionalThreshold = thresh; confirmations = conf;
    }
    function mint(address to, uint256 amt) external onlyOwner { balanceOf[to] += amt; totalSupply += amt; }

    function _toSD(uint256 amtLD) internal view returns (uint64) {
        if (localDecimals <= sharedDecimals) return uint64(amtLD);
        return uint64(amtLD / (10 ** (localDecimals - sharedDecimals)));
    }
    function _toLD(uint64 amtSD) internal view returns (uint256) {
        if (localDecimals <= sharedDecimals) return uint256(amtSD);
        return uint256(amtSD) * (10 ** (localDecimals - sharedDecimals));
    }

    // Burns locally, asks endpoint to send. Amount is round-tripped through
    // shared-decimal conversion exactly like real OFT (this is where dust /
    // rounding bugs live).
    function send(uint32 dstEid, address to, uint256 amtLD) external returns (bytes memory message, uint64 nonce) {
        require(balanceOf[msg.sender] >= amtLD, "insufficient");
        uint64 amtSD = _toSD(amtLD);
        require(amtSD > 0, "dust: rounds to zero");
        balanceOf[msg.sender] -= amtLD; totalSupply -= amtLD;
        message = abi.encode(to, amtSD);
        nonce = IEndpoint(endpoint).send(dstEid, peers[dstEid], message);
    }

    // #FEE01: real OFTAdapter vulnerability - the adapter wraps an EXTERNAL
    // token and its _debit typically calls token.transferFrom(user, this,
    // amount). If that token charges a fee-on-transfer (or is rebasing), the
    // ACTUAL balance received by the adapter is LESS than the nominal
    // `amount` parameter. If the adapter naively bridges the NOMINAL amount
    // (not the observed balance delta), the destination mints more value
    // than was ever actually locked - real fund-multiplication class, the
    // same shape as several real bridge hacks. Modeled directly: only a
    // FEE-REDUCED amount actually leaves circulation, but the bridged
    // message still declares the full nominal amount.
    function sendFeeOnTransfer(uint32 dstEid, address to, uint256 amtLD, uint256 feeBps) external returns (bytes memory message, uint64 nonce) {
        require(balanceOf[msg.sender] >= amtLD, "insufficient");
        uint64 amtSD = _toSD(amtLD); // BUG SURFACE: derived from the full nominal amount
        require(amtSD > 0, "dust: rounds to zero");
        uint256 actuallyRemoved = amtLD - (amtLD * feeBps / 10000); // less actually leaves circulation
        balanceOf[msg.sender] -= actuallyRemoved; totalSupply -= actuallyRemoved;
        message = abi.encode(to, amtSD);
        nonce = IEndpoint(endpoint).send(dstEid, peers[dstEid], message);
    }

    // Called by endpoint after nonce ordering + DVN quorum + payload hash verified.
    function lzReceive(uint32 srcEid, bytes32 sender, bytes calldata message) external onlyEndpoint {
        (address to, uint64 amtSD) = abi.decode(message, (address, uint64));
        // #USDC01: real USDC-style recipient blacklist - if the destination
        // account is blacklisted, credit() reverts. This makes the whole
        // lzReceive revert too (matching a real stuck-message scenario),
        // since our simplified mock has no separate escrow/credit split.
        require(!blacklisted[to], "recipient blacklisted - message stuck until clear()");
        if (nftMode) {
            // #NFT01: treat amtSD as a tokenId. Real ONFT must reject a
            // second mint of the same tokenId - unlike fungible OFT credit,
            // which just adds balance on redelivery.
            require(!nftOwned[amtSD], "NFT: tokenId already minted - ONFT uniqueness violated");
            nftOwned[amtSD] = true;
            emit Received(to, amtSD);
            return;
        }
        uint256 amtLD = _toLD(amtSD);
        balanceOf[to] += amtLD; totalSupply += amtLD;
        emit Received(to, amtLD);
        // #10: reentrancy - real LZ allows an OApp's lzReceive to trigger a new
        // outbound send() (composability is a feature). The question is whether
        // anything upstream (ULN storage reclaim, endpoint nonce bookkeeping)
        // assumes it has exclusive control mid-callback. We re-enter here if the
        // harness has armed it, and the test driver checks post-state for
        // corruption (e.g. a nonce or hashLookup entry left in an inconsistent
        // state because the reentrant send() ran before the outer call finished).
        if (reenterOnReceive) {
            reenterOnReceive = false; // avoid infinite reentry within the mock
            try this.send(reenterDstEid, to, amtLD > 0 ? amtLD / 2 : 0) {} catch {}
        }
        // #2: real OApps can queue a compose follow-up during lzReceive.
        // Harness arms this via composeArmed; the compose payload here just
        // mints a small bonus to simulate a follow-up action.
        if (composeArmed) {
            composeArmed = false;
            bytes memory composeMsg = abi.encode(to, uint256(1 ether));
            EndpointMock(payable(endpoint)).sendCompose(address(this), composeGuid, 0, composeMsg);
        }
    }

    bool public composeArmed;
    bytes32 public composeGuid;
    function armCompose(bytes32 guid) external onlyOwner { composeArmed = true; composeGuid = guid; }

    // Called by endpoint.lzCompose() once the compose slot is validated.
    function lzCompose(address /*from*/, bytes32 /*guid*/, bytes calldata message) external {
        require(msg.sender == endpoint, "not endpoint");
        (address to2, uint256 bonus) = abi.decode(message, (address, uint256));
        balanceOf[to2] += bonus; totalSupply += bonus;
    }
}

interface IEndpoint {
    function send(uint32 dstEid, bytes32 peer, bytes calldata message) external returns (uint64 nonce);
}

// -- Mock Endpoint: nonce-ordered lossless channel --
contract EndpointMock is IEndpoint {
    receive() external payable {}
    // #DROP01: real ExecutorOptions.decodeNativeDropOption decodes
    // (amount, receiver) - encoded ONCE by the SENDER inside options at
    // send-time. The real security property: the executor should only ever
    // execute EXACTLY the pre-declared amount for a SPECIFIC delivered
    // message, never an arbitrary amount. This function has no such binding
    // at all - testing whether a permissionless "executor" can drain the
    // endpoint's entire collected-fee balance via one uncapped call.
    function executeNativeDrop(address to, uint256 amount) external {
        payable(to).transfer(amount);
    }
    uint32 public immutable eid;
    address public uln;
    mapping(address => bool) public isValidUln; // #1: real LZ grace period allows old+new libs valid simultaneously

    // outbound: sender => dstEid => nonce
    mapping(address => mapping(uint32 => uint64)) public outboundNonce;
    // inbound: receiver => srcEid => sender(as bytes32) => nonce => payloadHash committed
    mapping(address => mapping(uint32 => mapping(bytes32 => mapping(uint64 => bytes32)))) public inboundPayloadHash;
    // lazy inbound nonce: highest nonce eligible for skip-ahead (LZ's actual mechanism)
    mapping(address => mapping(uint32 => mapping(bytes32 => uint64))) public lazyInboundNonce;
    // executed nonce: highest nonce actually delivered (lzReceive succeeded)
    mapping(address => mapping(uint32 => mapping(bytes32 => uint64))) public inboundNonce;

    constructor(uint32 _eid) { eid = _eid; }
    // #2: compose message chain. Real LZ lets an OApp queue a follow-up call
    // via endpoint.sendCompose() during lzReceive; an executor later delivers
    // it via lzCompose(), tracked entirely separately from the main inbound
    // nonce. Two real properties worth fuzzing: (a) can a compose slot be
    // executed twice (replay), (b) can lzCompose be called for a slot that
    // was never actually queued (fabricated compose delivery).
    mapping(bytes32 => bool) public composeQueued;
    mapping(bytes32 => bytes32) public composeHash;
    mapping(bytes32 => bool) public composeExecuted;

    function sendCompose(address to, bytes32 guid, uint16 index, bytes calldata message) external {
        bytes32 key = keccak256(abi.encodePacked(msg.sender, to, guid, index));
        composeQueued[key] = true;
        composeHash[key] = keccak256(message);
    }

    function lzCompose(address from, address to, bytes32 guid, uint16 index, bytes calldata message) external {
        bytes32 key = keccak256(abi.encodePacked(from, to, guid, index));
        require(composeQueued[key], "compose not queued");
        require(!composeExecuted[key], "compose already executed");
        require(composeHash[key] == keccak256(message), "compose payload mismatch");
        composeExecuted[key] = true;
        OAppToken(to).lzCompose(from, guid, message);
    }

    function setUln(address _uln) external { uln = _uln; isValidUln[_uln] = true; }
    // #1: real LZ setReceiveLibrary has a gracePeriod where the OLD library
    // stays valid alongside the new one until the grace period ends. Modeled
    // here as: admin can mark an additional (older, weaker) library valid
    // without revoking the new one - commitPayload accepts either.
    function addGraceUln(address _oldUln) external { isValidUln[_oldUln] = true; }
    function revokeGraceUln(address _oldUln) external { isValidUln[_oldUln] = false; }

    function send(uint32 dstEid, bytes32 /*peer*/, bytes calldata message) external returns (uint64 nonce) {
        nonce = ++outboundNonce[msg.sender][dstEid];
        // in real LZ this emits PacketSent for DVNs/executors to pick up off-chain;
        // in our harness the test driver plays DVN + Executor directly.
        message; // silence unused warning in some solc configs
    }

    // Called by ULN once quorum verified - commits the payload hash for this nonce.
    function commitPayload(address receiver, uint32 srcEid, bytes32 sender, uint64 nonce, bytes32 payloadHash) external {
        require(isValidUln[msg.sender], "not a valid receive library for this pathway");
        // Lossless channel rule: a nonce can only be committed if it isn't
        // already committed, and (in the strict model) prior nonces are
        // either committed or explicitly skipped via lazyInboundNonce.
        require(inboundPayloadHash[receiver][srcEid][sender][nonce] == bytes32(0), "already committed");
        inboundPayloadHash[receiver][srcEid][sender][nonce] = payloadHash;
    }

    // Executor calls this to actually deliver. Enforces strict ordering:
    // nonce must be lazyInboundNonce+1 unless skip() was called (real LZ
    // behavior - this is what "lossless channel reverts to prevent
    // censorship" means in the whitepaper).
    // FIXED after finding real PacketV1Codec.sol: real payloadHash = keccak256(payload)
    // where payload = abi.encodePacked(guid, message) - NOT keccak256(message) alone.
    // Our mock previously omitted guid entirely from every hash comparison.
    function lzReceive(address receiver, uint32 srcEid, bytes32 sender, uint64 nonce, bytes32 guid, bytes calldata message) external {
        bytes32 committed = inboundPayloadHash[receiver][srcEid][sender][nonce];
        require(committed != bytes32(0), "not verified");
        require(committed == keccak256(abi.encodePacked(guid, message)), "payload mismatch");
        uint64 lastExec = inboundNonce[receiver][srcEid][sender];
        uint64 lazy = lazyInboundNonce[receiver][srcEid][sender];
        uint64 floor = lazy > lastExec ? lazy : lastExec;
        require(nonce == floor + 1, "out of order: preceding nonce not delivered/skipped");
        inboundNonce[receiver][srcEid][sender] = nonce;
        OAppToken(receiver).lzReceive(srcEid, sender, message);
    }

    // #USDC01: real ILayerZeroEndpointV2.clear(oapp, origin, guid, message) -
    // "oapp can burn messages partially by calling this function with its
    // own business logic if messages are verified in order." Lets the OApp
    // itself explicitly discard a message that's permanently stuck (e.g. its
    // own credit() logic keeps reverting on a blacklisted recipient) without
    // ever running the business logic - just advances the nonce floor.
    function clear(address oapp, uint32 srcEid, bytes32 sender, uint64 nonce, bytes32 guid, bytes calldata message) external {
        require(msg.sender == oapp, "only the oapp itself can clear its own message");
        bytes32 committed = inboundPayloadHash[oapp][srcEid][sender][nonce];
        require(committed != bytes32(0), "not verified");
        require(committed == keccak256(abi.encodePacked(guid, message)), "payload mismatch");
        uint64 lastExec = inboundNonce[oapp][srcEid][sender];
        uint64 lazy = lazyInboundNonce[oapp][srcEid][sender];
        uint64 floor = lazy > lastExec ? lazy : lastExec;
        require(nonce == floor + 1, "out of order");
        inboundNonce[oapp][srcEid][sender] = nonce; // advances floor WITHOUT calling lzReceive - message discarded, not delivered
    }

    // Real ILayerZeroEndpointV2.verifiable(origin, receiver) - "true" once a
    // payload hash has been committed for that nonce but not yet executed.
    function verifiable(address receiver, uint32 srcEid, bytes32 sender, uint64 nonce) external view returns (bool) {
        return inboundPayloadHash[receiver][srcEid][sender][nonce] != bytes32(0);
    }

    // Real ILayerZeroEndpointV2.initializable(origin, receiver) - true only
    // for the very first nonce on a pathway that's never had anything
    // executed or skipped yet (floor == 0).
    function initializable(address receiver, uint32 srcEid, bytes32 sender) external view returns (bool) {
        uint64 lastExec = inboundNonce[receiver][srcEid][sender];
        uint64 lazy = lazyInboundNonce[receiver][srcEid][sender];
        return (lastExec == 0 && lazy == 0);
    }

    // Real LZ lets an OApp/owner "skip" a nonce it knows will never be
    // deliverable, advancing the lazy floor without executing it.
    function skip(address receiver, uint32 srcEid, bytes32 sender, uint64 nonceToSkip) external {
        require(msg.sender == receiver, "only receiver oapp");
        uint64 lastExec = inboundNonce[receiver][srcEid][sender];
        uint64 lazy = lazyInboundNonce[receiver][srcEid][sender];
        uint64 floor = lazy > lastExec ? lazy : lastExec;
        require(nonceToSkip == floor + 1, "can only skip next nonce");
        lazyInboundNonce[receiver][srcEid][sender] = nonceToSkip;
    }
}

// -- Mock ULN: X-of-Y-of-N DVN quorum, structurally per real ReceiveUlnBase/ReceiveUln302 --
// Patched after diffing against real source:
//  (1) Verification now carries a `confirmations` depth, matching real
//      `struct Verification { bool submitted; uint64 confirmations; }` and the
//      real check `confirmations >= config.confirmations` per DVN.
//  (2) commitVerification DELETES hashLookup entries for every required/
//      optional DVN after a successful commit, matching real
//      `_verifyAndReclaimStorage`. Without this, a stale attestation could be
//      reused across an unrelated later commit attempt in our mock in ways
//      the real contract explicitly prevents.
//  (3) NOTE on semantics we still simplify: real UlnConfig treats
//      requiredDVNCount==0 as "inherit DEFAULT config" and a NIL sentinel as
//      explicit "NONE". We don't have a separate default-config contract in
//      this harness, so our D45 "config wiped to req=[],opt=[],thresh=0"
//      injection is best read as "OApp owner explicitly sets an open config"
//      (a governance/timing risk), not a protocol-level DEFAULT/NONE bypass.
//      Detection text below has been corrected to reflect that.
contract UlnMock {
    EndpointMock public endpoint;
    uint8 internal constant PACKET_VERSION = 1; // matches real PacketV1Codec.PACKET_VERSION
    constructor(address _endpoint) { endpoint = EndpointMock(payable(_endpoint)); }

    struct Verification { bool submitted; uint64 confirmations; }
    // hashLookup[headerHash][payloadHash][dvn]
    mapping(bytes32 => mapping(bytes32 => mapping(address => Verification))) public hashLookup;

    struct Pathway { address[] required; address[] optional; uint8 optionalThreshold; uint64 confirmations; }
    mapping(bytes32 => Pathway) public pathway; // key = keccak(receiver, srcEid, sender)
    mapping(bytes32 => bool) public hasOverride; // #3: has this pathway ever been explicitly set?
    Pathway public defaultPathway; // #3: real LZ - requiredDVNCount==0 means "inherit this", not "no DVNs"

    // Errors named to match real UlnBase.sol for clarity in test output.
    error LZ_ULN_AtLeastOneDVN();
    error LZ_ULN_InvalidOptionalDVNThreshold();

    function setPathway(address receiver, uint32 srcEid, bytes32 sender, address[] calldata req, address[] calldata opt, uint8 thresh, uint64 confirmations) external {
        _assertThresholdConsistency(opt, thresh);
        bytes32 key = keccak256(abi.encodePacked(receiver, srcEid, sender));
        pathway[key] = Pathway(req, opt, thresh, confirmations);
        hasOverride[key] = true;
    }

    // #3: real LayerZero (the admin) can change the global default library
    // config. Any OApp that never explicitly overrode its own pathway (the
    // common case - requiredDVNCount==0 literally means "use default") gets
    // repriced/reconfigured with zero on-chain signal to that OApp's owner.
    // Fixed after our earlier honest gap: we used to treat an unconfigured
    // pathway as an empty Solidity default (silently permissive); now it
    // correctly falls back to whatever LZ has set as the real default.
    // #3 CORRECTED TWICE now, against the literal real source (not inference):
    //   real: function _assertAtLeastOneDVN(UlnConfig memory _config) private pure {
    //       if (_config.requiredDVNCount == 0 && _config.optionalDVNThreshold == 0)
    //           revert LZ_ULN_AtLeastOneDVN();
    //   }
    // This checks requiredDVNCount and optionalDVNThreshold specifically - NOT
    // "total array length", which is what our first fix used as an approximation.
    // Also added the real _setConfig consistency rule we were missing entirely:
    // optionalDVNThreshold must be 0 when there are no optional DVNs, and in
    // (0, optionalCount] otherwise - real code enforces this at every setConfig
    // call, we previously enforced it nowhere.
    function setDefaultPathway(address[] calldata req, address[] calldata opt, uint8 thresh, uint64 confirmations) external {
        _assertThresholdConsistency(opt, thresh);
        if (req.length == 0 && thresh == 0) revert LZ_ULN_AtLeastOneDVN();
        defaultPathway = Pathway(req, opt, thresh, confirmations);
    }

    function _assertThresholdConsistency(address[] calldata opt, uint8 thresh) internal pure {
        if (opt.length == 0) {
            if (thresh != 0) revert LZ_ULN_InvalidOptionalDVNThreshold();
        } else {
            if (thresh == 0 || thresh > opt.length) revert LZ_ULN_InvalidOptionalDVNThreshold();
        }
    }

    function _resolvePathway(bytes32 key) internal view returns (Pathway memory) {
        return hasOverride[key] ? pathway[key] : defaultPathway;
    }

    // Called by a DVN (honest or malicious) with what it claims is the payload hash,
    // plus the confirmation depth it claims to have observed (real IReceiveUlnE2.verify signature).
    function verify(bytes32 headerHash, bytes32 payloadHash, address dvn, uint64 confirmations) external {
        hashLookup[headerHash][payloadHash][dvn] = Verification(true, confirmations);
    }

    // Called by executor once it believes quorum is met. Re-derives quorum
    // on-chain (this is the actual security boundary - if this check is
    // wrong or bypassable, quorum is meaningless). Now checks confirmation
    // depth per DVN, matching real _checkVerifiable, and reclaims storage
    // afterward, matching real _verifyAndReclaimStorage.
    //
    // NEW: also asserts the header's claimed dstEid/version before touching
    // any state, matching real ReceiveUlnBase.assertHeader / _assertHeader
    // called at the top of the real commitVerification. Our earlier version
    // skipped this entirely and trusted the executor's srcEid/receiver args
    // outright - this closes that gap (Group G injections below).
    function commitVerification(
        address receiver, uint32 srcEid, bytes32 sender, uint64 nonce,
        bytes32 headerHash, bytes32 payloadHash,
        uint32 claimedDstEid, uint8 claimedVersion
    ) external {
        // real: if (_packetHeader.version() != PACKET_VERSION) revert LZ_ULN_InvalidPacketVersion();
        require(claimedVersion == PACKET_VERSION, "invalid packet version");
        // real: if (_packetHeader.dstEid() != localEid) revert LZ_ULN_InvalidEid();
        require(claimedDstEid == endpoint.eid(), "invalid eid: packet not addressed to this endpoint");

        Pathway memory p = _resolvePathway(keccak256(abi.encodePacked(receiver, srcEid, sender)));
        for (uint256 i = 0; i < p.required.length; i++) {
            Verification memory v = hashLookup[headerHash][payloadHash][p.required[i]];
            require(v.submitted && v.confirmations >= p.confirmations, "required DVN missing or insufficient confirmations");
        }
        if (p.optionalThreshold > 0) {
            uint256 count = 0;
            for (uint256 i = 0; i < p.optional.length; i++) {
                Verification memory v = hashLookup[headerHash][payloadHash][p.optional[i]];
                if (v.submitted && v.confirmations >= p.confirmations) count++;
            }
            require(count >= p.optionalThreshold, "optional threshold not met");
        }
        endpoint.commitPayload(receiver, srcEid, sender, nonce, payloadHash);
        // storage reclaim, matching real _verifyAndReclaimStorage
        for (uint256 i = 0; i < p.required.length; i++) delete hashLookup[headerHash][payloadHash][p.required[i]];
        for (uint256 i = 0; i < p.optional.length; i++) delete hashLookup[headerHash][payloadHash][p.optional[i]];
    }
}

contract DVN {
    UlnMock public uln;
    bool public malicious;
    uint256 public minFee; // #6: DVN's minimum required fee to bother attesting
    address public currentSigner; // #SIG01: real DVNs gate attestation on an authorized signer key
    constructor(address _uln, bool _malicious) {
        uln = _uln == address(0) ? UlnMock(address(0)) : UlnMock(_uln);
        malicious = _malicious;
        currentSigner = address(this); // defaults to self-signing, matching prior behavior
    }
    function setMinFee(uint256 fee) external { minFee = fee; }
    // #SIG01: real KelpDAO incident report: "the signer list can only be
    // modified if a quorum of existing signers sign the change." Modeled
    // minimally as a single current signer that only itself can rotate.
    function rotateSigner(address newSigner) external {
        require(msg.sender == currentSigner, "only current signer can rotate");
        currentSigner = newSigner;
    }
    // #6: real DVNs are paid per job via SendUln302._payDVNs. If the fee paid
    // is below what this DVN requires, an honest (non-malicious, non-byzantine)
    // DVN simply declines to attest - this is real economic griefing surface,
    // not a code bug: underpaying required DVNs can silently stall a pathway
    // with no on-chain signal distinguishing it from active censorship.
    function attest(bytes32 headerHash, bytes calldata realMessage, bytes calldata claimedMessage, uint64 confirmations, uint256 feePaid) external {
        if (feePaid < minFee) return; // declines silently, exactly like a real underpaid DVN would
        require(msg.sender == currentSigner, "not the authorized signer");
        bytes32 hash = malicious ? keccak256(claimedMessage) : keccak256(realMessage);
        uln.verify(headerHash, hash, address(this), confirmations);
    }
}

contract IceBallConfirmed is Test {
    EndpointMock srcEndpoint; EndpointMock dstEndpoint;
    UlnMock uln;
    UlnMock ulnOld; // #1: grace-period-valid old library, deliberately weak (no required DVNs)
    OAppToken srcApp; OAppToken dstApp;
    OAppToken dstApp2; // #3/#9: relies purely on default pathway, never explicitly configured
    DVN dvnA; DVN dvnB; DVN dvnMalicious;

    address OWNER = address(0x1111);
    address ATTACKER = address(0xDEAD);
    address RECEIVER = address(0xBEEF);
    address ALICE = address(0xA11CE);
    uint32 constant SRC_EID = 30101;
    uint32 constant DST_EID = 30102;
    uint256 constant AMT = 1000 ether;

    uint8 constant N = 114; // NUM_INJ (v7 - Group P: native gas-drop drain, forged read-response, hollow payload)
    uint32 constant READ_CHANNEL_EID = 4294967295; // #9: reserved-range sentinel, real LZ reserves a high eid range for read channels

    // Group A (0-14): DVN quorum manipulation
    uint8 constant A00=102; uint8 constant A01=101; uint8 constant A02=100; uint8 constant A03=99; uint8 constant A04=98;
    uint8 constant A05=97; uint8 constant A06=96; uint8 constant A07=95; uint8 constant A08=94; uint8 constant A09=93;
    uint8 constant A10=92; uint8 constant A11=91; uint8 constant A12=90; uint8 constant A13=89; uint8 constant A14=88;
    // Group B (15-29): Nonce / ordering (lossless channel) attacks
    uint8 constant B15=87; uint8 constant B16=86; uint8 constant B17=85; uint8 constant B18=84; uint8 constant B19=83;
    uint8 constant B20=82; uint8 constant B21=81; uint8 constant B22=80; uint8 constant B23=79; uint8 constant B24=78;
    uint8 constant B25=77; uint8 constant B26=76; uint8 constant B27=75; uint8 constant B28=74; uint8 constant B29=73;
    // Group C (30-44): Payload / message tampering post-verification
    uint8 constant C30=72; uint8 constant C31=71; uint8 constant C32=70; uint8 constant C33=69; uint8 constant C34=68;
    uint8 constant C35=67; uint8 constant C36=66; uint8 constant C37=65; uint8 constant C38=64; uint8 constant C39=63;
    uint8 constant C40=62; uint8 constant C41=61; uint8 constant C42=60; uint8 constant C43=59; uint8 constant C44=58;
    // Group D (45-59): Security-stack config drift
    uint8 constant D45=57; uint8 constant D46=56; uint8 constant D47=55; uint8 constant D48=54; uint8 constant D49=53;
    uint8 constant D50=52; uint8 constant D51=51; uint8 constant D52=50; uint8 constant D53=49; uint8 constant D54=48;
    uint8 constant D55=47; uint8 constant D56=46; uint8 constant D57=45; uint8 constant D58=44; uint8 constant D59=43;
    // Group E (60-74): OFT decimal / amount edge cases
    uint8 constant E60=42; uint8 constant E61=41; uint8 constant E62=40; uint8 constant E63=39; uint8 constant E64=38;
    uint8 constant E65=37; uint8 constant E66=36; uint8 constant E67=35; uint8 constant E68=34; uint8 constant E69=33;
    uint8 constant E70=32; uint8 constant E71=31; uint8 constant E72=30; uint8 constant E73=29; uint8 constant E74=28;
    // Group F (75-89): Executor / peer / economic griefing
    uint8 constant F75=27; uint8 constant F76=26; uint8 constant F77=25; uint8 constant F78=24; uint8 constant F79=23;
    uint8 constant F80=22; uint8 constant F81=21; uint8 constant F82=20; uint8 constant F83=19; uint8 constant F84=18;
    uint8 constant F85=17; uint8 constant F86=16; uint8 constant F87=15; uint8 constant F88=14; uint8 constant F89=13;
    // Group G (90-91): Header validation (real _assertHeader: dstEid + version)
    uint8 constant G90=12; uint8 constant G91=11;
    // Group H (92-93): dual-hat DVN (#4), fee-starved DVN griefing (#6)
    uint8 constant H92=10; uint8 constant H93=9;
    // Group I (94-95): cross-pathway nonce floor confusion (#5), initializable/verifiable race (#7)
    uint8 constant I94=8; uint8 constant I95=7;
    // Group J (96): delegate revocation guard check (#8)
    uint8 constant J96=6;
    // Group K (97): grace-period dual-library race (#1)
    uint8 constant K97=5;
    // Group L (98): reentrancy via composability (#10)
    uint8 constant L98=4;
    // Group M (99-102): default-config inheritance (#3), read-channel (#9), compose replay/forgery (#2)
    uint8 constant M99=3; uint8 constant M100=2; uint8 constant M101=1; uint8 constant M102=0;
    // Group N (103-106): NFT uniqueness, address-truncation collision,
    // USDC-style blacklist+clear(), and real verifiable()/initializable() checks.
    uint8 constant NFT01=103; uint8 constant ADDR01=104; uint8 constant USDC01=105; uint8 constant RDY01=106;
    // Group O (107-110): fee-on-transfer accounting mismatch, encodePacked
    // collision audit, cross-OApp receiver-confusion replay, DVN signer
    // rotation mid-flight (real KelpDAO incident report quote: "the signer
    // list can only be modified if a quorum of existing signers sign the change").
    uint8 constant FEE01=107; uint8 constant MAC01=108; uint8 constant RCV01=109; uint8 constant SIG01=110;
    // Group P (111-113): native gas-drop drain, forged read-response, and
    // "hollow" (empty/malformed) message payload decode boundary.
    uint8 constant DROP01=111; uint8 constant READ01=112; uint8 constant HOLLOW01=113;

    uint256 public totalRun;
    uint256 public critCount; uint256 public highCount; uint256 public medCount; uint256 public lowCount;
    mapping(bytes32 => bool) public seen;

    // per-run mutable flags (reset each _run so groups can toggle behavior)
    bool _skipRequiredDVN; bool _dupOptionalDVN; bool _fakeExtraDVNAttests; bool _thresholdZeroButOptionalOnly;
    bool _insufficientConfirmations; // A05, new: required DVN attests but below config's confirmation depth
    bool _wrongDstEidInHeader; bool _wrongPacketVersion; // G90/G91, new: real _assertHeader checks
    bool _replayCommit; bool _skipAheadNonce; bool _executeWithoutSkip; bool _reuseNonceAcrossPathway;
    bool _tamperAfterVerify; bool _wrongReceiverInMessage; bool _zeroAmountMessage;
    bool _configChangedMidFlight; bool _thresholdLoweredMidFlight; bool _dvnRemovedMidFlight;
    uint8 _decimalsLocal = 18; uint8 _decimalsShared = 6;
    bool _peerZero; bool _peerMismatch; bool _doubleDeliver;
    bool _dualHatDVN; bool _feeStarvedDVN;
    bool _crossPathwayNonceConfusion; bool _initializableRace;
    bool _delegateRevoked; bool _graceOldLibRace; bool _reentrancyArmed;
    bool _weakenedDefaultConfig; bool _readChannelUnconfigured; bool _composeReplay; bool _composeForgery;
    bool _nftDoubleMint; bool _addrTruncationCollision; bool _usdcBlacklistStuck; bool _checkReadyStates;
    bool _feeOnTransferMismatch; bool _macCollisionCheck; bool _receiverConfusion; bool _signerRotationMidFlight;
    bool _nativeDropDrain; bool _forgedReadResponse; bool _hollowPayload;

    function setUp() public {
        vm.startPrank(OWNER);
        srcEndpoint = new EndpointMock(SRC_EID);
        dstEndpoint = new EndpointMock(DST_EID);
        uln = new UlnMock(address(dstEndpoint));
        dstEndpoint.setUln(address(uln));
        ulnOld = new UlnMock(address(dstEndpoint)); // #1: deliberately weak/no-DVN pathway, not registered as current lib
        srcApp = new OAppToken(address(srcEndpoint));
        dstApp = new OAppToken(address(dstEndpoint));
        dvnA = new DVN(address(uln), false);
        dvnB = new DVN(address(uln), false);
        dvnMalicious = new DVN(address(uln), true);
        dvnA.setMinFee(100); dvnB.setMinFee(100); // #6: DVNs require a minimum fee to bother attesting
        vm.deal(address(dstEndpoint), 10 ether); // #DROP01: simulated collected fees

        srcApp.setPeer(DST_EID, bytes32(uint256(uint160(address(dstApp)))));
        dstApp.setPeer(SRC_EID, bytes32(uint256(uint160(address(srcApp)))));

        address[] memory req = new address[](1); req[0] = address(dvnA);
        address[] memory opt = new address[](1); opt[0] = address(dvnB);
        uln.setPathway(address(dstApp), SRC_EID, bytes32(uint256(uint160(address(srcApp)))), req, opt, 1, 5);
        {
            // #3/#9: baseline global default - represents LayerZero's actual
            // chosen default DVN set. dstApp2 below NEVER gets its own
            // uln.setPathway call, so it relies entirely on this default,
            // exactly like most real OApps that never touch requiredDVNCount.
            address[] memory defReq = new address[](1); defReq[0] = address(dvnA);
            address[] memory defOpt = new address[](0);
            uln.setDefaultPathway(defReq, defOpt, 0, 5);
        }
        dstApp2 = new OAppToken(address(dstEndpoint)); // #3/#9: intentionally never overridden
        {
            // #1 CORRECTED: real _setUlnConfig re-validates via getUlnConfig's own
            // _assertAtLeastOneDVN check too (not just setDefaultUlnConfigs) - so a
            // literally-zero-DVN old library pathway is likely unrealistic, same
            // correction as #3/M99. Old library is weak (1 DVN, dvnB) not empty.
            address[] memory weakReq = new address[](1); weakReq[0] = address(dvnB);
            address[] memory noOpt = new address[](0);
            ulnOld.setPathway(address(dstApp2), SRC_EID, bytes32(uint256(uint160(address(srcApp)))), weakReq, noOpt, 0, 5);
        }

        srcApp.mint(ALICE, AMT * 1000);
        vm.stopPrank();
    }

    function _computeGuid(uint64 nonce_, uint32 srcEid_, bytes32 sender_, uint32 dstEid_, address receiver_) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(nonce_, srcEid_, sender_, dstEid_, bytes32(uint256(uint160(receiver_)))));
    }

    // ================================================================
    // ISOLATED CONFIRMED-REAL FINDINGS ONLY.
    //
    // This file is a deliberate extraction from IceBallQuery.sol, keeping
    // ONLY the mock infrastructure (EndpointMock, UlnMock, DVN, OAppToken),
    // setUp(), and the direct tests for findings that were confirmed REAL
    // - stripped of the 114-injection catalog, the _run()/_bug() harness,
    // and all 11 tests that confirmed a claim was a FALSE POSITIVE. The
    // goal: a clean, focused surface for thorough re-testing of exactly
    // the findings that matter, per Doctor Amr's request.
    //
    // Two tiers below, kept explicitly separate:
    //
    // TIER 1 - TRACE-VERIFIED: these 9 tests (matching the 9 confirmed-
    // real findings) were run in this session, and their full execution
    // traces were read and confirmed line by line before being logged
    // as real findings.
    //
    // TIER 2 - NEEDS FRESH VERIFICATION: these 3 tests were found in the
    // uploaded file's tail but were NEVER walked through with a trace in
    // this session. They claim real findings (fee-on-transfer supply
    // mismatch, two peer-spoofing variants), but per the "don't assume"
    // standard applied to everything else in this file, they are NOT
    // being treated as confirmed until they're actually run and their
    // traces reviewed - same rigor as every other finding here got.
    // ================================================================

    // ---------------- TIER 1: TRACE-VERIFIED REAL FINDINGS ----------------

    function test_ASSERT_DROP01_NativeDropDrain_DIRECT() public {
        EndpointMock freshEndpoint = new EndpointMock(DST_EID);
        address randomAttacker = address(0xA77ACC);

        uint256 fundedAmount = 5 ether;
        vm.deal(address(freshEndpoint), fundedAmount);

        uint256 endpointBalBefore = address(freshEndpoint).balance;
        uint256 attackerBalBefore = randomAttacker.balance;
        assertEq(endpointBalBefore, fundedAmount, "sanity: endpoint should hold the funded amount");
        assertEq(attackerBalBefore, 0, "sanity: attacker should start with zero balance");

        vm.prank(randomAttacker);
        freshEndpoint.executeNativeDrop(randomAttacker, endpointBalBefore);

        uint256 endpointBalAfter = address(freshEndpoint).balance;
        uint256 attackerBalAfter = randomAttacker.balance;

        assertEq(endpointBalAfter, 0, "DROP01 did NOT reproduce: endpoint balance was not drained to zero");
        assertEq(
            attackerBalAfter,
            attackerBalBefore + endpointBalBefore,
            "DROP01 did NOT reproduce: attacker did not receive the full drained amount"
        );
    }

    function test_ASSERT_A01D45_QuorumBypass_DIRECT() public {
        vm.prank(ALICE);
        (bytes memory message, uint64 nonce) = srcApp.send(DST_EID, RECEIVER, AMT);
        bytes32 senderKey = bytes32(uint256(uint160(address(srcApp))));
        bytes32 headerHash = keccak256(abi.encodePacked(SRC_EID, senderKey, DST_EID, address(dstApp), nonce));

        vm.prank(address(dvnB));
        dvnB.attest(headerHash, message, message, 10, 100);

        vm.prank(OWNER);
        address[] memory emptyReq = new address[](0);
        address[] memory emptyOpt = new address[](0);
        uln.setPathway(address(dstApp), SRC_EID, senderKey, emptyReq, emptyOpt, 0, 0);

        bytes32 guid = _computeGuid(nonce, SRC_EID, senderKey, DST_EID, address(dstApp));
        bytes32 payloadHash = keccak256(abi.encodePacked(guid, message));

        vm.prank(ATTACKER);
        uln.commitVerification(address(dstApp), SRC_EID, senderKey, nonce, headerHash, payloadHash, DST_EID, 1);

        bytes32 committedHash = dstEndpoint.inboundPayloadHash(address(dstApp), SRC_EID, senderKey, nonce);
        assertEq(committedHash, payloadHash, "A01+D45 did NOT reproduce: payload was not marked committed");

        uint256 receiverBefore = dstApp.balanceOf(RECEIVER);
        vm.prank(ATTACKER);
        dstEndpoint.lzReceive(address(dstApp), SRC_EID, senderKey, nonce, guid, message);
        uint256 receiverAfter = dstApp.balanceOf(RECEIVER);
        assertEq(receiverAfter, receiverBefore + AMT, "A01+D45 did NOT reproduce: tokens were not actually delivered");
    }

    function test_ASSERT_D45_ConfigDrift_DIRECT() public {
        vm.prank(ALICE);
        (bytes memory message, uint64 nonce) = srcApp.send(DST_EID, RECEIVER, AMT);
        bytes32 senderKey = bytes32(uint256(uint160(address(srcApp))));
        bytes32 headerHash = keccak256(abi.encodePacked(SRC_EID, senderKey, DST_EID, address(dstApp), nonce));

        vm.prank(dvnA.currentSigner());
        dvnA.attest(headerHash, message, message, 10, 100);
        vm.prank(address(dvnB));
        dvnB.attest(headerHash, message, message, 10, 100);

        vm.prank(OWNER);
        address[] memory emptyReq = new address[](0);
        address[] memory emptyOpt = new address[](0);
        uln.setPathway(address(dstApp), SRC_EID, senderKey, emptyReq, emptyOpt, 0, 0);

        bytes32 guid = _computeGuid(nonce, SRC_EID, senderKey, DST_EID, address(dstApp));
        bytes32 payloadHash = keccak256(abi.encodePacked(guid, message));

        vm.prank(ATTACKER);
        uln.commitVerification(address(dstApp), SRC_EID, senderKey, nonce, headerHash, payloadHash, DST_EID, 1);

        bytes32 committedHash = dstEndpoint.inboundPayloadHash(address(dstApp), SRC_EID, senderKey, nonce);
        assertEq(committedHash, payloadHash, "D45 did NOT reproduce: payload was not committed under the weakened config");
    }

    function test_ASSERT_K97_GraceLibrary_DIRECT() public {
        bytes32 senderKey = bytes32(uint256(uint160(address(srcApp))));
        uint64 graceNonce = 555555;
        bytes memory message = abi.encode(RECEIVER, AMT);
        bytes32 oldHeaderHash = keccak256(abi.encodePacked(SRC_EID, senderKey, DST_EID, address(dstApp2), graceNonce));
        bytes32 payloadHash = keccak256(message);

        vm.prank(OWNER);
        dstEndpoint.addGraceUln(address(ulnOld));

        vm.prank(address(dvnB));
        ulnOld.verify(oldHeaderHash, payloadHash, address(dvnB), 10);

        vm.prank(ATTACKER);
        ulnOld.commitVerification(address(dstApp2), SRC_EID, senderKey, graceNonce, oldHeaderHash, payloadHash, DST_EID, 1);

        bytes32 committedHash = dstEndpoint.inboundPayloadHash(address(dstApp2), SRC_EID, senderKey, graceNonce);
        assertEq(committedHash, payloadHash, "K97 did NOT reproduce: old grace-valid library did not commit under its own weaker policy");
    }

    function test_ASSERT_M99_DefaultDrift_DIRECT() public {
        bytes32 senderKey = bytes32(uint256(uint160(address(srcApp))));
        uint64 nonce = 666666;
        bytes memory message = abi.encode(RECEIVER, AMT);
        bytes32 headerHash = keccak256(abi.encodePacked(SRC_EID, senderKey, DST_EID, address(dstApp2), nonce));
        bytes32 payloadHash = keccak256(message);

        address[] memory emptyReq = new address[](0);
        address[] memory oneOpt = new address[](1); oneOpt[0] = address(dvnB);
        vm.prank(OWNER);
        uln.setDefaultPathway(emptyReq, oneOpt, 1, 5);

        vm.prank(address(dvnB));
        dvnB.attest(headerHash, message, message, 10, 100);

        vm.prank(ATTACKER);
        uln.commitVerification(address(dstApp2), SRC_EID, senderKey, nonce, headerHash, payloadHash, DST_EID, 1);

        bytes32 committedHash = dstEndpoint.inboundPayloadHash(address(dstApp2), SRC_EID, senderKey, nonce);
        assertEq(committedHash, payloadHash, "M99 did NOT reproduce: single-DVN weakened default did not commit");
    }

    function test_ASSERT_M100_ReadChannelDrift_DIRECT() public {
        bytes32 senderKey = bytes32(uint256(uint160(address(srcApp))));
        uint64 nonce = 777777;
        bytes memory message = abi.encode(RECEIVER, AMT);
        bytes32 readHeaderHash = keccak256(abi.encodePacked(READ_CHANNEL_EID, senderKey, DST_EID, address(dstApp2), nonce));
        bytes32 payloadHash = keccak256(message);

        address[] memory emptyReq = new address[](0);
        address[] memory oneOpt = new address[](1); oneOpt[0] = address(dvnB);
        vm.prank(OWNER);
        uln.setDefaultPathway(emptyReq, oneOpt, 1, 5);

        vm.prank(address(dvnB));
        dvnB.attest(readHeaderHash, message, message, 10, 100);

        vm.prank(ATTACKER);
        uln.commitVerification(address(dstApp2), READ_CHANNEL_EID, senderKey, nonce, readHeaderHash, payloadHash, DST_EID, 1);

        bytes32 committedHash = dstEndpoint.inboundPayloadHash(address(dstApp2), READ_CHANNEL_EID, senderKey, nonce);
        assertEq(committedHash, payloadHash, "M100 did NOT reproduce: read-channel eid did not get the same weakened-default treatment");
    }

    function test_ASSERT_PreInitDefaultPathway_HOLDS_DIRECT_V2() public {
        UlnMock freshUln = new UlnMock(address(dstEndpoint));
        vm.prank(OWNER);
        dstEndpoint.addGraceUln(address(freshUln));

        bytes32 senderKey = bytes32(uint256(uint160(address(srcApp))));
        uint64 nonce = 999998;
        bytes memory message = abi.encode(RECEIVER, AMT);
        bytes32 headerHash = keccak256(abi.encodePacked(SRC_EID, senderKey, DST_EID, address(dstApp2), nonce));
        bytes32 payloadHash = keccak256(message);

        vm.prank(ATTACKER);
        freshUln.commitVerification(address(dstApp2), SRC_EID, senderKey, nonce, headerHash, payloadHash, DST_EID, 1);

        bytes32 committedHash = dstEndpoint.inboundPayloadHash(address(dstApp2), SRC_EID, senderKey, nonce);
        assertEq(committedHash, payloadHash, "4b did NOT reproduce: pre-init empty default did not commit with zero attestations");
    }

    function test_ASSERT_PreInitDefaultPathway_ReadChannel_HOLDS_DIRECT() public {
        UlnMock freshUln = new UlnMock(address(dstEndpoint));
        vm.prank(OWNER);
        dstEndpoint.addGraceUln(address(freshUln));

        bytes32 senderKey = bytes32(uint256(uint160(address(srcApp))));
        uint64 nonce = 777776;
        bytes memory message = abi.encode(RECEIVER, AMT);
        bytes32 headerHash = keccak256(abi.encodePacked(READ_CHANNEL_EID, senderKey, DST_EID, address(dstApp2), nonce));
        bytes32 payloadHash = keccak256(message);

        vm.prank(ATTACKER);
        freshUln.commitVerification(address(dstApp2), READ_CHANNEL_EID, senderKey, nonce, headerHash, payloadHash, DST_EID, 1);

        bytes32 committedHash = dstEndpoint.inboundPayloadHash(address(dstApp2), READ_CHANNEL_EID, senderKey, nonce);
        assertEq(committedHash, payloadHash, "5-final did NOT reproduce: read-channel pre-init did not match 4b");
    }

    function test_ASSERT_PeerValidation_HOLDS_DIRECT() public {
        vm.prank(OWNER);
        dstApp.setPeer(SRC_EID, bytes32(uint256(uint160(address(0xBADBAD1234)))));

        vm.prank(ALICE);
        (bytes memory honestMessage, uint64 nonce) = srcApp.send(DST_EID, RECEIVER, AMT);
        bytes32 senderKey = bytes32(uint256(uint160(address(srcApp))));
        bytes32 headerHash = keccak256(abi.encodePacked(SRC_EID, senderKey, DST_EID, address(dstApp), nonce));
        bytes32 guid = _computeGuid(nonce, SRC_EID, senderKey, DST_EID, address(dstApp));
        bytes memory guidCombined = abi.encodePacked(guid, honestMessage);

        vm.prank(dvnA.currentSigner());
        dvnA.attest(headerHash, guidCombined, guidCombined, 10, 100);
        vm.prank(address(dvnB));
        dvnB.attest(headerHash, guidCombined, guidCombined, 10, 100);

        bytes32 honestPayloadHash = keccak256(guidCombined);

        vm.prank(ATTACKER);
        uln.commitVerification(address(dstApp), SRC_EID, senderKey, nonce, headerHash, honestPayloadHash, DST_EID, 1);

        vm.prank(ATTACKER);
        dstEndpoint.lzReceive(address(dstApp), SRC_EID, senderKey, nonce, guid, honestMessage);

        uint256 receiverBal = dstApp.balanceOf(RECEIVER);
        assertEq(receiverBal, AMT, "13+14 did NOT reproduce: peer mismatch DID prevent delivery");
    }

    // ---------------- TIER 2: NEEDS FRESH VERIFICATION ----------------
    // These 3 tests appeared in the source file's tail but were NEVER run
    // with their trace reviewed in this session. Treat every assertion
    // below as an open question, not a confirmed finding, until run.

    function test_ASSERT_FeeOnTransferSupplyInflation_HOLDS_DIRECT() public {
        // UNVERIFIED. Claim: sendFeeOnTransfer debits the fee-reduced
        // amount from source supply/balance, but encodes the FULL nominal
        // amount into the outbound message - meaning destination credits
        // more than was ever removed from source. Needs a fresh run with
        // full trace review before this can be trusted as real.
        uint256 feeBps = 1000;
        uint256 srcSupplyBefore = srcApp.totalSupply();
        uint256 dstSupplyBefore = dstApp.totalSupply();
        uint256 aliceBalBefore = srcApp.balanceOf(ALICE);

        vm.prank(ALICE);
        (bytes memory message, uint64 nonce) = srcApp.sendFeeOnTransfer(DST_EID, RECEIVER, AMT, feeBps);

        uint256 actuallyRemoved = AMT - (AMT * feeBps / 10000);
        assertEq(srcApp.totalSupply(), srcSupplyBefore - actuallyRemoved, "sanity: only the fee-reduced amount should leave source supply");
        assertEq(srcApp.balanceOf(ALICE), aliceBalBefore - actuallyRemoved, "sanity: sender debited only the fee-reduced amount");

        bytes32 senderKey = bytes32(uint256(uint160(address(srcApp))));
        bytes32 headerHash = keccak256(abi.encodePacked(SRC_EID, senderKey, DST_EID, address(dstApp), nonce));
        bytes32 guid = _computeGuid(nonce, SRC_EID, senderKey, DST_EID, address(dstApp));
        bytes memory guidCombined = abi.encodePacked(guid, message);

        vm.prank(dvnA.currentSigner());
        dvnA.attest(headerHash, guidCombined, guidCombined, 10, 100);
        vm.prank(address(dvnB));
        dvnB.attest(headerHash, guidCombined, guidCombined, 10, 100);

        vm.prank(ATTACKER);
        uln.commitVerification(address(dstApp), SRC_EID, senderKey, nonce, headerHash, keccak256(guidCombined), DST_EID, 1);

        vm.prank(ATTACKER);
        dstEndpoint.lzReceive(address(dstApp), SRC_EID, senderKey, nonce, guid, message);

        uint256 dstSupplyAfter = dstApp.totalSupply();
        uint256 dstCredited = dstSupplyAfter - dstSupplyBefore;

        assertEq(dstCredited, AMT, "destination credited the FULL nominal amount, not the fee-reduced amount");
        assertTrue(dstCredited > actuallyRemoved, "UNVERIFIED CLAIM: combined supply increased - more credited on destination than removed on source");
    }

    function test_ASSERT_ZeroAddressPeer_HOLDS_DIRECT() public {
        // UNVERIFIED. Claim: a message from a sender key that was never
        // configured as dstApp's peer (falls back to default pathway,
        // requiring just dvnA) can still be committed and delivered.
        // NOTE: despite the name, "fakeSender" here is NOT literally
        // bytes32(0) - it's 0xBADBEEF cast to bytes32. Worth checking
        // whether that's intentional or a naming/implementation mismatch
        // when this gets reviewed.
        bytes32 fakeSender = bytes32(uint256(0xBADBEEF));
        bytes32 realPeer = dstApp.peers(SRC_EID);
        assertTrue(fakeSender != realPeer, "sanity: fake sender must not equal the real configured peer");

        uint64 nonce = 1;
        bytes memory message = abi.encode(RECEIVER, uint64(1000));
        bytes32 headerHash = keccak256(abi.encodePacked(SRC_EID, fakeSender, DST_EID, address(dstApp), nonce));
        bytes32 guid = _computeGuid(nonce, SRC_EID, fakeSender, DST_EID, address(dstApp));
        bytes memory guidCombined = abi.encodePacked(guid, message);

        vm.prank(dvnA.currentSigner());
        dvnA.attest(headerHash, guidCombined, guidCombined, 10, 100);

        vm.prank(ATTACKER);
        uln.commitVerification(address(dstApp), SRC_EID, fakeSender, nonce, headerHash, keccak256(guidCombined), DST_EID, 1);

        uint256 receiverBefore = dstApp.balanceOf(RECEIVER);
        vm.prank(ATTACKER);
        dstEndpoint.lzReceive(address(dstApp), SRC_EID, fakeSender, nonce, guid, message);
        uint256 receiverAfter = dstApp.balanceOf(RECEIVER);

        assertTrue(receiverAfter > receiverBefore, "UNVERIFIED CLAIM: spoofed sender accepted despite never matching configured peer");
    }

    function test_ASSERT_MismatchedPeer_HOLDS_DIRECT() public {
        // UNVERIFIED. Claim: a REAL, legitimate contract's address
        // (dstApp2, genuinely deployed in this suite) claiming to be
        // dstApp's peer for SRC_EID - despite never being granted that
        // role - can still be committed and delivered.
        bytes32 mismatchedSender = bytes32(uint256(uint160(address(dstApp2))));
        bytes32 realPeer = dstApp.peers(SRC_EID);
        assertTrue(mismatchedSender != realPeer, "sanity: dstApp2 must not equal dstApp's real configured peer");

        uint64 nonce = 1;
        bytes memory message = abi.encode(RECEIVER, uint64(1000));
        bytes32 headerHash = keccak256(abi.encodePacked(SRC_EID, mismatchedSender, DST_EID, address(dstApp), nonce));
        bytes32 guid = _computeGuid(nonce, SRC_EID, mismatchedSender, DST_EID, address(dstApp));
        bytes memory guidCombined = abi.encodePacked(guid, message);

        vm.prank(dvnA.currentSigner());
        dvnA.attest(headerHash, guidCombined, guidCombined, 10, 100);

        vm.prank(ATTACKER);
        uln.commitVerification(address(dstApp), SRC_EID, mismatchedSender, nonce, headerHash, keccak256(guidCombined), DST_EID, 1);

        uint256 receiverBefore = dstApp.balanceOf(RECEIVER);
        vm.prank(ATTACKER);
        dstEndpoint.lzReceive(address(dstApp), SRC_EID, mismatchedSender, nonce, guid, message);
        uint256 receiverAfter = dstApp.balanceOf(RECEIVER);

        assertTrue(receiverAfter > receiverBefore, "UNVERIFIED CLAIM: mismatched-but-real peer accepted despite never being configured");
    }
}

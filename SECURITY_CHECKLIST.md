# CCIP/USDC Security Checklist
## Verified against actual code, file:line cited for every entry

| # | Vulnerability Class | Status | Evidence (file:line) | Notes |
|---|---|---|---|---|
| 1 | Reentrancy | NEEDS VERIFICATION | | |
| 2 | Access control - missing onlyOwner | PARTIAL FINDING | USDCTokenPoolProxy.sol:575 withdrawFeeTokens | No access control, LOW impact only |
| 3 | Access control - privileged migration | DOCUMENTED DESIGN | SiloedUSDCTokenPool.sol:195 | Chainlink confirmed intentional |
| 4 | Integer overflow/underflow | NEEDS VERIFICATION | | Solidity 0.8.24 has built-in checks |
| 5 | Unchecked external call return | NEEDS VERIFICATION | | |
| 6 | Front-running / MEV | NEEDS VERIFICATION | | |
| 7 | Signature replay | NEEDS VERIFICATION | | CCTPVerifier uses messageId checks |
| 8 | Timestamp dependence | NEEDS VERIFICATION | | |
| 9 | Denial of Service (gas) | NEEDS VERIFICATION | | |
| 10 | Denial of Service (logic) | CONFIRMED ARCHITECTURAL GAP | SiloedUSDCTokenPool.sol releaseOrMint | Permanent freeze possible, ruled owner-responsibility by Chainlink |

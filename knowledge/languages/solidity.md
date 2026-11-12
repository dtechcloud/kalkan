---
name: solidity
title: Solidity (EVM smart contracts)
tech: solidity
sources: third_party/codecrucible/prompts/exploit-proof-solidity/analysis_sections.yaml, third_party/codecrucible/prompts/exploit-proof-solidity/cwe_deep_analysis.yaml, third_party/open-code-review/rules/rule_docs/solidity.md
---

# Solidity (EVM smart contracts)

Smart contracts, libraries, and proxies on EVM chains. Every `external` and `public` function is an attacker entry point, and value loss is permanent. Read the `pragma` first: Solidity 0.8 and later revert on overflow and underflow outside `unchecked` blocks, so an overflow report on checked code is a false positive. The `smart-contract` class owns these findings.

## Sources of attacker input

- Function arguments on every `external` and `public` function, plus `receive()` and `fallback()`, which anyone can call.
- `msg.sender`, `msg.value`, `tx.origin`, and `msg.data`.
- Return values and callbacks from external contracts: token transfers, flash-loan callbacks, and oracle reads.
- Proxy `initialize` and `upgradeTo` functions, and any `delegatecall` target or calldata.
- Block values an attacker or validator can influence: `block.timestamp`, `block.number`, `blockhash`, and `block.prevrandao`.

## Dangerous sinks

### smart-contract: reentrancy

- **Check:** state written after an external call (`to.call{value:}`, `token.transfer`, `token.transferFrom`, ERC-777, ERC-721, and ERC-1155 hooks, flash-loan and swap callbacks). The callee can re-enter and read stale state.
- **Check:** cross-function reentrancy, where one function guarded by `nonReentrant` shares state with an unguarded sibling, and read-only reentrancy, where a `view` getter returns half-updated state to another protocol.
- **Safe signal:** all state updates happen before every external call (checks-effects-interactions), and `nonReentrant` covers every attacker-reachable path.

### smart-contract: access control

- **Check:** state-changing functions without `onlyOwner`, `onlyRole`, or a `msg.sender` check, an `initialize` without the `initializer` modifier (anyone can call it first), UUPS proxies without `_authorizeUpgrade`, and `tx.origin` used for authentication.
- **Safe signal:** a reviewed modifier on every privileged function, a two-step ownership transfer, and a disabled initializer on the implementation.

### smart-contract: unchecked calls

- **Check:** the return value of `.call`, `.send`, or `.delegatecall` discarded so a failed call proceeds as success, a low-level call to an address without a code check (a call to an address with no code returns `true`), and ERC-20 `transfer` or `approve` on tokens that return nothing or `false` instead of `SafeERC20`.

### smart-contract: delegatecall and proxies

- **Check:** `delegatecall` to a target that a caller can influence or that comes from mutable storage without an allowlist, storage-slot collisions between proxy and implementation (reordered variables, a reduced `__gap`), and an implementation that can `selfdestruct` or `delegatecall`, which can brick every proxy that points at it.

### smart-contract: arithmetic and conversions

- **Check:** `unchecked` blocks whose bound is not locally provable (a subtraction on caller input), downcasts such as `uint256` to `uint128` that truncate on reachable values, signed-to-unsigned conversions that flip a value, and division before multiplication that loses precision in fee or share math. Pre-0.8 code without SafeMath.

### smart-contract: oracle and price manipulation

- **Check:** `getReserves()` or a spot pool price read in the same transaction as the swap that moves it (flash-loan manipulable), contract balance used as a supply proxy (donation attack), ERC-4626 vaults without inflation-attack protection, and Chainlink reads that skip `updatedAt` freshness, a positive answer, or round completeness.

### smart-contract: randomness and time

- **Check:** `block.timestamp`, `block.number`, `blockhash`, or `block.prevrandao` used as randomness for anything of value, and timestamp comparisons that assume a fixed block interval. Use Chainlink VRF or commit-reveal for randomness.

### smart-contract: front-running and MEV

- **Check:** swaps, mints, or redeems without both a deadline and a minimum-output or maximum-input bound, the ERC-20 approve race (a non-zero allowance overwritten with another non-zero value), and commit-reveal schemes whose commitment omits the sender or a salt.

### smart-contract: signatures

- **Check:** `ecrecover` used without rejecting the zero address and the malleable high-`s` form, signatures accepted without a nonce, a chain id, or an EIP-712 domain separator (replay across accounts, chains, or contracts), and `abi.encodePacked` over two or more dynamic arguments feeding a hash (collisions).

### smart-contract: denial of service and ether handling

- **Check:** loops over an array that any caller can grow, external calls or token transfers inside a loop, `transfer` or `send` with the 2300-gas stipend to a possible contract, push payments where one reverting recipient blocks the rest, and fee-on-transfer or rebasing tokens credited with the argument amount rather than the measured balance delta.

### smart-contract: storage and initialization

- **Check:** an uninitialized local `storage` pointer (it aliases slot 0), a `memory` copy mutated where `storage` was intended (the write is discarded), and `delete` on a struct that contains a mapping (the mapping stays populated).

## Framework notes

### OpenZeppelin

- `ReentrancyGuard`, `Ownable2Step`, `AccessControl`, `SafeERC20`, and `ECDSA` are the vetted building blocks. A missing or custom reimplementation is worth a close read.
- Upgradeable contracts use `Initializable`. Check that the constructor calls `_disableInitializers()` and that each `__X_init` runs once.

### Proxies and upgrades

- A variable that changes type or becomes `constant` or `immutable` across an upgrade shifts every later storage slot. Compare the layouts.
- Transparent and UUPS proxies differ in where the upgrade authorization lives. Confirm it exists and names the intended role.

### Tokens

- Do not assume 18 decimals or equal decimals between two tokens.
- Treat any ERC-20 `transfer` to an arbitrary address as an external call, because token hooks can run code.

## Safe idioms

- Checks-effects-interactions ordering, plus `nonReentrant` on functions with external calls.
- `SafeERC20` (`safeTransfer`, `safeTransferFrom`, `forceApprove`) for token calls, and a checked success flag on every low-level call.
- A TWAP or a decentralized oracle with freshness and round checks, not a spot reserve read.
- Chainlink VRF or commit-reveal for randomness, and `block.timestamp` only for coarse deadlines.
- A deadline and a slippage bound on every swap, mint, and redeem.
- EIP-712 typed data with a domain separator that includes the chain id, plus per-message nonces, and `ECDSA.recover` with signer equality.
- Pull-payment patterns, and `call{value:}` with a checked result instead of `transfer`.

## Common false positives

- Overflow or underflow reports on Solidity 0.8 or later outside an `unchecked` block.
- An `unchecked` block whose counter is bounded by a loop against `.length`.
- An external call that is the last statement with no state read after it.
- A `delegatecall` to an immutable, audited library address set at construction.
- `tx.origin` used only for a convenience check that is not the security decision, when a `msg.sender` check also guards the function.
- A `.sol` file that is a Gerber solder-mask layer, not Solidity source. Report nothing for it.
- Typos inside comments, NatSpec, or revert strings, unless a revert string is matched elsewhere.

## Sources

- `third_party/codecrucible/prompts/exploit-proof-solidity/analysis_sections.yaml` and `cwe_deep_analysis.yaml`, from block/codecrucible at commit `b5c8086` (Apache-2.0, Copyright 2026 Block, Inc.).
- `third_party/open-code-review/rules/rule_docs/solidity.md`, from alibaba/open-code-review at commit `11ac6d4` (Apache-2.0, Copyright 2026 alibaba/open-code-review contributors).
- kalkan condensed and rewrote the material, regrouped it by kalkan class slug, kept the SWC mapping in mind, and removed the agent-orchestration instructions.

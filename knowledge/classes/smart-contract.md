---
slug: smart-contract
title_en: Smart contracts
title_tr: Akıllı kontrat (smart contract)
cwe:
owasp:
sources: codecrucible, open-code-review
---

## Summary

On-chain code where every `external` and `public` function is an attacker entry point and every external call can re-enter. The attacker also controls transaction order and can borrow large amounts inside one transaction. Report a concrete sequence of transactions and its effect: stolen funds, a takeover, broken accounting or locked funds.

## What it is

Put the Smart Contract Weakness Classification (SWC) ID in the description. Use the most specific CWE: CWE-841 for reentrancy, CWE-284 for access control, CWE-682 for price math, CWE-252 for unchecked calls, CWE-347 for signatures.

- **Reentrancy (SWC-107).** State changes after an external call: ETH transfers, token transfers with hooks (ERC-777, ERC-721 and ERC-1155 safe transfers), flash-loan or swap callbacks. Also cross-function, cross-contract and read-only reentrancy (a `view` function that another protocol reads mid-call).
- **Access control (SWC-105, SWC-106, SWC-115).** A privileged function has no `onlyOwner` or `onlyRole`. `initialize` lacks `initializer`, so anyone can call it first. A UUPS `_authorizeUpgrade` has an empty body. `selfdestruct` is reachable. `tx.origin` decides authorization.
- **Arithmetic (SWC-101).** Math in `unchecked` blocks, or below Solidity 0.8 without SafeMath. Downcasts and signed-to-unsigned casts. Division before multiplication. Rounding that favors the user on deposit and on withdrawal. Assumed 18 decimals.
- **Price and oracle manipulation.** Spot reserves (`getReserves`) or `balanceOf(this)` used as a price or as the supply. The first-depositor inflation attack on ERC-4626 vaults. Chainlink data without staleness, sign or round checks.
- **Unchecked calls (SWC-104).** The `bool` of a low-level `call` is ignored. ERC-20 `transfer` without SafeERC20 on tokens that return nothing. A call to an address without code returns success.
- **Delegatecall and proxies (SWC-112).** `delegatecall` to an address or with calldata that a caller controls. Storage slot collisions across upgrades. Selector clashes between proxy and implementation.
- **Signatures (SWC-117, SWC-121, SWC-122, SWC-133).** `ecrecover` without a zero-address check, malleable signatures, no nonce, no chain ID or EIP-712 domain, `abi.encodePacked` over two dynamic values, a signature not bound to the caller or the action.
- **Front-running (SWC-114).** Swaps, mints or redeems without a minimum output and a deadline. The ERC-20 approve race. A commitment without the sender or a salt.
- **Weak randomness and time (SWC-120, SWC-116).** `block.timestamp`, `blockhash` or `prevrandao` as randomness for anything of value.
- **Denial of service (SWC-113, SWC-128).** Loops over arrays that anyone can grow. Push payments where one reverting receiver blocks everyone.
- **Token handling.** Fee-on-transfer or rebasing tokens credited with the amount argument. `msg.value` counted many times in a loop or a multicall.

## What it is not

- Bugs in the off-chain backend, signer service or keeper bot → their web classes (`authn`, `missing-authz`, `ssrf`).
- Private keys or mnemonics in the repository or in deploy scripts → `hardcoded-secrets`.
- XSS in the dApp front end → `xss`.
- A known-vulnerable library version in a lockfile (for example OpenZeppelin) → `vulnerable-dependency`. A compiler pin with a known miscompilation stays here, because SCA tools do not read pragmas.
- Gas optimizations, style and missing events without an accounting effect → not a finding.

## Where to look

List every `external` and `public` function, `receive`, `fallback` and callback. For each one, note the state it reads and writes, the external calls and their order, and the guard.

### Solidity
- The `pragma`: below 0.8, all math wraps. From 0.8, only `unchecked` blocks wrap. Casts truncate in every version.
- External calls: `call{value:}`, `transfer`, `send`, `safeTransfer*`, `IERC20.transfer*`, `onERC721Received` and other hooks, flash-loan and swap callbacks.
- Modifiers and inherited base contracts. Read the real implementation, not the name.
- Proxies: `initialize`, `_disableInitializers()` in the constructor, `_authorizeUpgrade`, storage layout and `__gap`, `delegatecall` targets. Deploy scripts that initialize a proxy in a second transaction leave a window.
- Price reads: `getReserves`, `slot0`, `balanceOf(address(this))`, `latestRoundData`, `totalAssets`.
- Signatures: `ecrecover`, `ECDSA.recover`, nonces, `DOMAIN_SEPARATOR`, `abi.encodePacked` in hashes.
- Inline `assembly`: the free memory pointer, calldata offsets, manual storage slots.

### Vyper
- `# pragma version`. Versions 0.2.15, 0.2.16 and 0.3.0 miscompiled the `@nonreentrant` lock.
- Vyper has no modifiers. Each privileged function needs its own `assert msg.sender == self.owner` line.
- Math is checked by default. Review `unsafe_add`, `unsafe_sub`, `unsafe_mul` and `unsafe_div`.
- `raw_call` with `revert_on_failure=False` and a dropped result, `delegate_call=True` to a non-constant target, `send()` to contracts.

## Safe patterns

- Checks-effects-interactions: write all state before any external call. Add `nonReentrant` to every function that shares the state.
- Use OpenZeppelin `Ownable` or `AccessControl` on every privileged function. Use the `initializer` modifier, call `_disableInitializers()` in the implementation constructor, and guard `_authorizeUpgrade`.
- Use SafeERC20, and check every low-level call result.
- Read prices from a time-weighted average price (TWAP) or from Chainlink with staleness, `answer > 0` and sequencer checks. Measure token balances before and after a transfer.
- Use virtual shares or a decimals offset in ERC-4626 vaults.
- Use EIP-712 with a nonce, a deadline and the chain ID. Use `ECDSA.recover`, which rejects malleable signatures.
- Require `minOut` and `deadline` parameters on swaps, mints and redeems.
- Use pull payments. Bound loops or paginate them.
- Use Chainlink VRF or commit-reveal for randomness.

## Weak mitigations

- `nonReentrant` on one function while a sibling function that shares the state has none.
- `transfer` and `send` as reentrancy protection. Gas costs change, and the 2300-gas stipend can block contract receivers.
- A guard on a wrapper while another public path reaches the internal function.
- A one-step ownership transfer to an unchecked address.
- A TWAP over a single block, or a Chainlink read without a staleness check.
- A deadline of `block.timestamp`, which always passes.
- An `unchecked` block justified by a comment instead of a provable bound.

## Verification checklist

- **attacker_control:** Name the entry function or callback and the transaction sequence. Quote the function signature, the external call, and the state write that comes too late or the missing guard.
- **privilege_boundary:** Name the gain: other users' funds, admin control, protocol insolvency, permanently locked funds. A function that only the owner or a role can call by design refutes it (quote the modifier). A front-runnable initializer does not refute, because the attacker becomes the owner.
- **unmitigated:** Quote the missing control: effect order, `nonReentrant`, access modifier, slippage parameter, staleness check, nonce. Read the full modifier chain and the inherited code.
- Read the `pragma` before any arithmetic claim. Check that a token assumption applies: does the contract accept hook tokens or fee-on-transfer tokens?
- Write the attack as steps: attacker contract functions, calls in order, and the balance change.
- Severity guide: reentrancy that drains funds, critical. An admin access bypass, high to critical. Oracle manipulation for profit, high. Griefing or denial of service, medium.
- If the effect depends on a deployment fact (private mempool, off-chain keeper, token list), the result is `needs_validation`.

## Examples

### Solidity
```solidity
// Vulnerable: the balance is cleared after the call, so the receiver re-enters withdraw()
function withdraw() external {
    uint256 amount = balances[msg.sender];
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok);
    balances[msg.sender] = 0;
}

// Secure: effect first, and a guard against cross-function reentry
function withdraw() external nonReentrant {
    uint256 amount = balances[msg.sender];
    balances[msg.sender] = 0;
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "send failed");
}
```

```solidity
// Vulnerable: anyone can initialize the proxy, and anyone can upgrade it
function initialize(address admin) public { __Ownable_init(admin); }
function _authorizeUpgrade(address) internal override {}

// Secure
constructor() { _disableInitializers(); }
function initialize(address admin) public initializer { __Ownable_init(admin); __UUPSUpgradeable_init(); }
function _authorizeUpgrade(address) internal override onlyOwner {}
```

```solidity
// Vulnerable: a stale or negative price passes
(, int256 answer, , , ) = feed.latestRoundData();
uint256 price = uint256(answer);

// Secure
(, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();
require(answer > 0 && block.timestamp - updatedAt <= MAX_AGE, "bad price");
uint256 price = uint256(answer);
```

### Vyper
```vyper
# Vulnerable: the call can fail, and the code continues
raw_call(recipient, b"", value=amount, revert_on_failure=False)

# Secure
success: bool = raw_call(recipient, b"", value=amount, revert_on_failure=False)
assert success, "send failed"
```

## Dynamic test hints

- Write a Foundry or Hardhat test on a local chain. Deploy the contract, an attacker contract, and mock tokens or oracles. Run `forge test -vvv`.
- Reentrancy: the attacker contract re-enters from `receive()` or a token hook. Compare the balances before and after.
- Access control: call the privileged function or `initialize` with `vm.prank` from a random address.
- Oracle: a mock feed returns an old `updatedAt` or a negative answer. A mock pool moves its reserves inside the same transaction.
- Use invariant or fuzz tests for accounting, for example total shares against total assets.
- A fork test needs an RPC endpoint and network access. Use it only when the run allows network access, pin a block number, and never send a transaction to a real network.

## False positive traps

- Solidity 0.8 or newer, and the math is outside `unchecked`. No overflow finding.
- The external call is the last operation and nothing reads state after it. Or every function that shares the state has `nonReentrant`.
- The function is public by design and safe for any caller: a keeper `harvest()`, a view function, a deposit of the caller's own funds.
- The guard comes from a base contract or a reviewed library.
- The vault uses OpenZeppelin ERC-4626 with virtual shares.
- An admin-only setter controls the array length.
- `block.timestamp` is a loose deadline of minutes or more, not randomness.
- The file is a mock, a test or a script under `test/`, `script/` or `mocks/`.
- The `.sol` file is not Solidity: PCB tools use the same extension for solder-mask layers.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `block/codecrucible@b5c8086: prompts/exploit-proof-solidity/analysis_sections.yaml`, `security_analysis_base.yaml`, `cwe_deep_analysis.yaml` (Apache-2.0, Block): attack method, SWC and CWE mapping, severity guide, false positive indicators.
- `block/codecrucible@b5c8086: prompts/default/analysis_sections.yaml` (Apache-2.0, Block): signed-data coverage, replay, oracle and ordering checks.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/solidity.md`, `vyper.md` (Apache-2.0, alibaba/open-code-review contributors): reentrancy forms, proxies, storage, token handling, the Vyper version and `raw_call` rules.
- Foundry commands, OpenZeppelin function names and the exact SWC numbers come from general knowledge.

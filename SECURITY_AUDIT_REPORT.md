# Security Audit Report - Veilo Privacy Pool

**Audit Date:** 31 January 2026  
**Auditor:** Senior Solana Security Auditor  
**Program:** Privacy Pool (Solana/Anchor)  
**Program ID:** `AaWZfKYkZdF1zFMb4VAYKLF176Lpqe7hE6eLr65NFvgw`

---

## High

### AUDIT-H01 Missing Authorization for add_merkle_tree

**Severity:** High  
**Location:** [lib.rs:905-933](programs/privacy-pool/src/lib.rs#L905-L933)

**Description:** The `add_merkle_tree` function allows anyone who is either admin OR relayer to create new Merkle trees. Relayers should not have this privilege as they could create an unbounded number of trees (up to MAX_MERKLE_TREES=10000), consuming rent and potentially disrupting protocol accounting. This violates the principle of least privilege for relayers.

**Impact:** Malicious or compromised relayer can drain pool funds via excessive rent costs (10000 trees × ~0.065 SOL = 650 SOL rent) and potentially manipulate tree assignment to degrade service or track users.

**Fix:** Remove relayer authorization, restrict to admin only:

```rust
// Line 917-921
require!(
    payer.key() == cfg.admin,
    PrivacyError::Unauthorized
);
```

---

### AUDIT-H02 Missing Tree ID Validation in Swap

**Severity:** High  
**Location:** [swap.rs:155-160](programs/privacy-pool/src/swap.rs#L155-L160)

**Description:** The `transact_swap` function does not validate that `source_tree_id` and `dest_tree_id` are within bounds (`< num_trees`) before using them to derive PDA addresses. While the PDA derivation will succeed for any u16 value, attempting to load uninitialized tree accounts will fail only AFTER consuming significant compute units for proof verification (~400K CUs), nullifier marking, and other operations.

**Impact:** Attackers can cause relayers to waste compute units (up to 400K+ CUs) by submitting swap transactions with invalid tree IDs, leading to DoS on relayers and potential economic griefing. Similar to AUDIT-004 but affects swap path.

**Fix:** Add early validation matching the `transact` handler:

```rust
// After line 158
require!(source_tree_id < ctx.accounts.source_config.num_trees, PrivacyError::InvalidTreeId);
require!(dest_tree_id < ctx.accounts.dest_config.num_trees, PrivacyError::InvalidTreeId);
```

---

### AUDIT-H03 SPL Token Delegation Bypass in Deposits

**Severity:** High  
**Location:** [lib.rs:1187-1194](programs/privacy-pool/src/lib.rs#L1187-L1194)

**Description:** Deposit validation checks that `user_token.owner == relayer.key()` but also allows delegation where `delegate.is_some()` as long as `delegated_amount == 0`. This creates a race condition: an attacker can set up a token account with their own wallet as owner, delegate to the relayer with 0 amount, submit a deposit transaction, then frontrun it by increasing `delegated_amount` to steal the deposited tokens. The relayer signs the transfer, but the tokens belong to the attacker's account, not the relayer.

**Impact:** Users lose deposited funds. Attacker can steal arbitrary amounts by exploiting the delegation mechanism that should be completely prohibited for deposits.

**Fix:** Completely prohibit any delegation for deposits:

```rust
// Line 1190-1194 (replace existing check)
require!(
    user_token.delegate.is_none(),
    PrivacyError::InvalidTokenAuthority
);
```

---

### AUDIT-H04 SwapExecutor PDA Seed Collision

**Severity:** High  
**Location:** [swap.rs:234-237](programs/privacy-pool/src/swap.rs#L234-L237), [lib.rs:716](programs/privacy-pool/src/lib.rs#L716)

**Description:** SwapExecutor PDA is derived using only `input_nullifier_0` as seed: `[b"swap_executor", input_nullifier_0.as_ref()]`. Since nullifier space is shared across ALL pools (any token mint), a user can create notes in Pool A with specific nullifiers, then attempt a swap in Pool B using identical input nullifiers. This causes PDA collision - the same executor address is used for completely different source/dest mint pairs, potentially allowing note reuse across pools or blocking legitimate swaps.

**Impact:** Cross-pool nullifier reuse attack - attacker can double-spend notes from one pool in another pool's swap context, or DoS legitimate swaps by pre-occupying executor PDAs with incompatible mint pairs.

**Fix:** Include both source_mint and dest_mint in executor seeds:

```rust
// Line 235 (TransactSwap account context)
seeds = [b"swap_executor", source_mint.as_ref(), dest_mint.as_ref(), input_nullifier_0.as_ref()],

// Line 359 (executor_seeds in transact_swap)
let executor_seeds: &[&[u8]] = &[
    b"swap_executor",
    source_mint.as_ref(),
    dest_mint.as_ref(),
    input_nullifiers[0].as_ref(),
    &[executor.bump],
];
```

---

## Medium

### AUDIT-M01 Unvalidated Remaining Accounts in Swap CPIs

**Severity:** Medium  
**Location:** [swap.rs:413-431](programs/privacy-pool/src/swap.rs#L413-L431), [swap.rs:478-496](programs/privacy-pool/src/swap.rs#L478-L496)

**Description:** The swap handler performs basic owner checks on critical accounts (CPMM config, pool state, token vaults) but doesn't validate the complete account set or their relationships. For CPMM, it checks 5/8 accounts; for AMM, 5/14 accounts. Missing validations include: pool authority derivation, observation state, serum market accounts, vault signer PDA. Attacker could substitute malicious accounts that pass ownership checks but have manipulated state.

**Impact:** Potential for manipulation of swap execution via fake pool accounts, though direct fund theft is prevented by token account ownership checks. Could lead to unfavorable swap rates, failed transactions consuming user CUs, or information leakage.

**Fix:** Validate all critical accounts thoroughly, especially pool authority PDAs and market accounts. Consider implementing a whitelist of approved pool addresses for additional security.

---

### AUDIT-M02 Merkle Root History Size-Root Index Desync

**Severity:** Medium  
**Location:** [merkle_tree.rs:99-105](programs/privacy-pool/src/merkle_tree.rs#L99-L105)

**Description:** `MerkleTree::append` uses modulo arithmetic for circular root buffer: `new_root_index = (root_index + 1) % root_history_size`. If `root_history_size` changes between initialization and usage (though currently it's const), or if the root_index wraps around multiple times, the `is_known_root` search could miss valid roots or incorrectly accept old roots that should be expired. The loop termination logic counts iterations but doesn't properly handle all edge cases.

**Impact:** Users may be unable to withdraw using valid recent roots (false rejection), or may be able to use expired roots beyond intended history depth (privacy leak - reveals note age).

**Fix:** Make `root_history_size` immutable after initialization, and add explicit bounds checking in append:

```rust
require!(tree.root_index < tree.root_history_size as u64, PrivacyError::MerkleHashFailed);
```

---

### AUDIT-M03 Unconstrained Fee Error Margin Amplification

**Severity:** Medium  
**Location:** [lib.rs:1567-1571](programs/privacy-pool/src/lib.rs#L1567-L1571)

**Description:** Fee validation applies error margin multiplicatively: `max_fee * (1 + margin)`. At maximum allowed margin (5000 bps = 50%), a 1% fee (100 bps) becomes 1.5%, effectively allowing 50% fee increase. For small withdrawals near minimum thresholds, this could result in relayers extracting disproportionate fees. Combined with minimum fee requirements, the actual fee range becomes quite wide.

**Impact:** Users pay up to 50% more than advertised fee_bps, reducing anonymity set effectiveness as users avoid high-fee periods. Economic inefficiency could drive users to competing protocols.

**Fix:** Reduce maximum fee_error_margin_bps to 1000 (10%) or implement absolute margin rather than multiplicative:

```rust
// Line 966
require!(val <= 1000, PrivacyError::ExcessiveFeeMargin);
```

---

### AUDIT-M04 Missing Deadline Validation in Transact

**Severity:** Medium  
**Location:** [lib.rs:1021-1365](programs/privacy-pool/src/lib.rs#L1021-L1365)

**Description:** The `transact` function has no deadline parameter, unlike `transact_swap` which validates `clock.unix_timestamp <= swap_params.deadline`. Users submitting withdrawal transactions have no protection against delayed execution, MEV, or stale transaction replays after market conditions change. Relayers can hold transactions indefinitely.

**Impact:** Users may experience unfavorable outcomes if relayers delay submission. For withdrawals to convert to other tokens off-chain, price slippage cannot be controlled. Enables griefing and MEV extraction.

**Fix:** Add optional deadline parameter to ExtData and validate in transact handler similar to swap.

---

## Low

### AUDIT-L01 GlobalConfig Unused

**Severity:** Low  
**Location:** [lib.rs:175-179](programs/privacy-pool/src/lib.rs#L175-L179), [lib.rs:1021-1365](programs/privacy-pool/src/lib.rs#L1021-L1365)

**Description:** The `GlobalConfig` account is created, validated, and passed to transaction handlers but never actually used. The `update_global_config` function is empty and `handle_public_amount` ignores the `_global_config` parameter. This wastes rent (~0.001 SOL) and compute units (~500 CUs) on every transaction for account deserialization and validation.

**Impact:** Minor inefficiency - wasted rent and compute. Creates confusion about intended architecture.

**Fix:** Either implement global configuration features (e.g., emergency pause, global fee limits) or remove GlobalConfig entirely and save ~0.001 SOL + 500 CUs per tx.

---

### AUDIT-L02 Merkle Tree Height Hardcoded

**Severity:** Low  
**Location:** [merkle_tree.rs:5](programs/privacy-pool/src/merkle_tree.rs#L5)

**Description:** `MERKLE_TREE_HEIGHT = 22` is hardcoded as a constant, limiting maximum capacity to 2^22 = 4.2M leaves per tree. While multi-tree support mitigates this (10K trees × 4.2M = 42B capacity), individual tree exhaustion forces tree rotation which fragments the anonymity set. No upgrade path exists without account migration.

**Impact:** Individual tree fills up requiring rotation, potentially disrupting service if not monitored. Users must track which trees have capacity before submitting transactions.

**Fix:** Document tree capacity limits clearly and implement proactive tree addition automation. Consider making height configurable in future versions.

---

### AUDIT-L03 Missing Slippage Protection in Swap

**Severity:** Low  
**Location:** [swap.rs:694-697](programs/privacy-pool/src/swap.rs#L694-L697)

**Description:** Swap validation only checks `swapped_amount >= swap_params.min_amount_out`, but doesn't validate against the input `swap_amount` or expected swap rate. A malicious or buggy DEX could return exactly `min_amount_out` regardless of input, stealing the difference. While DEX is validated to be Raydium/Jupiter, bugs or oracle manipulation could cause this.

**Impact:** Users may receive significantly less than fair market value if min_amount_out is set too low or if DEX experiences issues. Limited by ZK proof validation of input amounts.

**Fix:** Add sanity check that swapped_amount is reasonable relative to swap_amount (e.g., at least 50% to prevent catastrophic failures):

```rust
require!(swapped_amount >= swap_amount / 2, PrivacyError::InvalidPublicAmount);
```

---

### AUDIT-L04 Deposit Zero-Fee Requirement Too Strict

**Severity:** Low  
**Location:** [lib.rs:1475-1478](programs/privacy-pool/src/lib.rs#L1475-L1478)

**Description:** Deposits require `ext_data.fee == 0 && ext_data.refund == 0`. While logical for security (deposits shouldn't pay fees), this prevents implementing sponsored deposits where a third party covers gas/fees for onboarding users. Could limit UX improvements.

**Impact:** Cannot implement gasless deposit features for user onboarding. Minor UX limitation.

**Fix:** Consider allowing `refund > 0` for deposits where user prepays for future transaction costs:

```rust
require!(ext_data.fee == 0, PrivacyError::InvalidPublicAmount);
```

---

## Summary

**Total Findings:**

- **High:** 4 issues
- **Medium:** 4 issues
- **Low:** 4 issues

**Critical Issues Requiring Immediate Attention:**

1. **AUDIT-H01** - Remove relayer authorization from tree creation
2. **AUDIT-H02** - Add tree ID validation in swap to prevent compute waste
3. **AUDIT-H03** - Fix delegation bypass vulnerability in deposits
4. **AUDIT-H04** - Fix PDA collision in SwapExecutor seeds

**Positive Findings:**

- ZK verification properly implemented and cannot be disabled
- Checked arithmetic used throughout
- PDA derivations generally sound
- Token account ownership validation comprehensive
- Nullifier tracking prevents double-spend

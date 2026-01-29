# Security Audit Report: Veilo Privacy Pool

**Audit Date:** January 29, 2026  
**Branch:** features/swap  
**Auditor:** Senior Solana Security Review

---

## Critical

### AUDIT-001: Missing ZK Proof Verification in transact_swap

**Severity:** Critical  
**Location:** `swap.rs:118-138`

**Description:**  
The `transact_swap` function has ZK proof verification explicitly commented out with a "CRITICAL TODO" comment. Without proof verification, an attacker can submit arbitrary nullifiers and output commitments, drain funds from the source pool, and create arbitrary notes in the destination pool. The swap executes purely based on the accounts passed, with no cryptographic validation that the user owns the input notes.

**Impact:**  
Complete theft of all pool funds. Attacker can fabricate nullifiers for notes they don't own and drain entire vault balances.

**Fix:**  
Uncomment and implement the proof verification:

```rust
let public_inputs = SwapPublicInputs {
    source_root,
    swap_params_hash: swap_params.hash()?,
    ext_data_hash: ext_data.hash()?,
    source_mint,
    dest_mint,
    input_nullifiers,
    output_commitments,
    swap_amount,
};
verify_swap_groth16(proof, &public_inputs)?;
```

---

## High

### AUDIT-002: Unchecked Swap Program ID Allows Arbitrary CPI

**Severity:** High  
**Location:** `swap.rs:224-320`

**Description:**  
The `swap_program` is an `UncheckedAccount` and its program ID is never validated against known Raydium program IDs. An attacker can pass a malicious program that returns tokens to `executor_dest_token` in a manipulated way, potentially draining funds or bypassing slippage protection. The only validation is checking instruction discriminator bytes in `swap_data`, which a malicious program can easily satisfy.

**Impact:**  
Attacker can route swaps through malicious programs to steal funds or manipulate swap outcomes.

**Fix:**  
Add explicit program ID validation:

```rust
const RAYDIUM_CPMM_ID: Pubkey = pubkey!("CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C");
const RAYDIUM_AMM_ID: Pubkey = pubkey!("675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8");

require!(
    ctx.accounts.swap_program.key() == RAYDIUM_CPMM_ID
    || ctx.accounts.swap_program.key() == RAYDIUM_AMM_ID,
    PrivacyError::InvalidSwapProgram
);
```

---

### AUDIT-003: Executor Account Not Closed Atomically on Swap Failure

**Severity:** High  
**Location:** `swap.rs:498-510`

**Description:**  
The executor PDA is closed by manually zeroing lamports after successful swap. If the transaction fails mid-execution after the executor is initialized but before closure, the executor PDA with its seed `[b"swap_executor", input_nullifier_0]` becomes permanently unusable. An attacker could intentionally cause failures to grief specific nullifiers, preventing legitimate notes from ever being swapped.

**Impact:**  
Permanent DoS on specific notes that could be worth significant value.

**Fix:**  
Use Anchor's `close` constraint or ensure executor closure happens in a cleanup pattern that works even on partial failures, or use ephemeral keypairs instead of deterministic PDAs.

---

## Medium

### AUDIT-005: init_if_needed Nullifier Marker - Inconsistent Error Path (Informational)

**Severity:** Low (Downgraded from Medium)  
**Location:** `lib.rs:541-559`

**Description:**  
The nullifier markers use `init_if_needed` with a check that `nullifier_marker.nullifier == [0u8; 32]` to detect double-spend. While there's no actual security vulnerability (Solana's runtime provides atomic account initialization protection, and only one of two racing transactions can succeed), the error message returned when a race occurs differs from the expected `NullifierAlreadyUsed` error.

**Impact:**  
Users may experience confusing error messages during race conditions, but no actual double-spend is possible. This is an informational/UX concern, not a security vulnerability.

**Fix:**  
Add documentation clarifying the security model, or wrap the error handling to provide consistent error messages. No code change required for security.

---

### AUDIT-006: TVL Underflow on Concurrent Withdrawals

**Severity:** Medium  
**Location:** `lib.rs:1503`, `swap.rs:191`

**Description:**  
The `total_tvl` field uses `checked_sub` for withdrawals, which will cause transaction failure if TVL tracking becomes desynchronized with actual vault balance. If a previous transaction corrupted TVL (e.g., through a bug or admin action), all future withdrawals would fail even if the vault has sufficient funds.

**Impact:**  
Potential permanent DoS if TVL becomes desynchronized with reality.

**Fix:**  
Consider deriving TVL from actual vault balance rather than maintaining separate state, or add admin recovery function.

---

### AUDIT-007: Missing Validation of remaining_accounts in Swap CPI

**Severity:** Medium  
**Location:** `swap.rs:233-320`

**Description:**  
The `remaining_accounts` passed to the swap CPI are not validated for ownership or program association. A malicious relayer could pass fake pool accounts that appear valid but are controlled by the attacker, potentially manipulating swap routing or outcomes.

**Impact:**  
Relayer could manipulate swap execution to the user's detriment (worse rates, MEV extraction).

**Fix:**  
Validate that critical remaining accounts (pool_state, token vaults) are owned by the expected Raydium program.

---

### AUDIT-008: Missing Deadline Check After Swap Execution

**Severity:** Medium  
**Location:** `swap.rs:96-99`

**Description:**  
The deadline is checked before swap execution, but the actual swap CPI could be delayed by validator prioritization. By the time the swap executes on-chain, the deadline may have passed, allowing stale price execution.

**Impact:**  
Users may receive worse swap rates than intended if transaction is delayed.

**Fix:**  
This is inherent to Solana's model, but consider documenting the limitation clearly.

---

## Low

### AUDIT-009: Tree ID Increment Without Bounds Check on num_trees

**Severity:** Low  
**Location:** `lib.rs:809-810`

**Description:**  
In `add_merkle_tree`, `num_trees` is validated against `MAX_MERKLE_TREES` (10,000), but the increment `cfg.num_trees += 1` happens after validation without overflow check. With `MAX_MERKLE_TREES = 10000` and `num_trees: u16` (max 65535), this is safe, but the pattern is fragile.

**Impact:**  
None currently, but could cause issues if MAX_MERKLE_TREES is increased.

**Fix:**  
Use `checked_add` for consistency:

```rust
cfg.num_trees = cfg.num_trees.checked_add(1).ok_or(PrivacyError::ArithmeticOverflow)?;
```

---

### AUDIT-010: Swap Fee Validation Uses Destination Pool Config Only

**Severity:** Low  
**Location:** `swap.rs:343-352`

**Description:**  
The swap fee is validated against `dest_config.swap_fee_bps` and `dest_config.min_swap_fee`, but the source pool's fee configuration is ignored. If source and destination pools have different fee structures, this could lead to inconsistent fee collection.

**Impact:**  
Minor economic inconsistency; potential for relayers to profit from fee arbitrage.

**Fix:**  
Consider validating against both source and destination pool fee requirements, or document the intended behavior.

---

## Summary

| Severity | Count |
| -------- | ----- |
| Critical | 1     |
| High     | 2     |
| Medium   | 3     |
| Low      | 3     |

**Recommendation:** Do not deploy to mainnet until AUDIT-001 (Critical) is resolved. The missing ZK proof verification in `transact_swap` allows complete fund theft.

# Security Audit Report: Privacy Pool Program

**Auditor**: Senior Solana Security Review  
**Date**: January 15, 2026  
**Scope**: `programs/privacy-pool/src/*.rs`

---

## Medium

### AUDIT-001: Root History Buffer Wraparound May Invalidate In-Flight Transactions

**Severity**: Medium  
**Location**: `merkle_tree.rs:59-73`

**Description**: The `root_history` is a 512-slot circular buffer. High-throughput deposits (>512 between proof generation and submission) can evict the root used in an honest user's withdrawal proof, causing `UnknownRoot` failure. Attackers with funds could intentionally spam 512+ deposits to grief specific in-flight withdrawals.

**Impact**: DoS of pending withdrawal transactions; loss of relayer gas costs.

**Fix**: Document the root history constraint prominently; consider optional extended root history for high-value withdrawals.

---

### AUDIT-002: Nullifier Marker Init_if_needed Race Condition

**Severity**: Medium  
**Location**: `lib.rs:533-548` (`init_if_needed` on `nullifier_marker_0/1`)

**Description**: Using `init_if_needed` for nullifier markers creates a TOCTOU window. While the code checks `nullifier == [0u8; 32]` after account creation, if two transactions with the same nullifier race, both could pass the PDA derivation check before either marks it spent. The second transaction would fail on the `NullifierAlreadyUsed` check, but this relies on the check being present—if it were absent or bypassed, double-spend occurs.

**Impact**: Currently mitigated by the `nullifier == [0u8; 32]` check, but fragile pattern. No immediate exploit with current code, but increases attack surface for future modifications.

**Fix**: Consider using `init` with a separate instruction for nullifier creation, or use the existence check via `try_borrow_data` before init.

---

### AUDIT-003: Unsigned Abs Correctness for i64::MIN Edge Case

**Severity**: Medium  
**Location**: `zk.rs:110-127` (`i64_to_field_be`)

**Description**: The function correctly uses `unsigned_abs()` for `i64::MIN`, but the downstream logic in `handle_public_amount` uses `public_amount.unsigned_abs()` (correct). However, if `public_amount = i64::MIN` (-9223372036854775808), this equals `9223372036854775808` as u64. This exceeds realistic withdrawal amounts and could cause TVL underflow if `config.total_tvl` is less than this amount.

**Impact**: If somehow exploited (would require vault to have > 9.2 quintillion lamports), could cause TVL accounting underflow panic.

**Fix**: Add upper bound check: `require!(withdrawal_amount <= config.max_withdraw_amount)` (already present, but ensure `max_withdraw_amount` is always reasonable).

---

## Low

### AUDIT-004: TVL Tracking Can Desync from Actual Vault Balance

**Severity**: Low  
**Location**: `lib.rs:1207`, `lib.rs:1289`

**Description**: `total_tvl` is updated atomically with deposits/withdrawals but if a transaction partially fails after TVL update (e.g., CPI failure in token transfer), Anchor rollback should restore it. However, external lamport donations to the vault PDA would not update TVL, creating discrepancy.

**Impact**: Informational for accounting; no direct security impact since actual vault balance is checked independently for withdrawals.

**Fix**: Document that TVL is approximate; consider deriving from vault balance rather than tracking separately if precision is required.

---

### AUDIT-005: Missing Explicit Check That Output Commitments Are Non-Zero

**Severity**: Low  
**Location**: `lib.rs:803-807`

**Description**: While duplicate commitments are rejected, there's no check that `output_commitments[0]` or `output_commitments[1]` are not `[0u8; 32]`. A zero commitment could be valid per the circuit but creates a known-value note that anyone could claim (if the secret/blinding are zero).

**Impact**: Unlikely exploit—attacker would be burning their own funds into an unspendable note. Low priority.

**Fix**: Add:
```rust
require!(
    output_commitments[0] != [0u8; 32] && output_commitments[1] != [0u8; 32],
    PrivacyError::ZeroCommitment
);
```

---

### AUDIT-006: Relayer Authorization Bypass for Deposits Could Enable Spam

**Severity**: Low  
**Location**: `lib.rs:816-823`

**Description**: Deposits (`public_amount > 0`) skip relayer authorization check. While this enables permissionless deposits, it allows anyone to spam the Merkle tree with low-value deposits, potentially filling trees faster and forcing admin to add new trees.

**Impact**: Minor griefing; tree fills are recoverable via `add_merkle_tree`. Cost of attack = deposit amounts which are locked.

**Fix**: Consider optional deposit-side relayer allowlist or minimum deposit amount enforcement (already present via `min_deposit_amount`).

---

### AUDIT-007: G1 Negation Logic Relies on Ark Serialization Compatibility

**Severity**: Low  
**Location**: `zk.rs:195-211`

**Description**: The proof_a G1 point is deserialized, negated, and re-serialized with specific endianness handling. If `ark-bn254` or serialization changes in a dependency update, proof verification could silently break. No runtime validation that the point is on the curve beyond `Validate::Yes`.

**Impact**: Upgrade risk; current code appears correct.

**Fix**: Pin `ark-bn254` version; add integration test with known-good proofs.

---

### AUDIT-008: Clock Timestamp Used Without Validation

**Severity**: Low  
**Location**: `lib.rs:1094`, `lib.rs:1125`

**Description**: `Clock::get()?.unix_timestamp` is used for event timestamps and nullifier markers. While timestamp manipulation by validators is bounded (~10 seconds), timestamps are informational only and not used in security-critical comparisons.

**Impact**: None currently; informational timestamps could be slightly inaccurate.

**Fix**: Acceptable as-is; document that timestamps are approximate.

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0     |
| High     | 0     |
| Medium   | 3     |
| Low      | 5     |

No critical or high severity issues found. The program demonstrates solid security practices with proper signer checks, PDA validation, arithmetic overflow protection, and nullifier double-spend prevention. The medium findings are primarily edge cases and defense-in-depth considerations rather than immediately exploitable vulnerabilities.

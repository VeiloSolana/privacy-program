# AUDIT-002 Resolution: Public Amount Sign Convention

## Issue Summary

**Severity:** High (Correctness/Documentation)  
**Status:** RESOLVED - Documentation errors fixed, implementation was correct  
**Date:** January 12, 2026

---

## Original Concern

The audit flagged potential inconsistency between documentation and implementation regarding the `public_amount` sign convention:

> "TransactionPublicInputs docs say positive = withdrawal, negative = deposit; handle_public_amount implements the opposite"

---

## Analysis: Circuit Truth

The circuit file `transaction.circom` contains the canonical balance equation:

```circom
// Balance equation
sumIns + publicAmount === sumOuts;
```

### Mathematical Proof of Convention

**Deposit Scenario (funds entering pool):**

```
Input UTXOs:  0 tokens (no existing notes)
Output UTXOs: 100 tokens (new notes created in pool)
Balance: 0 + publicAmount = 100
Therefore: publicAmount = +100 (POSITIVE)
```

**Withdrawal Scenario (funds leaving pool):**

```
Input UTXOs:  100 tokens (spending existing notes)
Output UTXOs: 50 tokens (change note)
Balance: 100 + publicAmount = 50
Therefore: publicAmount = -50 (NEGATIVE)
```

**Private Transfer (no funds cross boundary):**

```
Input UTXOs:  100 tokens
Output UTXOs: 100 tokens (same total, different notes)
Balance: 100 + publicAmount = 100
Therefore: publicAmount = 0 (ZERO)
```

### **Circuit Convention:**

- ✅ **POSITIVE** `publicAmount` = **DEPOSIT** (adding value to pool)
- ✅ **NEGATIVE** `publicAmount` = **WITHDRAWAL** (removing value from pool)
- ✅ **ZERO** `publicAmount` = **PRIVATE TRANSFER** (no value crosses boundary)

---

## Implementation Verification

### Code Implementation (CORRECT)

[lib.rs#L920-L973](../programs/privacy-pool/src/lib.rs#L920-L973)

```rust
if public_amount > 0 {
    // DEPOSIT: user deposits public_amount lamports/tokens
    let deposit_amount = public_amount as u64;
    // ... transfer funds INTO vault ...

    // Update TVL (increase)
    config.total_tvl = config.total_tvl.checked_add(deposit_amount)?;

} else if public_amount < 0 {
    // WITHDRAWAL: vault pays out |public_amount| lamports
    let withdrawal_amount = public_amount.abs() as u64;
    // ... transfer funds OUT OF vault to recipient + relayer ...

    // Update TVL (decrease)
    config.total_tvl = config.total_tvl.checked_sub(withdrawal_amount)?;
}
```

**Implementation is CORRECT and matches circuit!**

---

## Documentation Errors Found and Fixed

### ❌ Error 1: TransactionPublicInputs Comment

**Location:** [lib.rs#L131](../programs/privacy-pool/src/lib.rs#L131) (old line number)

**Before (WRONG):**

```rust
/// Net public amount (i64 - can be negative for deposits)
/// Positive = withdrawal, Negative = deposit, Zero = private transfer
pub public_amount: i64,
```

**After (CORRECT):**

```rust
/// Net public amount (i64 - signed for deposits/withdrawals)
/// Circuit equation: sumIns + publicAmount = sumOuts
/// POSITIVE = DEPOSIT (adding to pool: 0 + amount = outputs)
/// NEGATIVE = WITHDRAWAL (removing from pool: inputs + negative = smaller outputs)
/// ZERO = PRIVATE TRANSFER (no value crossing pool boundary)
pub public_amount: i64,
```

### ❌ Error 2: Transact Function Doc

**Location:** [lib.rs#L628](../programs/privacy-pool/src/lib.rs#L628)

**Before (WRONG):**

```rust
/// Handles deposits (publicAmount < 0), withdrawals (publicAmount > 0), and transfers (publicAmount = 0)
```

**After (CORRECT):**

```rust
/// Circuit equation: sumIns + publicAmount = sumOuts
/// Handles deposits (publicAmount > 0), withdrawals (publicAmount < 0), and transfers (publicAmount = 0)
```

### ❌ Error 3: Relayer Authorization Comment

**Location:** [lib.rs#L669](../programs/privacy-pool/src/lib.rs#L669)

**Before (WRONG):**

```rust
// For deposits (public_amount < 0), anyone can deposit without being a relayer
```

**After (CORRECT):**

```rust
// For deposits (public_amount > 0), anyone can facilitate deposit without being authorized
// For withdrawals (public_amount < 0) and transfers (public_amount = 0), require authorized relayer
```

### ❌ Error 4: handle_public_amount Function Doc

**Location:** [lib.rs#L887-889](../programs/privacy-pool/src/lib.rs#L887-889)

**Before (WRONG):**

```rust
/// public_amount < 0: Deposit (user -> vault)
/// public_amount > 0: Withdrawal (vault -> recipient + relayer)
```

**After (CORRECT):**

```rust
/// Circuit equation: sumIns + publicAmount = sumOuts
/// public_amount > 0: DEPOSIT (user -> vault, funds entering pool)
/// public_amount < 0: WITHDRAWAL (vault -> recipient + relayer, funds leaving pool)
```

---

## Verification

### ✅ Circuit Analysis

- Circuit balance equation: `sumIns + publicAmount = sumOuts`
- Mathematical verification confirms: **POSITIVE = DEPOSIT**

### ✅ Implementation Analysis

- Code logic at line 920: `if public_amount > 0` → deposits funds
- Code logic at line 973: `else if public_amount < 0` → withdraws funds
- **Implementation correctly follows circuit convention**

### ✅ Documentation Fixed

- All 4 documentation errors corrected
- Comments now accurately reflect circuit equation
- Consistent terminology throughout codebase

### ✅ Build Verification

```bash
$ anchor build
✅ Compiled successfully
```

---

## Conclusion

### Finding Summary

| Aspect                     | Status                   |
| -------------------------- | ------------------------ |
| Circuit Implementation     | ✅ Correct               |
| Rust Code Logic            | ✅ Correct (always was)  |
| Documentation (before fix) | ❌ Incorrect in 4 places |
| Documentation (after fix)  | ✅ Correct               |

### Root Cause

The issue was **purely documentation errors**. The program implementation was always correct and properly synchronized with the circuit. Multiple comments incorrectly stated the sign convention as the reverse of reality.

### Risk Assessment

- **No code changes required** - Implementation was correct
- **No economic risk** - Funds flows were always correct
- **No security vulnerability** - Circuit/program were synchronized
- **Documentation risk only** - Could confuse developers integrating with the protocol

### Recommended Next Steps

1. ✅ Review all updated documentation
2. ⏳ Add integration tests with real proofs for all three scenarios:
   - Deposit (publicAmount > 0)
   - Withdrawal (publicAmount < 0)
   - Private transfer (publicAmount = 0)
3. ⏳ Update any external documentation/client SDKs with correct convention
4. ⏳ Add circuit equation comment to TypeScript client helpers

---

## For Developers

### Correct Sign Convention (Memorize This)

```
Circuit: sumIns + publicAmount = sumOuts

DEPOSIT:    publicAmount = +100  (positive, adds to pool)
WITHDRAWAL: publicAmount = -50   (negative, removes from pool)
TRANSFER:   publicAmount = 0     (zero, internal shuffle)
```

### Client Implementation Example

```typescript
// Deposit 100 tokens
const depositAmount = 100_000_000; // positive
const publicAmount = depositAmount; // +100 million (positive = deposit)

// Withdraw 50 tokens
const withdrawAmount = 50_000_000;
const publicAmount = -withdrawAmount; // -50 million (negative = withdrawal)

// Private transfer
const publicAmount = 0; // zero = private transfer
```

---

**AUDIT-002 is RESOLVED with documentation fixes only. No security or correctness issues existed in the implementation.**

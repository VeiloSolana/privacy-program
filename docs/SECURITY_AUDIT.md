# Security Audit — Privacy Pool Program

**Date:** 4 March 2026
**Auditor:** Senior Solana Security Review (Neodyme/Certora/Kudelski-style)
**Scope:** `programs/privacy-pool/src/` — all `.rs` files
**Commit branch:** `main` (`VeiloSolana/privacy-program`)

---

## Medium

### AUDIT-001 Relayer-Controlled DEX Slippage Bypass in `transact_swap`

**Severity:** Medium
**Location:** `swap.rs` — `transact_swap`, lines ~344–360

**Description:**
The `swap_data` byte blob is forwarded directly to Raydium/Jupiter CPIs and is **not** committed in the ZK proof. A whitelisted-but-rogue relayer can set the DEX-level `minimum_amount_out` to 0 inside `swap_data` while the ZK proof commits to a non-zero `swap_params.min_amount_out`. This exposes users to full MEV/sandwich attacks that bring the received amount down to the ZK-committed minimum. The on-chain post-swap check (`swapped_amount >= swap_params.min_amount_out`) is the sole protection — Raydium/Jupiter's own slippage guard is silently neutered.

**Impact:**
Malicious relayer can systematically extract all slippage tolerance on every swap routed through them, costing users the difference between market rate and their `min_amount_out` floor.

**Fix:**
Either include a hash of `swap_data` as a public input in the ZK proof, or explicitly decode and assert the DEX `minimum_amount_out` field in `swap_data` matches `swap_params.min_amount_out` before the CPI.

---

### AUDIT-002 Deposit Path Is Fully Permissionless — Merkle Tree Leaf Griefing

**Severity:** Medium
**Location:** `lib.rs` — `transact`, deposit branch (~lines 1107–1115)

**Description:**
For `public_amount > 0`, the relayer whitelist check is skipped (`if public_amount <= 0 { require!(is_relayer…) }`). Any party who can generate a valid ZK deposit proof can fill tree leaves. With a fixed `MERKLE_TREE_HEIGHT = 22`, each tree holds 4,194,304 leaves. At ~1,000 deposits/second this is a sustained griefing path. Each deposit only costs transaction fees + proof generation; no whitelisted relayer is required.

**Impact:**
Adversary can systematically fill active trees, forcing users and relayers into constant `add_merkle_tree` overhead, increasing operational friction and potential timing-based privacy degradation.

**Fix:**
Either gate deposits behind the same relayer whitelist as withdrawals, or enforce a minimum deposit amount high enough to make griefing economically infeasible.

---

## Low

### AUDIT-003 Incorrect Field-Reduction Early-Exit in `SwapParams::reduce_to_field`

**Severity:** Low
**Location:** `swap.rs` — `SwapParams::reduce_to_field`, lines ~52–65

**Description:**
The `needs_reduction` flag is set only when `bytes[i] > FR_MODULUS[i]`. If `bytes == FR_MODULUS` (i.e., exactly `p`), every byte-pair is equal, neither branch sets the flag, and the function returns `p` unreduced. `p` is not a valid BN254 field element and must map to `0`. The equivalent function in `zk.rs` (`reduce_to_field_be`) correctly handles this via `is_less_than` (which returns `false` for equal inputs, falling through to BigUint reduction). The inconsistency means a `swap_params` hash containing a value equal to `p` would produce an invalid public input and fail ZK verification.

**Impact:**
Transaction DoS for the astronomically rare case of a Poseidon output equaling the field modulus exactly; no fund loss.

**Fix:**
Replace the `needs_reduction` heuristic in `swap.rs` with the same `is_less_than`-based guard used in `zk.rs`, or unify into a single shared `reduce_to_field` function used by both modules:

```rust
// Unified helper (add to a shared module or zk.rs, re-export)
pub fn reduce_to_field_be(bytes: [u8; 32]) -> [u8; 32] {
    if is_less_than(&bytes, &FR_MODULUS) {
        return bytes; // already < p, no reduction needed
    }
    // handles bytes == p AND bytes > p
    let val = BigUint::from_bytes_be(&bytes);
    let reduced = val % BigUint::from_bytes_be(&FR_MODULUS);
    let mut result = [0u8; 32];
    let b = reduced.to_bytes_be();
    result[32 - b.len()..].copy_from_slice(&b);
    result
}
```

---

### AUDIT-004 Executor PDA Closed via Manual Lamport Drain Without Data Zeroing

**Severity:** Low
**Location:** `swap.rs` — `transact_swap` close sequence, lines ~790–803

**Description:**
The executor PDA is "closed" by manually zeroing its lamports and crediting the relayer. Anchor's account-exit serialization will still write the discriminator and struct fields back into the (now zero-lamport) account data. This bypasses Anchor's `close = target` mechanism, which zeros account data and sets a closed discriminator before the lamport transfer. If the executor's SOL is replenished externally (by anyone sending SOL to the PDA) before the runtime garbage-collects it, a stale account with the old discriminator and data could persist.

**Impact:**
Low; the old nullifiers are already marked spent, so the zombie executor cannot be misused to re-authorize a swap. Theoretical resurrection risk with no direct fund-theft vector.

**Fix:**
Use `close = relayer` as an Anchor account constraint on the executor account instead of manual lamport manipulation, or at minimum zero the account data bytes explicitly before draining lamports:

```rust
// Zero account data before lamport drain
let mut data = executor.to_account_info().try_borrow_mut_data()?;
data.fill(0);
drop(data);
// then drain lamports...
```

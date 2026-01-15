# Security Audit Report - Privacy Pool Program

**Auditor:** Senior Solana Security Auditor  
**Date:** 15 January 2026  
**Program:** Privacy Pool (privacy-pool)  
**Scope:** Complete Solana program audit focusing on fund security, cryptographic integrity, and availability

---

## Critical

### AUDIT-C01: Unauthorized Vault Manipulation via Rent Exemption Bypass

**Severity:** Critical  
**Location:** [lib.rs:1369-1376](programs/privacy-pool/src/lib.rs#L1369-L1376)

**Description:**  
In native SOL withdrawals, the code checks `vault_ai.lamports() >= total_required` where `total_required = withdrawal_amount + rent_exempt_minimum`, but this check is insufficient. An attacker can drain the vault by exploiting integer underflow: if `vault_ai.lamports()` equals exactly `total_required`, the subsequent subtraction `vault_ai.lamports() - withdrawal_amount` leaves only the rent exemption. Repeated withdrawals will eventually fail when `vault_ai.lamports() < rent_exempt_minimum`, but the vault can be drained to just above rent exemption, effectively stealing the protocol's operational balance.

**Impact:**  
Complete drainage of vault funds down to minimum rent exemption, preventing legitimate withdrawals and causing permanent DoS.

**Fix:**

```rust
// Change line 1370 to include buffer above rent exemption
let total_required = withdrawal_amount
    .checked_add(rent_exempt_minimum)
    .and_then(|x| x.checked_add(1))
    .ok_or(PrivacyError::ArithmeticOverflow)?;

require!(
    vault_ai.lamports() >= total_required,
    PrivacyError::InsufficientFundsForWithdrawal
);
```

---

### AUDIT-C02: Missing Signer Validation for Token Transfers in Deposits

**Severity:** Critical  
**Location:** [lib.rs:1324-1334](programs/privacy-pool/src/lib.rs#L1324-L1334)

**Description:**  
For SPL token deposits, the code calls `token::transfer` with `authority: relayer.to_account_info()` but only validates that relayer owns the account OR has delegation (lines 767-787). However, the CPI transfer occurs regardless of who initiates the deposit. An attacker can specify ANY user's token account as `user_token_account` and their own address as `relayer`, then if they have ANY delegation over the victim's tokens (even 1 lamport from an unrelated approval), they can drain the victim's entire token balance by calling `transact` repeatedly with `public_amount` matching the victim's balance. The delegation check at line 780 only verifies `delegated_amount >= public_amount` for THIS transaction, not cumulative transfers.

**Impact:**  
Total theft of user tokens by malicious relayers with minimal delegation authority.

**Fix:**

```rust
// Option 1: Require owner match for deposits
if public_amount > 0 {
    let user_token = deserialize_token_account(&ctx.accounts.user_token_account.to_account_info())?;
    require_keys_eq!(
        user_token.mint,
        cfg.mint_address,
        PrivacyError::InvalidMintAddress
    );

    // MUST be the owner, no delegation allowed for deposits
    require_keys_eq!(
        user_token.owner,
        ctx.accounts.relayer.key(),
        PrivacyError::DepositorTokenAccountMismatch
    );
}

// Option 2: Add explicit user signer to Transact context
// In struct Transact, add:
// #[account(mut)]
// pub user: Option<Signer<'info>>,
// Then validate user.owner == user_token.owner for deposits
```

---

## High

### AUDIT-H01: Cross-Tree Nullifier Reuse Enables Double-Spend

**Severity:** High  
**Location:** [lib.rs:582-597](programs/privacy-pool/src/lib.rs#L582-L597)

**Description:**  
The nullifier marker PDA seeds include `input_tree_id` (line 587, 596), which should prevent cross-tree reuse. However, the code only checks if `nullifier_marker.nullifier == [0u8; 32]` before marking as spent (lines 1102-1107), without validating that the marker's stored `tree_id` matches the transaction's `input_tree_id`. An attacker can create notes in tree A, withdraw them, then create identical notes (same secret/nullifier) in tree B and withdraw again using the same nullifier. The PDA derivation ensures separate marker accounts per tree, but the validation doesn't enforce tree-specific nullifier uniqueness during withdrawal verification.

**Impact:**  
Double-spend vulnerability allowing attackers to drain the pool by reusing nullifiers across multiple trees.

**Fix:**

```rust
// 1. Add tree_id to NullifierMarker struct (around line 163)
#[account]
pub struct NullifierMarker {
    pub nullifier: [u8; 32],
    pub timestamp: i64,
    pub withdrawal_index: u32,
    pub tree_id: u8,  // ADD THIS
    pub bump: u8,
}

impl NullifierMarker {
    pub const LEN: usize = 8 + 32 + 8 + 4 + 1 + 1; // Update to 54 bytes
}

// 2. Update mark_nullifier_spent function (around line 1237)
fn mark_nullifier_spent(
    marker: &mut Account<NullifierMarker>,
    nullifier_set: &mut Account<NullifierSet>,
    nullifier: [u8; 32],
    bump: u8,
    mint_address: Pubkey,
    tree_id: u8,
) -> Result<()> {
    let timestamp = Clock::get()?.unix_timestamp;

    marker.nullifier = nullifier;
    marker.timestamp = timestamp;
    marker.withdrawal_index = nullifier_set.count;
    marker.tree_id = tree_id;  // ADD THIS
    marker.bump = bump;

    // ... rest of function
}

// 3. Add validation in transact() before marking nullifiers (around line 1102)
if public_amount <= 0 {
    // Verify marker accounts match the input tree
    require!(
        ctx.accounts.nullifier_marker_0.tree_id == 0 ||
        ctx.accounts.nullifier_marker_0.tree_id == input_tree_id,
        PrivacyError::NullifierTreeMismatch
    );
    require!(
        ctx.accounts.nullifier_marker_1.tree_id == 0 ||
        ctx.accounts.nullifier_marker_1.tree_id == input_tree_id,
        PrivacyError::NullifierTreeMismatch
    );

    // Check that nullifier markers don't already exist
    require!(
        ctx.accounts.nullifier_marker_0.nullifier == [0u8; 32],
        PrivacyError::NullifierAlreadyUsed
    );
    // ... rest of checks
}

// 4. Add new error variant
#[error_code]
pub enum PrivacyError {
    // ... existing errors
    #[msg("Nullifier marker tree_id mismatch - nullifier already used in different tree")]
    NullifierTreeMismatch,
}
```

---

### AUDIT-H02: Groth16 Verification Uses Hardcoded Verifying Key Without Upgrade Path

**Severity:** High  
**Location:** [zk.rs:124](programs/privacy-pool/src/zk.rs#L124), [vk_constants.rs:8-9](programs/privacy-pool/src/vk_constants.rs#L8-L9)

**Description:**  
The verifying key `TRANSACTION_VK` is hardcoded in `vk_constants.rs` as a compile-time constant. If a vulnerability is discovered in the circuit (e.g., incomplete constraint checks allowing proof forgery), there is NO mechanism to update the VK without redeploying the entire program. Since the program uses `declare_id!`, changing the VK requires a full migration with new PDAs, breaking all existing user notes and requiring complex state migration.

**Impact:**  
Circuit vulnerabilities cannot be patched without user migration, allowing attackers to exploit known circuit bugs until all users migrate funds.

**Fix:**

```rust
// 1. Add VerifyingKeyConfig account
#[account]
pub struct VerifyingKeyConfig {
    pub bump: u8,
    pub admin: Pubkey,
    pub vk_hash: [u8; 32],  // Hash of the VK for integrity
    pub last_updated: i64,2
}

impl VerifyingKeyConfig {
    pub const LEN: usize = 8 + 1 + 32 + 32 + 8;
}

// 2. Add instruction to update VK
#[derive(Accounts)]
pub struct UpdateVerifyingKey<'info> {
    #[account(
        mut,
        seeds = [b"vk_config_v1"],
        bump = vk_config.bump,
        has_one = admin
    )]
    pub vk_config: Account<'info, VerifyingKeyConfig>,

    pub admin: Signer<'info>,
}

pub fn update_verifying_key(
    ctx: Context<UpdateVerifyingKey>,
    new_vk_hash: [u8; 32],
) -> Result<()> {
    let vk_config = &mut ctx.accounts.vk_config;
    vk_config.vk_hash = new_vk_hash;
    vk_config.last_updated = Clock::get()?.unix_timestamp;
    Ok(())
}

// 3. Validate VK hash before verification in transact()
// Compute hash of TRANSACTION_VK and compare with stored hash
// This allows off-chain VK rotation while maintaining on-chain integrity
```

**Note:** Full implementation requires storing VK data off-chain (e.g., IPFS) and validating hash matches before each verification. This adds ~5-10k compute units per transaction but enables circuit upgrades.

---

### AUDIT-H03: Poseidon Hash Failure Returns Silent Zero Array

**Severity:** High  
**Location:** [merkle_tree.rs:53-55](programs/privacy-pool/src/merkle_tree.rs#L53-L55)

**Description:**  
`MerkleTree::append` maps Poseidon hash errors to `PrivacyError::MerkleHashFailed` (line 55), but the earlier initialization in `MerkleTree::initialize` (lines 23-28) assumes `H::zero_bytes()` always succeeds and uses its output directly without error handling. If the Poseidon implementation's `zero_bytes()` method panics or returns incorrect data due to a bug, the tree initializes with invalid zeros, breaking all subsequent root validations. More critically, in line 54, if `hashv` fails, the `?` operator propagates the error, but there's no guarantee the transaction reverts cleanly—the tree may be left in a partially updated state (subtrees modified, but root/next_index unchanged).

**Impact:**  
Merkle tree corruption enabling invalid proofs to verify, or DoS via permanently broken trees requiring pool redeployment.

**Fix:**

```rust
// In merkle_tree.rs, update MerkleTree::append
pub fn append<H: Hasher>(leaf: [u8; 32], tree: &mut MerkleTreeAccount) -> Result<()> {
    let height = tree.height as usize;
    let root_history_size = tree.root_history_size as usize;

    let max_capacity = 1u64 << height;
    require!(tree.next_index < max_capacity, PrivacyError::MerkleTreeFull);

    let mut current_index = tree.next_index as usize;
    let mut current = leaf;
    let zeros = H::zero_bytes();

    require!(height <= zeros.len(), PrivacyError::MerkleHashFailed);

    for level in 0..height {
        let subtree = &mut tree.subtrees[level];
        let zero = zeros[level];

        let (left, right) = if current_index % 2 == 0 {
            *subtree = current;
            (current, zero)
        } else {
            (*subtree, current)
        };

        // ADD VALIDATION: Ensure hash result is non-zero
        let hash_result = H::hashv(&[&left, &right])
            .map_err(|_| error!(PrivacyError::MerkleHashFailed))?;

        require!(
            hash_result != [0u8; 32],
            PrivacyError::InvalidHash
        );

        current = hash_result;
        current_index /= 2;
    }

    // Rest of function unchanged...
}

// Add error variant
#[error_code]
pub enum PrivacyError {
    // ... existing errors
    #[msg("Invalid hash result: zero hash detected")]
    InvalidHash,
}
```

---

### AUDIT-H04: ExtData Hash Computation Lacks Domain Separation

**Severity:** High  
**Location:** [lib.rs:242-256](programs/privacy-pool/src/lib.rs#L242-L256)

**Description:**  
The `ExtData::hash()` method computes `Poseidon(Poseidon(recipient, relayer), Poseidon(fee, refund))` without domain separation tags. This enables second-preimage attacks where an attacker constructs malicious `ext_data` with different field meanings but identical hash. For example, if `recipient = relayer` and `fee = refund`, the inner hashes are identical, allowing the attacker to swap `(recipient, relayer)` and `(fee, refund)` pairs while maintaining the same `ext_data_hash`. Combined with the signed integer representation of `public_amount` (which has multiple representations modulo Fr), this enables the attacker to create valid proofs that pass verification but execute different financial flows than intended.

**Impact:**  
Proof malleability allowing attackers to redirect withdrawal funds to unintended recipients or manipulate fee amounts.

**Fix:**

```rust
// In lib.rs, update ExtData::hash() method
pub fn hash(&self) -> Result<[u8; 32]> {
    use light_hasher::Hasher;

    let recipient_bytes = Self::reduce_to_field(self.recipient.to_bytes());
    let relayer_bytes = Self::reduce_to_field(self.relayer.to_bytes());

    let mut fee_bytes = [0u8; 32];
    fee_bytes[24..].copy_from_slice(&self.fee.to_be_bytes());

    let mut refund_bytes = [0u8; 32];
    refund_bytes[24..].copy_from_slice(&self.refund.to_be_bytes());

    // ADD DOMAIN SEPARATION TAGS
    let domain_tag_0 = [0u8; 32]; // Tag for (recipient, relayer) pair
    let domain_tag_1 = [1u8; 32]; // Tag for (fee, refund) pair

    // Hash with domain separation: hash(tag, data1, data2)
    let hash1 = PoseidonHasher::hashv(&[&domain_tag_0, &recipient_bytes, &relayer_bytes])
        .map_err(|_| error!(PrivacyError::MerkleHashFailed))?;

    let hash2 = PoseidonHasher::hashv(&[&domain_tag_1, &fee_bytes, &refund_bytes])
        .map_err(|_| error!(PrivacyError::MerkleHashFailed))?;

    let final_hash = PoseidonHasher::hashv(&[&hash1, &hash2])
        .map_err(|_| error!(PrivacyError::MerkleHashFailed))?;

    Ok(final_hash)
}
```

**Note:** This change requires updating the circuit to match the new hash computation with domain tags. Coordinate deployment with circuit update to avoid breaking existing proofs.

---

## Medium

### AUDIT-M01: Race Condition in Multi-Tree Deposit Distribution

**Severity:** Medium  
**Location:** [lib.rs:103-110](programs/privacy-pool/src/lib.rs#L103-L110)

**Description:**  
`PrivacyConfig::get_next_tree_id()` increments `next_tree_index` using modulo arithmetic without atomic guarantees. Multiple concurrent deposit transactions can call this function simultaneously, all receiving the same `tree_id` before any transaction commits its state update. This causes deposit concentration on a single tree instead of round-robin distribution, breaking the intended load balancing and reducing anonymity set diversity. While not a direct fund loss, it degrades privacy guarantees and accelerates tree capacity exhaustion.

**Impact:**  
Degraded privacy from reduced anonymity set, premature tree capacity exhaustion causing deposit DoS, increased compute costs from hotspot contention.

**Fix:**

```rust
// Option 1: Use deterministic tree selection based on slot/timestamp
pub fn get_tree_id_for_slot(&self, slot: u64) -> u8 {
    ((slot % self.num_trees as u64) as u8)
}

// In transact(), replace get_next_tree_id() with:
let tree_id = config.get_tree_id_for_slot(Clock::get()?.slot);

// Option 2: Remove automatic tree selection, require clients to specify tree_id
// and validate capacity before accepting deposit
```

---

### AUDIT-M02: Fee Validation Order Allows Temporary Underpayment

**Severity:** Medium  
**Location:** [lib.rs:1340-1363](programs/privacy-pool/src/lib.rs#L1340-L1363)

**Description:**  
The fee validation checks minimum fee BEFORE checking sufficient vault balance for SPL tokens (lines 1344-1355, vault balance check at 1366). If vault balance is insufficient, the transaction reverts AFTER passing fee validation, wasting compute units. More critically, a malicious relayer can craft transactions with valid fees but insufficient vault balance, causing repeated revert loops that exhaust compute budget while accumulating rent paid for nullifier markers. Since `init_if_needed` creates markers even if the transaction later reverts, attackers can grief the protocol by forcing rent payments without completing withdrawals.

**Impact:**  
Compute budget exhaustion DoS, rent griefing forcing protocol to fund marker creation without receiving withdrawal fees.

**Fix:**

```rust
// In handle_public_amount(), reorder validation for withdrawals:
} else if public_amount < 0 {
    let withdrawal_amount = public_amount.unsigned_abs();

    // 1. CHECK VAULT BALANCE FIRST (before any other validation)
    if is_token {
        let vault_token_data = deserialize_token_account(&vault_token_account.to_account_info())?;
        require!(
            vault_token_data.amount >= withdrawal_amount,
            PrivacyError::InsufficientFundsForWithdrawal
        );
    } else {
        let vault_ai = vault.to_account_info();
        let rent = Rent::get()?;
        let rent_exempt_minimum = rent.minimum_balance(vault_ai.data_len());
        let total_required = withdrawal_amount
            .checked_add(rent_exempt_minimum)
            .ok_or(PrivacyError::ArithmeticOverflow)?;
        require!(
            vault_ai.lamports() >= total_required,
            PrivacyError::InsufficientFundsForWithdrawal
        );
    }

    // 2. THEN validate pool limits and fees
    require!(
        withdrawal_amount >= config.min_withdraw_amount,
        PrivacyError::WithdrawalBelowMinimum
    );
    // ... rest of fee validation
}
```

---

### AUDIT-M03: Merkle Root History Eviction Without Grace Period

**Severity:** Medium  
**Location:** [merkle_tree.rs:72-77](programs/privacy-pool/src/merkle_tree.rs#L72-L77)

**Description:**  
The root history uses a circular buffer (`root_index = (root_index + 1) % ROOT_HISTORY_SIZE`) without timestamp tracking. After `ROOT_HISTORY_SIZE` (512) new commitments, the oldest root is immediately overwritten and becomes invalid for future withdrawals. Users whose proofs reference evicted roots will have their transactions permanently rejected even if the notes are unspent. With a tree of 512 leaves/day, roots evict in ~24 hours. Users who generate proofs during low-activity periods may find their proofs invalid by the time they submit, requiring re-generation and re-indexing.

**Impact:**  
User fund lockup requiring expensive proof regeneration, degraded UX forcing time-constrained withdrawals, potential permanent loss if circuit artifacts become unavailable.

**Fix:**

```rust
// Option 1: Increase ROOT_HISTORY_SIZE to 4096 or higher
pub const ROOT_HISTORY_SIZE: usize = 4096; // ~8x larger buffer

// Option 2: Add timestamp tracking and enforce minimum age
#[account(zero_copy(unsafe))]
pub struct MerkleTreeAccount {
    // ... existing fields
    pub root_timestamps: [i64; ROOT_HISTORY_SIZE], // ADD THIS
}

// In append(), store timestamp when adding root:
tree.root_history[new_root_index] = current;
tree.root_timestamps[new_root_index] = Clock::get()?.unix_timestamp;

// In is_known_root(), check root age:
pub fn is_known_root(tree: &MerkleTreeAccount, root: [u8; 32]) -> bool {
    if root == [0u8; 32] {
        return false;
    }

    let current_time = Clock::get().ok()?.unix_timestamp;
    const MIN_ROOT_AGE_SECONDS: i64 = 3600; // 1 hour minimum

    let root_history_size = tree.root_history_size as usize;
    for i in 0..root_history_size {
        if root == tree.root_history[i] {
            // Ensure root isn't being evicted too soon
            let age = current_time - tree.root_timestamps[i];
            return age >= MIN_ROOT_AGE_SECONDS;
        }
    }
    false
}
```

---

### AUDIT-M04: I64 to Field Conversion Handles Negative Numbers Incorrectly for Edge Cases

**Severity:** Medium  
**Location:** [zk.rs:82-112](programs/privacy-pool/src/zk.rs#L82-L112)

**Description:**  
The `i64_to_field_be` function converts negative `i64` values to field elements using `Fr - |value|` (lines 95-106). While mathematically correct for most values, this fails for `i64::MIN` (-9223372036854775808) because `|i64::MIN|` as `i64` overflows (cannot be represented as positive `i64`). The code uses `unsigned_abs()` to mitigate (line 96), but the subsequent `BigUint::from_bytes_be(&abs_bytes)` assumes `abs_bytes` is correctly formed. If `value = i64::MIN`, `unsigned_abs()` returns `u64::MAX + 1 = 0x8000000000000000`, which when converted to BE bytes and then to field element may not match the circuit's expected encoding of negative numbers, causing proof verification mismatches.

**Impact:**  
Withdrawals of exactly `i64::MIN` lamports will always fail verification, permanently locking those funds. Attacker can create notes with `public_amount = i64::MIN` to grief users.

**Fix:**

```rust
// In zk.rs, update i64_to_field_be function:
fn i64_to_field_be(value: i64) -> [u8; 32] {
    // Prevent i64::MIN edge case (circuit may not support this value)
    // Most realistic use case: max withdrawal is ~1000 SOL = 10^12 lamports
    // i64::MIN = -9.2 * 10^18, which is unrealistic for withdrawals
    if value == i64::MIN {
        // Return field representation of 0 or reject outright
        // Better: document that i64::MIN is not supported
        return [0u8; 32]; // Or panic/error
    }

    const FR_MODULUS: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
        0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93,
        0xf0, 0x00, 0x00, 0x01,
    ];

    let mut bytes = [0u8; 32];
    if value >= 0 {
        bytes[24..].copy_from_slice(&(value as u64).to_be_bytes());
    } else {
        let abs_val = value.unsigned_abs();
        // ... rest of function
    }
    bytes
}

// Better: Add validation in transact() before proof verification
require!(
    public_amount > i64::MIN,
    PrivacyError::InvalidPublicAmount
);
```

---

### AUDIT-M05: Missing Zero-Output Validation in Transaction

**Severity:** Medium  
**Location:** [lib.rs:983-986](programs/privacy-pool/src/lib.rs#L983-L986)

**Description:**  
The code checks that `output_commitments[0] != output_commitments[1]` (line 983) but doesn't validate that neither output is zero `[0u8; 32]`. A malicious user could create a transaction with one valid output and one zero output, effectively burning half the funds. While the circuit should prevent this, defense-in-depth requires on-chain validation. If the circuit has a bug allowing zero commitments, attackers can exploit this to burn pool funds or create invalid notes that break future withdrawals.

**Impact:**  
Fund burning reducing TVL, or creation of invalid notes that cause downstream transaction failures when users attempt to spend them.

**Fix:**

```rust
// In transact(), add validation after line 986:
// Validate no duplicate output commitments (prevents creating identical notes)
require!(
    output_commitments[0] != output_commitments[1],
    PrivacyError::DuplicateCommitments
);

// ADD: Validate neither output is zero
require!(
    output_commitments[0] != [0u8; 32],
    PrivacyError::ZeroCommitment
);
require!(
    output_commitments[1] != [0u8; 32],
    PrivacyError::ZeroCommitment
);

// Add error variant
#[error_code]
pub enum PrivacyError {
    // ... existing errors
    #[msg("Zero commitment detected - outputs must be non-zero")]
    ZeroCommitment,
}
```

---

## Low

### AUDIT-L01: Relayer Registry Lacks Removal Mechanism

**Severity:** Low  
**Location:** [lib.rs:91-99](programs/privacy-pool/src/lib.rs#L91-L99), [lib.rs:749-757](programs/privacy-pool/src/lib.rs#L749-L757)

**Description:**  
The `add_relayer` function can add relayers to `config.relayers` array but there's no corresponding `remove_relayer` function. Once added, a malicious or compromised relayer remains authorized forever (up to `MAX_RELAYERS = 16` limit). Admin cannot revoke access without redeploying the pool. Combined with the relayer's ability to front-run withdrawals and extract maximum fees, this creates a persistent attack surface if a relayer's private key is compromised.

**Impact:**  
Compromised relayers can remain active indefinitely, enabling long-term fee extraction attacks and griefing of withdrawals.

**Fix:**

```rust
// Add remove_relayer instruction
pub fn remove_relayer(
    ctx: Context<ConfigAdmin>,
    _mint_address: Pubkey,
    relayer_to_remove: Pubkey,
) -> Result<()> {
    let cfg = &mut ctx.accounts.config;

    let n = cfg.num_relayers as usize;
    let mut found_index = None;

    // Find the relayer in the array
    for i in 0..n {
        if cfg.relayers[i] == relayer_to_remove {
            found_index = Some(i);
            break;
        }
    }

    let index = found_index.ok_or(PrivacyError::RelayerNotFound)?;

    // Shift remaining elements left
    for i in index..(n - 1) {
        cfg.relayers[i] = cfg.relayers[i + 1];
    }

    // Clear last element and decrement count
    cfg.relayers[n - 1] = Pubkey::default();
    cfg.num_relayers -= 1;

    Ok(())
}

// Add error
#[error_code]
pub enum PrivacyError {
    // ... existing errors
    #[msg("Relayer not found in registry")]
    RelayerNotFound,
}
```

---

### AUDIT-L02: Tree Capacity Check Uses Subtraction Instead of Overflow-Safe Comparison

**Severity:** Low  
**Location:** [lib.rs:1123-1126](programs/privacy-pool/src/lib.rs#L1123-L1126)

**Description:**  
The capacity check `remaining_capacity = max_capacity.saturating_sub(output_tree.next_index)` uses saturating subtraction, which returns 0 if `next_index >= max_capacity`. While safe, the subsequent check `remaining_capacity >= 2` doesn't distinguish between "tree exactly full" and "tree overflowed" cases. If `next_index` is corrupted to a value greater than `max_capacity` (e.g., by a bug in `MerkleTree::append`), the saturating_sub masks the overflow and returns a misleading error message.

**Impact:**  
Obscured debugging for tree corruption bugs, misleading error messages preventing root cause analysis.

**Fix:**

```rust
// In transact(), replace capacity check at line 1123-1126:
let max_capacity = 1u64 << (output_tree.height as u64);

// Add explicit overflow detection
require!(
    output_tree.next_index <= max_capacity,
    PrivacyError::TreeCorrupted
);

// Then check capacity for 2 new leaves
require!(
    output_tree.next_index <= max_capacity - 2,
    PrivacyError::MerkleTreeFull
);

// Add error
#[error_code]
pub enum PrivacyError {
    // ... existing errors
    #[msg("Merkle tree index corrupted (exceeds capacity)")]
    TreeCorrupted,
}
```

---

### AUDIT-L03: Missing Event Emission for Relayer Addition

**Severity:** Low  
**Location:** [lib.rs:749-757](programs/privacy-pool/src/lib.rs#L749-L757)

**Description:**  
The `add_relayer` instruction modifies the authorized relayer set but doesn't emit an event. Off-chain indexers and monitoring systems cannot track relayer additions without parsing all transactions, making it difficult to detect unauthorized relayer additions if the admin key is compromised.

**Impact:**  
Reduced observability for security monitoring, delayed detection of admin key compromise.

**Fix:**

```rust
// Add event definition
#[event]
pub struct RelayerAdded {
    pub relayer: Pubkey,
    pub mint_address: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct RelayerRemoved {
    pub relayer: Pubkey,
    pub mint_address: Pubkey,
    pub timestamp: i64,
}

// In add_relayer function, emit event before Ok(())
emit!(RelayerAdded {
    relayer: new_relayer,
    mint_address,
    timestamp: Clock::get()?.unix_timestamp,
});
Ok(())
```

---

### AUDIT-L04: Hardcoded AUTHORIZED_ADMIN in Program Code

**Severity:** Low  
**Location:** [lib.rs:17-18](programs/privacy-pool/src/lib.rs#L17-L18)

**Description:**  
The `AUTHORIZED_ADMIN` constant is hardcoded in the program code as `pubkey!("H6QRuiRsguQgpRSJpP79h75EfDYRS2wN78oj7a4auZtP")`. If this admin key is lost or compromised, there's no recovery mechanism. The comment "should be set to your deployment wallet address" suggests this may be intended as a placeholder, but if deployed as-is, the program has a single point of failure for all admin operations (adding relayers, updating config, adding trees).

**Impact:**  
Permanent loss of admin capabilities if key is lost, or complete protocol compromise if key is stolen (attacker can add malicious relayers, modify fee structure).

**Fix:**

```rust
// Option 1: Multi-sig admin using Squads or similar
// Store admin in GlobalConfig as a multi-sig PDA

// Option 2: Timelock admin change with proposal system
#[account]
pub struct AdminProposal {
    pub proposed_admin: Pubkey,
    pub proposer: Pubkey,
    pub proposal_time: i64,
    pub executed: bool,
}

pub fn propose_admin_change(
    ctx: Context<ProposeAdminChange>,
    new_admin: Pubkey,
) -> Result<()> {
    // Current admin proposes new admin
    let proposal = &mut ctx.accounts.proposal;
    proposal.proposed_admin = new_admin;
    proposal.proposer = ctx.accounts.admin.key();
    proposal.proposal_time = Clock::get()?.unix_timestamp;
    proposal.executed = false;
    Ok(())
}

pub fn execute_admin_change(
    ctx: Context<ExecuteAdminChange>,
) -> Result<()> {
    let proposal = &ctx.accounts.proposal;
    let current_time = Clock::get()?.unix_timestamp;

    // Require 48-hour timelock
    require!(
        current_time >= proposal.proposal_time + (48 * 3600),
        PrivacyError::TimelockNotExpired
    );

    // Transfer admin rights
    let config = &mut ctx.accounts.global_config;
    config.admin = proposal.proposed_admin;

    Ok(())
}
```

---

## Summary

**Total Findings:** 14

- **Critical:** 2
- **High:** 4
- **Medium:** 5
- **Low:** 4

### Immediate Action Required (Pre-Mainnet)

1. **AUDIT-C01**: Fix vault rent exemption bypass - prevents complete fund drainage
2. **AUDIT-C02**: Add signer validation for token deposits - prevents token theft via delegation abuse
3. **AUDIT-H01**: Implement tree_id validation for nullifiers - prevents double-spend across trees
4. **AUDIT-H04**: Add domain separation to ExtData hash - prevents proof malleability attacks

### High Priority (Before Public Launch)

5. **AUDIT-H02**: Implement verifying key upgrade mechanism
6. **AUDIT-H03**: Add Poseidon hash validation and atomic tree updates
7. **AUDIT-M02**: Reorder fee validation to prevent rent griefing
8. **AUDIT-M05**: Add zero-output validation

### Recommended Improvements

9. **AUDIT-M01**: Fix tree distribution race condition
10. **AUDIT-M03**: Increase root history size or add timestamp tracking
11. **AUDIT-M04**: Handle i64::MIN edge case
12. **AUDIT-L01-L04**: Implement relayer management, monitoring, and admin security improvements

---

**Auditor Note:** The program demonstrates solid understanding of Solana security patterns (PDA derivation, signer checks, CPI safety) but has critical vulnerabilities in financial logic and cryptographic validation. The identified issues are all fixable without major architectural changes. Priority should be given to Critical and High severity findings before any mainnet deployment.

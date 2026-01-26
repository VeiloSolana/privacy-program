# Private Swaps Architecture

## Overview

Veilo's private swap feature enables users to swap between different tokens (e.g., SOL → USDC) while preserving complete privacy. The swap execution happens atomically in a single transaction, breaking all on-chain links between the user's deposit, swap, and withdrawal.

## Core Design Philosophy

**Privacy through pooling and indirection:**

- Funds never move directly from user wallet to DEX
- Ephemeral executor PDA acts as privacy boundary
- Tokens return to destination pool, not directly to user
- On-chain observers cannot link deposits to swaps to withdrawals

## Architecture: Atomic Single-Transaction Swap

### Why Single Transaction?

| Aspect         | Single Transaction ✅    | Two-Step Approach ❌           |
| -------------- | ------------------------ | ------------------------------ |
| Atomicity      | All-or-nothing execution | Can fail between steps         |
| Relayer Trust  | No trust needed          | Must trust relayer to complete |
| Privacy        | No timing gaps           | Timing correlation risk        |
| UX             | One transaction          | Two transactions               |
| MEV Protection | Built-in                 | Vulnerable between steps       |

### High-Level Flow

```
┌─────────────────────────────────────────────┐
│  Single Atomic Transaction                  │
├─────────────────────────────────────────────┤
│                                              │
│  1. Verify ZK proof                         │
│     ✓ User owns SOL notes                   │
│     ✓ Commit to swap parameters             │
│                                              │
│  2. Burn nullifiers in SOL pool             │
│                                              │
│  3. Create ephemeral executor PDA           │
│     seeds = [b"swap_executor", nullifier]   │
│                                              │
│  4. Transfer: SOL vault → executor PDA      │
│                                              │
│  5. **CPI to Jupiter** (executor signs)     │
│     - Swap SOL → USDC                       │
│     - Slippage protection enforced          │
│                                              │
│  6. Transfer: executor PDA → USDC vault     │
│                                              │
│  7. Insert commitments in USDC pool         │
│                                              │
│  8. Close executor PDA (return rent)        │
│                                              │
│  ✅ All atomic - reverts if any step fails  │
└─────────────────────────────────────────────┘
```

## Detailed Token Movement

### Phase 1: Setup (User has private funds)

```
User owns notes in SOL pool
  ↓
Commitments in SOL Merkle tree
  ↓
Funds in SOL vault (pooled with others)
```

### Phase 2: Swap Execution (Single Transaction)

```
┌─────────────────┐
│   SOL POOL      │
│  privacy_vault  │
│   1000 SOL      │
└────────┬────────┘
         │ Step 1: Withdraw 5 SOL
         │ (burn nullifiers)
         ↓
    ┌─────────┐
    │Executor │
    │   PDA   │ 5 SOL (ephemeral)
    └────┬────┘
         │ Step 2: CPI to Jupiter
         │ (executor signs with PDA seeds)
         ↓
    ┌─────────┐
    │Executor │
    │   PDA   │ 125 USDC (swapped)
    └────┬────┘
         │ Step 3: Deposit to USDC vault
         │ (create new commitments)
         ↓
┌─────────────────┐
│   USDC POOL     │
│  privacy_vault  │  ← Tokens go here
│   5125 USDC     │
└─────────────────┘
```

### Phase 3: User withdraws later (separate transaction)

```
User proves ownership of USDC notes
  ↓
Withdraws to fresh wallet
  ↓
No link to original SOL deposit or swap
```

## Privacy Guarantees

### What is Private ✅

1. **User Identity** - Relayer submits, user never signs
2. **Source of Funds** - Can't link to original deposit
3. **Swap Intent** - Encrypted in ZK proof commitment
4. **Trading History** - Can't correlate multiple swaps
5. **Destination** - Withdrawal to fresh address later

### What is Observable ❌

1. **That Veilo exists** - Public protocol
2. **That a swap happened** - Transaction is on-chain
3. **Token types involved** - SOL → USDC visible
4. **Approximate timing** - Block timestamp public

### What Cannot Be Linked 🔒

- Deposit wallet → Swap transaction
- Swap transaction → Withdrawal wallet
- Multiple swaps by same user
- Amount deposited → Amount swapped
- Source pool → Destination pool intent

## Implementation Components

### 1. Account Structures

**SwapExecutor PDA:**

```rust
#[account]
pub struct SwapExecutor {
    pub source_mint: Pubkey,    // SOL
    pub dest_mint: Pubkey,      // USDC
    pub nullifier: [u8; 32],    // Unique per swap
    pub bump: u8,               // PDA bump
}

// Seeds: [b"swap_executor", nullifier]
// One-time use, never reused
```

**SwapParams (committed in proof):**

```rust
pub struct SwapParams {
    pub min_amount_out: u64,    // Slippage protection
    pub deadline: i64,          // Prevents stale swaps
    pub source_mint: Pubkey,    // Must match pool
    pub dest_mint: Pubkey,      // Must match pool
}
```

### 2. Key Instructions

**`transact_swap`** - Main atomic swap instruction

**Inputs:**

- Source pool proof (owns SOL notes)
- Destination pool commitments (USDC notes to create)
- Swap parameters (min output, deadline, mints)
- Jupiter route data (dynamic accounts)
- ZK proof (proves ownership and commitments)

**Execution:**

1. Verify ZK proof
2. Burn source nullifiers
3. Initialize executor PDA + token accounts
4. Transfer source vault → executor
5. CPI to Jupiter (executor signs)
6. Transfer executor → dest vault
7. Insert dest commitments
8. Close executor accounts

**Atomicity:** All steps succeed or entire transaction reverts

### 3. Jupiter Integration

**Why Jupiter?**

- Aggregates all major DEXes (Raydium, Orca, Whirlpool, etc.)
- Best price routing
- Single CPI interface
- Supports all SPL tokens

**CPI Pattern:**

```rust
let executor_seeds = &[
    b"swap_executor",
    nullifier.as_ref(),
    &[executor_bump]
];

// Executor PDA signs the Jupiter CPI
invoke_signed(
    &jupiter_swap_ix,
    &jupiter_accounts,
    &[executor_seeds]
)?;
```

**Route Accounts:**

- Passed via `remaining_accounts`
- Dynamic based on best route
- Client calculates, program validates

## Supporting All Major Tokens

### Multi-Pool Architecture

Each token has its own pool:

```
privacy_config_v3 [SOL_MINT]   → SOL pool
privacy_config_v3 [USDC_MINT]  → USDC pool
privacy_config_v3 [USDT_MINT]  → USDT pool
privacy_config_v3 [*]          → Any allowed token
```

### Swap Paths

Any token to any token via Jupiter:

```
SOL → USDC
USDC → SOL
SOL → USDT
ORE → USDC
ZEC → stORE
... any combination
```

**Liquidity:** Jupiter finds best route across all DEXes

### Allowed Tokens

**Devnet:**

- USDC, USDT, ORE, ZEC, stORE
- Configurable via `ALLOWED_TOKENS` constant

**Mainnet:**

- Same list with mainnet mint addresses
- Admin can add more via pool initialization

## Security Measures

### 1. Executor PDA Protection

**Deterministic derivation:**

```rust
PDA = derive([b"swap_executor", nullifier, bump])
```

- Unique per swap (bound to nullifier)
- Cannot be hijacked or reused
- Automatically cleaned up after use

### 2. Slippage Protection

```rust
require!(
    actual_output >= swap_params.min_amount_out,
    PrivacyError::SlippageExceeded
);
```

- Enforced on-chain
- Committed in ZK proof
- Transaction reverts if not met

### 3. Deadline Enforcement

```rust
require!(
    clock.unix_timestamp <= swap_params.deadline,
    PrivacyError::SwapDeadlineExceeded
);
```

- Prevents stale swap intents
- User controls expiration
- No execution after deadline

### 4. Nullifier Binding

- Each swap consumes source notes (burns nullifiers)
- Cannot double-spend
- Tree-specific to prevent cross-pool reuse

### 5. Proof Verification

```rust
verify_swap_groth16(proof, &public_inputs)?;
```

- Proves note ownership
- Validates swap commitment
- Ensures amount consistency

## Privacy Attack Mitigations

### Timing Correlation

**Attack:** Link deposit and swap by timestamp

**Mitigation:**

- Encourage users to wait random blocks
- Batch multiple users' swaps together
- Deposit in one session, swap in another

### Amount Correlation

**Attack:** Link by exact amounts (5.0 SOL deposit → 5.0 SOL swap)

**Mitigation:**

- Split notes into non-round amounts
- Use change notes (swap 5.123 SOL, receive 0.123 change)
- Pool liquidity masks individual amounts

### Endpoint Correlation

**Attack:** Link deposit wallet to withdrawal wallet

**Mitigation:**

- User always withdraws to fresh address
- No metadata linking addresses
- Pooling breaks custody chain

### MEV/Front-Running

**Attack:** Front-run swap with better price

**Mitigation:**

- Atomic execution prevents sandwich attacks
- Executor PDA prevents transaction manipulation
- Slippage protection enforced

## Compute Unit Requirements

**Estimated compute units:**

- ZK proof verification: ~150K CU
- Jupiter CPI: ~200K CU
- Merkle operations: ~100K CU
- Transfers + overhead: ~50K CU
- **Total: ~500K CU**

**Solana limits:**

- Base: 200K CU (too low)
- With priority fee: Up to 1.4M CU
- **Recommendation:** Request 600K CU

## Future Enhancements

### Phase 2 Improvements

1. **Multi-hop swaps** - SOL → USDC → USDT in one proof
2. **Batched swaps** - Multiple users in one transaction
3. **Limit orders** - Swap when price reaches target
4. **Partial fills** - Swap only portion of notes

### Phase 3 Advanced Features

1. **Cross-chain swaps** - Via wormhole or other bridges
2. **LP provision** - Private liquidity providing
3. **Private yield** - Stake swapped tokens privately
4. **Social recovery** - Backup note secrets

## Implementation Status

### ✅ Completed

- Account structures (SwapExecutor, SwapParams)
- TransactSwap instruction skeleton
- Validation logic (mints, relayer, deadline)
- Merkle tree operations (insert commitments)
- Event emissions (SwapExecutedEvent)

### 🚧 In Progress

- ZK circuit design for swap proofs
- Token transfer implementation (source → executor → dest)
- Jupiter CPI integration

### 📋 TODO

- Proof verification (verify_swap_groth16)
- Executor account cleanup (close accounts)
- Relayer fee payment
- Comprehensive testing (devnet → mainnet)

## Development Roadmap

### Milestone 1: Core Swap Logic

- [ ] Implement token transfers (vault ↔ executor)
- [ ] Integrate Jupiter CPI
- [ ] Add executor cleanup
- [ ] Unit tests

### Milestone 2: ZK Proof Integration

- [ ] Design swap circuit
- [ ] Generate proving/verification keys
- [ ] Integrate proof verification
- [ ] Circuit tests

### Milestone 3: Integration Testing

- [ ] Deploy to devnet
- [ ] Test with real Jupiter swaps
- [ ] Measure compute units
- [ ] Optimize if needed

### Milestone 4: Production Readiness

- [ ] Security audit
- [ ] Mainnet deployment
- [ ] Documentation
- [ ] SDK integration

## Usage Example (Conceptual)

```typescript
// User side (off-chain)
const user = await VeiloUser.load(secretKey);

// User has 5 SOL notes in Veilo SOL pool
const solNotes = await user.getNotesForToken(SOL_MINT);

// Create swap intent
const swapIntent = {
  inputNotes: solNotes.slice(0, 2), // Use 2 notes
  sourceToken: SOL_MINT,
  destToken: USDC_MINT,
  minAmountOut: 125_000_000, // 125 USDC minimum
  deadline: Date.now() + 3600_000, // 1 hour
};

// Generate proof (proves ownership + swap commitment)
const proof = await generateSwapProof(swapIntent);

// Submit to relayer (user doesn't sign)
const tx = await relayer.submitSwap({
  proof,
  jupiterRoute: await getJupiterRoute(swapIntent),
});

// Wait for confirmation
await tx.confirm();

// User now has USDC notes in Veilo USDC pool
// Can withdraw to fresh wallet later
```

## Conclusion

Veilo's atomic private swap architecture provides:

- ✅ Strong privacy guarantees
- ✅ Support for all major tokens (via Jupiter)
- ✅ Atomic execution (no trust needed)
- ✅ Slippage and deadline protection
- ✅ MEV resistance
- ✅ Efficient compute usage

By combining UTXO-based privacy pools, ZK proofs, and Jupiter's aggregated liquidity, users can swap any token to any other token while maintaining complete anonymity.

---

**For more details:**

- Implementation: See `programs/privacy-pool/src/swap.rs`
- Main protocol: See `programs/privacy-pool/src/lib.rs`
- Security checklist: See `docs/SECURITY_CHECKLIST.md`

# Veilo Privacy Protocol - Build Plan

This document outlines the roadmap to upgrade the Veilo privacy protocol. The goal is to achieve feature parity with state-of-the-art privacy mixers while introducing improvements for better decentralization and flexibility.

## 🚨 Phase 1: Critical Security & Core Architecture

_These items address immediate security vulnerabilities and fundamental design limitations._

### 1. PDA-Based Nullifier System (Anti-Double-Spend)

**Priority:** Critical

- **Current State:** Uses a single `NullifierSet` account that only tracks the _last_ spent note. Vulnerable to double-spending.
- **Target State:** Use Solana's account model to enforce uniqueness.
- **Implementation:**
  - Remove `NullifierSet`.
  - Update `transact` instruction to initialize a new PDA for every spent nullifier.
  - `seeds = [b"nullifier", nullifier_hash]`.
  - If the account already exists, the transaction fails automatically.

### 2. UTXO Model (Arbitrary Amounts)

**Priority:** High

- **Current State:** Fixed denominations (e.g., 1 SOL, 10 SOL). Users cannot split notes or withdraw partial amounts.
- **Target State:** 2-Input / 2-Output UTXO model.
- **Implementation:**
  - Update ZK circuit to prove `Input1 + Input2 + PublicAmount = Output1 + Output2`.
  - Update `transact` to accept 2 input nullifiers and 2 output commitments.
  - Remove `denom_index` and replace with `public_amount` (signed integer).

### 3. External Data Verification (Integrity)

**Priority:** High

- **Current State:** Transaction parameters (recipient, fee) are passed directly. Relayers could potentially tamper with them if not bound to the proof.
- **Target State:** Bind all transaction metadata to the ZK proof.
- **Implementation:**
  - Create `ExtData` struct (recipient, fee, relayer, etc.).
  - Hash `ExtData` on-chain.
  - Verify `Hash(ExtData) == Proof.public_signal`.

---

## 🚀 Phase 2: "Better Than Theirs" (Differentiation)

_Features that make Veilo superior to the reference implementation._

### 4. Permissionless SPL Token Support

**Priority:** Medium

- **Reference Implementation:** Uses a hardcoded whitelist of allowed tokens (USDC, USDT). Centralized.
- **Veilo Target:** **Permissionless Pools.**
- **Implementation:**
  - Allow `initialize_pool` to accept _any_ SPL Mint address.
  - Create a unique Merkle Tree PDA for each Mint: `seeds = [b"merkle_tree", mint_address]`.
  - No whitelist. Anyone can create a privacy pool for any token (like Uniswap).

### 5. Encrypted Note Events (Data Availability)

**Priority:** Medium

- **Current State:** No events emitted. Users must store note data locally.
- **Target State:** On-chain data availability.
- **Implementation:**
  - Define `#[event]` structs for `Deposit` and `Withdraw`.
  - Emit encrypted note data (ciphertext) in the logs.
  - Allows users to recover their funds by scanning the blockchain with their private key.

---

## ⚖️ Phase 3: Economics & Governance

_Fine-tuning the protocol for production._

### 6. Configurable Economics

**Priority:** Low

- **Current State:** Fixed fee hardcoded.
- **Target State:** Dynamic fee adjustment.
- **Implementation:**
  - Add `GlobalConfig` account.
  - Store `fee_basis_points` and `max_deposit_limit`.
  - Add admin instructions to update these values without redeploying.

### 7. Relayer Incentives

**Priority:** Low

- **Current State:** Permissioned relayer list.
- **Target State:** Open relayer market.
- **Implementation:**
  - Allow users to specify `fee_recipient` in `ExtData`.
  - Any signer can relay a transaction and claim the fee.

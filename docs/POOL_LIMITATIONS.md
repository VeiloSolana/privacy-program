# Pool Interaction Limitations & Edge Cases

This document provides a comprehensive overview of all constraints, limitations, and edge cases for interacting with Veilo privacy pools.

---

## Table of Contents

1. [Deposit Constraints](#1-deposit-constraints)
2. [Withdrawal Constraints](#2-withdrawal-constraints)
3. [Private Transfer Constraints](#3-private-transfer-constraints)
4. [Nullifier Constraints](#4-nullifier-constraints)
5. [Commitment Constraints](#5-commitment-constraints)
6. [Merkle Tree Constraints](#6-merkle-tree-constraints)
7. [Relayer Constraints](#7-relayer-constraints)
8. [ZK Proof Constraints](#8-zk-proof-constraints)
9. [Token Account Constraints](#9-token-account-constraints)
10. [Swap Constraints (Jupiter Integration)](#10-swap-constraints-jupiter-integration)
11. [Global Constraints](#11-global-constraints)
12. [Fee Configuration Limits](#12-fee-configuration-limits)
13. [Summary Tables](#13-summary-tables)

---

## 1. Deposit Constraints

### Limits by Token

| Token | Min Deposit | Max Deposit     |
| ----- | ----------- | --------------- |
| SOL   | 0.01 SOL    | 1,000 SOL       |
| USDT  | 1 USDT      | 100,000 USDT    |
| USDC  | 1 USDC      | 100,000 USDC    |
| USD1  | 1 USD1      | 100,000 USD1    |
| JUP   | 10 JUP      | 100,000,000 JUP |

### Edge Cases & Errors

| Error                           | Cause                                                                         |
| ------------------------------- | ----------------------------------------------------------------------------- |
| `DepositBelowMinimum`           | Deposit amount is below pool minimum                                          |
| `DepositLimitExceeded`          | Deposit amount exceeds pool maximum                                           |
| `InvalidNullifiersForDeposit`   | Deposits MUST have zero nullifiers (no notes consumed)                        |
| `InvalidPrivateTransferFee`     | Deposits must have `fee == 0` and `refund == 0`                               |
| `InsufficientDelegation`        | For SPL tokens, relayer needs sufficient delegation from user's token account |
| `DepositorTokenAccountMismatch` | Token account not owned/delegated to relayer                                  |

---

## 2. Withdrawal Constraints

### Limits by Token

| Token | Min Withdrawal | Max Withdrawal | Min Fee     | Fee % |
| ----- | -------------- | -------------- | ----------- | ----- |
| SOL   | 0.01 SOL       | 1,000 SOL      | 0.00005 SOL | 0.5%  |
| USDT  | 1 USDT         | 50,000 USDT    | 0.005 USDT  | 0.5%  |
| USDC  | 1 USDC         | 50,000 USDC    | 0.005 USDC  | 0.5%  |
| USD1  | 1 USD1         | 50,000 USD1    | 0.005 USD1  | 0.5%  |
| JUP   | 10 JUP         | 50,000,000 JUP | 0.05 JUP    | 0.5%  |

### Fee Calculation

```
max_fee = withdrawal_amount * fee_bps / 10000
max_fee_with_margin = max_fee * (1 + fee_error_margin_bps / 10000)

Valid fee range: [min_withdrawal_fee, max_fee_with_margin]
```

### Edge Cases & Errors

| Error                            | Cause                                                                   |
| -------------------------------- | ----------------------------------------------------------------------- |
| `WithdrawalBelowMinimum`         | Withdrawal amount is below pool minimum                                 |
| `WithdrawalLimitExceeded`        | Withdrawal amount exceeds pool maximum                                  |
| `WithdrawalTooSmallForMinFee`    | Withdrawal where `max_fee < min_withdrawal_fee` (prevents fee evasion)  |
| `InvalidFeeAmount`               | Fee not in valid range `[min_fee, max_fee * 1.05]`                      |
| `InsufficientFundsForWithdrawal` | Vault doesn't have enough balance (plus rent + 0.01 SOL buffer for SOL) |
| `ZeroNullifier`                  | Withdrawals MUST have non-zero nullifiers (notes being consumed)        |
| `ExcessiveFee`                   | Fee exceeds maximum allowed                                             |
| `InsufficientFee`                | Fee below minimum required                                              |

---

## 3. Private Transfer Constraints

Private transfers occur when `public_amount == 0` (no funds cross the pool boundary).

### Rules

- No on-chain fund movement occurs
- Only nullifiers are consumed and new commitments are created
- Must have `fee == 0` and `refund == 0`

### Edge Cases & Errors

| Error                       | Cause                                       |
| --------------------------- | ------------------------------------------- |
| `InvalidPrivateTransferFee` | Private transfer has non-zero fee or refund |

---

## 4. Nullifier Constraints

Nullifiers are used to prevent double-spending of notes.

### Rules

- Each nullifier can only be spent once globally
- Nullifiers are tied to specific tree IDs
- Deposits must use zero nullifiers
- Withdrawals/transfers must use non-zero nullifiers

### Edge Cases & Errors

| Error                              | Cause                                                              |
| ---------------------------------- | ------------------------------------------------------------------ |
| `NullifierAlreadyUsed`             | Nullifier has already been spent (double-spend attempt)            |
| `DuplicateNullifiers`              | Same nullifier used twice in one transaction                       |
| `NullifierTableFull`               | Nullifier storage capacity exceeded                                |
| `ZeroNullifier`                    | Nullifier cannot be zero for withdrawals/transfers                 |
| `InvalidNullifierMarkerForDeposit` | Nullifier marker doesn't correspond to zero nullifier for deposits |

**Note:** Nullifier markers are global per-mint (no tree_id in PDA seeds) to prevent cross-tree double-spend attacks.

---

## 5. Commitment Constraints

Commitments represent new notes being created.

### Rules

- Output commitments must be unique within a transaction
- Commitments cannot be zero

### Edge Cases & Errors

| Error                  | Cause                                                |
| ---------------------- | ---------------------------------------------------- |
| `DuplicateCommitments` | Same output commitment used twice in one transaction |
| `ZeroCommitment`       | Output commitment cannot be zero                     |

---

## 6. Merkle Tree Constraints

### Capacity

| Parameter            | Value                            |
| -------------------- | -------------------------------- |
| Tree Height          | 22 levels                        |
| Notes per Tree       | ~4,194,304 (2²²)                 |
| Max Trees per Pool   | 10,000                           |
| Total Notes per Pool | ~42 billion                      |
| Root History Size    | Recent roots kept for validation |

### Edge Cases & Errors

| Error              | Cause                                             |
| ------------------ | ------------------------------------------------- |
| `MerkleTreeFull`   | Tree has 2²² leaves, must use different `tree_id` |
| `InvalidTreeId`    | `tree_id` doesn't exist or exceeds `num_trees`    |
| `UnknownRoot`      | Provided root not found in recent root history    |
| `TooManyTrees`     | Cannot exceed 10,000 trees per pool               |
| `MerkleHashFailed` | Poseidon hash computation failed                  |

---

## 7. Relayer Constraints

### Limits

| Parameter             | Value |
| --------------------- | ----- |
| Max Relayers per Pool | 16    |

### Edge Cases & Errors

| Error                         | Cause                                           |
| ----------------------------- | ----------------------------------------------- |
| `RelayerNotAllowed`           | Relayer not registered for this pool            |
| `RelayerMismatch`             | Relayer signer doesn't match `ext_data.relayer` |
| `RelayerTokenAccountMismatch` | Relayer token account not owned by the relayer  |
| `TooManyRelayers`             | Cannot exceed 16 relayers per pool              |

---

## 8. ZK Proof Constraints

### Requirements

- Groth16 proof with correct public inputs
- `ext_data_hash` must match the hash committed in the proof
- Proof must verify against the on-chain verification key

### Edge Cases & Errors

| Error            | Cause                                        |
| ---------------- | -------------------------------------------- |
| `InvalidProof`   | Malformed proof data or encoding             |
| `VerifyFailed`   | Groth16 verification failed                  |
| `InvalidExtData` | `ext_data_hash` doesn't match committed hash |

---

## 9. Token Account Constraints

### SPL Token Requirements

- Valid token accounts for vault, recipient, relayer, and depositor
- Token Program account must be provided
- Vault must use canonical Associated Token Account (ATA)

### Edge Cases & Errors

| Error                           | Cause                                                      |
| ------------------------------- | ---------------------------------------------------------- |
| `MissingTokenAccount`           | SPL token operation missing required token account         |
| `MissingTokenProgram`           | Token Program account not provided                         |
| `InvalidTokenAuthority`         | Token account authority mismatch                           |
| `RecipientTokenAccountMismatch` | Recipient token account doesn't match `ext_data.recipient` |
| `VaultTokenAccountNotATA`       | Vault not using canonical ATA                              |
| `InvalidTokenAccountOwner`      | Token account not owned by SPL Token Program               |

---

## 10. Swap Constraints (Jupiter Integration)

### Supported Programs

- **Raydium CPMM**: `CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C`
- **Raydium AMM V4**: `675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8`
- **Jupiter Aggregator V6**: `JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4`

### Swap Fees

| Token          | Min Swap Fee | Swap Fee % |
| -------------- | ------------ | ---------- |
| SOL            | 0.00005 SOL  | 0.5%       |
| USDT/USDC/USD1 | 0.005 token  | 0.5%       |
| JUP            | 0.05 JUP     | 0.5%       |

### Edge Cases & Errors

| Error                         | Cause                                     |
| ----------------------------- | ----------------------------------------- |
| `InvalidSwapProgram`          | Swap program not Raydium CPMM or AMM      |
| `JupiterInsufficientAccounts` | Jupiter routing missing required accounts |
| `JupiterInvalidInstruction`   | Unsupported Jupiter instruction format    |
| `InvalidRemainingAccounts`    | Wrong count or ownership of swap accounts |
| `ExecutorNotStale`            | Executor PDA exists and hasn't expired    |

---

## 11. Global Constraints

### Admin Controls

| Parameter                  | Value                                          |
| -------------------------- | ---------------------------------------------- |
| Authorized Admin (Mainnet) | `H6QRuiRsguQgpRSJpP79h75EfDYRS2wN78oj7a4auZtP` |

### Edge Cases & Errors

| Error                | Cause                                                |
| -------------------- | ---------------------------------------------------- |
| `Paused`             | Pool has been paused by admin                        |
| `UnauthorizedAdmin`  | Caller is not the authorized admin                   |
| `Unauthorized`       | Only admin or relayers can perform this action       |
| `RecipientMismatch`  | Recipient account doesn't match `ext_data.recipient` |
| `InvalidMintAddress` | Token mint doesn't match pool configuration          |
| `ArithmeticOverflow` | Integer overflow in calculations                     |

---

## 12. Fee Configuration Limits

| Setting                | Max Value  | Description                                           |
| ---------------------- | ---------- | ----------------------------------------------------- |
| `fee_bps`              | 100 (1%)   | Maximum withdrawal fee percentage                     |
| `fee_error_margin_bps` | 5000 (50%) | Maximum fee error margin for timing attack protection |
| `swap_fee_bps`         | 100 (1%)   | Maximum swap fee percentage                           |

### Edge Cases & Errors

| Error                    | Cause                                         |
| ------------------------ | --------------------------------------------- |
| `ExcessiveFeeBps`        | Fee basis points exceeds maximum (100 = 1%)   |
| `ExcessiveFeeMargin`     | Fee error margin exceeds maximum (5000 = 50%) |
| `InvalidPoolConfigRange` | Min value greater than max value              |

---

## 13. Summary Tables

### User Interaction Limits

| Operation          | SOL                    | USDT/USDC/USD1         | JUP                 |
| ------------------ | ---------------------- | ---------------------- | ------------------- |
| **Min Deposit**    | 0.01 SOL               | 1 token                | 10 JUP              |
| **Max Deposit**    | 1,000 SOL              | 100,000 tokens         | 100M JUP            |
| **Min Withdrawal** | 0.01 SOL               | 1 token                | 10 JUP              |
| **Max Withdrawal** | 1,000 SOL              | 50,000 tokens          | 50M JUP             |
| **Withdrawal Fee** | 0.5% (min 0.00005 SOL) | 0.5% (min 0.005 token) | 0.5% (min 0.05 JUP) |
| **Swap Fee**       | 0.5% (min 0.00005 SOL) | 0.5% (min 0.005 token) | 0.5% (min 0.05 JUP) |

### Pool Capacity

| Parameter             | Value        |
| --------------------- | ------------ |
| Notes per Tree        | ~4.2 million |
| Max Trees per Pool    | 10,000       |
| Max Relayers per Pool | 16           |
| Root History Size     | Configurable |

### Complete Error Reference

| Error Code                         | Description                          |
| ---------------------------------- | ------------------------------------ |
| `Paused`                           | Pool is paused                       |
| `NoDenoms`                         | No denominations configured          |
| `TooManyDenoms`                    | Too many denominations               |
| `BadDenomIndex`                    | Bad denomination index               |
| `MathOverflow`                     | Math overflow                        |
| `NullifierAlreadyUsed`             | Nullifier already used               |
| `NullifierTableFull`               | Nullifier table is full              |
| `UnknownRoot`                      | Unknown root                         |
| `RelayerNotAllowed`                | Relayer not allowed                  |
| `InsufficientVaultBalance`         | Vault balance too low                |
| `TooManyRelayers`                  | Too many relayers                    |
| `InvalidProof`                     | Invalid proof encoding               |
| `VerifyFailed`                     | Groth16 verification failed          |
| `MerkleTreeFull`                   | Merkle tree is full                  |
| `MerkleHashFailed`                 | Merkle hash failed                   |
| `InvalidExtData`                   | Invalid external data hash           |
| `RecipientMismatch`                | Recipient mismatch                   |
| `InvalidMintAddress`               | Invalid mint address                 |
| `ExcessiveFee`                     | Excessive fee                        |
| `InsufficientFee`                  | Fee below minimum                    |
| `ArithmeticOverflow`               | Arithmetic overflow/underflow        |
| `InsufficientFundsForWithdrawal`   | Insufficient funds for withdrawal    |
| `InsufficientFundsForFee`          | Insufficient funds for fee           |
| `InvalidPublicAmount`              | Invalid public amount data           |
| `InvalidFeeAmount`                 | Invalid fee amount                   |
| `DuplicateNullifiers`              | Duplicate nullifiers detected        |
| `DuplicateCommitments`             | Duplicate output commitments         |
| `MissingTokenAccount`              | Token account required               |
| `MissingTokenProgram`              | Token program required               |
| `InvalidTokenAuthority`            | Invalid token account authority      |
| `RelayerMismatch`                  | Relayer account mismatch             |
| `RelayerTokenAccountMismatch`      | Relayer token account mismatch       |
| `RecipientTokenAccountMismatch`    | Recipient token account mismatch     |
| `DepositorTokenAccountMismatch`    | Depositor token account mismatch     |
| `InvalidPrivateTransferFee`        | Invalid private transfer fee         |
| `DepositBelowMinimum`              | Deposit below minimum                |
| `DepositLimitExceeded`             | Deposit limit exceeded               |
| `WithdrawalBelowMinimum`           | Withdrawal below minimum             |
| `WithdrawalLimitExceeded`          | Withdrawal limit exceeded            |
| `InvalidPoolConfigRange`           | Invalid pool config range            |
| `ExcessiveFeeBps`                  | Excessive fee bps                    |
| `ExcessiveFeeMargin`               | Excessive fee margin                 |
| `UnauthorizedAdmin`                | Unauthorized admin                   |
| `Unauthorized`                     | Unauthorized action                  |
| `InvalidTreeId`                    | Invalid tree_id                      |
| `TooManyTrees`                     | Too many trees                       |
| `InvalidNullifiersForDeposit`      | Invalid nullifiers for deposit       |
| `ZeroNullifier`                    | Zero nullifier not allowed           |
| `ZeroCommitment`                   | Zero commitment not allowed          |
| `InvalidTokenAccountOwner`         | Invalid token account owner          |
| `VaultTokenAccountNotATA`          | Vault token account not ATA          |
| `WithdrawalTooSmallForMinFee`      | Withdrawal too small for min fee     |
| `InvalidNullifierMarkerForDeposit` | Invalid nullifier marker for deposit |
| `InsufficientDelegation`           | Insufficient delegation              |
| `InvalidSwapProgram`               | Invalid swap program                 |
| `ExecutorNotStale`                 | Executor not stale                   |
| `InvalidRemainingAccounts`         | Invalid remaining accounts           |
| `JupiterInsufficientAccounts`      | Jupiter insufficient accounts        |
| `JupiterInvalidInstruction`        | Jupiter invalid instruction          |

---

_Last updated: February 2026_

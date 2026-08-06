# Veilo Audit Context

This file exists to reduce false positives in AI-assisted and human reviews. It
does not waive findings, suppress known issues, or override the source code. If
this file and the code disagree, treat the code and verified on-chain state as
the source of truth and report the discrepancy.

## Current State (update on every deploy)

- Reviewed source commit: `e1b3bd0`
- Deployed slot / ELF sha256: `432860998` / `048add2c2d817a044bbbafd2547c7533d8883310f3dcdd8f1fded8fa248f6efb`
- Known historical fund-loss bug classes, all fixed and verified live:
  non-canonical field elements used as PDA seeds; reissue paths not burning input nullifiers;
  native pre-fund debits not bound to the paired proof-verified amount; operations on a user's
  executor lacking claimant co-signature.
- Open scoping gaps: circuits not in repo; no reproducible build; historical incident review
  not performed.

## What This Repository Contains

Veilo is an Anchor/Solana program named `privacy_pool`.

- Main program ID: `GYy4kM6GHhpgLCUscuABbzkD2ZbJ2fneYryaZ6Ch7fFU`
- Devnet program ID: `HL8wNTnaVqNEkEetPa2eFgyiJVh9iBXeuD4k1pbdfVZa`
- Anchor version: `0.32.1`
- Solana version: `2.3.0`
- On-chain source: `programs/privacy-pool/src/`
- Tracked tests: `tests/*.test.ts`

The tracked on-chain surfaces include:

- Core privacy pool deposits, withdrawals, and private transfers.
- Merkle tree commitment storage and nullifier-marker double-spend protection.
- Groth16 verification for the transaction and swap circuits.
- Swap paths through Raydium and Jupiter.
- Position-pool flows through Jupiter routes.
- Phoenix Eternal integration flows.
- Jupiter Perps and prediction-market integration flows.

## What Is NOT In This Repository (read before scoping a review)

The Circom circuits, R1CS, proving keys, witness generators, and trusted-setup transcript are
**not** tracked here. No `.circom`, `.r1cs`, `.zkey`, or `.wasm` exists in the tree.

This is load-bearing. The on-chain program *trusts* the circuit to enforce value conservation:

- `sumIns + publicAmount = sumOuts`
- a note's committed value equals the `swap_amount` / `dest_amount` public inputs

A flawed circuit or an unsound trusted setup therefore breaks pool solvency in a way that is
**invisible to any on-chain-only review**. Findings that depend on value conservation cannot be
cleared from this repository alone. Reviewers should label each finding as either an
*unconditional on-chain flaw* or *contingent on circuit soundness*, and should request the circuit
artifacts and ceremony transcript separately.

Also out of scope here: the off-chain proving SDK, relayer infrastructure, and key custody.

## Build And Deployment Assumptions

Use the versions pinned in `Anchor.toml` when reproducing builds or tests. The
Cargo release profile has `overflow-checks = true`.

The `custom-heap` feature is expected for deployed builds. It selects the
program's custom allocator so high-memory instructions can use a 256 KB heap
frame when the client prepends the matching compute-budget instruction. Missing
the heap-frame instruction should be treated as a transaction construction or
liveness failure unless a reviewer can show a fund-safety impact.

The Cargo feature named `zk-verify` is a compatibility stub. It is documented in
`programs/privacy-pool/Cargo.toml` as deprecated and must not be interpreted as a
switch that disables proof verification.

Local package scripts are convenience entry points, not proof of current mainnet
authority. For mainnet authority and bytecode claims, verify on-chain state with
`solana program show` and compare executable hashes. Do not infer mainnet control
from the presence of local keypair filenames.

### Verified deployed state (2026-07-30)

| Item | Value |
|---|---|
| ProgramData account | `T1arFasFzpCgUxCkzWquUwGKwDwrMgygTW8x6PF2bo3` |
| Last deploy slot | `432860998` |
| Upgrade authority | `cu82g8m9evMKYFyedsrfr789bz5kgKpqyssNwKfjayR` (Squads v4 3-of-4) |
| sha256 of on-chain ELF | `048add2c2d817a044bbbafd2547c7533d8883310f3dcdd8f1fded8fa248f6efb` |
| ELF length | 1,808,464 B (includes 10,255 B trailing zero padding) |
| sha256, padding stripped | `7e4b0a59f6621bd2061c3ad933624393d0b694e25b90824818bd763d4a213c0e` |

```bash
solana program dump GYy4kM6GHhpgLCUscuABbzkD2ZbJ2fneYryaZ6Ch7fFU /tmp/deployed.so
shasum -a 256 /tmp/deployed.so
```

A full reproducible build under Anchor 0.32.1 / Solana 2.3.0 has still **not** been performed, so
"commit X is byte-identical to the deployed binary" remains unproven. Two cheaper techniques do
establish commit lineage, and were used on 2026-07-30 to confirm every historical fix is live:

1. **Embedded error strings.** `#[msg("...")]` literals are compiled into the ELF. Diff them across
   candidate commits and `grep -a` the dump. Example: `"Field element is not in canonical form
   (>= BN254 Fr)"` exists only at/after the field-canonicity fix, and is present on-chain.
2. **`simulateTransaction` probes** (`sigVerify:false`, `replaceRecentBlockhash:true` — nothing is
   signed, submitted, or moved). Anchor deserializes instruction *arguments* before validating
   accounts, so argument-shape probes need no real accounts. Account-ordering probes reveal whether
   a signer field was added: supplying N accounts and reading which account name Anchor blames in
   the `AccountNotSigner` error pins the field order of the deployed context.

## Source Scope And Ignored Local Files

The repository intentionally ignores operational, generated, and local-private
paths such as:

- `.env`
- `keys/`
- `deployments/`
- `docs/`
- `docss/`
- `zk/`
- `circuits/`
- `scripts/`
- `tools/`
- `test-accounts/`
- `test-logs/`

If these paths exist in a local workspace, do not assume they are part of the
audited Git repository. Confirm with:

```bash
git ls-files <path>
git check-ignore -v <path>
```

If real secret material is ever tracked by Git, report it as a security issue.
If secret material exists only in ignored local files, treat it as an operations
and custody item and avoid copying it into audit logs.

## Security Invariants To Verify

The following are intended invariants. Auditors should verify the referenced
behavior in code rather than relying on this file alone.

- Groth16 public inputs bind the Merkle root, public amount, external-data hash,
  mint, input nullifiers, and output commitments.
- `ExtData::hash()` binds recipient, relayer, fee, refund, and claimant, so a
  relayer cannot substitute those values without invalidating the proof.
- Nullifier markers are global per mint, within one of **two disjoint namespaces**. Their PDA
  seeds include the mint and nullifier, not a tree ID, to prevent cross-tree double spends within
  a namespace. A nullifier burned in one namespace does **not** block the other:

  | Namespace | Seeds | Used by |
  |---|---|---|
  | `nullifier_v3` | `[seed, mint, nullifier]` | core pool, phoenix, jperp, prediction/ephemeral |
  | `position_nullifier_v1` | `[seed, mint, nullifier]` | position pool (`open/close/merge_positions`) |
- All `transact` paths require **non-zero, distinct** input nullifiers, including deposits.
  Deposit-shaped proofs (`public_amount > 0`) use dummy witnesses that produce non-zero Poseidon
  outputs; they are not zero and must not be assumed inert. Any handler running a deposit-shaped
  proof must still check `is_spent` and mark both nullifiers spent — reissue/recover paths
  previously did not, which allowed unbounded note inflation.
- Output commitments must be non-zero and unique within the transaction.
- Merkle roots must be present in the recent root history of the input tree.
- SPL vault accounts are expected to be canonical ATAs for the configured mint.
- Native SOL pools store `Pubkey::default()` as the pool mint and use WSOL only
  where token-program operations require an SPL mint.
- Relayers are whitelisted per pool. They are trusted for submission and liveness,
  not for custody of private notes.
- Admin operations are constrained by the global and pool config accounts.
- External CPI integrations must be reviewed per handler. `UncheckedAccount` and
  `remaining_accounts` are intentional in these paths, but each use must still
  be checked for program-ID, signer, ATA, PDA, amount, and proof-binding
  constraints.

## Known Review Notes

- `SwapParams::swap_data_hash` is a runtime consistency check for Jupiter swap
  data in the current source. It is compared with `sha256(swap_data)` before CPI,
  but the current swap circuit/VK do not include it in `swap_params_hash`.
  Reviewers should not describe it as proof-bound until the circuit, verifier
  constants, and client proof generation are upgraded together.

## Trust And Privacy Boundaries

Veilo aims to break the on-chain link between deposits and later withdrawals or
reissues. It does not provide:

- Network-level privacy.
- Protection from a compromised wallet, browser, relayer client, or note store.
- Amount hiding for flows where public amounts are visible by design.
- Correctness guarantees for external protocols such as Raydium, Jupiter,
  Phoenix Eternal, or Jupiter Perps beyond the checks performed by this program.
- Relayer-free liveness for flows that intentionally require a whitelisted
  relayer.

Users must protect note secrets and claimant keys. Losing the note or claimant
material can make funds unrecoverable even if the on-chain program is correct.

## Common False Positives To Check Carefully

This list explains patterns that are *intentional*. It is not a list of things that cannot be
bugs. If a specific code path violates a stated invariant, report it — the pattern being
intentional elsewhere is not a defense.

- "Proof verification can be disabled by `zk-verify`": check the source. The
  feature is a compatibility stub and is not intended to disable verification.
- "Nullifiers can be reused across trees": check the nullifier PDA seeds. They
  are mint-scoped and intentionally omit tree ID.
- "Local keypairs prove leaked mainnet authority": verify whether the files are
  tracked, then verify current authority on-chain. Ignored local files are not by
  themselves repository leaks.
- "Every `UncheckedAccount` is an arbitrary-account vulnerability": inspect the
  account constraints and handler checks. Some unchecked accounts are required
  for CPI routing, but missing validation is still reportable.
- "Default localnet features are the mainnet build": reproduce the intended
  mainnet build configuration and verify the on-chain executable hash.
- "A missing compute-budget heap frame is fund theft": first show whether the
  transaction can do more than fail. Heavy instructions require clients to
  request the expected heap frame.

## Findings Still Matter

Report any issue that is supported by code behavior, reproducible tests, or
verified on-chain state. This file is audit context, not a defense against real
bugs.

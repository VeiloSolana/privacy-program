# Veilo

A zero-knowledge privacy protocol on Solana.

Deposit SOL or SPL tokens and withdraw to any address with no on-chain link between the two. Commitments are stored in an on-chain Merkle tree; withdrawals are verified via Groth16 proofs. A relayer network enables gas-less withdrawals for enhanced unlinkability.

---

### Features

- Groth16 ZK-SNARK verification on-chain
- Merkle tree commitment scheme (deposit anonymity set)
- PDA-based nullifiers — double-spend protection
- Native SOL and SPL token support
- Relayer network — decouple withdrawer from depositor
- `ExtData::hash()` binds recipient, relayer, fee, and claimant into the proof — prevents front-running

---

### Requirements

- Rust `>=1.70`
- Solana CLI `>=2.2`
- Anchor `>=0.32.1`
- Node.js `>=18`

### Build

```bash
npm install
anchor build
```

### Test

```bash
anchor test
```

---

### Security

Veilo breaks the on-chain link between deposits and withdrawals. It does not protect against network-level surveillance or a compromised client. Notes must be stored securely — losing a note means losing access to the funds.

---

### License

MIT — see [LICENSE](./LICENSE).

> This software is provided as-is. Use at your own risk. Always audit before using in production.

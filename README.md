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
- `ExtData::hash()` binds recipient, relayer, fee, refund, and claimant into the proof — a relayer
  cannot substitute those fields without invalidating it
- Jupiter route bytes are **not** proof-bound; swap outcomes are bounded by the proof-bound
  `min_amount_out` and `dest_amount` checks, not by the route itself (see AUDIT.md)

> Note: the Circom circuits and proving artifacts are maintained separately and are not in this
> repository. See [AUDIT.md](./AUDIT.md) for what that means for review scope.

---

### Requirements

- Rust `>=1.70`
- Solana CLI `>=2.3.0`
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

The program is deployed under the upgradeable BPF loader and **is mutable**. The upgrade authority
is a Squads v4 3-of-4 multisig vault (`cu82g8m9evMKYFyedsrfr789bz5kgKpqyssNwKfjayR`) with no
timelock. Upgrade authority can change program behavior affecting deposited funds.

For third-party review context, see [AUDIT.md](./AUDIT.md). For security reporting and scope, see [SECURITY.md](./SECURITY.md).

---

### License

MIT — see [LICENSE](./LICENSE).

> This software is provided as-is. Use at your own risk. Always audit before using in production.

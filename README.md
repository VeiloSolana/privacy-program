# Veilo Privacy Protocol

<div align="center">

**A Zero-Knowledge Privacy Layer for Solana**

[![Anchor](https://img.shields.io/badge/Anchor-0.32.1-blue)](https://www.anchor-lang.com/)
[![Solana](https://img.shields.io/badge/Solana-2.2.0-blueviolet)](https://solana.com/)
[![License](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

_Break the chain, maintain your privacy._

</div>

---

## 📖 Overview

Veilo is a privacy-preserving protocol built on Solana that enables private transactions through zero-knowledge proofs. Using Groth16 proof systems and Merkle trees, Veilo allows users to deposit, store, and withdraw SOL and SPL tokens without revealing transaction histories or linking deposits to withdrawals.

### Key Features

- 🔒 **Zero-Knowledge Privacy**: Deposit and withdraw without revealing the connection
- 🌳 **Merkle Tree Commitments**: Efficient proof-of-inclusion using on-chain Merkle trees
- 🔐 **Groth16 Proofs**: Cryptographically secure ZK-SNARK verification on Solana
- 💰 **Multi-Token Support**: Native SOL and SPL token compatibility
- 🚀 **Relayer Network**: Enable gas-less withdrawals for enhanced anonymity
- ⚡ **PDA-Based Nullifiers**: Double-spend protection using Solana's account model
- 🔄 **UTXO Model** _(Roadmap)_: Arbitrary amounts with multi-input/output transactions

---

## 🏗️ Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────┐
│                    Veilo Protocol                        │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  ┌──────────────┐    ┌──────────────┐    ┌───────────┐ │
│  │  Privacy     │    │   Merkle     │    │    ZK     │ │
│  │   Config     │───▶│    Tree      │◀───│  Verifier │ │
│  └──────────────┘    └──────────────┘    └───────────┘ │
│         │                    │                   │      │
│         ▼                    ▼                   ▼      │
│  ┌──────────────┐    ┌──────────────┐    ┌───────────┐ │
│  │    Vault     │    │  Nullifier   │    │  Relayer  │ │
│  │   (PDA)      │    │    PDAs      │    │  Registry │ │
│  └──────────────┘    └──────────────┘    └───────────┘ │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

### How It Works

1. **Deposit**: User creates a commitment (hash of secrets) and deposits funds
2. **Privacy Set**: Commitment added to on-chain Merkle tree with other deposits
3. **Withdrawal**: User generates ZK proof knowing secrets without revealing which deposit
4. **Verification**: On-chain program verifies proof and releases funds to recipient

---

## 🚀 Getting Started

### Prerequisites

- **Rust**: `>=1.70.0`
- **Solana CLI**: `>=2.2.0`
- **Anchor**: `>=0.32.1`
- **Node.js**: `>=18.0.0`
- **SnarkJS**: For ZK proof generation

### Installation

```bash
# Clone the repository
git clone https://github.com/VeiloSolana/privacy-program.git
cd privacy-program

# Install dependencies
npm install

# Install Rust dependencies
cargo build

# Build the Anchor program
anchor build
```

### Configuration

Update the cluster in [`Anchor.toml`](./Anchor.toml):

```toml
[provider]
cluster = "devnet"  # or "localnet" / "mainnet"
wallet = "~/.config/solana/id.json"
```

### Deploy

```bash
# Deploy to devnet
anchor deploy --provider.cluster devnet

# Or deploy to localnet (requires test validator)
solana-test-validator
anchor deploy --provider.cluster localnet
```

---

## 💻 Usage

### Initialize Pool

```typescript
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PrivacyPool } from "../target/types/privacy_pool";

const program = anchor.workspace.PrivacyPool as Program<PrivacyPool>;

await program.methods
  .initialize(
    new anchor.BN(100), // fee_bps (1%)
    new anchor.BN(1_000_000), // min_withdrawal_fee
    new anchor.BN(1_000_000_000_000) // max_deposit_amount
  )
  .accounts({
    admin: adminKeypair.publicKey,
    // ... other accounts
  })
  .signers([adminKeypair])
  .rpc();
```

### Deposit (Create Note)

```typescript
import { buildPoseidon } from "circomlibjs";

// Generate secrets
const privateKey = randomBytes(31);
const blinding = randomBytes(31);
const poseidon = await buildPoseidon();

const publicKey = poseidon.F.toString(
  poseidon([BigInt("0x" + privateKey.toString("hex"))])
);

const commitment = poseidon([
  publicKey,
  BigInt("0x" + blinding.toString("hex")),
  amount,
]);

// Deposit
await program.methods
  .deposit(Array.from(commitment))
  .accounts({
    depositor: wallet.publicKey,
    merkleTree: merkleTreePDA,
    // ... other accounts
  })
  .rpc();

// ⚠️ CRITICAL: Save these secrets securely!
const note = {
  amount,
  commitment,
  nullifier,
  blinding,
  privateKey,
  publicKey,
  leafIndex,
};
```

### Withdraw

```typescript
import { generateWithdrawProof } from "./zk/withdrawProver";

// Load saved note
const note = await noteStorage.get(noteId);

// Generate ZK proof
const { proof, publicSignals } = await generateWithdrawProof({
  privateKey: note.privateKey,
  blinding: note.blinding,
  amount: note.amount,
  leafIndex: note.leafIndex,
  merklePath: note.merklePath,
  recipient: recipientPubkey,
  relayer: relayerPubkey,
  fee: feeAmount,
});

// Submit withdrawal
await program.methods
  .transact(
    Array.from(proof.a),
    Array.from(proof.b),
    Array.from(proof.c),
    Array.from(publicSignals),
    recipient,
    new anchor.BN(feeAmount)
  )
  .accounts({
    nullifierMarker: nullifierPDA,
    merkleTree: merkleTreePDA,
    // ... other accounts
  })
  .rpc();
```

### SPL Token Support

```typescript
// Initialize for SPL token
await program.methods
  .initializeSpl(
    tokenMintAddress,
    new anchor.BN(100), // fee_bps
    new anchor.BN(1_000_000), // min_withdrawal_fee
    new anchor.BN(1_000_000_000_000) // max_deposit_amount
  )
  .accounts({
    admin: adminKeypair.publicKey,
    tokenMint: tokenMintAddress,
    // ... other accounts
  })
  .rpc();

// Deposit SPL tokens
await program.methods
  .depositSpl(Array.from(commitment))
  .accounts({
    depositor: wallet.publicKey,
    depositorTokenAccount: depositorATA,
    vaultTokenAccount: vaultATA,
    // ... other accounts
  })
  .rpc();
```

---

## 🧪 Testing

### Run Tests

```bash
# Run SOL privacy pool tests
npm run test

# Run SPL token tests
npm run test:spl

# Run specific test file
npx mocha -r ts-node/register tests/privacy-pool.test.ts
```

### Test Scripts

```bash
# Test proof generation
npx ts-node scripts/test-proof-gen.ts

# Debug Merkle root
npx ts-node scripts/debug-root.js

# Run indexer (track deposits)
npx ts-node scripts/indexer.ts
```

---

## 🔐 Security

### Threat Model

Veilo provides privacy guarantees under the following assumptions:

✅ **Protected Against**:

- Transaction graph analysis (deposits ↔ withdrawals unlinkable)
- Amount correlation (via fixed denominations or UTXO model)
- Timing attacks (relayer network breaks timing patterns)
- Double-spending (nullifier PDAs prevent reuse)

⚠️ **Not Protected Against**:

- Network-level surveillance (use Tor/VPN)
- Compromised client device (secure your note storage!)
- Quantum computers (Groth16 is not post-quantum secure)

### Best Practices

1. **🔑 Secure Note Storage**: Use encrypted storage (see [`note-manager.example.ts`](./tests/note-manager.example.ts))
2. **🌐 Use Relayers**: Never withdraw directly to avoid linking your wallet
3. **⏱️ Add Delays**: Wait before withdrawing to break timing correlations
4. **💰 Mix Amounts**: Use different denominations across deposits
5. **🔒 Verify Proofs**: Always validate ZK proofs before trusting outputs

See [SECURITY_CHECKLIST.md](./docs/SECURITY_CHECKLIST.md) for detailed security guidelines.

---

## 📚 Documentation

- [**Note Management Guide**](./docs/NOTE_MANAGEMENT.md) - How to securely store and manage privacy notes
- [**Security Checklist**](./docs/SECURITY_CHECKLIST.md) - Comprehensive security best practices
- [**Build Plan**](./BUILD_PLAN.md) - Roadmap and upcoming features

---

## 🗺️ Roadmap

### ✅ Phase 1: Core Privacy (Completed)

- [x] Groth16 ZK proof verification on-chain
- [x] Merkle tree commitment system
- [x] PDA-based nullifier protection
- [x] Native SOL support
- [x] SPL token support
- [x] Relayer network infrastructure

### 🚧 Phase 2: Advanced Features (In Progress)

- [ ] UTXO model (2-in/2-out transactions)
- [ ] Arbitrary amount support
- [ ] External data verification (tamper-proof metadata)
- [ ] Permissionless token support
- [ ] Compliance features (optional transparency)

### 🔮 Phase 3: Ecosystem Integration

- [ ] Cross-chain bridges
- [ ] DeFi protocol integrations
- [ ] Mobile SDK
- [ ] Privacy-preserving DeFi composability

---

## 🛠️ Development

### Project Structure

```
.
├── programs/
│   └── privacy-pool/
│       ├── src/
│       │   ├── lib.rs              # Main program logic
│       │   ├── groth16.rs          # Groth16 verifier
│       │   ├── merkle_tree.rs      # Merkle tree implementation
│       │   ├── zk.rs               # ZK proof verification
│       │   └── vk_constants.rs     # Verification key constants
│       └── Cargo.toml
├── tests/
│   ├── privacy-pool.test.ts        # SOL tests
│   ├── privacy-pool-spl.test.ts    # SPL token tests
│   └── helpers/
│       ├── note-selector.ts        # UTXO selection
│       └── note-storage.ts         # Note management
├── scripts/
│   ├── indexer.ts                  # Track deposits
│   ├── add-relayer.ts              # Relayer management
│   └── test-proof-gen.ts           # Proof testing
├── zk/
│   ├── circuits/                   # ZK circuits
│   └── withdrawProver.ts           # Proof generation
└── docs/                           # Documentation
```

### Building from Source

```bash
# Build Rust program
anchor build

# Build TypeScript SDK
npm run build

# Generate IDL types
anchor build && anchor test --skip-build
```

### Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 🔗 Links

- **Website**: [Coming Soon]
- **Documentation**: [./docs](./docs)
- **Twitter**: [@VeiloSolana](https://twitter.com/VeiloSolana)
- **Discord**: [Join Community]

---

## ⚖️ License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

---

## ⚠️ Disclaimer

This software is provided "as is" without warranty of any kind. Use at your own risk. Always audit the code and understand the security model before using in production. The developers are not responsible for any loss of funds.

**Privacy Notice**: While Veilo provides strong privacy guarantees, no system is perfect. Always follow security best practices and understand the limitations of the protocol.

---

## 🙏 Acknowledgments

Built with:

- [Anchor](https://www.anchor-lang.com/) - Solana framework
- [SnarkJS](https://github.com/iden3/snarkjs) - ZK proof generation
- [Circom](https://github.com/iden3/circom) - Circuit compiler
- [Light Protocol](https://www.lightprotocol.com/) - Poseidon hash implementation

Special thanks to the Solana and ZK communities for their invaluable contributions to privacy technology.

---

<div align="center">

**Made with ❤️ by the Veilo Team**

_Bringing privacy to Solana, one proof at a time._

</div>

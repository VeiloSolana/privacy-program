# Security Checklist for Privacy Pool

## 🔐 Note Security - Critical Requirements

### What Prevents Note Theft?

Your privacy pool uses **Zero-Knowledge Proofs** to enforce ownership. Here's what protects your deposits:

---

## 🛡️ Protection Layers

### 1. **ZK Circuit Enforcement** (Cryptographic)

- **Location**: Circuit constraints in transaction.circom
- **What it does**: Mathematically proves you know the `privateKey` without revealing it
- **How**: `publicKey = Poseidon(privateKey)` constraint in the circuit
- **Attack resistance**: Impossible to forge without the actual privateKey (2^256 combinations)

### 2. **Groth16 Verification** (On-chain)

- **Location**: [`programs/privacy-pool/src/zk.rs:100`](../programs/privacy-pool/src/zk.rs#L100)
- **Function**: `verify_withdraw_groth16()`
- **What it does**: Verifies the ZK proof using pairing checks on BN254 curve
- **Attack resistance**: Mathematically impossible to forge without circuit secrets

### 3. **Nullifier Uniqueness** (On-chain)

- **Location**: [`programs/privacy-pool/src/lib.rs:635`](../programs/privacy-pool/src/lib.rs#L635)
- **What it does**: Ensures each note can only be spent once
- **How**: Anchor's `init` constraint enforces unique nullifier PDAs
- **Attack resistance**: Transaction reverts if nullifier already exists

### 4. **Encrypted Storage** (Off-chain) ⚠️ **YOUR RESPONSIBILITY**

- **Location**: [`tests/note-manager.example.ts`](../tests/note-manager.example.ts)
- **What it does**: Protects `privateKey` and `blinding` at rest
- **How**: AES-256-CBC encryption with scrypt key derivation
- **Attack resistance**: Depends on password strength

---

## ⚠️ Critical Security Requirements

### DO ✅

1. **Use Encrypted Storage**

   ```typescript
   import { NoteManager } from "./note-manager.example";

   const manager = new NoteManager("./notes.enc", "your-strong-password");
   await manager.saveNote(note);
   ```

2. **Use Strong Passwords**

   - Minimum 20 characters
   - Include numbers, symbols, uppercase, lowercase
   - Use a password manager
   - Never reuse passwords

3. **Backup Your Notes**

   - Keep encrypted backups in multiple locations
   - Test recovery process
   - **Warning**: If notes are lost, funds are UNRECOVERABLE

4. **Verify Before Sharing**

   - ✅ Safe to share: `commitment`, `leafIndex`, `amount` (if you want)
   - ❌ NEVER share: `privateKey`, `blinding`, `nullifier`

5. **Use Hardware Security**
   - iOS: Keychain
   - Android: KeyStore
   - Web: WebAuthn for password protection
   - Production: AWS KMS, Google Cloud KMS

### DON'T ❌

1. **Never Store Notes in Plain Text**

   ```typescript
   // ❌ WRONG - Anyone with file access can steal your deposits
   fs.writeFileSync("notes.json", JSON.stringify(notes));

   // ✅ CORRECT - Encrypted storage
   const encrypted = manager.encrypt(notes, password);
   fs.writeFileSync("notes.enc", encrypted);
   ```

2. **Never Commit Notes to Git**

   ```bash
   # Add to .gitignore
   notes.json
   notes.enc
   *.priv
   *.secret
   ```

3. **Never Share Full Notes**

   - Don't send via email, Slack, Discord, etc.
   - Don't screenshot with secrets visible
   - Don't paste into ChatGPT/AI tools

4. **Never Use Weak Encryption**

   - Don't use simple XOR or Caesar cipher
   - Don't use MD5 or SHA1 for passwords
   - Don't use ECB mode for AES

5. **Never Skip Backups**
   - Blockchain has NO "forgot password" feature
   - Lost notes = Lost funds FOREVER
   - No customer support can recover them

---

## 🎯 Implementation Checklist

### For Testing (Development)

- [x] Use `InMemoryNoteStorage` from [`tests/helpers/note-storage.ts`](../tests/helpers/note-storage.ts)
- [x] Run security demonstration test: `anchor test`
- [ ] Verify all 4 tests pass (including "demonstrates note security model")

### For Production (Real Money)

- [ ] Implement `NoteManager` from [`tests/note-manager.example.ts`](../tests/note-manager.example.ts)
- [ ] Use scrypt/Argon2 for key derivation (not simple hash)
- [ ] Store encrypted notes file in secure location
- [ ] Implement backup/restore functionality
- [ ] Add password strength requirements (20+ chars)
- [ ] Use hardware security module for key storage
- [ ] Test recovery process before depositing real funds
- [ ] Add multi-signature for large deposits
- [ ] Implement note export/import for backups
- [ ] Add rate limiting for failed decryption attempts

### For Web Applications

- [ ] Implement server-side note storage with database
- [ ] Use per-user encryption keys
- [ ] Implement 2FA for sensitive operations
- [ ] Add audit logging for note access
- [ ] Use HTTPS only (no HTTP)
- [ ] Implement session timeouts
- [ ] Add CSRF protection
- [ ] Use WebAuthn for authentication
- [ ] Implement automatic backups
- [ ] Add disaster recovery procedures

---

## 🔍 Security Testing

### Test Suite Included

Run `anchor test` to execute:

1. ✅ **Deposit Test**: Demonstrates proper note creation and storage
2. ✅ **Withdrawal Test**: Shows how to retrieve and spend notes
3. ✅ **Security Model Test**: Educational demo of all protection layers

### Manual Security Audit

1. **Verify ZK Circuit**

   ```bash
   # Check circuit has ownership constraints
   grep "publicKey.*Poseidon.*privateKey" zk/circuits/transaction.circom
   ```

2. **Verify On-chain Verification**

   ```bash
   # Check Rust code calls verify_withdraw_groth16
   grep "verify_withdraw_groth16" programs/privacy-pool/src/lib.rs
   ```

3. **Verify Nullifier Uniqueness**

   ```bash
   # Check nullifier uses init constraint
   grep "init.*nullifier_marker" programs/privacy-pool/src/lib.rs
   ```

4. **Test Encrypted Storage**
   ```bash
   # Run note manager example
   ts-node tests/note-manager.example.ts
   ```

---

## 🚨 Attack Scenarios & Mitigations

### Scenario 1: Attacker Sees Commitment On-chain

- **What attacker knows**: Commitment hash, leaf index
- **Can they spend?**: ❌ NO - They need privateKey to generate valid proof
- **Mitigation**: None needed, this is by design

### Scenario 2: Attacker Steals Encrypted Notes File

- **What attacker knows**: Encrypted blob
- **Can they spend?**: ❌ NO (if strong password) - Need to crack encryption
- **Mitigation**: Use 20+ character password, rate limit decryption attempts

### Scenario 3: Attacker Steals Plaintext Notes

- **What attacker knows**: privateKey + blinding
- **Can they spend?**: ✅ YES - They can generate valid proofs
- **Mitigation**: NEVER store notes in plaintext, always encrypt

### Scenario 4: Attacker Compromises Your Device

- **What attacker knows**: Everything (keylogger, memory dump)
- **Can they spend?**: ✅ YES - Full access to secrets
- **Mitigation**: Use hardware wallet, secure your device, 2FA for withdrawals

### Scenario 5: Attacker Brute Forces Private Key

- **What attacker knows**: Nothing (trying random keys)
- **Can they spend?**: ❌ NO - 2^256 combinations, universe would end first
- **Mitigation**: None needed, cryptographically secure

---

## 📊 Code Locations

| Component             | File                               | Function                             | Purpose                       |
| --------------------- | ---------------------------------- | ------------------------------------ | ----------------------------- |
| ZK Proof Generation   | `tests/privacy-pool.test.ts`       | `generateTransactionProof()`         | Creates proof with privateKey |
| ZK Proof Verification | `programs/privacy-pool/src/zk.rs`  | `verify_withdraw_groth16()`          | Verifies proof on-chain       |
| Nullifier Check       | `programs/privacy-pool/src/lib.rs` | `withdraw()`                         | Prevents double-spend         |
| Note Storage (Test)   | `tests/helpers/note-storage.ts`    | `InMemoryNoteStorage`                | In-memory note management     |
| Note Storage (Prod)   | `tests/note-manager.example.ts`    | `NoteManager`                        | Encrypted file storage        |
| Security Demo         | `tests/privacy-pool.test.ts`       | `"demonstrates note security model"` | Educational test              |

---

## 📚 Further Reading

- [NOTE_MANAGEMENT.md](./NOTE_MANAGEMENT.md) - Complete guide to note lifecycle
- [Groth16 Paper](https://eprint.iacr.org/2016/260.pdf) - Understanding the proof system
- [BN254 Curve](https://hackmd.io/@jpw/bn254) - The elliptic curve used
- [Poseidon Hash](https://www.poseidon-hash.info/) - The hash function used

---

## ✅ Quick Verification

To verify your implementation is secure, check:

```bash
# 1. Tests pass (including security demo)
anchor test

# 2. Notes are encrypted in storage
grep "crypto.createCipher\|AES" your-note-storage.ts

# 3. No plaintext notes in codebase
grep -r "privateKey.*=.*randomBytes" --include="*.ts" | grep -v "test"

# 4. .gitignore includes note files
grep "notes\|*.enc\|*.priv" .gitignore

# 5. Password strength requirements
grep "password.*length.*20" your-app.ts
```

**All checks passing?** ✅ You're secure!

**Any checks failing?** ⚠️ Review this checklist and fix before production!

---

## 🆘 Emergency: Note Compromised

If you believe your note has been stolen:

1. **Act Fast**: Generate withdrawal proof immediately
2. **Withdraw to New Address**: Don't reuse recipient address
3. **Check Balance**: Verify funds haven't been stolen yet
4. **Revoke Access**: Change all passwords, scan for malware
5. **Create New Notes**: Use fresh privateKeys for new deposits
6. **Report**: Document the incident for audit trail

**Remember**: Once stolen, there's NO WAY to prevent spending. Speed is critical.

---

_Last updated: January 6, 2026_

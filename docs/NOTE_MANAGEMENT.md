# Note Management Guide

## How Privacy Pool Deposits Work

### The Problem
When you deposit into a privacy pool, the deposit is recorded on-chain as a **commitment** (a hash). To withdraw later, you need to prove you know the **secrets** behind that commitment without revealing which deposit is yours.

### What You Need to Store

After depositing, you MUST save these private details:

```typescript
{
  amount: bigint,           // How much you deposited
  commitment: Uint8Array,   // Public commitment (on-chain)
  nullifier: Uint8Array,    // Prevents double-spending
  blinding: Uint8Array,     // Random secret
  privateKey: Uint8Array,   // Your secret key
  publicKey: bigint,        // Derived from privateKey
  leafIndex: number,        // Position in Merkle tree
  merklePath: {...}         // Proof path (can be recomputed)
}
```

**⚠️ WARNING:** If you lose these secrets, **you lose access to your deposit forever!**

---

## Implementation Approaches

### 1. **Development/Testing: In-Memory Storage**

For tests and development:

```typescript
import { InMemoryNoteStorage } from './helpers/note-storage';

const noteStorage = new InMemoryNoteStorage();

// After deposit
const noteId = noteStorage.save(depositNote);

// Before withdrawal
const note = noteStorage.get(noteId);
if (note) {
  // Generate proof and withdraw
}
```

**Pros:** Simple, fast  
**Cons:** Lost when process ends

---

### 2. **Production: Encrypted File Storage**

For wallets and applications:

```typescript
import { NoteManager } from './note-manager';

const manager = new NoteManager(
  './notes.enc',
  'user-password'
);

// After deposit
await manager.saveNote({
  amount: depositAmount,
  commitment: commitmentHex,
  privateKey: privateKeyHex,
  // ... other fields
});

// Before withdrawal
const unspent = await manager.getUnspentNotes();
const noteToSpend = unspent[0];
```

**Pros:** Persistent, encrypted  
**Cons:** Need secure password management

---

### 3. **Production: Database Storage**

For web applications:

```sql
CREATE TABLE deposit_notes (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  amount BIGINT NOT NULL,
  commitment TEXT NOT NULL,
  nullifier TEXT NOT NULL,
  -- Encrypt these fields!
  encrypted_private_key TEXT NOT NULL,
  encrypted_blinding TEXT NOT NULL,
  leaf_index INTEGER NOT NULL,
  mint_address TEXT NOT NULL,
  spent BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW(),
  spent_at TIMESTAMP
);

CREATE INDEX idx_unspent ON deposit_notes(user_id, spent) 
WHERE spent = FALSE;
```

**Pros:** Multi-user, scalable  
**Cons:** Must encrypt sensitive fields properly

---

## Security Best Practices

### 🔒 **Always Encrypt Sensitive Data**

```typescript
// ❌ NEVER DO THIS
fs.writeFileSync('notes.json', JSON.stringify(notes));

// ✅ DO THIS
const encrypted = encrypt(JSON.stringify(notes), userPassword);
fs.writeFileSync('notes.enc', encrypted);
```

### 🔐 **Key Management**

- **User-controlled:** User provides password (they must remember it)
- **Hardware wallet:** Store keys on hardware device
- **KMS (production):** Use AWS KMS, Google Cloud KMS, etc.

### 🗝️ **Backup Strategy**

```typescript
// Export encrypted note for backup
const backup = await manager.exportNote(noteId, 'backup-password');

// User can save this string safely
// To restore: import with same password
```

---

## Real-World Workflow

### **Scenario: Alice deposits 10 SOL today, withdraws in 1 month**

#### **Step 1: Deposit (Today)**

```typescript
// 1. Generate secrets
const privateKey = randomBytes32();
const blinding = randomBytes32();
const publicKey = derivePublicKey(poseidon, privateKey);

// 2. Create commitment
const commitment = computeCommitment(
  poseidon,
  10_000_000_000n, // 10 SOL
  publicKey,
  blinding,
  SOL_MINT
);

// 3. Submit deposit transaction
const tx = await program.methods.transact(...).rpc();

// 4. CRITICAL: Save note to encrypted storage
const noteId = await noteManager.saveNote({
  amount: 10_000_000_000n,
  commitment: commitment.toString('hex'),
  privateKey: privateKey.toString('hex'),
  blinding: blinding.toString('hex'),
  publicKey: publicKey.toString(),
  leafIndex: leafIndex,
  mintAddress: SOL_MINT.toBase58(),
  txSignature: tx,
});

console.log(`✅ Deposit complete! Note ID: ${noteId}`);
console.log(`⚠️  Keep your password safe - you'll need it to withdraw!`);
```

#### **Step 2: Withdraw (1 Month Later)**

```typescript
// 1. Load note from encrypted storage
const noteManager = new NoteManager('./notes.enc', userPassword);
const unspentNotes = await noteManager.getUnspentNotes();

console.log(`You have ${unspentNotes.length} unspent notes:`);
unspentNotes.forEach((note, i) => {
  console.log(`  ${i+1}. ${Number(note.amount)/1e9} SOL (deposited ${new Date(note.timestamp)})`);
});

// 2. Select note to spend
const noteToSpend = unspentNotes[0];

// 3. Get current Merkle proof (tree may have grown)
const currentMerklePath = offchainTree.getMerkleProof(noteToSpend.leafIndex);

// 4. Generate withdrawal proof
const proof = await generateTransactionProof({
  root: currentRoot,
  publicAmount: -noteToSpend.amount, // Negative for withdrawal
  inputNullifiers: [
    hexToUint8Array(noteToSpend.nullifier),
    dummyNullifier
  ],
  inputAmounts: [noteToSpend.amount, 0n],
  inputPrivateKeys: [
    hexToUint8Array(noteToSpend.privateKey),
    dummyPrivKey
  ],
  inputMerklePaths: [
    currentMerklePath,
    zeroPath
  ],
  // ... other fields
});

// 5. Submit withdrawal
const withdrawTx = await program.methods.transact(...).rpc();

// 6. Mark note as spent
await noteManager.markAsSpent(noteToSpend.id, withdrawTx);

console.log(`✅ Withdrawal complete!`);
```

---

## Privacy Considerations

### **Breaking the Link**

The whole point of a privacy pool is to break the link between deposit and withdrawal:

```
Alice deposits 10 SOL    →  [Privacy Pool]  →  Bob receives 10 SOL
                              (many txs)
                              
Who sent to Bob? 🤷 Could be anyone who deposited ~10 SOL!
```

### **Best Practices for Maximum Privacy**

1. **Wait between deposit and withdrawal** (hours/days)
2. **Don't withdraw to same address** that deposited
3. **Use different amounts** (e.g., deposit 10.5, withdraw 10.0)
4. **Batch deposits** (deposit multiple times from different sources)
5. **Use relayers** (don't send withdrawal from your own address)

---

## Troubleshooting

### "I lost my note, can I recover it?"

**If you have the private key and blinding factor:** Yes, you can reconstruct the commitment and nullifier.

**If you lost everything:** No, the deposit is permanently lost. This is by design - no one can help you, not even the protocol developers.

### "How do I know which deposits are mine?"

You must keep track of your notes. The blockchain only stores commitments (hashes), not ownership information.

### "Can I transfer my note to someone else?"

Yes! Export the encrypted note and share it with them securely. They can import it with their own password.

```typescript
const exported = await manager.exportNote(noteId, 'recipient-password');
// Send 'exported' to recipient securely
```

---

## Summary

| Stage | What to Store | Where |
|-------|---------------|-------|
| **Development** | In-memory variable | RAM (temporary) |
| **Testing** | InMemoryNoteStorage | RAM (temporary) |
| **Production** | Encrypted file/DB | Disk (persistent) |
| **Enterprise** | KMS + Database | Cloud (highly secure) |

**Golden Rule:** The security of your deposits depends on keeping your note secrets safe. Treat them like private keys! 🔐

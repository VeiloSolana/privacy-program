# Tree Monitoring & Management Guide

## Getting the Latest Tree ID

### Method 1: Query PrivacyConfig (Recommended)

```typescript
import { Program, AnchorProvider } from "@coral-xyz/anchor";
import { PublicKey } from "@solana/web3.js";

// Get the config PDA
const [configPDA] = PublicKey.findProgramAddressSync(
  [Buffer.from("privacy_config_v3"), mintAddress.toBuffer()],
  program.programId
);

// Fetch config account
const config = await program.account.privacyConfig.fetch(configPDA);

console.log("Total trees:", config.numTrees); // e.g., 3 (trees 0, 1, 2 exist)
console.log("Next tree ID:", config.numTrees); // e.g., 3 (next tree to create)
console.log("Suggested tree:", config.nextTreeIndex); // e.g., 1 (round-robin suggestion)

// Latest tree ID (most recent)
const latestTreeId = config.numTrees - 1;
console.log("Latest tree:", latestTreeId); // e.g., 2
```

### Method 2: Using Anchor IDL

```typescript
interface PrivacyConfig {
  bump: number;
  vaultBump: number;
  admin: PublicKey;
  feeBps: number;
  minWithdrawalFee: BN;
  feeErrorMarginBps: number;
  totalTvl: BN;
  mintAddress: PublicKey;
  minDepositAmount: BN;
  maxDepositAmount: BN;
  minWithdrawAmount: BN;
  maxWithdrawAmount: BN;
  numRelayers: number;
  relayers: PublicKey[];
  numTrees: number; // ← Total trees created
  nextTreeIndex: number; // ← Round-robin suggestion
}

const config = await program.account.privacyConfig.fetch(configPDA);
```

## Checking Tree Capacity

### Tree Capacity Constants

```rust
// In Rust program
pub const MERKLE_TREE_HEIGHT: usize = 26;
pub const TREE_CAPACITY: u64 = 1 << 26;  // 67,108,864 leaves
```

```typescript
// In TypeScript
const TREE_HEIGHT = 26;
const TREE_CAPACITY = Math.pow(2, 26); // 67,108,864
```

### Query Individual Tree State

```typescript
// Derive tree PDA
function getTreePDA(mintAddress: PublicKey, treeId: number) {
  const treeIdBuffer = Buffer.alloc(2);
  treeIdBuffer.writeUInt16LE(treeId, 0);

  const [treePDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("privacy_note_tree_v3"), mintAddress.toBuffer(), treeIdBuffer],
    program.programId
  );

  return treePDA;
}

// Fetch tree account
const treePDA = getTreePDA(mintAddress, treeId);
const treeAccount = await program.account.merkleTreeAccount.fetch(treePDA);

console.log("Next leaf index:", treeAccount.nextIndex); // e.g., 45,000,000
console.log("Current root:", treeAccount.currentRoot);
console.log("Tree ID:", treeAccount.treeId);
```

### Calculate Tree Utilization

```typescript
interface TreeStats {
  treeId: number;
  leafCount: number;
  capacity: number;
  utilizationPercent: number;
  remainingCapacity: number;
  isFull: boolean;
  isNearCapacity: boolean;
}

async function getTreeStats(
  program: Program,
  mintAddress: PublicKey,
  treeId: number
): Promise<TreeStats> {
  const treePDA = getTreePDA(mintAddress, treeId);
  const tree = await program.account.merkleTreeAccount.fetch(treePDA);

  const leafCount = tree.nextIndex;
  const capacity = TREE_CAPACITY;
  const utilizationPercent = (leafCount / capacity) * 100;
  const remainingCapacity = capacity - leafCount;

  return {
    treeId,
    leafCount,
    capacity,
    utilizationPercent,
    remainingCapacity,
    isFull: leafCount >= capacity,
    isNearCapacity: utilizationPercent >= 90, // 90% threshold
  };
}

// Usage
const stats = await getTreeStats(program, mintAddress, 0);
console.log(`Tree 0: ${stats.utilizationPercent.toFixed(2)}% full`);
console.log(`Remaining: ${stats.remainingCapacity.toLocaleString()} leaves`);

if (stats.isNearCapacity) {
  console.warn("⚠️  Tree is near capacity! Create a new tree soon.");
}
```

## Tree Creation Timing

### Recommended Thresholds

| Threshold | Action  | Reason                         |
| --------- | ------- | ------------------------------ |
| 50%       | Monitor | Start tracking more frequently |
| 75%       | Alert   | Admin should be aware          |
| 90%       | Create  | Initiate new tree creation     |
| 95%       | Urgent  | Critical - tree almost full    |
| 100%      | Full    | No more deposits possible      |

### Monitoring Script Example

```typescript
import { Connection, PublicKey } from "@solana/web3.js";
import { AnchorProvider, Program } from "@coral-xyz/anchor";

const TREE_CAPACITY = Math.pow(2, 26);
const WARNING_THRESHOLD = 0.9; // 90%
const CRITICAL_THRESHOLD = 0.95; // 95%

async function monitorTrees(program: Program, mintAddress: PublicKey) {
  // Get total number of trees
  const [configPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("privacy_config_v3"), mintAddress.toBuffer()],
    program.programId
  );

  const config = await program.account.privacyConfig.fetch(configPDA);
  const numTrees = config.numTrees;

  console.log(
    `\n📊 Monitoring ${numTrees} tree(s) for mint: ${mintAddress.toBase58()}\n`
  );

  // Check each tree
  for (let treeId = 0; treeId < numTrees; treeId++) {
    const stats = await getTreeStats(program, mintAddress, treeId);
    const utilization = stats.leafCount / TREE_CAPACITY;

    let status = "✅ OK";
    if (utilization >= CRITICAL_THRESHOLD) {
      status = "🔴 CRITICAL";
    } else if (utilization >= WARNING_THRESHOLD) {
      status = "⚠️  WARNING";
    }

    console.log(
      `Tree ${treeId}: ${status} | ` +
        `${stats.leafCount.toLocaleString()}/${TREE_CAPACITY.toLocaleString()} ` +
        `(${stats.utilizationPercent.toFixed(2)}%)`
    );

    // Auto-create new tree if critical
    if (utilization >= WARNING_THRESHOLD && treeId === numTrees - 1) {
      console.log(
        `\n🔧 Action Required: Tree ${treeId} is ${stats.utilizationPercent.toFixed(
          2
        )}% full`
      );
      console.log(`📝 Next tree ID to create: ${numTrees}`);
      console.log(`💡 Run: npm run create-tree ${numTrees}\n`);
    }
  }
}

// Run every 5 minutes
setInterval(async () => {
  try {
    await monitorTrees(program, mintAddress);
  } catch (error) {
    console.error("Monitoring error:", error);
  }
}, 5 * 60 * 1000);
```

## Creating a New Tree (Admin)

### Script: `scripts/add-tree.ts`

```typescript
import { Program, AnchorProvider, Wallet } from "@coral-xyz/anchor";
import { PublicKey, Keypair } from "@solana/web3.js";
import fs from "fs";

async function createNewTree(
  program: Program,
  adminKeypair: Keypair,
  mintAddress: PublicKey
) {
  console.log("🌳 Creating new Merkle tree...\n");

  // Get config to find next tree ID
  const [configPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("privacy_config_v3"), mintAddress.toBuffer()],
    program.programId
  );

  const config = await program.account.privacyConfig.fetch(configPDA);
  const nextTreeId = config.numTrees;

  console.log(`Current trees: ${config.numTrees}`);
  console.log(`Creating tree ID: ${nextTreeId}`);

  // Derive new tree PDA
  const treeIdBuffer = Buffer.alloc(2);
  treeIdBuffer.writeUInt16LE(nextTreeId, 0);

  const [noteTreePDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("privacy_note_tree_v3"), mintAddress.toBuffer(), treeIdBuffer],
    program.programId
  );

  console.log(`Tree PDA: ${noteTreePDA.toBase58()}\n`);

  // Create tree
  const tx = await program.methods
    .addMerkleTree(mintAddress, nextTreeId)
    .accounts({
      config: configPDA,
      noteTree: noteTreePDA,
      admin: adminKeypair.publicKey,
      systemProgram: SystemProgram.programId,
    })
    .signers([adminKeypair])
    .rpc();

  console.log(`✅ Tree ${nextTreeId} created!`);
  console.log(`📝 Transaction: ${tx}`);

  // Verify
  const updatedConfig = await program.account.privacyConfig.fetch(configPDA);
  console.log(`Total trees now: ${updatedConfig.numTrees}`);

  return nextTreeId;
}

// Run
const adminKeyPath = process.env.ADMIN_KEYPAIR || "~/.config/solana/id.json";
const adminKeypair = Keypair.fromSecretKey(
  new Uint8Array(JSON.parse(fs.readFileSync(adminKeyPath, "utf-8")))
);

const mintAddress = new PublicKey("11111111111111111111111111111111"); // SOL
await createNewTree(program, adminKeypair, mintAddress);
```

### Usage

```bash
# Add to package.json
{
  "scripts": {
    "monitor-trees": "ts-node scripts/monitor-trees.ts",
    "create-tree": "ts-node scripts/add-tree.ts"
  }
}

# Monitor trees
npm run monitor-trees

# Create new tree when needed
npm run create-tree
```

## Indexer Integration

### Track Tree Stats in Database

```typescript
// Example: PostgreSQL schema
CREATE TABLE tree_stats (
  mint_address TEXT NOT NULL,
  tree_id INTEGER NOT NULL,
  leaf_count BIGINT NOT NULL,
  capacity BIGINT NOT NULL,
  utilization_percent DECIMAL(5,2) NOT NULL,
  last_updated TIMESTAMP DEFAULT NOW(),
  PRIMARY KEY (mint_address, tree_id)
);

CREATE INDEX idx_tree_utilization ON tree_stats(utilization_percent DESC);

// Update on every CommitmentEvent
async function onCommitmentEvent(event: CommitmentEvent) {
  const { mintAddress, treeId, leafIndex } = event;

  await db.query(`
    INSERT INTO tree_stats (mint_address, tree_id, leaf_count, capacity, utilization_percent)
    VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT (mint_address, tree_id)
    DO UPDATE SET
      leaf_count = $3,
      utilization_percent = $5,
      last_updated = NOW()
  `, [
    mintAddress,
    treeId,
    leafIndex + 1,
    TREE_CAPACITY,
    ((leafIndex + 1) / TREE_CAPACITY) * 100
  ]);

  // Check if tree is near capacity
  const utilization = ((leafIndex + 1) / TREE_CAPACITY);
  if (utilization >= 0.90) {
    await sendAlert({
      type: "TREE_NEAR_CAPACITY",
      mintAddress,
      treeId,
      utilization: utilization * 100
    });
  }
}
```

### API Endpoint for Frontend

```typescript
// Express.js example
app.get("/api/trees/:mintAddress", async (req, res) => {
  const { mintAddress } = req.params;

  const trees = await db.query(
    `
    SELECT
      tree_id,
      leaf_count,
      capacity,
      utilization_percent,
      CASE
        WHEN utilization_percent >= 95 THEN 'critical'
        WHEN utilization_percent >= 90 THEN 'warning'
        WHEN utilization_percent >= 75 THEN 'monitor'
        ELSE 'ok'
      END as status
    FROM tree_stats
    WHERE mint_address = $1
    ORDER BY tree_id DESC
  `,
    [mintAddress]
  );

  res.json({
    mintAddress,
    trees: trees.rows,
    recommendedTreeId:
      trees.rows.find((t) => t.utilization_percent < 90)?.tree_id || null,
  });
});

// Frontend usage
const { trees, recommendedTreeId } = await fetch(
  `/api/trees/${mintAddress}`
).then((r) => r.json());
console.log(`Recommended tree for deposits: ${recommendedTreeId}`);
```

## Best Practices Summary

### When to Create New Trees

1. **Proactive** (Recommended): Create when latest tree reaches 90% capacity

   - Gives time for tree creation transaction to confirm
   - Users won't experience deposit failures
   - Admin has time to monitor and verify

2. **Reactive** (Not Recommended): Wait until tree is full
   - Deposits will start failing
   - Poor user experience
   - Rushed tree creation under pressure

### Monitoring Frequency

- **Production**: Every 1-5 minutes
- **Development**: Every 10-30 minutes
- **Alert channels**: Email, Slack, PagerDuty for >90% utilization

### Tree Creation Lead Time

Assuming 10,000 deposits per day:

- **90% threshold** = ~6 days lead time before full
- **95% threshold** = ~3 days lead time before full
- **99% threshold** = ~16 hours lead time before full

### Example Timeline

```
Day 0:   Tree 0 created (0% full)
Day 60:  50% full - Start monitoring more frequently
Day 80:  75% full - Admin alerted
Day 90:  90% full - CREATE TREE 1 NOW ← Trigger point
Day 93:  Tree 0 = 95% full, Tree 1 ready
Day 100: Tree 0 = 100% full, all deposits go to Tree 1
```

## Quick Reference Commands

```bash
# Check tree stats
ts-node -e "
  const stats = await getTreeStats(program, mintAddress, 0);
  console.log(stats);
"

# Monitor all trees
npm run monitor-trees

# Create new tree
npm run create-tree

# Query via Anchor CLI
anchor account MerkleTreeAccount <TREE_PDA>
```

## Troubleshooting

**Q: Tree shows as full but nextIndex < capacity?**
A: Check if you're reading the correct tree PDA. Verify tree_id encoding (2-byte little-endian).

**Q: Multiple trees being created at once?**
A: Ensure only one admin process is running. Use atomic checks or distributed locks.

**Q: How to know which tree a note is in?**
A: CommitmentEvent includes `tree_id`. Store this with each note in your note manager.

**Q: Can I prioritize certain trees?**
A: Yes! Use custom tree selection logic instead of the default round-robin `nextTreeIndex`.

// tests/test-helpers.ts
//
// Shared test utilities for Privacy Pool tests
// Contains interfaces, classes, helper functions, and proof generation logic
//

import { AnchorProvider, BN, Wallet } from "@coral-xyz/anchor";
import { PublicKey, Keypair, Connection } from "@solana/web3.js";
import { getOrCreateAssociatedTokenAccount, mintTo } from "@solana/spl-token";
import fs from "fs";
import os from "os";
import path from "path";
import { groth16 } from "snarkjs";

// =============================================================================
// Simple Note Storage (inline for test compatibility)
// =============================================================================

export interface DepositNote {
  amount: bigint;
  commitment: Uint8Array;
  nullifier: Uint8Array;
  blinding: Uint8Array;
  privateKey: Uint8Array;
  publicKey: bigint;
  leafIndex: number;
  merklePath: {
    pathElements: bigint[];
    pathIndices: number[];
  };
  mintAddress?: PublicKey;
  timestamp?: number;
  spent?: boolean;
}

export class InMemoryNoteStorage {
  private notes: Map<string, DepositNote> = new Map();

  save(note: DepositNote): string {
    const id = `note_${Buffer.from(note.commitment)
      .toString("hex")
      .slice(0, 12)}`;
    this.notes.set(id, {
      ...note,
      timestamp: Date.now(),
      spent: false,
    });
    return id;
  }

  get(id: string): DepositNote | undefined {
    return this.notes.get(id);
  }

  markSpent(id: string): void {
    const note = this.notes.get(id);
    if (note) {
      note.spent = true;
      note.timestamp = Date.now();
    }
  }
}

// =============================================================================
// Configuration
// =============================================================================

export const WASM_PATH = path.join(
  process.cwd(),
  "zk/circuits/transaction/transaction_js/transaction.wasm",
);
export const ZKEY_PATH = path.join(
  process.cwd(),
  "zk/circuits/transaction/transaction_final.zkey",
);
export const VK_PATH = path.join(
  process.cwd(),
  "zk/circuits/transaction/transaction_verification_key.json",
);

// =============================================================================
// Helper Functions
// =============================================================================

export function makeProvider(): AnchorProvider {
  const url = process.env.ANCHOR_PROVIDER_URL ?? "http://127.0.0.1:8899";
  const connection = new Connection(url, "confirmed");

  const keypairPath =
    process.env.ANCHOR_WALLET ??
    path.join(os.homedir(), ".config", "solana", "id.json");

  const secret = JSON.parse(fs.readFileSync(keypairPath, "utf8"));
  const kp = Keypair.fromSecretKey(Uint8Array.from(secret));
  const wallet = new Wallet(kp);

  return new AnchorProvider(connection, wallet, {
    commitment: "confirmed",
  });
}

export async function airdropAndConfirm(
  provider: AnchorProvider,
  pubkey: PublicKey,
  amount: number,
) {
  const sig = await provider.connection.requestAirdrop(pubkey, amount);
  const latestBlockhash = await provider.connection.getLatestBlockhash();
  await provider.connection.confirmTransaction({
    signature: sig,
    ...latestBlockhash,
  });
}

export function randomBytes32(): Uint8Array {
  return Keypair.generate().publicKey.toBytes();
}

// Helper: Create and fund SPL token account
export async function createAndFundTokenAccount(
  provider: AnchorProvider,
  mint: PublicKey,
  owner: PublicKey,
  amount: number,
): Promise<PublicKey> {
  const tokenAccount = await getOrCreateAssociatedTokenAccount(
    provider.connection,
    (provider.wallet as Wallet).payer,
    mint,
    owner,
  );

  if (amount > 0) {
    await mintTo(
      provider.connection,
      (provider.wallet as Wallet).payer,
      mint,
      tokenAccount.address,
      (provider.wallet as Wallet).payer,
      amount,
    );
  }

  return tokenAccount.address;
}

export function bytesToBigIntBE(bytes: Uint8Array): bigint {
  return BigInt("0x" + Buffer.from(bytes).toString("hex"));
}

// Helper: Reduce value modulo BN254 Fr field
export function reduceToField(bytes: Uint8Array): bigint {
  const FR_MODULUS = BigInt(
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
  );
  const value = BigInt("0x" + Buffer.from(bytes).toString("hex"));
  return value % FR_MODULUS;
}

// Helper: Derive public key from private key: pubkey = Poseidon(privateKey)
export function derivePublicKey(poseidon: any, privateKey: Uint8Array): bigint {
  const privateKeyField = poseidon.F.e(bytesToBigIntBE(privateKey));
  const publicKeyHash = poseidon([privateKeyField]);
  return poseidon.F.toObject(publicKeyHash);
}

// Helper: Compute extDataHash = Poseidon(Poseidon(recipient, relayer), Poseidon(fee, refund))
export function computeExtDataHash(
  poseidon: any,
  extData: {
    recipient: PublicKey;
    relayer: PublicKey;
    fee: BN;
    refund: BN;
  },
): Uint8Array {
  const recipientField = poseidon.F.e(
    reduceToField(extData.recipient.toBytes()),
  );
  const relayerField = poseidon.F.e(reduceToField(extData.relayer.toBytes()));
  const feeField = poseidon.F.e(extData.fee.toString());
  const refundField = poseidon.F.e(extData.refund.toString());

  const hash1 = poseidon([recipientField, relayerField]);
  const hash2 = poseidon([feeField, refundField]);
  const finalHash = poseidon([hash1, hash2]);

  const hashBytes = poseidon.F.toString(finalHash, 16).padStart(64, "0");
  return Uint8Array.from(Buffer.from(hashBytes, "hex"));
}

// Helper: Compute commitment = Poseidon(amount, pubkey, blinding)
// This matches the circuit's UTXOCommitment template (3 inputs)
export function computeCommitment(
  poseidon: any,
  amount: bigint,
  ownerPubkey: bigint, // Already derived from private key
  blinding: Uint8Array,
  mintAddress: PublicKey,
): Uint8Array {
  const amountField = poseidon.F.e(amount.toString());
  const ownerField = poseidon.F.e(ownerPubkey.toString());
  const blindingField = poseidon.F.e(bytesToBigIntBE(blinding));
  const mintField = poseidon.F.e(
    reduceToField(mintAddress.toBytes()).toString(),
  );

  // Poseidon hash with 4 inputs (amount, pubkey, blinding, mint)
  const commitment = poseidon([
    amountField,
    ownerField,
    blindingField,
    mintField,
  ]);

  const hashBytes = poseidon.F.toString(commitment, 16).padStart(64, "0");
  return Uint8Array.from(Buffer.from(hashBytes, "hex"));
}

// Helper: Compute nullifier matching circuit's UTXONullifier template
// signature = Poseidon(privateKey, commitment, pathIndex)
// nullifier = Poseidon(commitment, pathIndex, signature)
export function computeNullifier(
  poseidon: any,
  commitment: Uint8Array,
  leafIndex: number,
  privateKey: Uint8Array,
): Uint8Array {
  const commitmentField = poseidon.F.e(bytesToBigIntBE(commitment));
  const indexField = poseidon.F.e(BigInt(leafIndex));
  const keyField = poseidon.F.e(bytesToBigIntBE(privateKey));

  // Step 1: Compute signature
  const signature = poseidon([keyField, commitmentField, indexField]);

  // Step 2: Compute nullifier
  const nullifierHash = poseidon([commitmentField, indexField, signature]);
  const hashBytes = poseidon.F.toString(nullifierHash, 16).padStart(64, "0");
  return Uint8Array.from(Buffer.from(hashBytes, "hex"));
}

export function createDummyInput(
  poseidon: any,
  owner: bigint,
  mintAddress: PublicKey,
) {
  const amount = 0n;
  const blinding = new Uint8Array(32).fill(0);
  const privateKey = new Uint8Array(32).fill(0);
  const pathIndices = new Array(16).fill(0);

  const commitment = computeCommitment(
    poseidon,
    amount,
    owner,
    blinding,
    mintAddress,
  );
  const nullifier = computeNullifier(poseidon, commitment, 0, privateKey);

  return {
    amount,
    owner,
    blinding,
    privateKey,
    pathIndices,
    commitment,
    nullifier,
  };
}

// Helper: Create dummy note
export function createDummyNote(): {
  commitment: Uint8Array;
  nullifier: Uint8Array;
} {
  return {
    commitment: randomBytes32(),
    nullifier: randomBytes32(),
  };
}

// // Helper: Extract root from MerkleTreeAccount
// export function extractRootFromAccount(acc: any): Uint8Array {
//   const rootIndex = acc.rootIndex;
//   const rootHistory = acc.rootHistory;
//   if (!rootHistory || rootHistory.length === 0) {
//     throw new Error("Root history is empty");
//   }
//   const root = rootHistory[rootIndex];
//   return new Uint8Array(root);
// }

// Helper: Extract root from MerkleTreeAccount
export function extractRootFromAccount(acc: any): Uint8Array {
  // Anchor's zero-copy deserialization doesn't account for #[repr(C)] padding in Rust,
  // causing acc.root to have 5 leading zero bytes. We fix this by reading from acc.subtrees
  // to get the missing last 5 bytes.

  const root = acc.root;
  if (!root) {
    throw new Error("Root is undefined in account");
  }

  const rootBytes = new Uint8Array(root);

  // Check if we have the deserialization bug (5 leading zeros)
  const hasLeadingZeros =
    rootBytes[0] === 0 &&
    rootBytes[1] === 0 &&
    rootBytes[2] === 0 &&
    rootBytes[3] === 0 &&
    rootBytes[4] === 0 &&
    rootBytes[5] !== 0;

  if (hasLeadingZeros) {
    // The root field is shifted by 5 bytes due to struct padding.
    // Actual root bytes 0-26 are at positions 5-31 of rootBytes,
    // and the missing last 5 bytes are at the start of acc.subtrees[0]
    const subtree0 = new Uint8Array(acc.subtrees[0]);

    const corrected = new Uint8Array(32);
    corrected.set(rootBytes.slice(5, 32), 0); // Bytes 0-26 of root
    corrected.set(subtree0.slice(0, 5), 27); // Bytes 27-31 of root

    return corrected;
  }

  return rootBytes;
}

// =============================================================================
// Off-chain Merkle Tree
// =============================================================================

export class OffchainMerkleTree {
  private leaves: Map<number, Uint8Array> = new Map();
  private levels: number;
  private poseidon: any;
  private zeros: Uint8Array[] = [];

  constructor(levels: number, poseidon: any) {
    this.levels = levels;
    this.poseidon = poseidon;

    // Precompute zero hashes
    let currentZero = new Uint8Array(32).fill(0);
    this.zeros.push(currentZero);
    console.log(`Level 0 zero: ${bytesToBigIntBE(currentZero)}`);

    for (let i = 0; i < levels; i++) {
      const zeroField = poseidon.F.e(bytesToBigIntBE(currentZero));
      const hash = poseidon([zeroField, zeroField]);
      const hashBytes = poseidon.F.toString(hash, 16).padStart(64, "0");
      currentZero = Uint8Array.from(Buffer.from(hashBytes, "hex"));
      this.zeros.push(currentZero);
      console.log(`Level ${i + 1} zero: ${bytesToBigIntBE(currentZero)}`);
    }
  }

  getZeros(): Uint8Array[] {
    return this.zeros;
  }

  get nextIndex(): number {
    return this.leaves.size;
  }

  insert(commitment: Uint8Array): number {
    const index = this.leaves.size;
    this.leaves.set(index, commitment);
    return index;
  }

  getNode(level: number, index: number): Uint8Array {
    if (level === 0) {
      return this.leaves.get(index) || this.zeros[0];
    }

    const left = this.getNode(level - 1, 2 * index);
    const right = this.getNode(level - 1, 2 * index + 1);

    // Optimization: if both children are zeros, this node is zero[level]
    // We can check if they equal zeros[level-1]
    // But simple comparison of bytes is enough, or just rely on the fact that
    // if we don't have leaves in this subtree, it's a zero node.
    // Since we fill sequentially, we can check if the range [start, end] has any leaves.
    // But recursive is fine for small trees/tests.

    // Check if we are in a zero subtree
    // A node at (level, index) covers leaves from index*2^level to (index+1)*2^level - 1
    // If this range is >= this.leaves.size, it's all zeros.
    const rangeStart = index * Math.pow(2, level);
    if (rangeStart >= this.leaves.size) {
      return this.zeros[level];
    }

    const leftField = this.poseidon.F.e(bytesToBigIntBE(left));
    const rightField = this.poseidon.F.e(bytesToBigIntBE(right));
    const hash = this.poseidon([leftField, rightField]);

    const hashBytes = this.poseidon.F.toString(hash, 16).padStart(64, "0");
    return Uint8Array.from(Buffer.from(hashBytes, "hex"));
  }

  getMerkleProof(leafIndex: number): {
    pathElements: bigint[];
    pathIndices: number[];
  } {
    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];

    let currentIndex = leafIndex;

    for (let level = 0; level < this.levels; level++) {
      const isLeft = currentIndex % 2 === 0;
      const siblingIndex = isLeft ? currentIndex + 1 : currentIndex - 1;

      const sibling = this.getNode(level, siblingIndex);
      pathElements.push(bytesToBigIntBE(sibling));
      pathIndices.push(isLeft ? 0 : 1);

      currentIndex = Math.floor(currentIndex / 2);
    }

    return { pathElements, pathIndices };
  }

  getRoot(): Uint8Array {
    return this.getNode(this.levels, 0);
  }
}

// =============================================================================
// Proof Generation
// =============================================================================

/**
 * Convert snarkjs proof to Solana format
 */
export function convertProofToBytes(proof: any): {
  proofA: number[];
  proofB: number[];
  proofC: number[];
} {
  function bigintTo32BytesBE(x: bigint): number[] {
    const out = new Array(32).fill(0);
    let v = x;
    for (let i = 31; i >= 0; i--) {
      out[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    return out;
  }

  const ax = BigInt(proof.pi_a[0]);
  const ay = BigInt(proof.pi_a[1]);

  const bx0 = BigInt(proof.pi_b[0][0]);
  const bx1 = BigInt(proof.pi_b[0][1]);
  const by0 = BigInt(proof.pi_b[1][0]);
  const by1 = BigInt(proof.pi_b[1][1]);

  const cx = BigInt(proof.pi_c[0]);
  const cy = BigInt(proof.pi_c[1]);

  const proofA = [...bigintTo32BytesBE(ax), ...bigintTo32BytesBE(ay)];
  const proofB = [
    ...bigintTo32BytesBE(bx1),
    ...bigintTo32BytesBE(bx0),
    ...bigintTo32BytesBE(by1),
    ...bigintTo32BytesBE(by0),
  ];
  const proofC = [...bigintTo32BytesBE(cx), ...bigintTo32BytesBE(cy)];

  return { proofA, proofB, proofC };
}

export function packPathIndices(indices: number[]): bigint {
  let packed = 0n;
  for (let i = 0; i < indices.length; i++) {
    if (indices[i] === 1) {
      packed += 1n << BigInt(i);
    }
  }
  return packed;
}

/**
 * Generate transaction proof (2-in-2-out)
 */
export async function generateTransactionProof(inputs: {
  // Public inputs (8 total)
  root: Uint8Array;
  publicAmount: bigint;
  extDataHash: Uint8Array;
  mintAddress: PublicKey;
  inputNullifiers: [Uint8Array, Uint8Array];
  outputCommitments: [Uint8Array, Uint8Array];

  // Private inputs
  inputAmounts: [bigint, bigint];
  inputPrivateKeys: [Uint8Array, Uint8Array]; // Private keys for input UTXOs
  inputPublicKeys: [bigint, bigint]; // Derived public keys (Poseidon(privateKey))
  inputBlindings: [Uint8Array, Uint8Array];
  inputMerklePaths: [
    { pathElements: bigint[]; pathIndices: number[] },
    { pathElements: bigint[]; pathIndices: number[] },
  ];

  outputAmounts: [bigint, bigint];
  outputOwners: [bigint, bigint]; // Public keys as field elements
  outputBlindings: [Uint8Array, Uint8Array];
}) {
  // Format inputs for circuit - matching signal names from transaction.circom
  const circuitInputs = {
    // Public inputs (single values)
    root: bytesToBigIntBE(inputs.root).toString(),
    // For negative publicAmount (withdrawals), convert to field representation
    // In BN254 Fr field, negative numbers are represented as (modulus - abs(value))
    publicAmount: (() => {
      if (inputs.publicAmount < 0n) {
        const FR_MODULUS = BigInt(
          "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
        );
        return (FR_MODULUS + inputs.publicAmount).toString();
      }
      return inputs.publicAmount.toString();
    })(),
    extDataHash: bytesToBigIntBE(inputs.extDataHash).toString(),
    mintAddress: reduceToField(inputs.mintAddress.toBytes()).toString(),

    // Public inputs (arrays)
    inputNullifier: inputs.inputNullifiers.map((n) =>
      bytesToBigIntBE(n).toString(),
    ),
    outputCommitment: inputs.outputCommitments.map((c) =>
      bytesToBigIntBE(c).toString(),
    ),

    // Private inputs - input UTXOs (arrays)
    inAmount: inputs.inputAmounts.map((a) => a.toString()),
    inPubkey: inputs.inputPublicKeys.map((pk) => pk.toString()),
    inBlinding: inputs.inputBlindings.map((b) => bytesToBigIntBE(b).toString()),
    inPathIndex: inputs.inputMerklePaths.map((p) =>
      p.pathIndices.reduce((acc, bit, i) => acc + (bit << i), 0),
    ),
    inPathElements: inputs.inputMerklePaths.map((p) =>
      p.pathElements.map((e) => e.toString()),
    ),
    inPrivateKey: inputs.inputPrivateKeys.map((pk) =>
      bytesToBigIntBE(pk).toString(),
    ),

    // Private inputs - output UTXOs (arrays)
    outAmount: inputs.outputAmounts.map((a) => a.toString()),
    outPubkey: inputs.outputOwners.map((o) => o.toString()),
    outBlinding: inputs.outputBlindings.map((b) =>
      bytesToBigIntBE(b).toString(),
    ),
  };

  console.log(
    "Generating proof with inputs:",
    JSON.stringify(circuitInputs, null, 2),
  );

  // Generate proof
  let proof, publicSignals;
  try {
    ({ proof, publicSignals } = await groth16.fullProve(
      circuitInputs,
      WASM_PATH,
      ZKEY_PATH,
    ));
  } catch (e: any) {
    console.error("\n❌ Proof generation failed!");
    console.error("Error:", e.message);
    console.error("\n💡 Your circuit might expect different signal names.");
    console.error("Common patterns:");
    console.error("  1. Array syntax: inputNullifier[0], inputNullifier[1]");
    console.error("  2. Flat signals: inputNullifier0, inputNullifier1");
    console.error("  3. Different names: nullifier0, nullifier1");
    console.error(
      "\nPlease check your circuit's signal declarations in transaction.circom\n",
    );
    throw e;
  }

  console.log("✓ Proof generated successfully");
  console.log("Public signals:", publicSignals);

  // Verify proof off-chain
  const vKey = JSON.parse(fs.readFileSync(VK_PATH, "utf8"));
  const valid = await groth16.verify(vKey, publicSignals, proof);
  console.log("Proof valid off-chain?", valid);

  if (!valid) {
    throw new Error("Generated proof is invalid!");
  }

  return convertProofToBytes(proof);
}

/**
 * Fetches, parses, and verifies events from a transaction
 * Returns the count of verified events
 */
export async function fetchAndDisplayEvents(
  connection: Connection,
  txSignature: string,
  expectedMintAddress: PublicKey,
): Promise<number> {
  const tx = await connection.getTransaction(txSignature, {
    commitment: "confirmed",
    maxSupportedTransactionVersion: 0,
  });

  if (!tx || !tx.meta) {
    console.log("❌ Transaction not found");
    throw new Error("Transaction not found");
  }

  const logs = tx.meta.logMessages || [];
  console.log("\n=== Transaction Events ===");

  // Filter for event logs (Anchor emits as "Program data: <base64>")
  const eventLogs = logs.filter((log) => log.includes("Program data:"));
  console.log(`📊 Found ${eventLogs.length} event log entries`);

  // Event discriminators (first 8 bytes of event data)
  // CommitmentEvent discriminator: [89, 205, 140, 111, 36, 129, 217, 125]
  // NullifierSpent discriminator: [166, 111, 130, 54, 212, 115, 152, 215]

  let commitmentEventCount = 0;
  let nullifierSpentCount = 0;
  let mintAddressMatches = 0;

  eventLogs.forEach((log, i) => {
    // Extract base64 data from "Program data: <base64>"
    const parts = log.split("Program data: ");
    if (parts.length < 2) return;

    const base64Data = parts[1].trim();
    const eventData = Buffer.from(base64Data, "base64");

    if (eventData.length < 8) return;

    // Check discriminator
    const discriminator = Array.from(eventData.subarray(0, 8));

    // CommitmentEvent: commitment[32] + leaf_index[8] + new_root[32] + timestamp[8] + mint_address[32]
    // Total: 8 (discriminator) + 32 + 8 + 32 + 8 + 32 = 120 bytes
    if (discriminator.join(",") === "89,205,140,111,36,129,217,125") {
      commitmentEventCount++;
      console.log(`\nEvent ${i + 1}: CommitmentEvent`);

      if (eventData.length >= 120) {
        // Extract mint_address (last 32 bytes of the data)
        const mintAddressBytes = eventData.subarray(88, 120);
        const mintAddress = new PublicKey(mintAddressBytes);

        console.log(
          `   Commitment: ${eventData
            .subarray(8, 40)
            .toString("hex")
            .slice(0, 20)}...`,
        );
        console.log(`   Leaf Index: ${eventData.readBigUInt64LE(40)}`);
        console.log(`   Mint Address: ${mintAddress.toString()}`);

        if (mintAddress.equals(expectedMintAddress)) {
          console.log(`   ✅ Mint address matches expected!`);
          mintAddressMatches++;
        } else {
          console.log(`   ❌ Mint address MISMATCH!`);
          console.log(`      Expected: ${expectedMintAddress.toString()}`);
          console.log(`      Got:      ${mintAddress.toString()}`);
          throw new Error(
            `Mint address mismatch in CommitmentEvent: expected ${expectedMintAddress.toString()}, got ${mintAddress.toString()}`,
          );
        }
      }
    }

    // NullifierSpent: nullifier[32] + timestamp[8] + mint_address[32]
    // Total: 8 (discriminator) + 32 + 8 + 32 = 80 bytes
    else if (discriminator.join(",") === "166,111,130,54,212,115,152,215") {
      nullifierSpentCount++;
      console.log(`\nEvent ${i + 1}: NullifierSpent`);

      if (eventData.length >= 80) {
        // Extract mint_address (last 32 bytes of the data)
        const mintAddressBytes = eventData.subarray(48, 80);
        const mintAddress = new PublicKey(mintAddressBytes);

        console.log(
          `   Nullifier: ${eventData
            .subarray(8, 40)
            .toString("hex")
            .slice(0, 20)}...`,
        );
        console.log(`   Mint Address: ${mintAddress.toString()}`);

        if (mintAddress.equals(expectedMintAddress)) {
          console.log(`   ✅ Mint address matches expected!`);
          mintAddressMatches++;
        } else {
          console.log(`   ❌ Mint address MISMATCH!`);
          console.log(`      Expected: ${expectedMintAddress.toString()}`);
          console.log(`      Got:      ${mintAddress.toString()}`);
          throw new Error(
            `Mint address mismatch in NullifierSpent: expected ${expectedMintAddress.toString()}, got ${mintAddress.toString()}`,
          );
        }
      }
    }
  });

  console.log(`\n📊 Event Summary:`);
  console.log(`   CommitmentEvent count: ${commitmentEventCount}`);
  console.log(`   NullifierSpent count: ${nullifierSpentCount}`);
  console.log(
    `   Mint addresses verified: ${mintAddressMatches}/${
      commitmentEventCount + nullifierSpentCount
    }`,
  );
  console.log(`   Expected mint_address: ${expectedMintAddress.toString()}`);

  // Assert that we found the expected events and all mint addresses match
  const totalEvents = commitmentEventCount + nullifierSpentCount;
  if (totalEvents === 0) {
    throw new Error("No events found in transaction");
  }

  if (mintAddressMatches !== totalEvents) {
    throw new Error(
      `Mint address verification failed: ${mintAddressMatches}/${totalEvents} events matched`,
    );
  }

  console.log(`✅ All event mint_address fields verified successfully!`);
  console.log("=== End Events ===\n");

  return totalEvents;
}

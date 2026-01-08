// tests/privacy-pool.test.ts
//
// UTXO Model (2-in-2-out) with real ZK proofs
//

import "mocha";
import {
  AnchorProvider,
  BN,
  setProvider,
  Wallet,
  workspace,
} from "@coral-xyz/anchor";
import {
  PublicKey,
  Keypair,
  SystemProgram,
  LAMPORTS_PER_SOL,
  SendTransactionError,
  Connection,
  ComputeBudgetProgram,
  Transaction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  createMint,
  getOrCreateAssociatedTokenAccount,
  mintTo,
  getAssociatedTokenAddress,
} from "@solana/spl-token";
import fs from "fs";
import os from "os";
import path from "path";
import { buildPoseidon } from "circomlibjs";
import { groth16 } from "snarkjs";
import { getPoolPdas } from "@zkprivacysol/sdk-core";

// =============================================================================
// Simple Note Storage (inline for test compatibility)
// =============================================================================

interface DepositNote {
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

class InMemoryNoteStorage {
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

const WASM_PATH = path.join(
  process.cwd(),
  "zk/circuits/transaction/transaction_js/transaction.wasm"
);
const ZKEY_PATH = path.join(
  process.cwd(),
  "zk/circuits/transaction/transaction_final.zkey"
);
const VK_PATH = path.join(
  process.cwd(),
  "zk/circuits/transaction/transaction_verification_key.json"
);

// =============================================================================
// Helper Functions
// =============================================================================

function makeProvider(): AnchorProvider {
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

async function airdropAndConfirm(
  provider: AnchorProvider,
  pubkey: PublicKey,
  amount: number
) {
  const sig = await provider.connection.requestAirdrop(pubkey, amount);
  const latestBlockhash = await provider.connection.getLatestBlockhash();
  await provider.connection.confirmTransaction({
    signature: sig,
    ...latestBlockhash,
  });
}

function randomBytes32(): Uint8Array {
  return Keypair.generate().publicKey.toBytes();
}

// Helper: Create and fund SPL token account
async function createAndFundTokenAccount(
  provider: AnchorProvider,
  mint: PublicKey,
  owner: PublicKey,
  amount: number
): Promise<PublicKey> {
  const tokenAccount = await getOrCreateAssociatedTokenAccount(
    provider.connection,
    (provider.wallet as Wallet).payer,
    mint,
    owner
  );

  if (amount > 0) {
    await mintTo(
      provider.connection,
      (provider.wallet as Wallet).payer,
      mint,
      tokenAccount.address,
      (provider.wallet as Wallet).payer,
      amount
    );
  }

  return tokenAccount.address;
}

function bytesToBigIntBE(bytes: Uint8Array): bigint {
  return BigInt("0x" + Buffer.from(bytes).toString("hex"));
}

// Helper: Reduce value modulo BN254 Fr field
function reduceToField(bytes: Uint8Array): bigint {
  const FR_MODULUS = BigInt(
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
  );
  const value = BigInt("0x" + Buffer.from(bytes).toString("hex"));
  return value % FR_MODULUS;
}

// Helper: Derive public key from private key: pubkey = Poseidon(privateKey)
function derivePublicKey(poseidon: any, privateKey: Uint8Array): bigint {
  const privateKeyField = poseidon.F.e(bytesToBigIntBE(privateKey));
  const publicKeyHash = poseidon([privateKeyField]);
  return poseidon.F.toObject(publicKeyHash);
}

// Helper: Compute extDataHash = Poseidon(Poseidon(recipient, relayer), Poseidon(fee, refund))
function computeExtDataHash(
  poseidon: any,
  extData: {
    recipient: PublicKey;
    relayer: PublicKey;
    fee: BN;
    refund: BN;
  }
): Uint8Array {
  const recipientField = poseidon.F.e(
    reduceToField(extData.recipient.toBytes())
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
function computeCommitment(
  poseidon: any,
  amount: bigint,
  ownerPubkey: bigint, // Already derived from private key
  blinding: Uint8Array,
  mintAddress: PublicKey
): Uint8Array {
  const amountField = poseidon.F.e(amount.toString());
  const ownerField = poseidon.F.e(ownerPubkey.toString());
  const blindingField = poseidon.F.e(bytesToBigIntBE(blinding));
  const mintField = poseidon.F.e(
    reduceToField(mintAddress.toBytes()).toString()
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
function computeNullifier(
  poseidon: any,
  commitment: Uint8Array,
  leafIndex: number,
  privateKey: Uint8Array
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

function createDummyInput(
  poseidon: any,
  owner: bigint,
  mintAddress: PublicKey
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
    mintAddress
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
function createDummyNote(): { commitment: Uint8Array; nullifier: Uint8Array } {
  return {
    commitment: randomBytes32(),
    nullifier: randomBytes32(),
  };
}

// Helper: Extract root from MerkleTreeAccount
function extractRootFromAccount(acc: any): Uint8Array {
  const rootIndex = acc.rootIndex;
  const rootHistory = acc.rootHistory;
  if (!rootHistory || rootHistory.length === 0) {
    throw new Error("Root history is empty");
  }
  const root = rootHistory[rootIndex];
  return new Uint8Array(root);
}

// =============================================================================
// Off-chain Merkle Tree
// =============================================================================

class OffchainMerkleTree {
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
function convertProofToBytes(proof: any): {
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

function packPathIndices(indices: number[]): bigint {
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
async function generateTransactionProof(inputs: {
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
    { pathElements: bigint[]; pathIndices: number[] }
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
          "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
        );
        return (FR_MODULUS + inputs.publicAmount).toString();
      }
      return inputs.publicAmount.toString();
    })(),
    extDataHash: bytesToBigIntBE(inputs.extDataHash).toString(),
    mintAddress: reduceToField(inputs.mintAddress.toBytes()).toString(),

    // Public inputs (arrays)
    inputNullifier: inputs.inputNullifiers.map((n) =>
      bytesToBigIntBE(n).toString()
    ),
    outputCommitment: inputs.outputCommitments.map((c) =>
      bytesToBigIntBE(c).toString()
    ),

    // Private inputs - input UTXOs (arrays)
    inAmount: inputs.inputAmounts.map((a) => a.toString()),
    inPubkey: inputs.inputPublicKeys.map((pk) => pk.toString()),
    inBlinding: inputs.inputBlindings.map((b) => bytesToBigIntBE(b).toString()),
    inPathIndex: inputs.inputMerklePaths.map((p) =>
      p.pathIndices.reduce((acc, bit, i) => acc + (bit << i), 0)
    ),
    inPathElements: inputs.inputMerklePaths.map((p) =>
      p.pathElements.map((e) => e.toString())
    ),
    inPrivateKey: inputs.inputPrivateKeys.map((pk) =>
      bytesToBigIntBE(pk).toString()
    ),

    // Private inputs - output UTXOs (arrays)
    outAmount: inputs.outputAmounts.map((a) => a.toString()),
    outPubkey: inputs.outputOwners.map((o) => o.toString()),
    outBlinding: inputs.outputBlindings.map((b) =>
      bytesToBigIntBE(b).toString()
    ),
  };

  console.log(
    "Generating proof with inputs:",
    JSON.stringify(circuitInputs, null, 2)
  );

  // Generate proof
  let proof, publicSignals;
  try {
    ({ proof, publicSignals } = await groth16.fullProve(
      circuitInputs,
      WASM_PATH,
      ZKEY_PATH
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
      "\nPlease check your circuit's signal declarations in transaction.circom\n"
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

// =============================================================================
// Main Test Suite
// =============================================================================

// describe("Privacy Pool - UTXO Model (2-in-2-out) with Real Proofs", () => {
//   const provider = makeProvider();
//   setProvider(provider);

//   const wallet = provider.wallet as Wallet;
//   const program: any = workspace.PrivacyPool as any;

//   let poseidon: any;
//   let config: PublicKey;
//   let vault: PublicKey;
//   let noteTree: PublicKey;
//   let nullifiers: PublicKey;

//   const SOL_MINT = PublicKey.default;
//   const feeBps = 50; // 0.5%

//   // Off-chain tree
//   let offchainTree: OffchainMerkleTree;

//   // ⚠️ SECURITY WARNING: In production, NEVER store notes in plain variables!
//   // Use encrypted storage (see tests/note-manager.example.ts for AES-256 encryption)
//   // Or use InMemoryNoteStorage which demonstrates proper note lifecycle management
//   const noteStorage = new InMemoryNoteStorage();
//   let depositNoteId: string | null = null; // Store ID instead of raw note

//   // =============================================================================
//   // Setup
//   // =============================================================================

//   before(async () => {
//     console.log("\n🔧 Setting up test environment...\n");

//     // Initialize Poseidon
//     poseidon = await buildPoseidon();
//     offchainTree = new OffchainMerkleTree(16, poseidon);

//     // Get PDAs
//     const pdas = getPoolPdas(program.programId);
//     config = pdas.config;
//     vault = pdas.vault;
//     noteTree = pdas.noteTree;
//     nullifiers = pdas.nullifiers;

//     console.log("Program ID:", program.programId.toBase58());
//     console.log("Config PDA:", config.toBase58());
//     console.log("Vault PDA:", vault.toBase58());

//     // Airdrop to admin
//     await airdropAndConfirm(provider, wallet.publicKey, 10 * LAMPORTS_PER_SOL);
//   });

//   it("initializes the privacy pool (UTXO model)", async () => {
//     try {
//       await (program.methods as any)
//         .initialize(feeBps, SOL_MINT)
//         .accounts({
//           config,
//           vault,
//           noteTree,
//           nullifiers,
//           admin: wallet.publicKey,
//           systemProgram: SystemProgram.programId,
//         })
//         .rpc();

//       const configAcc = await (program.account as any).privacyConfig.fetch(
//         config
//       );
//       console.log("✅ Pool initialized");
//       console.log(`   Fee BPS: ${configAcc.feeBps}`);
//       console.log(
//         `   Min Withdrawal Fee: ${configAcc.minWithdrawalFee} lamports`
//       );
//       console.log(`   Max Deposit: ${configAcc.maxDepositAmount} lamports`);
//     } catch (e: any) {
//       if (e instanceof SendTransactionError) {
//         const logs = await e.getLogs(provider.connection);
//         console.error("Initialize failed:", logs);
//       }
//       throw e;
//     }
//   });

//   // =============================================================================
//   // Deposit Test
//   // =============================================================================

//   it("deposits 1.5 SOL using transact with real proof", async () => {
//     // Generate sender (who will sign and pay for the deposit)
//     const sender = Keypair.generate();

//     // Airdrop funds to sender
//     console.log("\n🎁 Airdropping funds for deposit test...");
//     console.log(`   Sender:  ${sender.publicKey.toBase58()}`);
//     await airdropAndConfirm(provider, sender.publicKey, 3 * LAMPORTS_PER_SOL);

//     // For deposit, sender acts as their own relayer (self-deposit)
//     // Register sender as relayer
//     await (program.methods as any)
//       .addRelayer(sender.publicKey)
//       .accounts({ config, admin: wallet.publicKey })
//       .rpc();

//     const depositAmount = BigInt(Math.floor(1.5 * LAMPORTS_PER_SOL));

//     // 💰 BALANCE CHECK: Before deposit
//     const beforeSender = BigInt(
//       await provider.connection.getBalance(sender.publicKey)
//     );
//     const beforeVault = BigInt(await provider.connection.getBalance(vault));

//     console.log("\n💰 Balance Check - Before Deposit:");
//     console.log(`   Sender/Relayer: ${sender.publicKey.toBase58()}`);
//     console.log(
//       `                   ${beforeSender} lamports (${
//         Number(beforeSender) / LAMPORTS_PER_SOL
//       } SOL)`
//     );
//     console.log(`   Vault:          ${vault.toBase58()}`);
//     console.log(
//       `                   ${beforeVault} lamports (${
//         Number(beforeVault) / LAMPORTS_PER_SOL
//       } SOL)`
//     );
//     console.log(
//       `   Deposit amount: ${depositAmount} lamports (${
//         Number(depositAmount) / LAMPORTS_PER_SOL
//       } SOL)`
//     );

//     // Generate keypair for the note
//     const privateKey = randomBytes32();
//     const publicKey = derivePublicKey(poseidon, privateKey);
//     const blinding = randomBytes32();

//     // Generate commitment using the derived public key
//     const commitment = computeCommitment(
//       poseidon,
//       depositAmount,
//       publicKey,
//       blinding,
//       SOL_MINT
//     );

//     // Create dummy output (will be inserted as second output on-chain)
//     const dummyOutputPrivKey = randomBytes32();
//     const dummyOutputPubKey = derivePublicKey(poseidon, dummyOutputPrivKey);
//     const dummyOutputBlinding = randomBytes32();
//     const dummyOutputAmount = 0n;

//     const dummyOutputCommitment = computeCommitment(
//       poseidon,
//       dummyOutputAmount,
//       dummyOutputPubKey,
//       dummyOutputBlinding,
//       SOL_MINT
//     );

//     // Insert into off-chain tree - INSERT BOTH outputs to match on-chain behavior
//     const leafIndex = offchainTree.insert(commitment);
//     offchainTree.insert(dummyOutputCommitment); // Second output also gets inserted on-chain

//     const merklePath = offchainTree.getMerkleProof(leafIndex);
//     const nullifier = computeNullifier(
//       poseidon,
//       commitment,
//       leafIndex,
//       privateKey
//     );

//     // For deposit: use dummy inputs - MUST BE INTERNALLY CONSISTENT
//     // The circuit checks: nullifier == Poseidon(commitment, pathIndex, signature)
//     // So we cannot just use random bytes for nullifier if we pass specific private keys/blindings as witness.

//     // 1. Generate Witness Data
//     const dummyPrivKey0 = randomBytes32();
//     const dummyPrivKey1 = randomBytes32();
//     const dummyBlinding0 = randomBytes32();
//     const dummyBlinding1 = randomBytes32();

//     const dummyPubKey0 = derivePublicKey(poseidon, dummyPrivKey0);
//     const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);

//     // 2. Compute Commitments for Dummy Inputs
//     const dummyCommitment0 = computeCommitment(
//       poseidon,
//       0n,
//       dummyPubKey0,
//       dummyBlinding0,
//       SOL_MINT
//     );
//     const dummyCommitment1 = computeCommitment(
//       poseidon,
//       0n,
//       dummyPubKey1,
//       dummyBlinding1,
//       SOL_MINT
//     );

//     // 3. Compute Nullifiers for Dummy Inputs (pathIndex = 0)
//     const dummyNullifier0 = computeNullifier(
//       poseidon,
//       dummyCommitment0,
//       0,
//       dummyPrivKey0
//     );
//     const dummyNullifier1 = computeNullifier(
//       poseidon,
//       dummyCommitment1,
//       0,
//       dummyPrivKey1
//     );

//     // --- Restore context variables (extData, onchainRoot) ---
//     const extData = {
//       recipient: sender.publicKey,
//       relayer: sender.publicKey, // Sender is their own relayer for deposit
//       fee: new BN(0),
//       refund: new BN(0),
//     };
//     const extDataHash = computeExtDataHash(poseidon, extData);

//     const noteTreeAcc: any = await (
//       program.account as any
//     ).merkleTreeAccount.fetch(noteTree);
//     const onchainRoot = extractRootFromAccount(noteTreeAcc);
//     // ---------------------------------------------------------

//     // Generate real proof
//     const zeros = offchainTree.getZeros();
//     const zeroPathElements = zeros.slice(0, 16).map((z) => bytesToBigIntBE(z));

//     const proof = await generateTransactionProof({
//       root: onchainRoot,
//       publicAmount: depositAmount, // Positive for deposit (adds to pool)
//       extDataHash,
//       mintAddress: SOL_MINT,
//       inputNullifiers: [dummyNullifier0, dummyNullifier1],
//       outputCommitments: [commitment, dummyOutputCommitment],

//       // Private inputs (dummy inputs for deposit)
//       inputAmounts: [0n, 0n],
//       inputPrivateKeys: [dummyPrivKey0, dummyPrivKey1],
//       inputPublicKeys: [dummyPubKey0, dummyPubKey1],
//       inputBlindings: [dummyBlinding0, dummyBlinding1],
//       inputMerklePaths: [
//         {
//           pathElements: zeroPathElements,
//           pathIndices: new Array(16).fill(0),
//         },
//         {
//           pathElements: zeroPathElements,
//           pathIndices: new Array(16).fill(0),
//         },
//       ],

//       // Output UTXOs
//       outputAmounts: [depositAmount, dummyOutputAmount],
//       outputOwners: [publicKey, dummyOutputPubKey],
//       outputBlindings: [blinding, dummyOutputBlinding],
//     });

//     const [nullifierMarker0] = PublicKey.findProgramAddressSync(
//       [Buffer.from("nullifier_v3"), Buffer.from(dummyNullifier0)],
//       program.programId
//     );
//     const [nullifierMarker1] = PublicKey.findProgramAddressSync(
//       [Buffer.from("nullifier_v3"), Buffer.from(dummyNullifier1)],
//       program.programId
//     );

//     const publicAmount = new BN(depositAmount.toString());

//     try {
//       const tx = await (program.methods as any)
//         .transact(
//           Array.from(onchainRoot),
//           publicAmount,
//           Array.from(extDataHash),
//           SOL_MINT,
//           Array.from(dummyNullifier0),
//           Array.from(dummyNullifier1),
//           Array.from(commitment),
//           Array.from(dummyOutputCommitment),
//           extData,
//           proof
//         )
//         .accounts({
//           config,
//           vault,
//           noteTree,
//           nullifiers,
//           nullifierMarker0,
//           nullifierMarker1,
//           relayer: sender.publicKey,
//           recipient: sender.publicKey,
//           vaultTokenAccount: sender.publicKey, // Placeholder for SOL
//           userTokenAccount: sender.publicKey, // Placeholder for SOL
//           recipientTokenAccount: sender.publicKey, // Placeholder for SOL
//           relayerTokenAccount: sender.publicKey, // Placeholder for SOL
//           tokenProgram: sender.publicKey, // Placeholder for SOL
//           systemProgram: SystemProgram.programId,
//         })
//         .signers([sender])
//         .transaction();

//       // Add compute budget instructions
//       const modifyComputeUnits = ComputeBudgetProgram.setComputeUnitLimit({
//         units: 1_400_000,
//       });
//       const addPriorityFee = ComputeBudgetProgram.setComputeUnitPrice({
//         microLamports: 1,
//       });

//       const transaction = new Transaction();
//       transaction.add(modifyComputeUnits);
//       transaction.add(addPriorityFee);
//       transaction.add(tx);

//       await provider.sendAndConfirm(transaction, [sender]);
//     } catch (e: any) {
//       if (e instanceof SendTransactionError) {
//         const logs = await e.getLogs(provider.connection);
//         console.error("Deposit failed:", logs);
//       }
//       throw e;
//     }

//     // 💰 BALANCE CHECK: After deposit
//     const afterSender = BigInt(
//       await provider.connection.getBalance(sender.publicKey)
//     );
//     const afterVault = BigInt(await provider.connection.getBalance(vault));

//     const senderSpent = beforeSender - afterSender;
//     const vaultReceived = afterVault - beforeVault;

//     console.log("\n💰 Balance Check - After Deposit:");
//     console.log(`   Sender/Relayer: ${sender.publicKey.toBase58()}`);
//     console.log(
//       `                   ${afterSender} lamports (${
//         Number(afterSender) / LAMPORTS_PER_SOL
//       } SOL)`
//     );
//     console.log(`   Vault:          ${vault.toBase58()}`);
//     console.log(
//       `                   ${afterVault} lamports (${
//         Number(afterVault) / LAMPORTS_PER_SOL
//       } SOL)`
//     );

//     console.log("\n📊 Balance Changes:");
//     console.log(
//       `   Sender spent:     ${senderSpent} lamports (${depositAmount} deposit + ${
//         senderSpent - depositAmount
//       } tx fees)`
//     );
//     console.log(`   Vault received:   ${vaultReceived} lamports`);
//     console.log(`   Expected deposit: ${depositAmount} lamports`);

//     // Verify vault received exactly the deposit amount
//     if (vaultReceived !== depositAmount) {
//       throw new Error(
//         `Vault delta mismatch: expected ${depositAmount}, got ${vaultReceived}`
//       );
//     }

//     // Verify sender paid deposit + tx fees
//     if (senderSpent < depositAmount) {
//       throw new Error(
//         `Sender spent too little: expected at least ${depositAmount}, got ${senderSpent}`
//       );
//     }

//     console.log("\n✅ Balance verification passed!");
//     console.log(`   ✓ Vault received exactly ${depositAmount} lamports`);
//     console.log(
//       `   ✓ Sender paid ${senderSpent} lamports (${depositAmount} deposit + ${
//         senderSpent - depositAmount
//       } tx fees)`
//     );

//     // Recompute Merkle path now that tree has both outputs inserted
//     const updatedMerklePath = offchainTree.getMerkleProof(leafIndex);

//     // 💾 Save note for withdrawal using secure storage
//     // ⚠️ CRITICAL: This note contains secrets that prove ownership!
//     //    - privateKey: proves you own the deposit
//     //    - blinding: needed to reconstruct commitment
//     //    If someone steals these, they can spend your deposit!
//     const noteToSave: DepositNote = {
//       amount: depositAmount,
//       commitment,
//       nullifier,
//       blinding,
//       privateKey,
//       publicKey,
//       leafIndex,
//       merklePath: updatedMerklePath,
//       mintAddress: SOL_MINT,
//     };

//     depositNoteId = noteStorage.save(noteToSave);

//     console.log("\n🔒 Note Security Check:");
//     console.log(`   ✅ Note saved with ID: ${depositNoteId}`);
//     console.log(`   ⚠️  privateKey is SECRET - never share!`);
//     console.log(`   ⚠️  blinding is SECRET - never share!`);
//     console.log(
//       `   ✅ commitment is public: ${Buffer.from(commitment)
//         .toString("hex")
//         .slice(0, 20)}...`
//     );
//     console.log(`   💡 In production: use encrypted storage (NoteManager)`);

//     console.log("\n✅ Deposit successful");
//     console.log(`   Amount: ${depositAmount} lamports`);
//     console.log(`   Leaf index: ${leafIndex}`);
//   });

//   // =============================================================================
//   // Withdrawal Test
//   // =============================================================================

//   it("withdraws via relayer with fee (real proof)", async () => {
//     if (!depositNoteId) {
//       throw new Error("No deposit note - deposit test must run first");
//     }

//     // 🔓 Retrieve note from secure storage
//     const depositNote = noteStorage.get(depositNoteId);
//     if (!depositNote) {
//       throw new Error(`Note not found: ${depositNoteId}`);
//     }

//     console.log("\n🔓 Retrieved note from storage:");
//     console.log(`   Note ID: ${depositNoteId}`);
//     console.log(`   Amount: ${depositNote.amount} lamports`);
//     console.log(`   Leaf Index: ${depositNote.leafIndex}`);

//     // Generate relayer and recipient keypairs
//     const relayer = Keypair.generate();
//     const recipient = Keypair.generate();

//     // Airdrop funds to relayer and recipient
//     console.log("\n🎁 Airdropping funds for withdrawal test...");
//     console.log(`   Relayer:   ${relayer.publicKey.toBase58()}`);
//     await airdropAndConfirm(provider, relayer.publicKey, 2 * LAMPORTS_PER_SOL);
//     console.log(`   Recipient: ${recipient.publicKey.toBase58()}`);
//     await airdropAndConfirm(
//       provider,
//       recipient.publicKey,
//       0.2 * LAMPORTS_PER_SOL
//     );

//     // Register relayer
//     await (program.methods as any)
//       .addRelayer(relayer.publicKey)
//       .accounts({ config, admin: wallet.publicKey })
//       .rpc();

//     const withdrawAmount = depositNote.amount;
//     const fee = (depositNote.amount * BigInt(feeBps)) / 10_000n;
//     const toRecipient = depositNote.amount - fee;

//     // 💰 BALANCE CHECK: Before withdrawal
//     const beforeVaultWithdraw = BigInt(
//       await provider.connection.getBalance(vault)
//     );
//     const beforeRelayerWithdraw = BigInt(
//       await provider.connection.getBalance(relayer.publicKey)
//     );
//     const beforeRecipientWithdraw = BigInt(
//       await provider.connection.getBalance(recipient.publicKey)
//     );

//     console.log("\n💰 Balance Check - Before Withdrawal:");
//     console.log(`   Vault:     ${vault.toBase58()}`);
//     console.log(
//       `              ${beforeVaultWithdraw} lamports (${
//         Number(beforeVaultWithdraw) / LAMPORTS_PER_SOL
//       } SOL)`
//     );
//     console.log(`   Relayer:   ${relayer.publicKey.toBase58()}`);
//     console.log(
//       `              ${beforeRelayerWithdraw} lamports (${
//         Number(beforeRelayerWithdraw) / LAMPORTS_PER_SOL
//       } SOL)`
//     );
//     console.log(`   Recipient: ${recipient.publicKey.toBase58()}`);
//     console.log(
//       `              ${beforeRecipientWithdraw} lamports (${
//         Number(beforeRecipientWithdraw) / LAMPORTS_PER_SOL
//       } SOL)`
//     );
//     console.log(
//       `   Withdrawal amount: ${withdrawAmount} lamports (${
//         Number(withdrawAmount) / LAMPORTS_PER_SOL
//       } SOL)`
//     );
//     console.log(`   Fee (${feeBps} BPS): ${fee} lamports`);
//     console.log(`   Expected to recipient: ${toRecipient} lamports`);

//     const publicAmount = new BN(-withdrawAmount.toString());

//     const extData = {
//       recipient: recipient.publicKey,
//       relayer: relayer.publicKey,
//       fee: new BN(fee.toString()),
//       refund: new BN(0),
//     };
//     const extDataHash = computeExtDataHash(poseidon, extData);

//     const noteTreeAcc: any = await (
//       program.account as any
//     ).merkleTreeAccount.fetch(noteTree);
//     const onchainRoot = extractRootFromAccount(noteTreeAcc);

//     // Debug: Check root synchronization
//     const offchainRoot = offchainTree.getRoot();
//     console.log("\n🔍 Withdrawal - Root verification:");
//     console.log("   On-chain root: ", bytesToBigIntBE(onchainRoot).toString());
//     console.log("   Off-chain root:", bytesToBigIntBE(offchainRoot).toString());
//     console.log(
//       "   Deposit commitment:",
//       bytesToBigIntBE(depositNote.commitment).toString()
//     );
//     console.log("   Leaf index:", depositNote.leafIndex);

//     if (bytesToBigIntBE(onchainRoot) !== bytesToBigIntBE(offchainRoot)) {
//       console.warn("   ⚠️  WARNING: Roots don't match!");
//     }

//     // Recompute Merkle path from off-chain tree (now includes deposited note)
//     const updatedMerklePath = offchainTree.getMerkleProof(
//       depositNote.leafIndex
//     );

//     console.log(
//       "   Updated path[0]:",
//       updatedMerklePath.pathElements[0].toString()
//     );
//     console.log("   Path indices:", updatedMerklePath.pathIndices);

//     // Create consistent dummy input (second input)
//     const dummyPrivKey1 = randomBytes32();
//     const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);
//     const dummyBlinding1 = randomBytes32();

//     const dummyCommitment1 = computeCommitment(
//       poseidon,
//       0n,
//       dummyPubKey1,
//       dummyBlinding1,
//       SOL_MINT
//     );

//     const dummyNullifier1 = computeNullifier(
//       poseidon,
//       dummyCommitment1,
//       0,
//       dummyPrivKey1
//     );

//     // Create consistent dummy outputs
//     const dummyOutputPrivKey0 = randomBytes32();
//     const dummyOutputPubKey0 = derivePublicKey(poseidon, dummyOutputPrivKey0);
//     const dummyOutputBlinding0 = randomBytes32();
//     const dummyOutputCommitment0 = computeCommitment(
//       poseidon,
//       0n,
//       dummyOutputPubKey0,
//       dummyOutputBlinding0,
//       SOL_MINT
//     );

//     const dummyOutputPrivKey1 = randomBytes32();
//     const dummyOutputPubKey1 = derivePublicKey(poseidon, dummyOutputPrivKey1);
//     const dummyOutputBlinding1 = randomBytes32();
//     const dummyOutputCommitment1 = computeCommitment(
//       poseidon,
//       0n,
//       dummyOutputPubKey1,
//       dummyOutputBlinding1,
//       SOL_MINT
//     );

//     // Get zero path for dummy input
//     const zeros = offchainTree.getZeros();
//     const zeroPathElements = zeros.slice(0, 16).map((z) => bytesToBigIntBE(z));

//     // Generate real proof
//     const proof = await generateTransactionProof({
//       root: onchainRoot,
//       publicAmount: -withdrawAmount, // Negative for withdrawal (removes from pool)
//       extDataHash,
//       mintAddress: SOL_MINT,
//       inputNullifiers: [depositNote.nullifier, dummyNullifier1],
//       outputCommitments: [dummyOutputCommitment0, dummyOutputCommitment1],

//       // Private inputs
//       inputAmounts: [depositNote.amount, 0n],
//       inputPrivateKeys: [depositNote.privateKey, dummyPrivKey1],
//       inputPublicKeys: [depositNote.publicKey, dummyPubKey1],
//       inputBlindings: [depositNote.blinding, dummyBlinding1],
//       inputMerklePaths: [
//         updatedMerklePath,
//         {
//           pathElements: zeroPathElements,
//           pathIndices: new Array(16).fill(0),
//         },
//       ],

//       outputAmounts: [0n, 0n],
//       outputOwners: [dummyOutputPubKey0, dummyOutputPubKey1],
//       outputBlindings: [dummyOutputBlinding0, dummyOutputBlinding1],
//     });

//     const [nullifierMarker0] = PublicKey.findProgramAddressSync(
//       [Buffer.from("nullifier_v3"), Buffer.from(depositNote.nullifier)],
//       program.programId
//     );
//     const [nullifierMarker1] = PublicKey.findProgramAddressSync(
//       [Buffer.from("nullifier_v3"), Buffer.from(dummyNullifier1)],
//       program.programId
//     );

//     try {
//       const tx = await (program.methods as any)
//         .transact(
//           Array.from(onchainRoot),
//           publicAmount,
//           Array.from(extDataHash),
//           SOL_MINT,
//           Array.from(depositNote.nullifier),
//           Array.from(dummyNullifier1),
//           Array.from(dummyOutputCommitment0),
//           Array.from(dummyOutputCommitment1),
//           extData,
//           proof
//         )
//         .accounts({
//           config,
//           vault,
//           noteTree,
//           nullifiers,
//           nullifierMarker0,
//           nullifierMarker1,
//           relayer: relayer.publicKey,
//           recipient: recipient.publicKey,
//           vaultTokenAccount: relayer.publicKey, // Placeholder for SOL
//           userTokenAccount: relayer.publicKey, // Placeholder for SOL
//           recipientTokenAccount: relayer.publicKey, // Placeholder for SOL
//           relayerTokenAccount: relayer.publicKey, // Placeholder for SOL
//           tokenProgram: relayer.publicKey, // Placeholder for SOL
//           systemProgram: SystemProgram.programId,
//         })
//         .signers([relayer])
//         .transaction();

//       // Add compute budget instructions
//       const modifyComputeUnits = ComputeBudgetProgram.setComputeUnitLimit({
//         units: 1_400_000,
//       });
//       const addPriorityFee = ComputeBudgetProgram.setComputeUnitPrice({
//         microLamports: 1,
//       });

//       const transaction = new Transaction();
//       transaction.add(modifyComputeUnits);
//       transaction.add(addPriorityFee);
//       transaction.add(tx);

//       await provider.sendAndConfirm(transaction, [relayer]);

//       // Insert withdrawal outputs into offchain tree (to stay in sync with on-chain)
//       offchainTree.insert(dummyOutputCommitment0);
//       offchainTree.insert(dummyOutputCommitment1);
//     } catch (e: any) {
//       if (e instanceof SendTransactionError) {
//         const logs = await e.getLogs(provider.connection);
//         console.error("Withdrawal failed:", logs);
//       }
//       throw e;
//     }

//     // 💰 BALANCE CHECK: After withdrawal
//     const afterVaultWithdraw = BigInt(
//       await provider.connection.getBalance(vault)
//     );
//     const afterRelayerWithdraw = BigInt(
//       await provider.connection.getBalance(relayer.publicKey)
//     );
//     const afterRecipientWithdraw = BigInt(
//       await provider.connection.getBalance(recipient.publicKey)
//     );

//     const vaultPaid = beforeVaultWithdraw - afterVaultWithdraw;
//     const relayerReceived = afterRelayerWithdraw - beforeRelayerWithdraw;
//     const recipientReceived = afterRecipientWithdraw - beforeRecipientWithdraw;

//     console.log("\n💰 Balance Check - After Withdrawal:");
//     console.log(`   Vault:     ${vault.toBase58()}`);
//     console.log(
//       `              ${afterVaultWithdraw} lamports (${
//         Number(afterVaultWithdraw) / LAMPORTS_PER_SOL
//       } SOL)`
//     );
//     console.log(`   Relayer:   ${relayer.publicKey.toBase58()}`);
//     console.log(
//       `              ${afterRelayerWithdraw} lamports (${
//         Number(afterRelayerWithdraw) / LAMPORTS_PER_SOL
//       } SOL)`
//     );
//     console.log(`   Recipient: ${recipient.publicKey.toBase58()}`);
//     console.log(
//       `              ${afterRecipientWithdraw} lamports (${
//         Number(afterRecipientWithdraw) / LAMPORTS_PER_SOL
//       } SOL)`
//     );

//     console.log("\n📊 Balance Changes:");
//     console.log(`   Vault paid:          ${vaultPaid} lamports`);
//     console.log(
//       `   Relayer received:    ${relayerReceived} lamports (after tx fees)`
//     );
//     console.log(`   Recipient received:  ${recipientReceived} lamports`);
//     console.log(`   Expected withdrawal: ${withdrawAmount} lamports`);
//     console.log(`   Expected fee:        ${fee} lamports`);
//     console.log(`   Expected to recipient: ${toRecipient} lamports`);

//     // Verify vault paid exactly the withdrawal amount
//     if (vaultPaid !== withdrawAmount) {
//       throw new Error(
//         `Vault paid mismatch: expected ${withdrawAmount}, got ${vaultPaid}`
//       );
//     }

//     // Verify recipient received exactly the expected amount (withdrawal - fee)
//     if (recipientReceived !== toRecipient) {
//       throw new Error(
//         `Recipient received mismatch: expected ${toRecipient}, got ${recipientReceived}`
//       );
//     }

//     // Verify relayer received fee (minus tx costs)
//     // Note: Relayer's balance change includes fee income minus tx costs
//     const expectedRelayerMin = fee - 10_000_000n; // Allow up to 0.01 SOL for tx fees
//     if (relayerReceived < expectedRelayerMin) {
//       console.warn(
//         `   ⚠️  Relayer received less than expected (likely due to tx fees): ${relayerReceived} < ${expectedRelayerMin}`
//       );
//     }

//     console.log("\n✅ Balance verification passed!");
//     console.log(`   ✓ Vault paid exactly ${withdrawAmount} lamports`);
//     console.log(
//       `   ✓ Recipient received exactly ${toRecipient} lamports (${withdrawAmount} - ${fee} fee)`
//     );
//     console.log(
//       `   ✓ Relayer received ${relayerReceived} lamports (${fee} fee - tx costs)`
//     );
//     console.log(
//       `   ✓ Total accounted: ${vaultPaid} = ${recipientReceived} + ${fee} (sent to relayer)`
//     );

//     console.log("\n✅ Withdrawal successful");
//     console.log(`   Withdrawn: ${withdrawAmount} lamports`);
//     console.log(`   Fee: ${fee} lamports`);
//     console.log(`   To recipient: ${toRecipient} lamports`);

//     // 🗑️ Mark note as spent in storage
//     noteStorage.markSpent(depositNoteId!);
//     console.log(`\n🗑️  Note marked as spent (nullifier published on-chain)`);
//     console.log(
//       `   ⚠️  Note can NEVER be spent again (double-spend protection)`
//     );
//   });

//   // =============================================================================
//   // Private Transfer Test
//   // =============================================================================

//   it("transfers note privately and recipient withdraws", async () => {
//     console.log("\n🔄 Private Transfer Test:\n");

//     // Alice deposits 2 SOL that she will transfer to Bob
//     const alice = Keypair.generate();
//     console.log(`   Alice: ${alice.publicKey.toBase58()}`);
//     await airdropAndConfirm(provider, alice.publicKey, 3 * LAMPORTS_PER_SOL);

//     // Register Alice as relayer
//     await (program.methods as any)
//       .addRelayer(alice.publicKey)
//       .accounts({ config, admin: wallet.publicKey })
//       .rpc();

//     // Alice deposits 2 SOL
//     const aliceDepositAmount = BigInt(2 * LAMPORTS_PER_SOL);
//     const alicePrivateKey = randomBytes32();
//     const alicePublicKey = derivePublicKey(poseidon, alicePrivateKey);
//     const aliceBlinding = randomBytes32();

//     const aliceCommitment = computeCommitment(
//       poseidon,
//       aliceDepositAmount,
//       alicePublicKey,
//       aliceBlinding,
//       SOL_MINT
//     );

//     const aliceDummyOutput = randomBytes32();
//     const aliceDummyPubKey = derivePublicKey(poseidon, aliceDummyOutput);
//     const aliceDummyBlinding = randomBytes32();
//     const aliceDummyCommitment = computeCommitment(
//       poseidon,
//       0n,
//       aliceDummyPubKey,
//       aliceDummyBlinding,
//       SOL_MINT
//     );

//     // Remember the index where Alice's commitment will be (but don't insert yet)
//     const aliceLeafIndex = offchainTree.nextIndex;

//     const aliceNullifier = computeNullifier(
//       poseidon,
//       aliceCommitment,
//       aliceLeafIndex,
//       alicePrivateKey
//     );

//     // Generate deposit proof for Alice
//     const dummyPrivKey0 = randomBytes32();
//     const dummyPrivKey1 = randomBytes32();
//     const dummyPubKey0 = derivePublicKey(poseidon, dummyPrivKey0);
//     const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);
//     const dummyBlinding0 = randomBytes32();
//     const dummyBlinding1 = randomBytes32();
//     const dummyCommitment0 = computeCommitment(
//       poseidon,
//       0n,
//       dummyPubKey0,
//       dummyBlinding0,
//       SOL_MINT
//     );
//     const dummyCommitment1 = computeCommitment(
//       poseidon,
//       0n,
//       dummyPubKey1,
//       dummyBlinding1,
//       SOL_MINT
//     );
//     const dummyNullifier0 = computeNullifier(
//       poseidon,
//       dummyCommitment0,
//       0,
//       dummyPrivKey0
//     );
//     const dummyNullifier1 = computeNullifier(
//       poseidon,
//       dummyCommitment1,
//       0,
//       dummyPrivKey1
//     );

//     const extDataDeposit = {
//       recipient: alice.publicKey,
//       relayer: alice.publicKey,
//       fee: new BN(0),
//       refund: new BN(0),
//     };
//     const extDataHashDeposit = computeExtDataHash(poseidon, extDataDeposit);

//     let noteTreeAcc: any = await (
//       program.account as any
//     ).merkleTreeAccount.fetch(noteTree);
//     let onchainRoot = extractRootFromAccount(noteTreeAcc);

//     const zeros = offchainTree.getZeros();
//     const zeroPathElements = zeros.slice(0, 16).map((z) => bytesToBigIntBE(z));

//     const depositProof = await generateTransactionProof({
//       root: onchainRoot,
//       publicAmount: aliceDepositAmount,
//       extDataHash: extDataHashDeposit,
//       mintAddress: SOL_MINT,
//       inputNullifiers: [dummyNullifier0, dummyNullifier1],
//       outputCommitments: [aliceCommitment, aliceDummyCommitment],
//       inputAmounts: [0n, 0n],
//       inputPrivateKeys: [dummyPrivKey0, dummyPrivKey1],
//       inputPublicKeys: [dummyPubKey0, dummyPubKey1],
//       inputBlindings: [dummyBlinding0, dummyBlinding1],
//       inputMerklePaths: [
//         { pathElements: zeroPathElements, pathIndices: new Array(16).fill(0) },
//         { pathElements: zeroPathElements, pathIndices: new Array(16).fill(0) },
//       ],
//       outputAmounts: [aliceDepositAmount, 0n],
//       outputOwners: [alicePublicKey, aliceDummyPubKey],
//       outputBlindings: [aliceBlinding, aliceDummyBlinding],
//     });

//     const [nullifierMarker0] = PublicKey.findProgramAddressSync(
//       [Buffer.from("nullifier_v3"), Buffer.from(dummyNullifier0)],
//       program.programId
//     );
//     const [nullifierMarker1] = PublicKey.findProgramAddressSync(
//       [Buffer.from("nullifier_v3"), Buffer.from(dummyNullifier1)],
//       program.programId
//     );

//     const depositTx = await (program.methods as any)
//       .transact(
//         Array.from(onchainRoot),
//         new BN(aliceDepositAmount.toString()),
//         Array.from(extDataHashDeposit),
//         SOL_MINT,
//         Array.from(dummyNullifier0),
//         Array.from(dummyNullifier1),
//         Array.from(aliceCommitment),
//         Array.from(aliceDummyCommitment),
//         extDataDeposit,
//         depositProof
//       )
//       .accounts({
//         config,
//         vault,
//         noteTree,
//         nullifiers,
//         nullifierMarker0,
//         nullifierMarker1,
//         relayer: alice.publicKey,
//         recipient: alice.publicKey,
//         vaultTokenAccount: alice.publicKey, // Placeholder for SOL
//         userTokenAccount: alice.publicKey, // Placeholder for SOL
//         recipientTokenAccount: alice.publicKey, // Placeholder for SOL
//         relayerTokenAccount: alice.publicKey, // Placeholder for SOL
//         tokenProgram: alice.publicKey, // Placeholder for SOL
//         systemProgram: SystemProgram.programId,
//       })
//       .signers([alice])
//       .transaction();

//     // Add compute budget instructions
//     const modifyComputeUnits = ComputeBudgetProgram.setComputeUnitLimit({
//       units: 1_400_000,
//     });
//     const addPriorityFee = ComputeBudgetProgram.setComputeUnitPrice({
//       microLamports: 1,
//     });

//     const depositTransaction = new Transaction();
//     depositTransaction.add(modifyComputeUnits);
//     depositTransaction.add(addPriorityFee);
//     depositTransaction.add(depositTx);

//     await provider.sendAndConfirm(depositTransaction, [alice]);

//     // NOW insert Alice's deposit outputs into offchainTree (after on-chain transaction)
//     offchainTree.insert(aliceCommitment);
//     offchainTree.insert(aliceDummyCommitment);

//     console.log(
//       `✅ Alice deposited ${aliceDepositAmount} lamports (Leaf ${aliceLeafIndex})\n`
//     );

//     // =============================================================================
//     // PRIVATE TRANSFER: Alice sends 1 SOL to Bob, keeps 1 SOL change
//     // =============================================================================

//     console.log("🔄 Private Transfer: Alice → Bob\n");

//     // Bob generates his keypair (only Bob has this private key)
//     const bobPrivateKey = randomBytes32();
//     const bobPublicKey = derivePublicKey(poseidon, bobPrivateKey);
//     const bobBlinding = randomBytes32();
//     console.log(
//       `   Bob (recipient): ${Keypair.generate().publicKey.toBase58()} (for display only)`
//     );
//     console.log(
//       `   ⚠️  Bob's real identity hidden - only commitment visible on-chain\n`
//     );

//     // Transfer amounts
//     const transferAmount = BigInt(1 * LAMPORTS_PER_SOL); // 1 SOL to Bob
//     const changeAmount = aliceDepositAmount - transferAmount; // 1 SOL back to Alice

//     console.log("📋 Transfer Breakdown:");
//     console.log(`   Input: Alice's ${aliceDepositAmount} lamports note`);
//     console.log(`   Output 1: Bob receives ${transferAmount} lamports`);
//     console.log(`   Output 2: Alice keeps ${changeAmount} lamports (change)`);
//     console.log(`   On-chain trace: NONE - fully private! 🎭\n`);

//     // Create Alice's change note (new privateKey for security)
//     const aliceChangePrivKey = randomBytes32();
//     const aliceChangePubKey = derivePublicKey(poseidon, aliceChangePrivKey);
//     const aliceChangeBlinding = randomBytes32();

//     // Compute output commitments
//     const bobCommitment = computeCommitment(
//       poseidon,
//       transferAmount,
//       bobPublicKey,
//       bobBlinding,
//       SOL_MINT
//     );

//     const aliceChangeCommitment = computeCommitment(
//       poseidon,
//       changeAmount,
//       aliceChangePubKey,
//       aliceChangeBlinding,
//       SOL_MINT
//     );

//     // Generate dummy input (2-in-2-out requirement)
//     const transferDummyPrivKey = randomBytes32();
//     const transferDummyPubKey = derivePublicKey(poseidon, transferDummyPrivKey);
//     const transferDummyBlinding = randomBytes32();
//     const transferDummyCommitment = computeCommitment(
//       poseidon,
//       0n,
//       transferDummyPubKey,
//       transferDummyBlinding,
//       SOL_MINT
//     );
//     const transferDummyNullifier = computeNullifier(
//       poseidon,
//       transferDummyCommitment,
//       0,
//       transferDummyPrivKey
//     );

//     // Prepare transaction (publicAmount = 0 for pure transfer, no deposit/withdrawal)
//     const extDataTransfer = {
//       recipient: alice.publicKey, // Doesn't reveal anything
//       relayer: alice.publicKey,
//       fee: new BN(0),
//       refund: new BN(0),
//     };
//     const extDataHashTransfer = computeExtDataHash(poseidon, extDataTransfer);

//     noteTreeAcc = await (program.account as any).merkleTreeAccount.fetch(
//       noteTree
//     );
//     onchainRoot = extractRootFromAccount(noteTreeAcc);

//     // Get Alice's Merkle path (after deposit, before transfer)
//     const aliceUpdatedPath = offchainTree.getMerkleProof(aliceLeafIndex);

//     // Generate proof: Alice spends her note, creates Bob's note + her change
//     const transferProof = await generateTransactionProof({
//       root: onchainRoot,
//       publicAmount: 0n, // No deposit/withdrawal, just internal transfer
//       extDataHash: extDataHashTransfer,
//       mintAddress: SOL_MINT,
//       inputNullifiers: [aliceNullifier, transferDummyNullifier],
//       outputCommitments: [bobCommitment, aliceChangeCommitment],

//       // Private inputs
//       inputAmounts: [aliceDepositAmount, 0n],
//       inputPrivateKeys: [alicePrivateKey, transferDummyPrivKey],
//       inputPublicKeys: [alicePublicKey, transferDummyPubKey],
//       inputBlindings: [aliceBlinding, transferDummyBlinding],
//       inputMerklePaths: [
//         aliceUpdatedPath,
//         { pathElements: zeroPathElements, pathIndices: new Array(16).fill(0) },
//       ],

//       // Output UTXOs: Bob gets transferAmount, Alice gets change
//       outputAmounts: [transferAmount, changeAmount],
//       outputOwners: [bobPublicKey, aliceChangePubKey], // Bob and Alice own outputs
//       outputBlindings: [bobBlinding, aliceChangeBlinding],
//     });

//     // Execute on-chain (nullifies Alice's old note, creates 2 new commitments)
//     const [aliceNullifierMarker] = PublicKey.findProgramAddressSync(
//       [Buffer.from("nullifier_v3"), Buffer.from(aliceNullifier)],
//       program.programId
//     );
//     const [transferDummyNullifierMarker] = PublicKey.findProgramAddressSync(
//       [Buffer.from("nullifier_v3"), Buffer.from(transferDummyNullifier)],
//       program.programId
//     );

//     const transferTx = await (program.methods as any)
//       .transact(
//         Array.from(onchainRoot),
//         new BN(0), // publicAmount = 0
//         Array.from(extDataHashTransfer),
//         SOL_MINT,
//         Array.from(aliceNullifier),
//         Array.from(transferDummyNullifier),
//         Array.from(bobCommitment),
//         Array.from(aliceChangeCommitment),
//         extDataTransfer,
//         transferProof
//       )
//       .accounts({
//         config,
//         vault,
//         noteTree,
//         nullifiers,
//         nullifierMarker0: aliceNullifierMarker,
//         nullifierMarker1: transferDummyNullifierMarker,
//         relayer: alice.publicKey,
//         recipient: alice.publicKey,
//         vaultTokenAccount: alice.publicKey, // Placeholder for SOL
//         userTokenAccount: alice.publicKey, // Placeholder for SOL
//         recipientTokenAccount: alice.publicKey, // Placeholder for SOL
//         relayerTokenAccount: alice.publicKey, // Placeholder for SOL
//         tokenProgram: alice.publicKey, // Placeholder for SOL
//         systemProgram: SystemProgram.programId,
//       })
//       .signers([alice])
//       .transaction();

//     // Add compute budget instructions
//     const transferComputeUnits = ComputeBudgetProgram.setComputeUnitLimit({
//       units: 1_400_000,
//     });
//     const transferPriorityFee = ComputeBudgetProgram.setComputeUnitPrice({
//       microLamports: 1,
//     });

//     const transferTransaction = new Transaction();
//     transferTransaction.add(transferComputeUnits);
//     transferTransaction.add(transferPriorityFee);
//     transferTransaction.add(transferTx);

//     await provider.sendAndConfirm(transferTransaction, [alice]);

//     // Now insert outputs into off-chain tree (after on-chain transaction)
//     const bobLeafIndex = offchainTree.insert(bobCommitment);
//     const aliceChangeLeafIndex = offchainTree.insert(aliceChangeCommitment);

//     console.log("✅ Private transfer complete!\n");
//     console.log("📦 Notes Created:");
//     console.log(
//       `   Bob's note: ${transferAmount} lamports (Leaf ${bobLeafIndex})`
//     );
//     console.log(
//       `   Alice's change: ${changeAmount} lamports (Leaf ${aliceChangeLeafIndex})`
//     );
//     console.log(
//       `   🔒 Bob needs his secrets to spend (Alice sends these off-chain)\n`
//     );

//     // =============================================================================
//     // SECURITY CHECK: Verify Alice CANNOT withdraw Bob's note
//     // =============================================================================

//     console.log("🔒 Security Verification: Can Alice withdraw Bob's note?\n");

//     // Try to compute nullifier with Alice's private key (wrong key!)
//     const aliceAttemptNullifier = computeNullifier(
//       poseidon,
//       bobCommitment,
//       bobLeafIndex,
//       alicePrivateKey // Alice tries to use her own key - WRONG!
//     );

//     // Get current on-chain state
//     noteTreeAcc = await (program.account as any).merkleTreeAccount.fetch(
//       noteTree
//     );
//     onchainRoot = extractRootFromAccount(noteTreeAcc);
//     const bobPathForAliceAttempt = offchainTree.getMerkleProof(bobLeafIndex);

//     // Create dummy for 2-in-2-out
//     const aliceAttemptDummyPrivKey = randomBytes32();
//     const aliceAttemptDummyPubKey = derivePublicKey(
//       poseidon,
//       aliceAttemptDummyPrivKey
//     );
//     const aliceAttemptDummyBlinding = randomBytes32();
//     const aliceAttemptDummyCommitment = computeCommitment(
//       poseidon,
//       0n,
//       aliceAttemptDummyPubKey,
//       aliceAttemptDummyBlinding,
//       SOL_MINT
//     );
//     const aliceAttemptDummyNullifier = computeNullifier(
//       poseidon,
//       aliceAttemptDummyCommitment,
//       0,
//       aliceAttemptDummyPrivKey
//     );

//     const aliceAttemptDummyOutput0 = randomBytes32();
//     const aliceAttemptDummyOutputPubKey0 = derivePublicKey(
//       poseidon,
//       aliceAttemptDummyOutput0
//     );
//     const aliceAttemptDummyOutputBlinding0 = randomBytes32();
//     const aliceAttemptDummyOutputCommitment0 = computeCommitment(
//       poseidon,
//       0n,
//       aliceAttemptDummyOutputPubKey0,
//       aliceAttemptDummyOutputBlinding0,
//       SOL_MINT
//     );

//     const aliceAttemptDummyOutput1 = randomBytes32();
//     const aliceAttemptDummyOutputPubKey1 = derivePublicKey(
//       poseidon,
//       aliceAttemptDummyOutput1
//     );
//     const aliceAttemptDummyOutputBlinding1 = randomBytes32();
//     const aliceAttemptDummyOutputCommitment1 = computeCommitment(
//       poseidon,
//       0n,
//       aliceAttemptDummyOutputPubKey1,
//       aliceAttemptDummyOutputBlinding1,
//       SOL_MINT
//     );

//     const aliceAttemptRecipient = Keypair.generate();
//     await airdropAndConfirm(
//       provider,
//       aliceAttemptRecipient.publicKey,
//       0.1 * LAMPORTS_PER_SOL
//     );

//     const aliceAttemptFee = (transferAmount * BigInt(feeBps)) / 10_000n;
//     const aliceAttemptExtData = {
//       recipient: aliceAttemptRecipient.publicKey,
//       relayer: alice.publicKey,
//       fee: new BN(aliceAttemptFee.toString()),
//       refund: new BN(0),
//     };
//     const aliceAttemptExtDataHash = computeExtDataHash(
//       poseidon,
//       aliceAttemptExtData
//     );

//     let aliceAttemptFailed = false;
//     try {
//       // Alice tries to generate proof with WRONG private key
//       await generateTransactionProof({
//         root: onchainRoot,
//         publicAmount: -transferAmount,
//         extDataHash: aliceAttemptExtDataHash,
//         mintAddress: SOL_MINT,
//         inputNullifiers: [aliceAttemptNullifier, aliceAttemptDummyNullifier],
//         outputCommitments: [
//           aliceAttemptDummyOutputCommitment0,
//           aliceAttemptDummyOutputCommitment1,
//         ],
//         inputAmounts: [transferAmount, 0n],
//         inputPrivateKeys: [alicePrivateKey, aliceAttemptDummyPrivKey], // WRONG KEY!
//         inputPublicKeys: [alicePublicKey, aliceAttemptDummyPubKey], // WRONG PUBLIC KEY!
//         inputBlindings: [aliceBlinding, aliceAttemptDummyBlinding], // WRONG BLINDING!
//         inputMerklePaths: [
//           bobPathForAliceAttempt,
//           {
//             pathElements: zeroPathElements,
//             pathIndices: new Array(16).fill(0),
//           },
//         ],
//         outputAmounts: [0n, 0n],
//         outputOwners: [
//           aliceAttemptDummyOutputPubKey0,
//           aliceAttemptDummyOutputPubKey1,
//         ],
//         outputBlindings: [
//           aliceAttemptDummyOutputBlinding0,
//           aliceAttemptDummyOutputBlinding1,
//         ],
//       });
//       console.log(
//         "   ❌ SECURITY FAILURE: Alice generated proof with wrong privateKey!"
//       );
//     } catch (error: any) {
//       aliceAttemptFailed = true;
//       console.log("   ✅ Alice's withdrawal attempt FAILED (as expected)");
//       console.log(
//         "   ✅ Proof generation failed: wrong privateKey/blinding combination"
//       );
//       console.log(
//         "   ✅ ZK circuit enforces: commitment = hash(amount, publicKey, blinding)"
//       );
//       console.log(
//         "   ✅ Only Bob's privateKey produces correct publicKey for Bob's commitment\n"
//       );
//     }

//     if (!aliceAttemptFailed) {
//       throw new Error(
//         "SECURITY VIOLATION: Alice should NOT be able to generate valid proof with wrong privateKey!"
//       );
//     }

//     console.log("✅ Security Check Passed:");
//     console.log(
//       "   ✅ Alice CANNOT withdraw Bob's note (she doesn't have bobPrivateKey)"
//     );
//     console.log("   ✅ No on-chain link between Alice and Bob");
//     console.log(
//       "   ✅ Transfer is fully private (publicAmount = 0, no vault movement)"
//     );
//     console.log(
//       "   ✅ Recipient-only withdrawal enforced by ZK circuit requiring privateKey knowledge\n"
//     );

//     // =============================================================================
//     // BOB WITHDRAWS: Only Bob can withdraw because only he has the private key
//     // =============================================================================

//     console.log("💰 Bob Withdraws His Note:\n");

//     // Bob is a new user (not Alice!)
//     const bob = Keypair.generate();
//     const bobRecipient = Keypair.generate(); // Where Bob wants to send funds

//     console.log(`   Bob's wallet: ${bob.publicKey.toBase58()}`);
//     console.log(
//       `   Withdrawal destination: ${bobRecipient.publicKey.toBase58()}`
//     );

//     // Airdrop to Bob (for tx fees) and recipient (for account rent)
//     await airdropAndConfirm(provider, bob.publicKey, 1 * LAMPORTS_PER_SOL);
//     await airdropAndConfirm(
//       provider,
//       bobRecipient.publicKey,
//       0.1 * LAMPORTS_PER_SOL
//     );

//     // Register Bob as relayer
//     await (program.methods as any)
//       .addRelayer(bob.publicKey)
//       .accounts({ config, admin: wallet.publicKey })
//       .rpc();

//     // Bob computes his nullifier (proves he knows the private key)
//     const bobNullifier = computeNullifier(
//       poseidon,
//       bobCommitment,
//       bobLeafIndex,
//       bobPrivateKey
//     );

//     const bobWithdrawAmount = transferAmount;
//     const bobFee = (bobWithdrawAmount * BigInt(feeBps)) / 10_000n;
//     const bobToRecipient = bobWithdrawAmount - bobFee;

//     console.log(`   Withdrawing: ${bobWithdrawAmount} lamports`);
//     console.log(`   Fee: ${bobFee} lamports`);
//     console.log(`   Net to recipient: ${bobToRecipient} lamports\n`);

//     const extDataBobWithdraw = {
//       recipient: bobRecipient.publicKey,
//       relayer: bob.publicKey, // Bob signs the transaction
//       fee: new BN(bobFee.toString()),
//       refund: new BN(0),
//     };
//     const extDataHashBobWithdraw = computeExtDataHash(
//       poseidon,
//       extDataBobWithdraw
//     );

//     noteTreeAcc = await (program.account as any).merkleTreeAccount.fetch(
//       noteTree
//     );
//     onchainRoot = extractRootFromAccount(noteTreeAcc);

//     // Get updated Merkle path for Bob's note
//     const bobUpdatedPath = offchainTree.getMerkleProof(bobLeafIndex);

//     // Generate dummy input for 2-in-2-out
//     const bobDummyPrivKey = randomBytes32();
//     const bobDummyPubKey = derivePublicKey(poseidon, bobDummyPrivKey);
//     const bobDummyBlinding = randomBytes32();
//     const bobDummyCommitment = computeCommitment(
//       poseidon,
//       0n,
//       bobDummyPubKey,
//       bobDummyBlinding,
//       SOL_MINT
//     );
//     const bobDummyNullifier = computeNullifier(
//       poseidon,
//       bobDummyCommitment,
//       0,
//       bobDummyPrivKey
//     );

//     // Dummy outputs (withdrawal has no outputs)
//     const bobDummyOutputPrivKey0 = randomBytes32();
//     const bobDummyOutputPubKey0 = derivePublicKey(
//       poseidon,
//       bobDummyOutputPrivKey0
//     );
//     const bobDummyOutputBlinding0 = randomBytes32();
//     const bobDummyOutputCommitment0 = computeCommitment(
//       poseidon,
//       0n,
//       bobDummyOutputPubKey0,
//       bobDummyOutputBlinding0,
//       SOL_MINT
//     );

//     const bobDummyOutputPrivKey1 = randomBytes32();
//     const bobDummyOutputPubKey1 = derivePublicKey(
//       poseidon,
//       bobDummyOutputPrivKey1
//     );
//     const bobDummyOutputBlinding1 = randomBytes32();
//     const bobDummyOutputCommitment1 = computeCommitment(
//       poseidon,
//       0n,
//       bobDummyOutputPubKey1,
//       bobDummyOutputBlinding1,
//       SOL_MINT
//     );

//     // Bob generates proof using HIS private key (not Alice's!)
//     const bobWithdrawProof = await generateTransactionProof({
//       root: onchainRoot,
//       publicAmount: -bobWithdrawAmount, // Negative for withdrawal
//       extDataHash: extDataHashBobWithdraw,
//       mintAddress: SOL_MINT,
//       inputNullifiers: [bobNullifier, bobDummyNullifier],
//       outputCommitments: [bobDummyOutputCommitment0, bobDummyOutputCommitment1],

//       // Bob's private inputs - ONLY BOB HAS THESE!
//       inputAmounts: [transferAmount, 0n],
//       inputPrivateKeys: [bobPrivateKey, bobDummyPrivKey], // Bob's privateKey here!
//       inputPublicKeys: [bobPublicKey, bobDummyPubKey],
//       inputBlindings: [bobBlinding, bobDummyBlinding],
//       inputMerklePaths: [
//         bobUpdatedPath,
//         { pathElements: zeroPathElements, pathIndices: new Array(16).fill(0) },
//       ],

//       outputAmounts: [0n, 0n],
//       outputOwners: [bobDummyOutputPubKey0, bobDummyOutputPubKey1],
//       outputBlindings: [bobDummyOutputBlinding0, bobDummyOutputBlinding1],
//     });

//     const [bobNullifierMarker] = PublicKey.findProgramAddressSync(
//       [Buffer.from("nullifier_v3"), Buffer.from(bobNullifier)],
//       program.programId
//     );
//     const [bobDummyNullifierMarker] = PublicKey.findProgramAddressSync(
//       [Buffer.from("nullifier_v3"), Buffer.from(bobDummyNullifier)],
//       program.programId
//     );

//     // Check balances before
//     const beforeVault = BigInt(await provider.connection.getBalance(vault));
//     const beforeBobRecipient = BigInt(
//       await provider.connection.getBalance(bobRecipient.publicKey)
//     );

//     console.log("🔐 Proof of Ownership:");
//     console.log(`   ✅ Bob generated valid ZK proof with his privateKey`);
//     console.log(`   ✅ Only Bob could generate this proof`);
//     console.log(
//       `   ⚠️  Alice CANNOT withdraw Bob's note (she doesn't have Bob's privateKey)\n`
//     );

//     // BOB signs and submits the transaction (not Alice!)
//     const bobWithdrawTx = await (program.methods as any)
//       .transact(
//         Array.from(onchainRoot),
//         new BN(-bobWithdrawAmount.toString()),
//         Array.from(extDataHashBobWithdraw),
//         SOL_MINT,
//         Array.from(bobNullifier),
//         Array.from(bobDummyNullifier),
//         Array.from(bobDummyOutputCommitment0),
//         Array.from(bobDummyOutputCommitment1),
//         extDataBobWithdraw,
//         bobWithdrawProof
//       )
//       .accounts({
//         config,
//         vault,
//         noteTree,
//         nullifiers,
//         nullifierMarker0: bobNullifierMarker,
//         nullifierMarker1: bobDummyNullifierMarker,
//         relayer: bob.publicKey, // Bob is the relayer
//         recipient: bobRecipient.publicKey,
//         vaultTokenAccount: bob.publicKey, // Placeholder for SOL
//         userTokenAccount: bob.publicKey, // Placeholder for SOL
//         recipientTokenAccount: bob.publicKey, // Placeholder for SOL
//         relayerTokenAccount: bob.publicKey, // Placeholder for SOL
//         tokenProgram: bob.publicKey, // Placeholder for SOL
//         systemProgram: SystemProgram.programId,
//       })
//       .signers([bob]) // BOB SIGNS, NOT ALICE!
//       .transaction();

//     // Add compute budget instructions
//     const bobComputeUnits = ComputeBudgetProgram.setComputeUnitLimit({
//       units: 1_400_000,
//     });
//     const bobPriorityFee = ComputeBudgetProgram.setComputeUnitPrice({
//       microLamports: 1,
//     });

//     const bobTransaction = new Transaction();
//     bobTransaction.add(bobComputeUnits);
//     bobTransaction.add(bobPriorityFee);
//     bobTransaction.add(bobWithdrawTx);

//     await provider.sendAndConfirm(bobTransaction, [bob]);

//     // Check balances after
//     const afterVault = BigInt(await provider.connection.getBalance(vault));
//     const afterBobRecipient = BigInt(
//       await provider.connection.getBalance(bobRecipient.publicKey)
//     );

//     const vaultPaid = beforeVault - afterVault;
//     const bobRecipientReceived = afterBobRecipient - beforeBobRecipient;

//     console.log("✅ Bob's Withdrawal Successful!\n");
//     console.log("📊 Verification:");
//     console.log(`   Vault paid: ${vaultPaid} lamports`);
//     console.log(
//       `   Bob's recipient received: ${bobRecipientReceived} lamports`
//     );
//     console.log(`   Expected: ${bobToRecipient} lamports`);

//     if (vaultPaid !== bobWithdrawAmount) {
//       throw new Error(
//         `Vault paid mismatch: expected ${bobWithdrawAmount}, got ${vaultPaid}`
//       );
//     }

//     if (bobRecipientReceived !== bobToRecipient) {
//       throw new Error(
//         `Recipient received mismatch: expected ${bobToRecipient}, got ${bobRecipientReceived}`
//       );
//     }

//     console.log("\n🎉 Private Transfer Complete!");
//     console.log("   ✅ Alice transferred 1 SOL to Bob privately");
//     console.log("   ✅ Bob withdrew his 1 SOL successfully");
//     console.log("   ✅ No on-chain link between Alice and Bob");
//     console.log(
//       "   ✅ Only Bob (recipient) could withdraw the transferred note"
//     );
//     console.log(
//       "   ✅ Alice cannot spend Bob's note (she doesn't have his privateKey)\n"
//     );
//   });

//   // =============================================================================
//   // Security Test: Note Theft Scenario
//   // =============================================================================

//   it("demonstrates note security model", async () => {
//     console.log("\n🔐 Security Model Demonstration:\n");

//     // Generate a new note
//     const privateKey = randomBytes32();
//     const publicKey = derivePublicKey(poseidon, privateKey);
//     const blinding = randomBytes32();
//     const amount = 1_000_000_000n;

//     const commitment = computeCommitment(
//       poseidon,
//       amount,
//       publicKey,
//       blinding,
//       SOL_MINT
//     );

//     console.log("1️⃣  What's PUBLIC (visible on-chain):");
//     console.log(
//       `   ✅ Commitment: ${Buffer.from(commitment)
//         .toString("hex")
//         .slice(0, 40)}...`
//     );
//     console.log(`   ✅ Amount: Someone deposited, but amount is HIDDEN`);
//     console.log(
//       `   ℹ️  Attacker CAN see this, but it's useless without secrets\n`
//     );

//     console.log("2️⃣  What's SECRET (proves ownership):");
//     console.log(
//       `   🔒 privateKey: ${Buffer.from(privateKey)
//         .toString("hex")
//         .slice(0, 20)}... (NEVER share!)`
//     );
//     console.log(
//       `   🔒 blinding: ${Buffer.from(blinding)
//         .toString("hex")
//         .slice(0, 20)}... (NEVER share!)`
//     );
//     console.log(
//       `   ⚠️  If attacker gets these → THEY CAN SPEND YOUR DEPOSIT!\n`
//     );

//     console.log("3️⃣  How ZK Proof Protects You:");
//     console.log(
//       `   🔐 To withdraw, you must prove: publicKey = Poseidon(privateKey)`
//     );
//     console.log(`   🔐 Without privateKey, the proof verification FAILS`);
//     console.log(`   🔐 Rust code: verify_withdraw_groth16() enforces this\n`);

//     console.log("4️⃣  Protection Layers:");
//     console.log(
//       `   ✅ Layer 1: ZK Circuit - proves you know privateKey without revealing it`
//     );
//     console.log(
//       `   ✅ Layer 2: Groth16 Verification - mathematically impossible to forge`
//     );
//     console.log(`   ✅ Layer 3: Nullifier Uniqueness - prevents double-spend`);
//     console.log(
//       `   ✅ Layer 4: Encrypted Storage - protects privateKey at rest\n`
//     );

//     console.log("5️⃣  Your Responsibility:");
//     console.log(
//       `   💾 Use NoteManager with AES-256 encryption (see note-manager.example.ts)`
//     );
//     console.log(`   🔑 Use strong password (20+ characters, random)`);
//     console.log(`   🔐 Store encrypted notes.enc file securely`);
//     console.log(`   ⚠️  Backup your notes - if lost, funds are UNRECOVERABLE`);
//     console.log(
//       `   ⚠️  Never commit notes to git or share via insecure channels\n`
//     );

//     console.log("✅ Security model verified\n");
//   });

//   // =============================================================================
//   // Summary
//   // =============================================================================

//   after(() => {
//     console.log("\n📊 Test Complete!\n");
//     console.log("All tests passed with real ZK proofs ✅");
//   });
// });

// =============================================================================
// SPL Token Tests
// =============================================================================

describe("Privacy Pool - SPL Token Support", () => {
  const provider = makeProvider();
  setProvider(provider);

  const wallet = provider.wallet as Wallet;
  const program: any = workspace.PrivacyPool as any;

  let poseidon: any;
  let tokenConfig: PublicKey;
  let tokenVault: PublicKey;
  let tokenNoteTree: PublicKey;
  let tokenNullifiers: PublicKey;

  let testMint: PublicKey;
  let vaultTokenAccount: PublicKey;

  const feeBps = 50; // 0.5%
  const MINT_DECIMALS = 6;
  const TOKEN_AMOUNT = 200_000_000; // 200 tokens with 6 decimals (ensures 0.5% fee meets 1M minimum)

  let offchainTokenTree: OffchainMerkleTree;
  const tokenNoteStorage = new InMemoryNoteStorage();
  let tokenDepositNoteId: string | null = null;

  // =============================================================================
  // Setup
  // =============================================================================

  before(async () => {
    console.log("\n🔧 Setting up SPL token test environment...\n");

    // Initialize Poseidon
    poseidon = await buildPoseidon();
    offchainTokenTree = new OffchainMerkleTree(16, poseidon);

    // Create test token mint
    console.log("Creating test token mint...");
    testMint = await createMint(
      provider.connection,
      wallet.payer,
      wallet.publicKey,
      null,
      MINT_DECIMALS
    );
    console.log(`✅ Test mint created: ${testMint.toBase58()}`);

    // Get PDAs for token pool
    const pdas = getPoolPdas(program.programId);
    tokenConfig = pdas.config;
    tokenVault = pdas.vault;
    tokenNoteTree = pdas.noteTree;
    tokenNullifiers = pdas.nullifiers;

    // Create vault's token account (ATA)
    vaultTokenAccount = await getAssociatedTokenAddress(
      testMint,
      tokenVault,
      true
    );

    console.log("Token Config PDA:", tokenConfig.toBase58());
    console.log("Token Vault PDA:", tokenVault.toBase58());
    console.log("Vault Token Account:", vaultTokenAccount.toBase58());
  });

  it("initializes the privacy pool with SPL token", async () => {
    try {
      await (program.methods as any)
        .initialize(feeBps, testMint)
        .accounts({
          config: tokenConfig,
          vault: tokenVault,
          noteTree: tokenNoteTree,
          nullifiers: tokenNullifiers,
          admin: wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      const configAcc = await (program.account as any).privacyConfig.fetch(
        tokenConfig
      );
      console.log("✅ Token pool initialized");
      console.log(`   Token mint: ${configAcc.mintAddress.toBase58()}`);
      console.log(`   Fee BPS: ${configAcc.feeBps}`);
      console.log(`   Max Deposit: ${configAcc.maxDepositAmount} tokens`);
    } catch (e: any) {
      if (e instanceof SendTransactionError) {
        const logs = await e.getLogs(provider.connection);
        console.error("Initialize failed:", logs);
      }
      throw e;
    }
  });

  // =============================================================================
  // Token Deposit Test
  // =============================================================================

  it("deposits SPL tokens using transact with real proof", async () => {
    const sender = Keypair.generate();

    console.log("\n🎁 Setting up token deposit test...");
    console.log(`   Sender: ${sender.publicKey.toBase58()}`);

    // Airdrop SOL for transaction fees
    await airdropAndConfirm(provider, sender.publicKey, 2 * LAMPORTS_PER_SOL);

    // Create sender's token account and mint tokens
    const senderTokenAccount = await createAndFundTokenAccount(
      provider,
      testMint,
      sender.publicKey,
      TOKEN_AMOUNT * 2
    );

    console.log(`   Sender token account: ${senderTokenAccount.toBase58()}`);
    console.log(`   Funded with: ${TOKEN_AMOUNT * 2} tokens`);

    // Create vault's token account (if not exists)
    await getOrCreateAssociatedTokenAccount(
      provider.connection,
      wallet.payer,
      testMint,
      tokenVault,
      true
    );

    // Register sender as relayer
    await (program.methods as any)
      .addRelayer(sender.publicKey)
      .accounts({ config: tokenConfig, admin: wallet.publicKey })
      .rpc();

    const depositAmount = BigInt(TOKEN_AMOUNT);

    // Generate deposit note
    const privateKey = randomBytes32();
    const publicKey = derivePublicKey(poseidon, privateKey);
    const blinding = randomBytes32();

    const commitment = computeCommitment(
      poseidon,
      depositAmount,
      publicKey,
      blinding,
      testMint
    );

    // Create dummy output
    const dummyOutputPrivKey = randomBytes32();
    const dummyOutputPubKey = derivePublicKey(poseidon, dummyOutputPrivKey);
    const dummyOutputBlinding = randomBytes32();
    const dummyOutputCommitment = computeCommitment(
      poseidon,
      0n,
      dummyOutputPubKey,
      dummyOutputBlinding,
      testMint
    );

    const leafIndex = offchainTokenTree.nextIndex;
    const nullifier = computeNullifier(
      poseidon,
      commitment,
      leafIndex,
      privateKey
    );

    // Generate dummy inputs
    const dummyPrivKey0 = randomBytes32();
    const dummyPrivKey1 = randomBytes32();
    const dummyPubKey0 = derivePublicKey(poseidon, dummyPrivKey0);
    const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);
    const dummyBlinding0 = randomBytes32();
    const dummyBlinding1 = randomBytes32();

    const dummyCommitment0 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey0,
      dummyBlinding0,
      testMint
    );
    const dummyCommitment1 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey1,
      dummyBlinding1,
      testMint
    );

    const dummyNullifier0 = computeNullifier(
      poseidon,
      dummyCommitment0,
      0,
      dummyPrivKey0
    );
    const dummyNullifier1 = computeNullifier(
      poseidon,
      dummyCommitment1,
      0,
      dummyPrivKey1
    );

    const extData = {
      recipient: sender.publicKey,
      relayer: sender.publicKey,
      fee: new BN(0),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    const noteTreeAcc: any = await (
      program.account as any
    ).merkleTreeAccount.fetch(tokenNoteTree);
    const onchainRoot = extractRootFromAccount(noteTreeAcc);

    // Generate proof
    const zeros = offchainTokenTree.getZeros();
    const zeroPathElements = zeros.slice(0, 16).map((z) => bytesToBigIntBE(z));

    const proof = await generateTransactionProof({
      root: onchainRoot,
      publicAmount: depositAmount,
      extDataHash,
      mintAddress: testMint,
      inputNullifiers: [dummyNullifier0, dummyNullifier1],
      outputCommitments: [commitment, dummyOutputCommitment],

      inputAmounts: [0n, 0n],
      inputPrivateKeys: [dummyPrivKey0, dummyPrivKey1],
      inputPublicKeys: [dummyPubKey0, dummyPubKey1],
      inputBlindings: [dummyBlinding0, dummyBlinding1],
      inputMerklePaths: [
        { pathElements: zeroPathElements, pathIndices: new Array(16).fill(0) },
        { pathElements: zeroPathElements, pathIndices: new Array(16).fill(0) },
      ],

      outputAmounts: [depositAmount, 0n],
      outputOwners: [publicKey, dummyOutputPubKey],
      outputBlindings: [blinding, dummyOutputBlinding],
    });

    const [nullifierMarker0] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_v3"), Buffer.from(dummyNullifier0)],
      program.programId
    );
    const [nullifierMarker1] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_v3"), Buffer.from(dummyNullifier1)],
      program.programId
    );

    try {
      const tx = await (program.methods as any)
        .transact(
          Array.from(onchainRoot),
          new BN(depositAmount.toString()),
          Array.from(extDataHash),
          testMint,
          Array.from(dummyNullifier0),
          Array.from(dummyNullifier1),
          Array.from(commitment),
          Array.from(dummyOutputCommitment),
          extData,
          proof
        )
        .accounts({
          config: tokenConfig,
          vault: tokenVault,
          noteTree: tokenNoteTree,
          nullifiers: tokenNullifiers,
          nullifierMarker0,
          nullifierMarker1,
          relayer: sender.publicKey,
          recipient: sender.publicKey,
          vaultTokenAccount,
          userTokenAccount: senderTokenAccount,
          recipientTokenAccount: senderTokenAccount,
          relayerTokenAccount: senderTokenAccount,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .signers([sender])
        .transaction();

      const modifyComputeUnits = ComputeBudgetProgram.setComputeUnitLimit({
        units: 1_400_000,
      });
      const addPriorityFee = ComputeBudgetProgram.setComputeUnitPrice({
        microLamports: 1,
      });

      const transaction = new Transaction();
      transaction.add(modifyComputeUnits);
      transaction.add(addPriorityFee);
      transaction.add(tx);

      await provider.sendAndConfirm(transaction, [sender]);

      // Insert outputs into offchain tree
      offchainTokenTree.insert(commitment);
      offchainTokenTree.insert(dummyOutputCommitment);

      // Save note
      const merklePath = offchainTokenTree.getMerkleProof(leafIndex);
      const noteToSave: DepositNote = {
        amount: depositAmount,
        commitment,
        nullifier,
        blinding,
        privateKey,
        publicKey,
        leafIndex,
        merklePath,
        mintAddress: testMint,
      };

      tokenDepositNoteId = tokenNoteStorage.save(noteToSave);

      console.log("\n✅ Token deposit successful");
      console.log(`   Amount: ${depositAmount} tokens`);
      console.log(`   Leaf index: ${leafIndex}`);
      console.log(`   Note ID: ${tokenDepositNoteId}`);
    } catch (e: any) {
      if (e instanceof SendTransactionError) {
        const logs = await e.getLogs(provider.connection);
        console.error("Token deposit failed:", logs);
      }
      throw e;
    }
  });

  // =============================================================================
  // Token Withdrawal Test
  // =============================================================================

  it("withdraws SPL tokens via relayer with fee", async () => {
    if (!tokenDepositNoteId) {
      throw new Error("No token deposit note - deposit test must run first");
    }

    const depositNote = tokenNoteStorage.get(tokenDepositNoteId);
    if (!depositNote) {
      throw new Error(`Note not found: ${tokenDepositNoteId}`);
    }

    console.log("\n💰 Token Withdrawal Test:");
    console.log(`   Note ID: ${tokenDepositNoteId}`);
    console.log(`   Amount: ${depositNote.amount} tokens`);

    const relayer = Keypair.generate();
    const recipient = Keypair.generate();

    // Airdrop SOL for fees
    await airdropAndConfirm(provider, relayer.publicKey, 2 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(
      provider,
      recipient.publicKey,
      0.2 * LAMPORTS_PER_SOL
    );

    // Create token accounts
    const relayerTokenAccount = await createAndFundTokenAccount(
      provider,
      testMint,
      relayer.publicKey,
      0
    );
    const recipientTokenAccount = await createAndFundTokenAccount(
      provider,
      testMint,
      recipient.publicKey,
      0
    );

    // Register relayer
    await (program.methods as any)
      .addRelayer(relayer.publicKey)
      .accounts({ config: tokenConfig, admin: wallet.publicKey })
      .rpc();

    const withdrawAmount = depositNote.amount;
    const fee = (depositNote.amount * BigInt(feeBps)) / 10_000n;
    const toRecipient = depositNote.amount - fee;

    const extData = {
      recipient: recipient.publicKey,
      relayer: relayer.publicKey,
      fee: new BN(fee.toString()),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    const noteTreeAcc: any = await (
      program.account as any
    ).merkleTreeAccount.fetch(tokenNoteTree);
    const onchainRoot = extractRootFromAccount(noteTreeAcc);

    const updatedMerklePath = offchainTokenTree.getMerkleProof(
      depositNote.leafIndex
    );

    // Create dummy input
    const dummyPrivKey1 = randomBytes32();
    const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);
    const dummyBlinding1 = randomBytes32();
    const dummyCommitment1 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey1,
      dummyBlinding1,
      testMint
    );
    const dummyNullifier1 = computeNullifier(
      poseidon,
      dummyCommitment1,
      0,
      dummyPrivKey1
    );

    // Create dummy outputs
    const dummyOutputPrivKey0 = randomBytes32();
    const dummyOutputPubKey0 = derivePublicKey(poseidon, dummyOutputPrivKey0);
    const dummyOutputBlinding0 = randomBytes32();
    const dummyOutputCommitment0 = computeCommitment(
      poseidon,
      0n,
      dummyOutputPubKey0,
      dummyOutputBlinding0,
      testMint
    );

    const dummyOutputPrivKey1 = randomBytes32();
    const dummyOutputPubKey1 = derivePublicKey(poseidon, dummyOutputPrivKey1);
    const dummyOutputBlinding1 = randomBytes32();
    const dummyOutputCommitment1 = computeCommitment(
      poseidon,
      0n,
      dummyOutputPubKey1,
      dummyOutputBlinding1,
      testMint
    );

    const zeros = offchainTokenTree.getZeros();
    const zeroPathElements = zeros.slice(0, 16).map((z) => bytesToBigIntBE(z));

    const proof = await generateTransactionProof({
      root: onchainRoot,
      publicAmount: -withdrawAmount,
      extDataHash,
      mintAddress: testMint,
      inputNullifiers: [depositNote.nullifier, dummyNullifier1],
      outputCommitments: [dummyOutputCommitment0, dummyOutputCommitment1],

      inputAmounts: [depositNote.amount, 0n],
      inputPrivateKeys: [depositNote.privateKey, dummyPrivKey1],
      inputPublicKeys: [depositNote.publicKey, dummyPubKey1],
      inputBlindings: [depositNote.blinding, dummyBlinding1],
      inputMerklePaths: [
        updatedMerklePath,
        { pathElements: zeroPathElements, pathIndices: new Array(16).fill(0) },
      ],

      outputAmounts: [0n, 0n],
      outputOwners: [dummyOutputPubKey0, dummyOutputPubKey1],
      outputBlindings: [dummyOutputBlinding0, dummyOutputBlinding1],
    });

    const [nullifierMarker0] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_v3"), Buffer.from(depositNote.nullifier)],
      program.programId
    );
    const [nullifierMarker1] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_v3"), Buffer.from(dummyNullifier1)],
      program.programId
    );

    try {
      const modifyComputeUnits = ComputeBudgetProgram.setComputeUnitLimit({
        units: 1_400_000,
      });
      const addPriorityFee = ComputeBudgetProgram.setComputeUnitPrice({
        microLamports: 1,
      });

      const ix = await (program.methods as any)
        .transact(
          Array.from(onchainRoot),
          new BN(-withdrawAmount.toString()),
          Array.from(extDataHash),
          testMint,
          Array.from(depositNote.nullifier),
          Array.from(dummyNullifier1),
          Array.from(dummyOutputCommitment0),
          Array.from(dummyOutputCommitment1),
          extData,
          proof
        )
        .accounts({
          config: tokenConfig,
          vault: tokenVault,
          noteTree: tokenNoteTree,
          nullifiers: tokenNullifiers,
          nullifierMarker0,
          nullifierMarker1,
          relayer: relayer.publicKey,
          recipient: recipient.publicKey,
          vaultTokenAccount,
          userTokenAccount: relayerTokenAccount,
          recipientTokenAccount,
          relayerTokenAccount,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .instruction();

      const { blockhash } = await provider.connection.getLatestBlockhash();
      const messageV0 = new TransactionMessage({
        payerKey: relayer.publicKey,
        recentBlockhash: blockhash,
        instructions: [modifyComputeUnits, addPriorityFee, ix],
      }).compileToV0Message();

      const versionedTx = new VersionedTransaction(messageV0);
      versionedTx.sign([relayer]);

      const sig = await provider.connection.sendTransaction(versionedTx);
      await provider.connection.confirmTransaction({
        signature: sig,
        blockhash: blockhash,
        lastValidBlockHeight: (await provider.connection.getLatestBlockhash())
          .lastValidBlockHeight,
      });

      // Insert outputs into offchain tree
      offchainTokenTree.insert(dummyOutputCommitment0);
      offchainTokenTree.insert(dummyOutputCommitment1);

      console.log("\n✅ Token withdrawal successful");
      console.log(`   Withdrawn: ${withdrawAmount} tokens`);
      console.log(`   Fee: ${fee} tokens`);
      console.log(`   To recipient: ${toRecipient} tokens`);

      tokenNoteStorage.markSpent(tokenDepositNoteId!);
    } catch (e: any) {
      if (e instanceof SendTransactionError) {
        const logs = await e.getLogs(provider.connection);
        console.error("Token withdrawal failed:", logs);
      }
      throw e;
    }
  });

  // =============================================================================
  // Token Private Transfer Test
  // =============================================================================

  it("transfers SPL tokens privately", async () => {
    console.log("\n🔄 SPL Token Private Transfer Test:\n");

    // Alice deposits tokens
    const alice = Keypair.generate();
    console.log(`   Alice: ${alice.publicKey.toBase58()}`);
    await airdropAndConfirm(provider, alice.publicKey, 3 * LAMPORTS_PER_SOL);

    // Create Alice's token account and fund it
    const aliceTokenAccount = await createAndFundTokenAccount(
      provider,
      testMint,
      alice.publicKey,
      TOKEN_AMOUNT * 2
    );

    // Register Alice as relayer
    await (program.methods as any)
      .addRelayer(alice.publicKey)
      .accounts({ config: tokenConfig, admin: wallet.publicKey })
      .rpc();

    const aliceDepositAmount = BigInt(TOKEN_AMOUNT * 2);
    const alicePrivateKey = randomBytes32();
    const alicePublicKey = derivePublicKey(poseidon, alicePrivateKey);
    const aliceBlinding = randomBytes32();

    const aliceCommitment = computeCommitment(
      poseidon,
      aliceDepositAmount,
      alicePublicKey,
      aliceBlinding,
      testMint
    );

    const aliceDummyOutput = randomBytes32();
    const aliceDummyPubKey = derivePublicKey(poseidon, aliceDummyOutput);
    const aliceDummyBlinding = randomBytes32();
    const aliceDummyCommitment = computeCommitment(
      poseidon,
      0n,
      aliceDummyPubKey,
      aliceDummyBlinding,
      testMint
    );

    const aliceLeafIndex = offchainTokenTree.nextIndex;
    const aliceNullifier = computeNullifier(
      poseidon,
      aliceCommitment,
      aliceLeafIndex,
      alicePrivateKey
    );

    // Generate deposit proof for Alice
    const dummyPrivKey0 = randomBytes32();
    const dummyPrivKey1 = randomBytes32();
    const dummyPubKey0 = derivePublicKey(poseidon, dummyPrivKey0);
    const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);
    const dummyBlinding0 = randomBytes32();
    const dummyBlinding1 = randomBytes32();
    const dummyCommitment0 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey0,
      dummyBlinding0,
      testMint
    );
    const dummyCommitment1 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey1,
      dummyBlinding1,
      testMint
    );
    const dummyNullifier0 = computeNullifier(
      poseidon,
      dummyCommitment0,
      0,
      dummyPrivKey0
    );
    const dummyNullifier1 = computeNullifier(
      poseidon,
      dummyCommitment1,
      0,
      dummyPrivKey1
    );

    const extDataDeposit = {
      recipient: alice.publicKey,
      relayer: alice.publicKey,
      fee: new BN(0),
      refund: new BN(0),
    };
    const extDataHashDeposit = computeExtDataHash(poseidon, extDataDeposit);

    let noteTreeAcc: any = await (
      program.account as any
    ).merkleTreeAccount.fetch(tokenNoteTree);
    let onchainRoot = extractRootFromAccount(noteTreeAcc);

    const zeros = offchainTokenTree.getZeros();
    const zeroPathElements = zeros.slice(0, 16).map((z) => bytesToBigIntBE(z));

    const depositProof = await generateTransactionProof({
      root: onchainRoot,
      publicAmount: aliceDepositAmount,
      extDataHash: extDataHashDeposit,
      mintAddress: testMint,
      inputNullifiers: [dummyNullifier0, dummyNullifier1],
      outputCommitments: [aliceCommitment, aliceDummyCommitment],
      inputAmounts: [0n, 0n],
      inputPrivateKeys: [dummyPrivKey0, dummyPrivKey1],
      inputPublicKeys: [dummyPubKey0, dummyPubKey1],
      inputBlindings: [dummyBlinding0, dummyBlinding1],
      inputMerklePaths: [
        { pathElements: zeroPathElements, pathIndices: new Array(16).fill(0) },
        { pathElements: zeroPathElements, pathIndices: new Array(16).fill(0) },
      ],
      outputAmounts: [aliceDepositAmount, 0n],
      outputOwners: [alicePublicKey, aliceDummyPubKey],
      outputBlindings: [aliceBlinding, aliceDummyBlinding],
    });

    const [nullifierMarker0] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_v3"), Buffer.from(dummyNullifier0)],
      program.programId
    );
    const [nullifierMarker1] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_v3"), Buffer.from(dummyNullifier1)],
      program.programId
    );

    const depositTx = await (program.methods as any)
      .transact(
        Array.from(onchainRoot),
        new BN(aliceDepositAmount.toString()),
        Array.from(extDataHashDeposit),
        testMint,
        Array.from(dummyNullifier0),
        Array.from(dummyNullifier1),
        Array.from(aliceCommitment),
        Array.from(aliceDummyCommitment),
        extDataDeposit,
        depositProof
      )
      .accounts({
        config: tokenConfig,
        vault: tokenVault,
        noteTree: tokenNoteTree,
        nullifiers: tokenNullifiers,
        nullifierMarker0,
        nullifierMarker1,
        relayer: alice.publicKey,
        recipient: alice.publicKey,
        vaultTokenAccount,
        userTokenAccount: aliceTokenAccount,
        recipientTokenAccount: aliceTokenAccount,
        relayerTokenAccount: aliceTokenAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .instruction();

    const modifyComputeUnits = ComputeBudgetProgram.setComputeUnitLimit({
      units: 1_400_000,
    });
    const addPriorityFee = ComputeBudgetProgram.setComputeUnitPrice({
      microLamports: 1,
    });

    const { blockhash } = await provider.connection.getLatestBlockhash();
    const messageV0 = new TransactionMessage({
      payerKey: alice.publicKey,
      recentBlockhash: blockhash,
      instructions: [modifyComputeUnits, addPriorityFee, depositTx],
    }).compileToV0Message();

    const versionedTx = new VersionedTransaction(messageV0);
    versionedTx.sign([alice]);

    const depositSig = await provider.connection.sendTransaction(versionedTx);
    await provider.connection.confirmTransaction({
      signature: depositSig,
      blockhash: blockhash,
      lastValidBlockHeight: (await provider.connection.getLatestBlockhash())
        .lastValidBlockHeight,
    });

    offchainTokenTree.insert(aliceCommitment);
    offchainTokenTree.insert(aliceDummyCommitment);

    console.log(
      `✅ Alice deposited ${aliceDepositAmount} tokens (Leaf ${aliceLeafIndex})\n`
    );

    // =============================================================================
    // PRIVATE TRANSFER: Alice sends half to Bob
    // =============================================================================

    console.log("🔄 Private Transfer: Alice → Bob (SPL Tokens)\n");

    const bobPrivateKey = randomBytes32();
    const bobPublicKey = derivePublicKey(poseidon, bobPrivateKey);
    const bobBlinding = randomBytes32();

    const transferAmount = BigInt(TOKEN_AMOUNT);
    const changeAmount = aliceDepositAmount - transferAmount;

    console.log("📋 Transfer Breakdown:");
    console.log(`   Input: Alice's ${aliceDepositAmount} tokens note`);
    console.log(`   Output 1: Bob receives ${transferAmount} tokens`);
    console.log(`   Output 2: Alice keeps ${changeAmount} tokens (change)\n`);

    const aliceChangePrivKey = randomBytes32();
    const aliceChangePubKey = derivePublicKey(poseidon, aliceChangePrivKey);
    const aliceChangeBlinding = randomBytes32();

    const bobCommitment = computeCommitment(
      poseidon,
      transferAmount,
      bobPublicKey,
      bobBlinding,
      testMint
    );

    const aliceChangeCommitment = computeCommitment(
      poseidon,
      changeAmount,
      aliceChangePubKey,
      aliceChangeBlinding,
      testMint
    );

    const transferDummyPrivKey = randomBytes32();
    const transferDummyPubKey = derivePublicKey(poseidon, transferDummyPrivKey);
    const transferDummyBlinding = randomBytes32();
    const transferDummyCommitment = computeCommitment(
      poseidon,
      0n,
      transferDummyPubKey,
      transferDummyBlinding,
      testMint
    );
    const transferDummyNullifier = computeNullifier(
      poseidon,
      transferDummyCommitment,
      0,
      transferDummyPrivKey
    );

    const extDataTransfer = {
      recipient: alice.publicKey,
      relayer: alice.publicKey,
      fee: new BN(0),
      refund: new BN(0),
    };
    const extDataHashTransfer = computeExtDataHash(poseidon, extDataTransfer);

    noteTreeAcc = await (program.account as any).merkleTreeAccount.fetch(
      tokenNoteTree
    );
    onchainRoot = extractRootFromAccount(noteTreeAcc);

    const aliceUpdatedPath = offchainTokenTree.getMerkleProof(aliceLeafIndex);

    const transferProof = await generateTransactionProof({
      root: onchainRoot,
      publicAmount: 0n,
      extDataHash: extDataHashTransfer,
      mintAddress: testMint,
      inputNullifiers: [aliceNullifier, transferDummyNullifier],
      outputCommitments: [bobCommitment, aliceChangeCommitment],

      inputAmounts: [aliceDepositAmount, 0n],
      inputPrivateKeys: [alicePrivateKey, transferDummyPrivKey],
      inputPublicKeys: [alicePublicKey, transferDummyPubKey],
      inputBlindings: [aliceBlinding, transferDummyBlinding],
      inputMerklePaths: [
        aliceUpdatedPath,
        { pathElements: zeroPathElements, pathIndices: new Array(16).fill(0) },
      ],

      outputAmounts: [transferAmount, changeAmount],
      outputOwners: [bobPublicKey, aliceChangePubKey],
      outputBlindings: [bobBlinding, aliceChangeBlinding],
    });

    const [aliceNullifierMarker] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_v3"), Buffer.from(aliceNullifier)],
      program.programId
    );
    const [transferDummyNullifierMarker] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_v3"), Buffer.from(transferDummyNullifier)],
      program.programId
    );

    const transferTx = await (program.methods as any)
      .transact(
        Array.from(onchainRoot),
        new BN(0),
        Array.from(extDataHashTransfer),
        testMint,
        Array.from(aliceNullifier),
        Array.from(transferDummyNullifier),
        Array.from(bobCommitment),
        Array.from(aliceChangeCommitment),
        extDataTransfer,
        transferProof
      )
      .accounts({
        config: tokenConfig,
        vault: tokenVault,
        noteTree: tokenNoteTree,
        nullifiers: tokenNullifiers,
        nullifierMarker0: aliceNullifierMarker,
        nullifierMarker1: transferDummyNullifierMarker,
        relayer: alice.publicKey,
        recipient: alice.publicKey,
        vaultTokenAccount,
        userTokenAccount: aliceTokenAccount,
        recipientTokenAccount: aliceTokenAccount,
        relayerTokenAccount: aliceTokenAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .instruction();

    const transferComputeUnits = ComputeBudgetProgram.setComputeUnitLimit({
      units: 1_400_000,
    });
    const transferPriorityFee = ComputeBudgetProgram.setComputeUnitPrice({
      microLamports: 1,
    });

    const { blockhash: transferBlockhash } =
      await provider.connection.getLatestBlockhash();
    const transferMessageV0 = new TransactionMessage({
      payerKey: alice.publicKey,
      recentBlockhash: transferBlockhash,
      instructions: [transferComputeUnits, transferPriorityFee, transferTx],
    }).compileToV0Message();

    const transferVersionedTx = new VersionedTransaction(transferMessageV0);
    transferVersionedTx.sign([alice]);

    const transferSig = await provider.connection.sendTransaction(
      transferVersionedTx
    );
    await provider.connection.confirmTransaction({
      signature: transferSig,
      blockhash: transferBlockhash,
      lastValidBlockHeight: (await provider.connection.getLatestBlockhash())
        .lastValidBlockHeight,
    });

    const bobLeafIndex = offchainTokenTree.insert(bobCommitment);
    const aliceChangeLeafIndex = offchainTokenTree.insert(
      aliceChangeCommitment
    );

    console.log("✅ Private token transfer complete!");
    console.log(
      `   Bob's note: ${transferAmount} tokens (Leaf ${bobLeafIndex})`
    );
    console.log(
      `   Alice's change: ${changeAmount} tokens (Leaf ${aliceChangeLeafIndex})\n`
    );
  });

  // =============================================================================
  // Token Error Cases
  // =============================================================================

  it("rejects token deposit with wrong mint address", async () => {
    const sender = Keypair.generate();
    await airdropAndConfirm(provider, sender.publicKey, 2 * LAMPORTS_PER_SOL);

    // Create a DIFFERENT token mint
    const wrongMint = await createMint(
      provider.connection,
      wallet.payer,
      wallet.publicKey,
      null,
      MINT_DECIMALS
    );

    const senderTokenAccount = await createAndFundTokenAccount(
      provider,
      wrongMint,
      sender.publicKey,
      TOKEN_AMOUNT
    );

    await (program.methods as any)
      .addRelayer(sender.publicKey)
      .accounts({ config: tokenConfig, admin: wallet.publicKey })
      .rpc();

    const depositAmount = BigInt(TOKEN_AMOUNT);
    const privateKey = randomBytes32();
    const publicKey = derivePublicKey(poseidon, privateKey);
    const blinding = randomBytes32();

    // Use WRONG mint in commitment
    const commitment = computeCommitment(
      poseidon,
      depositAmount,
      publicKey,
      blinding,
      wrongMint
    );

    const dummyOutputPrivKey = randomBytes32();
    const dummyOutputPubKey = derivePublicKey(poseidon, dummyOutputPrivKey);
    const dummyOutputBlinding = randomBytes32();
    const dummyOutputCommitment = computeCommitment(
      poseidon,
      0n,
      dummyOutputPubKey,
      dummyOutputBlinding,
      wrongMint
    );

    const dummyPrivKey0 = randomBytes32();
    const dummyPrivKey1 = randomBytes32();
    const dummyPubKey0 = derivePublicKey(poseidon, dummyPrivKey0);
    const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);
    const dummyBlinding0 = randomBytes32();
    const dummyBlinding1 = randomBytes32();

    const dummyCommitment0 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey0,
      dummyBlinding0,
      wrongMint
    );
    const dummyCommitment1 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey1,
      dummyBlinding1,
      wrongMint
    );

    const dummyNullifier0 = computeNullifier(
      poseidon,
      dummyCommitment0,
      0,
      dummyPrivKey0
    );
    const dummyNullifier1 = computeNullifier(
      poseidon,
      dummyCommitment1,
      0,
      dummyPrivKey1
    );

    const extData = {
      recipient: sender.publicKey,
      relayer: sender.publicKey,
      fee: new BN(0),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    const noteTreeAcc: any = await (
      program.account as any
    ).merkleTreeAccount.fetch(tokenNoteTree);
    const onchainRoot = extractRootFromAccount(noteTreeAcc);

    const zeros = offchainTokenTree.getZeros();
    const zeroPathElements = zeros.slice(0, 16).map((z) => bytesToBigIntBE(z));

    const proof = await generateTransactionProof({
      root: onchainRoot,
      publicAmount: depositAmount,
      extDataHash,
      mintAddress: wrongMint, // WRONG MINT!
      inputNullifiers: [dummyNullifier0, dummyNullifier1],
      outputCommitments: [commitment, dummyOutputCommitment],

      inputAmounts: [0n, 0n],
      inputPrivateKeys: [dummyPrivKey0, dummyPrivKey1],
      inputPublicKeys: [dummyPubKey0, dummyPubKey1],
      inputBlindings: [dummyBlinding0, dummyBlinding1],
      inputMerklePaths: [
        { pathElements: zeroPathElements, pathIndices: new Array(16).fill(0) },
        { pathElements: zeroPathElements, pathIndices: new Array(16).fill(0) },
      ],

      outputAmounts: [depositAmount, 0n],
      outputOwners: [publicKey, dummyOutputPubKey],
      outputBlindings: [blinding, dummyOutputBlinding],
    });

    const [nullifierMarker0] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_v3"), Buffer.from(dummyNullifier0)],
      program.programId
    );
    const [nullifierMarker1] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_v3"), Buffer.from(dummyNullifier1)],
      program.programId
    );

    try {
      await (program.methods as any)
        .transact(
          Array.from(onchainRoot),
          new BN(depositAmount.toString()),
          Array.from(extDataHash),
          wrongMint, // Pass wrong mint!
          Array.from(dummyNullifier0),
          Array.from(dummyNullifier1),
          Array.from(commitment),
          Array.from(dummyOutputCommitment),
          extData,
          proof
        )
        .accounts({
          config: tokenConfig,
          vault: tokenVault,
          noteTree: tokenNoteTree,
          nullifiers: tokenNullifiers,
          nullifierMarker0,
          nullifierMarker1,
          relayer: sender.publicKey,
          recipient: sender.publicKey,
          vaultTokenAccount,
          userTokenAccount: senderTokenAccount,
          recipientTokenAccount: senderTokenAccount,
          relayerTokenAccount: senderTokenAccount,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .signers([sender])
        .rpc();

      throw new Error("Should have failed with wrong mint address");
    } catch (e: any) {
      if (e.message.includes("Should have failed")) {
        throw e;
      }
      // Expected error
      console.log("\n✅ Correctly rejected deposit with wrong mint address");
      console.log(`   Error: ${e.message}`);
    }
  });

  after(() => {
    console.log("\n📊 SPL Token Tests Complete!\n");
    console.log("All token tests passed ✅");
  });
});

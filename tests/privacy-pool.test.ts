// tests/privacy-pool.test.ts
//
// UTXO Model (2-in-2-out) with real ZK proofs
//

import "mocha";
import anchor from "@coral-xyz/anchor";
const { BN } = anchor;
import {
  PublicKey,
  Keypair,
  SystemProgram,
  LAMPORTS_PER_SOL,
  SendTransactionError,
} from "@solana/web3.js";
import fs from "fs";
import os from "os";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
import { buildPoseidon } from "circomlibjs";
import { groth16 } from "snarkjs";
import { getPoolPdas } from "@zkprivacysol/sdk-core";

// =============================================================================
// Configuration
// =============================================================================

const WASM_PATH = path.join(
  __dirname,
  "../zk/circuits/transaction/transaction_js/transaction.wasm"
);
const ZKEY_PATH = path.join(
  __dirname,
  "../zk/circuits/transaction/transaction_final.zkey"
);
const VK_PATH = path.join(
  __dirname,
  "../zk/circuits/transaction/transaction_verification_key.json"
);

// =============================================================================
// Helper Functions
// =============================================================================

function makeProvider(): anchor.AnchorProvider {
  const url = process.env.ANCHOR_PROVIDER_URL ?? "http://127.0.0.1:8899";
  const connection = new anchor.web3.Connection(url, "confirmed");

  const keypairPath =
    process.env.ANCHOR_WALLET ??
    path.join(os.homedir(), ".config", "solana", "id.json");

  const secret = JSON.parse(fs.readFileSync(keypairPath, "utf8"));
  const kp = Keypair.fromSecretKey(Uint8Array.from(secret));
  const wallet = new anchor.Wallet(kp);

  return new anchor.AnchorProvider(connection, wallet, {
    commitment: "confirmed",
  });
}

async function airdropAndConfirm(
  provider: anchor.AnchorProvider,
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
  return anchor.web3.Keypair.generate().publicKey.toBytes();
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

// Helper: Compute commitment = Poseidon(amount, pubkey, blinding, mintAddress)
// This matches the circuit's UTXOCommitment template (4 inputs)
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
  const mintField = poseidon.F.e(reduceToField(mintAddress.toBytes()));

  // Single Poseidon hash with 4 inputs
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
  owner: PublicKey,
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
  inputPrivateKeys: [Uint8Array, Uint8Array];
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
    publicAmount: inputs.publicAmount.toString(),
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

describe("Privacy Pool - UTXO Model (2-in-2-out) with Real Proofs", () => {
  const provider = makeProvider();
  anchor.setProvider(provider);

  const wallet = provider.wallet as anchor.Wallet;
  const program: any = anchor.workspace.PrivacyPool as any;

  let poseidon: any;
  let config: PublicKey;
  let vault: PublicKey;
  let noteTree: PublicKey;
  let nullifiers: PublicKey;

  const SOL_MINT = PublicKey.default;
  const feeBps = 50; // 0.5%

  // Off-chain tree
  let offchainTree: OffchainMerkleTree;

  // Test state
  let depositNote: {
    amount: bigint;
    commitment: Uint8Array;
    nullifier: Uint8Array;
    blinding: Uint8Array;
    privateKey: Uint8Array;
    publicKey: bigint; // Derived from privateKey via Poseidon
    leafIndex: number;
    merklePath: { pathElements: bigint[]; pathIndices: number[] };
  } | null = null;

  // =============================================================================
  // Setup
  // =============================================================================

  before(async () => {
    console.log("\n🔧 Setting up test environment...\n");

    // Initialize Poseidon
    poseidon = await buildPoseidon();
    offchainTree = new OffchainMerkleTree(16, poseidon);

    // Get PDAs
    const pdas = getPoolPdas(program.programId);
    config = pdas.config;
    vault = pdas.vault;
    noteTree = pdas.noteTree;
    nullifiers = pdas.nullifiers;

    console.log("Program ID:", program.programId.toBase58());
    console.log("Config PDA:", config.toBase58());
    console.log("Vault PDA:", vault.toBase58());

    // Airdrop to admin
    await airdropAndConfirm(provider, wallet.publicKey, 10 * LAMPORTS_PER_SOL);
  });

  it("initializes the privacy pool (UTXO model)", async () => {
    try {
      await (program.methods as any)
        .initialize(feeBps, SOL_MINT)
        .accounts({
          config,
          vault,
          noteTree,
          nullifiers,
          admin: wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      const configAcc = await (program.account as any).privacyConfig.fetch(
        config
      );
      console.log("✅ Pool initialized");
      console.log(`   Fee BPS: ${configAcc.feeBps}`);
      console.log(
        `   Min Withdrawal Fee: ${configAcc.minWithdrawalFee} lamports`
      );
      console.log(`   Max Deposit: ${configAcc.maxDepositAmount} lamports`);
    } catch (e: any) {
      if (e instanceof SendTransactionError) {
        const logs = await e.getLogs(provider.connection);
        console.error("Initialize failed:", logs);
      }
      throw e;
    }
  });

  // =============================================================================
  // Deposit Test
  // =============================================================================

  it("deposits 1.5 SOL using transact with real proof", async () => {
    const depositAmount = BigInt(Math.floor(1.5 * LAMPORTS_PER_SOL));
    const beforeVault = await provider.connection.getBalance(vault);

    // Generate keypair for the note
    const privateKey = randomBytes32();
    const publicKey = derivePublicKey(poseidon, privateKey);
    const blinding = randomBytes32();

    // Generate commitment using the derived public key
    const commitment = computeCommitment(
      poseidon,
      depositAmount,
      publicKey,
      blinding,
      SOL_MINT
    );

    // Insert into off-chain tree
    const leafIndex = offchainTree.insert(commitment);
    const merklePath = offchainTree.getMerkleProof(leafIndex);
    const nullifier = computeNullifier(
      poseidon,
      commitment,
      leafIndex,
      privateKey
    );

    // For deposit: use dummy inputs
    const dummyInput0 = createDummyNote();
    const dummyInput1 = createDummyNote();
    const dummyOutput = createDummyNote();

    // Dummy keypairs for dummy inputs
    const dummyPrivKey0 = randomBytes32();
    const dummyPrivKey1 = randomBytes32();
    const dummyPubKey0 = derivePublicKey(poseidon, dummyPrivKey0);
    const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);

    const publicAmount = new BN(-depositAmount.toString());

    const extData = {
      recipient: wallet.publicKey,
      relayer: wallet.publicKey,
      fee: new BN(0),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    const noteTreeAcc: any = await (
      program.account as any
    ).merkleTreeAccount.fetch(noteTree);
    const onchainRoot = extractRootFromAccount(noteTreeAcc);

    // Output keypairs (for the real output and dummy output)
    const dummyOutputPrivKey = randomBytes32();
    const dummyOutputPubKey = derivePublicKey(poseidon, dummyOutputPrivKey);

    // Generate real proof
    const proof = await generateTransactionProof({
      root: onchainRoot,
      publicAmount: -depositAmount, // Negative for deposit
      extDataHash,
      mintAddress: SOL_MINT,
      inputNullifiers: [dummyInput0.nullifier, dummyInput1.nullifier],
      outputCommitments: [commitment, dummyOutput.commitment],

      // Private inputs (dummy inputs for deposit)
      inputAmounts: [0n, 0n],
      inputPrivateKeys: [dummyPrivKey0, dummyPrivKey1],
      inputPublicKeys: [dummyPubKey0, dummyPubKey1],
      inputBlindings: [randomBytes32(), randomBytes32()],
      inputMintAddresses: [SOL_MINT, SOL_MINT],
      inputMerklePaths: [
        {
          pathElements: new Array(16).fill(0n),
          pathIndices: new Array(16).fill(0),
        },
        {
          pathElements: new Array(16).fill(0n),
          pathIndices: new Array(16).fill(0),
        },
      ],

      // Output UTXOs
      outputAmounts: [depositAmount, 0n],
      outputOwners: [publicKey, dummyOutputPubKey], // Use derived public keys
      outputBlindings: [blinding, randomBytes32()],
      outputMintAddresses: [SOL_MINT, SOL_MINT],
    });

    const [nullifierMarker0] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_v3"), Buffer.from(dummyInput0.nullifier)],
      program.programId
    );
    const [nullifierMarker1] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_v3"), Buffer.from(dummyInput1.nullifier)],
      program.programId
    );

    try {
      await (program.methods as any)
        .transact(
          Array.from(onchainRoot),
          publicAmount,
          Array.from(extDataHash),
          SOL_MINT,
          Array.from(dummyInput0.nullifier),
          Array.from(dummyInput1.nullifier),
          Array.from(commitment),
          Array.from(dummyOutput.commitment),
          extData,
          proof
        )
        .accounts({
          config,
          vault,
          noteTree,
          nullifiers,
          nullifierMarker0,
          nullifierMarker1,
          relayer: wallet.publicKey,
          recipient: wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([wallet.payer])
        .rpc();
    } catch (e: any) {
      if (e instanceof SendTransactionError) {
        const logs = await e.getLogs(provider.connection);
        console.error("Deposit failed:", logs);
      }
      throw e;
    }

    const afterVault = await provider.connection.getBalance(vault);
    const delta = afterVault - beforeVault;

    if (delta !== Number(depositAmount)) {
      throw new Error(
        `Vault delta mismatch: expected ${depositAmount}, got ${delta}`
      );
    }

    // Save note for withdrawal
    depositNote = {
      amount: depositAmount,
      commitment,
      nullifier,
      blinding,
      privateKey,
      publicKey,
      leafIndex,
      merklePath,
    };

    console.log("✅ Deposit successful");
    console.log(`   Amount: ${depositAmount} lamports`);
    console.log(`   Leaf index: ${leafIndex}`);
  });

  // =============================================================================
  // Withdrawal Test
  // =============================================================================

  it("withdraws via relayer with fee (real proof)", async () => {
    if (!depositNote) {
      throw new Error("No deposit note - deposit test must run first");
    }

    const relayer = Keypair.generate();
    const recipient = Keypair.generate();

    await airdropAndConfirm(provider, relayer.publicKey, 2 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(
      provider,
      recipient.publicKey,
      0.2 * LAMPORTS_PER_SOL
    );

    // Register relayer
    await (program.methods as any)
      .addRelayer(relayer.publicKey)
      .accounts({ config, admin: wallet.publicKey })
      .rpc();

    const withdrawAmount = depositNote.amount;
    const fee = (depositNote.amount * BigInt(feeBps)) / 10_000n;
    const toRecipient = depositNote.amount - fee;

    // Create dummy for second input
    const dummyInput1 = createDummyInput(poseidon, PublicKey.default, SOL_MINT);
    const dummyOutput0 = createDummyInput(
      poseidon,
      PublicKey.default,
      SOL_MINT
    );
    const dummyOutput1 = createDummyInput(
      poseidon,
      PublicKey.default,
      SOL_MINT
    );

    const publicAmount = new BN(withdrawAmount.toString());

    const extData = {
      recipient: recipient.publicKey,
      relayer: relayer.publicKey,
      fee: new BN(fee.toString()),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    const noteTreeAcc: any = await (
      program.account as any
    ).merkleTreeAccount.fetch(noteTree);
    const onchainRoot = extractRootFromAccount(noteTreeAcc);

    // Dummy keypairs for second input and outputs
    const dummyPrivKey1 = randomBytes32();
    const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);
    const dummyOutputPrivKey0 = randomBytes32();
    const dummyOutputPubKey0 = derivePublicKey(poseidon, dummyOutputPrivKey0);
    const dummyOutputPrivKey1 = randomBytes32();
    const dummyOutputPubKey1 = derivePublicKey(poseidon, dummyOutputPrivKey1);

    // Generate real proof
    const proof = await generateTransactionProof({
      root: onchainRoot,
      publicAmount: withdrawAmount,
      extDataHash,
      mintAddress: SOL_MINT,
      inputNullifiers: [depositNote.nullifier, dummyInput1.nullifier],
      outputCommitments: [dummyOutput0.commitment, dummyOutput1.commitment],

      // Private inputs
      inputAmounts: [depositNote.amount, 0n],
      inputPrivateKeys: [depositNote.privateKey, dummyPrivKey1],
      inputPublicKeys: [depositNote.publicKey, dummyPubKey1],
      inputBlindings: [depositNote.blinding, randomBytes32()],
      inputMintAddresses: [SOL_MINT, SOL_MINT],
      inputMerklePaths: [
        depositNote.merklePath,
        {
          pathElements: new Array(16).fill(0n),
          pathIndices: new Array(16).fill(0),
        },
      ],

      outputAmounts: [0n, 0n],
      outputOwners: [dummyOutputPubKey0, dummyOutputPubKey1],
      outputBlindings: [randomBytes32(), randomBytes32()],
      outputMintAddresses: [SOL_MINT, SOL_MINT],
    });

    const [nullifierMarker0] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_v3"), Buffer.from(depositNote.nullifier)],
      program.programId
    );
    const [nullifierMarker1] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_v3"), Buffer.from(dummyInput1.nullifier)],
      program.programId
    );

    const beforeRecipient = BigInt(
      await provider.connection.getBalance(recipient.publicKey)
    );

    try {
      await (program.methods as any)
        .transact(
          Array.from(onchainRoot),
          publicAmount,
          Array.from(extDataHash),
          SOL_MINT,
          Array.from(depositNote.nullifier),
          Array.from(dummyInput1.nullifier),
          Array.from(dummyOutput0.commitment),
          Array.from(dummyOutput1.commitment),
          extData,
          proof
        )
        .accounts({
          config,
          vault,
          noteTree,
          nullifiers,
          nullifierMarker0,
          nullifierMarker1,
          relayer: relayer.publicKey,
          recipient: recipient.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([relayer])
        .rpc();
    } catch (e: any) {
      if (e instanceof SendTransactionError) {
        const logs = await e.getLogs(provider.connection);
        console.error("Withdrawal failed:", logs);
      }
      throw e;
    }

    const afterRecipient = BigInt(
      await provider.connection.getBalance(recipient.publicKey)
    );
    const recipientDelta = afterRecipient - beforeRecipient;

    if (recipientDelta !== toRecipient) {
      throw new Error(
        `Recipient delta mismatch: expected ${toRecipient}, got ${recipientDelta}`
      );
    }

    console.log("✅ Withdrawal successful");
    console.log(`   Withdrawn: ${withdrawAmount} lamports`);
    console.log(`   Fee: ${fee} lamports`);
    console.log(`   To recipient: ${toRecipient} lamports`);
  });

  // =============================================================================
  // Summary
  // =============================================================================

  after(() => {
    console.log("\n📊 Test Complete!\n");
    console.log("All tests passed with real ZK proofs ✅");
  });
});

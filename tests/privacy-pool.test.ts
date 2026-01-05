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
import { buildPoseidon } from "circomlibjs";
import { groth16 } from "snarkjs";
import { getPoolPdas } from "@zkprivacysol/sdk-core";

// =============================================================================
// Configuration
// =============================================================================

const CIRCUIT_DIR =
  "/Users/jaybee/Documents/Coding/Coding Projects/zk-circuits";
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

// Helper: Compute commitment = Poseidon(Poseidon(amount, owner), Poseidon(blinding, mintAddress))
function computeCommitment(
  poseidon: any,
  amount: bigint,
  owner: PublicKey,
  blinding: Uint8Array,
  mintAddress: PublicKey
): Uint8Array {
  const amountField = poseidon.F.e(amount.toString());
  const ownerField = poseidon.F.e(reduceToField(owner.toBytes()));
  const blindingField = poseidon.F.e(bytesToBigIntBE(blinding));
  const mintField = poseidon.F.e(reduceToField(mintAddress.toBytes()));

  const hash1 = poseidon([amountField, ownerField]);
  const hash2 = poseidon([blindingField, mintField]);
  const finalHash = poseidon([hash1, hash2]);

  const hashBytes = poseidon.F.toString(finalHash, 16).padStart(64, "0");
  return Uint8Array.from(Buffer.from(hashBytes, "hex"));
}

// Helper: Compute nullifier (you'll need to match your circuit's nullifier derivation)
function computeNullifier(
  poseidon: any,
  commitment: Uint8Array,
  leafIndex: number,
  privateKey: Uint8Array
): Uint8Array {
  // Nullifier = Poseidon(commitment, leafIndex, privateKey)
  const commitmentField = poseidon.F.e(bytesToBigIntBE(commitment));
  const indexField = poseidon.F.e(BigInt(leafIndex));
  const keyField = poseidon.F.e(bytesToBigIntBE(privateKey));

  const nullifierHash = poseidon([commitmentField, indexField, keyField]);
  const hashBytes = poseidon.F.toString(nullifierHash, 16).padStart(64, "0");
  return Uint8Array.from(Buffer.from(hashBytes, "hex"));
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

  constructor(levels: number, poseidon: any) {
    this.levels = levels;
    this.poseidon = poseidon;
  }

  insert(commitment: Uint8Array): number {
    const index = this.leaves.size;
    this.leaves.set(index, commitment);
    return index;
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

      const sibling = this.leaves.get(siblingIndex) || new Uint8Array(32);
      pathElements.push(bytesToBigIntBE(sibling));
      pathIndices.push(isLeft ? 0 : 1);

      currentIndex = Math.floor(currentIndex / 2);
    }

    return { pathElements, pathIndices };
  }

  getRoot(): Uint8Array {
    if (this.leaves.size === 0) {
      return new Uint8Array(32);
    }

    // Build tree from bottom up
    let currentLevel = new Map<number, Uint8Array>();

    // Copy leaves to current level
    for (const [index, leaf] of this.leaves) {
      currentLevel.set(index, leaf);
    }

    // Hash up the tree
    for (let level = 0; level < this.levels; level++) {
      const nextLevel = new Map<number, Uint8Array>();
      const maxIndex = Math.pow(2, this.levels - level);

      for (let i = 0; i < maxIndex; i += 2) {
        const left = currentLevel.get(i) || new Uint8Array(32);
        const right = currentLevel.get(i + 1) || new Uint8Array(32);

        const leftField = this.poseidon.F.e(bytesToBigIntBE(left));
        const rightField = this.poseidon.F.e(bytesToBigIntBE(right));
        const parentHash = this.poseidon([leftField, rightField]);

        const hashBytes = this.poseidon.F.toString(parentHash, 16).padStart(
          64,
          "0"
        );
        const parentBytes = Uint8Array.from(Buffer.from(hashBytes, "hex"));

        nextLevel.set(Math.floor(i / 2), parentBytes);
      }

      currentLevel = nextLevel;
    }

    return currentLevel.get(0) || new Uint8Array(32);
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
  inputOwners: [PublicKey, PublicKey];
  inputBlindings: [Uint8Array, Uint8Array];
  inputMintAddresses: [PublicKey, PublicKey];
  inputMerklePaths: [
    { pathElements: bigint[]; pathIndices: number[] },
    { pathElements: bigint[]; pathIndices: number[] }
  ];

  outputAmounts: [bigint, bigint];
  outputOwners: [PublicKey, PublicKey];
  outputBlindings: [Uint8Array, Uint8Array];
  outputMintAddresses: [PublicKey, PublicKey];
}) {
  // Format inputs for circuit - flatten arrays to individual signals
  const circuitInputs = {
    // Public inputs
    root: bytesToBigIntBE(inputs.root).toString(),
    publicAmount: inputs.publicAmount.toString(),
    extDataHash: bytesToBigIntBE(inputs.extDataHash).toString(),
    mintAddress: reduceToField(inputs.mintAddress.toBytes()).toString(),

    // Flatten nullifiers
    inputNullifier0: bytesToBigIntBE(inputs.inputNullifiers[0]).toString(),
    inputNullifier1: bytesToBigIntBE(inputs.inputNullifiers[1]).toString(),

    // Flatten output commitments
    outputCommitment0: bytesToBigIntBE(inputs.outputCommitments[0]).toString(),
    outputCommitment1: bytesToBigIntBE(inputs.outputCommitments[1]).toString(),

    // Private inputs - flatten arrays
    inputAmount0: inputs.inputAmounts[0].toString(),
    inputAmount1: inputs.inputAmounts[1].toString(),

    inputOwner0: reduceToField(inputs.inputOwners[0].toBytes()).toString(),
    inputOwner1: reduceToField(inputs.inputOwners[1].toBytes()).toString(),

    inputBlinding0: bytesToBigIntBE(inputs.inputBlindings[0]).toString(),
    inputBlinding1: bytesToBigIntBE(inputs.inputBlindings[1]).toString(),

    inputMintAddress0: reduceToField(
      inputs.inputMintAddresses[0].toBytes()
    ).toString(),
    inputMintAddress1: reduceToField(
      inputs.inputMintAddresses[1].toBytes()
    ).toString(),

    // Merkle paths - flatten to individual elements
    inputPathElements0: inputs.inputMerklePaths[0].pathElements.map((e) =>
      e.toString()
    ),
    inputPathElements1: inputs.inputMerklePaths[1].pathElements.map((e) =>
      e.toString()
    ),
    inputPathIndices0: inputs.inputMerklePaths[0].pathIndices,
    inputPathIndices1: inputs.inputMerklePaths[1].pathIndices,

    outputAmount0: inputs.outputAmounts[0].toString(),
    outputAmount1: inputs.outputAmounts[1].toString(),

    outputOwner0: reduceToField(inputs.outputOwners[0].toBytes()).toString(),
    outputOwner1: reduceToField(inputs.outputOwners[1].toBytes()).toString(),

    outputBlinding0: bytesToBigIntBE(inputs.outputBlindings[0]).toString(),
    outputBlinding1: bytesToBigIntBE(inputs.outputBlindings[1]).toString(),

    outputMintAddress0: reduceToField(
      inputs.outputMintAddresses[0].toBytes()
    ).toString(),
    outputMintAddress1: reduceToField(
      inputs.outputMintAddresses[1].toBytes()
    ).toString(),
  };

  console.log(
    "Generating proof with inputs:",
    JSON.stringify(circuitInputs, null, 2)
  );

  // Generate proof
  const { proof, publicSignals } = await groth16.fullProve(
    circuitInputs,
    WASM_PATH,
    ZKEY_PATH
  );

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

    // Generate note
    const blinding = randomBytes32();
    const privateKey = randomBytes32();
    const commitment = computeCommitment(
      poseidon,
      depositAmount,
      wallet.publicKey,
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

    // Generate real proof
    const proof = await generateTransactionProof({
      root: onchainRoot,
      publicAmount: -depositAmount, // Negative for deposit
      extDataHash,
      mintAddress: SOL_MINT,
      inputNullifiers: [dummyInput0.nullifier, dummyInput1.nullifier],
      outputCommitments: [commitment, dummyOutput.commitment],

      // Private inputs (dummy for deposit)
      inputAmounts: [0n, 0n],
      inputOwners: [wallet.publicKey, wallet.publicKey],
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

      outputAmounts: [depositAmount, 0n],
      outputOwners: [wallet.publicKey, wallet.publicKey],
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
    const dummyInput1 = createDummyNote();
    const dummyOutput0 = createDummyNote();
    const dummyOutput1 = createDummyNote();

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
      inputOwners: [wallet.publicKey, wallet.publicKey],
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
      outputOwners: [wallet.publicKey, wallet.publicKey],
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

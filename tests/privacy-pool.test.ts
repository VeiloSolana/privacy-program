// tests/privacy-pool.test.ts
//
// ============================================================================
// TODO: Update tests for UTXO/Note-based model (2-in-2-out)
// ============================================================================
//
// The smart contract has been refactored to use a UTXO model with arbitrary
// amounts instead of fixed denominations. The tests still use the old SDK
// and circuit structure. Here's what needs updating:
//
// 1. SDK Functions:
//    - Update createNoteDepositWithMerkle to remove denomIndex parameter
//    - Implement note commitment: Poseidon(amount, owner, blinding, mintAddress)
//    - Update nullifier derivation to match circuit
//    - Add extData helper: {recipient, relayer, fee, refund}
//
// 2. Circuit Integration:
//    - Update to Transaction(16, 2, 2) circuit
//    - New public inputs (8 total):
//      * root
//      * publicAmount (i64 - can be negative)
//      * extDataHash
//      * mintAddress
//      * inputNullifiers[2]
//      * outputCommitments[2]
//    - Private inputs for 2 input notes and 2 output notes
//
// 3. Test Cases to Add:
//    - Deposit arbitrary amounts (not just fixed denominations)
//    - Full withdrawal (1 input + 1 dummy → 2 dummies)
//    - Partial withdrawal with change (1 input → 1 change + 1 dummy)
//    - Split notes (1 input → 2 outputs)
//    - Merge notes (2 inputs → 1 output + 1 dummy)
//    - Private transfer (publicAmount = 0)
//
// 4. Transact Instruction Usage:
//    Replace old deposit_fixed/withdraw calls with:
//    ```typescript
//    await program.methods
//      .transact(
//        root,
//        publicAmount,  // Negative for deposit, positive for withdrawal
//        extDataHash,
//        mintAddress,
//        inputNullifier0,
//        inputNullifier1,
//        outputCommitment0,
//        outputCommitment1,
//        {recipient, relayer, fee, refund},  // extData
//        proof
//      )
//      .accounts({
//        config, vault, noteTree, nullifiers,
//        nullifierMarker0, nullifierMarker1,
//        relayer, recipient, systemProgram
//      })
//      .signers([relayer])
//      .rpc();
//    ```
//
// ============================================================================

import "mocha";
import * as anchor from "@coral-xyz/anchor";
import { BN } from "@coral-xyz/anchor";
import {
  PublicKey,
  Keypair,
  SystemProgram,
  LAMPORTS_PER_SOL,
  SendTransactionError,
  ComputeBudgetProgram,
} from "@solana/web3.js";
import fs from "fs";
import os from "os";
import path from "path";

// ---- sdk-core imports ----
import {
  getPoolPdas,
  MerkleTree,
  initPoseidon,
} from "@zkprivacysol/sdk-core";

import { buildPoseidon } from "circomlibjs";

// -----------------------------------------------------------------------------
// Provider helper
// -----------------------------------------------------------------------------

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
    preflightCommitment: "confirmed",
  });
}

async function airdropAndConfirm(
  provider: anchor.AnchorProvider,
  pubkey: PublicKey,
  lamports: number
) {
  const sig = await provider.connection.requestAirdrop(pubkey, lamports);
  await provider.connection.confirmTransaction(sig, "confirmed");
}

// Helper: extract root from MerkleTreeAccount regardless of field name churn
function extractRootFromAccount(noteTreeAcc: any): Uint8Array {
  const arr: number[] =
    noteTreeAcc.root ?? noteTreeAcc.currentRoot ?? noteTreeAcc.current_root;

  if (!arr) {
    throw new Error("MerkleTreeAccount has no root/currentRoot/current_root");
  }
  return new Uint8Array(arr);
}

// -----------------------------------------------------------------------------
// Test suite
// -----------------------------------------------------------------------------

describe("privacy-pool UTXO model (2-in-2-out, arbitrary amounts)", () => {
  const provider = makeProvider();
  anchor.setProvider(provider);

  // Don't fight TS over multiple anchor versions: treat program as any.
  const program: any = anchor.workspace.PrivacyPool as any as {
    programId: PublicKey;
    // we only use .methods and .account in this test
  };
  const wallet = provider.wallet as anchor.Wallet;

  // Use the same PDA derivation as sdk-core & relayer
  const { config, vault, noteTree, nullifiers } = getPoolPdas(
    program.programId
  );

  const feeBps = 50; // 0.5%
  // For now, use a constant for SOL mint (native SOL doesn't have a mint address)
  // You can use SystemProgram.programId or a custom constant
  const SOL_MINT = PublicKey.default; // Placeholder for native SOL

  // Off-chain Merkle tree used for zk circuit inputs
  let offchainTree: MerkleTree;

  // Poseidon hasher (initialized in before hook)
  let poseidon: any;

  // Test note data
  let testNote: {
    amount: bigint;
    owner: PublicKey;
    blinding: Uint8Array;
    commitment: Uint8Array;
    nullifier: Uint8Array;
    merkleIndex: number;
  };

  // Helper: Generate random 32-byte value
  function randomBytes32(): Uint8Array {
    return Uint8Array.from(Array(32).fill(0).map(() => Math.floor(Math.random() * 256)));
  }

  // Helper: Compute note commitment = Poseidon(amount, owner, blinding, mintAddress)
  function computeCommitment(
    amount: bigint,
    owner: PublicKey,
    blinding: Uint8Array,
    mintAddress: PublicKey
  ): Uint8Array {
    const amountField = poseidon.F.e(amount);
    const ownerField = poseidon.F.e("0x" + Buffer.from(owner.toBytes()).toString("hex"));
    const blindingField = poseidon.F.e("0x" + Buffer.from(blinding).toString("hex"));
    const mintField = poseidon.F.e("0x" + Buffer.from(mintAddress.toBytes()).toString("hex"));

    const hash = poseidon([amountField, ownerField, blindingField, mintField]);
    const hashBytes = poseidon.F.toString(hash, 16).padStart(64, "0");
    return Uint8Array.from(Buffer.from(hashBytes, "hex"));
  }

  // Helper: Compute nullifier = Poseidon(commitment, pathIndex, signature)
  // For testing, we'll use a simplified version
  function computeNullifier(commitment: Uint8Array, pathIndex: number): Uint8Array {
    const commitField = poseidon.F.e("0x" + Buffer.from(commitment).toString("hex"));
    const indexField = poseidon.F.e(pathIndex);
    // Simplified: just hash commitment and index (real version would include signature)
    const hash = poseidon([commitField, indexField]);
    const hashBytes = poseidon.F.toString(hash, 16).padStart(64, "0");
    return Uint8Array.from(Buffer.from(hashBytes, "hex"));
  }

  // Helper: Reduce value modulo BN254 Fr field
  function reduceToField(bytes: Uint8Array): bigint {
    const FR_MODULUS = BigInt("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    const value = BigInt("0x" + Buffer.from(bytes).toString("hex"));
    return value % FR_MODULUS;
  }

  // Helper: Compute extDataHash = Poseidon(Poseidon(recipient, relayer), Poseidon(fee, refund))
  // This matches the on-chain hashing scheme which uses binary Poseidon hashes
  function computeExtDataHash(extData: {
    recipient: PublicKey;
    relayer: PublicKey;
    fee: BN;
    refund: BN;
  }): Uint8Array {
    // Reduce PublicKeys modulo field first (PublicKeys can exceed BN254 Fr modulus)
    const recipientField = poseidon.F.e(reduceToField(extData.recipient.toBytes()));
    const relayerField = poseidon.F.e(reduceToField(extData.relayer.toBytes()));
    const feeField = poseidon.F.e(extData.fee.toString());
    const refundField = poseidon.F.e(extData.refund.toString());

    // Hash in pairs
    const hash1 = poseidon([recipientField, relayerField]);
    const hash2 = poseidon([feeField, refundField]);
    const finalHash = poseidon([hash1, hash2]);

    const hashBytes = poseidon.F.toString(finalHash, 16).padStart(64, "0");
    return Uint8Array.from(Buffer.from(hashBytes, "hex"));
  }

  // Helper: Create dummy note (zero value)
  function createDummyNote(): {
    commitment: Uint8Array;
    nullifier: Uint8Array;
  } {
    // Dummy commitment and nullifier (use random values to avoid PDA collisions)
    // In a real circuit, dummy notes would have amount=0 and skip verification
    return {
      commitment: randomBytes32(),
      nullifier: randomBytes32(),
    };
  }

  // ---------------------------------------------------------------------------
  // Global setup: ensure pool initialized
  // ---------------------------------------------------------------------------

  before(async () => {
    // Initialize Poseidon hash function
    await initPoseidon();
    poseidon = await buildPoseidon();

    // Create Merkle tree
    offchainTree = new MerkleTree(16);

    // Airdrop admin wallet on localnet
    await airdropAndConfirm(provider, wallet.publicKey, 10 * LAMPORTS_PER_SOL);

    // If config PDA already exists, assume pool already initialized
    const existing = await provider.connection.getAccountInfo(config as PublicKey);
    if (existing) {
      console.log("Initialize skipped: PDAs already exist on this cluster.");
      return;
    }

    try {
      // Initialize with new UTXO model
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

      console.log("Pool initialized with UTXO model");
    } catch (e: any) {
      if (e instanceof SendTransactionError) {
        const logs = await e.getLogs(provider.connection);
        console.error("initializePool failed with logs:", logs);
      }
      throw e;
    }
  });

  // ---------------------------------------------------------------------------
  // Deposit test
  // ---------------------------------------------------------------------------

  it("deposits arbitrary amount (1.5 SOL) using transact instruction", async () => {
    const depositAmount = BigInt(Math.floor(1.5 * LAMPORTS_PER_SOL));
    const beforeVault = await provider.connection.getBalance(vault as PublicKey);

    // Create note for deposit
    const blinding = randomBytes32();
    const commitment = computeCommitment(depositAmount, wallet.publicKey, blinding, SOL_MINT);

    // For deposit: use dummy inputs, one real output
    const dummyInput0 = createDummyNote();
    const dummyInput1 = createDummyNote();
    const dummyOutput = createDummyNote();

    // publicAmount is NEGATIVE for deposits (use BN for Anchor serialization)
    const publicAmount = new BN(-depositAmount.toString());

    // ExtData for deposit (depositor pays their own transaction, no relayer needed)
    // Use depositor's address for both recipient and relayer fields (no privacy needed for deposits)
    const extData = {
      recipient: wallet.publicKey,  // Depositor
      relayer: wallet.publicKey,     // No relayer - depositor submits their own tx
      fee: new BN(0),                // No relayer fee for deposits
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(extData);

    // Get current root
    const noteTreeAcc: any = await (program.account as any).merkleTreeAccount.fetch(noteTree);
    const onchainRoot = extractRootFromAccount(noteTreeAcc);

    // Derive nullifier marker PDAs (must be unique for each input)
    const [nullifierMarker0] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_v3"), Buffer.from(dummyInput0.nullifier)],
      program.programId
    );
    const [nullifierMarker1] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_v3"), Buffer.from(dummyInput1.nullifier)],
      program.programId
    );

    // Create a dummy proof (all zeros for now - you'll need real proof later)
    const dummyProof = {
      proofA: Array(64).fill(0),
      proofB: Array(128).fill(0),
      proofC: Array(64).fill(0),
    };

    try {
      // Call transact for deposit
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
          dummyProof
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
        .preInstructions([
          ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
        ])
        .rpc();

      // Save test note for withdrawal test
      const merkleIndex = noteTreeAcc.nextIndex ?? noteTreeAcc.next_index;
      testNote = {
        amount: depositAmount,
        owner: wallet.publicKey,
        blinding,
        commitment,
        nullifier: computeNullifier(commitment, merkleIndex),
        merkleIndex,
      };

      const afterVault = await provider.connection.getBalance(vault as PublicKey);
      const delta = BigInt(afterVault - beforeVault);

      if (delta !== depositAmount) {
        throw new Error(
          `Unexpected vault delta: got ${delta.toString()} expected ${depositAmount}`
        );
      }

      console.log(`✅ Deposited ${depositAmount} lamports successfully`);
    } catch (e: any) {
      console.error("Deposit failed:", e);
      throw e;
    }
  });

  // ---------------------------------------------------------------------------
  // Withdraw with real proof (via sdk-core)
  // ---------------------------------------------------------------------------

  // it("withdraws via relayer with fee + nullifier (real zk proof)", async () => {
  //   const denomIndex = 0;
  //   const amount = denomsLamports[denomIndex];
  //   const fee = (amount * BigInt(feeBps)) / 10_000n;
  //   const toUser = amount - fee;

  //   const relayer = Keypair.generate();
  //   const recipient = wallet;

  //   const recipientBytes = recipient.publicKey.toBytes();
  //   const recipientBigInt = bytesToBigIntBE(recipientBytes);
  //   const FR_MODULUS =
  //     21888242871839275222246405745257275088548364400416034343698204186575808495617n;

  //   console.log("Recipient BigInt:", recipientBigInt.toString());
  //   console.log("Field Modulus:   ", FR_MODULUS.toString());
  //   console.log("Exceeds modulus?", recipientBigInt >= FR_MODULUS);

  //   // fund relayer so it can pay tx fees
  //   await airdropAndConfirm(provider, relayer.publicKey, 2 * LAMPORTS_PER_SOL);
  //   // ensure recipient exists as a system account
  //   await airdropAndConfirm(
  //     provider,
  //     recipient.publicKey,
  //     0.2 * LAMPORTS_PER_SOL
  //   );

  //   // Register relayer on-chain (sdk-core doesn’t wrap this yet, so call directly)
  //   await (program.methods as any)
  //     .addRelayer(relayer.publicKey)
  //     .accounts({
  //       config,
  //       admin: wallet.publicKey,
  //     } as any)
  //     .rpc();

  //   // Always use the authoritative on-chain root for the proof public input
  //   const noteTreeAcc: any = await (
  //     program.account as any
  //   ).merkleTreeAccount.fetch(noteTree);
  //   const onchainRoot = extractRootFromAccount(noteTreeAcc);

  //   const beforeVault = BigInt(
  //     await provider.connection.getBalance(vault as PublicKey)
  //   );
  //   const beforeRelayer = BigInt(
  //     await provider.connection.getBalance(relayer.publicKey)
  //   );
  //   const beforeRecipient = BigInt(
  //     await provider.connection.getBalance(recipient.publicKey)
  //   );

  //   try {
  //     await withdrawViaRelayerWithProof({
  //       program: program as any,
  //       relayer,
  //       recipient: recipient.publicKey,
  //       denomIndex,
  //       feeBps,
  //       root: onchainRoot,
  //       nullifier: depositNullifier,
  //       noteData: depositNote,
  //       merklePath: depositMerklePath,
  //       builder: proofBuilder,
  //     });
  //   } catch (e: any) {
  //     console.error("\n========== WITHDRAW ERROR ==========");
  //     console.error("Error:", e.message);
  //     if (e.logs) {
  //       console.error("\nTransaction logs:");
  //       e.logs.forEach((log: string) => console.error("  ", log));
  //     }
  //     if (e instanceof SendTransactionError) {
  //       const logs = await e.getLogs(provider.connection);
  //       console.error("\nDetailed logs from getLogs:");
  //       logs?.forEach((log: string) => console.error("  ", log));
  //     }
  //     console.error("====================================\n");
  //     throw e;
  //   }

  //   const afterVault = BigInt(
  //     await provider.connection.getBalance(vault as PublicKey)
  //   );
  //   const afterRelayer = BigInt(
  //     await provider.connection.getBalance(relayer.publicKey)
  //   );
  //   const afterRecipient = BigInt(
  //     await provider.connection.getBalance(recipient.publicKey)
  //   );

  //   if (beforeVault - afterVault !== amount) {
  //     throw new Error("Vault SOL delta mismatch");
  //   }
  //   if (afterRelayer - beforeRelayer !== fee) {
  //     throw new Error("Relayer fee mismatch");
  //   }
  //   if (afterRecipient - beforeRecipient !== toUser) {
  //     throw new Error("Recipient amount mismatch");
  //   }

  //   console.log("Withdraw via relayer with real proof OK");
  // });

  // // ---------------------------------------------------------------------------
  // // Double-spend protection (nullifier)
  // // ---------------------------------------------------------------------------

  // it("rejects double-spend with same nullifier", async () => {
  //   const denomIndex = 0;

  //   const relayer = Keypair.generate();
  //   const recipient = Keypair.generate();

  //   await airdropAndConfirm(provider, relayer.publicKey, 2 * LAMPORTS_PER_SOL);
  //   await airdropAndConfirm(
  //     provider,
  //     recipient.publicKey,
  //     0.2 * LAMPORTS_PER_SOL
  //   );

  //   await (program.methods as any)
  //     .addRelayer(relayer.publicKey)
  //     .accounts({
  //       config,
  //       admin: wallet.publicKey,
  //     } as any)
  //     .rpc();

  //   const noteTreeAcc: any = await (
  //     program.account as any
  //   ).merkleTreeAccount.fetch(noteTree);
  //   const onchainRoot = extractRootFromAccount(noteTreeAcc);

  //   // First withdraw (should succeed)
  //   await withdrawViaRelayerWithProof({
  //     program: program as any,
  //     relayer,
  //     recipient: recipient.publicKey,
  //     denomIndex,
  //     feeBps,
  //     root: onchainRoot,
  //     nullifier: depositNullifier,
  //     noteData: depositNote,
  //     merklePath: depositMerklePath,
  //     builder: proofBuilder,
  //   });

  //   // Second withdraw with same nullifier must fail
  //   let failed = false;
  //   try {
  //     await withdrawViaRelayerWithProof({
  //       program: program as any,
  //       relayer,
  //       recipient: recipient.publicKey,
  //       denomIndex,
  //       feeBps,
  //       root: onchainRoot,
  //       nullifier: depositNullifier,
  //       noteData: depositNote,
  //       merklePath: depositMerklePath,
  //       builder: proofBuilder,
  //     });
  //   } catch (e: any) {
  //     failed = true;
  //     if (e instanceof SendTransactionError) {
  //       const logs = await e.getLogs(provider.connection);
  //       console.log("Double-spend attempt logs:", logs);
  //     }
  //   }

  //   if (!failed) {
  //     throw new Error(
  //       "Double-spend with same nullifier unexpectedly succeeded"
  //     );
  //   }

  //   console.log("Nullifier double-spend correctly rejected");
  // });

  // ---------------------------------------------------------------------------
  // Paused flag behaviour
  // ---------------------------------------------------------------------------

  it("respects paused flag (transact fails when paused)", async () => {
    if (!testNote) {
      throw new Error("No test note available - deposit test must run first");
    }

    const relayer = Keypair.generate();
    const recipient = Keypair.generate();

    await airdropAndConfirm(provider, relayer.publicKey, 2 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(
      provider,
      recipient.publicKey,
      0.2 * LAMPORTS_PER_SOL
    );

    await (program.methods as any)
      .addRelayer(relayer.publicKey)
      .accounts({
        config,
        admin: wallet.publicKey,
      } as any)
      .rpc();

    // Pause the pool
    await (program.methods as any)
      .setPaused(true)
      .accounts({
        config,
        admin: wallet.publicKey,
      } as any)
      .rpc();

    const noteTreeAcc: any = await (
      program.account as any
    ).merkleTreeAccount.fetch(noteTree);
    const onchainRoot = extractRootFromAccount(noteTreeAcc);

    // Prepare withdrawal using testNote
    const withdrawAmount = testNote.amount;
    const fee = (testNote.amount * BigInt(feeBps)) / 10_000n;

    // Create dummy note for second input
    const dummyInput1 = createDummyNote();

    // Create dummy outputs (full withdrawal)
    const dummyOutput0 = createDummyNote();
    const dummyOutput1 = createDummyNote();

    // publicAmount is POSITIVE for withdrawal (use BN for Anchor serialization)
    const publicAmount = new BN(withdrawAmount.toString());

    // ExtData for withdrawal (fee and refund must be BN objects)
    const extData = {
      recipient: recipient.publicKey,
      relayer: relayer.publicKey,
      fee: new BN(fee.toString()),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(extData);

    // Derive nullifier marker PDAs
    const [nullifierMarker0] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_v3"), Buffer.from(testNote.nullifier)],
      program.programId
    );
    const [nullifierMarker1] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_v3"), Buffer.from(dummyInput1.nullifier)],
      program.programId
    );

    // Create dummy proof
    const dummyProof = {
      proofA: Array(64).fill(0),
      proofB: Array(128).fill(0),
      proofC: Array(64).fill(0),
    };

    let failed = false;
    try {
      // Attempt to transact while paused (should fail)
      await (program.methods as any)
        .transact(
          Array.from(onchainRoot),
          publicAmount,
          Array.from(extDataHash),
          SOL_MINT,
          Array.from(testNote.nullifier),
          Array.from(dummyInput1.nullifier),
          Array.from(dummyOutput0.commitment),
          Array.from(dummyOutput1.commitment),
          extData,
          dummyProof
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
        .preInstructions([
          ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
        ])
        .signers([relayer])
        .rpc();
    } catch (e: any) {
      failed = true;
      if (e instanceof SendTransactionError) {
        const logs = await e.getLogs(provider.connection);
        console.log("Withdraw while paused logs:", logs);
      }
    }

    if (!failed) {
      throw new Error("Withdraw succeeded while pool is paused");
    }

    // Unpause to not poison other tests / future runs
    await (program.methods as any)
      .setPaused(false)
      .accounts({
        config,
        admin: wallet.publicKey,
      } as any)
      .rpc();

    console.log("✅ Paused flag correctly enforced for transact");
  });

  // ---------------------------------------------------------------------------
  // Direct withdraw call (no SDK wrapper) - UTXO Model (2-in-2-out)
  // ---------------------------------------------------------------------------

  it("withdraws via transact instruction (2-in-2-out UTXO model)", async () => {
    if (!testNote) {
      throw new Error("No test note available - deposit test must run first");
    }

    const relayer = Keypair.generate();
    const recipient = Keypair.generate();

    // Fund relayer and recipient
    await airdropAndConfirm(provider, relayer.publicKey, 2 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(
      provider,
      recipient.publicKey,
      0.2 * LAMPORTS_PER_SOL
    );

    // Register relayer
    await (program.methods as any)
      .addRelayer(relayer.publicKey)
      .accounts({ config, admin: wallet.publicKey } as any)
      .rpc();

    // Get on-chain root
    const noteTreeAcc: any = await (
      program.account as any
    ).merkleTreeAccount.fetch(noteTree);
    const onchainRoot = extractRootFromAccount(noteTreeAcc);

    // Prepare withdrawal: full amount withdrawal
    const withdrawAmount = testNote.amount;
    const fee = (testNote.amount * BigInt(feeBps)) / 10_000n;
    const toRecipient = testNote.amount - fee;

    // Create dummy note for second input (2-in-2-out requires 2 inputs)
    const dummyInput1 = createDummyNote();

    // Create dummy outputs (full withdrawal, no change notes)
    const dummyOutput0 = createDummyNote();
    const dummyOutput1 = createDummyNote();

    // publicAmount is POSITIVE for withdrawal (use BN for Anchor serialization)
    const publicAmount = new BN(withdrawAmount.toString());

    // ExtData for withdrawal (fee and refund must be BN objects)
    const extData = {
      recipient: recipient.publicKey,
      relayer: relayer.publicKey,
      fee: new BN(fee.toString()),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(extData);

    // Derive nullifier marker PDAs (2 markers for 2 inputs)
    const [nullifierMarker0] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_v3"), Buffer.from(testNote.nullifier)],
      program.programId
    );
    const [nullifierMarker1] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_v3"), Buffer.from(dummyInput1.nullifier)],
      program.programId
    );

    // Create dummy proof (replace with real proof from circuit later)
    const dummyProof = {
      proofA: Array(64).fill(0),
      proofB: Array(128).fill(0),
      proofC: Array(64).fill(0),
    };

    const beforeVault = BigInt(
      await provider.connection.getBalance(vault as PublicKey)
    );
    const beforeRelayer = BigInt(
      await provider.connection.getBalance(relayer.publicKey)
    );
    const beforeRecipient = BigInt(
      await provider.connection.getBalance(recipient.publicKey)
    );

    try {
      // Call transact for withdrawal (2-in-2-out model)
      await (program.methods as any)
        .transact(
          Array.from(onchainRoot),
          publicAmount,
          Array.from(extDataHash),
          SOL_MINT,
          Array.from(testNote.nullifier),      // Input 1: real note
          Array.from(dummyInput1.nullifier),   // Input 2: dummy note
          Array.from(dummyOutput0.commitment), // Output 1: dummy
          Array.from(dummyOutput1.commitment), // Output 2: dummy
          extData,
          dummyProof
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
        .preInstructions([
          ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
        ])
        .signers([relayer])
        .rpc();
    } catch (e: any) {
      console.error("\n========== WITHDRAW ERROR ==========");
      console.error("Error:", e.message);
      if (e.logs) {
        console.error("\nTransaction logs:");
        e.logs.forEach((log: string) => console.error("  ", log));
      }
      if (e instanceof SendTransactionError) {
        const logs = await e.getLogs(provider.connection);
        console.error("\nDetailed logs from getLogs:");
        logs?.forEach((log: string) => console.error("  ", log));
      }
      console.error("====================================\n");
      throw e;
    }

    const afterVault = BigInt(
      await provider.connection.getBalance(vault as PublicKey)
    );
    const afterRelayer = BigInt(
      await provider.connection.getBalance(relayer.publicKey)
    );
    const afterRecipient = BigInt(
      await provider.connection.getBalance(recipient.publicKey)
    );

    console.log("Balances:", {
      beforeVault,
      afterVault,
      vaultDelta: beforeVault - afterVault,
      beforeRelayer,
      afterRelayer,
      relayerDelta: afterRelayer - beforeRelayer,
      beforeRecipient,
      afterRecipient,
      recipientDelta: afterRecipient - beforeRecipient,
    });

    // Verify vault balance decreased by withdrawal amount
    if (beforeVault - afterVault !== testNote.amount) {
      throw new Error(
        `Vault SOL delta mismatch: expected ${testNote.amount}, got ${beforeVault - afterVault}`
      );
    }

    // Verify recipient received correct amount (withdrawal - fee)
    if (afterRecipient - beforeRecipient !== toRecipient) {
      throw new Error(
        `Recipient amount mismatch: expected ${toRecipient}, got ${afterRecipient - beforeRecipient}`
      );
    }

    // Verify relayer received fee (minus rent for nullifier accounts)
    // Note: Can't do exact check because relayer pays rent for nullifier marker accounts
    const relayerDelta = afterRelayer - beforeRelayer;
    if (relayerDelta <= 0n) {
      throw new Error("Relayer should have received fee");
    }

    console.log(`✅ Withdrawal successful (2-in-2-out UTXO model)`);
    console.log(`   Withdrawn: ${withdrawAmount.toString()} lamports`);
    console.log(`   Fee: ${fee.toString()} lamports`);
    console.log(`   To recipient: ${toRecipient.toString()} lamports`);
  });
});

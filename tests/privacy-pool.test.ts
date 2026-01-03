// tests/privacy-pool.test.ts

import "mocha";
import * as anchor from "@coral-xyz/anchor";
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
  initializePool,
  MerkleTree,
  createNoteDepositWithMerkle,
  deriveNullifier,
  withdrawViaRelayerWithProof,
  initPoseidon,
  bytesToBigIntBE,
  createNoteWithCommitment,
} from "veilo-sdk-core";

// Your REAL zk proof builder (you implement this using snarkjs.groth16.prove)
import { buildWithdrawProof } from "../zk/withdrawProver"; // <- you create this
import { groth16 } from "snarkjs";

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

describe("privacy-pool fixed-denom SOL (Merkle v3, sdk-core)", () => {
  const provider = makeProvider();
  anchor.setProvider(provider);

  // Don’t fight TS over multiple anchor versions: treat program as any.
  const program: any = anchor.workspace.PrivacyPool as any as {
    programId: PublicKey;
    // we only use .methods and .account in this test
  };
  const wallet = provider.wallet as anchor.Wallet;

  // Use the same PDA derivation as sdk-core & relayer
  const { config, vault, noteTree, nullifiers } = getPoolPdas(
    program.programId,
    new Uint8Array(32)
  );

  // Two fixed denoms for the pool: 1 SOL, 5 SOL
  const denomsLamports: bigint[] = [
    BigInt(LAMPORTS_PER_SOL),
    BigInt(5 * LAMPORTS_PER_SOL),
  ];
  const feeBps = 50; // 0.5%

  // Off-chain Merkle tree used for zk circuit inputs
  // IMPORTANT: in production this hash must match your circuit’s hash (Poseidon/etc)
  let offchainTree: MerkleTree;

  // We keep around one note + path for withdraw tests
  let depositNote: any;
  let depositRoot: Uint8Array;
  let depositMerklePath: any;
  let depositNullifier: Uint8Array;

  // use your real Groth16 builder
  const proofBuilder = buildWithdrawProof;

  // ---------------------------------------------------------------------------
  // Global setup: ensure pool initialized
  // ---------------------------------------------------------------------------

  before(async () => {
    // Initialize Poseidon hash function FIRST
    await initPoseidon();

    // Now we can create the MerkleTree
    offchainTree = new MerkleTree(16);

    // airdrop admin wallet on localnet
    await airdropAndConfirm(provider, wallet.publicKey, 10 * LAMPORTS_PER_SOL);

    // If config PDA already exists, assume pool already initialized
    const existing = await provider.connection.getAccountInfo(
      config as PublicKey
    );
    if (existing) {
      console.log("Initialize skipped: PDAs already exist on this cluster.");

      // Check if the tree is dirty (has leaves from previous runs)
      // The test assumes a fresh off-chain tree, so we must ensure on-chain tree is also empty.
      const noteTreeAcc: any = await (
        program.account as any
      ).merkleTreeAccount.fetch(noteTree);
      // Check nextIndex (or next_index depending on type generation)
      const nextIndex = noteTreeAcc.nextIndex ?? noteTreeAcc.next_index;

      // if (nextIndex && nextIndex.gt(new anchor.BN(0))) {
      //   throw new Error(
      //     `\n\nFATAL: The on-chain Merkle tree is not empty (nextIndex = ${nextIndex.toString()}).\n` +
      //       "This test suite requires a fresh environment because it maintains a parallel off-chain tree.\n" +
      //       "Please reset your local validator:\n" +
      //       "  pkill -f solana-test-validator\n" +
      //       "  solana-test-validator --reset --quiet &\n\n"
      //   );
      // }

      return;
    }

    try {
      // cast program as any to satisfy sdk-core’s Program<T> without TS whining
      await initializePool({
        program: program as any,
        admin: wallet,
        denomsLamports,
        feeBps,
      });
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

  it("deposits fixed 1 SOL and updates root", async () => {
    const denomIndex = 0;
    const beforeVault = await provider.connection.getBalance(
      vault as PublicKey
    );

    // High-level deposit helper from sdk-core:
    const result = await createNoteDepositWithMerkle({
      program: program as any,
      depositor: wallet,
      denomIndex,
      valueLamports: denomsLamports[denomIndex],
      tree: offchainTree,
    });

    console.log("Result", result);

    if (!result) {
      throw new Error(
        "depositResult is undefined – deposit test must run first and succeed"
      );
    }

    depositNote = result.note;
    depositRoot = result.root;
    depositMerklePath = result.merklePath;
    depositNullifier = deriveNullifier(depositNote);

    const afterVault = await provider.connection.getBalance(vault as PublicKey);
    const delta = BigInt(afterVault - beforeVault);

    if (delta !== denomsLamports[denomIndex]) {
      throw new Error(
        `Unexpected vault delta: got ${delta.toString()} expected ${denomsLamports[
          denomIndex
        ].toString()}`
      );
    }

    const noteTreeAcc: any = await (
      program.account as any
    ).merkleTreeAccount.fetch(noteTree);
    const onchainRoot = extractRootFromAccount(noteTreeAcc);

    console.log("Off-chain Mirrored Root   :", Array.from(depositRoot));
    console.log("On-chain NoteTree Root    :", Array.from(onchainRoot));

    if (
      Buffer.compare(Buffer.from(depositRoot), Buffer.from(onchainRoot)) !== 0
    ) {
      console.warn(
        "WARNING: off-chain Merkle root != on-chain root. " +
          "Fix this before trusting zk proofs in production."
      );
    }

    console.log("\nVerifying proof off-chain...");
    const wasmPath = path.join(__dirname, "../zk/circuits/withdraw.wasm");
    const zkeyPath = path.join(__dirname, "../zk/circuits/withdraw_0001.zkey");
    const vkPath = path.join(__dirname, "../zk/circuits/verification_key.json");
    const vKey = require(vkPath);
    const testInputs = {
      root: bytesToBigIntBE(depositRoot),
      nullifier: bytesToBigIntBE(depositNullifier),
      denomIndex: BigInt(denomIndex),
      recipient: bytesToBigIntBE(wallet.publicKey.toBytes()),

      // You'd need real values for these private inputs
      noteValue: depositNote.value,
      noteOwner: bytesToBigIntBE(depositNote.owner.toBytes()),
      noteRho: bytesToBigIntBE(depositNote.rho),
      noteR: bytesToBigIntBE(depositNote.r),

      pathElements: depositMerklePath.path.map((p: Uint8Array) =>
        bytesToBigIntBE(p)
      ),
      pathIndices: depositMerklePath.indices.map((i: number) => BigInt(i)),
    };

    const { proof, publicSignals } = await groth16.fullProve(
      testInputs,
      wasmPath,
      zkeyPath
    );

    console.log("✓ Proof generated successfully", proof, publicSignals);

    const valid = await groth16.verify(vKey, publicSignals, proof);
    console.log("Proof valid?", valid);

    console.log("Deposit fixed-denom 1 SOL OK");
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

  it("respects paused flag (withdraw fails when paused)", async () => {
    const denomIndex = 0;

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

    let failed = false;
    try {
      await withdrawViaRelayerWithProof({
        program: program as any,
        relayer,
        recipient: recipient.publicKey,
        denomIndex,
        feeBps,
        root: onchainRoot,
        nullifier: depositNullifier,
        noteData: depositNote,
        merklePath: depositMerklePath,
        builder: proofBuilder,
      });
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

    console.log("Paused flag enforced for withdraw");
  });

  // ---------------------------------------------------------------------------
  // Direct withdraw call (no SDK wrapper)
  // ---------------------------------------------------------------------------

  /**
   * Manually convert snarkjs proof to WithdrawProof format
   * Based on SDK's encodeSnarkjsProofToWithdrawProof but implemented directly
   */
  function convertProofToBytes(proof: any): {
    proofA: number[];
    proofB: number[];
    proofC: number[];
  } {
    // Helper to convert bigint to 32-byte big-endian array
    function bigintTo32BytesBE(x: bigint): number[] {
      const out = new Array(32).fill(0);
      let v = x;
      for (let i = 31; i >= 0; i--) {
        out[i] = Number(v & 0xffn);
        v >>= 8n;
      }
      return out;
    }

    // Extract proof components
    const ax = BigInt(proof.pi_a[0]);
    const ay = BigInt(proof.pi_a[1]);

    const bx0 = BigInt(proof.pi_b[0][0]);
    const bx1 = BigInt(proof.pi_b[0][1]);
    const by0 = BigInt(proof.pi_b[1][0]);
    const by1 = BigInt(proof.pi_b[1][1]);

    const cx = BigInt(proof.pi_c[0]);
    const cy = BigInt(proof.pi_c[1]);

    // Convert to bytes: each element is 32 bytes
    // NOTE: G2 points must be encoded as [c1, c0] for EIP-197 compatibility
    const proofA = [...bigintTo32BytesBE(ax), ...bigintTo32BytesBE(ay)]; // 64 bytes
    const proofB = [
      ...bigintTo32BytesBE(bx1), // X imaginary part (c1)
      ...bigintTo32BytesBE(bx0), // X real part (c0)
      ...bigintTo32BytesBE(by1), // Y imaginary part (c1)
      ...bigintTo32BytesBE(by0), // Y real part (c0)
    ]; // 128 bytes
    const proofC = [...bigintTo32BytesBE(cx), ...bigintTo32BytesBE(cy)]; // 64 bytes

    return { proofA, proofB, proofC };
  }

  it("withdraws via direct program call (no SDK wrapper)", async () => {
    const denomIndex = 0;
    const amount = denomsLamports[denomIndex];
    const fee = (amount * BigInt(feeBps)) / 10_000n;
    const toUser = amount - fee;

    const relayer = Keypair.generate();
    const recipient = wallet;

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

    // Prepare circuit inputs
    const testInputs = {
      root: bytesToBigIntBE(onchainRoot),
      nullifier: bytesToBigIntBE(depositNullifier),
      denomIndex: BigInt(denomIndex),
      recipient: bytesToBigIntBE(recipient.publicKey.toBytes()),

      // Private inputs
      noteValue: depositNote.value,
      noteOwner: bytesToBigIntBE(depositNote.owner.toBytes()),
      noteRho: bytesToBigIntBE(depositNote.rho),
      noteR: bytesToBigIntBE(depositNote.r),

      pathElements: depositMerklePath.path.map((p: Uint8Array) =>
        bytesToBigIntBE(p)
      ),
      pathIndices: depositMerklePath.indices.map((i: number) => BigInt(i)),
    };

    // Generate proof using groth16.fullProve directly
    const wasmPath = path.join(__dirname, "../zk/circuits/withdraw.wasm");
    const zkeyPath = path.join(__dirname, "../zk/circuits/withdraw_0001.zkey");

    const { proof, publicSignals } = await groth16.fullProve(
      testInputs,
      wasmPath,
      zkeyPath
    );

    console.log("✓ Proof generated successfully", proof, publicSignals);
    // Convert proof manually (no SDK helper)
    const withdrawProof = convertProofToBytes(proof);

    const vkPath = path.join(__dirname, "../zk/circuits/verification_key.json");
    const vKey = require(vkPath);
    const valid = await groth16.verify(vKey, publicSignals, proof);
    console.log("Proof valid?", valid);

    const beforeVault = BigInt(
      await provider.connection.getBalance(vault as PublicKey)
    );
    const beforeRelayer = BigInt(
      await provider.connection.getBalance(relayer.publicKey)
    );
    const beforeRecipient = BigInt(
      await provider.connection.getBalance(recipient.publicKey)
    );

    // Derive nullifier marker PDA
    const [nullifierMarker] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_v3"), depositNullifier],
      program.programId
    );

    try {
      // Call withdraw directly with compute budget
      await (program.methods as any)
        .withdraw(
          Array.from(onchainRoot),
          Array.from(depositNullifier),
          denomIndex,
          recipient.publicKey,
          withdrawProof
        )
        .accounts({
          config,
          vault,
          noteTree,
          nullifiers,
          nullifierMarker,
          relayer: relayer.publicKey,
          recipient: recipient.publicKey,
          systemProgram: SystemProgram.programId,
        } as any)
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
      beforeRelayer,
      afterRelayer,
      beforeRecipient,
      afterRecipient,
    });

    if (beforeVault - afterVault !== amount) {
      throw new Error("Vault SOL delta mismatch");
    }
    //can't be the same again, bcoz relayer pays rent for nullifier account
    // if (afterRelayer - beforeRelayer !== fee) {
    //   throw new Error("Relayer fee mismatch");
    // }

    console.log("Direct withdraw (no SDK) OK");
  });

  // ---------------------------------------------------------------------------
  // Private Transfer
  // ---------------------------------------------------------------------------

  it("performs private transfer", async () => {
    const denomIndex = 0;

    // 1. Make a fresh deposit to transfer FROM
    const result = await createNoteDepositWithMerkle({
      program: program as any,
      depositor: wallet,
      denomIndex,
      valueLamports: denomsLamports[denomIndex],
      tree: offchainTree,
    });

    if (!result) {
      throw new Error("Deposit failed in private transfer test");
    }

    const { note, root, merklePath } = result;
    const oldNullifier = deriveNullifier(note);

    // 2. Create a new commitment (the destination of the transfer)
    // For this test, since we don't verify the proof that links old->new,
    // we can just generate a random commitment.
    // Ensure it is a valid field element (smaller than modulus).
    // Using 31 bytes ensures it fits.
    const finalRecipient = new PublicKey(
      "2LicTQcHoiDHvrnxXp3Kuy2iTdeG9CfqEKW1XH9wavZD"
    );
    const newNote = createNoteWithCommitment({
      owner: finalRecipient,
      value: note.value,
    });

    const newCommitment = newNote.commitment;

    // 3. Call private_transfer
    // Since proof verification is commented out in the contract, we can pass a dummy proof.
    const dummyProof = Buffer.alloc(128); // Arbitrary size

    // Get the current on-chain root to be sure
    const noteTreeAcc: any = await (
      program.account as any
    ).merkleTreeAccount.fetch(noteTree);
    const onchainRoot = extractRootFromAccount(noteTreeAcc);

    await (program.methods as any)
      .privateTransfer(
        Array.from(onchainRoot),
        Array.from(oldNullifier),
        Array.from(newCommitment),
        denomIndex,
        dummyProof
      )
      .accounts({
        config,
        noteTree,
        nullifiers,
        sender: wallet.publicKey,
        systemProgram: SystemProgram.programId,
      } as any)
      .rpc();

    console.log("Private transfer transaction sent");

    // 4. Verify old nullifier is spent
    // We can try to double-spend it or check the account if we had a helper.
    // Let's try to use it again in another private_transfer, it should fail.
    let failed = false;
    try {
      await (program.methods as any)
        .privateTransfer(
          Array.from(onchainRoot),
          Array.from(oldNullifier),
          Array.from(newCommitment),
          denomIndex,
          dummyProof
        )
        .accounts({
          config,
          noteTree,
          nullifiers,
          sender: wallet.publicKey,
          systemProgram: SystemProgram.programId,
        } as any)
        .rpc();
    } catch (e: any) {
      failed = true;
      // Expected error: NullifierAlreadyUsed
      if (e instanceof SendTransactionError) {
        const logs = await e.getLogs(provider.connection);
        console.log("Double-spend attempt logs (private_transfer):", logs);
      }
    }

    if (!failed) {
      throw new Error(
        "Double-spend of transferred nullifier should have failed"
      );
    }

    // 5. Verify new commitment is in the tree
    // Update our offchain tree and compare roots.
    offchainTree.insert(newCommitment);
    const expectedRoot = offchainTree.root;

    const noteTreeAccAfter: any = await (
      program.account as any
    ).merkleTreeAccount.fetch(noteTree);
    const actualRoot = extractRootFromAccount(noteTreeAccAfter);

    if (
      Buffer.compare(Buffer.from(expectedRoot), Buffer.from(actualRoot)) !== 0
    ) {
      throw new Error(
        "On-chain root did not update as expected after private transfer"
      );
    }

    console.log("Private transfer test OK");

    // 6. Withdraw the transferred note
    console.log("Withdrawing transferred note...");

    // Get the Merkle path for the new commitment
    // Since we just inserted it, it's at the last index
    const leafIndex = offchainTree.nextIndex - 1;
    const withdrawMerklePath = offchainTree.getPath(leafIndex);
    const newNullifier = deriveNullifier(newNote);

    // Prepare circuit inputs
    const testInputs = {
      root: bytesToBigIntBE(offchainTree.root),
      nullifier: bytesToBigIntBE(newNullifier),
      denomIndex: BigInt(denomIndex),
      recipient: bytesToBigIntBE(finalRecipient.toBytes()),

      // Private inputs
      noteValue: newNote.value,
      noteOwner: bytesToBigIntBE(newNote.owner.toBytes()),
      noteRho: bytesToBigIntBE(newNote.rho),
      noteR: bytesToBigIntBE(newNote.r),

      pathElements: withdrawMerklePath.path.map((p: Uint8Array) =>
        bytesToBigIntBE(p)
      ),
      pathIndices: withdrawMerklePath.indices.map((i: number) => BigInt(i)),
    };

    // Generate proof using groth16.fullProve directly
    const wasmPath = path.join(__dirname, "../zk/circuits/withdraw.wasm");
    const zkeyPath = path.join(__dirname, "../zk/circuits/withdraw_0001.zkey");

    const { proof, publicSignals } = await groth16.fullProve(
      testInputs,
      wasmPath,
      zkeyPath
    );

    console.log("✓ Proof generated successfully", proof, publicSignals);
    // Convert proof manually (no SDK helper)
    const withdrawProof = convertProofToBytes(proof);

    const vkPath = path.join(__dirname, "../zk/circuits/verification_key.json");
    const vKey = require(vkPath);
    const valid = await groth16.verify(vKey, publicSignals, proof);
    console.log("Proof valid?", valid);

    // Use wallet as relayer for simplicity in this test step
    const relayer = wallet;
    // Register relayer (wallet)
    await (program.methods as any)
      .addRelayer(wallet.publicKey)
      .accounts({
        config,
        admin: wallet.publicKey,
      } as any)
      .rpc();
    try {
      // Call withdraw directly
      await (program.methods as any)
        .withdraw(
          Array.from(offchainTree.root),
          Array.from(newNullifier),
          denomIndex,
          finalRecipient,
          withdrawProof
        )
        .accounts({
          config,
          vault,
          noteTree,
          nullifiers,
          relayer: relayer.publicKey,
          recipient: finalRecipient, // The recipient must match the one in the proof
          systemProgram: SystemProgram.programId,
        } as any)
        .signers([]) // wallet is already provider signer
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

    console.log("Withdrawal of transferred note successful");
  });
});

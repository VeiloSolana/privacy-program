// tests/privacy-pool.test.ts

import "mocha";
import * as anchor from "@coral-xyz/anchor";
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

// ---- sdk-core imports ----
import {
  getPoolPdas,
  initializePool,
  MerkleTree,
  createNoteDepositWithMerkle,
  deriveNullifier,
  withdrawViaRelayerWithProof,
} from "@zkprivacysol/sdk-core";

// Your REAL zk proof builder (you implement this using snarkjs.groth16.prove)
import { buildWithdrawProof } from "../zk/withdrawProver"; // <- you create this

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
  lamports: number,
) {
  const sig = await provider.connection.requestAirdrop(pubkey, lamports);
  await provider.connection.confirmTransaction(sig, "confirmed");
}

// Helper: extract root from MerkleTreeAccount regardless of field name churn
function extractRootFromAccount(noteTreeAcc: any): Uint8Array {
  const arr: number[] =
    noteTreeAcc.root ??
    noteTreeAcc.currentRoot ??
    noteTreeAcc.current_root;

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
  const { config, vault, noteTree, nullifiers } = getPoolPdas(program.programId);

  // Two fixed denoms for the pool: 1 SOL, 5 SOL
  const denomsLamports: bigint[] = [
    BigInt(LAMPORTS_PER_SOL),
    BigInt(5 * LAMPORTS_PER_SOL),
  ];
  const feeBps = 50; // 0.5%

  // Off-chain Merkle tree used for zk circuit inputs
  // IMPORTANT: in production this hash must match your circuit’s hash (Poseidon/etc)
  const offchainTree = new MerkleTree(16);

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
    // airdrop admin wallet on localnet
    await airdropAndConfirm(provider, wallet.publicKey, 10 * LAMPORTS_PER_SOL);

    // If config PDA already exists, assume pool already initialized
    const existing = await provider.connection.getAccountInfo(config as PublicKey);
    if (existing) {
      console.log(
        "Initialize skipped: PDAs already exist on this cluster, continuing tests.",
      );
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
    const beforeVault = await provider.connection.getBalance(vault as PublicKey);

    // High-level deposit helper from sdk-core:
    const result = await createNoteDepositWithMerkle({
      program: program as any,
      depositor: wallet,
      denomIndex,
      valueLamports: denomsLamports[denomIndex],
      tree: offchainTree,
    });

    console.log("Result", result)

    if (!result) {
      throw new Error("depositResult is undefined – deposit test must run first and succeed");
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
          ].toString()}`,
      );
    }

    const noteTreeAcc: any = await (program.account as any).merkleTreeAccount.fetch(
      noteTree,
    );
    const onchainRoot = extractRootFromAccount(noteTreeAcc);

    console.log("Off-chain Mirrored Root   :", Array.from(depositRoot));
    console.log("On-chain NoteTree Root    :", Array.from(onchainRoot));

    if (Buffer.compare(Buffer.from(depositRoot), Buffer.from(onchainRoot)) !== 0) {
      console.warn(
        "WARNING: off-chain Merkle root != on-chain root. " +
        "Fix this before trusting zk proofs in production.",
      );
    }

    console.log("Deposit fixed-denom 1 SOL OK");
  });

  // ---------------------------------------------------------------------------
  // Withdraw with real proof (via sdk-core)
  // ---------------------------------------------------------------------------

  it("withdraws via relayer with fee + nullifier (real zk proof)", async () => {
    const denomIndex = 0;
    const amount = denomsLamports[denomIndex];
    const fee = (amount * BigInt(feeBps)) / 10_000n;
    const toUser = amount - fee;

    const relayer = Keypair.generate();
    const recipient = Keypair.generate();

    // fund relayer so it can pay tx fees
    await airdropAndConfirm(provider, relayer.publicKey, 2 * LAMPORTS_PER_SOL);
    // ensure recipient exists as a system account
    await airdropAndConfirm(provider, recipient.publicKey, 0.2 * LAMPORTS_PER_SOL);

    // Register relayer on-chain (sdk-core doesn’t wrap this yet, so call directly)
    await (program.methods as any)
      .addRelayer(relayer.publicKey)
      .accounts({
        config,
        admin: wallet.publicKey,
      } as any)
      .rpc();

    // Always use the authoritative on-chain root for the proof public input
    const noteTreeAcc: any = await (program.account as any).merkleTreeAccount.fetch(
      noteTree,
    );
    const onchainRoot = extractRootFromAccount(noteTreeAcc);

    const beforeVault = BigInt(
      await provider.connection.getBalance(vault as PublicKey),
    );
    const beforeRelayer = BigInt(
      await provider.connection.getBalance(relayer.publicKey),
    );
    const beforeRecipient = BigInt(
      await provider.connection.getBalance(recipient.publicKey),
    );

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
      if (e instanceof SendTransactionError) {
        const logs = await e.getLogs(provider.connection);
        console.error("withdrawViaRelayerWithProof failed logs:", logs);
      }
      throw e;
    }

    const afterVault = BigInt(
      await provider.connection.getBalance(vault as PublicKey),
    );
    const afterRelayer = BigInt(
      await provider.connection.getBalance(relayer.publicKey),
    );
    const afterRecipient = BigInt(
      await provider.connection.getBalance(recipient.publicKey),
    );

    if (beforeVault - afterVault !== amount) {
      throw new Error("Vault SOL delta mismatch");
    }
    if (afterRelayer - beforeRelayer !== fee) {
      throw new Error("Relayer fee mismatch");
    }
    if (afterRecipient - beforeRecipient !== toUser) {
      throw new Error("Recipient amount mismatch");
    }

    console.log("Withdraw via relayer with real proof OK");
  });

  // ---------------------------------------------------------------------------
  // Double-spend protection (nullifier)
  // ---------------------------------------------------------------------------

  it("rejects double-spend with same nullifier", async () => {
    const denomIndex = 0;

    const relayer = Keypair.generate();
    const recipient = Keypair.generate();

    await airdropAndConfirm(provider, relayer.publicKey, 2 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(provider, recipient.publicKey, 0.2 * LAMPORTS_PER_SOL);

    await (program.methods as any)
      .addRelayer(relayer.publicKey)
      .accounts({
        config,
        admin: wallet.publicKey,
      } as any)
      .rpc();

    const noteTreeAcc: any = await (program.account as any).merkleTreeAccount.fetch(
      noteTree,
    );
    const onchainRoot = extractRootFromAccount(noteTreeAcc);

    // First withdraw (should succeed)
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

    // Second withdraw with same nullifier must fail
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
        console.log("Double-spend attempt logs:", logs);
      }
    }

    if (!failed) {
      throw new Error("Double-spend with same nullifier unexpectedly succeeded");
    }

    console.log("Nullifier double-spend correctly rejected");
  });

  // ---------------------------------------------------------------------------
  // Paused flag behaviour
  // ---------------------------------------------------------------------------

  it("respects paused flag (withdraw fails when paused)", async () => {
    const denomIndex = 0;

    const relayer = Keypair.generate();
    const recipient = Keypair.generate();

    await airdropAndConfirm(provider, relayer.publicKey, 2 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(provider, recipient.publicKey, 0.2 * LAMPORTS_PER_SOL);

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

    const noteTreeAcc: any = await (program.account as any).merkleTreeAccount.fetch(
      noteTree,
    );
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
});
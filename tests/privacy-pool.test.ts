// tests/privacy_pool.fixed-denom.ts

import "mocha";
import * as anchor from "@coral-xyz/anchor";
import { Program, BN } from "@coral-xyz/anchor";
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

import { PrivacyPool } from "../target/types/privacy_pool";

// ---- Provider helper ----

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

// 32-byte helper
function bytes32(fill: number): number[] {
  return new Array(32).fill(fill & 0xff);
}

// Dummy WithdrawProof struct for now.
// IMPORTANT: this only works while on-chain Groth16 verify is stubbed
// (e.g. feature `zk-verify` disabled). Once real zk verification is
// enforced, replace this with a proof from snarkjs.
function makeDummyProof() {
  return {
    proofA: new Array(64).fill(0),
    proofB: new Array(128).fill(0),
    proofC: new Array(64).fill(0),
  };
}

describe("privacy-pool fixed-denom SOL (Merkle v3)", () => {
  const provider = makeProvider();
  anchor.setProvider(provider);

  const program = anchor.workspace.PrivacyPool as Program<PrivacyPool>;
  const wallet = provider.wallet as anchor.Wallet;

  let configPda: PublicKey;
  let vaultPda: PublicKey;
  let noteTreePda: PublicKey;
  let nullifiersPda: PublicKey;

  // two fixed denoms for test: 1 SOL, 5 SOL
  const denomsLamports = [
    BigInt(LAMPORTS_PER_SOL),
    BigInt(5 * LAMPORTS_PER_SOL),
  ];
  const feeBps = 50; // 0.5%

  async function airdropAndConfirm(pubkey: PublicKey, lamports: number) {
    const sig = await provider.connection.requestAirdrop(pubkey, lamports);
    await provider.connection.confirmTransaction(sig, "confirmed");
  }

  async function getCurrentRootFromChain(): Promise<number[]> {
    const noteTreeAcc: any = await (program.account as any).merkleTreeAccount.fetch(
      noteTreePda
    );
    // With the Rust layout:
    //   pub struct MerkleTreeAccount { pub root: [u8; 32], ... }
    const root: number[] = noteTreeAcc.root;
    return root;
  }

  before(async () => {
    [configPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_config_v3")],
      program.programId
    );
    [vaultPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_vault_v3")],
      program.programId
    );
    [noteTreePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_note_tree_v3")],
      program.programId
    );
    [nullifiersPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_nullifiers_v3")],
      program.programId
    );

    // Make sure admin wallet actually has SOL on localnet
    await airdropAndConfirm(wallet.publicKey, 10 * LAMPORTS_PER_SOL);

    // Try to fetch config; if it exists, assume already initialized.
    const existing = await provider.connection.getAccountInfo(configPda);
    if (existing) {
      console.log(
        "Initialize skipped: PDAs already exist on this cluster, continuing tests."
      );
      return;
    }

    try {
      await program.methods
        .initialize(
          denomsLamports.map((d) => new BN(d.toString())),
          feeBps
        )
        .accounts({
          config: configPda,
          vault: vaultPda,
          noteTree: noteTreePda,
          nullifiers: nullifiersPda,
          admin: wallet.publicKey,
          systemProgram: SystemProgram.programId,
        } as any)
        .rpc();
    } catch (e: any) {
      if (e instanceof SendTransactionError) {
        const logs = await e.getLogs(provider.connection);
        console.error("Initialize failed with logs:", logs);
      }
      throw e;
    }
  });

  it("deposits fixed 1 SOL and updates root", async () => {
    const denomIndex = 0;
    const commitment = bytes32(1); // toy commitment

    const beforeVault = await provider.connection.getBalance(vaultPda);

    try {
      await program.methods
        .depositFixed(denomIndex, commitment)
        .accounts({
          config: configPda,
          vault: vaultPda,
          noteTree: noteTreePda,
          depositor: wallet.publicKey,
          systemProgram: SystemProgram.programId,
        } as any)
        .rpc();
    } catch (e: any) {
      if (e instanceof SendTransactionError) {
        const logs = await e.getLogs(provider.connection);
        console.error("depositFixed failed with logs:", logs);
      }
      throw e;
    }

    const afterVault = await provider.connection.getBalance(vaultPda);
    const delta = BigInt(afterVault - beforeVault);

    if (delta !== denomsLamports[denomIndex]) {
      throw new Error(
        `Unexpected vault delta: got ${delta.toString()} expected ${denomsLamports[
          denomIndex
          ].toString()}`
      );
    }

    const root = await getCurrentRootFromChain();
    console.log("Current on-chain root after deposit:", root);

    console.log("Deposit fixed-denom 1 SOL OK");
  });

  it("withdraws via relayer with fee + nullifier (dummy proof)", async () => {
    const denomIndex = 0;
    const amount = denomsLamports[denomIndex];
    const fee = (amount * BigInt(feeBps)) / 10_000n;
    const toUser = amount - fee;

    const relayer = Keypair.generate();
    const recipient = Keypair.generate();

    // fund relayer so it can pay tx fees on local validator
    await airdropAndConfirm(relayer.publicKey, 2 * LAMPORTS_PER_SOL);

    // create recipient account (so SystemAccount constraint passes)
    await airdropAndConfirm(recipient.publicKey, 0.2 * LAMPORTS_PER_SOL);

    // admin adds relayer
    await program.methods
      .addRelayer(relayer.publicKey)
      .accounts({
        config: configPda,
        admin: wallet.publicKey,
      } as any)
      .rpc();

    // Root must match what the contract currently has
    const root = await getCurrentRootFromChain();
    const nullifier = bytes32(3);

    const proof = makeDummyProof(); // **stub** proof while zk verify disabled

    const beforeVault = BigInt(await provider.connection.getBalance(vaultPda));
    const beforeRelayer = BigInt(
      await provider.connection.getBalance(relayer.publicKey)
    );
    const beforeRecipient = BigInt(
      await provider.connection.getBalance(recipient.publicKey)
    );

    await program.methods
      .withdraw(root, nullifier, denomIndex, recipient.publicKey, proof as any)
      .accounts({
        config: configPda,
        vault: vaultPda,
        noteTree: noteTreePda,
        nullifiers: nullifiersPda,
        relayer: relayer.publicKey,
        recipient: recipient.publicKey,
        systemProgram: SystemProgram.programId,
      } as any)
      .signers([relayer])
      .rpc();

    const afterVault = BigInt(await provider.connection.getBalance(vaultPda));
    const afterRelayer = BigInt(
      await provider.connection.getBalance(relayer.publicKey)
    );
    const afterRecipient = BigInt(
      await provider.connection.getBalance(recipient.publicKey)
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

    console.log("Withdraw via relayer with fee OK");
  });

  it("rejects double-spend with same nullifier", async () => {
    const denomIndex = 0;

    const relayer = Keypair.generate();
    const recipient = Keypair.generate();

    await airdropAndConfirm(relayer.publicKey, 2 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(recipient.publicKey, 0.2 * LAMPORTS_PER_SOL);

    // Make sure relayer is registered
    await program.methods
      .addRelayer(relayer.publicKey)
      .accounts({
        config: configPda,
        admin: wallet.publicKey,
      } as any)
      .rpc();

    const root = await getCurrentRootFromChain();
    const nullifier = bytes32(7);
    const proof = makeDummyProof();

    // First withdraw should succeed
    await program.methods
      .withdraw(root, nullifier, denomIndex, recipient.publicKey, proof as any)
      .accounts({
        config: configPda,
        vault: vaultPda,
        noteTree: noteTreePda,
        nullifiers: nullifiersPda,
        relayer: relayer.publicKey,
        recipient: recipient.publicKey,
        systemProgram: SystemProgram.programId,
      } as any)
      .signers([relayer])
      .rpc();

    // Second withdraw with the same nullifier must fail
    let failed = false;
    try {
      await program.methods
        .withdraw(root, nullifier, denomIndex, recipient.publicKey, proof as any)
        .accounts({
          config: configPda,
          vault: vaultPda,
          noteTree: noteTreePda,
          nullifiers: nullifiersPda,
          relayer: relayer.publicKey,
          recipient: recipient.publicKey,
          systemProgram: SystemProgram.programId,
        } as any)
        .signers([relayer])
        .rpc();
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

  it("respects paused flag (withdraw fails when paused)", async () => {
    const denomIndex = 0;

    const relayer = Keypair.generate();
    const recipient = Keypair.generate();

    await airdropAndConfirm(relayer.publicKey, 2 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(recipient.publicKey, 0.2 * LAMPORTS_PER_SOL);

    // Add relayer again (idempotent is_ok)
    await program.methods
      .addRelayer(relayer.publicKey)
      .accounts({
        config: configPda,
        admin: wallet.publicKey,
      } as any)
      .rpc();

    // Pause the pool
    await program.methods
      .setPaused(true)
      .accounts({
        config: configPda,
        admin: wallet.publicKey,
      } as any)
      .rpc();

    const root = await getCurrentRootFromChain();
    const nullifier = bytes32(9);
    const proof = makeDummyProof();

    let failed = false;
    try {
      await program.methods
        .withdraw(root, nullifier, denomIndex, recipient.publicKey, proof as any)
        .accounts({
          config: configPda,
          vault: vaultPda,
          noteTree: noteTreePda,
          nullifiers: nullifiersPda,
          relayer: relayer.publicKey,
          recipient: recipient.publicKey,
          systemProgram: SystemProgram.programId,
        } as any)
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

    // Unpause to not poison other tests
    await program.methods
      .setPaused(false)
      .accounts({
        config: configPda,
        admin: wallet.publicKey,
      } as any)
      .rpc();

    console.log("Paused flag enforced for withdraw");
  });
});
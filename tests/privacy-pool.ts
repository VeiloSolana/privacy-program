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

import { PrivacyPool } from "../target/types/privacy_pool";

describe("privacy-pool fixed-denom SOL", () => {
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

  before(async () => {
    [configPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("config")],
      program.programId
    );
    [vaultPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault")],
      program.programId
    );
    [noteTreePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("note_tree")],
      program.programId
    );
    [nullifiersPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifiers")],
      program.programId
    );

    // Try to fetch config; if it exists, assume already initialized.
    const existing = await provider.connection.getAccountInfo(configPda);
    if (existing) {
      console.log(
        "Initialize skipped: PDAs already exist on this cluster, continuing tests."
      );
      return;
    }

    // initialize once
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

  it("deposits fixed 1 SOL and appends root", async () => {
    const denomIndex = 0;
    const commitment = new Array(32).fill(1); // number[]
    const root = new Array(32).fill(2);       // number[]

    const beforeVault = await provider.connection.getBalance(vaultPda);

    await program.methods
      .depositFixed(denomIndex, commitment, root)
      .accounts({
        config: configPda,
        vault: vaultPda,
        noteTree: noteTreePda,
        depositor: wallet.publicKey,
        systemProgram: SystemProgram.programId,
      } as any)
      .rpc();

    const afterVault = await provider.connection.getBalance(vaultPda);
    const delta = BigInt(afterVault - beforeVault);

    if (delta !== denomsLamports[denomIndex]) {
      throw new Error(
        `Unexpected vault delta: got ${delta.toString()} expected ${denomsLamports[
          denomIndex
          ].toString()}`
      );
    }

    console.log("Deposit fixed-denom 1 SOL OK");
  });

  it("withdraws via relayer with fee + nullifier", async () => {
    const denomIndex = 0;
    const amount = denomsLamports[denomIndex];
    const fee = (amount * BigInt(feeBps)) / 10_000n;
    const toUser = amount - fee;

    const relayer = anchor.web3.Keypair.generate();
    const recipient = anchor.web3.Keypair.generate();

    // fund relayer so it can pay tx fees on local validator
    await provider.connection.requestAirdrop(
      relayer.publicKey,
      2 * LAMPORTS_PER_SOL
    );

    // admin adds relayer
    await program.methods
      .addRelayer(relayer.publicKey)
      .accounts({
        config: configPda,
        admin: wallet.publicKey,
      } as any)
      .rpc();

    // reuse the root from previous test
    const root = new Array(32).fill(2);       // number[]
    const nullifier = new Array(32).fill(3);  // number[]
    const proof = Buffer.alloc(0);            // Buffer for now (dummy)

    const beforeVault = BigInt(await provider.connection.getBalance(vaultPda));
    const beforeRelayer = BigInt(
      await provider.connection.getBalance(relayer.publicKey)
    );
    const beforeRecipient = BigInt(
      await provider.connection.getBalance(recipient.publicKey)
    );

    await program.methods
      .withdraw(root, nullifier, denomIndex, recipient.publicKey, proof)
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
});
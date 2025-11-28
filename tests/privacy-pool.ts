import "mocha";
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import {
  Keypair,
  PublicKey,
  SystemProgram,
} from "@solana/web3.js";

import { PrivacyPool } from "../target/types/privacy_pool";

describe("privacy-pool fixed-denom SOL", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.PrivacyPool as Program<PrivacyPool>;
  const wallet = provider.wallet as anchor.Wallet;

  const denomIndex = 0; // 1 SOL (index into ALLOWED_DENOMS)

  let configPda: PublicKey;
  let noteTreePda: PublicKey;
  let nullifiersPda: PublicKey;
  let vaultPda: PublicKey;

  before(async () => {
    // PDAs must match the seeds in Rust
    [configPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("config")],
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
    [vaultPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault")],
      program.programId
    );

    // Initialize everything
    await program.methods
      .initialize()
      .accounts({
        config: configPda,
        noteTree: noteTreePda,
        nullifiers: nullifiersPda,
        vault: vaultPda,
        payer: wallet.publicKey,
        systemProgram: SystemProgram.programId,
      } as any)
      .rpc();
  });

  it("deposit + withdraw via verify_and_nullify", async () => {
    // 1) Append a root we pretend contains our note
    const root: number[] = new Array(32).fill(0);
    root[0] = 1;

    await program.methods
      .appendRoot(root)
      .accounts({
        config: configPda,
        noteTree: noteTreePda,
        authority: wallet.publicKey,
      } as any)
      .rpc();

    // 2) Deposit 1 SOL with dummy commitment
    const commitment: number[] = new Array(32).fill(0);
    commitment[0] = 123;

    await program.methods
      .depositFixed(denomIndex, commitment)
      .accounts({
        config: configPda,
        vault: vaultPda,
        depositor: wallet.publicKey,
        systemProgram: SystemProgram.programId,
      } as any)
      .rpc();

    // 3) Withdraw through relayer (wallet acts as relayer here)
    const recipient = Keypair.generate();
    const nullifier: number[] = new Array(32).fill(0);
    nullifier[0] = 77;

    const before = await provider.connection.getBalance(recipient.publicKey);

    await program.methods
      .verifyAndNullify(
        root,
        nullifier,
        denomIndex,
        Buffer.alloc(0), // zk proof placeholder
      )
      .accounts({
        config: configPda,
        noteTree: noteTreePda,
        nullifiers: nullifiersPda,
        vault: vaultPda,
        recipient: recipient.publicKey,
        relayer: wallet.publicKey,
        systemProgram: SystemProgram.programId,
      } as any)
      .rpc();

    const after = await provider.connection.getBalance(recipient.publicKey);
    console.log("Recipient balance before/after:", before, after);
  });

  it("rejects double-spend of same nullifier", async () => {
    const root: number[] = new Array(32).fill(0);
    root[0] = 2;

    await program.methods
      .appendRoot(root)
      .accounts({
        config: configPda,
        noteTree: noteTreePda,
        authority: wallet.publicKey,
      } as any)
      .rpc();

    const commitment: number[] = new Array(32).fill(0);
    commitment[0] = 200;

    await program.methods
      .depositFixed(denomIndex, commitment)
      .accounts({
        config: configPda,
        vault: vaultPda,
        depositor: wallet.publicKey,
        systemProgram: SystemProgram.programId,
      } as any)
      .rpc();

    const nullifier: number[] = new Array(32).fill(0);
    nullifier[0] = 99;

    const recipient1 = Keypair.generate();

    // First spend succeeds
    await program.methods
      .verifyAndNullify(
        root,
        nullifier,
        denomIndex,
        Buffer.alloc(0),
      )
      .accounts({
        config: configPda,
        noteTree: noteTreePda,
        nullifiers: nullifiersPda,
        vault: vaultPda,
        recipient: recipient1.publicKey,
        relayer: wallet.publicKey,
        systemProgram: SystemProgram.programId,
      } as any)
      .rpc();

    const recipient2 = Keypair.generate();
    let failed = false;
    try {
      // Second spend with same nullifier should fail
      await program.methods
        .verifyAndNullify(
          root,
          nullifier,
          denomIndex,
          Buffer.alloc(0),
        )
        .accounts({
          config: configPda,
          noteTree: noteTreePda,
          nullifiers: nullifiersPda,
          vault: vaultPda,
          recipient: recipient2.publicKey,
          relayer: wallet.publicKey,
          systemProgram: SystemProgram.programId,
        } as any)
        .rpc();
    } catch (e) {
      failed = true;
      console.log("Expected double-spend failure:", (e as Error).message);
    }

    if (!failed) {
      throw new Error("Second spend with same nullifier unexpectedly succeeded");
    }
  });
});
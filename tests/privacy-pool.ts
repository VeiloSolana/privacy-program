// tests/privacy-pool.ts
import "mocha";
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, SystemProgram } from "@solana/web3.js";
import { randomBytes } from "crypto";

import { PrivacyPool } from "../target/types/privacy_pool";

describe("privacy-pool ZK notes", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.PrivacyPool as Program<PrivacyPool>;
  const wallet = provider.wallet as anchor.Wallet;

  it("publishes a note", async () => {
    // 1) Fake commitment + ciphertext
    const commitmentBytes = randomBytes(32);             // 32 random bytes
    const commitmentArray = Array.from(commitmentBytes); // number[]

    const ownerHint = PublicKey.default;                 // or some real recipient pk
    const ciphertext = Buffer.from("hello zk world", "utf8");

    // 2) Derive note PDA: seeds = ["note", commitment]
    const [notePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("note"), commitmentBytes],
      program.programId
    );

    // 3) Call publish_note
    const sig = await program.methods
      .publishNote(
        commitmentArray, // [u8;32] as number[]
        ownerHint,       // Pubkey
        ciphertext       // bytes
      )
      .accounts({
        note: notePda,
        sender: wallet.publicKey,
        systemProgram: SystemProgram.programId,
      } as any)
      .rpc();

    console.log("publish_note tx:", sig);

    // 4) Fetch account back
    const noteAccount = await program.account.noteAccount.fetch(notePda);

    console.log("Note account:", {
      notePda: notePda.toBase58(),
      author: noteAccount.author.toBase58(),
      ownerHint: noteAccount.ownerHint.toBase58(),
      commitment: Buffer.from(noteAccount.commitment).toString("hex"),
      nullified: noteAccount.nullified,
      createdAtSlot: noteAccount.createdAtSlot.toString(),
      ciphertext: Buffer.from(noteAccount.ciphertext).toString("utf8"),
    });

    // Very lightweight sanity checks
    if (!noteAccount.author.equals(wallet.publicKey)) {
      throw new Error("author mismatch");
    }
    if (
      Buffer.compare(
        Buffer.from(noteAccount.commitment),
        commitmentBytes
      ) !== 0
    ) {
      throw new Error("commitment mismatch");
    }
  });

  it("registers a nullifier", async () => {
    // 1) Fake nullifier
    const nullifierBytes = randomBytes(32);
    const nullifierArray = Array.from(nullifierBytes);

    // 2) Derive nullifier PDA: seeds = ["nullifier", nullifier]
    const [nullifierPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier"), nullifierBytes],
      program.programId
    );

    // 3) Call register_nullifier
    const sig = await program.methods
      .registerNullifier(nullifierArray)
      .accounts({
        nullifier: nullifierPda,
        payer: wallet.publicKey,
        systemProgram: SystemProgram.programId,
      } as any)
      .rpc();

    console.log("register_nullifier tx:", sig);

    // 4) Fetch nullifier account
    const nullifierAccount =
      await program.account.nullifierAccount.fetch(nullifierPda);

    console.log("Nullifier account:", {
      nullifierPda: nullifierPda.toBase58(),
      used: nullifierAccount.used,
      nullifier: Buffer.from(nullifierAccount.nullifier).toString("hex"),
    });

    if (!nullifierAccount.used) {
      throw new Error("nullifier should be marked used");
    }
  });
});
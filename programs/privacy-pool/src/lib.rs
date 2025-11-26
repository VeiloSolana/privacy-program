import "mocha";
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, SystemProgram } from "@solana/web3.js";
import { randomBytes } from "crypto";

import { PrivacyPool } from "../target/types/privacy_pool";

describe("privacy-pool note + nullifier", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.PrivacyPool as Program<PrivacyPool>;
  const wallet = provider.wallet as anchor.Wallet;

  it("initialize → publish_note → verify_and_nullify", async () => {
    // 1) derive PDAs
    const [noteTreePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("note_tree")],
      program.programId
    );

    const [nullifiersPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifiers")],
      program.programId
    );

    // 2) initialize global state
    await program.methods
      .initialize()
      .accounts({
        noteTree: noteTreePda,
        nullifiers: nullifiersPda,
        payer: wallet.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // 3) fake root + nullifier (in real life: output of zk + Merkle tree)
    const fakeRoot = randomBytes(32);
    const fakeNullifier = randomBytes(32);

    // publish the root
    await program.methods
      .publishNote(Array.from(fakeRoot))
      .accounts({
        noteTree: noteTreePda,
        authority: wallet.publicKey,
      })
      .rpc();

    // 4) first spend (should succeed)
    await program.methods
      .verifyAndNullify(
        Array.from(fakeRoot),
        Array.from(fakeNullifier),
        Buffer.alloc(0) // placeholder proof bytes
      )
      .accounts({
        noteTree: noteTreePda,
        nullifiers: nullifiersPda,
        relayer: wallet.publicKey,
      })
      .rpc();

    // 5) second spend with same nullifier must fail
    let doubleSpendFailed = false;
    try {
      await program.methods
        .verifyAndNullify(
          Array.from(fakeRoot),
          Array.from(fakeNullifier),
          Buffer.alloc(0)
        )
        .accounts({
          noteTree: noteTreePda,
          nullifiers: nullifiersPda,
          relayer: wallet.publicKey,
        })
        .rpc();
    } catch (e) {
      doubleSpendFailed = true;
      console.log("Expected double-spend failure:", (e as any).toString());
    }

    if (!doubleSpendFailed) {
      throw new Error("Nullifier double-spend unexpectedly succeeded");
    }
  });
});
import "mocha";
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, SystemProgram } from "@solana/web3.js";

import { PrivacyPool } from "../target/types/privacy_pool";

describe("privacy-pool note/nullifier smoke test", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.PrivacyPool as Program<PrivacyPool>;
  const wallet = provider.wallet as anchor.Wallet;

  it("initializes + calls verify_and_nullify with dummy proof", async () => {
    // --- 1) PDAs that match the Rust seeds used in Initialize ---

    // #[account(init, seeds = [b"note_tree"], bump, ...)]
    const [noteTreePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("note_tree")],
      program.programId
    );

    // #[account(init, seeds = [b"nullifiers"], bump, ...)]
    const [nullifiersPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifiers")],
      program.programId
    );

    // --- 2) initialize() ---

    await program.methods
      .initialize()
      .accounts({
        noteTree: noteTreePda,
        nullifiers: nullifiersPda,
        payer: wallet.publicKey,
        systemProgram: SystemProgram.programId,
      } as any)
      .rpc();

    // --- 3) Prepare fake root + nullifier + dummy proof ---

    const root: number[] = new Array(32).fill(0);
    root[0] = 42; // arbitrary marker

    const nullifier: number[] = new Array(32).fill(0);
    nullifier[0] = 7; // arbitrary marker

    // IDL expects `bytes` for proof → Buffer in TS
    const proof = Buffer.alloc(0); // placeholder until real zk proof

    // --- 4) verify_and_nullify(root, nullifier, proof) ---

    await program.methods
      .verifyAndNullify(root, nullifier, proof)
      .accounts({
        noteTree: noteTreePda,
        nullifiers: nullifiersPda,
        authority: wallet.publicKey,
      } as any)
      .rpc();

    console.log("initialize + verify_and_nullify smoke test passed");
  });
});
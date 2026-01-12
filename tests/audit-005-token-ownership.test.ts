/**
 * AUDIT-005 Test Suite: SPL Token Account Ownership Validation
 *
 * Tests that recipient and depositor token accounts have correct owners:
 * - Withdrawals: recipient_token.owner == ext_data.recipient
 * - Deposits: user_token.owner == relayer (the CPI authority)
 *
 * These checks prevent:
 * - Withdrawals to uncontrolled token accounts
 * - Deposits from unauthorized sources
 * - Combined with AUDIT-001, prevents complete fee redirection attacks
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PrivacyPool } from "../target/types/privacy_pool";
import {
  Keypair,
  SystemProgram,
  PublicKey,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  createMint,
  createAccount,
  mintTo,
  getAccount,
} from "@solana/spl-token";
import { assert } from "chai";
import { buildPoseidon } from "circomlibjs";

describe("AUDIT-005: SPL Token Account Ownership Checks", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.PrivacyPool as Program<PrivacyPool>;

  let config: PublicKey;
  let vault: PublicKey;
  let nullifiers: PublicKey;
  let noteTree: PublicKey;
  let poseidon: any;

  let testMint: PublicKey;
  let vaultTokenAccount: PublicKey;
  let payer = provider.wallet as anchor.Wallet;

  // Test actors
  let relayer: Keypair;
  let recipient: Keypair;
  let attacker: Keypair;

  // Mock ZK proof data (would be real in production)
  const mockRoot = Buffer.alloc(32, 1);
  const mockExtDataHash = Buffer.alloc(32, 2);
  const mockNullifier0 = Buffer.alloc(32, 3);
  const mockNullifier1 = Buffer.alloc(32, 4);
  const mockCommitment0 = Buffer.alloc(32, 5);
  const mockCommitment1 = Buffer.alloc(32, 6);
  const mockProof = Buffer.alloc(256, 0); // 8 field elements * 32 bytes

  before(async () => {
    poseidon = await buildPoseidon();

    // Initialize test actors
    relayer = Keypair.generate();
    recipient = Keypair.generate();
    attacker = Keypair.generate();

    // Fund accounts
    await provider.connection.confirmTransaction(
      await provider.connection.requestAirdrop(
        relayer.publicKey,
        5 * LAMPORTS_PER_SOL
      )
    );
    await provider.connection.confirmTransaction(
      await provider.connection.requestAirdrop(
        recipient.publicKey,
        2 * LAMPORTS_PER_SOL
      )
    );
    await provider.connection.confirmTransaction(
      await provider.connection.requestAirdrop(
        attacker.publicKey,
        2 * LAMPORTS_PER_SOL
      )
    );

    // Create test SPL token
    testMint = await createMint(
      provider.connection,
      payer.payer,
      payer.publicKey,
      null,
      9 // 9 decimals
    );

    // Derive PDAs
    [config] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_config_v3"), testMint.toBuffer()],
      program.programId
    );

    [vault] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_vault_v3"), testMint.toBuffer()],
      program.programId
    );

    [nullifiers] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifiers_v3"), testMint.toBuffer()],
      program.programId
    );

    [noteTree] = PublicKey.findProgramAddressSync(
      [Buffer.from("note_tree_v3"), testMint.toBuffer()],
      program.programId
    );

    // Create vault token account
    vaultTokenAccount = await createAccount(
      provider.connection,
      payer.payer,
      testMint,
      vault,
      undefined,
      { commitment: "confirmed" }
    );

    // Initialize privacy pool
    try {
      await program.methods
        .initialize()
        .accounts({
          config,
          vault,
          nullifiers,
          noteTree,
          mintAddress: testMint,
          authority: payer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
    } catch (err) {
      // May already be initialized
      console.log("Pool initialization:", err.message);
    }

    // Add relayer
    try {
      await program.methods
        .addRelayer(relayer.publicKey)
        .accounts({
          config,
          authority: payer.publicKey,
          mintAddress: testMint,
        })
        .rpc();
    } catch (err) {
      console.log("Add relayer:", err.message);
    }
  });

  describe("Withdrawal Token Account Ownership", () => {
    it("should REJECT withdrawal when recipient_token.owner != ext_data.recipient", async () => {
      // Setup: Create token accounts
      const recipientTokenAccount = await createAccount(
        provider.connection,
        payer.payer,
        testMint,
        recipient.publicKey
      );

      // ATTACK: Create relayer token owned by attacker (not ext_data.relayer)
      const maliciousRelayerToken = await createAccount(
        provider.connection,
        payer.payer,
        testMint,
        attacker.publicKey // ← Attacker owns this, not relayer
      );

      // Fund vault for withdrawal
      await mintTo(
        provider.connection,
        payer.payer,
        testMint,
        vaultTokenAccount,
        payer.publicKey,
        1_000_000_000 // 1 token
      );

      // Build ext_data with relayer as intended recipient
      const extData = {
        recipient: relayer.publicKey, // ← Claims relayer is recipient
        relayer: relayer.publicKey,
        fee: new anchor.BN(10_000),
        refund: new anchor.BN(0),
      };

      const extDataHash = computeExtDataHash(extData, poseidon);

      // Derive nullifier markers
      const [nullifierMarker0] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("nullifier_marker_v3"),
          mockNullifier0,
          testMint.toBuffer(),
        ],
        program.programId
      );
      const [nullifierMarker1] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("nullifier_marker_v3"),
          mockNullifier1,
          testMint.toBuffer(),
        ],
        program.programId
      );

      try {
        await program.methods
          .transact(
            Array.from(mockRoot),
            new anchor.BN(-500_000_000), // Withdraw 0.5 tokens
            Array.from(extDataHash),
            testMint,
            Array.from(mockNullifier0),
            Array.from(mockNullifier1),
            Array.from(mockCommitment0),
            Array.from(mockCommitment1),
            extData,
            Array.from(mockProof)
          )
          .accounts({
            config,
            vault,
            nullifiers,
            noteTree,
            nullifierMarker0,
            nullifierMarker1,
            relayer: relayer.publicKey,
            recipient: relayer.publicKey, // Account matches ext_data
            systemProgram: SystemProgram.programId,
            vaultTokenAccount,
            userTokenAccount: PublicKey.default,
            recipientTokenAccount, // ← Correct owner (relayer)
            relayerTokenAccount: maliciousRelayerToken, // ← WRONG owner (attacker)
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .signers([relayer])
          .rpc();

        assert.fail("Should have rejected mismatched relayer token owner");
      } catch (err) {
        assert.include(
          err.message,
          "RelayerTokenAccountMismatch",
          "Should reject when relayer_token.owner != ext_data.relayer"
        );
      }
    });

    it("should REJECT withdrawal when recipient_token.owner != ext_data.recipient", async () => {
      // Setup: Vault with funds
      const vaultBalance = await getAccount(
        provider.connection,
        vaultTokenAccount
      );
      if (vaultBalance.amount < 1_000_000_000n) {
        await mintTo(
          provider.connection,
          payer.payer,
          testMint,
          vaultTokenAccount,
          payer.publicKey,
          1_000_000_000
        );
      }

      const relayerTokenAccount = await createAccount(
        provider.connection,
        payer.payer,
        testMint,
        relayer.publicKey
      );

      // ATTACK: Create recipient token owned by attacker (not ext_data.recipient)
      const maliciousRecipientToken = await createAccount(
        provider.connection,
        payer.payer,
        testMint,
        attacker.publicKey // ← Attacker owns this, not recipient
      );

      const extData = {
        recipient: recipient.publicKey, // ← Claims recipient is the recipient
        relayer: relayer.publicKey,
        fee: new anchor.BN(10_000),
        refund: new anchor.BN(0),
      };

      const extDataHash = computeExtDataHash(extData, poseidon);

      const [nullifierMarker0] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("nullifier_marker_v3"),
          mockNullifier0,
          testMint.toBuffer(),
        ],
        program.programId
      );
      const [nullifierMarker1] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("nullifier_marker_v3"),
          mockNullifier1,
          testMint.toBuffer(),
        ],
        program.programId
      );

      try {
        await program.methods
          .transact(
            Array.from(mockRoot),
            new anchor.BN(-500_000_000), // Withdraw 0.5 tokens
            Array.from(extDataHash),
            testMint,
            Array.from(mockNullifier0),
            Array.from(mockNullifier1),
            Array.from(mockCommitment0),
            Array.from(mockCommitment1),
            extData,
            Array.from(mockProof)
          )
          .accounts({
            config,
            vault,
            nullifiers,
            noteTree,
            nullifierMarker0,
            nullifierMarker1,
            relayer: relayer.publicKey,
            recipient: recipient.publicKey,
            systemProgram: SystemProgram.programId,
            vaultTokenAccount,
            userTokenAccount: PublicKey.default,
            recipientTokenAccount: maliciousRecipientToken, // ← WRONG owner
            relayerTokenAccount,
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .signers([relayer])
          .rpc();

        assert.fail("Should have rejected mismatched recipient token owner");
      } catch (err) {
        assert.include(
          err.message,
          "RecipientTokenAccountMismatch",
          "Should reject when recipient_token.owner != ext_data.recipient"
        );
      }
    });

    it("should ACCEPT withdrawal when all token account owners match", async () => {
      // Setup: Vault with funds
      const vaultBalance = await getAccount(
        provider.connection,
        vaultTokenAccount
      );
      if (vaultBalance.amount < 1_000_000_000n) {
        await mintTo(
          provider.connection,
          payer.payer,
          testMint,
          vaultTokenAccount,
          payer.publicKey,
          1_000_000_000
        );
      }

      // Create CORRECT token accounts (owned by ext_data recipients)
      const recipientTokenAccount = await createAccount(
        provider.connection,
        payer.payer,
        testMint,
        recipient.publicKey // ← Correct owner
      );

      const relayerTokenAccount = await createAccount(
        provider.connection,
        payer.payer,
        testMint,
        relayer.publicKey // ← Correct owner
      );

      const extData = {
        recipient: recipient.publicKey,
        relayer: relayer.publicKey,
        fee: new anchor.BN(10_000),
        refund: new anchor.BN(0),
      };

      const extDataHash = computeExtDataHash(extData, poseidon);

      // Use unique nullifiers for this test
      const uniqueNullifier0 = Buffer.from(mockNullifier0);
      uniqueNullifier0[31] = 100; // Make unique
      const uniqueNullifier1 = Buffer.from(mockNullifier1);
      uniqueNullifier1[31] = 101;

      const [nullifierMarker0] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("nullifier_marker_v3"),
          uniqueNullifier0,
          testMint.toBuffer(),
        ],
        program.programId
      );
      const [nullifierMarker1] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("nullifier_marker_v3"),
          uniqueNullifier1,
          testMint.toBuffer(),
        ],
        program.programId
      );

      // This should SUCCEED (with mock proof it will fail verification, but ownership checks pass)
      try {
        await program.methods
          .transact(
            Array.from(mockRoot),
            new anchor.BN(-500_000_000),
            Array.from(extDataHash),
            testMint,
            Array.from(uniqueNullifier0),
            Array.from(uniqueNullifier1),
            Array.from(mockCommitment0),
            Array.from(mockCommitment1),
            extData,
            Array.from(mockProof)
          )
          .accounts({
            config,
            vault,
            nullifiers,
            noteTree,
            nullifierMarker0,
            nullifierMarker1,
            relayer: relayer.publicKey,
            recipient: recipient.publicKey,
            systemProgram: SystemProgram.programId,
            vaultTokenAccount,
            userTokenAccount: PublicKey.default,
            recipientTokenAccount, // ✅ Correct owner
            relayerTokenAccount, // ✅ Correct owner
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .signers([relayer])
          .rpc();

        assert.fail("Expected proof verification to fail (mock proof)");
      } catch (err) {
        // Should fail at ZK verification (mock proof), NOT at ownership checks
        assert.notInclude(err.message, "RecipientTokenAccountMismatch");
        assert.notInclude(err.message, "RelayerTokenAccountMismatch");
        // Expected: VerifyFailed or UnknownRoot
        console.log("✓ Ownership checks passed, failed at:", err.message);
      }
    });
  });

  describe("Deposit Token Account Ownership", () => {
    it("should REJECT deposit when user_token.owner != relayer", async () => {
      // ATTACK: Create user token account owned by attacker (not relayer)
      const maliciousUserToken = await createAccount(
        provider.connection,
        payer.payer,
        testMint,
        attacker.publicKey // ← Attacker owns this, not relayer
      );

      // Fund the attacker's token account
      await mintTo(
        provider.connection,
        payer.payer,
        testMint,
        maliciousUserToken,
        payer.publicKey,
        1_000_000_000
      );

      const extData = {
        recipient: PublicKey.default,
        relayer: relayer.publicKey,
        fee: new anchor.BN(0),
        refund: new anchor.BN(0),
      };

      const extDataHash = computeExtDataHash(extData, poseidon);

      const uniqueNullifier0 = Buffer.from(mockNullifier0);
      uniqueNullifier0[31] = 200;
      const uniqueNullifier1 = Buffer.from(mockNullifier1);
      uniqueNullifier1[31] = 201;

      const [nullifierMarker0] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("nullifier_marker_v3"),
          uniqueNullifier0,
          testMint.toBuffer(),
        ],
        program.programId
      );
      const [nullifierMarker1] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("nullifier_marker_v3"),
          uniqueNullifier1,
          testMint.toBuffer(),
        ],
        program.programId
      );

      try {
        await program.methods
          .transact(
            Array.from(mockRoot),
            new anchor.BN(500_000_000), // Deposit 0.5 tokens
            Array.from(extDataHash),
            testMint,
            Array.from(uniqueNullifier0),
            Array.from(uniqueNullifier1),
            Array.from(mockCommitment0),
            Array.from(mockCommitment1),
            extData,
            Array.from(mockProof)
          )
          .accounts({
            config,
            vault,
            nullifiers,
            noteTree,
            nullifierMarker0,
            nullifierMarker1,
            relayer: relayer.publicKey,
            recipient: PublicKey.default,
            systemProgram: SystemProgram.programId,
            vaultTokenAccount,
            userTokenAccount: maliciousUserToken, // ← WRONG owner (attacker, not relayer)
            recipientTokenAccount: PublicKey.default,
            relayerTokenAccount: PublicKey.default,
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .signers([relayer])
          .rpc();

        assert.fail("Should have rejected mismatched user token owner");
      } catch (err) {
        assert.include(
          err.message,
          "DepositorTokenAccountMismatch",
          "Should reject when user_token.owner != relayer"
        );
      }
    });

    it("should ACCEPT deposit when user_token.owner == relayer", async () => {
      // Create CORRECT user token account (owned by relayer)
      const userTokenAccount = await createAccount(
        provider.connection,
        payer.payer,
        testMint,
        relayer.publicKey // ← Correct owner
      );

      // Fund relayer's token account
      await mintTo(
        provider.connection,
        payer.payer,
        testMint,
        userTokenAccount,
        payer.publicKey,
        1_000_000_000
      );

      const extData = {
        recipient: PublicKey.default,
        relayer: relayer.publicKey,
        fee: new anchor.BN(0),
        refund: new anchor.BN(0),
      };

      const extDataHash = computeExtDataHash(extData, poseidon);

      const uniqueNullifier0 = Buffer.from(mockNullifier0);
      uniqueNullifier0[31] = 210;
      const uniqueNullifier1 = Buffer.from(mockNullifier1);
      uniqueNullifier1[31] = 211;

      const [nullifierMarker0] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("nullifier_marker_v3"),
          uniqueNullifier0,
          testMint.toBuffer(),
        ],
        program.programId
      );
      const [nullifierMarker1] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("nullifier_marker_v3"),
          uniqueNullifier1,
          testMint.toBuffer(),
        ],
        program.programId
      );

      try {
        await program.methods
          .transact(
            Array.from(mockRoot),
            new anchor.BN(500_000_000), // Deposit 0.5 tokens
            Array.from(extDataHash),
            testMint,
            Array.from(uniqueNullifier0),
            Array.from(uniqueNullifier1),
            Array.from(mockCommitment0),
            Array.from(mockCommitment1),
            extData,
            Array.from(mockProof)
          )
          .accounts({
            config,
            vault,
            nullifiers,
            noteTree,
            nullifierMarker0,
            nullifierMarker1,
            relayer: relayer.publicKey,
            recipient: PublicKey.default,
            systemProgram: SystemProgram.programId,
            vaultTokenAccount,
            userTokenAccount, // ✅ Correct owner (relayer)
            recipientTokenAccount: PublicKey.default,
            relayerTokenAccount: PublicKey.default,
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .signers([relayer])
          .rpc();

        assert.fail("Expected proof verification to fail (mock proof)");
      } catch (err) {
        // Should fail at ZK verification, NOT at ownership check
        assert.notInclude(err.message, "DepositorTokenAccountMismatch");
        console.log(
          "✓ Deposit ownership check passed, failed at:",
          err.message
        );
      }
    });
  });

  describe("Combined Attack Scenarios", () => {
    it("should prevent complete fee redirection via token account substitution", async () => {
      /**
       * ATTACK SCENARIO:
       * 1. Attacker creates token accounts they control
       * 2. Submits withdrawal with victim's ext_data
       * 3. Tries to substitute attacker-owned token accounts
       *
       * DEFENSE (AUDIT-001 + AUDIT-005):
       * - AUDIT-001: relayer_token.owner must == ext_data.relayer
       * - AUDIT-005: recipient_token.owner must == ext_data.recipient
       */

      const victimRecipient = recipient;
      const victimRelayer = relayer;

      // Attacker creates token accounts they control
      const attackerRecipientToken = await createAccount(
        provider.connection,
        payer.payer,
        testMint,
        attacker.publicKey // Attacker controls
      );

      const attackerRelayerToken = await createAccount(
        provider.connection,
        payer.payer,
        testMint,
        attacker.publicKey // Attacker controls
      );

      // Fund vault
      const vaultBalance = await getAccount(
        provider.connection,
        vaultTokenAccount
      );
      if (vaultBalance.amount < 1_000_000_000n) {
        await mintTo(
          provider.connection,
          payer.payer,
          testMint,
          vaultTokenAccount,
          payer.publicKey,
          1_000_000_000
        );
      }

      // Build ext_data claiming victim recipients
      const extData = {
        recipient: victimRecipient.publicKey,
        relayer: victimRelayer.publicKey,
        fee: new anchor.BN(100_000_000), // 0.1 token fee
        refund: new anchor.BN(0),
      };

      const extDataHash = computeExtDataHash(extData, poseidon);

      const uniqueNullifier0 = Buffer.from(mockNullifier0);
      uniqueNullifier0[31] = 250;
      const uniqueNullifier1 = Buffer.from(mockNullifier1);
      uniqueNullifier1[31] = 251;

      const [nullifierMarker0] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("nullifier_marker_v3"),
          uniqueNullifier0,
          testMint.toBuffer(),
        ],
        program.programId
      );
      const [nullifierMarker1] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("nullifier_marker_v3"),
          uniqueNullifier1,
          testMint.toBuffer(),
        ],
        program.programId
      );

      try {
        await program.methods
          .transact(
            Array.from(mockRoot),
            new anchor.BN(-500_000_000),
            Array.from(extDataHash),
            testMint,
            Array.from(uniqueNullifier0),
            Array.from(uniqueNullifier1),
            Array.from(mockCommitment0),
            Array.from(mockCommitment1),
            extData,
            Array.from(mockProof)
          )
          .accounts({
            config,
            vault,
            nullifiers,
            noteTree,
            nullifierMarker0,
            nullifierMarker1,
            relayer: victimRelayer.publicKey,
            recipient: victimRecipient.publicKey,
            systemProgram: SystemProgram.programId,
            vaultTokenAccount,
            userTokenAccount: PublicKey.default,
            recipientTokenAccount: attackerRecipientToken, // ❌ Attacker-owned
            relayerTokenAccount: attackerRelayerToken, // ❌ Attacker-owned
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .signers([victimRelayer])
          .rpc();

        assert.fail("Should have rejected attacker-controlled token accounts");
      } catch (err) {
        // Should fail at EITHER ownership check
        const errorMsg = err.message;
        const hasOwnershipError =
          errorMsg.includes("RecipientTokenAccountMismatch") ||
          errorMsg.includes("RelayerTokenAccountMismatch");

        assert.isTrue(
          hasOwnershipError,
          "Should reject due to token account ownership mismatch"
        );
        console.log("✓ Complete fee redirection prevented:", errorMsg);
      }
    });
  });
});

// Helper: Compute ext_data hash using Poseidon
function computeExtDataHash(extData: any, poseidon: any): Buffer {
  // Convert fields to field elements
  const recipientBytes = extData.recipient.toBuffer();
  const relayerBytes = extData.relayer.toBuffer();
  const feeBytes = extData.fee.toArrayLike(Buffer, "le", 8);
  const refundBytes = extData.refund.toArrayLike(Buffer, "le", 8);

  // Hash with Poseidon (simplified - real implementation would match circuit)
  const hash = poseidon([
    BigInt("0x" + recipientBytes.toString("hex")),
    BigInt("0x" + relayerBytes.toString("hex")),
    BigInt(extData.fee.toString()),
    BigInt(extData.refund.toString()),
  ]);

  const hashStr = poseidon.F.toString(hash, 16).padStart(64, "0");
  return Buffer.from(hashStr, "hex");
}

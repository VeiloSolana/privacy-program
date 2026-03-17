import * as anchor from "@coral-xyz/anchor";
import { Program, BN, Wallet } from "@coral-xyz/anchor";
import {
  PublicKey,
  Keypair,
  SystemProgram,
  LAMPORTS_PER_SOL,
  ComputeBudgetProgram,
  SendTransactionError,
  AddressLookupTableProgram,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  getOrCreateAssociatedTokenAccount,
  getAssociatedTokenAddress,
  NATIVE_MINT,
} from "@solana/spl-token";
import { expect } from "chai";
import { buildPoseidon } from "circomlibjs";
import { PrivacyPool } from "../target/types/privacy_pool";
import {
  InMemoryNoteStorage,
  OffchainMerkleTree,
  makeProvider,
  airdropAndConfirm,
  randomBytes32,
  computeCommitment,
  computeNullifier,
  computeExtDataHash,
  computeSwapParamsHash,
  derivePublicKey,
  generateTransactionProof,
  generateSwapProof,
} from "./test-helpers";

/**
 * Privacy Pool Cross-Pool Swap Tests using Raydium AMM V4
 *
 * Tests the transact_swap instruction which:
 * 1. Consumes notes from source pool (SOL)
 * 2. CPIs to Raydium AMM V4 to execute swap SOL→USDC
 * 3. Creates notes in destination pool (USDC)
 *
 * Uses cloned mainnet Raydium AMM V4 SOL/USDC pool for testing.
 */

// Raydium AMM V4 Program ID (cloned from mainnet)
const RAYDIUM_AMM_V4_PROGRAM = new PublicKey(
  "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8",
);

// Serum/OpenBook Program ID
const SERUM_PROGRAM = new PublicKey(
  "srmqPvymJeFKQ4zGQed1GFppgkRHL9kaELCbyksJtPX",
);

// Mainnet token mints (cloned)
const SOL_MINT = PublicKey.default; // Native SOL identity (all zeros)
const USDC_MINT = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

// Helper: map SOL_MINT (PublicKey.default) → NATIVE_MINT for SPL operations
function tokenMintFor(mint: PublicKey): PublicKey {
  return mint.equals(PublicKey.default) ? NATIVE_MINT : mint;
}

// ============================================
// Raydium AMM V4 SOL/USDC Pool Accounts (from Anchor.toml clones)
// ============================================
const AMM_POOL_STATE = new PublicKey(
  "58oQChx4yWmvKdwLLZzBi4ChoCc2fqCUWBkwMihLYQo2",
);
const AMM_AUTHORITY = new PublicKey(
  "5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1",
);
const AMM_OPEN_ORDERS = new PublicKey(
  "HmiHHzq4Fym9e1D4qzLS6LDDM3tNsCTBPDWHTLZ763jY",
);
const AMM_TARGET_ORDERS = new PublicKey(
  "CZza3Ej4Mc58MnxWA385itCC9jCo3L1D7zc3LKy1bZMR",
);
const AMM_BASE_VAULT = new PublicKey(
  "DQyrAcCrDXQ7NeoqGgDCZwBvWDcYmFCjSb9JtteuvPpz",
); // SOL
const AMM_QUOTE_VAULT = new PublicKey(
  "HLmqeL62xR1QoZ1HKKbXRrdN1p3phKpxRMb2VVopvBBz",
); // USDC

// Serum Market Accounts
const SERUM_MARKET = new PublicKey(
  "8BnEgHoWFysVcuFFX7QztDmzuH8r5ZFvyP3sYwn1XTh6",
);
const SERUM_BIDS = new PublicKey(
  "5jWUncPNBMZJ3sTHKmMLszypVkoRK6bfEQMQUHweeQnh",
);
const SERUM_ASKS = new PublicKey(
  "EaXdHx7x3mdGA38j5RSmKYSXMzAFzzUXCLNBEDXDn1d5",
);
const SERUM_EVENT_QUEUE = new PublicKey(
  "8CvwxZ9Db6XbLD46NZwwmVDZZRDy7eydFcAGkXKh9axa",
);
const SERUM_BASE_VAULT = new PublicKey(
  "CKxTHwM9fPMRRvZmFnFoqKNd9pQR21c5Aq9bh5h9oghX",
);
const SERUM_QUOTE_VAULT = new PublicKey(
  "6A5NHCj1yF6urc9wZNe6Bcjj4LVszQNj5DwAWG97yzMu",
);

// AMM V4 Instruction discriminators
// swap_base_in: 0x09
const AMM_SWAP_BASE_IN_DISCRIMINATOR = 9;

// Helper: Encode tree_id as 2-byte little-endian (u16)
function encodeTreeId(treeId: number): Buffer {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16LE(treeId, 0);
  return buffer;
}

/**
 * Build AMM V4 swap instruction data
 * Format: [instruction_id (1 byte), amount_in (8 bytes LE), min_amount_out (8 bytes LE)]
 */
function buildAmmSwapData(
  amountIn: anchor.BN,
  minAmountOut: anchor.BN,
): Buffer {
  const data = Buffer.alloc(17);
  data.writeUInt8(AMM_SWAP_BASE_IN_DISCRIMINATOR, 0);
  data.writeBigUInt64LE(BigInt(amountIn.toString()), 1);
  data.writeBigUInt64LE(BigInt(minAmountOut.toString()), 9);
  return data;
}

/**
 * Derive Serum Vault Signer PDA
 * The vault signer is derived from the market with nonce
 */
function deriveSerumVaultSigner(marketId: PublicKey, nonce: BN): PublicKey {
  // Vault signer = createProgramAddress([market.toBuffer()], nonce, SERUM_PROGRAM)
  // For simplicity, we'll derive it using a known pattern
  // The nonce is stored in the market state
  const seeds = [marketId.toBuffer()];

  // Try to find the PDA with the given nonce
  for (let i = 0; i < 256; i++) {
    try {
      const [pda] = PublicKey.findProgramAddressSync(
        [...seeds, Buffer.from([i])],
        SERUM_PROGRAM,
      );
      return pda;
    } catch {
      continue;
    }
  }

  // Fallback: use createProgramAddress directly with nonce
  return PublicKey.createProgramAddressSync(
    [...seeds, nonce.toArrayLike(Buffer, "le", 8)],
    SERUM_PROGRAM,
  );
}

// Helper: Derive nullifier marker PDA (global, no tree_id to prevent cross-tree double-spend)
function deriveNullifierMarkerPDA(
  programId: PublicKey,
  mintAddress: PublicKey,
  _treeId: number, // Kept for API compatibility but unused
  nullifier: Uint8Array,
): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [
      Buffer.from("nullifier_v3"),
      mintAddress.toBuffer(),
      Buffer.from(nullifier),
    ],
    programId,
  );
  return pda;
}

describe("Privacy Pool AMM V4 Swap", () => {
  const provider = makeProvider();
  anchor.setProvider(provider);

  const program = anchor.workspace.PrivacyPool as Program<PrivacyPool>;
  const payer = (provider.wallet as Wallet).payer;

  // Poseidon hasher
  let poseidon: any;

  // Source pool (SOL)
  let sourceTokenMint: PublicKey;
  let sourceConfig: PublicKey;
  let sourceVault: PublicKey;
  let sourceNoteTree: PublicKey;
  let sourceNullifiers: PublicKey;
  let sourceVaultTokenAccount: PublicKey;

  // Destination pool (USDC)
  let destTokenMint: PublicKey;
  let destConfig: PublicKey;
  let destVault: PublicKey;
  let destNoteTree: PublicKey;
  let destNullifiers: PublicKey;
  let destVaultTokenAccount: PublicKey;

  // Global config
  let globalConfig: PublicKey;

  // Off-chain Merkle trees
  let sourceOffchainTree: OffchainMerkleTree;
  let destOffchainTree: OffchainMerkleTree;

  // Note storage
  const noteStorage = new InMemoryNoteStorage();

  // Test constants
  const SOURCE_DECIMALS = 9; // SOL
  const DEST_DECIMALS = 6; // USDC
  const INITIAL_DEPOSIT = 2_000_000_000; // 2 SOL
  const SWAP_AMOUNT = 500_000_000; // 0.5 SOL
  const SWAP_FEE = 100_000n; // 0.1 USDC relayer fee
  const feeBps = 50; // 0.5%

  // Deposited note reference
  let depositedNoteId: string | null = null;

  // Notes from swap results
  let usdcNoteId: string | null = null;
  let solChangeNoteId: string | null = null;
  let usdcChangeNoteId: string | null = null;
  let solFromUsdcNoteId: string | null = null;

  // Serum vault signer (derived)
  let serumVaultSigner: PublicKey;

  // Shared lookup table for reuse
  let sharedLookupTableAddress: PublicKey | null = null;

  before(async () => {
    console.log("\n🔧 Setting up AMM V4 swap test environment...\n");
    console.log("Using cloned mainnet Raydium AMM V4 SOL/USDC pool\n");

    // Initialize Poseidon
    poseidon = await buildPoseidon();
    sourceOffchainTree = new OffchainMerkleTree(22, poseidon);
    destOffchainTree = new OffchainMerkleTree(22, poseidon);

    // Airdrop SOL for gas and deposits
    await airdropAndConfirm(provider, payer.publicKey, 10 * LAMPORTS_PER_SOL);

    // Use mainnet mints (cloned)
    sourceTokenMint = SOL_MINT;
    destTokenMint = USDC_MINT;

    console.log(`✅ Source Token (SOL): ${sourceTokenMint.toBase58()}`);
    console.log(`✅ Dest Token (USDC): ${destTokenMint.toBase58()}`);
    console.log(`✅ AMM V4 Pool: ${AMM_POOL_STATE.toBase58()}`);

    // Derive Serum vault signer (nonce is typically 0 or found by trying)
    // For this pool, we derive it using the market
    try {
      serumVaultSigner = PublicKey.createProgramAddressSync(
        [SERUM_MARKET.toBuffer(), Buffer.from([0])],
        SERUM_PROGRAM,
      );
    } catch {
      // Try with nonce 1
      serumVaultSigner = PublicKey.createProgramAddressSync(
        [SERUM_MARKET.toBuffer(), Buffer.from([1])],
        SERUM_PROGRAM,
      );
    }
    console.log(`✅ Serum Vault Signer: ${serumVaultSigner.toBase58()}`);

    // Derive PDAs for source pool (SOL)
    [sourceConfig] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_config_v3"), sourceTokenMint.toBuffer()],
      program.programId,
    );
    [sourceVault] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_vault_v3"), sourceTokenMint.toBuffer()],
      program.programId,
    );
    [sourceNoteTree] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("privacy_note_tree_v3"),
        sourceTokenMint.toBuffer(),
        encodeTreeId(0),
      ],
      program.programId,
    );
    [sourceNullifiers] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_nullifiers_v3"), sourceTokenMint.toBuffer()],
      program.programId,
    );
    sourceVaultTokenAccount = await getAssociatedTokenAddress(
      tokenMintFor(sourceTokenMint),
      sourceVault,
      true,
    );

    // Derive PDAs for destination pool (USDC)
    [destConfig] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_config_v3"), destTokenMint.toBuffer()],
      program.programId,
    );
    [destVault] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_vault_v3"), destTokenMint.toBuffer()],
      program.programId,
    );
    [destNoteTree] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("privacy_note_tree_v3"),
        destTokenMint.toBuffer(),
        encodeTreeId(0),
      ],
      program.programId,
    );
    [destNullifiers] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_nullifiers_v3"), destTokenMint.toBuffer()],
      program.programId,
    );
    destVaultTokenAccount = await getAssociatedTokenAddress(
      destTokenMint,
      destVault,
      true,
    );

    // Derive global config
    [globalConfig] = PublicKey.findProgramAddressSync(
      [Buffer.from("global_config_v1")],
      program.programId,
    );

    console.log("Source Config PDA (SOL):", sourceConfig.toBase58());
    console.log("Dest Config PDA (USDC):", destConfig.toBase58());
  });

  it("initializes source privacy pool (SOL)", async () => {
    try {
      await (program.methods as any)
        .initialize(
          feeBps,
          sourceTokenMint,
          new BN(1_000_000),
          new BN(1_000_000_000_000),
          new BN(1_000_000),
          new BN(1_000_000_000_000),
        )
        .accounts({
          config: sourceConfig,
          vault: sourceVault,
          noteTree: sourceNoteTree,
          nullifiers: sourceNullifiers,
          admin: payer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      console.log("✅ Source pool (SOL) initialized");
    } catch (e: any) {
      if (e.message?.includes("already in use")) {
        console.log("Source pool (SOL) already initialized");
      } else {
        throw e;
      }
    }
  });

  it("initializes destination privacy pool (USDC)", async () => {
    try {
      await (program.methods as any)
        .initialize(
          feeBps,
          destTokenMint,
          new BN(1_000_000),
          new BN(1_000_000_000_000),
          new BN(1_000_000),
          new BN(1_000_000_000_000),
        )
        .accounts({
          config: destConfig,
          vault: destVault,
          noteTree: destNoteTree,
          nullifiers: destNullifiers,
          admin: payer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      console.log("✅ Dest pool (USDC) initialized");
    } catch (e: any) {
      if (e.message?.includes("already in use")) {
        console.log("Dest pool (USDC) already initialized");
      } else {
        throw e;
      }
    }
  });

  it("initializes global config", async () => {
    try {
      try {
        const existingConfig = await (
          program.account as any
        ).globalConfig.fetch(globalConfig);
        console.log("✅ Global config already initialized");
        return;
      } catch {
        // Account doesn't exist, proceed
      }

      await (program.methods as any)
        .initializeGlobalConfig()
        .accounts({
          globalConfig,
          admin: payer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      console.log("✅ Global config initialized");
    } catch (e: any) {
      if (e instanceof SendTransactionError) {
        const logs = await e.getLogs(provider.connection);
        console.error("Global config init failed:", logs);
      }
      throw e;
    }
  });

  it("registers relayer for source pool", async () => {
    try {
      await (program.methods as any)
        .addRelayer(sourceTokenMint, payer.publicKey)
        .accounts({ config: sourceConfig, admin: payer.publicKey })
        .rpc();
      console.log("✅ Relayer registered for source pool (SOL)");
    } catch (e: any) {
      if (
        e.message?.includes("already added") ||
        e.message?.includes("RelayerAlreadyExists")
      ) {
        console.log("✅ Relayer already registered for source pool");
      } else {
        throw e;
      }
    }
  });

  it("registers relayer for dest pool", async () => {
    try {
      await (program.methods as any)
        .addRelayer(destTokenMint, payer.publicKey)
        .accounts({ config: destConfig, admin: payer.publicKey })
        .rpc();
      console.log("✅ Relayer registered for dest pool (USDC)");
    } catch (e: any) {
      if (
        e.message?.includes("already added") ||
        e.message?.includes("RelayerAlreadyExists")
      ) {
        console.log("✅ Relayer already registered for dest pool");
      } else {
        throw e;
      }
    }
  });

  it("deposits SOL to source pool for AMM swap", async () => {
    console.log("\n🎁 Depositing SOL to source pool...");

    // Create vault's token account
    await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      tokenMintFor(sourceTokenMint),
      sourceVault,
      true,
    );

    // Native SOL: use payer.publicKey directly (on-chain uses system_program::transfer)
    console.log(
      `   Using native SOL from payer: ${payer.publicKey.toBase58()}`,
    );

    // Generate keypair for the note
    const privateKey = randomBytes32();
    const publicKey = derivePublicKey(poseidon, privateKey);
    const blinding = randomBytes32();
    const amount = BigInt(INITIAL_DEPOSIT);

    // Compute commitment
    const commitment = computeCommitment(
      poseidon,
      amount,
      publicKey,
      blinding,
      sourceTokenMint,
    );

    // Create dummy inputs for deposit
    const dummyPrivKey1 = randomBytes32();
    const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);
    const dummyBlinding1 = randomBytes32();
    const dummyCommitment1 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey1,
      dummyBlinding1,
      sourceTokenMint,
    );
    const dummyNullifier1 = computeNullifier(
      poseidon,
      dummyCommitment1,
      0,
      dummyPrivKey1,
    );

    const dummyPrivKey2 = randomBytes32();
    const dummyPubKey2 = derivePublicKey(poseidon, dummyPrivKey2);
    const dummyBlinding2 = randomBytes32();
    const dummyCommitment2 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey2,
      dummyBlinding2,
      sourceTokenMint,
    );
    const dummyNullifier2 = computeNullifier(
      poseidon,
      dummyCommitment2,
      0,
      dummyPrivKey2,
    );

    // Change output
    const changePrivKey = randomBytes32();
    const changePubKey = derivePublicKey(poseidon, changePrivKey);
    const changeBlinding = randomBytes32();
    const changeCommitment = computeCommitment(
      poseidon,
      0n,
      changePubKey,
      changeBlinding,
      sourceTokenMint,
    );

    // External data
    const extData = {
      recipient: payer.publicKey,
      relayer: payer.publicKey,
      fee: new BN(0),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    // Get Merkle proof
    const dummyProof = sourceOffchainTree.getMerkleProof(0);
    const root = sourceOffchainTree.getRoot();

    // Generate proof
    const proof = await generateTransactionProof({
      root,
      publicAmount: amount,
      extDataHash,
      mintAddress: sourceTokenMint,
      inputNullifiers: [dummyNullifier1, dummyNullifier2],
      outputCommitments: [commitment, changeCommitment],
      inputAmounts: [0n, 0n],
      inputPrivateKeys: [dummyPrivKey1, dummyPrivKey2],
      inputPublicKeys: [dummyPubKey1, dummyPubKey2],
      inputBlindings: [dummyBlinding1, dummyBlinding2],
      inputMerklePaths: [dummyProof, dummyProof],
      outputAmounts: [amount, 0n],
      outputOwners: [publicKey, changePubKey],
      outputBlindings: [blinding, changeBlinding],
    });

    // Derive nullifier marker PDAs
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      sourceTokenMint,
      0,
      dummyNullifier1,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      sourceTokenMint,
      0,
      dummyNullifier2,
    );

    // Execute deposit
    const tx = await (program.methods as any)
      .transact(
        Array.from(root),
        0,
        0,
        new BN(amount.toString()),
        Array.from(extDataHash),
        sourceTokenMint,
        Array.from(dummyNullifier1),
        Array.from(dummyNullifier2),
        Array.from(commitment),
        Array.from(changeCommitment),
        new BN(9999999999), // deadline (far future for tests)
        {
          recipient: extData.recipient,
          relayer: extData.relayer,
          fee: extData.fee,
          refund: extData.refund,
        },
        proof,
      )
      .accounts({
        config: sourceConfig,
        globalConfig,
        vault: sourceVault,
        inputTree: sourceNoteTree,
        outputTree: sourceNoteTree,
        nullifiers: sourceNullifiers,
        nullifierMarker0,
        nullifierMarker1,
        relayer: payer.publicKey,
        recipient: payer.publicKey,
        vaultTokenAccount: sourceVaultTokenAccount,
        userTokenAccount: payer.publicKey,
        recipientTokenAccount: payer.publicKey,
        relayerTokenAccount: payer.publicKey,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
      ])
      .rpc();

    console.log(`✅ Deposit tx: ${tx}`);

    // Update off-chain tree
    const leafIndex = sourceOffchainTree.insert(commitment);
    sourceOffchainTree.insert(changeCommitment);

    // Save note
    depositedNoteId = noteStorage.save({
      amount,
      commitment,
      nullifier: computeNullifier(poseidon, commitment, leafIndex, privateKey),
      blinding,
      privateKey,
      publicKey,
      leafIndex,
      merklePath: sourceOffchainTree.getMerkleProof(leafIndex),
      mintAddress: sourceTokenMint,
    });

    console.log(`   Note saved: ${depositedNoteId}`);
  });

  it("should build correct AMM V4 swap data", () => {
    const amountIn = new anchor.BN(500_000_000); // 0.5 SOL
    const minOut = new anchor.BN(50_000_000); // 50 USDC (conservative)

    const swapData = buildAmmSwapData(amountIn, minOut);

    expect(swapData.length).to.equal(17);
    expect(swapData[0]).to.equal(AMM_SWAP_BASE_IN_DISCRIMINATOR);

    const decodedAmountIn = swapData.readBigUInt64LE(1);
    const decodedMinOut = swapData.readBigUInt64LE(9);

    expect(decodedAmountIn.toString()).to.equal(amountIn.toString());
    expect(decodedMinOut.toString()).to.equal(minOut.toString());

    console.log("\n✅ AMM V4 swap data validated:");
    console.log(`   Instruction ID: ${swapData[0]} (swap_base_in)`);
    console.log(
      `   Amount In: ${decodedAmountIn} (${Number(decodedAmountIn) / 1e9} SOL)`,
    );
    console.log(
      `   Min Out: ${decodedMinOut} (${Number(decodedMinOut) / 1e6} USDC)`,
    );
  });

  it("verifies AMM accounts are correctly configured", async () => {
    // Verify AMM pool state exists
    const poolInfo = await provider.connection.getAccountInfo(AMM_POOL_STATE);
    expect(poolInfo).to.not.be.null;
    console.log("\n✅ AMM V4 Pool State verified:");
    console.log(`   Address: ${AMM_POOL_STATE.toBase58()}`);
    console.log(`   Owner: ${poolInfo!.owner.toBase58()}`);
    console.log(`   Data Length: ${poolInfo!.data.length}`);

    // Verify Serum market exists
    const marketInfo = await provider.connection.getAccountInfo(SERUM_MARKET);
    expect(marketInfo).to.not.be.null;
    console.log("\n✅ Serum Market verified:");
    console.log(`   Address: ${SERUM_MARKET.toBase58()}`);
  });

  it("verifies deposited note exists", async () => {
    expect(depositedNoteId).to.not.be.null;
    const note = noteStorage.get(depositedNoteId!);
    expect(note).to.not.be.undefined;
    expect(note!.amount).to.equal(BigInt(INITIAL_DEPOSIT));

    console.log("\n✅ Deposited note verified:");
    console.log(
      `   Amount: ${note!.amount} lamports (${Number(note!.amount) / 1e9} SOL)`,
    );
    console.log(`   Leaf index: ${note!.leafIndex}`);
  });

  it("executes cross-pool swap (SOL → USDC via AMM V4)", async () => {
    console.log("\n🔄 Executing cross-pool swap SOL → USDC via AMM V4...");

    const note = noteStorage.get(depositedNoteId!);
    if (!note) throw new Error("Note not found");

    console.log(`   Input note amount: ${note.amount} lamports`);
    console.log(`   Swap amount: ${SWAP_AMOUNT} lamports`);

    // Get merkle proof
    const merkleProof = sourceOffchainTree.getMerkleProof(note.leafIndex);
    const root = sourceOffchainTree.getRoot();

    // Dummy second input
    const dummyPrivKey = randomBytes32();
    const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
    const dummyBlinding = randomBytes32();
    const dummyCommitment = computeCommitment(
      poseidon,
      0n,
      dummyPubKey,
      dummyBlinding,
      sourceTokenMint,
    );
    const dummyNullifier = computeNullifier(
      poseidon,
      dummyCommitment,
      0,
      dummyPrivKey,
    );
    const dummyProof = sourceOffchainTree.getMerkleProof(0);

    // Output commitments
    const destPrivKey = randomBytes32();
    const destPubKey = derivePublicKey(poseidon, destPrivKey);
    const destBlinding = randomBytes32();
    const swappedAmount = 50_000_000n; // ~50 USDC (estimated)
    const destCommitment = computeCommitment(
      poseidon,
      swappedAmount,
      destPubKey,
      destBlinding,
      destTokenMint,
    );
    const destCommitmentForProof = computeCommitment(
      poseidon,
      0n,
      destPubKey,
      destBlinding,
      sourceTokenMint,
    );

    // Change note
    const changeAmount = note.amount - BigInt(SWAP_AMOUNT);
    const changePrivKey = randomBytes32();
    const changePubKey = derivePublicKey(poseidon, changePrivKey);
    const changeBlinding = randomBytes32();
    const changeCommitment = computeCommitment(
      poseidon,
      changeAmount,
      changePubKey,
      changeBlinding,
      sourceTokenMint,
    );

    // External data
    const extData = {
      recipient: payer.publicKey,
      relayer: payer.publicKey,
      fee: new BN(SWAP_FEE.toString()),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    // Build swap params (must precede proof so values match)
    const minAmountOutBigInt = 40_000_000n; // 40 USDC min (conservative slippage)
    const deadlineBigInt = BigInt(Math.floor(Date.now() / 1000) + 3600);
    const swapParamsHash = computeSwapParamsHash(
      poseidon,
      sourceTokenMint,
      destTokenMint,
      minAmountOutBigInt,
      deadlineBigInt,
      new Uint8Array(32), // MEDIUM-001: zero for CPMM/AMM
      swappedAmount,
    );

    // Generate ZK swap proof
    console.log("   Generating ZK proof...");
    const proof = await generateSwapProof({
      sourceRoot: root,
      swapParamsHash,
      extDataHash,
      sourceMint: sourceTokenMint,
      destMint: destTokenMint,
      inputNullifiers: [note.nullifier, dummyNullifier],
      changeCommitment,
      destCommitment,
      swapAmount: BigInt(SWAP_AMOUNT),
      inputAmounts: [note.amount, 0n],
      inputPrivateKeys: [note.privateKey, dummyPrivKey],
      inputPublicKeys: [note.publicKey, dummyPubKey],
      inputBlindings: [note.blinding, dummyBlinding],
      inputMerklePaths: [merkleProof, dummyProof],
      changeAmount,
      changePubkey: changePubKey,
      changeBlinding,
      destAmount: swappedAmount,
      destPubkey: destPubKey,
      destBlinding,
      minAmountOut: minAmountOutBigInt,
      deadline: deadlineBigInt,
      swapDataHash: new Uint8Array(32), // MEDIUM-001: zero for CPMM/AMM
    });
    console.log("   ✅ ZK proof generated");

    const minAmountOut = new BN(minAmountOutBigInt.toString());
    const swapData = buildAmmSwapData(new BN(SWAP_AMOUNT), minAmountOut);

    // Swap params (must match values used in ZK proof)
    const swapParams = {
      minAmountOut,
      deadline: new BN(deadlineBigInt.toString()),
      sourceMint: sourceTokenMint,
      destMint: destTokenMint,
      destAmount: new BN(swappedAmount.toString()),
      swapDataHash: Buffer.alloc(32), // MEDIUM-001: zero for CPMM/AMM
    };

    // Derive executor PDA
    const [executorPda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("swap_executor"),
        sourceTokenMint.toBuffer(),
        destTokenMint.toBuffer(),
        Buffer.from(note.nullifier),
        payer.publicKey.toBuffer(),
      ],
      program.programId,
    );
    const executorSourceToken = await getAssociatedTokenAddress(
      tokenMintFor(sourceTokenMint),
      executorPda,
      true,
    );
    const executorDestToken = await getAssociatedTokenAddress(
      destTokenMint,
      executorPda,
      true,
    );

    // Nullifier markers
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      sourceTokenMint,
      0,
      note.nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      sourceTokenMint,
      0,
      dummyNullifier,
    );

    // Token accounts
    const sourceVaultWsolAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      tokenMintFor(sourceTokenMint),
      sourceVault,
      true,
    );
    const destVaultUsdcAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      destTokenMint,
      destVault,
      true,
    );
    const relayerTokenAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      destTokenMint,
      payer.publicKey,
    );

    console.log("   Executor PDA:", executorPda.toBase58());

    // Create Address Lookup Table
    console.log("   Creating Address Lookup Table...");
    const recentSlot = await provider.connection.getSlot("finalized");

    const lookupTableAddresses = [
      sourceConfig,
      globalConfig,
      sourceVault,
      sourceNoteTree,
      sourceNullifiers,
      sourceVaultWsolAccount.address,
      tokenMintFor(sourceTokenMint),
      destConfig,
      destVault,
      destNoteTree,
      destVaultUsdcAccount.address,
      destTokenMint,
      RAYDIUM_AMM_V4_PROGRAM,
      SERUM_PROGRAM,
      TOKEN_PROGRAM_ID,
      SystemProgram.programId,
      ASSOCIATED_TOKEN_PROGRAM_ID,
      AMM_POOL_STATE,
      AMM_AUTHORITY,
      AMM_OPEN_ORDERS,
      AMM_TARGET_ORDERS,
      AMM_BASE_VAULT,
      AMM_QUOTE_VAULT,
      SERUM_MARKET,
      SERUM_BIDS,
      SERUM_ASKS,
      SERUM_EVENT_QUEUE,
      SERUM_BASE_VAULT,
      SERUM_QUOTE_VAULT,
      serumVaultSigner,
    ];

    const [createLutIx, lookupTableAddress] =
      AddressLookupTableProgram.createLookupTable({
        authority: payer.publicKey,
        payer: payer.publicKey,
        recentSlot,
      });

    const extendLutIx = AddressLookupTableProgram.extendLookupTable({
      payer: payer.publicKey,
      authority: payer.publicKey,
      lookupTable: lookupTableAddress,
      addresses: lookupTableAddresses,
    });

    const createLutTx = new anchor.web3.Transaction()
      .add(createLutIx)
      .add(extendLutIx);
    await provider.sendAndConfirm(createLutTx);
    console.log(`   ALT created: ${lookupTableAddress.toBase58()}`);

    await new Promise((resolve) => setTimeout(resolve, 1000));

    const lookupTableAccount = await provider.connection.getAddressLookupTable(
      lookupTableAddress,
    );
    if (!lookupTableAccount.value)
      throw new Error("Failed to fetch lookup table");

    try {
      // Build swap instruction
      // AMM V4 requires 14 remaining accounts:
      // 0: Amm Id, 1: Amm Authority, 2: Open Orders, 3: Target Orders
      // 4: Pool Coin Vault, 5: Pool Pc Vault, 6: Serum Program, 7: Serum Market
      // 8: Serum Bids, 9: Serum Asks, 10: Serum Event Queue
      // 11: Serum Coin Vault, 12: Serum Pc Vault, 13: Serum Vault Signer
      const swapIx = await (program.methods as any)
        .transactSwap(
          proof,
          Array.from(root),
          0,
          sourceTokenMint,
          Array.from(note.nullifier),
          Array.from(dummyNullifier),
          0,
          destTokenMint,
          Array.from(changeCommitment),
          Array.from(destCommitment),
          swapParams,
          new BN(SWAP_AMOUNT.toString()),
          swapData,
          extData,
        )
        .accounts({
          sourceConfig,
          globalConfig,
          sourceVault,
          sourceTree: sourceNoteTree,
          sourceNullifiers: sourceNullifiers,
          sourceNullifierMarker0: nullifierMarker0,
          sourceNullifierMarker1: nullifierMarker1,
          sourceVaultTokenAccount: sourceVaultWsolAccount.address,
          sourceMintAccount: tokenMintFor(sourceTokenMint),
          destConfig,
          destVault,
          destTree: destNoteTree,
          destVaultTokenAccount: destVaultUsdcAccount.address,
          destMintAccount: destTokenMint,
          executor: executorPda,
          executorSourceToken,
          executorDestToken,
          relayer: payer.publicKey,
          relayerTokenAccount: relayerTokenAccount.address,
          swapProgram: RAYDIUM_AMM_V4_PROGRAM,
          jupiterEventAuthority: SystemProgram.programId,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
          associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
        })
        .remainingAccounts([
          { pubkey: AMM_POOL_STATE, isSigner: false, isWritable: true }, // 0: Amm Id
          { pubkey: AMM_AUTHORITY, isSigner: false, isWritable: false }, // 1: Amm Authority
          { pubkey: AMM_OPEN_ORDERS, isSigner: false, isWritable: true }, // 2: Open Orders
          { pubkey: AMM_TARGET_ORDERS, isSigner: false, isWritable: true }, // 3: Target Orders
          { pubkey: AMM_BASE_VAULT, isSigner: false, isWritable: true }, // 4: Pool Coin Vault
          { pubkey: AMM_QUOTE_VAULT, isSigner: false, isWritable: true }, // 5: Pool Pc Vault
          { pubkey: SERUM_PROGRAM, isSigner: false, isWritable: false }, // 6: Serum Program
          { pubkey: SERUM_MARKET, isSigner: false, isWritable: true }, // 7: Serum Market
          { pubkey: SERUM_BIDS, isSigner: false, isWritable: true }, // 8: Serum Bids
          { pubkey: SERUM_ASKS, isSigner: false, isWritable: true }, // 9: Serum Asks
          { pubkey: SERUM_EVENT_QUEUE, isSigner: false, isWritable: true }, // 10: Serum Event Queue
          { pubkey: SERUM_BASE_VAULT, isSigner: false, isWritable: true }, // 11: Serum Coin Vault
          { pubkey: SERUM_QUOTE_VAULT, isSigner: false, isWritable: true }, // 12: Serum Pc Vault
          { pubkey: serumVaultSigner, isSigner: false, isWritable: false }, // 13: Serum Vault Signer
        ])
        .instruction();

      // Build versioned transaction
      const computeBudgetIx = ComputeBudgetProgram.setComputeUnitLimit({
        units: 1_400_000,
      });
      const { blockhash, lastValidBlockHeight } =
        await provider.connection.getLatestBlockhash();

      const messageV0 = new TransactionMessage({
        payerKey: payer.publicKey,
        recentBlockhash: blockhash,
        instructions: [computeBudgetIx, swapIx],
      }).compileToV0Message([lookupTableAccount.value]);

      const versionedTx = new VersionedTransaction(messageV0);
      versionedTx.sign([payer]);

      const serialized = versionedTx.serialize();
      console.log(
        `   Transaction size: ${serialized.length} bytes (limit: 1232)`,
      );

      if (serialized.length > 1232) {
        throw new Error(
          `Transaction too large: ${serialized.length} > 1232 bytes`,
        );
      }

      const txSig = await provider.connection.sendTransaction(versionedTx, {
        skipPreflight: false,
      });
      await provider.connection.confirmTransaction({
        signature: txSig,
        blockhash,
        lastValidBlockHeight,
      });

      console.log(`✅ AMM V4 swap executed: ${txSig}`);

      // Verify balances changed
      const destVaultBalance = await provider.connection.getTokenAccountBalance(
        destVaultUsdcAccount.address,
      );
      console.log(
        `   Dest vault USDC balance: ${destVaultBalance.value.uiAmountString}`,
      );

      // Save the USDC note from swap output
      const usdcLeafIndex = destOffchainTree.insert(destCommitment);
      usdcNoteId = noteStorage.save({
        amount: swappedAmount,
        commitment: destCommitment,
        nullifier: computeNullifier(
          poseidon,
          destCommitment,
          usdcLeafIndex,
          destPrivKey,
        ),
        blinding: destBlinding,
        privateKey: destPrivKey,
        publicKey: destPubKey,
        leafIndex: usdcLeafIndex,
        merklePath: destOffchainTree.getMerkleProof(usdcLeafIndex),
        mintAddress: destTokenMint,
      });
      console.log(`   USDC note saved: ${usdcNoteId} (${swappedAmount} units)`);

      // Save the SOL change note
      const solChangeLeafIndex = sourceOffchainTree.insert(changeCommitment);
      solChangeNoteId = noteStorage.save({
        amount: changeAmount,
        commitment: changeCommitment,
        nullifier: computeNullifier(
          poseidon,
          changeCommitment,
          solChangeLeafIndex,
          changePrivKey,
        ),
        blinding: changeBlinding,
        privateKey: changePrivKey,
        publicKey: changePubKey,
        leafIndex: solChangeLeafIndex,
        merklePath: sourceOffchainTree.getMerkleProof(solChangeLeafIndex),
        mintAddress: sourceTokenMint,
      });
      console.log(
        `   SOL change note saved: ${solChangeNoteId} (${changeAmount} lamports = ${
          Number(changeAmount) / 1e9
        } SOL)`,
      );

      // Save lookup table for reuse
      sharedLookupTableAddress = lookupTableAddress;
    } catch (e: any) {
      console.error("❌ AMM V4 swap failed:", e.message);
      if (e.logs) {
        console.error("Logs:", e.logs.slice(-20));
      }
      throw e;
    }
  });

  it("spends the SOL change note (internal transfer)", async () => {
    console.log("\n🔄 Spending SOL change note (internal transfer)...");

    const note = noteStorage.get(solChangeNoteId!);
    if (!note) throw new Error("SOL change note not found");

    console.log(
      `   Input note amount: ${note.amount} lamports (${
        Number(note.amount) / 1e9
      } SOL)`,
    );

    // Get merkle proof
    const merkleProof = sourceOffchainTree.getMerkleProof(note.leafIndex);
    const root = sourceOffchainTree.getRoot();

    // Dummy second input
    const dummyPrivKey = randomBytes32();
    const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
    const dummyBlinding = randomBytes32();
    const dummyCommitment = computeCommitment(
      poseidon,
      0n,
      dummyPubKey,
      dummyBlinding,
      sourceTokenMint,
    );
    const dummyNullifier = computeNullifier(
      poseidon,
      dummyCommitment,
      0,
      dummyPrivKey,
    );
    const dummyProof = sourceOffchainTree.getMerkleProof(0);

    // Output: new note with same amount (internal transfer, no fee)
    const fee = 0n; // No fee for internal transfer
    const outputAmount = note.amount; // Keep full amount
    const outputPrivKey = randomBytes32();
    const outputPubKey = derivePublicKey(poseidon, outputPrivKey);
    const outputBlinding = randomBytes32();
    const outputCommitment = computeCommitment(
      poseidon,
      outputAmount,
      outputPubKey,
      outputBlinding,
      sourceTokenMint,
    );

    // Change output (zero)
    const changePrivKey = randomBytes32();
    const changePubKey = derivePublicKey(poseidon, changePrivKey);
    const changeBlinding = randomBytes32();
    const changeCommitment = computeCommitment(
      poseidon,
      0n,
      changePubKey,
      changeBlinding,
      sourceTokenMint,
    );

    // External data (paying fee to relayer)
    const extData = {
      recipient: payer.publicKey,
      relayer: payer.publicKey,
      fee: new BN(fee.toString()),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    // Generate ZK proof
    console.log("   Generating ZK proof...");
    const proof = await generateTransactionProof({
      root,
      publicAmount: 0n, // No fee, pure internal transfer
      extDataHash,
      mintAddress: sourceTokenMint,
      inputNullifiers: [note.nullifier, dummyNullifier],
      outputCommitments: [outputCommitment, changeCommitment],
      inputAmounts: [note.amount, 0n],
      inputPrivateKeys: [note.privateKey, dummyPrivKey],
      inputPublicKeys: [note.publicKey, dummyPubKey],
      inputBlindings: [note.blinding, dummyBlinding],
      inputMerklePaths: [merkleProof, dummyProof],
      outputAmounts: [outputAmount, 0n],
      outputOwners: [outputPubKey, changePubKey],
      outputBlindings: [outputBlinding, changeBlinding],
    });
    console.log("   ✅ ZK proof generated");

    // Derive nullifier marker PDAs
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      sourceTokenMint,
      0,
      note.nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      sourceTokenMint,
      0,
      dummyNullifier,
    );

    // Token accounts
    const vaultTokenAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      tokenMintFor(sourceTokenMint),
      sourceVault,
      true,
    );
    const relayerTokenAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      tokenMintFor(sourceTokenMint),
      payer.publicKey,
    );

    // Execute transaction
    const tx = await (program.methods as any)
      .transact(
        Array.from(root),
        0,
        0,
        new BN(0), // No public amount for internal transfer
        Array.from(extDataHash),
        sourceTokenMint,
        Array.from(note.nullifier),
        Array.from(dummyNullifier),
        Array.from(outputCommitment),
        Array.from(changeCommitment),
        new BN(9999999999), // deadline (far future for tests)
        extData,
        proof,
      )
      .accounts({
        config: sourceConfig,
        globalConfig,
        vault: sourceVault,
        inputTree: sourceNoteTree,
        outputTree: sourceNoteTree,
        nullifiers: sourceNullifiers,
        nullifierMarker0,
        nullifierMarker1,
        relayer: payer.publicKey,
        recipient: payer.publicKey,
        vaultTokenAccount: vaultTokenAccount.address,
        userTokenAccount: relayerTokenAccount.address,
        recipientTokenAccount: relayerTokenAccount.address,
        relayerTokenAccount: relayerTokenAccount.address,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
      ])
      .rpc();

    console.log(`✅ SOL change note spent: ${tx}`);

    // Update off-chain tree
    sourceOffchainTree.insert(outputCommitment);
    sourceOffchainTree.insert(changeCommitment);

    console.log(`   Internal transfer - no fee`);
    console.log(
      `   New note created: ${outputAmount} lamports (${
        Number(outputAmount) / 1e9
      } SOL)`,
    );
  });

  it("spends the USDC note (internal transfer)", async () => {
    console.log("\n🔄 Spending USDC note (internal transfer)...");

    const note = noteStorage.get(usdcNoteId!);
    if (!note) throw new Error("USDC note not found");

    console.log(
      `   Input note amount: ${note.amount} units (${
        Number(note.amount) / 1e6
      } USDC)`,
    );

    // Get merkle proof
    const merkleProof = destOffchainTree.getMerkleProof(note.leafIndex);
    const root = destOffchainTree.getRoot();

    // Dummy second input
    const dummyPrivKey = randomBytes32();
    const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
    const dummyBlinding = randomBytes32();
    const dummyCommitment = computeCommitment(
      poseidon,
      0n,
      dummyPubKey,
      dummyBlinding,
      destTokenMint,
    );
    const dummyNullifier = computeNullifier(
      poseidon,
      dummyCommitment,
      0,
      dummyPrivKey,
    );
    const dummyProof = destOffchainTree.getMerkleProof(0);

    // Output: split into two notes for later use (internal transfer, no fee)
    const fee = 0n; // No fee for internal transfer
    const swapAmount = 25_000_000n; // 25 USDC to use for reverse swap
    const keepAmount = note.amount - swapAmount;

    // Note to keep
    const keepPrivKey = randomBytes32();
    const keepPubKey = derivePublicKey(poseidon, keepPrivKey);
    const keepBlinding = randomBytes32();
    const keepCommitment = computeCommitment(
      poseidon,
      keepAmount,
      keepPubKey,
      keepBlinding,
      destTokenMint,
    );

    // Note for reverse swap
    const swapPrivKey = randomBytes32();
    const swapPubKey = derivePublicKey(poseidon, swapPrivKey);
    const swapBlinding = randomBytes32();
    const swapCommitment = computeCommitment(
      poseidon,
      swapAmount,
      swapPubKey,
      swapBlinding,
      destTokenMint,
    );

    // External data
    const extData = {
      recipient: payer.publicKey,
      relayer: payer.publicKey,
      fee: new BN(fee.toString()),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    // Generate ZK proof
    console.log("   Generating ZK proof...");
    const proof = await generateTransactionProof({
      root,
      publicAmount: 0n, // No fee, pure internal transfer
      extDataHash,
      mintAddress: destTokenMint,
      inputNullifiers: [note.nullifier, dummyNullifier],
      outputCommitments: [keepCommitment, swapCommitment],
      inputAmounts: [note.amount, 0n],
      inputPrivateKeys: [note.privateKey, dummyPrivKey],
      inputPublicKeys: [note.publicKey, dummyPubKey],
      inputBlindings: [note.blinding, dummyBlinding],
      inputMerklePaths: [merkleProof, dummyProof],
      outputAmounts: [keepAmount, swapAmount],
      outputOwners: [keepPubKey, swapPubKey],
      outputBlindings: [keepBlinding, swapBlinding],
    });
    console.log("   ✅ ZK proof generated");

    // Derive nullifier marker PDAs
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      destTokenMint,
      0,
      note.nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      destTokenMint,
      0,
      dummyNullifier,
    );

    // Token accounts
    const vaultTokenAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      destTokenMint,
      destVault,
      true,
    );
    const relayerTokenAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      destTokenMint,
      payer.publicKey,
    );

    // Execute transaction
    const tx = await (program.methods as any)
      .transact(
        Array.from(root),
        0,
        0,
        new BN(0), // No public amount for internal transfer
        Array.from(extDataHash),
        destTokenMint,
        Array.from(note.nullifier),
        Array.from(dummyNullifier),
        Array.from(keepCommitment),
        Array.from(swapCommitment),
        new BN(9999999999), // deadline (far future for tests)
        extData,
        proof,
      )
      .accounts({
        config: destConfig,
        globalConfig,
        vault: destVault,
        inputTree: destNoteTree,
        outputTree: destNoteTree,
        nullifiers: destNullifiers,
        nullifierMarker0,
        nullifierMarker1,
        relayer: payer.publicKey,
        recipient: payer.publicKey,
        vaultTokenAccount: vaultTokenAccount.address,
        userTokenAccount: relayerTokenAccount.address,
        recipientTokenAccount: relayerTokenAccount.address,
        relayerTokenAccount: relayerTokenAccount.address,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
      ])
      .rpc();

    console.log(`✅ USDC note spent: ${tx}`);

    // Update off-chain tree
    const keepLeafIndex = destOffchainTree.insert(keepCommitment);
    const swapLeafIndex = destOffchainTree.insert(swapCommitment);

    // Save the swap note for reverse swap test
    usdcChangeNoteId = noteStorage.save({
      amount: swapAmount,
      commitment: swapCommitment,
      nullifier: computeNullifier(
        poseidon,
        swapCommitment,
        swapLeafIndex,
        swapPrivKey,
      ),
      blinding: swapBlinding,
      privateKey: swapPrivKey,
      publicKey: swapPubKey,
      leafIndex: swapLeafIndex,
      merklePath: destOffchainTree.getMerkleProof(swapLeafIndex),
      mintAddress: destTokenMint,
    });

    console.log(`   Internal transfer - no fee`);
    console.log(
      `   Keep note: ${keepAmount} units (${Number(keepAmount) / 1e6} USDC)`,
    );
    console.log(
      `   Swap note saved: ${usdcChangeNoteId} - ${swapAmount} units (${
        Number(swapAmount) / 1e6
      } USDC)`,
    );
  });

  it("executes reverse swap (USDC → SOL via AMM V4)", async () => {
    console.log("\n🔄 Executing reverse swap USDC → SOL via AMM V4...");

    const note = noteStorage.get(usdcChangeNoteId!);
    if (!note) throw new Error("USDC swap note not found");

    console.log(
      `   Input note amount: ${note.amount} units (${
        Number(note.amount) / 1e6
      } USDC)`,
    );

    // Get merkle proof
    const merkleProof = destOffchainTree.getMerkleProof(note.leafIndex);
    const root = destOffchainTree.getRoot();

    // Dummy second input
    const dummyPrivKey = randomBytes32();
    const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
    const dummyBlinding = randomBytes32();
    const dummyCommitment = computeCommitment(
      poseidon,
      0n,
      dummyPubKey,
      dummyBlinding,
      destTokenMint,
    );
    const dummyNullifier = computeNullifier(
      poseidon,
      dummyCommitment,
      0,
      dummyPrivKey,
    );
    const dummyProof = destOffchainTree.getMerkleProof(0);

    // Swap all USDC
    const swapAmount = note.amount;
    const expectedSol = 100_000_000n; // ~0.1 SOL estimated output

    // Output: SOL note in source pool
    const solOutputPrivKey = randomBytes32();
    const solOutputPubKey = derivePublicKey(poseidon, solOutputPrivKey);
    const solOutputBlinding = randomBytes32();
    const solOutputCommitment = computeCommitment(
      poseidon,
      expectedSol,
      solOutputPubKey,
      solOutputBlinding,
      sourceTokenMint,
    );
    // For proof, we use dest mint
    const solOutputCommitmentForProof = computeCommitment(
      poseidon,
      0n,
      solOutputPubKey,
      solOutputBlinding,
      destTokenMint,
    );

    // Change note (zero, swapping all)
    const changePrivKey = randomBytes32();
    const changePubKey = derivePublicKey(poseidon, changePrivKey);
    const changeBlinding = randomBytes32();
    const changeCommitment = computeCommitment(
      poseidon,
      0n,
      changePubKey,
      changeBlinding,
      destTokenMint,
    );

    // External data - fee must meet dest pool minimum (1_000_000 for SOL pool)
    const reverseSwapFee = 1_000_000n; // 0.001 SOL minimum fee
    const extData = {
      recipient: payer.publicKey,
      relayer: payer.publicKey,
      fee: new BN(reverseSwapFee.toString()),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    // Build swap params (must precede proof so values match)
    const minSolOutBigInt = 50_000_000n; // 0.05 SOL min (conservative)
    const deadlineBigInt = BigInt(Math.floor(Date.now() / 1000) + 3600);
    const swapParamsHash = computeSwapParamsHash(
      poseidon,
      destTokenMint, // source = USDC
      sourceTokenMint, // dest = SOL
      minSolOutBigInt,
      deadlineBigInt,
      new Uint8Array(32), // MEDIUM-001: zero for CPMM/AMM
      expectedSol,
    );

    // Generate ZK swap proof
    console.log("   Generating ZK proof...");
    const proof = await generateSwapProof({
      sourceRoot: root,
      swapParamsHash,
      extDataHash,
      sourceMint: destTokenMint, // USDC
      destMint: sourceTokenMint, // SOL
      inputNullifiers: [note.nullifier, dummyNullifier],
      changeCommitment,
      destCommitment: solOutputCommitment,
      swapAmount,
      inputAmounts: [note.amount, 0n],
      inputPrivateKeys: [note.privateKey, dummyPrivKey],
      inputPublicKeys: [note.publicKey, dummyPubKey],
      inputBlindings: [note.blinding, dummyBlinding],
      inputMerklePaths: [merkleProof, dummyProof],
      changeAmount: 0n,
      changePubkey: changePubKey,
      changeBlinding,
      destAmount: expectedSol,
      destPubkey: solOutputPubKey,
      destBlinding: solOutputBlinding,
      minAmountOut: minSolOutBigInt,
      deadline: deadlineBigInt,
      swapDataHash: new Uint8Array(32), // MEDIUM-001: zero for CPMM/AMM
    });
    console.log("   ✅ ZK proof generated");

    // Build AMM swap data (USDC → SOL = swap_base_in with USDC as base)
    // For reverse swap, we need to check the pool direction
    // In SOL/USDC pool, SOL is base (coin) and USDC is quote (pc)
    // So swapping USDC → SOL is swap_base_out (0x0a) or we swap with reversed accounts
    // Actually for AMM V4, swap_base_in always uses the "in" token as base
    // We'll use swap_base_in with amount_in = USDC amount
    const minSolOut = new BN(minSolOutBigInt.toString());
    const swapData = buildAmmSwapData(new BN(swapAmount.toString()), minSolOut);

    // Swap params (reversed: USDC → SOL) - must match values in ZK proof
    const swapParams = {
      minAmountOut: minSolOut,
      deadline: new BN(deadlineBigInt.toString()),
      sourceMint: destTokenMint, // USDC
      destMint: sourceTokenMint, // SOL
      destAmount: new BN(expectedSol.toString()),
      swapDataHash: Buffer.alloc(32), // MEDIUM-001: zero for CPMM/AMM
    };

    // Derive executor PDA
    const [executorPda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("swap_executor"),
        destTokenMint.toBuffer(),
        sourceTokenMint.toBuffer(),
        Buffer.from(note.nullifier),
        payer.publicKey.toBuffer(),
      ],
      program.programId,
    );
    const executorSourceToken = await getAssociatedTokenAddress(
      destTokenMint,
      executorPda,
      true,
    );
    const executorDestToken = await getAssociatedTokenAddress(
      tokenMintFor(sourceTokenMint),
      executorPda,
      true,
    );

    // Nullifier markers (using USDC pool)
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      destTokenMint,
      0,
      note.nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      destTokenMint,
      0,
      dummyNullifier,
    );

    // Token accounts
    const sourceVaultUsdcAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      destTokenMint,
      destVault,
      true,
    );
    const destVaultSolAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      tokenMintFor(sourceTokenMint),
      sourceVault,
      true,
    );
    const relayerTokenAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      tokenMintFor(sourceTokenMint),
      payer.publicKey,
    );

    console.log("   Executor PDA:", executorPda.toBase58());

    // Create new lookup table for this transaction
    console.log("   Creating Address Lookup Table...");
    const recentSlot = await provider.connection.getSlot("finalized");

    const lookupTableAddresses = [
      destConfig,
      globalConfig,
      destVault,
      destNoteTree,
      destNullifiers,
      sourceVaultUsdcAccount.address,
      destTokenMint,
      sourceConfig,
      sourceVault,
      sourceNoteTree,
      destVaultSolAccount.address,
      tokenMintFor(sourceTokenMint),
      RAYDIUM_AMM_V4_PROGRAM,
      SERUM_PROGRAM,
      TOKEN_PROGRAM_ID,
      SystemProgram.programId,
      ASSOCIATED_TOKEN_PROGRAM_ID,
      AMM_POOL_STATE,
      AMM_AUTHORITY,
      AMM_OPEN_ORDERS,
      AMM_TARGET_ORDERS,
      AMM_BASE_VAULT,
      AMM_QUOTE_VAULT,
      SERUM_MARKET,
      SERUM_BIDS,
      SERUM_ASKS,
      SERUM_EVENT_QUEUE,
      SERUM_BASE_VAULT,
      SERUM_QUOTE_VAULT,
      serumVaultSigner,
    ];

    const [createLutIx, lookupTableAddress] =
      AddressLookupTableProgram.createLookupTable({
        authority: payer.publicKey,
        payer: payer.publicKey,
        recentSlot,
      });

    const extendLutIx = AddressLookupTableProgram.extendLookupTable({
      payer: payer.publicKey,
      authority: payer.publicKey,
      lookupTable: lookupTableAddress,
      addresses: lookupTableAddresses,
    });

    const createLutTx = new anchor.web3.Transaction()
      .add(createLutIx)
      .add(extendLutIx);
    await provider.sendAndConfirm(createLutTx);
    console.log(`   ALT created: ${lookupTableAddress.toBase58()}`);

    await new Promise((resolve) => setTimeout(resolve, 1000));

    const lookupTableAccount = await provider.connection.getAddressLookupTable(
      lookupTableAddress,
    );
    if (!lookupTableAccount.value)
      throw new Error("Failed to fetch lookup table");

    try {
      // For USDC → SOL swap, we reverse the vault order in remaining accounts
      // AMM expects: pool_coin_vault (SOL), pool_pc_vault (USDC)
      // When swapping USDC → SOL:
      // - Input: USDC (quote/pc)
      // - Output: SOL (base/coin)
      const swapIx = await (program.methods as any)
        .transactSwap(
          proof,
          Array.from(root),
          0,
          destTokenMint, // Source is USDC
          Array.from(note.nullifier),
          Array.from(dummyNullifier),
          0,
          sourceTokenMint, // Dest is SOL
          Array.from(changeCommitment), // output_commitment_0 → source pool (USDC change)
          Array.from(solOutputCommitment), // output_commitment_1 → dest pool (SOL)
          swapParams,
          new BN(swapAmount.toString()),
          swapData,
          extData,
        )
        .accounts({
          sourceConfig: destConfig, // USDC pool config
          globalConfig,
          sourceVault: destVault, // USDC vault
          sourceTree: destNoteTree,
          sourceNullifiers: destNullifiers,
          sourceNullifierMarker0: nullifierMarker0,
          sourceNullifierMarker1: nullifierMarker1,
          sourceVaultTokenAccount: sourceVaultUsdcAccount.address,
          sourceMintAccount: destTokenMint,
          destConfig: sourceConfig, // SOL pool config
          destVault: sourceVault, // SOL vault
          destTree: sourceNoteTree,
          destVaultTokenAccount: destVaultSolAccount.address,
          destMintAccount: tokenMintFor(sourceTokenMint),
          executor: executorPda,
          executorSourceToken,
          executorDestToken,
          relayer: payer.publicKey,
          relayerTokenAccount: relayerTokenAccount.address,
          swapProgram: RAYDIUM_AMM_V4_PROGRAM,
          jupiterEventAuthority: SystemProgram.programId,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
          associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
        })
        .remainingAccounts([
          { pubkey: AMM_POOL_STATE, isSigner: false, isWritable: true },
          { pubkey: AMM_AUTHORITY, isSigner: false, isWritable: false },
          { pubkey: AMM_OPEN_ORDERS, isSigner: false, isWritable: true },
          { pubkey: AMM_TARGET_ORDERS, isSigner: false, isWritable: true },
          // For USDC → SOL: still use same vault order, AMM handles direction
          { pubkey: AMM_BASE_VAULT, isSigner: false, isWritable: true },
          { pubkey: AMM_QUOTE_VAULT, isSigner: false, isWritable: true },
          { pubkey: SERUM_PROGRAM, isSigner: false, isWritable: false },
          { pubkey: SERUM_MARKET, isSigner: false, isWritable: true },
          { pubkey: SERUM_BIDS, isSigner: false, isWritable: true },
          { pubkey: SERUM_ASKS, isSigner: false, isWritable: true },
          { pubkey: SERUM_EVENT_QUEUE, isSigner: false, isWritable: true },
          { pubkey: SERUM_BASE_VAULT, isSigner: false, isWritable: true },
          { pubkey: SERUM_QUOTE_VAULT, isSigner: false, isWritable: true },
          { pubkey: serumVaultSigner, isSigner: false, isWritable: false },
        ])
        .instruction();

      // Build versioned transaction
      const computeBudgetIx = ComputeBudgetProgram.setComputeUnitLimit({
        units: 1_400_000,
      });
      const { blockhash, lastValidBlockHeight } =
        await provider.connection.getLatestBlockhash();

      const messageV0 = new TransactionMessage({
        payerKey: payer.publicKey,
        recentBlockhash: blockhash,
        instructions: [computeBudgetIx, swapIx],
      }).compileToV0Message([lookupTableAccount.value]);

      const versionedTx = new VersionedTransaction(messageV0);
      versionedTx.sign([payer]);

      const serialized = versionedTx.serialize();
      console.log(
        `   Transaction size: ${serialized.length} bytes (limit: 1232)`,
      );

      if (serialized.length > 1232) {
        throw new Error(
          `Transaction too large: ${serialized.length} > 1232 bytes`,
        );
      }

      const txSig = await provider.connection.sendTransaction(versionedTx, {
        skipPreflight: false,
      });
      await provider.connection.confirmTransaction({
        signature: txSig,
        blockhash,
        lastValidBlockHeight,
      });

      console.log(`✅ Reverse AMM V4 swap executed: ${txSig}`);

      // Verify balances changed
      const solVaultBalance = await provider.connection.getTokenAccountBalance(
        destVaultSolAccount.address,
      );
      console.log(
        `   SOL vault balance: ${solVaultBalance.value.uiAmountString} SOL`,
      );

      // Save the SOL note from reverse swap
      const solLeafIndex = sourceOffchainTree.insert(solOutputCommitment);
      solFromUsdcNoteId = noteStorage.save({
        amount: expectedSol,
        commitment: solOutputCommitment,
        nullifier: computeNullifier(
          poseidon,
          solOutputCommitment,
          solLeafIndex,
          solOutputPrivKey,
        ),
        blinding: solOutputBlinding,
        privateKey: solOutputPrivKey,
        publicKey: solOutputPubKey,
        leafIndex: solLeafIndex,
        merklePath: sourceOffchainTree.getMerkleProof(solLeafIndex),
        mintAddress: sourceTokenMint,
      });
      console.log(`   SOL note saved: ${solFromUsdcNoteId}`);
    } catch (e: any) {
      console.error("❌ Reverse AMM V4 swap failed:", e.message);
      if (e.logs) {
        console.error("Logs:", e.logs.slice(-20));
      }
      throw e;
    }
  });
});

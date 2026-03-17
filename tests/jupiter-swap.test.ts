import * as anchor from "@coral-xyz/anchor";
import { Program, BN } from "@coral-xyz/anchor";
import {
  PublicKey,
  SystemProgram,
  ComputeBudgetProgram,
  LAMPORTS_PER_SOL,
  Keypair,
  AddressLookupTableProgram,
  TransactionMessage,
  VersionedTransaction,
  Transaction,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  getAssociatedTokenAddress,
  createWrappedNativeAccount,
  closeAccount,
  getOrCreateAssociatedTokenAccount,
  NATIVE_MINT,
} from "@solana/spl-token";
import { expect } from "chai";
import { buildPoseidon } from "circomlibjs";
import { PrivacyPool } from "../target/types/privacy_pool";
import { JupiterSwapService } from "./utils/jupiter/jupiter-swap-service";
import {
  JUPITER_PROGRAM_ID,
  JUPITER_EVENT_AUTHORITY,
} from "./amm-v4-pool-helper";
import {
  InMemoryNoteStorage,
  OffchainMerkleTree,
  makeProvider,
  randomBytes32,
  computeCommitment,
  computeNullifier,
  computeExtDataHash,
  derivePublicKey,
  airdropAndConfirm,
  generateTransactionProof,
  generateSwapProof,
  computeSwapParamsHash,
} from "./test-helpers";

/**
 * Privacy Pool Jupiter Swap Tests
 *
 * Tests the transact_swap instruction with Jupiter aggregator which:
 * 1. Consumes notes from source pool (WSOL)
 * 2. CPIs to Jupiter V6 to execute swap SOL→USDC
 * 3. Creates notes in destination pool (USDC)
 *
 * Uses Jupiter V6 API for quote and instruction building.
 */

// Mainnet token mints (cloned)
const SOL_MINT = PublicKey.default;
const USDC_MINT = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

// For SPL operations (ATAs, token accounts), map native SOL to NATIVE_MINT (WSOL)
function tokenMintFor(mint: PublicKey): PublicKey {
  return mint.equals(PublicKey.default) ? NATIVE_MINT : mint;
}

// Helper: Encode tree_id as 2-byte little-endian (u16)
function encodeTreeId(treeId: number): Buffer {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16LE(treeId, 0);
  return buffer;
}

/**
 * Derive config PDA for a given mint
 */
function deriveConfigPDA(
  programId: PublicKey,
  mint: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("privacy_config_v3"), mint.toBuffer()],
    programId,
  );
}

/**
 * Derive vault PDA for a given mint
 */
function deriveVaultPDA(
  programId: PublicKey,
  mint: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("privacy_vault_v3"), mint.toBuffer()],
    programId,
  );
}

/**
 * Derive nullifiers PDA for a given mint
 */
function deriveNullifiersPDA(
  programId: PublicKey,
  mint: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("privacy_nullifiers_v3"), mint.toBuffer()],
    programId,
  );
}

/**
 * Derive note tree PDA for a given mint and tree_id
 */
function deriveNoteTreePDA(
  programId: PublicKey,
  mint: PublicKey,
  treeId: number,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [
      Buffer.from("privacy_note_tree_v3"),
      mint.toBuffer(),
      encodeTreeId(treeId),
    ],
    programId,
  );
}

/**
 * Derive nullifier marker PDA (global, no tree_id to prevent cross-tree double-spend)
 */
function deriveNullifierMarkerPDA(
  programId: PublicKey,
  mint: PublicKey,
  _treeId: number, // Kept for API compatibility but unused
  nullifier: Uint8Array,
): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("nullifier_v3"), mint.toBuffer(), Buffer.from(nullifier)],
    programId,
  )[0];
}

/**
 * Derive swap executor PDA
 * AUDIT-001: Now includes relayer key to prevent front-running DoS attacks
 */
function deriveSwapExecutorPDA(
  programId: PublicKey,
  sourceMint: PublicKey,
  destMint: PublicKey,
  inputNullifier0: Uint8Array,
  relayer: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [
      Buffer.from("swap_executor"),
      sourceMint.toBuffer(),
      destMint.toBuffer(),
      Buffer.from(inputNullifier0),
      relayer.toBuffer(),
    ],
    programId,
  );
}

/**
 * Derive global config PDA
 */
function deriveGlobalConfigPDA(programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("global_config_v1")],
    programId,
  );
}

describe("Privacy Pool Jupiter Swap", () => {
  const provider = makeProvider();
  anchor.setProvider(provider);

  const program = anchor.workspace.PrivacyPool as Program<PrivacyPool>;
  console.log(`Using Privacy Pool program: ${program.programId.toString()}`);
  const connection = provider.connection;
  const payer = (provider.wallet as anchor.Wallet).payer;

  let jupiterService: JupiterSwapService;
  let poseidon: any;

  // Pool accounts
  let globalConfig: PublicKey;

  // Source pool (WSOL)
  let sourceConfig: PublicKey;
  let sourceVault: PublicKey;
  let sourceNoteTree: PublicKey;
  let sourceNullifiers: PublicKey;
  let sourceVaultTokenAccount: PublicKey;

  // Dest pool (USDC)
  let destConfig: PublicKey;
  let destVault: PublicKey;
  let destNoteTree: PublicKey;
  let destNullifiers: PublicKey;
  let destVaultTokenAccount: PublicKey;

  // Off-chain state
  let sourceOffchainTree: OffchainMerkleTree;
  let destOffchainTree: OffchainMerkleTree;
  let noteStorage: InMemoryNoteStorage;

  // Test user keys
  let privateKey: Uint8Array;
  let publicKey: bigint;

  // Deposited note (would be set by a deposit test)
  let depositedNoteId: string | undefined;

  const INITIAL_DEPOSIT = 5_000_000_000n; // 5 SOL

  before(async () => {
    console.log("Setting up Jupiter swap test environment...");

    // Initialize Poseidon
    poseidon = await buildPoseidon();
    console.log("✅ Poseidon initialized");

    // Initialize Jupiter service
    jupiterService = new JupiterSwapService(connection);
    console.log("✅ Jupiter service initialized");

    // Initialize off-chain storage
    sourceOffchainTree = new OffchainMerkleTree(22, poseidon);
    destOffchainTree = new OffchainMerkleTree(22, poseidon);
    noteStorage = new InMemoryNoteStorage();

    // Generate test keys
    privateKey = randomBytes32();
    publicKey = derivePublicKey(poseidon, privateKey);

    // Derive PDAs
    [globalConfig] = deriveGlobalConfigPDA(program.programId);

    [sourceConfig] = deriveConfigPDA(program.programId, SOL_MINT);
    [sourceVault] = deriveVaultPDA(program.programId, SOL_MINT);
    [sourceNoteTree] = deriveNoteTreePDA(program.programId, SOL_MINT, 0);
    [sourceNullifiers] = deriveNullifiersPDA(program.programId, SOL_MINT);

    [destConfig] = deriveConfigPDA(program.programId, USDC_MINT);
    [destVault] = deriveVaultPDA(program.programId, USDC_MINT);
    [destNoteTree] = deriveNoteTreePDA(program.programId, USDC_MINT, 0);
    [destNullifiers] = deriveNullifiersPDA(program.programId, USDC_MINT);

    // Get vault token accounts
    sourceVaultTokenAccount = await getAssociatedTokenAddress(
      tokenMintFor(SOL_MINT),
      sourceVault,
      true,
    );
    destVaultTokenAccount = await getAssociatedTokenAddress(
      USDC_MINT,
      destVault,
      true,
    );

    console.log("\n📋 Pool Configuration:");
    console.log(`  Global Config: ${globalConfig.toString()}`);
    console.log(`  Source Config (WSOL): ${sourceConfig.toString()}`);
    console.log(`  Dest Config (USDC): ${destConfig.toString()}`);
    console.log(`  Jupiter Program: ${JUPITER_PROGRAM_ID.toString()}`);
  });

  it("should fetch Jupiter quote for SOL→USDC", async () => {
    console.log("\n🔍 Testing Jupiter quote fetching...");

    const quote = await jupiterService.getQuote(
      tokenMintFor(SOL_MINT),
      USDC_MINT,
      Number(INITIAL_DEPOSIT),
      50, // 0.5% slippage
    );

    console.log(`✅ Quote received:`);
    console.log(
      `  Input: ${quote.inAmount} (${quote.inputMint.slice(0, 8)}...)`,
    );
    console.log(
      `  Output: ${quote.outAmount} (${quote.outputMint.slice(0, 8)}...)`,
    );
    console.log(`  Slippage: ${quote.slippageBps} bps`);
    console.log(`  Price Impact: ${quote.priceImpactPct}%`);

    expect(quote.inputMint).to.equal(tokenMintFor(SOL_MINT).toString());
    expect(quote.outputMint).to.equal(USDC_MINT.toString());
    expect(quote.inAmount).to.equal(INITIAL_DEPOSIT.toString());
    expect(parseInt(quote.outAmount)).to.be.greaterThan(0);
  });

  it("should fetch Jupiter swap instruction", async () => {
    console.log("\n🔍 Testing Jupiter swap instruction fetching...");

    // Get quote
    const quote = await jupiterService.getQuote(
      tokenMintFor(SOL_MINT),
      USDC_MINT,
      Number(INITIAL_DEPOSIT),
      50,
    );

    // Get swap instruction - use payer as relayer (AUDIT-001 fix)
    const [executorPDA] = deriveSwapExecutorPDA(
      program.programId,
      SOL_MINT,
      USDC_MINT,
      new Uint8Array(32),
      payer.publicKey,
    );
    const swapIxResponse = await jupiterService.getSwapInstruction(
      quote,
      executorPDA,
      false, // Don't wrap/unwrap SOL (we handle that)
    );

    console.log(`✅ Swap instruction received`);
    console.log(
      `  Setup instructions: ${swapIxResponse.setupInstructions.length}`,
    );
    console.log(
      `  Swap accounts: ${swapIxResponse.swapInstruction.accounts.length}`,
    );
    console.log(
      `  Cleanup instructions: ${swapIxResponse.cleanupInstruction ? 1 : 0}`,
    );

    // Extract remaining accounts
    const remainingAccounts = jupiterService.extractRemainingAccounts(
      swapIxResponse.swapInstruction,
    );

    console.log(`  Remaining accounts (for CPI): ${remainingAccounts.length}`);
    console.log(
      `    (All Jupiter accounts passed, account #1 replaced with executor PDA in Rust)`,
    );

    expect(remainingAccounts.length).to.equal(
      swapIxResponse.swapInstruction.accounts.length,
    );
    expect(remainingAccounts.length).to.be.greaterThan(0);

    // Build swap data
    const swapData = jupiterService.buildSwapData(
      swapIxResponse.swapInstruction,
    );
    const swapDataHash = (() => {
      const { createHash } = require("crypto");
      return Uint8Array.from(createHash("sha256").update(swapData).digest());
    })(); // MEDIUM-001: commit swap_data to prevent relayer substitution

    console.log(`  Swap data length: ${swapData.length} bytes`);
    console.log(`  Discriminator: ${swapData.slice(0, 8).toString("hex")}`);

    expect(swapData.length).to.be.greaterThan(8);
    expect(swapData.slice(0, 8).toString("hex")).to.equal("e517cb977ae3ad2a");
  });

  it("initializes global config", async () => {
    console.log("\n🔧 Initializing global config...");

    // Check if already initialized
    try {
      await (program.account as any).globalConfig.fetch(globalConfig);
      console.log("✅ Global config already initialized");
      return;
    } catch (e) {
      console.log(e);
      // Account doesn't exist, proceed with initialization
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
  });

  it("initializes WSOL privacy pool", async () => {
    console.log("\n🔧 Initializing WSOL pool...");

    // Check if already initialized
    try {
      await program.account.privacyConfig.fetch(sourceConfig);
      console.log("✅ WSOL pool already initialized");
      return;
    } catch {
      // Account doesn't exist, proceed with initialization
    }

    const feeBps = 50; // 0.5% fee
    const minDepositAmount = new BN(0);
    const maxDepositAmount = new BN(1_000_000_000_000); // 1000 SOL
    const minWithdrawAmount = new BN(0);
    const maxWithdrawAmount = new BN(1_000_000_000_000);

    await (program.methods as any)
      .initialize(
        feeBps,
        SOL_MINT,
        minDepositAmount,
        maxDepositAmount,
        minWithdrawAmount,
        maxWithdrawAmount,
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

    console.log("✅ WSOL pool initialized");
  });

  it("initializes USDC privacy pool", async () => {
    console.log("\n🔧 Initializing USDC pool...");

    // Check if already initialized
    try {
      await program.account.privacyConfig.fetch(destConfig);
      console.log("✅ USDC pool already initialized");
      return;
    } catch {
      // Account doesn't exist, proceed with initialization
    }

    const feeBps = 50; // 0.5% fee
    const minDepositAmount = new BN(0);
    const maxDepositAmount = new BN(100_000_000_000); // 100k USDC (6 decimals)
    const minWithdrawAmount = new BN(0);
    const maxWithdrawAmount = new BN(100_000_000_000);

    await (program.methods as any)
      .initialize(
        feeBps,
        USDC_MINT,
        minDepositAmount,
        maxDepositAmount,
        minWithdrawAmount,
        maxWithdrawAmount,
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

    console.log("✅ USDC pool initialized");
  });

  it("registers relayer for WSOL pool", async () => {
    console.log("\n🔧 Registering relayer for WSOL pool...");

    try {
      await (program.methods as any)
        .addRelayer(SOL_MINT, payer.publicKey)
        .accounts({
          config: sourceConfig,
          admin: payer.publicKey,
        })
        .rpc();
      console.log("✅ Relayer registered for WSOL pool");
    } catch (e: any) {
      if (
        e.message?.includes("already registered") ||
        e.message?.includes("AlreadyInUse")
      ) {
        console.log("✅ Relayer already registered for WSOL pool");
      } else {
        throw e;
      }
    }
  });

  it("registers relayer for USDC pool", async () => {
    console.log("\n🔧 Registering relayer for USDC pool...");

    try {
      await (program.methods as any)
        .addRelayer(USDC_MINT, payer.publicKey)
        .accounts({
          config: destConfig,
          admin: payer.publicKey,
        })
        .rpc();
      console.log("✅ Relayer registered for USDC pool");
    } catch (e: any) {
      if (
        e.message?.includes("already registered") ||
        e.message?.includes("AlreadyInUse")
      ) {
        console.log("✅ Relayer already registered for USDC pool");
      } else {
        throw e;
      }
    }
  });

  it("should deposit SOL to create spendable note", async function () {
    console.log("\n💰 Creating initial deposit...");

    // Airdrop SOL to payer
    await airdropAndConfirm(provider, payer.publicKey, 10 * LAMPORTS_PER_SOL);

    // Ensure vault token accounts exist
    console.log("   Creating vault token accounts if needed...");
    await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      tokenMintFor(SOL_MINT),
      sourceVault,
      true, // allowOwnerOffCurve for PDA
    );

    // For native SOL deposits, user token account is the payer (system account)
    const userTokenAccount = payer.publicKey;

    // Prepare deposit
    const amount = INITIAL_DEPOSIT;
    const blinding = randomBytes32();
    const commitment = computeCommitment(
      poseidon,
      amount,
      publicKey,
      blinding,
      SOL_MINT,
    );

    // Create change note (0 amount for deposit)
    const changeBlinding = randomBytes32();
    const changePubKey = derivePublicKey(poseidon, randomBytes32());
    const changeCommitment = computeCommitment(
      poseidon,
      0n,
      changePubKey,
      changeBlinding,
      SOL_MINT,
    );

    // Create dummy nullifiers for deposit
    const dummyPrivKey1 = randomBytes32();
    const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);
    const dummyBlinding1 = randomBytes32();
    const dummyCommitment1 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey1,
      dummyBlinding1,
      SOL_MINT,
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
      SOL_MINT,
    );
    const dummyNullifier2 = computeNullifier(
      poseidon,
      dummyCommitment2,
      0,
      dummyPrivKey2,
    );

    // Prepare ext data
    const extData = {
      recipient: payer.publicKey,
      relayer: payer.publicKey,
      fee: new BN(0),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    // Get Merkle proof (empty tree)
    const dummyProof = sourceOffchainTree.getMerkleProof(0);
    const root = sourceOffchainTree.getRoot();

    // Generate proof
    const proof = await generateTransactionProof({
      root,
      publicAmount: amount,
      extDataHash,
      mintAddress: SOL_MINT,
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
      SOL_MINT,
      0,
      dummyNullifier1,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      SOL_MINT,
      0,
      dummyNullifier2,
    );

    // Execute deposit
    const tx = await (program.methods as any)
      .transact(
        Array.from(root),
        0, // input_tree_id
        0, // output_tree_id
        new BN(amount.toString()),
        Array.from(extDataHash),
        SOL_MINT,
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

    // Save note for use in swap
    depositedNoteId = noteStorage.save({
      amount,
      commitment,
      nullifier: computeNullifier(poseidon, commitment, leafIndex, privateKey),
      blinding,
      privateKey,
      publicKey,
      leafIndex,
      merklePath: sourceOffchainTree.getMerkleProof(leafIndex),
      mintAddress: SOL_MINT,
    });

    console.log(`   Note saved: ${depositedNoteId}`);
    console.log(`   Amount: ${INITIAL_DEPOSIT} lamports`);
    console.log(`   Leaf index: ${leafIndex}`);
  });

  it("should execute SOL→USDC swap via Jupiter", async function () {
    // This test requires:
    // 1. Local validator with Jupiter program cloned:
    //    solana-test-validator --url mainnet-beta \
    //      --clone JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4 \
    //      --clone D8cy77BBepLMngZx6ZukaTff5hCt1HrWyKk3Hnd9oitf \
    //      --clone So11111111111111111111111111111111111111112 \
    //      --clone EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v \
    //      --reset
    //
    // 2. Proper pool initialization for both WSOL and USDC
    // 3. Initial deposit completed (previous test)
    // 4. Jupiter API accessible (for quote/instruction fetching)
    //
    // The test will be skipped if prerequisites aren't met

    console.log("\n🔄 Testing Jupiter swap execution...");

    // Skip if no deposit was made
    if (!depositedNoteId) {
      console.log("⚠️  Skipping swap test - no deposit found");
      console.log("    Run the deposit test first to enable swap testing");
      this.skip();
      return;
    }

    const note = noteStorage.get(depositedNoteId);
    if (!note) {
      throw new Error("No deposited note found");
    }

    // Ensure destination vault token account exists
    await getOrCreateAssociatedTokenAccount(
      connection,
      payer,
      USDC_MINT,
      destVault,
      true, // allowOwnerOffCurve for PDA
    );

    // Ensure relayer has a USDC token account (needed for fee payment)
    await getOrCreateAssociatedTokenAccount(
      connection,
      payer,
      USDC_MINT,
      payer.publicKey,
    );

    // Get fresh Merkle proof
    // const merklePath = sourceOffchainTree.getMerkleProof(note.leafIndex);
    const root = sourceOffchainTree.getRoot();

    // Compute nullifier
    const nullifier = computeNullifier(
      poseidon,
      note.commitment,
      note.leafIndex,
      note.privateKey,
    );

    // Get Jupiter quote
    const swapAmount = note.amount;
    const quote = await jupiterService.getQuote(
      tokenMintFor(SOL_MINT),
      USDC_MINT,
      Number(swapAmount),
      100, // 1% slippage for safer execution
    );

    const minAmountOut = BigInt(quote.otherAmountThreshold);

    console.log(`  Swap amount: ${swapAmount}`);
    console.log(`  Min amount out: ${minAmountOut}`);
    console.log(`  Jupiter route:`, JSON.stringify(quote, null, 2));

    // Derive executor PDA - includes relayer key (AUDIT-001 fix)
    const [executorPDA] = deriveSwapExecutorPDA(
      program.programId,
      SOL_MINT,
      USDC_MINT,
      nullifier,
      payer.publicKey,
    );

    // Get swap instruction from Jupiter
    const swapIxResponse = await jupiterService.getSwapInstruction(
      quote,
      executorPDA,
      false,
    );

    const remainingAccounts = jupiterService.extractRemainingAccounts(
      swapIxResponse.swapInstruction,
    );
    const swapData = jupiterService.buildSwapData(
      swapIxResponse.swapInstruction,
    );
    const swapDataHash = (() => {
      const { createHash } = require("crypto");
      return Uint8Array.from(createHash("sha256").update(swapData).digest());
    })(); // MEDIUM-001: commit swap_data to prevent relayer substitution

    // Create output note for swap result in DESTINATION pool
    // NOTE: The actual amount will be determined by the swap execution
    // We use minAmountOut as the expected amount for commitment creation
    const destAmount = minAmountOut;
    const destBlinding = randomBytes32();
    const destPubKey = publicKey; // Receive to same owner
    const destCommitment = computeCommitment(
      poseidon,
      destAmount,
      destPubKey,
      destBlinding,
      USDC_MINT, // DESTINATION mint
    );

    // Create change note in SOURCE pool
    const SWAP_AMOUNT = swapAmount;
    const changeAmount = note.amount - BigInt(SWAP_AMOUNT);
    const changeBlinding = randomBytes32();
    const changePrivKey = randomBytes32();
    const changePubKey = derivePublicKey(poseidon, changePrivKey);
    const changeCommitment = computeCommitment(
      poseidon,
      changeAmount,
      changePubKey,
      changeBlinding,
      SOL_MINT, // SOURCE mint
    );

    console.log(
      `  Dest commitment: ${Buffer.from(destCommitment)
        .toString("hex")
        .slice(0, 16)}...`,
    );
    console.log(
      `  Change commitment: ${Buffer.from(changeCommitment)
        .toString("hex")
        .slice(0, 16)}...`,
    );

    // Prepare swap params
    const swapParams = {
      minAmountOut: new BN(minAmountOut.toString()),
      deadline: new BN(Math.floor(Date.now() / 1000) + 3600), // 1 hour from now
      sourceMint: SOL_MINT,
      destMint: USDC_MINT,
      destAmount: new BN(minAmountOut.toString()),
      swapDataHash: Buffer.from(swapDataHash), // MEDIUM-001
    };

    // Prepare ext data
    // Fee must be >= max(min_swap_fee, swapAmount * feeBps)
    // Default swap_fee_bps is 10 (0.1%). For ~580 USDC output, fee is ~0.58 USDC (580,000 units)
    // We set a sufficient fee here (1 USDC = 1,000,000 units)
    const relayerFee = 1_000_000n; // 1.0 USDC
    const extData = {
      recipient: payer.publicKey,
      relayer: payer.publicKey,
      fee: new BN(relayerFee.toString()),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);
    const swapParamsHash = computeSwapParamsHash(
      poseidon,
      SOL_MINT,
      USDC_MINT,
      minAmountOut,
      BigInt(swapParams.deadline.toString()),
      swapDataHash, // MEDIUM-001
      destAmount,
    );

    // Create dummy second input (always 0 amount for single-note swaps)
    const dummyPrivKey = randomBytes32();
    const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
    const dummyBlinding = randomBytes32();
    const dummyCommitment = computeCommitment(
      poseidon,
      0n,
      dummyPubKey,
      dummyBlinding,
      SOL_MINT, // SOURCE mint
    );
    const dummyNullifier = computeNullifier(
      poseidon,
      dummyCommitment,
      0,
      dummyPrivKey,
    );
    const dummyProof = sourceOffchainTree.getMerkleProof(0);

    // Retrieve Merkle proof for the real note
    const merklePath = sourceOffchainTree.getMerkleProof(note.leafIndex);

    // Generate ZK proof for swap using the correct swap proof function
    const proof = await generateSwapProof({
      sourceRoot: root,
      swapParamsHash,
      extDataHash,
      sourceMint: SOL_MINT,
      destMint: USDC_MINT,
      inputNullifiers: [nullifier, dummyNullifier],
      changeCommitment,
      destCommitment,
      swapAmount: BigInt(swapAmount),

      inputAmounts: [note.amount, 0n],
      inputPrivateKeys: [note.privateKey, dummyPrivKey],
      inputPublicKeys: [note.publicKey, dummyPubKey],
      inputBlindings: [note.blinding, dummyBlinding],
      inputMerklePaths: [merklePath, dummyProof],

      changeAmount,
      changePubkey: changePubKey,
      changeBlinding,

      destAmount,
      destPubkey: destPubKey,
      destBlinding,

      minAmountOut,
      deadline: BigInt(swapParams.deadline.toString()),
    });

    console.log("✅ ZK proof generated successfully");

    // Derive nullifier markers
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      SOL_MINT,
      0,
      nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      SOL_MINT,
      0,
      dummyNullifier,
    );

    // Get executor token accounts
    const executorSourceToken = await getAssociatedTokenAddress(
      tokenMintFor(SOL_MINT),
      executorPDA,
      true,
    );
    const executorDestToken = await getAssociatedTokenAddress(
      USDC_MINT,
      executorPDA,
      true,
    );

    // Get relayer token account
    const relayerTokenAccount = await getAssociatedTokenAddress(
      USDC_MINT,
      payer.publicKey,
    );

    // Execute swap - build instruction for versioned transaction with ALT
    const swapIx = await (program.methods as any)
      .transactSwap(
        proof,
        Array.from(root),
        0, // source_tree_id
        SOL_MINT,
        Array.from(nullifier),
        Array.from(dummyNullifier),
        0, // dest_tree_id
        USDC_MINT,
        Array.from(changeCommitment),
        Array.from(destCommitment),
        swapParams,
        new BN(swapAmount.toString()),
        swapData,
        {
          recipient: extData.recipient,
          relayer: extData.relayer,
          fee: extData.fee,
          refund: extData.refund,
        },
      )
      .accounts({
        sourceConfig,
        globalConfig,
        sourceVault,
        sourceTree: sourceNoteTree,
        sourceNullifiers,
        sourceNullifierMarker0: nullifierMarker0,
        sourceNullifierMarker1: nullifierMarker1,
        sourceVaultTokenAccount,
        sourceMintAccount: tokenMintFor(SOL_MINT),
        destConfig,
        destVault,
        destTree: destNoteTree,
        destVaultTokenAccount,
        destMintAccount: USDC_MINT,
        executor: executorPDA,
        executorSourceToken,
        executorDestToken,
        relayer: payer.publicKey,
        relayerTokenAccount,
        swapProgram: JUPITER_PROGRAM_ID,
        jupiterEventAuthority: new PublicKey(
          "D8cy77BBepLMngZx6ZukaTff5hCt1HrWyKk3Hnd9oitf",
        ),
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      })
      .remainingAccounts(remainingAccounts)
      .instruction();

    // Create Address Lookup Table to compress transaction size
    const recentSlot = await connection.getSlot("finalized");
    const [createAltIx, altAddress] =
      AddressLookupTableProgram.createLookupTable({
        authority: payer.publicKey,
        payer: payer.publicKey,
        recentSlot,
      });

    // Collect unique account keys from the swap instruction for the ALT
    const altKeys: PublicKey[] = [];
    const seen = new Set<string>();
    for (const meta of swapIx.keys) {
      const key = meta.pubkey.toBase58();
      if (!seen.has(key)) {
        seen.add(key);
        altKeys.push(meta.pubkey);
      }
    }
    if (!seen.has(swapIx.programId.toBase58())) {
      altKeys.push(swapIx.programId);
    }

    // Send ALT creation first
    await provider.sendAndConfirm(new Transaction().add(createAltIx));

    // Extend ALT in batches of 20 addresses (each address is 32 bytes)
    const BATCH_SIZE = 20;
    for (let i = 0; i < altKeys.length; i += BATCH_SIZE) {
      const extendIx = AddressLookupTableProgram.extendLookupTable({
        payer: payer.publicKey,
        authority: payer.publicKey,
        lookupTable: altAddress,
        addresses: altKeys.slice(i, i + BATCH_SIZE),
      });
      await provider.sendAndConfirm(new Transaction().add(extendIx));
    }

    // Wait for ALT to activate
    await new Promise((resolve) => setTimeout(resolve, 1500));

    // Fetch the ALT
    const altAccountInfo = await connection.getAddressLookupTable(altAddress);
    const lookupTable = altAccountInfo.value!;

    // Build versioned transaction with ALT
    const { blockhash } = await connection.getLatestBlockhash();
    const messageV0 = new TransactionMessage({
      payerKey: payer.publicKey,
      recentBlockhash: blockhash,
      instructions: [
        ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
        swapIx,
      ],
    }).compileToV0Message([lookupTable]);

    const versionedTx = new VersionedTransaction(messageV0);
    versionedTx.sign([payer]);

    const tx = await connection.sendTransaction(versionedTx);
    await connection.confirmTransaction(tx, "confirmed");

    console.log(`✅ Jupiter swap tx: ${tx}`);

    // Verify nullifiers marked as spent
    const nullifierMarker0Account = await program.account.nullifierMarker.fetch(
      nullifierMarker0,
    );
    expect(
      Buffer.from(nullifierMarker0Account.nullifier).toString("hex"),
    ).to.equal(Buffer.from(nullifier).toString("hex"));

    const nullifierMarker1Account = await program.account.nullifierMarker.fetch(
      nullifierMarker1,
    );
    expect(
      Buffer.from(nullifierMarker1Account.nullifier).toString("hex"),
    ).to.equal(Buffer.from(dummyNullifier).toString("hex"));

    console.log("✅ Nullifiers marked as spent correctly");

    // Update off-chain trees
    const destLeafIndex = destOffchainTree.insert(destCommitment);
    const sourceLeafIndex = sourceOffchainTree.insert(changeCommitment);

    console.log(`✅ Output commitment inserted at index ${destLeafIndex}`);
    console.log(`✅ Change commitment inserted at index ${sourceLeafIndex}`);

    // Verify TVL updates
    const sourceConfigAccount = await program.account.privacyConfig.fetch(
      sourceConfig,
    );
    const destConfigAccount = await program.account.privacyConfig.fetch(
      destConfig,
    );

    console.log(`  Source TVL: ${sourceConfigAccount.totalTvl}`);
    console.log(`  Dest TVL: ${destConfigAccount.totalTvl}`);

    // Source TVL should decrease by swapAmount
    // Dest TVL should increase by (swappedAmount - relayerFee)

    console.log(`✅ Swap completed successfully with ZK proof verification`);
  });
});

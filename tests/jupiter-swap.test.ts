import * as anchor from "@coral-xyz/anchor";
import { Program, BN } from "@coral-xyz/anchor";
import {
  PublicKey,
  Keypair,
  SystemProgram,
  LAMPORTS_PER_SOL,
  ComputeBudgetProgram,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  getAssociatedTokenAddress,
  NATIVE_MINT,
  createWrappedNativeAccount,
  closeAccount,
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
  DepositNote,
  InMemoryNoteStorage,
  OffchainMerkleTree,
  makeProvider,
  airdropAndConfirm,
  randomBytes32,
  createAndFundTokenAccount,
  createDummyNote,
  extractRootFromAccount,
  computeCommitment,
  computeNullifier,
  computeExtDataHash,
  derivePublicKey,
  bytesToBigIntBE,
  generateTransactionProof,
  reduceToField,
} from "./test-helpers";
import { generateSwapProof } from "./swap-test-helpers";

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
const WSOL_MINT = new PublicKey("So11111111111111111111111111111111111111112");
const USDC_MINT = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

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
 * Derive nullifier marker PDA
 */
function deriveNullifierMarkerPDA(
  programId: PublicKey,
  mint: PublicKey,
  treeId: number,
  nullifier: Uint8Array,
): PublicKey {
  return PublicKey.findProgramAddressSync(
    [
      Buffer.from("nullifier_v3"),
      mint.toBuffer(),
      encodeTreeId(treeId),
      Buffer.from(nullifier),
    ],
    programId,
  )[0];
}

/**
 * Derive swap executor PDA
 */
function deriveSwapExecutorPDA(
  programId: PublicKey,
  nullifier: Uint8Array,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("swap_executor"), Buffer.from(nullifier)],
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
  let publicKey: Uint8Array;

  // Deposited note
  let depositedNoteId: string;

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
    sourceOffchainTree = new OffchainMerkleTree(20, poseidon);
    destOffchainTree = new OffchainMerkleTree(20, poseidon);
    noteStorage = new InMemoryNoteStorage();

    // Generate test keys
    privateKey = randomBytes32();
    publicKey = derivePublicKey(poseidon, privateKey);

    // Derive PDAs
    [globalConfig] = deriveGlobalConfigPDA(program.programId);

    [sourceConfig] = deriveConfigPDA(program.programId, WSOL_MINT);
    [sourceVault] = deriveVaultPDA(program.programId, WSOL_MINT);
    [sourceNoteTree] = deriveNoteTreePDA(program.programId, WSOL_MINT, 0);
    [sourceNullifiers] = deriveNullifiersPDA(program.programId, WSOL_MINT);

    [destConfig] = deriveConfigPDA(program.programId, USDC_MINT);
    [destVault] = deriveVaultPDA(program.programId, USDC_MINT);
    [destNoteTree] = deriveNoteTreePDA(program.programId, USDC_MINT, 0);
    [destNullifiers] = deriveNullifiersPDA(program.programId, USDC_MINT);

    // Get vault token accounts
    sourceVaultTokenAccount = await getAssociatedTokenAddress(
      WSOL_MINT,
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
    console.log(
      `  Jupiter Program: ${JUPITER_PROGRAM_ID.toString()}`,
    );
  });

  it("should fetch Jupiter quote for SOL→USDC", async () => {
    console.log("\n🔍 Testing Jupiter quote fetching...");

    const quote = await jupiterService.getQuote(
      WSOL_MINT,
      USDC_MINT,
      Number(INITIAL_DEPOSIT),
      50, // 0.5% slippage
    );

    console.log(`✅ Quote received:`);
    console.log(`  Input: ${quote.inAmount} (${quote.inputMint.slice(0, 8)}...)`);
    console.log(`  Output: ${quote.outAmount} (${quote.outputMint.slice(0, 8)}...)`);
    console.log(`  Slippage: ${quote.slippageBps} bps`);
    console.log(`  Price Impact: ${quote.priceImpactPct}%`);

    expect(quote.inputMint).to.equal(WSOL_MINT.toString());
    expect(quote.outputMint).to.equal(USDC_MINT.toString());
    expect(quote.inAmount).to.equal(INITIAL_DEPOSIT.toString());
    expect(parseInt(quote.outAmount)).to.be.greaterThan(0);
  });

  it("should fetch Jupiter swap instruction", async () => {
    console.log("\n🔍 Testing Jupiter swap instruction fetching...");

    // Get quote
    const quote = await jupiterService.getQuote(
      WSOL_MINT,
      USDC_MINT,
      Number(INITIAL_DEPOSIT),
      50,
    );

    // Get swap instruction
    const [executorPDA] = deriveSwapExecutorPDA(
      program.programId,
      new Uint8Array(32),
    );
    const swapIxResponse = await jupiterService.getSwapInstruction(
      quote,
      executorPDA,
      false, // Don't wrap/unwrap SOL (we handle that)
    );

    console.log(`✅ Swap instruction received`);
    console.log(`  Setup instructions: ${swapIxResponse.setupInstructions.length}`);
    console.log(`  Swap accounts: ${swapIxResponse.swapInstruction.accounts.length}`);
    console.log(`  Cleanup instructions: ${swapIxResponse.cleanupInstruction ? 1 : 0}`);

    // Extract remaining accounts
    const remainingAccounts = jupiterService.extractRemainingAccounts(
      swapIxResponse.swapInstruction,
    );

    console.log(`  Remaining accounts (for CPI): ${remainingAccounts.length}`);
    console.log(`    Event Authority: ${remainingAccounts[0].pubkey.toString()}`);

    expect(remainingAccounts.length).to.be.greaterThan(0);
    expect(remainingAccounts[0].pubkey.toString()).to.equal(
      JUPITER_EVENT_AUTHORITY.toString(),
    );

    // Build swap data
    const swapData = jupiterService.buildSwapData(
      swapIxResponse.swapInstruction,
    );

    console.log(`  Swap data length: ${swapData.length} bytes`);
    console.log(`  Discriminator: ${swapData.slice(0, 8).toString("hex")}`);

    expect(swapData.length).to.be.greaterThan(8);
    expect(swapData.slice(0, 8).toString("hex")).to.equal("e517cb977ae3ad2a");
  });

  it.skip("should execute SOL→USDC swap via Jupiter", async () => {
    // This test is skipped because it requires:
    // 1. Local validator with Jupiter program cloned
    // 2. Proper pool initialization for both WSOL and USDC
    // 3. Initial deposit transaction to create notes
    // 4. Complex setup for executor PDA and token accounts
    //
    // To enable this test:
    // 1. Start validator with: solana-test-validator --clone JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4
    // 2. Initialize pools (see pool initialization tests)
    // 3. Make a deposit to create spendable notes
    // 4. Remove .skip from this test

    console.log("\n🔄 Testing Jupiter swap execution...");

    // Get deposited note
    const note = noteStorage.get(depositedNoteId);
    if (!note) {
      throw new Error("No deposited note found");
    }

    // Get fresh Merkle proof
    const merklePath = sourceOffchainTree.getMerkleProof(note.leafIndex);
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
      WSOL_MINT,
      USDC_MINT,
      Number(swapAmount),
      100, // 1% slippage for safer execution
    );

    const minAmountOut = BigInt(quote.otherAmountThreshold);

    console.log(`  Swap amount: ${swapAmount}`);
    console.log(`  Min amount out: ${minAmountOut}`);

    // Derive executor PDA
    const [executorPDA] = deriveSwapExecutorPDA(
      program.programId,
      nullifier,
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

    // Create output notes
    const outputAmount = minAmountOut;
    const outputBlinding = randomBytes32();
    const outputCommitment = computeCommitment(
      poseidon,
      outputAmount,
      publicKey,
      outputBlinding,
    );

    // Create change note (0 amount - no change expected)
    const changeBlinding = randomBytes32();
    const changePubKey = derivePublicKey(poseidon, randomBytes32());
    const changeCommitment = computeCommitment(
      poseidon,
      0n,
      changePubKey,
      changeBlinding,
    );

    // Prepare swap params
    const swapParams = {
      minAmountOut: new BN(minAmountOut.toString()),
      deadline: new BN(Math.floor(Date.now() / 1000) + 3600), // 1 hour from now
      sourceMint: WSOL_MINT,
      destMint: USDC_MINT,
    };

    // Prepare ext data
    const relayerFee = 100_000n; // 0.1 USDC
    const extData = {
      recipient: payer.publicKey,
      relayer: payer.publicKey,
      fee: new BN(relayerFee.toString()),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    // Generate ZK proof
    const proof = await generateSwapProof({
      sourceRoot: root,
      swapParams,
      extDataHash,
      sourceMint: WSOL_MINT,
      destMint: USDC_MINT,
      inputNullifiers: [nullifier, new Uint8Array(32)], // Second input is dummy
      outputCommitments: [outputCommitment, changeCommitment],
      swapAmount,
      inputAmounts: [note.amount, 0n],
      inputPrivateKeys: [note.privateKey, randomBytes32()],
      inputPublicKeys: [note.publicKey, derivePublicKey(poseidon, randomBytes32())],
      inputBlindings: [note.blinding, randomBytes32()],
      inputMerklePaths: [merklePath, sourceOffchainTree.getMerkleProof(0)],
      outputAmounts: [outputAmount, 0n],
      outputOwners: [publicKey, changePubKey],
      outputBlindings: [outputBlinding, changeBlinding],
    });

    // Derive nullifier markers
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      WSOL_MINT,
      0,
      nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      WSOL_MINT,
      0,
      new Uint8Array(32),
    );

    // Get executor token accounts
    const executorSourceToken = await getAssociatedTokenAddress(
      WSOL_MINT,
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

    // Execute swap
    const tx = await (program.methods as any)
      .transactSwap(
        proof,
        Array.from(root),
        0, // source_tree_id
        WSOL_MINT,
        Array.from(nullifier),
        Array.from(new Uint8Array(32)),
        0, // dest_tree_id
        USDC_MINT,
        Array.from(outputCommitment),
        Array.from(changeCommitment),
        swapParams,
        new BN(swapAmount.toString()),
        Array.from(swapData),
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
        sourceMintAccount: WSOL_MINT,
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
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      })
      .remainingAccounts(remainingAccounts)
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
      ])
      .rpc();

    console.log(`✅ Jupiter swap tx: ${tx}`);

    // Update off-chain trees
    destOffchainTree.insert(outputCommitment);
    sourceOffchainTree.insert(changeCommitment);

    console.log(`✅ Swap completed successfully`);
  });
});

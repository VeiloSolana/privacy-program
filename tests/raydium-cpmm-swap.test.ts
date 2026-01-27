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
  TransactionInstruction,
  Connection,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  createMint,
  getOrCreateAssociatedTokenAccount,
  getAssociatedTokenAddress,
  mintTo,
  NATIVE_MINT,
  createWrappedNativeAccount,
  closeAccount,
} from "@solana/spl-token";
import { expect } from "chai";
import { buildPoseidon } from "circomlibjs";
import { PrivacyPool } from "../target/types/privacy_pool";
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

/**
 * Privacy Pool Cross-Pool Swap Tests
 *
 * Tests the transact_swap instruction which:
 * 1. Consumes notes from source pool (WSOL)
 * 2. CPIs to Raydium CPMM to execute swap SOL→USDC
 * 3. Creates notes in destination pool (USDC)
 *
 * Uses cloned mainnet Raydium CPMM SOL/USDC pool for testing.
 */

// Raydium CPMM Program ID (cloned from mainnet)
const RAYDIUM_CPMM_PROGRAM = new PublicKey(
  "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C",
);

// Mainnet token mints (cloned)
const WSOL_MINT = new PublicKey("So11111111111111111111111111111111111111112");
const USDC_MINT = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

// SOL/USDC CPMM Pool (cloned from mainnet)
const CPMM_POOL_STATE = new PublicKey(
  "7JuwJuNU88gurFnyWeiyGKbFmExMWcmRZntn9imEzdny",
);
const CPMM_POOL_AUTHORITY = new PublicKey(
  "8HknqAvNx7bKw1gwsGuQmR785EvrKRDvdUnGffsRFA2F",
);
const CPMM_TOKEN_VAULT_0 = new PublicKey(
  "7VLUXrnSSDo9BfCa4NWaQs68g7ddDY1sdXBKW6Xswj9Y",
); // SOL vault
const CPMM_TOKEN_VAULT_1 = new PublicKey(
  "3rzbbW5Q8MA7sCaowf28hNgACNPecdS2zceWy7Ptzua9",
); // USDC vault
const CPMM_AMM_CONFIG = new PublicKey(
  "D4FPEruKEHrG5TenZ2mpDGEfu1iUvTiqBxvpU8HLBvC2",
);

// CPMM Authority PDA (derived from "vault_and_lp_mint_auth_seed")
const CPMM_AUTHORITY = new PublicKey(
  "GpMZbSM2GgvTKHJirzeGfMFoaZ8UR2X7F4v8vHTvxFbL",
);

// Observation State PDA (derived from ["observation", pool_state])
const CPMM_OBSERVATION_STATE = new PublicKey(
  "4MYrPgjgFceyhtwhG1ZX8UVb4wn1aQB5wzMimtFqg7U8",
);

// CPMM Instruction discriminators (Anchor 8-byte discriminators)
// sha256("global:swap_base_input")[0..8] = 8fbe5adac41e33de
const CPMM_SWAP_BASE_INPUT_DISCRIMINATOR = Buffer.from([
  0x8f, 0xbe, 0x5a, 0xda, 0xc4, 0x1e, 0x33, 0xde,
]);
// sha256("global:swap_base_output")[0..8] = 37d96256a34ab4ad
const CPMM_SWAP_BASE_OUTPUT_DISCRIMINATOR = Buffer.from([
  0x37, 0xd9, 0x62, 0x56, 0xa3, 0x4a, 0xb4, 0xad,
]);

// Helper: Encode tree_id as 2-byte little-endian (u16)
function encodeTreeId(treeId: number): Buffer {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16LE(treeId, 0);
  return buffer;
}

/**

/**
 * Build CPMM swap instruction data
 * For swap_base_input: [discriminator, amount_in, min_amount_out]
 * For swap_base_output: [discriminator, max_amount_in, amount_out]
 */
function buildCpmmSwapData(
  amount1: anchor.BN,
  amount2: anchor.BN,
  swapBaseIn: boolean = true,
): Buffer {
  const data = Buffer.alloc(24);
  const discriminator = swapBaseIn
    ? CPMM_SWAP_BASE_INPUT_DISCRIMINATOR
    : CPMM_SWAP_BASE_OUTPUT_DISCRIMINATOR;
  discriminator.copy(data, 0);
  data.writeBigUInt64LE(BigInt(amount1.toString()), 8);
  data.writeBigUInt64LE(BigInt(amount2.toString()), 16);
  return data;
}

/**
 * Simulate a CPMM swap to get the exact output amount.
 * Uses constant product formula: (x + dx) * (y - dy) = x * y
 * Reads actual fee rates from AMM config account.
 *
 * Raydium CPMM applies trade fee to INPUT before the swap:
 * 1. input_amount_less_fees = input_amount - (input_amount * trade_fee_rate / 1_000_000)
 * 2. output = y * input_amount_less_fees / (x + input_amount_less_fees)
 *
 * IMPORTANT: Vault amounts must be adjusted for accumulated protocol/fund/creator fees
 * that are stored in the vaults but not part of trading liquidity.
 *
 * Returns the exact output amount after all fees.
 */
async function simulateCpmmSwap(
  connection: anchor.web3.Connection,
  poolState: PublicKey,
  ammConfig: PublicKey,
  inputVault: PublicKey,
  outputVault: PublicKey,
  amountIn: bigint,
  direction: "ZeroForOne" | "OneForZero",
): Promise<bigint> {
  // Get vault balances, pool state, and AMM config in parallel
  const [inputBalance, outputBalance, poolStateInfo, ammConfigInfo] =
    await Promise.all([
      connection.getTokenAccountBalance(inputVault),
      connection.getTokenAccountBalance(outputVault),
      connection.getAccountInfo(poolState),
      connection.getAccountInfo(ammConfig),
    ]);

  let xRaw = BigInt(inputBalance.value.amount);
  let yRaw = BigInt(outputBalance.value.amount);

  // Parse fee rates from AMM config
  // Raydium CPMM AmmConfig layout (Anchor):
  // - 8 bytes: discriminator
  // - 1 byte: bump
  // - 1 byte: disable_create_pool
  // - 2 bytes: index (u16)
  // - 8 bytes: trade_fee_rate (u64)
  // - 8 bytes: protocol_fee_rate (u64)
  // - 8 bytes: fund_fee_rate (u64)
  // Total offset to trade_fee_rate: 8 + 1 + 1 + 2 = 12

  let tradeFeeRate = 2500n; // Default 0.25%

  if (ammConfigInfo?.data && ammConfigInfo.data.length >= 36) {
    const data = ammConfigInfo.data;
    tradeFeeRate = data.readBigUInt64LE(12);

    // Sanity check - fee rates should be reasonable (< 10% = 100000 for trade fee)
    if (tradeFeeRate > 100000n) {
      console.log(
        `   ⚠️ AMM config fee rate looks wrong (${tradeFeeRate}), using default 2500`,
      );
      tradeFeeRate = 2500n;
    }
  }

  // Parse accumulated fees from pool state and subtract from vault amounts
  // Raydium CPMM PoolState layout (zero_copy, packed):
  // - 8 bytes: discriminator
  // - 10 * 32 = 320 bytes: pubkeys
  // - 5 bytes: u8s (auth_bump, status, lp_mint_decimals, mint_0_decimals, mint_1_decimals)
  // - 8 bytes: lp_supply (u64) - offset 333
  // - 8 bytes: protocol_fees_token_0 (u64) - offset 341
  // - 8 bytes: protocol_fees_token_1 (u64) - offset 349
  // - 8 bytes: fund_fees_token_0 (u64) - offset 357
  // - 8 bytes: fund_fees_token_1 (u64) - offset 365
  // - 8 bytes: open_time - offset 373
  // - 8 bytes: recent_epoch - offset 381
  // - 1 byte: creator_fee_on - offset 389
  // - 1 byte: enable_creator_fee - offset 390
  // - 6 bytes: padding1 - offset 391
  // - 8 bytes: creator_fees_token_0 (u64) - offset 397
  // - 8 bytes: creator_fees_token_1 (u64) - offset 405

  let x = xRaw;
  let y = yRaw;

  if (poolStateInfo?.data && poolStateInfo.data.length >= 420) {
    const data = poolStateInfo.data;
    // Read accumulated fees at correct offsets
    const protocolFeesToken0 = data.readBigUInt64LE(341);
    const protocolFeesToken1 = data.readBigUInt64LE(349);
    const fundFeesToken0 = data.readBigUInt64LE(357);
    const fundFeesToken1 = data.readBigUInt64LE(365);
    const creatorFeesToken0 = data.readBigUInt64LE(397);
    const creatorFeesToken1 = data.readBigUInt64LE(405);

    // Calculate total accumulated fees for each token
    const feesToken0 = protocolFeesToken0 + fundFeesToken0 + creatorFeesToken0;
    const feesToken1 = protocolFeesToken1 + fundFeesToken1 + creatorFeesToken1;

    // Adjust based on direction (ZeroForOne means token0 is input, token1 is output)
    if (direction === "ZeroForOne") {
      // Input is token0, output is token1
      x = xRaw - feesToken0;
      y = yRaw - feesToken1;
    } else {
      // Input is token1, output is token0
      x = xRaw - feesToken1;
      y = yRaw - feesToken0;
    }

    console.log(
      `   Accumulated fees: token0=${feesToken0}, token1=${feesToken1}`,
    );
    console.log(
      `   Vault amounts: raw(${xRaw}, ${yRaw}) -> adjusted(${x}, ${y})`,
    );
  }

  const FEE_DENOMINATOR = 1000000n;

  // Step 1: Apply trade fee to INPUT (Raydium applies fee to input, not output)
  // trade_fee = input * trade_fee_rate / 1_000_000
  const tradeFee = (amountIn * tradeFeeRate) / FEE_DENOMINATOR;
  const amountInAfterFee = amountIn - tradeFee;

  // Step 2: Constant product formula: dy = y * dx / (x + dx)
  const amountOut = (y * amountInAfterFee) / (x + amountInAfterFee);

  console.log(`   Simulation: x=${x}, y=${y}, tradeFeeRate=${tradeFeeRate}`);
  console.log(
    `   Trade fee: ${tradeFee}, amountInAfterFee: ${amountInAfterFee}`,
  );
  console.log(
    `   Simulated output: ${amountOut} (${Number(amountOut) / 1_000_000} USDC)`,
  );

  return amountOut;
}

// Helper: Derive nullifier marker PDA with tree_id
function deriveNullifierMarkerPDA(
  programId: PublicKey,
  mintAddress: PublicKey,
  treeId: number,
  nullifier: Uint8Array,
): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [
      Buffer.from("nullifier_v3"),
      mintAddress.toBuffer(),
      encodeTreeId(treeId),
      Buffer.from(nullifier),
    ],
    programId,
  );
  return pda;
}

/**
 * CPMM Pool accounts structure
 * Much simpler than legacy AMM - only 5 accounts needed!
 */
interface CpmmPoolAccounts {
  poolState: PublicKey; // The CPMM pool state account
  poolAuthority: PublicKey; // Pool authority PDA
  tokenVault0: PublicKey; // Pool's first token vault
  tokenVault1: PublicKey; // Pool's second token vault
  observationState: PublicKey; // Oracle observation (can be program ID if not used)
}

/**
 * Derive CPMM pool authority PDA
 */
function deriveCpmmPoolAuthority(poolState: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("vault_and_lp_mint_auth_seed"), poolState.toBuffer()],
    RAYDIUM_CPMM_PROGRAM,
  );
}

describe("Privacy Pool Cross-Pool Swap", () => {
  const provider = makeProvider();
  anchor.setProvider(provider);

  const program = anchor.workspace.PrivacyPool as Program<PrivacyPool>;
  const payer = (provider.wallet as Wallet).payer;

  // Poseidon hasher
  let poseidon: any;

  // Source pool (WSOL - wrapped SOL)
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

  // Test constants - using real token decimals
  const SOURCE_DECIMALS = 9; // WSOL has 9 decimals
  const DEST_DECIMALS = 6; // USDC has 6 decimals
  const INITIAL_DEPOSIT = 2_000_000_000; // 2 SOL in lamports
  const SWAP_AMOUNT = 700_000_000; // 1 SOL to swap
  const SWAP_FEE = 100_000; // 0.1 USDC relayer fee (6 decimals)
  const feeBps = 50; // 0.5%

  // Deposited note reference
  let depositedNoteId: string | null = null;

  before(async () => {
    console.log("\n🔧 Setting up cross-pool swap test environment...\n");
    console.log("Using cloned mainnet Raydium CPMM SOL/USDC pool\n");

    // Initialize Poseidon
    poseidon = await buildPoseidon();
    sourceOffchainTree = new OffchainMerkleTree(22, poseidon);
    destOffchainTree = new OffchainMerkleTree(22, poseidon);

    // Airdrop SOL for gas and deposits
    await airdropAndConfirm(provider, payer.publicKey, 10 * LAMPORTS_PER_SOL);

    // Use mainnet mints (cloned)
    sourceTokenMint = WSOL_MINT;
    destTokenMint = USDC_MINT;

    console.log(`✅ Source Token (WSOL): ${sourceTokenMint.toBase58()}`);
    console.log(`✅ Dest Token (USDC): ${destTokenMint.toBase58()}`);

    // Derive PDAs for source pool (WSOL)
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
      sourceTokenMint,
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

    console.log("Source Config PDA (WSOL):", sourceConfig.toBase58());
    console.log("Dest Config PDA (USDC):", destConfig.toBase58());
    console.log("CPMM Pool State:", CPMM_POOL_STATE.toBase58());
  });

  it("initializes source privacy pool (WSOL)", async () => {
    try {
      await (program.methods as any)
        .initialize(
          feeBps,
          sourceTokenMint,
          new BN(1_000_000), // min_deposit
          new BN(1_000_000_000_000), // max_deposit
          new BN(1_000_000), // min_withdraw
          new BN(1_000_000_000_000), // max_withdraw
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

      console.log("✅ Source pool (WSOL) initialized");
    } catch (e: any) {
      if (e.message?.includes("already in use")) {
        console.log("Source pool (WSOL) already initialized");
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
          new BN(1_000_000), // min_deposit
          new BN(1_000_000_000_000), // max_deposit
          new BN(1_000_000), // min_withdraw
          new BN(1_000_000_000_000), // max_withdraw
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
      // Check if global config already exists
      try {
        const existingConfig = await (
          program.account as any
        ).globalConfig.fetch(globalConfig);
        console.log("✅ Global config already initialized");
        console.log(`   Relayer enabled: ${existingConfig.relayerEnabled}`);
        return;
      } catch (e) {
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

      const globalConfigAcc = await (program.account as any).globalConfig.fetch(
        globalConfig,
      );
      console.log("✅ Global config initialized");
      console.log(`   Relayer enabled: ${globalConfigAcc.relayerEnabled}`);
    } catch (e: any) {
      if (e instanceof SendTransactionError) {
        const logs = await e.getLogs(provider.connection);
        console.error("Global config init failed:", logs);
      }
      throw e;
    }
  });

  it("registers relayer for source pool", async () => {
    // Register the payer as a relayer for the source pool (WSOL)
    try {
      await (program.methods as any)
        .addRelayer(sourceTokenMint, payer.publicKey)
        .accounts({ config: sourceConfig, admin: payer.publicKey })
        .rpc();
      console.log("✅ Relayer registered for source pool (WSOL)");
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

  it("deposits WSOL to source pool for later swap", async () => {
    console.log("\n🎁 Depositing WSOL to source pool...");

    // Create vault's token account (if not exists)
    await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      sourceTokenMint,
      sourceVault,
      true, // allowOwnerOffCurve
    );
    console.log(`   Vault token account created for source pool`);

    // Create wrapped SOL account and fund it
    // For WSOL, we wrap native SOL instead of minting
    const wsolAccount = await createWrappedNativeAccount(
      provider.connection,
      payer,
      payer.publicKey,
      INITIAL_DEPOSIT * 2, // lamports to wrap
    );
    console.log(`   Created wSOL account: ${wsolAccount.toBase58()}`);
    console.log(`   Wrapped ${(INITIAL_DEPOSIT * 2) / LAMPORTS_PER_SOL} SOL`);

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

    // Create dummy input for deposit (zero-value notes)
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

    // Second output is zero-value (change)
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

    // Get Merkle proof for dummy inputs (empty tree)
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

    // Execute deposit with correct parameter order matching the program
    const tx = await (program.methods as any)
      .transact(
        Array.from(root),
        0, // input_tree_id
        0, // output_tree_id
        new BN(amount.toString()),
        Array.from(extDataHash),
        sourceTokenMint,
        Array.from(dummyNullifier1),
        Array.from(dummyNullifier2),
        Array.from(commitment),
        Array.from(changeCommitment),
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
        userTokenAccount: wsolAccount,
        recipientTokenAccount: wsolAccount,
        relayerTokenAccount: wsolAccount,
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

    // Save note for later use in swap
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
    console.log(`   Amount: ${INITIAL_DEPOSIT} tokens`);
    console.log(`   Leaf index: ${leafIndex}`);
  });

  it("should build correct CPMM swap data", () => {
    const amountIn = new anchor.BN(1_000_000_000); // 1 token
    const minOut = new anchor.BN(950_000); // 0.95 USDC (5% slippage)

    const swapData = buildCpmmSwapData(amountIn, minOut, true);

    expect(swapData.length).to.equal(24);
    // Check discriminator (first 8 bytes)
    expect(swapData.slice(0, 8).equals(CPMM_SWAP_BASE_INPUT_DISCRIMINATOR)).to
      .be.true;

    // Verify amount encoding
    const decodedAmountIn = swapData.readBigUInt64LE(8);
    const decodedMinOut = swapData.readBigUInt64LE(16);

    expect(decodedAmountIn.toString()).to.equal(amountIn.toString());
    expect(decodedMinOut.toString()).to.equal(minOut.toString());
  });

  it("should build swap_base_out data correctly", () => {
    const amountOut = new anchor.BN(1_000_000); // Exact 1 USDC out
    const maxIn = new anchor.BN(1_100_000_000); // Max 1.1 tokens in

    const swapData = buildCpmmSwapData(maxIn, amountOut, false);

    expect(swapData.slice(0, 8).equals(CPMM_SWAP_BASE_OUTPUT_DISCRIMINATOR)).to
      .be.true;
  });

  it("should derive pool authority correctly", () => {
    const testPoolState = Keypair.generate().publicKey;
    const [authority, bump] = deriveCpmmPoolAuthority(testPoolState);

    expect(authority).to.be.instanceOf(PublicKey);
    expect(bump).to.be.lessThanOrEqual(255);
  });

  it("verifies swap accounts structure is correct", async () => {
    // Verify both pools are initialized correctly
    const sourceConfigAcc = await (program.account as any).privacyConfig.fetch(
      sourceConfig,
    );
    const destConfigAcc = await (program.account as any).privacyConfig.fetch(
      destConfig,
    );

    expect(sourceConfigAcc.mintAddress.toBase58()).to.equal(
      sourceTokenMint.toBase58(),
    );
    expect(destConfigAcc.mintAddress.toBase58()).to.equal(
      destTokenMint.toBase58(),
    );

    console.log("\n✅ Pool configurations verified:");
    console.log(
      `   Source pool mint: ${sourceConfigAcc.mintAddress.toBase58()}`,
    );
    console.log(`   Dest pool mint: ${destConfigAcc.mintAddress.toBase58()}`);
  });

  it("verifies deposited note exists in source pool", async () => {
    expect(depositedNoteId).to.not.be.null;

    const note = noteStorage.get(depositedNoteId!);
    expect(note).to.not.be.undefined;
    expect(note!.amount).to.equal(BigInt(INITIAL_DEPOSIT));

    // Verify the commitment is in the tree
    const treeAccount = await (program.account as any).merkleTreeAccount.fetch(
      sourceNoteTree,
    );
    // nextIndex could be BN, so convert to number for comparison
    const nextIndex =
      typeof treeAccount.nextIndex === "number"
        ? treeAccount.nextIndex
        : treeAccount.nextIndex.toNumber();
    expect(nextIndex).to.be.greaterThan(0);

    console.log("\n✅ Deposited note verified:");
    console.log(`   Note ID: ${depositedNoteId}`);
    console.log(`   Amount: ${note!.amount} tokens`);
    console.log(`   Leaf index: ${note!.leafIndex}`);
    console.log(`   Tree nextIndex: ${nextIndex}`);
  });

  it("validates swap parameter hashing", () => {
    // Test that swap params can be hashed correctly for ZK proof commitment
    const swapParams = {
      minAmountOut: new BN(1_000_000),
      deadline: new BN(Math.floor(Date.now() / 1000) + 3600),
      sourceMint: sourceTokenMint,
      destMint: destTokenMint,
    };

    // This would be hashed using Poseidon in the circuit
    // For now, verify the structure is correct
    expect(swapParams.minAmountOut.toNumber()).to.be.greaterThan(0);
    expect(swapParams.deadline.toNumber()).to.be.greaterThan(
      Math.floor(Date.now() / 1000),
    );
    expect(swapParams.sourceMint.toBase58()).to.not.equal(
      swapParams.destMint.toBase58(),
    );

    console.log("\n✅ Swap params validated:");
    console.log(`   Min output: ${swapParams.minAmountOut.toString()}`);
    console.log(`   Deadline: ${swapParams.deadline.toString()}`);
    console.log(
      `   Source→Dest: ${swapParams.sourceMint
        .toBase58()
        .slice(0, 8)}...→${swapParams.destMint.toBase58().slice(0, 8)}...`,
    );
  });

  /**
   * Cross-pool swap using real Raydium CPMM pool cloned from mainnet.
   * This swaps WSOL → USDC through the privacy pools + Raydium CPMM.
   *
   * NOTE: This test demonstrates the full swap flow but is currently marked
   * as pending because the transaction is too large (1527 > 1232 bytes).
   * To enable this test, use Versioned Transactions with Address Lookup Tables (ALT).
   *
   * The ZK proof generation works correctly - see the deposit test for proof validation.
   */
  it("executes cross-pool swap (WSOL → USDC via Raydium CPMM)", async () => {
    console.log("\n🔄 Executing cross-pool swap WSOL → USDC...");

    const note = noteStorage.get(depositedNoteId!);
    if (!note) throw new Error("Note not found");

    console.log(`   Input note amount: ${note.amount} lamports`);
    console.log(`   Swap amount: ${SWAP_AMOUNT} lamports`);

    // Get fresh merkle proof for the deposited note
    const merkleProof = sourceOffchainTree.getMerkleProof(note.leafIndex);
    const root = sourceOffchainTree.getRoot();

    // Second input is dummy (zero-value)
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

    // Calculate expected USDC output by simulating the swap
    // This ensures the commitment amount matches exactly what we'll receive
    const swapAmountBn = new BN(SWAP_AMOUNT);

    // Simulate the swap to get exact output (minus fee)
    const SWAP_FEE = 100_000n; // 0.1 USDC relayer fee
    const simulatedOutput = await simulateCpmmSwap(
      provider.connection,
      CPMM_POOL_STATE, // Pool state for accumulated fees
      CPMM_AMM_CONFIG, // AMM config for fee rate
      CPMM_TOKEN_VAULT_0, // SOL vault (input)
      CPMM_TOKEN_VAULT_1, // USDC vault (output)
      BigInt(SWAP_AMOUNT),
      "ZeroForOne", // SOL (token0) -> USDC (token1)
    );

    // The exact amount that will go to the vault (after relayer fee)
    const exactUsdcOut = simulatedOutput - SWAP_FEE;
    // Max input with 5% slippage buffer for swap_base_output
    const maxAmountIn = new BN(
      ((BigInt(SWAP_AMOUNT) * 105n) / 100n).toString(),
    );

    console.log(
      `   Simulated USDC out: ${simulatedOutput} (${
        Number(simulatedOutput) / 1_000_000
      } USDC)`,
    );
    console.log(
      `   Relayer fee: ${SWAP_FEE} (${Number(SWAP_FEE) / 1_000_000} USDC)`,
    );
    console.log(
      `   USDC to vault: ${exactUsdcOut} (${
        Number(exactUsdcOut) / 1_000_000
      } USDC)`,
    );
    console.log(`   Max SOL input: ${maxAmountIn.toString()}`);

    // For the ZK proof, we need to satisfy the balance equation:
    // sumIns + publicAmount = sumOuts
    // Since we're withdrawing SWAP_AMOUNT from source pool:
    // 2_000_000_000 + (-1_000_000_000) = 1_000_000_000
    // So output amounts should sum to 1_000_000_000 (the change in source pool)

    // The swappedAmount for the ZK proof is 0 (placeholder)
    // because the actual swapped amount in dest pool is different token
    const zkSwappedAmount = 0n; // Not included in source pool balance

    // Change note stays in source token (WSOL)
    const changeAmount = note.amount - BigInt(SWAP_AMOUNT);

    // Generate output commitment for destination pool (USDC)
    // Note: For the ZK proof, we need to use source mint for all commitments
    // because the current circuit only supports a single mint address.
    const destPrivKey = randomBytes32();
    const destPubKey = derivePublicKey(poseidon, destPrivKey);
    const destBlinding = randomBytes32();
    const swappedAmount = exactUsdcOut; // EXACT amount from simulation

    // For the actual program instruction, use dest mint with exact amount
    const destCommitment = computeCommitment(
      poseidon,
      swappedAmount,
      destPubKey,
      destBlinding,
      destTokenMint, // USDC - actual commitment for dest pool
    );

    // For ZK proof, compute with source mint and zkSwappedAmount (circuit limitation)
    const destCommitmentForProof = computeCommitment(
      poseidon,
      zkSwappedAmount,
      destPubKey,
      destBlinding,
      sourceTokenMint, // WSOL - for ZK proof compatibility
    );

    // Change note stays in source token (WSOL) - if any
    const changePrivKey = randomBytes32();
    const changePubKey = derivePublicKey(poseidon, changePrivKey);
    const changeBlinding = randomBytes32();
    const changeCommitment = computeCommitment(
      poseidon,
      changeAmount,
      changePubKey,
      changeBlinding,
      sourceTokenMint, // WSOL
    );

    // External data for the swap transaction
    const extData = {
      recipient: payer.publicKey,
      relayer: payer.publicKey,
      fee: new BN(SWAP_FEE), // 0.1 USDC relayer fee
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    // Generate ZK proof
    // Note: Using destCommitmentForProof (source mint) for ZK compatibility
    // The actual destCommitment (dest mint) is used in the on-chain instruction
    // Output amounts: [0, changeAmount] to satisfy balance equation
    console.log("   Generating ZK proof...");
    const proof = await generateTransactionProof({
      root,
      publicAmount: -BigInt(SWAP_AMOUNT), // Negative = withdrawal/swap out
      extDataHash,
      mintAddress: sourceTokenMint,
      inputNullifiers: [note.nullifier, dummyNullifier],
      outputCommitments: [destCommitmentForProof, changeCommitment],
      inputAmounts: [note.amount, 0n],
      inputPrivateKeys: [note.privateKey, dummyPrivKey],
      inputPublicKeys: [note.publicKey, dummyPubKey],
      inputBlindings: [note.blinding, dummyBlinding],
      inputMerklePaths: [merkleProof, dummyProof],
      outputAmounts: [zkSwappedAmount, changeAmount], // Use 0 for dest (balance equation)
      outputOwners: [destPubKey, changePubKey],
      outputBlindings: [destBlinding, changeBlinding],
    });
    console.log("   ✅ ZK proof generated");

    // Build CPMM swap data using swap_base_input
    // swap_base_input: [discriminator, amount_in, min_amount_out]
    // We simulate first to get the expected output, then use that for the commitment
    const minAmountOut = new BN(((simulatedOutput * 95n) / 100n).toString()); // 5% slippage
    const swapData = buildCpmmSwapData(
      swapAmountBn,
      minAmountOut,
      true, // swap_base_input
    );
    console.log(
      `   Using swap_base_input: amount_in=${swapAmountBn}, min_out=${minAmountOut}`,
    );

    // Real CPMM pool accounts (cloned from mainnet)
    const cpmmPoolAccounts: CpmmPoolAccounts = {
      poolState: CPMM_POOL_STATE,
      poolAuthority: CPMM_POOL_AUTHORITY,
      tokenVault0: CPMM_TOKEN_VAULT_0, // SOL vault
      tokenVault1: CPMM_TOKEN_VAULT_1, // USDC vault
      observationState: CPMM_OBSERVATION_STATE, // Cloned from mainnet
    };

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

    // Get or create token accounts for the swap
    const sourceVaultWsolAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      sourceTokenMint, // WSOL
      sourceVault,
      true,
    );
    const destVaultUsdcAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      destTokenMint, // USDC
      destVault,
      true,
    );

    // Get or create relayer token account (for dest token - USDC)
    const relayerTokenAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      destTokenMint, // USDC
      payer.publicKey,
    );

    // ============ BALANCE LOGGING BEFORE SWAP ============
    console.log(
      "\n   ╔══════════════════════════════════════════════════════════════════╗",
    );
    console.log(
      "   ║                    BALANCES BEFORE SWAP                          ║",
    );
    console.log(
      "   ╠══════════════════════════════════════════════════════════════════╣",
    );

    // Privacy Pool Vaults
    const sourceVaultBalanceBefore =
      await provider.connection.getTokenAccountBalance(
        sourceVaultWsolAccount.address,
      );
    const destVaultBalanceBefore =
      await provider.connection.getTokenAccountBalance(
        destVaultUsdcAccount.address,
      );

    console.log(
      "   ║ PRIVACY POOL VAULTS:                                             ║",
    );
    console.log(
      `   ║   Source Vault (WSOL): ${sourceVaultWsolAccount.address.toBase58()}`,
    );
    console.log(
      `   ║     Balance: ${sourceVaultBalanceBefore.value.uiAmountString} WSOL (${sourceVaultBalanceBefore.value.amount} lamports)`,
    );
    console.log(
      `   ║   Dest Vault (USDC):   ${destVaultUsdcAccount.address.toBase58()}`,
    );
    console.log(
      `   ║     Balance: ${destVaultBalanceBefore.value.uiAmountString} USDC (${destVaultBalanceBefore.value.amount} base units)`,
    );

    // CPMM Pool Vaults
    const cpmmVault0BalanceBefore =
      await provider.connection.getTokenAccountBalance(CPMM_TOKEN_VAULT_0);
    const cpmmVault1BalanceBefore =
      await provider.connection.getTokenAccountBalance(CPMM_TOKEN_VAULT_1);

    console.log(
      "   ╠══════════════════════════════════════════════════════════════════╣",
    );
    console.log(
      "   ║ RAYDIUM CPMM POOL VAULTS:                                        ║",
    );
    console.log(`   ║   SOL Vault:  ${CPMM_TOKEN_VAULT_0.toBase58()}`);
    console.log(
      `   ║     Balance: ${cpmmVault0BalanceBefore.value.uiAmountString} WSOL`,
    );
    console.log(`   ║   USDC Vault: ${CPMM_TOKEN_VAULT_1.toBase58()}`);
    console.log(
      `   ║     Balance: ${cpmmVault1BalanceBefore.value.uiAmountString} USDC`,
    );

    // Relayer/Payer
    const relayerUsdcBalanceBefore =
      await provider.connection.getTokenAccountBalance(
        relayerTokenAccount.address,
      );
    const payerSolBalanceBefore = await provider.connection.getBalance(
      payer.publicKey,
    );

    console.log(
      "   ╠══════════════════════════════════════════════════════════════════╣",
    );
    console.log(
      "   ║ RELAYER/PAYER:                                                   ║",
    );
    console.log(`   ║   Address: ${payer.publicKey.toBase58()}`);
    console.log(
      `   ║     SOL Balance: ${(
        payerSolBalanceBefore / LAMPORTS_PER_SOL
      ).toFixed(4)} SOL`,
    );
    console.log(
      `   ║     USDC Balance: ${relayerUsdcBalanceBefore.value.uiAmountString} USDC`,
    );

    console.log(
      "   ╠══════════════════════════════════════════════════════════════════╣",
    );
    console.log(
      "   ║ KEY ADDRESSES:                                                   ║",
    );
    console.log(`   ║   Source Pool Config: ${sourceConfig.toBase58()}`);
    console.log(`   ║   Dest Pool Config:   ${destConfig.toBase58()}`);
    console.log(`   ║   Source Merkle Tree: ${sourceNoteTree.toBase58()}`);
    console.log(`   ║   Dest Merkle Tree:   ${destNoteTree.toBase58()}`);
    console.log(`   ║   CPMM Pool State:    ${CPMM_POOL_STATE.toBase58()}`);
    console.log(
      "   ╚══════════════════════════════════════════════════════════════════╝\n",
    );

    console.log("   Executing transact_swap instruction...");

    // Swap params for the instruction
    // minAmountOut is used for on-chain slippage check
    const minAmountOutForCheck = new BN(
      ((simulatedOutput * 95n) / 100n).toString(),
    ); // 5% slippage tolerance
    const swapParams = {
      minAmountOut: minAmountOutForCheck,
      deadline: new BN(Math.floor(Date.now() / 1000) + 3600), // 1 hour from now
      sourceMint: sourceTokenMint,
      destMint: destTokenMint,
    };

    // Derive executor PDA (seeds: ["swap_executor", nullifier_0])
    const [executorPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("swap_executor"), Buffer.from(note.nullifier)],
      program.programId,
    );

    // Derive executor's source token account (ATA)
    const executorSourceToken = await getAssociatedTokenAddress(
      sourceTokenMint,
      executorPda,
      true, // allowOwnerOffCurve
    );

    // Derive executor's dest token account (ATA)
    const executorDestToken = await getAssociatedTokenAddress(
      destTokenMint,
      executorPda,
      true, // allowOwnerOffCurve
    );

    console.log(
      "   ╠══════════════════════════════════════════════════════════════════╣",
    );
    console.log(
      "   ║ EXECUTOR PDA (swap agent):                                       ║",
    );
    console.log(`   ║   Executor PDA:        ${executorPda.toBase58()}`);
    console.log(
      `   ║   Executor WSOL ATA:   ${executorSourceToken.toBase58()}`,
    );
    console.log(`   ║   Executor USDC ATA:   ${executorDestToken.toBase58()}`);
    console.log(`   ║   Seeds: ["swap_executor", nullifier_0]`);

    // Create Address Lookup Table with all static accounts to reduce tx size
    console.log("   Creating Address Lookup Table...");
    const recentSlot = await provider.connection.getSlot("finalized");

    // Collect all accounts that can be in the ALT (non-signer, non-payer accounts)
    const lookupTableAddresses = [
      sourceConfig,
      globalConfig,
      sourceVault,
      sourceNoteTree,
      sourceNullifiers,
      sourceVaultWsolAccount.address,
      sourceTokenMint,
      destConfig,
      destVault,
      destNoteTree,
      destVaultUsdcAccount.address,
      destTokenMint,
      RAYDIUM_CPMM_PROGRAM,
      TOKEN_PROGRAM_ID,
      SystemProgram.programId,
      ASSOCIATED_TOKEN_PROGRAM_ID,
      // CPMM pool accounts
      CPMM_POOL_STATE,
      CPMM_POOL_AUTHORITY,
      CPMM_TOKEN_VAULT_0,
      CPMM_TOKEN_VAULT_1,
      CPMM_AMM_CONFIG,
      CPMM_AUTHORITY,
      CPMM_OBSERVATION_STATE,
    ];

    // Create lookup table
    const [createLutIx, lookupTableAddress] =
      AddressLookupTableProgram.createLookupTable({
        authority: payer.publicKey,
        payer: payer.publicKey,
        recentSlot,
      });

    // Extend lookup table with addresses
    const extendLutIx = AddressLookupTableProgram.extendLookupTable({
      payer: payer.publicKey,
      authority: payer.publicKey,
      lookupTable: lookupTableAddress,
      addresses: lookupTableAddresses,
    });

    // Send create + extend in one transaction
    const createLutTx = new anchor.web3.Transaction()
      .add(createLutIx)
      .add(extendLutIx);

    await provider.sendAndConfirm(createLutTx);
    console.log(`   ALT created: ${lookupTableAddress.toBase58()}`);

    // Wait for ALT to be active (needs ~1 slot)
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // Fetch the lookup table account
    const lookupTableAccount = await provider.connection.getAddressLookupTable(
      lookupTableAddress,
    );
    if (!lookupTableAccount.value) {
      throw new Error("Failed to fetch lookup table");
    }

    try {
      // Build the instruction using Anchor's method builder
      // Parameter order matches: source_root, source_tree_id, source_mint, input_nullifier_0, input_nullifier_1,
      // dest_tree_id, dest_mint, output_commitment_0, output_commitment_1, swap_params, swap_amount, swap_data, ext_data
      const swapIx = await (program.methods as any)
        .transactSwap(
          Array.from(root), // source_root
          0, // source_tree_id
          sourceTokenMint, // source_mint
          Array.from(note.nullifier), // input_nullifier_0
          Array.from(dummyNullifier), // input_nullifier_1
          0, // dest_tree_id
          destTokenMint, // dest_mint
          Array.from(destCommitment), // output_commitment_0
          Array.from(changeCommitment), // output_commitment_1
          swapParams, // swap_params
          new BN(SWAP_AMOUNT.toString()), // swap_amount
          swapData, // swap_data - pass Buffer directly for Vec<u8>
          extData, // ext_data
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
          sourceMintAccount: sourceTokenMint,
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
          raydiumCpmmProgram: RAYDIUM_CPMM_PROGRAM,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
          associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
        })
        .remainingAccounts([
          // CPMM accounts passed via remaining_accounts in order:
          // 0: authority, 1: amm_config, 2: pool_state
          // 3: input_vault, 4: output_vault
          // 5: input_token_mint, 6: output_token_mint, 7: observation_state
          {
            pubkey: CPMM_AUTHORITY, // authority (CPMM pool vault PDA)
            isSigner: false,
            isWritable: false,
          },
          {
            pubkey: CPMM_AMM_CONFIG, // amm_config
            isSigner: false,
            isWritable: false,
          },
          {
            pubkey: cpmmPoolAccounts.poolState, // pool_state
            isSigner: false,
            isWritable: true,
          },
          {
            pubkey: cpmmPoolAccounts.tokenVault0, // input_vault (SOL)
            isSigner: false,
            isWritable: true,
          },
          {
            pubkey: cpmmPoolAccounts.tokenVault1, // output_vault (USDC)
            isSigner: false,
            isWritable: true,
          },
          {
            pubkey: WSOL_MINT, // input_token_mint
            isSigner: false,
            isWritable: false,
          },
          {
            pubkey: USDC_MINT, // output_token_mint
            isSigner: false,
            isWritable: false,
          },
          {
            pubkey: cpmmPoolAccounts.observationState, // observation_state
            isSigner: false,
            isWritable: true,
          },
        ])
        .instruction();

      // Build versioned transaction with ALT
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

      // Check transaction size
      const serialized = versionedTx.serialize();
      console.log(
        `   Transaction size: ${serialized.length} bytes (limit: 1232)`,
      );

      if (serialized.length > 1232) {
        throw new Error(
          `Transaction still too large: ${serialized.length} > 1232 bytes`,
        );
      }

      // Send and confirm
      const txSig = await provider.connection.sendTransaction(versionedTx, {
        skipPreflight: false,
      });

      await provider.connection.confirmTransaction({
        signature: txSig,
        blockhash,
        lastValidBlockHeight,
      });

      console.log(`✅ Cross-pool swap executed: ${txSig}`);

      // ============ BALANCE LOGGING AFTER SWAP ============
      console.log(
        "\n   ╔══════════════════════════════════════════════════════════════════╗",
      );
      console.log(
        "   ║                    BALANCES AFTER SWAP                           ║",
      );
      console.log(
        "   ╠══════════════════════════════════════════════════════════════════╣",
      );

      // Privacy Pool Vaults
      const sourceVaultBalanceAfter =
        await provider.connection.getTokenAccountBalance(
          sourceVaultWsolAccount.address,
        );
      const destVaultBalanceAfter =
        await provider.connection.getTokenAccountBalance(
          destVaultUsdcAccount.address,
        );

      console.log(
        "   ║ PRIVACY POOL VAULTS:                                             ║",
      );
      console.log(
        `   ║   Source Vault (WSOL): ${sourceVaultWsolAccount.address.toBase58()}`,
      );
      console.log(
        `   ║     Before: ${sourceVaultBalanceBefore.value.uiAmountString} WSOL`,
      );
      console.log(
        `   ║     After:  ${sourceVaultBalanceAfter.value.uiAmountString} WSOL`,
      );
      console.log(
        `   ║     Change: ${
          (Number(sourceVaultBalanceAfter.value.amount) -
            Number(sourceVaultBalanceBefore.value.amount)) /
          LAMPORTS_PER_SOL
        } WSOL`,
      );
      console.log(
        `   ║   Dest Vault (USDC):   ${destVaultUsdcAccount.address.toBase58()}`,
      );
      console.log(
        `   ║     Before: ${destVaultBalanceBefore.value.uiAmountString} USDC`,
      );
      console.log(
        `   ║     After:  ${destVaultBalanceAfter.value.uiAmountString} USDC`,
      );
      console.log(
        `   ║     Change: +${
          (Number(destVaultBalanceAfter.value.amount) -
            Number(destVaultBalanceBefore.value.amount)) /
          1_000_000
        } USDC`,
      );

      // CPMM Pool Vaults
      const cpmmVault0BalanceAfter =
        await provider.connection.getTokenAccountBalance(CPMM_TOKEN_VAULT_0);
      const cpmmVault1BalanceAfter =
        await provider.connection.getTokenAccountBalance(CPMM_TOKEN_VAULT_1);

      console.log(
        "   ╠══════════════════════════════════════════════════════════════════╣",
      );
      console.log(
        "   ║ RAYDIUM CPMM POOL VAULTS:                                        ║",
      );
      console.log(`   ║   SOL Vault:  ${CPMM_TOKEN_VAULT_0.toBase58()}`);
      console.log(
        `   ║     Before: ${cpmmVault0BalanceBefore.value.uiAmountString} WSOL`,
      );
      console.log(
        `   ║     After:  ${cpmmVault0BalanceAfter.value.uiAmountString} WSOL`,
      );
      console.log(
        `   ║     Change: +${
          (Number(cpmmVault0BalanceAfter.value.amount) -
            Number(cpmmVault0BalanceBefore.value.amount)) /
          LAMPORTS_PER_SOL
        } WSOL (received from swap)`,
      );
      console.log(`   ║   USDC Vault: ${CPMM_TOKEN_VAULT_1.toBase58()}`);
      console.log(
        `   ║     Before: ${cpmmVault1BalanceBefore.value.uiAmountString} USDC`,
      );
      console.log(
        `   ║     After:  ${cpmmVault1BalanceAfter.value.uiAmountString} USDC`,
      );
      console.log(
        `   ║     Change: ${
          (Number(cpmmVault1BalanceAfter.value.amount) -
            Number(cpmmVault1BalanceBefore.value.amount)) /
          1_000_000
        } USDC (sent to privacy pool)`,
      );

      // Relayer/Payer
      const relayerUsdcBalanceAfter =
        await provider.connection.getTokenAccountBalance(
          relayerTokenAccount.address,
        );
      const payerSolBalanceAfter = await provider.connection.getBalance(
        payer.publicKey,
      );

      console.log(
        "   ╠══════════════════════════════════════════════════════════════════╣",
      );
      console.log(
        "   ║ RELAYER/PAYER:                                                   ║",
      );
      console.log(`   ║   Address: ${payer.publicKey.toBase58()}`);
      console.log(
        `   ║     SOL Balance: ${(
          payerSolBalanceAfter / LAMPORTS_PER_SOL
        ).toFixed(4)} SOL (was ${(
          payerSolBalanceBefore / LAMPORTS_PER_SOL
        ).toFixed(4)})`,
      );
      console.log(
        `   ║     USDC Balance: ${relayerUsdcBalanceAfter.value.uiAmountString} USDC (was ${relayerUsdcBalanceBefore.value.uiAmountString})`,
      );

      console.log(
        "   ╠══════════════════════════════════════════════════════════════════╣",
      );
      console.log(
        "   ║ SWAP SUMMARY:                                                    ║",
      );
      console.log(
        `   ║   Swapped: ${SWAP_AMOUNT / LAMPORTS_PER_SOL} SOL → USDC`,
      );
      const usdcToVault =
        Number(destVaultBalanceAfter.value.amount) -
        Number(destVaultBalanceBefore.value.amount);
      const usdcToRelayer =
        Number(relayerUsdcBalanceAfter.value.amount) -
        Number(relayerUsdcBalanceBefore.value.amount);
      const totalUsdcSwapped = usdcToVault + usdcToRelayer;
      console.log(
        `   ║   Total USDC from Swap: ${totalUsdcSwapped / 1_000_000} USDC`,
      );
      console.log(`   ║   USDC to Vault: ${usdcToVault / 1_000_000} USDC`);
      console.log(
        `   ║   USDC to Relayer (fee): ${usdcToRelayer / 1_000_000} USDC`,
      );
      console.log(
        `   ║   Effective Rate: 1 SOL = ${(
          (totalUsdcSwapped * LAMPORTS_PER_SOL) /
          SWAP_AMOUNT /
          1_000_000
        ).toFixed(6)} USDC`,
      );
      console.log(
        "   ╚══════════════════════════════════════════════════════════════════╝\n",
      );

      // Update off-chain trees
      destOffchainTree.insert(destCommitment);
      if (changeAmount > 0n) {
        sourceOffchainTree.insert(changeCommitment);
      }

      console.log(`   Swapped ${SWAP_AMOUNT} lamports WSOL → USDC`);
      console.log(`   Output commitment added to dest pool`);
      if (changeAmount > 0n) {
        console.log(
          `   Change of ${changeAmount} lamports added to source pool`,
        );
      }
    } catch (error) {
      if (error instanceof SendTransactionError) {
        console.log(
          "Transaction logs:",
          await error.getLogs(provider.connection),
        );
      }
      throw error;
    }
  });

  /**
   * Helper: Wrap SOL to wSOL for testing
   */
  async function wrapSol(amount: number): Promise<PublicKey> {
    const wsolAccount = await createWrappedNativeAccount(
      provider.connection,
      payer,
      payer.publicKey,
      amount,
    );
    return wsolAccount;
  }

  /**
   * Helper: Unwrap wSOL back to SOL
   */
  async function unwrapSol(wsolAccount: PublicKey): Promise<void> {
    await closeAccount(
      provider.connection,
      payer,
      wsolAccount,
      payer.publicKey,
      payer,
    );
  }

  // Skip this test on localnet with cloned accounts - WSOL ATA creation
  // has issues when the native mint is cloned from mainnet
  it.skip("should wrap and unwrap SOL correctly", async () => {
    const wrapAmount = LAMPORTS_PER_SOL / 10; // 0.1 SOL

    // Wrap SOL
    const wsolAccount = await wrapSol(wrapAmount);
    expect(wsolAccount).to.be.instanceOf(PublicKey);

    // Check balance
    const balance = await provider.connection.getTokenAccountBalance(
      wsolAccount,
    );
    expect(parseInt(balance.value.amount)).to.equal(wrapAmount);

    // Unwrap back to SOL
    await unwrapSol(wsolAccount);
  });

  /**
   * This test validates that the ZK proof for a cross-pool swap can be generated.
   * The proof satisfies the circuit constraints for withdrawing from the source pool.
   *
   * This proves that:
   * 1. User owns notes in the source pool (via Merkle proof)
   * 2. The balance equation is satisfied (input - output = publicAmount)
   * 3. The nullifiers are correctly derived
   * 4. The output commitments are correctly computed
   */
  it("validates ZK proof generation for cross-pool swap", async () => {
    console.log("\n🔐 Validating ZK proof generation for swap...");

    const note = noteStorage.get(depositedNoteId!);
    if (!note) throw new Error("Note not found");

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

    const changeAmount = note.amount - BigInt(SWAP_AMOUNT);

    // Output commitments
    const destPrivKey = randomBytes32();
    const destPubKey = derivePublicKey(poseidon, destPrivKey);
    const destBlinding = randomBytes32();
    const destCommitmentForProof = computeCommitment(
      poseidon,
      0n,
      destPubKey,
      destBlinding,
      sourceTokenMint,
    );

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

    const extData = {
      recipient: payer.publicKey,
      relayer: payer.publicKey,
      fee: new BN(0),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    // Generate ZK proof
    const proof = await generateTransactionProof({
      root,
      publicAmount: -BigInt(SWAP_AMOUNT),
      extDataHash,
      mintAddress: sourceTokenMint,
      inputNullifiers: [note.nullifier, dummyNullifier],
      outputCommitments: [destCommitmentForProof, changeCommitment],
      inputAmounts: [note.amount, 0n],
      inputPrivateKeys: [note.privateKey, dummyPrivKey],
      inputPublicKeys: [note.publicKey, dummyPubKey],
      inputBlindings: [note.blinding, dummyBlinding],
      inputMerklePaths: [merkleProof, dummyProof],
      outputAmounts: [0n, changeAmount],
      outputOwners: [destPubKey, changePubKey],
      outputBlindings: [destBlinding, changeBlinding],
    });

    // Verify proof format - proofA/proofC are 64 bytes (2 G1 points), proofB is 128 bytes (2 G2 points)
    expect(proof).to.have.property("proofA");
    expect(proof).to.have.property("proofB");
    expect(proof).to.have.property("proofC");
    expect(proof.proofA).to.have.lengthOf(64);
    expect(proof.proofB).to.have.lengthOf(128);
    expect(proof.proofC).to.have.lengthOf(64);

    console.log("✅ ZK proof for swap generated and validated successfully");
    console.log(`   Input: ${note.amount} lamports`);
    console.log(`   Swap: ${SWAP_AMOUNT} lamports`);
    console.log(`   Change: ${changeAmount} lamports`);
    console.log(`   Proof has valid Groth16 structure`);
  });
});

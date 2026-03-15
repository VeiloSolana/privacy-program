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
  createWrappedNativeAccount,
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
  derivePublicKey,
  generateTransactionProof,
  generateSwapProof,
  computeSwapParamsHash,
} from "./test-helpers";
import {
  RAYDIUM_AMM_V4_PROGRAM,
  SERUM_PROGRAM,
  AMM_AUTHORITY,
  AMM_SWAP_BASE_IN_DISCRIMINATOR,
  WSOL_MINT,
  USDT_MINT,
  getPoolConfig,
  buildAmmSwapData,
  deriveSerumVaultSigner,
  getSwapVaults,
  getSerumSwapVaults,
  getOutputMint,
  getTokenDecimals,
  isBaseToQuote,
  logPoolConfig,
  logPoolKeys,
  PoolName,
  AmmV4PoolConfig,
  getPoolKeysFromMints,
  getPoolConfigFromMints,
  poolKeysToConfig,
} from "./amm-v4-pool-helper";
import { LiquidityPoolKeysV4 } from "@raydium-io/raydium-sdk";

const SOL_MINT = PublicKey.default;

/** For native SOL pools, SPL operations use WSOL (NATIVE_MINT) */
function tokenMintFor(mint: PublicKey): PublicKey {
  return mint.equals(PublicKey.default) ? NATIVE_MINT : mint;
}

/**
 * Privacy Pool Cross-Pool Swap Tests using Raydium AMM V4 - SOL/USDT
 *
 * Tests bidirectional swaps between SOL and USDT:
 * 1. SOL → USDT: Consumes SOL notes, swaps via AMM V4, creates USDT notes
 * 2. USDT → SOL: Consumes USDT notes, swaps via AMM V4, creates SOL notes
 *
 * Uses cloned mainnet Raydium AMM V4 SOL/USDT pool for testing.
 */

// Get pool configuration - can use static or dynamic
const POOL_NAME: PoolName = "SOL-USDT";
let poolConfig: AmmV4PoolConfig;
let poolKeys: LiquidityPoolKeysV4 | null = null;

// Set to true to use dynamic pool key fetching from Raydium SDK
const USE_DYNAMIC_POOL_KEYS = true;

// Helper: Encode tree_id as 2-byte little-endian (u16)
function encodeTreeId(treeId: number): Buffer {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16LE(treeId, 0);
  return buffer;
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

// Balance tracking interfaces and helpers
interface BalanceSnapshot {
  userSol: number;
  userWsol?: number;
  userUsdt?: number;
  solVault?: number;
  usdtVault?: number;
  poolBaseLiquidity?: number;
  poolQuoteLiquidity?: number;
  relayerSol: number;
  relayerUsdt?: number;
}

// Helper to get SOL balance
async function getSolBalance(
  connection: any,
  pubkey: PublicKey,
): Promise<number> {
  const balance = await connection.getBalance(pubkey);
  return balance / LAMPORTS_PER_SOL;
}

// Helper to get token balance
async function getTokenBalance(
  connection: any,
  tokenAccount: PublicKey,
): Promise<number | undefined> {
  try {
    const balance = await connection.getTokenAccountBalance(tokenAccount);
    return parseFloat(balance.value.uiAmountString || "0");
  } catch {
    return undefined;
  }
}

// Helper to get comprehensive balance snapshot
async function getBalanceSnapshot(
  connection: any,
  userPubkey: PublicKey,
  userWsolAccount?: PublicKey,
  userUsdtAccount?: PublicKey,
  solVaultAccount?: PublicKey,
  usdtVaultAccount?: PublicKey,
  relayerUsdtAccount?: PublicKey,
): Promise<BalanceSnapshot> {
  const [
    userSol,
    userWsol,
    userUsdt,
    solVault,
    usdtVault,
    relayerSol,
    relayerUsdt,
  ] = await Promise.all([
    getSolBalance(connection, userPubkey),
    userWsolAccount
      ? getTokenBalance(connection, userWsolAccount)
      : Promise.resolve(undefined),
    userUsdtAccount
      ? getTokenBalance(connection, userUsdtAccount)
      : Promise.resolve(undefined),
    solVaultAccount
      ? getTokenBalance(connection, solVaultAccount)
      : Promise.resolve(undefined),
    usdtVaultAccount
      ? getTokenBalance(connection, usdtVaultAccount)
      : Promise.resolve(undefined),
    getSolBalance(connection, userPubkey), // relayer is same as user in tests
    relayerUsdtAccount
      ? getTokenBalance(connection, relayerUsdtAccount)
      : Promise.resolve(undefined),
  ]);

  return {
    userSol,
    userWsol,
    userUsdt,
    solVault,
    usdtVault,
    relayerSol,
    relayerUsdt,
  };
}

// Helper to log balance differences
function logBalanceChanges(
  before: BalanceSnapshot,
  after: BalanceSnapshot,
  operation: string,
) {
  console.log(`\n📊 Balance Changes - ${operation}:`);

  if (before.userSol !== after.userSol) {
    const diff = after.userSol - before.userSol;
    console.log(
      `   User SOL: ${before.userSol.toFixed(6)} → ${after.userSol.toFixed(
        6,
      )} (${diff >= 0 ? "+" : ""}${diff.toFixed(6)} SOL)`,
    );
  }

  if (
    before.userWsol !== after.userWsol &&
    (before.userWsol || after.userWsol)
  ) {
    const beforeVal = before.userWsol || 0;
    const afterVal = after.userWsol || 0;
    const diff = afterVal - beforeVal;
    console.log(
      `   User WSOL: ${beforeVal.toFixed(6)} → ${afterVal.toFixed(6)} (${
        diff >= 0 ? "+" : ""
      }${diff.toFixed(6)} WSOL)`,
    );
  }

  if (
    before.userUsdt !== after.userUsdt &&
    (before.userUsdt || after.userUsdt)
  ) {
    const beforeVal = before.userUsdt || 0;
    const afterVal = after.userUsdt || 0;
    const diff = afterVal - beforeVal;
    console.log(
      `   User USDT: ${beforeVal.toFixed(6)} → ${afterVal.toFixed(6)} (${
        diff >= 0 ? "+" : ""
      }${diff.toFixed(6)} USDT)`,
    );
  }

  if (
    before.solVault !== after.solVault &&
    (before.solVault || after.solVault)
  ) {
    const beforeVal = before.solVault || 0;
    const afterVal = after.solVault || 0;
    const diff = afterVal - beforeVal;
    console.log(
      `   SOL Vault: ${beforeVal.toFixed(6)} → ${afterVal.toFixed(6)} (${
        diff >= 0 ? "+" : ""
      }${diff.toFixed(6)} SOL)`,
    );
  }

  if (
    before.usdtVault !== after.usdtVault &&
    (before.usdtVault || after.usdtVault)
  ) {
    const beforeVal = before.usdtVault || 0;
    const afterVal = after.usdtVault || 0;
    const diff = afterVal - beforeVal;
    console.log(
      `   USDT Vault: ${beforeVal.toFixed(6)} → ${afterVal.toFixed(6)} (${
        diff >= 0 ? "+" : ""
      }${diff.toFixed(6)} USDT)`,
    );
  }

  if (
    before.relayerUsdt !== after.relayerUsdt &&
    (before.relayerUsdt || after.relayerUsdt)
  ) {
    const beforeVal = before.relayerUsdt || 0;
    const afterVal = after.relayerUsdt || 0;
    const diff = afterVal - beforeVal;
    console.log(
      `   Relayer USDT: ${beforeVal.toFixed(6)} → ${afterVal.toFixed(6)} (${
        diff >= 0 ? "+" : ""
      }${diff.toFixed(6)} USDT)`,
    );
  }
}

describe("Privacy Pool AMM V4 Swap - SOL/USDT", () => {
  const provider = makeProvider();
  anchor.setProvider(provider);

  const program = anchor.workspace.PrivacyPool as Program<PrivacyPool>;
  const payer = (provider.wallet as Wallet).payer;

  // Poseidon hasher
  let poseidon: any;

  // Source pool (WSOL)
  let solTokenMint: PublicKey;
  let solConfig: PublicKey;
  let solVault: PublicKey;
  let solNoteTree: PublicKey;
  let solNullifiers: PublicKey;
  let solVaultTokenAccount: PublicKey;

  // Destination pool (USDT)
  let usdtTokenMint: PublicKey;
  let usdtConfig: PublicKey;
  let usdtVault: PublicKey;
  let usdtNoteTree: PublicKey;
  let usdtNullifiers: PublicKey;
  let usdtVaultTokenAccount: PublicKey;

  // Global config
  let globalConfig: PublicKey;

  // Off-chain Merkle trees
  let solOffchainTree: OffchainMerkleTree;
  let usdtOffchainTree: OffchainMerkleTree;

  // Note storage
  const noteStorage = new InMemoryNoteStorage();

  // Test constants
  const SOL_DECIMALS = 9;
  const USDT_DECIMALS = 6;
  const INITIAL_SOL_DEPOSIT = 2_000_000_000; // 2 SOL
  const SWAP_AMOUNT_SOL = 500_000_000; // 0.5 SOL
  const SWAP_FEE = 2_500_000n; // 0.5% (50bps) of 0.5 SOL
  const feeBps = 50; // 0.5%

  // Deposited note references
  let solDepositNoteId: string | null = null;
  let usdtFromSwapNoteId: string | null = null;
  let solChangeNoteId: string | null = null;
  let solTransferredNoteId: string | null = null;

  // Serum vault signer (derived)
  let serumVaultSigner: PublicKey;

  // Shared lookup table for reuse
  let sharedLookupTableAddress: PublicKey | null = null;

  before(async () => {
    console.log("\n🔧 Setting up SOL/USDT AMM V4 swap test environment...\n");

    // Initialize Poseidon
    poseidon = await buildPoseidon();
    solOffchainTree = new OffchainMerkleTree(22, poseidon);
    usdtOffchainTree = new OffchainMerkleTree(22, poseidon);

    // Airdrop SOL for gas and deposits
    await airdropAndConfirm(provider, payer.publicKey, 10 * LAMPORTS_PER_SOL);

    // Use mainnet mints (cloned)
    solTokenMint = SOL_MINT;
    usdtTokenMint = USDT_MINT;

    // Get pool configuration - either static or dynamic
    if (USE_DYNAMIC_POOL_KEYS) {
      console.log("📡 Using DYNAMIC pool key fetching from Raydium SDK...");
      poolKeys = await getPoolKeysFromMints(
        provider.connection,
        tokenMintFor(solTokenMint),
        usdtTokenMint,
      );
      poolConfig = poolKeysToConfig(poolKeys);
      logPoolKeys(poolKeys);
    } else {
      console.log("📋 Using STATIC pool configuration...");
      poolConfig = getPoolConfig(POOL_NAME);
      logPoolConfig(POOL_NAME);
    }

    console.log(`\n✅ SOL Token (WSOL): ${solTokenMint.toBase58()}`);
    console.log(`✅ USDT Token: ${usdtTokenMint.toBase58()}`);
    console.log(`✅ AMM V4 Pool: ${poolConfig.poolId.toBase58()}`);

    // Derive Serum vault signer
    serumVaultSigner = deriveSerumVaultSigner(
      poolConfig.serumMarket,
      new BN(poolConfig.serumVaultSignerNonce),
    );
    console.log(`✅ Serum Vault Signer: ${serumVaultSigner.toBase58()}`);

    // Derive PDAs for SOL pool
    [solConfig] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_config_v3"), solTokenMint.toBuffer()],
      program.programId,
    );
    [solVault] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_vault_v3"), solTokenMint.toBuffer()],
      program.programId,
    );
    [solNoteTree] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("privacy_note_tree_v3"),
        solTokenMint.toBuffer(),
        encodeTreeId(0),
      ],
      program.programId,
    );
    [solNullifiers] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_nullifiers_v3"), solTokenMint.toBuffer()],
      program.programId,
    );
    solVaultTokenAccount = await getAssociatedTokenAddress(
      tokenMintFor(solTokenMint),
      solVault,
      true,
    );

    // Derive PDAs for USDT pool
    [usdtConfig] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_config_v3"), usdtTokenMint.toBuffer()],
      program.programId,
    );
    [usdtVault] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_vault_v3"), usdtTokenMint.toBuffer()],
      program.programId,
    );
    [usdtNoteTree] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("privacy_note_tree_v3"),
        usdtTokenMint.toBuffer(),
        encodeTreeId(0),
      ],
      program.programId,
    );
    [usdtNullifiers] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_nullifiers_v3"), usdtTokenMint.toBuffer()],
      program.programId,
    );
    usdtVaultTokenAccount = await getAssociatedTokenAddress(
      usdtTokenMint,
      usdtVault,
      true,
    );

    // Derive global config
    [globalConfig] = PublicKey.findProgramAddressSync(
      [Buffer.from("global_config_v1")],
      program.programId,
    );

    console.log("SOL Config PDA:", solConfig.toBase58());
    console.log("USDT Config PDA:", usdtConfig.toBase58());
  });

  it("initializes SOL privacy pool", async () => {
    try {
      await (program.methods as any)
        .initialize(
          feeBps,
          solTokenMint,
          new BN(1_000_000),
          new BN(1_000_000_000_000),
          new BN(1_000_000),
          new BN(1_000_000_000_000),
        )
        .accounts({
          config: solConfig,
          vault: solVault,
          noteTree: solNoteTree,
          nullifiers: solNullifiers,
          admin: payer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      console.log("✅ SOL pool initialized");
    } catch (e: any) {
      if (e.message?.includes("already in use")) {
        console.log("SOL pool already initialized");
      } else {
        throw e;
      }
    }
  });

  it("initializes USDT privacy pool", async () => {
    try {
      await (program.methods as any)
        .initialize(
          feeBps,
          usdtTokenMint,
          new BN(1_000_000),
          new BN(1_000_000_000_000),
          new BN(1_000_000),
          new BN(1_000_000_000_000),
        )
        .accounts({
          config: usdtConfig,
          vault: usdtVault,
          noteTree: usdtNoteTree,
          nullifiers: usdtNullifiers,
          admin: payer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      console.log("✅ USDT pool initialized");
    } catch (e: any) {
      if (e.message?.includes("already in use")) {
        console.log("USDT pool already initialized");
      } else {
        throw e;
      }
    }
  });

  it("configures USDT pool (50bps swap fees)", async () => {
    try {
      await (program.methods as any)
        .updatePoolConfig(
          usdtTokenMint,
          null,
          null,
          null,
          null,
          null,
          null,
          null,
          null, // min_swap_fee (keep default)
          new BN(50), // swap_fee_bps = 50 (0.5%)
        )
        .accounts({
          config: usdtConfig,
          admin: payer.publicKey,
        })
        .rpc();
      console.log("✅ USDT pool configured with 50bps swap fees");
    } catch (e: any) {
      console.error("Failed to update USDT pool config:", e);
      throw e;
    }
  });

  it("configures SOL pool (default withdrawal fees, 50bps swap fees)", async () => {
    try {
      await (program.methods as any)
        .updatePoolConfig(
          solTokenMint,
          null, // min_deposit
          null, // max_deposit
          null, // min_withdraw
          null, // max_withdraw
          null, // fee_bps
          null, // min_withdrawal_fee (keep default 1,000,000)
          null, // fee_error_margin_bps
          null, // min_swap_fee
          new BN(50), // swap_fee_bps = 50 (0.5%)
        )
        .accounts({
          config: solConfig,
          admin: payer.publicKey,
        })
        .rpc();
      console.log("✅ SOL pool configured with 50bps swap fees");
    } catch (e: any) {
      console.error("Failed to update SOL pool config:", e);
      throw e;
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

  it("registers relayer for SOL pool", async () => {
    try {
      await (program.methods as any)
        .addRelayer(solTokenMint, payer.publicKey)
        .accounts({ config: solConfig, admin: payer.publicKey })
        .rpc();
      console.log("✅ Relayer registered for SOL pool");
    } catch (e: any) {
      if (
        e.message?.includes("already added") ||
        e.message?.includes("RelayerAlreadyExists")
      ) {
        console.log("✅ Relayer already registered for SOL pool");
      } else {
        throw e;
      }
    }
  });

  it("registers relayer for USDT pool", async () => {
    try {
      await (program.methods as any)
        .addRelayer(usdtTokenMint, payer.publicKey)
        .accounts({ config: usdtConfig, admin: payer.publicKey })
        .rpc();
      console.log("✅ Relayer registered for USDT pool");
    } catch (e: any) {
      if (
        e.message?.includes("already added") ||
        e.message?.includes("RelayerAlreadyExists")
      ) {
        console.log("✅ Relayer already registered for USDT pool");
      } else {
        throw e;
      }
    }
  });

  it("deposits SOL to SOL pool for AMM swap", async () => {
    console.log("\n🎁 Depositing SOL to SOL pool...");

    // Native SOL: on-chain uses system_program::transfer, token accounts are unused
    const userTokenAccount = payer.publicKey;

    // Generate keypair for the note
    const privateKey = randomBytes32();
    const publicKey = derivePublicKey(poseidon, privateKey);
    const blinding = randomBytes32();
    const amount = BigInt(INITIAL_SOL_DEPOSIT);

    // Compute commitment
    const commitment = computeCommitment(
      poseidon,
      amount,
      publicKey,
      blinding,
      solTokenMint,
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
      solTokenMint,
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
      solTokenMint,
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
      solTokenMint,
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
    const dummyProof = solOffchainTree.getMerkleProof(0);
    const root = solOffchainTree.getRoot();

    // Generate proof
    const proof = await generateTransactionProof({
      root,
      publicAmount: amount,
      extDataHash,
      mintAddress: solTokenMint,
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
      solTokenMint,
      0,
      dummyNullifier1,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      solTokenMint,
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
        solTokenMint,
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
        config: solConfig,
        globalConfig,
        vault: solVault,
        inputTree: solNoteTree,
        outputTree: solNoteTree,
        nullifiers: solNullifiers,
        nullifierMarker0,
        nullifierMarker1,
        relayer: payer.publicKey,
        recipient: payer.publicKey,
        vaultTokenAccount: solVaultTokenAccount,
        userTokenAccount: userTokenAccount,
        recipientTokenAccount: userTokenAccount,
        relayerTokenAccount: userTokenAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
      ])
      .rpc();

    console.log(`✅ Deposit tx: ${tx}`);

    // Update off-chain tree
    const leafIndex = solOffchainTree.insert(commitment);
    solOffchainTree.insert(changeCommitment);

    // Save note
    solDepositNoteId = noteStorage.save({
      amount,
      commitment,
      nullifier: computeNullifier(poseidon, commitment, leafIndex, privateKey),
      blinding,
      privateKey,
      publicKey,
      leafIndex,
      merklePath: solOffchainTree.getMerkleProof(leafIndex),
      mintAddress: solTokenMint,
    });

    console.log(`   Note saved: ${solDepositNoteId}`);
    console.log(`   Amount: ${Number(amount) / 1e9} SOL`);
  });

  it("should build correct AMM V4 swap data for SOL/USDT", () => {
    const amountIn = new anchor.BN(500_000_000); // 0.5 SOL
    const minOut = new anchor.BN(50_000_000); // 50 USDT (conservative)

    const swapData = buildAmmSwapData(amountIn, minOut);

    expect(swapData.length).to.equal(17);
    expect(swapData[0]).to.equal(AMM_SWAP_BASE_IN_DISCRIMINATOR);

    const decodedAmountIn = swapData.readBigUInt64LE(1);
    const decodedMinOut = swapData.readBigUInt64LE(9);

    expect(decodedAmountIn.toString()).to.equal(amountIn.toString());
    expect(decodedMinOut.toString()).to.equal(minOut.toString());

    console.log("\n✅ AMM V4 swap data validated for SOL/USDT:");
    console.log(`   Instruction ID: ${swapData[0]} (swap_base_in)`);
    console.log(
      `   Amount In: ${decodedAmountIn} (${Number(decodedAmountIn) / 1e9} SOL)`,
    );
    console.log(
      `   Min Out: ${decodedMinOut} (${Number(decodedMinOut) / 1e6} USDT)`,
    );
  });

  it("verifies SOL/USDT AMM accounts are correctly configured", async () => {
    // Verify AMM pool state exists
    const poolInfo = await provider.connection.getAccountInfo(
      poolConfig.poolId,
    );
    expect(poolInfo).to.not.be.null;
    console.log("\n✅ AMM V4 Pool State verified:");
    console.log(`   Address: ${poolConfig.poolId.toBase58()}`);
    console.log(`   Owner: ${poolInfo!.owner.toBase58()}`);
    console.log(`   Data Length: ${poolInfo!.data.length}`);

    // Verify Serum market exists
    const marketInfo = await provider.connection.getAccountInfo(
      poolConfig.serumMarket,
    );
    expect(marketInfo).to.not.be.null;
    console.log("\n✅ Serum Market verified:");
    console.log(`   Address: ${poolConfig.serumMarket.toBase58()}`);
  });

  it("verifies deposited SOL note exists", async () => {
    expect(solDepositNoteId).to.not.be.null;
    const note = noteStorage.get(solDepositNoteId!);
    expect(note).to.not.be.undefined;
    expect(note!.amount).to.equal(BigInt(INITIAL_SOL_DEPOSIT));

    console.log("\n✅ Deposited SOL note verified:");
    console.log(
      `   Amount: ${note!.amount} lamports (${Number(note!.amount) / 1e9} SOL)`,
    );
    console.log(`   Leaf index: ${note!.leafIndex}`);
  });

  it("executes cross-pool swap (SOL → USDT via AMM V4)", async () => {
    console.log("\n🔄 Executing cross-pool swap SOL → USDT via AMM V4...");

    const note = noteStorage.get(solDepositNoteId!);
    if (!note) throw new Error("Note not found");

    console.log(`   Input note amount: ${note.amount} lamports`);
    console.log(`   Swap amount: ${SWAP_AMOUNT_SOL} lamports`);

    // Get merkle proof
    const merkleProof = solOffchainTree.getMerkleProof(note.leafIndex);
    const root = solOffchainTree.getRoot();

    // Dummy second input
    const dummyPrivKey = randomBytes32();
    const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
    const dummyBlinding = randomBytes32();
    const dummyCommitment = computeCommitment(
      poseidon,
      0n,
      dummyPubKey,
      dummyBlinding,
      solTokenMint,
    );
    const dummyNullifier = computeNullifier(
      poseidon,
      dummyCommitment,
      0,
      dummyPrivKey,
    );
    const dummyProof = solOffchainTree.getMerkleProof(0);

    // Output commitments
    const destPrivKey = randomBytes32();
    const destPubKey = derivePublicKey(poseidon, destPrivKey);
    const destBlinding = randomBytes32();
    const swappedAmount = 50_000_000n; // ~50 USDT (estimated)
    const destCommitment = computeCommitment(
      poseidon,
      swappedAmount,
      destPubKey,
      destBlinding,
      usdtTokenMint,
    );
    const destCommitmentForProof = computeCommitment(
      poseidon,
      0n,
      destPubKey,
      destBlinding,
      solTokenMint,
    );

    // Change note
    const changeAmount = note.amount - BigInt(SWAP_AMOUNT_SOL);
    const changePrivKey = randomBytes32();
    const changePubKey = derivePublicKey(poseidon, changePrivKey);
    const changeBlinding = randomBytes32();
    const changeCommitment = computeCommitment(
      poseidon,
      changeAmount,
      changePubKey,
      changeBlinding,
      solTokenMint,
    );

    // External data
    const extData = {
      recipient: payer.publicKey,
      relayer: payer.publicKey,
      fee: new BN(SWAP_FEE.toString()),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    // Build AMM swap data
    const minAmountOut = new BN(40_000_000); // 40 USDT min (conservative slippage)
    const swapData = buildAmmSwapData(new BN(SWAP_AMOUNT_SOL), minAmountOut);
    const deadline = new BN(Math.floor(Date.now() / 1000) + 3600);

    // Swap params
    const swapParams = {
      minAmountOut,
      deadline,
      sourceMint: solTokenMint,
      destMint: usdtTokenMint,
      swapDataHash: Buffer.alloc(32), // MEDIUM-001: zero for CPMM/AMM
    };

    const swapParamsHash = computeSwapParamsHash(
      poseidon,
      solTokenMint,
      usdtTokenMint,
      BigInt(minAmountOut.toString()),
      BigInt(deadline.toString()),
      new Uint8Array(32), // MEDIUM-001: zero for CPMM/AMM
    );

    // Generate ZK proof
    console.log("   Generating ZK proof...");
    const proof = await generateSwapProof({
      sourceRoot: root,
      swapParamsHash,
      extDataHash,
      sourceMint: solTokenMint,
      destMint: usdtTokenMint,
      inputNullifiers: [note.nullifier, dummyNullifier],
      changeCommitment,
      destCommitment,
      swapAmount: BigInt(SWAP_AMOUNT_SOL),

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

      minAmountOut: BigInt(minAmountOut.toString()),
      deadline: BigInt(deadline.toString()),
      swapDataHash: new Uint8Array(32), // MEDIUM-001: zero for CPMM/AMM
    });
    console.log("   ✅ ZK proof generated");

    // Derive executor PDA
    const [executorPda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("swap_executor"),
        solTokenMint.toBuffer(),
        usdtTokenMint.toBuffer(),
        Buffer.from(note.nullifier),
        payer.publicKey.toBuffer(),
      ],
      program.programId,
    );
    const executorSourceToken = await getAssociatedTokenAddress(
      tokenMintFor(solTokenMint),
      executorPda,
      true,
    );
    const executorDestToken = await getAssociatedTokenAddress(
      usdtTokenMint,
      executorPda,
      true,
    );

    // Nullifier markers
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      solTokenMint,
      0,
      note.nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      solTokenMint,
      0,
      dummyNullifier,
    );

    // Token accounts
    const solVaultAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      tokenMintFor(solTokenMint),
      solVault,
      true,
    );
    const usdtVaultAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      usdtTokenMint,
      usdtVault,
      true,
    );
    const relayerTokenAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      usdtTokenMint,
      payer.publicKey,
    );

    console.log("   Executor PDA:", executorPda.toBase58());

    // Create Address Lookup Table
    console.log("   Creating Address Lookup Table...");
    const recentSlot = await provider.connection.getSlot("finalized");

    const lookupTableAddresses = [
      solConfig,
      globalConfig,
      solVault,
      solNoteTree,
      solNullifiers,
      solVaultAccount.address,
      tokenMintFor(solTokenMint),
      usdtConfig,
      usdtVault,
      usdtNoteTree,
      usdtVaultAccount.address,
      usdtTokenMint,
      RAYDIUM_AMM_V4_PROGRAM,
      SERUM_PROGRAM,
      TOKEN_PROGRAM_ID,
      SystemProgram.programId,
      ASSOCIATED_TOKEN_PROGRAM_ID,
      poolConfig.poolId,
      AMM_AUTHORITY,
      poolConfig.ammOpenOrders,
      poolConfig.ammTargetOrders,
      poolConfig.ammBaseVault,
      poolConfig.ammQuoteVault,
      poolConfig.serumMarket,
      poolConfig.serumBids,
      poolConfig.serumAsks,
      poolConfig.serumEventQueue,
      poolConfig.serumBaseVault,
      poolConfig.serumQuoteVault,
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
      // Build swap instruction with AMM V4 remaining accounts
      const swapIx = await (program.methods as any)
        .transactSwap(
          proof,
          Array.from(root),
          0,
          solTokenMint,
          Array.from(note.nullifier),
          Array.from(dummyNullifier),
          0,
          usdtTokenMint,
          Array.from(changeCommitment),
          Array.from(destCommitment),
          swapParams,
          new BN(SWAP_AMOUNT_SOL.toString()),
          swapData,
          extData,
        )
        .accounts({
          sourceConfig: solConfig,
          globalConfig,
          sourceVault: solVault,
          sourceTree: solNoteTree,
          sourceNullifiers: solNullifiers,
          sourceNullifierMarker0: nullifierMarker0,
          sourceNullifierMarker1: nullifierMarker1,
          sourceVaultTokenAccount: solVaultAccount.address,
          sourceMintAccount: tokenMintFor(solTokenMint),
          destConfig: usdtConfig,
          destVault: usdtVault,
          destTree: usdtNoteTree,
          destVaultTokenAccount: usdtVaultAccount.address,
          destMintAccount: usdtTokenMint,
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
          { pubkey: poolConfig.poolId, isSigner: false, isWritable: true },
          { pubkey: AMM_AUTHORITY, isSigner: false, isWritable: false },
          {
            pubkey: poolConfig.ammOpenOrders,
            isSigner: false,
            isWritable: true,
          },
          {
            pubkey: poolConfig.ammTargetOrders,
            isSigner: false,
            isWritable: true,
          },
          {
            pubkey: poolConfig.ammBaseVault,
            isSigner: false,
            isWritable: true,
          },
          {
            pubkey: poolConfig.ammQuoteVault,
            isSigner: false,
            isWritable: true,
          },
          { pubkey: SERUM_PROGRAM, isSigner: false, isWritable: false },
          { pubkey: poolConfig.serumMarket, isSigner: false, isWritable: true },
          { pubkey: poolConfig.serumBids, isSigner: false, isWritable: true },
          { pubkey: poolConfig.serumAsks, isSigner: false, isWritable: true },
          {
            pubkey: poolConfig.serumEventQueue,
            isSigner: false,
            isWritable: true,
          },
          {
            pubkey: poolConfig.serumBaseVault,
            isSigner: false,
            isWritable: true,
          },
          {
            pubkey: poolConfig.serumQuoteVault,
            isSigner: false,
            isWritable: true,
          },
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

      console.log(`✅ AMM V4 swap (SOL → USDT) executed: ${txSig}`);

      // Verify balances changed
      const usdtVaultBalance = await provider.connection.getTokenAccountBalance(
        usdtVaultAccount.address,
      );
      console.log(
        `   USDT vault balance: ${usdtVaultBalance.value.uiAmountString}`,
      );

      // Save the USDT note from swap output
      const usdtLeafIndex = usdtOffchainTree.insert(destCommitment);
      usdtFromSwapNoteId = noteStorage.save({
        amount: swappedAmount,
        commitment: destCommitment,
        nullifier: computeNullifier(
          poseidon,
          destCommitment,
          usdtLeafIndex,
          destPrivKey,
        ),
        blinding: destBlinding,
        privateKey: destPrivKey,
        publicKey: destPubKey,
        leafIndex: usdtLeafIndex,
        merklePath: usdtOffchainTree.getMerkleProof(usdtLeafIndex),
        mintAddress: usdtTokenMint,
      });
      console.log(
        `   USDT note saved: ${usdtFromSwapNoteId} (${swappedAmount} units = ${
          Number(swappedAmount) / 1e6
        } USDT)`,
      );

      // Save the SOL change note
      const solChangeLeafIndex = solOffchainTree.insert(changeCommitment);
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
        merklePath: solOffchainTree.getMerkleProof(solChangeLeafIndex),
        mintAddress: solTokenMint,
      });
      console.log(
        `   SOL change note saved: ${solChangeNoteId} (${changeAmount} lamports = ${
          Number(changeAmount) / 1e9
        } SOL)`,
      );

      // Save lookup table for reuse
      sharedLookupTableAddress = lookupTableAddress;
    } catch (e: any) {
      if (e instanceof SendTransactionError) {
        const logs = await e.getLogs(provider.connection);
        console.error("\n❌ Transaction failed. Logs:");
        logs?.forEach((log: string) => console.error(`   ${log}`));
      }
      throw e;
    }
  });

  it("verifies USDT note from SOL swap exists", async () => {
    expect(usdtFromSwapNoteId).to.not.be.null;
    const note = noteStorage.get(usdtFromSwapNoteId!);
    expect(note).to.not.be.undefined;

    console.log("\n✅ USDT note from swap verified:");
    console.log(
      `   Amount: ${note!.amount} (${Number(note!.amount) / 1e6} USDT)`,
    );
    console.log(`   Leaf index: ${note!.leafIndex}`);
    console.log(`   Mint: ${note!.mintAddress?.toBase58() ?? "N/A"}`);
  });

  it("verifies SOL change note from swap exists", async () => {
    expect(solChangeNoteId).to.not.be.null;
    const note = noteStorage.get(solChangeNoteId!);
    expect(note).to.not.be.undefined;

    console.log("\n✅ SOL change note from swap verified:");
    console.log(
      `   Amount: ${note!.amount} lamports (${Number(note!.amount) / 1e9} SOL)`,
    );
    console.log(`   Leaf index: ${note!.leafIndex}`);
  });

  // Internal transfer tests for USDT (like USDC tests in the original file)
  it("executes internal USDT transfer", async () => {
    console.log("\n📤 Executing internal USDT transfer...");

    const note = noteStorage.get(usdtFromSwapNoteId!);
    if (!note) throw new Error("USDT note not found");

    // Get merkle proof
    const merkleProof = usdtOffchainTree.getMerkleProof(note.leafIndex);
    const root = usdtOffchainTree.getRoot();

    // Dummy second input
    const dummyPrivKey = randomBytes32();
    const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
    const dummyBlinding = randomBytes32();
    const dummyCommitment = computeCommitment(
      poseidon,
      0n,
      dummyPubKey,
      dummyBlinding,
      usdtTokenMint,
    );
    const dummyNullifier = computeNullifier(
      poseidon,
      dummyCommitment,
      0,
      dummyPrivKey,
    );
    const dummyProof = usdtOffchainTree.getMerkleProof(0);

    // Transfer to new owner
    const newPrivKey = randomBytes32();
    const newPubKey = derivePublicKey(poseidon, newPrivKey);
    const newBlinding = randomBytes32();
    const newCommitment = computeCommitment(
      poseidon,
      note.amount,
      newPubKey,
      newBlinding,
      usdtTokenMint,
    );

    // Zero change output
    const changePrivKey = randomBytes32();
    const changePubKey = derivePublicKey(poseidon, changePrivKey);
    const changeBlinding = randomBytes32();
    const changeCommitment = computeCommitment(
      poseidon,
      0n,
      changePubKey,
      changeBlinding,
      usdtTokenMint,
    );

    // External data (no public amount for transfer)
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
      publicAmount: 0n,
      extDataHash,
      mintAddress: usdtTokenMint,
      inputNullifiers: [note.nullifier, dummyNullifier],
      outputCommitments: [newCommitment, changeCommitment],
      inputAmounts: [note.amount, 0n],
      inputPrivateKeys: [note.privateKey, dummyPrivKey],
      inputPublicKeys: [note.publicKey, dummyPubKey],
      inputBlindings: [note.blinding, dummyBlinding],
      inputMerklePaths: [merkleProof, dummyProof],
      outputAmounts: [note.amount, 0n],
      outputOwners: [newPubKey, changePubKey],
      outputBlindings: [newBlinding, changeBlinding],
    });

    // Derive nullifier marker PDAs
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      usdtTokenMint,
      0,
      note.nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      usdtTokenMint,
      0,
      dummyNullifier,
    );

    const usdtVaultAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      usdtTokenMint,
      usdtVault,
      true,
    );

    // Execute transfer
    const tx = await (program.methods as any)
      .transact(
        Array.from(root),
        0,
        0,
        new BN(0),
        Array.from(extDataHash),
        usdtTokenMint,
        Array.from(note.nullifier),
        Array.from(dummyNullifier),
        Array.from(newCommitment),
        Array.from(changeCommitment),
        new BN(9999999999), // deadline (far future for tests)
        extData,
        proof,
      )
      .accounts({
        config: usdtConfig,
        globalConfig,
        vault: usdtVault,
        inputTree: usdtNoteTree,
        outputTree: usdtNoteTree,
        nullifiers: usdtNullifiers,
        nullifierMarker0,
        nullifierMarker1,
        relayer: payer.publicKey,
        recipient: payer.publicKey,
        vaultTokenAccount: usdtVaultAccount.address,
        userTokenAccount: usdtVaultAccount.address,
        recipientTokenAccount: usdtVaultAccount.address,
        relayerTokenAccount: usdtVaultAccount.address,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
      ])
      .rpc();

    console.log(`✅ Internal USDT transfer: ${tx}`);

    // Update off-chain tree
    const leafIndex = usdtOffchainTree.insert(newCommitment);
    usdtOffchainTree.insert(changeCommitment);

    // Save transferred note
    const transferredNoteId = noteStorage.save({
      amount: note.amount,
      commitment: newCommitment,
      nullifier: computeNullifier(
        poseidon,
        newCommitment,
        leafIndex,
        newPrivKey,
      ),
      blinding: newBlinding,
      privateKey: newPrivKey,
      publicKey: newPubKey,
      leafIndex,
      merklePath: usdtOffchainTree.getMerkleProof(leafIndex),
      mintAddress: usdtTokenMint,
    });

    console.log(`   Transferred USDT note: ${transferredNoteId}`);
    console.log(`   Amount: ${Number(note.amount) / 1e6} USDT`);
  });

  it("executes internal SOL transfer", async () => {
    console.log("\n📤 Executing internal SOL transfer...");

    const note = noteStorage.get(solChangeNoteId!);
    if (!note) throw new Error("SOL change note not found");

    // Get merkle proof
    const merkleProof = solOffchainTree.getMerkleProof(note.leafIndex);
    const root = solOffchainTree.getRoot();

    // Dummy second input
    const dummyPrivKey = randomBytes32();
    const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
    const dummyBlinding = randomBytes32();
    const dummyCommitment = computeCommitment(
      poseidon,
      0n,
      dummyPubKey,
      dummyBlinding,
      solTokenMint,
    );
    const dummyNullifier = computeNullifier(
      poseidon,
      dummyCommitment,
      0,
      dummyPrivKey,
    );
    const dummyProof = solOffchainTree.getMerkleProof(0);

    // Transfer to new owner
    const newPrivKey = randomBytes32();
    const newPubKey = derivePublicKey(poseidon, newPrivKey);
    const newBlinding = randomBytes32();
    const newCommitment = computeCommitment(
      poseidon,
      note.amount,
      newPubKey,
      newBlinding,
      solTokenMint,
    );

    // Zero change output
    const changePrivKey = randomBytes32();
    const changePubKey = derivePublicKey(poseidon, changePrivKey);
    const changeBlinding = randomBytes32();
    const changeCommitment = computeCommitment(
      poseidon,
      0n,
      changePubKey,
      changeBlinding,
      solTokenMint,
    );

    // External data
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
      publicAmount: 0n,
      extDataHash,
      mintAddress: solTokenMint,
      inputNullifiers: [note.nullifier, dummyNullifier],
      outputCommitments: [newCommitment, changeCommitment],
      inputAmounts: [note.amount, 0n],
      inputPrivateKeys: [note.privateKey, dummyPrivKey],
      inputPublicKeys: [note.publicKey, dummyPubKey],
      inputBlindings: [note.blinding, dummyBlinding],
      inputMerklePaths: [merkleProof, dummyProof],
      outputAmounts: [note.amount, 0n],
      outputOwners: [newPubKey, changePubKey],
      outputBlindings: [newBlinding, changeBlinding],
    });

    // Derive nullifier marker PDAs
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      solTokenMint,
      0,
      note.nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      solTokenMint,
      0,
      dummyNullifier,
    );

    // Execute transfer
    const tx = await (program.methods as any)
      .transact(
        Array.from(root),
        0,
        0,
        new BN(0),
        Array.from(extDataHash),
        solTokenMint,
        Array.from(note.nullifier),
        Array.from(dummyNullifier),
        Array.from(newCommitment),
        Array.from(changeCommitment),
        new BN(9999999999), // deadline (far future for tests)
        extData,
        proof,
      )
      .accounts({
        config: solConfig,
        globalConfig,
        vault: solVault,
        inputTree: solNoteTree,
        outputTree: solNoteTree,
        nullifiers: solNullifiers,
        nullifierMarker0,
        nullifierMarker1,
        relayer: payer.publicKey,
        recipient: payer.publicKey,
        vaultTokenAccount: solVaultTokenAccount,
        userTokenAccount: solVaultTokenAccount,
        recipientTokenAccount: solVaultTokenAccount,
        relayerTokenAccount: solVaultTokenAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
      ])
      .rpc();

    console.log(`✅ Internal SOL transfer: ${tx}`);

    // Update off-chain tree
    const leafIndex = solOffchainTree.insert(newCommitment);
    solOffchainTree.insert(changeCommitment);

    // Save transferred note
    const transferredNoteId = noteStorage.save({
      amount: note.amount,
      commitment: newCommitment,
      nullifier: computeNullifier(
        poseidon,
        newCommitment,
        leafIndex,
        newPrivKey,
      ),
      blinding: newBlinding,
      privateKey: newPrivKey,
      publicKey: newPubKey,
      leafIndex,
      merklePath: solOffchainTree.getMerkleProof(leafIndex),
      mintAddress: solTokenMint,
    });
    solTransferredNoteId = transferredNoteId; // Save for next test step

    console.log(`   Transferred SOL note: ${transferredNoteId}`);
    console.log(`   Amount: ${Number(note.amount) / 1e9} SOL`);
  });

  it("executes external SOL withdrawal", async () => {
    console.log("\n💸 Executing external SOL withdrawal...");

    // Use the note from internal transfer
    const note = noteStorage.get(solTransferredNoteId!);
    if (!note) throw new Error("SOL transferred note not found");

    console.log(
      `   Withdrawing ${Number(note.amount) / 1e9} SOL to external wallet`,
    );

    // Create external recipient
    const externalRecipient = Keypair.generate();

    // Native SOL: use wallet address for token accounts
    const externalWsolAccount = externalRecipient.publicKey;

    // Take balance snapshot before withdrawal
    const balanceBefore = await getBalanceSnapshot(
      provider.connection,
      externalRecipient.publicKey,
      externalWsolAccount,
      undefined,
      await getAssociatedTokenAddress(
        tokenMintFor(solTokenMint),
        solVault,
        true,
      ),
      undefined,
      undefined,
    );

    // Get merkle proof
    const merkleProof = solOffchainTree.getMerkleProof(note.leafIndex);
    const root = solOffchainTree.getRoot();

    // Dummy second input
    const dummyPrivKey = randomBytes32();
    const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
    const dummyBlinding = randomBytes32();
    const dummyCommitment = computeCommitment(
      poseidon,
      0n,
      dummyPubKey,
      dummyBlinding,
      solTokenMint,
    );
    const dummyNullifier = computeNullifier(
      poseidon,
      dummyCommitment,
      0,
      dummyPrivKey,
    );
    const dummyProof = solOffchainTree.getMerkleProof(0);

    // Zero change outputs
    const changePrivKey1 = randomBytes32();
    const changePubKey1 = derivePublicKey(poseidon, changePrivKey1);
    const changeBlinding1 = randomBytes32();
    const changeCommitment1 = computeCommitment(
      poseidon,
      0n,
      changePubKey1,
      changeBlinding1,
      solTokenMint,
    );

    const changePrivKey2 = randomBytes32();
    const changePubKey2 = derivePublicKey(poseidon, changePrivKey2);
    const changeBlinding2 = randomBytes32();
    const changeCommitment2 = computeCommitment(
      poseidon,
      0n,
      changePubKey2,
      changeBlinding2,
      solTokenMint,
    );

    // External data for withdrawal
    // Fee = 0.5% (50bps) of 1.5 SOL = 7,500,000 lamports
    const fee = new BN(7_500_000);
    const extData = {
      recipient: externalRecipient.publicKey,
      relayer: payer.publicKey,
      fee: fee,
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    // Generate ZK proof for withdrawal
    const proof = await generateTransactionProof({
      root,
      publicAmount: -note.amount, // Negative for withdrawal
      extDataHash,
      mintAddress: solTokenMint,
      inputNullifiers: [note.nullifier, dummyNullifier],
      outputCommitments: [changeCommitment1, changeCommitment2],
      inputAmounts: [note.amount, 0n],
      inputPrivateKeys: [note.privateKey, dummyPrivKey],
      inputPublicKeys: [note.publicKey, dummyPubKey],
      inputBlindings: [note.blinding, dummyBlinding],
      inputMerklePaths: [merkleProof, dummyProof],
      outputAmounts: [0n, 0n],
      outputOwners: [changePubKey1, changePubKey2],
      outputBlindings: [changeBlinding1, changeBlinding2],
    });

    // Derive nullifier marker PDAs
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      solTokenMint,
      0,
      note.nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      solTokenMint,
      0,
      dummyNullifier,
    );

    // Create token account for relayer
    const relayerWsolAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      tokenMintFor(solTokenMint),
      payer.publicKey,
    );

    // Execute withdrawal
    const tx = await (program.methods as any)
      .transact(
        Array.from(root),
        0,
        0,
        new BN(note.amount.toString()).neg(),
        Array.from(extDataHash),
        solTokenMint,
        Array.from(note.nullifier),
        Array.from(dummyNullifier),
        Array.from(changeCommitment1),
        Array.from(changeCommitment2),
        new BN(9999999999), // deadline (far future for tests)
        extData,
        proof,
      )
      .accounts({
        config: solConfig,
        globalConfig,
        vault: solVault,
        inputTree: solNoteTree,
        outputTree: solNoteTree,
        nullifiers: solNullifiers,
        nullifierMarker0,
        nullifierMarker1,
        relayer: payer.publicKey,
        recipient: externalRecipient.publicKey,
        vaultTokenAccount: solVaultTokenAccount,
        userTokenAccount: externalWsolAccount,
        recipientTokenAccount: externalWsolAccount,
        relayerTokenAccount: relayerWsolAccount.address,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
      ])
      .rpc();

    console.log(`✅ External SOL withdrawal: ${tx}`);

    // Take balance snapshot after withdrawal
    const balanceAfter = await getBalanceSnapshot(
      provider.connection,
      externalRecipient.publicKey,
      externalWsolAccount,
      undefined,
      await getAssociatedTokenAddress(
        tokenMintFor(solTokenMint),
        solVault,
        true,
      ),
      undefined,
      undefined,
    );

    // Log balance changes
    const wsolIncrease =
      (balanceAfter.userWsol || 0) - (balanceBefore.userWsol || 0);
    const vaultDecrease =
      (balanceBefore.solVault || 0) - (balanceAfter.solVault || 0);

    console.log(`📊 Withdrawal Results:`);
    console.log(
      `   External WSOL increased by: ${wsolIncrease.toFixed(6)} WSOL`,
    );
    console.log(`   SOL Vault decreased by: ${vaultDecrease.toFixed(6)} SOL`);

    // Verify withdrawal worked
    expect(wsolIncrease).to.be.greaterThan(
      0,
      "External wallet should receive WSOL",
    );
    expect(vaultDecrease).to.be.greaterThan(0, "SOL vault should decrease");

    // Update off-chain tree
    solOffchainTree.insert(changeCommitment1);
    solOffchainTree.insert(changeCommitment2);

    console.log(
      `   ✅ Successfully withdrew ${wsolIncrease.toFixed(
        6,
      )} SOL to external wallet`,
    );
  });
});

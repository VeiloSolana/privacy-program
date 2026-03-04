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
  USD1_MINT,
  getPoolConfig,
  buildAmmSwapData,
  deriveSerumVaultSigner,
  getSwapVaults,
  logPoolConfig,
  logPoolKeys,
  PoolName,
  AmmV4PoolConfig,
  getPoolKeysFromMints,
  poolKeysToConfig,
} from "./amm-v4-pool-helper";
import {
  Liquidity,
  LiquidityPoolKeysV4,
  Token as RaydiumToken,
  TokenAmount,
  Percent,
} from "@raydium-io/raydium-sdk";

// Balance tracking interfaces and helpers
interface BalanceSnapshot {
  userSol: number;
  userWsol?: number;
  userUsd1?: number;
  solVault?: number;
  usd1Vault?: number;
  poolBaseLiquidity?: number;
  poolQuoteLiquidity?: number;
  relayerSol: number;
  relayerUsd1?: number;
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
  userUsd1Account?: PublicKey,
  solVaultAccount?: PublicKey,
  usd1VaultAccount?: PublicKey,
  relayerUsd1Account?: PublicKey,
): Promise<BalanceSnapshot> {
  const [
    userSol,
    userWsol,
    userUsd1,
    solVault,
    usd1Vault,
    relayerSol,
    relayerUsd1,
  ] = await Promise.all([
    getSolBalance(connection, userPubkey),
    userWsolAccount
      ? getTokenBalance(connection, userWsolAccount)
      : Promise.resolve(undefined),
    userUsd1Account
      ? getTokenBalance(connection, userUsd1Account)
      : Promise.resolve(undefined),
    solVaultAccount
      ? getTokenBalance(connection, solVaultAccount)
      : Promise.resolve(undefined),
    usd1VaultAccount
      ? getTokenBalance(connection, usd1VaultAccount)
      : Promise.resolve(undefined),
    getSolBalance(connection, userPubkey), // relayer is same as user in tests
    relayerUsd1Account
      ? getTokenBalance(connection, relayerUsd1Account)
      : Promise.resolve(undefined),
  ]);

  return {
    userSol,
    userWsol,
    userUsd1,
    solVault,
    usd1Vault,
    relayerSol,
    relayerUsd1,
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
    before.userUsd1 !== after.userUsd1 &&
    (before.userUsd1 || after.userUsd1)
  ) {
    const beforeVal = before.userUsd1 || 0;
    const afterVal = after.userUsd1 || 0;
    const diff = afterVal - beforeVal;
    console.log(
      `   User USD1: ${beforeVal.toFixed(6)} → ${afterVal.toFixed(6)} (${
        diff >= 0 ? "+" : ""
      }${diff.toFixed(6)} USD1)`,
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
    before.usd1Vault !== after.usd1Vault &&
    (before.usd1Vault || after.usd1Vault)
  ) {
    const beforeVal = before.usd1Vault || 0;
    const afterVal = after.usd1Vault || 0;
    const diff = afterVal - beforeVal;
    console.log(
      `   USD1 Vault: ${beforeVal.toFixed(6)} → ${afterVal.toFixed(6)} (${
        diff >= 0 ? "+" : ""
      }${diff.toFixed(6)} USD1)`,
    );
  }

  if (
    before.relayerUsd1 !== after.relayerUsd1 &&
    (before.relayerUsd1 || after.relayerUsd1)
  ) {
    const beforeVal = before.relayerUsd1 || 0;
    const afterVal = after.relayerUsd1 || 0;
    const diff = afterVal - beforeVal;
    console.log(
      `   Relayer USD1: ${beforeVal.toFixed(6)} → ${afterVal.toFixed(6)} (${
        diff >= 0 ? "+" : ""
      }${diff.toFixed(6)} USD1)`,
    );
  }
}

/**
 * Privacy Pool Cross-Pool Swap Tests using Raydium AMM V4 - SOL/USD1
 *
 * Tests bidirectional swaps between SOL and USD1:
 * 1. SOL → USD1: Consumes SOL notes, swaps via AMM V4, creates USD1 notes
 * 2. USD1 → SOL: Consumes USD1 notes, swaps via AMM V4, creates SOL notes
 *
 * Uses cloned mainnet Raydium AMM V4 USD1/SOL pool for testing.
 */

// Get pool configuration - can use static or dynamic
const POOL_NAME: PoolName = "SOL-USD1";
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

describe("Privacy Pool AMM V4 Swap - SOL/USD1", () => {
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

  // Destination pool (USD1)
  let usd1TokenMint: PublicKey;
  let usd1Config: PublicKey;
  let usd1Vault: PublicKey;
  let usd1NoteTree: PublicKey;
  let usd1Nullifiers: PublicKey;
  let usd1VaultTokenAccount: PublicKey;

  // Global config
  let globalConfig: PublicKey;

  // Off-chain Merkle trees
  let solOffchainTree: OffchainMerkleTree;
  let usd1OffchainTree: OffchainMerkleTree;

  // Note storage
  const noteStorage = new InMemoryNoteStorage();

  // Test constants
  const SOURCE_DECIMALS = 9; // WSOL
  const DEST_DECIMALS = 6; // USD1
  const INITIAL_DEPOSIT = 2_000_000_000; // 2 SOL
  const SWAP_AMOUNT = 500_000_000; // 0.5 SOL
  const SWAP_FEE = 100_000n; // 0.1 USD1 relayer fee
  const feeBps = 50; // 0.5%

  // Deposited note references
  let solDepositNoteId: string | null = null;

  // Notes from swap results
  let usd1NoteId: string | null = null;
  let solChangeNoteId: string | null = null;
  let usd1ChangeNoteId: string | null = null;
  let transferredNoteId: string | null = null;
  let usd1KeepNoteId: string | null = null; // Keep note from USD1 split
  let solFromUsd1NoteId: string | null = null;

  // Serum vault signer (derived)
  let serumVaultSigner: PublicKey;

  // Shared lookup table for reuse
  let sharedLookupTableAddress: PublicKey | null = null;

  before(async () => {
    console.log("\n🔧 Setting up SOL/USD1 AMM V4 swap test environment...\n");

    // Initialize Poseidon
    poseidon = await buildPoseidon();
    solOffchainTree = new OffchainMerkleTree(22, poseidon);
    usd1OffchainTree = new OffchainMerkleTree(22, poseidon);

    // Airdrop SOL for gas and deposits
    await airdropAndConfirm(provider, payer.publicKey, 10 * LAMPORTS_PER_SOL);

    // Use mainnet mints (cloned)
    solTokenMint = WSOL_MINT;
    usd1TokenMint = USD1_MINT;

    // Get pool configuration - either static or dynamic
    if (USE_DYNAMIC_POOL_KEYS) {
      console.log("📡 Using DYNAMIC pool key fetching from Raydium SDK...");
      poolKeys = await getPoolKeysFromMints(
        provider.connection,
        solTokenMint,
        usd1TokenMint,
      );
      poolConfig = poolKeysToConfig(poolKeys);
      logPoolKeys(poolKeys);
    } else {
      console.log("📋 Using STATIC pool configuration...");
      poolConfig = getPoolConfig(POOL_NAME);
      logPoolConfig(POOL_NAME);
    }

    console.log(`\n✅ SOL Token (WSOL): ${solTokenMint.toBase58()}`);
    console.log(`✅ USD1 Token: ${usd1TokenMint.toBase58()}`);
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
      solTokenMint,
      solVault,
      true,
    );

    // Derive PDAs for USD1 pool
    [usd1Config] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_config_v3"), usd1TokenMint.toBuffer()],
      program.programId,
    );
    [usd1Vault] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_vault_v3"), usd1TokenMint.toBuffer()],
      program.programId,
    );
    [usd1NoteTree] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("privacy_note_tree_v3"),
        usd1TokenMint.toBuffer(),
        encodeTreeId(0),
      ],
      program.programId,
    );
    [usd1Nullifiers] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_nullifiers_v3"), usd1TokenMint.toBuffer()],
      program.programId,
    );
    usd1VaultTokenAccount = await getAssociatedTokenAddress(
      usd1TokenMint,
      usd1Vault,
      true,
    );

    // Derive global config
    [globalConfig] = PublicKey.findProgramAddressSync(
      [Buffer.from("global_config_v1")],
      program.programId,
    );
  });

  it("initializes SOL privacy pool", async () => {
    try {
      await (program.methods as any)
        .initialize(
          feeBps,
          solTokenMint,
          new BN(0),
          new BN(1_000_000_000_000),
          new BN(0),
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

  it("initializes USD1 privacy pool", async () => {
    try {
      await (program.methods as any)
        .initialize(
          feeBps,
          usd1TokenMint,
          new BN(0),
          new BN(100_000_000_000),
          new BN(0),
          new BN(100_000_000_000),
        )
        .accounts({
          config: usd1Config,
          vault: usd1Vault,
          noteTree: usd1NoteTree,
          nullifiers: usd1Nullifiers,
          admin: payer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      console.log("✅ USD1 pool initialized");
    } catch (e: any) {
      if (e.message?.includes("already in use")) {
        console.log("USD1 pool already initialized");
      } else {
        throw e;
      }
    }
  });

  it("configures USD1 pool for testing (low fees for $5 withdrawals)", async () => {
    try {
      await (program.methods as any)
        .updatePoolConfig(
          usd1TokenMint,
          new BN(1_000_000), // min_deposit_amount = 1 USD1 ($1 minimum deposit)
          null,
          new BN(5_000_000), // min_withdraw_amount = 5 USD1 ($5 minimum withdrawal)
          null,
          new BN(50), // fee_bps = 50 (0.5% fee)
          new BN(25_000), // min_withdrawal_fee = 0.025 USD1 (0.5% of $5 = $0.025)
          null,
          new BN(0), // min_swap_fee = 0
          new BN(0), // swap_fee_bps = 0
        )
        .accounts({
          config: usd1Config,
          admin: payer.publicKey,
        })
        .rpc();
      console.log(
        "✅ USD1 pool configured with 0.5% fee supporting $5 minimum withdrawals",
      );
    } catch (e: any) {
      console.error("Failed to update USD1 pool config:", e);
      throw e;
    }
  });

  it("initializes global config", async () => {
    try {
      try {
        await (program.account as any).globalConfig.fetch(globalConfig);
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
      if (e instanceof SendTransactionError)
        console.error("Global config init failed", e);
      throw e;
    }
  });

  it("registers relayer for source pool", async () => {
    try {
      await (program.methods as any)
        .addRelayer(solTokenMint, payer.publicKey)
        .accounts({ config: solConfig, admin: payer.publicKey })
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

  it("registers relayer for dest pool", async () => {
    try {
      await (program.methods as any)
        .addRelayer(usd1TokenMint, payer.publicKey)
        .accounts({ config: usd1Config, admin: payer.publicKey })
        .rpc();
      console.log("✅ Relayer registered for dest pool (USD1)");
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

  it("deposits WSOL to source pool for AMM swap", async () => {
    console.log("\n🎁 Depositing WSOL to source pool...");

    // Create required accounts first
    await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      solTokenMint,
      solVault,
      true,
    );
    const wsolAccount = await createWrappedNativeAccount(
      provider.connection,
      payer,
      payer.publicKey,
      INITIAL_DEPOSIT * 2,
    );
    const depositSolVaultAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      solTokenMint,
      solVault,
      true,
    );

    // Take balance snapshot before deposit
    const balanceBefore = await getBalanceSnapshot(
      provider.connection,
      payer.publicKey,
      wsolAccount,
      undefined,
      depositSolVaultAccount.address,
      undefined,
      undefined,
    );
    console.log(
      `💰 Pre-deposit balances: User SOL: ${balanceBefore.userSol.toFixed(
        6,
      )}, User WSOL: ${(balanceBefore.userWsol || 0).toFixed(6)}, SOL Vault: ${(
        balanceBefore.solVault || 0
      ).toFixed(6)}`,
    );

    const privateKey = randomBytes32();
    const publicKey = derivePublicKey(poseidon, privateKey);
    const blinding = randomBytes32();
    const amount = BigInt(INITIAL_DEPOSIT);
    const commitment = computeCommitment(
      poseidon,
      amount,
      publicKey,
      blinding,
      solTokenMint,
    );

    // Dummy inputs
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
    const extDataHash = computeExtDataHash(poseidon, {
      recipient: payer.publicKey,
      relayer: payer.publicKey,
      fee: new BN(0),
      refund: new BN(0),
    });

    const root = solOffchainTree.getRoot();
    const dummyProof = solOffchainTree.getMerkleProof(0);
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

    const nm0 = deriveNullifierMarkerPDA(
      program.programId,
      solTokenMint,
      0,
      dummyNullifier1,
    );
    const nm1 = deriveNullifierMarkerPDA(
      program.programId,
      solTokenMint,
      0,
      dummyNullifier2,
    );

    await (program.methods as any)
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
          recipient: payer.publicKey,
          relayer: payer.publicKey,
          fee: new BN(0),
          refund: new BN(0),
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
        nullifierMarker0: nm0,
        nullifierMarker1: nm1,
        relayer: payer.publicKey,
        recipient: payer.publicKey,
        vaultTokenAccount: solVaultTokenAccount,
        userTokenAccount: wsolAccount,
        recipientTokenAccount: wsolAccount,
        relayerTokenAccount: wsolAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: 1_000_000 }),
      ])
      .rpc();

    const leafIndex = solOffchainTree.insert(commitment);
    solOffchainTree.insert(changeCommitment);

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

    // Take balance snapshot after deposit
    const balanceAfter = await getBalanceSnapshot(
      provider.connection,
      payer.publicKey,
      wsolAccount,
      undefined,
      depositSolVaultAccount.address,
      undefined,
      undefined,
    );

    // Log balance changes
    logBalanceChanges(balanceBefore, balanceAfter, "WSOL Deposit");

    // Verify expected balance changes
    const expectedDeposit = Number(amount) / LAMPORTS_PER_SOL;
    const actualVaultIncrease =
      (balanceAfter.solVault || 0) - (balanceBefore.solVault || 0);
    expect(Math.abs(actualVaultIncrease - expectedDeposit)).to.be.lessThan(
      0.001,
    );
    console.log(
      `✅ Vault balance increased by ${actualVaultIncrease.toFixed(
        6,
      )} SOL (expected: ${expectedDeposit.toFixed(6)} SOL)`,
    );
  });

  it("should build correct AMM V4 swap data", () => {
    const amountIn = new anchor.BN(SWAP_AMOUNT);
    const minOut = new anchor.BN(50_000_000); // 50 USD1 (conservative)

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
      `   Min Out: ${decodedMinOut} (${Number(decodedMinOut) / 1e6} USD1)`,
    );
  });

  it("verifies AMM accounts are correctly configured", async () => {
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

  it("verifies deposited note exists", async () => {
    expect(solDepositNoteId).to.not.be.null;
    const note = noteStorage.get(solDepositNoteId!);
    expect(note).to.not.be.undefined;
    expect(note!.amount).to.equal(BigInt(INITIAL_DEPOSIT));

    console.log("\n✅ Deposited note verified:");
    console.log(
      `   Amount: ${note!.amount} lamports (${Number(note!.amount) / 1e9} SOL)`,
    );
    console.log(`   Leaf index: ${note!.leafIndex}`);
  });

  it("executes cross-pool swap (SOL → USD1 via AMM V4)", async () => {
    console.log("\n🔄 Executing cross-pool swap SOL → USD1 via AMM V4...");

    const note = noteStorage.get(solDepositNoteId!);
    if (!note) throw new Error("Note not found");

    // Get token accounts for balance tracking
    const swapSolVaultAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      solTokenMint,
      solVault,
      true,
    );
    const swapUsd1VaultAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      usd1TokenMint,
      usd1Vault,
      true,
    );
    const relayerUsd1Account = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      usd1TokenMint,
      payer.publicKey,
    );

    // Take balance snapshot before swap
    const balanceBefore = await getBalanceSnapshot(
      provider.connection,
      payer.publicKey,
      undefined,
      undefined,
      swapSolVaultAccount.address,
      swapUsd1VaultAccount.address,
      relayerUsd1Account.address,
    );
    console.log(
      `💰 Pre-swap balances: SOL Vault: ${(balanceBefore.solVault || 0).toFixed(
        6,
      )}, USD1 Vault: ${(balanceBefore.usd1Vault || 0).toFixed(
        6,
      )}, User SOL: ${balanceBefore.userSol.toFixed(6)}`,
    );

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

    // --- Dynamic Fee Calculation ---
    if (!poolKeys) throw new Error("Pool keys not found");

    let poolInfo; // : LiquidityPoolInfo
    try {
      poolInfo = await Liquidity.fetchInfo({
        connection: provider.connection,
        poolKeys,
      });
    } catch (e) {
      console.warn(
        "⚠️ Liquidity.fetchInfo failed (RPC simulation error), using manual fallback...",
      );
      // Manual fetch of reserves
      const [baseBalance, quoteBalance] = await Promise.all([
        provider.connection.getTokenAccountBalance(poolKeys.baseVault),
        provider.connection.getTokenAccountBalance(poolKeys.quoteVault),
      ]);

      poolInfo = {
        status: new BN(6), // 6 = Enabled
        baseDecimals: poolKeys.baseDecimals,
        quoteDecimals: poolKeys.quoteDecimals,
        lpDecimals: poolKeys.lpDecimals,
        baseReserve: new BN(baseBalance.value.amount),
        quoteReserve: new BN(quoteBalance.value.amount),
        lpSupply: new BN(0),
        startTime: new BN(0),
      };
    }

    // Create Token objects for SDK
    const solToken = new RaydiumToken(
      TOKEN_PROGRAM_ID,
      solTokenMint,
      SOURCE_DECIMALS,
    );
    const usd1Token = new RaydiumToken(
      TOKEN_PROGRAM_ID,
      usd1TokenMint,
      DEST_DECIMALS,
    );

    const amountIn = new TokenAmount(solToken, SWAP_AMOUNT, false);
    // Using 10% slippage for SDK estimation - actual minAmountOut is overridden to 1 for test environment
    // const slippageTolerance = new Percent(5, 1000);

    console.log("Pool Info fetched2");

    const slippage = new Percent(5, 100);

    const { amountOut, minAmountOut: computedMinAmountOut } =
      Liquidity.computeAmountOut({
        poolKeys,
        poolInfo,
        amountIn,
        currencyOut: usd1Token,
        slippage,
      });

    console.log(`Pool Info: Amount In: ${amountIn.toExact()} SOL`);
    console.log(`Pool Info: Estimated Out: ${amountOut.toExact()} USD1`);
    console.log(
      `Pool Info: Min Amount Out: ${computedMinAmountOut.toExact()} USD1`,
    );
    console.log(
      `Pool Info: Min Amount Out Raw: ${computedMinAmountOut.raw.toString()}`,
    );

    // Use a minimal fixed fee for testing - the pool state in local validator may differ from mainnet
    // The actual swap output may be much smaller than estimated, so we use a tiny fee
    const swapFee = SWAP_FEE;
    console.log(
      `Fixed Swap Fee for testing: ${swapFee.toString()} (${
        Number(swapFee) / 10 ** DEST_DECIMALS
      } USD1)`,
    );

    // Output USD1 note
    const destPrivKey = randomBytes32();
    const destPubKey = derivePublicKey(poseidon, destPrivKey);
    const destBlinding = randomBytes32();
    const swappedAmount = 50_000_000n; // ~50 USD1 (estimated)
    const destCommitment = computeCommitment(
      poseidon,
      swappedAmount,
      destPubKey,
      destBlinding,
      usd1TokenMint,
    ); // Dummy amount in proof

    // Output SOL Change note
    const changeAmount = note.amount - BigInt(SWAP_AMOUNT);
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

    const extData = {
      recipient: payer.publicKey,
      relayer: payer.publicKey,
      fee: new BN(swapFee.toString()),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    // NOTE: For testing with cloned mainnet accounts, we use minAmountOut = 1
    // The SDK's computed estimate is based on pool reserves that may not match
    // the local validator's cloned state. In production, use computedMinAmountOut.raw
    //
    // We still log the computed value for reference:
    console.log(
      `SDK computed minAmountOut: ${computedMinAmountOut.raw.toString()}`,
    );
    console.log(
      `Using minAmountOut: 1 (test environment with stale pool state)`,
    );

    const minAmountOut = new BN(1); // Accept any output for test environment
    const swapData = buildAmmSwapData(new BN(SWAP_AMOUNT), minAmountOut);
    const swapParams = {
      minAmountOut,
      deadline: new BN(Math.floor(Date.now() / 1000) + 3600),
      sourceMint: solTokenMint,
      destMint: usd1TokenMint,
      swapDataHash: Buffer.alloc(32), // MEDIUM-001: zero for CPMM/AMM
    };

    const swapParamsHash = computeSwapParamsHash(
      poseidon,
      solTokenMint,
      usd1TokenMint,
      BigInt(minAmountOut.toString()),
      BigInt(swapParams.deadline.toString()),
      new Uint8Array(32), // MEDIUM-001: zero for CPMM/AMM
    );

    const proof = await generateSwapProof({
      sourceRoot: solOffchainTree.getRoot(),
      swapParamsHash,
      extDataHash,
      sourceMint: solTokenMint,
      destMint: usd1TokenMint,
      inputNullifiers: [note.nullifier, dummyNullifier],
      changeCommitment: changeCommitment,
      destCommitment: destCommitment,
      swapAmount: BigInt(SWAP_AMOUNT),
      inputAmounts: [note.amount, 0n],
      inputPrivateKeys: [note.privateKey, dummyPrivKey],
      inputPublicKeys: [note.publicKey, dummyPubKey],
      inputBlindings: [note.blinding, dummyBlinding],
      inputMerklePaths: [
        solOffchainTree.getMerkleProof(note.leafIndex),
        solOffchainTree.getMerkleProof(0),
      ],
      changeAmount,
      changePubkey: changePubKey,
      changeBlinding,
      destAmount: swappedAmount,
      destPubkey: destPubKey,
      destBlinding,
      minAmountOut: BigInt(minAmountOut.toString()),
      deadline: BigInt(swapParams.deadline.toString()),
      swapDataHash: new Uint8Array(32), // MEDIUM-001: zero for CPMM/AMM
    });

    const [executorPda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("swap_executor"),
        solTokenMint.toBuffer(),
        usd1TokenMint.toBuffer(),
        Buffer.from(note.nullifier),
        payer.publicKey.toBuffer(),
      ],
      program.programId,
    );
    console.log("   Forward swap executor PDA:", executorPda.toBase58());
    const executorSourceToken = await getAssociatedTokenAddress(
      solTokenMint,
      executorPda,
      true,
    );
    const executorDestToken = await getAssociatedTokenAddress(
      usd1TokenMint,
      executorPda,
      true,
    );

    // Ensure accounts exist
    const swapSolVaultAccountFinal = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      solTokenMint,
      solVault,
      true,
    );
    const swapUsd1VaultAccountFinal = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      usd1TokenMint,
      usd1Vault,
      true,
    );
    const relayerTokenAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      usd1TokenMint,
      payer.publicKey,
    );

    // ALT
    const recentSlot = await provider.connection.getSlot("finalized");
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
      addresses: [
        solConfig,
        globalConfig,
        solVault,
        solNoteTree,
        solNullifiers,
        swapSolVaultAccount.address,
        solTokenMint,
        usd1Config,
        usd1Vault,
        usd1NoteTree,
        swapUsd1VaultAccount.address,
        usd1TokenMint,
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
      ],
    });
    const createLutTx = new anchor.web3.Transaction()
      .add(createLutIx)
      .add(extendLutIx);
    await provider.sendAndConfirm(createLutTx);
    await new Promise((resolve) => setTimeout(resolve, 1000));
    const lookupTableAccount = await provider.connection.getAddressLookupTable(
      lookupTableAddress,
    );

    const swapIx = await (program.methods as any)
      .transactSwap(
        proof,
        Array.from(solOffchainTree.getRoot()),
        0,
        solTokenMint,
        Array.from(note.nullifier),
        Array.from(dummyNullifier),
        0,
        usd1TokenMint,
        Array.from(changeCommitment),
        Array.from(destCommitment),
        swapParams,
        new BN(SWAP_AMOUNT.toString()),
        swapData,
        extData,
      )
      .accounts({
        sourceConfig: solConfig,
        globalConfig,
        sourceVault: solVault,
        sourceTree: solNoteTree,
        sourceNullifiers: solNullifiers,
        sourceNullifierMarker0: deriveNullifierMarkerPDA(
          program.programId,
          solTokenMint,
          0,
          note.nullifier,
        ),
        sourceNullifierMarker1: deriveNullifierMarkerPDA(
          program.programId,
          solTokenMint,
          0,
          dummyNullifier,
        ),
        sourceVaultTokenAccount: swapSolVaultAccountFinal.address,
        sourceMintAccount: solTokenMint,
        destConfig: usd1Config,
        destVault: usd1Vault,
        destTree: usd1NoteTree,
        destVaultTokenAccount: swapUsd1VaultAccountFinal.address,
        destMintAccount: usd1TokenMint,
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
        { pubkey: poolConfig.ammOpenOrders, isSigner: false, isWritable: true },
        {
          pubkey: poolConfig.ammTargetOrders,
          isSigner: false,
          isWritable: true,
        },
        { pubkey: poolConfig.ammBaseVault, isSigner: false, isWritable: true },
        { pubkey: poolConfig.ammQuoteVault, isSigner: false, isWritable: true },
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

    const messageV0 = new TransactionMessage({
      payerKey: payer.publicKey,
      recentBlockhash: (await provider.connection.getLatestBlockhash())
        .blockhash,
      instructions: [
        ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
        swapIx,
      ],
    }).compileToV0Message([lookupTableAccount.value!]);
    const versionedTx = new VersionedTransaction(messageV0);
    versionedTx.sign([payer]);

    try {
      const txSig = await provider.connection.sendTransaction(versionedTx, {
        skipPreflight: false,
      });
      await provider.connection.confirmTransaction({
        signature: txSig,
        ...(await provider.connection.getLatestBlockhash()),
      });
      console.log(`   ✅ SOL->USD1 Swap TX: ${txSig}`);

      // Take balance snapshot after swap
      const balanceAfter = await getBalanceSnapshot(
        provider.connection,
        payer.publicKey,
        undefined,
        undefined,
        swapSolVaultAccount.address,
        swapUsd1VaultAccount.address,
        relayerUsd1Account.address,
      );

      // Log detailed balance changes
      logBalanceChanges(balanceBefore, balanceAfter, "SOL → USD1 Swap");

      // Verify expected balance changes
      const swapAmountSol = SWAP_AMOUNT / LAMPORTS_PER_SOL;
      const solVaultDecrease =
        (balanceBefore.solVault || 0) - (balanceAfter.solVault || 0);
      const usd1VaultIncrease =
        (balanceAfter.usd1Vault || 0) - (balanceBefore.usd1Vault || 0);
      const relayerUsd1Increase =
        (balanceAfter.relayerUsd1 || 0) - (balanceBefore.relayerUsd1 || 0);

      console.log(`📈 Swap Metrics:`);
      console.log(
        `   SOL Vault decreased by: ${solVaultDecrease.toFixed(
          6,
        )} SOL (expected: ~${swapAmountSol.toFixed(6)} SOL)`,
      );
      console.log(
        `   USD1 Vault increased by: ${usd1VaultIncrease.toFixed(6)} USD1`,
      );
      console.log(
        `   Relayer USD1 fee: ${relayerUsd1Increase.toFixed(6)} USD1`,
      );

      // Verify balances changed in expected direction
      expect(solVaultDecrease).to.be.greaterThan(
        0,
        "SOL vault should decrease",
      );
      expect(usd1VaultIncrease).to.be.greaterThan(
        0,
        "USD1 vault should increase",
      );

      console.log(
        `   ✅ Dest vault USD1 balance: ${(balanceAfter.usd1Vault || 0).toFixed(
          6,
        )}`,
      );

      // Save the USD1 note from swap output
      const usd1LeafIndex = usd1OffchainTree.insert(destCommitment);
      usd1NoteId = noteStorage.save({
        amount: swappedAmount,
        commitment: destCommitment,
        nullifier: computeNullifier(
          poseidon,
          destCommitment,
          usd1LeafIndex,
          destPrivKey,
        ),
        blinding: destBlinding,
        privateKey: destPrivKey,
        publicKey: destPubKey,
        leafIndex: usd1LeafIndex,
        merklePath: usd1OffchainTree.getMerkleProof(usd1LeafIndex),
        mintAddress: usd1TokenMint,
      });
      console.log(`   USD1 note saved: ${usd1NoteId} (${swappedAmount} units)`);

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
      console.error("Simulation error occurred:", e);
      if (e.logs) {
        console.error("Tx Logs:", e.logs);
      }
      if (e instanceof anchor.web3.SendTransactionError) {
        console.error("SendTransactionError logs:", e.logs);
      }
      throw e;
    }
  });

  it("verifies USD1 note from SOL swap exists", async () => {
    expect(usd1NoteId).to.not.be.null;
    const note = noteStorage.get(usd1NoteId!);
    expect(note).to.not.be.undefined;

    console.log("\n✅ USD1 note from swap verified:");
    console.log(
      `   Amount: ${note!.amount} (${Number(note!.amount) / 1e6} USD1)`,
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

  it("spends the SOL change note (internal transfer)", async () => {
    console.log("\n🔄 Spending SOL change note (internal transfer)...");

    const note = noteStorage.get(solChangeNoteId!);
    if (!note) throw new Error("SOL change note not found");

    console.log(
      `   Input note amount: ${note.amount} lamports (${
        Number(note.amount) / 1e9
      } SOL)`,
    );

    // Take balance snapshot before internal transfer
    const balanceBefore = await getBalanceSnapshot(
      provider.connection,
      payer.publicKey,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
    );
    console.log("📊 Balance snapshot taken before SOL internal transfer");

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
      solTokenMint,
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
      solTokenMint,
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
      mintAddress: solTokenMint,
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
    const vaultTokenAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      solTokenMint,
      solVault,
      true,
    );
    const relayerTokenAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      solTokenMint,
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
        solTokenMint,
        Array.from(note.nullifier),
        Array.from(dummyNullifier),
        Array.from(outputCommitment),
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

    // Take balance snapshot after internal transfer
    const balanceAfter = await getBalanceSnapshot(
      provider.connection,
      payer.publicKey,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
    );

    // Log balance changes (should be minimal for internal transfer)
    logBalanceChanges(balanceBefore, balanceAfter, "SOL Internal Transfer");

    // Verify no unexpected balance changes (internal transfers should only affect gas)
    const userSolChange = Math.abs(
      (balanceAfter.userSol || 0) - (balanceBefore.userSol || 0),
    );
    console.log(`💱 Gas cost: ~${userSolChange.toFixed(6)} SOL`);

    // Gas should be reasonable (less than 0.01 SOL)
    expect(userSolChange).to.be.lessThan(0.01, "Gas cost should be reasonable");

    // Update off-chain tree
    solOffchainTree.insert(outputCommitment);
    solOffchainTree.insert(changeCommitment);

    console.log(`   Internal transfer - no fee`);
    console.log(
      `   New note created: ${outputAmount} lamports (${
        Number(outputAmount) / 1e9
      } SOL)`,
    );
  });

  it("spends the USD1 note (internal transfer)", async () => {
    console.log("\n🔄 Spending USD1 note (internal transfer)...");

    const note = noteStorage.get(usd1NoteId!);
    if (!note) throw new Error("USD1 note not found");

    console.log(
      `   Input note amount: ${note.amount} units (${
        Number(note.amount) / 1e6
      } USD1)`,
    );

    // Take balance snapshot before internal transfer
    const balanceBefore = await getBalanceSnapshot(
      provider.connection,
      payer.publicKey,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
    );
    console.log("📊 Balance snapshot taken before USD1 internal transfer");

    // Get merkle proof
    const merkleProof = usd1OffchainTree.getMerkleProof(note.leafIndex);
    const root = usd1OffchainTree.getRoot();

    // Dummy second input
    const dummyPrivKey = randomBytes32();
    const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
    const dummyBlinding = randomBytes32();
    const dummyCommitment = computeCommitment(
      poseidon,
      0n,
      dummyPubKey,
      dummyBlinding,
      usd1TokenMint,
    );
    const dummyNullifier = computeNullifier(
      poseidon,
      dummyCommitment,
      0,
      dummyPrivKey,
    );
    const dummyProof = usd1OffchainTree.getMerkleProof(0);

    // Output: split into two notes for later use (internal transfer, no fee)
    const fee = 0n; // No fee for internal transfer
    const swapAmount = 25_000_000n; // 25 USD1 to use for reverse swap
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
      usd1TokenMint,
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
      usd1TokenMint,
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
      mintAddress: usd1TokenMint,
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
      usd1TokenMint,
      0,
      note.nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      usd1TokenMint,
      0,
      dummyNullifier,
    );

    // Token accounts
    const vaultTokenAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      usd1TokenMint,
      usd1Vault,
      true,
    );
    const relayerTokenAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      usd1TokenMint,
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
        usd1TokenMint,
        Array.from(note.nullifier),
        Array.from(dummyNullifier),
        Array.from(keepCommitment),
        Array.from(swapCommitment),
        new BN(9999999999), // deadline (far future for tests)
        extData,
        proof,
      )
      .accounts({
        config: usd1Config,
        globalConfig,
        vault: usd1Vault,
        inputTree: usd1NoteTree,
        outputTree: usd1NoteTree,
        nullifiers: usd1Nullifiers,
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

    console.log(`✅ USD1 note spent: ${tx}`);

    // Take balance snapshot after internal transfer
    const balanceAfter = await getBalanceSnapshot(
      provider.connection,
      payer.publicKey,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
    );

    // Log balance changes (should be minimal for internal transfer)
    logBalanceChanges(balanceBefore, balanceAfter, "USD1 Internal Transfer");

    // Verify no unexpected balance changes (internal transfers should only affect gas)
    const userSolChange = Math.abs(
      (balanceAfter.userSol || 0) - (balanceBefore.userSol || 0),
    );
    console.log(`💱 Gas cost: ~${userSolChange.toFixed(6)} SOL`);

    // Gas should be reasonable (less than 0.01 SOL)
    expect(userSolChange).to.be.lessThan(0.01, "Gas cost should be reasonable");

    // Update off-chain tree
    const keepLeafIndex = usd1OffchainTree.insert(keepCommitment);
    const swapLeafIndex = usd1OffchainTree.insert(swapCommitment);

    // Save the keep note for external withdrawal test
    usd1KeepNoteId = noteStorage.save({
      amount: keepAmount,
      commitment: keepCommitment,
      nullifier: computeNullifier(
        poseidon,
        keepCommitment,
        keepLeafIndex,
        keepPrivKey,
      ),
      blinding: keepBlinding,
      privateKey: keepPrivKey,
      publicKey: keepPubKey,
      leafIndex: keepLeafIndex,
      merklePath: usd1OffchainTree.getMerkleProof(keepLeafIndex),
      mintAddress: usd1TokenMint,
    });

    // Save the swap note for reverse swap test
    usd1ChangeNoteId = noteStorage.save({
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
      merklePath: usd1OffchainTree.getMerkleProof(swapLeafIndex),
      mintAddress: usd1TokenMint,
    });

    console.log(`   Internal transfer - no fee`);
    console.log(
      `   Keep note: ${keepAmount} units (${Number(keepAmount) / 1e6} USD1)`,
    );
    console.log(
      `   Swap note saved: ${usd1ChangeNoteId} - ${swapAmount} units (${
        Number(swapAmount) / 1e6
      } USD1)`,
    );
  });

  it("executes internal USD1 transfer", async () => {
    console.log("\n📤 Executing internal USD1 transfer...");

    // Use the change note from the previous split (usd1ChangeNoteId)
    const originalNote = noteStorage.get(usd1ChangeNoteId!);
    if (!originalNote) throw new Error("USD1 change note not found");

    // Get merkle proof
    const merkleProof = usd1OffchainTree.getMerkleProof(originalNote.leafIndex);
    const root = usd1OffchainTree.getRoot();

    // Dummy second input
    const dummyPrivKey = randomBytes32();
    const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
    const dummyBlinding = randomBytes32();
    const dummyCommitment = computeCommitment(
      poseidon,
      0n,
      dummyPubKey,
      dummyBlinding,
      usd1TokenMint,
    );
    const dummyNullifier = computeNullifier(
      poseidon,
      dummyCommitment,
      0,
      dummyPrivKey,
    );
    const dummyProof = usd1OffchainTree.getMerkleProof(0);

    // Transfer to new owner
    const newPrivKey = randomBytes32();
    const newPubKey = derivePublicKey(poseidon, newPrivKey);
    const newBlinding = randomBytes32();
    const newCommitment = computeCommitment(
      poseidon,
      originalNote.amount,
      newPubKey,
      newBlinding,
      usd1TokenMint,
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
      usd1TokenMint,
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
      mintAddress: usd1TokenMint,
      inputNullifiers: [originalNote.nullifier, dummyNullifier],
      outputCommitments: [newCommitment, changeCommitment],
      inputAmounts: [originalNote.amount, 0n],
      inputPrivateKeys: [originalNote.privateKey, dummyPrivKey],
      inputPublicKeys: [originalNote.publicKey, dummyPubKey],
      inputBlindings: [originalNote.blinding, dummyBlinding],
      inputMerklePaths: [merkleProof, dummyProof],
      outputAmounts: [originalNote.amount, 0n],
      outputOwners: [newPubKey, changePubKey],
      outputBlindings: [newBlinding, changeBlinding],
    });

    // Derive nullifier marker PDAs
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      usd1TokenMint,
      0,
      originalNote.nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      usd1TokenMint,
      0,
      dummyNullifier,
    );

    const usd1VaultAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      usd1TokenMint,
      usd1Vault,
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
        usd1TokenMint,
        Array.from(originalNote.nullifier),
        Array.from(dummyNullifier),
        Array.from(newCommitment),
        Array.from(changeCommitment),
        new BN(9999999999), // deadline (far future for tests)
        extData,
        proof,
      )
      .accounts({
        config: usd1Config,
        globalConfig,
        vault: usd1Vault,
        inputTree: usd1NoteTree,
        outputTree: usd1NoteTree,
        nullifiers: usd1Nullifiers,
        nullifierMarker0,
        nullifierMarker1,
        relayer: payer.publicKey,
        recipient: payer.publicKey,
        vaultTokenAccount: usd1VaultAccount.address,
        userTokenAccount: usd1VaultAccount.address,
        recipientTokenAccount: usd1VaultAccount.address,
        relayerTokenAccount: usd1VaultAccount.address,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
      ])
      .rpc();

    console.log(`✅ Internal USD1 transfer: ${tx}`);

    // Update off-chain tree
    const leafIndex = usd1OffchainTree.insert(newCommitment);
    usd1OffchainTree.insert(changeCommitment);

    // Save transferred note
    transferredNoteId = noteStorage.save({
      amount: originalNote.amount,
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
      merklePath: usd1OffchainTree.getMerkleProof(leafIndex),
      mintAddress: usd1TokenMint,
    });

    console.log(`   Transferred USD1 note: ${transferredNoteId}`);
    console.log(`   Amount: ${Number(originalNote.amount) / 1e6} USD1`);
  });

  it("executes reverse swap (USD1 → SOL via AMM V4)", async () => {
    // TODO: Fix account collision issue - executor token accounts from forward swap
    // are not being properly closed, causing "Allocate: account already in use" error.
    // This is a Solana localnet account cleanup issue that needs investigation.
    // The JUP test (identical structure) passes, suggesting it's intermittent/timing-related.

    console.log("\n🔄 Executing reverse swap USD1 → SOL via AMM V4...");

    const note = noteStorage.get(transferredNoteId!);
    if (!note) throw new Error("USD1 transferred note not found");

    console.log(
      `   Input note amount: ${note.amount} units (${
        Number(note.amount) / 1e6
      } USD1)`,
    );

    // Get merkle proof
    const merkleProof = usd1OffchainTree.getMerkleProof(note.leafIndex);
    const root = usd1OffchainTree.getRoot();

    // Dummy second input
    const dummyPrivKey = randomBytes32();
    const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
    const dummyBlinding = randomBytes32();
    const dummyCommitment = computeCommitment(
      poseidon,
      0n,
      dummyPubKey,
      dummyBlinding,
      usd1TokenMint,
    );
    const dummyNullifier = computeNullifier(
      poseidon,
      dummyCommitment,
      0,
      dummyPrivKey,
    );
    const dummyProof = usd1OffchainTree.getMerkleProof(0);

    // Swap all USD1
    const swapAmount = note.amount;
    const expectedSol = 200_000_000n; // ~0.2 SOL estimated output

    // Output: SOL note in source pool
    const solOutputPrivKey = randomBytes32();
    const solOutputPubKey = derivePublicKey(poseidon, solOutputPrivKey);
    const solOutputBlinding = randomBytes32();
    const solOutputCommitment = computeCommitment(
      poseidon,
      expectedSol,
      solOutputPubKey,
      solOutputBlinding,
      solTokenMint,
    );
    // For proof, we use dest mint
    const solOutputCommitmentForProof = computeCommitment(
      poseidon,
      0n,
      solOutputPubKey,
      solOutputBlinding,
      usd1TokenMint,
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
      usd1TokenMint,
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

    // Generate ZK proof
    console.log("   Generating ZK proof...");
    // Swap params (reversed: USD1 → SOL)
    const minSolOut = new BN(1);
    const swapParams = {
      minAmountOut: minSolOut,
      deadline: new BN(Math.floor(Date.now() / 1000) + 3600),
      sourceMint: usd1TokenMint,
      destMint: solTokenMint,
      swapDataHash: Buffer.alloc(32), // MEDIUM-001: zero for CPMM/AMM
    };

    const swapParamsHash = computeSwapParamsHash(
      poseidon,
      swapParams.sourceMint,
      swapParams.destMint,
      BigInt(swapParams.minAmountOut.toString()),
      BigInt(swapParams.deadline.toString()),
      new Uint8Array(32), // MEDIUM-001: zero for CPMM/AMM
    );

    const proof = await generateSwapProof({
      sourceRoot: root,
      swapParamsHash,
      extDataHash,
      sourceMint: usd1TokenMint,
      destMint: solTokenMint,
      inputNullifiers: [note.nullifier, dummyNullifier],
      changeCommitment,
      destCommitment: solOutputCommitment,
      swapAmount: note.amount,
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
      minAmountOut: BigInt(swapParams.minAmountOut.toString()),
      deadline: BigInt(swapParams.deadline.toString()),
      swapDataHash: new Uint8Array(32), // MEDIUM-001: zero for CPMM/AMM
    });
    console.log("   ✅ ZK proof generated");

    const swapData = buildAmmSwapData(new BN(swapAmount.toString()), minSolOut);

    // Derive executor PDA
    const [executorPda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("swap_executor"),
        usd1TokenMint.toBuffer(),
        solTokenMint.toBuffer(),
        Buffer.from(note.nullifier),
        payer.publicKey.toBuffer(),
      ],
      program.programId,
    );
    const executorSourceToken = await getAssociatedTokenAddress(
      usd1TokenMint,
      executorPda,
      true,
    );
    const executorDestToken = await getAssociatedTokenAddress(
      solTokenMint,
      executorPda,
      true,
    );

    // Nullifier markers (using USD1 pool)
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      usd1TokenMint,
      0,
      note.nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      usd1TokenMint,
      0,
      dummyNullifier,
    );

    // Token accounts
    const sourceVaultUsd1Account = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      usd1TokenMint,
      usd1Vault,
      true,
    );
    const destVaultSolAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      solTokenMint,
      solVault,
      true,
    );
    const relayerTokenAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      solTokenMint,
      payer.publicKey,
    );

    const dstTokenInfo = await provider.connection.getAccountInfo(
      executorDestToken,
    );
    if (dstTokenInfo) console.log("   ⚠️ Executor Dest Token already exists!");

    // Take balance snapshot before reverse swap
    const balanceBefore = await getBalanceSnapshot(
      provider.connection,
      payer.publicKey,
      undefined,
      undefined,
      destVaultSolAccount.address,
      sourceVaultUsd1Account.address,
      relayerTokenAccount.address,
    );
    console.log("📊 Balance snapshot taken before USD1→SOL reverse swap");

    // Create new lookup table for this transaction
    console.log("   Creating Address Lookup Table...");
    const recentSlot = await provider.connection.getSlot("finalized");

    const lookupTableAddresses = [
      usd1Config,
      globalConfig,
      usd1Vault,
      usd1NoteTree,
      usd1Nullifiers,
      sourceVaultUsd1Account.address,
      usd1TokenMint,
      solConfig,
      solVault,
      solNoteTree,
      destVaultSolAccount.address,
      solTokenMint,
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
      // For USD1 → SOL swap, we reverse the vault order in remaining accounts
      // AMM expects: pool_coin_vault (SOL), pool_pc_vault (USD1)
      // When swapping USD1 → SOL:
      // - Input: USD1 (quote/pc)
      // - Output: SOL (base/coin)
      const swapIx = await (program.methods as any)
        .transactSwap(
          proof,
          Array.from(root),
          0,
          usd1TokenMint, // Source is USD1
          Array.from(note.nullifier),
          Array.from(dummyNullifier),
          0,
          solTokenMint, // Dest is SOL
          Array.from(changeCommitment), // Change (USD1)
          Array.from(solOutputCommitment), // Dest (SOL)
          swapParams,
          new BN(swapAmount.toString()),
          swapData,
          extData,
        )
        .accounts({
          sourceConfig: usd1Config, // USD1 pool config
          globalConfig,
          sourceVault: usd1Vault, // USD1 vault
          sourceTree: usd1NoteTree,
          sourceNullifiers: usd1Nullifiers,
          sourceNullifierMarker0: nullifierMarker0,
          sourceNullifierMarker1: nullifierMarker1,
          sourceVaultTokenAccount: sourceVaultUsd1Account.address,
          sourceMintAccount: usd1TokenMint,
          destConfig: solConfig, // SOL pool config
          destVault: solVault, // SOL vault
          destTree: solNoteTree,
          destVaultTokenAccount: destVaultSolAccount.address,
          destMintAccount: solTokenMint,
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
          // For USD1 → SOL: still use same vault order, AMM handles direction
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

      console.log(`✅ Reverse AMM V4 swap executed: ${txSig}`);

      // Take balance snapshot after reverse swap
      const balanceAfter = await getBalanceSnapshot(
        provider.connection,
        payer.publicKey,
        undefined,
        undefined,
        destVaultSolAccount.address,
        sourceVaultUsd1Account.address,
        relayerTokenAccount.address,
      );

      // Log detailed balance changes
      logBalanceChanges(balanceBefore, balanceAfter, "USD1 → SOL Reverse Swap");

      // Verify expected balance changes
      const swapAmountUsd1 = Number(swapAmount) / 1e6;
      const usd1VaultDecrease =
        (balanceBefore.usd1Vault || 0) - (balanceAfter.usd1Vault || 0);
      const solVaultIncrease =
        (balanceAfter.solVault || 0) - (balanceBefore.solVault || 0);
      const relayerSolIncrease =
        (balanceAfter.relayerUsd1 || 0) - (balanceBefore.relayerUsd1 || 0);

      console.log(`📈 Reverse Swap Metrics:`);
      console.log(
        `   USD1 Vault decreased by: ${usd1VaultDecrease.toFixed(
          6,
        )} USD1 (expected: ~${swapAmountUsd1.toFixed(6)} USD1)`,
      );
      console.log(
        `   SOL Vault increased by: ${solVaultIncrease.toFixed(6)} SOL`,
      );
      console.log(`   Relayer SOL fee: ${relayerSolIncrease.toFixed(6)} SOL`);

      // Verify balances changed in expected direction
      expect(usd1VaultDecrease).to.be.greaterThan(
        0,
        "USD1 vault should decrease",
      );
      expect(solVaultIncrease).to.be.greaterThan(
        0,
        "SOL vault should increase",
      );

      console.log(
        `   ✅ SOL vault balance: ${(balanceAfter.solVault || 0).toFixed(
          6,
        )} SOL`,
      );

      // Save the SOL note from reverse swap
      const solLeafIndex = solOffchainTree.insert(solOutputCommitment);
      solFromUsd1NoteId = noteStorage.save({
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
        merklePath: solOffchainTree.getMerkleProof(solLeafIndex),
        mintAddress: solTokenMint,
      });
      console.log(`   SOL note saved: ${solFromUsd1NoteId}`);
    } catch (e: any) {
      console.error("❌ Reverse AMM V4 swap failed:", e.message);
      if (e.logs) {
        console.error("Logs:", e.logs.slice(-20));
      }
      throw e;
    }
  });

  it("executes external USD1 withdrawal", async () => {
    console.log("\n💸 Executing external USD1 withdrawal...");

    const note = noteStorage.get(usd1KeepNoteId!);
    if (!note) throw new Error("USD1 keep note not found");

    const withdrawAmount = 5_000_000n; // 5 USD1 withdrawal ($5 minimum)
    const changeAmount = note.amount - withdrawAmount;

    console.log(
      `   Withdrawing ${
        Number(withdrawAmount) / 1e6
      } USD1 to external wallet (from ${Number(note.amount) / 1e6} USD1 note)`,
    );
    console.log(`   Change amount: ${Number(changeAmount) / 1e6} USD1`);

    // Create external recipient
    const externalRecipient = Keypair.generate();

    // Create USD1 token account for external recipient
    const externalUsd1Account = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      usd1TokenMint,
      externalRecipient.publicKey,
      false,
    );

    // Create relayer USD1 account
    const relayerUsd1Account = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      usd1TokenMint,
      payer.publicKey,
      false,
    );

    // Take balance snapshot before withdrawal
    const balanceBefore = await getBalanceSnapshot(
      provider.connection,
      payer.publicKey,
      undefined,
      externalUsd1Account.address,
      undefined,
      await getAssociatedTokenAddress(usd1TokenMint, usd1Vault, true),
      undefined,
    );

    // Get merkle proof
    const merkleProof = usd1OffchainTree.getMerkleProof(note.leafIndex);
    const root = usd1OffchainTree.getRoot();

    // Dummy second input
    const dummyPrivKey = randomBytes32();
    const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
    const dummyBlinding = randomBytes32();
    const dummyCommitment = computeCommitment(
      poseidon,
      0n,
      dummyPubKey,
      dummyBlinding,
      usd1TokenMint,
    );
    const dummyNullifier = computeNullifier(
      poseidon,
      dummyCommitment,
      0,
      dummyPrivKey,
    );
    const dummyProof = usd1OffchainTree.getMerkleProof(0);

    // Change output (remaining USD1)
    const changePrivKey1 = randomBytes32();
    const changePubKey1 = derivePublicKey(poseidon, changePrivKey1);
    const changeBlinding1 = randomBytes32();
    const changeCommitment1 = computeCommitment(
      poseidon,
      changeAmount,
      changePubKey1,
      changeBlinding1,
      usd1TokenMint,
    );

    // Zero change output
    const changePrivKey2 = randomBytes32();
    const changePubKey2 = derivePublicKey(poseidon, changePrivKey2);
    const changeBlinding2 = randomBytes32();
    const changeCommitment2 = computeCommitment(
      poseidon,
      0n,
      changePubKey2,
      changeBlinding2,
      usd1TokenMint,
    );

    // External data for withdrawal - fee of 0.025 USD1 (0.5% of 5 USD1)
    const withdrawalFee = 25_000n; // 0.025 USD1 fee for relayer (0.5% of $5)
    const extData = {
      recipient: externalRecipient.publicKey,
      relayer: payer.publicKey,
      fee: new BN(withdrawalFee.toString()),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    // Generate ZK proof for withdrawal
    const proof = await generateTransactionProof({
      root,
      publicAmount: -withdrawAmount, // Negative for withdrawal
      extDataHash,
      mintAddress: usd1TokenMint,
      inputNullifiers: [note.nullifier, dummyNullifier],
      outputCommitments: [changeCommitment1, changeCommitment2],
      inputAmounts: [note.amount, 0n],
      inputPrivateKeys: [note.privateKey, dummyPrivKey],
      inputPublicKeys: [note.publicKey, dummyPubKey],
      inputBlindings: [note.blinding, dummyBlinding],
      inputMerklePaths: [merkleProof, dummyProof],
      outputAmounts: [changeAmount, 0n],
      outputOwners: [changePubKey1, changePubKey2],
      outputBlindings: [changeBlinding1, changeBlinding2],
    });

    // Derive nullifier marker PDAs
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      usd1TokenMint,
      0,
      note.nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      usd1TokenMint,
      0,
      dummyNullifier,
    );

    // Execute withdrawal
    const tx = await (program.methods as any)
      .transact(
        Array.from(root),
        0,
        0,
        new BN(withdrawAmount.toString()).neg(),
        Array.from(extDataHash),
        usd1TokenMint,
        Array.from(note.nullifier),
        Array.from(dummyNullifier),
        Array.from(changeCommitment1),
        Array.from(changeCommitment2),
        new BN(9999999999), // deadline (far future for tests)
        extData,
        proof,
      )
      .accounts({
        config: usd1Config,
        globalConfig,
        vault: usd1Vault,
        inputTree: usd1NoteTree,
        outputTree: usd1NoteTree,
        nullifiers: usd1Nullifiers,
        nullifierMarker0,
        nullifierMarker1,
        relayer: payer.publicKey,
        recipient: externalRecipient.publicKey,
        vaultTokenAccount: usd1VaultTokenAccount,
        userTokenAccount: externalUsd1Account.address,
        recipientTokenAccount: externalUsd1Account.address,
        relayerTokenAccount: relayerUsd1Account.address,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
      ])
      .rpc();

    console.log(`✅ External USD1 withdrawal: ${tx}`);

    // Take balance snapshot after withdrawal
    const balanceAfter = await getBalanceSnapshot(
      provider.connection,
      payer.publicKey,
      undefined,
      externalUsd1Account.address,
      undefined,
      await getAssociatedTokenAddress(usd1TokenMint, usd1Vault, true),
      undefined,
    );

    // Log balance changes
    const usd1Increase =
      (balanceAfter.userUsd1 || 0) - (balanceBefore.userUsd1 || 0);
    const vaultDecrease =
      (balanceBefore.usd1Vault || 0) - (balanceAfter.usd1Vault || 0);
    const expectedNet = Number(withdrawAmount - withdrawalFee) / 1e6;

    console.log(`📊 Withdrawal Results:`);
    console.log(
      `   External USD1 increased by: ${usd1Increase.toFixed(6)} USD1`,
    );
    console.log(`   USD1 Vault decreased by: ${vaultDecrease.toFixed(6)} USD1`);
    console.log(
      `   Expected net (5 - 0.025 fee): ${expectedNet.toFixed(6)} USD1`,
    );

    // Verify withdrawal worked
    expect(usd1Increase).to.be.greaterThan(
      0,
      "External wallet should receive USD1",
    );
    expect(vaultDecrease).to.be.greaterThan(0, "USD1 vault should decrease");
    expect(usd1Increase).to.be.approximately(
      expectedNet,
      0.01,
      "Net withdrawal should match expected amount",
    );

    // Update off-chain tree
    usd1OffchainTree.insert(changeCommitment1);
    usd1OffchainTree.insert(changeCommitment2);

    console.log(
      `   ✅ Successfully withdrew ${usd1Increase.toFixed(
        6,
      )} USD1 to external wallet`,
    );
  });
});

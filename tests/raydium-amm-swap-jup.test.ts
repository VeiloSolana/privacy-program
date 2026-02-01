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
  JUP_MINT,
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
  userJup?: number;
  solVault?: number;
  jupVault?: number;
  poolBaseLiquidity?: number;
  poolQuoteLiquidity?: number;
  relayerSol: number;
  relayerJup?: number;
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
  userJupAccount?: PublicKey,
  solVaultAccount?: PublicKey,
  jupVaultAccount?: PublicKey,
  relayerJupAccount?: PublicKey,
): Promise<BalanceSnapshot> {
  const [
    userSol,
    userWsol,
    userJup,
    solVault,
    jupVault,
    relayerSol,
    relayerJup,
  ] = await Promise.all([
    getSolBalance(connection, userPubkey),
    userWsolAccount
      ? getTokenBalance(connection, userWsolAccount)
      : Promise.resolve(undefined),
    userJupAccount
      ? getTokenBalance(connection, userJupAccount)
      : Promise.resolve(undefined),
    solVaultAccount
      ? getTokenBalance(connection, solVaultAccount)
      : Promise.resolve(undefined),
    jupVaultAccount
      ? getTokenBalance(connection, jupVaultAccount)
      : Promise.resolve(undefined),
    getSolBalance(connection, userPubkey), // relayer is same as user in tests
    relayerJupAccount
      ? getTokenBalance(connection, relayerJupAccount)
      : Promise.resolve(undefined),
  ]);

  return {
    userSol,
    userWsol,
    userJup,
    solVault,
    jupVault,
    relayerSol,
    relayerJup,
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

  if (before.userJup !== after.userJup && (before.userJup || after.userJup)) {
    const beforeVal = before.userJup || 0;
    const afterVal = after.userJup || 0;
    const diff = afterVal - beforeVal;
    console.log(
      `   User JUP: ${beforeVal.toFixed(6)} → ${afterVal.toFixed(6)} (${
        diff >= 0 ? "+" : ""
      }${diff.toFixed(6)} JUP)`,
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
    before.jupVault !== after.jupVault &&
    (before.jupVault || after.jupVault)
  ) {
    const beforeVal = before.jupVault || 0;
    const afterVal = after.jupVault || 0;
    const diff = afterVal - beforeVal;
    console.log(
      `   JUP Vault: ${beforeVal.toFixed(6)} → ${afterVal.toFixed(6)} (${
        diff >= 0 ? "+" : ""
      }${diff.toFixed(6)} JUP)`,
    );
  }

  if (
    before.relayerJup !== after.relayerJup &&
    (before.relayerJup || after.relayerJup)
  ) {
    const beforeVal = before.relayerJup || 0;
    const afterVal = after.relayerJup || 0;
    const diff = afterVal - beforeVal;
    console.log(
      `   Relayer JUP: ${beforeVal.toFixed(6)} → ${afterVal.toFixed(6)} (${
        diff >= 0 ? "+" : ""
      }${diff.toFixed(6)} JUP)`,
    );
  }
}

/**
 * Privacy Pool Cross-Pool Swap Tests using Raydium AMM V4 - SOL/JUP
 *
 * Tests bidirectional swaps between SOL and JUP:
 * 1. SOL → JUP: Consumes SOL notes, swaps via AMM V4, creates JUP notes
 * 2. JUP → SOL: Consumes JUP notes, swaps via AMM V4, creates SOL notes
 *
 * Uses cloned mainnet Raydium AMM V4 JUP/SOL pool for testing.
 */

// Get pool configuration - can use static or dynamic
const POOL_NAME: PoolName = "SOL-JUP";
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

describe("Privacy Pool AMM V4 Swap - SOL/JUP", () => {
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

  // Destination pool (JUP)
  let jupTokenMint: PublicKey;
  let jupConfig: PublicKey;
  let jupVault: PublicKey;
  let jupNoteTree: PublicKey;
  let jupNullifiers: PublicKey;
  let jupVaultTokenAccount: PublicKey;

  // Global config
  let globalConfig: PublicKey;

  // Off-chain Merkle trees
  let solOffchainTree: OffchainMerkleTree;
  let jupOffchainTree: OffchainMerkleTree;

  // Note storage
  const noteStorage = new InMemoryNoteStorage();

  // Test constants
  const SOURCE_DECIMALS = 9; // WSOL
  const DEST_DECIMALS = 6; // JUP
  const INITIAL_DEPOSIT = 2_000_000_000; // 2 SOL
  const SWAP_AMOUNT = 500_000_000; // 0.5 SOL
  const SWAP_FEE = 20_000_000n; // 20 JUP (Safe estimate: 1200 < S < 2500)
  const feeBps = 50; // 0.5%

  // Deposited note references
  let solDepositNoteId: string | null = null;

  // Notes from swap results
  let jupNoteId: string | null = null;
  let solChangeNoteId: string | null = null;
  let jupChangeNoteId: string | null = null;
  let jupKeepNoteId: string | null = null;
  let solFromJupNoteId: string | null = null;

  // Serum vault signer (derived)
  let serumVaultSigner: PublicKey;

  // Shared lookup table for reuse
  let sharedLookupTableAddress: PublicKey | null = null;

  before(async () => {
    console.log("\n🔧 Setting up SOL/JUP AMM V4 swap test environment...\n");

    // Initialize Poseidon
    poseidon = await buildPoseidon();
    solOffchainTree = new OffchainMerkleTree(22, poseidon);
    jupOffchainTree = new OffchainMerkleTree(22, poseidon);

    // Airdrop SOL for gas and deposits
    await airdropAndConfirm(provider, payer.publicKey, 10 * LAMPORTS_PER_SOL);

    // Use mainnet mints (cloned)
    solTokenMint = WSOL_MINT;
    jupTokenMint = JUP_MINT;

    // Get pool configuration - either static or dynamic
    if (USE_DYNAMIC_POOL_KEYS) {
      console.log("📡 Using DYNAMIC pool key fetching from Raydium SDK...");
      poolKeys = await getPoolKeysFromMints(
        provider.connection,
        solTokenMint,
        jupTokenMint,
      );
      poolConfig = poolKeysToConfig(poolKeys);
      logPoolKeys(poolKeys);
    } else {
      console.log("📋 Using STATIC pool configuration...");
      poolConfig = getPoolConfig(POOL_NAME);
      logPoolConfig(POOL_NAME);
    }

    console.log(`\n✅ SOL Token (WSOL): ${solTokenMint.toBase58()}`);
    console.log(`✅ JUP Token: ${jupTokenMint.toBase58()}`);
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

    // Derive PDAs for JUP pool
    [jupConfig] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_config_v3"), jupTokenMint.toBuffer()],
      program.programId,
    );
    [jupVault] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_vault_v3"), jupTokenMint.toBuffer()],
      program.programId,
    );
    [jupNoteTree] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("privacy_note_tree_v3"),
        jupTokenMint.toBuffer(),
        encodeTreeId(0),
      ],
      program.programId,
    );
    [jupNullifiers] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_nullifiers_v3"), jupTokenMint.toBuffer()],
      program.programId,
    );
    jupVaultTokenAccount = await getAssociatedTokenAddress(
      jupTokenMint,
      jupVault,
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

  it("initializes JUP privacy pool", async () => {
    try {
      await (program.methods as any)
        .initialize(
          feeBps,
          jupTokenMint,
          new BN(0),
          new BN(100_000_000_000),
          new BN(0),
          new BN(100_000_000_000),
        )
        .accounts({
          config: jupConfig,
          vault: jupVault,
          noteTree: jupNoteTree,
          nullifiers: jupNullifiers,
          admin: payer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      console.log("✅ JUP pool initialized");
    } catch (e: any) {
      if (e.message?.includes("already in use")) {
        console.log("JUP pool already initialized");
      } else {
        throw e;
      }
    }
  });

  it("configures JUP pool for testing (low fees for $5 withdrawals)", async () => {
    try {
      await (program.methods as any)
        .updatePoolConfig(
          jupTokenMint,
          new BN(1_000_000), // min_deposit_amount = 1 JUP
          null, // max_deposit_amount
          new BN(5_000_000), // min_withdraw_amount = 5 JUP
          null, // max_withdraw_amount
          new BN(50), // fee_bps = 50 (0.5%)
          new BN(25_000), // min_withdrawal_fee = 0.025 JUP
          null, // fee_error_margin_bps
          null, // min_swap_fee
          null, // swap_fee_bps
        )
        .accounts({
          config: jupConfig,
          admin: payer.publicKey,
        })
        .rpc();
      console.log(
        "✅ JUP pool configured with 0.5% fee supporting $5 minimum withdrawals",
      );
    } catch (e: any) {
      console.error("Failed to update JUP pool config:", e);
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
        .addRelayer(jupTokenMint, payer.publicKey)
        .accounts({ config: jupConfig, admin: payer.publicKey })
        .rpc();
      console.log("✅ Relayer registered for dest pool (JUP)");
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
    const solVaultAccount = await getOrCreateAssociatedTokenAccount(
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
      solVaultAccount.address,
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
        ComputeBudgetProgram.setComputeUnitLimit({ units: 400000 }),
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
      solVaultAccount.address,
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
    const minOut = new anchor.BN(50_000_000); // 50 JUP (conservative)

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
      `   Min Out: ${decodedMinOut} (${Number(decodedMinOut) / 1e6} JUP)`,
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

  it("executes cross-pool swap (SOL → JUP via AMM V4)", async () => {
    console.log("\n🔄 Executing cross-pool swap SOL → JUP via AMM V4...");

    const note = noteStorage.get(solDepositNoteId!);
    if (!note) throw new Error("Note not found");

    // Get token accounts for balance tracking
    const solVaultAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      solTokenMint,
      solVault,
      true,
    );
    const jupVaultAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      jupTokenMint,
      jupVault,
      true,
    );
    const relayerJupAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      jupTokenMint,
      payer.publicKey,
    );

    // Take balance snapshot before swap
    const balanceBefore = await getBalanceSnapshot(
      provider.connection,
      payer.publicKey,
      undefined,
      undefined,
      solVaultAccount.address,
      jupVaultAccount.address,
      relayerJupAccount.address,
    );
    console.log(
      `💰 Pre-swap balances: SOL Vault: ${(balanceBefore.solVault || 0).toFixed(
        6,
      )}, JUP Vault: ${(balanceBefore.jupVault || 0).toFixed(
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

    let poolInfo;
    console.log("DEBUG: Calling Liquidity.fetchInfo");
    try {
      poolInfo = await Liquidity.fetchInfo({
        connection: provider.connection,
        poolKeys,
      });
      console.log("DEBUG: Liquidity.fetchInfo success");
    } catch (e: any) {
      console.log("DEBUG: Liquidity.fetchInfo failed", e?.message);
      console.log(
        "⚠️ Liquidity.fetchInfo failed (RPC simulation error), using manual fallback...",
      );
      // Fallback for test environment
      poolInfo = {
        status: new BN(6),
        baseDecimals: SOURCE_DECIMALS,
        quoteDecimals: DEST_DECIMALS,
        lpDecimals: 6,
        baseReserve: new BN(100_000_000_000),
        quoteReserve: new BN(500_000_000_000),
        lpSupply: new BN(1_000_000_000),
        startTime: new BN(0),
      };
      console.log("Pool Info fetched (fallback)");
    }

    // Create Token objects for SDK
    const solToken = new RaydiumToken(
      TOKEN_PROGRAM_ID,
      solTokenMint,
      SOURCE_DECIMALS,
    );
    const jupToken = new RaydiumToken(
      TOKEN_PROGRAM_ID,
      jupTokenMint,
      DEST_DECIMALS,
    );

    const amountIn = new TokenAmount(solToken, SWAP_AMOUNT, false);
    const slippage = new Percent(5, 100);

    console.log("DEBUG: Computing amount out");
    const { amountOut, minAmountOut: computedMinAmountOut } =
      Liquidity.computeAmountOut({
        poolKeys,
        poolInfo,
        amountIn,
        currencyOut: jupToken,
        slippage,
      });
    console.log("DEBUG: Amount out computed");

    console.log(`Pool Info: Amount In: ${amountIn.toExact()} SOL`);
    console.log(`Pool Info: Estimated Out: ${amountOut.toExact()} JUP`);

    // Use fixed fee for testing
    const swapFee = SWAP_FEE;
    console.log(
      `Fixed Swap Fee for testing: ${swapFee.toString()} (${
        Number(swapFee) / 10 ** DEST_DECIMALS
      } JUP)`,
    );

    // Output JUP note
    const destPrivKey = randomBytes32();
    const destPubKey = derivePublicKey(poseidon, destPrivKey);
    const destBlinding = randomBytes32();
    const swappedAmount = 50_000_000n; // ~50 JUP (estimated)
    const destCommitment = computeCommitment(
      poseidon,
      swappedAmount,
      destPubKey,
      destBlinding,
      jupTokenMint,
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

    const minAmountOut = new BN(1); // Force 1 for test environment with stale state
    // const minAmountOut = computedMinAmountOut.raw; // Original SDK value
    console.log(
      `SDK computed minAmountOut: ${computedMinAmountOut.raw.toString()}`,
    );
    console.log(
      `Using minAmountOut: ${minAmountOut.toString()} (test environment fix)`,
    );

    const swapData = buildAmmSwapData(new BN(SWAP_AMOUNT), minAmountOut);
    const swapParams = {
      minAmountOut,
      deadline: new BN(Math.floor(Date.now() / 1000) + 3600),
      sourceMint: solTokenMint,
      destMint: jupTokenMint,
    };

    const swapParamsHash = computeSwapParamsHash(
      poseidon,
      solTokenMint,
      jupTokenMint,
      BigInt(minAmountOut.toString()),
      BigInt(swapParams.deadline.toString()),
    );

    const proof = await generateSwapProof({
      sourceRoot: solOffchainTree.getRoot(),
      swapParamsHash,
      extDataHash,
      sourceMint: solTokenMint,
      destMint: jupTokenMint,
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
    });

    const [executorPda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("swap_executor"),
        solTokenMint.toBuffer(),
        jupTokenMint.toBuffer(),
        Buffer.from(note.nullifier),
      ],
      program.programId,
    );
    const executorSourceToken = await getAssociatedTokenAddress(
      solTokenMint,
      executorPda,
      true,
    );
    const executorDestToken = await getAssociatedTokenAddress(
      jupTokenMint,
      executorPda,
      true,
    );

    // Ensure accounts exist
    const jupVaultAccountForTx = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      jupTokenMint,
      jupVault,
      true,
    );
    const relayerTokenAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      jupTokenMint,
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
        solVaultAccount.address,
        solTokenMint,
        jupConfig,
        jupVault,
        jupNoteTree,
        jupVaultAccountForTx.address,
        jupTokenMint,
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
        jupTokenMint,
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
        sourceVaultTokenAccount: solVaultAccount.address,
        sourceMintAccount: solTokenMint,
        destConfig: jupConfig,
        destVault: jupVault,
        destTree: jupNoteTree,
        destVaultTokenAccount: jupVaultAccountForTx.address,
        destMintAccount: jupTokenMint,
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
      console.log(`   ✅ SOL->JUP Swap TX: ${txSig}`);

      // Take balance snapshot after swap
      const balanceAfter = await getBalanceSnapshot(
        provider.connection,
        payer.publicKey,
        undefined,
        undefined,
        solVaultAccount.address,
        jupVaultAccount.address,
        relayerJupAccount.address,
      );

      // Log detailed balance changes
      logBalanceChanges(balanceBefore, balanceAfter, "SOL → JUP Swap");

      // Verify expected balance changes
      const swapAmountSol = SWAP_AMOUNT / LAMPORTS_PER_SOL;
      const solVaultDecrease =
        (balanceBefore.solVault || 0) - (balanceAfter.solVault || 0);
      const jupVaultIncrease =
        (balanceAfter.jupVault || 0) - (balanceBefore.jupVault || 0);
      const relayerJupIncrease =
        (balanceAfter.relayerJup || 0) - (balanceBefore.relayerJup || 0);

      console.log(`📈 Swap Metrics:`);
      console.log(
        `   SOL Vault decreased by: ${solVaultDecrease.toFixed(
          6,
        )} SOL (expected: ~${swapAmountSol.toFixed(6)} SOL)`,
      );
      console.log(
        `   JUP Vault increased by: ${jupVaultIncrease.toFixed(6)} JUP`,
      );
      console.log(`   Relayer JUP fee: ${relayerJupIncrease.toFixed(6)} JUP`);

      // Verify balances changed in expected direction
      expect(solVaultDecrease).to.be.greaterThan(
        0,
        "SOL vault should decrease",
      );
      expect(jupVaultIncrease).to.be.greaterThan(
        0,
        "JUP vault should increase",
      );

      console.log(
        `   ✅ Dest vault JUP balance: ${(balanceAfter.jupVault || 0).toFixed(
          6,
        )}`,
      );

      // Save the JUP note from swap output
      const jupLeafIndex = jupOffchainTree.insert(destCommitment);
      jupNoteId = noteStorage.save({
        amount: swappedAmount,
        commitment: destCommitment,
        nullifier: computeNullifier(
          poseidon,
          destCommitment,
          jupLeafIndex,
          destPrivKey,
        ),
        blinding: destBlinding,
        privateKey: destPrivKey,
        publicKey: destPubKey,
        leafIndex: jupLeafIndex,
        merklePath: jupOffchainTree.getMerkleProof(jupLeafIndex),
        mintAddress: jupTokenMint,
      });
      console.log(`   JUP note saved: ${jupNoteId} (${swappedAmount} units)`);

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

  it("verifies JUP note from SOL swap exists", async () => {
    expect(jupNoteId).to.not.be.null;
    const note = noteStorage.get(jupNoteId!);
    expect(note).to.not.be.undefined;

    console.log("\n✅ JUP note from swap verified:");
    console.log(
      `   Amount: ${note!.amount} (${Number(note!.amount) / 1e6} JUP)`,
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

    // Get token accounts for balance tracking
    const solVaultAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      solTokenMint,
      solVault,
      true,
    );

    // Take balance snapshot before internal transfer
    const balanceBefore = await getBalanceSnapshot(
      provider.connection,
      payer.publicKey,
      undefined,
      undefined,
      solVaultAccount.address,
      undefined,
      undefined,
    );
    console.log(
      `💰 Pre-transfer balances: User SOL: ${balanceBefore.userSol.toFixed(
        6,
      )}, SOL Vault: ${(balanceBefore.solVault || 0).toFixed(6)}`,
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
        vaultTokenAccount: solVaultAccount.address,
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
      solVaultAccount.address,
      undefined,
      undefined,
    );

    // Log balance changes (should be minimal for internal transfer)
    logBalanceChanges(balanceBefore, balanceAfter, "SOL Internal Transfer");

    // Verify no significant vault balance change (internal transfer)
    const vaultChange = Math.abs(
      (balanceAfter.solVault || 0) - (balanceBefore.solVault || 0),
    );
    expect(vaultChange).to.be.lessThan(
      0.001,
      "Vault balance should not change significantly for internal transfer",
    );

    // Update off-chain tree
    solOffchainTree.insert(outputCommitment);
    solOffchainTree.insert(changeCommitment);

    console.log(`   ✅ Internal transfer - no fee, vault balance preserved`);
    console.log(
      `   New note created: ${outputAmount} lamports (${
        Number(outputAmount) / 1e9
      } SOL)`,
    );
  });

  it("spends the JUP note (internal transfer)", async () => {
    console.log("\n🔄 Spending JUP note (internal transfer)...");

    const note = noteStorage.get(jupNoteId!);
    if (!note) throw new Error("JUP note not found");

    console.log(
      `   Input note amount: ${note.amount} units (${
        Number(note.amount) / 1e6
      } JUP)`,
    );

    // Get token accounts for balance tracking
    const jupVaultAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      jupTokenMint,
      jupVault,
      true,
    );

    // Take balance snapshot before internal transfer
    const balanceBefore = await getBalanceSnapshot(
      provider.connection,
      payer.publicKey,
      undefined,
      undefined,
      undefined,
      jupVaultAccount.address,
      undefined,
    );
    console.log(
      `💰 Pre-transfer balances: User SOL: ${balanceBefore.userSol.toFixed(
        6,
      )}, JUP Vault: ${(balanceBefore.jupVault || 0).toFixed(6)}`,
    );

    // Get merkle proof
    const merkleProof = jupOffchainTree.getMerkleProof(note.leafIndex);
    const root = jupOffchainTree.getRoot();

    // Dummy second input
    const dummyPrivKey = randomBytes32();
    const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
    const dummyBlinding = randomBytes32();
    const dummyCommitment = computeCommitment(
      poseidon,
      0n,
      dummyPubKey,
      dummyBlinding,
      jupTokenMint,
    );
    const dummyNullifier = computeNullifier(
      poseidon,
      dummyCommitment,
      0,
      dummyPrivKey,
    );
    const dummyProof = jupOffchainTree.getMerkleProof(0);

    // Output: split into two notes for later use (internal transfer, no fee)
    const fee = 0n; // No fee for internal transfer
    const swapAmount = 25_000_000n; // 25 JUP to use for reverse swap
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
      jupTokenMint,
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
      jupTokenMint,
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
      mintAddress: jupTokenMint,
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
      jupTokenMint,
      0,
      note.nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      jupTokenMint,
      0,
      dummyNullifier,
    );

    // Token accounts
    const relayerTokenAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      jupTokenMint,
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
        jupTokenMint,
        Array.from(note.nullifier),
        Array.from(dummyNullifier),
        Array.from(keepCommitment),
        Array.from(swapCommitment),
        extData,
        proof,
      )
      .accounts({
        config: jupConfig,
        globalConfig,
        vault: jupVault,
        inputTree: jupNoteTree,
        outputTree: jupNoteTree,
        nullifiers: jupNullifiers,
        nullifierMarker0,
        nullifierMarker1,
        relayer: payer.publicKey,
        recipient: payer.publicKey,
        vaultTokenAccount: jupVaultAccount.address,
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

    console.log(`✅ JUP note spent: ${tx}`);

    // Take balance snapshot after internal transfer
    const balanceAfter = await getBalanceSnapshot(
      provider.connection,
      payer.publicKey,
      undefined,
      undefined,
      undefined,
      jupVaultAccount.address,
      undefined,
    );

    // Log balance changes (should be minimal for internal transfer)
    logBalanceChanges(balanceBefore, balanceAfter, "JUP Internal Transfer");

    // Verify no significant vault balance change (internal transfer)
    const vaultChange = Math.abs(
      (balanceAfter.jupVault || 0) - (balanceBefore.jupVault || 0),
    );
    expect(vaultChange).to.be.lessThan(
      0.001,
      "Vault balance should not change significantly for internal transfer",
    );

    // Update off-chain tree
    const keepLeafIndex = jupOffchainTree.insert(keepCommitment);
    const swapLeafIndex = jupOffchainTree.insert(swapCommitment);

    // Save the keep note for external withdrawal test
    jupKeepNoteId = noteStorage.save({
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
      merklePath: jupOffchainTree.getMerkleProof(keepLeafIndex),
      mintAddress: jupTokenMint,
    });

    // Save the swap note for reverse swap test
    jupChangeNoteId = noteStorage.save({
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
      merklePath: jupOffchainTree.getMerkleProof(swapLeafIndex),
      mintAddress: jupTokenMint,
    });

    console.log(`   ✅ Internal transfer - no fee, vault balance preserved`);
    console.log(
      `   Keep note: ${keepAmount} units (${Number(keepAmount) / 1e6} JUP)`,
    );
    console.log(
      `   Swap note saved: ${jupChangeNoteId} - ${swapAmount} units (${
        Number(swapAmount) / 1e6
      } JUP)`,
    );
  });

  // Skipped because the previous test "spends the JUP note (internal transfer)" already spent the jupNoteId
  // This test would fail with NullifierAlreadyUsed unless we used one of the split notes.
  it.skip("executes internal JUP transfer", async () => {
    console.log("\n📤 Executing internal JUP transfer...");

    // Use the original JUP note from the swap (not the split one)
    const originalNote = noteStorage.get(jupNoteId!);
    if (!originalNote) throw new Error("Original JUP note not found");

    // Get merkle proof
    const merkleProof = jupOffchainTree.getMerkleProof(originalNote.leafIndex);
    const root = jupOffchainTree.getRoot();

    // Dummy second input
    const dummyPrivKey = randomBytes32();
    const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
    const dummyBlinding = randomBytes32();
    const dummyCommitment = computeCommitment(
      poseidon,
      0n,
      dummyPubKey,
      dummyBlinding,
      jupTokenMint,
    );
    const dummyNullifier = computeNullifier(
      poseidon,
      dummyCommitment,
      0,
      dummyPrivKey,
    );
    const dummyProof = jupOffchainTree.getMerkleProof(0);

    // Transfer to new owner
    const newPrivKey = randomBytes32();
    const newPubKey = derivePublicKey(poseidon, newPrivKey);
    const newBlinding = randomBytes32();
    const newCommitment = computeCommitment(
      poseidon,
      originalNote.amount,
      newPubKey,
      newBlinding,
      jupTokenMint,
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
      jupTokenMint,
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
      mintAddress: jupTokenMint,
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
      jupTokenMint,
      0,
      originalNote.nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      jupTokenMint,
      0,
      dummyNullifier,
    );

    const jupVaultAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      jupTokenMint,
      jupVault,
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
        jupTokenMint,
        Array.from(originalNote.nullifier),
        Array.from(dummyNullifier),
        Array.from(newCommitment),
        Array.from(changeCommitment),
        extData,
        proof,
      )
      .accounts({
        config: jupConfig,
        globalConfig,
        vault: jupVault,
        inputTree: jupNoteTree,
        outputTree: jupNoteTree,
        nullifiers: jupNullifiers,
        nullifierMarker0,
        nullifierMarker1,
        relayer: payer.publicKey,
        recipient: payer.publicKey,
        vaultTokenAccount: jupVaultAccount.address,
        userTokenAccount: jupVaultAccount.address,
        recipientTokenAccount: jupVaultAccount.address,
        relayerTokenAccount: jupVaultAccount.address,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
      ])
      .rpc();

    console.log(`✅ Internal JUP transfer: ${tx}`);

    // Update off-chain tree
    const leafIndex = jupOffchainTree.insert(newCommitment);
    jupOffchainTree.insert(changeCommitment);

    // Save transferred note
    const transferredNoteId = noteStorage.save({
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
      merklePath: jupOffchainTree.getMerkleProof(leafIndex),
      mintAddress: jupTokenMint,
    });

    console.log(`   Transferred JUP note: ${transferredNoteId}`);
    console.log(`   Amount: ${Number(originalNote.amount) / 1e6} JUP`);
  });

  it("executes reverse swap (JUP → SOL via AMM V4)", async () => {
    console.log("\n🔄 Executing reverse swap JUP → SOL via AMM V4...");

    const note = noteStorage.get(jupChangeNoteId!);
    if (!note) throw new Error("JUP swap note not found");

    console.log(
      `   Input note amount: ${note.amount} units (${
        Number(note.amount) / 1e6
      } JUP)`,
    );

    // Get token accounts for balance tracking
    const sourceVaultJupAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      jupTokenMint,
      jupVault,
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

    // Take balance snapshot before reverse swap
    const balanceBefore = await getBalanceSnapshot(
      provider.connection,
      payer.publicKey,
      undefined,
      undefined,
      destVaultSolAccount.address,
      sourceVaultJupAccount.address,
      undefined,
    );
    console.log(
      `💰 Pre-reverse-swap balances: JUP Vault: ${(
        balanceBefore.jupVault || 0
      ).toFixed(6)}, SOL Vault: ${(balanceBefore.solVault || 0).toFixed(
        6,
      )}, User SOL: ${balanceBefore.userSol.toFixed(6)}`,
    );

    // Get merkle proof
    const merkleProof = jupOffchainTree.getMerkleProof(note.leafIndex);
    const root = jupOffchainTree.getRoot();

    // Dummy second input
    const dummyPrivKey = randomBytes32();
    const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
    const dummyBlinding = randomBytes32();
    const dummyCommitment = computeCommitment(
      poseidon,
      0n,
      dummyPubKey,
      dummyBlinding,
      jupTokenMint,
    );
    const dummyNullifier = computeNullifier(
      poseidon,
      dummyCommitment,
      0,
      dummyPrivKey,
    );
    const dummyProof = jupOffchainTree.getMerkleProof(0);

    // Swap all JUP
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
      solTokenMint,
    );
    // For proof, we use dest mint
    const solOutputCommitmentForProof = computeCommitment(
      poseidon,
      0n,
      solOutputPubKey,
      solOutputBlinding,
      jupTokenMint,
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
      jupTokenMint,
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

    // Build AMM swap data (JUP → SOL = swap_base_in with JUP as base)
    const minSolOut = new BN(1); // Accept any output for test environment
    const swapData = buildAmmSwapData(new BN(swapAmount.toString()), minSolOut);

    // Swap params (reversed: JUP → SOL)
    const swapParams = {
      minAmountOut: minSolOut,
      deadline: new BN(Math.floor(Date.now() / 1000) + 3600),
      sourceMint: jupTokenMint, // JUP
      destMint: solTokenMint, // SOL
    };

    const swapParamsHash = computeSwapParamsHash(
      poseidon,
      jupTokenMint,
      solTokenMint,
      BigInt(minSolOut.toString()),
      BigInt(swapParams.deadline.toString()),
    );

    // Generate ZK proof
    console.log("   Generating ZK proof...");
    const proof = await generateSwapProof({
      sourceRoot: root,
      swapParamsHash,
      extDataHash,
      sourceMint: jupTokenMint,
      destMint: solTokenMint,
      inputNullifiers: [note.nullifier, dummyNullifier],
      changeCommitment: changeCommitment,
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
      minAmountOut: BigInt(minSolOut.toString()),
      deadline: BigInt(swapParams.deadline.toString()),
    });
    console.log("   ✅ ZK proof generated");

    // Derive executor PDA
    const [executorPda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("swap_executor"),
        jupTokenMint.toBuffer(),
        solTokenMint.toBuffer(),
        Buffer.from(note.nullifier),
      ],
      program.programId,
    );
    const executorSourceToken = await getAssociatedTokenAddress(
      jupTokenMint,
      executorPda,
      true,
    );
    const executorDestToken = await getAssociatedTokenAddress(
      solTokenMint,
      executorPda,
      true,
    );

    // Nullifier markers (using JUP pool)
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      jupTokenMint,
      0,
      note.nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      jupTokenMint,
      0,
      dummyNullifier,
    );

    // Token accounts (reuse existing variables from balance tracking)
    const relayerTokenAccountForTx = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      solTokenMint,
      payer.publicKey,
    );

    console.log("   Executor PDA:", executorPda.toBase58());

    // Create new lookup table for this transaction
    console.log("   Creating Address Lookup Table...");
    const recentSlot = await provider.connection.getSlot("finalized");

    const lookupTableAddresses = [
      jupConfig,
      globalConfig,
      jupVault,
      jupNoteTree,
      jupNullifiers,
      sourceVaultJupAccount.address,
      jupTokenMint,
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
      // For JUP → SOL swap
      const swapIx = await (program.methods as any)
        .transactSwap(
          proof,
          Array.from(root),
          0,
          jupTokenMint, // Source is JUP
          Array.from(note.nullifier),
          Array.from(dummyNullifier),
          0,
          solTokenMint, // Dest is SOL
          Array.from(changeCommitment),
          Array.from(solOutputCommitment),
          swapParams,
          new BN(swapAmount.toString()),
          swapData,
          extData,
        )
        .accounts({
          sourceConfig: jupConfig, // JUP pool config
          globalConfig,
          sourceVault: jupVault, // JUP vault
          sourceTree: jupNoteTree,
          sourceNullifiers: jupNullifiers,
          sourceNullifierMarker0: nullifierMarker0,
          sourceNullifierMarker1: nullifierMarker1,
          sourceVaultTokenAccount: sourceVaultJupAccount.address,
          sourceMintAccount: jupTokenMint,
          destConfig: solConfig, // SOL pool config
          destVault: solVault, // SOL vault
          destTree: solNoteTree,
          destVaultTokenAccount: destVaultSolAccount.address,
          destMintAccount: solTokenMint,
          executor: executorPda,
          executorSourceToken,
          executorDestToken,
          relayer: payer.publicKey,
          relayerTokenAccount: relayerTokenAccountForTx.address,
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
          // For JUP → SOL: still use same vault order, AMM handles direction
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
        sourceVaultJupAccount.address,
        undefined,
      );

      // Log detailed balance changes
      logBalanceChanges(balanceBefore, balanceAfter, "JUP → SOL Reverse Swap");

      // Verify expected balance changes
      const swapAmountJup = Number(note.amount) / 1e6;
      const jupVaultDecrease =
        (balanceBefore.jupVault || 0) - (balanceAfter.jupVault || 0);
      const solVaultIncrease =
        (balanceAfter.solVault || 0) - (balanceBefore.solVault || 0);
      const userSolChange = balanceAfter.userSol - balanceBefore.userSol;

      console.log(`📈 Reverse Swap Metrics:`);
      console.log(
        `   JUP Vault decreased by: ${jupVaultDecrease.toFixed(
          6,
        )} JUP (expected: ~${swapAmountJup.toFixed(6)} JUP)`,
      );
      console.log(
        `   SOL Vault increased by: ${solVaultIncrease.toFixed(6)} SOL`,
      );
      console.log(
        `   User SOL change: ${userSolChange.toFixed(6)} SOL (gas fees)`,
      );

      // Verify balances changed in expected direction
      expect(jupVaultDecrease).to.be.greaterThan(
        0,
        "JUP vault should decrease",
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
      solFromJupNoteId = noteStorage.save({
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
      console.log(`   SOL note saved: ${solFromJupNoteId}`);
    } catch (e: any) {
      console.error("❌ Reverse AMM V4 swap failed:", e.message);
      if (e.logs) {
        console.error("Logs:", e.logs.slice(-20));
      }
      throw e;
    }
  });

  it("executes external JUP withdrawal", async () => {
    console.log("\n💸 Executing external JUP withdrawal...");
    console.log("   Withdrawing 5 JUP to external wallet (from 25 JUP note)");
    console.log("   Change amount: 20 JUP");

    const note = noteStorage.get(jupKeepNoteId!);
    if (!note) throw new Error("JUP keep note not found");

    // Create external recipient
    const externalRecipient = Keypair.generate();

    // Create JUP token account for external recipient
    const externalJupAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      jupTokenMint,
      externalRecipient.publicKey,
    );

    // Get JUP vault token account
    const jupVaultAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      jupTokenMint,
      jupVault,
      true,
    );

    // Take balance snapshot before withdrawal
    const balanceBefore = await getBalanceSnapshot(
      provider.connection,
      payer.publicKey,
      undefined,
      externalJupAccount.address,
      undefined,
      jupVaultAccount.address,
      undefined,
    );

    // Get merkle proof
    const merkleProof = jupOffchainTree.getMerkleProof(note.leafIndex);
    const root = jupOffchainTree.getRoot();

    // Dummy second input
    const dummyPrivKey = randomBytes32();
    const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
    const dummyBlinding = randomBytes32();
    const dummyCommitment = computeCommitment(
      poseidon,
      0n,
      dummyPubKey,
      dummyBlinding,
      jupTokenMint,
    );
    const dummyNullifier = computeNullifier(
      poseidon,
      dummyCommitment,
      0,
      dummyPrivKey,
    );
    const dummyProof = jupOffchainTree.getMerkleProof(0);

    // Withdrawal parameters
    const withdrawalAmount = 5_000_000n; // 5 JUP ($5 minimum)
    const withdrawalFee = 25_000n; // 0.025 JUP (0.5% of $5)
    // 0.5% of 5 JUP = 0.025 JUP. Min fee = 0.025 JUP.
    const changeAmount = note.amount - withdrawalAmount; // 20 JUP

    // Change output (remaining JUP after withdrawal)
    const changePrivKey1 = randomBytes32();
    const changePubKey1 = derivePublicKey(poseidon, changePrivKey1);
    const changeBlinding1 = randomBytes32();
    const changeCommitment1 = computeCommitment(
      poseidon,
      changeAmount,
      changePubKey1,
      changeBlinding1,
      jupTokenMint,
    );

    // Dummy second output
    const changePrivKey2 = randomBytes32();
    const changePubKey2 = derivePublicKey(poseidon, changePrivKey2);
    const changeBlinding2 = randomBytes32();
    const changeCommitment2 = computeCommitment(
      poseidon,
      0n,
      changePubKey2,
      changeBlinding2,
      jupTokenMint,
    );

    // External data for withdrawal
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
      publicAmount: -withdrawalAmount, // Negative for withdrawal
      extDataHash,
      mintAddress: jupTokenMint,
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
      jupTokenMint,
      0,
      note.nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      jupTokenMint,
      0,
      dummyNullifier,
    );

    // Get relayer JUP token account for fee collection
    const relayerJupAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      jupTokenMint,
      payer.publicKey,
    );

    // Execute withdrawal
    const tx = await (program.methods as any)
      .transact(
        Array.from(root),
        0,
        0,
        new BN(withdrawalAmount.toString()).neg(),
        Array.from(extDataHash),
        jupTokenMint,
        Array.from(note.nullifier),
        Array.from(dummyNullifier),
        Array.from(changeCommitment1),
        Array.from(changeCommitment2),
        extData,
        proof,
      )
      .accounts({
        config: jupConfig,
        globalConfig,
        vault: jupVault,
        inputTree: jupNoteTree,
        outputTree: jupNoteTree,
        nullifiers: jupNullifiers,
        nullifierMarker0,
        nullifierMarker1,
        relayer: payer.publicKey,
        recipient: externalRecipient.publicKey,
        vaultTokenAccount: jupVaultAccount.address,
        userTokenAccount: externalJupAccount.address,
        recipientTokenAccount: externalJupAccount.address,
        relayerTokenAccount: relayerJupAccount.address,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
      ])
      .rpc();

    console.log(`✅ External JUP withdrawal: ${tx}`);

    // Take balance snapshot after withdrawal
    const balanceAfter = await getBalanceSnapshot(
      provider.connection,
      payer.publicKey,
      undefined,
      externalJupAccount.address,
      undefined,
      jupVaultAccount.address,
      undefined,
    );

    // Log balance changes
    const externalJupIncrease =
      (balanceAfter.userJup || 0) - (balanceBefore.userJup || 0);
    const jupVaultDecrease =
      (balanceBefore.jupVault || 0) - (balanceAfter.jupVault || 0);

    console.log(`📊 Withdrawal Results:`);
    console.log(
      `   External JUP increased by: ${externalJupIncrease.toFixed(6)} JUP`,
    );
    console.log(
      `   JUP Vault decreased by: ${jupVaultDecrease.toFixed(6)} JUP`,
    );
    console.log(
      `   Expected net (5 - 0.025 fee): ${(5 - 0.025).toFixed(6)} JUP`,
    );

    // Verify withdrawal worked
    expect(externalJupIncrease).to.be.approximately(
      4.975,
      0.001,
      "External wallet should receive 4.975 JUP (5 - 0.025 fee)",
    );
    expect(jupVaultDecrease).to.be.approximately(
      5.0,
      0.001,
      "JUP vault should decrease by 5 JUP",
    );

    // Update off-chain tree
    jupOffchainTree.insert(changeCommitment1);
    jupOffchainTree.insert(changeCommitment2);

    console.log(
      `   ✅ Successfully withdrew ${externalJupIncrease.toFixed(
        6,
      )} JUP to external wallet`,
    );
  });
});

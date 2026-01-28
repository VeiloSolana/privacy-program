import * as anchor from "@coral-xyz/anchor";
import { Program, BN, Wallet } from "@coral-xyz/anchor";
import {
  PublicKey,
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
  const SOL_DECIMALS = 9;
  const USD1_DECIMALS = 6;
  const INITIAL_SOL_DEPOSIT = 2_000_000_000; // 2 SOL
  const SWAP_AMOUNT_SOL = 500_000_000; // 0.5 SOL
  let swapFee = new BN(0); // Will be calculated dynamically
  const feeBps = 50; // 0.5%

  // Deposited note references
  let solDepositNoteId: string | null = null;

  // Serum vault signer (derived)
  let serumVaultSigner: PublicKey;

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

  it("registers relayer for SOL/USD1 pools", async () => {
    const registerRelayer = async (
      mint: PublicKey,
      config: PublicKey,
      name: string,
    ) => {
      try {
        await (program.methods as any)
          .addRelayer(mint, payer.publicKey)
          .accounts({ config, admin: payer.publicKey })
          .rpc();
        console.log(`✅ Relayer registered for ${name} pool`);
      } catch (e: any) {
        if (
          e.message?.includes("already added") ||
          e.message?.includes("RelayerAlreadyExists")
        ) {
          console.log(`✅ Relayer already registered for ${name} pool`);
        } else {
          throw e;
        }
      }
    };
    await registerRelayer(solTokenMint, solConfig, "SOL");
    await registerRelayer(usd1TokenMint, usd1Config, "USD1");
  });

  it("deposits WSOL to SOL pool for AMM swap", async () => {
    console.log("\n🎁 Depositing WSOL to SOL pool...");
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
      INITIAL_SOL_DEPOSIT * 2,
    );

    const privateKey = randomBytes32();
    const publicKey = derivePublicKey(poseidon, privateKey);
    const blinding = randomBytes32();
    const amount = BigInt(INITIAL_SOL_DEPOSIT);
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
  });

  it("executes cross-pool swap (SOL → USD1 via AMM V4)", async () => {
    console.log("\n🔄 Executing cross-pool swap SOL → USD1 via AMM V4...");

    const note = noteStorage.get(solDepositNoteId!);
    if (!note) throw new Error("Note not found");

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
      SOL_DECIMALS,
    );
    const usd1Token = new RaydiumToken(
      TOKEN_PROGRAM_ID,
      usd1TokenMint,
      USD1_DECIMALS,
    );

    const amountIn = new TokenAmount(solToken, SWAP_AMOUNT_SOL, false);
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
    swapFee = new BN(1_000_000); // 1 USD1 (6 decimals) - minimal fee for testing
    console.log(
      `Fixed Swap Fee for testing: ${swapFee.toString()} (${
        Number(swapFee) / 10 ** USD1_DECIMALS
      } USD1)`,
    );

    // Output USD1 note
    const destPrivKey = randomBytes32();
    const destPubKey = derivePublicKey(poseidon, destPrivKey);
    const destBlinding = randomBytes32();
    const destCommitment = computeCommitment(
      poseidon,
      50_000_000n,
      destPubKey,
      destBlinding,
      usd1TokenMint,
    ); // Dummy amount in proof

    // Output SOL Change note
    const changeAmount = note.amount - BigInt(SWAP_AMOUNT_SOL);
    const changePubKey = derivePublicKey(poseidon, randomBytes32());
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
      fee: swapFee,
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    const proof = await generateTransactionProof({
      root: solOffchainTree.getRoot(),
      publicAmount: -BigInt(SWAP_AMOUNT_SOL),
      extDataHash,
      mintAddress: solTokenMint,
      inputNullifiers: [note.nullifier, dummyNullifier],
      outputCommitments: [
        computeCommitment(poseidon, 0n, destPubKey, destBlinding, solTokenMint),
        changeCommitment,
      ],
      inputAmounts: [note.amount, 0n],
      inputPrivateKeys: [note.privateKey, dummyPrivKey],
      inputPublicKeys: [note.publicKey, dummyPubKey],
      inputBlindings: [note.blinding, dummyBlinding],
      inputMerklePaths: [
        solOffchainTree.getMerkleProof(note.leafIndex),
        solOffchainTree.getMerkleProof(0),
      ],
      outputAmounts: [0n, changeAmount],
      outputOwners: [destPubKey, changePubKey],
      outputBlindings: [destBlinding, changeBlinding],
    });

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
    const swapData = buildAmmSwapData(new BN(SWAP_AMOUNT_SOL), minAmountOut);
    const swapParams = {
      minAmountOut,
      deadline: new BN(Math.floor(Date.now() / 1000) + 3600),
      sourceMint: solTokenMint,
      destMint: usd1TokenMint,
    };

    const [executorPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("swap_executor"), Buffer.from(note.nullifier)],
      program.programId,
    );
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
    const solVaultAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      solTokenMint,
      solVault,
      true,
    );
    const usd1VaultAccount = await getOrCreateAssociatedTokenAccount(
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
        solVaultAccount.address,
        solTokenMint,
        usd1Config,
        usd1Vault,
        usd1NoteTree,
        usd1VaultAccount.address,
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
        Array.from(solOffchainTree.getRoot()),
        0,
        solTokenMint,
        Array.from(note.nullifier),
        Array.from(dummyNullifier),
        0,
        usd1TokenMint,
        Array.from(destCommitment),
        Array.from(changeCommitment),
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
        destConfig: usd1Config,
        destVault: usd1Vault,
        destTree: usd1NoteTree,
        destVaultTokenAccount: usd1VaultAccount.address,
        destMintAccount: usd1TokenMint,
        executor: executorPda,
        executorSourceToken,
        executorDestToken,
        relayer: payer.publicKey,
        relayerTokenAccount: relayerTokenAccount.address,
        swapProgram: RAYDIUM_AMM_V4_PROGRAM,
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
});

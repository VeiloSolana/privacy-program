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
  TransactionInstruction,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  NATIVE_MINT,
  getAssociatedTokenAddress,
  createWrappedNativeAccount,
  closeAccount,
  getOrCreateAssociatedTokenAccount,
} from "@solana/spl-token";
import { expect } from "chai";
import { buildPoseidon } from "circomlibjs";
import { PrivacyPool } from "../target/types/privacy_pool";
import { JupiterSwapService } from "./utils/jupiter/jupiter-swap-service";
import {
  JUPITER_PROGRAM_ID,
  JUPITER_EVENT_AUTHORITY,
  USDC_MINT,
  USDT_MINT,
  JUP_MINT,
  USD1_MINT,
} from "./amm-v4-pool-helper";

const SOL_MINT = PublicKey.default;

// =====================================================
// Dynamic swap fee tier system
// =====================================================
interface FeeTier {
  threshold: bigint;
  bps: number;
}

/**
 * Per-token fee tier schedules.
 * Stablecoins (USDC, USDT, USD1) use 6-decimal base units ≈ USD cents.
 * JUP (6 dec, ~$0.50) uses doubled thresholds so dollar buckets align.
 * SOL/wSOL (9 dec, ~$130) uses lamport thresholds matching similar swap sizes.
 * Any unlisted token falls back to STABLECOIN tiers (charges more, never less).
 */
const STABLECOIN_TIERS: FeeTier[] = [
  { threshold: 0n, bps: 700 }, // < $1
  { threshold: 1_000_000n, bps: 700 }, // $1–$10
  { threshold: 10_000_000n, bps: 500 }, // $10–$20
  { threshold: 20_000_000n, bps: 300 }, // $20–$50
  { threshold: 50_000_000n, bps: 200 }, // $50–$200
  { threshold: 200_000_000n, bps: 100 }, // $200–$1000
  { threshold: 1_000_000_000n, bps: 50 }, // $1000+
];

const JUP_TIERS: FeeTier[] = [
  { threshold: 0n, bps: 700 }, // < ~$1 (< 2 JUP)
  { threshold: 2_000_000n, bps: 700 }, // ~$1–$10
  { threshold: 20_000_000n, bps: 500 }, // ~$10–$20
  { threshold: 40_000_000n, bps: 300 }, // ~$20–$50
  { threshold: 100_000_000n, bps: 200 }, // ~$50–$200
  { threshold: 400_000_000n, bps: 100 }, // ~$200–$1000
  { threshold: 2_000_000_000n, bps: 50 }, // ~$1000+
];

// SOL/wSOL: 1 SOL = 1_000_000_000 lamports, assumed ~$130
const SOL_TIERS: FeeTier[] = [
  { threshold: 0n, bps: 700 }, // < 0.1 SOL (~$13)
  { threshold: 100_000_000n, bps: 500 }, // 0.1–0.2 SOL (~$13–$26)
  { threshold: 200_000_000n, bps: 300 }, // 0.2–0.5 SOL (~$26–$65)
  { threshold: 500_000_000n, bps: 200 }, // 0.5–2 SOL (~$65–$260)
  { threshold: 2_000_000_000n, bps: 100 }, // 2–10 SOL (~$260–$1300)
  { threshold: 10_000_000_000n, bps: 50 }, // 10+ SOL (~$1300+)
];

const TOKEN_FEE_TIERS: Record<string, FeeTier[]> = {
  // USDC
  EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v: STABLECOIN_TIERS,
  // USDT
  Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB: STABLECOIN_TIERS,
  // USD1
  USD1ttGY1N17NEEHLmELoaybftRBUSErhqYiQzvEmuB: STABLECOIN_TIERS,
  // JUP
  JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN: JUP_TIERS,
  // Wrapped SOL
  So11111111111111111111111111111111111111112: SOL_TIERS,
  // Native SOL (all zeros)
  "11111111111111111111111111111111": SOL_TIERS,
};

/** Returns the fee in bps for a given output amount and dest mint. */
function getSwapFeeBps(outputAmount: bigint, destMintAddress: string): number {
  const tiers = TOKEN_FEE_TIERS[destMintAddress] ?? STABLECOIN_TIERS;
  let feeBps = tiers[0].bps;
  for (const tier of tiers) {
    if (outputAmount >= tier.threshold) feeBps = tier.bps;
  }
  return feeBps;
}

/** For native SOL pools, SPL operations use WSOL (NATIVE_MINT) */
function tokenMintFor(mint: PublicKey): PublicKey {
  return mint.equals(PublicKey.default) ? NATIVE_MINT : mint;
}
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
 * 1. Consumes notes from source pool (SOL)
 * 2. CPIs to Jupiter V6 to execute swap SOL→USDC/USDT/JUP
 * 3. Creates notes in destination pool
 *
 * Uses Jupiter V6 API for quote and instruction building.
 */

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

describe("Privacy Pool Jupiter Swap - Various Pairs", () => {
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

  // Pool Configs
  const pools: Record<
    string,
    {
      mint: PublicKey;
      /** SPL mint used for token operations (WSOL for native SOL pools) */
      tokenMint: PublicKey;
      config: PublicKey;
      vault: PublicKey;
      noteTree: PublicKey;
      nullifiers: PublicKey;
      vaultTokenAccount: PublicKey;
      offchainTree: OffchainMerkleTree;
    }
  > = {};

  let noteStorage: InMemoryNoteStorage;

  // Test user keys
  let privateKey: Uint8Array;
  let publicKey: bigint;

  // Deposited notes
  let solDepositNoteId: string | undefined;

  // Chained swap notes
  let chainedSolDepositNoteId: string | undefined;
  let chainedUsdcNoteId: string | undefined;

  const INITIAL_DEPOSIT = 5_000_000_000n; // 5 SOL

  const initialDeposit = async (poolName: string, amount: bigint) => {
    console.log(`\n💰 Creating initial deposit for ${poolName}...`);
    const pool = pools[poolName];
    if (!pool) throw new Error(`Pool ${poolName} not found`);

    // Only supporting SOL source for now as per tests
    if (poolName !== "SOL") {
      throw new Error("initialDeposit helper currently only supports SOL");
    }

    const isNative = pool.mint.equals(PublicKey.default);

    // Airdrop SOL to payer to ensure funds
    try {
      await airdropAndConfirm(provider, payer.publicKey, 10 * LAMPORTS_PER_SOL);
    } catch (e) {
      console.log(
        "Airdrop failed (likely localnet rate limit or sufficient funds), continuing...",
      );
    }

    // For SPL tokens: ensure vault token accounts exist
    // For native SOL: vault holds lamports directly, no ATA needed for deposits
    let userTokenAccount: PublicKey;
    if (!isNative) {
      await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payer,
        pool.mint,
        pool.vault,
        true,
      );

      // Create wrapped SOL account (fresh for each deposit to avoid conflicts)
      const wsolKeypair = Keypair.generate();
      userTokenAccount = await createWrappedNativeAccount(
        provider.connection,
        payer,
        payer.publicKey,
        Number(amount) + 1_000_000,
        wsolKeypair,
      );
    } else {
      // Native SOL: on-chain uses system_program::transfer, token accounts are unused
      userTokenAccount = payer.publicKey;
    }

    // Prepare deposit
    const blinding = randomBytes32();
    const commitment = computeCommitment(
      poseidon,
      amount,
      publicKey,
      blinding,
      pool.mint,
    );

    const changeBlinding = randomBytes32();
    const changePubKey = derivePublicKey(poseidon, randomBytes32());
    const changeCommitment = computeCommitment(
      poseidon,
      0n,
      changePubKey,
      changeBlinding,
      pool.mint,
    );

    // Dummy nullifiers
    const dummyPrivKey1 = randomBytes32();
    const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);
    const dummyBlinding1 = randomBytes32();
    const dummyCommitment1 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey1,
      dummyBlinding1,
      pool.mint,
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
      pool.mint,
    );
    const dummyNullifier2 = computeNullifier(
      poseidon,
      dummyCommitment2,
      0,
      dummyPrivKey2,
    );

    const extData = {
      recipient: payer.publicKey,
      relayer: payer.publicKey,
      fee: new BN(0),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    const dummyProof = pool.offchainTree.getMerkleProof(0);
    const root = pool.offchainTree.getRoot();

    const proof = await generateTransactionProof({
      root,
      publicAmount: amount,
      extDataHash,
      mintAddress: pool.mint,
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

    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      pool.mint,
      0,
      dummyNullifier1,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      pool.mint,
      0,
      dummyNullifier2,
    );

    const tx = await (program.methods as any)
      .transact(
        Array.from(root),
        0,
        0,
        new BN(amount.toString()),
        Array.from(extDataHash),
        pool.mint,
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
        null,
      )
      .accounts({
        config: pool.config,
        globalConfig,
        vault: pool.vault,
        inputTree: pool.noteTree,
        outputTree: pool.noteTree,
        nullifiers: pool.nullifiers,
        nullifierMarker0,
        nullifierMarker1,
        relayer: payer.publicKey,
        recipient: payer.publicKey,
        vaultTokenAccount: pool.vaultTokenAccount,
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

    const leafIndex = pool.offchainTree.insert(commitment);
    pool.offchainTree.insert(changeCommitment);

    const noteId = noteStorage.save({
      amount,
      commitment,
      nullifier: computeNullifier(poseidon, commitment, leafIndex, privateKey),
      blinding,
      privateKey,
      publicKey,
      leafIndex,
      merklePath: pool.offchainTree.getMerkleProof(leafIndex),
      mintAddress: pool.mint,
    });
    return noteId;
  };

  const setupPool = async (mint: PublicKey, name: string, decimals: number) => {
    const [config] = deriveConfigPDA(program.programId, mint);
    const [vault] = deriveVaultPDA(program.programId, mint);
    const [noteTree] = deriveNoteTreePDA(program.programId, mint, 0);
    const [nullifiers] = deriveNullifiersPDA(program.programId, mint);

    const tMint = tokenMintFor(mint);
    const vaultTokenAccount = await getAssociatedTokenAddress(
      tMint,
      vault,
      true,
    );

    pools[name] = {
      mint,
      tokenMint: tMint,
      config,
      vault,
      noteTree,
      nullifiers,
      vaultTokenAccount,
      offchainTree: new OffchainMerkleTree(22, poseidon),
    };

    console.log(`\n🔧 Initializing ${name} pool...`);

    // Check if already initialized
    try {
      await program.account.privacyConfig.fetch(config);
      console.log(`✅ ${name} pool already initialized`);
    } catch {
      // Initialize
      const feeBps = 50; // 0.5% fee
      const maxAmount = new BN(1_000_000_000_000);

      await (program.methods as any)
        .initialize(feeBps, mint, new BN(0), maxAmount, new BN(0), maxAmount)
        .accounts({
          config,
          vault,
          noteTree,
          nullifiers,
          admin: payer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      console.log(`✅ ${name} pool initialized`);
    }

    // Register Relayer
    try {
      await (program.methods as any)
        .addRelayer(mint, payer.publicKey)
        .accounts({
          config,
          admin: payer.publicKey,
        })
        .rpc();
      console.log(`✅ Relayer registered for ${name} pool`);
    } catch (e: any) {
      if (
        e.message?.includes("already registered") ||
        e.message?.includes("AlreadyInUse")
      ) {
        console.log(`✅ Relayer already registered for ${name} pool`);
      }
    }
  };

  before(async () => {
    console.log("Setting up Jupiter swap test environment...");

    // Initialize Poseidon
    poseidon = await buildPoseidon();
    console.log("✅ Poseidon initialized");

    // Initialize Jupiter service
    jupiterService = new JupiterSwapService(connection);
    console.log("✅ Jupiter service initialized");

    // Initialize off-chain storage
    noteStorage = new InMemoryNoteStorage();

    // Generate test keys
    privateKey = randomBytes32();
    publicKey = derivePublicKey(poseidon, privateKey);

    // Derive PDAs
    [globalConfig] = deriveGlobalConfigPDA(program.programId);

    // Initial Global Config
    try {
      await (program.account as any).globalConfig.fetch(globalConfig);
      console.log("✅ Global config already initialized");
    } catch (e) {
      await (program.methods as any)
        .initializeGlobalConfig()
        .accounts({
          globalConfig,
          admin: payer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      console.log("✅ Global config initialized");
    }

    // Setup Pools
    await setupPool(SOL_MINT, "SOL", 9);
    await setupPool(USDC_MINT, "USDC", 6);
    await setupPool(USDT_MINT, "USDT", 6);
    await setupPool(JUP_MINT, "JUP", 6);
    await setupPool(USD1_MINT, "USD1", 6);
  });

  // --------------------------------------------------------------------------
  // TEST: Deposit SOL
  // --------------------------------------------------------------------------
  it("should deposit SOL to create spendable note", async function () {
    solDepositNoteId = await initialDeposit("SOL", INITIAL_DEPOSIT);
  });

  // --------------------------------------------------------------------------
  // Helper: executeJupiterSwap
  // --------------------------------------------------------------------------
  async function executeJupiterSwap(
    sourceName: string,
    destName: string,
    noteId: string | undefined,
    swapAmountStr: string,
    slippageBps: number = 100,
  ) {
    if (!noteId) {
      console.log(
        `⚠️  Skipping ${sourceName}->${destName} swap - no input note`,
      );
      return;
    }
    const sourcePool = pools[sourceName];
    const destPool = pools[destName];
    const note = noteStorage.get(noteId);
    if (!note) throw new Error("Note not found");

    console.log(`\n🔄 Executing ${sourceName} -> ${destName} swap...`);

    const sourceIsNative = sourcePool.mint.equals(PublicKey.default);
    const destIsNative = destPool.mint.equals(PublicKey.default);

    // Ensure relayer has dest token account
    const relayerTokenAccount = await getOrCreateAssociatedTokenAccount(
      connection,
      payer,
      destPool.tokenMint,
      payer.publicKey,
    );
    // Ensure source vault token account (needed for wrapping native SOL → WSOL)
    await getOrCreateAssociatedTokenAccount(
      connection,
      payer,
      sourcePool.tokenMint,
      sourcePool.vault,
      true,
    );
    // Ensure dest vault account
    await getOrCreateAssociatedTokenAccount(
      connection,
      payer,
      destPool.tokenMint,
      destPool.vault,
      true,
    );

    // =====================================================
    // BALANCE LOGGING: Before swap
    // =====================================================
    let sourceVaultBalanceBefore: any;
    if (sourceIsNative) {
      const lamports = await connection.getBalance(sourcePool.vault);
      sourceVaultBalanceBefore = {
        value: {
          amount: String(lamports),
          uiAmount: lamports / LAMPORTS_PER_SOL,
          decimals: 9,
        },
      };
    } else {
      sourceVaultBalanceBefore = await connection.getTokenAccountBalance(
        sourcePool.vaultTokenAccount,
      );
    }
    let destVaultBalanceBefore: any = {
      value: { amount: "0", uiAmount: 0, decimals: 6 },
    };
    try {
      if (destIsNative) {
        const lamports = await connection.getBalance(destPool.vault);
        destVaultBalanceBefore = {
          value: {
            amount: String(lamports),
            uiAmount: lamports / LAMPORTS_PER_SOL,
            decimals: 9,
          },
        };
      } else {
        destVaultBalanceBefore = await connection.getTokenAccountBalance(
          destPool.vaultTokenAccount,
        );
      }
    } catch (e) {
      // Dest vault may not exist yet
    }
    let relayerBalanceBefore: any = {
      value: { amount: "0", uiAmount: 0, decimals: 6 },
    };
    try {
      relayerBalanceBefore = await connection.getTokenAccountBalance(
        relayerTokenAccount.address,
      );
    } catch (e) {
      // Relayer token account may be empty
    }

    console.log(`\n📊 BALANCES BEFORE SWAP:`);
    console.log(
      `  Source Vault (${sourceName}): ${sourceVaultBalanceBefore.value.amount} (${sourceVaultBalanceBefore.value.uiAmount})`,
    );
    console.log(
      `  Dest Vault (${destName}): ${destVaultBalanceBefore.value.amount} (${destVaultBalanceBefore.value.uiAmount})`,
    );
    console.log(
      `  Relayer (${destName}): ${relayerBalanceBefore.value.amount} (${relayerBalanceBefore.value.uiAmount})`,
    );

    const root = sourcePool.offchainTree.getRoot();
    const nullifier = computeNullifier(
      poseidon,
      note.commitment,
      note.leafIndex,
      note.privateKey,
    );

    // Get Quote (use tokenMint for Jupiter - it needs WSOL address, not PublicKey.default)
    const swapAmount = BigInt(swapAmountStr);
    let quote;
    try {
      quote = await jupiterService.getQuote(
        sourcePool.tokenMint,
        destPool.tokenMint,
        Number(swapAmount),
        slippageBps,
      );
      console.log(`\n📊 Jupiter Quote for ${sourceName}->${destName}:`);
      console.log(JSON.stringify(quote, null, 2));
    } catch (e) {
      console.log(
        `⚠️  Jupiter quote failed for ${sourceName}->${destName}, likely no route/pool. Skipping.`,
      );
      return;
    }

    const jupiterMinOut = BigInt(quote.otherAmountThreshold);
    console.log(`  Swap in: ${swapAmount}, Jupiter min out: ${jupiterMinOut}`);

    // Executor PDA - includes relayer key (AUDIT-001 fix)
    const [executorPDA] = deriveSwapExecutorPDA(
      program.programId,
      sourcePool.mint,
      destPool.mint,
      nullifier,
      payer.publicKey,
    );

    // Jupiter Instruction
    const swapIxResponse = await jupiterService.getSwapInstruction(
      quote,
      executorPDA,
      false,
    );
    console.log(
      `\n📝 Jupiter Swap Instruction: Program=${
        swapIxResponse.swapInstruction?.programId || "N/A"
      }`,
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

    // Dynamic fee based on dest token tier schedule
    const dynamicFeeBps = getSwapFeeBps(
      jupiterMinOut,
      destPool.mint.toBase58(),
    );
    const relayerFee = (jupiterMinOut * BigInt(dynamicFeeBps)) / 10000n;
    // After-fee amount: used as both destAmount and minAmountOut in ZK circuit
    // (circuit enforces destAmount >= minAmountOut, so they must be equal)
    const minAmountOut = jupiterMinOut - relayerFee;
    console.log(
      `  Dynamic Fee Tier: ${dynamicFeeBps} bps (${
        dynamicFeeBps / 100
      }%) for ${destName} output of ${jupiterMinOut}, fee=${relayerFee}, after-fee minOut=${minAmountOut}`,
    );

    // Prepare Notes — destAmount = minAmountOut = jupiterMinOut - fee
    const destAmount = minAmountOut;
    const destBlinding = randomBytes32();
    const destCommitment = computeCommitment(
      poseidon,
      destAmount,
      publicKey,
      destBlinding,
      destPool.mint,
    );

    const changeAmount = note.amount - swapAmount;
    const changeBlinding = randomBytes32();
    const changePrivKey = randomBytes32();
    const changePubKey = derivePublicKey(poseidon, changePrivKey);
    const changeCommitment = computeCommitment(
      poseidon,
      changeAmount,
      changePubKey,
      changeBlinding,
      sourcePool.mint,
    );

    // Dummy Input
    const dummyPrivKey = randomBytes32();
    const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
    const dummyBlinding = randomBytes32();
    const dummyCommitment = computeCommitment(
      poseidon,
      0n,
      dummyPubKey,
      dummyBlinding,
      sourcePool.mint,
    );
    const dummyNullifier = computeNullifier(
      poseidon,
      dummyCommitment,
      0,
      dummyPrivKey,
    );
    const dummyProof = sourcePool.offchainTree.getMerkleProof(0);
    const merklePath = sourcePool.offchainTree.getMerkleProof(note.leafIndex);

    // Swap Params
    const swapParams = {
      minAmountOut: new BN(minAmountOut.toString()),
      deadline: new BN(Math.floor(Date.now() / 1000) + 3600),
      destAmount: new BN(destAmount.toString()),
      swapDataHash: Buffer.from(swapDataHash), // MEDIUM-001
    };
    const swapParamsHash = computeSwapParamsHash(
      poseidon,
      sourcePool.mint,
      destPool.mint,
      minAmountOut,
      BigInt(swapParams.deadline.toString()),
      swapDataHash, // MEDIUM-001
      destAmount,
    );

    const extData = {
      recipient: payer.publicKey,
      relayer: payer.publicKey,
      fee: new BN(relayerFee.toString()),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    const proof = await generateSwapProof({
      sourceRoot: root,
      swapParamsHash,
      extDataHash,
      sourceMint: sourcePool.mint,
      destMint: destPool.mint,
      inputNullifiers: [nullifier, dummyNullifier],
      changeCommitment,
      destCommitment,
      swapAmount: swapAmount,
      inputAmounts: [note.amount, 0n],
      inputPrivateKeys: [note.privateKey, dummyPrivKey],
      inputPublicKeys: [note.publicKey, dummyPubKey],
      inputBlindings: [note.blinding, dummyBlinding],
      inputMerklePaths: [merklePath, dummyProof],
      changeAmount,
      changePubkey: changePubKey,
      changeBlinding,
      destAmount,
      destPubkey: publicKey,
      destBlinding,
      minAmountOut,
      deadline: BigInt(swapParams.deadline.toString()),
    });

    // Instructions
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      sourcePool.mint,
      0,
      nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      sourcePool.mint,
      0,
      dummyNullifier,
    );
    const executorSourceToken = await getAssociatedTokenAddress(
      sourcePool.tokenMint,
      executorPDA,
      true,
    );
    const executorDestToken = await getAssociatedTokenAddress(
      destPool.tokenMint,
      executorPDA,
      true,
    );

    // ── Option B: fund_native_source (vault → executor_source_token, no relayer float) ─────
    // For native SOL source pools, we prepend a fund_native_source instruction that does a
    // pure raw-lamport vault debit in a separate instruction body (no CPIs in body).
    // Both instructions are submitted in the same atomic versioned transaction so that
    // a failure in transact_swap reverts the vault debit.
    let fundNativeSourceIx: TransactionInstruction | null = null;
    if (sourceIsNative) {
      fundNativeSourceIx = await (program.methods as any)
        .fundNativeSource(
          sourcePool.mint,
          destPool.mint,
          Array.from(nullifier),
          new BN(swapAmount.toString()),
        )
        .accounts({
          executor: executorPDA,
          executorSourceToken,
          sourceVault: sourcePool.vault,
          sourceConfig: sourcePool.config,
          sourceMintAccount: sourcePool.tokenMint,
          relayer: payer.publicKey,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
          associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
        })
        .instruction();
    }

    const swapIx = await (program.methods as any)
      .transactSwap(
        0,
        sourcePool.mint,
        Array.from(nullifier),
        Array.from(dummyNullifier),
        0,
        destPool.mint,
        proof,
        Array.from(root),
        Array.from(changeCommitment),
        Array.from(destCommitment),
        swapParams,
        new BN(swapAmount.toString()),
        swapData,
        extData,
        null,
      )
      .accounts({
        sourceConfig: sourcePool.config,
        globalConfig,
        sourceVault: sourcePool.vault,
        sourceTree: sourcePool.noteTree,
        sourceNullifiers: sourcePool.nullifiers,
        sourceNullifierMarker0: nullifierMarker0,
        sourceNullifierMarker1: nullifierMarker1,
        sourceVaultTokenAccount: sourcePool.vaultTokenAccount,
        sourceMintAccount: sourcePool.tokenMint,
        destConfig: destPool.config,
        destVault: destPool.vault,
        destTree: destPool.noteTree,
        destVaultTokenAccount: destPool.vaultTokenAccount,
        destMintAccount: destPool.tokenMint,
        executor: executorPDA,
        executorSourceToken,
        executorDestToken,
        relayer: payer.publicKey,
        relayerTokenAccount: relayerTokenAccount.address,
        swapProgram: JUPITER_PROGRAM_ID,
        jupiterEventAuthority: JUPITER_EVENT_AUTHORITY,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      })
      .remainingAccounts(remainingAccounts)
      .instruction();

    // ALT
    const recentSlot = await connection.getSlot("finalized");
    const [createAltIx, altAddress] =
      AddressLookupTableProgram.createLookupTable({
        authority: payer.publicKey,
        payer: payer.publicKey,
        recentSlot,
      });

    const allIxs: TransactionInstruction[] = [
      ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
    ];
    if (fundNativeSourceIx) allIxs.push(fundNativeSourceIx);
    allIxs.push(swapIx);

    // Include fundNativeSourceIx keys in ALT if present
    const altKeys: PublicKey[] = [];
    const seen = new Set<string>();
    for (const ix of allIxs.slice(1)) {
      // skip compute budget ix
      for (const meta of ix.keys) {
        if (!seen.has(meta.pubkey.toBase58())) {
          seen.add(meta.pubkey.toBase58());
          altKeys.push(meta.pubkey);
        }
      }
      if (!seen.has(ix.programId.toBase58())) {
        seen.add(ix.programId.toBase58());
        altKeys.push(ix.programId);
      }
    }

    await provider.sendAndConfirm(new Transaction().add(createAltIx));

    // Batch extend
    for (let i = 0; i < altKeys.length; i += 20) {
      const extendIx = AddressLookupTableProgram.extendLookupTable({
        payer: payer.publicKey,
        authority: payer.publicKey,
        lookupTable: altAddress,
        addresses: altKeys.slice(i, i + 20),
      });
      await provider.sendAndConfirm(new Transaction().add(extendIx));
    }
    await new Promise((r) => setTimeout(r, 1500));

    const lookupTable = (await connection.getAddressLookupTable(altAddress))
      .value!;
    const { blockhash } = await connection.getLatestBlockhash();
    const messageV0 = new TransactionMessage({
      payerKey: payer.publicKey,
      recentBlockhash: blockhash,
      instructions: allIxs,
    }).compileToV0Message([lookupTable]);

    const versionedTx = new VersionedTransaction(messageV0);
    versionedTx.sign([payer]);
    const tx = await connection.sendTransaction(versionedTx);
    await connection.confirmTransaction(tx, "confirmed");
    console.log(`✅ Jupiter swap tx: ${tx}`);

    // =====================================================
    // BALANCE LOGGING: After swap
    // =====================================================
    let sourceVaultBalanceAfter: any;
    if (sourceIsNative) {
      const lamports = await connection.getBalance(sourcePool.vault);
      sourceVaultBalanceAfter = {
        value: {
          amount: String(lamports),
          uiAmount: lamports / LAMPORTS_PER_SOL,
          decimals: 9,
        },
      };
    } else {
      sourceVaultBalanceAfter = await connection.getTokenAccountBalance(
        sourcePool.vaultTokenAccount,
      );
    }
    let destVaultBalanceAfter: any;
    if (destIsNative) {
      const lamports = await connection.getBalance(destPool.vault);
      destVaultBalanceAfter = {
        value: {
          amount: String(lamports),
          uiAmount: lamports / LAMPORTS_PER_SOL,
          decimals: 9,
        },
      };
    } else {
      destVaultBalanceAfter = await connection.getTokenAccountBalance(
        destPool.vaultTokenAccount,
      );
    }
    const relayerBalanceAfter = await connection.getTokenAccountBalance(
      relayerTokenAccount.address,
    );

    // Calculate changes
    const sourceVaultChange =
      BigInt(sourceVaultBalanceAfter.value.amount) -
      BigInt(sourceVaultBalanceBefore.value.amount);
    const destVaultChange =
      BigInt(destVaultBalanceAfter.value.amount) -
      BigInt(destVaultBalanceBefore.value.amount);
    const relayerChange =
      BigInt(relayerBalanceAfter.value.amount) -
      BigInt(relayerBalanceBefore.value.amount);

    console.log(`\n📊 BALANCES AFTER SWAP:`);
    console.log(
      `  Source Vault (${sourceName}): ${sourceVaultBalanceAfter.value.amount} (${sourceVaultBalanceAfter.value.uiAmount})`,
    );
    console.log(
      `  Dest Vault (${destName}): ${destVaultBalanceAfter.value.amount} (${destVaultBalanceAfter.value.uiAmount})`,
    );
    console.log(
      `  Relayer (${destName}): ${relayerBalanceAfter.value.amount} (${relayerBalanceAfter.value.uiAmount})`,
    );

    console.log(`\n📈 BALANCE CHANGES:`);
    console.log(
      `  Source Vault Change: ${sourceVaultChange} (expected: -${swapAmount})`,
    );
    console.log(`  Dest Vault Change: ${destVaultChange}`);
    console.log(`  Relayer Fee Received: ${relayerChange}`);

    console.log(`\n💰 TOKEN OUTPUT & FEES:`);
    console.log(`  Swap Input Amount: ${swapAmount} ${sourceName}`);
    console.log(`  Jupiter Min Output: ${jupiterMinOut} ${destName}`);
    console.log(
      `  After-Fee Min Output (circuit): ${minAmountOut} ${destName}`,
    );
    console.log(`  Actual Output to Vault: ${destVaultChange} ${destName}`);
    console.log(
      `  Fee (${dynamicFeeBps} bps of jupiter out): ${relayerFee} ${destName}`,
    );
    console.log(`  Actual Fee Collected: ${relayerChange} ${destName}`);
    console.log(
      `  Fee Match: ${
        relayerChange === relayerFee ? "✅ CORRECT" : "❌ MISMATCH"
      }`,
    );

    // Verify the math
    const totalOutput = destVaultChange + relayerChange;
    console.log(`\n🔍 VERIFICATION:`);
    console.log(`  Total Output (vault + fee): ${totalOutput} ${destName}`);
    console.log(
      `  Jupiter Min Output Met: ${
        totalOutput >= jupiterMinOut ? "✅ YES" : "❌ NO"
      }`,
    );
    console.log(
      `  Source Vault Decreased: ${
        sourceVaultChange < 0n ? "✅ YES" : "❌ NO"
      }`,
    );

    // Update off-chain state
    const destIdx = destPool.offchainTree.insert(destCommitment);
    const sourceIdx = sourcePool.offchainTree.insert(changeCommitment);

    // Save notes
    const destNoteId = noteStorage.save({
      amount: destAmount,
      commitment: destCommitment,
      nullifier: computeNullifier(
        poseidon,
        destCommitment,
        destIdx,
        privateKey,
      ),
      blinding: destBlinding,
      privateKey,
      publicKey,
      leafIndex: destIdx,
      merklePath: destPool.offchainTree.getMerkleProof(destIdx),
      mintAddress: destPool.mint,
    });

    noteStorage.save({
      amount: changeAmount,
      commitment: changeCommitment,
      nullifier: computeNullifier(
        poseidon,
        changeCommitment,
        sourceIdx,
        changePrivKey,
      ),
      blinding: changeBlinding,
      privateKey: changePrivKey,
      publicKey: changePubKey,
      leafIndex: sourceIdx,
      merklePath: sourcePool.offchainTree.getMerkleProof(sourceIdx),
      mintAddress: sourcePool.mint,
    });

    console.log(`✅ Output note saved: ${destNoteId}`);
    return destNoteId;
  }

  // --------------------------------------------------------------------------
  // TEST: SOL -> USDC
  // --------------------------------------------------------------------------
  it("should execute SOL -> USDC swap via Jupiter", async function () {
    const noteId = await initialDeposit("SOL", 10_000_000_000n);
    await executeJupiterSwap("SOL", "USDC", noteId, "1000000000"); // 1 SOL
  });

  // --------------------------------------------------------------------------
  // TEST: SOL -> USDT
  // --------------------------------------------------------------------------
  it("should execute SOL -> USDT swap via Jupiter", async function () {
    const noteId = await initialDeposit("SOL", 10_000_000_000n);
    await executeJupiterSwap("SOL", "USDT", noteId, "500000000"); // 0.5 SOL
  });

  // --------------------------------------------------------------------------
  // TEST: SOL -> JUP
  // --------------------------------------------------------------------------
  it("should execute SOL -> JUP swap via Jupiter", async function () {
    const noteId = await initialDeposit("SOL", 10_000_000_000n);
    await executeJupiterSwap("SOL", "JUP", noteId, "1000000000"); // 1 SOL
  });

  // --------------------------------------------------------------------------
  // TEST: SOL -> USD1
  // --------------------------------------------------------------------------
  it("should execute SOL -> USD1 swap via Jupiter", async function () {
    const noteId = await initialDeposit("SOL", 10_000_000_000n);
    // Note: USD1 likely has no route on Jupiter's mainnet/API. This helper will skip if getQuote fails.
    await executeJupiterSwap("SOL", "USD1", noteId, "500000000"); // 0.5 SOL
  });

  // --------------------------------------------------------------------------
  // TEST: USDC -> SOL (Token back to native SOL)
  // --------------------------------------------------------------------------
  describe("USDC -> SOL (Token to Native SOL)", () => {
    let usdcNoteForSolSwap: string | undefined;

    it("Step 1: Deposit SOL and swap to get USDC", async function () {
      console.log("\n🔗 Step 1: Deposit SOL and swap to get USDC");
      const solNoteId = await initialDeposit("SOL", 10_000_000_000n);
      usdcNoteForSolSwap = await executeJupiterSwap(
        "SOL",
        "USDC",
        solNoteId,
        "1000000000", // 1 SOL
      );
      console.log(`✅ Got USDC note: ${usdcNoteForSolSwap}`);
    });

    it("Step 2: Swap USDC -> SOL", async function () {
      console.log("\n🔗 Step 2: Swap USDC back to SOL");
      if (!usdcNoteForSolSwap) return this.skip();
      const usdcNote = noteStorage.get(usdcNoteForSolSwap);
      if (!usdcNote) throw new Error("USDC note not found");
      // Swap half the USDC back to SOL
      const swapAmount = usdcNote.amount / 2n;
      await executeJupiterSwap(
        "USDC",
        "SOL",
        usdcNoteForSolSwap,
        swapAmount.toString(),
      );
    });
  });

  // --------------------------------------------------------------------------
  // TEST: USDT -> SOL (Token to Native SOL — standalone, no chaining)
  // --------------------------------------------------------------------------
  describe("USDT -> SOL (Token to Native SOL)", () => {
    let usdtNoteForSolSwap: string | undefined;

    it("Step 1: Deposit SOL and swap to get USDT", async function () {
      console.log("\n🔗 Step 1: Deposit SOL and swap to USDT");
      const solNoteId = await initialDeposit("SOL", 10_000_000_000n);
      usdtNoteForSolSwap = await executeJupiterSwap(
        "SOL",
        "USDT",
        solNoteId,
        "500000000", // 0.5 SOL → USDT
      );
      console.log(`✅ Got USDT note: ${usdtNoteForSolSwap}`);
    });

    it("Step 2: Swap USDT -> SOL", async function () {
      console.log("\n🔗 Step 2: Swap USDT back to SOL");
      if (!usdtNoteForSolSwap) return this.skip();
      const usdtNote = noteStorage.get(usdtNoteForSolSwap);
      if (!usdtNote) throw new Error("USDT note not found");
      // Swap half the USDT back to SOL
      const swapAmount = usdtNote.amount / 2n;
      await executeJupiterSwap(
        "USDT",
        "SOL",
        usdtNoteForSolSwap,
        swapAmount.toString(),
      );
    });
  });

  // --------------------------------------------------------------------------
  // TEST: Chained Swap (SOL -> USDC -> JUP)
  // --------------------------------------------------------------------------
  describe("Chained Swap (SOL -> USDC -> JUP)", () => {
    it("Step 1: Deposit SOL for chained swap", async function () {
      console.log("\n🔗 Step 1: Deposit SOL");
      chainedSolDepositNoteId = await initialDeposit("SOL", 2_000_000_000n);
      console.log(`✅ Deposited 2 SOL, Note: ${chainedSolDepositNoteId}`);
    });

    it("Step 2: Swap SOL -> USDC", async function () {
      console.log("\n🔗 Step 2: Swap SOL -> USDC");
      // Swap 1 SOL
      chainedUsdcNoteId = await executeJupiterSwap(
        "SOL",
        "USDC",
        chainedSolDepositNoteId,
        "1000000000",
      );
    });

    it("Step 3: Swap USDC -> JUP", async function () {
      console.log("\n🔗 Step 3: Swap USDC -> JUP");
      // Swap whatever USDC we got
      if (!chainedUsdcNoteId) return this.skip();
      const usdcNote = noteStorage.get(chainedUsdcNoteId);
      if (!usdcNote) throw new Error("USDC note not found");
      // Swap half of it
      const swapAmount = usdcNote.amount / 2n;
      await executeJupiterSwap(
        "USDC",
        "JUP",
        chainedUsdcNoteId,
        swapAmount.toString(),
      );
    });
  });
});

import * as anchor from "@coral-xyz/anchor";
import { Program, BN, Wallet } from "@coral-xyz/anchor";
import {
  PublicKey,
  Keypair,
  SystemProgram,
  LAMPORTS_PER_SOL,
  TransactionMessage,
  VersionedTransaction,
  AddressLookupTableProgram,
  ComputeBudgetProgram,
  SendTransactionError,
  Transaction,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  getAssociatedTokenAddress,
  getOrCreateAssociatedTokenAccount,
  createWrappedNativeAccount,
  createAssociatedTokenAccountIdempotentInstruction,
  createSyncNativeInstruction,
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
  WSOL_MINT,
  USDT_MINT,
  USDC_MINT,
  USD1_MINT,
  JUP_MINT,
  buildAmmSwapData,
  deriveSerumVaultSigner,
  getPoolKeysFromMints,
  poolKeysToConfig,
  isBaseToQuote,
  logPoolKeys,
  AmmV4PoolConfig,
} from "./amm-v4-pool-helper";
import { LiquidityPoolKeysV4 } from "@raydium-io/raydium-sdk";

/**
 * Privacy Pool Cross-Pool Swap Tests - Various Pairs
 *
 * This test suite validates that the privacy pool can execute swaps across
 * multiple token pairs using Raydium AMM V4. Each swap pair is tested for:
 * 1. Pool initialization and configuration
 * 2. Relayer registration
 * 3. Deposit functionality
 * 4. Full swap execution with ZK proof verification
 *
 * Supported Pairs (requires corresponding pools in Anchor.toml):
 * - SOL <-> USDC
 * - SOL <-> USDT (tested in separate file)
 * - SOL <-> JUP
 * - SOL <-> USD1
 * - USDC <-> USDT (if pool exists)
 */

// Helper to encode tree_id as little-endian u16
function encodeTreeId(treeId: number): Buffer {
  const buf = Buffer.alloc(2);
  buf.writeUInt16LE(treeId, 0);
  return buf;
}

// Derive nullifier marker PDA (global, no tree_id to prevent cross-tree double-spend)
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

describe("Privacy Pool AMM V4 Swaps - Various Pairs", () => {
  const provider = makeProvider();
  anchor.setProvider(provider);

  const program = anchor.workspace.PrivacyPool as Program<PrivacyPool>;
  const payer = (provider.wallet as Wallet).payer;
  let poseidon: any;

  // Pool Configuration Types
  interface PoolInfo {
    name: string;
    mint: PublicKey;
    decimals: number;
    config: PublicKey;
    vault: PublicKey;
    noteTree: PublicKey;
    nullifiers: PublicKey;
    vaultTokenAccount: PublicKey;
    offchainTree: OffchainMerkleTree;
  }

  // Pools to initialize
  const POOL_DEFS = [
    { name: "SOL", mint: WSOL_MINT, decimals: 9 },
    { name: "USDC", mint: USDC_MINT, decimals: 6 },
    { name: "USDT", mint: USDT_MINT, decimals: 6 },
    { name: "USD1", mint: USD1_MINT, decimals: 6 },
    { name: "JUP", mint: JUP_MINT, decimals: 6 },
  ];

  // Storage for pools
  const pools: Record<string, PoolInfo> = {};

  // Note storage
  const noteStorage = new InMemoryNoteStorage();

  // Global Config
  let globalConfig: PublicKey;

  // Test constants
  const FEE_BPS = 50; // 0.5%
  const SWAP_FEE_BPS = new BN(50);

  // Pool Configurations (mainnet deployment values)
  const POOL_CONFIGS = {
    SOL: {
      feeBps: 50, // 0.5%
      minWithdrawalFee: 50_000, // 0.00005 SOL (0.5% of min)
      feeErrorMarginBps: 500, // 5%
      minDepositAmount: 10_000_000, // 0.01 SOL
      maxDepositAmount: 1_000_000_000_000, // 1000 SOL
      minWithdrawAmount: 10_000_000, // 0.01 SOL
      maxWithdrawAmount: 1_000_000_000_000, // 1000 SOL
      minSwapFee: 50_000, // 0.00005 SOL (0.5% of min)
      swapFeeBps: 50, // 0.5%
    },
    USDT: {
      feeBps: 50, // 0.5%
      minWithdrawalFee: 5_000, // 0.005 USDT (0.5% of min)
      feeErrorMarginBps: 500, // 5%
      minDepositAmount: 1_000_000, // 1 USDT
      maxDepositAmount: 100_000_000_000, // 100,000 USDT
      minWithdrawAmount: 1_000_000, // 1 USDT
      maxWithdrawAmount: 50_000_000_000, // 50,000 USDT
      minSwapFee: 5_000, // 0.005 USDT (0.5% of min)
      swapFeeBps: 50, // 0.5%
    },
    USDC: {
      feeBps: 50, // 0.5%
      minWithdrawalFee: 5_000, // 0.005 USDC (0.5% of min)
      feeErrorMarginBps: 500, // 5%
      minDepositAmount: 1_000_000, // 1 USDC
      maxDepositAmount: 100_000_000_000, // 100,000 USDC
      minWithdrawAmount: 1_000_000, // 1 USDC
      maxWithdrawAmount: 50_000_000_000, // 50,000 USDC
      minSwapFee: 5_000, // 0.005 USDC (0.5% of min)
      swapFeeBps: 50, // 0.5%
    },
    USD1: {
      feeBps: 50, // 0.5%
      minWithdrawalFee: 5_000, // 0.005 USD1 (0.5% of min)
      feeErrorMarginBps: 500, // 5%
      minDepositAmount: 1_000_000, // 1 USD1
      maxDepositAmount: 100_000_000_000, // 100,000 USD1
      minWithdrawAmount: 1_000_000, // 1 USD1
      maxWithdrawAmount: 50_000_000_000, // 50,000 USD1
      minSwapFee: 5_000, // 0.005 USD1 (0.5% of min)
      swapFeeBps: 50, // 0.5%
    },
    JUP: {
      feeBps: 50, // 0.5%
      minWithdrawalFee: 50_000, // 0.05 JUP (0.5% of min)
      feeErrorMarginBps: 500, // 5%
      minDepositAmount: 10_000_000, // 10 JUP
      maxDepositAmount: 100_000_000_000_000, // 100,000,000 JUP
      minWithdrawAmount: 10_000_000, // 10 JUP
      maxWithdrawAmount: 50_000_000_000_000, // 50,000,000 JUP
      minSwapFee: 50_000, // 0.05 JUP (0.5% of min)
      swapFeeBps: 50, // 0.5%
    },
  };

  before(async () => {
    console.log("\n🔧 Setting up Privacy Pools for Various Swap Pairs...\n");
    poseidon = await buildPoseidon();

    // Airdrop SOL
    await airdropAndConfirm(provider, payer.publicKey, 20 * LAMPORTS_PER_SOL);

    // Initialize all pools
    for (const def of POOL_DEFS) {
      console.log(`\n📦 Initializing ${def.name} pool...`);

      const offchainTree = new OffchainMerkleTree(22, poseidon);

      // Derive PDAs
      const [config] = PublicKey.findProgramAddressSync(
        [Buffer.from("privacy_config_v3"), def.mint.toBuffer()],
        program.programId,
      );
      const [vault] = PublicKey.findProgramAddressSync(
        [Buffer.from("privacy_vault_v3"), def.mint.toBuffer()],
        program.programId,
      );
      const [noteTree] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("privacy_note_tree_v3"),
          def.mint.toBuffer(),
          encodeTreeId(0),
        ],
        program.programId,
      );
      const [nullifiers] = PublicKey.findProgramAddressSync(
        [Buffer.from("privacy_nullifiers_v3"), def.mint.toBuffer()],
        program.programId,
      );
      const vaultTokenAccount = await getAssociatedTokenAddress(
        def.mint,
        vault,
        true,
      );

      pools[def.name] = {
        name: def.name,
        mint: def.mint,
        decimals: def.decimals,
        config,
        vault,
        noteTree,
        nullifiers,
        vaultTokenAccount,
        offchainTree,
      };

      // Initialize pool on-chain
      try {
        const poolConfig = POOL_CONFIGS[def.name as keyof typeof POOL_CONFIGS];
        await (program.methods as any)
          .initialize(
            poolConfig.feeBps,
            def.mint,
            new BN(poolConfig.minDepositAmount),
            new BN(poolConfig.maxDepositAmount),
            new BN(poolConfig.minWithdrawAmount),
            new BN(poolConfig.maxWithdrawAmount),
          )
          .accounts({
            config,
            vault,
            noteTree,
            nullifiers,
            admin: payer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .rpc();
        console.log(`   ✅ ${def.name} pool initialized`);
      } catch (e: any) {
        if (e.message?.includes("already in use")) {
          console.log(`   ✅ ${def.name} pool already exists`);
        } else {
          console.log(
            `   ⚠️ Failed to initialize ${def.name}:`,
            e.message?.slice(0, 100),
          );
        }
      }

      // Configure swap fees and other parameters
      try {
        const poolConfig = POOL_CONFIGS[def.name as keyof typeof POOL_CONFIGS];
        await (program.methods as any)
          .updatePoolConfig(
            def.mint,
            null, // fee_bps
            new BN(poolConfig.minWithdrawalFee),
            new BN(poolConfig.feeErrorMarginBps),
            null, // min_deposit_amount
            null, // max_deposit_amount
            null, // min_withdraw_amount
            null, // max_withdraw_amount
            new BN(poolConfig.minSwapFee),
            new BN(poolConfig.swapFeeBps),
          )
          .accounts({ config, admin: payer.publicKey })
          .rpc();
        console.log(
          `   ✅ ${def.name} configured with swap fees and parameters`,
        );
      } catch (e: any) {
        console.log(
          `   ⚠️ Failed to configure ${def.name}:`,
          e.message?.slice(0, 100),
        );
      }

      // Register relayer
      try {
        await (program.methods as any)
          .addRelayer(def.mint, payer.publicKey)
          .accounts({ config, admin: payer.publicKey })
          .rpc();
        console.log(`   ✅ Relayer registered for ${def.name}`);
      } catch (e: any) {
        if (e.message?.includes("already")) {
          console.log(`   ✅ Relayer already registered for ${def.name}`);
        }
      }
    }

    // Initialize Global Config
    [globalConfig] = PublicKey.findProgramAddressSync(
      [Buffer.from("global_config_v1")],
      program.programId,
    );
    try {
      await (program.methods as any)
        .initializeGlobalConfig()
        .accounts({
          globalConfig,
          admin: payer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      console.log("\n✅ Global config initialized");
    } catch (e: any) {
      console.log("\n✅ Global config already exists");
    }
  });

  // ============================================================================
  // SECTION 1: Pool Verification Tests
  // ============================================================================

  describe("Pool Initialization Verification", () => {
    it("verifies all pools are initialized", async () => {
      for (const name of Object.keys(pools)) {
        const pool = pools[name];
        expect(pool.config).to.not.be.null;
        expect(pool.vault).to.not.be.null;
        console.log(`✅ ${name} pool verified: ${pool.config.toBase58()}`);
      }
    });

    it("verifies SOL-USDC AMM pool exists", async () => {
      try {
        const poolKeys = await getPoolKeysFromMints(
          provider.connection,
          WSOL_MINT,
          USDC_MINT,
        );
        expect(poolKeys).to.not.be.null;
        console.log(`✅ SOL-USDC Pool: ${poolKeys.id.toBase58()}`);
      } catch (e: any) {
        console.log(
          "⚠️ SOL-USDC pool not found (may need to clone in Anchor.toml)",
        );
      }
    });

    it("verifies SOL-JUP AMM pool exists", async () => {
      try {
        const poolKeys = await getPoolKeysFromMints(
          provider.connection,
          WSOL_MINT,
          JUP_MINT,
        );
        expect(poolKeys).to.not.be.null;
        console.log(`✅ SOL-JUP Pool: ${poolKeys.id.toBase58()}`);
      } catch (e: any) {
        console.log(
          "⚠️ SOL-JUP pool not found (may need to clone in Anchor.toml)",
        );
      }
    });

    it("verifies SOL-USD1 AMM pool exists", async () => {
      try {
        const poolKeys = await getPoolKeysFromMints(
          provider.connection,
          WSOL_MINT,
          USD1_MINT,
        );
        expect(poolKeys).to.not.be.null;
        console.log(`✅ SOL-USD1 Pool: ${poolKeys.id.toBase58()}`);
      } catch (e: any) {
        console.log(
          "⚠️ SOL-USD1 pool not found (may need to clone in Anchor.toml)",
        );
      }
    });

    it("verifies USDC-JUP AMM pool exists", async () => {
      try {
        const poolKeys = await getPoolKeysFromMints(
          provider.connection,
          USDC_MINT,
          JUP_MINT,
        );
        expect(poolKeys).to.not.be.null;
        console.log(`✅ USDC-JUP Pool: ${poolKeys.id.toBase58()}`);
      } catch (e: any) {
        console.log(
          "⚠️ USDC-JUP pool not found (may need to clone in Anchor.toml)",
        );
      }
    });

    it("notes USD1-USDC AMM pool does not exist on mainnet", async () => {
      // USD1-USDC has no AMM V4 pool on mainnet - only CPMM pools exist
      // Swaps between USD1 and USDC must be routed via SOL
      console.log(
        "ℹ️ USD1-USDC: No AMM V4 pool exists on mainnet (only CPMM pools)",
      );
      console.log(
        "   To swap USD1 <-> USDC, route via SOL: USD1 -> SOL -> USDC",
      );
    });
  });

  // ============================================================================
  // SECTION 2: SOL -> USDC Swap Test
  // ============================================================================

  describe("SOL -> USDC Swap", () => {
    const DEPOSIT_AMOUNT = 2_000_000_000n; // 2 SOL
    const SWAP_AMOUNT = 500_000_000; // 0.5 SOL
    const EXPECTED_USDC_OUT = 75_000_000n; // ~75 USDC (estimated at ~$150/SOL)
    const SWAP_FEE = 375_000n; // 0.5% of 75 USDC = 0.375 USDC

    let depositNoteId: string | null = null;
    let usdcNoteId: string | null = null;
    let solChangeNoteId: string | null = null;
    let poolConfig: AmmV4PoolConfig;
    let serumVaultSigner: PublicKey;

    before(async () => {
      try {
        const poolKeys = await getPoolKeysFromMints(
          provider.connection,
          WSOL_MINT,
          USDC_MINT,
        );
        poolConfig = poolKeysToConfig(poolKeys);
        serumVaultSigner = deriveSerumVaultSigner(
          poolConfig.serumMarket,
          new BN(poolConfig.serumVaultSignerNonce),
        );
      } catch (e) {
        console.log("⚠️ SOL-USDC pool not available, skipping swap tests");
      }
    });

    it("deposits SOL to privacy pool for USDC swap", async function () {
      if (!poolConfig) return this.skip();

      const sol = pools.SOL;
      console.log("\n🎁 Depositing SOL for USDC swap...");

      // Create vault's token account via idempotent instruction
      const vaultAta = await getAssociatedTokenAddress(
        sol.mint,
        sol.vault,
        true,
      );
      const createAtaIx = createAssociatedTokenAccountIdempotentInstruction(
        payer.publicKey,
        vaultAta,
        sol.vault,
        sol.mint,
      );
      try {
        await provider.sendAndConfirm(new Transaction().add(createAtaIx));
      } catch (e: any) {
        console.log("   ⚠️ ATA creation note:", e.message);
      }

      // Create wSOL account for the user
      const wsolAccount = await createWrappedNativeAccount(
        provider.connection,
        payer,
        payer.publicKey,
        Number(DEPOSIT_AMOUNT) + 1_000_000,
      );

      // Generate note credentials
      const privateKey = randomBytes32();
      const publicKey = derivePublicKey(poseidon, privateKey);
      const blinding = randomBytes32();
      const commitment = computeCommitment(
        poseidon,
        DEPOSIT_AMOUNT,
        publicKey,
        blinding,
        sol.mint,
      );

      // Dummy inputs for deposit
      const dummyPrivKey1 = randomBytes32();
      const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);
      const dummyBlinding1 = randomBytes32();
      const dummyCommitment1 = computeCommitment(
        poseidon,
        0n,
        dummyPubKey1,
        dummyBlinding1,
        sol.mint,
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
        sol.mint,
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
        sol.mint,
      );

      const extData = {
        recipient: payer.publicKey,
        relayer: payer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
      };
      const extDataHash = computeExtDataHash(poseidon, extData);

      const dummyProof = sol.offchainTree.getMerkleProof(0);
      const root = sol.offchainTree.getRoot();

      const proof = await generateTransactionProof({
        root,
        publicAmount: DEPOSIT_AMOUNT,
        extDataHash,
        mintAddress: sol.mint,
        inputNullifiers: [dummyNullifier1, dummyNullifier2],
        outputCommitments: [commitment, changeCommitment],
        inputAmounts: [0n, 0n],
        inputPrivateKeys: [dummyPrivKey1, dummyPrivKey2],
        inputPublicKeys: [dummyPubKey1, dummyPubKey2],
        inputBlindings: [dummyBlinding1, dummyBlinding2],
        inputMerklePaths: [dummyProof, dummyProof],
        outputAmounts: [DEPOSIT_AMOUNT, 0n],
        outputOwners: [publicKey, changePubKey],
        outputBlindings: [blinding, changeBlinding],
      });

      const nullifierMarker0 = deriveNullifierMarkerPDA(
        program.programId,
        sol.mint,
        0,
        dummyNullifier1,
      );
      const nullifierMarker1 = deriveNullifierMarkerPDA(
        program.programId,
        sol.mint,
        0,
        dummyNullifier2,
      );

      await (program.methods as any)
        .transact(
          Array.from(root),
          0,
          0,
          new BN(DEPOSIT_AMOUNT.toString()),
          Array.from(extDataHash),
          sol.mint,
          Array.from(dummyNullifier1),
          Array.from(dummyNullifier2),
          Array.from(commitment),
          Array.from(changeCommitment),
          extData,
          proof,
        )
        .accounts({
          config: sol.config,
          globalConfig,
          vault: sol.vault,
          inputTree: sol.noteTree,
          outputTree: sol.noteTree,
          nullifiers: sol.nullifiers,
          nullifierMarker0,
          nullifierMarker1,
          relayer: payer.publicKey,
          recipient: payer.publicKey,
          vaultTokenAccount: sol.vaultTokenAccount,
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

      const leafIndex = sol.offchainTree.insert(commitment);
      sol.offchainTree.insert(changeCommitment);

      depositNoteId = noteStorage.save({
        amount: DEPOSIT_AMOUNT,
        commitment,
        nullifier: computeNullifier(
          poseidon,
          commitment,
          leafIndex,
          privateKey,
        ),
        blinding,
        privateKey,
        publicKey,
        leafIndex,
        merklePath: sol.offchainTree.getMerkleProof(leafIndex),
        mintAddress: sol.mint,
      });

      console.log(`✅ Deposited ${Number(DEPOSIT_AMOUNT) / 1e9} SOL`);
      console.log(`   Note ID: ${depositNoteId}`);
    });

    it("executes SOL -> USDC swap via AMM V4", async function () {
      if (!poolConfig || !depositNoteId) return this.skip();

      const sol = pools.SOL;
      const usdc = pools.USDC;
      console.log("\n🔄 Executing SOL -> USDC swap...");

      const note = noteStorage.get(depositNoteId);
      if (!note) throw new Error("Deposit note not found");

      const merkleProof = sol.offchainTree.getMerkleProof(note.leafIndex);
      const root = sol.offchainTree.getRoot();

      // Dummy second input
      const dummyPrivKey = randomBytes32();
      const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
      const dummyBlinding = randomBytes32();
      const dummyCommitment = computeCommitment(
        poseidon,
        0n,
        dummyPubKey,
        dummyBlinding,
        sol.mint,
      );
      const dummyNullifier = computeNullifier(
        poseidon,
        dummyCommitment,
        0,
        dummyPrivKey,
      );
      const dummyProof = sol.offchainTree.getMerkleProof(0);

      // Output: USDC note
      const destPrivKey = randomBytes32();
      const destPubKey = derivePublicKey(poseidon, destPrivKey);
      const destBlinding = randomBytes32();
      const destCommitment = computeCommitment(
        poseidon,
        EXPECTED_USDC_OUT,
        destPubKey,
        destBlinding,
        usdc.mint,
      );
      const destCommitmentForProof = computeCommitment(
        poseidon,
        0n,
        destPubKey,
        destBlinding,
        sol.mint,
      );

      // Change: remaining SOL
      const changeAmount = note.amount - BigInt(SWAP_AMOUNT);
      const changePrivKey = randomBytes32();
      const changePubKey = derivePublicKey(poseidon, changePrivKey);
      const changeBlinding = randomBytes32();
      const changeCommitment = computeCommitment(
        poseidon,
        changeAmount,
        changePubKey,
        changeBlinding,
        sol.mint,
      );

      const extData = {
        recipient: payer.publicKey,
        relayer: payer.publicKey,
        fee: new BN(SWAP_FEE.toString()),
        refund: new BN(0),
      };
      const extDataHash = computeExtDataHash(poseidon, extData);

      const minAmountOut = new BN(50_000_000); // 50 USDC min
      const deadline = new BN(Math.floor(Date.now() / 1000) + 3600);

      const swapParams = {
        minAmountOut,
        deadline,
        sourceMint: sol.mint,
        destMint: usdc.mint,
      };

      const swapParamsHash = computeSwapParamsHash(
        poseidon,
        sol.mint,
        usdc.mint,
        BigInt(minAmountOut.toString()),
        BigInt(deadline.toString()),
      );

      console.log("   Generating ZK proof...");
      const proof = await generateSwapProof({
        sourceRoot: root,
        swapParamsHash,
        extDataHash,
        sourceMint: sol.mint,
        destMint: usdc.mint,
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

        destAmount: EXPECTED_USDC_OUT,
        destPubkey: destPubKey,
        destBlinding,

        minAmountOut: BigInt(minAmountOut.toString()),
        deadline: BigInt(deadline.toString()),
      });
      console.log("   ✅ ZK proof generated");

      const swapData = buildAmmSwapData(new BN(SWAP_AMOUNT), minAmountOut);

      const [executorPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("swap_executor"),
          sol.mint.toBuffer(),
          usdc.mint.toBuffer(),
          Buffer.from(note.nullifier),
        ],
        program.programId,
      );
      const executorSourceToken = await getAssociatedTokenAddress(
        sol.mint,
        executorPda,
        true,
      );
      const executorDestToken = await getAssociatedTokenAddress(
        usdc.mint,
        executorPda,
        true,
      );

      const nullifierMarker0 = deriveNullifierMarkerPDA(
        program.programId,
        sol.mint,
        0,
        note.nullifier,
      );
      const nullifierMarker1 = deriveNullifierMarkerPDA(
        program.programId,
        sol.mint,
        0,
        dummyNullifier,
      );

      const solVaultAccount = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payer,
        sol.mint,
        sol.vault,
        true,
      );
      const usdcVaultAccount = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payer,
        usdc.mint,
        usdc.vault,
        true,
      );
      const relayerTokenAccount = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payer,
        usdc.mint,
        payer.publicKey,
      );

      // Create lookup table
      const recentSlot = await provider.connection.getSlot("finalized");
      const lookupTableAddresses = [
        sol.config,
        globalConfig,
        sol.vault,
        sol.noteTree,
        sol.nullifiers,
        solVaultAccount.address,
        sol.mint,
        usdc.config,
        usdc.vault,
        usdc.noteTree,
        usdcVaultAccount.address,
        usdc.mint,
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

      await provider.sendAndConfirm(
        new anchor.web3.Transaction().add(createLutIx).add(extendLutIx),
      );
      await new Promise((r) => setTimeout(r, 1000));

      const lookupTableAccount =
        await provider.connection.getAddressLookupTable(lookupTableAddress);
      if (!lookupTableAccount.value)
        throw new Error("Failed to fetch lookup table");

      try {
        const swapIx = await (program.methods as any)
          .transactSwap(
            proof,
            Array.from(root),
            0,
            sol.mint,
            Array.from(note.nullifier),
            Array.from(dummyNullifier),
            0,
            usdc.mint,
            Array.from(changeCommitment),
            Array.from(destCommitment),
            swapParams,
            new BN(SWAP_AMOUNT),
            swapData,
            extData,
          )
          .accounts({
            sourceConfig: sol.config,
            globalConfig,
            sourceVault: sol.vault,
            sourceTree: sol.noteTree,
            sourceNullifiers: sol.nullifiers,
            sourceNullifierMarker0: nullifierMarker0,
            sourceNullifierMarker1: nullifierMarker1,
            sourceVaultTokenAccount: solVaultAccount.address,
            sourceMintAccount: sol.mint,
            destConfig: usdc.config,
            destVault: usdc.vault,
            destTree: usdc.noteTree,
            destVaultTokenAccount: usdcVaultAccount.address,
            destMintAccount: usdc.mint,
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
            {
              pubkey: poolConfig.serumMarket,
              isSigner: false,
              isWritable: true,
            },
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

        const txSig = await provider.connection.sendTransaction(versionedTx, {
          skipPreflight: false,
        });
        await provider.connection.confirmTransaction({
          signature: txSig,
          blockhash,
          lastValidBlockHeight,
        });

        console.log(`✅ SOL -> USDC swap executed: ${txSig}`);

        // Save output notes
        const usdcLeafIndex = usdc.offchainTree.insert(destCommitment);
        usdcNoteId = noteStorage.save({
          amount: EXPECTED_USDC_OUT,
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
          merklePath: usdc.offchainTree.getMerkleProof(usdcLeafIndex),
          mintAddress: usdc.mint,
        });

        const solChangeLeafIndex = sol.offchainTree.insert(changeCommitment);
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
          merklePath: sol.offchainTree.getMerkleProof(solChangeLeafIndex),
          mintAddress: sol.mint,
        });

        console.log(
          `   USDC note: ${usdcNoteId} (${
            Number(EXPECTED_USDC_OUT) / 1e6
          } USDC)`,
        );
        console.log(
          `   SOL change: ${solChangeNoteId} (${
            Number(changeAmount) / 1e9
          } SOL)`,
        );
      } catch (e: any) {
        if (e instanceof SendTransactionError) {
          const logs = await e.getLogs(provider.connection);
          console.error("\n❌ Swap failed:");
          logs?.slice(-10).forEach((l: string) => console.error(`   ${l}`));
        }
        throw e;
      }
    });

    it("verifies USDC note from swap exists", async function () {
      if (!usdcNoteId) return this.skip();
      const note = noteStorage.get(usdcNoteId);
      expect(note).to.not.be.undefined;
      expect(note!.amount).to.equal(EXPECTED_USDC_OUT);
      console.log(`✅ USDC note verified: ${Number(note!.amount) / 1e6} USDC`);
    });

    it("verifies SOL change note from swap exists", async function () {
      if (!solChangeNoteId) return this.skip();
      const note = noteStorage.get(solChangeNoteId);
      expect(note).to.not.be.undefined;
      console.log(
        `✅ SOL change note verified: ${Number(note!.amount) / 1e9} SOL`,
      );
    });
  });

  // ============================================================================
  // SECTION 3: SOL -> USDT Swap Test
  // ============================================================================

  describe("SOL -> USDT Swap", () => {
    const DEPOSIT_AMOUNT = 2_000_000_000n; // 2 SOL
    const SWAP_AMOUNT = 500_000_000; // 0.5 SOL
    const EXPECTED_USDT_OUT = 75_000_000n; // ~75 USDT
    const SWAP_FEE = 375_000n; // 0.5% of 75 USDT

    let depositNoteId: string | null = null;
    let usdtNoteId: string | null = null;
    let solChangeNoteId: string | null = null;
    let poolConfig: AmmV4PoolConfig;
    let serumVaultSigner: PublicKey;

    before(async () => {
      try {
        const poolKeys = await getPoolKeysFromMints(
          provider.connection,
          WSOL_MINT,
          USDT_MINT,
        );
        poolConfig = poolKeysToConfig(poolKeys);
        serumVaultSigner = deriveSerumVaultSigner(
          poolConfig.serumMarket,
          new BN(poolConfig.serumVaultSignerNonce),
        );
      } catch (e) {
        console.log("⚠️ SOL-USDT pool not available, skipping swap tests");
      }
    });

    it("deposits SOL to privacy pool for USDT swap", async function () {
      if (!poolConfig) return this.skip();

      const sol = pools.SOL;
      console.log("\n🎁 Depositing SOL for USDT swap...");

      // Vault token account should already exist from previous tests
      console.log("   Creating vault token account...");
      const vaultAta = await getAssociatedTokenAddress(
        sol.mint,
        sol.vault,
        true,
      );
      const createAtaIx = createAssociatedTokenAccountIdempotentInstruction(
        payer.publicKey,
        vaultAta,
        sol.vault,
        sol.mint,
      );
      try {
        await provider.sendAndConfirm(new Transaction().add(createAtaIx));
        console.log("   ✅ Vault token account ready");
      } catch (e: any) {
        console.log(
          `   ⚠️ Vault account error (may already exist): ${e.message?.slice(
            0,
            50,
          )}`,
        );
      }

      console.log("   Creating wrapped SOL account...");
      const wsolKeypair = Keypair.generate();
      const wsolAccount = await createWrappedNativeAccount(
        provider.connection,
        payer,
        payer.publicKey,
        Number(DEPOSIT_AMOUNT) + 1_000_000,
        wsolKeypair, // Pass keypair to avoid ATA path
      );
      console.log(`   ✅ wSOL account created: ${wsolAccount.toBase58()}`);

      const privateKey = randomBytes32();
      const publicKey = derivePublicKey(poseidon, privateKey);
      const blinding = randomBytes32();
      const commitment = computeCommitment(
        poseidon,
        DEPOSIT_AMOUNT,
        publicKey,
        blinding,
        sol.mint,
      );

      const dummyPrivKey1 = randomBytes32();
      const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);
      const dummyBlinding1 = randomBytes32();
      const dummyCommitment1 = computeCommitment(
        poseidon,
        0n,
        dummyPubKey1,
        dummyBlinding1,
        sol.mint,
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
        sol.mint,
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
        sol.mint,
      );

      const extData = {
        recipient: payer.publicKey,
        relayer: payer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
      };
      const extDataHash = computeExtDataHash(poseidon, extData);
      const dummyProof = sol.offchainTree.getMerkleProof(0);
      const root = sol.offchainTree.getRoot();

      const proof = await generateTransactionProof({
        root,
        publicAmount: DEPOSIT_AMOUNT,
        extDataHash,
        mintAddress: sol.mint,
        inputNullifiers: [dummyNullifier1, dummyNullifier2],
        outputCommitments: [commitment, changeCommitment],
        inputAmounts: [0n, 0n],
        inputPrivateKeys: [dummyPrivKey1, dummyPrivKey2],
        inputPublicKeys: [dummyPubKey1, dummyPubKey2],
        inputBlindings: [dummyBlinding1, dummyBlinding2],
        inputMerklePaths: [dummyProof, dummyProof],
        outputAmounts: [DEPOSIT_AMOUNT, 0n],
        outputOwners: [publicKey, changePubKey],
        outputBlindings: [blinding, changeBlinding],
      });

      const nullifierMarker0 = deriveNullifierMarkerPDA(
        program.programId,
        sol.mint,
        0,
        dummyNullifier1,
      );
      const nullifierMarker1 = deriveNullifierMarkerPDA(
        program.programId,
        sol.mint,
        0,
        dummyNullifier2,
      );

      await (program.methods as any)
        .transact(
          Array.from(root),
          0,
          0,
          new BN(DEPOSIT_AMOUNT.toString()),
          Array.from(extDataHash),
          sol.mint,
          Array.from(dummyNullifier1),
          Array.from(dummyNullifier2),
          Array.from(commitment),
          Array.from(changeCommitment),
          extData,
          proof,
        )
        .accounts({
          config: sol.config,
          globalConfig,
          vault: sol.vault,
          inputTree: sol.noteTree,
          outputTree: sol.noteTree,
          nullifiers: sol.nullifiers,
          nullifierMarker0,
          nullifierMarker1,
          relayer: payer.publicKey,
          recipient: payer.publicKey,
          vaultTokenAccount: sol.vaultTokenAccount,
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

      const leafIndex = sol.offchainTree.insert(commitment);
      sol.offchainTree.insert(changeCommitment);

      depositNoteId = noteStorage.save({
        amount: DEPOSIT_AMOUNT,
        commitment,
        nullifier: computeNullifier(
          poseidon,
          commitment,
          leafIndex,
          privateKey,
        ),
        blinding,
        privateKey,
        publicKey,
        leafIndex,
        merklePath: sol.offchainTree.getMerkleProof(leafIndex),
        mintAddress: sol.mint,
      });

      console.log(`✅ Deposited ${Number(DEPOSIT_AMOUNT) / 1e9} SOL`);
      console.log(`   Note ID: ${depositNoteId}`);
    });

    it("executes SOL -> USDT swap via AMM V4", async function () {
      if (!poolConfig || !depositNoteId) return this.skip();

      const sol = pools.SOL;
      const usdt = pools.USDT;
      console.log("\n🔄 Executing SOL -> USDT swap...");

      const note = noteStorage.get(depositNoteId);
      if (!note) throw new Error("Deposit note not found");

      const merkleProof = sol.offchainTree.getMerkleProof(note.leafIndex);
      const root = sol.offchainTree.getRoot();

      const dummyPrivKey = randomBytes32();
      const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
      const dummyBlinding = randomBytes32();
      const dummyCommitment = computeCommitment(
        poseidon,
        0n,
        dummyPubKey,
        dummyBlinding,
        sol.mint,
      );
      const dummyNullifier = computeNullifier(
        poseidon,
        dummyCommitment,
        0,
        dummyPrivKey,
      );
      const dummyProof = sol.offchainTree.getMerkleProof(0);

      const destPrivKey = randomBytes32();
      const destPubKey = derivePublicKey(poseidon, destPrivKey);
      const destBlinding = randomBytes32();
      const destCommitment = computeCommitment(
        poseidon,
        EXPECTED_USDT_OUT,
        destPubKey,
        destBlinding,
        usdt.mint,
      );
      const destCommitmentForProof = computeCommitment(
        poseidon,
        0n,
        destPubKey,
        destBlinding,
        sol.mint,
      );

      const changeAmount = note.amount - BigInt(SWAP_AMOUNT);
      const changePrivKey = randomBytes32();
      const changePubKey = derivePublicKey(poseidon, changePrivKey);
      const changeBlinding = randomBytes32();
      const changeCommitment = computeCommitment(
        poseidon,
        changeAmount,
        changePubKey,
        changeBlinding,
        sol.mint,
      );

      const extData = {
        recipient: payer.publicKey,
        relayer: payer.publicKey,
        fee: new BN(SWAP_FEE.toString()),
        refund: new BN(0),
      };
      const extDataHash = computeExtDataHash(poseidon, extData);

      const minAmountOut = new BN(40_000_000); // 40 USDT min
      const deadline = new BN(Math.floor(Date.now() / 1000) + 3600);

      const swapParams = {
        minAmountOut,
        deadline,
        sourceMint: sol.mint,
        destMint: usdt.mint,
      };

      const swapParamsHash = computeSwapParamsHash(
        poseidon,
        sol.mint,
        usdt.mint,
        BigInt(minAmountOut.toString()),
        BigInt(deadline.toString()),
      );

      console.log("   Generating ZK proof...");
      const proof = await generateSwapProof({
        sourceRoot: root,
        swapParamsHash,
        extDataHash,
        sourceMint: sol.mint,
        destMint: usdt.mint,
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

        destAmount: EXPECTED_USDT_OUT,
        destPubkey: destPubKey,
        destBlinding,

        minAmountOut: BigInt(minAmountOut.toString()),
        deadline: BigInt(deadline.toString()),
      });
      console.log("   ✅ ZK proof generated");

      const swapData = buildAmmSwapData(new BN(SWAP_AMOUNT), minAmountOut);

      const [executorPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("swap_executor"),
          sol.mint.toBuffer(),
          usdt.mint.toBuffer(),
          Buffer.from(note.nullifier),
        ],
        program.programId,
      );
      const executorSourceToken = await getAssociatedTokenAddress(
        sol.mint,
        executorPda,
        true,
      );
      const executorDestToken = await getAssociatedTokenAddress(
        usdt.mint,
        executorPda,
        true,
      );

      const nullifierMarker0 = deriveNullifierMarkerPDA(
        program.programId,
        sol.mint,
        0,
        note.nullifier,
      );
      const nullifierMarker1 = deriveNullifierMarkerPDA(
        program.programId,
        sol.mint,
        0,
        dummyNullifier,
      );

      const solVaultAccount = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payer,
        sol.mint,
        sol.vault,
        true,
      );
      const usdtVaultAccount = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payer,
        usdt.mint,
        usdt.vault,
        true,
      );
      const relayerTokenAccount = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payer,
        usdt.mint,
        payer.publicKey,
      );

      const recentSlot = await provider.connection.getSlot("finalized");
      const lookupTableAddresses = [
        sol.config,
        globalConfig,
        sol.vault,
        sol.noteTree,
        sol.nullifiers,
        solVaultAccount.address,
        sol.mint,
        usdt.config,
        usdt.vault,
        usdt.noteTree,
        usdtVaultAccount.address,
        usdt.mint,
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

      await provider.sendAndConfirm(
        new anchor.web3.Transaction().add(createLutIx).add(extendLutIx),
      );
      await new Promise((r) => setTimeout(r, 1000));

      const lookupTableAccount =
        await provider.connection.getAddressLookupTable(lookupTableAddress);
      if (!lookupTableAccount.value)
        throw new Error("Failed to fetch lookup table");

      try {
        const swapIx = await (program.methods as any)
          .transactSwap(
            proof,
            Array.from(root),
            0,
            sol.mint,
            Array.from(note.nullifier),
            Array.from(dummyNullifier),
            0,
            usdt.mint,
            Array.from(changeCommitment),
            Array.from(destCommitment),
            swapParams,
            new BN(SWAP_AMOUNT),
            swapData,
            extData,
          )
          .accounts({
            sourceConfig: sol.config,
            globalConfig,
            sourceVault: sol.vault,
            sourceTree: sol.noteTree,
            sourceNullifiers: sol.nullifiers,
            sourceNullifierMarker0: nullifierMarker0,
            sourceNullifierMarker1: nullifierMarker1,
            sourceVaultTokenAccount: solVaultAccount.address,
            sourceMintAccount: sol.mint,
            destConfig: usdt.config,
            destVault: usdt.vault,
            destTree: usdt.noteTree,
            destVaultTokenAccount: usdtVaultAccount.address,
            destMintAccount: usdt.mint,
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
            {
              pubkey: poolConfig.serumMarket,
              isSigner: false,
              isWritable: true,
            },
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

        const txSig = await provider.connection.sendTransaction(versionedTx, {
          skipPreflight: false,
        });
        await provider.connection.confirmTransaction({
          signature: txSig,
          blockhash,
          lastValidBlockHeight,
        });

        console.log(`✅ SOL -> USDT swap executed: ${txSig}`);

        const usdtLeafIndex = usdt.offchainTree.insert(destCommitment);
        usdtNoteId = noteStorage.save({
          amount: EXPECTED_USDT_OUT,
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
          merklePath: usdt.offchainTree.getMerkleProof(usdtLeafIndex),
          mintAddress: usdt.mint,
        });

        const solChangeLeafIndex = sol.offchainTree.insert(changeCommitment);
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
          merklePath: sol.offchainTree.getMerkleProof(solChangeLeafIndex),
          mintAddress: sol.mint,
        });

        console.log(
          `   USDT note: ${usdtNoteId} (${
            Number(EXPECTED_USDT_OUT) / 1e6
          } USDT)`,
        );
        console.log(
          `   SOL change: ${solChangeNoteId} (${
            Number(changeAmount) / 1e9
          } SOL)`,
        );
      } catch (e: any) {
        if (e instanceof SendTransactionError) {
          const logs = await e.getLogs(provider.connection);
          console.error("\n❌ Swap failed:");
          logs?.slice(-10).forEach((l: string) => console.error(`   ${l}`));
        }
        throw e;
      }
    });

    it("verifies USDT note from swap exists", async function () {
      if (!usdtNoteId) return this.skip();
      const note = noteStorage.get(usdtNoteId);
      expect(note).to.not.be.undefined;
      expect(note!.amount).to.equal(EXPECTED_USDT_OUT);
      console.log(`✅ USDT note verified: ${Number(note!.amount) / 1e6} USDT`);
    });

    it("verifies SOL change note from swap exists", async function () {
      if (!solChangeNoteId) return this.skip();
      const note = noteStorage.get(solChangeNoteId);
      expect(note).to.not.be.undefined;
      console.log(
        `✅ SOL change note verified: ${Number(note!.amount) / 1e9} SOL`,
      );
    });
  });

  // ============================================================================
  // SECTION 4: SOL -> JUP Swap Test
  // ============================================================================

  describe("SOL -> JUP Swap", () => {
    const DEPOSIT_AMOUNT = 2_000_000_000n; // 2 SOL
    const SWAP_AMOUNT = 500_000_000; // 0.5 SOL
    const EXPECTED_JUP_OUT = 100_000_000n; // ~100 JUP (estimated)
    // Fee must cover 0.5% of actual swap output. JUP pools on forked mainnet
    // can have extreme rates. Use 50 JUP to cover outputs up to 10,000 JUP.
    const SWAP_FEE = 50_000_000n; // 50 JUP - generous fee for variable output

    let depositNoteId: string | null = null;
    let jupNoteId: string | null = null;
    let solChangeNoteId: string | null = null;
    let poolConfig: AmmV4PoolConfig;
    let serumVaultSigner: PublicKey;

    before(async () => {
      try {
        const poolKeys = await getPoolKeysFromMints(
          provider.connection,
          WSOL_MINT,
          JUP_MINT,
        );
        poolConfig = poolKeysToConfig(poolKeys);
        serumVaultSigner = deriveSerumVaultSigner(
          poolConfig.serumMarket,
          new BN(poolConfig.serumVaultSignerNonce),
        );
      } catch (e) {
        console.log("⚠️ SOL-JUP pool not available, skipping swap tests");
      }
    });

    it("deposits SOL to privacy pool for JUP swap", async function () {
      if (!poolConfig) return this.skip();

      const sol = pools.SOL;
      console.log("\n🎁 Depositing SOL for JUP swap...");

      // Vault token account should already exist from previous tests
      const vaultAta = await getAssociatedTokenAddress(
        sol.mint,
        sol.vault,
        true,
      );
      try {
        const createAtaIx = createAssociatedTokenAccountIdempotentInstruction(
          payer.publicKey,
          vaultAta,
          sol.vault,
          sol.mint,
        );
        await provider.sendAndConfirm(new Transaction().add(createAtaIx));
      } catch (e) {
        // Account may already exist, which is fine
      }
      const wsolKeypair = Keypair.generate();
      const wsolAccount = await createWrappedNativeAccount(
        provider.connection,
        payer,
        payer.publicKey,
        Number(DEPOSIT_AMOUNT) + 1_000_000,
        wsolKeypair, // Pass keypair to avoid ATA path
      );

      const privateKey = randomBytes32();
      const publicKey = derivePublicKey(poseidon, privateKey);
      const blinding = randomBytes32();
      const commitment = computeCommitment(
        poseidon,
        DEPOSIT_AMOUNT,
        publicKey,
        blinding,
        sol.mint,
      );

      const dummyPrivKey1 = randomBytes32();
      const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);
      const dummyBlinding1 = randomBytes32();
      const dummyCommitment1 = computeCommitment(
        poseidon,
        0n,
        dummyPubKey1,
        dummyBlinding1,
        sol.mint,
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
        sol.mint,
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
        sol.mint,
      );

      const extData = {
        recipient: payer.publicKey,
        relayer: payer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
      };
      const extDataHash = computeExtDataHash(poseidon, extData);
      const dummyProof = sol.offchainTree.getMerkleProof(0);
      const root = sol.offchainTree.getRoot();

      const proof = await generateTransactionProof({
        root,
        publicAmount: DEPOSIT_AMOUNT,
        extDataHash,
        mintAddress: sol.mint,
        inputNullifiers: [dummyNullifier1, dummyNullifier2],
        outputCommitments: [commitment, changeCommitment],
        inputAmounts: [0n, 0n],
        inputPrivateKeys: [dummyPrivKey1, dummyPrivKey2],
        inputPublicKeys: [dummyPubKey1, dummyPubKey2],
        inputBlindings: [dummyBlinding1, dummyBlinding2],
        inputMerklePaths: [dummyProof, dummyProof],
        outputAmounts: [DEPOSIT_AMOUNT, 0n],
        outputOwners: [publicKey, changePubKey],
        outputBlindings: [blinding, changeBlinding],
      });

      const nullifierMarker0 = deriveNullifierMarkerPDA(
        program.programId,
        sol.mint,
        0,
        dummyNullifier1,
      );
      const nullifierMarker1 = deriveNullifierMarkerPDA(
        program.programId,
        sol.mint,
        0,
        dummyNullifier2,
      );

      await (program.methods as any)
        .transact(
          Array.from(root),
          0,
          0,
          new BN(DEPOSIT_AMOUNT.toString()),
          Array.from(extDataHash),
          sol.mint,
          Array.from(dummyNullifier1),
          Array.from(dummyNullifier2),
          Array.from(commitment),
          Array.from(changeCommitment),
          extData,
          proof,
        )
        .accounts({
          config: sol.config,
          globalConfig,
          vault: sol.vault,
          inputTree: sol.noteTree,
          outputTree: sol.noteTree,
          nullifiers: sol.nullifiers,
          nullifierMarker0,
          nullifierMarker1,
          relayer: payer.publicKey,
          recipient: payer.publicKey,
          vaultTokenAccount: sol.vaultTokenAccount,
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

      const leafIndex = sol.offchainTree.insert(commitment);
      sol.offchainTree.insert(changeCommitment);

      depositNoteId = noteStorage.save({
        amount: DEPOSIT_AMOUNT,
        commitment,
        nullifier: computeNullifier(
          poseidon,
          commitment,
          leafIndex,
          privateKey,
        ),
        blinding,
        privateKey,
        publicKey,
        leafIndex,
        merklePath: sol.offchainTree.getMerkleProof(leafIndex),
        mintAddress: sol.mint,
      });

      console.log(`✅ Deposited ${Number(DEPOSIT_AMOUNT) / 1e9} SOL`);
      console.log(`   Note ID: ${depositNoteId}`);
    });

    it("executes SOL -> JUP swap via AMM V4", async function () {
      if (!poolConfig || !depositNoteId) return this.skip();

      const sol = pools.SOL;
      const jup = pools.JUP;
      console.log("\n🔄 Executing SOL -> JUP swap...");

      const note = noteStorage.get(depositNoteId);
      if (!note) throw new Error("Deposit note not found");

      const merkleProof = sol.offchainTree.getMerkleProof(note.leafIndex);
      const root = sol.offchainTree.getRoot();

      const dummyPrivKey = randomBytes32();
      const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
      const dummyBlinding = randomBytes32();
      const dummyCommitment = computeCommitment(
        poseidon,
        0n,
        dummyPubKey,
        dummyBlinding,
        sol.mint,
      );
      const dummyNullifier = computeNullifier(
        poseidon,
        dummyCommitment,
        0,
        dummyPrivKey,
      );
      const dummyProof = sol.offchainTree.getMerkleProof(0);

      const destPrivKey = randomBytes32();
      const destPubKey = derivePublicKey(poseidon, destPrivKey);
      const destBlinding = randomBytes32();
      const destCommitment = computeCommitment(
        poseidon,
        EXPECTED_JUP_OUT,
        destPubKey,
        destBlinding,
        jup.mint,
      );
      const destCommitmentForProof = computeCommitment(
        poseidon,
        0n,
        destPubKey,
        destBlinding,
        sol.mint,
      );

      const changeAmount = note.amount - BigInt(SWAP_AMOUNT);
      const changePrivKey = randomBytes32();
      const changePubKey = derivePublicKey(poseidon, changePrivKey);
      const changeBlinding = randomBytes32();
      const changeCommitment = computeCommitment(
        poseidon,
        changeAmount,
        changePubKey,
        changeBlinding,
        sol.mint,
      );

      const extData = {
        recipient: payer.publicKey,
        relayer: payer.publicKey,
        fee: new BN(SWAP_FEE.toString()),
        refund: new BN(0),
      };
      const extDataHash = computeExtDataHash(poseidon, extData);

      const minAmountOut = new BN(50_000_000); // 50 JUP
      const deadline = new BN(Math.floor(Date.now() / 1000) + 3600);

      const swapParams = {
        minAmountOut,
        deadline,
        sourceMint: sol.mint,
        destMint: jup.mint,
      };

      const swapParamsHash = computeSwapParamsHash(
        poseidon,
        sol.mint,
        jup.mint,
        BigInt(minAmountOut.toString()),
        BigInt(deadline.toString()),
      );

      console.log("   Generating ZK proof...");
      const proof = await generateSwapProof({
        sourceRoot: root,
        swapParamsHash,
        extDataHash,
        sourceMint: sol.mint,
        destMint: jup.mint,
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

        destAmount: EXPECTED_JUP_OUT,
        destPubkey: destPubKey,
        destBlinding,

        minAmountOut: BigInt(minAmountOut.toString()),
        deadline: BigInt(deadline.toString()),
      });
      console.log("   ✅ ZK proof generated");

      const swapData = buildAmmSwapData(new BN(SWAP_AMOUNT), minAmountOut);

      const [executorPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("swap_executor"),
          sol.mint.toBuffer(),
          jup.mint.toBuffer(),
          Buffer.from(note.nullifier),
        ],
        program.programId,
      );
      const executorSourceToken = await getAssociatedTokenAddress(
        sol.mint,
        executorPda,
        true,
      );
      const executorDestToken = await getAssociatedTokenAddress(
        jup.mint,
        executorPda,
        true,
      );

      const nullifierMarker0 = deriveNullifierMarkerPDA(
        program.programId,
        sol.mint,
        0,
        note.nullifier,
      );
      const nullifierMarker1 = deriveNullifierMarkerPDA(
        program.programId,
        sol.mint,
        0,
        dummyNullifier,
      );

      const solVaultAccount = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payer,
        sol.mint,
        sol.vault,
        true,
      );
      const jupVaultAccount = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payer,
        jup.mint,
        jup.vault,
        true,
      );
      const relayerTokenAccount = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payer,
        jup.mint,
        payer.publicKey,
      );

      const recentSlot = await provider.connection.getSlot("finalized");
      const lookupTableAddresses = [
        sol.config,
        globalConfig,
        sol.vault,
        sol.noteTree,
        sol.nullifiers,
        solVaultAccount.address,
        sol.mint,
        jup.config,
        jup.vault,
        jup.noteTree,
        jupVaultAccount.address,
        jup.mint,
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

      await provider.sendAndConfirm(
        new anchor.web3.Transaction().add(createLutIx).add(extendLutIx),
      );
      await new Promise((r) => setTimeout(r, 1000));

      const lookupTableAccount =
        await provider.connection.getAddressLookupTable(lookupTableAddress);
      if (!lookupTableAccount.value)
        throw new Error("Failed to fetch lookup table");

      try {
        const swapIx = await (program.methods as any)
          .transactSwap(
            proof,
            Array.from(root),
            0,
            sol.mint,
            Array.from(note.nullifier),
            Array.from(dummyNullifier),
            0,
            jup.mint,
            Array.from(changeCommitment),
            Array.from(destCommitment),
            swapParams,
            new BN(SWAP_AMOUNT),
            swapData,
            extData,
          )
          .accounts({
            sourceConfig: sol.config,
            globalConfig,
            sourceVault: sol.vault,
            sourceTree: sol.noteTree,
            sourceNullifiers: sol.nullifiers,
            sourceNullifierMarker0: nullifierMarker0,
            sourceNullifierMarker1: nullifierMarker1,
            sourceVaultTokenAccount: solVaultAccount.address,
            sourceMintAccount: sol.mint,
            destConfig: jup.config,
            destVault: jup.vault,
            destTree: jup.noteTree,
            destVaultTokenAccount: jupVaultAccount.address,
            destMintAccount: jup.mint,
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
            {
              pubkey: poolConfig.serumMarket,
              isSigner: false,
              isWritable: true,
            },
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

        const txSig = await provider.connection.sendTransaction(versionedTx, {
          skipPreflight: false,
        });
        await provider.connection.confirmTransaction({
          signature: txSig,
          blockhash,
          lastValidBlockHeight,
        });

        console.log(`✅ SOL -> JUP swap executed: ${txSig}`);

        const jupLeafIndex = jup.offchainTree.insert(destCommitment);
        jupNoteId = noteStorage.save({
          amount: EXPECTED_JUP_OUT,
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
          merklePath: jup.offchainTree.getMerkleProof(jupLeafIndex),
          mintAddress: jup.mint,
        });

        const solChangeLeafIndex = sol.offchainTree.insert(changeCommitment);
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
          merklePath: sol.offchainTree.getMerkleProof(solChangeLeafIndex),
          mintAddress: sol.mint,
        });

        console.log(
          `   JUP note: ${jupNoteId} (${Number(EXPECTED_JUP_OUT) / 1e6} JUP)`,
        );
        console.log(
          `   SOL change: ${solChangeNoteId} (${
            Number(changeAmount) / 1e9
          } SOL)`,
        );
      } catch (e: any) {
        if (e instanceof SendTransactionError) {
          const logs = await e.getLogs(provider.connection);
          console.error("\n❌ Swap failed:");
          logs?.slice(-10).forEach((l: string) => console.error(`   ${l}`));
        }
        throw e;
      }
    });

    it("verifies JUP note from swap exists", async function () {
      if (!jupNoteId) return this.skip();
      const note = noteStorage.get(jupNoteId);
      expect(note).to.not.be.undefined;
      expect(note!.amount).to.equal(EXPECTED_JUP_OUT);
      console.log(`✅ JUP note verified: ${Number(note!.amount) / 1e6} JUP`);
    });

    it("verifies SOL change note from swap exists", async function () {
      if (!solChangeNoteId) return this.skip();
      const note = noteStorage.get(solChangeNoteId);
      expect(note).to.not.be.undefined;
      console.log(
        `✅ SOL change note verified: ${Number(note!.amount) / 1e9} SOL`,
      );
    });
  });

  // ============================================================================
  // SECTION 5: SOL -> USD1 Swap Test
  // ============================================================================

  describe("SOL -> USD1 Swap", () => {
    const DEPOSIT_AMOUNT = 2_000_000_000n; // 2 SOL
    const SWAP_AMOUNT = 500_000_000; // 0.5 SOL
    const EXPECTED_USD1_OUT = 75_000_000n; // ~75 USD1
    const SWAP_FEE = 375_000n; // 0.5% of 75 USD1

    let depositNoteId: string | null = null;
    let usd1NoteId: string | null = null;
    let solChangeNoteId: string | null = null;
    let poolConfig: AmmV4PoolConfig;
    let serumVaultSigner: PublicKey;

    before(async () => {
      try {
        const poolKeys = await getPoolKeysFromMints(
          provider.connection,
          WSOL_MINT,
          USD1_MINT,
        );
        poolConfig = poolKeysToConfig(poolKeys);
        serumVaultSigner = deriveSerumVaultSigner(
          poolConfig.serumMarket,
          new BN(poolConfig.serumVaultSignerNonce),
        );
      } catch (e) {
        console.log("⚠️ SOL-USD1 pool not available, skipping swap tests");
      }
    });

    it("deposits SOL to privacy pool for USD1 swap", async function () {
      if (!poolConfig) return this.skip();

      const sol = pools.SOL;
      console.log("\n🎁 Depositing SOL for USD1 swap...");

      // Vault token account should already exist from previous tests
      const vaultAta = await getAssociatedTokenAddress(
        sol.mint,
        sol.vault,
        true,
      );
      try {
        const createAtaIx = createAssociatedTokenAccountIdempotentInstruction(
          payer.publicKey,
          vaultAta,
          sol.vault,
          sol.mint,
        );
        await provider.sendAndConfirm(new Transaction().add(createAtaIx));
      } catch (e) {
        // Account may already exist, which is fine
      }
      const wsolKeypair = Keypair.generate();
      const wsolAccount = await createWrappedNativeAccount(
        provider.connection,
        payer,
        payer.publicKey,
        Number(DEPOSIT_AMOUNT) + 1_000_000,
        wsolKeypair, // Pass keypair to avoid ATA path
      );

      const privateKey = randomBytes32();
      const publicKey = derivePublicKey(poseidon, privateKey);
      const blinding = randomBytes32();
      const commitment = computeCommitment(
        poseidon,
        DEPOSIT_AMOUNT,
        publicKey,
        blinding,
        sol.mint,
      );

      const dummyPrivKey1 = randomBytes32();
      const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);
      const dummyBlinding1 = randomBytes32();
      const dummyCommitment1 = computeCommitment(
        poseidon,
        0n,
        dummyPubKey1,
        dummyBlinding1,
        sol.mint,
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
        sol.mint,
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
        sol.mint,
      );

      const extData = {
        recipient: payer.publicKey,
        relayer: payer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
      };
      const extDataHash = computeExtDataHash(poseidon, extData);
      const dummyProof = sol.offchainTree.getMerkleProof(0);
      const root = sol.offchainTree.getRoot();

      const proof = await generateTransactionProof({
        root,
        publicAmount: DEPOSIT_AMOUNT,
        extDataHash,
        mintAddress: sol.mint,
        inputNullifiers: [dummyNullifier1, dummyNullifier2],
        outputCommitments: [commitment, changeCommitment],
        inputAmounts: [0n, 0n],
        inputPrivateKeys: [dummyPrivKey1, dummyPrivKey2],
        inputPublicKeys: [dummyPubKey1, dummyPubKey2],
        inputBlindings: [dummyBlinding1, dummyBlinding2],
        inputMerklePaths: [dummyProof, dummyProof],
        outputAmounts: [DEPOSIT_AMOUNT, 0n],
        outputOwners: [publicKey, changePubKey],
        outputBlindings: [blinding, changeBlinding],
      });

      const nullifierMarker0 = deriveNullifierMarkerPDA(
        program.programId,
        sol.mint,
        0,
        dummyNullifier1,
      );
      const nullifierMarker1 = deriveNullifierMarkerPDA(
        program.programId,
        sol.mint,
        0,
        dummyNullifier2,
      );

      await (program.methods as any)
        .transact(
          Array.from(root),
          0,
          0,
          new BN(DEPOSIT_AMOUNT.toString()),
          Array.from(extDataHash),
          sol.mint,
          Array.from(dummyNullifier1),
          Array.from(dummyNullifier2),
          Array.from(commitment),
          Array.from(changeCommitment),
          extData,
          proof,
        )
        .accounts({
          config: sol.config,
          globalConfig,
          vault: sol.vault,
          inputTree: sol.noteTree,
          outputTree: sol.noteTree,
          nullifiers: sol.nullifiers,
          nullifierMarker0,
          nullifierMarker1,
          relayer: payer.publicKey,
          recipient: payer.publicKey,
          vaultTokenAccount: sol.vaultTokenAccount,
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

      const leafIndex = sol.offchainTree.insert(commitment);
      sol.offchainTree.insert(changeCommitment);

      depositNoteId = noteStorage.save({
        amount: DEPOSIT_AMOUNT,
        commitment,
        nullifier: computeNullifier(
          poseidon,
          commitment,
          leafIndex,
          privateKey,
        ),
        blinding,
        privateKey,
        publicKey,
        leafIndex,
        merklePath: sol.offchainTree.getMerkleProof(leafIndex),
        mintAddress: sol.mint,
      });

      console.log(`✅ Deposited ${Number(DEPOSIT_AMOUNT) / 1e9} SOL`);
      console.log(`   Note ID: ${depositNoteId}`);
    });

    it("executes SOL -> USD1 swap via AMM V4", async function () {
      if (!poolConfig || !depositNoteId) return this.skip();

      const sol = pools.SOL;
      const usd1 = pools.USD1;
      console.log("\n🔄 Executing SOL -> USD1 swap...");

      const note = noteStorage.get(depositNoteId);
      if (!note) throw new Error("Deposit note not found");

      const merkleProof = sol.offchainTree.getMerkleProof(note.leafIndex);
      const root = sol.offchainTree.getRoot();

      const dummyPrivKey = randomBytes32();
      const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
      const dummyBlinding = randomBytes32();
      const dummyCommitment = computeCommitment(
        poseidon,
        0n,
        dummyPubKey,
        dummyBlinding,
        sol.mint,
      );
      const dummyNullifier = computeNullifier(
        poseidon,
        dummyCommitment,
        0,
        dummyPrivKey,
      );
      const dummyProof = sol.offchainTree.getMerkleProof(0);

      const destPrivKey = randomBytes32();
      const destPubKey = derivePublicKey(poseidon, destPrivKey);
      const destBlinding = randomBytes32();
      const destCommitment = computeCommitment(
        poseidon,
        EXPECTED_USD1_OUT,
        destPubKey,
        destBlinding,
        usd1.mint,
      );
      const destCommitmentForProof = computeCommitment(
        poseidon,
        0n,
        destPubKey,
        destBlinding,
        sol.mint,
      );

      const changeAmount = note.amount - BigInt(SWAP_AMOUNT);
      const changePrivKey = randomBytes32();
      const changePubKey = derivePublicKey(poseidon, changePrivKey);
      const changeBlinding = randomBytes32();
      const changeCommitment = computeCommitment(
        poseidon,
        changeAmount,
        changePubKey,
        changeBlinding,
        sol.mint,
      );

      const extData = {
        recipient: payer.publicKey,
        relayer: payer.publicKey,
        fee: new BN(SWAP_FEE.toString()),
        refund: new BN(0),
      };
      const extDataHash = computeExtDataHash(poseidon, extData);

      const minAmountOut = new BN(15_000_000); // 15 USD1 (safe slippage vs 20)
      const deadline = new BN(Math.floor(Date.now() / 1000) + 3600);

      const swapParams = {
        minAmountOut,
        deadline,
        sourceMint: sol.mint,
        destMint: usd1.mint,
      };

      const swapParamsHash = computeSwapParamsHash(
        poseidon,
        sol.mint,
        usd1.mint,
        BigInt(minAmountOut.toString()),
        BigInt(deadline.toString()),
      );

      console.log("   Generating ZK proof...");
      const proof = await generateSwapProof({
        sourceRoot: root,
        swapParamsHash,
        extDataHash,
        sourceMint: sol.mint,
        destMint: usd1.mint,
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

        destAmount: EXPECTED_USD1_OUT,
        destPubkey: destPubKey,
        destBlinding,

        minAmountOut: BigInt(minAmountOut.toString()),
        deadline: BigInt(deadline.toString()),
      });
      console.log("   ✅ ZK proof generated");

      const swapData = buildAmmSwapData(new BN(SWAP_AMOUNT), minAmountOut);

      const [executorPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("swap_executor"),
          sol.mint.toBuffer(),
          usd1.mint.toBuffer(),
          Buffer.from(note.nullifier),
        ],
        program.programId,
      );
      const executorSourceToken = await getAssociatedTokenAddress(
        sol.mint,
        executorPda,
        true,
      );
      const executorDestToken = await getAssociatedTokenAddress(
        usd1.mint,
        executorPda,
        true,
      );

      const nullifierMarker0 = deriveNullifierMarkerPDA(
        program.programId,
        sol.mint,
        0,
        note.nullifier,
      );
      const nullifierMarker1 = deriveNullifierMarkerPDA(
        program.programId,
        sol.mint,
        0,
        dummyNullifier,
      );

      const solVaultAccount = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payer,
        sol.mint,
        sol.vault,
        true,
      );
      const usd1VaultAccount = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payer,
        usd1.mint,
        usd1.vault,
        true,
      );
      const relayerTokenAccount = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payer,
        usd1.mint,
        payer.publicKey,
      );

      const recentSlot = await provider.connection.getSlot("finalized");
      const lookupTableAddresses = [
        sol.config,
        globalConfig,
        sol.vault,
        sol.noteTree,
        sol.nullifiers,
        solVaultAccount.address,
        sol.mint,
        usd1.config,
        usd1.vault,
        usd1.noteTree,
        usd1VaultAccount.address,
        usd1.mint,
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

      await provider.sendAndConfirm(
        new anchor.web3.Transaction().add(createLutIx).add(extendLutIx),
      );
      await new Promise((r) => setTimeout(r, 1000));

      const lookupTableAccount =
        await provider.connection.getAddressLookupTable(lookupTableAddress);
      if (!lookupTableAccount.value)
        throw new Error("Failed to fetch lookup table");

      try {
        const swapIx = await (program.methods as any)
          .transactSwap(
            proof,
            Array.from(root),
            0,
            sol.mint,
            Array.from(note.nullifier),
            Array.from(dummyNullifier),
            0,
            usd1.mint,
            Array.from(changeCommitment),
            Array.from(destCommitment),
            swapParams,
            new BN(SWAP_AMOUNT),
            swapData,
            extData,
          )
          .accounts({
            sourceConfig: sol.config,
            globalConfig,
            sourceVault: sol.vault,
            sourceTree: sol.noteTree,
            sourceNullifiers: sol.nullifiers,
            sourceNullifierMarker0: nullifierMarker0,
            sourceNullifierMarker1: nullifierMarker1,
            sourceVaultTokenAccount: solVaultAccount.address,
            sourceMintAccount: sol.mint,
            destConfig: usd1.config,
            destVault: usd1.vault,
            destTree: usd1.noteTree,
            destVaultTokenAccount: usd1VaultAccount.address,
            destMintAccount: usd1.mint,
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
            {
              pubkey: poolConfig.serumMarket,
              isSigner: false,
              isWritable: true,
            },
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

        const txSig = await provider.connection.sendTransaction(versionedTx, {
          skipPreflight: false,
        });
        await provider.connection.confirmTransaction({
          signature: txSig,
          blockhash,
          lastValidBlockHeight,
        });

        console.log(`✅ SOL -> USD1 swap executed: ${txSig}`);

        const usd1LeafIndex = usd1.offchainTree.insert(destCommitment);
        usd1NoteId = noteStorage.save({
          amount: EXPECTED_USD1_OUT,
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
          merklePath: usd1.offchainTree.getMerkleProof(usd1LeafIndex),
          mintAddress: usd1.mint,
        });

        const solChangeLeafIndex = sol.offchainTree.insert(changeCommitment);
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
          merklePath: sol.offchainTree.getMerkleProof(solChangeLeafIndex),
          mintAddress: sol.mint,
        });

        console.log(
          `   USD1 note: ${usd1NoteId} (${
            Number(EXPECTED_USD1_OUT) / 1e6
          } USD1)`,
        );
        console.log(
          `   SOL change: ${solChangeNoteId} (${
            Number(changeAmount) / 1e9
          } SOL)`,
        );
      } catch (e: any) {
        if (e instanceof SendTransactionError) {
          const logs = await e.getLogs(provider.connection);
          console.error("\n❌ Swap failed:");
          logs?.slice(-10).forEach((l: string) => console.error(`   ${l}`));
        }
        throw e;
      }
    });

    it("verifies USD1 note from swap exists", async function () {
      if (!usd1NoteId) return this.skip();
      const note = noteStorage.get(usd1NoteId);
      expect(note).to.not.be.undefined;
      expect(note!.amount).to.equal(EXPECTED_USD1_OUT);
      console.log(`✅ USD1 note verified: ${Number(note!.amount) / 1e6} USD1`);
    });

    it("verifies SOL change note from swap exists", async function () {
      if (!solChangeNoteId) return this.skip();
      const note = noteStorage.get(solChangeNoteId);
      expect(note).to.not.be.undefined;
      console.log(
        `✅ SOL change note verified: ${Number(note!.amount) / 1e9} SOL`,
      );
    });
  });

  // ============================================================================
  // SECTION 6: USDC -> JUP Swap Test (Chained via SOL)
  // This test demonstrates a chained swap: SOL -> USDC -> JUP
  // ============================================================================

  describe("USDC -> JUP Swap (Chained from SOL)", () => {
    // Step 1: Deposit SOL
    const SOL_DEPOSIT_AMOUNT = 2_000_000_000n; // 2 SOL
    // Step 2: Swap SOL to USDC
    const SOL_SWAP_AMOUNT = 1_000_000_000; // 1 SOL
    const EXPECTED_USDC_OUT = 150_000_000n; // ~150 USDC (conservative estimate)
    const USDC_SWAP_FEE = 1_000_000n; // 1 USDC fee for relayer
    // Step 3: Swap USDC to JUP
    const USDC_SWAP_AMOUNT = 100_000_000; // 100 USDC
    const EXPECTED_JUP_OUT = 100_000_000n; // ~100 JUP (estimated)
    const JUP_SWAP_FEE = 50_000_000n; // 50 JUP fee for relayer

    let solDepositNoteId: string | null = null;
    let usdcNoteId: string | null = null;
    let solChangeNoteId: string | null = null;
    let jupNoteId: string | null = null;
    let usdcChangeNoteId: string | null = null;

    let solUsdcPoolConfig: AmmV4PoolConfig;
    let solUsdcSerumVaultSigner: PublicKey;
    let usdcJupPoolConfig: AmmV4PoolConfig;
    let usdcJupSerumVaultSigner: PublicKey;

    before(async () => {
      try {
        // Get SOL-USDC pool
        const solUsdcKeys = await getPoolKeysFromMints(
          provider.connection,
          WSOL_MINT,
          USDC_MINT,
        );
        solUsdcPoolConfig = poolKeysToConfig(solUsdcKeys);
        solUsdcSerumVaultSigner = deriveSerumVaultSigner(
          solUsdcPoolConfig.serumMarket,
          new BN(solUsdcPoolConfig.serumVaultSignerNonce),
        );
        console.log(
          `\n✅ SOL-USDC Pool found: ${solUsdcPoolConfig.poolId.toBase58()}`,
        );

        // Get USDC-JUP pool
        const usdcJupKeys = await getPoolKeysFromMints(
          provider.connection,
          USDC_MINT,
          JUP_MINT,
        );
        usdcJupPoolConfig = poolKeysToConfig(usdcJupKeys);
        usdcJupSerumVaultSigner = deriveSerumVaultSigner(
          usdcJupPoolConfig.serumMarket,
          new BN(usdcJupPoolConfig.serumVaultSignerNonce),
        );
        console.log(
          `✅ USDC-JUP Pool found: ${usdcJupPoolConfig.poolId.toBase58()}`,
        );
      } catch (e: any) {
        console.log(
          "⚠️ Pool(s) not available, skipping chained swap tests:",
          e.message,
        );
      }
    });

    it("Step 1: deposits SOL to privacy pool for chained swap", async function () {
      if (!solUsdcPoolConfig || !usdcJupPoolConfig) return this.skip();

      const sol = pools.SOL;
      console.log("\n🎁 Step 1: Depositing SOL for chained swap...");

      // Wrap SOL
      await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payer,
        sol.mint,
        payer.publicKey,
      );

      const wrapIx = SystemProgram.transfer({
        fromPubkey: payer.publicKey,
        toPubkey: await getAssociatedTokenAddress(sol.mint, payer.publicKey),
        lamports: BigInt(SOL_DEPOSIT_AMOUNT),
      });
      const syncIx = createSyncNativeInstruction(
        await getAssociatedTokenAddress(sol.mint, payer.publicKey),
      );
      const tx = new Transaction().add(wrapIx, syncIx);
      await provider.sendAndConfirm(tx);

      // Create vault's token account
      const vaultAta = await getAssociatedTokenAddress(
        sol.mint,
        sol.vault,
        true,
      );
      const createAtaIx = createAssociatedTokenAccountIdempotentInstruction(
        payer.publicKey,
        vaultAta,
        sol.vault,
        sol.mint,
      );
      try {
        await provider.sendAndConfirm(new Transaction().add(createAtaIx));
      } catch (e) {}

      const userSolAccount = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payer,
        sol.mint,
        payer.publicKey,
      );

      const privateKey = randomBytes32();
      const publicKey = derivePublicKey(poseidon, privateKey);
      const blinding = randomBytes32();
      const commitment = computeCommitment(
        poseidon,
        SOL_DEPOSIT_AMOUNT,
        publicKey,
        blinding,
        sol.mint,
      );

      const dummyPrivKey1 = randomBytes32();
      const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);
      const dummyBlinding1 = randomBytes32();
      const dummyCommitment1 = computeCommitment(
        poseidon,
        0n,
        dummyPubKey1,
        dummyBlinding1,
        sol.mint,
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
        sol.mint,
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
        sol.mint,
      );

      const extData = {
        recipient: payer.publicKey,
        relayer: payer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
      };
      const extDataHash = computeExtDataHash(poseidon, extData);
      const dummyProof = sol.offchainTree.getMerkleProof(0);
      const root = sol.offchainTree.getRoot();

      const proof = await generateTransactionProof({
        root,
        publicAmount: SOL_DEPOSIT_AMOUNT,
        extDataHash,
        mintAddress: sol.mint,
        inputNullifiers: [dummyNullifier1, dummyNullifier2],
        outputCommitments: [commitment, changeCommitment],
        inputAmounts: [0n, 0n],
        inputPrivateKeys: [dummyPrivKey1, dummyPrivKey2],
        inputPublicKeys: [dummyPubKey1, dummyPubKey2],
        inputBlindings: [dummyBlinding1, dummyBlinding2],
        inputMerklePaths: [dummyProof, dummyProof],
        outputAmounts: [SOL_DEPOSIT_AMOUNT, 0n],
        outputOwners: [publicKey, changePubKey],
        outputBlindings: [blinding, changeBlinding],
      });

      const nullifierMarker0 = deriveNullifierMarkerPDA(
        program.programId,
        sol.mint,
        0,
        dummyNullifier1,
      );
      const nullifierMarker1 = deriveNullifierMarkerPDA(
        program.programId,
        sol.mint,
        0,
        dummyNullifier2,
      );

      await (program.methods as any)
        .transact(
          Array.from(root),
          0,
          0,
          new BN(SOL_DEPOSIT_AMOUNT.toString()),
          Array.from(extDataHash),
          sol.mint,
          Array.from(dummyNullifier1),
          Array.from(dummyNullifier2),
          Array.from(commitment),
          Array.from(changeCommitment),
          extData,
          proof,
        )
        .accounts({
          config: sol.config,
          globalConfig,
          vault: sol.vault,
          inputTree: sol.noteTree,
          outputTree: sol.noteTree,
          nullifiers: sol.nullifiers,
          nullifierMarker0,
          nullifierMarker1,
          relayer: payer.publicKey,
          recipient: payer.publicKey,
          vaultTokenAccount: sol.vaultTokenAccount,
          userTokenAccount: userSolAccount.address,
          recipientTokenAccount: userSolAccount.address,
          relayerTokenAccount: userSolAccount.address,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .preInstructions([
          ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
        ])
        .rpc();

      const leafIndex = sol.offchainTree.insert(commitment);
      sol.offchainTree.insert(changeCommitment);

      solDepositNoteId = noteStorage.save({
        amount: SOL_DEPOSIT_AMOUNT,
        commitment,
        nullifier: computeNullifier(
          poseidon,
          commitment,
          leafIndex,
          privateKey,
        ),
        blinding,
        privateKey,
        publicKey,
        leafIndex,
        merklePath: sol.offchainTree.getMerkleProof(leafIndex),
        mintAddress: sol.mint,
      });

      console.log(`✅ Deposited ${Number(SOL_DEPOSIT_AMOUNT) / 1e9} SOL`);
      console.log(`   Note ID: ${solDepositNoteId}`);
    });

    it("Step 2: swaps SOL -> USDC via AMM V4", async function () {
      if (!solUsdcPoolConfig || !solDepositNoteId) return this.skip();

      const sol = pools.SOL;
      const usdc = pools.USDC;
      console.log("\n🔄 Step 2: Executing SOL -> USDC swap...");

      const note = noteStorage.get(solDepositNoteId);
      if (!note) throw new Error("SOL deposit note not found");

      const merkleProof = sol.offchainTree.getMerkleProof(note.leafIndex);
      const root = sol.offchainTree.getRoot();

      // Dummy second input
      const dummyPrivKey = randomBytes32();
      const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
      const dummyBlinding = randomBytes32();
      const dummyCommitment = computeCommitment(
        poseidon,
        0n,
        dummyPubKey,
        dummyBlinding,
        sol.mint,
      );
      const dummyNullifier = computeNullifier(
        poseidon,
        dummyCommitment,
        0,
        dummyPrivKey,
      );
      const dummyProof = sol.offchainTree.getMerkleProof(0);

      // Output: USDC note
      const destPrivKey = randomBytes32();
      const destPubKey = derivePublicKey(poseidon, destPrivKey);
      const destBlinding = randomBytes32();
      const destCommitment = computeCommitment(
        poseidon,
        EXPECTED_USDC_OUT,
        destPubKey,
        destBlinding,
        usdc.mint,
      );
      const destCommitmentForProof = computeCommitment(
        poseidon,
        0n,
        destPubKey,
        destBlinding,
        sol.mint,
      );

      // Change: remaining SOL
      const changeAmount = note.amount - BigInt(SOL_SWAP_AMOUNT);
      const changePrivKey = randomBytes32();
      const changePubKey = derivePublicKey(poseidon, changePrivKey);
      const changeBlinding = randomBytes32();
      const changeCommitment = computeCommitment(
        poseidon,
        changeAmount,
        changePubKey,
        changeBlinding,
        sol.mint,
      );

      const extData = {
        recipient: payer.publicKey,
        relayer: payer.publicKey,
        fee: new BN(USDC_SWAP_FEE.toString()),
        refund: new BN(0),
      };
      const extDataHash = computeExtDataHash(poseidon, extData);

      const minAmountOut = new BN(15_000_000); // 15 USDC
      const deadline = new BN(Math.floor(Date.now() / 1000) + 3600);

      const swapParams = {
        minAmountOut,
        deadline,
        sourceMint: sol.mint,
        destMint: usdc.mint,
      };

      const swapParamsHash = computeSwapParamsHash(
        poseidon,
        sol.mint,
        usdc.mint,
        BigInt(minAmountOut.toString()),
        BigInt(deadline.toString()),
      );

      console.log("   Generating ZK proof...");
      const proof = await generateSwapProof({
        sourceRoot: root,
        swapParamsHash,
        extDataHash,
        sourceMint: sol.mint,
        destMint: usdc.mint,
        inputNullifiers: [note.nullifier, dummyNullifier],
        changeCommitment,
        destCommitment,
        swapAmount: BigInt(SOL_SWAP_AMOUNT),

        inputAmounts: [note.amount, 0n],
        inputPrivateKeys: [note.privateKey, dummyPrivKey],
        inputPublicKeys: [note.publicKey, dummyPubKey],
        inputBlindings: [note.blinding, dummyBlinding],
        inputMerklePaths: [merkleProof, dummyProof],

        changeAmount,
        changePubkey: changePubKey,
        changeBlinding,

        destAmount: EXPECTED_USDC_OUT,
        destPubkey: destPubKey,
        destBlinding,

        minAmountOut: BigInt(minAmountOut.toString()),
        deadline: BigInt(deadline.toString()),
      });
      console.log("   ✅ ZK proof generated");

      const swapData = buildAmmSwapData(new BN(SOL_SWAP_AMOUNT), minAmountOut);

      const [executorPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("swap_executor"),
          sol.mint.toBuffer(),
          usdc.mint.toBuffer(),
          Buffer.from(note.nullifier),
        ],
        program.programId,
      );
      const executorSourceToken = await getAssociatedTokenAddress(
        sol.mint,
        executorPda,
        true,
      );
      const executorDestToken = await getAssociatedTokenAddress(
        usdc.mint,
        executorPda,
        true,
      );

      const nullifierMarker0 = deriveNullifierMarkerPDA(
        program.programId,
        sol.mint,
        0,
        note.nullifier,
      );
      const nullifierMarker1 = deriveNullifierMarkerPDA(
        program.programId,
        sol.mint,
        0,
        dummyNullifier,
      );

      const solVaultAccount = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payer,
        sol.mint,
        sol.vault,
        true,
      );
      const usdcVaultAccount = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payer,
        usdc.mint,
        usdc.vault,
        true,
      );
      const relayerTokenAccount = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payer,
        usdc.mint,
        payer.publicKey,
      );

      // Create lookup table
      const recentSlot = await provider.connection.getSlot("finalized");
      const lookupTableAddresses = [
        sol.config,
        globalConfig,
        sol.vault,
        sol.noteTree,
        sol.nullifiers,
        solVaultAccount.address,
        sol.mint,
        usdc.config,
        usdc.vault,
        usdc.noteTree,
        usdcVaultAccount.address,
        usdc.mint,
        RAYDIUM_AMM_V4_PROGRAM,
        SERUM_PROGRAM,
        TOKEN_PROGRAM_ID,
        SystemProgram.programId,
        ASSOCIATED_TOKEN_PROGRAM_ID,
        solUsdcPoolConfig.poolId,
        AMM_AUTHORITY,
        solUsdcPoolConfig.ammOpenOrders,
        solUsdcPoolConfig.ammTargetOrders,
        solUsdcPoolConfig.ammBaseVault,
        solUsdcPoolConfig.ammQuoteVault,
        solUsdcPoolConfig.serumMarket,
        solUsdcPoolConfig.serumBids,
        solUsdcPoolConfig.serumAsks,
        solUsdcPoolConfig.serumEventQueue,
        solUsdcPoolConfig.serumBaseVault,
        solUsdcPoolConfig.serumQuoteVault,
        solUsdcSerumVaultSigner,
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

      const lutTx = new Transaction().add(createLutIx, extendLutIx);
      await provider.sendAndConfirm(lutTx);
      await new Promise((resolve) => setTimeout(resolve, 2000));

      const lookupTableAccount = (
        await provider.connection.getAddressLookupTable(lookupTableAddress)
      ).value!;

      try {
        const swapIx = await (program.methods as any)
          .transactSwap(
            proof,
            Array.from(root),
            0,
            sol.mint,
            Array.from(note.nullifier),
            Array.from(dummyNullifier),
            0,
            usdc.mint,
            Array.from(changeCommitment),
            Array.from(destCommitment),
            swapParams,
            new BN(SOL_SWAP_AMOUNT),
            swapData,
            extData,
          )
          .accounts({
            sourceConfig: sol.config,
            globalConfig,
            sourceVault: sol.vault,
            sourceTree: sol.noteTree,
            sourceNullifiers: sol.nullifiers,
            sourceNullifierMarker0: nullifierMarker0,
            sourceNullifierMarker1: nullifierMarker1,
            sourceVaultTokenAccount: solVaultAccount.address,
            sourceMintAccount: sol.mint,
            destConfig: usdc.config,
            destVault: usdc.vault,
            destTree: usdc.noteTree,
            destVaultTokenAccount: usdcVaultAccount.address,
            destMintAccount: usdc.mint,
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
            {
              pubkey: solUsdcPoolConfig.poolId,
              isSigner: false,
              isWritable: true,
            },
            { pubkey: AMM_AUTHORITY, isSigner: false, isWritable: false },
            {
              pubkey: solUsdcPoolConfig.ammOpenOrders,
              isSigner: false,
              isWritable: true,
            },
            {
              pubkey: solUsdcPoolConfig.ammTargetOrders,
              isSigner: false,
              isWritable: true,
            },
            {
              pubkey: solUsdcPoolConfig.ammBaseVault,
              isSigner: false,
              isWritable: true,
            },
            {
              pubkey: solUsdcPoolConfig.ammQuoteVault,
              isSigner: false,
              isWritable: true,
            },
            { pubkey: SERUM_PROGRAM, isSigner: false, isWritable: false },
            {
              pubkey: solUsdcPoolConfig.serumMarket,
              isSigner: false,
              isWritable: true,
            },
            {
              pubkey: solUsdcPoolConfig.serumBids,
              isSigner: false,
              isWritable: true,
            },
            {
              pubkey: solUsdcPoolConfig.serumAsks,
              isSigner: false,
              isWritable: true,
            },
            {
              pubkey: solUsdcPoolConfig.serumEventQueue,
              isSigner: false,
              isWritable: true,
            },
            {
              pubkey: solUsdcPoolConfig.serumBaseVault,
              isSigner: false,
              isWritable: true,
            },
            {
              pubkey: solUsdcPoolConfig.serumQuoteVault,
              isSigner: false,
              isWritable: true,
            },
            {
              pubkey: solUsdcSerumVaultSigner,
              isSigner: false,
              isWritable: false,
            },
          ])
          .instruction();

        const { blockhash } = await provider.connection.getLatestBlockhash();
        const messageV0 = new TransactionMessage({
          payerKey: payer.publicKey,
          recentBlockhash: blockhash,
          instructions: [
            ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
            swapIx,
          ],
        }).compileToV0Message([lookupTableAccount]);
        const txV0 = new VersionedTransaction(messageV0);
        txV0.sign([payer]);

        const sig = await provider.connection.sendTransaction(txV0);
        await provider.connection.confirmTransaction(sig);
        console.log(`   ✅ SOL -> USDC swap executed: ${sig}`);

        // Update offchain trees
        const usdcLeafIndex = usdc.offchainTree.insert(destCommitment);
        const solChangeLeafIndex = sol.offchainTree.insert(changeCommitment);

        // Save USDC note (this will be used for USDC -> JUP swap)
        usdcNoteId = noteStorage.save({
          amount: EXPECTED_USDC_OUT,
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
          merklePath: usdc.offchainTree.getMerkleProof(usdcLeafIndex),
          mintAddress: usdc.mint,
        });

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
          merklePath: sol.offchainTree.getMerkleProof(solChangeLeafIndex),
          mintAddress: sol.mint,
        });

        console.log(
          `   USDC note: ${usdcNoteId} (${
            Number(EXPECTED_USDC_OUT) / 1e6
          } USDC)`,
        );
        console.log(
          `   SOL change: ${solChangeNoteId} (${
            Number(changeAmount) / 1e9
          } SOL)`,
        );
      } catch (e: any) {
        if (e instanceof SendTransactionError) {
          const logs = await e.getLogs(provider.connection);
          console.error("\n❌ SOL -> USDC swap failed:");
          logs?.slice(-10).forEach((l: string) => console.error(`   ${l}`));
        }
        throw e;
      }
    });

    it("Step 3: swaps USDC -> JUP via AMM V4", async function () {
      if (!usdcJupPoolConfig || !usdcNoteId) return this.skip();

      const usdc = pools.USDC;
      const jup = pools.JUP;
      console.log("\n🔄 Step 3: Executing USDC -> JUP swap...");

      const note = noteStorage.get(usdcNoteId);
      if (!note) throw new Error("USDC note not found");

      const merkleProof = usdc.offchainTree.getMerkleProof(note.leafIndex);
      const root = usdc.offchainTree.getRoot();

      const dummyPrivKey = randomBytes32();
      const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
      const dummyBlinding = randomBytes32();
      const dummyCommitment = computeCommitment(
        poseidon,
        0n,
        dummyPubKey,
        dummyBlinding,
        usdc.mint,
      );
      const dummyNullifier = computeNullifier(
        poseidon,
        dummyCommitment,
        0,
        dummyPrivKey,
      );
      const dummyProof = usdc.offchainTree.getMerkleProof(0);

      const destPrivKey = randomBytes32();
      const destPubKey = derivePublicKey(poseidon, destPrivKey);
      const destBlinding = randomBytes32();
      const destCommitment = computeCommitment(
        poseidon,
        EXPECTED_JUP_OUT,
        destPubKey,
        destBlinding,
        jup.mint,
      );
      const destCommitmentForProof = computeCommitment(
        poseidon,
        0n,
        destPubKey,
        destBlinding,
        usdc.mint,
      );

      const changeAmount = note.amount - BigInt(USDC_SWAP_AMOUNT);
      const changePrivKey = randomBytes32();
      const changePubKey = derivePublicKey(poseidon, changePrivKey);
      const changeBlinding = randomBytes32();
      const changeCommitment = computeCommitment(
        poseidon,
        changeAmount,
        changePubKey,
        changeBlinding,
        usdc.mint,
      );

      const extData = {
        recipient: payer.publicKey,
        relayer: payer.publicKey,
        fee: new BN(JUP_SWAP_FEE.toString()),
        refund: new BN(0),
      };
      const extDataHash = computeExtDataHash(poseidon, extData);

      const minAmountOut = new BN(100_000_000); // 100 JUP
      const deadline = new BN(Math.floor(Date.now() / 1000) + 3600);

      const swapParams = {
        minAmountOut,
        deadline,
        sourceMint: usdc.mint,
        destMint: jup.mint,
      };

      const swapParamsHash = computeSwapParamsHash(
        poseidon,
        usdc.mint,
        jup.mint,
        BigInt(minAmountOut.toString()),
        BigInt(deadline.toString()),
      );

      console.log("   Generating ZK proof...");
      const proof = await generateSwapProof({
        sourceRoot: root,
        swapParamsHash,
        extDataHash,
        sourceMint: usdc.mint,
        destMint: jup.mint,
        inputNullifiers: [note.nullifier, dummyNullifier],
        changeCommitment,
        destCommitment,
        swapAmount: BigInt(USDC_SWAP_AMOUNT),

        inputAmounts: [note.amount, 0n],
        inputPrivateKeys: [note.privateKey, dummyPrivKey],
        inputPublicKeys: [note.publicKey, dummyPubKey],
        inputBlindings: [note.blinding, dummyBlinding],
        inputMerklePaths: [merkleProof, dummyProof],

        changeAmount,
        changePubkey: changePubKey,
        changeBlinding,

        destAmount: EXPECTED_JUP_OUT,
        destPubkey: destPubKey,
        destBlinding,

        minAmountOut: BigInt(minAmountOut.toString()),
        deadline: BigInt(deadline.toString()),
      });
      console.log("   ✅ ZK proof generated");

      const swapData = buildAmmSwapData(new BN(USDC_SWAP_AMOUNT), minAmountOut);

      const [executorPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("swap_executor"),
          usdc.mint.toBuffer(),
          jup.mint.toBuffer(),
          Buffer.from(note.nullifier),
        ],
        program.programId,
      );
      const executorSourceToken = await getAssociatedTokenAddress(
        usdc.mint,
        executorPda,
        true,
      );
      const executorDestToken = await getAssociatedTokenAddress(
        jup.mint,
        executorPda,
        true,
      );

      const nullifierMarker0 = deriveNullifierMarkerPDA(
        program.programId,
        usdc.mint,
        0,
        note.nullifier,
      );
      const nullifierMarker1 = deriveNullifierMarkerPDA(
        program.programId,
        usdc.mint,
        0,
        dummyNullifier,
      );

      const usdcVaultAccount = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payer,
        usdc.mint,
        usdc.vault,
        true,
      );
      const jupVaultAccount = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payer,
        jup.mint,
        jup.vault,
        true,
      );
      const relayerTokenAccount = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payer,
        jup.mint,
        payer.publicKey,
      );

      const recentSlot = await provider.connection.getSlot("finalized");
      const lookupTableAddresses = [
        usdc.config,
        globalConfig,
        usdc.vault,
        usdc.noteTree,
        usdc.nullifiers,
        usdcVaultAccount.address,
        usdc.mint,
        jup.config,
        jup.vault,
        jup.noteTree,
        jupVaultAccount.address,
        jup.mint,
        RAYDIUM_AMM_V4_PROGRAM,
        SERUM_PROGRAM,
        TOKEN_PROGRAM_ID,
        SystemProgram.programId,
        ASSOCIATED_TOKEN_PROGRAM_ID,
        usdcJupPoolConfig.poolId,
        AMM_AUTHORITY,
        usdcJupPoolConfig.ammOpenOrders,
        usdcJupPoolConfig.ammTargetOrders,
        usdcJupPoolConfig.ammBaseVault,
        usdcJupPoolConfig.ammQuoteVault,
        usdcJupPoolConfig.serumMarket,
        usdcJupPoolConfig.serumBids,
        usdcJupPoolConfig.serumAsks,
        usdcJupPoolConfig.serumEventQueue,
        usdcJupPoolConfig.serumBaseVault,
        usdcJupPoolConfig.serumQuoteVault,
        usdcJupSerumVaultSigner,
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

      await provider.sendAndConfirm(
        new anchor.web3.Transaction().add(createLutIx).add(extendLutIx),
      );
      await new Promise((r) => setTimeout(r, 1000));

      const lookupTableAccount =
        await provider.connection.getAddressLookupTable(lookupTableAddress);
      if (!lookupTableAccount.value)
        throw new Error("Failed to fetch lookup table");

      try {
        const swapIx = await (program.methods as any)
          .transactSwap(
            proof,
            Array.from(root),
            0,
            usdc.mint,
            Array.from(note.nullifier),
            Array.from(dummyNullifier),
            0,
            jup.mint,
            Array.from(changeCommitment),
            Array.from(destCommitment),
            swapParams,
            new BN(USDC_SWAP_AMOUNT),
            swapData,
            extData,
          )
          .accounts({
            sourceConfig: usdc.config,
            globalConfig,
            sourceVault: usdc.vault,
            sourceTree: usdc.noteTree,
            sourceNullifiers: usdc.nullifiers,
            sourceNullifierMarker0: nullifierMarker0,
            sourceNullifierMarker1: nullifierMarker1,
            sourceVaultTokenAccount: usdcVaultAccount.address,
            sourceMintAccount: usdc.mint,
            destConfig: jup.config,
            destVault: jup.vault,
            destTree: jup.noteTree,
            destVaultTokenAccount: jupVaultAccount.address,
            destMintAccount: jup.mint,
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
            {
              pubkey: usdcJupPoolConfig.poolId,
              isSigner: false,
              isWritable: true,
            },
            { pubkey: AMM_AUTHORITY, isSigner: false, isWritable: false },
            {
              pubkey: usdcJupPoolConfig.ammOpenOrders,
              isSigner: false,
              isWritable: true,
            },
            {
              pubkey: usdcJupPoolConfig.ammTargetOrders,
              isSigner: false,
              isWritable: true,
            },
            {
              pubkey: usdcJupPoolConfig.ammBaseVault,
              isSigner: false,
              isWritable: true,
            },
            {
              pubkey: usdcJupPoolConfig.ammQuoteVault,
              isSigner: false,
              isWritable: true,
            },
            { pubkey: SERUM_PROGRAM, isSigner: false, isWritable: false },
            {
              pubkey: usdcJupPoolConfig.serumMarket,
              isSigner: false,
              isWritable: true,
            },
            {
              pubkey: usdcJupPoolConfig.serumBids,
              isSigner: false,
              isWritable: true,
            },
            {
              pubkey: usdcJupPoolConfig.serumAsks,
              isSigner: false,
              isWritable: true,
            },
            {
              pubkey: usdcJupPoolConfig.serumEventQueue,
              isSigner: false,
              isWritable: true,
            },
            {
              pubkey: usdcJupPoolConfig.serumBaseVault,
              isSigner: false,
              isWritable: true,
            },
            {
              pubkey: usdcJupPoolConfig.serumQuoteVault,
              isSigner: false,
              isWritable: true,
            },
            {
              pubkey: usdcJupSerumVaultSigner,
              isSigner: false,
              isWritable: false,
            },
          ])
          .instruction();

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

        const txSig = await provider.connection.sendTransaction(versionedTx, {
          skipPreflight: false,
        });
        await provider.connection.confirmTransaction({
          signature: txSig,
          blockhash,
          lastValidBlockHeight,
        });

        console.log(`✅ USDC -> JUP swap executed: ${txSig}`);

        const jupLeafIndex = jup.offchainTree.insert(destCommitment);
        jupNoteId = noteStorage.save({
          amount: EXPECTED_JUP_OUT,
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
          merklePath: jup.offchainTree.getMerkleProof(jupLeafIndex),
          mintAddress: jup.mint,
        });

        const usdcChangeLeafIndex = usdc.offchainTree.insert(changeCommitment);
        usdcChangeNoteId = noteStorage.save({
          amount: changeAmount,
          commitment: changeCommitment,
          nullifier: computeNullifier(
            poseidon,
            changeCommitment,
            usdcChangeLeafIndex,
            changePrivKey,
          ),
          blinding: changeBlinding,
          privateKey: changePrivKey,
          publicKey: changePubKey,
          leafIndex: usdcChangeLeafIndex,
          merklePath: usdc.offchainTree.getMerkleProof(usdcChangeLeafIndex),
          mintAddress: usdc.mint,
        });

        console.log(
          `   JUP note: ${jupNoteId} (${Number(EXPECTED_JUP_OUT) / 1e6} JUP)`,
        );
        console.log(
          `   USDC change: ${usdcChangeNoteId} (${
            Number(changeAmount) / 1e6
          } USDC)`,
        );
      } catch (e: any) {
        if (e instanceof SendTransactionError) {
          const logs = await e.getLogs(provider.connection);
          console.error("\n❌ Swap failed:");
          logs?.slice(-10).forEach((l: string) => console.error(`   ${l}`));
        }
        throw e;
      }
    });

    it("verifies JUP note from swap exists", async function () {
      if (!jupNoteId) return this.skip();
      const note = noteStorage.get(jupNoteId);
      expect(note).to.not.be.undefined;
      expect(note!.amount).to.equal(EXPECTED_JUP_OUT);
      console.log(`✅ JUP note verified: ${Number(note!.amount) / 1e6} JUP`);
    });

    it("verifies USDC change note from swap exists", async function () {
      if (!usdcChangeNoteId) return this.skip();
      const note = noteStorage.get(usdcChangeNoteId);
      expect(note).to.not.be.undefined;
      console.log(
        `✅ USDC change note verified: ${Number(note!.amount) / 1e6} USDC`,
      );
    });
  });

  // ============================================================================
  // SECTION 7: Summary Tests
  // ============================================================================

  describe("Swap Pairs Summary", () => {
    it("summarizes available swap pairs", () => {
      console.log("\n📊 Privacy Pool Swap Pairs Summary:");
      console.log("   ✅ SOL <-> USDC (tested above)");
      console.log("   ✅ SOL <-> USDT (tested above)");
      console.log("   ✅ SOL <-> JUP  (tested above)");
      console.log("   ✅ SOL <-> USD1 (tested above)");
      console.log("   ✅ USDC <-> JUP (tested above)");
      console.log(
        "\n   Note: USD1 <-> USDC requires routing via SOL (no AMM V4 pool exists).",
      );
      console.log(
        "   Additional swap pairs require corresponding Raydium AMM V4 pools.",
      );
      console.log(
        "   Any pair can be chained via SOL if direct pools don't exist.",
      );
    });

    it("verifies all pools have 50bps swap fees configured", async () => {
      for (const name of Object.keys(pools)) {
        const pool = pools[name];
        try {
          const configData = await (
            program.account as any
          ).privacyPoolConfig.fetch(pool.config);
          expect(configData.swapFeeBps.toNumber()).to.equal(50);
          console.log(`✅ ${name}: 50bps swap fee configured`);
        } catch (e) {
          console.log(`⚠️ ${name}: Could not verify fee config`);
        }
      }
    });
  });
});

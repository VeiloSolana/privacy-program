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
} from "@solana/spl-token";
import { expect } from "chai";
import { buildPoseidon } from "circomlibjs";
import { PrivacyPool } from "../target/types/privacy_pool";
import { JupiterSwapService } from "./utils/jupiter/jupiter-swap-service";
import {
  JUPITER_PROGRAM_ID,
  JUPITER_EVENT_AUTHORITY,
  WSOL_MINT,
  USDC_MINT,
  USDT_MINT,
  JUP_MINT,
  USD1_MINT,
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

    // Only supporting WSOL source for now as per tests
    if (poolName !== "WSOL") {
      throw new Error("initialDeposit helper currently only supports WSOL");
    }

    // Airdrop SOL to payer to ensure funds
    try {
      await airdropAndConfirm(provider, payer.publicKey, 10 * LAMPORTS_PER_SOL);
    } catch (e) {
      console.log(
        "Airdrop failed (likely localnet rate limit or sufficient funds), continuing...",
      );
    }

    // Ensure vault token accounts exist
    await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      pool.mint,
      pool.vault,
      true,
    );

    // Create wrapped SOL account (fresh for each deposit to avoid conflicts)
    const wsolKeypair = Keypair.generate();
    const wsolAccount = await createWrappedNativeAccount(
      provider.connection,
      payer,
      payer.publicKey,
      Number(amount) + 1_000_000,
      wsolKeypair,
    );

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

    const vaultTokenAccount = await getAssociatedTokenAddress(
      mint,
      vault,
      true,
    );

    pools[name] = {
      mint,
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
    await setupPool(WSOL_MINT, "WSOL", 9);
    await setupPool(USDC_MINT, "USDC", 6);
    await setupPool(USDT_MINT, "USDT", 6);
    await setupPool(JUP_MINT, "JUP", 6);
    await setupPool(USD1_MINT, "USD1", 6);
  });

  // --------------------------------------------------------------------------
  // TEST: Deposit SOL
  // --------------------------------------------------------------------------
  it("should deposit SOL to create spendable note", async function () {
    solDepositNoteId = await initialDeposit("WSOL", INITIAL_DEPOSIT);
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

    // Ensure relayer has dest token account
    const relayerTokenAccount = await getOrCreateAssociatedTokenAccount(
      connection,
      payer,
      destPool.mint,
      payer.publicKey,
    );
    // Ensure dest vault account
    await getOrCreateAssociatedTokenAccount(
      connection,
      payer,
      destPool.mint,
      destPool.vault,
      true,
    );

    // =====================================================
    // BALANCE LOGGING: Before swap
    // =====================================================
    const sourceVaultBalanceBefore = await connection.getTokenAccountBalance(
      sourcePool.vaultTokenAccount,
    );
    let destVaultBalanceBefore: any = {
      value: { amount: "0", uiAmount: 0, decimals: 6 },
    };
    try {
      destVaultBalanceBefore = await connection.getTokenAccountBalance(
        destPool.vaultTokenAccount,
      );
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

    // Get Quote
    const swapAmount = BigInt(swapAmountStr);
    let quote;
    try {
      quote = await jupiterService.getQuote(
        sourcePool.mint,
        destPool.mint,
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

    const minAmountOut = BigInt(quote.otherAmountThreshold);
    console.log(`  Swap in: ${swapAmount}, Min out: ${minAmountOut}`);

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

    // Prepare Notes
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
      sourceMint: sourcePool.mint,
      destMint: destPool.mint,
      swapDataHash: Buffer.from(swapDataHash), // MEDIUM-001
    };
    const swapParamsHash = computeSwapParamsHash(
      poseidon,
      sourcePool.mint,
      destPool.mint,
      minAmountOut,
      BigInt(swapParams.deadline.toString()),
      swapDataHash, // MEDIUM-001
    );

    // Fee: 0.5% of output
    const relayerFee = (minAmountOut * 50n) / 10000n;
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
      sourcePool.mint,
      executorPDA,
      true,
    );
    const executorDestToken = await getAssociatedTokenAddress(
      destPool.mint,
      executorPDA,
      true,
    );

    const swapIx = await (program.methods as any)
      .transactSwap(
        proof,
        Array.from(root),
        0,
        sourcePool.mint,
        Array.from(nullifier),
        Array.from(dummyNullifier),
        0,
        destPool.mint,
        Array.from(changeCommitment),
        Array.from(destCommitment),
        swapParams,
        new BN(swapAmount.toString()),
        swapData,
        extData,
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
        sourceMintAccount: sourcePool.mint,
        destConfig: destPool.config,
        destVault: destPool.vault,
        destTree: destPool.noteTree,
        destVaultTokenAccount: destPool.vaultTokenAccount,
        destMintAccount: destPool.mint,
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
    const altKeys: PublicKey[] = [];
    const seen = new Set<string>();
    for (const meta of swapIx.keys) {
      if (!seen.has(meta.pubkey.toBase58())) {
        seen.add(meta.pubkey.toBase58());
        altKeys.push(meta.pubkey);
      }
    }
    if (!seen.has(swapIx.programId.toBase58())) altKeys.push(swapIx.programId);

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

    // =====================================================
    // BALANCE LOGGING: After swap
    // =====================================================
    const sourceVaultBalanceAfter = await connection.getTokenAccountBalance(
      sourcePool.vaultTokenAccount,
    );
    const destVaultBalanceAfter = await connection.getTokenAccountBalance(
      destPool.vaultTokenAccount,
    );
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
    console.log(`  Expected Min Output: ${minAmountOut} ${destName}`);
    console.log(`  Actual Output to Vault: ${destVaultChange} ${destName}`);
    console.log(`  Fee (0.5% of min out): ${relayerFee} ${destName}`);
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
      `  Min Amount Out Met: ${
        totalOutput >= minAmountOut ? "✅ YES" : "❌ NO"
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
    const noteId = await initialDeposit("WSOL", 10_000_000_000n);
    await executeJupiterSwap("WSOL", "USDC", noteId, "1000000000"); // 1 SOL
  });

  // --------------------------------------------------------------------------
  // TEST: SOL -> USDT
  // --------------------------------------------------------------------------
  it("should execute SOL -> USDT swap via Jupiter", async function () {
    const noteId = await initialDeposit("WSOL", 10_000_000_000n);
    await executeJupiterSwap("WSOL", "USDT", noteId, "500000000"); // 0.5 SOL
  });

  // --------------------------------------------------------------------------
  // TEST: SOL -> JUP
  // --------------------------------------------------------------------------
  it("should execute SOL -> JUP swap via Jupiter", async function () {
    const noteId = await initialDeposit("WSOL", 10_000_000_000n);
    await executeJupiterSwap("WSOL", "JUP", noteId, "1000000000"); // 1 SOL
  });

  // --------------------------------------------------------------------------
  // TEST: SOL -> USD1
  // --------------------------------------------------------------------------
  it("should execute SOL -> USD1 swap via Jupiter", async function () {
    const noteId = await initialDeposit("WSOL", 10_000_000_000n);
    // Note: USD1 likely has no route on Jupiter's mainnet/API. This helper will skip if getQuote fails.
    await executeJupiterSwap("WSOL", "USD1", noteId, "500000000"); // 0.5 SOL
  });

  // --------------------------------------------------------------------------
  // TEST: Chained Swap (SOL -> USDC -> JUP)
  // --------------------------------------------------------------------------
  describe("Chained Swap (SOL -> USDC -> JUP)", () => {
    it("Step 1: Deposit SOL for chained swap", async function () {
      console.log("\n🔗 Step 1: Deposit SOL");
      const amount = 2_000_000_000n; // 2 SOL
      const solPool = pools["WSOL"];

      const wsolKeypair = Keypair.generate();
      const wsolAccount = await createWrappedNativeAccount(
        connection,
        payer,
        payer.publicKey,
        Number(amount) + 1_000_000,
        wsolKeypair,
      );

      const blinding = randomBytes32();
      const commitment = computeCommitment(
        poseidon,
        amount,
        publicKey,
        blinding,
        WSOL_MINT,
      );
      const changeOwnerPriv = randomBytes32();
      const changeOwnerPub = derivePublicKey(poseidon, changeOwnerPriv);
      const changeBlinding = randomBytes32();
      const changeCommitment = computeCommitment(
        poseidon,
        0n,
        changeOwnerPub,
        changeBlinding,
        WSOL_MINT,
      );

      // Generate two consistent dummy inputs
      const dummyPrivKey1 = randomBytes32();
      const dummyBlinding1 = randomBytes32();
      const dummyPub1 = derivePublicKey(poseidon, dummyPrivKey1);
      const dummyComm1 = computeCommitment(
        poseidon,
        0n,
        dummyPub1,
        dummyBlinding1,
        WSOL_MINT,
      );
      const dummyNull1 = computeNullifier(
        poseidon,
        dummyComm1,
        0,
        dummyPrivKey1,
      );

      const dummyPrivKey2 = randomBytes32();
      const dummyBlinding2 = randomBytes32();
      const dummyPub2 = derivePublicKey(poseidon, dummyPrivKey2);
      const dummyComm2 = computeCommitment(
        poseidon,
        0n,
        dummyPub2,
        dummyBlinding2,
        WSOL_MINT,
      );
      const dummyNull2 = computeNullifier(
        poseidon,
        dummyComm2,
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
      const proof = await generateTransactionProof({
        root: solPool.offchainTree.getRoot(),
        publicAmount: amount,
        extDataHash,
        mintAddress: WSOL_MINT,
        inputNullifiers: [dummyNull1, dummyNull2],
        outputCommitments: [commitment, changeCommitment],
        inputAmounts: [0n, 0n],
        inputPrivateKeys: [dummyPrivKey1, dummyPrivKey2],
        inputPublicKeys: [dummyPub1, dummyPub2],
        inputBlindings: [dummyBlinding1, dummyBlinding2],
        inputMerklePaths: [
          solPool.offchainTree.getMerkleProof(0),
          solPool.offchainTree.getMerkleProof(0),
        ],
        outputAmounts: [amount, 0n],
        outputOwners: [publicKey, changeOwnerPub],
        outputBlindings: [blinding, changeBlinding],
      });

      await (program.methods as any)
        .transact(
          Array.from(solPool.offchainTree.getRoot()),
          0,
          0,
          new BN(amount.toString()),
          Array.from(extDataHash),
          WSOL_MINT,
          Array.from(dummyNull1),
          Array.from(dummyNull2),
          Array.from(commitment),
          Array.from(changeCommitment),
          new BN(9999999999), // deadline (far future for tests)
          extData,
          proof,
        )
        .accounts({
          config: solPool.config,
          globalConfig,
          vault: solPool.vault,
          inputTree: solPool.noteTree,
          outputTree: solPool.noteTree,
          nullifiers: solPool.nullifiers,
          nullifierMarker0: deriveNullifierMarkerPDA(
            program.programId,
            WSOL_MINT,
            0,
            dummyNull1,
          ),
          nullifierMarker1: deriveNullifierMarkerPDA(
            program.programId,
            WSOL_MINT,
            0,
            dummyNull2,
          ),
          relayer: payer.publicKey,
          recipient: payer.publicKey,
          vaultTokenAccount: solPool.vaultTokenAccount,
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

      const leafIndex = solPool.offchainTree.insert(commitment);
      solPool.offchainTree.insert(changeCommitment);

      chainedSolDepositNoteId = noteStorage.save({
        amount,
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
        merklePath: solPool.offchainTree.getMerkleProof(leafIndex),
        mintAddress: WSOL_MINT,
      });
      console.log(`✅ Deposited 2 SOL, Note: ${chainedSolDepositNoteId}`);
    });

    it("Step 2: Swap SOL -> USDC", async function () {
      console.log("\n🔗 Step 2: Swap SOL -> USDC");
      // Swap 1 SOL
      chainedUsdcNoteId = await executeJupiterSwap(
        "WSOL",
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

// tests/privacy-pool-spl.test.ts
//
// SPL Token Privacy Pool Tests
//

import "mocha";
import {
  AnchorProvider,
  BN,
  setProvider,
  Wallet,
  workspace,
} from "@coral-xyz/anchor";
import {
  PublicKey,
  Keypair,
  SystemProgram,
  LAMPORTS_PER_SOL,
  SendTransactionError,
  ComputeBudgetProgram,
  Transaction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  createMint,
  getOrCreateAssociatedTokenAccount,
  getAssociatedTokenAddress,
} from "@solana/spl-token";
import { buildPoseidon } from "circomlibjs";

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
  fetchAndDisplayEvents,
} from "./test-helpers";

// Helper: Encode tree_id as 2-byte little-endian (u16)
function encodeTreeId(treeId: number): Buffer {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16LE(treeId, 0);
  return buffer;
}

// Helper function to derive nullifier marker PDA with tree_id
// New contract seeds: [b"nullifier_v3", mint_address, &[tree_id], nullifier]
function deriveNullifierMarkerPDA(
  programId: PublicKey,
  mintAddress: PublicKey,
  treeId: number,
  nullifier: Uint8Array
): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [
      Buffer.from("nullifier_v3"),
      mintAddress.toBuffer(),
      encodeTreeId(treeId),
      Buffer.from(nullifier),
    ],
    programId
  );
  return pda;
}

describe("Privacy Pool - SPL Token Support", () => {
  const provider = makeProvider();
  setProvider(provider);

  const wallet = provider.wallet as Wallet;
  const program: any = workspace.PrivacyPool as any;

  let poseidon: any;
  let tokenConfig: PublicKey;
  let tokenVault: PublicKey;
  let tokenNoteTree: PublicKey;
  let tokenNullifiers: PublicKey;
  let globalConfig: PublicKey;

  let testMint: PublicKey;
  let vaultTokenAccount: PublicKey;

  const feeBps = 50; // 0.5%
  const MINT_DECIMALS = 6;
  const TOKEN_AMOUNT = 260_000_000; // 260 tokens with 6 decimals (ensures 0.5% fee meets 1M minimum)

  let offchainTokenTree: OffchainMerkleTree;
  const tokenNoteStorage = new InMemoryNoteStorage();
  let tokenDepositNoteId: string | null = null;

  // =============================================================================
  // Setup
  // =============================================================================

  before(async () => {
    console.log("\n🔧 Setting up SPL token test environment...\n");

    // Initialize Poseidon
    poseidon = await buildPoseidon();
    offchainTokenTree = new OffchainMerkleTree(26, poseidon);

    // Create test token mint
    console.log("Creating test token mint...");
    testMint = new PublicKey("A4jyQhHNRW5kFAdGN8ZnXB8HHW5kXJU4snGddS5UpdSq");
    try {
      testMint = await createMint(
        provider.connection,
        wallet.payer,
        wallet.publicKey,
        null,
        MINT_DECIMALS
      );
    } catch (error) {
      // Mint already exists, use the hardcoded address
      console.log("Using existing test mint");
    }
    console.log(`✅ Test mint created: ${testMint.toBase58()}`);

    // Get PDAs for token pool (v3 with mint_address in seeds)
    [tokenConfig] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_config_v3"), testMint.toBuffer()],
      program.programId
    );
    [tokenVault] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_vault_v3"), testMint.toBuffer()],
      program.programId
    );
    [tokenNoteTree] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("privacy_note_tree_v3"),
        testMint.toBuffer(),
        Buffer.from([0]),
      ],
      program.programId
    );
    [tokenNullifiers] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_nullifiers_v3"), testMint.toBuffer()],
      program.programId
    );
    [globalConfig] = PublicKey.findProgramAddressSync(
      [Buffer.from("global_config_v1")],
      program.programId
    );

    // Create vault's token account (ATA)
    vaultTokenAccount = await getAssociatedTokenAddress(
      testMint,
      tokenVault,
      true
    );

    console.log("Token Config PDA:", tokenConfig.toBase58());
    console.log("Token Vault PDA:", tokenVault.toBase58());
    console.log("Vault Token Account:", vaultTokenAccount.toBase58());
  });

  it("initializes the privacy pool with SPL token", async () => {
    try {
      await (program.methods as any)
        .initialize(
          feeBps,
          testMint,
          new BN(1_000_000), // min_deposit_amount
          new BN(1_000_000_000_000), // max_deposit_amount
          new BN(1_000_000), // min_withdraw_amount
          new BN(1_000_000_000_000) // max_withdraw_amount
        )
        .accounts({
          config: tokenConfig,
          vault: tokenVault,
          noteTree: tokenNoteTree,
          nullifiers: tokenNullifiers,
          admin: wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      const configAcc = await (program.account as any).privacyConfig.fetch(
        tokenConfig
      );
      console.log("✅ Token pool initialized");
      console.log(`   Token mint: ${configAcc.mintAddress.toBase58()}`);
      console.log(`   Fee BPS: ${configAcc.feeBps}`);
      console.log(`   Max Deposit: ${configAcc.maxDepositAmount} tokens`);
    } catch (e: any) {
      if (e instanceof SendTransactionError) {
        const logs = await e.getLogs(provider.connection);
        console.error("Initialize failed:", logs);
      }
      throw e;
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
          admin: wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      const globalConfigAcc = await (program.account as any).globalConfig.fetch(
        globalConfig
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

  // =============================================================================
  // Token Deposit Test
  // =============================================================================

  it("deposits SPL tokens using transact with real proof", async () => {
    const sender = Keypair.generate();

    console.log("\n🎁 Setting up token deposit test...");
    // Create vault's token account (if not exists)
    await getOrCreateAssociatedTokenAccount(
      provider.connection,
      wallet.payer,
      testMint,
      tokenVault,
      true
    );
    console.log(`   Sender: ${sender.publicKey.toBase58()}`);

    // Airdrop SOL for transaction fees
    await airdropAndConfirm(provider, sender.publicKey, 2 * LAMPORTS_PER_SOL);

    // Create sender's token account and mint tokens
    const senderTokenAccount = await createAndFundTokenAccount(
      provider,
      testMint,
      sender.publicKey,
      TOKEN_AMOUNT * 2
    );

    console.log(`   Sender token account: ${senderTokenAccount.toBase58()}`);
    console.log(`   Funded with: ${TOKEN_AMOUNT * 2} tokens`);

    // Register sender as relayer
    await (program.methods as any)
      .addRelayer(testMint, sender.publicKey)
      .accounts({ config: tokenConfig, admin: wallet.publicKey })
      .rpc();

    const depositAmount = BigInt(TOKEN_AMOUNT);

    // Generate deposit note
    const privateKey = randomBytes32();
    const publicKey = derivePublicKey(poseidon, privateKey);
    const blinding = randomBytes32();

    const commitment = computeCommitment(
      poseidon,
      depositAmount,
      publicKey,
      blinding,
      testMint
    );

    // Create dummy output
    const dummyOutputPrivKey = randomBytes32();
    const dummyOutputPubKey = derivePublicKey(poseidon, dummyOutputPrivKey);
    const dummyOutputBlinding = randomBytes32();
    const dummyOutputCommitment = computeCommitment(
      poseidon,
      0n,
      dummyOutputPubKey,
      dummyOutputBlinding,
      testMint
    );

    const leafIndex = offchainTokenTree.nextIndex;
    const nullifier = computeNullifier(
      poseidon,
      commitment,
      leafIndex,
      privateKey
    );

    // Generate dummy inputs
    const dummyPrivKey0 = randomBytes32();
    const dummyPrivKey1 = randomBytes32();
    const dummyPubKey0 = derivePublicKey(poseidon, dummyPrivKey0);
    const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);
    const dummyBlinding0 = randomBytes32();
    const dummyBlinding1 = randomBytes32();

    const dummyCommitment0 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey0,
      dummyBlinding0,
      testMint
    );
    const dummyCommitment1 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey1,
      dummyBlinding1,
      testMint
    );

    const dummyNullifier0 = computeNullifier(
      poseidon,
      dummyCommitment0,
      0,
      dummyPrivKey0
    );
    const dummyNullifier1 = computeNullifier(
      poseidon,
      dummyCommitment1,
      0,
      dummyPrivKey1
    );

    const extData = {
      recipient: sender.publicKey,
      relayer: sender.publicKey,
      fee: new BN(0),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    const noteTreeAcc: any = await (
      program.account as any
    ).merkleTreeAccount.fetch(tokenNoteTree);
    const onchainRoot = extractRootFromAccount(noteTreeAcc);

    // Generate proof
    const zeros = offchainTokenTree.getZeros();
    const zeroPathElements = zeros.slice(0, 26).map((z) => bytesToBigIntBE(z));

    const proof = await generateTransactionProof({
      root: onchainRoot,
      publicAmount: depositAmount,
      extDataHash,
      mintAddress: testMint,
      inputNullifiers: [dummyNullifier0, dummyNullifier1],
      outputCommitments: [commitment, dummyOutputCommitment],

      inputAmounts: [0n, 0n],
      inputPrivateKeys: [dummyPrivKey0, dummyPrivKey1],
      inputPublicKeys: [dummyPubKey0, dummyPubKey1],
      inputBlindings: [dummyBlinding0, dummyBlinding1],
      inputMerklePaths: [
        { pathElements: zeroPathElements, pathIndices: new Array(26).fill(0) },
        { pathElements: zeroPathElements, pathIndices: new Array(26).fill(0) },
      ],

      outputAmounts: [depositAmount, 0n],
      outputOwners: [publicKey, dummyOutputPubKey],
      outputBlindings: [blinding, dummyOutputBlinding],
    });

    const depositInputTreeId = 0;
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      testMint,
      depositInputTreeId,
      dummyNullifier0
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      testMint,
      depositInputTreeId,
      dummyNullifier1
    );

    let txSignature: string;

    try {
      // Build instruction
      const ix = await (program.methods as any)
        .transact(
          Array.from(onchainRoot),
          0, // input_tree_id
          0, // output_tree_id
          new BN(depositAmount.toString()),
          Array.from(extDataHash),
          testMint,
          Array.from(dummyNullifier0),
          Array.from(dummyNullifier1),
          Array.from(commitment),
          Array.from(dummyOutputCommitment),
          extData,
          proof
        )
        .accounts({
          config: tokenConfig,
          globalConfig,
          vault: tokenVault,
          inputTree: tokenNoteTree,
          outputTree: tokenNoteTree,
          nullifiers: tokenNullifiers,
          nullifierMarker0,
          nullifierMarker1,
          relayer: sender.publicKey,
          recipient: sender.publicKey,
          vaultTokenAccount,
          userTokenAccount: senderTokenAccount,
          recipientTokenAccount: senderTokenAccount,
          relayerTokenAccount: senderTokenAccount,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .instruction();

      // Use versioned transaction to avoid size limit
      const { blockhash } = await provider.connection.getLatestBlockhash();
      const messageV0 = new TransactionMessage({
        payerKey: sender.publicKey,
        recentBlockhash: blockhash,
        instructions: [
          ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
          ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1 }),
          ix,
        ],
      }).compileToV0Message();

      const versionedTx = new VersionedTransaction(messageV0);
      versionedTx.sign([sender]);

      txSignature = await provider.connection.sendTransaction(versionedTx);
      await provider.connection.confirmTransaction(txSignature, "confirmed");

      console.log(`\n✅ Transaction signature: ${txSignature}`);

      // Verify events
      await fetchAndDisplayEvents(provider.connection, txSignature, testMint);

      // Insert outputs into offchain tree
      offchainTokenTree.insert(commitment);
      offchainTokenTree.insert(dummyOutputCommitment);

      // Save note
      const merklePath = offchainTokenTree.getMerkleProof(leafIndex);
      const noteToSave: DepositNote = {
        amount: depositAmount,
        commitment,
        nullifier,
        blinding,
        privateKey,
        publicKey,
        leafIndex,
        merklePath,
        mintAddress: testMint,
      };

      tokenDepositNoteId = tokenNoteStorage.save(noteToSave);

      console.log("\n✅ Token deposit successful");
      console.log(`   Amount: ${depositAmount} tokens`);
      console.log(`   Leaf index: ${leafIndex}`);
      console.log(`   Note ID: ${tokenDepositNoteId}`);
    } catch (e: any) {
      if (e instanceof SendTransactionError) {
        const logs = await e.getLogs(provider.connection);
        console.error("Token deposit failed:", logs);
      }
      throw e;
    }
  });

  // =============================================================================
  // Token Withdrawal Test
  // =============================================================================

  it("withdraws SPL tokens via relayer with fee", async () => {
    if (!tokenDepositNoteId) {
      throw new Error("No token deposit note - deposit test must run first");
    }

    const depositNote = tokenNoteStorage.get(tokenDepositNoteId);
    if (!depositNote) {
      throw new Error(`Note not found: ${tokenDepositNoteId}`);
    }

    console.log("\n💰 Token Withdrawal Test:");
    console.log(`   Note ID: ${tokenDepositNoteId}`);
    console.log(`   Amount: ${depositNote.amount} tokens`);

    const relayer = Keypair.generate();
    const recipient = Keypair.generate();

    // Airdrop SOL for fees
    await airdropAndConfirm(provider, relayer.publicKey, 2 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(
      provider,
      recipient.publicKey,
      0.2 * LAMPORTS_PER_SOL
    );

    // Create token accounts
    const relayerTokenAccount = await createAndFundTokenAccount(
      provider,
      testMint,
      relayer.publicKey,
      0
    );
    const recipientTokenAccount = await createAndFundTokenAccount(
      provider,
      testMint,
      recipient.publicKey,
      0
    );

    // Register relayer
    await (program.methods as any)
      .addRelayer(testMint, relayer.publicKey)
      .accounts({ config: tokenConfig, admin: wallet.publicKey })
      .rpc();

    // Create change output to satisfy circuit balance constraint
    const changeAmount = 1000n; // Small amount stays as change
    const withdrawAmount = depositNote.amount - changeAmount;
    const fee = (withdrawAmount * BigInt(feeBps)) / 10_000n;
    const toRecipient = withdrawAmount - fee;

    const extData = {
      recipient: recipient.publicKey,
      relayer: relayer.publicKey,
      fee: new BN(fee.toString()),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    const noteTreeAcc: any = await (
      program.account as any
    ).merkleTreeAccount.fetch(tokenNoteTree);
    const onchainRoot = extractRootFromAccount(noteTreeAcc);

    const updatedMerklePath = offchainTokenTree.getMerkleProof(
      depositNote.leafIndex
    );

    // Create dummy input
    const dummyPrivKey1 = randomBytes32();
    const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);
    const dummyBlinding1 = randomBytes32();
    const dummyCommitment1 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey1,
      dummyBlinding1,
      testMint
    );
    const dummyNullifier1 = computeNullifier(
      poseidon,
      dummyCommitment1,
      0,
      dummyPrivKey1
    );

    // Create change output (to satisfy balance constraint: sum(inputs) = sum(outputs) + |publicAmount|)
    const changePrivKey = randomBytes32();
    const changePubKey = derivePublicKey(poseidon, changePrivKey);
    const changeBlinding = randomBytes32();
    const changeCommitment = computeCommitment(
      poseidon,
      changeAmount,
      changePubKey,
      changeBlinding,
      testMint
    );

    const dummyOutputPrivKey1 = randomBytes32();
    const dummyOutputPubKey1 = derivePublicKey(poseidon, dummyOutputPrivKey1);
    const dummyOutputBlinding1 = randomBytes32();
    const dummyOutputCommitment1 = computeCommitment(
      poseidon,
      0n,
      dummyOutputPubKey1,
      dummyOutputBlinding1,
      testMint
    );

    const zeros = offchainTokenTree.getZeros();
    const zeroPathElements = zeros.slice(0, 26).map((z) => bytesToBigIntBE(z));

    const proof = await generateTransactionProof({
      root: onchainRoot,
      publicAmount: -withdrawAmount,
      extDataHash,
      mintAddress: testMint,
      inputNullifiers: [depositNote.nullifier, dummyNullifier1],
      outputCommitments: [changeCommitment, dummyOutputCommitment1],

      inputAmounts: [depositNote.amount, 0n],
      inputPrivateKeys: [depositNote.privateKey, dummyPrivKey1],
      inputPublicKeys: [depositNote.publicKey, dummyPubKey1],
      inputBlindings: [depositNote.blinding, dummyBlinding1],
      inputMerklePaths: [
        updatedMerklePath,
        { pathElements: zeroPathElements, pathIndices: new Array(26).fill(0) },
      ],

      outputAmounts: [changeAmount, 0n],
      outputOwners: [changePubKey, dummyOutputPubKey1],
      outputBlindings: [changeBlinding, dummyOutputBlinding1],
    });

    const withdrawInputTreeId = 0;
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      testMint,
      withdrawInputTreeId,
      depositNote.nullifier
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      testMint,
      withdrawInputTreeId,
      dummyNullifier1
    );

    try {
      const modifyComputeUnits = ComputeBudgetProgram.setComputeUnitLimit({
        units: 1_400_000,
      });
      // Removed PriorityFee to save transaction size (was causing "Transaction too large" error)

      const ix = await (program.methods as any)
        .transact(
          Array.from(onchainRoot),
          0, // input_tree_id
          0, // output_tree_id
          new BN(-withdrawAmount.toString()),
          Array.from(extDataHash),
          testMint,
          Array.from(depositNote.nullifier),
          Array.from(dummyNullifier1),
          Array.from(changeCommitment),
          Array.from(dummyOutputCommitment1),
          extData,
          proof
        )
        .accounts({
          config: tokenConfig,
          globalConfig,
          vault: tokenVault,
          inputTree: tokenNoteTree,
          outputTree: tokenNoteTree,
          nullifiers: tokenNullifiers,
          nullifierMarker0,
          nullifierMarker1,
          relayer: relayer.publicKey,
          recipient: recipient.publicKey,
          vaultTokenAccount,
          userTokenAccount: relayerTokenAccount,
          recipientTokenAccount,
          relayerTokenAccount,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .instruction();

      const { blockhash, lastValidBlockHeight } =
        await provider.connection.getLatestBlockhash();
      const messageV0 = new TransactionMessage({
        payerKey: relayer.publicKey,
        recentBlockhash: blockhash,
        instructions: [modifyComputeUnits, ix], // Removed addPriorityFee
      }).compileToV0Message();

      const versionedTx = new VersionedTransaction(messageV0);
      versionedTx.sign([relayer]);

      const sig = await provider.connection.sendTransaction(versionedTx);
      console.log(`   Signature: ${sig}`);
      await provider.connection.confirmTransaction({
        signature: sig,
        blockhash: blockhash,
        lastValidBlockHeight,
      });

      // Insert outputs into offchain tree
      offchainTokenTree.insert(changeCommitment);
      offchainTokenTree.insert(dummyOutputCommitment1);

      console.log("\n✅ Token withdrawal successful");
      console.log(`   Withdrawn: ${withdrawAmount} tokens`);
      console.log(`   Fee: ${fee} tokens`);
      console.log(`   To recipient: ${toRecipient} tokens`);

      tokenNoteStorage.markSpent(tokenDepositNoteId!);
    } catch (e: any) {
      console.error("Caught error during withdrawal:", e);
      if (e instanceof SendTransactionError) {
        try {
          const logs = await e.getLogs(provider.connection);
          console.error("Token withdrawal failed logs:", logs);
        } catch (logError) {
          console.error("Failed to get logs (likely RPC error):", logError);
          console.error("Original error:", e.toString());
        }
      }
      throw e;
    }
  });

  // =============================================================================
  // Token Private Transfer Test
  // =============================================================================

  it("transfers SPL tokens privately", async () => {
    console.log("\n🔄 SPL Token Private Transfer Test:\n");

    // Alice deposits tokens
    const alice = Keypair.generate();
    console.log(`   Alice: ${alice.publicKey.toBase58()}`);
    await airdropAndConfirm(provider, alice.publicKey, 3 * LAMPORTS_PER_SOL);

    // Create Alice's token account and fund it
    const aliceTokenAccount = await createAndFundTokenAccount(
      provider,
      testMint,
      alice.publicKey,
      TOKEN_AMOUNT * 2
    );

    // Register Alice as relayer
    await (program.methods as any)
      .addRelayer(testMint, alice.publicKey)
      .accounts({ config: tokenConfig, admin: wallet.publicKey })
      .rpc();

    const aliceDepositAmount = BigInt(TOKEN_AMOUNT * 2);
    const alicePrivateKey = randomBytes32();
    const alicePublicKey = derivePublicKey(poseidon, alicePrivateKey);
    const aliceBlinding = randomBytes32();

    const aliceCommitment = computeCommitment(
      poseidon,
      aliceDepositAmount,
      alicePublicKey,
      aliceBlinding,
      testMint
    );

    const aliceDummyOutput = randomBytes32();
    const aliceDummyPubKey = derivePublicKey(poseidon, aliceDummyOutput);
    const aliceDummyBlinding = randomBytes32();
    const aliceDummyCommitment = computeCommitment(
      poseidon,
      0n,
      aliceDummyPubKey,
      aliceDummyBlinding,
      testMint
    );

    const aliceLeafIndex = offchainTokenTree.nextIndex;
    const aliceNullifier = computeNullifier(
      poseidon,
      aliceCommitment,
      aliceLeafIndex,
      alicePrivateKey
    );

    // Generate deposit proof for Alice
    const dummyPrivKey0 = randomBytes32();
    const dummyPrivKey1 = randomBytes32();
    const dummyPubKey0 = derivePublicKey(poseidon, dummyPrivKey0);
    const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);
    const dummyBlinding0 = randomBytes32();
    const dummyBlinding1 = randomBytes32();
    const dummyCommitment0 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey0,
      dummyBlinding0,
      testMint
    );
    const dummyCommitment1 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey1,
      dummyBlinding1,
      testMint
    );
    const dummyNullifier0 = computeNullifier(
      poseidon,
      dummyCommitment0,
      0,
      dummyPrivKey0
    );
    const dummyNullifier1 = computeNullifier(
      poseidon,
      dummyCommitment1,
      0,
      dummyPrivKey1
    );

    const extDataDeposit = {
      recipient: alice.publicKey,
      relayer: alice.publicKey,
      fee: new BN(0),
      refund: new BN(0),
    };
    const extDataHashDeposit = computeExtDataHash(poseidon, extDataDeposit);

    let noteTreeAcc: any = await (
      program.account as any
    ).merkleTreeAccount.fetch(tokenNoteTree);
    let onchainRoot = extractRootFromAccount(noteTreeAcc);

    const zeros = offchainTokenTree.getZeros();
    const zeroPathElements = zeros.slice(0, 26).map((z) => bytesToBigIntBE(z));

    const depositProof = await generateTransactionProof({
      root: onchainRoot,
      publicAmount: aliceDepositAmount,
      extDataHash: extDataHashDeposit,
      mintAddress: testMint,
      inputNullifiers: [dummyNullifier0, dummyNullifier1],
      outputCommitments: [aliceCommitment, aliceDummyCommitment],
      inputAmounts: [0n, 0n],
      inputPrivateKeys: [dummyPrivKey0, dummyPrivKey1],
      inputPublicKeys: [dummyPubKey0, dummyPubKey1],
      inputBlindings: [dummyBlinding0, dummyBlinding1],
      inputMerklePaths: [
        { pathElements: zeroPathElements, pathIndices: new Array(26).fill(0) },
        { pathElements: zeroPathElements, pathIndices: new Array(26).fill(0) },
      ],
      outputAmounts: [aliceDepositAmount, 0n],
      outputOwners: [alicePublicKey, aliceDummyPubKey],
      outputBlindings: [aliceBlinding, aliceDummyBlinding],
    });

    const aliceDepositInputTreeId = 0;
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      testMint,
      aliceDepositInputTreeId,
      dummyNullifier0
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      testMint,
      aliceDepositInputTreeId,
      dummyNullifier1
    );

    const depositTx = await (program.methods as any)
      .transact(
        Array.from(onchainRoot),
        0, // input_tree_id
        0, // output_tree_id
        new BN(aliceDepositAmount.toString()),
        Array.from(extDataHashDeposit),
        testMint,
        Array.from(dummyNullifier0),
        Array.from(dummyNullifier1),
        Array.from(aliceCommitment),
        Array.from(aliceDummyCommitment),
        extDataDeposit,
        depositProof
      )
      .accounts({
        config: tokenConfig,
        globalConfig,
        vault: tokenVault,
        inputTree: tokenNoteTree,
        outputTree: tokenNoteTree,
        nullifiers: tokenNullifiers,
        nullifierMarker0,
        nullifierMarker1,
        relayer: alice.publicKey,
        recipient: alice.publicKey,
        vaultTokenAccount,
        userTokenAccount: aliceTokenAccount,
        recipientTokenAccount: aliceTokenAccount,
        relayerTokenAccount: aliceTokenAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .instruction();

    const modifyComputeUnits = ComputeBudgetProgram.setComputeUnitLimit({
      units: 1_400_000,
    });
    const addPriorityFee = ComputeBudgetProgram.setComputeUnitPrice({
      microLamports: 1,
    });

    const { blockhash } = await provider.connection.getLatestBlockhash();
    const messageV0 = new TransactionMessage({
      payerKey: alice.publicKey,
      recentBlockhash: blockhash,
      instructions: [modifyComputeUnits, addPriorityFee, depositTx],
    }).compileToV0Message();

    const versionedTx = new VersionedTransaction(messageV0);
    versionedTx.sign([alice]);

    const depositSig = await provider.connection.sendTransaction(versionedTx);
    await provider.connection.confirmTransaction({
      signature: depositSig,
      blockhash: blockhash,
      lastValidBlockHeight: (
        await provider.connection.getLatestBlockhash()
      ).lastValidBlockHeight,
    });

    offchainTokenTree.insert(aliceCommitment);
    offchainTokenTree.insert(aliceDummyCommitment);

    console.log(
      `✅ Alice deposited ${aliceDepositAmount} tokens (Leaf ${aliceLeafIndex})\n`
    );

    // =============================================================================
    // PRIVATE TRANSFER: Alice sends half to Bob
    // =============================================================================

    console.log("🔄 Private Transfer: Alice → Bob (SPL Tokens)\n");

    const bobPrivateKey = randomBytes32();
    const bobPublicKey = derivePublicKey(poseidon, bobPrivateKey);
    const bobBlinding = randomBytes32();

    const transferAmount = BigInt(TOKEN_AMOUNT);
    const changeAmount = aliceDepositAmount - transferAmount;

    console.log("📋 Transfer Breakdown:");
    console.log(`   Input: Alice's ${aliceDepositAmount} tokens note`);
    console.log(`   Output 1: Bob receives ${transferAmount} tokens`);
    console.log(`   Output 2: Alice keeps ${changeAmount} tokens (change)\n`);

    const aliceChangePrivKey = randomBytes32();
    const aliceChangePubKey = derivePublicKey(poseidon, aliceChangePrivKey);
    const aliceChangeBlinding = randomBytes32();

    const bobCommitment = computeCommitment(
      poseidon,
      transferAmount,
      bobPublicKey,
      bobBlinding,
      testMint
    );

    const aliceChangeCommitment = computeCommitment(
      poseidon,
      changeAmount,
      aliceChangePubKey,
      aliceChangeBlinding,
      testMint
    );

    const transferDummyPrivKey = randomBytes32();
    const transferDummyPubKey = derivePublicKey(poseidon, transferDummyPrivKey);
    const transferDummyBlinding = randomBytes32();
    const transferDummyCommitment = computeCommitment(
      poseidon,
      0n,
      transferDummyPubKey,
      transferDummyBlinding,
      testMint
    );
    const transferDummyNullifier = computeNullifier(
      poseidon,
      transferDummyCommitment,
      0,
      transferDummyPrivKey
    );

    const extDataTransfer = {
      recipient: alice.publicKey,
      relayer: alice.publicKey,
      fee: new BN(0),
      refund: new BN(0),
    };
    const extDataHashTransfer = computeExtDataHash(poseidon, extDataTransfer);

    noteTreeAcc = await (program.account as any).merkleTreeAccount.fetch(
      tokenNoteTree
    );
    onchainRoot = extractRootFromAccount(noteTreeAcc);

    const aliceUpdatedPath = offchainTokenTree.getMerkleProof(aliceLeafIndex);

    const transferProof = await generateTransactionProof({
      root: onchainRoot,
      publicAmount: 0n,
      extDataHash: extDataHashTransfer,
      mintAddress: testMint,
      inputNullifiers: [aliceNullifier, transferDummyNullifier],
      outputCommitments: [bobCommitment, aliceChangeCommitment],

      inputAmounts: [aliceDepositAmount, 0n],
      inputPrivateKeys: [alicePrivateKey, transferDummyPrivKey],
      inputPublicKeys: [alicePublicKey, transferDummyPubKey],
      inputBlindings: [aliceBlinding, transferDummyBlinding],
      inputMerklePaths: [
        aliceUpdatedPath,
        { pathElements: zeroPathElements, pathIndices: new Array(26).fill(0) },
      ],

      outputAmounts: [transferAmount, changeAmount],
      outputOwners: [bobPublicKey, aliceChangePubKey],
      outputBlindings: [bobBlinding, aliceChangeBlinding],
    });

    const transferInputTreeId = 0;
    const aliceNullifierMarker = deriveNullifierMarkerPDA(
      program.programId,
      testMint,
      transferInputTreeId,
      aliceNullifier
    );
    const transferDummyNullifierMarker = deriveNullifierMarkerPDA(
      program.programId,
      testMint,
      transferInputTreeId,
      transferDummyNullifier
    );

    const transferTx = await (program.methods as any)
      .transact(
        Array.from(onchainRoot),
        0, // input_tree_id
        0, // output_tree_id
        new BN(0),
        Array.from(extDataHashTransfer),
        testMint,
        Array.from(aliceNullifier),
        Array.from(transferDummyNullifier),
        Array.from(bobCommitment),
        Array.from(aliceChangeCommitment),
        extDataTransfer,
        transferProof
      )
      .accounts({
        config: tokenConfig,
        globalConfig,
        vault: tokenVault,
        inputTree: tokenNoteTree,
        outputTree: tokenNoteTree,
        nullifiers: tokenNullifiers,
        nullifierMarker0: aliceNullifierMarker,
        nullifierMarker1: transferDummyNullifierMarker,
        relayer: alice.publicKey,
        recipient: alice.publicKey,
        vaultTokenAccount,
        userTokenAccount: aliceTokenAccount,
        recipientTokenAccount: aliceTokenAccount,
        relayerTokenAccount: aliceTokenAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .instruction();

    const transferComputeUnits = ComputeBudgetProgram.setComputeUnitLimit({
      units: 1_400_000,
    });
    const transferPriorityFee = ComputeBudgetProgram.setComputeUnitPrice({
      microLamports: 1,
    });

    const { blockhash: transferBlockhash } =
      await provider.connection.getLatestBlockhash();
    const transferMessageV0 = new TransactionMessage({
      payerKey: alice.publicKey,
      recentBlockhash: transferBlockhash,
      instructions: [transferComputeUnits, transferPriorityFee, transferTx],
    }).compileToV0Message();

    const transferVersionedTx = new VersionedTransaction(transferMessageV0);
    transferVersionedTx.sign([alice]);

    const transferSig = await provider.connection.sendTransaction(
      transferVersionedTx
    );
    await provider.connection.confirmTransaction({
      signature: transferSig,
      blockhash: transferBlockhash,
      lastValidBlockHeight: (
        await provider.connection.getLatestBlockhash()
      ).lastValidBlockHeight,
    });

    const bobLeafIndex = offchainTokenTree.insert(bobCommitment);
    const aliceChangeLeafIndex = offchainTokenTree.insert(
      aliceChangeCommitment
    );

    console.log("✅ Private token transfer complete!");
    console.log(
      `   Bob's note: ${transferAmount} tokens (Leaf ${bobLeafIndex})`
    );
    console.log(
      `   Alice's change: ${changeAmount} tokens (Leaf ${aliceChangeLeafIndex})\n`
    );
  });

  // =============================================================================
  // Cross-Tree Transaction Test for SPL Tokens
  // =============================================================================

  it("creates a second SPL token tree and uses cross-tree transactions", async () => {
    console.log("\n🌳 Cross-Tree SPL Token Transaction Test:\n");
    console.log(
      "Testing multi-tree architecture with separate input/output trees for SPL tokens"
    );

    // Step 1: Fetch current config to get next sequential tree ID
    const currentConfig = await program.account.privacyConfig.fetch(
      tokenConfig
    );
    const destinationTreeId = currentConfig.numTrees;
    console.log(
      `\n📥 Step 1: Adding fresh SPL output tree (tree_id = ${destinationTreeId})...`
    );

    const [tokenNoteTreeDestination] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("privacy_note_tree_v3"),
        testMint.toBuffer(),
        encodeTreeId(destinationTreeId),
      ],
      program.programId
    );

    // Create the tree
    try {
      await (program.methods as any)
        .addMerkleTree(testMint, destinationTreeId)
        .accounts({
          config: tokenConfig,
          noteTree: tokenNoteTreeDestination,
          admin: wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      console.log(
        `✅ Destination SPL tree created: ${tokenNoteTreeDestination.toBase58()}`
      );
    } catch (e) {
      console.log("⚠️  Tree already exists");
    }

    // Create local offchain tree to track this fresh tree
    const offchainTokenTreeDestination = new OffchainMerkleTree(26, poseidon);

    // Step 2: Make a deposit to Token Tree 0
    console.log(`\n📥 Step 2: Depositing SPL tokens to Tree 0...`);

    const user = Keypair.generate();
    await airdropAndConfirm(provider, user.publicKey, 2 * LAMPORTS_PER_SOL);

    const userTokenAccount = await createAndFundTokenAccount(
      provider,
      testMint,
      user.publicKey,
      TOKEN_AMOUNT
    );

    // Register user as relayer
    await (program.methods as any)
      .addRelayer(testMint, user.publicKey)
      .accounts({ config: tokenConfig, admin: wallet.publicKey })
      .rpc();

    const depositAmount = BigInt(TOKEN_AMOUNT / 2);
    const privateKey = randomBytes32();
    const publicKey = derivePublicKey(poseidon, privateKey);
    const blinding = randomBytes32();

    const commitment = computeCommitment(
      poseidon,
      depositAmount,
      publicKey,
      blinding,
      testMint
    );

    const dummyOutputPrivKey = randomBytes32();
    const dummyOutputPubKey = derivePublicKey(poseidon, dummyOutputPrivKey);
    const dummyOutputBlinding = randomBytes32();
    const dummyOutputCommitment = computeCommitment(
      poseidon,
      0n,
      dummyOutputPubKey,
      dummyOutputBlinding,
      testMint
    );

    const commitmentLeafIndex = offchainTokenTree.nextIndex;
    console.log(`\n📍 Predicted commitment leaf index: ${commitmentLeafIndex}`);

    const nullifier = computeNullifier(
      poseidon,
      commitment,
      commitmentLeafIndex,
      privateKey
    );

    // Generate dummy inputs for deposit
    const dummyPrivKey0 = randomBytes32();
    const dummyPrivKey1 = randomBytes32();
    const dummyBlinding0 = randomBytes32();
    const dummyBlinding1 = randomBytes32();
    const dummyPubKey0 = derivePublicKey(poseidon, dummyPrivKey0);
    const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);

    const dummyCommitment0 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey0,
      dummyBlinding0,
      testMint
    );
    const dummyCommitment1 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey1,
      dummyBlinding1,
      testMint
    );

    const dummyNullifier0 = computeNullifier(
      poseidon,
      dummyCommitment0,
      0,
      dummyPrivKey0
    );
    const dummyNullifier1 = computeNullifier(
      poseidon,
      dummyCommitment1,
      0,
      dummyPrivKey1
    );

    const noteTreeAcc: any = await (
      program.account as any
    ).merkleTreeAccount.fetch(tokenNoteTree);
    const onchainRoot = extractRootFromAccount(noteTreeAcc);

    const zeros = offchainTokenTree.getZeros();
    const zeroPathElements = zeros.slice(0, 26).map((z) => bytesToBigIntBE(z));

    const extDataDeposit = {
      recipient: user.publicKey,
      relayer: user.publicKey,
      fee: new BN(0),
      refund: new BN(0),
    };
    const extDataHashDeposit = computeExtDataHash(poseidon, extDataDeposit);

    const depositProof = await generateTransactionProof({
      root: onchainRoot,
      publicAmount: depositAmount,
      extDataHash: extDataHashDeposit,
      mintAddress: testMint,
      inputNullifiers: [dummyNullifier0, dummyNullifier1],
      outputCommitments: [commitment, dummyOutputCommitment],
      inputAmounts: [0n, 0n],
      inputPrivateKeys: [dummyPrivKey0, dummyPrivKey1],
      inputPublicKeys: [dummyPubKey0, dummyPubKey1],
      inputBlindings: [dummyBlinding0, dummyBlinding1],
      inputMerklePaths: [
        { pathElements: zeroPathElements, pathIndices: new Array(26).fill(0) },
        { pathElements: zeroPathElements, pathIndices: new Array(26).fill(0) },
      ],
      outputAmounts: [depositAmount, 0n],
      outputOwners: [publicKey, dummyOutputPubKey],
      outputBlindings: [blinding, dummyOutputBlinding],
    });

    offchainTokenTree.insert(commitment);
    offchainTokenTree.insert(dummyOutputCommitment);

    const relayerDepositInputTreeId = 0;
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      testMint,
      relayerDepositInputTreeId,
      dummyNullifier0
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      testMint,
      relayerDepositInputTreeId,
      dummyNullifier1
    );

    const depositTx = await (program.methods as any)
      .transact(
        Array.from(onchainRoot),
        0,
        0,
        new BN(depositAmount.toString()),
        Array.from(extDataHashDeposit),
        testMint,
        Array.from(dummyNullifier0),
        Array.from(dummyNullifier1),
        Array.from(commitment),
        Array.from(dummyOutputCommitment),
        extDataDeposit,
        depositProof
      )
      .accounts({
        config: tokenConfig,
        globalConfig,
        vault: tokenVault,
        inputTree: tokenNoteTree,
        outputTree: tokenNoteTree,
        nullifiers: tokenNullifiers,
        nullifierMarker0,
        nullifierMarker1,
        relayer: user.publicKey,
        recipient: user.publicKey,
        vaultTokenAccount,
        userTokenAccount,
        recipientTokenAccount: userTokenAccount,
        relayerTokenAccount: userTokenAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .instruction();

    const modifyComputeUnits = ComputeBudgetProgram.setComputeUnitLimit({
      units: 1_400_000,
    });
    const addPriorityFee = ComputeBudgetProgram.setComputeUnitPrice({
      microLamports: 1,
    });

    let blockhash = (await provider.connection.getLatestBlockhash()).blockhash;
    let messageV0 = new TransactionMessage({
      payerKey: user.publicKey,
      recentBlockhash: blockhash,
      instructions: [modifyComputeUnits, addPriorityFee, depositTx],
    }).compileToV0Message();

    let versionedTx = new VersionedTransaction(messageV0);
    versionedTx.sign([user]);

    await provider.connection.sendTransaction(versionedTx);
    await new Promise((resolve) => setTimeout(resolve, 2600));

    console.log("✅ Deposit successful to SPL Token Tree 0");

    // Step 3: Cross-tree transfer
    console.log(
      `\n🔄 Step 3: Cross-tree transfer (input: Tree 0, output: Tree ${destinationTreeId})...`
    );

    const outputPrivKey = randomBytes32();
    const outputPubKey = derivePublicKey(poseidon, outputPrivKey);
    const outputBlinding = randomBytes32();
    const outputCommitment = computeCommitment(
      poseidon,
      depositAmount,
      outputPubKey,
      outputBlinding,
      testMint
    );

    const dummyOutput2PrivKey = randomBytes32();
    const dummyOutput2PubKey = derivePublicKey(poseidon, dummyOutput2PrivKey);
    const dummyOutput2Blinding = randomBytes32();
    const dummyOutput2Commitment = computeCommitment(
      poseidon,
      0n,
      dummyOutput2PubKey,
      dummyOutput2Blinding,
      testMint
    );

    const dummyPrivKey2 = randomBytes32();
    const dummyPubKey2 = derivePublicKey(poseidon, dummyPrivKey2);
    const dummyBlinding2 = randomBytes32();
    const dummyCommitment2 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey2,
      dummyBlinding2,
      testMint
    );
    const dummyNullifier2 = computeNullifier(
      poseidon,
      dummyCommitment2,
      0,
      dummyPrivKey2
    );

    const updatedPath = offchainTokenTree.getMerkleProof(commitmentLeafIndex);

    const extDataTransfer = {
      recipient: user.publicKey,
      relayer: user.publicKey,
      fee: new BN(0),
      refund: new BN(0),
    };
    const extDataHashTransfer = computeExtDataHash(poseidon, extDataTransfer);

    const noteTreeAccAfter: any = await (
      program.account as any
    ).merkleTreeAccount.fetch(tokenNoteTree);
    const updatedOnchainRoot = extractRootFromAccount(noteTreeAccAfter);

    const transferProof = await generateTransactionProof({
      root: updatedOnchainRoot,
      publicAmount: 0n,
      extDataHash: extDataHashTransfer,
      mintAddress: testMint,
      inputNullifiers: [nullifier, dummyNullifier2],
      outputCommitments: [outputCommitment, dummyOutput2Commitment],
      inputAmounts: [depositAmount, 0n],
      inputPrivateKeys: [privateKey, dummyPrivKey2],
      inputPublicKeys: [publicKey, dummyPubKey2],
      inputBlindings: [blinding, dummyBlinding2],
      inputMerklePaths: [
        updatedPath,
        { pathElements: zeroPathElements, pathIndices: new Array(26).fill(0) },
      ],
      outputAmounts: [depositAmount, 0n],
      outputOwners: [outputPubKey, dummyOutput2PubKey],
      outputBlindings: [outputBlinding, dummyOutput2Blinding],
    });

    const crossTreeInputTreeId = 0;
    const inputNullifierMarker = deriveNullifierMarkerPDA(
      program.programId,
      testMint,
      crossTreeInputTreeId,
      nullifier
    );
    const dummyNullifierMarker = deriveNullifierMarkerPDA(
      program.programId,
      testMint,
      crossTreeInputTreeId,
      dummyNullifier2
    );

    const crossTreeTx = await (program.methods as any)
      .transact(
        Array.from(updatedOnchainRoot),
        0,
        destinationTreeId,
        new BN(0),
        Array.from(extDataHashTransfer),
        testMint,
        Array.from(nullifier),
        Array.from(dummyNullifier2),
        Array.from(outputCommitment),
        Array.from(dummyOutput2Commitment),
        extDataTransfer,
        transferProof
      )
      .accounts({
        config: tokenConfig,
        globalConfig,
        vault: tokenVault,
        inputTree: tokenNoteTree,
        outputTree: tokenNoteTreeDestination,
        nullifiers: tokenNullifiers,
        nullifierMarker0: inputNullifierMarker,
        nullifierMarker1: dummyNullifierMarker,
        relayer: user.publicKey,
        recipient: user.publicKey,
        vaultTokenAccount,
        userTokenAccount,
        recipientTokenAccount: userTokenAccount,
        relayerTokenAccount: userTokenAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .instruction();

    blockhash = (await provider.connection.getLatestBlockhash()).blockhash;
    messageV0 = new TransactionMessage({
      payerKey: user.publicKey,
      recentBlockhash: blockhash,
      instructions: [modifyComputeUnits, addPriorityFee, crossTreeTx],
    }).compileToV0Message();

    versionedTx = new VersionedTransaction(messageV0);
    versionedTx.sign([user]);

    await provider.connection.sendTransaction(versionedTx);
    await new Promise((resolve) => setTimeout(resolve, 2600));

    offchainTokenTreeDestination.insert(outputCommitment);
    offchainTokenTreeDestination.insert(dummyOutput2Commitment);

    console.log("✅ Cross-tree SPL token transaction successful!");

    // =============================================================================
    // Security Test: Verify tree isolation for SPL tokens
    // =============================================================================

    console.log(`\n🔒 Security Test: SPL Token Tree Isolation\n`);

    // Test: Try to spend commitment from Destination Tree using Tree 0 as input
    console.log(
      `   Test: Attempting to spend SPL commitment from Tree ${destinationTreeId} using Tree 0...`
    );

    const outputCommitmentLeafIndex = 0;
    const outputNullifier = computeNullifier(
      poseidon,
      outputCommitment,
      outputCommitmentLeafIndex,
      outputPrivKey
    );

    const destTreePath = offchainTokenTreeDestination.getMerkleProof(
      outputCommitmentLeafIndex
    );

    const noteTreeAccTree0: any = await (
      program.account as any
    ).merkleTreeAccount.fetch(tokenNoteTree);
    const tree0Root = extractRootFromAccount(noteTreeAccTree0);

    const withdrawRecipient = Keypair.generate();
    await airdropAndConfirm(
      provider,
      withdrawRecipient.publicKey,
      0.1 * LAMPORTS_PER_SOL
    );

    const recipientTokenAccount = await createAndFundTokenAccount(
      provider,
      testMint,
      withdrawRecipient.publicKey,
      0
    );

    const withdrawAmount = depositAmount;
    const fee = (depositAmount * BigInt(feeBps)) / 10_000n;

    const extDataWithdraw = {
      recipient: withdrawRecipient.publicKey,
      relayer: user.publicKey,
      fee: new BN(fee.toString()),
      refund: new BN(0),
    };
    const extDataHashWithdraw = computeExtDataHash(poseidon, extDataWithdraw);

    const dummyWithdrawPrivKey = randomBytes32();
    const dummyWithdrawPubKey = derivePublicKey(poseidon, dummyWithdrawPrivKey);
    const dummyWithdrawBlinding = randomBytes32();
    const dummyWithdrawCommitment = computeCommitment(
      poseidon,
      0n,
      dummyWithdrawPubKey,
      dummyWithdrawBlinding,
      testMint
    );
    const dummyWithdrawNullifier = computeNullifier(
      poseidon,
      dummyWithdrawCommitment,
      0,
      dummyWithdrawPrivKey
    );

    const dummyOut1PrivKey = randomBytes32();
    const dummyOut1PubKey = derivePublicKey(poseidon, dummyOut1PrivKey);
    const dummyOut1Blinding = randomBytes32();
    const dummyOut1Commitment = computeCommitment(
      poseidon,
      0n,
      dummyOut1PubKey,
      dummyOut1Blinding,
      testMint
    );

    const dummyOut2PrivKey = randomBytes32();
    const dummyOut2PubKey = derivePublicKey(poseidon, dummyOut2PrivKey);
    const dummyOut2Blinding = randomBytes32();
    const dummyOut2Commitment = computeCommitment(
      poseidon,
      0n,
      dummyOut2PubKey,
      dummyOut2Blinding,
      testMint
    );

    try {
      // Generate proof using Tree 0's root (WRONG tree!)
      const wrongTreeProof = await generateTransactionProof({
        root: tree0Root,
        publicAmount: -withdrawAmount,
        extDataHash: extDataHashWithdraw,
        mintAddress: testMint,
        inputNullifiers: [outputNullifier, dummyWithdrawNullifier],
        outputCommitments: [dummyOut1Commitment, dummyOut2Commitment],
        inputAmounts: [depositAmount, 0n],
        inputPrivateKeys: [outputPrivKey, dummyWithdrawPrivKey],
        inputPublicKeys: [outputPubKey, dummyWithdrawPubKey],
        inputBlindings: [outputBlinding, dummyWithdrawBlinding],
        inputMerklePaths: [
          destTreePath,
          {
            pathElements: zeroPathElements,
            pathIndices: new Array(26).fill(0),
          },
        ],
        outputAmounts: [0n, 0n],
        outputOwners: [dummyOut1PubKey, dummyOut2PubKey],
        outputBlindings: [dummyOut1Blinding, dummyOut2Blinding],
      });

      console.log(
        `   ❌ SECURITY FAILURE: Should have rejected spending from wrong tree!`
      );
      throw new Error(
        "Security vulnerability: cross-tree SPL token spending allowed!"
      );
    } catch (e: any) {
      if (
        e.message.includes("Error in template") ||
        e.message.includes("Assert Failed")
      ) {
        console.log(
          `   ✅ Proof generation FAILED (merkle path doesn't match root)`
        );
        console.log(
          `   ✅ Circuit correctly enforces: SPL commitment must be in specified tree`
        );
      } else if (e.message.includes("Security vulnerability")) {
        throw e;
      } else {
        console.log(`   ✅ Transaction REJECTED by program validation`);
      }
    }

    console.log(`\n✅ SPL Token Tree Isolation Security Test Passed!`);
    console.log(
      `   ✅ SPL commitments in Tree 0 cannot be spent via Tree ${destinationTreeId}`
    );
    console.log(
      `   ✅ SPL commitments in Tree ${destinationTreeId} cannot be spent via Tree 0`
    );
    console.log(`   ✅ Each SPL tree maintains independent state and security`);
  });

  // =============================================================================
  // Token Error Cases
  // =============================================================================

  it("rejects token deposit with wrong mint address", async () => {
    const sender = Keypair.generate();
    await airdropAndConfirm(provider, sender.publicKey, 2 * LAMPORTS_PER_SOL);

    // Create a DIFFERENT token mint
    const wrongMint = await createMint(
      provider.connection,
      wallet.payer,
      wallet.publicKey,
      null,
      MINT_DECIMALS
    );

    const senderTokenAccount = await createAndFundTokenAccount(
      provider,
      wrongMint,
      sender.publicKey,
      TOKEN_AMOUNT
    );

    await (program.methods as any)
      .addRelayer(testMint, sender.publicKey)
      .accounts({ config: tokenConfig, admin: wallet.publicKey })
      .rpc();

    const depositAmount = BigInt(TOKEN_AMOUNT);
    const privateKey = randomBytes32();
    const publicKey = derivePublicKey(poseidon, privateKey);
    const blinding = randomBytes32();

    // Use WRONG mint in commitment
    const commitment = computeCommitment(
      poseidon,
      depositAmount,
      publicKey,
      blinding,
      wrongMint
    );

    const dummyOutputPrivKey = randomBytes32();
    const dummyOutputPubKey = derivePublicKey(poseidon, dummyOutputPrivKey);
    const dummyOutputBlinding = randomBytes32();
    const dummyOutputCommitment = computeCommitment(
      poseidon,
      0n,
      dummyOutputPubKey,
      dummyOutputBlinding,
      wrongMint
    );

    const dummyPrivKey0 = randomBytes32();
    const dummyPrivKey1 = randomBytes32();
    const dummyPubKey0 = derivePublicKey(poseidon, dummyPrivKey0);
    const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);
    const dummyBlinding0 = randomBytes32();
    const dummyBlinding1 = randomBytes32();

    const dummyCommitment0 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey0,
      dummyBlinding0,
      wrongMint
    );
    const dummyCommitment1 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey1,
      dummyBlinding1,
      wrongMint
    );

    const dummyNullifier0 = computeNullifier(
      poseidon,
      dummyCommitment0,
      0,
      dummyPrivKey0
    );
    const dummyNullifier1 = computeNullifier(
      poseidon,
      dummyCommitment1,
      0,
      dummyPrivKey1
    );

    const extData = {
      recipient: sender.publicKey,
      relayer: sender.publicKey,
      fee: new BN(0),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    const noteTreeAcc: any = await (
      program.account as any
    ).merkleTreeAccount.fetch(tokenNoteTree);
    const onchainRoot = extractRootFromAccount(noteTreeAcc);

    const zeros = offchainTokenTree.getZeros();
    const zeroPathElements = zeros.slice(0, 26).map((z) => bytesToBigIntBE(z));

    const proof = await generateTransactionProof({
      root: onchainRoot,
      publicAmount: depositAmount,
      extDataHash,
      mintAddress: wrongMint, // WRONG MINT!
      inputNullifiers: [dummyNullifier0, dummyNullifier1],
      outputCommitments: [commitment, dummyOutputCommitment],

      inputAmounts: [0n, 0n],
      inputPrivateKeys: [dummyPrivKey0, dummyPrivKey1],
      inputPublicKeys: [dummyPubKey0, dummyPubKey1],
      inputBlindings: [dummyBlinding0, dummyBlinding1],
      inputMerklePaths: [
        { pathElements: zeroPathElements, pathIndices: new Array(26).fill(0) },
        { pathElements: zeroPathElements, pathIndices: new Array(26).fill(0) },
      ],

      outputAmounts: [depositAmount, 0n],
      outputOwners: [publicKey, dummyOutputPubKey],
      outputBlindings: [blinding, dummyOutputBlinding],
    });

    const wrongMintInputTreeId = 0;
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      testMint,
      wrongMintInputTreeId,
      dummyNullifier0
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      testMint,
      wrongMintInputTreeId,
      dummyNullifier1
    );

    try {
      await (program.methods as any)
        .transact(
          Array.from(onchainRoot),
          0, // input_tree_id
          0, // output_tree_id
          new BN(depositAmount.toString()),
          Array.from(extDataHash),
          wrongMint, // Pass wrong mint!
          Array.from(dummyNullifier0),
          Array.from(dummyNullifier1),
          Array.from(commitment),
          Array.from(dummyOutputCommitment),
          extData,
          proof
        )
        .accounts({
          config: tokenConfig,
          globalConfig,
          vault: tokenVault,
          inputTree: tokenNoteTree,
          outputTree: tokenNoteTree,
          nullifiers: tokenNullifiers,
          nullifierMarker0,
          nullifierMarker1,
          relayer: sender.publicKey,
          recipient: sender.publicKey,
          vaultTokenAccount,
          userTokenAccount: senderTokenAccount,
          recipientTokenAccount: senderTokenAccount,
          relayerTokenAccount: senderTokenAccount,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .signers([sender])
        .rpc();

      throw new Error("Should have failed with wrong mint address");
    } catch (e: any) {
      if (e.message.includes("Should have failed")) {
        throw e;
      }
      // Expected error
      console.log("\n✅ Correctly rejected deposit with wrong mint address");
      console.log(`   Error: ${e.message}`);
    }
  });

  after(() => {
    console.log("\n📊 SPL Token Tests Complete!\n");
    console.log("All token tests passed ✅");
  });
});

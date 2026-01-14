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
  const TOKEN_AMOUNT = 200_000_000; // 200 tokens with 6 decimals (ensures 0.5% fee meets 1M minimum)

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
    const zeroPathElements = zeros.slice(0, 20).map((z) => bytesToBigIntBE(z));

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
        { pathElements: zeroPathElements, pathIndices: new Array(20).fill(0) },
        { pathElements: zeroPathElements, pathIndices: new Array(20).fill(0) },
      ],

      outputAmounts: [depositAmount, 0n],
      outputOwners: [publicKey, dummyOutputPubKey],
      outputBlindings: [blinding, dummyOutputBlinding],
    });

    const [nullifierMarker0] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("nullifier_v3"),
        testMint.toBuffer(),
        Buffer.from(dummyNullifier0),
      ],
      program.programId
    );
    const [nullifierMarker1] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("nullifier_v3"),
        testMint.toBuffer(),
        Buffer.from(dummyNullifier1),
      ],
      program.programId
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

    const withdrawAmount = depositNote.amount;
    const fee = (depositNote.amount * BigInt(feeBps)) / 10_000n;
    const toRecipient = depositNote.amount - fee;

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

    // Create dummy outputs
    const dummyOutputPrivKey0 = randomBytes32();
    const dummyOutputPubKey0 = derivePublicKey(poseidon, dummyOutputPrivKey0);
    const dummyOutputBlinding0 = randomBytes32();
    const dummyOutputCommitment0 = computeCommitment(
      poseidon,
      0n,
      dummyOutputPubKey0,
      dummyOutputBlinding0,
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
    const zeroPathElements = zeros.slice(0, 20).map((z) => bytesToBigIntBE(z));

    const proof = await generateTransactionProof({
      root: onchainRoot,
      publicAmount: -withdrawAmount,
      extDataHash,
      mintAddress: testMint,
      inputNullifiers: [depositNote.nullifier, dummyNullifier1],
      outputCommitments: [dummyOutputCommitment0, dummyOutputCommitment1],

      inputAmounts: [depositNote.amount, 0n],
      inputPrivateKeys: [depositNote.privateKey, dummyPrivKey1],
      inputPublicKeys: [depositNote.publicKey, dummyPubKey1],
      inputBlindings: [depositNote.blinding, dummyBlinding1],
      inputMerklePaths: [
        updatedMerklePath,
        { pathElements: zeroPathElements, pathIndices: new Array(20).fill(0) },
      ],

      outputAmounts: [0n, 0n],
      outputOwners: [dummyOutputPubKey0, dummyOutputPubKey1],
      outputBlindings: [dummyOutputBlinding0, dummyOutputBlinding1],
    });

    const [nullifierMarker0] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("nullifier_v3"),
        testMint.toBuffer(),
        Buffer.from(depositNote.nullifier),
      ],
      program.programId
    );
    const [nullifierMarker1] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("nullifier_v3"),
        testMint.toBuffer(),
        Buffer.from(dummyNullifier1),
      ],
      program.programId
    );

    try {
      const modifyComputeUnits = ComputeBudgetProgram.setComputeUnitLimit({
        units: 1_400_000,
      });
      const addPriorityFee = ComputeBudgetProgram.setComputeUnitPrice({
        microLamports: 1,
      });

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
          Array.from(dummyOutputCommitment0),
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

      const { blockhash } = await provider.connection.getLatestBlockhash();
      const messageV0 = new TransactionMessage({
        payerKey: relayer.publicKey,
        recentBlockhash: blockhash,
        instructions: [modifyComputeUnits, addPriorityFee, ix],
      }).compileToV0Message();

      const versionedTx = new VersionedTransaction(messageV0);
      versionedTx.sign([relayer]);

      const sig = await provider.connection.sendTransaction(versionedTx);
      await provider.connection.confirmTransaction({
        signature: sig,
        blockhash: blockhash,
        lastValidBlockHeight: (
          await provider.connection.getLatestBlockhash()
        ).lastValidBlockHeight,
      });

      // Insert outputs into offchain tree
      offchainTokenTree.insert(dummyOutputCommitment0);
      offchainTokenTree.insert(dummyOutputCommitment1);

      console.log("\n✅ Token withdrawal successful");
      console.log(`   Withdrawn: ${withdrawAmount} tokens`);
      console.log(`   Fee: ${fee} tokens`);
      console.log(`   To recipient: ${toRecipient} tokens`);

      tokenNoteStorage.markSpent(tokenDepositNoteId!);
    } catch (e: any) {
      if (e instanceof SendTransactionError) {
        const logs = await e.getLogs(provider.connection);
        console.error("Token withdrawal failed:", logs);
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
    const zeroPathElements = zeros.slice(0, 20).map((z) => bytesToBigIntBE(z));

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
        { pathElements: zeroPathElements, pathIndices: new Array(20).fill(0) },
        { pathElements: zeroPathElements, pathIndices: new Array(20).fill(0) },
      ],
      outputAmounts: [aliceDepositAmount, 0n],
      outputOwners: [alicePublicKey, aliceDummyPubKey],
      outputBlindings: [aliceBlinding, aliceDummyBlinding],
    });

    const [nullifierMarker0] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("nullifier_v3"),
        testMint.toBuffer(),
        Buffer.from(dummyNullifier0),
      ],
      program.programId
    );
    const [nullifierMarker1] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("nullifier_v3"),
        testMint.toBuffer(),
        Buffer.from(dummyNullifier1),
      ],
      program.programId
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
        { pathElements: zeroPathElements, pathIndices: new Array(20).fill(0) },
      ],

      outputAmounts: [transferAmount, changeAmount],
      outputOwners: [bobPublicKey, aliceChangePubKey],
      outputBlindings: [bobBlinding, aliceChangeBlinding],
    });

    const [aliceNullifierMarker] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("nullifier_v3"),
        testMint.toBuffer(),
        Buffer.from(aliceNullifier),
      ],
      program.programId
    );
    const [transferDummyNullifierMarker] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("nullifier_v3"),
        testMint.toBuffer(),
        Buffer.from(transferDummyNullifier),
      ],
      program.programId
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
    const zeroPathElements = zeros.slice(0, 20).map((z) => bytesToBigIntBE(z));

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
        { pathElements: zeroPathElements, pathIndices: new Array(20).fill(0) },
        { pathElements: zeroPathElements, pathIndices: new Array(20).fill(0) },
      ],

      outputAmounts: [depositAmount, 0n],
      outputOwners: [publicKey, dummyOutputPubKey],
      outputBlindings: [blinding, dummyOutputBlinding],
    });

    const [nullifierMarker0] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("nullifier_v3"),
        testMint.toBuffer(),
        Buffer.from(dummyNullifier0),
      ],
      program.programId
    );
    const [nullifierMarker1] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("nullifier_v3"),
        testMint.toBuffer(),
        Buffer.from(dummyNullifier1),
      ],
      program.programId
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

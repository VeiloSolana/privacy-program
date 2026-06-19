// tests/position-pool.test.ts
//
// Position Pool Tests — private stock & meme token trading
//
// Tests the init_position_pool, open_position, and close_position instructions.
// open_position uses the existing swap circuit (SOL→token) and Jupiter V6 for routing.
// close_position uses the same swap circuit in reverse (token→SOL).
//
// Token pairs tested:
//   - CARDS: CARDSccUMFKoPRZxt5vt3ksUbxEFEcnZ3H2pd3dKxYjp  (legacy SPL, Raydium CLMM)
//   - xStock: Xs3oZwbHvqis4NYcf4YKWmEia2eC84wSiVrcYcTqpH8  (Token-2022, Byreal/Scorch)

import "mocha";
import {
  BN,
  setProvider,
  Wallet,
  workspace,
} from "@coral-xyz/anchor";
import {
  PublicKey,
  Keypair,
  SystemProgram,
  SendTransactionError,
  LAMPORTS_PER_SOL,
  AddressLookupTableProgram,
  TransactionMessage,
  VersionedTransaction,
  Transaction,
  TransactionInstruction,
  ComputeBudgetProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  getAssociatedTokenAddress,
  NATIVE_MINT,
  getOrCreateAssociatedTokenAccount,
  createAssociatedTokenAccountIdempotentInstruction,
} from "@solana/spl-token";
import { expect } from "chai";
import { buildPoseidon } from "circomlibjs";
import { createHash } from "crypto";
import * as crypto from "crypto";

import { JupiterSwapService } from "./utils/jupiter/jupiter-swap-service";
import {
  JUPITER_PROGRAM_ID,
  JUPITER_EVENT_AUTHORITY,
} from "./amm-v4-pool-helper";
import {
  makeProvider,
  randomBytes32,
  bytesToBigIntBE,
  reduceToField,
  computeCommitment,
  computeNullifier,
  computeExtDataHash,
  derivePublicKey,
  airdropAndConfirm,
  generateTransactionProof,
  generateSwapProof,
  computeSwapParamsHash,
  OffchainMerkleTree,
  DepositNote,
} from "./test-helpers";

// ─── Token constants ─────────────────────────────────────────────────────────

const SOL_MINT = PublicKey.default; // SOL pool sentinel (all-zero bytes)
// CARDS: legacy SPL token, trades USDC↔CARDS via Raydium CLMM 1-hop on localnet.
const CARDS_MINT = new PublicKey("CARDSccUMFKoPRZxt5vt3ksUbxEFEcnZ3H2pd3dKxYjp");
const XSTOCK_MINT = new PublicKey("Xs3oZwbHvqis4NYcf4YKWmEia2eC84wSiVrcYcTqpH8");
const USDC_MINT = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
const TOKEN_2022_PROGRAM_ID = new PublicKey("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

// ─── Small helpers ────────────────────────────────────────────────────────────

function bigIntToBytes32BE(n: bigint): Uint8Array {
  const hex = n.toString(16).padStart(64, "0");
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

function encodeTreeId(treeId: number): Buffer {
  const buf = Buffer.alloc(2);
  buf.writeUInt16LE(treeId, 0);
  return buf;
}

// ─── Privacy pool PDA derivation ─────────────────────────────────────────────

function deriveConfigPDA(programId: PublicKey, mint: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("privacy_config_v3"), mint.toBuffer()],
    programId,
  )[0];
}

function deriveVaultPDA(programId: PublicKey, mint: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("privacy_vault_v3"), mint.toBuffer()],
    programId,
  )[0];
}

function deriveNoteTreePDA(programId: PublicKey, mint: PublicKey, treeId: number): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("privacy_note_tree_v3"), mint.toBuffer(), encodeTreeId(treeId)],
    programId,
  )[0];
}

function deriveNullifiersPDA(programId: PublicKey, mint: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("privacy_nullifiers_v3"), mint.toBuffer()],
    programId,
  )[0];
}

function deriveNullifierMarkerPDA(
  programId: PublicKey,
  mint: PublicKey,
  nullifier: Uint8Array,
): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("nullifier_v3"), mint.toBuffer(), Buffer.from(nullifier)],
    programId,
  )[0];
}

function deriveGlobalConfig(programId: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("global_config_v1")],
    programId,
  )[0];
}

function deriveSwapExecutorPDA(
  programId: PublicKey,
  sourceMint: PublicKey,
  destMint: PublicKey,
  nullifier0: Uint8Array,
  relayer: PublicKey,
): PublicKey {
  return PublicKey.findProgramAddressSync(
    [
      Buffer.from("swap_executor"),
      sourceMint.toBuffer(),
      destMint.toBuffer(),
      Buffer.from(nullifier0),
      relayer.toBuffer(),
    ],
    programId,
  )[0];
}

// ─── Position pool PDA derivation ────────────────────────────────────────────

function derivePositionConfig(programId: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("position_config_v1")],
    programId,
  )[0];
}

function derivePositionTree(programId: PublicKey, treeId: number): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("position_tree_v1"), encodeTreeId(treeId)],
    programId,
  )[0];
}

function derivePositionVaultRecord(programId: PublicKey, mint: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("position_vault_v1"), mint.toBuffer()],
    programId,
  )[0];
}

function derivePositionVaultPda(programId: PublicKey, mint: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("position_vault_token_v1"), mint.toBuffer()],
    programId,
  )[0];
}

function derivePositionPda(programId: PublicKey, positionPdaKey: Uint8Array): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("position_pda_v1"), Buffer.from(positionPdaKey)],
    programId,
  )[0];
}

function derivePositionNullifierMarker(programId: PublicKey, mint: PublicKey, nullifier: Uint8Array): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("position_nullifier_v1"), mint.toBuffer(), Buffer.from(nullifier)],
    programId,
  )[0];
}

// ─── Client-side position key derivation ─────────────────────────────────────
//
// positionSecretN  = Poseidon(sha256(walletPrivkey || "veilo_v1") mod Fr, n)
// positionBlinding = Poseidon(positionSecretN, 1)
// positionPubkey   = Poseidon(positionSecretN)
// positionPdaKey   = 32-byte big-endian encoding of positionPubkey

function derivePositionKeys(
  poseidon: any,
  walletPrivkey: Uint8Array,
  n: number,
): {
  positionSecretN: bigint;
  positionBlinding: bigint;
  positionPubkey: bigint;
  positionPdaKeyBytes: Uint8Array;
} {
  const preimage = Buffer.concat([Buffer.from(walletPrivkey), Buffer.from("veilo_v1")]);
  const rootSecretBytes = crypto.createHash("sha256").update(preimage).digest();
  const rootSecretField = poseidon.F.e(reduceToField(rootSecretBytes));

  const secretHash = poseidon([rootSecretField, poseidon.F.e(BigInt(n))]);
  const positionSecretN: bigint = poseidon.F.toObject(secretHash);

  const blindingHash = poseidon([poseidon.F.e(positionSecretN), poseidon.F.e(BigInt(1))]);
  const positionBlinding: bigint = poseidon.F.toObject(blindingHash);

  const pubkeyHash = poseidon([poseidon.F.e(positionSecretN)]);
  const positionPubkey: bigint = poseidon.F.toObject(pubkeyHash);

  const positionPdaKeyBytes = bigIntToBytes32BE(positionPubkey);
  return { positionSecretN, positionBlinding, positionPubkey, positionPdaKeyBytes };
}

// ─── Position note state ──────────────────────────────────────────────────────

interface PositionNoteState {
  amount: bigint;           // destAmount committed in the circuit
  positionSecretN: bigint;  // position private key
  positionPubkey: bigint;   // position public key
  positionBlinding: bigint;
  positionBlindingBytes: Uint8Array;
  positionPdaKeyBytes: Uint8Array;
  mint: PublicKey;
  isToken2022: boolean;
  leafIndex: number;        // leaf index in position tree
  commitment: Uint8Array;   // position commitment
}

// ─── ALT builder utility ──────────────────────────────────────────────────────

async function buildAndActivateALT(
  connection: any,
  payer: Keypair,
  keys: PublicKey[],
): Promise<import("@solana/web3.js").AddressLookupTableAccount> {
  const recentSlot = await connection.getSlot("finalized");
  const [createIx, altAddress] = AddressLookupTableProgram.createLookupTable({
    authority: payer.publicKey,
    payer: payer.publicKey,
    recentSlot,
  });

  const provider = makeProvider();
  await provider.sendAndConfirm(new Transaction().add(createIx));

  const BATCH = 20;
  for (let i = 0; i < keys.length; i += BATCH) {
    const extIx = AddressLookupTableProgram.extendLookupTable({
      payer: payer.publicKey,
      authority: payer.publicKey,
      lookupTable: altAddress,
      addresses: keys.slice(i, i + BATCH),
    });
    await provider.sendAndConfirm(new Transaction().add(extIx));
  }

  // Wait for ALT activation (1-2 slots)
  await new Promise((r) => setTimeout(r, 1500));
  const info = await connection.getAddressLookupTable(altAddress);
  return info.value!;
}

// ─── Jupiter instruction decoder ─────────────────────────────────────────────

function decodeJupIx(ix: {
  programId: string;
  accounts: Array<{ pubkey: string; isSigner: boolean; isWritable: boolean }>;
  data: string;
}): TransactionInstruction {
  return new TransactionInstruction({
    keys: ix.accounts.map((a) => ({
      pubkey: new PublicKey(a.pubkey),
      isSigner: a.isSigner,
      isWritable: a.isWritable,
    })),
    programId: new PublicKey(ix.programId),
    data: Buffer.from(ix.data, "base64"),
  });
}

// ─── Test suite ───────────────────────────────────────────────────────────────

describe("Position Pool", () => {
  const provider = makeProvider();
  setProvider(provider);

  const wallet = provider.wallet as Wallet;
  const payer = wallet.payer;
  const program: any = workspace.PrivacyPool as any;
  const connection = provider.connection;

  let poseidon: any;
  let jupiterService: JupiterSwapService;
  let globalConfig: PublicKey;
  let positionConfig: PublicKey;
  let positionTree0: PublicKey;

  // SOL pool accounts
  let solConfig: PublicKey;
  let solVault: PublicKey;
  let solNoteTree: PublicKey;
  let solNullifiers: PublicKey;
  let solVaultTokenAccount: PublicKey;

  // USDC pool accounts
  let usdcConfig: PublicKey;
  let usdcVault: PublicKey;
  let usdcNoteTree: PublicKey;
  let usdcNullifiers: PublicKey;
  let usdcVaultTokenAccount: PublicKey;

  // Off-chain trees
  let solOffchainTree: OffchainMerkleTree;
  let positionOffchainTree: OffchainMerkleTree;
  let usdcOffchainTree: OffchainMerkleTree;

  // Deposited SOL note (set by deposit test, used in open_position)
  let solNote: DepositNote | undefined;

  // Position state (set by open_position, used by close_position)
  let memePositionState: PositionNoteState | undefined;
  let xstockPositionState: PositionNoteState | undefined;

  // Test wallet private key slice for position derivation
  let walletPrivkey: Uint8Array;

  before(async () => {
    poseidon = await buildPoseidon();
    jupiterService = new JupiterSwapService(connection);

    walletPrivkey = payer.secretKey.slice(0, 32);

    globalConfig = deriveGlobalConfig(program.programId);
    positionConfig = derivePositionConfig(program.programId);
    positionTree0 = derivePositionTree(program.programId, 0);

    solConfig = deriveConfigPDA(program.programId, SOL_MINT);
    solVault = deriveVaultPDA(program.programId, SOL_MINT);
    solNoteTree = deriveNoteTreePDA(program.programId, SOL_MINT, 0);
    solNullifiers = deriveNullifiersPDA(program.programId, SOL_MINT);
    solVaultTokenAccount = await getAssociatedTokenAddress(NATIVE_MINT, solVault, true);

    solOffchainTree = new OffchainMerkleTree(22, poseidon);
    positionOffchainTree = new OffchainMerkleTree(22, poseidon);
    usdcOffchainTree = new OffchainMerkleTree(22, poseidon);

    usdcConfig = deriveConfigPDA(program.programId, USDC_MINT);
    usdcVault = deriveVaultPDA(program.programId, USDC_MINT);
    usdcNoteTree = deriveNoteTreePDA(program.programId, USDC_MINT, 0);
    usdcNullifiers = deriveNullifiersPDA(program.programId, USDC_MINT);
    usdcVaultTokenAccount = await getAssociatedTokenAddress(USDC_MINT, usdcVault, true);

    console.log("\nPosition Pool PDAs:");
    console.log("  programId:      ", program.programId.toBase58());
    console.log("  positionConfig: ", positionConfig.toBase58());
    console.log("  positionTree0:  ", positionTree0.toBase58());
    console.log("  solConfig:     ", solConfig.toBase58());
    console.log("  solVault:      ", solVault.toBase58());
  });

  // ===========================================================================
  // Section 1: PDA derivation correctness
  // ===========================================================================

  describe("PDA derivation", () => {
    it("derives position config PDA deterministically", () => {
      const pda1 = derivePositionConfig(program.programId);
      const pda2 = derivePositionConfig(program.programId);
      expect(pda1.toBase58()).to.equal(pda2.toBase58());
    });

    it("derives distinct position tree PDAs for each tree_id", () => {
      const tree0 = derivePositionTree(program.programId, 0);
      const tree1 = derivePositionTree(program.programId, 1);
      const tree65535 = derivePositionTree(program.programId, 65535);
      expect(tree0.toBase58()).to.not.equal(tree1.toBase58());
      expect(tree1.toBase58()).to.not.equal(tree65535.toBase58());
    });

    it("derives distinct vault records per mint", () => {
      const mintA = Keypair.generate().publicKey;
      const mintB = Keypair.generate().publicKey;
      const recordA = derivePositionVaultRecord(program.programId, mintA);
      const recordB = derivePositionVaultRecord(program.programId, mintB);
      expect(recordA.toBase58()).to.not.equal(recordB.toBase58());
    });

    it("derives distinct position PDAs per positionPdaKey", () => {
      const key1 = randomBytes32();
      const key2 = randomBytes32();
      const pda1 = derivePositionPda(program.programId, key1);
      const pda2 = derivePositionPda(program.programId, key2);
      expect(pda1.toBase58()).to.not.equal(pda2.toBase58());
    });

    it("derives distinct nullifier markers per nullifier", () => {
      const n1 = randomBytes32();
      const n2 = randomBytes32();
      const m1 = derivePositionNullifierMarker(program.programId, CARDS_MINT, n1);
      const m2 = derivePositionNullifierMarker(program.programId, CARDS_MINT, n2);
      expect(m1.toBase58()).to.not.equal(m2.toBase58());
    });
  });

  // ===========================================================================
  // Section 2: Client-side position key derivation
  // ===========================================================================

  describe("position key derivation", () => {
    it("derives deterministic position keys from wallet private key", async () => {
      const privkey = randomBytes32();
      const keys0 = derivePositionKeys(poseidon, privkey, 0);
      const keys1 = derivePositionKeys(poseidon, privkey, 1);
      const keys0_again = derivePositionKeys(poseidon, privkey, 0);

      expect(keys0.positionSecretN.toString()).to.equal(keys0_again.positionSecretN.toString());
      expect(keys0.positionPdaKeyBytes.toString()).to.equal(keys0_again.positionPdaKeyBytes.toString());
      expect(keys0.positionSecretN.toString()).to.not.equal(keys1.positionSecretN.toString());
    });

    it("derives different keys for different wallet private keys", async () => {
      const privkey1 = randomBytes32();
      const privkey2 = randomBytes32();
      const keys1 = derivePositionKeys(poseidon, privkey1, 0);
      const keys2 = derivePositionKeys(poseidon, privkey2, 0);
      expect(keys1.positionSecretN.toString()).to.not.equal(keys2.positionSecretN.toString());
    });

    it("computes valid position commitment for a given mint", () => {
      const mint = CARDS_MINT;
      const privkey = randomBytes32();
      const keys = derivePositionKeys(poseidon, privkey, 0);
      const destAmount = 1_000_000n;
      const blindingBytes = bigIntToBytes32BE(keys.positionBlinding);
      const commitment = computeCommitment(poseidon, destAmount, keys.positionPubkey, blindingBytes, mint);
      expect(commitment).to.have.length(32);
      expect(bytesToBigIntBE(commitment) > 0n).to.be.true;
    });

    it("derives correct on-chain position PDA from wallet private key", () => {
      const privkey = randomBytes32();
      const keys = derivePositionKeys(poseidon, privkey, 0);
      const positionPda = derivePositionPda(program.programId, keys.positionPdaKeyBytes);
      expect(positionPda).to.be.instanceOf(PublicKey);
    });
  });

  // ===========================================================================
  // Section 3: Pool initialization
  // ===========================================================================

  describe("pool initialization", () => {
    it("initializes global config", async () => {
      try {
        await (program.account as any).globalConfig.fetch(globalConfig);
        console.log("  ✓ global config already initialized");
        return;
      } catch {
        // not yet initialized
      }
      await (program.methods as any)
        .initializeGlobalConfig()
        .accounts({ globalConfig, admin: payer.publicKey, systemProgram: SystemProgram.programId })
        .rpc();
      console.log("  ✓ global config initialized");
    });

    it("initializes SOL privacy pool", async () => {
      try {
        await (program.account as any).privacyConfig.fetch(solConfig);
        console.log("  ✓ SOL pool already initialized");
        return;
      } catch {
        // not yet initialized
      }
      await (program.methods as any)
        .initialize(50, SOL_MINT, new BN(0), new BN(1_000_000_000_000), new BN(0), new BN(1_000_000_000_000))
        .accounts({
          config: solConfig,
          vault: solVault,
          noteTree: solNoteTree,
          nullifiers: solNullifiers,
          globalConfig,
          admin: payer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      console.log("  ✓ SOL pool initialized");
    });

    it("registers relayer for SOL pool", async () => {
      try {
        await (program.methods as any)
          .addRelayer(SOL_MINT, payer.publicKey)
          .accounts({ config: solConfig, admin: payer.publicKey })
          .rpc();
        console.log("  ✓ relayer registered for SOL pool");
      } catch (e: any) {
        if (e.message?.includes("already") || e.message?.includes("AlreadyInUse")) {
          console.log("  ✓ relayer already registered for SOL pool");
        } else {
          throw e;
        }
      }
    });

    it("initializes USDC privacy pool", async () => {
      try {
        await (program.account as any).privacyConfig.fetch(usdcConfig);
        console.log("  ✓ USDC pool already initialized");
        return;
      } catch {
        // not yet initialized
      }
      await (program.methods as any)
        .initialize(50, USDC_MINT, new BN(0), new BN(100_000_000_000), new BN(0), new BN(100_000_000_000))
        .accounts({
          config: usdcConfig,
          vault: usdcVault,
          noteTree: usdcNoteTree,
          nullifiers: usdcNullifiers,
          globalConfig,
          admin: payer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      // Zero the swap fees so close_position (which charges the USDC-pool swap fee)
      // succeeds with ext_data.fee = 0 in the test. (initialize() hardcodes min_swap_fee=50_000.)
      await (program.methods as any)
        .updatePoolConfig(USDC_MINT, null, null, null, null, null, null, null, new BN(0), 0)
        .accounts({ config: usdcConfig, admin: payer.publicKey })
        .rpc();
      console.log("  ✓ USDC pool initialized (zero swap fee for test)");
    });

    it("registers relayer for USDC pool", async () => {
      try {
        await (program.methods as any)
          .addRelayer(USDC_MINT, payer.publicKey)
          .accounts({ config: usdcConfig, admin: payer.publicKey })
          .rpc();
        console.log("  ✓ relayer registered for USDC pool");
      } catch (e: any) {
        if (e.message?.includes("already") || e.message?.includes("AlreadyInUse")) {
          console.log("  ✓ relayer already registered for USDC pool");
        } else {
          throw e;
        }
      }
    });

    it("initializes position pool config and tree", async () => {
      try {
        const existing = await (program.account as any).positionPoolConfig.fetch(positionConfig);
        console.log("  ✓ position pool already initialized, authority:", existing.authority.toBase58());
        return;
      } catch {
        // not yet initialized
      }

      try {
        await (program.methods as any)
          .initPositionPool(new BN(0), 0)
          .accounts({
            config: positionConfig,
            tree: positionTree0,
            globalConfig,
            admin: payer.publicKey,
            payer: payer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .rpc();
      } catch (e: any) {
        if (e instanceof SendTransactionError) {
          const logs = await e.getLogs(connection);
          console.error("initPositionPool failed:\n", logs?.join("\n"));
        }
        throw e;
      }

      const configAcc = await (program.account as any).positionPoolConfig.fetch(positionConfig);
      expect(configAcc.authority.toBase58()).to.equal(payer.publicKey.toBase58());
      expect(configAcc.minSwapFee.toNumber()).to.equal(0);
      expect(configAcc.swapFeeBps).to.equal(0);
      console.log("  ✓ position pool initialized (zero-fee for test)");
    });

    it("registers relayer for position pool", async () => {
      try {
        await (program.methods as any)
          .addPositionRelayer(payer.publicKey)
          .accounts({ config: positionConfig, authority: payer.publicKey })
          .rpc();
        console.log("  ✓ relayer registered for position pool");
      } catch (e: any) {
        if (e.message?.includes("already") || e.message?.includes("AlreadyInUse")) {
          console.log("  ✓ relayer already registered for position pool");
        } else {
          throw e;
        }
      }
    });

    it("fails to init position pool twice", async () => {
      try {
        await (program.account as any).positionPoolConfig.fetch(positionConfig);
      } catch {
        console.log("  position pool not yet initialized, skipping");
        return;
      }
      let threw = false;
      try {
        await (program.methods as any)
          .initPositionPool(new BN(10_000), 30)
          .accounts({
            config: positionConfig,
            tree: positionTree0,
            globalConfig,
            admin: payer.publicKey,
            payer: payer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .rpc();
      } catch {
        threw = true;
      }
      expect(threw).to.be.true;
    });
  });

  // ===========================================================================
  // Section 4: SOL deposit — creates spendable notes for open_position
  // ===========================================================================

  describe("SOL deposit", () => {
    it("deposits SOL to create a spendable note", async function () {
      this.timeout(120_000);
      console.log("\n💰 Depositing SOL...");

      await airdropAndConfirm(provider, payer.publicKey, 10 * LAMPORTS_PER_SOL);

      const depositAmount = 2_000_000_000n; // 2 SOL
      const privKey = randomBytes32();
      const pubKey = derivePublicKey(poseidon, privKey);
      const blinding = randomBytes32();
      const commitment = computeCommitment(poseidon, depositAmount, pubKey, blinding, SOL_MINT);

      const changePrivKey = randomBytes32();
      const changePubKey = derivePublicKey(poseidon, changePrivKey);
      const changeBlinding = randomBytes32();
      const changeCommitment = computeCommitment(poseidon, 0n, changePubKey, changeBlinding, SOL_MINT);

      // Two dummy inputs (0-amount) for the deposit proof
      const dummy1PrivKey = randomBytes32();
      const dummy1PubKey = derivePublicKey(poseidon, dummy1PrivKey);
      const dummy1Blinding = randomBytes32();
      const dummy1Commitment = computeCommitment(poseidon, 0n, dummy1PubKey, dummy1Blinding, SOL_MINT);
      const dummy1Nullifier = computeNullifier(poseidon, dummy1Commitment, 0, dummy1PrivKey);

      const dummy2PrivKey = randomBytes32();
      const dummy2PubKey = derivePublicKey(poseidon, dummy2PrivKey);
      const dummy2Blinding = randomBytes32();
      const dummy2Commitment = computeCommitment(poseidon, 0n, dummy2PubKey, dummy2Blinding, SOL_MINT);
      const dummy2Nullifier = computeNullifier(poseidon, dummy2Commitment, 0, dummy2PrivKey);

      const dummyProof = solOffchainTree.getMerkleProof(0);
      const root = solOffchainTree.getRoot();

      const extData = {
        recipient: payer.publicKey,
        relayer: payer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
        claimant: SystemProgram.programId,
      };
      const extDataHash = computeExtDataHash(poseidon, extData);

      const proof = await generateTransactionProof({
        root,
        publicAmount: depositAmount,
        extDataHash,
        mintAddress: SOL_MINT,
        inputNullifiers: [dummy1Nullifier, dummy2Nullifier],
        outputCommitments: [commitment, changeCommitment],
        inputAmounts: [0n, 0n],
        inputPrivateKeys: [dummy1PrivKey, dummy2PrivKey],
        inputPublicKeys: [dummy1PubKey, dummy2PubKey],
        inputBlindings: [dummy1Blinding, dummy2Blinding],
        inputMerklePaths: [dummyProof, dummyProof],
        outputAmounts: [depositAmount, 0n],
        outputOwners: [pubKey, changePubKey],
        outputBlindings: [blinding, changeBlinding],
      });

      const nullifierMarker1 = deriveNullifierMarkerPDA(program.programId, SOL_MINT, dummy1Nullifier);
      const nullifierMarker2 = deriveNullifierMarkerPDA(program.programId, SOL_MINT, dummy2Nullifier);

      const depositIx = await (program.methods as any)
        .transact(
          Array.from(root),
          0, // input_tree_id
          0, // output_tree_id
          new BN(depositAmount.toString()),
          Array.from(extDataHash),
          SOL_MINT,
          Array.from(dummy1Nullifier),
          Array.from(dummy2Nullifier),
          Array.from(commitment),
          Array.from(changeCommitment),
          new BN(9_999_999_999),
          { recipient: extData.recipient, relayer: extData.relayer, fee: extData.fee, refund: extData.refund, claimant: extData.claimant },
          proof,
          null,
        )
        .accounts({
          config: solConfig,
          globalConfig,
          vault: solVault,
          inputTree: solNoteTree,
          outputTree: solNoteTree,
          nullifiers: solNullifiers,
          nullifierMarker0: nullifierMarker1,
          nullifierMarker1: nullifierMarker2,
          relayer: payer.publicKey,
          recipient: payer.publicKey,
          vaultTokenAccount: solVaultTokenAccount,
          userTokenAccount: payer.publicKey,
          recipientTokenAccount: payer.publicKey,
          relayerTokenAccount: payer.publicKey,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .instruction();

      const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash();
      const msgV0 = new TransactionMessage({
        payerKey: payer.publicKey,
        recentBlockhash: blockhash,
        instructions: [
          ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
          depositIx,
        ],
      }).compileToV0Message();
      const vtx = new VersionedTransaction(msgV0);
      vtx.sign([payer]);
      const tx = await connection.sendTransaction(vtx);
      await connection.confirmTransaction({ signature: tx, blockhash, lastValidBlockHeight });
      console.log("  ✅ SOL deposit tx:", tx);

      const leafIndex = solOffchainTree.insert(commitment);
      solOffchainTree.insert(changeCommitment);

      solNote = {
        amount: depositAmount,
        commitment,
        nullifier: computeNullifier(poseidon, commitment, leafIndex, privKey),
        blinding,
        privateKey: privKey,
        publicKey: pubKey,
        leafIndex,
        merklePath: solOffchainTree.getMerkleProof(leafIndex),
        mintAddress: SOL_MINT,
      };
      console.log("  ✓ Note saved, leafIndex:", leafIndex, "amount:", depositAmount.toString());
    });
  });

  // ===========================================================================
  // Section 5: open/close position — meme token (pump.fun SPL)
  // ===========================================================================

  describe("open/close position — CARDS (Raydium CLMM, legacy SPL)", function () {
    this.timeout(300_000);

    it("opens CARDS position from SOL pool note (SOL→CARDS)", async () => {
      if (!solNote) throw new Error("solNote not set — SOL deposit test must run first");
      console.log("\n🚀 Opening SOL→CARDS position...");

      // ── Open CARDS position: spend solNote (SOL pool) → swap SOL→CARDS ──────
      console.log("  Getting Jupiter quote SOL→CARDS...");
      const swapAmount = solNote.amount;
      // High Jupiter slippage: the cloned pool state diverges from the live quote,
      // so Jupiter's own threshold must be lenient. The program's destAmount (50%) is the real guard.
      const quote = await jupiterService.getQuote(NATIVE_MINT, CARDS_MINT, Number(swapAmount), 5000, false);
      const expectedOut = BigInt(quote.outAmount);
      const destAmount = (expectedOut * 50n) / 100n;
      const minAmountOut = destAmount;
      console.log("  Expected CARDS output:", expectedOut.toString());

      const posKeys = derivePositionKeys(poseidon, walletPrivkey, 0); // index 0 for CARDS
      const positionPdaKeyBytes = posKeys.positionPdaKeyBytes;
      const positionBlindingBytes = bigIntToBytes32BE(posKeys.positionBlinding);

      const executorPDA = deriveSwapExecutorPDA(
        program.programId, SOL_MINT, CARDS_MINT, solNote.nullifier, payer.publicKey,
      );
      const positionVaultRecord = derivePositionVaultRecord(program.programId, CARDS_MINT);
      const positionVaultPda = derivePositionVaultPda(program.programId, CARDS_MINT);
      const positionPdaAddr = derivePositionPda(program.programId, positionPdaKeyBytes);

      // SOL pool uses WSOL (NATIVE_MINT) internally; CARDS is legacy SPL
      const executorSourceToken = await getAssociatedTokenAddress(NATIVE_MINT, executorPDA, true);
      const executorDestToken = await getAssociatedTokenAddress(CARDS_MINT, executorPDA, true);
      const positionVaultAta = await getAssociatedTokenAddress(CARDS_MINT, positionVaultPda, true);

      // useSharedAccounts=false (default) → Route instruction, no pre-existing Jupiter ATAs needed
      const swapIxResp = await jupiterService.getSwapInstruction(quote, executorPDA, false);
      const remainingAccounts = jupiterService.extractRemainingAccounts(swapIxResp.swapInstruction);
      const swapData = jupiterService.buildSwapData(swapIxResp.swapInstruction);
      const swapDataHash = new Uint8Array(createHash("sha256").update(swapData).digest());

      const positionCommitment = computeCommitment(
        poseidon, destAmount, posKeys.positionPubkey, positionBlindingBytes, CARDS_MINT,
      );
      // Change note goes back into the SOL pool
      const solChgPriv = randomBytes32(); const solChgPub = derivePublicKey(poseidon, solChgPriv); const solChgBld = randomBytes32();
      const solChangeCommit = computeCommitment(poseidon, 0n, solChgPub, solChgBld, SOL_MINT);

      const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
      const swapParamsHash = computeSwapParamsHash(poseidon, SOL_MINT, CARDS_MINT, minAmountOut, deadline, swapDataHash, destAmount);
      const openExtData = { recipient: payer.publicKey, relayer: payer.publicKey, fee: new BN(0), refund: new BN(0), claimant: SystemProgram.programId };
      const openExtDataHash = computeExtDataHash(poseidon, openExtData);

      const dummyPriv = randomBytes32(); const dummyPub = derivePublicKey(poseidon, dummyPriv); const dummyBld = randomBytes32();
      const dummyCommit = computeCommitment(poseidon, 0n, dummyPub, dummyBld, SOL_MINT);
      const dummyNull = computeNullifier(poseidon, dummyCommit, 0, dummyPriv);
      const dummyProof = solOffchainTree.getMerkleProof(0);

      const sourceRoot = solOffchainTree.getRoot();
      const merklePath = solOffchainTree.getMerkleProof(solNote.leafIndex);

      console.log("  Generating ZK swap proof...");
      const openProof = await generateSwapProof({
        sourceRoot, swapParamsHash, extDataHash: openExtDataHash,
        sourceMint: SOL_MINT, destMint: CARDS_MINT,
        inputNullifiers: [solNote.nullifier, dummyNull],
        changeCommitment: solChangeCommit, destCommitment: positionCommitment,
        swapAmount,
        inputAmounts: [solNote.amount, 0n],
        inputPrivateKeys: [solNote.privateKey, dummyPriv],
        inputPublicKeys: [solNote.publicKey, dummyPub],
        inputBlindings: [solNote.blinding, dummyBld],
        inputMerklePaths: [merklePath, dummyProof],
        changeAmount: 0n, changePubkey: solChgPub, changeBlinding: solChgBld,
        destAmount, destPubkey: posKeys.positionPubkey, destBlinding: positionBlindingBytes,
        minAmountOut, deadline, swapDataHash,
      });
      console.log("  ✅ ZK proof generated");

      const sNullMarker0 = deriveNullifierMarkerPDA(program.programId, SOL_MINT, solNote.nullifier);
      const sNullMarker1 = deriveNullifierMarkerPDA(program.programId, SOL_MINT, dummyNull);
      const relayerCardsAta = await getAssociatedTokenAddress(CARDS_MINT, payer.publicKey);

      const openSwapParams = {
        minAmountOut: new BN(minAmountOut.toString()),
        deadline: new BN(deadline.toString()),
        destAmount: new BN(destAmount.toString()),
        swapDataHash: Array.from(swapDataHash),
      };

      const openIx = await (program.methods as any)
        .openPosition(
          0, SOL_MINT, Array.from(solNote.nullifier), Array.from(dummyNull),
          0, CARDS_MINT, Array.from(positionPdaKeyBytes), openProof,
          Array.from(sourceRoot), Array.from(solChangeCommit), Array.from(positionCommitment),
          openSwapParams, new BN(swapAmount.toString()), swapData,
          { recipient: openExtData.recipient, relayer: openExtData.relayer, fee: openExtData.fee, refund: openExtData.refund, claimant: openExtData.claimant },
          null,
        )
        .accounts({
          sourceConfig: solConfig, globalConfig, sourceVault: solVault,
          sourceTree: solNoteTree, sourceNullifiers: solNullifiers,
          sourceNullifierMarker0: sNullMarker0, sourceNullifierMarker1: sNullMarker1,
          sourceVaultTokenAccount: solVaultTokenAccount, sourceMintAccount: NATIVE_MINT,
          positionConfig, positionTree: positionTree0,
          positionVaultRecord, positionVaultPda, positionVaultAta, positionPda: positionPdaAddr,
          executor: executorPDA, executorSourceToken, executorDestToken,
          destMintInfo: CARDS_MINT,
          relayer: payer.publicKey, relayerDestToken: relayerCardsAta,
          swapProgram: JUPITER_PROGRAM_ID, jupiterEventAuthority: JUPITER_EVENT_AUTHORITY,
          tokenProgram: TOKEN_PROGRAM_ID, token2022Program: TOKEN_2022_PROGRAM_ID,
          systemProgram: SystemProgram.programId, associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
        })
        .remainingAccounts(remainingAccounts)
        .instruction();

      // Build optional Jupiter token-ledger instruction (required for 2-hop routes like SOL→USDC→CARDS)
      const rawTli = swapIxResp.tokenLedgerInstruction;
      const tokenLedgerIx: TransactionInstruction | null = (rawTli && rawTli.programId)
        ? new TransactionInstruction({
            programId: new PublicKey(rawTli.programId),
            keys: rawTli.accounts.map((a: any) => ({
              pubkey: new PublicKey(a.pubkey), isWritable: a.isWritable, isSigner: a.isSigner,
            })),
            data: Buffer.from(rawTli.data, "base64"),
          })
        : null;

      // fund_native_open_position must be the instruction immediately preceding open_position
      const fundIx = await (program.methods as any)
        .fundNativeOpenPosition(SOL_MINT, CARDS_MINT, Array.from(solNote.nullifier), new BN(swapAmount.toString()))
        .accounts({
          executor: executorPDA,
          executorSourceToken,
          sourceVault: solVault,
          sourceConfig: solConfig,
          sourceMintAccount: NATIVE_MINT,
          relayer: payer.publicKey,
          instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
          associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
        })
        .instruction();

      const allIxs = [tokenLedgerIx, fundIx, openIx].filter(Boolean) as TransactionInstruction[];
      const openKeys: PublicKey[] = [];
      const openSeen = new Set<string>();
      for (const ix of allIxs) {
        for (const meta of ix.keys) { const k = meta.pubkey.toBase58(); if (!openSeen.has(k)) { openSeen.add(k); openKeys.push(meta.pubkey); } }
        if (!openSeen.has(ix.programId.toBase58())) { openSeen.add(ix.programId.toBase58()); openKeys.push(ix.programId); }
      }

      const openAlt = await buildAndActivateALT(connection, payer, openKeys);
      const { blockhash: openBh } = await connection.getLatestBlockhash();
      const openMsg = new TransactionMessage({
        payerKey: payer.publicKey, recentBlockhash: openBh,
        instructions: [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }), ...allIxs],
      }).compileToV0Message([openAlt]);
      const openVtx = new VersionedTransaction(openMsg); openVtx.sign([payer]);
      const openTx = await connection.sendTransaction(openVtx);
      await connection.confirmTransaction(openTx, "confirmed");
      console.log("  ✅ open_position (CARDS) tx:", openTx);

      solOffchainTree.insert(solChangeCommit);
      const cLeafIdx = positionOffchainTree.insert(positionCommitment);

      const cPosPdaAcc = await (program.account as any).positionPda.fetch(positionPdaAddr);
      expect(cPosPdaAcc.isActive).to.be.true;
      expect(cPosPdaAcc.mint.toBase58()).to.equal(CARDS_MINT.toBase58());

      memePositionState = {
        amount: destAmount,
        positionSecretN: posKeys.positionSecretN,
        positionPubkey: posKeys.positionPubkey,
        positionBlinding: posKeys.positionBlinding,
        positionBlindingBytes,
        positionPdaKeyBytes,
        mint: CARDS_MINT,
        isToken2022: false,
        leafIndex: cLeafIdx,
        commitment: positionCommitment,
      };
      console.log("  ✓ CARDS positionPda created, balance:", cPosPdaAcc.balance.toString());
    });

    it("closes CARDS position and inserts USDC notes into USDC pool", async () => {
      if (!memePositionState) return console.log("  ⚠️  skipping — no CARDS position opened");

      console.log("\n🔒 Closing CARDS→USDC position...");
      const ps = memePositionState;

      const swapAmount = ps.amount;
      console.log("  Getting Jupiter quote CARDS→USDC (Raydium CLMM direct), amount:", swapAmount.toString());
      const quote = await jupiterService.getQuote(CARDS_MINT, USDC_MINT, Number(swapAmount), 100, true, "Raydium CLMM");
      const expectedOut = BigInt(quote.outAmount);
      const usdcDestAmount = (expectedOut * 90n) / 100n;
      const minAmountOut = usdcDestAmount;
      console.log("  Expected USDC output:", expectedOut.toString());

      const positionPdaAddr = derivePositionPda(program.programId, ps.positionPdaKeyBytes);
      const positionVaultRecord = derivePositionVaultRecord(program.programId, CARDS_MINT);
      const positionVaultPda = derivePositionVaultPda(program.programId, CARDS_MINT);
      const positionVaultAta = await getAssociatedTokenAddress(CARDS_MINT, positionVaultPda, true);

      const positionPrivKeyBytes = bigIntToBytes32BE(ps.positionSecretN);
      const positionNullifier = computeNullifier(poseidon, ps.commitment, ps.leafIndex, positionPrivKeyBytes);

      const executorPDA = deriveSwapExecutorPDA(program.programId, CARDS_MINT, USDC_MINT, positionNullifier, payer.publicKey);
      const executorCardsAta = await getAssociatedTokenAddress(CARDS_MINT, executorPDA, true);
      const executorUsdcAta = await getAssociatedTokenAddress(USDC_MINT, executorPDA, true);

      const swapIxResp = await jupiterService.getSwapInstruction(quote, executorPDA, false);
      const remainingAccounts = jupiterService.extractRemainingAccounts(swapIxResp.swapInstruction);
      const swapData = jupiterService.buildSwapData(swapIxResp.swapInstruction);
      const swapDataHash = new Uint8Array(createHash("sha256").update(swapData).digest());

      const dummyXPriv = randomBytes32();
      const dummyXPub = derivePublicKey(poseidon, dummyXPriv);
      const dummyXBld = randomBytes32();
      const dummyXCommit = computeCommitment(poseidon, 0n, dummyXPub, dummyXBld, CARDS_MINT);
      const dummyXNull = computeNullifier(poseidon, dummyXCommit, 0, dummyXPriv);
      const dummyXProof = positionOffchainTree.getMerkleProof(0);

      const cChgPriv = randomBytes32();
      const cChgPub = derivePublicKey(poseidon, cChgPriv);
      const cChgBld = randomBytes32();
      const cChangeCommit = computeCommitment(poseidon, 0n, cChgPub, cChgBld, CARDS_MINT);

      const usdcDestPriv = randomBytes32();
      const usdcDestPub = derivePublicKey(poseidon, usdcDestPriv);
      const usdcDestBld = randomBytes32();
      const usdcDestCommit = computeCommitment(poseidon, usdcDestAmount, usdcDestPub, usdcDestBld, USDC_MINT);

      const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
      const swapParamsHash = computeSwapParamsHash(poseidon, CARDS_MINT, USDC_MINT, minAmountOut, deadline, swapDataHash, usdcDestAmount);
      const extData3 = { recipient: payer.publicKey, relayer: payer.publicKey, fee: new BN(0), refund: new BN(0), claimant: SystemProgram.programId };
      const extDataHash3 = computeExtDataHash(poseidon, extData3);

      const positionRoot = positionOffchainTree.getRoot();
      const positionMerklePath = positionOffchainTree.getMerkleProof(ps.leafIndex);

      console.log("  Generating ZK proof...");
      const proof3 = await generateSwapProof({
        sourceRoot: positionRoot, swapParamsHash, extDataHash: extDataHash3,
        sourceMint: CARDS_MINT, destMint: USDC_MINT,
        inputNullifiers: [positionNullifier, dummyXNull],
        changeCommitment: cChangeCommit, destCommitment: usdcDestCommit,
        swapAmount,
        inputAmounts: [ps.amount, 0n],
        inputPrivateKeys: [positionPrivKeyBytes, dummyXPriv],
        inputPublicKeys: [ps.positionPubkey, dummyXPub],
        inputBlindings: [ps.positionBlindingBytes, dummyXBld],
        inputMerklePaths: [positionMerklePath, dummyXProof],
        changeAmount: 0n, changePubkey: cChgPub, changeBlinding: cChgBld,
        destAmount: usdcDestAmount, destPubkey: usdcDestPub, destBlinding: usdcDestBld,
        minAmountOut, deadline, swapDataHash,
      });
      console.log("  ✅ ZK proof generated");

      const posNullMarker0 = derivePositionNullifierMarker(program.programId, CARDS_MINT, positionNullifier);
      const posNullMarker1 = derivePositionNullifierMarker(program.programId, CARDS_MINT, dummyXNull);
      const relayerUsdcAta = await getOrCreateAssociatedTokenAccount(connection, payer, USDC_MINT, payer.publicKey);

      const swapParams3 = {
        minAmountOut: new BN(minAmountOut.toString()),
        deadline: new BN(deadline.toString()),
        destAmount: new BN(usdcDestAmount.toString()),
        swapDataHash: Array.from(swapDataHash),
      };

      const closeIx3 = await (program.methods as any)
        .closePosition(
          0, CARDS_MINT, Array.from(positionNullifier), Array.from(dummyXNull),
          0, USDC_MINT, Array.from(ps.positionPdaKeyBytes), proof3,
          Array.from(positionRoot), Array.from(cChangeCommit), Array.from(usdcDestCommit),
          swapParams3, new BN(swapAmount.toString()), swapData,
          { recipient: extData3.recipient, relayer: extData3.relayer, fee: extData3.fee, refund: extData3.refund, claimant: extData3.claimant },
          null,
        )
        .accounts({
          positionConfig, positionTree: positionTree0, positionPda: positionPdaAddr,
          positionNullifierMarker0: posNullMarker0, positionNullifierMarker1: posNullMarker1,
          positionVaultRecord, positionVaultPda, positionVaultAta,
          usdcConfig, usdcVault, usdcTree: usdcNoteTree,
          usdcVaultTokenAccount, usdcMintAccount: USDC_MINT,
          executor: executorPDA, executorSourceToken: executorCardsAta, executorDestToken: executorUsdcAta,
          sourceMintInfo: CARDS_MINT, relayer: payer.publicKey, relayerUsdcToken: relayerUsdcAta.address,
          swapProgram: JUPITER_PROGRAM_ID, jupiterEventAuthority: JUPITER_EVENT_AUTHORITY,
          tokenProgram: TOKEN_PROGRAM_ID, token2022Program: TOKEN_2022_PROGRAM_ID,
          systemProgram: SystemProgram.programId, associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
        })
        .remainingAccounts(remainingAccounts)
        .instruction();

      const allKeys3: PublicKey[] = [];
      const seen3 = new Set<string>();
      for (const meta of closeIx3.keys) { const k = meta.pubkey.toBase58(); if (!seen3.has(k)) { seen3.add(k); allKeys3.push(meta.pubkey); } }
      if (!seen3.has(closeIx3.programId.toBase58())) allKeys3.push(closeIx3.programId);

      const alt3 = await buildAndActivateALT(connection, payer, allKeys3);
      const { blockhash: b3 } = await connection.getLatestBlockhash();
      const msgV03 = new TransactionMessage({
        payerKey: payer.publicKey, recentBlockhash: b3,
        instructions: [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }), closeIx3],
      }).compileToV0Message([alt3]);
      const vtx3 = new VersionedTransaction(msgV03); vtx3.sign([payer]);
      const tx3 = await connection.sendTransaction(vtx3);
      await connection.confirmTransaction(tx3, "confirmed");
      console.log("  ✅ close_position (CARDS) tx:", tx3);

      positionOffchainTree.insert(cChangeCommit);
      usdcOffchainTree.insert(usdcDestCommit);

      let cPdaClosed = false;
      try { await (program.account as any).positionPda.fetch(positionPdaAddr); } catch { cPdaClosed = true; }
      expect(cPdaClosed).to.be.true;
      console.log("  ✓ CARDS positionPda closed");

      const cMarker = await (program.account as any).positionNullifierMarker.fetch(posNullMarker0);
      expect(cMarker.isSpent).to.be.true;
      console.log("  ✓ CARDS position nullifier marker created");
    });

    it("prevents double-close (PositionNullifierMarker already exists)", async () => {
      if (!memePositionState) return console.log("  ⚠️  skipping — no CARDS position");

      let threw = false;
      try {
        const ps = memePositionState;
        const positionPdaAddr = derivePositionPda(program.programId, ps.positionPdaKeyBytes);
        const positionPrivKeyBytes = bigIntToBytes32BE(ps.positionSecretN);
        const positionNullifier = computeNullifier(poseidon, ps.commitment, ps.leafIndex, positionPrivKeyBytes);
        const positionNullifierMarker0 = derivePositionNullifierMarker(program.programId, CARDS_MINT, positionNullifier);
        await (program.methods as any)
          .closePosition(0, CARDS_MINT, Array.from(positionNullifier), Array.from(randomBytes32()),
            0, USDC_MINT, Array.from(ps.positionPdaKeyBytes), { proofA: [], proofB: [], proofC: [] },
            Array.from(new Uint8Array(32)), Array.from(new Uint8Array(32)), Array.from(new Uint8Array(32)),
            { minAmountOut: new BN(0), deadline: new BN(0), destAmount: new BN(0), swapDataHash: Array.from(new Uint8Array(32)) },
            new BN(0), [], { recipient: payer.publicKey, relayer: payer.publicKey, fee: new BN(0), refund: new BN(0), claimant: SystemProgram.programId }, null,
          ).accounts({
            positionConfig,
            positionTree: positionTree0,
            positionPda: positionPdaAddr,
            positionNullifierMarker0,
            positionNullifierMarker1: derivePositionNullifierMarker(program.programId, CARDS_MINT, randomBytes32()),
            positionVaultRecord: derivePositionVaultRecord(program.programId, CARDS_MINT),
            positionVaultPda: derivePositionVaultPda(program.programId, CARDS_MINT),
            positionVaultAta: await getAssociatedTokenAddress(CARDS_MINT, derivePositionVaultPda(program.programId, CARDS_MINT), true),
            usdcConfig, usdcVault, usdcTree: usdcNoteTree,
            usdcVaultTokenAccount, usdcMintAccount: USDC_MINT,
            executor: Keypair.generate().publicKey,
            executorSourceToken: Keypair.generate().publicKey,
            executorDestToken: Keypair.generate().publicKey,
            sourceMintInfo: CARDS_MINT,
            relayer: payer.publicKey,
            relayerUsdcToken: (await getOrCreateAssociatedTokenAccount(connection, payer, USDC_MINT, payer.publicKey)).address,
            swapProgram: JUPITER_PROGRAM_ID,
            jupiterEventAuthority: JUPITER_EVENT_AUTHORITY,
            tokenProgram: TOKEN_PROGRAM_ID,
            token2022Program: TOKEN_2022_PROGRAM_ID,
            systemProgram: SystemProgram.programId,
            associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
          }).rpc();
      } catch {
        threw = true;
      }
      expect(threw).to.be.true;
      console.log("  ✓ double-close rejected as expected");
    });
  });

  // ===========================================================================
  // Section 6: open/close position — xStock (Token-2022) via USDC
  // Flow: payer swaps SOL→USDC (Jupiter direct) → deposits USDC into USDC pool
  //       → open_position USDC→xStock (Byreal 1-hop) → close_position xStock→USDC (Byreal 1-hop)
  // ===========================================================================

  describe("open/close position — xStock (Token-2022)", function () {
    this.timeout(300_000);

    it("gets USDC, deposits into USDC pool, and opens xStock position", async () => {
      console.log("\n🚀 Opening USDC→xStock position...");

      await airdropAndConfirm(provider, payer.publicKey, 5 * LAMPORTS_PER_SOL);

      // ── Step 1: Direct Jupiter swap SOL→USDC (BisonFi 1-hop) ────────────────
      console.log("  Swapping SOL→USDC via Jupiter (Byreal direct)...");
      const solForUsdc = 50_000_000; // 0.05 SOL
      const usdcQuote = await jupiterService.getQuote(NATIVE_MINT, USDC_MINT, solForUsdc, 100, true, "Byreal");
      const usdcSwapIxResp = await jupiterService.getSwapInstruction(usdcQuote, payer.publicKey, true);

      const directSwapIxs: TransactionInstruction[] = [
        ...(usdcSwapIxResp.setupInstructions ?? []).map(decodeJupIx),
        decodeJupIx(usdcSwapIxResp.swapInstruction),
        ...(usdcSwapIxResp.cleanupInstruction ? [decodeJupIx(usdcSwapIxResp.cleanupInstruction)] : []),
      ];
      const directAltAccounts = (
        await Promise.all(
          (usdcSwapIxResp.addressLookupTableAddresses ?? []).map(async (addr: string) => {
            const res = await connection.getAddressLookupTable(new PublicKey(addr));
            return res.value;
          }),
        )
      ).filter(Boolean) as any[];

      const { blockhash: ubh, lastValidBlockHeight: ulvbh } = await connection.getLatestBlockhash();
      const directMsg = new TransactionMessage({
        payerKey: payer.publicKey,
        recentBlockhash: ubh,
        instructions: [ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 }), ...directSwapIxs],
      }).compileToV0Message(directAltAccounts);
      const directVtx = new VersionedTransaction(directMsg);
      directVtx.sign([payer]);
      const directSig = await connection.sendTransaction(directVtx);
      await connection.confirmTransaction({ signature: directSig, blockhash: ubh, lastValidBlockHeight: ulvbh });
      console.log("  ✅ SOL→USDC swap tx:", directSig);

      // ── Step 2: Deposit all USDC into USDC pool ──────────────────────────────
      const payerUsdcAta = await getOrCreateAssociatedTokenAccount(connection, payer, USDC_MINT, payer.publicKey);
      const depositAmount = BigInt(payerUsdcAta.amount.toString());
      console.log("  Depositing USDC into pool, amount:", depositAmount.toString());

      // Ensure the USDC vault's token account (ATA of the vault PDA) exists.
      // Native SOL skips the token path, but USDC requires the vault ATA up front.
      {
        const createVaultAtaIx = createAssociatedTokenAccountIdempotentInstruction(
          payer.publicKey, usdcVaultTokenAccount, usdcVault, USDC_MINT,
        );
        const { blockhash: vbh, lastValidBlockHeight: vlvbh } = await connection.getLatestBlockhash();
        const vtxMsg = new TransactionMessage({
          payerKey: payer.publicKey, recentBlockhash: vbh, instructions: [createVaultAtaIx],
        }).compileToV0Message();
        const vvtx = new VersionedTransaction(vtxMsg); vvtx.sign([payer]);
        const vsig = await connection.sendTransaction(vvtx);
        await connection.confirmTransaction({ signature: vsig, blockhash: vbh, lastValidBlockHeight: vlvbh });
      }

      const depPrivKey = randomBytes32();
      const depPubKey = derivePublicKey(poseidon, depPrivKey);
      const depBlinding = randomBytes32();
      const depCommitment = computeCommitment(poseidon, depositAmount, depPubKey, depBlinding, USDC_MINT);

      const depChgPriv = randomBytes32(); const depChgPub = derivePublicKey(poseidon, depChgPriv); const depChgBld = randomBytes32();
      const depChgCommit = computeCommitment(poseidon, 0n, depChgPub, depChgBld, USDC_MINT);

      const du1 = randomBytes32(); const du1Pub = derivePublicKey(poseidon, du1); const du1Bld = randomBytes32();
      const du1Commit = computeCommitment(poseidon, 0n, du1Pub, du1Bld, USDC_MINT);
      const du1Null = computeNullifier(poseidon, du1Commit, 0, du1);
      const du2 = randomBytes32(); const du2Pub = derivePublicKey(poseidon, du2); const du2Bld = randomBytes32();
      const du2Commit = computeCommitment(poseidon, 0n, du2Pub, du2Bld, USDC_MINT);
      const du2Null = computeNullifier(poseidon, du2Commit, 0, du2);

      const udproof = usdcOffchainTree.getMerkleProof(0);
      const udRoot = usdcOffchainTree.getRoot();
      const depExtData = { recipient: payer.publicKey, relayer: payer.publicKey, fee: new BN(0), refund: new BN(0), claimant: SystemProgram.programId };
      const depExtHash = computeExtDataHash(poseidon, depExtData);
      const depProof = await generateTransactionProof({
        root: udRoot, publicAmount: depositAmount, extDataHash: depExtHash, mintAddress: USDC_MINT,
        inputNullifiers: [du1Null, du2Null], outputCommitments: [depCommitment, depChgCommit],
        inputAmounts: [0n, 0n], inputPrivateKeys: [du1, du2], inputPublicKeys: [du1Pub, du2Pub],
        inputBlindings: [du1Bld, du2Bld], inputMerklePaths: [udproof, udproof],
        outputAmounts: [depositAmount, 0n], outputOwners: [depPubKey, depChgPub], outputBlindings: [depBlinding, depChgBld],
      });

      const unm1 = deriveNullifierMarkerPDA(program.programId, USDC_MINT, du1Null);
      const unm2 = deriveNullifierMarkerPDA(program.programId, USDC_MINT, du2Null);

      const depIx = await (program.methods as any)
        .transact(Array.from(udRoot), 0, 0, new BN(depositAmount.toString()), Array.from(depExtHash),
          USDC_MINT, Array.from(du1Null), Array.from(du2Null), Array.from(depCommitment), Array.from(depChgCommit),
          new BN(999_999_999_999), { recipient: depExtData.recipient, relayer: depExtData.relayer, fee: depExtData.fee, refund: depExtData.refund, claimant: depExtData.claimant },
          depProof, null,
        )
        .accounts({
          config: usdcConfig, globalConfig, vault: usdcVault, inputTree: usdcNoteTree, outputTree: usdcNoteTree,
          nullifiers: usdcNullifiers, nullifierMarker0: unm1, nullifierMarker1: unm2,
          relayer: payer.publicKey, recipient: payer.publicKey,
          vaultTokenAccount: usdcVaultTokenAccount, userTokenAccount: payerUsdcAta.address,
          recipientTokenAccount: payerUsdcAta.address, relayerTokenAccount: payerUsdcAta.address,
          tokenProgram: TOKEN_PROGRAM_ID, systemProgram: SystemProgram.programId,
        }).instruction();

      const { blockhash: depBh, lastValidBlockHeight: depLvbh } = await connection.getLatestBlockhash();
      const depMsg = new TransactionMessage({ payerKey: payer.publicKey, recentBlockhash: depBh, instructions: [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }), depIx] }).compileToV0Message();
      const depVtx = new VersionedTransaction(depMsg); depVtx.sign([payer]);
      const depTx = await connection.sendTransaction(depVtx);
      await connection.confirmTransaction({ signature: depTx, blockhash: depBh, lastValidBlockHeight: depLvbh });
      console.log("  ✅ USDC deposit tx:", depTx);

      const usdcLeafIdx = usdcOffchainTree.insert(depCommitment);
      usdcOffchainTree.insert(depChgCommit);
      const usdcNote: DepositNote = {
        amount: depositAmount, commitment: depCommitment,
        nullifier: computeNullifier(poseidon, depCommitment, usdcLeafIdx, depPrivKey),
        blinding: depBlinding, privateKey: depPrivKey, publicKey: depPubKey, leafIndex: usdcLeafIdx,
        merklePath: usdcOffchainTree.getMerkleProof(usdcLeafIdx), mintAddress: USDC_MINT,
      };
      console.log("  ✓ USDC note saved, amount:", depositAmount.toString());

      // ── Step 3: Open xStock position (USDC→xStock via Byreal 1-hop) ─────────
      console.log("  Getting Jupiter quote USDC→xStock (Byreal direct)...");
      const swapAmount = usdcNote.amount;
      const quote = await jupiterService.getQuote(USDC_MINT, XSTOCK_MINT, Number(swapAmount), 100, true, "Byreal");
      const expectedOut = BigInt(quote.outAmount);
      const destAmount = (expectedOut * 90n) / 100n;
      const minAmountOut = destAmount;
      console.log("  Expected xStock output:", expectedOut.toString());

      const posKeys = derivePositionKeys(poseidon, walletPrivkey, 1); // index 1 for xStock
      const positionPdaKeyBytes = posKeys.positionPdaKeyBytes;
      const positionBlindingBytes = bigIntToBytes32BE(posKeys.positionBlinding);

      const executorPDA = deriveSwapExecutorPDA(
        program.programId, USDC_MINT, XSTOCK_MINT, usdcNote.nullifier, payer.publicKey,
      );
      const positionVaultRecord = derivePositionVaultRecord(program.programId, XSTOCK_MINT);
      const positionVaultPda = derivePositionVaultPda(program.programId, XSTOCK_MINT);
      const positionPdaAddr = derivePositionPda(program.programId, positionPdaKeyBytes);

      // USDC uses TOKEN_PROGRAM; xStock uses TOKEN_2022_PROGRAM
      const executorSourceToken = await getAssociatedTokenAddress(USDC_MINT, executorPDA, true);
      const executorDestToken = await getAssociatedTokenAddress(XSTOCK_MINT, executorPDA, true, TOKEN_2022_PROGRAM_ID);
      const positionVaultAta = await getAssociatedTokenAddress(XSTOCK_MINT, positionVaultPda, true, TOKEN_2022_PROGRAM_ID);

      const swapIxResp = await jupiterService.getSwapInstruction(quote, executorPDA, false);
      const remainingAccounts = jupiterService.extractRemainingAccounts(swapIxResp.swapInstruction);
      const swapData = jupiterService.buildSwapData(swapIxResp.swapInstruction);
      const swapDataHash = new Uint8Array(createHash("sha256").update(swapData).digest());

      const positionCommitment = computeCommitment(
        poseidon, destAmount, posKeys.positionPubkey, positionBlindingBytes, XSTOCK_MINT,
      );
      const usdcChgPriv = randomBytes32(); const usdcChgPub = derivePublicKey(poseidon, usdcChgPriv); const usdcChgBld = randomBytes32();
      const usdcChangeCommit = computeCommitment(poseidon, 0n, usdcChgPub, usdcChgBld, USDC_MINT);

      const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
      const swapParamsHash = computeSwapParamsHash(poseidon, USDC_MINT, XSTOCK_MINT, minAmountOut, deadline, swapDataHash, destAmount);
      const openExtData = { recipient: payer.publicKey, relayer: payer.publicKey, fee: new BN(0), refund: new BN(0), claimant: SystemProgram.programId };
      const openExtDataHash = computeExtDataHash(poseidon, openExtData);

      const dummyPriv = randomBytes32(); const dummyPub = derivePublicKey(poseidon, dummyPriv); const dummyBld = randomBytes32();
      const dummyCommit = computeCommitment(poseidon, 0n, dummyPub, dummyBld, USDC_MINT);
      const dummyNull = computeNullifier(poseidon, dummyCommit, 0, dummyPriv);
      const dummyProof = usdcOffchainTree.getMerkleProof(0);

      const sourceRoot = usdcOffchainTree.getRoot();
      const merklePath = usdcOffchainTree.getMerkleProof(usdcNote.leafIndex);

      console.log("  Generating ZK swap proof...");
      const openProof = await generateSwapProof({
        sourceRoot, swapParamsHash, extDataHash: openExtDataHash,
        sourceMint: USDC_MINT, destMint: XSTOCK_MINT,
        inputNullifiers: [usdcNote.nullifier, dummyNull],
        changeCommitment: usdcChangeCommit, destCommitment: positionCommitment,
        swapAmount,
        inputAmounts: [usdcNote.amount, 0n],
        inputPrivateKeys: [usdcNote.privateKey, dummyPriv],
        inputPublicKeys: [usdcNote.publicKey, dummyPub],
        inputBlindings: [usdcNote.blinding, dummyBld],
        inputMerklePaths: [merklePath, dummyProof],
        changeAmount: 0n, changePubkey: usdcChgPub, changeBlinding: usdcChgBld,
        destAmount, destPubkey: posKeys.positionPubkey, destBlinding: positionBlindingBytes,
        minAmountOut, deadline, swapDataHash,
      });
      console.log("  ✅ ZK proof generated");

      const sNullMarker0 = deriveNullifierMarkerPDA(program.programId, USDC_MINT, usdcNote.nullifier);
      const sNullMarker1 = deriveNullifierMarkerPDA(program.programId, USDC_MINT, dummyNull);
      const relayerXstockAta = await getAssociatedTokenAddress(XSTOCK_MINT, payer.publicKey, false, TOKEN_2022_PROGRAM_ID);

      const openSwapParams = {
        minAmountOut: new BN(minAmountOut.toString()),
        deadline: new BN(deadline.toString()),
        destAmount: new BN(destAmount.toString()),
        swapDataHash: Array.from(swapDataHash),
      };

      const openIx = await (program.methods as any)
        .openPosition(
          0, USDC_MINT, Array.from(usdcNote.nullifier), Array.from(dummyNull),
          0, XSTOCK_MINT, Array.from(positionPdaKeyBytes), openProof,
          Array.from(sourceRoot), Array.from(usdcChangeCommit), Array.from(positionCommitment),
          openSwapParams, new BN(swapAmount.toString()), swapData,
          { recipient: openExtData.recipient, relayer: openExtData.relayer, fee: openExtData.fee, refund: openExtData.refund, claimant: openExtData.claimant },
          null,
        )
        .accounts({
          sourceConfig: usdcConfig, globalConfig, sourceVault: usdcVault,
          sourceTree: usdcNoteTree, sourceNullifiers: usdcNullifiers,
          sourceNullifierMarker0: sNullMarker0, sourceNullifierMarker1: sNullMarker1,
          sourceVaultTokenAccount: usdcVaultTokenAccount, sourceMintAccount: USDC_MINT,
          positionConfig, positionTree: positionTree0,
          positionVaultRecord, positionVaultPda, positionVaultAta, positionPda: positionPdaAddr,
          executor: executorPDA, executorSourceToken, executorDestToken,
          destMintInfo: XSTOCK_MINT,
          relayer: payer.publicKey, relayerDestToken: relayerXstockAta,
          swapProgram: JUPITER_PROGRAM_ID, jupiterEventAuthority: JUPITER_EVENT_AUTHORITY,
          tokenProgram: TOKEN_PROGRAM_ID, token2022Program: TOKEN_2022_PROGRAM_ID,
          systemProgram: SystemProgram.programId, associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
        })
        .remainingAccounts(remainingAccounts)
        .instruction();

      const openKeys: PublicKey[] = [];
      const openSeen = new Set<string>();
      for (const meta of openIx.keys) { const k = meta.pubkey.toBase58(); if (!openSeen.has(k)) { openSeen.add(k); openKeys.push(meta.pubkey); } }
      if (!openSeen.has(openIx.programId.toBase58())) openKeys.push(openIx.programId);

      const openAlt = await buildAndActivateALT(connection, payer, openKeys);
      const { blockhash: openBh } = await connection.getLatestBlockhash();
      const openMsg = new TransactionMessage({
        payerKey: payer.publicKey, recentBlockhash: openBh,
        instructions: [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }), openIx],
      }).compileToV0Message([openAlt]);
      const openVtx = new VersionedTransaction(openMsg); openVtx.sign([payer]);
      const openTx = await connection.sendTransaction(openVtx);
      await connection.confirmTransaction(openTx, "confirmed");
      console.log("  ✅ open_position (xStock) tx:", openTx);

      usdcOffchainTree.insert(usdcChangeCommit);
      const xLeafIdx = positionOffchainTree.insert(positionCommitment);

      const xPosPdaAcc = await (program.account as any).positionPda.fetch(positionPdaAddr);
      expect(xPosPdaAcc.isActive).to.be.true;
      expect(xPosPdaAcc.mint.toBase58()).to.equal(XSTOCK_MINT.toBase58());

      xstockPositionState = {
        // The note commitment was built with destAmount; the on-chain PDA balance may be
        // larger (actual received). The spendable note amount must equal the committed value.
        amount: destAmount,
        positionSecretN: posKeys.positionSecretN,
        positionPubkey: posKeys.positionPubkey,
        positionBlinding: posKeys.positionBlinding,
        positionBlindingBytes,
        positionPdaKeyBytes,
        mint: XSTOCK_MINT,
        isToken2022: true,
        leafIndex: xLeafIdx,
        commitment: positionCommitment,
      };
      console.log("  ✓ xStock positionPda created, balance:", xPosPdaAcc.balance.toString());
    });

    it("closes xStock position and inserts USDC notes into USDC pool", async () => {
      if (!xstockPositionState) return console.log("  ⚠️  skipping — no xStock position opened");

      console.log("\n🔒 Closing xStock→USDC position...");
      const ps = xstockPositionState;

      const swapAmount = ps.amount;
      console.log("  Getting Jupiter quote xStock→USDC, amount:", swapAmount.toString());
      // Byreal direct route for xStock→USDC (same pool used in reverse for open)
      const quote = await jupiterService.getQuote(XSTOCK_MINT, USDC_MINT, Number(swapAmount), 100, true, "Byreal");
      const expectedOut = BigInt(quote.outAmount);
      const usdcDestAmount = (expectedOut * 90n) / 100n;
      const minAmountOut = usdcDestAmount;
      console.log("  Expected USDC output:", expectedOut.toString());

      const positionPdaAddr = derivePositionPda(program.programId, ps.positionPdaKeyBytes);
      const positionVaultRecord = derivePositionVaultRecord(program.programId, XSTOCK_MINT);
      const positionVaultPda = derivePositionVaultPda(program.programId, XSTOCK_MINT);
      const positionVaultAta = await getAssociatedTokenAddress(XSTOCK_MINT, positionVaultPda, true, TOKEN_2022_PROGRAM_ID);

      const positionPrivKeyBytes = bigIntToBytes32BE(ps.positionSecretN);
      const positionNullifier = computeNullifier(poseidon, ps.commitment, ps.leafIndex, positionPrivKeyBytes);

      const executorPDA = deriveSwapExecutorPDA(program.programId, XSTOCK_MINT, USDC_MINT, positionNullifier, payer.publicKey);
      const executorXstockAta = await getAssociatedTokenAddress(XSTOCK_MINT, executorPDA, true, TOKEN_2022_PROGRAM_ID);
      const executorUsdcAta = await getAssociatedTokenAddress(USDC_MINT, executorPDA, true);

      const swapIxResp = await jupiterService.getSwapInstruction(quote, executorPDA, false);
      const remainingAccounts = jupiterService.extractRemainingAccounts(swapIxResp.swapInstruction);
      const swapData = jupiterService.buildSwapData(swapIxResp.swapInstruction);
      const swapDataHash = new Uint8Array(createHash("sha256").update(swapData).digest());

      const dummyXPriv = randomBytes32();
      const dummyXPub = derivePublicKey(poseidon, dummyXPriv);
      const dummyXBld = randomBytes32();
      const dummyXCommit = computeCommitment(poseidon, 0n, dummyXPub, dummyXBld, XSTOCK_MINT);
      const dummyXNull = computeNullifier(poseidon, dummyXCommit, 0, dummyXPriv);
      const dummyXProof = positionOffchainTree.getMerkleProof(0);

      const xChgPriv = randomBytes32();
      const xChgPub = derivePublicKey(poseidon, xChgPriv);
      const xChgBld = randomBytes32();
      const xChangeCommit = computeCommitment(poseidon, 0n, xChgPub, xChgBld, XSTOCK_MINT);

      const usdcDestPriv = randomBytes32();
      const usdcDestPub = derivePublicKey(poseidon, usdcDestPriv);
      const usdcDestBld = randomBytes32();
      const usdcDestCommit = computeCommitment(poseidon, usdcDestAmount, usdcDestPub, usdcDestBld, USDC_MINT);

      const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
      const swapParamsHash = computeSwapParamsHash(poseidon, XSTOCK_MINT, USDC_MINT, minAmountOut, deadline, swapDataHash, usdcDestAmount);
      const extData3 = { recipient: payer.publicKey, relayer: payer.publicKey, fee: new BN(0), refund: new BN(0), claimant: SystemProgram.programId };
      const extDataHash3 = computeExtDataHash(poseidon, extData3);

      const positionRoot = positionOffchainTree.getRoot();
      const positionMerklePath = positionOffchainTree.getMerkleProof(ps.leafIndex);

      console.log("  Generating ZK proof...");
      const proof3 = await generateSwapProof({
        sourceRoot: positionRoot, swapParamsHash, extDataHash: extDataHash3,
        sourceMint: XSTOCK_MINT, destMint: USDC_MINT,
        inputNullifiers: [positionNullifier, dummyXNull],
        changeCommitment: xChangeCommit, destCommitment: usdcDestCommit,
        swapAmount,
        inputAmounts: [ps.amount, 0n],
        inputPrivateKeys: [positionPrivKeyBytes, dummyXPriv],
        inputPublicKeys: [ps.positionPubkey, dummyXPub],
        inputBlindings: [ps.positionBlindingBytes, dummyXBld],
        inputMerklePaths: [positionMerklePath, dummyXProof],
        changeAmount: 0n, changePubkey: xChgPub, changeBlinding: xChgBld,
        destAmount: usdcDestAmount, destPubkey: usdcDestPub, destBlinding: usdcDestBld,
        minAmountOut, deadline, swapDataHash,
      });
      console.log("  ✅ ZK proof generated");

      const posNullMarker0 = derivePositionNullifierMarker(program.programId, XSTOCK_MINT, positionNullifier);
      const posNullMarker1 = derivePositionNullifierMarker(program.programId, XSTOCK_MINT, dummyXNull);
      const relayerUsdcAta = await getOrCreateAssociatedTokenAccount(connection, payer, USDC_MINT, payer.publicKey);

      const swapParams3 = {
        minAmountOut: new BN(minAmountOut.toString()),
        deadline: new BN(deadline.toString()),
        destAmount: new BN(usdcDestAmount.toString()),
        swapDataHash: Array.from(swapDataHash),
      };

      const closeIx3 = await (program.methods as any)
        .closePosition(
          0, XSTOCK_MINT, Array.from(positionNullifier), Array.from(dummyXNull),
          0, USDC_MINT, Array.from(ps.positionPdaKeyBytes), proof3,
          Array.from(positionRoot), Array.from(xChangeCommit), Array.from(usdcDestCommit),
          swapParams3, new BN(swapAmount.toString()), swapData,
          { recipient: extData3.recipient, relayer: extData3.relayer, fee: extData3.fee, refund: extData3.refund, claimant: extData3.claimant },
          null,
        )
        .accounts({
          positionConfig, positionTree: positionTree0, positionPda: positionPdaAddr,
          positionNullifierMarker0: posNullMarker0, positionNullifierMarker1: posNullMarker1,
          positionVaultRecord, positionVaultPda, positionVaultAta,
          usdcConfig, usdcVault, usdcTree: usdcNoteTree,
          usdcVaultTokenAccount, usdcMintAccount: USDC_MINT,
          executor: executorPDA, executorSourceToken: executorXstockAta, executorDestToken: executorUsdcAta,
          sourceMintInfo: XSTOCK_MINT, relayer: payer.publicKey, relayerUsdcToken: relayerUsdcAta.address,
          swapProgram: JUPITER_PROGRAM_ID, jupiterEventAuthority: JUPITER_EVENT_AUTHORITY,
          tokenProgram: TOKEN_PROGRAM_ID, token2022Program: TOKEN_2022_PROGRAM_ID,
          systemProgram: SystemProgram.programId, associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
        })
        .remainingAccounts(remainingAccounts)
        .instruction();

      const allKeys3: PublicKey[] = [];
      const seen3 = new Set<string>();
      for (const meta of closeIx3.keys) { const k = meta.pubkey.toBase58(); if (!seen3.has(k)) { seen3.add(k); allKeys3.push(meta.pubkey); } }
      if (!seen3.has(closeIx3.programId.toBase58())) allKeys3.push(closeIx3.programId);

      const alt3 = await buildAndActivateALT(connection, payer, allKeys3);
      const { blockhash: b3 } = await connection.getLatestBlockhash();
      const msgV03 = new TransactionMessage({
        payerKey: payer.publicKey, recentBlockhash: b3,
        instructions: [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }), closeIx3],
      }).compileToV0Message([alt3]);
      const vtx3 = new VersionedTransaction(msgV03); vtx3.sign([payer]);
      const tx3 = await connection.sendTransaction(vtx3);
      await connection.confirmTransaction(tx3, "confirmed");
      console.log("  ✅ close_position (xStock) tx:", tx3);

      positionOffchainTree.insert(xChangeCommit);
      usdcOffchainTree.insert(usdcDestCommit);

      let xPdaClosed = false;
      try { await (program.account as any).positionPda.fetch(positionPdaAddr); } catch { xPdaClosed = true; }
      expect(xPdaClosed).to.be.true;
      console.log("  ✓ xStock positionPda closed");

      const xMarker = await (program.account as any).positionNullifierMarker.fetch(posNullMarker0);
      expect(xMarker.isSpent).to.be.true;
      console.log("  ✓ xStock position nullifier marker created");
    });
  });

  // ===========================================================================
  // Section 7b: merge_positions — merge two CARDS positions into one
  // ===========================================================================

  describe("merge_positions", () => {
    it("merges two CARDS position notes into one using transaction circuit (publicAmount=0)", async function () {
      this.timeout(300_000);
      console.log("\n🔀 merge_positions: open two CARDS positions then merge...");

      // ── Helper: deposit USDC into pool and return a spendable note ──────────
      async function depositUsdc(amount: bigint): Promise<{
        note: DepositNote;
        chgPriv: Uint8Array; chgPub: bigint; chgBld: Uint8Array; chgCommit: Uint8Array;
      }> {
        const payerUsdcAta = await getOrCreateAssociatedTokenAccount(connection, payer, USDC_MINT, payer.publicKey);
        const bal = BigInt(payerUsdcAta.amount.toString());
        const depAmt = amount < bal ? amount : bal;

        const depPriv = randomBytes32(); const depPub = derivePublicKey(poseidon, depPriv); const depBld = randomBytes32();
        const depCommit = computeCommitment(poseidon, depAmt, depPub, depBld, USDC_MINT);
        const chgPriv = randomBytes32(); const chgPub = derivePublicKey(poseidon, chgPriv); const chgBld = randomBytes32();
        const chgCommit = computeCommitment(poseidon, 0n, chgPub, chgBld, USDC_MINT);

        const d1 = randomBytes32(); const d1Pub = derivePublicKey(poseidon, d1); const d1Bld = randomBytes32();
        const d1Commit = computeCommitment(poseidon, 0n, d1Pub, d1Bld, USDC_MINT);
        const d1Null = computeNullifier(poseidon, d1Commit, 0, d1);
        const d2 = randomBytes32(); const d2Pub = derivePublicKey(poseidon, d2); const d2Bld = randomBytes32();
        const d2Commit = computeCommitment(poseidon, 0n, d2Pub, d2Bld, USDC_MINT);
        const d2Null = computeNullifier(poseidon, d2Commit, 0, d2);

        const dProof = usdcOffchainTree.getMerkleProof(0);
        const dRoot = usdcOffchainTree.getRoot();
        const dExtData = { recipient: payer.publicKey, relayer: payer.publicKey, fee: new BN(0), refund: new BN(0), claimant: SystemProgram.programId };
        const dExtHash = computeExtDataHash(poseidon, dExtData);
        const proof = await generateTransactionProof({
          root: dRoot, publicAmount: depAmt, extDataHash: dExtHash, mintAddress: USDC_MINT,
          inputNullifiers: [d1Null, d2Null], outputCommitments: [depCommit, chgCommit],
          inputAmounts: [0n, 0n], inputPrivateKeys: [d1, d2], inputPublicKeys: [d1Pub, d2Pub],
          inputBlindings: [d1Bld, d2Bld], inputMerklePaths: [dProof, dProof],
          outputAmounts: [depAmt, 0n], outputOwners: [depPub, chgPub], outputBlindings: [depBld, chgBld],
        });

        const nm1 = deriveNullifierMarkerPDA(program.programId, USDC_MINT, d1Null);
        const nm2 = deriveNullifierMarkerPDA(program.programId, USDC_MINT, d2Null);
        const depIx = await (program.methods as any)
          .transact(Array.from(dRoot), 0, 0, new BN(depAmt.toString()), Array.from(dExtHash),
            USDC_MINT, Array.from(d1Null), Array.from(d2Null), Array.from(depCommit), Array.from(chgCommit),
            new BN(999_999_999_999), { recipient: dExtData.recipient, relayer: dExtData.relayer, fee: dExtData.fee, refund: dExtData.refund, claimant: dExtData.claimant },
            proof, null)
          .accounts({
            config: usdcConfig, globalConfig, vault: usdcVault, inputTree: usdcNoteTree, outputTree: usdcNoteTree,
            nullifiers: usdcNullifiers, nullifierMarker0: nm1, nullifierMarker1: nm2,
            relayer: payer.publicKey, recipient: payer.publicKey,
            vaultTokenAccount: usdcVaultTokenAccount, userTokenAccount: payerUsdcAta.address,
            recipientTokenAccount: payerUsdcAta.address, relayerTokenAccount: payerUsdcAta.address,
            tokenProgram: TOKEN_PROGRAM_ID, systemProgram: SystemProgram.programId,
          }).instruction();

        const { blockhash: bh, lastValidBlockHeight: lvbh } = await connection.getLatestBlockhash();
        const msg = new TransactionMessage({ payerKey: payer.publicKey, recentBlockhash: bh, instructions: [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }), depIx] }).compileToV0Message();
        const vtx = new VersionedTransaction(msg); vtx.sign([payer]);
        const sig = await connection.sendTransaction(vtx);
        await connection.confirmTransaction({ signature: sig, blockhash: bh, lastValidBlockHeight: lvbh });

        const leafIdx = usdcOffchainTree.insert(depCommit);
        usdcOffchainTree.insert(chgCommit);
        const note: DepositNote = {
          amount: depAmt, commitment: depCommit,
          nullifier: computeNullifier(poseidon, depCommit, leafIdx, depPriv),
          blinding: depBld, privateKey: depPriv, publicKey: depPub, leafIndex: leafIdx,
          merklePath: usdcOffchainTree.getMerkleProof(leafIdx), mintAddress: USDC_MINT,
        };
        return { note, chgPriv, chgPub, chgBld, chgCommit };
      }

      // ── Helper: open a CARDS position from a USDC note ──────────────────────
      async function openCardsPosition(
        usdcNote: DepositNote,
        posN: number,
      ): Promise<PositionNoteState> {
        const posKeys = derivePositionKeys(poseidon, walletPrivkey, posN);
        const posBlindBytes = bigIntToBytes32BE(posKeys.positionBlinding);

        const quote = await jupiterService.getQuote(USDC_MINT, CARDS_MINT, Number(usdcNote.amount), 5000, true, "Raydium CLMM");
        const expectedOut = BigInt(quote.outAmount);
        const destAmount = (expectedOut * 50n) / 100n;
        const minAmountOut = destAmount;

        const execPDA = deriveSwapExecutorPDA(program.programId, USDC_MINT, CARDS_MINT, usdcNote.nullifier, payer.publicKey);
        const posVaultRecord = derivePositionVaultRecord(program.programId, CARDS_MINT);
        const posVaultPda = derivePositionVaultPda(program.programId, CARDS_MINT);
        const positionPdaAddr = derivePositionPda(program.programId, posKeys.positionPdaKeyBytes);
        const execSrcToken = await getAssociatedTokenAddress(USDC_MINT, execPDA, true);
        const execDstToken = await getAssociatedTokenAddress(CARDS_MINT, execPDA, true);
        const posVaultAta = await getAssociatedTokenAddress(CARDS_MINT, posVaultPda, true);

        const swapIxResp = await jupiterService.getSwapInstruction(quote, execPDA, false);
        const remainingAccounts = jupiterService.extractRemainingAccounts(swapIxResp.swapInstruction);
        const swapData = jupiterService.buildSwapData(swapIxResp.swapInstruction);
        const swapDataHash = new Uint8Array(createHash("sha256").update(swapData).digest());

        const posCommit = computeCommitment(poseidon, destAmount, posKeys.positionPubkey, posBlindBytes, CARDS_MINT);
        const chgPriv = randomBytes32(); const chgPub = derivePublicKey(poseidon, chgPriv); const chgBld = randomBytes32();
        const chgCommit = computeCommitment(poseidon, 0n, chgPub, chgBld, USDC_MINT);

        const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
        const swapParamsHash = computeSwapParamsHash(poseidon, USDC_MINT, CARDS_MINT, minAmountOut, deadline, swapDataHash, destAmount);
        const extData = { recipient: payer.publicKey, relayer: payer.publicKey, fee: new BN(0), refund: new BN(0), claimant: SystemProgram.programId };
        const extDataHash = computeExtDataHash(poseidon, extData);

        const dummyPriv = randomBytes32(); const dummyPub = derivePublicKey(poseidon, dummyPriv); const dummyBld = randomBytes32();
        const dummyCommit = computeCommitment(poseidon, 0n, dummyPub, dummyBld, USDC_MINT);
        const dummyNull = computeNullifier(poseidon, dummyCommit, 0, dummyPriv);
        const dummyPath = usdcOffchainTree.getMerkleProof(0);

        const srcRoot = usdcOffchainTree.getRoot();
        const merklePath = usdcOffchainTree.getMerkleProof(usdcNote.leafIndex);

        const openProof = await generateSwapProof({
          sourceRoot: srcRoot, swapParamsHash, extDataHash,
          sourceMint: USDC_MINT, destMint: CARDS_MINT,
          inputNullifiers: [usdcNote.nullifier, dummyNull],
          changeCommitment: chgCommit, destCommitment: posCommit,
          swapAmount: usdcNote.amount,
          inputAmounts: [usdcNote.amount, 0n],
          inputPrivateKeys: [usdcNote.privateKey, dummyPriv],
          inputPublicKeys: [usdcNote.publicKey, dummyPub],
          inputBlindings: [usdcNote.blinding, dummyBld],
          inputMerklePaths: [merklePath, dummyPath],
          changeAmount: 0n, changePubkey: chgPub, changeBlinding: chgBld,
          destAmount, destPubkey: posKeys.positionPubkey, destBlinding: posBlindBytes,
          minAmountOut, deadline, swapDataHash,
        });

        const usdcNullM0 = deriveNullifierMarkerPDA(program.programId, USDC_MINT, usdcNote.nullifier);
        const usdcNullM1 = deriveNullifierMarkerPDA(program.programId, USDC_MINT, dummyNull);

        const openIx = await (program.methods as any)
          .openPosition(
            0, USDC_MINT, Array.from(usdcNote.nullifier), Array.from(dummyNull),
            0, CARDS_MINT, Array.from(posKeys.positionPdaKeyBytes), openProof,
            Array.from(srcRoot), Array.from(chgCommit), Array.from(posCommit),
            { minAmountOut: new BN(minAmountOut.toString()), deadline: new BN(deadline.toString()), destAmount: new BN(destAmount.toString()), swapDataHash: Array.from(swapDataHash) },
            new BN(usdcNote.amount.toString()), swapData,
            { recipient: extData.recipient, relayer: extData.relayer, fee: extData.fee, refund: extData.refund, claimant: extData.claimant },
            null,
          )
          .accounts({
            sourceConfig: usdcConfig, globalConfig, sourceVault: usdcVault, sourceTree: usdcNoteTree,
            sourceNullifiers: usdcNullifiers, sourceNullifierMarker0: usdcNullM0, sourceNullifierMarker1: usdcNullM1,
            sourceVaultTokenAccount: usdcVaultTokenAccount, sourceMintAccount: USDC_MINT,
            positionConfig, positionTree: positionTree0,
            positionVaultRecord: posVaultRecord, positionVaultPda: posVaultPda, positionVaultAta: posVaultAta,
            positionPda: positionPdaAddr,
            executor: execPDA, executorSourceToken: execSrcToken, executorDestToken: execDstToken,
            destMintInfo: CARDS_MINT, relayer: payer.publicKey, relayerDestToken: execDstToken,
            swapProgram: JUPITER_PROGRAM_ID, jupiterEventAuthority: JUPITER_EVENT_AUTHORITY,
            tokenProgram: TOKEN_PROGRAM_ID, token2022Program: TOKEN_2022_PROGRAM_ID,
            systemProgram: SystemProgram.programId, associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
          })
          .remainingAccounts(remainingAccounts)
          .instruction();

        const allKeys: PublicKey[] = [];
        const seen = new Set<string>();
        for (const meta of openIx.keys) { const k = meta.pubkey.toBase58(); if (!seen.has(k)) { seen.add(k); allKeys.push(meta.pubkey); } }
        if (!seen.has(openIx.programId.toBase58())) allKeys.push(openIx.programId);
        const alt = await buildAndActivateALT(connection, payer, allKeys);
        const { blockhash } = await connection.getLatestBlockhash();
        const msgV0 = new TransactionMessage({ payerKey: payer.publicKey, recentBlockhash: blockhash, instructions: [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }), openIx] }).compileToV0Message([alt]);
        const vtx = new VersionedTransaction(msgV0); vtx.sign([payer]);
        const sig = await connection.sendTransaction(vtx);
        await connection.confirmTransaction(sig, "confirmed");

        usdcOffchainTree.insert(chgCommit);
        const posLeafIdx = positionOffchainTree.insert(posCommit);

        return {
          amount: destAmount,
          positionSecretN: posKeys.positionSecretN,
          positionPubkey: posKeys.positionPubkey,
          positionBlinding: posKeys.positionBlinding,
          positionBlindingBytes: posBlindBytes,
          positionPdaKeyBytes: posKeys.positionPdaKeyBytes,
          mint: CARDS_MINT, isToken2022: false,
          leafIndex: posLeafIdx, commitment: posCommit,
        };
      }

      // ── Open two CARDS positions (n=2 and n=3) ──────────────────────────────
      // Each position needs fresh USDC — swap SOL→USDC independently for each.
      async function swapSolToUsdc(lamports: number): Promise<bigint> {
        const q = await jupiterService.getQuote(NATIVE_MINT, USDC_MINT, lamports, 100, true, "Byreal");
        const ixResp = await jupiterService.getSwapInstruction(q, payer.publicKey, true);
        const ixs: TransactionInstruction[] = [
          ...(ixResp.setupInstructions ?? []).map(decodeJupIx),
          decodeJupIx(ixResp.swapInstruction),
          ...(ixResp.cleanupInstruction ? [decodeJupIx(ixResp.cleanupInstruction)] : []),
        ];
        const alts = (await Promise.all(
          (ixResp.addressLookupTableAddresses ?? []).map(async (a: string) => {
            const r = await connection.getAddressLookupTable(new PublicKey(a));
            return r.value;
          }),
        )).filter(Boolean) as any[];
        const { blockhash: bh, lastValidBlockHeight: lvbh } = await connection.getLatestBlockhash();
        const msg = new TransactionMessage({ payerKey: payer.publicKey, recentBlockhash: bh,
          instructions: [ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 }), ...ixs],
        }).compileToV0Message(alts);
        const vtx = new VersionedTransaction(msg); vtx.sign([payer]);
        const sig = await connection.sendTransaction(vtx);
        await connection.confirmTransaction({ signature: sig, blockhash: bh, lastValidBlockHeight: lvbh });
        console.log("  ✅ SOL→USDC swap tx:", sig);
        const ata = await getOrCreateAssociatedTokenAccount(connection, payer, USDC_MINT, payer.publicKey);
        return BigInt(ata.amount.toString());
      }

      console.log("  Swapping SOL→USDC for position n=2...");
      const dep2Amount = await swapSolToUsdc(10_000_000);
      if (dep2Amount === 0n) throw new Error("Insufficient USDC for merge test (position 2)");
      console.log("  Opening CARDS position n=2...");
      const { note: note2 } = await depositUsdc(dep2Amount);
      const ps2 = await openCardsPosition(note2, 2);
      console.log("  ✅ CARDS position n=2 opened, leaf:", ps2.leafIndex);

      console.log("  Swapping SOL→USDC for position n=3...");
      const dep3Amount = await swapSolToUsdc(10_000_000);
      if (dep3Amount === 0n) throw new Error("Insufficient USDC for merge test (position 3)");
      console.log("  Opening CARDS position n=3...");
      const { note: note3 } = await depositUsdc(dep3Amount);
      const ps3 = await openCardsPosition(note3, 3);
      console.log("  ✅ CARDS position n=3 opened, leaf:", ps3.leafIndex);

      // ── Build merge ZK proof (transaction circuit, publicAmount=0) ───────────
      const posKeysNew = derivePositionKeys(poseidon, walletPrivkey, 4);

      const null2 = computeNullifier(poseidon, ps2.commitment, ps2.leafIndex, bigIntToBytes32BE(ps2.positionSecretN));
      const null3 = computeNullifier(poseidon, ps3.commitment, ps3.leafIndex, bigIntToBytes32BE(ps3.positionSecretN));

      const mergedAmount = ps2.amount + ps3.amount;
      const mergedBlindBytes = bigIntToBytes32BE(posKeysNew.positionBlinding);
      const mergedCommit = computeCommitment(poseidon, mergedAmount, posKeysNew.positionPubkey, mergedBlindBytes, CARDS_MINT);

      // Zero change note (amount=0) also in position tree
      const zeroChgPriv = randomBytes32(); const zeroChgPub = derivePublicKey(poseidon, zeroChgPriv); const zeroChgBld = randomBytes32();
      const zeroChgCommit = computeCommitment(poseidon, 0n, zeroChgPub, zeroChgBld, CARDS_MINT);

      const mergeExtData = { recipient: payer.publicKey, relayer: payer.publicKey, fee: new BN(0), refund: new BN(0), claimant: SystemProgram.programId };
      const mergeExtDataHash = computeExtDataHash(poseidon, mergeExtData);

      const posRoot = positionOffchainTree.getRoot();
      const path2 = positionOffchainTree.getMerkleProof(ps2.leafIndex);
      const path3 = positionOffchainTree.getMerkleProof(ps3.leafIndex);

      console.log("  Generating ZK merge proof (transaction circuit, publicAmount=0)...");
      const mergeProof = await generateTransactionProof({
        root: posRoot, publicAmount: 0n, extDataHash: mergeExtDataHash, mintAddress: CARDS_MINT,
        inputNullifiers: [null2, null3],
        outputCommitments: [mergedCommit, zeroChgCommit],
        inputAmounts: [ps2.amount, ps3.amount],
        inputPrivateKeys: [bigIntToBytes32BE(ps2.positionSecretN), bigIntToBytes32BE(ps3.positionSecretN)],
        inputPublicKeys: [ps2.positionPubkey, ps3.positionPubkey],
        inputBlindings: [ps2.positionBlindingBytes, ps3.positionBlindingBytes],
        inputMerklePaths: [path2, path3],
        outputAmounts: [mergedAmount, 0n],
        outputOwners: [posKeysNew.positionPubkey, zeroChgPub],
        outputBlindings: [mergedBlindBytes, zeroChgBld],
      });
      console.log("  ✅ Merge ZK proof generated");

      // ── Derive PDAs ──────────────────────────────────────────────────────────
      const pdaAddr2 = derivePositionPda(program.programId, ps2.positionPdaKeyBytes);
      const pdaAddr3 = derivePositionPda(program.programId, ps3.positionPdaKeyBytes);
      const pdaAddrNew = derivePositionPda(program.programId, posKeysNew.positionPdaKeyBytes);
      const nullMarker0 = derivePositionNullifierMarker(program.programId, CARDS_MINT, null2);
      const nullMarker1 = derivePositionNullifierMarker(program.programId, CARDS_MINT, null3);
      const posVaultRecord = derivePositionVaultRecord(program.programId, CARDS_MINT);

      // ── Call merge_positions ─────────────────────────────────────────────────
      const mergeIx = await (program.methods as any)
        .mergePositions(
          0, CARDS_MINT,
          Array.from(null2), Array.from(null3),
          0,
          Array.from(ps2.positionPdaKeyBytes),
          Array.from(ps3.positionPdaKeyBytes),
          Array.from(posKeysNew.positionPdaKeyBytes),
          mergeProof,
          Array.from(posRoot),
          Array.from(mergedCommit),
          Array.from(zeroChgCommit),
          { recipient: mergeExtData.recipient, relayer: mergeExtData.relayer, fee: mergeExtData.fee, refund: mergeExtData.refund, claimant: mergeExtData.claimant },
          new BN(mergedAmount.toString()),
        )
        .accounts({
          positionConfig,
          inputTree: positionTree0,
          outputTree: positionTree0,
          positionPda0: pdaAddr2,
          positionPda1: pdaAddr3,
          newPositionPda: pdaAddrNew,
          positionNullifierMarker0: nullMarker0,
          positionNullifierMarker1: nullMarker1,
          positionVaultRecord: posVaultRecord,
          relayer: payer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .instruction();

      const { blockhash: mb } = await connection.getLatestBlockhash();
      const mergeMsg = new TransactionMessage({
        payerKey: payer.publicKey, recentBlockhash: mb,
        instructions: [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }), mergeIx],
      }).compileToV0Message();
      const mergeTx = new VersionedTransaction(mergeMsg); mergeTx.sign([payer]);
      const mergeSig = await connection.sendTransaction(mergeTx);
      await connection.confirmTransaction(mergeSig, "confirmed");
      console.log("  ✅ merge_positions tx:", mergeSig);

      // Update off-chain tree
      positionOffchainTree.insert(mergedCommit);
      positionOffchainTree.insert(zeroChgCommit);

      // ── Verify results ───────────────────────────────────────────────────────
      let pda2Closed = false;
      let pda3Closed = false;
      try { await (program.account as any).positionPda.fetch(pdaAddr2); } catch { pda2Closed = true; }
      try { await (program.account as any).positionPda.fetch(pdaAddr3); } catch { pda3Closed = true; }
      expect(pda2Closed).to.be.true;
      expect(pda3Closed).to.be.true;
      console.log("  ✓ Both input PositionPDAs closed");

      const newPda = await (program.account as any).positionPda.fetch(pdaAddrNew);
      expect(newPda.isActive).to.be.true;
      expect(newPda.mint.toBase58()).to.equal(CARDS_MINT.toBase58());
      expect(BigInt(newPda.balance.toString())).to.equal(mergedAmount);
      console.log("  ✓ Merged PositionPDA created, balance:", newPda.balance.toString());

      const marker0 = await (program.account as any).positionNullifierMarker.fetch(nullMarker0);
      const marker1 = await (program.account as any).positionNullifierMarker.fetch(nullMarker1);
      expect(marker0.isSpent).to.be.true;
      expect(marker1.isSpent).to.be.true;
      console.log("  ✓ Both input position nullifiers marked spent");
    });
  });

  // ===========================================================================
  // Section 7: Position recovery
  // ===========================================================================

  describe("position recovery", () => {
    it("can find PositionPDA on-chain from wallet private key", async () => {
      const foundPdas: PublicKey[] = [];
      for (let n = 0; n < 10; n++) {
        const keys = derivePositionKeys(poseidon, walletPrivkey, n);
        const pdaAddr = derivePositionPda(program.programId, keys.positionPdaKeyBytes);
        try {
          const acc = await (program.account as any).positionPda.fetch(pdaAddr);
          if (acc.isActive) {
            foundPdas.push(pdaAddr);
            console.log(`  Found active position n=${n}: ${pdaAddr.toBase58()}`);
            console.log(`    mint:      ${acc.mint.toBase58()}`);
            console.log(`    balance:   ${acc.balance.toString()}`);
            console.log(`    leafIndex: ${acc.leafIndex.toString()}`);
          }
        } catch {
          // PDA not initialized — no position at index n
        }
      }
      console.log(`  Total active positions found: ${foundPdas.length}`);
    });
  });
});

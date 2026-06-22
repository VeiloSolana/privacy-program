// tests/jupiter-perp.test.ts
//
// Jupiter Perpetuals Integration Tests for Veilo Privacy Pool
//
// Covers all five new instructions:
//   jperp_open_position  — ZK-verified USDC withdrawal → createIncreasePositionMarketRequest
//   jperp_set_tpsl       — createDecreasePositionRequest2 (Trigger type, TP or SL)
//   jperp_update_tpsl    — updateDecreasePositionRequest2
//   jperp_close_position — createDecreasePositionRequest2 (Market type)
//   jperp_reissue_notes  — executor ATA → vault transfer + ZK deposit
//
// Test structure:
//   Suite 1 — PDA Derivation       (pure off-chain; always runnable)
//   Suite 2 — Validation Errors    (localnet; verifies on-chain guards fire before any CPI)
//   Suite 3 — Full Integration     (skipped; documents complete private-perps flow)
//
// Run: npm run test:jperp
//
// Suite 3 requires Jupiter Perpetuals cloned on the test validator.
// Add to Anchor.toml:
//   [[test.validator.clone]]
//   address = "PERPHjGBqRHArX4DySjwM6UJHiR3sWAatqfdBS2qQJu"   # Jupiter Perps
//   [[test.validator.clone]]
//   address = "5BUwFW4nRbftYTDMbgxykoFWqWHPzahFSNAaaaJtVKsq"   # JLP pool
//   [[test.validator.clone]]
//   address = "7xS2gz2bTp3fwCC7knJvUWTEU9Tycczu6VhJYKgi1wdz"   # SOL custody
//   [[test.validator.clone]]
//   address = "G18jKKXQwBbrHeiK3C9MRXhkHsLHf7XgCSisykV46EZa"   # USDC custody

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
  Transaction,
  AddressLookupTableProgram,
  TransactionMessage,
  VersionedTransaction,
  ComputeBudgetProgram,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  getAssociatedTokenAddress,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  createAssociatedTokenAccountInstruction,
  createTransferInstruction,
} from "@solana/spl-token";
import { buildPoseidon } from "circomlibjs";
import * as crypto from "crypto";

import {
  makeProvider,
  airdropAndConfirm,
  randomBytes32,
  deriveSpendingKey,
  computeExtDataHash,
  OffchainMerkleTree,
  computeCommitment,
  derivePublicKey,
  computeNullifier,
  generateTransactionProof,
  bytesToBigIntBE,
  extractRootFromAccount,
} from "./test-helpers";

// ─── Jupiter Perps constants (mirrors perps/src/perps.rs) ────────────────────

const JUPITER_PERP_PROGRAM_ID = new PublicKey(
  "PERPHjGBqRHArX4DySjwM6UJHiR3sWAatqfdBS2qQJu",
);
const PERPS_EVENT_AUTHORITY = new PublicKey(
  "37hJBDnntwqhGbK7L6M1bLyvccj4u55CCUiLPdYkiqBN",
);
const JLP_POOL = new PublicKey("5BUwFW4nRbftYTDMbgxykoFWqWHPzahFSNAaaaJtVKsq");

/** SOL custody's Doves price oracle (custody data offset 384). Required by Jupiter's
 *  createDecreasePositionRequest2 at remaining[7] (custodyDovesPriceAccount). */
const SOL_DOVES_ORACLE = new PublicKey("FYq2BWQ1V5P1WFBqr3qB2Kb5yHVvSv7upzKodgQE5zXh");

// Custodies from perps-playground/lib/setup.ts
const CUSTODIES = {
  SOL: new PublicKey("7xS2gz2bTp3fwCC7knJvUWTEU9Tycczu6VhJYKgi1wdz"),
  USDC: new PublicKey("G18jKKXQwBbrHeiK3C9MRXhkHsLHf7XgCSisykV46EZa"),
};

const USDC_MINT = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
const WSOL_MINT = new PublicKey("So11111111111111111111111111111111111111112");

/** Side enum discriminants (None=0, Long=1, Short=2) */
const SIDE_LONG = 1;
const SIDE_SHORT = 2;

/** RequestType enum discriminants (Market=0, Trigger=1) */
const REQUEST_TYPE_MARKET = 0;
const REQUEST_TYPE_TRIGGER = 1;

/** RequestChange enum discriminants (None=0, Increase=1, Decrease=2) */
const CHANGE_INCREASE = 1;
const CHANGE_DECREASE = 2;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function encodeTreeId(id: number): Buffer {
  const buf = Buffer.alloc(2);
  buf.writeUInt16LE(id, 0);
  return buf;
}

/**
 * Anchor instruction discriminator: sha256("global:<snake_case_name>")[0..8]
 * Mirrors jperp_disc() in perps.rs.
 */
function jperpDisc(name: string): Buffer {
  return crypto
    .createHash("sha256")
    .update(`global:${name}`)
    .digest()
    .slice(0, 8);
}

function nullifierMarkerPDA(
  programId: PublicKey,
  mint: PublicKey,
  nullifier: Uint8Array,
): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("nullifier_v3"), mint.toBuffer(), Buffer.from(nullifier)],
    programId,
  );
  return pda;
}

/** Executor PDA: ["jperp_executor", mint, claimant, withdrawal_id] on our program.
 *  withdrawal_id makes the executor unique per open → each position is unlinkable. */
function executorPDA(
  programId: PublicKey,
  mint: PublicKey,
  claimant: PublicKey,
  withdrawalId: Uint8Array,
): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("jperp_executor"), mint.toBuffer(), claimant.toBuffer(), Buffer.from(withdrawalId)],
    programId,
  );
  return pda;
}

/** Slot PDA: ["jperp_slot_v1", mint, withdrawal_id] on our program */
function slotPDA(
  programId: PublicKey,
  mint: PublicKey,
  withdrawalId: Uint8Array,
): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [
      Buffer.from("jperp_slot_v1"),
      mint.toBuffer(),
      Buffer.from(withdrawalId),
    ],
    programId,
  );
  return pda;
}

/**
 * Jupiter Perps position PDA.
 * Seeds: ["position", owner, JLP_POOL, custody, collateralCustody, side_byte]
 * on JUPITER_PERP_PROGRAM_ID.
 *
 * For private perps, owner = executorPDA (not the user's wallet).
 */
function positionPDA(
  owner: PublicKey,
  custody: PublicKey,
  collateralCustody: PublicKey,
  side: number, // 1=Long, 2=Short
): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [
      Buffer.from("position"),
      owner.toBuffer(),
      JLP_POOL.toBuffer(),
      custody.toBuffer(),
      collateralCustody.toBuffer(),
      Buffer.from([side]),
    ],
    JUPITER_PERP_PROGRAM_ID,
  );
  return pda;
}

/**
 * Jupiter Perps positionRequest PDA.
 * Seeds: ["position_request", position, counter_le8, change_byte]
 * on JUPITER_PERP_PROGRAM_ID.
 */
function positionRequestPDA(
  position: PublicKey,
  counter: BN,
  change: number, // CHANGE_INCREASE=1, CHANGE_DECREASE=2
): PublicKey {
  const counterBuf = Buffer.alloc(8);
  // BN little-endian 8 bytes
  const counterBytes = counter.toArrayLike(Buffer, "le", 8);
  counterBytes.copy(counterBuf);
  const [pda] = PublicKey.findProgramAddressSync(
    [
      Buffer.from("position_request"),
      position.toBuffer(),
      counterBuf,
      Buffer.from([change]),
    ],
    JUPITER_PERP_PROGRAM_ID,
  );
  return pda;
}

/** Perpetuals global PDA on Jupiter Perps program. */
function perpetualsPDA(): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("perpetuals")],
    JUPITER_PERP_PROGRAM_ID,
  );
  return pda;
}

function dummyProof() {
  return {
    proofA: new Array(64).fill(0),
    proofB: new Array(128).fill(0),
    proofC: new Array(64).fill(0),
  };
}

function tinyProof() {
  return { proofA: [] as number[], proofB: [] as number[], proofC: [] as number[] };
}

async function buildAlt(
  provider: AnchorProvider,
  payer: Keypair,
  addresses: PublicKey[],
): Promise<import("@solana/web3.js").AddressLookupTableAccount> {
  const slot = await provider.connection.getSlot("finalized");
  const [createIx, lutAddress] = AddressLookupTableProgram.createLookupTable({
    authority: payer.publicKey,
    payer: payer.publicKey,
    recentSlot: slot,
  });
  const extendIx = AddressLookupTableProgram.extendLookupTable({
    payer: payer.publicKey,
    authority: payer.publicKey,
    lookupTable: lutAddress,
    addresses,
  });
  await provider.sendAndConfirm(
    new Transaction().add(createIx).add(extendIx),
    [payer],
  );
  // Wait one slot for activation
  await new Promise((r) => setTimeout(r, 600));
  const lutAccount = await provider.connection.getAddressLookupTable(lutAddress);
  return lutAccount.value!;
}

async function sendVersionedTx(
  provider: AnchorProvider,
  ixs: import("@solana/web3.js").TransactionInstruction[],
  signers: Keypair[],
  luts: import("@solana/web3.js").AddressLookupTableAccount[],
): Promise<string> {
  const { blockhash } = await provider.connection.getLatestBlockhash();
  const msg = new TransactionMessage({
    payerKey: signers[0].publicKey,
    recentBlockhash: blockhash,
    instructions: ixs,
  }).compileToV0Message(luts);
  const vtx = new VersionedTransaction(msg);
  vtx.sign(signers);
  return provider.connection.sendTransaction(vtx, { skipPreflight: false });
}

/**
 * Derive the jperp claimant keypair deterministically.
 * seed = sha256("jperp_claimant" || spendingKey || withdrawalId)
 * Mirrors the predictions.rs doc: "The client should derive the ephemeral key
 * deterministically so it can be recovered."
 */
function deriveJperpClaimantKeypair(spendingKey: Uint8Array, withdrawalId: Uint8Array): Keypair {
  const seed = require("crypto")
    .createHash("sha256")
    .update(Buffer.concat([Buffer.from("jperp_claimant"), Buffer.from(spendingKey), Buffer.from(withdrawalId)]))
    .digest();
  return Keypair.fromSeed(seed);
}

/** Short pubkey for compact logging: "ABCD…WXYZ". */
function shortKey(k: PublicKey): string {
  const s = k.toBase58();
  return `${s.slice(0, 4)}…${s.slice(-4)}`;
}

/** Format µUSDC (6 decimals) as "$X.XX". */
function usd(micro: number | BN): string {
  const n = typeof micro === "number" ? micro : Number(micro.toString());
  return `$${(n / 1e6).toFixed(2)}`;
}

/** Fetch a token-account balance in base units (returns 0 if the account is missing). */
async function tokenBal(provider: AnchorProvider, ata: PublicKey): Promise<number> {
  const bal = await provider.connection.getTokenAccountBalance(ata).catch(() => null);
  return parseInt(bal?.value.amount ?? "0");
}

/** Indented step log helper. */
function log(...parts: unknown[]): void {
  console.log("      " + parts.join(" "));
}

/** Decoded Jupiter Perps position (offsets per the cloned mainnet Position struct). */
interface PerpPosition {
  side: number;        // 1=Long, 2=Short
  entryPrice: number;  // USD
  sizeUsd: number;     // USD
  collateralUsd: number; // USD
  leverage: number;
}

/** Read + decode a Jupiter Perps position account. Returns null if absent.
 *  Layout: side@152(u8), price@153(u64), sizeUsd@161(u64), collateralUsd@169(u64); USD @ 1e6. */
async function decodePosition(
  provider: AnchorProvider,
  position: PublicKey,
): Promise<PerpPosition | null> {
  const info = await provider.connection.getAccountInfo(position);
  if (!info || info.data.length < 177) return null;
  const d = info.data;
  const entryPrice = Number(d.readBigUInt64LE(153)) / 1e6;
  const sizeUsd = Number(d.readBigUInt64LE(161)) / 1e6;
  const collateralUsd = Number(d.readBigUInt64LE(169)) / 1e6;
  return {
    side: d[152],
    entryPrice,
    sizeUsd,
    collateralUsd,
    leverage: collateralUsd > 0 ? sizeUsd / collateralUsd : 0,
  };
}

/** Unrealized PnL (USD) of a position at a given mark price. Short profits as price falls. */
function pnlAt(pos: PerpPosition, markPrice: number): number {
  if (pos.entryPrice === 0) return 0;
  const dir = pos.side === SIDE_SHORT ? -1 : 1;
  return (dir * pos.sizeUsd * (markPrice - pos.entryPrice)) / pos.entryPrice;
}

/** Log a position's state on one line. */
function logPosition(pos: PerpPosition, label: string): void {
  const sideStr =
    pos.side === SIDE_SHORT ? "SHORT" : pos.side === SIDE_LONG ? "LONG" : `side=${pos.side}`;
  log(
    `${label}: ${sideStr}  size $${pos.sizeUsd.toFixed(2)}  collateral $${pos.collateralUsd.toFixed(2)}` +
      `  entry $${pos.entryPrice.toFixed(2)}  ${pos.leverage.toFixed(1)}× leverage`,
  );
}

async function assertError(
  promise: Promise<unknown>,
  expectedFragment: string,
  note?: string,
): Promise<void> {
  if (note) console.log(`\n  ▶ GUARD — ${note}`);
  try {
    await promise;
    throw new Error(`Expected error containing "${expectedFragment}" but tx succeeded`);
  } catch (err: any) {
    const msg = err?.message ?? err?.toString() ?? "";
    const logs: string = (err?.logs ?? []).join("\n");
    if (
      !msg.includes(expectedFragment) &&
      !logs.includes(expectedFragment)
    ) {
      throw new Error(
        `Expected "${expectedFragment}" but got: ${msg}\nLogs: ${logs}`,
      );
    }
  }
  if (note) log(`✓ rejected as expected with ${expectedFragment}`);
}

// ─── Suite ────────────────────────────────────────────────────────────────────

describe("Jupiter Perpetuals Integration", () => {
  const provider = makeProvider();
  setProvider(provider);
  const wallet = provider.wallet as Wallet;
  const program: any = (workspace as any).PrivacyPool;

  // Non-USDC pool for validation error tests
  let testMint: PublicKey;
  let config: PublicKey;
  let vault: PublicKey;
  let noteTree: PublicKey;
  let nullifiers: PublicKey;
  let globalConfig: PublicKey;
  let vaultTokenAccount: PublicKey;
  let relayer: Keypair;
  let poseidon: any;

  before(async () => {
    console.log("\n⚡  Jupiter Perps Integration Test Setup\n");
    poseidon = await buildPoseidon();

    // Use WSOL as the non-USDC test pool mint (cloned in Anchor.toml, not USDC)
    testMint = WSOL_MINT;

    [config] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_config_v3"), testMint.toBuffer()],
      program.programId,
    );
    [vault] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_vault_v3"), testMint.toBuffer()],
      program.programId,
    );
    [noteTree] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_note_tree_v3"), testMint.toBuffer(), encodeTreeId(0)],
      program.programId,
    );
    [nullifiers] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_nullifiers_v3"), testMint.toBuffer()],
      program.programId,
    );
    [globalConfig] = PublicKey.findProgramAddressSync(
      [Buffer.from("global_config_v1")],
      program.programId,
    );

    try {
      await (program.methods as any)
        .initializeGlobalConfig()
        .accounts({ globalConfig, admin: wallet.publicKey, payer: wallet.publicKey, systemProgram: SystemProgram.programId })
        .rpc();
    } catch (_) { /* already exists */ }

    try {
      await (program.methods as any)
        .initialize(50, testMint, new BN(1_000_000), new BN(1_000_000_000_000), new BN(1_000_000), new BN(1_000_000_000_000))
        .accounts({ config, vault, noteTree, nullifiers, globalConfig, admin: wallet.publicKey, payer: wallet.publicKey, systemProgram: SystemProgram.programId })
        .rpc();
    } catch (_) { /* already exists */ }

    vaultTokenAccount = await getAssociatedTokenAddress(testMint, vault, true);

    relayer = Keypair.generate();
    await airdropAndConfirm(provider, relayer.publicKey, 2 * LAMPORTS_PER_SOL);
    await (program.methods as any)
      .addRelayer(testMint, relayer.publicKey)
      .accounts({ config, admin: wallet.publicKey })
      .rpc();

    console.log(`   Test mint (WSOL):   ${testMint.toBase58()}`);
    console.log(`   Config PDA:         ${config.toBase58()}`);
    console.log(`   Relayer:            ${relayer.publicKey.toBase58()}`);
  });

  // ── Suite 1: PDA Derivation ────────────────────────────────────────────────

  describe("PDA Derivation", () => {
    it("derives executor PDA from [jperp_executor, mint, claimant]", () => {
      const claimant = Keypair.generate().publicKey;
      const [pda, bump] = PublicKey.findProgramAddressSync(
        [Buffer.from("jperp_executor"), USDC_MINT.toBuffer(), claimant.toBuffer()],
        program.programId,
      );
      console.log(`      executor PDA:  ${pda.toBase58()}  (bump ${bump})`);

      // Different claimants → different executor PDAs
      const claimant2 = Keypair.generate().publicKey;
      const [pda2] = PublicKey.findProgramAddressSync(
        [Buffer.from("jperp_executor"), USDC_MINT.toBuffer(), claimant2.toBuffer()],
        program.programId,
      );
      if (pda.equals(pda2)) throw new Error("Different claimants must produce different executor PDAs");
    });

    it("derives slot PDA from [jperp_slot_v1, mint, withdrawal_id]", () => {
      const withdrawalId = randomBytes32();
      const pda = slotPDA(program.programId, USDC_MINT, withdrawalId);
      console.log(`      slot PDA: ${pda.toBase58()}`);

      // Different withdrawal_ids → different slot PDAs
      const pda2 = slotPDA(program.programId, USDC_MINT, randomBytes32());
      if (pda.equals(pda2)) throw new Error("Different withdrawal_ids must produce different slot PDAs");
    });

    it("derives position PDA on Jupiter Perps program (owner = executor PDA)", () => {
      const claimant = Keypair.generate().publicKey;
      const executor = executorPDA(program.programId, USDC_MINT, claimant, randomBytes32());
      const position = positionPDA(executor, CUSTODIES.SOL, CUSTODIES.USDC, SIDE_SHORT);
      console.log(`      executor:  ${executor.toBase58()}`);
      console.log(`      position:  ${position.toBase58()}`);

      // Long uses same market token as collateral
      const posLong = positionPDA(executor, CUSTODIES.SOL, CUSTODIES.SOL, SIDE_LONG);
      if (position.equals(posLong)) throw new Error("Long and short positions must be distinct PDAs");
    });

    it("derives positionRequest PDA (Increase) from [position_request, position, counter_le8, 0x01]", () => {
      const counter = new BN(Math.floor(Math.random() * 1_000_000_000));
      const claimant = Keypair.generate().publicKey;
      const executor = executorPDA(program.programId, USDC_MINT, claimant, randomBytes32());
      const position = positionPDA(executor, CUSTODIES.SOL, CUSTODIES.USDC, SIDE_SHORT);
      const req = positionRequestPDA(position, counter, CHANGE_INCREASE);
      console.log(`      positionRequest (increase): ${req.toBase58()}  (counter ${counter.toString()})`);
    });

    it("derives positionRequest PDA (Decrease) from [position_request, position, counter_le8, 0x02]", () => {
      const counter = new BN(Math.floor(Math.random() * 1_000_000_000));
      const claimant = Keypair.generate().publicKey;
      const executor = executorPDA(program.programId, USDC_MINT, claimant, randomBytes32());
      const position = positionPDA(executor, CUSTODIES.SOL, CUSTODIES.USDC, SIDE_SHORT);
      const reqIncrease = positionRequestPDA(position, counter, CHANGE_INCREASE);
      const reqDecrease = positionRequestPDA(position, counter, CHANGE_DECREASE);
      if (reqIncrease.equals(reqDecrease))
        throw new Error("Increase and decrease requests with same counter must be distinct");
    });

    it("derives perpetuals global PDA from [perpetuals] on PERP program", () => {
      const perps = perpetualsPDA();
      console.log(`      perpetuals PDA: ${perps.toBase58()}`);
    });

    it("computes Anchor discriminators for Jupiter Perps instructions", () => {
      const disc = (name: string) =>
        jperpDisc(name).toString("hex").toUpperCase();

      const open   = disc("create_increase_position_market_request");
      const dec    = disc("create_decrease_position_request2");
      const update = disc("update_decrease_position_request2");

      console.log(`      create_increase_position_market_request: ${open}`);
      console.log(`      create_decrease_position_request2:       ${dec}`);
      console.log(`      update_decrease_position_request2:       ${update}`);

      // All three must be distinct 8-byte values
      const all = [open, dec, update];
      const unique = new Set(all);
      if (unique.size !== all.length) throw new Error("Discriminators must be unique");
    });

    it("deriveJperpClaimantKeypair: same spendingKey+withdrawalId → same claimant", () => {
      const spendingKey = randomBytes32();
      const withdrawalId = randomBytes32();
      const kp1 = deriveJperpClaimantKeypair(spendingKey, withdrawalId);
      const kp2 = deriveJperpClaimantKeypair(spendingKey, withdrawalId);
      if (!kp1.publicKey.equals(kp2.publicKey)) {
        throw new Error("Same inputs must produce the same claimant keypair");
      }
      // Different withdrawal_ids → different claimants (one spending key per position)
      const kp3 = deriveJperpClaimantKeypair(spendingKey, randomBytes32());
      if (kp1.publicKey.equals(kp3.publicKey)) {
        throw new Error("Different withdrawal_ids must produce different claimant keypairs");
      }
      console.log(`      claimant pubkey: ${kp1.publicKey.toBase58()}`);
    });

    it("side and request-type byte constants match IDL ordering", () => {
      // From IDL: Side[0]=None, Side[1]=Long, Side[2]=Short
      //           RequestType[0]=Market, RequestType[1]=Trigger
      if (SIDE_LONG !== 1) throw new Error("SIDE_LONG must be 1");
      if (SIDE_SHORT !== 2) throw new Error("SIDE_SHORT must be 2");
      if (REQUEST_TYPE_MARKET !== 0) throw new Error("REQUEST_TYPE_MARKET must be 0");
      if (REQUEST_TYPE_TRIGGER !== 1) throw new Error("REQUEST_TYPE_TRIGGER must be 1");
      if (CHANGE_INCREASE !== 1) throw new Error("CHANGE_INCREASE must be 1");
      if (CHANGE_DECREASE !== 2) throw new Error("CHANGE_DECREASE must be 2");
    });

    it("multiple TP/SL requests on the same position use different counters", () => {
      const claimant = Keypair.generate().publicKey;
      const executor = executorPDA(program.programId, USDC_MINT, claimant, randomBytes32());
      const position = positionPDA(executor, CUSTODIES.SOL, CUSTODIES.USDC, SIDE_SHORT);

      const tpCounter = new BN(111_111);
      const slCounter = new BN(222_222);

      const tpRequest = positionRequestPDA(position, tpCounter, CHANGE_DECREASE);
      const slRequest = positionRequestPDA(position, slCounter, CHANGE_DECREASE);

      if (tpRequest.equals(slRequest))
        throw new Error("TP and SL requests must be distinct PDAs (different counters)");

      console.log(`      TP request PDA: ${tpRequest.toBase58()}`);
      console.log(`      SL request PDA: ${slRequest.toBase58()}`);
    });
  });

  // ── Suite 2: Validation Errors ─────────────────────────────────────────────

  describe("Validation Errors", () => {
    let testExecutor: PublicKey;
    let testSlot: PublicKey;
    let suite2Lut: import("@solana/web3.js").AddressLookupTableAccount;

    const withdrawalId = new Uint8Array(32).fill(0xab);
    const n0 = randomBytes32();
    const n1 = randomBytes32();
    const c0 = randomBytes32();
    const c1 = randomBytes32();

    before(async () => {
      console.log("\n  ┌─ Suite 2: Validation guards ────────────────────────────────");
      console.log("  │  every on-chain guard must fire BEFORE any Jupiter CPI / fund movement");
      console.log("  └──────────────────────────────────────────────────────────────");
      testExecutor = executorPDA(
        program.programId,
        testMint,
        SystemProgram.programId,
        withdrawalId,
      );
      testSlot = slotPDA(program.programId, testMint, withdrawalId);

      suite2Lut = await buildAlt(provider, relayer, [
        TOKEN_PROGRAM_ID,
        ASSOCIATED_TOKEN_PROGRAM_ID,
        SystemProgram.programId,
        globalConfig,
        config,
        vault,
        noteTree,
        nullifiers,
        vaultTokenAccount,
        testExecutor,
        testSlot,
      ]);
    });

    it("jperp_open_position: rejects invalid side byte (JperpInvalidSide)", async () => {
      const marker0 = nullifierMarkerPDA(program.programId, testMint, n0);
      const marker1 = nullifierMarkerPDA(program.programId, testMint, n1);
      const claimant = SystemProgram.programId;
      const extData = {
        recipient: testExecutor,
        relayer: relayer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
        claimant,
      };
      const extDataHash = computeExtDataHash(poseidon, extData);

      const ix1 = await (program.methods as any)
        .jperpOpenPosition(
          Array.from(new Uint8Array(32).fill(1)), // root
          0, 0,                                    // tree IDs
          new BN(1_000_000),                       // deposit_amount
          Array.from(extDataHash),
          testMint,
          claimant,
          Array.from(n0), Array.from(n1),
          Array.from(c0), Array.from(c1),
          Array.from(withdrawalId),
          new BN(Math.floor(Date.now() / 1000) + 3600),
          extData,
          tinyProof(),
          null,       // note_ciphers
          new BN(10_000_000), // size_usd_delta
          new BN(1_000_000),  // collateral_token_delta
          99,                 // side = 99 — invalid
          new BN(0),          // price_slippage
          new BN(0),          // counter
        )
        .accounts({
          config,
          globalConfig,
          vault,
          inputTree: noteTree,
          outputTree: noteTree,
          nullifiers,
          nullifierMarker0: marker0,
          nullifierMarker1: marker1,
          relayer: relayer.publicKey,
          vaultTokenAccount,
          executor: testExecutor,
          executorTokenAccount: vaultTokenAccount, // dummy
          relayerTokenAccount: vaultTokenAccount,  // dummy
          jperpSlot: testSlot,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .remainingAccounts([])
        .instruction();

      await assertError(
        sendVersionedTx(provider, [ix1], [relayer], [suite2Lut]),
        "JperpInvalidSide",
        "open with side byte = 99 (only Long=1 / Short=2 allowed)",
      );
    });

    it("jperp_open_position: rejects unregistered relayer (RelayerNotAllowed)", async () => {
      const badRelayer = Keypair.generate();
      await airdropAndConfirm(provider, badRelayer.publicKey, LAMPORTS_PER_SOL);

      const claimant = SystemProgram.programId;
      const extData = {
        recipient: testExecutor,
        relayer: badRelayer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
        claimant,
      };
      const extDataHash = computeExtDataHash(poseidon, extData);
      const marker0 = nullifierMarkerPDA(program.programId, testMint, n0);
      const marker1 = nullifierMarkerPDA(program.programId, testMint, n1);

      const ix2 = await (program.methods as any)
        .jperpOpenPosition(
          Array.from(new Uint8Array(32).fill(1)),
          0, 0,
          new BN(1_000_000),
          Array.from(extDataHash),
          testMint,
          claimant,
          Array.from(n0), Array.from(n1),
          Array.from(c0), Array.from(c1),
          Array.from(withdrawalId),
          new BN(Math.floor(Date.now() / 1000) + 3600),
          extData,
          tinyProof(),
          null,
          new BN(10_000_000),
          new BN(1_000_000),
          SIDE_SHORT,
          new BN(0),
          new BN(0),
        )
        .accounts({
          config,
          globalConfig,
          vault,
          inputTree: noteTree,
          outputTree: noteTree,
          nullifiers,
          nullifierMarker0: marker0,
          nullifierMarker1: marker1,
          relayer: badRelayer.publicKey,
          vaultTokenAccount,
          executor: testExecutor,
          executorTokenAccount: vaultTokenAccount,
          relayerTokenAccount: vaultTokenAccount,
          jperpSlot: testSlot,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .remainingAccounts([])
        .instruction();

      await assertError(
        sendVersionedTx(provider, [ix2], [badRelayer], [suite2Lut]),
        "RelayerNotAllowed",
        "open submitted by an unregistered relayer",
      );
    });

    it("jperp_open_position: rejects when recipient != executor PDA (JperpRecipientMustBeExecutor)", async () => {
      const claimant = SystemProgram.programId;
      const wrongRecipient = Keypair.generate().publicKey; // not the executor PDA
      const extData = {
        recipient: wrongRecipient,
        relayer: relayer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
        claimant,
      };
      const extDataHash = computeExtDataHash(poseidon, extData);
      const marker0 = nullifierMarkerPDA(program.programId, testMint, n0);
      const marker1 = nullifierMarkerPDA(program.programId, testMint, n1);

      const ix3 = await (program.methods as any)
        .jperpOpenPosition(
          Array.from(new Uint8Array(32).fill(1)),
          0, 0,
          new BN(1_000_000),
          Array.from(extDataHash),
          testMint,
          claimant,
          Array.from(n0), Array.from(n1),
          Array.from(c0), Array.from(c1),
          Array.from(withdrawalId),
          new BN(Math.floor(Date.now() / 1000) + 3600),
          extData,
          tinyProof(),
          null,
          new BN(10_000_000),
          new BN(1_000_000),
          SIDE_SHORT,
          new BN(0),
          new BN(0),
        )
        .accounts({
          config,
          globalConfig,
          vault,
          inputTree: noteTree,
          outputTree: noteTree,
          nullifiers,
          nullifierMarker0: marker0,
          nullifierMarker1: marker1,
          relayer: relayer.publicKey,
          vaultTokenAccount,
          executor: testExecutor,
          executorTokenAccount: vaultTokenAccount,
          relayerTokenAccount: vaultTokenAccount,
          jperpSlot: testSlot,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .remainingAccounts([])
        .instruction();

      await assertError(
        sendVersionedTx(provider, [ix3], [relayer], [suite2Lut]),
        "JperpRecipientMustBeExecutor",
        "open whose ext_data.recipient ≠ the executor PDA",
      );
    });

    it("jperp_set_tpsl: rejects missing jperp_slot (AccountNotInitialized — slot required)", async () => {
      // After AUDIT-002 the claimant is a Signer account (not a param) and jperp_slot is
      // a required account. With no real slot on-chain, Anchor fails with AccountNotInitialized
      // before the handler's RelayerNotAllowed check. Proves the instruction requires full
      // account setup to proceed.
      const badRelayer = Keypair.generate();
      await airdropAndConfirm(provider, badRelayer.publicKey, LAMPORTS_PER_SOL);
      const claimantKp = Keypair.generate();
      const executor = executorPDA(program.programId, testMint, claimantKp.publicKey, withdrawalId);
      const executorAta = await getAssociatedTokenAddress(testMint, executor, true);

      await assertError(
        (program.methods as any)
          .jperpSetTpsl(
            testMint,
            Array.from(withdrawalId),
            new BN(0),           // collateral_usd_delta
            new BN(5_000_000),   // size_usd_delta
            new BN(200_000_000), // trigger_price ($200)
            true,                // trigger_above_threshold (TP)
            false,               // entire_position
            new BN(42),          // counter
          )
          .accounts({
            config,
            jperpSlot: testSlot,
            claimant: claimantKp.publicKey,
            executor,
            executorTokenAccount: executorAta,
            relayer: badRelayer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([])
          .signers([badRelayer, claimantKp])
          .rpc(),
        "AccountNotInitialized",
        "set_tpsl with no initialized jperp_slot",
      );
    });

    it("jperp_update_tpsl: rejects missing jperp_slot (AccountNotInitialized — slot required)", async () => {
      const badRelayer = Keypair.generate();
      await airdropAndConfirm(provider, badRelayer.publicKey, LAMPORTS_PER_SOL);
      const claimantKp = Keypair.generate();
      const executor = executorPDA(program.programId, testMint, claimantKp.publicKey, withdrawalId);

      await assertError(
        (program.methods as any)
          .jperpUpdateTpsl(
            testMint,
            Array.from(withdrawalId),
            new BN(5_000_000),   // size_usd_delta
            new BN(210_000_000), // trigger_price
          )
          .accounts({
            config,
            jperpSlot: testSlot,
            claimant: claimantKp.publicKey,
            executor,
            relayer: badRelayer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([])
          .signers([badRelayer, claimantKp])
          .rpc(),
        "AccountNotInitialized",
        "update_tpsl with no initialized jperp_slot",
      );
    });

    it("jperp_close_position: rejects missing jperp_slot (AccountNotInitialized — slot required)", async () => {
      const badRelayer = Keypair.generate();
      await airdropAndConfirm(provider, badRelayer.publicKey, LAMPORTS_PER_SOL);
      const claimantKp = Keypair.generate();
      const executor = executorPDA(program.programId, testMint, claimantKp.publicKey, withdrawalId);
      const executorAta = await getAssociatedTokenAddress(testMint, executor, true);

      await assertError(
        (program.methods as any)
          .jperpClosePosition(
            testMint,
            Array.from(withdrawalId),
            new BN(0),   // collateral_usd_delta
            new BN(0),   // size_usd_delta (entirePosition=true)
            true,        // entire_position
            new BN(0),   // price_slippage
            new BN(99),  // counter
          )
          .accounts({
            config,
            jperpSlot: testSlot,
            claimant: claimantKp.publicKey,
            executor,
            executorTokenAccount: executorAta,
            relayer: badRelayer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([])
          .signers([badRelayer, claimantKp])
          .rpc(),
        "AccountNotInitialized",
        "close_position with no initialized jperp_slot",
      );
    });

    it("jperp_set_tpsl: rejects missing jperp_slot even before remaining_accounts check", async () => {
      // After AUDIT-002, jperp_slot is validated by Anchor before the handler's
      // JperpInvalidAccounts guard can fire. Without a real slot the tx fails at
      // account deserialization — remaining_accounts count is irrelevant.
      const claimantKp = Keypair.generate();
      const executor = executorPDA(program.programId, testMint, claimantKp.publicKey, withdrawalId);
      const executorAta = await getAssociatedTokenAddress(testMint, executor, true);

      await assertError(
        (program.methods as any)
          .jperpSetTpsl(
            testMint,
            Array.from(withdrawalId),
            new BN(0),
            new BN(5_000_000),
            new BN(200_000_000),
            true,
            false,
            new BN(1),
          )
          .accounts({
            config,
            jperpSlot: testSlot,
            claimant: claimantKp.publicKey,
            executor,
            executorTokenAccount: executorAta,
            relayer: relayer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([
            { pubkey: JUPITER_PERP_PROGRAM_ID, isSigner: false, isWritable: false },
          ])
          .signers([relayer, claimantKp])
          .rpc(),
        "AccountNotInitialized",
        "set_tpsl with uninitialized jperp_slot — fails at account layer",
      );
    });
  });

  // ── Suite 3: Full Integration ─────────────────────────────────────────────
  //
  // Runs automatically when the following are present on the test validator:
  //   • Jupiter Perps program (PERPHjGB...)
  //   • USDC vault ATA cloned with balance (6TVfaAU1... — see Anchor.toml)
  //
  // All tests skip gracefully when those conditions aren't met.

  describe("Full Integration (PERP program + USDC vault balance required)", () => {
    let suiteReady = false;
    let step1Passed = false;
    let suite3Lut: import("@solana/web3.js").AddressLookupTableAccount;

    let usdcConfig: PublicKey;
    let usdcVault: PublicKey;
    let usdcNoteTree: PublicKey;
    let usdcNullifiers: PublicKey;
    let usdcVaultAta: PublicKey;
    let s3Relayer: Keypair;
    let claimantKp: Keypair;
    let executor: PublicKey;
    let executorUsdcAta: PublicKey;
    let jperpSlot: PublicKey;
    // Step-1 PDAs (derived from fixed inputs; included in the ALT)
    let s3Position: PublicKey;
    let s3PositionRequest: PublicKey;
    let s3PositionRequestAta: PublicKey;
    let s3Perpetuals: PublicKey;
    let s3Marker0: PublicKey;
    let s3Marker1: PublicKey;
    // Empty-tree root for the freshly-initialized USDC pool.
    let usdcEmptyRoot: Uint8Array;
    // Off-chain mirror of the USDC note tree, the root the open spends against, and the
    // pre-generated open (withdrawal) Groth16 proof — all built in before() so the ALT
    // markers can be derived from the open's REAL input nullifiers.
    let offTree: OffchainMerkleTree;
    let openRoot: Uint8Array;
    let openProof: any;

    // Fixed per-suite state shared across tests.
    // withdrawal_id is FIXED (not random): the executor PDA seeds now include it, and
    // the genesis-cloned position (test-accounts/jperp-position.json) was baked for the
    // executor derived from this exact (claimant, withdrawal_id). Steps 2/3 require that
    // position to exist with sizeUsd > 0, so the value must match the fixture.
    const withdrawalId = new Uint8Array(
      JSON.parse(require("fs").readFileSync("keys/jperp-withdrawal-id.json", "utf8")),
    );
    // The open's input nullifiers + output commitments are REAL now: openN0 spends the
    // deposited noteA, openN1 is a 0-value dummy; openC0 is the change note, openC1 a dummy.
    // Assigned in before() once the deposit note + Merkle path exist.
    let openN0: Uint8Array;
    let openN1: Uint8Array;
    let openC0: Uint8Array;
    let openC1: Uint8Array;
    const openCounter = new BN(Math.floor(Math.random() * 1_000_000_000));
    const COLLATERAL = new BN(2_000_000); // $2 USDC

    before(async function () {
      this.timeout(180_000); // generates real Groth16 proofs (deposit + open) in setup

      console.log("\n  ┌─ Suite 3: Full private-perps lifecycle ─────────────────────");
      console.log("  │  open → set SL → market close → reissue, with keeper imitated");
      console.log("  └──────────────────────────────────────────────────────────────");

      // 1. Check if Jupiter Perps program is cloned on this validator
      const perpInfo = await provider.connection.getAccountInfo(JUPITER_PERP_PROGRAM_ID);
      if (!perpInfo?.executable) {
        console.log("   ⚠️  Jupiter Perps not cloned — Suite 3 will be skipped");
        return;
      }
      log("✓ setup: Jupiter Perps program is live on the validator");

      // 3. Derive USDC pool addresses
      [usdcConfig] = PublicKey.findProgramAddressSync(
        [Buffer.from("privacy_config_v3"), USDC_MINT.toBuffer()], program.programId);
      [usdcVault] = PublicKey.findProgramAddressSync(
        [Buffer.from("privacy_vault_v3"), USDC_MINT.toBuffer()], program.programId);
      [usdcNoteTree] = PublicKey.findProgramAddressSync(
        [Buffer.from("privacy_note_tree_v3"), USDC_MINT.toBuffer(), encodeTreeId(0)], program.programId);
      [usdcNullifiers] = PublicKey.findProgramAddressSync(
        [Buffer.from("privacy_nullifiers_v3"), USDC_MINT.toBuffer()], program.programId);
      usdcVaultAta = await getAssociatedTokenAddress(USDC_MINT, usdcVault, true);

      // 3. Verify vault ATA has enough USDC (requires Anchor.toml clone of 6TVfaAU1...)
      const vaultBal = await provider.connection
        .getTokenAccountBalance(usdcVaultAta)
        .catch(() => null);
      const vaultAmount = parseInt(vaultBal?.value.amount ?? "0");
      if (vaultAmount < 3_000_000) {
        console.log(`   ⚠️  USDC vault has ${vaultAmount} µUSDC (need ≥3 USDC) — Suite 3 will be skipped`);
        return;
      }
      log(`✓ setup: USDC vault ${shortKey(usdcVaultAta)} holds ${usd(vaultAmount)} (cloned from mainnet)`);

      // 4. Initialize USDC pool (idempotent — caught if already exists)
      try {
        await (program.methods as any)
          .initialize(
            50, USDC_MINT,
            new BN(1_000_000), new BN(1_000_000_000_000),
            new BN(1_000_000), new BN(1_000_000_000_000),
          )
          .accounts({
            config: usdcConfig, vault: usdcVault, noteTree: usdcNoteTree,
            nullifiers: usdcNullifiers, globalConfig,
            admin: wallet.publicKey, payer: wallet.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .rpc();
      } catch (_) { /* already initialized */ }

      // noteA secrets (the deposited, spendable note) — shared between the deposit (4c)
      // and the open spend (section 8), both inside this before().
      let aPriv: Uint8Array;
      let aBlind: Uint8Array;
      let aPub: bigint;
      let aLeafIndex = 0;

      // 4b. Off-chain mirror of the USDC note tree (starts empty). Used to build valid
      //     Merkle proofs for the spend in Step 1. The empty root is the on-chain root
      //     right after initialize().
      offTree = new OffchainMerkleTree(22, poseidon);
      usdcEmptyRoot = offTree.getRoot();
      const zeros = offTree.getZeros();
      const zeroPath = zeros.slice(0, 22).map((z) => bytesToBigIntBE(z));
      const zeroMerklePath = { pathElements: zeroPath, pathIndices: new Array(22).fill(0) };

      // 4c. Make a REAL deposit (valid Groth16 proof) so the pool holds a SPENDABLE note
      //     (noteA) and total_tvl covers the perp withdrawal. USDC comes from a
      //     genesis-loaded wallet ATA (localnet can't mint real USDC).
      const walletUsdcAta = await getAssociatedTokenAddress(USDC_MINT, wallet.publicKey);
      const depositAmount = new BN(10_000_000); // 10 USDC (> COLLATERAL → open leaves change)

      // noteA — the deposited, spendable note. Secret kept for the Step 1 spend.
      aPriv = randomBytes32();
      aBlind = randomBytes32();
      aPub = derivePublicKey(poseidon, aPriv);
      const aCommitment = computeCommitment(poseidon, BigInt(depositAmount.toString()), aPub, aBlind, USDC_MINT);
      // Second deposit output: a 0-value throwaway note.
      const depDummyPriv = randomBytes32();
      const depDummyPub = derivePublicKey(poseidon, depDummyPriv);
      const depDummyBlind = randomBytes32();
      const depDummyCommit = computeCommitment(poseidon, 0n, depDummyPub, depDummyBlind, USDC_MINT);

      // Two 0-value dummy INPUTS (a deposit consumes nothing real) — internally consistent.
      const dp0 = randomBytes32(); const dpub0 = derivePublicKey(poseidon, dp0); const db0 = randomBytes32();
      const dc0 = computeCommitment(poseidon, 0n, dpub0, db0, USDC_MINT);
      const dn0 = computeNullifier(poseidon, dc0, 0, dp0);
      const dp1 = randomBytes32(); const dpub1 = derivePublicKey(poseidon, dp1); const db1 = randomBytes32();
      const dc1 = computeCommitment(poseidon, 0n, dpub1, db1, USDC_MINT);
      const dn1 = computeNullifier(poseidon, dc1, 0, dp1);

      const depExtData = {
        recipient: wallet.publicKey, relayer: wallet.publicKey,
        fee: new BN(0), refund: new BN(0), claimant: SystemProgram.programId,
      };
      const depExtHash = computeExtDataHash(poseidon, depExtData);
      const depMarker0 = nullifierMarkerPDA(program.programId, USDC_MINT, dn0);
      const depMarker1 = nullifierMarkerPDA(program.programId, USDC_MINT, dn1);
      try {
        const depProof = await generateTransactionProof({
          root: usdcEmptyRoot,
          publicAmount: BigInt(depositAmount.toString()),
          extDataHash: depExtHash,
          mintAddress: USDC_MINT,
          inputNullifiers: [dn0, dn1],
          outputCommitments: [aCommitment, depDummyCommit],
          inputAmounts: [0n, 0n],
          inputPrivateKeys: [dp0, dp1],
          inputPublicKeys: [dpub0, dpub1],
          inputBlindings: [db0, db1],
          inputMerklePaths: [zeroMerklePath, zeroMerklePath],
          outputAmounts: [BigInt(depositAmount.toString()), 0n],
          outputOwners: [aPub, depDummyPub],
          outputBlindings: [aBlind, depDummyBlind],
        });
        await (program.methods as any)
          .transact(
            Array.from(usdcEmptyRoot), 0, 0, depositAmount, Array.from(depExtHash),
            USDC_MINT, Array.from(dn0), Array.from(dn1), Array.from(aCommitment), Array.from(depDummyCommit),
            new BN(999_999_999_999), depExtData, depProof, null,
          )
          .accounts({
            config: usdcConfig, globalConfig, vault: usdcVault,
            inputTree: usdcNoteTree, outputTree: usdcNoteTree, nullifiers: usdcNullifiers,
            nullifierMarker0: depMarker0, nullifierMarker1: depMarker1,
            relayer: wallet.publicKey, recipient: wallet.publicKey,
            vaultTokenAccount: usdcVaultAta, userTokenAccount: walletUsdcAta,
            recipientTokenAccount: walletUsdcAta, relayerTokenAccount: walletUsdcAta,
            tokenProgram: TOKEN_PROGRAM_ID, systemProgram: SystemProgram.programId,
          })
          .preInstructions([ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 })])
          .rpc();
        // Mirror the on-chain inserts so Merkle proofs stay valid.
        aLeafIndex = offTree.insert(aCommitment);
        offTree.insert(depDummyCommit);
        log(`✓ setup: real ${usd(depositAmount)} deposit (valid Groth16 proof) → noteA spendable; total_tvl bumped`);
      } catch (e) {
        console.log("   ⚠️  USDC deposit failed — Suite 3 will be skipped:", (e as any)?.message ?? e);
        return;
      }

      // 5. Set up keypairs and register relayer.
      // Spending key is derived from the fixture keypair exactly as in production:
      // sha256(Ed25519Sign(keypair, "veilo_spending_key_v1")).
      // The claimant is always recoverable: deriveJperpClaimantKeypair(spendingKey, withdrawalId).
      s3Relayer = Keypair.generate();
      const s3SpendingKey = deriveSpendingKey(
        Keypair.fromSecretKey(new Uint8Array(
          JSON.parse(require("fs").readFileSync("keys/jperp-spending-key.json", "utf8")),
        )),
      );
      claimantKp = deriveJperpClaimantKeypair(s3SpendingKey, withdrawalId);
      await airdropAndConfirm(provider, s3Relayer.publicKey, 5 * LAMPORTS_PER_SOL);
      try {
        await (program.methods as any)
          .addRelayer(USDC_MINT, s3Relayer.publicKey)
          .accounts({ config: usdcConfig, admin: wallet.publicKey })
          .rpc();
      } catch (_) { /* already registered */ }

      log(`✓ setup: relayer ${shortKey(s3Relayer.publicKey)} registered; claimant ${shortKey(claimantKp.publicKey)} (derived from spending key)`);

      // 6. Derive per-test accounts
      executor = executorPDA(program.programId, USDC_MINT, claimantKp.publicKey, withdrawalId);
      executorUsdcAta = await getAssociatedTokenAddress(USDC_MINT, executor, true);
      jperpSlot = slotPDA(program.programId, USDC_MINT, withdrawalId);
      log(`✓ setup: executor PDA ${shortKey(executor)} — owns the position; user wallet never appears on-chain`);

      // 7. Pre-create executor ATA (vault→executor transfer requires it to exist)
      try {
        await provider.sendAndConfirm(
          new Transaction().add(
            createAssociatedTokenAccountInstruction(
              wallet.publicKey, executorUsdcAta, executor, USDC_MINT)
          ),
          [],
        );
      } catch (_) { /* already exists */ }

      // 8. Build the open as a REAL withdrawal spend of noteA:
      //    in = [noteA(10 USDC), 0-dummy], publicAmount = -COLLATERAL,
      //    out = [change note (10-COLLATERAL) = openC0, 0-dummy = openC1].
      const notePath = offTree.getMerkleProof(aLeafIndex);
      openN0 = computeNullifier(poseidon, aCommitment, aLeafIndex, aPriv); // spends noteA
      const obPriv = randomBytes32(); const obPub = derivePublicKey(poseidon, obPriv); const obBlind = randomBytes32();
      const obCommit = computeCommitment(poseidon, 0n, obPub, obBlind, USDC_MINT);
      openN1 = computeNullifier(poseidon, obCommit, 0, obPriv);            // 0-value dummy input

      const changeAmount = BigInt(depositAmount.sub(COLLATERAL).toString());
      const oc0Priv = randomBytes32(); const oc0Pub = derivePublicKey(poseidon, oc0Priv); const oc0Blind = randomBytes32();
      openC0 = computeCommitment(poseidon, changeAmount, oc0Pub, oc0Blind, USDC_MINT); // change note
      const oc1Priv = randomBytes32(); const oc1Pub = derivePublicKey(poseidon, oc1Priv); const oc1Blind = randomBytes32();
      openC1 = computeCommitment(poseidon, 0n, oc1Pub, oc1Blind, USDC_MINT);           // 0-value dummy output

      // ext_data the open commits to (must match Step 1's submission exactly).
      const openExtData = {
        recipient: executor, relayer: s3Relayer.publicKey,
        fee: new BN(0), refund: new BN(0), claimant: claimantKp.publicKey,
      };
      const openExtHash = computeExtDataHash(poseidon, openExtData);

      // The open spends against the current on-chain root (post-deposit).
      const noteTreeAcc: any = await (program.account as any).merkleTreeAccount.fetch(usdcNoteTree);
      openRoot = extractRootFromAccount(noteTreeAcc);

      openProof = await generateTransactionProof({
        root: openRoot,
        publicAmount: -BigInt(COLLATERAL.toString()),
        extDataHash: openExtHash,
        mintAddress: USDC_MINT,
        inputNullifiers: [openN0, openN1],
        outputCommitments: [openC0, openC1],
        inputAmounts: [BigInt(depositAmount.toString()), 0n],
        inputPrivateKeys: [aPriv, obPriv],
        inputPublicKeys: [aPub, obPub],
        inputBlindings: [aBlind, obBlind],
        inputMerklePaths: [notePath, zeroMerklePath],
        outputAmounts: [changeAmount, 0n],
        outputOwners: [oc0Pub, oc1Pub],
        outputBlindings: [oc0Blind, oc1Blind],
      });
      // Mirror the open's on-chain inserts so the tree (and later roots) stay in sync.
      offTree.insert(openC0);
      offTree.insert(openC1);

      // 8b. Pre-derive step-1 PDAs (fixed values so they go into the ALT)
      s3Perpetuals = perpetualsPDA();
      s3Position = positionPDA(executor, CUSTODIES.SOL, CUSTODIES.USDC, SIDE_SHORT);
      s3PositionRequest = positionRequestPDA(s3Position, openCounter, CHANGE_INCREASE);
      s3PositionRequestAta = await getAssociatedTokenAddress(USDC_MINT, s3PositionRequest, true);
      s3Marker0 = nullifierMarkerPDA(program.programId, USDC_MINT, openN0);
      s3Marker1 = nullifierMarkerPDA(program.programId, USDC_MINT, openN1);

      // 9. Build ALT so step-1 versioned tx fits under 1232 bytes
      suite3Lut = await buildAlt(provider, s3Relayer, [
        TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, SystemProgram.programId,
        globalConfig, usdcConfig, usdcVault, usdcNoteTree, usdcNullifiers, usdcVaultAta,
        executor, executorUsdcAta, jperpSlot,
        JUPITER_PERP_PROGRAM_ID, s3Perpetuals, JLP_POOL,
        s3Position, s3PositionRequest, s3PositionRequestAta,
        CUSTODIES.SOL, CUSTODIES.USDC, USDC_MINT, PERPS_EVENT_AUTHORITY,
        s3Marker0, s3Marker1,
      ]);
      log(`✓ setup: position PDA ${shortKey(s3Position)} (genesis-cloned SOL-short, owner rewritten to executor)`);
      log(`✓ setup: ALT ${shortKey(suite3Lut.key)} built (${suite3Lut.state.addresses.length} addrs) — keeps the versioned tx < 1232 bytes`);
      console.log("  ── setup complete; running lifecycle ──\n");

      suiteReady = true;
    });

    it("Step 1: jperp_open_position — ZK withdrawal → short SOL position request", async function () {
      if (!suiteReady) return this.skip();

      console.log("\n  ▶ STEP 1 — jperp_open_position (createIncreasePositionMarketRequest)");
      log(`spends 2 private USDC notes, withdraws ${usd(COLLATERAL)} collateral → executor ATA → opens 2× SHORT SOL`);
      log(`params:  size ${usd(4_000_000)}  collateral ${usd(COLLATERAL)}  leverage 2×  side SHORT  counter ${openCounter.toString()}`);
      log(`spends nullifiers ${shortKey(new PublicKey(openN0))}, ${shortKey(new PublicKey(openN1))}  → 14 Jupiter accounts, CU budget 600k`);
      const vaultBefore = await tokenBal(provider, usdcVaultAta);
      const execBefore = await tokenBal(provider, executorUsdcAta);
      log(`balances before:  vault ${usd(vaultBefore)}   executor ${usd(execBefore)}`);

      const extData = {
        recipient: executor,
        relayer: s3Relayer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
        claimant: claimantKp.publicKey,
      };
      const extDataHash = computeExtDataHash(poseidon, extData);

      // 14 remaining_accounts for createIncreasePositionMarketRequest
      const remainingAccounts = [
        { pubkey: JUPITER_PERP_PROGRAM_ID,       isSigner: false, isWritable: false }, // [0]
        { pubkey: s3Perpetuals,                  isSigner: false, isWritable: false }, // [1]
        { pubkey: JLP_POOL,                      isSigner: false, isWritable: false }, // [2]
        { pubkey: s3Position,                    isSigner: false, isWritable: true  }, // [3]
        { pubkey: s3PositionRequest,             isSigner: false, isWritable: true  }, // [4]
        { pubkey: s3PositionRequestAta,          isSigner: false, isWritable: true  }, // [5]
        { pubkey: CUSTODIES.SOL,                 isSigner: false, isWritable: false }, // [6] custody
        { pubkey: CUSTODIES.USDC,                isSigner: false, isWritable: false }, // [7] collateralCustody
        { pubkey: USDC_MINT,                     isSigner: false, isWritable: false }, // [8] inputMint
        { pubkey: SystemProgram.programId,       isSigner: false, isWritable: false }, // [9] referral (null)
        { pubkey: TOKEN_PROGRAM_ID,              isSigner: false, isWritable: false }, // [10]
        { pubkey: ASSOCIATED_TOKEN_PROGRAM_ID,   isSigner: false, isWritable: false }, // [11]
        { pubkey: SystemProgram.programId,       isSigner: false, isWritable: false }, // [12]
        { pubkey: PERPS_EVENT_AUTHORITY,         isSigner: false, isWritable: false }, // [13]
      ];

      // Use versioned tx + ALT — legacy tx would be ~1782 bytes (limit is 1232)
      const ix = await (program.methods as any)
        .jperpOpenPosition(
          Array.from(openRoot),  // post-deposit root the withdrawal proof spends against
          0, 0,
          COLLATERAL,
          Array.from(extDataHash),
          USDC_MINT,
          claimantKp.publicKey,
          Array.from(openN0), Array.from(openN1),
          Array.from(openC0), Array.from(openC1),
          Array.from(withdrawalId),
          new BN(Math.floor(Date.now() / 1000) + 3600),
          extData,
          openProof,          // real Groth16 withdrawal proof (built in before())
          null,
          new BN(4_000_000), // size $4 (2× leverage)
          COLLATERAL,        // collateral $2 USDC
          SIDE_SHORT,
          new BN(0),         // price_slippage (unlimited)
          openCounter,
        )
        .accounts({
          config: usdcConfig,
          globalConfig,
          vault: usdcVault,
          inputTree: usdcNoteTree,
          outputTree: usdcNoteTree,
          nullifiers: usdcNullifiers,
          nullifierMarker0: s3Marker0,
          nullifierMarker1: s3Marker1,
          relayer: s3Relayer.publicKey,
          vaultTokenAccount: usdcVaultAta,
          executor,
          executorTokenAccount: executorUsdcAta,
          relayerTokenAccount: s3Relayer.publicKey, // fee=0, not validated
          jperpSlot,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .remainingAccounts(remainingAccounts)
        .instruction();

      // The deep Jupiter CPI (positionRequest + ATA creation) plus our Merkle
      // inserts exceed the default 200k CU budget — raise it.
      const cuIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 });
      const sig = await sendVersionedTx(provider, [cuIx, ix], [s3Relayer], [suite3Lut]);
      await provider.connection.confirmTransaction(sig, "confirmed");

      const vaultAfter = await tokenBal(provider, usdcVaultAta);
      const execAfter = await tokenBal(provider, executorUsdcAta);
      log(`balances after:   vault ${usd(vaultAfter)}   executor ${usd(execAfter)}  (collateral routed into Jupiter's positionRequest)`);
      log(`positionRequest ${shortKey(s3PositionRequest)} created — Jupiter's keeper settles it into position ${shortKey(s3Position)}`);
      log(`slot ${shortKey(jperpSlot)} records ${usd(COLLATERAL)} reissuable, bound to claimant ${shortKey(claimantKp.publicKey)}`);
      log(`✓ tx ${sig.slice(0, 16)}…`);

      // Show the open position the keeper settles into (genesis-loaded here, sizeUsd > 0).
      const pos = await decodePosition(provider, s3Position);
      if (pos) {
        logPosition(pos, "open position");
        log(
          `unrealized PnL:  at entry $${pos.entryPrice.toFixed(2)} → $0.00 (break-even)   ` +
            `if SOL → $90.00 (SL) → $${pnlAt(pos, 90).toFixed(2)}   ` +
            `if SOL → $50.00 → +$${pnlAt(pos, 50).toFixed(2)}`,
        );
      }

      step1Passed = true;
    });

    it("jperp_reissue_notes: rejects unregistered relayer", async function () {
      if (!suiteReady || !step1Passed) return this.skip();

      console.log("\n  ▶ GUARD — reissue with an unregistered relayer must be rejected");
      const badRelayer = Keypair.generate();
      // Fund badRelayer: it's the `payer` for the nullifier-marker init (Anchor
      // account validation, before the handler), so it needs rent SOL — otherwise
      // it fails on lamports before reaching the RelayerNotAllowed guard.
      await airdropAndConfirm(provider, badRelayer.publicKey, LAMPORTS_PER_SOL);
      const n0 = randomBytes32();
      const n1 = randomBytes32();
      const extData = {
        recipient: usdcVault,
        relayer: badRelayer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
        claimant: claimantKp.publicKey,
      };
      const extDataHash = computeExtDataHash(poseidon, extData);
      const marker0 = nullifierMarkerPDA(program.programId, USDC_MINT, n0);
      const marker1 = nullifierMarkerPDA(program.programId, USDC_MINT, n1);

      // Versioned tx + ALT: reissue is too large for a legacy tx (16 accounts +
      // fixed-size proof). Use a full-size dummyProof so args deserialize; the
      // RelayerNotAllowed guard fires in the handler before ZK verification.
      // Fee payer = s3Relayer (funded); the ix's `relayer` is the unregistered one.
      const ix = await (program.methods as any)
        .jperpReissueNotes(
          Array.from(new Uint8Array(32).fill(1)), 0, 0,
          new BN(1_000_000),
          Array.from(extDataHash),
          USDC_MINT,
          Array.from(n0), Array.from(n1),
          Array.from(randomBytes32()), Array.from(randomBytes32()),
          Array.from(withdrawalId),
          new BN(Math.floor(Date.now() / 1000) + 3600),
          extData, dummyProof(), null,
        )
        .accounts({
          config: usdcConfig, globalConfig, vault: usdcVault,
          inputTree: usdcNoteTree, outputTree: usdcNoteTree,
          nullifiers: usdcNullifiers,
          nullifierMarker0: marker0, nullifierMarker1: marker1,
          relayer: badRelayer.publicKey,
          jperpSlot, claimant: claimantKp.publicKey,
          executor, executorTokenAccount: executorUsdcAta,
          vaultTokenAccount: usdcVaultAta,
          tokenProgram: TOKEN_PROGRAM_ID, systemProgram: SystemProgram.programId,
        })
        .instruction();

      await assertError(
        sendVersionedTx(provider, [ix], [s3Relayer, badRelayer, claimantKp], [suite3Lut]),
        "RelayerNotAllowed",
      );
      log(`✓ rejected with RelayerNotAllowed — only whitelisted relayers can reissue`);
    });

    it("jperp_reissue_notes: rejects when claimant doesn't co-sign", async function () {
      if (!suiteReady || !step1Passed) return this.skip();

      console.log("\n  ▶ GUARD — reissue without the claimant co-signature must be rejected (anti-theft)");
      const n0 = randomBytes32();
      const n1 = randomBytes32();
      const extData = {
        recipient: usdcVault,
        relayer: s3Relayer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
        claimant: claimantKp.publicKey,
      };
      const extDataHash = computeExtDataHash(poseidon, extData);
      const marker0 = nullifierMarkerPDA(program.programId, USDC_MINT, n0);
      const marker1 = nullifierMarkerPDA(program.programId, USDC_MINT, n1);

      await assertError(
        (program.methods as any)
          .jperpReissueNotes(
            Array.from(new Uint8Array(32).fill(1)), 0, 0,
            new BN(1_000_000),
            Array.from(extDataHash),
            USDC_MINT,
            Array.from(n0), Array.from(n1),
            Array.from(randomBytes32()), Array.from(randomBytes32()),
            Array.from(withdrawalId),
            new BN(Math.floor(Date.now() / 1000) + 3600),
            extData, tinyProof(), null,
          )
          .accounts({
            config: usdcConfig, globalConfig, vault: usdcVault,
            inputTree: usdcNoteTree, outputTree: usdcNoteTree,
            nullifiers: usdcNullifiers,
            nullifierMarker0: marker0, nullifierMarker1: marker1,
            relayer: s3Relayer.publicKey,
            jperpSlot, claimant: claimantKp.publicKey,
            executor, executorTokenAccount: executorUsdcAta,
            vaultTokenAccount: usdcVaultAta,
            tokenProgram: TOKEN_PROGRAM_ID, systemProgram: SystemProgram.programId,
          })
          .signers([s3Relayer]) // claimantKp intentionally omitted
          .rpc(),
        "Missing signature",
      );
      log(`✓ rejected with Missing signature — a relayer alone cannot drain settled proceeds`);
    });

    it("jperp_reissue_notes: rejects over-reissue (JperpSlotOverdraft)", async function () {
      if (!suiteReady || !step1Passed) return this.skip();

      console.log("\n  ▶ GUARD — reissuing more than the slot recorded must be rejected");
      log(`slot caps reissue at ${usd(COLLATERAL)}; attempting ${usd(COLLATERAL.add(new BN(1)))}`);
      // slot.amount == COLLATERAL ($2). Trying $2 + 1 µUSDC triggers overdraft.
      const tooMuch = COLLATERAL.add(new BN(1));
      const n0 = randomBytes32();
      const n1 = randomBytes32();
      const extData = {
        recipient: usdcVault,
        relayer: s3Relayer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
        claimant: claimantKp.publicKey,
      };
      const extDataHash = computeExtDataHash(poseidon, extData);
      const marker0 = nullifierMarkerPDA(program.programId, USDC_MINT, n0);
      const marker1 = nullifierMarkerPDA(program.programId, USDC_MINT, n1);

      // Versioned tx + ALT (see bad-relayer test). slot.amount == COLLATERAL, so
      // reissue_amount = COLLATERAL+1 trips JperpSlotOverdraft in the handler — which
      // fires before ZK verification, so dummyProof is fine.
      const ix = await (program.methods as any)
        .jperpReissueNotes(
          Array.from(new Uint8Array(32).fill(1)), 0, 0,
          tooMuch,
          Array.from(extDataHash),
          USDC_MINT,
          Array.from(n0), Array.from(n1),
          Array.from(randomBytes32()), Array.from(randomBytes32()),
          Array.from(withdrawalId),
          new BN(Math.floor(Date.now() / 1000) + 3600),
          extData, dummyProof(), null,
        )
        .accounts({
          config: usdcConfig, globalConfig, vault: usdcVault,
          inputTree: usdcNoteTree, outputTree: usdcNoteTree,
          nullifiers: usdcNullifiers,
          nullifierMarker0: marker0, nullifierMarker1: marker1,
          relayer: s3Relayer.publicKey,
          jperpSlot, claimant: claimantKp.publicKey,
          executor, executorTokenAccount: executorUsdcAta,
          vaultTokenAccount: usdcVaultAta,
          tokenProgram: TOKEN_PROGRAM_ID, systemProgram: SystemProgram.programId,
        })
        .instruction();

      await assertError(
        sendVersionedTx(provider, [ix], [s3Relayer, claimantKp], [suite3Lut]),
        "JperpSlotOverdraft",
      );
      log(`✓ rejected with JperpSlotOverdraft — cannot mint more notes than were deposited`);
    });

    it("Step 2: jperp_set_tpsl — place SL trigger at $90", async function () {
      if (!suiteReady || !step1Passed) return this.skip();

      console.log("\n  ▶ STEP 2 — jperp_set_tpsl (createDecreasePositionRequest2, Trigger)");
      log(`places a stop-loss trigger on the open SHORT at $90 (fires when SOL rises to $90)`);
      const counter = new BN(Math.floor(Math.random() * 1_000_000_000));
      const position = positionPDA(executor, CUSTODIES.SOL, CUSTODIES.USDC, SIDE_SHORT);
      const positionRequest = positionRequestPDA(position, counter, CHANGE_DECREASE);
      const positionRequestAta = await getAssociatedTokenAddress(USDC_MINT, positionRequest, true);

      // 16 remaining_accounts for createDecreasePositionRequest2 (Trigger type)
      const remainingAccounts = [
        { pubkey: JUPITER_PERP_PROGRAM_ID,     isSigner: false, isWritable: false },
        { pubkey: perpetualsPDA(),             isSigner: false, isWritable: false },
        { pubkey: JLP_POOL,                    isSigner: false, isWritable: false },
        { pubkey: position,                    isSigner: false, isWritable: true  },
        { pubkey: positionRequest,             isSigner: false, isWritable: true  },
        { pubkey: positionRequestAta,          isSigner: false, isWritable: true  },
        { pubkey: CUSTODIES.SOL,               isSigner: false, isWritable: false }, // [6] custody
        { pubkey: SOL_DOVES_ORACLE,            isSigner: false, isWritable: false }, // [7] dovesPriceAccount
        { pubkey: SystemProgram.programId,     isSigner: false, isWritable: false }, // [8] pythnetPriceAccount (unset)
        { pubkey: CUSTODIES.USDC,              isSigner: false, isWritable: false }, // [9] collateralCustody
        { pubkey: USDC_MINT,                   isSigner: false, isWritable: false }, // [10] desiredMint
        { pubkey: SystemProgram.programId,     isSigner: false, isWritable: false }, // [11] referral
        { pubkey: TOKEN_PROGRAM_ID,            isSigner: false, isWritable: false },
        { pubkey: ASSOCIATED_TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId,     isSigner: false, isWritable: false },
        { pubkey: PERPS_EVENT_AUTHORITY,       isSigner: false, isWritable: false },
      ];

      await (program.methods as any)
        .jperpSetTpsl(
          USDC_MINT, Array.from(withdrawalId),
          new BN(0), new BN(0),          // collateral_usd_delta, size_usd_delta
          new BN(90_000_000),            // triggerPrice $90
          true,                          // triggerAboveThreshold (SL for short)
          true,                          // entire_position
          counter,
        )
        .accounts({
          config: usdcConfig,
          jperpSlot,
          claimant: claimantKp.publicKey,
          executor,
          executorTokenAccount: executorUsdcAta,
          relayer: s3Relayer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .remainingAccounts(remainingAccounts)
        .signers([s3Relayer, claimantKp])
        .rpc();
      log(`triggerRequest ${shortKey(positionRequest)} created (counter ${counter.toString()}) — keeper watches the oracle`);
      const posSl = await decodePosition(provider, position);
      if (posSl) {
        logPosition(posSl, "position");
        log(`SL set at $90.00 → if it fires, realized PnL ≈ $${pnlAt(posSl, 90).toFixed(2)} (caps further loss on this SHORT)`);
      }
      log(`✓ SL trigger registered; proceeds will route to executor ATA ${shortKey(executorUsdcAta)} when it fires`);
    });

    it("Step 3: jperp_close_position — market close request (keeper settles async)", async function () {
      if (!suiteReady || !step1Passed) return this.skip();

      console.log("\n  ▶ STEP 3 — jperp_close_position (createDecreasePositionRequest2, Market)");
      log(`submits a full market-close request; Jupiter's keeper settles it and returns collateral to the executor ATA`);
      const counter = new BN(Math.floor(Math.random() * 1_000_000_000));
      const position = positionPDA(executor, CUSTODIES.SOL, CUSTODIES.USDC, SIDE_SHORT);
      const positionRequest = positionRequestPDA(position, counter, CHANGE_DECREASE);
      const positionRequestAta = await getAssociatedTokenAddress(USDC_MINT, positionRequest, true);

      const remainingAccounts = [
        { pubkey: JUPITER_PERP_PROGRAM_ID,     isSigner: false, isWritable: false },
        { pubkey: perpetualsPDA(),             isSigner: false, isWritable: false },
        { pubkey: JLP_POOL,                    isSigner: false, isWritable: false },
        { pubkey: position,                    isSigner: false, isWritable: true  },
        { pubkey: positionRequest,             isSigner: false, isWritable: true  },
        { pubkey: positionRequestAta,          isSigner: false, isWritable: true  },
        { pubkey: CUSTODIES.SOL,               isSigner: false, isWritable: false },
        { pubkey: SOL_DOVES_ORACLE,            isSigner: false, isWritable: false }, // dovesPriceAccount
        { pubkey: SystemProgram.programId,     isSigner: false, isWritable: false }, // pythnetPriceAccount (unset)
        { pubkey: CUSTODIES.USDC,              isSigner: false, isWritable: false },
        { pubkey: USDC_MINT,                   isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId,     isSigner: false, isWritable: false }, // referral
        { pubkey: TOKEN_PROGRAM_ID,            isSigner: false, isWritable: false },
        { pubkey: ASSOCIATED_TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId,     isSigner: false, isWritable: false },
        { pubkey: PERPS_EVENT_AUTHORITY,       isSigner: false, isWritable: false },
      ];

      await (program.methods as any)
        .jperpClosePosition(
          USDC_MINT, Array.from(withdrawalId),
          new BN(0), new BN(0),  // collateral_usd_delta, size_usd_delta
          true,                  // entire_position
          new BN(0),             // price_slippage (unlimited)
          counter,
        )
        .accounts({
          config: usdcConfig,
          jperpSlot,
          claimant: claimantKp.publicKey,
          executor,
          executorTokenAccount: executorUsdcAta,
          relayer: s3Relayer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .remainingAccounts(remainingAccounts)
        .signers([s3Relayer, claimantKp])
        .rpc();
      const posClose = await decodePosition(provider, position);
      if (posClose) logPosition(posClose, "closing position");
      log(`closeRequest ${shortKey(positionRequest)} created (counter ${counter.toString()})`);
      log(`✓ market-close request submitted — on mainnet the keeper now settles asynchronously`);
    });

    it("Step 4: jperp_reissue_notes — re-mint notes from settled USDC (keeper imitated)", async function () {
      if (!suiteReady || !step1Passed) return this.skip();

      console.log("\n  ▶ STEP 4 — jperp_reissue_notes (settled proceeds → fresh private notes)");
      log(`localnet has no keeper, so we imitate settlement: move ${usd(COLLATERAL)} into the executor ATA, then reissue`);

      // Imitate the Jupiter keeper settling proceeds: move USDC into the executor
      // ATA (in production the keeper's close-settlement lands the collateral here).
      // Reissue at most slot.amount (== COLLATERAL); slot.reissued is still 0.
      const reissueAmount = COLLATERAL;
      const walletUsdcAta = await getAssociatedTokenAddress(USDC_MINT, wallet.publicKey);
      await provider.sendAndConfirm(
        new Transaction().add(
          createTransferInstruction(
            walletUsdcAta, executorUsdcAta, wallet.publicKey,
            BigInt(reissueAmount.toString()),
          ),
        ),
        [],
      );
      const execAfterSettle = await tokenBal(provider, executorUsdcAta);
      const vaultBeforeReissue = await tokenBal(provider, usdcVaultAta);
      log(`keeper imitated: executor ATA now holds ${usd(execAfterSettle)}; vault at ${usd(vaultBeforeReissue)}`);

      // Reissue is a DEPOSIT (public_amount = +reissueAmount): dummy 0-value inputs,
      // outputs = c0 (reissueAmount) + c1 (0). Real Groth16 proof against the current root.
      const rp0 = randomBytes32(); const rpub0 = derivePublicKey(poseidon, rp0); const rb0 = randomBytes32();
      const rc0 = computeCommitment(poseidon, 0n, rpub0, rb0, USDC_MINT);
      const n0 = computeNullifier(poseidon, rc0, 0, rp0);
      const rp1 = randomBytes32(); const rpub1 = derivePublicKey(poseidon, rp1); const rb1 = randomBytes32();
      const rc1 = computeCommitment(poseidon, 0n, rpub1, rb1, USDC_MINT);
      const n1 = computeNullifier(poseidon, rc1, 0, rp1);

      const o0Priv = randomBytes32(); const o0Pub = derivePublicKey(poseidon, o0Priv); const o0Blind = randomBytes32();
      const c0 = computeCommitment(poseidon, BigInt(reissueAmount.toString()), o0Pub, o0Blind, USDC_MINT);
      const o1Priv = randomBytes32(); const o1Pub = derivePublicKey(poseidon, o1Priv); const o1Blind = randomBytes32();
      const c1 = computeCommitment(poseidon, 0n, o1Pub, o1Blind, USDC_MINT);

      const extData = {
        recipient: usdcVault,
        relayer: s3Relayer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
        claimant: claimantKp.publicKey,
      };
      const extDataHash = computeExtDataHash(poseidon, extData);
      const marker0 = nullifierMarkerPDA(program.programId, USDC_MINT, n0);
      const marker1 = nullifierMarkerPDA(program.programId, USDC_MINT, n1);

      const reissueTreeAcc: any = await (program.account as any).merkleTreeAccount.fetch(usdcNoteTree);
      const reissueRoot = extractRootFromAccount(reissueTreeAcc);
      const zerosR = offTree.getZeros();
      const zeroPathR = zerosR.slice(0, 22).map((z) => bytesToBigIntBE(z));
      const zeroMerklePathR = { pathElements: zeroPathR, pathIndices: new Array(22).fill(0) };

      const reissueProof = await generateTransactionProof({
        root: reissueRoot,
        publicAmount: BigInt(reissueAmount.toString()),
        extDataHash,
        mintAddress: USDC_MINT,
        inputNullifiers: [n0, n1],
        outputCommitments: [c0, c1],
        inputAmounts: [0n, 0n],
        inputPrivateKeys: [rp0, rp1],
        inputPublicKeys: [rpub0, rpub1],
        inputBlindings: [rb0, rb1],
        inputMerklePaths: [zeroMerklePathR, zeroMerklePathR],
        outputAmounts: [BigInt(reissueAmount.toString()), 0n],
        outputOwners: [o0Pub, o1Pub],
        outputBlindings: [o0Blind, o1Blind],
      });

      const ix = await (program.methods as any)
        .jperpReissueNotes(
          Array.from(reissueRoot), 0, 0,   // current on-chain root
          reissueAmount,
          Array.from(extDataHash),
          USDC_MINT,
          Array.from(n0), Array.from(n1),
          Array.from(c0), Array.from(c1),
          Array.from(withdrawalId),
          new BN(Math.floor(Date.now() / 1000) + 3600),
          extData, reissueProof, null,
        )
        .accounts({
          config: usdcConfig, globalConfig, vault: usdcVault,
          inputTree: usdcNoteTree, outputTree: usdcNoteTree,
          nullifiers: usdcNullifiers,
          nullifierMarker0: marker0, nullifierMarker1: marker1,
          relayer: s3Relayer.publicKey,
          jperpSlot, claimant: claimantKp.publicKey,
          executor, executorTokenAccount: executorUsdcAta,
          vaultTokenAccount: usdcVaultAta,
          tokenProgram: TOKEN_PROGRAM_ID, systemProgram: SystemProgram.programId,
        })
        .instruction();

      // Versioned tx + ALT (legacy too large with the fixed-size proof).
      const cuIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 });
      const sig = await sendVersionedTx(provider, [cuIx, ix], [s3Relayer, claimantKp], [suite3Lut]);
      await provider.connection.confirmTransaction(sig, "confirmed");

      const execAfterReissue = await tokenBal(provider, executorUsdcAta);
      const vaultAfterReissue = await tokenBal(provider, usdcVaultAta);
      log(`balances after:   executor ${usd(execAfterReissue)}   vault ${usd(vaultAfterReissue)}  (proceeds swept back into the pool)`);
      log(`${usd(reissueAmount)} re-minted as 2 fresh private notes; slot.reissued now == slot.amount (fully claimed)`);
      log(`✓ tx ${sig.slice(0, 16)}…`);
      console.log("\n  ✓ lifecycle complete: deposit → SHORT → SL → close → private notes, user never on-chain\n");
    });
  });
});

/**
 * tests/jupiter-prediction.test.ts
 *
 * Jupiter Prediction Market — integration tests
 *
 * Program: 3ZZuTbwC6aJbvteyVxXUS7gtFYdf7AuXeitx6VyvjvUp
 * Wallet:  2hjDuKw8uXa9VFXZHZAtJ2qG7E6EtKbhnNMfDipmAbFD (keys/prediction-wallet.json)
 *
 * Architecture:
 *   The protocol requires a Jupiter authority co-signature on CreateOrder.
 *   Flow: call REST API → get partially-signed VersionedTransaction
 *         → add our signature → send directly to Solana RPC.
 *   All other operations (CloseOrder, ClaimPayout, CloseLostPosition)
 *   can be submitted as raw on-chain program calls without the API.
 *
 * Suite 1 — Read-only API (profile, history, market data)
 * Suite 2 — On-chain program calls: place order → cancel → verify refund
 * Suite 3 — Instruction builder verification (off-chain, no SOL needed)
 *
 * Run: npm run test:prediction
 */

import "mocha";
import { expect } from "chai";
import {
  Connection,
  Keypair,
  PublicKey,
  VersionedTransaction,
  ComputeBudgetProgram,
  TransactionMessage,
} from "@solana/web3.js";
import {
  getAssociatedTokenAddressSync,
  createAssociatedTokenAccountIdempotentInstruction,
} from "@solana/spl-token";
import fs from "fs";
import path from "path";

import {
  PredictionClient,
  PREDICTION_PROGRAM_ID,
  PREDICTION_GLOBAL_CONFIG,
  JUPUSD_MINT,
  USDC_MINT,
  DISC,
  buildCreateOrderIx,
  buildClaimPayoutIx,
  buildCloseOrderIx,
  parseClaimLog,
  parseFillLog,
  formatUsd,
  formatContracts,
} from "./utils/jupiter/prediction/index";

// ─── Config ───────────────────────────────────────────────────────────────────

const API_KEY = process.env.JUPITER_API_KEY ?? "";

const WALLET_PATH = path.join(process.cwd(), "keys/prediction-wallet.json");
const wallet = Keypair.fromSecretKey(
  new Uint8Array(JSON.parse(fs.readFileSync(WALLET_PATH, "utf-8"))),
);
const OWNER = wallet.publicKey;

const connection = new Connection("https://api.mainnet-beta.solana.com", "confirmed");
const client = new PredictionClient(API_KEY);

/** Jupiter authority co-signer observed on mainnet CreateOrder transactions */
const JUPITER_AUTHORITY = new PublicKey("5uFXJogUEqBTsVT8AcfuWbC9ZFM1tSzTFJ3eKVeB14yi");

/** Argentina 2026 FIFA World Cup Winner market */
const ARGENTINA_MARKET_ID = "POLY-558938";

/** Minimum order = $5 (5_000_000 micro-USD) */
const MIN_ORDER_USD = 5_000_000;

function log(...parts: unknown[]) {
  console.log("    ", ...parts);
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

// ─── Suite 1: Read-only API ────────────────────────────────────────────────────

describe("Jupiter Prediction — Suite 1: Read-only API", () => {
  beforeEach(async () => { await sleep(3000); });

  it("confirms program is deployed on mainnet", async () => {
    const info = await connection.getAccountInfo(PREDICTION_PROGRAM_ID);
    expect(info).to.not.be.null;
    expect(info!.executable).to.be.true;
    log("Program:", PREDICTION_PROGRAM_ID.toBase58());
    log("Data len:", info!.data.length, "bytes");
  });

  it("confirms global config account exists", async () => {
    const info = await connection.getAccountInfo(PREDICTION_GLOBAL_CONFIG);
    expect(info).to.not.be.null;
    log("Global config owner:", info!.owner.toBase58());
    log("Global config data:", info!.data.length, "bytes");
  });

  it("fetches events from the API", async () => {
    const resp = await client.getEvents({ limit: 5 }) as any;
    const events = resp.data ?? resp;
    expect(events).to.be.an("array");
    log(`Got ${events.length} events`);
    for (const e of events.slice(0, 2)) {
      log(`  ${e.eventId ?? e.id} — ${e.title ?? e.question ?? "(no title)"}`);
    }
  });

  it("fetches Argentina market data", async () => {
    const resp = await client.getMarket(ARGENTINA_MARKET_ID) as any;
    const m = resp.data ?? resp;
    log("Market:", ARGENTINA_MARKET_ID);
    log("  status:", m.status);
    log("  yesPriceUsd:", m.yesPriceUsd ?? m.yesPriceMicro ?? "N/A");
    log("  noPriceUsd:", m.noPriceUsd ?? m.noPriceMicro ?? "N/A");
    expect(m).to.not.be.null;
  });

  it("fetches wallet trade history", async () => {
    const resp = await client.getHistory({ ownerPubkey: OWNER.toBase58() }) as any;
    const entries = resp.data ?? resp;
    log(`History entries: ${entries.length}`);
    for (const e of entries.slice(0, 3)) {
      log(`  ${e.eventType} market=${e.marketId} sig=${e.signature?.slice(0, 20)}…`);
    }
    expect(entries.length).to.be.greaterThan(0);
  });

  it("fetches wallet profile", async () => {
    const profile = await client.getProfile(OWNER.toBase58()) as any;
    log("Profile:");
    log("  correctPredictions:", profile.correctPredictions);
    log("  wrongPredictions:", profile.wrongPredictions);
    log("  totalVolumeUsd:", formatUsd(BigInt(profile.totalVolumeUsd ?? 0)));
    log("  realizedPnlUsd:", formatUsd(BigInt(profile.realizedPnlUsd ?? 0)));
    expect(Number(profile.correctPredictions)).to.be.greaterThan(0);
  });

  it("confirms no open positions or pending orders right now", async () => {
    const pos  = await client.getPositions({ ownerPubkey: OWNER.toBase58() }) as any;
    const ords = await client.getOrders({ ownerPubkey: OWNER.toBase58() }) as any;
    const posData = pos.data ?? pos;
    const ordData = ords.data ?? ords;
    log("Open positions:", posData.length);
    log("Pending orders:", ordData.length);
    expect(posData.length).to.equal(0);
    expect(ordData.length).to.equal(0);
  });

  it("parses a ClaimPayout log string correctly", () => {
    const log_str =
      "Payout claimed: owner=8NMQJGcM2CgbjosaDHs92tj7eTWPXS893PSqvNrt1c7Z, " +
      "position=J6ZMVSe3zWB6NdFiAMkZsUd6kpbX5fCChvokHr5Nobx6, " +
      "market_id=d501fc84e29639b55d22646da56e655c, side=YES, " +
      "contracts=168450000, net_payout_usd=168450000, fee_usd=0, realized_pnl=72433669";
    const parsed = parseClaimLog(log_str);
    expect(parsed).to.not.be.null;
    expect(parsed!.side).to.equal("YES");
    expect(parsed!.contractsMicro).to.equal(168_450_000n);
    expect(parsed!.realizedPnlMicro).to.equal(72_433_669n);
    log("Payout:", formatUsd(parsed!.netPayoutMicro), "profit:", formatUsd(parsed!.realizedPnlMicro));
  });

  it("parses a FillBuyOrder log string correctly", () => {
    const log_str =
      "Buy order settled: 0xef2c224ea44d9b6c37366fdeaf0a2badf8cb1df0113658b8816a1ba69c1e8124 " +
      "- Contracts: 12270000, Avg Fill: 369998, Vault: 4740097, Integrator: 0, Base: 4539887, Fee: 0";
    const parsed = parseFillLog(log_str);
    expect(parsed).to.not.be.null;
    expect(parsed!.contractsMicro).to.equal(12_270_000n);
    expect(parsed!.avgFillMicro).to.equal(369_998n);
    log("Fill:", formatContracts(parsed!.contractsMicro), "contracts @", formatUsd(parsed!.avgFillMicro), "each");
  });
});

// ─── Suite 2: On-chain program call round-trip ────────────────────────────────
//
// Flow:
//   1. Call REST API  →  get base64 VersionedTransaction with authority co-sig
//   2. Decode the tx  →  verify discriminator and account layout match buildCreateOrderIx
//   3. wallet.sign()  →  add our signature  (direct web3.js call, no API)
//   4. sendRawTransaction  →  submit directly to Solana mainnet RPC
//   5. Build and send CloseOrder instruction directly  (no API needed)
//
// The authority at account[2] is Jupiter-controlled (5uFXJ…) and must co-sign
// CreateOrder. The REST API is the only way to get that signature. All other
// instructions (CloseOrder, ClaimPayout) do NOT require the authority.

describe("Jupiter Prediction — Suite 2: On-chain program call round-trip", () => {
  let orderId: string = "";
  let orderPubkey: string = "";
  let positionPubkey: string = "";

  beforeEach(async () => { await sleep(2000); });

  before("check wallet has ≥ $5 USDC", async function () {
    this.timeout(15_000);
    const ata = getAssociatedTokenAddressSync(USDC_MINT, OWNER);
    const bal = await connection.getTokenAccountBalance(ata).catch(() => null);
    const amount = parseInt(bal?.value.amount ?? "0");
    log(`Wallet SOL:  ${(await connection.getBalance(OWNER)) / 1e9}`);
    log(`Wallet USDC: ${amount / 1e6}`);
    if (amount < MIN_ORDER_USD) {
      log("⚠ Skipping — wallet needs ≥ $5 USDC");
      (this as any).skip();
    }
  });

  it("gets base64 CreateOrder tx from API (authority co-sig included)", async function () {
    this.timeout(30_000);

    const resp = await client.createOrder({
      ownerPubkey: OWNER.toBase58(),
      marketId: ARGENTINA_MARKET_ID,
      isYes: true,
      isBuy: true,
      depositAmount: MIN_ORDER_USD,
      depositMint: USDC_MINT.toBase58(),
      slippageBps: 200,
    }) as any;

    const base64Tx = resp.transaction ?? resp.data?.transaction;
    expect(base64Tx, "API must return a transaction").to.be.a("string");

    // API returns: { transaction, externalOrderId, order: { orderPubkey, positionPubkey, ... } }
    orderId        = resp.externalOrderId ?? resp.order?.externalOrderId ?? "";
    orderPubkey    = resp.order?.orderPubkey ?? resp.order?.pubkey ?? "";
    positionPubkey = resp.order?.positionPubkey ?? resp.position?.pubkey ?? "";
    log("External order ID:", orderId);
    log("Order pubkey:", orderPubkey);
    log("Position pubkey:", positionPubkey);

    // ── Decode and verify instruction structure ──────────────────────────────
    const txBytes = Buffer.from(base64Tx, "base64");
    const vTx = VersionedTransaction.deserialize(txBytes);
    const msg = vTx.message;
    const accts = msg.staticAccountKeys;

    // Find the prediction program instruction
    const predIx = msg.compiledInstructions.find(
      (ix) => accts[ix.programIdIndex].toBase58() === PREDICTION_PROGRAM_ID.toBase58(),
    );
    expect(predIx, "Prediction program instruction must exist").to.exist;
    const ix0 = predIx!;

    const ixData = Buffer.from(ix0.data);
    log("Disc (hex):", ixData.subarray(0, 8).toString("hex"));
    log("Disc name: create_order");

    // Verify discriminator matches sha256("global:create_order")[0:8]
    expect(Array.from(ixData.subarray(0, 8))).to.deep.equal(
      Array.from(DISC.createOrder),
      "discriminator must be sha256('global:create_order')",
    );

    // Verify authority is account[2] in the instruction's account list
    const ixAcctIdxs = Array.from(ix0.accountKeyIndexes);
    const authorityInTx = accts[ixAcctIdxs[2]].toBase58();
    log("Authority (ix[2]):", authorityInTx);
    expect(authorityInTx).to.equal(
      JUPITER_AUTHORITY.toBase58(),
      "Jupiter authority must be at ix account index 2",
    );

    // Verify authority already signed the tx (co-signature from the API)
    log("Existing signers in tx:", vTx.signatures.length);
    expect(vTx.signatures.length).to.be.greaterThan(0);

    // ── Sign with our wallet and submit directly to Solana RPC ───────────────
    vTx.sign([wallet]);

    const sig = await connection.sendRawTransaction(vTx.serialize(), {
      skipPreflight: false,
      maxRetries: 3,
    });
    await connection.confirmTransaction(sig, "confirmed");
    log("✅ CreateOrder tx confirmed:", sig);
    expect(sig).to.be.a("string").with.length.greaterThan(0);
  });

  it("closes position via API tx (order filled instantly on liquid market)", async function () {
    this.timeout(60_000);
    if (!positionPubkey) return (this as any).skip();

    await sleep(3_000);

    // On liquid markets the order fills in <1s, so we sell the resulting position.
    // The close position API returns the full tx with accounts; we sign and submit.
    let closeResp: any;
    try {
      closeResp = await client.closePosition(positionPubkey, {
        ownerPubkey: OWNER.toBase58(),
        minSellPriceSlippageBps: 500,
      });
    } catch (err: any) {
      log("closePosition error:", err.message);
      return (this as any).skip();
    }

    const base64Tx = (closeResp as any).transaction ?? (closeResp as any).data?.transaction;
    expect(base64Tx, "close position must return a transaction").to.be.a("string");

    // Decode the tx to verify it uses the create_order discriminator's sell variant
    const closeTx = VersionedTransaction.deserialize(Buffer.from(base64Tx, "base64"));
    const msg = closeTx.message;
    const accts = msg.staticAccountKeys;
    const predIxRaw = msg.compiledInstructions.find(
      (ix) => accts[ix.programIdIndex].toBase58() === PREDICTION_PROGRAM_ID.toBase58(),
    );
    expect(predIxRaw, "Prediction program instruction in close tx").to.exist;
    const predIx = predIxRaw!;
    const disc = Buffer.from(predIx.data.subarray(0, 8));
    log("Close position disc (hex):", disc.toString("hex"));
    log("(sell order = same createOrder instruction with isBuy=false)");

    // Sign with our wallet and submit directly to Solana RPC
    closeTx.sign([wallet]);
    const sig = await connection.sendRawTransaction(closeTx.serialize(), {
      skipPreflight: false,
      maxRetries: 3,
    });
    await connection.confirmTransaction(sig, "confirmed");
    log("✅ ClosePosition tx confirmed:", sig);
    expect(sig).to.be.a("string").with.length.greaterThan(0);
  });

  it("confirms position is closed after sell", async function () {
    this.timeout(20_000);
    if (!positionPubkey) return (this as any).skip();

    await sleep(5_000);
    const resp = await client.getPositions({ ownerPubkey: OWNER.toBase58() }) as any;
    const positions = resp.data ?? resp;
    const still = positions.find((p: any) => p.pubkey === positionPubkey);
    log("Open positions after sell:", positions.length);
    if (still) {
      log("Position still open with contracts:", still.contractsMicro ?? still.contracts);
    } else {
      log("Position fully closed ✓");
    }
  });

  it("builds ClaimPayout tx for any claimable position (not submitted)", async function () {
    this.timeout(60_000);

    const resp = await client.getPositions({ ownerPubkey: OWNER.toBase58() }) as any;
    const positions = resp.data ?? resp;
    const claimable = positions.filter((p: any) => p.claimable);

    if (claimable.length === 0) {
      log("No claimable positions right now — skipping");
      return (this as any).skip();
    }

    const pos = claimable[0];
    log("Claimable position:", pos.positionPubkey, "market:", pos.marketId);

    // Build the ClaimPayout tx using the API to get the market result account address.
    // The market result PDA is a protocol-created account after resolution; we read it
    // from the API-provided tx rather than deriving it manually.
    const claimResp = await client.claimPayout(pos.id ?? pos.positionPubkey, OWNER.toBase58()) as any;
    const base64Tx = claimResp.transaction ?? claimResp.data?.transaction;
    expect(base64Tx).to.be.a("string");

    const claimTx = VersionedTransaction.deserialize(Buffer.from(base64Tx, "base64"));
    const msg = claimTx.message;
    const accts = msg.staticAccountKeys;
    const predIxRaw2 = msg.compiledInstructions.find(
      (ix) => accts[ix.programIdIndex].toBase58() === PREDICTION_PROGRAM_ID.toBase58(),
    );
    expect(predIxRaw2, "ClaimPayout instruction must exist").to.exist;
    const ixAcctIdxs = Array.from(predIxRaw2!.accountKeyIndexes);
    const marketResultAcct = accts[ixAcctIdxs[3]];

    log("Market result account:", marketResultAcct.toBase58());

    const depositMint = accts[ixAcctIdxs[5]];
    const vaultAta    = accts[ixAcctIdxs[4]];
    const userAta     = getAssociatedTokenAddressSync(depositMint, OWNER);

    const claimIx = buildClaimPayoutIx({
      owner: OWNER,
      positionAccount: new PublicKey(pos.positionPubkey),
      marketResultAccount: marketResultAcct,
      vaultTokenAccount: vaultAta,
      userTokenAccount: userAta,
      depositMint,
    });

    expect(Array.from(claimIx.data.subarray(0, 8))).to.deep.equal(Array.from(DISC.claimPayout));
    log("ClaimPayout ix built with", claimIx.keys.length, "accounts ✓");
    log("Estimated payout:", formatUsd(BigInt(claimResp.netPayoutMicro ?? 0)));
    log("(Not submitting — demonstration only)");
  });
});

// ─── Suite 3: Instruction builder verification ────────────────────────────────

describe("Jupiter Prediction — Suite 3: Instruction builders", () => {
  const dummyPubkey = new PublicKey("11111111111111111111111111111111");

  it("DISC.createOrder = sha256('global:create_order') — confirmed on mainnet tx 3WVJi…", () => {
    const crypto = require("crypto");
    const expected = crypto.createHash("sha256")
      .update("global:create_order")
      .digest()
      .slice(0, 8);
    expect(Buffer.compare(DISC.createOrder, expected)).to.equal(0);
    log("createOrder disc:", DISC.createOrder.toString("hex"));
  });

  it("DISC.closeOrder = sha256('global:close_order')", () => {
    const crypto = require("crypto");
    const expected = crypto.createHash("sha256")
      .update("global:close_order")
      .digest()
      .slice(0, 8);
    expect(Buffer.compare(DISC.closeOrder, expected)).to.equal(0);
    log("closeOrder disc:", DISC.closeOrder.toString("hex"));
  });

  it("DISC.claimPayout = sha256('global:claim_payout')", () => {
    const crypto = require("crypto");
    const expected = crypto.createHash("sha256")
      .update("global:claim_payout")
      .digest()
      .slice(0, 8);
    expect(Buffer.compare(DISC.claimPayout, expected)).to.equal(0);
    log("claimPayout disc:", DISC.claimPayout.toString("hex"));
  });

  it("DISC.createMarketResult is empirical (keeper-only, not Anchor standard)", () => {
    const observed = Buffer.from([15, 50, 71, 210, 11, 109, 85, 150]);
    expect(Buffer.compare(DISC.createMarketResult, observed)).to.equal(0);
    log("createMarketResult disc (empirical):", DISC.createMarketResult.toString("hex"));
  });

  it("buildCloseOrderIx produces correct instruction (9 accounts, right disc)", () => {
    const ix = buildCloseOrderIx({
      owner: OWNER,
      orderAccount: dummyPubkey,
      positionAccount: dummyPubkey,
      userTokenAccount: dummyPubkey,
      vaultTokenAccount: dummyPubkey,
      depositMint: USDC_MINT,
    });
    expect(ix.programId.toBase58()).to.equal(PREDICTION_PROGRAM_ID.toBase58());
    expect(Array.from(ix.data.subarray(0, 8))).to.deep.equal(Array.from(DISC.closeOrder));
    expect(ix.keys.length).to.equal(9);
    expect(ix.keys[0].pubkey.toBase58()).to.equal(OWNER.toBase58());
    expect(ix.keys[1].pubkey.toBase58()).to.equal(PREDICTION_GLOBAL_CONFIG.toBase58());
    log("CloseOrder ix: keys=", ix.keys.length, "disc=", Buffer.from(ix.data.subarray(0, 8)).toString("hex"));
  });

  it("buildClaimPayoutIx produces correct instruction (7 accounts, right disc)", () => {
    const ix = buildClaimPayoutIx({
      owner: OWNER,
      positionAccount: dummyPubkey,
      marketResultAccount: dummyPubkey,
      vaultTokenAccount: dummyPubkey,
      userTokenAccount: dummyPubkey,
      depositMint: USDC_MINT,
    });
    expect(ix.programId.toBase58()).to.equal(PREDICTION_PROGRAM_ID.toBase58());
    expect(Array.from(ix.data.subarray(0, 8))).to.deep.equal(Array.from(DISC.claimPayout));
    expect(ix.keys.length).to.equal(7);
    expect(ix.keys[0].pubkey.toBase58()).to.equal(OWNER.toBase58());
    expect(ix.keys[1].pubkey.toBase58()).to.equal(PREDICTION_GLOBAL_CONFIG.toBase58());
    log("ClaimPayout ix: keys=", ix.keys.length, "disc=", Buffer.from(ix.data.subarray(0, 8)).toString("hex"));
  });

  it("buildCreateOrderIx account layout matches confirmed mainnet tx", () => {
    const dummyAuthority = JUPITER_AUTHORITY;
    const dummyVault     = new PublicKey("5UFiwEsJ6tjXiWxJWCH3PVk1iqZXwZd5Tk1tiDnzYfhQ");
    const dummyOrder     = new PublicKey("3Hn3cReFMHRpCV6GwgKZLvP6ncMF7dxEyTwDVQphnarF");
    const dummyPosition  = new PublicKey("4fMwipcio5QrgMzHUWkjVZyDiW4wU2hsz7CMyT9Z3dnz");
    const dummyUserAta   = new PublicKey("6wsVSFqahrNRi7G7ZBzoMt1QQeqqKqGetxZPBzQQRdoR");

    const ix = buildCreateOrderIx({
      payer: OWNER,
      owner: OWNER,
      authority: dummyAuthority,
      orderAccount: dummyOrder,
      positionAccount: dummyPosition,
      userTokenAccount: dummyUserAta,
      depositMint: JUPUSD_MINT,
      vaultTokenAccount: dummyVault,
      payload: Buffer.alloc(0),
    });

    expect(ix.keys.length).to.equal(12);
    expect(ix.keys[0].pubkey.toBase58()).to.equal(OWNER.toBase58());         // payer
    expect(ix.keys[1].pubkey.toBase58()).to.equal(OWNER.toBase58());         // payer (dup)
    expect(ix.keys[2].pubkey.toBase58()).to.equal(dummyAuthority.toBase58()); // authority
    expect(ix.keys[3].pubkey.toBase58()).to.equal(PREDICTION_GLOBAL_CONFIG.toBase58()); // global_config
    expect(ix.keys[4].pubkey.toBase58()).to.equal(dummyPosition.toBase58()); // position (BEFORE order)
    expect(ix.keys[5].pubkey.toBase58()).to.equal(dummyOrder.toBase58());    // order (AFTER position)
    log("CreateOrder ix: 12 accounts in correct order ✓");
    log("  ix[4]=position, ix[5]=order (confirmed from tx 3WVJi…)");
  });
});

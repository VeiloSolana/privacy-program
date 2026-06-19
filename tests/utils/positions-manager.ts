/**
 * tests/utils/positions-manager.ts
 *
 * PositionsManager — read and manage Phoenix Eternal perp positions via the
 * Veilo Privacy Pool program.
 *
 * Provides:
 *   - PDA derivation for all Veilo/Phoenix accounts
 *   - On-chain position and collateral reading (binary decoder)
 *   - Mark price fetching from the Phoenix REST API
 *   - OrderPacket borsh encoding helpers (IOC market, PostOnly limit)
 *   - High-level PositionsManager class for order/exit actions
 *
 * Usage (in a test or script):
 *   import { PositionsManager, deriveExecutorPda, deriveTraderPda } from "./positions-manager";
 *
 *   const pm = new PositionsManager({ program, relayer, mint: USDC_MAINNET, poolConfig });
 *   await pm.printSummary();
 *   await pm.placeMarketOrder({ symbol: "SOL", side: "Long", numBaseLots: 2n });
 */

import * as crypto from "crypto";
import {
  PublicKey,
  Keypair,
  SystemProgram,
  ComputeBudgetProgram,
  Connection,
  VersionedTransaction,
  TransactionMessage,
} from "@solana/web3.js";
import { BN } from "@coral-xyz/anchor";
import { TOKEN_PROGRAM_ID } from "@solana/spl-token";

import {
  PHOENIX_PROGRAM_ID,
  PHOENIX_EXCHANGE,
  getMarket,
  getMarketByAssetId,
  buildOrderRemainingAccounts,
  buildWithdrawRemainingAccounts,
  buildConsumeWithdrawQueueAccounts,
  buildTransferCollateralRemainingAccounts,
  conditionalOrdersPda,
  buildCreateConditionalOrdersAccountRemainingAccounts,
  buildPositionConditionalOrderRemainingAccounts,
  buildCancelConditionalOrderRemainingAccounts,
} from "./phoenix-markets";

// ─── EMBER / PhUSD constants ──────────────────────────────────────────────────

/** EMBER wrapper program — wraps USDC into PhUSD (Phoenix collateral) */
export const EMBER_PROGRAM_ID = new PublicKey(
  "EMBERpYNE6ehWmXymZZS2skiFmCa9V5dp14e1iduM5qy",
);

/** PhUSD SPL mint */
export const PHUSD_MINT = new PublicKey(
  "PhUsd11YkbjSaWjFncfAAmatntsjx3MgDR9B6g1ks3A",
);

/** PhUSD mint authority PDA (of EMBER program) */
export const PHUSD_MINT_AUTHORITY = new PublicKey(
  "6ur7v6AXNpnHeEb6xuk7PyezvZ1i5GrgYyWZkNCpzbRz",
);

/** EMBER USDC reserve account */
export const EMBER_USDC_RESERVE = new PublicKey(
  "FKcEb4TdPDTRuMnQDpSEPQBcrm15S73xiUD6Qf8ZLUkq",
);

// ─── Types ────────────────────────────────────────────────────────────────────

/** Side for placing an order. */
export type OrderSide = "Long" | "Short";

/**
 * Direction for a conditional (stop-loss / take-profit) order.
 *   "LessThan"    fires when mark price drops below the trigger — use for SL on longs
 *   "GreaterThan" fires when mark price rises above the trigger — use for TP on longs / SL on shorts
 */
export type StopLossDirection = "LessThan" | "GreaterThan";

/** Decoded Phoenix trader account header. */
export interface PhoenixTraderState {
  traderPda: PublicKey;
  authority: PublicKey;
  /** Collateral balance in quote lots (1 lot = $0.000001 USDC). */
  quoteLotCollateral: bigint;
  flags: number;
  positionSeqNum: number;
  /** Negative = fee discount, positive = surcharge, 0 = protocol default. */
  makerFeeOverrideMultiplier: number;
  takerFeeOverrideMultiplier: number;
  /** Index of this PDA within the trader's PDA array (usually 0). */
  traderPdaIndex: number;
  traderSubaccountIndex: number;
  lastDepositSlot: bigint;
}

/** A single open perpetual position decoded from the Phoenix trader account. */
export interface PhoenixPosition {
  assetId: bigint;
  /** Positive = long, negative = short. */
  baseLots: bigint;
  /**
   * Running cost basis in quote lots (typically negative for a long position).
   * unrealizedPnL ≈ baseLots × markPrice + virtualQuoteLots / 1e6
   */
  virtualQuoteLots: bigint;
  cumulativeFunding: bigint;
  positionSeqNum: number;
  accumulatedFunding: bigint;
}

/** Position enriched with market symbol, direction label, and live PnL estimate. */
export interface PositionView {
  symbol: string;
  assetId: bigint;
  direction: "Long" | "Short" | "Flat";
  baseLots: bigint;
  virtualQuoteLots: bigint;
  /**
   * Average entry price in USD.
   * Formula: abs(virtualQuoteLots) / abs(baseLots) / 1_000_000
   * Null for flat positions.
   */
  entryPriceUsd: number | null;
  /** Live mark price from the Phoenix REST API, or null if unavailable. */
  markPriceUsd: number | null;
  /**
   * Approximate unrealised PnL in USD (mark vs entry, excluding funding).
   * Formula: baseLots × markPriceUsd + virtualQuoteLots / 1_000_000
   */
  unrealizedPnlUsd: number | null;
  /**
   * Accumulated funding in USD (positive = received, negative = paid).
   * Formula: accumulatedFunding / 1_000_000
   */
  fundingUsd: number;
  /**
   * Total PnL = unrealizedPnlUsd + fundingUsd.
   * Null when mark price is unavailable.
   */
  totalPnlUsd: number | null;
  /** Notional value of the position in USD (abs(baseLots) × markPriceUsd). */
  notionalUsd: number | null;
  /** Raw accumulated funding in quote lots for reference. */
  accumulatedFunding: bigint;
}

/**
 * Leverage and notional breakdown across all open positions.
 * Phoenix Eternal has no on-chain "set leverage" instruction — leverage is
 * implicit (notional / collateral).  Use `computeLotsForLeverage` to size an
 * order that will achieve a target leverage given current collateral.
 */
export interface LeverageSummary {
  /** Total USD notional across all open positions. */
  totalNotionalUsd: number;
  /** Available collateral in USD. */
  collateralUsd: number;
  /**
   * Effective (current) leverage = totalNotionalUsd / collateralUsd.
   * 0 when collateral is zero or there are no open positions.
   */
  effectiveLeverage: number;
  /** Enriched position views used to compute the summary (prices fetched). */
  positions: PositionView[];
}

/**
 * Everything about the account in one object — collateral, leverage, and all
 * enriched positions.  Returned by `PositionsManager.getPositionSummary()`.
 */
export interface PositionSummary extends CollateralSummary, LeverageSummary {
  /** Total unrealised PnL across all positions in USD. */
  totalUnrealizedPnlUsd: number;
  /** Total accumulated funding across all positions in USD. */
  totalFundingUsd: number;
  /** Total PnL (unrealized + funding) across all positions in USD. */
  totalPnlUsd: number;
}

/**
 * Calculate the number of base lots needed to reach a target leverage.
 * Useful for sizing a market order before placing it.
 *
 * @param targetLeverage  Desired leverage multiplier, e.g. 10 for 10×
 * @param collateralUsd   Current collateral in USD
 * @param markPriceUsd    Current mark price of the base asset in USD
 * @returns               Number of base lots (floored), or 0n if price is zero
 */
export function computeLotsForLeverage(opts: {
  targetLeverage: number;
  collateralUsd: number;
  markPriceUsd: number;
}): bigint {
  if (opts.markPriceUsd <= 0) return 0n;
  const notional = opts.targetLeverage * opts.collateralUsd;
  return BigInt(Math.floor(notional / opts.markPriceUsd));
}

/** Collateral and margin overview for a trader. */
export interface CollateralSummary {
  traderPda: PublicKey;
  /** Raw collateral in quote lots. */
  quoteLotCollateral: bigint;
  /** Collateral converted to USD (lots / 1_000_000). */
  collateralUsd: number;
  /** Trader flags bitmap. */
  flags: number;
  /** Number of open positions. */
  positionCount: number;
  /** Slot at which the last deposit was processed. */
  lastDepositSlot: bigint;
}

// ─── PDA derivation ───────────────────────────────────────────────────────────

/**
 * Derive the Veilo executor PDA for a given pool mint and claimant.
 * Seeds: ["phoenix_executor", mint, claimant]
 *
 * The `claimant` is the ephemeral pubkey committed in the ZK proof at deposit time,
 * giving each deposit its own isolated Phoenix trader account.
 */
export function deriveExecutorPda(
  veiloProgramId: PublicKey,
  mint: PublicKey,
  claimant: PublicKey,
): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("phoenix_executor"), mint.toBuffer(), claimant.toBuffer()],
    veiloProgramId,
  );
  return pda;
}

/**
 * Derive the Phoenix Eternal trader PDA for a given on-chain wallet/executor.
 * Seeds: ["trader", walletPubkey, pdaIndex=0, subaccountIndex=0]  (on PHOENIX_PROGRAM_ID)
 */
export function deriveTraderPda(walletPubkey: PublicKey): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [
      Buffer.from("trader"),
      walletPubkey.toBuffer(),
      Buffer.from([0]),
      Buffer.from([0]),
    ],
    PHOENIX_PROGRAM_ID,
  );
  return pda;
}

/**
 * Derive the Veilo pool config PDA.
 * Seeds: ["privacy_config_v3", mint]
 */
export function derivePoolConfig(
  veiloProgramId: PublicKey,
  mint: PublicKey,
): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("privacy_config_v3"), mint.toBuffer()],
    veiloProgramId,
  );
  return pda;
}

/**
 * Derive the Veilo pool vault PDA.
 * Seeds: ["privacy_vault_v3", mint]
 */
export function derivePoolVault(
  veiloProgramId: PublicKey,
  mint: PublicKey,
): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("privacy_vault_v3"), mint.toBuffer()],
    veiloProgramId,
  );
  return pda;
}

/**
 * Derive the phoenix-slot PDA that records a specific deposit/withdrawal round-trip.
 * Seeds: ["phoenix_slot_v1", mint, claimant, withdrawalId (32 bytes)]
 */
export function derivePhoenixSlotPda(
  veiloProgramId: PublicKey,
  mint: PublicKey,
  claimant: PublicKey,
  withdrawalId: Uint8Array,
): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [
      Buffer.from("phoenix_slot_v1"),
      mint.toBuffer(),
      claimant.toBuffer(),
      Buffer.from(withdrawalId),
    ],
    veiloProgramId,
  );
  return pda;
}

/**
 * Derive the pending-reissue PDA that tracks the amount pending reissuance.
 * Seeds: ["phoenix_pending_v1", mint, claimant, withdrawalId (32 bytes)]
 */
export function derivePendingReissuePda(
  veiloProgramId: PublicKey,
  mint: PublicKey,
  claimant: PublicKey,
  withdrawalId: Uint8Array,
): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [
      Buffer.from("phoenix_pending_v1"),
      mint.toBuffer(),
      claimant.toBuffer(),
      Buffer.from(withdrawalId),
    ],
    veiloProgramId,
  );
  return pda;
}

// ─── On-chain data readers ────────────────────────────────────────────────────

/**
 * Fetch and decode the Phoenix trader account header.
 * Returns null when the account does not exist.
 *
 * Binary layout (all offsets are from byte 0 of account data):
 *   [0..7]    discriminator (8 bytes, ignored)
 *   [8..23]   reserved (16 bytes)
 *   [24..55]  traderKey pubkey (32 bytes)
 *   [56..87]  authority pubkey (32 bytes)
 *   [88..95]  quoteLotCollateral (i64 LE)
 *   [96..99]  flags (u32 LE)
 *   [101]     positionSeqNum / globalPositionSequenceNumber (u8)
 *   [102]     makerFeeOverrideMultiplier (i8)
 *   [103]     takerFeeOverrideMultiplier (i8)
 *   [154]     traderPdaIndex (u8)
 *   [155]     traderSubaccountIndex (u8)
 *   [192..199] lastDepositSlot (u64 LE)
 */
export async function readTraderState(
  connection: Connection,
  traderPda: PublicKey,
): Promise<PhoenixTraderState | null> {
  const info = await connection.getAccountInfo(traderPda, "confirmed");
  if (!info) return null;
  const d = Buffer.from(info.data);
  if (d.length < 8 + 192) return null;
  const B = 8; // skip discriminator
  const authority = new PublicKey(d.subarray(B + 48, B + 80));
  return {
    traderPda,
    authority,
    quoteLotCollateral: d.readBigInt64LE(B + 80),
    flags: d.readUInt32LE(B + 88),
    positionSeqNum: d.readUInt8(B + 93),
    makerFeeOverrideMultiplier: d.readInt8(B + 94),
    takerFeeOverrideMultiplier: d.readInt8(B + 95),
    traderPdaIndex: d.readUInt8(B + 146),
    traderSubaccountIndex: d.readUInt8(B + 147),
    lastDepositSlot: d.readBigUInt64LE(B + 184),
  };
}

/**
 * Fetch and decode the list of open perpetual positions from the Phoenix trader account.
 * Returns an empty array when the account does not exist or has no positions.
 *
 * Positions array layout (within the account):
 *   offset 224 (= disc 8 + fixed header 216): u64 LE capacity
 *   offset 232: u64 LE length (number of live entries)
 *   offset 240: entries, each 40 bytes:
 *     [0..7]   assetId     u64 LE
 *     [8..15]  baseLots    i64 LE
 *     [16..23] virtualQuoteLots i64 LE
 *     [24..31] cumulativeFunding i64 LE
 *     [32]     positionSeqNum u8
 *     [33..39] accumulatedFunding i56 LE (sign-extended to i64)
 */
export async function readPositions(
  connection: Connection,
  traderPda: PublicKey,
): Promise<PhoenixPosition[]> {
  const info = await connection.getAccountInfo(traderPda, "confirmed");
  if (!info) return [];
  const d = Buffer.from(info.data);
  const POS_OFFSET = 8 + 216; // disc + fixed header
  if (d.length < POS_OFFSET + 16) return [];
  // skip capacity u64 at POS_OFFSET; read length u64 at POS_OFFSET + 8
  const len = Number(d.readBigUInt64LE(POS_OFFSET + 8));
  const ENTRY = 40;
  const start = POS_OFFSET + 16;
  if (d.length < start + len * ENTRY) return [];
  const out: PhoenixPosition[] = [];
  for (let i = 0; i < len; i++) {
    const o = start + i * ENTRY;
    const baseLots = d.readBigInt64LE(o + 8);
    // Skip empty slots — Phoenix pre-allocates all 128 positions to zero
    if (baseLots === 0n) continue;
    // accumulatedFunding is 7-byte signed integer (i56) — sign-extend to i64
    const i56 = Buffer.alloc(8, 0);
    d.copy(i56, 0, o + 33, o + 40);
    if (i56[6] & 0x80) i56[7] = 0xff; // sign-extend
    out.push({
      assetId: d.readBigUInt64LE(o),
      baseLots,
      virtualQuoteLots: d.readBigInt64LE(o + 16),
      cumulativeFunding: d.readBigInt64LE(o + 24),
      positionSeqNum: d.readUInt8(o + 32),
      accumulatedFunding: i56.readBigInt64LE(0),
    });
  }
  return out;
}

// ─── Mark price ───────────────────────────────────────────────────────────────

/**
 * Fetch the live mark price for a symbol from the Phoenix Eternal REST API.
 * Returns `fallbackUsd` if the API is unreachable or returns unexpected data.
 *
 * Endpoint: GET https://perp-api.phoenix.trade/v1/candles/{SYMBOL}?timeframe=1m&limit=1
 * Response: array of candle objects; `markClose`, `close`, or `c` field holds the price.
 */
export async function fetchMarkPrice(
  symbol: string,
  fallbackUsd = 0,
): Promise<number> {
  try {
    const upper = symbol.replace(/-PERP$/i, "").toUpperCase();
    const resp = await fetch(
      `https://perp-api.phoenix.trade/v1/candles/${upper}?timeframe=1m&limit=1`,
    );
    if (!resp.ok) return fallbackUsd;
    const candles = (await resp.json()) as Array<Record<string, number>>;
    const price =
      candles?.[0]?.markClose ?? candles?.[0]?.close ?? candles?.[0]?.c;
    return typeof price === "number" && price > 0 ? price : fallbackUsd;
  } catch {
    return fallbackUsd;
  }
}

/**
 * Enrich raw positions with market symbol, direction label, and live PnL.
 * Set `fetchPrices = false` to skip REST API calls (useful in offline/CI environments).
 */
export async function enrichPositions(
  positions: PhoenixPosition[],
  fetchPrices = true,
): Promise<PositionView[]> {
  return Promise.all(
    positions.map(async (pos): Promise<PositionView> => {
      let symbol = `UNKNOWN-${pos.assetId}`;
      try {
        symbol = getMarketByAssetId(pos.assetId).symbol;
      } catch {
        // unknown market — keep UNKNOWN label
      }

      const direction: "Long" | "Short" | "Flat" =
        pos.baseLots > 0n ? "Long" : pos.baseLots < 0n ? "Short" : "Flat";

      // Entry price = |virtualQuoteLots| / |baseLots| / 10_000
      // virtualQuoteLots is stored in units of $0.0001 USDC (Phoenix quote-lot denomination).
      // Dividing by 10_000 converts to USD per full coin.
      const entryPriceUsd: number | null =
        direction !== "Flat" && pos.baseLots !== 0n
          ? Math.abs(Number(pos.virtualQuoteLots)) /
            Math.abs(Number(pos.baseLots)) /
            10_000
          : null;

      // accumulatedFunding: positive = received by trader, negative = paid
      const fundingUsd = Number(pos.accumulatedFunding) / 1_000_000;

      let markPriceUsd: number | null = null;
      let unrealizedPnlUsd: number | null = null;
      let totalPnlUsd: number | null = null;
      let notionalUsd: number | null = null;

      if (fetchPrices && direction !== "Flat") {
        markPriceUsd = await fetchMarkPrice(symbol);
        if (markPriceUsd > 0) {
          // baseLots × markPriceUsd + virtualQuoteLots / 10_000
          // virtualQuoteLots is in $0.0001 USDC units; / 10_000 converts to USD.
          unrealizedPnlUsd =
            Number(pos.baseLots) * markPriceUsd +
            Number(pos.virtualQuoteLots) / 10_000;
          totalPnlUsd = unrealizedPnlUsd + fundingUsd;
          notionalUsd = Math.abs(Number(pos.baseLots)) * markPriceUsd;
        }
      }

      return {
        symbol,
        assetId: pos.assetId,
        direction,
        baseLots: pos.baseLots,
        virtualQuoteLots: pos.virtualQuoteLots,
        entryPriceUsd,
        markPriceUsd,
        unrealizedPnlUsd,
        fundingUsd,
        totalPnlUsd,
        notionalUsd,
        accumulatedFunding: pos.accumulatedFunding,
      };
    }),
  );
}

// ─── Display utilities ────────────────────────────────────────────────────────

/** Print a formatted collateral and margin summary to stdout. */
export function printCollateralSummary(summary: CollateralSummary): void {
  const usd = (lots: bigint) =>
    `$${(Number(lots) / 1_000_000).toFixed(6)} USDC`;
  console.log(`\n  ┌─ Collateral Summary ─────────────────────────────────`);
  console.log(`  │  Trader PDA     : ${summary.traderPda.toBase58()}`);
  console.log(
    `  │  Collateral     : ${summary.quoteLotCollateral} lots (${usd(
      summary.quoteLotCollateral,
    )})`,
  );
  console.log(
    `  │  Flags          : 0x${summary.flags.toString(16).padStart(2, "0")} (${
      summary.flags
    })`,
  );
  console.log(`  │  Open positions : ${summary.positionCount}`);
  console.log(`  │  Last deposit   : slot ${summary.lastDepositSlot}`);
  console.log(`  └──────────────────────────────────────────────────────\n`);
}

/** Print a formatted table of open positions to stdout. */
export function printPositions(positions: PositionView[]): void {
  if (positions.length === 0) {
    console.log("  (no open positions)\n");
    return;
  }
  console.log(
    `\n  ┌─ Open Positions (${positions.length}) ───────────────────────────────────────────────`,
  );
  for (const p of positions) {
    const dir = p.direction === "Long" ? "↑ LONG " : "↓ SHORT";
    const entry =
      p.entryPriceUsd != null ? `$${p.entryPriceUsd.toFixed(4)}` : "n/a";
    const mark =
      p.markPriceUsd != null ? `$${p.markPriceUsd.toFixed(4)}` : "n/a";
    const notional =
      p.notionalUsd != null ? `$${p.notionalUsd.toFixed(2)}` : "n/a";
    const pnl =
      p.totalPnlUsd != null
        ? (p.totalPnlUsd >= 0 ? "+" : "") + `$${p.totalPnlUsd.toFixed(4)}`
        : "n/a";
    const funding =
      p.fundingUsd !== 0
        ? (p.fundingUsd >= 0 ? "+" : "") + `$${p.fundingUsd.toFixed(4)}`
        : "$0";
    console.log(`  │  ${dir}  ${p.symbol.padEnd(8)} ${p.baseLots} lots`);
    console.log(`  │       entry=${entry}  mark=${mark}  notional=${notional}`);
    console.log(`  │       totalPnL=${pnl}  funding=${funding}`);
  }
  console.log(
    `  └────────────────────────────────────────────────────────────\n`,
  );
}

/**
 * Print a leverage summary (notional, collateral, effective leverage) to stdout.
 * Typically called after `getLeverage()` on the PositionsManager.
 */
export function printLeverageSummary(lev: LeverageSummary): void {
  console.log(
    `\n  ┌─ Leverage Summary ──────────────────────────────────────────`,
  );
  console.log(`  │  Collateral   : $${lev.collateralUsd.toFixed(4)} USDC`);
  console.log(
    `  │  Notional     : $${lev.totalNotionalUsd.toFixed(4)} (${
      lev.positions.length
    } position${lev.positions.length !== 1 ? "s" : ""})`,
  );
  const levStr =
    lev.effectiveLeverage > 0 ? `${lev.effectiveLeverage.toFixed(2)}×` : "flat";
  console.log(`  │  Leverage     : ${levStr}`);
  console.log(
    `  └────────────────────────────────────────────────────────────\n`,
  );
}

// ─── OrderPacket borsh encoding ───────────────────────────────────────────────

/**
 * Compute an 8-byte Anchor/Phoenix instruction discriminator:
 *   sha256("global:<name>")[0..8]
 */
function phoenixDisc(name: string): Buffer {
  return crypto
    .createHash("sha256")
    .update(`global:${name}`)
    .digest()
    .slice(0, 8);
}

/**
 * Encode a Phoenix IOC (ImmediateOrCancel) market OrderPacket — 57 bytes
 * (8-byte discriminator + 49-byte OrderPacket).
 *
 * @param side        0 = Bid (go Long), 1 = Ask (go Short / close long)
 * @param numBaseLots Number of base lots to trade
 * @param reduceOnly  When true sets orderFlags = 128 (ReduceOnly), preventing
 *                    an IOC order from accidentally opening a new position when
 *                    the intent is to close.  Defaults to false.
 */
export function encodeIocMarketOrder(
  side: 0 | 1,
  numBaseLots: bigint,
  reduceOnly = false,
): Buffer {
  const pkt = Buffer.alloc(49, 0);
  let p = 0;
  pkt.writeUInt8(2, p++); // variant: ImmediateOrCancel
  pkt.writeUInt8(side, p++); // side
  pkt.writeUInt8(0, p++); // priceInTicks: None
  pkt.writeBigUInt64LE(numBaseLots, p);
  p += 8; // numBaseLots.inner
  pkt.writeUInt8(0, p++); // numQuoteLots: None
  pkt.writeBigUInt64LE(0n, p);
  p += 8; // minBaseLotsToFill = 0
  pkt.writeBigUInt64LE(0n, p);
  p += 8; // minQuoteLotsToFill = 0
  pkt.writeUInt8(2, p++); // selfTradeBehavior: DecrementTake
  pkt.writeUInt8(0, p++); // matchLimit: None
  p += 16; // clientOrderId: zeros
  pkt.writeUInt8(0, p++); // lastValidSlot: None
  pkt.writeUInt8(reduceOnly ? 128 : 0, p++); // orderFlags
  pkt.writeUInt8(0, p++); // cancelExisting: false
  return Buffer.concat([phoenixDisc("place_market_order"), pkt]);
}

/**
 * Encode a Phoenix PostOnly (resting limit) OrderPacket — 65 bytes
 * (8-byte discriminator + 57-byte OrderPacket).
 *
 * @param side          0 = Bid (limit buy), 1 = Ask (limit sell)
 * @param priceInTicks  Limit price in Phoenix ticks (SOL-PERP: 1 tick ≈ $0.001)
 * @param numBaseLots   Size in base lots
 */
export function encodePostOnlyLimitOrder(
  side: 0 | 1,
  priceInTicks: bigint,
  numBaseLots: bigint,
): Buffer {
  const pkt = Buffer.alloc(57, 0);
  let p = 0;
  pkt.writeUInt8(0, p++); // variant: PostOnly
  pkt.writeUInt8(side, p++); // side
  pkt.writeUInt8(1, p++); // priceInTicks: Some
  pkt.writeBigUInt64LE(priceInTicks, p);
  p += 8; // priceInTicks.inner
  pkt.writeBigUInt64LE(numBaseLots, p);
  p += 8; // numBaseLots.inner
  pkt.writeUInt8(0, p++); // numQuoteLots: None
  pkt.writeBigUInt64LE(0n, p);
  p += 8; // minBaseLotsToFill = 0
  pkt.writeBigUInt64LE(0n, p);
  p += 8; // minQuoteLotsToFill = 0
  pkt.writeUInt8(2, p++); // selfTradeBehavior: DecrementTake
  pkt.writeUInt8(0, p++); // matchLimit: None
  p += 16; // clientOrderId: zeros
  pkt.writeUInt8(0, p++); // lastValidSlot: None
  pkt.writeUInt8(0, p++); // orderFlags: 0
  pkt.writeUInt8(0, p++); // cancelExisting: false
  return Buffer.concat([phoenixDisc("place_limit_order"), pkt]);
}

// ─── PositionsManager ─────────────────────────────────────────────────────────

export interface PositionsManagerConfig {
  /** Anchor program instance — cast from (workspace as any).PrivacyPool or similar. */
  program: any;
  /** Signer for all instructions — the relayer keypair. */
  relayer: Keypair;
  /**
   * SPL mint for the pool — USDC on mainnet.
   * Mainnet: `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`
   */
  mint: PublicKey;
  /** Veilo pool config PDA — use `derivePoolConfig(programId, mint)` or a known address. */
  poolConfig: PublicKey;
  /**
   * Ephemeral claimant pubkey committed in the ZK proof at deposit time.
   * Used as a seed for the per-user executor PDA: ["phoenix_executor", mint, claimant].
   * Derive deterministically from `walletMasterSeed + "veilo-phoenix" + withdrawalId`.
   */
  claimant: PublicKey;
  /** Compute unit budget per transaction (default 400 000). */
  computeUnitLimit?: number;
  /**
   * Override the Phoenix trader PDA used for all order/withdrawal CPIs.
   * By default this is the cross-margin subaccount (subaccount_index=0).
   * Pass `deriveIsolatedTraderPda(executorPda)` to target the isolated subaccount.
   */
  traderPdaOverride?: PublicKey;
}

/**
 * High-level manager for reading and acting on Phoenix Eternal perp positions
 * through the Veilo Privacy Pool program.
 *
 * All PDAs are derived deterministically in the constructor from the program ID
 * and mint, so only `program`, `relayer`, `mint`, and `poolConfig` are required.
 *
 * @example
 *   const pm = new PositionsManager({ program, relayer, mint: USDC_MAINNET, poolConfig });
 *   await pm.printSummary();
 *   const sig = await pm.placeMarketOrder({ symbol: "SOL", side: "Long", numBaseLots: 2n });
 */
export class PositionsManager {
  readonly mint: PublicKey;
  readonly poolConfig: PublicKey;
  /** Ephemeral claimant pubkey — PDA seed for per-user executor isolation. */
  readonly claimant: PublicKey;
  /** Veilo executor PDA — the on-chain signing wallet for Phoenix CPIs. */
  readonly executorPda: PublicKey;
  /** Phoenix Eternal trader PDA controlled by the executor. */
  readonly traderPda: PublicKey;

  private readonly program: any;
  private readonly relayer: Keypair;
  private readonly cu: number;

  constructor(cfg: PositionsManagerConfig) {
    this.program = cfg.program;
    this.relayer = cfg.relayer;
    this.mint = cfg.mint;
    this.poolConfig = cfg.poolConfig;
    this.claimant = cfg.claimant;
    this.cu = cfg.computeUnitLimit ?? 400_000;
    this.executorPda = deriveExecutorPda(
      cfg.program.programId,
      cfg.mint,
      cfg.claimant,
    );
    this.traderPda = cfg.traderPdaOverride ?? deriveTraderPda(this.executorPda);
  }

  private get connection(): Connection {
    return (this.program.provider as any).connection as Connection;
  }

  // ── Read methods ─────────────────────────────────────────────────────────

  /** Return the live collateral and margin summary for this trader. */
  async getCollateralSummary(): Promise<CollateralSummary> {
    const [state, positions] = await Promise.all([
      readTraderState(this.connection, this.traderPda),
      readPositions(this.connection, this.traderPda),
    ]);
    return {
      traderPda: this.traderPda,
      quoteLotCollateral: state?.quoteLotCollateral ?? 0n,
      collateralUsd: Number(state?.quoteLotCollateral ?? 0n) / 1_000_000,
      flags: state?.flags ?? 0,
      positionCount: positions.length,
      lastDepositSlot: state?.lastDepositSlot ?? 0n,
    };
  }

  /**
   * Return all open positions enriched with live mark prices and unrealised PnL.
   * Pass `fetchPrices = false` to skip the REST API calls (e.g. in offline/CI runs).
   */
  async getPositions(fetchPrices = true): Promise<PositionView[]> {
    const raw = await readPositions(this.connection, this.traderPda);
    return enrichPositions(raw, fetchPrices);
  }

  /** Print a full collateral + positions summary to stdout. */
  async printSummary(fetchPrices = true): Promise<void> {
    const [summary, positions] = await Promise.all([
      this.getCollateralSummary(),
      this.getPositions(fetchPrices),
    ]);
    printCollateralSummary(summary);
    printPositions(positions);
  }

  /**
   * Return the current effective leverage and full position breakdown.
   *
   * Effective leverage = total notional USD / collateral USD.
   * Also returns the number of base lots needed to reach any target leverage
   * per market via the standalone `computeLotsForLeverage` helper.
   *
   * @example
   *   const lev = await pm.getLeverage();
   *   console.log(`Current leverage: ${lev.effectiveLeverage.toFixed(1)}×`);
   *   // Size a new order to reach 5× total leverage on SOL:
   *   const solMark = await fetchMarkPrice("SOL");
   *   const lots = computeLotsForLeverage({ targetLeverage: 5, collateralUsd: lev.collateralUsd, markPriceUsd: solMark });
   */
  async getLeverage(): Promise<LeverageSummary> {
    const [summary, positions] = await Promise.all([
      this.getCollateralSummary(),
      this.getPositions(true),
    ]);
    const totalNotionalUsd = positions.reduce(
      (acc, p) =>
        acc +
        (p.notionalUsd != null && p.direction !== "Flat" ? p.notionalUsd : 0),
      0,
    );
    const effectiveLeverage =
      summary.collateralUsd > 0 ? totalNotionalUsd / summary.collateralUsd : 0;
    return {
      totalNotionalUsd,
      collateralUsd: summary.collateralUsd,
      effectiveLeverage,
      positions,
    };
  }

  /**
   * Return a single object containing everything about the account:
   * collateral, leverage, all enriched positions, and aggregated PnL.
   *
   * This is the most convenient call for displaying a dashboard-style overview.
   */
  async getPositionSummary(): Promise<PositionSummary> {
    const [state, rawPositions] = await Promise.all([
      readTraderState(this.connection, this.traderPda),
      readPositions(this.connection, this.traderPda),
    ]);
    const positions = await enrichPositions(rawPositions, true);
    const quoteLotCollateral = state?.quoteLotCollateral ?? 0n;
    const collateralUsd = Number(quoteLotCollateral) / 1_000_000;
    const totalNotionalUsd = positions.reduce(
      (acc, p) => acc + (p.notionalUsd ?? 0),
      0,
    );
    const effectiveLeverage =
      collateralUsd > 0 ? totalNotionalUsd / collateralUsd : 0;
    const totalUnrealizedPnlUsd = positions.reduce(
      (acc, p) => acc + (p.unrealizedPnlUsd ?? 0),
      0,
    );
    const totalFundingUsd = positions.reduce((acc, p) => acc + p.fundingUsd, 0);
    return {
      traderPda: this.traderPda,
      quoteLotCollateral,
      collateralUsd,
      flags: state?.flags ?? 0,
      positionCount: positions.length,
      lastDepositSlot: state?.lastDepositSlot ?? 0n,
      totalNotionalUsd,
      effectiveLeverage,
      positions,
      totalUnrealizedPnlUsd,
      totalFundingUsd,
      totalPnlUsd: totalUnrealizedPnlUsd + totalFundingUsd,
    };
  }

  /**
   * Print a leverage summary to stdout.
   * Fetches live mark prices — pass `false` to skip (prints last known data).
   */
  async printLeverage(): Promise<void> {
    const lev = await this.getLeverage();
    printLeverageSummary(lev);
    printPositions(lev.positions);
  }

  // ── Order management ────────────────────────────────────────────────────

  /**
   * Transfer collateral between two Phoenix trader sub-accounts owned by this executor.
   *
   * @param amountPhUsd  Amount in PhUSD (6-decimal) units to transfer.
   * @param srcTraderPda Source trader PDA (defaults to this.traderPda — cross sub-account).
   * @param dstTraderPda Destination trader PDA (required — typically the isolated sub-account).
   * @returns Transaction signature
   */
  async transferCollateral(opts: {
    amountPhUsd: bigint;
    srcTraderPda?: PublicKey;
    dstTraderPda: PublicKey;
  }): Promise<string> {
    const srcTraderPda = opts.srcTraderPda ?? this.traderPda;
    return this.program.methods
      .phoenixTransferCollateral(
        this.mint,
        this.claimant,
        new BN(opts.amountPhUsd.toString()),
      )
      .accounts({
        config: this.poolConfig,
        executor: this.executorPda,
        relayer: this.relayer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts(
        buildTransferCollateralRemainingAccounts(
          PHOENIX_EXCHANGE,
          srcTraderPda,
          opts.dstTraderPda,
        ),
      )
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: this.cu }),
      ])
      .signers([this.relayer])
      .rpc();
  }

  /**
   * Place a market IOC order on Phoenix Eternal.
   *
   * @param symbol      Market symbol — "SOL", "BTC", "ETH", "XRP", etc.
   * @param side        "Long" (Bid) or "Short" (Ask)
   * @param numBaseLots Number of base lots to trade
   * @returns Transaction signature
   */
  async placeMarketOrder(opts: {
    symbol: string;
    side: OrderSide;
    numBaseLots: bigint;
    /** If set, runs TransferCollateral (cross → isolated) atomically before the order. */
    transfer?: { amountPhUsd: bigint; srcTraderPda: PublicKey };
  }): Promise<string> {
    const market = getMarket(opts.symbol);
    const side: 0 | 1 = opts.side === "Long" ? 0 : 1;
    const pkt = encodeIocMarketOrder(side, opts.numBaseLots);
    const transferAmount = opts.transfer
      ? new BN(opts.transfer.amountPhUsd.toString())
      : null;
    const remainingAccounts = opts.transfer
      ? [
          ...buildTransferCollateralRemainingAccounts(
            PHOENIX_EXCHANGE,
            opts.transfer.srcTraderPda,
            this.traderPda,
          ),
          ...buildOrderRemainingAccounts(
            PHOENIX_EXCHANGE,
            market,
            this.traderPda,
          ),
        ]
      : buildOrderRemainingAccounts(PHOENIX_EXCHANGE, market, this.traderPda);
    return this.program.methods
      .phoenixPlaceOrder(this.mint, this.claimant, pkt, transferAmount)
      .accounts({
        config: this.poolConfig,
        executor: this.executorPda,
        relayer: this.relayer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts(remainingAccounts)
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: this.cu }),
      ])
      .signers([this.relayer])
      .rpc();
  }

  /**
   * Place a resting PostOnly (limit) order on Phoenix.
   * The order will sit on the orderbook at `priceInTicks` until filled or cancelled.
   *
   * @param symbol        Market symbol (e.g. "SOL", "BTC", "ETH")
   * @param side          "Long" = Bid (limit buy); "Short" = Ask (limit sell)
   * @param priceInTicks  Limit price in Phoenix ticks (1 tick ≈ $0.001)
   * @param numBaseLots   Size in base lots
   */
  async placeLimitOrder(opts: {
    symbol: string;
    side: OrderSide;
    priceInTicks: bigint;
    numBaseLots: bigint;
    /** If set, runs TransferCollateral (cross → isolated) atomically before the order. */
    transfer?: { amountPhUsd: bigint; srcTraderPda: PublicKey };
  }): Promise<string> {
    const market = getMarket(opts.symbol);
    const side: 0 | 1 = opts.side === "Long" ? 0 : 1;
    const pkt = encodePostOnlyLimitOrder(
      side,
      opts.priceInTicks,
      opts.numBaseLots,
    );
    const transferAmount = opts.transfer
      ? new BN(opts.transfer.amountPhUsd.toString())
      : null;
    const remainingAccounts = opts.transfer
      ? [
          ...buildTransferCollateralRemainingAccounts(
            PHOENIX_EXCHANGE,
            opts.transfer.srcTraderPda,
            this.traderPda,
          ),
          ...buildOrderRemainingAccounts(
            PHOENIX_EXCHANGE,
            market,
            this.traderPda,
          ),
        ]
      : buildOrderRemainingAccounts(PHOENIX_EXCHANGE, market, this.traderPda);
    return this.program.methods
      .phoenixPlaceOrder(this.mint, this.claimant, pkt, transferAmount)
      .accounts({
        config: this.poolConfig,
        executor: this.executorPda,
        relayer: this.relayer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts(remainingAccounts)
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: this.cu }),
      ])
      .signers([this.relayer])
      .rpc();
  }

  /**
   * Close an open position using a ReduceOnly IOC Ask order.
   * The `phoenixClosePosition` instruction enforces reduce-only semantics on-chain.
   *
   * @param symbol      Market symbol of the position to close
   * @param numBaseLots Exact number of base lots to close (match the open position size)
   * @returns Transaction signature
   */
  async closePosition(opts: {
    symbol: string;
    numBaseLots: bigint;
    /** Side of the position being closed. Long → Ask (sell); Short → Bid (buy). Default: "Long". */
    positionSide?: "Long" | "Short";
  }): Promise<string> {
    const market = getMarket(opts.symbol);
    const closeSide =
      (opts.positionSide ?? "Long") === "Long" ? 1 /* Ask */ : 0; /* Bid */
    const pkt = encodeIocMarketOrder(closeSide, opts.numBaseLots, true);
    return this.program.methods
      .phoenixClosePosition(this.mint, this.claimant, pkt)
      .accounts({
        config: this.poolConfig,
        executor: this.executorPda,
        relayer: this.relayer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts(
        buildOrderRemainingAccounts(PHOENIX_EXCHANGE, market, this.traderPda),
      )
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: this.cu }),
      ])
      .signers([this.relayer])
      .rpc();
  }

  /**
   * Cancel a conditional (stop-loss or take-profit) order.
   * The `direction` must match the direction used when the order was placed.
   *
   * @param symbol    Market symbol
   * @param direction "LessThan" or "GreaterThan" — must match the placed order
   */
  async cancelConditionalOrder(opts: {
    symbol: string;
    direction: StopLossDirection;
    /** Conditional-order slot index (1-based). Defaults to 1 (first slot). */
    conditionalOrderIndex?: number;
  }): Promise<string> {
    // disableFirst = LessThan (SL) leg, disableSecond = GreaterThan (TP) leg.
    return this.cancelBracketOrder({
      symbol: opts.symbol,
      conditionalOrderIndex: opts.conditionalOrderIndex ?? 1,
      disableFirst: opts.direction === "LessThan",
      disableSecond: opts.direction === "GreaterThan",
    });
  }

  /**
   * Place a market order and immediately set bracket SL and TP orders in one
   * atomic versioned transaction — matching the Rise SDK `place_position_bracket_order`
   * pattern.
   *
   * Both `stopLoss` and `takeProfit` are optional; omit either to place without that leg.
   *
   * **Order kinds** (matching Rise SDK defaults):
   *   - SL: `orderKind = 1` (IOC) — execute at market regardless of slippage
   *   - TP: `orderKind = 0` (Limit) — resting limit at trigger price, no slippage
   *
   * **Execution prices**:
   *   - SL: set `executionTicks` to trigger ±10% (slippage tolerance, required)
   *   - TP: `executionTicks` defaults to `triggerTicks` when omitted (limit at exact target)
   *
   * @param symbol       Market symbol (e.g. "SOL", "BTC")
   * @param side         "Long" (Bid) or "Short" (Ask)
   * @param numBaseLots  Size in base lots for the market order
   * @param stopLoss     SL leg — `executionTicks` required (set worse than trigger for slippage)
   * @param takeProfit   TP leg — `executionTicks` optional; defaults to `triggerTicks` (limit)
   * @returns Transaction signature
   *
   * Example — open a 2-lot SOL long with $140 SL (10% slippage) and $160 TP (limit):
   *   pm.placeOrderWithBracket({
   *     symbol: "SOL", side: "Long", numBaseLots: 2n,
   *     stopLoss:   { triggerTicks: 140_000n, executionTicks: 126_000n },  // ~10% below trigger
   *     takeProfit: { triggerTicks: 160_000n },                            // limit at $160
   *   });
   */
  async placeOrderWithBracket(opts: {
    symbol: string;
    side: OrderSide;
    numBaseLots: bigint;
    stopLoss?: { triggerTicks: bigint; executionTicks: bigint };
    takeProfit?: { triggerTicks: bigint; executionTicks?: bigint };
  }): Promise<string> {
    const market = getMarket(opts.symbol);
    const side: 0 | 1 = opts.side === "Long" ? 0 : 1;
    const pkt = encodeIocMarketOrder(side, opts.numBaseLots);

    // For a Long position:
    //   SL fires when price drops BELOW trigger → LessThan (direction 0), close with Ask (1)
    //   TP fires when price rises ABOVE trigger → GreaterThan (direction 1), close with Ask (1)
    // For a Short position the directions are reversed.
    // NOTE: direction is encoded implicitly by the greaterTrigger/lessTrigger slot in the new API.
    const closeSide: 0 | 1 = opts.side === "Long" ? 1 : 0; // Ask to close long, Bid to close short

    // Rise SDK StopLossOrderKind: Limit = 0 (TP default), IOC = 1 (SL default)
    const ORDER_KIND_LIMIT = 0; // resting limit at trigger — used for TP
    const ORDER_KIND_IOC = 1; // immediate-or-cancel with slippage — used for SL

    const baseAccounts = {
      config: this.poolConfig,
      executor: this.executorPda,
      relayer: this.relayer.publicKey,
      systemProgram: SystemProgram.programId,
    };

    // Build instructions
    const cuIx = ComputeBudgetProgram.setComputeUnitLimit({ units: this.cu });
    const orderIx = await this.program.methods
      .phoenixPlaceOrder(this.mint, this.claimant, pkt)
      .accounts(baseAccounts)
      .remainingAccounts(
        buildOrderRemainingAccounts(PHOENIX_EXCHANGE, market, this.traderPda),
      )
      .instruction();

    const ixs = [cuIx, orderIx];

    // Use the new atomic PlacePositionConditionalOrder if any bracket leg is requested.
    // This avoids the PositionSequenceInvalidated bug caused by two sequential place_stop_loss calls.
    if (opts.stopLoss || opts.takeProfit) {
      const isLong = opts.side === "Long";
      // Long:  TP fires when price RISES (greaterTrigger), SL when price DROPS (lessTrigger)
      // Short: SL fires when price RISES (greaterTrigger), TP when price DROPS (lessTrigger)
      const greaterOpt = isLong ? opts.takeProfit : opts.stopLoss;
      const lessOpt = isLong ? opts.stopLoss : opts.takeProfit;
      const hasGreater = !!greaterOpt;
      const hasLess = !!lessOpt;
      const greaterTrigger = greaterOpt?.triggerTicks ?? 0n;
      const greaterExecution =
        greaterOpt?.executionTicks ?? greaterOpt?.triggerTicks ?? 0n;
      const lessTrigger = lessOpt?.triggerTicks ?? 0n;
      const lessExecution =
        lessOpt?.executionTicks ?? lessOpt?.triggerTicks ?? 0n;
      const greaterOrderKind = isLong ? ORDER_KIND_LIMIT : ORDER_KIND_IOC;
      const lessOrderKind = isLong ? ORDER_KIND_IOC : ORDER_KIND_LIMIT;
      // Auto-create the conditionalOrders PDA if it doesn't exist yet.
      const createIxOrNull = await this._ensureConditionalOrdersIx();
      if (createIxOrNull) ixs.push(createIxOrNull);
      const bracketIx = await this.program.methods
        .phoenixPlacePositionConditionalOrder(
          this.mint,
          this.claimant,
          Number(market.assetId),
          hasGreater,
          new BN(greaterTrigger.toString()),
          new BN(greaterExecution.toString()),
          closeSide,
          greaterOrderKind,
          hasLess,
          new BN(lessTrigger.toString()),
          new BN(lessExecution.toString()),
          closeSide,
          lessOrderKind,
          100, // size_percent: close full position
        )
        .accounts(baseAccounts)
        .remainingAccounts(
          buildPositionConditionalOrderRemainingAccounts(
            PHOENIX_EXCHANGE,
            market,
            this.traderPda,
          ),
        )
        .instruction();
      ixs.push(bracketIx);
    }

    const conn: Connection = (this.program.provider as any).connection;
    const { blockhash } = await conn.getLatestBlockhash("confirmed");
    const msg = new TransactionMessage({
      payerKey: this.relayer.publicKey,
      recentBlockhash: blockhash,
      instructions: ixs,
    }).compileToV0Message();
    const tx = new VersionedTransaction(msg);
    tx.sign([this.relayer]);
    const sig = await conn.sendTransaction(tx, { skipPreflight: false });
    await conn.confirmTransaction(sig, "confirmed");
    return sig;
  }

  /**
   * Cancel all resting (PostOnly) limit orders for a market.
   *
   * @param symbol Market symbol
   */
  async cancelAllOrders(symbol: string): Promise<string> {
    const market = getMarket(symbol);
    return this.program.methods
      .phoenixCancelOrders(this.mint, this.claimant)
      .accounts({
        config: this.poolConfig,
        executor: this.executorPda,
        relayer: this.relayer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts(
        buildOrderRemainingAccounts(PHOENIX_EXCHANGE, market, this.traderPda),
      )
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: this.cu }),
      ])
      .signers([this.relayer])
      .rpc();
  }

  // ── Exit flow ───────────────────────────────────────────────────────────

  /**
   * Queue a USDC withdrawal from Phoenix collateral.
   *
   * This is step 1 of the two-step exit flow:
   *   1. `queueWithdraw` — Veilo calls Phoenix `withdrawFunds` CPI; PhUSD lands in
   *      the executor's PhUSD ATA and the amount is recorded in the phoenix-slot PDA.
   *   2. `emberUnwrap`   — PhUSD is burned via EMBER and USDC is returned to the pool.
   *
   * @param amount            Amount in USDC quote lots (1 lot = $0.000001 USDC)
   * @param withdrawalId      32-byte nonce identifying this withdrawal (e.g. Buffer.alloc(32, 0))
   * @param executorPhUsdAta  PhUSD ATA of the executor PDA (Phoenix deposits PhUSD here)
   */
  async queueWithdraw(opts: {
    amount: BN;
    withdrawalId: Uint8Array;
    executorPhUsdAta: PublicKey;
  }): Promise<string> {
    const phoenixSlot = derivePhoenixSlotPda(
      this.program.programId,
      this.mint,
      this.claimant,
      opts.withdrawalId,
    );
    return this.program.methods
      .phoenixQueueWithdraw(
        this.mint,
        this.claimant,
        opts.amount,
        Array.from(opts.withdrawalId),
      )
      .accounts({
        config: this.poolConfig,
        executor: this.executorPda,
        relayer: this.relayer.publicKey,
        phoenixSlot,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts([
        // [0..8]: Phoenix withdrawFunds remaining accounts
        ...buildWithdrawRemainingAccounts(PHOENIX_EXCHANGE, this.traderPda),
        // [9]: executor PhUSD ATA — Phoenix deposits PhUSD here
        { pubkey: opts.executorPhUsdAta, isSigner: false, isWritable: true },
      ])
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: this.cu }),
      ])
      .signers([this.relayer])
      .rpc();
  }

  /**
   * Unwrap PhUSD → USDC via EMBER and return funds to the pool vault.
   *
   * This is step 2 of the exit flow; must be called after `queueWithdraw` completes.
   * On success the pending-reissue PDA is populated so that `reissue_notes` can run.
   *
   * @param amount             Amount in USDC quote lots — must match what was queued
   * @param withdrawalId       Same 32-byte nonce used in `queueWithdraw`
   * @param vault              Pool vault PDA (use `derivePoolVault(programId, mint)`)
   * @param vaultTokenAccount  Vault's USDC ATA (receives USDC from EMBER unwrap)
   * @param executorUsdcAta    Executor's USDC ATA (interim USDC destination)
   * @param executorPhUsdAta   Executor's PhUSD ATA (PhUSD is burned from here)
   */
  async emberUnwrap(opts: {
    amount: BN;
    withdrawalId: Uint8Array;
    vault: PublicKey;
    vaultTokenAccount: PublicKey;
    executorUsdcAta: PublicKey;
    executorPhUsdAta: PublicKey;
  }): Promise<string> {
    const phoenixSlot = derivePhoenixSlotPda(
      this.program.programId,
      this.mint,
      this.claimant,
      opts.withdrawalId,
    );
    const pendingReissue = derivePendingReissuePda(
      this.program.programId,
      this.mint,
      this.claimant,
      opts.withdrawalId,
    );
    return this.program.methods
      .phoenixEmberUnwrap(
        this.mint,
        this.claimant,
        Array.from(opts.withdrawalId),
        opts.amount,
      )
      .accounts({
        config: this.poolConfig,
        vault: opts.vault,
        executor: this.executorPda,
        executorPhUsdAta: opts.executorPhUsdAta,
        executorTokenAccount: opts.executorUsdcAta,
        vaultTokenAccount: opts.vaultTokenAccount,
        relayer: this.relayer.publicKey,
        pendingReissue,
        phoenixSlot,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts([
        // [0..8]: Phoenix consumeWithdrawQueue remaining accounts
        ...buildConsumeWithdrawQueueAccounts(PHOENIX_EXCHANGE, this.traderPda),
        // [9..13]: EMBER burn/unwrap accounts
        { pubkey: EMBER_PROGRAM_ID, isSigner: false, isWritable: false }, // [9]  emberProgram
        { pubkey: PHUSD_MINT_AUTHORITY, isSigner: false, isWritable: false }, // [10] phUsdMintAuthPda
        { pubkey: this.mint, isSigner: false, isWritable: false }, // [11] usdcMint
        { pubkey: PHUSD_MINT, isSigner: false, isWritable: true }, // [12] phUsdMint
        { pubkey: EMBER_USDC_RESERVE, isSigner: false, isWritable: true }, // [13] emberUsdcReserve
      ])
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: this.cu }),
      ])
      .signers([this.relayer])
      .rpc();
  }

  // ── Convenience derivation helpers ───────────────────────────────────────

  /**
   * Derive the phoenix-slot PDA for a given withdrawal nonce.
   * Shorthand for `derivePhoenixSlotPda(program.programId, mint, claimant, withdrawalId)`.
   */
  phoenixSlotPda(withdrawalId: Uint8Array): PublicKey {
    return derivePhoenixSlotPda(
      this.program.programId,
      this.mint,
      this.claimant,
      withdrawalId,
    );
  }

  /**
   * Derive the pending-reissue PDA for a given withdrawal nonce.
   * Shorthand for `derivePendingReissuePda(program.programId, mint, claimant, withdrawalId)`.
   */
  pendingReissuePda(withdrawalId: Uint8Array): PublicKey {
    return derivePendingReissuePda(
      this.program.programId,
      this.mint,
      this.claimant,
      withdrawalId,
    );
  }


  /**
   * Derive the conditional-orders collection PDA for this executor's trader account.
   * Seeds: ["conditional_orders", traderPda]
   */
  conditionalOrdersAccountPda(): PublicKey {
    return conditionalOrdersPda(PHOENIX_PROGRAM_ID, this.traderPda);
  }

  /**
   * Create the conditional-orders collection account for this executor (one-time init).
   * Must be called before `setBracketOrder` / `phoenix_place_position_conditional_order`.
   * Idempotent — safe to call again if the account already exists.
   *
   * @param capacity Maximum concurrent conditional orders (default: 8)
   */
  async initConditionalOrdersAccount(capacity = 8): Promise<string> {
    return this.program.methods
      .phoenixCreateConditionalOrdersAccount(this.mint, this.claimant, capacity)
      .accounts({
        config: this.poolConfig,
        executor: this.executorPda,
        relayer: this.relayer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts(
        buildCreateConditionalOrdersAccountRemainingAccounts(
          PHOENIX_EXCHANGE,
          this.traderPda,
        ),
      )
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: this.cu }),
      ])
      .signers([this.relayer])
      .rpc();
  }

  /**
   * Build the `create_conditional_orders_account` instruction if the PDA doesn't
   * exist yet. Returns `null` if the account is already initialized.
   * Used by `setBracketOrder` and `placeOrderWithBracket` to auto-init transparently.
   */
  private async _ensureConditionalOrdersIx(): Promise<
    import("@solana/web3.js").TransactionInstruction | null
  > {
    const conn: Connection = (this.program.provider as any).connection;
    const condOrdersAcct = this.conditionalOrdersAccountPda();
    const acctInfo = await conn.getAccountInfo(condOrdersAcct);
    if (acctInfo) return null;
    return this.program.methods
      .phoenixCreateConditionalOrdersAccount(this.mint, this.claimant, 8)
      .accounts({
        config: this.poolConfig,
        executor: this.executorPda,
        relayer: this.relayer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts(
        buildCreateConditionalOrdersAccountRemainingAccounts(
          PHOENIX_EXCHANGE,
          this.traderPda,
        ),
      )
      .instruction();
  }

  /**
   * Atomically place a bracket order (SL and/or TP) using the new
   * `PlacePositionConditionalOrder` instruction.
   *
   * Unlike `setConditionalOrder` (legacy `place_stop_loss`), this places both legs
   * atomically and does NOT increment `positionSeqNum` twice, which caused
   * `PositionSequenceInvalidated` on mainnet when both SL and TP were set.
   *
   * The `traderConditionalOrders` account is created automatically the first time
   * if it doesn't already exist (transparent to the caller).
   *
   * @param symbol         Market symbol (e.g. "SOL")
   * @param side           Position side — determines which leg is SL vs TP
   * @param stopLoss       SL leg — `executionTicks` required (set worse for slippage)
   * @param takeProfit     TP leg — `executionTicks` defaults to `triggerTicks` (limit)
   * @param sizePercent    Percentage of position to close (1–100, default 100)
   */
  async setBracketOrder(opts: {
    symbol: string;
    side: OrderSide;
    stopLoss?: { triggerTicks: bigint; executionTicks: bigint };
    takeProfit?: { triggerTicks: bigint; executionTicks?: bigint };
    sizePercent?: number;
  }): Promise<string> {
    const market = getMarket(opts.symbol);
    const isLong = opts.side === "Long";
    const closeSide: 0 | 1 = isLong ? 1 : 0; // Ask to close long, Bid to close short
    const ORDER_KIND_LIMIT = 0;
    const ORDER_KIND_IOC = 1;
    const sizePercent = opts.sizePercent ?? 100;

    // Long:  TP fires when price RISES (greaterTrigger), SL when price DROPS (lessTrigger)
    // Short: SL fires when price RISES (greaterTrigger), TP when price DROPS (lessTrigger)
    const greaterOpt = isLong ? opts.takeProfit : opts.stopLoss;
    const lessOpt = isLong ? opts.stopLoss : opts.takeProfit;
    const hasGreater = !!greaterOpt;
    const hasLess = !!lessOpt;
    const greaterTrigger = greaterOpt?.triggerTicks ?? 0n;
    const greaterExecution =
      greaterOpt?.executionTicks ?? greaterOpt?.triggerTicks ?? 0n;
    const lessTrigger = lessOpt?.triggerTicks ?? 0n;
    const lessExecution =
      lessOpt?.executionTicks ?? lessOpt?.triggerTicks ?? 0n;
    // Long TP = limit (price favourable), Long SL = IOC (market out fast)
    // Short SL = IOC (price is rising — exit fast), Short TP = limit
    const greaterOrderKind = isLong ? ORDER_KIND_LIMIT : ORDER_KIND_IOC;
    const lessOrderKind = isLong ? ORDER_KIND_IOC : ORDER_KIND_LIMIT;

    // Auto-create the conditionalOrders PDA if this is the first bracket order for this executor.
    const createIxOrNull = await this._ensureConditionalOrdersIx();
    const preInstructions = [
      ComputeBudgetProgram.setComputeUnitLimit({ units: this.cu }),
      ...(createIxOrNull ? [createIxOrNull] : []),
    ];

    return this.program.methods
      .phoenixPlacePositionConditionalOrder(
        this.mint,
        this.claimant,
        Number(market.assetId),
        hasGreater,
        new BN(greaterTrigger.toString()),
        new BN(greaterExecution.toString()),
        closeSide,
        greaterOrderKind,
        hasLess,
        new BN(lessTrigger.toString()),
        new BN(lessExecution.toString()),
        closeSide,
        lessOrderKind,
        sizePercent,
      )
      .accounts({
        config: this.poolConfig,
        executor: this.executorPda,
        relayer: this.relayer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts(
        buildPositionConditionalOrderRemainingAccounts(
          PHOENIX_EXCHANGE,
          market,
          this.traderPda,
        ),
      )
      .preInstructions(preInstructions)
      .signers([this.relayer])
      .rpc();
  }

  /**
   * Cancel a conditional order from the collection by slot index.
   *
   * @param symbol                 Market symbol
   * @param conditionalOrderIndex  Slot index (1–191) returned at placement
   * @param disableFirst           Cancel the SL (lessTrigger) leg
   * @param disableSecond          Cancel the TP (greaterTrigger) leg
   */
  async cancelBracketOrder(opts: {
    symbol: string;
    conditionalOrderIndex: number;
    disableFirst?: boolean;
    disableSecond?: boolean;
  }): Promise<string> {
    const market = getMarket(opts.symbol);
    const disableFirst = opts.disableFirst ?? true;
    const disableSecond = opts.disableSecond ?? true;
    return this.program.methods
      .phoenixCancelConditionalOrder(
        this.mint,
        this.claimant,
        opts.conditionalOrderIndex,
        disableFirst,
        disableSecond,
      )
      .accounts({
        config: this.poolConfig,
        executor: this.executorPda,
        relayer: this.relayer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts(
        buildCancelConditionalOrderRemainingAccounts(
          PHOENIX_EXCHANGE,
          market,
          this.traderPda,
        ),
      )
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: this.cu }),
      ])
      .signers([this.relayer])
      .rpc();
  }
}

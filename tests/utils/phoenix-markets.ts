/**
 * tests/utils/phoenix-markets.ts
 *
 * Phoenix Eternal market helpers for the Veilo Privacy Pool test suite.
 *
 * Instead of hardcoding per-market public keys throughout tests, import from
 * here so that adding a new market only requires one change (if even that —
 * use `fetchLiveMarkets()` to get the live registry at test time).
 *
 * Quick-start:
 *   import {
 *     PHOENIX_EXCHANGE, PHOENIX_SOL, PHOENIX_BTC, PHOENIX_ETH,
 *     getMarket, assetIdFor, stopLossPda,
 *     buildOrderRemainingAccounts, fetchLiveMarkets,
 *   } from "./utils/phoenix-markets";
 *
 *   const market = getMarket("BTC");            // throws if unknown symbol
 *   const id     = assetIdFor("ETH");           // → 2n
 *   const slPda  = stopLossPda(PHOENIX_PROGRAM_ID, traderPda, id);
 *   const accts  = buildOrderRemainingAccounts(PHOENIX_EXCHANGE, market, traderPda);
 *
 * Data source: https://perp-api.phoenix.trade/v1/exchange/snapshot
 * (confirmed 2026-05-21, slot 421 084 972)
 */

import { PublicKey } from "@solana/web3.js";
import type { AccountMeta } from "@solana/web3.js";

// ─── Phoenix program constants ────────────────────────────────────────────────

/** Phoenix Eternal on-chain program */
export const PHOENIX_PROGRAM_ID = new PublicKey(
  "EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih",
);

// ─── Types ────────────────────────────────────────────────────────────────────

/**
 * Per-market configuration (unique to every traded instrument).
 *
 * `orderbook`  — the Phoenix perpetual market/orderbook account
 * `splines`    — the spline collection account used by the risk engine
 * `tickSize`   — quote-lot tick size (raw, as reported by the exchange API)
 * `baseLotsDecimals` — exponent: 1 base unit = 10^baseLotsDecimals base lots
 */
export interface PhoenixMarket {
  readonly symbol: string;
  readonly assetId: bigint;
  readonly orderbook: PublicKey;
  readonly splines: PublicKey;
  readonly tickSize: number;
  readonly baseLotsDecimals: number;
}

/**
 * Exchange-level global accounts — the same for every market.
 * Pass an instance of this alongside a `PhoenixMarket` to the `build*` helpers.
 */
export interface PhoenixExchangeAccounts {
  /** Phoenix Eternal program */
  readonly program: PublicKey;
  /** PDA ["log"] of the Phoenix program */
  readonly logAuthority: PublicKey;
  /** PDA ["global"] of the Phoenix program — global configuration account */
  readonly globalConfig: PublicKey;
  /** PerpAssetMap — stores per-asset oracle and risk data */
  readonly perpAssetMap: PublicKey;
  /** GlobalTraderIndex[0] — maps authority → trader PDA index */
  readonly globalTraderIndex: PublicKey;
  /** ActiveTraderBuffer[0] — active trader registry */
  readonly activeTraderBuffer: PublicKey;
  /** Global USDC vault for collateral */
  readonly globalVault: PublicKey;
  /** Async withdrawal queue */
  readonly withdrawQueue: PublicKey;
}

// ─── Known mainnet exchange accounts ─────────────────────────────────────────

/**
 * Mainnet Phoenix Eternal exchange accounts (slot 421 084 972, 2026-05-21).
 * `logAuthority` and `globalConfig` are PDAs; their addresses are computed
 * once at module load and cached here for convenience.
 */
export const PHOENIX_EXCHANGE: PhoenixExchangeAccounts = (() => {
  const [logAuthority] = PublicKey.findProgramAddressSync(
    [Buffer.from("log")],
    PHOENIX_PROGRAM_ID,
  );
  const [globalConfig] = PublicKey.findProgramAddressSync(
    [Buffer.from("global")],
    PHOENIX_PROGRAM_ID,
  );
  return {
    program: PHOENIX_PROGRAM_ID,
    logAuthority,
    globalConfig,
    perpAssetMap: new PublicKey("2nHGAaEw3D5dd4hVueaUNoygkQFmoeKqRQWnSPqSMFUC"),
    globalTraderIndex: new PublicKey(
      "HCrPXLByGqRh2szQi3gj7oRdRVBNi1gccAyn4CQCT3HK",
    ),
    activeTraderBuffer: new PublicKey(
      "2U32rSzzrQS3eVmGHsnbw5kcqKF3wQXpHGd3hMq5YJok",
    ),
    globalVault: new PublicKey("csZXgw2G58hbiWc9ndxaxrQVYVvqdXgQzYLuznEzHJu"),
    withdrawQueue: new PublicKey(
      "3c3NTwpg7yW91FxijkHBXwVH1xUifun3Z8TC5eW5Si3K",
    ),
  };
})();

// ─── Known mainnet markets ────────────────────────────────────────────────────
// Source: GET /v1/exchange/snapshot (2026-05-21)
// Fields: symbol, assetId, marketPubkey (orderbook), splinePubkey, tickSize, baseLotsDecimals

function market(
  symbol: string,
  assetId: number,
  orderbook: string,
  splines: string,
  tickSize: number,
  baseLotsDecimals: number,
): PhoenixMarket {
  return {
    symbol,
    assetId: BigInt(assetId),
    orderbook: new PublicKey(orderbook),
    splines: new PublicKey(splines),
    tickSize,
    baseLotsDecimals,
  };
}

/**
 * All currently-live Phoenix Eternal markets, keyed by uppercase base symbol
 * (e.g. "SOL", "BTC", "ETH").
 *
 * Use `getMarket(symbol)` or `assetIdFor(symbol)` instead of indexing directly
 * so that you get a helpful error on typos.
 */
export const PHOENIX_MARKETS: Readonly<Record<string, PhoenixMarket>> = {
  SOL: market(
    "SOL",
    0,
    "71Si24E4uc3oCaPbPZTozC1ptSNNqygjjebxSmErSsC2",
    "EVhkquLbfm5rDRXtZu9FoyDSXX5mYq2EYU6yD8zfKEqM",
    100,
    2,
  ),
  BTC: market(
    "BTC",
    1,
    "AXFz1MuzMUBHi5UKJuK3FDCQ73o3rSzubGU2mPr4LLU7",
    "Dh9NrYjzzdvcYgFSbrkATQ1rPkPjDovXWnFVhfWmD2ZF",
    100,
    4,
  ),
  ETH: market(
    "ETH",
    2,
    "9u7aqptdRFbsnnoHtjK13E5JkeM14EW5fAKTRPidVF88",
    "DN7uE4FBSs9Uy6V3GNvAbTdUMufY1hBkdy3JV1UfYdg",
    100,
    3,
  ),
  XRP: market(
    "XRP",
    3,
    "CwaHtR69D287PLnoX8zzzk1zqwNQKVJiJQTNs6JrVyna",
    "DTX3dsRdJfx2bUWWKgGAKv3UGfRFHB2NGX7a5DmG81Em",
    10,
    2,
  ),
  HYPE: market(
    "HYPE",
    4,
    "CEx9Mgz5cAmWwy6D5H2xGrhmwKeC5L7KtYhFhVGtiBaZ",
    "8QFRzJQHcUbVmedQv6TN35ppawVGSPn2k6sFFE8qVzGx",
    10,
    2,
  ),
  SKR: market(
    "SKR",
    5,
    "HnKUNWrcrpYqK5Uworv2wH6Ki3ciDVDDYqicE5SRAAWs",
    "CBiXToL5bStyjJKcvyMBNfD4JDrj6cmFu8H2ebsBTSDu",
    1,
    0,
  ),
  BNB: market(
    "BNB",
    6,
    "4Xd7E3eBXazSoudAMACsNdezA4UuJETURL1S6fqpjcTR",
    "AftmFSqv3xKC1cNjepN72RuHKWLmwrke5V8f8Va7Ss4W",
    100,
    2,
  ),
  DOGE: market(
    "DOGE",
    7,
    "Hqt5Vom5L3X3RcKysKnBmLAvjYgo6TGAwoheW658h5cz",
    "Fg5UGzY7pJ39zKCsJkcMnvX4kxroZb2waKDusM4RwihS",
    1,
    0,
  ),
  AAVE: market(
    "AAVE",
    8,
    "A6CdPuNY3mp4tsY1ifQoesHKfwYdVv3wqcaKirEGtaMS",
    "6LpsZSmcVU48zpbyFqJhNvVVGDF4keiQYM89ChJtuJLS",
    100,
    2,
  ),
  SUI: market(
    "SUI",
    9,
    "GQS3qn9EjKYpqoLwpvPVbeW9o1bjFYhc1SRMZYw4iNru",
    "7PNzQtPd1EjVEs9ixAqPb9ynRcNiK27tJ8qpTwjJYYme",
    10,
    0,
  ),
  ZEC: market(
    "ZEC",
    10,
    "FTbbqCP2N2NkUHw1nMPpBhiQCrYGiMQAhK7g1G8NJKEt",
    "A4DMNb5gn8QCTt8NB1zwTHyqUWZShjgonSMtRYFfqNfZ",
    100,
    2,
  ),
  TAO: market(
    "TAO",
    11,
    "CoshgxCZygQnS5jJLi24DkuJN4hddRNdPVSmTWrURbHu",
    "6E5o1ZzEwxW7xWwR6YPbYEL53bDpYTtqoQfXLLxXss7j",
    100,
    3,
  ),
  LIT: market(
    "LIT",
    12,
    "CuEkf4SopwRHsdYfTy5zE5aohcWXmFh693Fb99nueJ4r",
    "F3TiSunZ73cw3XHF2vd6oyJjZEYrSGG1Etta5h4b2qvs",
    10,
    1,
  ),
  MON: market(
    "MON",
    13,
    "7hnu7Fm4UXF3K5wpytJuaSeAjw2XYDN4avgy6ZDKCPhs",
    "ELApxywmv4VRB6iBuycAtJxepKd57oFenMvVfBdNyGab",
    1,
    0,
  ),
  NEAR: market(
    "NEAR",
    14,
    "AHLLA4oggZssMt1M3sfyZ1z2XWt9m6JjNzjS5getE78q",
    "7cPviQWgKSEiHQVwW99ntVk2EAT6sKffsjCxF4x9BVZ",
    100,
    0,
  ),
  XPL: market(
    "XPL",
    15,
    "9HTT4Do4i9NM6Lc8vBE1qPEhEDejuNkza3dnUstyzfcp",
    "EHLJQwwsF2K7ma8md8AeEQvHTpXEYhumJBWrAzXoxxHu",
    10,
    0,
  ),
  FARTCOIN: market(
    "FARTCOIN",
    16,
    "ERTPfrA1VzpnefeGWUtoWRuE9r8wak5KL3Mm4EYCVgc7",
    "6qiBuFdbYQwFKF9e834HTXrLkYvPdtjgH6QWtY9M4tbD",
    10,
    0,
  ),
  ENA: market(
    "ENA",
    17,
    "CQJduVF57Eycp6M6fPDv5GBUR2TL5cCiriaLBhoCz4dj",
    "A86xwLL4iaf75Z7kAHDMhwUEGH1ZRbZzYXA3pccentze",
    10,
    0,
  ),
  CHIP: market(
    "CHIP",
    18,
    "7kqxngbXdGsshqN6btUihJsKDJVXPe7ZENk8EAe41bjN",
    "DDNizK5aDRxCj4rFQo3pHW4HR1kasp7Vk9wHRAGzvwv1",
    10,
    0,
  ),
  MEGA: market(
    "MEGA",
    19,
    "6KS7HgwRHZG47d7yJgVQrEJQv3jVCrBwDDRxK3YFCMV4",
    "9MsdsbqstnKxw4hdBmDnRLVGjj49KDkpW4z2iLvQBwQg",
    10,
    0,
  ),
  WTIOIL: market(
    "WTIOIL",
    21,
    "aYRsjCr1JEcdPWYeztgRWz8zDTs2mzhQ1hTxNWCmXND",
    "8YutMhx5dJP7mdFCb9XzktmewafUbLmyDdRqZmv2R42U",
    100,
    2,
  ),
  JTO: market(
    "JTO",
    22,
    "AJCsYQYT9ezpdcq28yzVkXos5RKhaWrRbDFASgJxNtu9",
    "EbGkB4TxceMrZjtBhj5M8zqS3rwtRVhPHa9UD6hfhdH2",
    10,
    1,
  ),
  TON: market(
    "TON",
    23,
    "59qkaEUQJokbc8CGVzNg9ESzGDK8dro4D13UtfekR6JE",
    "9hY4Kc451MQhV7Z5XE2tC5JKgrAw2Jda3KjefyrZyn9r",
    10,
    1,
  ),
  VVV: market(
    "VVV",
    24,
    "5kPZcErZ12YbqhUHzguCgYyjMVHxpiMAW324KL2jWVHQ",
    "7CyFxgjHDxGt4hU3JoFuiFygAedgmHVY5CYoB2Tdezyx",
    10,
    2,
  ),
  JUP: market(
    "JUP",
    25,
    "9vhQ2yo3b23vQ75iK7qQTRcVkqtpLjaWuphkZ2TQiYEE",
    "FCLk7BZ4anY3dv3HeBqjnG2C9PhudP7MpBsvULBBWRjV",
    10,
    0,
  ),
  PUMP: market(
    "PUMP",
    26,
    "EwveokQBpaTiGkwCHm2yVdwogHm26PRwponFDt7EjEhz",
    "4RaR6tfT53to2dxU9XJT9jdBoS8bPGdDau51ALZa2f3A",
    10,
    -2,
  ),
  MET: market(
    "MET",
    29,
    "HxhDqvdDJ9qWaWJ5tvMEdyL1CvZmnBtqA5PTRLyr7CB",
    "DHFD2VwJkyT2hzMpyvnz34TLQuqPJyqnyVhnrx82A6gH",
    10,
    0,
  ),
  // Commodity markets — note non-sequential assetIds
  GOLD: market(
    "GOLD",
    65556,
    "7B7hDscDNBGFpNGypFygoiANCpdM3JR2PY3JbvPvQtmk",
    "4Xf7mkyTyWfiWnRo4oHjfwopSF46aLk8XciWotfG8voB",
    100,
    3,
  ),
  SILVER: market(
    "SILVER",
    131099,
    "GD4XZsTfAbjromE1zac61AUAhyfXhwFa8soBmUo59WqB",
    "AzLaPv4LcFAMBz1zNaSuFq1nY5tN74tRM8KmSPdwkVWS",
    10,
    2,
  ),
};

// ─── Convenience named exports ────────────────────────────────────────────────

export const PHOENIX_SOL = PHOENIX_MARKETS.SOL;
export const PHOENIX_BTC = PHOENIX_MARKETS.BTC;
export const PHOENIX_ETH = PHOENIX_MARKETS.ETH;
export const PHOENIX_XRP = PHOENIX_MARKETS.XRP;
export const PHOENIX_HYPE = PHOENIX_MARKETS.HYPE;
export const PHOENIX_BNB = PHOENIX_MARKETS.BNB;
export const PHOENIX_DOGE = PHOENIX_MARKETS.DOGE;
export const PHOENIX_AAVE = PHOENIX_MARKETS.AAVE;
export const PHOENIX_SUI = PHOENIX_MARKETS.SUI;
export const PHOENIX_NEAR = PHOENIX_MARKETS.NEAR;
export const PHOENIX_JTO = PHOENIX_MARKETS.JTO;
export const PHOENIX_JUP = PHOENIX_MARKETS.JUP;
export const PHOENIX_GOLD = PHOENIX_MARKETS.GOLD;
export const PHOENIX_SILVER = PHOENIX_MARKETS.SILVER;

// ─── Lookup helpers ───────────────────────────────────────────────────────────

/**
 * Look up a market by symbol (case-insensitive, strip "-PERP" suffix).
 * Throws with a helpful message if the symbol is not in `PHOENIX_MARKETS`.
 *
 * @example
 *   const market = getMarket("BTC");
 *   const market = getMarket("btc-perp"); // normalised → "BTC"
 */
export function getMarket(symbol: string): PhoenixMarket {
  const normalized = symbol
    .trim()
    .toUpperCase()
    .replace(/-PERP$/, "");
  const m = PHOENIX_MARKETS[normalized];
  if (!m) {
    const known = Object.keys(PHOENIX_MARKETS).join(", ");
    throw new Error(
      `Unknown Phoenix market "${symbol}". Known markets: ${known}`,
    );
  }
  return m;
}

/**
 * Return the `assetId` (bigint) for a market symbol.
 * Shorthand for `getMarket(symbol).assetId`.
 *
 * @example
 *   const id = assetIdFor("ETH"); // → 2n
 */
export function assetIdFor(symbol: string): bigint {
  return getMarket(symbol).assetId;
}

/**
 * Look up a market by its on-chain assetId.
 * Throws if no market with that assetId is registered.
 */
export function getMarketByAssetId(assetId: bigint): PhoenixMarket {
  const entry = Object.values(PHOENIX_MARKETS).find(
    (m) => m.assetId === assetId,
  );
  if (!entry) {
    throw new Error(`No Phoenix market found for assetId ${assetId}`);
  }
  return entry;
}

// ─── PDA helpers ──────────────────────────────────────────────────────────────

/**
 * Encode an assetId as an 8-byte little-endian buffer (for PDA seeds).
 *
 * @example
 *   const buf = assetIdToBuffer(2n); // ETH → [0x02, 0, 0, 0, 0, 0, 0, 0]
 */
export function assetIdToBuffer(assetId: bigint): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(assetId, 0);
  return buf;
}

/**
 * Derive the Phoenix stop-loss PDA for a given trader and market.
 *
 * Seeds: ["stoploss", traderAccount_pubkey, assetId_le_u64]
 *
 * @example
 *   const pda = stopLossPda(PHOENIX_PROGRAM_ID, traderPda, assetIdFor("BTC"));
 */
export function stopLossPda(
  phoenixProgramId: PublicKey,
  traderPda: PublicKey,
  assetId: bigint,
): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("stoploss"), traderPda.toBuffer(), assetIdToBuffer(assetId)],
    phoenixProgramId,
  );
  return pda;
}

// ─── Remaining-accounts builders ─────────────────────────────────────────────

/**
 * Build the 9 `remainingAccounts` for order placement and cancellation CPIs:
 *
 *   [0] phoenixProgram       (readonly)
 *   [1] logAuthority         (readonly)
 *   [2] globalConfig         (writable)
 *   [3] traderAccount        (writable)  ← executor PDA
 *   [4] perpAssetMap         (writable)
 *   [5] globalTraderIndex    (writable)
 *   [6] activeTraderBuffer   (writable)
 *   [7] orderbook            (writable)  ← per-market
 *   [8] splines              (writable)  ← per-market
 *
 * Applies to: `phoenix_place_order`, `phoenix_cancel_orders`,
 *             `phoenix_cancel_orders_by_id`, `phoenix_deposit_from_pool`
 */
export function buildOrderRemainingAccounts(
  exchange: PhoenixExchangeAccounts,
  market: PhoenixMarket,
  traderPda: PublicKey,
): AccountMeta[] {
  return [
    { pubkey: exchange.program, isSigner: false, isWritable: false },
    { pubkey: exchange.logAuthority, isSigner: false, isWritable: false },
    { pubkey: exchange.globalConfig, isSigner: false, isWritable: true },
    { pubkey: traderPda, isSigner: false, isWritable: true },
    { pubkey: exchange.perpAssetMap, isSigner: false, isWritable: true },
    { pubkey: exchange.globalTraderIndex, isSigner: false, isWritable: true },
    { pubkey: exchange.activeTraderBuffer, isSigner: false, isWritable: true },
    { pubkey: market.orderbook, isSigner: false, isWritable: true },
    { pubkey: market.splines, isSigner: false, isWritable: true },
  ];
}

/**
 * Build the 9 fixed `remainingAccounts` for `phoenix_queue_withdraw` CPIs
 * (withdrawFunds instruction).
 * Append the per-call destination ATA as account [9] after this array.
 *
 *   [0] phoenixProgram       (readonly)
 *   [1] logAuthority         (readonly)
 *   [2] globalConfig         (writable)
 *   [3] traderAccount        (writable)
 *   [4] perpAssetMap         (writable)
 *   [5] globalVault          (writable)
 *   [6] withdrawQueue        (writable)
 *   [7] globalTraderIndex    (writable)
 *   [8] activeTraderBuffer   (writable)
 */
export function buildWithdrawRemainingAccounts(
  exchange: PhoenixExchangeAccounts,
  traderPda: PublicKey,
): AccountMeta[] {
  return [
    { pubkey: exchange.program, isSigner: false, isWritable: false },
    { pubkey: exchange.logAuthority, isSigner: false, isWritable: false },
    { pubkey: exchange.globalConfig, isSigner: false, isWritable: true },
    { pubkey: traderPda, isSigner: false, isWritable: true },
    { pubkey: exchange.perpAssetMap, isSigner: false, isWritable: true },
    { pubkey: exchange.globalVault, isSigner: false, isWritable: true },
    { pubkey: exchange.withdrawQueue, isSigner: false, isWritable: true },
    { pubkey: exchange.globalTraderIndex, isSigner: false, isWritable: true },
    { pubkey: exchange.activeTraderBuffer, isSigner: false, isWritable: true },
  ];
}

/**
 * Build the 9 fixed `remainingAccounts` for `consumeWithdrawQueue`-based CPIs
 * (used by `phoenix_ember_unwrap` to flush the withdraw queue before unwrapping).
 * Note: traderAccount is last ([8]); perpAssetMap comes directly after globalConfig.
 *
 *   [0] phoenixProgram       (readonly)
 *   [1] logAuthority         (readonly)
 *   [2] globalConfig         (writable)
 *   [3] perpAssetMap         (writable)
 *   [4] globalVault          (writable)
 *   [5] globalTraderIndex    (writable)
 *   [6] activeTraderBuffer   (writable)
 *   [7] withdrawQueue        (writable)
 *   [8] traderAccount        (writable)
 */
export function buildConsumeWithdrawQueueAccounts(
  exchange: PhoenixExchangeAccounts,
  traderPda: PublicKey,
): AccountMeta[] {
  return [
    { pubkey: exchange.program, isSigner: false, isWritable: false },
    { pubkey: exchange.logAuthority, isSigner: false, isWritable: false },
    { pubkey: exchange.globalConfig, isSigner: false, isWritable: true },
    { pubkey: exchange.perpAssetMap, isSigner: false, isWritable: true },
    { pubkey: exchange.globalVault, isSigner: false, isWritable: true },
    { pubkey: exchange.globalTraderIndex, isSigner: false, isWritable: true },
    { pubkey: exchange.activeTraderBuffer, isSigner: false, isWritable: true },
    { pubkey: exchange.withdrawQueue, isSigner: false, isWritable: true },
    { pubkey: traderPda, isSigner: false, isWritable: true },
  ];
}

/**
 * Build the `remainingAccounts` for `phoenix_place_stop_loss` /
 * `phoenix_cancel_stop_loss` CPIs (adds `stopLossAccount`):
 *
 *   [0..8] same as buildOrderRemainingAccounts
 *   [9]  stopLossAccount  (writable)  ← PDA ["stoploss", traderPda, assetId]
 */
export function buildStopLossRemainingAccounts(
  exchange: PhoenixExchangeAccounts,
  market: PhoenixMarket,
  traderPda: PublicKey,
): AccountMeta[] {
  const stopLossAccount = stopLossPda(
    exchange.program,
    traderPda,
    market.assetId,
  );
  return [
    ...buildOrderRemainingAccounts(exchange, market, traderPda),
    { pubkey: stopLossAccount, isSigner: false, isWritable: true },
  ];
}

// ─── Live market data (optional, requires network) ───────────────────────────

interface SnapshotMarket {
  symbol: string;
  assetId: number;
  marketPubkey: string;
  splinePubkey: string;
  tickSize: number;
  baseLotsDecimals: number;
}

interface ExchangeSnapshot {
  exchange: {
    perpAssetMap: string;
    globalTraderIndex: string[];
    activeTraderBuffer: string[];
    globalVault: string;
    withdrawQueue: string;
  };
  markets: SnapshotMarket[];
}

/**
 * Fetch live market data from the Phoenix exchange API and return a record
 * keyed by uppercase symbol.
 *
 * Call this once at the start of a test suite (e.g. in a `before()` hook)
 * when you want to trade markets added after the last constants update.
 *
 * Falls back gracefully: if the API is unreachable the function throws, so
 * wrap in a try/catch and fall back to `PHOENIX_MARKETS` for offline runs.
 *
 * @example
 *   let liveMarkets = PHOENIX_MARKETS;
 *   before(async () => {
 *     try { liveMarkets = await fetchLiveMarkets(); }
 *     catch { console.warn("Phoenix API unreachable; using cached markets"); }
 *   });
 */
export async function fetchLiveMarkets(
  apiUrl = "https://perp-api.phoenix.trade",
): Promise<Record<string, PhoenixMarket>> {
  const resp = await fetch(`${apiUrl}/v1/exchange/snapshot`);
  if (!resp.ok) {
    throw new Error(
      `Phoenix API returned ${resp.status} for /v1/exchange/snapshot`,
    );
  }
  const data: ExchangeSnapshot = await resp.json();
  const result: Record<string, PhoenixMarket> = {};
  for (const m of data.markets) {
    result[m.symbol.toUpperCase()] = {
      symbol: m.symbol,
      assetId: BigInt(m.assetId),
      orderbook: new PublicKey(m.marketPubkey),
      splines: new PublicKey(m.splinePubkey),
      tickSize: m.tickSize,
      baseLotsDecimals: m.baseLotsDecimals,
    };
  }
  return result;
}

/**
 * Return the live `PhoenixExchangeAccounts` from the API snapshot.
 * Useful when you want to verify the cached constants are still current.
 *
 * @example
 *   const exchange = await fetchLiveExchangeAccounts();
 */
export async function fetchLiveExchangeAccounts(
  apiUrl = "https://perp-api.phoenix.trade",
): Promise<PhoenixExchangeAccounts> {
  const resp = await fetch(`${apiUrl}/v1/exchange/snapshot`);
  if (!resp.ok) {
    throw new Error(
      `Phoenix API returned ${resp.status} for /v1/exchange/snapshot`,
    );
  }
  const data: ExchangeSnapshot = await resp.json();
  const ex = data.exchange;
  const [logAuthority] = PublicKey.findProgramAddressSync(
    [Buffer.from("log")],
    PHOENIX_PROGRAM_ID,
  );
  const [globalConfig] = PublicKey.findProgramAddressSync(
    [Buffer.from("global")],
    PHOENIX_PROGRAM_ID,
  );
  return {
    program: PHOENIX_PROGRAM_ID,
    logAuthority,
    globalConfig,
    perpAssetMap: new PublicKey(ex.perpAssetMap),
    globalTraderIndex: new PublicKey(ex.globalTraderIndex[0]),
    activeTraderBuffer: new PublicKey(ex.activeTraderBuffer[0]),
    globalVault: new PublicKey(ex.globalVault),
    withdrawQueue: new PublicKey(ex.withdrawQueue),
  };
}

// ─── Price conversion helpers ─────────────────────────────────────────────────

/**
 * Convert a USD price to raw ticks for a given market.
 *
 * Phoenix stores prices as integer tick counts.
 * tick = round(priceUsd / (tickSize × 10^(-baseLotsDecimals - 6)))
 *
 * NOTE: This is a rough approximation. For production use, rely on the
 * `buildLimitOrderPacketFromMarketParams` helper from the rise SDK instead.
 *
 * @example
 *   const ticks = usdToTicks(PHOENIX_SOL, 150.50); // → 150_500n (approx)
 */
export function usdToTicks(market: PhoenixMarket, priceUsd: number): bigint {
  // quote lots per base lot at this price:
  //   ticks = priceUsd × 10^6 (USDC decimals) × 10^baseLotsDecimals / tickSize
  const scale = Math.pow(10, 6 + market.baseLotsDecimals);
  return BigInt(Math.round((priceUsd * scale) / market.tickSize));
}

/**
 * Convert raw ticks back to a USD price for a given market.
 *
 * @example
 *   const price = ticksToUsd(PHOENIX_SOL, 150_500n); // → ~150.50
 */
export function ticksToUsd(market: PhoenixMarket, ticks: bigint): number {
  const scale = Math.pow(10, 6 + market.baseLotsDecimals);
  return (Number(ticks) * market.tickSize) / scale;
}

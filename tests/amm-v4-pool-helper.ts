/**
 * AMM V4 Pool Helper Functions
 *
 * Provides pool configuration and account information for Raydium AMM V4 pools.
 * Uses Raydium SDK to dynamically derive pool keys from input/output mints.
 * Used by privacy pool swap tests to get the necessary accounts for CPI swaps.
 */

import { PublicKey, Connection } from "@solana/web3.js";
import * as anchor from "@coral-xyz/anchor";
import {
  Liquidity,
  LiquidityPoolKeysV4,
  LIQUIDITY_STATE_LAYOUT_V4,
  MAINNET_PROGRAM_ID,
  MARKET_STATE_LAYOUT_V3,
  Token,
  TOKEN_PROGRAM_ID,
} from "@raydium-io/raydium-sdk";
import { NATIVE_MINT, getMint } from "@solana/spl-token";
import axios from "axios";

// Raydium AMM V4 Program ID
export const RAYDIUM_AMM_V4_PROGRAM = new PublicKey(
  "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8",
);

// Serum/OpenBook Program ID
export const SERUM_PROGRAM = new PublicKey(
  "srmqPvymJeFKQ4zGQed1GFppgkRHL9kaELCbyksJtPX",
);

// AMM Authority (shared across all AMM V4 pools)
export const AMM_AUTHORITY = new PublicKey(
  "5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1",
);

// AMM V4 Instruction discriminators
export const AMM_SWAP_BASE_IN_DISCRIMINATOR = 9;

// Token Mints
export const WSOL_MINT = new PublicKey(
  "So11111111111111111111111111111111111111112",
);
export const USDC_MINT = new PublicKey(
  "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
);
export const USDT_MINT = new PublicKey(
  "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
);
export const JUP_MINT = new PublicKey(
  "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN",
);
export const USD1_MINT = new PublicKey(
  "USD1ttGY1N17NEEHLmELoaybftRBUSErhqYiQzvEmuB",
);

// Known OpenBook market IDs for common pairs (base/quote)
// These are the Serum/OpenBook market addresses
export const KNOWN_MARKETS: Record<string, PublicKey> = {
  // SOL-USDC market
  [`${WSOL_MINT.toBase58()}-${USDC_MINT.toBase58()}`]: new PublicKey(
    "8BnEgHoWFysVcuFFX7QztDmzuH8r5ZFvyP3sYwn1XTh6",
  ),
  // SOL-USDT market
  [`${WSOL_MINT.toBase58()}-${USDT_MINT.toBase58()}`]: new PublicKey(
    "2AdaV97p6SfkuMQJdu8DHhBhmJe7oWdvbm52MJfYQmfA",
  ),
};

// Global caches
const decimalCache: Record<string, number> = {};
const marketDataCache: Record<string, any> = {};
const poolKeysCache: Record<string, LiquidityPoolKeysV4> = {};

// Raydium API endpoint for fetching real pool data
const RAYDIUM_API_URL = "https://api-v3.raydium.io";

// Cache for API pool data
const apiPoolCache: Record<string, any> = {};

/**
 * Pool configuration interface
 */
export interface AmmV4PoolConfig {
  poolId: PublicKey;
  baseMint: PublicKey;
  quoteMint: PublicKey;
  baseDecimals: number;
  quoteDecimals: number;
  ammOpenOrders: PublicKey;
  ammTargetOrders: PublicKey;
  ammBaseVault: PublicKey;
  ammQuoteVault: PublicKey;
  serumMarket: PublicKey;
  serumBids: PublicKey;
  serumAsks: PublicKey;
  serumEventQueue: PublicKey;
  serumBaseVault: PublicKey;
  serumQuoteVault: PublicKey;
  serumVaultSignerNonce: number;
}

/**
 * Pool name type for type safety
 */
export type PoolName = "SOL-USDC" | "SOL-USDT" | "SOL-JUP" | "SOL-USD1";

/**
 * AMM V4 Pool configurations for all supported pools
 */
export const AMM_V4_POOLS: Record<PoolName, AmmV4PoolConfig> = {
  "SOL-USDC": {
    poolId: new PublicKey("58oQChx4yWmvKdwLLZzBi4ChoCc2fqCUWBkwMihLYQo2"),
    baseMint: WSOL_MINT,
    quoteMint: USDC_MINT,
    baseDecimals: 9,
    quoteDecimals: 6,
    ammOpenOrders: new PublicKey(
      "HmiHHzq4Fym9e1D4qzLS6LDDM3tNsCTBPDWHTLZ763jY",
    ),
    ammTargetOrders: new PublicKey(
      "CZza3Ej4Mc58MnxWA385itCC9jCo3L1D7zc3LKy1bZMR",
    ),
    ammBaseVault: new PublicKey("DQyrAcCrDXQ7NeoqGgDCZwBvWDcYmFCjSb9JtteuvPpz"),
    ammQuoteVault: new PublicKey(
      "HLmqeL62xR1QoZ1HKKbXRrdN1p3phKpxRMb2VVopvBBz",
    ),
    serumMarket: new PublicKey("8BnEgHoWFysVcuFFX7QztDmzuH8r5ZFvyP3sYwn1XTh6"),
    serumBids: new PublicKey("5jWUncPNBMZJ3sTHKmMLszypVkoRK6bfEQMQUHweeQnh"),
    serumAsks: new PublicKey("EaXdHx7x3mdGA38j5RSmKYSXMzAFzzUXCLNBEDXDn1d5"),
    serumEventQueue: new PublicKey(
      "8CvwxZ9Db6XbLD46NZwwmVDZZRDy7eydFcAGkXKh9axa",
    ),
    serumBaseVault: new PublicKey(
      "CKxTHwM9fPMRRvZmFnFoqKNd9pQR21c5Aq9bh5h9oghX",
    ),
    serumQuoteVault: new PublicKey(
      "6A5NHCj1yF6urc9wZNe6Bcjj4LVszQNj5DwAWG97yzMu",
    ),
    serumVaultSignerNonce: 1,
  },
  "SOL-JUP": {
    // Placeholder - Use Dynamic Keys
    poolId: new PublicKey("5Qtn7FFKmVH4Brx3V1cR8E4mot2V3eSmvFRBpmKjNy35"),
    baseMint: WSOL_MINT,
    quoteMint: JUP_MINT,
    baseDecimals: 9,
    quoteDecimals: 6,
    ammOpenOrders: PublicKey.default,
    ammTargetOrders: PublicKey.default,
    ammBaseVault: PublicKey.default,
    ammQuoteVault: PublicKey.default,
    serumMarket: PublicKey.default,
    serumBids: PublicKey.default,
    serumAsks: PublicKey.default,
    serumEventQueue: PublicKey.default,
    serumBaseVault: PublicKey.default,
    serumQuoteVault: PublicKey.default,
    serumVaultSignerNonce: 0,
  },
  "SOL-USD1": {
    // Placeholder - Use Dynamic Keys
    poolId: new PublicKey("FaDoeere161VKUFqcrQEM8it6kSCHKrLyq7wWyPvBkPq"),
    baseMint: WSOL_MINT,
    quoteMint: USD1_MINT,
    baseDecimals: 9,
    quoteDecimals: 6,
    ammOpenOrders: PublicKey.default,
    ammTargetOrders: PublicKey.default,
    ammBaseVault: PublicKey.default,
    ammQuoteVault: PublicKey.default,
    serumMarket: PublicKey.default,
    serumBids: PublicKey.default,
    serumAsks: PublicKey.default,
    serumEventQueue: PublicKey.default,
    serumBaseVault: PublicKey.default,
    serumQuoteVault: PublicKey.default,
    serumVaultSignerNonce: 0,
  },
  "SOL-USDT": {
    poolId: new PublicKey("7XawhbbxtsRcQA8KTkHT9f9nc6d69UwqCDh6U5EEbEmX"),
    baseMint: WSOL_MINT,
    quoteMint: USDT_MINT,
    baseDecimals: 9,
    quoteDecimals: 6,
    ammOpenOrders: new PublicKey(
      "3oWQRLewGsUMA2pebcpGPPGrzyRNfbs7fQEMUxPAGgff",
    ),
    ammTargetOrders: new PublicKey(
      "9x4knb3nuNAzxsV7YFuGLgnYqKArGemY54r2vFExM1dp",
    ),
    ammBaseVault: new PublicKey("876Z9waBygfzUrwwKFfnRcc7cfY4EQf6Kz1w7GRgbVYW"),
    ammQuoteVault: new PublicKey(
      "CB86HtaqpXbNWbq67L18y5x2RhqoJ6smb7xHUcyWdQAQ",
    ),
    serumMarket: new PublicKey("2AdaV97p6SfkuMQJdu8DHhBhmJe7oWdvbm52MJfYQmfA"),
    serumBids: new PublicKey("F4LnU7SarP7nLmGPnDHxnCqZ8gRwiFRgbo5seifyicfo"),
    serumAsks: new PublicKey("BKgZNz8tqJFoZ9gEHKR6k33wBMeXKAaSWpW5zMhSRhr3"),
    serumEventQueue: new PublicKey(
      "9zw6ztEpHfcKccahzTKgPkQNYhJMPwL4iJJc8BAztNYY",
    ),
    serumBaseVault: new PublicKey(
      "4zVFCGJVQhSvsJ625qTH4WKgvfPQpNpAVUfjpgCxbKh8",
    ),
    serumQuoteVault: new PublicKey(
      "9aoqhYjXBqWsTVCEjwtxrotx6sVPGVLmbpVSpSRzTv54",
    ),
    serumVaultSignerNonce: 0,
  },
};

/**
 * Get pool configuration by name
 */
export function getPoolConfig(poolName: PoolName): AmmV4PoolConfig {
  const config = AMM_V4_POOLS[poolName];
  if (!config) {
    throw new Error(`Unknown pool: ${poolName}`);
  }
  return config;
}

/**
 * Get pool configuration by token pair (finds the pool that matches the tokens)
 */
export function getPoolByTokens(
  tokenA: PublicKey,
  tokenB: PublicKey,
): AmmV4PoolConfig | null {
  for (const config of Object.values(AMM_V4_POOLS)) {
    if (
      (config.baseMint.equals(tokenA) && config.quoteMint.equals(tokenB)) ||
      (config.baseMint.equals(tokenB) && config.quoteMint.equals(tokenA))
    ) {
      return config;
    }
  }
  return null;
}

/**
 * Build AMM V4 swap instruction data
 * Format: [instruction_id (1 byte), amount_in (8 bytes LE), min_amount_out (8 bytes LE)]
 */
export function buildAmmSwapData(
  amountIn: anchor.BN,
  minAmountOut: anchor.BN,
): Buffer {
  const data = Buffer.alloc(17);
  data.writeUInt8(AMM_SWAP_BASE_IN_DISCRIMINATOR, 0);
  data.writeBigUInt64LE(BigInt(amountIn.toString()), 1);
  data.writeBigUInt64LE(BigInt(minAmountOut.toString()), 9);
  return data;
}

/**
 * Derive Serum Vault Signer PDA
 * The vault signer is derived from the market with nonce
 */
export function deriveSerumVaultSigner(
  marketId: PublicKey,
  nonce: anchor.BN,
): PublicKey {
  const seeds = [marketId.toBuffer()];

  // Try to find the PDA with the given nonce
  for (let i = 0; i < 256; i++) {
    try {
      const [pda] = PublicKey.findProgramAddressSync(
        [...seeds, Buffer.from([i])],
        SERUM_PROGRAM,
      );
      return pda;
    } catch {
      continue;
    }
  }

  // Fallback: use createProgramAddress directly with nonce
  return PublicKey.createProgramAddressSync(
    [...seeds, nonce.toArrayLike(Buffer, "le", 8)],
    SERUM_PROGRAM,
  );
}

/**
 * Get the vault signer for a specific pool
 */
export function getSerumVaultSigner(poolName: PoolName): PublicKey {
  const config = getPoolConfig(poolName);
  return deriveSerumVaultSigner(
    config.serumMarket,
    new anchor.BN(config.serumVaultSignerNonce),
  );
}

/**
 * Determine if swapping from base to quote or quote to base
 */
export function isBaseToQuote(
  poolConfig: AmmV4PoolConfig,
  inputMint: PublicKey,
): boolean {
  return poolConfig.baseMint.equals(inputMint);
}

/**
 * Get the input and output vaults based on swap direction
 */
export function getSwapVaults(
  poolConfig: AmmV4PoolConfig,
  inputMint: PublicKey,
): { inputVault: PublicKey; outputVault: PublicKey } {
  if (isBaseToQuote(poolConfig, inputMint)) {
    return {
      inputVault: poolConfig.ammBaseVault,
      outputVault: poolConfig.ammQuoteVault,
    };
  } else {
    return {
      inputVault: poolConfig.ammQuoteVault,
      outputVault: poolConfig.ammBaseVault,
    };
  }
}

/**
 * Get Serum vaults based on swap direction
 */
export function getSerumSwapVaults(
  poolConfig: AmmV4PoolConfig,
  inputMint: PublicKey,
): { inputVault: PublicKey; outputVault: PublicKey } {
  if (isBaseToQuote(poolConfig, inputMint)) {
    return {
      inputVault: poolConfig.serumBaseVault,
      outputVault: poolConfig.serumQuoteVault,
    };
  } else {
    return {
      inputVault: poolConfig.serumQuoteVault,
      outputVault: poolConfig.serumBaseVault,
    };
  }
}

/**
 * Get output mint based on input mint
 */
export function getOutputMint(
  poolConfig: AmmV4PoolConfig,
  inputMint: PublicKey,
): PublicKey {
  if (poolConfig.baseMint.equals(inputMint)) {
    return poolConfig.quoteMint;
  } else if (poolConfig.quoteMint.equals(inputMint)) {
    return poolConfig.baseMint;
  }
  throw new Error("Input mint not found in pool");
}

/**
 * Get token decimals for a mint in a pool
 */
export function getTokenDecimals(
  poolConfig: AmmV4PoolConfig,
  mint: PublicKey,
): number {
  if (poolConfig.baseMint.equals(mint)) {
    return poolConfig.baseDecimals;
  } else if (poolConfig.quoteMint.equals(mint)) {
    return poolConfig.quoteDecimals;
  }
  throw new Error("Mint not found in pool");
}

/**
 * Log pool configuration for debugging
 */
export function logPoolConfig(poolName: PoolName): void {
  const config = getPoolConfig(poolName);
  console.log(`\n${poolName} AMM V4 Pool Configuration:`);
  console.log(`  Pool ID: ${config.poolId.toString()}`);
  console.log(`  Base Mint: ${config.baseMint.toString()}`);
  console.log(`  Quote Mint: ${config.quoteMint.toString()}`);
  console.log(`  AMM Open Orders: ${config.ammOpenOrders.toString()}`);
  console.log(`  AMM Target Orders: ${config.ammTargetOrders.toString()}`);
  console.log(`  AMM Base Vault: ${config.ammBaseVault.toString()}`);
  console.log(`  AMM Quote Vault: ${config.ammQuoteVault.toString()}`);
  console.log(`  Serum Market: ${config.serumMarket.toString()}`);
  console.log(`  Serum Vault Signer Nonce: ${config.serumVaultSignerNonce}`);
}

// ============================================================================
// DYNAMIC POOL KEY FETCHING (using Raydium SDK)
// ============================================================================

/**
 * Get token decimals from mint address
 */
export async function fetchTokenDecimals(
  connection: Connection,
  mintAddress: PublicKey,
): Promise<number> {
  const mintStr = mintAddress.toBase58();

  // Check cache first
  if (decimalCache[mintStr] !== undefined) {
    return decimalCache[mintStr];
  }

  // Native SOL always has 9 decimals
  if (mintAddress.equals(NATIVE_MINT)) {
    decimalCache[mintStr] = 9;
    return 9;
  }

  try {
    const mintInfo = await getMint(connection, mintAddress);
    decimalCache[mintStr] = mintInfo.decimals;
    return mintInfo.decimals;
  } catch (error) {
    console.error(`Error fetching decimals for ${mintStr}:`, error);
    throw error;
  }
}

/**
 * Get market ID for a token pair from known markets or by searching
 */
export function getMarketIdForPair(
  baseMint: PublicKey,
  quoteMint: PublicKey,
): PublicKey | null {
  const key = `${baseMint.toBase58()}-${quoteMint.toBase58()}`;
  const reverseKey = `${quoteMint.toBase58()}-${baseMint.toBase58()}`;

  return KNOWN_MARKETS[key] || KNOWN_MARKETS[reverseKey] || null;
}

/**
 * Fetch market data from on-chain account
 */
export async function fetchMarketData(
  connection: Connection,
  marketId: PublicKey,
): Promise<{
  marketBaseVault: PublicKey;
  marketQuoteVault: PublicKey;
  marketBids: PublicKey;
  marketAsks: PublicKey;
  marketEventQueue: PublicKey;
}> {
  const marketIdStr = marketId.toBase58();

  // Check cache
  if (marketDataCache[marketIdStr]) {
    const info = marketDataCache[marketIdStr];
    return {
      marketBaseVault: new PublicKey(info.baseVault),
      marketQuoteVault: new PublicKey(info.quoteVault),
      marketBids: new PublicKey(info.bids),
      marketAsks: new PublicKey(info.asks),
      marketEventQueue: new PublicKey(info.eventQueue),
    };
  }

  // Fetch from chain
  const marketAccount = await connection.getAccountInfo(marketId);
  if (!marketAccount) {
    throw new Error(`Market account not found: ${marketIdStr}`);
  }

  const marketInfo = MARKET_STATE_LAYOUT_V3.decode(marketAccount.data);
  marketDataCache[marketIdStr] = marketInfo;

  return {
    marketBaseVault: new PublicKey(marketInfo.baseVault),
    marketQuoteVault: new PublicKey(marketInfo.quoteVault),
    marketBids: new PublicKey(marketInfo.bids),
    marketAsks: new PublicKey(marketInfo.asks),
    marketEventQueue: new PublicKey(marketInfo.eventQueue),
  };
}

/**
 * Fetch actual pool info from Raydium API for a token pair
 * This returns real pool data, not derived PDAs
 */
export async function fetchPoolFromRaydiumApi(
  baseMint: PublicKey,
  quoteMint: PublicKey,
): Promise<any | null> {
  const cacheKey = `${baseMint.toBase58()}-${quoteMint.toBase58()}`;

  // Check cache
  if (apiPoolCache[cacheKey]) {
    return apiPoolCache[cacheKey];
  }

  try {
    // Query Raydium API for AMM V4 pools with these mints
    const url = `${RAYDIUM_API_URL}/pools/info/mint?mint1=${baseMint.toBase58()}&mint2=${quoteMint.toBase58()}&poolType=standard&poolSortField=default&sortType=desc&pageSize=10&page=1`;
    console.log(`Fetching pool from Raydium API: ${url}`);

    // Use axios for better compatibility
    const response = await axios.get(url);
    const data = response.data;

    if (!data.success || !data.data?.data?.length) {
      console.log("No pools found in API response");
      return null;
    }

    // Find AMM V4 pool (programId matches Raydium AMM V4)
    const ammV4Pool = data.data.data.find(
      (pool: any) => pool.programId === RAYDIUM_AMM_V4_PROGRAM.toBase58(),
    );

    if (ammV4Pool) {
      console.log(`Found AMM V4 pool: ${ammV4Pool.id}`);
      apiPoolCache[cacheKey] = ammV4Pool;
      return ammV4Pool;
    }

    console.log("No AMM V4 pool found in API response");
    return null;
  } catch (error: any) {
    if (axios.isAxiosError(error)) {
      console.error("Error fetching from Raydium API:", error.message);
    } else {
      console.error("Error fetching from Raydium API:", error);
    }
    return null;
  }
}

/**
 * Fetch and decode on-chain pool state to get full pool keys
 */
export async function fetchPoolKeysFromOnChain(
  connection: Connection,
  poolId: PublicKey,
  baseMint: PublicKey,
  quoteMint: PublicKey,
): Promise<LiquidityPoolKeysV4> {
  const accountInfo = await connection.getAccountInfo(poolId);
  if (!accountInfo) {
    throw new Error(`Pool account not found: ${poolId.toBase58()}`);
  }

  const poolState = LIQUIDITY_STATE_LAYOUT_V4.decode(accountInfo.data);

  return {
    id: poolId,
    baseMint: poolState.baseMint,
    quoteMint: poolState.quoteMint,
    lpMint: poolState.lpMint,
    baseDecimals: poolState.baseDecimal.toNumber(),
    quoteDecimals: poolState.quoteDecimal.toNumber(),
    lpDecimals: poolState.baseDecimal.toNumber(), // Usually same or derived
    version: 4,
    programId: accountInfo.owner,
    authority: AMM_AUTHORITY,
    openOrders: poolState.openOrders,
    targetOrders: poolState.targetOrders,
    baseVault: poolState.baseVault,
    quoteVault: poolState.quoteVault,
    marketVersion: 3,
    marketProgramId: poolState.marketProgramId,
    marketId: poolState.marketId,
    marketAuthority: PublicKey.default, // Filled later if needed
    marketBaseVault: PublicKey.default, // Filled later
    marketQuoteVault: PublicKey.default, // Filled later
    marketBids: PublicKey.default, // Filled later
    marketAsks: PublicKey.default, // Filled later
    marketEventQueue: PublicKey.default, // Filled later
    withdrawQueue: poolState.withdrawQueue,
    lpVault: poolState.lpVault,
    lookupTableAccount: PublicKey.default,
  };
}

/**
 * Dynamically fetch real pool keys from Raydium API
 * Falls back to SDK derivation if API fails
 */
export async function getPoolKeysFromMints(
  connection: Connection,
  inputMint: PublicKey,
  outputMint: PublicKey,
): Promise<LiquidityPoolKeysV4> {
  // Determine base/quote order (WSOL is usually base when paired with stables)
  const inputIsSol =
    inputMint.equals(NATIVE_MINT) || inputMint.equals(WSOL_MINT);
  const baseMint = inputIsSol ? inputMint : outputMint;
  const quoteMint = inputIsSol ? outputMint : inputMint;

  const cacheKey = `${baseMint.toBase58()}-${quoteMint.toBase58()}`;

  // Check cache
  if (poolKeysCache[cacheKey]) {
    return poolKeysCache[cacheKey];
  }

  // Try to fetch real pool from Raydium API first
  const apiPool = await fetchPoolFromRaydiumApi(baseMint, quoteMint);

  if (apiPool) {
    console.log("✅ Using real pool data from Raydium API");
    const poolId = new PublicKey(apiPool.id);

    // Fetch and decode on-chain state to get full keys
    try {
      const poolKeys = await fetchPoolKeysFromOnChain(
        connection,
        poolId,
        baseMint,
        quoteMint,
      );

      // Fetch market data to fill in missing market fields
      try {
        const marketData = await fetchMarketData(connection, poolKeys.marketId);
        poolKeys.marketBaseVault = marketData.marketBaseVault;
        poolKeys.marketQuoteVault = marketData.marketQuoteVault;
        poolKeys.marketBids = marketData.marketBids;
        poolKeys.marketAsks = marketData.marketAsks;
        poolKeys.marketEventQueue = marketData.marketEventQueue;
        // Derive market authority
        // poolKeys.marketAuthority = ... (optional)
      } catch (e) {
        console.log("Could not fetch market data");
      }

      poolKeysCache[cacheKey] = poolKeys;
      return poolKeys;
    } catch (e) {
      console.error("Error fetching on-chain pool state:", e);
      // Fallback to SDK derivation if on-chain fetch fails?
    }
  }

  // Fallback: Get decimals and use SDK derivation
  console.log("⚠️ Falling back to SDK derivation (pool may not exist)");
  const baseDecimals = await fetchTokenDecimals(connection, baseMint);
  const quoteDecimals = await fetchTokenDecimals(connection, quoteMint);

  // Get market ID
  const marketId = getMarketIdForPair(baseMint, quoteMint);
  if (!marketId) {
    throw new Error(
      `No market found for pair: ${baseMint.toBase58()} / ${quoteMint.toBase58()}`,
    );
  }

  // Create Token objects
  const baseToken = new Token(TOKEN_PROGRAM_ID, baseMint, baseDecimals);
  const quoteToken = new Token(TOKEN_PROGRAM_ID, quoteMint, quoteDecimals);

  // Get associated pool keys using Raydium SDK
  const associatedPoolKeys = Liquidity.getAssociatedPoolKeys({
    version: 4,
    marketVersion: 3,
    baseMint: baseToken.mint,
    quoteMint: quoteToken.mint,
    baseDecimals: baseToken.decimals,
    quoteDecimals: quoteToken.decimals,
    marketId,
    programId: MAINNET_PROGRAM_ID.AmmV4,
    marketProgramId: MAINNET_PROGRAM_ID.OPENBOOK_MARKET,
  });

  // Fetch market data for serum accounts
  const marketData = await fetchMarketData(connection, marketId);

  // Combine into full pool keys
  const poolKeys: LiquidityPoolKeysV4 = {
    ...associatedPoolKeys,
    ...marketData,
  };

  // Cache and return
  poolKeysCache[cacheKey] = poolKeys;
  return poolKeys;
}

/**
 * Convert LiquidityPoolKeysV4 to AmmV4PoolConfig format
 * Useful for compatibility with existing code
 */
export function poolKeysToConfig(
  poolKeys: LiquidityPoolKeysV4,
): AmmV4PoolConfig {
  return {
    poolId: poolKeys.id,
    baseMint: poolKeys.baseMint,
    quoteMint: poolKeys.quoteMint,
    baseDecimals: poolKeys.baseDecimals,
    quoteDecimals: poolKeys.quoteDecimals,
    ammOpenOrders: poolKeys.openOrders,
    ammTargetOrders: poolKeys.targetOrders,
    ammBaseVault: poolKeys.baseVault,
    ammQuoteVault: poolKeys.quoteVault,
    serumMarket: poolKeys.marketId,
    serumBids: poolKeys.marketBids,
    serumAsks: poolKeys.marketAsks,
    serumEventQueue: poolKeys.marketEventQueue,
    serumBaseVault: poolKeys.marketBaseVault,
    serumQuoteVault: poolKeys.marketQuoteVault,
    serumVaultSignerNonce: (poolKeys as any).nonce ?? 0,
  };
}

/**
 * Get pool configuration dynamically from input/output mints
 * This is the main entry point for dynamic pool lookup
 */
export async function getPoolConfigFromMints(
  connection: Connection,
  inputMint: PublicKey,
  outputMint: PublicKey,
): Promise<AmmV4PoolConfig> {
  const poolKeys = await getPoolKeysFromMints(
    connection,
    inputMint,
    outputMint,
  );
  return poolKeysToConfig(poolKeys);
}

/**
 * Add a new market to the known markets registry
 * Use this to support new token pairs
 */
export function registerMarket(
  baseMint: PublicKey,
  quoteMint: PublicKey,
  marketId: PublicKey,
): void {
  const key = `${baseMint.toBase58()}-${quoteMint.toBase58()}`;
  KNOWN_MARKETS[key] = marketId;
}

/**
 * Log dynamic pool keys for debugging
 */
export function logPoolKeys(poolKeys: LiquidityPoolKeysV4): void {
  console.log("\nPool Keys (Dynamic):");
  console.log(`  Pool ID: ${poolKeys.id.toBase58()}`);
  console.log(`  Base Mint: ${poolKeys.baseMint.toBase58()}`);
  console.log(`  Quote Mint: ${poolKeys.quoteMint.toBase58()}`);
  console.log(`  Open Orders: ${poolKeys.openOrders.toBase58()}`);
  console.log(`  Target Orders: ${poolKeys.targetOrders.toBase58()}`);
  console.log(`  Base Vault: ${poolKeys.baseVault.toBase58()}`);
  console.log(`  Quote Vault: ${poolKeys.quoteVault.toBase58()}`);
  console.log(`  Market ID: ${poolKeys.marketId.toBase58()}`);
  console.log(`  Market Bids: ${poolKeys.marketBids.toBase58()}`);
  console.log(`  Market Asks: ${poolKeys.marketAsks.toBase58()}`);
  console.log(`  Market Event Queue: ${poolKeys.marketEventQueue.toBase58()}`);
  console.log(`  Market Base Vault: ${poolKeys.marketBaseVault.toBase58()}`);
  console.log(`  Market Quote Vault: ${poolKeys.marketQuoteVault.toBase58()}`);
  console.log(`  Nonce: ${(poolKeys as any).nonce ?? "N/A"}`);
}

// ============================================================================
// RaydiumPoolKeysFetcher CLASS (for input/output mint approach)
// ============================================================================

export type LiquidityPairTargetInfo = {
  baseToken: Token;
  quoteToken: Token;
  targetMarketId: PublicKey;
};

/**
 * Fetch market-associated pool keys using Raydium SDK
 */
export async function getMarketAssociatedPoolKeys(
  connection: Connection,
  input: LiquidityPairTargetInfo,
): Promise<LiquidityPoolKeysV4> {
  const marketIdString = input.targetMarketId.toBase58();

  if (!marketDataCache[marketIdString]) {
    console.log("Fetching market data for", marketIdString);
    const marketAccount = await connection.getAccountInfo(input.targetMarketId);
    if (!marketAccount) throw new Error("get market info error");
    marketDataCache[marketIdString] = MARKET_STATE_LAYOUT_V3.decode(
      marketAccount.data,
    );
  }

  const marketInfo = marketDataCache[marketIdString];
  const ensurePub = (k: string | PublicKey) =>
    typeof k === "string" ? new PublicKey(k) : k;

  const marketData = {
    marketBaseVault: ensurePub(marketInfo.baseVault),
    marketQuoteVault: ensurePub(marketInfo.quoteVault),
    marketBids: ensurePub(marketInfo.bids),
    marketAsks: ensurePub(marketInfo.asks),
    marketEventQueue: ensurePub(marketInfo.eventQueue),
  };

  const associated = Liquidity.getAssociatedPoolKeys({
    version: 4,
    marketVersion: 3,
    baseMint: input.baseToken.mint,
    quoteMint: input.quoteToken.mint,
    baseDecimals: input.baseToken.decimals,
    quoteDecimals: input.quoteToken.decimals,
    marketId: input.targetMarketId,
    programId: MAINNET_PROGRAM_ID.AmmV4,
    marketProgramId: MAINNET_PROGRAM_ID.OPENBOOK_MARKET,
  });

  const result = { ...associated, ...marketData } as LiquidityPoolKeysV4;
  return result;
}

/**
 * RaydiumPoolKeysFetcher - fetches pool keys for buy/sell operations
 * Supports deriving pool keys from input/output mints dynamically
 */
export class RaydiumPoolKeysFetcher {
  private baseToken: Token;
  private quoteToken: Token;
  private marketId: PublicKey;
  private connection: Connection;

  constructor(
    connection: Connection,
    baseToken: Token,
    quoteToken: Token,
    marketId: string | PublicKey,
  ) {
    this.connection = connection;
    this.baseToken = baseToken;
    this.quoteToken = quoteToken;
    this.marketId =
      typeof marketId === "string" ? new PublicKey(marketId) : marketId;
  }

  /**
   * Get pool keys for buying (base → quote, e.g., SOL → USDC)
   * Uses getPoolKeysFromMints to leverage API lookup priority
   */
  async getMarketBuyPoolKeys(): Promise<LiquidityPoolKeysV4> {
    // Buying = swapping Base -> Quote.
    // Raydium SDK pool keys are same regardless of swap direction intent.
    // We just need the canonical pool for these two mints.
    return getPoolKeysFromMints(
      this.connection,
      this.baseToken.mint,
      this.quoteToken.mint,
    );
  }

  /**
   * Get pool keys for selling (quote → base, e.g., USDC → SOL)
   * Uses getPoolKeysFromMints to leverage API lookup priority
   */
  async getMarketSellPoolKeys(): Promise<LiquidityPoolKeysV4> {
    // Selling = swapping Quote -> Base.
    return getPoolKeysFromMints(
      this.connection,
      this.quoteToken.mint,
      this.baseToken.mint,
    );
  }
}

/**
 * Create pool keys fetcher from input/output mints
 * Automatically determines base/quote order
 */
export async function createPoolKeysFetcher(
  connection: Connection,
  inputMint: PublicKey,
  outputMint: PublicKey,
): Promise<RaydiumPoolKeysFetcher> {
  // Determine base/quote order (SOL is usually base)
  const inputIsSol =
    inputMint.equals(NATIVE_MINT) || inputMint.equals(WSOL_MINT);
  const baseMint = inputIsSol ? inputMint : outputMint;
  const quoteMint = inputIsSol ? outputMint : inputMint;

  // Get decimals
  const baseDecimals = await fetchTokenDecimals(connection, baseMint);
  const quoteDecimals = await fetchTokenDecimals(connection, quoteMint);

  // Create tokens
  const baseToken = new Token(TOKEN_PROGRAM_ID, baseMint, baseDecimals);
  const quoteToken = new Token(TOKEN_PROGRAM_ID, quoteMint, quoteDecimals);

  // Get market ID
  const marketId = getMarketIdForPair(baseMint, quoteMint);
  if (!marketId) {
    throw new Error(
      `No market found for pair: ${baseMint.toBase58()} / ${quoteMint.toBase58()}`,
    );
  }

  return new RaydiumPoolKeysFetcher(
    connection,
    baseToken,
    quoteToken,
    marketId,
  );
}

/**
 * Helper to get pool keys directly from input/output mints with swap direction
 */
export async function getPoolKeysForSwap(
  connection: Connection,
  inputMint: PublicKey,
  outputMint: PublicKey,
): Promise<{
  poolKeys: LiquidityPoolKeysV4;
  isBuy: boolean;
}> {
  const inputIsSol =
    inputMint.equals(NATIVE_MINT) || inputMint.equals(WSOL_MINT);
  const fetcher = await createPoolKeysFetcher(
    connection,
    inputMint,
    outputMint,
  );

  // If input is SOL, we're buying (SOL → token)
  // If input is not SOL, we're selling (token → SOL)
  const isBuy = inputIsSol;
  const poolKeys = isBuy
    ? await fetcher.getMarketBuyPoolKeys()
    : await fetcher.getMarketSellPoolKeys();

  return { poolKeys, isBuy };
}

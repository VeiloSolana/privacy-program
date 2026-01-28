import {
  Liquidity,
  LiquidityPoolKeysV4,
  MAINNET_PROGRAM_ID,
  MARKET_STATE_LAYOUT_V3,
  Percent,
  SPL_ACCOUNT_LAYOUT,
  Token,
  TOKEN_PROGRAM_ID,
  TokenAmount,
} from "@raydium-io/raydium-sdk";
import {
  PublicKey,
  VersionedTransaction,
  TransactionMessage,
  Connection,
  Keypair,
} from "@solana/web3.js";
import { getMint, NATIVE_MINT } from "@solana/spl-token";
import axios from "axios";
import { WSOL } from "@raydium-io/raydium-sdk";
import * as anchor from "@coral-xyz/anchor";

export const WSOL_TOKEN = WSOL;

// Helper to get connection from Anchor provider
function getConnection(): Connection {
  return anchor.getProvider().connection;
}

// Helper to get transaction version
const txVersion = 0;

function initializeOwner(privateKey: string): Keypair {
  const secretKey = new Uint8Array(Buffer.from(privateKey, "base64")); // Or whatever format
  // Just assuming Keypair from secret key here, adapt if needed.
  // Usually tests pass Keypair directly.
  // User code passed string. I'll assume standard Keypair logic if not provided.
  // Actually, for tests, we usually have a Keypair object.
  // I will adapt createSwapIx to take Keypair instead of string privateKey.
  return Keypair.fromSecretKey(secretKey);
}

export async function getMarketId(mintStr: string): Promise<string | null> {
  const url = `https://api-v3.raydium.io/pools/info/mint?mint1=${mintStr}&mint2=${WSOL.mint}&poolType=all&poolSortField=default&sortType=desc&pageSize=1&page=1`;

  try {
    const { data } = await axios.get(url);
    return data.data.data[0]?.marketId;
  } catch (error) {
    console.error("Error fetching market ID:", error);
    return null;
  }
}

export interface TokenAccount {
  programId: PublicKey;
  pubkey: PublicKey;
  accountInfo: any;
}

// Global cache for token decimals to persist across instances
const globalDecimalCache: Record<string, number> = {};

// Global cache for market data
const marketDataCache: Record<string, any> = {};

// ==========================================
// RaydiumPoolKeysFetcher
// ==========================================

export class RaydiumPoolKeysFetcher {
  constructor(
    private mintToken: Token,
    private WSOL: Token,
    private marketId: string,
    private connection: Connection,
  ) {}

  async getMarketSellPoolKeys(): Promise<LiquidityPoolKeysV4> {
    return (await getMarketAssociatedPoolKeys({
      baseToken: this.mintToken,
      quoteToken: this.WSOL,
      targetMarketId: new PublicKey(this.marketId),
      connection: this.connection,
    })) as LiquidityPoolKeysV4;
  }

  async getMarketBuyPoolKeys(): Promise<LiquidityPoolKeysV4> {
    return (await getMarketAssociatedPoolKeys({
      baseToken: this.WSOL,
      quoteToken: this.mintToken,
      targetMarketId: new PublicKey(this.marketId),
      connection: this.connection,
    })) as LiquidityPoolKeysV4;
  }
}

// ==========================================
// RaydiumService (Swap Instruction)
// ==========================================

export class RaydiumSwapInstruction {
  private decimalCache: Record<string, number> = {};
  private connection: Connection;

  constructor(connection?: Connection) {
    this.connection = connection || getConnection();
  }

  async createSwapIx(
    inputMint: string,
    outputMint: string,
    owner: Keypair,
    amount: number | string,
    priorityFee: number = 10000,
  ): Promise<VersionedTransaction> {
    console.log("createSwapIx started");
    const start = Date.now();

    const inputDecimals = await this.getTokenDecimals(inputMint);
    console.log("inputDecimals:", inputDecimals);
    const outputDecimals = await this.getTokenDecimals(outputMint);
    console.log("outputDecimals:", outputDecimals);

    const inputIsSol = inputMint === NATIVE_MINT.toBase58();
    const tokenMintPk = new PublicKey(inputIsSol ? outputMint : inputMint);
    const tokenDecimals = inputIsSol ? outputDecimals : inputDecimals;
    // const owner = initializeOwner(privateKey); // Use passed Keypair

    // const marketIdStr = await getMarketId(tokenMintPk.toBase58())
    const marketIdStr = await getMarketId(tokenMintPk.toBase58());
    console.log("marketId:", marketIdStr);
    if (!marketIdStr) throw new Error("Market ID not found");

    const toSmallestUnit = (amt: number | string, dec: number): bigint => {
      const [w, f = ""] = amt.toString().split(".");
      const frac = (f || "").padEnd(dec, "0").slice(0, dec);
      return BigInt(w) * BigInt(10) ** BigInt(dec) + BigInt(frac);
    };
    const scaledAmount = toSmallestUnit(amount, inputDecimals);
    console.log("scaledAmount:", scaledAmount.toString());

    const mintToken = new Token(TOKEN_PROGRAM_ID, tokenMintPk, tokenDecimals);
    const WSOL_TOKEN_OBJ = new Token(TOKEN_PROGRAM_ID, NATIVE_MINT, 9);

    const amountIn = new TokenAmount(
      inputIsSol ? WSOL_TOKEN_OBJ : mintToken,
      scaledAmount,
    );

    const rayiumPool = new RaydiumPoolKeysFetcher(
      mintToken,
      WSOL_TOKEN_OBJ,
      marketIdStr,
      this.connection,
    );

    console.log({ inputIsSol });
    const poolKeys = inputIsSol
      ? ((await rayiumPool.getMarketBuyPoolKeys()) as unknown as LiquidityPoolKeysV4)
      : ((await rayiumPool.getMarketSellPoolKeys()) as unknown as LiquidityPoolKeysV4);

    // console.log("poolKeys:", poolKeys)
    console.log("poolKeys fetched");

    // In test environment, these should implicitly exist or be created by other helpers,
    // but we can try to find them.
    // For off-chain generation, we just need the addresses.
    const { tokenAccounts } = await this.getWalletTokenAccounts(
      owner.publicKey,
    );
    const wsolAccount = tokenAccounts.find((ta) =>
      ta.accountInfo.mint.equals(NATIVE_MINT),
    );
    const tokenAccount = tokenAccounts.find((ta) =>
      ta.accountInfo.mint.equals(tokenMintPk),
    );

    console.log("Token account fetched");

    const poolInfo = await Liquidity.fetchInfo({
      connection: this.connection,
      poolKeys,
    });
    console.log("Pool Info fetched");

    const slippageTolerance = new Percent(5, 1000);
    const { amountOut, minAmountOut } = Liquidity.computeAmountOut({
      poolKeys,
      poolInfo,
      amountIn,
      currencyOut: inputIsSol ? mintToken : WSOL_TOKEN_OBJ,
      slippage: slippageTolerance,
    });

    const computeBudgetConfig = {
      microLamports: priorityFee,
      units: 600000,
    };

    // We assume accounts exist for now (or handling it elsewhere).
    // Simplification: just pick first available or null if not found (SDK might complain).
    // In privacy pool tests, the relayer calls this, and relayer has token accounts.

    const swapIxResponse = await Liquidity.makeSwapInstructionSimple({
      connection: this.connection,
      poolKeys,
      userKeys: {
        tokenAccounts: tokenAccounts.map((ta) => ta.pubkey), // Pass all token accounts
        owner: owner.publicKey,
        payer: owner.publicKey,
      },
      amountIn,
      amountOut: minAmountOut,
      fixedSide: "in",
      makeTxVersion: txVersion,
      computeBudgetConfig,
    });
    // console.log("swapIxResponse:", swapIxResponse)

    const instructions = [...swapIxResponse.innerTransactions[0].instructions];
    const { blockhash } = await this.connection.getLatestBlockhash("processed");
    const messageV0 = new TransactionMessage({
      payerKey: owner.publicKey,
      recentBlockhash: blockhash,
      instructions,
    }).compileToV0Message();

    const tx = new VersionedTransaction(messageV0);
    tx.sign([owner]);

    // console.log("tx signed:", tx)
    console.log("createSwapIx total time:", `${Date.now() - start}ms`);

    return tx;
  }

  async getPoolKeys(
    inputMint: string,
    outputMint: string,
  ): Promise<liquidityPoolKeysV4> {
    const inputIsSol = inputMint === NATIVE_MINT.toBase58();
    const tokenMintPk = new PublicKey(inputIsSol ? outputMint : inputMint);
    const outputDecimals = await this.getTokenDecimals(outputMint);
    const inputDecimals = await this.getTokenDecimals(inputMint);
    const tokenDecimals = inputIsSol ? outputDecimals : inputDecimals;

    const marketIdStr = await getMarketId(tokenMintPk.toBase58());
    if (!marketIdStr) throw new Error("Market ID not found");

    const mintToken = new Token(TOKEN_PROGRAM_ID, tokenMintPk, tokenDecimals);
    const WSOL_TOKEN_OBJ = new Token(TOKEN_PROGRAM_ID, NATIVE_MINT, 9);

    const rayiumPool = new RaydiumPoolKeysFetcher(
      mintToken,
      WSOL_TOKEN_OBJ,
      marketIdStr,
      this.connection,
    );

    return inputIsSol
      ? ((await rayiumPool.getMarketBuyPoolKeys()) as unknown as LiquidityPoolKeysV4)
      : ((await rayiumPool.getMarketSellPoolKeys()) as unknown as LiquidityPoolKeysV4);
  }

  async getTokenDecimals(mintAddress: string): Promise<number> {
    // Check global cache first
    if (globalDecimalCache[mintAddress] !== undefined) {
      return globalDecimalCache[mintAddress];
    }

    // Fall back to instance cache
    if (this.decimalCache[mintAddress] !== undefined) {
      // Update global cache from instance cache
      globalDecimalCache[mintAddress] = this.decimalCache[mintAddress];
      return this.decimalCache[mintAddress];
    }

    // Native SOL always has 9 decimals
    if (mintAddress === NATIVE_MINT.toBase58()) {
      globalDecimalCache[mintAddress] = 9;
      this.decimalCache[mintAddress] = 9;
      return 9;
    }

    try {
      const mintInfo = await getMint(
        this.connection,
        new PublicKey(mintAddress),
      );
      globalDecimalCache[mintAddress] = mintInfo.decimals;
      this.decimalCache[mintAddress] = mintInfo.decimals;
      return mintInfo.decimals;
    } catch (error) {
      console.error(`Error fetching decimals for ${mintAddress}:`, error);
      throw error;
    }
  }

  async getWalletTokenAccounts(ownerPk: PublicKey) {
    const response = await this.connection.getTokenAccountsByOwner(ownerPk, {
      programId: TOKEN_PROGRAM_ID,
    });
    const tokenAccounts = response.value.map((ta) => {
      const accountInfo = SPL_ACCOUNT_LAYOUT.decode(ta.account.data);

      return {
        pubkey: ta.pubkey,
        programId: TOKEN_PROGRAM_ID,
        accountInfo,
      };
    });
    return { tokenAccounts };
  }
}

export type LiquidityPairTargetInfo = {
  baseToken: Token;
  quoteToken: Token;
  targetMarketId: PublicKey;
  connection: Connection;
};

export async function getMarketAssociatedPoolKeys(
  input: LiquidityPairTargetInfo,
) {
  const marketIdString = input.targetMarketId.toBase58();

  if (!marketDataCache[marketIdString]) {
    console.log("Fetching market data for", marketIdString);
    const marketAccount = await input.connection.getAccountInfo(
      input.targetMarketId,
    );
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

  const result = { ...associated, ...marketData };
  return result;
}

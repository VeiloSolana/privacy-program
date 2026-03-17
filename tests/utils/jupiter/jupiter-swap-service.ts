import { Connection, PublicKey, AccountMeta } from "@solana/web3.js";

export const JUPITER_PROGRAM_ID = new PublicKey(
  "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
);
export const JUPITER_EVENT_AUTHORITY = new PublicKey(
  "D8cy77BBepLMngZx6ZukaTff5hCt1HrWyKk3Hnd9oitf",
);

// Jupiter "route" instruction discriminator
export const JUPITER_ROUTE_DISCRIMINATOR = Buffer.from([
  0xe5, 0x17, 0xcb, 0x97, 0x7a, 0xe3, 0xad, 0x2a,
]);

interface QuoteResponse {
  inputMint: string;
  outputMint: string;
  inAmount: string;
  outAmount: string;
  otherAmountThreshold: string;
  swapMode: string;
  slippageBps: number;
  priceImpactPct: string;
  routePlan: any[];
}

interface SwapInstructionsResponse {
  tokenLedgerInstruction: any;
  computeBudgetInstructions: any[];
  setupInstructions: any[];
  swapInstruction: any;
  cleanupInstruction: any;
  addressLookupTableAddresses: string[];
}

export class JupiterSwapService {
  private connection: Connection;
  private apiUrl: string = "https://lite-api.jup.ag/swap/v1";

  constructor(connection: Connection) {
    this.connection = connection;
  }

  /**
   * Get quote from Jupiter API
   */
  async getQuote(
    inputMint: PublicKey,
    outputMint: PublicKey,
    amount: number,
    slippageBps: number = 50,
  ): Promise<QuoteResponse> {
    const params = new URLSearchParams({
      inputMint: inputMint.toString(),
      outputMint: outputMint.toString(),
      amount: amount.toString(),
      slippageBps: slippageBps.toString(),
      onlyDirectRoutes: "true", // Simple routes only (no ALTs)
      dexes: "Raydium,Raydium CPMM,Raydium Clmm", // Include Raydium AMM V4, CPMM, and CLMM pools
    });

    const response = await fetch(`${this.apiUrl}/quote?${params}`);
    if (!response.ok) {
      throw new Error(`Jupiter quote failed: ${response.statusText}`);
    }

    return await response.json();
  }

  /**
   * Get swap instruction from Jupiter API
   */
  async getSwapInstruction(
    quote: QuoteResponse,
    userPublicKey: PublicKey,
    wrapUnwrapSOL: boolean = true,
  ): Promise<SwapInstructionsResponse> {
    const response = await fetch(`${this.apiUrl}/swap-instructions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        quoteResponse: quote,
        userPublicKey: userPublicKey.toString(),
        wrapAndUnwrapSol: wrapUnwrapSOL,
        dynamicComputeUnitLimit: true,
        prioritizationFeeLamports: "auto",
      }),
    });

    if (!response.ok) {
      throw new Error(
        `Jupiter swap instruction failed: ${response.statusText}`,
      );
    }

    return await response.json();
  }

  /**
   * Extract remaining_accounts for privacy pool CPI
   * Returns ALL Jupiter instruction accounts
   * Jupiter needs complete account structure to route properly to underlying DEXs
   */
  extractRemainingAccounts(swapInstruction: any): AccountMeta[] {
    const accounts = swapInstruction.accounts;
    const remainingAccounts: AccountMeta[] = [];

    // Pass ALL Jupiter accounts - Jupiter will handle its own account structure
    for (let i = 0; i < accounts.length; i++) {
      remainingAccounts.push({
        pubkey: new PublicKey(accounts[i].pubkey),
        isWritable: accounts[i].isWritable,
        isSigner: false, // All signing handled by program via invoke_signed
      });
    }

    return remainingAccounts;
  }

  /**
   * Build swap_data for transact_swap
   * Format: discriminator (8 bytes) + serialized parameters
   */
  buildSwapData(swapInstruction: any): Buffer {
    // Jupiter API returns base64 encoded instruction data
    const instructionData = Buffer.from(swapInstruction.data, "base64");

    // Data already includes discriminator + route_plan + params
    return instructionData;
  }

  /**
   * Helper: Parse route plan for debugging
   */
  parseRoutePlan(quote: QuoteResponse): string {
    return quote.routePlan
      .map((step, i) => {
        const swapInfo = step.swapInfo;
        return `Step ${i + 1}: ${swapInfo.label} (${swapInfo.inputMint.slice(
          0,
          8,
        )}...→${swapInfo.outputMint.slice(0, 8)}...)`;
      })
      .join(" → ");
  }
}

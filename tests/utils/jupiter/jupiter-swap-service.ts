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
   * Jupiter Ultra order (Metis router) — reaches long-tail/multi-hop tokens (e.g. un-migrated
   * Raydium LaunchLab) that the swap/v1 instructions API returns "not tradable" for. Returns a full
   * `transaction` (base64) built for `taker`; decode it with `buildJupLegsFromUltra` to run via the
   * staged-legs cosigner path. Pass the ephemeral cosigner as `taker`.
   */
  async getUltraOrder(
    inputMint: PublicKey,
    outputMint: PublicKey,
    amount: number,
    taker: PublicKey,
  ): Promise<any> {
    const ultraUrl = this.apiUrl.replace("/swap/v1", "/ultra/v1");
    const params = new URLSearchParams({
      inputMint: inputMint.toString(),
      outputMint: outputMint.toString(),
      amount: amount.toString(),
      taker: taker.toString(),
    });
    const response = await fetch(`${ultraUrl}/order?${params}`);
    if (!response.ok) {
      throw new Error(`Jupiter Ultra order failed: ${response.status} ${response.statusText}`);
    }
    const data = await response.json();
    if (data.error) throw new Error(`Jupiter Ultra order error: ${JSON.stringify(data.error)}`);
    return data;
  }

  /**
   * Get quote from Jupiter API
   */
  async getQuote(
    inputMint: PublicKey,
    outputMint: PublicKey,
    amount: number,
    slippageBps: number = 50,
    onlyDirectRoutes: boolean = false,
    dexes?: string,
    maxAccounts?: number,
  ): Promise<QuoteResponse> {
    const params = new URLSearchParams({
      inputMint: inputMint.toString(),
      outputMint: outputMint.toString(),
      amount: amount.toString(),
      slippageBps: slippageBps.toString(),
      ...(onlyDirectRoutes ? { onlyDirectRoutes: "true" } : {}),
      ...(dexes ? { dexes } : {}),
      // Multi-hop tokens (e.g. un-migrated Raydium LaunchLab) need a higher account budget or
      // Jupiter returns "not tradable" with the restrictive defaults.
      ...(maxAccounts ? { maxAccounts: maxAccounts.toString() } : {}),
    });

    const response = await fetch(`${this.apiUrl}/quote?${params}`);
    if (!response.ok) {
      const body = await response.text();
      throw new Error(`Jupiter quote failed: ${response.status} ${response.statusText} — ${body}`);
    }

    const data = await response.json();
    if (data.error) {
      throw new Error(`Jupiter quote error: ${JSON.stringify(data.error)}`);
    }
    return data;
  }

  /**
   * Get swap instruction from Jupiter API
   */
  async getSwapInstruction(
    quote: QuoteResponse,
    userPublicKey: PublicKey,
    wrapUnwrapSOL: boolean = true,
    useSharedAccounts: boolean = false,
    destinationTokenAccount?: PublicKey,
  ): Promise<SwapInstructionsResponse> {
    const response = await fetch(`${this.apiUrl}/swap-instructions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        quoteResponse: quote,
        userPublicKey: userPublicKey.toString(),
        wrapAndUnwrapSol: wrapUnwrapSOL,
        useSharedAccounts,
        ...(destinationTokenAccount ? { destinationTokenAccount: destinationTokenAccount.toString() } : {}),
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

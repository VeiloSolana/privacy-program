import { Connection, PublicKey, AccountMeta } from '@solana/web3.js';

export const JUPITER_PROGRAM_ID = new PublicKey('JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4');
export const JUPITER_EVENT_AUTHORITY = new PublicKey('D8cy77BBepLMngZx6ZukaTff5hCt1HrWyKk3Hnd9oitf');

// Jupiter "route" instruction discriminator
export const JUPITER_ROUTE_DISCRIMINATOR = Buffer.from([0xe5, 0x17, 0xcb, 0x97, 0x7a, 0xe3, 0xad, 0x2a]);

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
  private apiUrl: string = 'https://quote-api.jup.ag/v6';

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
    slippageBps: number = 50
  ): Promise<QuoteResponse> {
    const params = new URLSearchParams({
      inputMint: inputMint.toString(),
      outputMint: outputMint.toString(),
      amount: amount.toString(),
      slippageBps: slippageBps.toString(),
      onlyDirectRoutes: 'true',  // Simple routes only (no ALTs)
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
    wrapUnwrapSOL: boolean = true
  ): Promise<SwapInstructionsResponse> {
    const response = await fetch(`${this.apiUrl}/swap-instructions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        quoteResponse: quote,
        userPublicKey: userPublicKey.toString(),
        wrapAndUnwrapSol: wrapUnwrapSOL,
        dynamicComputeUnitLimit: true,
        prioritizationFeeLamports: 'auto',
      }),
    });

    if (!response.ok) {
      throw new Error(`Jupiter swap instruction failed: ${response.statusText}`);
    }

    return await response.json();
  }

  /**
   * Extract remaining_accounts for privacy pool CPI
   * Filters out the base accounts (first 9) and returns DEX routing accounts
   */
  extractRemainingAccounts(swapInstruction: any): AccountMeta[] {
    const accounts = swapInstruction.accounts;

    // Jupiter route instruction has 9 base accounts + routing accounts
    // We need to pass routing accounts via remaining_accounts
    // Plus event authority as first item
    const remainingAccounts: AccountMeta[] = [
      {
        pubkey: JUPITER_EVENT_AUTHORITY,
        isWritable: false,
        isSigner: false,
      }
    ];

    // Add routing accounts (accounts 9+)
    for (let i = 9; i < accounts.length; i++) {
      remainingAccounts.push({
        pubkey: new PublicKey(accounts[i].pubkey),
        isWritable: accounts[i].isWritable,
        isSigner: false,
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
    const instructionData = Buffer.from(swapInstruction.data, 'base64');

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
        return `Step ${i + 1}: ${swapInfo.label} (${swapInfo.inputMint.slice(0, 8)}...→${swapInfo.outputMint.slice(0, 8)}...)`;
      })
      .join(' → ');
  }
}

import { PublicKey, Connection } from "@solana/web3.js";
import { struct, u8, blob } from "@solana/buffer-layout";
import { publicKey, u64 } from "@solana/buffer-layout-utils";

export const CPMM_PROGRAM_ID = new PublicKey(
  "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C",
);

export interface CpmmPoolState {
  amm_config: PublicKey;
  pool_creator: PublicKey;
  token_0_vault: PublicKey;
  token_1_vault: PublicKey;
  lp_mint: PublicKey;
  token_0_mint: PublicKey;
  token_1_mint: PublicKey;
  token_0_program: PublicKey;
  token_1_program: PublicKey;
  observation_key: PublicKey;
  auth_bump: number;
  status: number;
  lp_mint_decimals: number;
  mint_0_decimals: number;
  mint_1_decimals: number;
  lp_supply: bigint;
  protocol_fees_token_0: bigint;
  protocol_fees_token_1: bigint;
  fund_fees_token_0: bigint;
  fund_fees_token_1: bigint;
  open_time: bigint;
  recent_epoch: bigint;
  padding: Uint8Array;
}

export interface CpmmPool extends CpmmPoolState {
  poolId: PublicKey;
}

// Layout matching the IDL’s CpmmPoolState (packed, no padding beyond the final array)
export const POOL_STATE_LAYOUT = struct<CpmmPoolState>([
  u64("discriminator"),
  publicKey("amm_config"),
  publicKey("pool_creator"),
  publicKey("token_0_vault"),
  publicKey("token_1_vault"),
  publicKey("lp_mint"),
  publicKey("token_0_mint"),
  publicKey("token_1_mint"),
  publicKey("token_0_program"),
  publicKey("token_1_program"),
  publicKey("observation_key"),
  u8("auth_bump"),
  u8("status"),
  u8("lp_mint_decimals"),
  u8("mint_0_decimals"),
  u8("mint_1_decimals"),
  u64("lp_supply"),
  u64("protocol_fees_token_0"),
  u64("protocol_fees_token_1"),
  u64("fund_fees_token_0"),
  u64("fund_fees_token_1"),
  u64("open_time"),
  u64("recent_epoch"),
  blob(31 * 8, "padding"),
]);

const TOKEN0_MINT_OFFSET = 8 + 32 * 5; // = 168
const TOKEN1_MINT_OFFSET = TOKEN0_MINT_OFFSET + 32; // = 200

export const getCpmmPoolState = async (
  connection: Connection,
  tokenMint: string,
): Promise<CpmmPool | null> => {
  const mintBase58 = new PublicKey(tokenMint).toBase58();

  // First try filtering on token0Mint:
  let accts = await connection.getProgramAccounts(CPMM_PROGRAM_ID, {
    filters: [{ memcmp: { offset: TOKEN0_MINT_OFFSET, bytes: mintBase58 } }],
  });

  // If none, try token1Mint:
  if (accts.length === 0) {
    accts = await connection.getProgramAccounts(CPMM_PROGRAM_ID, {
      filters: [{ memcmp: { offset: TOKEN1_MINT_OFFSET, bytes: mintBase58 } }],
    });
  }

  if (accts.length === 0) {
    return null;
  }

  // Decode all matching accounts and find the one with the highest LP supply or liquidity
  const pools = accts.map(({ pubkey, account }) => {
    const decoded = POOL_STATE_LAYOUT.decode(
      account.data as Buffer,
    ) as CpmmPoolState;
    return {
      ...decoded,
      poolId: pubkey,
    };
  });

  // Sort by LP supply (descending) to find the most active pool
  // Since we are checking for empty pools, finding the one with the most "shares" or active liq is a good proxy.
  // Ideally we'd check real token balances, but that requires more RPC calls.
  // LP supply is a decent improved heuristic over "random first result".
  pools.sort((a, b) => {
    if (a.lp_supply > b.lp_supply) return -1;
    if (a.lp_supply < b.lp_supply) return 1;
    return 0;
  });

  return pools[0];
};

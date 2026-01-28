import { WSOL } from "@raydium-io/raydium-sdk";
import axios from "axios";

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

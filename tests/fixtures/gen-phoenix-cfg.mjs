import { Connection, PublicKey } from "@solana/web3.js";
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import * as bs58 from "bs58";

const conn = new Connection("https://api.mainnet-beta.solana.com", "confirmed");
const globalCfgAddr = new PublicKey(
  "2zskx2iyCvb6Stg7RBZkt1f6MrF4dpYtMG3yMvKwqtUZ",
);
const info = await conn.getAccountInfo(globalCfgAddr);
if (!info) throw new Error("Account not found");

// Test wallet pubkey
const testWalletB58 = "H6QRuiRsguQgpRSJpP79h75EfDYRS2wN78oj7a4auZtP";
const testWallet = bs58.decode(testWalletB58);

const data = Buffer.from(info.data);
console.log("Data length:", data.length);

// riskAuthority is at offset 72 (8 discriminant + 32 accountKey + 32 rootAuthority)
console.log("Original riskAuthority:", bs58.encode(data.slice(72, 104)));

// Replace riskAuthority with our test wallet
testWallet.forEach((b, i) => {
  data[72 + i] = b;
});
console.log("New riskAuthority:", bs58.encode(data.slice(72, 104)));

const accountJson = {
  pubkey: "2zskx2iyCvb6Stg7RBZkt1f6MrF4dpYtMG3yMvKwqtUZ",
  account: {
    lamports: info.lamports,
    data: [data.toString("base64"), "base64"],
    owner: info.owner.toBase58(),
    executable: false,
    rentEpoch: 0,
  },
};

mkdirSync("/Users/admin/Projects/veilo program/program/tests/fixtures", {
  recursive: true,
});
writeFileSync(
  "/Users/admin/Projects/veilo program/program/tests/fixtures/phoenix-global-config.json",
  JSON.stringify(accountJson, null, 2),
);
console.log("Fixture saved!");

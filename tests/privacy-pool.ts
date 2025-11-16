import { PrivacyPoolClient } from "../packages/sdk-core/src/client";
import * as anchor from '@coral-xyz/anchor'
import {PublicKey} from "@solana/web3.js";

describe("privacy-pool", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const client = new PrivacyPoolClient(provider);
  const wallet = provider.wallet as anchor.Wallet;

  let mint: PublicKey;

  it("initializes the pool", async () => {
    mint = await createMint(
      provider.connection,
      wallet.payer as Keypair,
      wallet.publicKey,
      null,
      6
  );

    const res = await client.initializePool({ mint });
    console.log("Pool:", res.poolStatePda.toBase58());
  });

  it("deposits using SDK", async () => {
    const note = await client.deposit({
      mint,
      amount: 100_000n,
    });
    console.log("Note commitment:", Buffer.from(note.commitment).toString("hex"));
  });

  it("withdraws using fake zk via SDK", async () => {
    await client.withdrawFake({
      mint,
      amount: 50_000n,
    });
  });
});
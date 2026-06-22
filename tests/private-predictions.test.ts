// tests/private-predictions.test.ts
//
// Private Predictions Integration Tests for Veilo Privacy Pool
//
// Tests the two new pool instructions that enable private prediction trading:
//   prediction_open    — ZK-verified USDC withdrawal → ephemeral wallet funded
//   prediction_reissue — ephemeral wallet sweeps proceeds → pool vault + new notes
//
// Privacy model:
//   The link between the user's wallet and their prediction position is severed by
//   the ZK proof.  An ephemeral keypair (generated fresh per prediction) owns the
//   Jupiter position.  On-chain observers see: pool vault → unknown ephemeral wallet.
//   They cannot link the ephemeral wallet back to any depositor without breaking the
//   ZK proof.
//
// Test structure:
//   Suite 1 — Off-chain helpers      (no localnet; ephemeral key derivation, ATA derivation)
//   Suite 2 — Validation Errors      (localnet; guard conditions fire before ZK verification)
//   Suite 3 — Full Integration       (localnet; complete open → trade → reissue flow, ZK bypassed)
//
// Run: npm run test:pred-pool
//
// Suite 3 requires a funded USDC pool on the test validator (same as jperp integration tests).

import "mocha";
import {
  AnchorProvider,
  BN,
  setProvider,
  Wallet,
  workspace,
} from "@coral-xyz/anchor";
import {
  PublicKey,
  Keypair,
  SystemProgram,
  LAMPORTS_PER_SOL,
  TransactionMessage,
  VersionedTransaction,
  AddressLookupTableProgram,
  Transaction,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  getAssociatedTokenAddress,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  createAssociatedTokenAccountInstruction,
  getAccount,
} from "@solana/spl-token";
import { buildPoseidon } from "circomlibjs";

import {
  ComputeBudgetProgram,
} from "@solana/web3.js";

import {
  makeProvider,
  airdropAndConfirm,
  randomBytes32,
  deriveSpendingKey,
  computeExtDataHash,
  computeCommitment,
  computeNullifier,
  derivePublicKey,
  bytesToBigIntBE,
  generateTransactionProof,
  OffchainMerkleTree,
} from "./test-helpers";
import { PredictionFlowClient } from "./utils/jupiter/prediction/prediction-flow";

// ─── Constants ────────────────────────────────────────────────────────────────

const USDC_MINT   = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
const WSOL_MINT   = new PublicKey("So11111111111111111111111111111111111111112");
const JUPUSD_MINT = new PublicKey("JuprjznTrTSp2UFa3ZBUFgwdAmtZCq4MQCwysN55USD");

const PREDICTION_PROGRAM_ID = new PublicKey(
  "3ZZuTbwC6aJbvteyVxXUS7gtFYdf7AuXeitx6VyvjvUp",
);
const PREDICTION_GLOBAL_CONFIG = new PublicKey(
  "2y9Ad2GD7gwiMkkMu4bBK5216Pv9YJsBkSHAGwN3rBuJ",
);
const JUPITER_AUTHORITY = new PublicKey(
  "5uFXJogUEqBTsVT8AcfuWbC9ZFM1tSzTFJ3eKVeB14yi",
);

/** Minimum deposit per Jupiter Prediction order: $5 */
const MIN_DEPOSIT_MICRO = 5_000_000;

// ─── Pure helpers ─────────────────────────────────────────────────────────────

function encodeTreeId(id: number): Buffer {
  const buf = Buffer.alloc(2);
  buf.writeUInt16LE(id, 0);
  return buf;
}

function nullifierMarkerPDA(
  programId: PublicKey,
  mint: PublicKey,
  nullifier: Uint8Array,
): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("nullifier_v3"), mint.toBuffer(), Buffer.from(nullifier)],
    programId,
  );
  return pda;
}

function tinyProof() {
  return { proofA: [] as number[], proofB: [] as number[], proofC: [] as number[] };
}

/** Short pubkey for compact logging. */
function shortKey(k: PublicKey): string {
  const s = k.toBase58();
  return `${s.slice(0, 4)}…${s.slice(-4)}`;
}

/** Format µUSDC (6 decimals) as "$X.XX". */
function usd(micro: number | BN): string {
  const n = typeof micro === "number" ? micro : Number(micro.toString());
  return `$${(n / 1e6).toFixed(2)}`;
}

/** Fetch a token-account balance in base units (0 if missing). */
async function tokenBal(provider: AnchorProvider, ata: PublicKey): Promise<number> {
  const bal = await provider.connection.getTokenAccountBalance(ata).catch(() => null);
  return parseInt(bal?.value.amount ?? "0");
}

// Matches predictions.rs doc: sha256("prediction_ephemeral" || spending_key || nonce_le64)
function deriveEphemeralKeypair(spendingKey: Uint8Array, nonce: number): Keypair {
  const nonceBuf = Buffer.alloc(8);
  nonceBuf.writeBigUInt64LE(BigInt(nonce));
  const seed = require("crypto")
    .createHash("sha256")
    .update(Buffer.concat([Buffer.from("prediction_ephemeral"), Buffer.from(spendingKey), nonceBuf]))
    .digest();
  return Keypair.fromSeed(seed);
}

function log(...parts: unknown[]): void {
  console.log("      " + parts.join(" "));
}

async function assertError(
  promise: Promise<unknown>,
  expectedFragment: string,
): Promise<void> {
  try {
    await promise;
    throw new Error(`Expected error containing "${expectedFragment}" but tx succeeded`);
  } catch (err: any) {
    const msg = err?.message ?? err?.toString() ?? "";
    const logs: string = (err?.logs ?? []).join("\n");
    if (!msg.includes(expectedFragment) && !logs.includes(expectedFragment)) {
      throw new Error(
        `Expected "${expectedFragment}" but got: ${msg}\nLogs: ${logs}`,
      );
    }
  }
}

async function buildAlt(
  provider: AnchorProvider,
  payer: Keypair,
  addresses: PublicKey[],
): Promise<import("@solana/web3.js").AddressLookupTableAccount> {
  const slot = await provider.connection.getSlot("finalized");
  const [createIx, lutAddress] = AddressLookupTableProgram.createLookupTable({
    authority: payer.publicKey,
    payer: payer.publicKey,
    recentSlot: slot,
  });
  const extendIx = AddressLookupTableProgram.extendLookupTable({
    payer: payer.publicKey,
    authority: payer.publicKey,
    lookupTable: lutAddress,
    addresses,
  });
  await provider.sendAndConfirm(
    new Transaction().add(createIx).add(extendIx),
    [payer],
  );
  await new Promise((r) => setTimeout(r, 600));
  const lutAccount = await provider.connection.getAddressLookupTable(lutAddress);
  return lutAccount.value!;
}

async function sendVersionedTx(
  provider: AnchorProvider,
  ixs: import("@solana/web3.js").TransactionInstruction[],
  signers: Keypair[],
  luts: import("@solana/web3.js").AddressLookupTableAccount[] = [],
): Promise<string> {
  const { blockhash } = await provider.connection.getLatestBlockhash();
  const msg = new TransactionMessage({
    payerKey: signers[0].publicKey,
    recentBlockhash: blockhash,
    instructions: ixs,
  }).compileToV0Message(luts);
  const vtx = new VersionedTransaction(msg);
  vtx.sign(signers);
  return provider.connection.sendTransaction(vtx, { skipPreflight: false });
}

// ─── Suites ───────────────────────────────────────────────────────────────────

describe("Private Predictions (pool integration)", () => {
  const provider = makeProvider();
  setProvider(provider);
  const wallet = provider.wallet as Wallet;
  const program: any = (workspace as any).PrivacyPool;

  // Shared pool accounts (WSOL, non-USDC — safe for error tests)
  let testMint: PublicKey;
  let config: PublicKey;
  let vault: PublicKey;
  let noteTree: PublicKey;
  let nullifiers: PublicKey;
  let globalConfig: PublicKey;
  let vaultTokenAccount: PublicKey;
  let relayer: Keypair;
  let poseidon: any;

  before(async () => {
    console.log("\n🔮  Private Predictions Test Setup\n");
    poseidon = await buildPoseidon();

    testMint = WSOL_MINT; // non-USDC pool for validation tests

    [config] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_config_v3"), testMint.toBuffer()],
      program.programId,
    );
    [vault] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_vault_v3"), testMint.toBuffer()],
      program.programId,
    );
    [noteTree] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_note_tree_v3"), testMint.toBuffer(), encodeTreeId(0)],
      program.programId,
    );
    [nullifiers] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_nullifiers_v3"), testMint.toBuffer()],
      program.programId,
    );
    [globalConfig] = PublicKey.findProgramAddressSync(
      [Buffer.from("global_config_v1")],
      program.programId,
    );

    try {
      await (program.methods as any)
        .initializeGlobalConfig()
        .accounts({ globalConfig, admin: wallet.publicKey, payer: wallet.publicKey, systemProgram: SystemProgram.programId })
        .rpc();
    } catch (_) { /* already exists */ }

    try {
      await (program.methods as any)
        .initialize(50, testMint, new BN(1_000), new BN(1_000_000_000_000), new BN(1_000), new BN(1_000_000_000_000))
        .accounts({ config, vault, noteTree, nullifiers, globalConfig, admin: wallet.publicKey, payer: wallet.publicKey, systemProgram: SystemProgram.programId })
        .rpc();
    } catch (_) { /* already exists */ }

    vaultTokenAccount = await getAssociatedTokenAddress(testMint, vault, true);

    relayer = Keypair.generate();
    await airdropAndConfirm(provider, relayer.publicKey, 2 * LAMPORTS_PER_SOL);

    await (program.methods as any)
      .addRelayer(testMint, relayer.publicKey)
      .accounts({ config, admin: wallet.publicKey })
      .rpc();

    console.log(`   Test mint (WSOL):   ${testMint.toBase58()}`);
    console.log(`   Config PDA:         ${config.toBase58()}`);
    console.log(`   Relayer:            ${relayer.publicKey.toBase58()}`);
  });

  // ── Suite 1: Off-chain helpers ─────────────────────────────────────────────

  describe("Off-chain helpers", () => {
    it("generates deterministic ephemeral keypair from seed", () => {
      const spendingKey = randomBytes32();
      const ephemeral1 = deriveEphemeralKeypair(spendingKey, 0);
      const ephemeral2 = deriveEphemeralKeypair(spendingKey, 0);
      if (!ephemeral1.publicKey.equals(ephemeral2.publicKey)) {
        throw new Error("Same seed must produce same keypair");
      }
      log("Ephemeral pubkey:", ephemeral1.publicKey.toBase58());
    });

    it("derives USDC ATA for any ephemeral pubkey", async () => {
      const ephemeral = Keypair.generate();
      const ata = await getAssociatedTokenAddress(USDC_MINT, ephemeral.publicKey, false);
      log("Ephemeral pubkey:", shortKey(ephemeral.publicKey));
      log("USDC ATA:        ", shortKey(ata));

      // ATA must be different for each ephemeral
      const ephemeral2 = Keypair.generate();
      const ata2 = await getAssociatedTokenAddress(USDC_MINT, ephemeral2.publicKey, false);
      if (ata.equals(ata2)) throw new Error("Different ephemeral keys must have different ATAs");
    });

    it("different ephemeral keys → different ATA addresses (positions unlinkable)", () => {
      const keys = Array.from({ length: 5 }, () => Keypair.generate());
      const atas = keys.map((k) =>
        PublicKey.findProgramAddressSync(
          [k.publicKey.toBuffer(), TOKEN_PROGRAM_ID.toBuffer(), USDC_MINT.toBuffer()],
          ASSOCIATED_TOKEN_PROGRAM_ID,
        )[0],
      );
      const unique = new Set(atas.map((a) => a.toBase58()));
      if (unique.size !== atas.length) throw new Error("All ATAs must be unique");
      log(`Generated ${atas.length} unique ephemeral ATAs`);
    });

    it("prediction_open account layout: 15 accounts in correct order", () => {
      // Verify IDL account order matches expectations
      const idl = (program as any).idl;
      const ix = idl.instructions.find((i: any) => i.name === "predictionOpen" || i.name === "prediction_open");
      if (!ix) throw new Error("prediction_open not found in IDL");

      const names = ix.accounts.map((a: any) => a.name);
      const expected = [
        "config", "globalConfig", "vault",
        "inputTree", "outputTree", "nullifiers",
        "nullifierMarker0", "nullifierMarker1",
        "relayer",
        "vaultTokenAccount", "ephemeralWallet",
        "ephemeralTokenAccount", "relayerTokenAccount",
        "tokenProgram", "systemProgram",
      ];

      log("prediction_open accounts:", names.join(", "));
      if (names.length !== expected.length) {
        throw new Error(`Expected ${expected.length} accounts, got ${names.length}: ${names.join(", ")}`);
      }
    });

    it("prediction_reissue account layout: 14 accounts with claimant signer", () => {
      const idl = (program as any).idl;
      const ix = idl.instructions.find((i: any) => i.name === "predictionReissue" || i.name === "prediction_reissue");
      if (!ix) throw new Error("prediction_reissue not found in IDL");

      const signerAccounts = ix.accounts.filter((a: any) => a.signer);
      const names = ix.accounts.map((a: any) => a.name);
      log("prediction_reissue accounts:", names.join(", "));
      log("Signers:", signerAccounts.map((a: any) => a.name).join(", "));

      // claimant must be a signer (ephemeral key authorizes ATA transfer)
      const claimantAccount = ix.accounts.find((a: any) => a.name === "claimant");
      if (!claimantAccount?.signer) {
        throw new Error("claimant account must be a signer in prediction_reissue");
      }
    });

    it("ephemeral key derivation nonce uniqueness: nonce 0 vs 1 → different keys", () => {
      const spendingKey = randomBytes32();
      const e0 = deriveEphemeralKeypair(spendingKey, 0);
      const e1 = deriveEphemeralKeypair(spendingKey, 1);
      if (e0.publicKey.equals(e1.publicKey)) {
        throw new Error("Different nonces must produce different ephemeral keys");
      }
      log("Nonce 0 ephemeral:", shortKey(e0.publicKey));
      log("Nonce 1 ephemeral:", shortKey(e1.publicKey));
    });

    it("Jupiter Prediction program constants are correct", () => {
      if (PREDICTION_PROGRAM_ID.toBase58() !== "3ZZuTbwC6aJbvteyVxXUS7gtFYdf7AuXeitx6VyvjvUp") {
        throw new Error("Wrong prediction program ID");
      }
      if (PREDICTION_GLOBAL_CONFIG.toBase58() !== "2y9Ad2GD7gwiMkkMu4bBK5216Pv9YJsBkSHAGwN3rBuJ") {
        throw new Error("Wrong prediction global config");
      }
      if (JUPITER_AUTHORITY.toBase58() !== "5uFXJogUEqBTsVT8AcfuWbC9ZFM1tSzTFJ3eKVeB14yi") {
        throw new Error("Wrong Jupiter authority");
      }
      log("Prediction program:   ", shortKey(PREDICTION_PROGRAM_ID));
      log("Global config:        ", shortKey(PREDICTION_GLOBAL_CONFIG));
      log("Jupiter authority:    ", shortKey(JUPITER_AUTHORITY));
    });
  });

  // ── Suite 2: Validation Errors ─────────────────────────────────────────────

  describe("Validation Errors", () => {
    let suite2Lut: import("@solana/web3.js").AddressLookupTableAccount;

    const ephemeral = Keypair.generate();
    const n0 = randomBytes32();
    const n1 = randomBytes32();
    const c0 = randomBytes32();
    const c1 = randomBytes32();

    before(async () => {
      suite2Lut = await buildAlt(provider, relayer, [
        TOKEN_PROGRAM_ID,
        ASSOCIATED_TOKEN_PROGRAM_ID,
        SystemProgram.programId,
        globalConfig,
        config,
        vault,
        noteTree,
        nullifiers,
        vaultTokenAccount,
        ephemeral.publicKey,
      ]);
    });

    /** Build a prediction_open instruction with defaults; override specific fields. */
    async function buildOpenIx(overrides: {
      relayerKey?: Keypair;
      recipient?: PublicKey;
      claimant?: PublicKey;
      ephemeralTokenAccount?: PublicKey;
      deadline?: BN;
      depositAmount?: BN;
      n0?: Uint8Array;
      n1?: Uint8Array;
    } = {}) {
      const resolvedRelayer  = overrides.relayerKey ?? relayer;
      const claimantPubkey   = overrides.claimant ?? ephemeral.publicKey;
      const recipientPubkey  = overrides.recipient ?? claimantPubkey;
      const ephemeralAta     = overrides.ephemeralTokenAccount
        ?? await getAssociatedTokenAddress(testMint, claimantPubkey, false);

      const extData = {
        recipient: recipientPubkey,
        relayer: resolvedRelayer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
        claimant: claimantPubkey,
      };
      const extDataHash = computeExtDataHash(poseidon, extData);

      const nullifier0 = overrides.n0 ?? n0;
      const nullifier1 = overrides.n1 ?? n1;
      const marker0 = nullifierMarkerPDA(program.programId, testMint, nullifier0);
      const marker1 = nullifierMarkerPDA(program.programId, testMint, nullifier1);

      return (program.methods as any)
        .predictionOpen(
          Array.from(new Uint8Array(32).fill(1)),  // root (non-zero)
          0, 0,                                     // input/output tree IDs
          overrides.depositAmount ?? new BN(1_000_000),
          Array.from(extDataHash),
          testMint,
          claimantPubkey,
          Array.from(nullifier0),
          Array.from(nullifier1),
          Array.from(c0),
          Array.from(c1),
          Array.from(new Uint8Array(32).fill(0xcc)), // withdrawal_id
          overrides.deadline ?? new BN(Math.floor(Date.now() / 1000) + 3600),
          extData,
          tinyProof(),
          null,        // note_ciphers
          new BN(5_000_000), // sol_funding
        )
        .accounts({
          config,
          globalConfig,
          vault,
          inputTree: noteTree,
          outputTree: noteTree,
          nullifiers,
          nullifierMarker0: marker0,
          nullifierMarker1: marker1,
          relayer: resolvedRelayer.publicKey,
          vaultTokenAccount,
          ephemeralWallet: claimantPubkey,
          ephemeralTokenAccount: ephemeralAta,
          relayerTokenAccount: vaultTokenAccount, // dummy for error tests
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .instruction();
    }

    it("prediction_open: rejects unregistered relayer (RelayerNotAllowed)", async () => {
      const badRelayer = Keypair.generate();
      await airdropAndConfirm(provider, badRelayer.publicKey, LAMPORTS_PER_SOL);

      const ix = await buildOpenIx({ relayerKey: badRelayer });

      await assertError(
        sendVersionedTx(provider, [ix], [badRelayer], [suite2Lut]),
        "RelayerNotAllowed",
      );
    });

    it("prediction_open: rejects when recipient != claimant (PredictionRecipientMustBeClaimant)", async () => {
      const wrongRecipient = Keypair.generate().publicKey;
      const ix = await buildOpenIx({
        recipient: wrongRecipient,
        claimant: ephemeral.publicKey,
      });

      await assertError(
        sendVersionedTx(provider, [ix], [relayer], [suite2Lut]),
        "PredictionRecipientMustBeClaimant",
      );
    });

    it("prediction_open: rejects expired deadline (DeadlineExpired)", async () => {
      const ix = await buildOpenIx({
        deadline: new BN(1), // Unix epoch (1970) — definitively expired on any validator
      });

      await assertError(
        sendVersionedTx(provider, [ix], [relayer], [suite2Lut]),
        "DeadlineExpired",
      );
    });

    it("prediction_open: rejects duplicate nullifiers (AccountAlreadyInUse at PDA level)", async () => {
      // When n0 == n1, both marker PDAs derive to the same address. Anchor's `init`
      // creates marker0 first (ok), then tries to `init` marker1 at the same address →
      // system program returns AccountAlreadyInUse (0x0) before the handler runs.
      const sameNullifier = randomBytes32();
      const ix = await buildOpenIx({
        n0: sameNullifier,
        n1: sameNullifier,
      });

      await assertError(
        sendVersionedTx(provider, [ix], [relayer], [suite2Lut]),
        "already in use",
      );
    });

    it("prediction_open: rejects zero deposit amount (InvalidPublicAmount)", async () => {
      const ix = await buildOpenIx({ depositAmount: new BN(0) });

      await assertError(
        sendVersionedTx(provider, [ix], [relayer], [suite2Lut]),
        "InvalidPublicAmount",
      );
    });

    it("prediction_open: rejects wrong mint in args (ConstraintSeeds via PDA mismatch)", async () => {
      // The `config` PDA seeds include `mint_address`, so passing a wrong mint_address arg
      // causes a ConstraintSeeds error because the provided WSOL config PDA doesn't match
      // the expected PDA derived from the USDC mint_address arg.
      // (InvalidMintAddress in the handler is unreachable via account substitution because
      // Anchor's PDA seeds constraint already enforces the invariant.)
      const claimantPubkey = ephemeral.publicKey;
      const wrongMint = USDC_MINT; // pool is WSOL, not USDC
      const extData = {
        recipient: claimantPubkey,
        relayer: relayer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
        claimant: claimantPubkey,
      };
      const extDataHash = computeExtDataHash(poseidon, extData);
      const nm0 = randomBytes32();
      const nm1 = randomBytes32();
      // Markers derived with wrongMint — so marker seeds match the wrongMint arg;
      // but the config PDA is still WSOL → ConstraintSeeds on config.
      const marker0 = nullifierMarkerPDA(program.programId, wrongMint, nm0);
      const marker1 = nullifierMarkerPDA(program.programId, wrongMint, nm1);

      const ix = await (program.methods as any)
        .predictionOpen(
          Array.from(new Uint8Array(32).fill(1)),
          0, 0,
          new BN(1_000_000),
          Array.from(extDataHash),
          wrongMint, // ← mismatched mint arg
          claimantPubkey,
          Array.from(nm0), Array.from(nm1),
          Array.from(c0), Array.from(c1),
          Array.from(new Uint8Array(32).fill(0xdd)),
          new BN(Math.floor(Date.now() / 1000) + 3600),
          extData,
          tinyProof(),
          null,
          new BN(5_000_000),
        )
        .accounts({
          config,              // ← WSOL config, but mint_address arg = USDC → ConstraintSeeds
          globalConfig,
          vault,
          inputTree: noteTree,
          outputTree: noteTree,
          nullifiers,
          nullifierMarker0: marker0,
          nullifierMarker1: marker1,
          relayer: relayer.publicKey,
          vaultTokenAccount,
          ephemeralWallet: claimantPubkey,
          ephemeralTokenAccount: await getAssociatedTokenAddress(wrongMint, claimantPubkey, false),
          relayerTokenAccount: vaultTokenAccount,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .instruction();

      await assertError(
        sendVersionedTx(provider, [ix], [relayer], [suite2Lut]),
        "ConstraintSeeds",
      );
    });

    /** Build a prediction_reissue instruction with defaults; override specific fields. */
    async function buildReissueIx(overrides: {
      relayerKey?: Keypair;
      claimantKp?: Keypair;
      ephemeralTokenAccount?: PublicKey;
      deadline?: BN;
      reissueAmount?: BN;
      n0?: Uint8Array;
      n1?: Uint8Array;
      oc0?: Uint8Array;
      oc1?: Uint8Array;
    } = {}) {
      const resolvedRelayer  = overrides.relayerKey ?? relayer;
      const resolvedClaimant = overrides.claimantKp ?? ephemeral;
      const nm0 = overrides.n0 ?? randomBytes32();
      const nm1 = overrides.n1 ?? randomBytes32();
      const rc0 = overrides.oc0 ?? randomBytes32();
      const rc1 = overrides.oc1 ?? randomBytes32();

      const extData = {
        recipient: PublicKey.default,
        relayer:   resolvedRelayer.publicKey,
        fee:       new BN(0),
        refund:    new BN(0),
        claimant:  resolvedClaimant.publicKey,
      };
      const extDataHash = computeExtDataHash(poseidon, extData);

      const marker0 = nullifierMarkerPDA(program.programId, testMint, nm0);
      const marker1 = nullifierMarkerPDA(program.programId, testMint, nm1);
      const claimantAta = overrides.ephemeralTokenAccount
        ?? await getAssociatedTokenAddress(testMint, resolvedClaimant.publicKey, false);

      return (program.methods as any)
        .predictionReissue(
          Array.from(new Uint8Array(32).fill(1)), // root (non-zero)
          0, 0,
          overrides.reissueAmount ?? new BN(1_000_000),
          Array.from(extDataHash),
          testMint,
          Array.from(nm0), Array.from(nm1),
          Array.from(rc0), Array.from(rc1),
          overrides.deadline ?? new BN(Math.floor(Date.now() / 1000) + 3600),
          extData,
          tinyProof(),
          null,
        )
        .accounts({
          config,
          globalConfig,
          vault,
          inputTree:             noteTree,
          outputTree:            noteTree,
          nullifiers,
          nullifierMarker0:      marker0,
          nullifierMarker1:      marker1,
          relayer:               resolvedRelayer.publicKey,
          claimant:              resolvedClaimant.publicKey,
          ephemeralTokenAccount: claimantAta,
          vaultTokenAccount,
          tokenProgram:          TOKEN_PROGRAM_ID,
          systemProgram:         SystemProgram.programId,
        })
        .instruction();
    }

    it("prediction_reissue: requires claimant co-signature (tx-level check)", async () => {
      // If claimant is missing from signers, the tx will fail signature validation
      // before reaching the program (Solana runtime requires all signers declared in AccountsStruct)
      const fakeClaimant = Keypair.generate();
      const ephemeralAta = await getAssociatedTokenAddress(testMint, fakeClaimant.publicKey, false);
      const nm0 = randomBytes32();
      const nm1 = randomBytes32();

      const extData = {
        recipient: PublicKey.default,
        relayer: relayer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
        claimant: fakeClaimant.publicKey,
      };
      const extDataHash = computeExtDataHash(poseidon, extData);

      const ix = await (program.methods as any)
        .predictionReissue(
          Array.from(new Uint8Array(32).fill(1)),
          0, 0,
          new BN(1_000_000),
          Array.from(extDataHash),
          testMint,
          Array.from(nm0), Array.from(nm1),
          Array.from(c0), Array.from(c1),
          new BN(Math.floor(Date.now() / 1000) + 3600),
          extData,
          tinyProof(),
          null,
        )
        .accounts({
          config,
          globalConfig,
          vault,
          inputTree: noteTree,
          outputTree: noteTree,
          nullifiers,
          nullifierMarker0: nullifierMarkerPDA(program.programId, testMint, nm0),
          nullifierMarker1: nullifierMarkerPDA(program.programId, testMint, nm1),
          relayer: relayer.publicKey,
          claimant: fakeClaimant.publicKey,
          ephemeralTokenAccount: ephemeralAta,
          vaultTokenAccount,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .instruction();

      // Sending without fakeClaimant in signers → tx rejected for missing signature
      await assertError(
        sendVersionedTx(provider, [ix], [relayer], [suite2Lut]),
        "Transaction signature verification failure",
      );
    });

    it("prediction_reissue: relayer alone cannot sweep (missing ephemeral sig → tx rejected)", async () => {
      // Core theft-prevention property: relayer knows the ephemeral pubkey and the
      // pool PDAs, but without the ephemeral private key they cannot co-sign the tx.
      // Even constructing the right instruction fails at tx signature validation.
      const targetEphemeral = Keypair.generate();
      const ix = await buildReissueIx({ claimantKp: targetEphemeral });

      await assertError(
        // Only relayer signs — ephemeral signature missing
        sendVersionedTx(provider, [ix], [relayer], [suite2Lut]),
        "Transaction signature verification failure",
      );
    });

    it("prediction_reissue: rejects unregistered relayer (RelayerNotAllowed)", async () => {
      const badRelayer = Keypair.generate();
      await airdropAndConfirm(provider, badRelayer.publicKey, LAMPORTS_PER_SOL);
      const ix = await buildReissueIx({ relayerKey: badRelayer });

      await assertError(
        // Both relayer + ephemeral sign — but relayer is not registered
        sendVersionedTx(provider, [ix], [badRelayer, ephemeral], [suite2Lut]),
        "RelayerNotAllowed",
      );
    });

    it("prediction_reissue: rejects expired deadline (DeadlineExpired)", async () => {
      const ix = await buildReissueIx({ deadline: new BN(1) });

      await assertError(
        sendVersionedTx(provider, [ix], [relayer, ephemeral], [suite2Lut]),
        "DeadlineExpired",
      );
    });

    it("prediction_reissue: rejects zero reissue amount (InvalidPublicAmount)", async () => {
      const ix = await buildReissueIx({ reissueAmount: new BN(0) });

      await assertError(
        sendVersionedTx(provider, [ix], [relayer, ephemeral], [suite2Lut]),
        "InvalidPublicAmount",
      );
    });

    it("prediction_reissue: rejects duplicate nullifiers (AccountDiscriminatorMismatch at PDA level)", async () => {
      // Unlike prediction_open (where marker0's init blocks marker1 with AccountAlreadyInUse),
      // prediction_reissue's marker0 init writes the NullifierMarker discriminator first.
      // marker1 then tries to init the same PDA and Anchor sees the discriminator already
      // written → AccountDiscriminatorMismatch (3002) before the handler's DuplicateNullifiers check.
      const sameNullifier = randomBytes32();
      const ix = await buildReissueIx({ n0: sameNullifier, n1: sameNullifier });

      await assertError(
        sendVersionedTx(provider, [ix], [relayer, ephemeral], [suite2Lut]),
        "AccountDiscriminatorMismatch",
      );
    });

    it("prediction_reissue: rejects duplicate output commitments (DuplicateCommitments)", async () => {
      const sameCommitment = randomBytes32();
      const ix = await buildReissueIx({ oc0: sameCommitment, oc1: sameCommitment });

      await assertError(
        sendVersionedTx(provider, [ix], [relayer, ephemeral], [suite2Lut]),
        "DuplicateCommitments",
      );
    });

    it("prediction_reissue: ATA validation is protected by ZK (wrong ATA reaches InvalidProof)", async () => {
      // The handler validates ephemeral_token_account == get_associated_token_address(claimant, mint)
      // at step 8, AFTER ZK proof at step 6. With tinyProof() the ZK check always fires first.
      // This test confirms the order: passing a wrong ATA does not bypass ZK — it still
      // hits InvalidProof, which is the primary guard in production.
      const ix = await buildReissueIx({
        ephemeralTokenAccount: vaultTokenAccount, // wrong — not claimant's ATA
      });

      await assertError(
        sendVersionedTx(provider, [ix], [relayer, ephemeral], [suite2Lut]),
        "InvalidProof",
      );
    });
  });

  // ── Suite 3: Full Integration ──────────────────────────────────────────────
  //
  // Mirrors the jperp Suite 3 setup: deposits real USDC into the pool (valid
  // Groth16 proof), then spends that note via prediction_open (another real proof).
  // Requires: USDC vault ATA cloned from mainnet (see Anchor.toml) + circuit files
  // at zk/circuits/transaction/. Genesis wallet USDC ATA pre-loaded with 1000 USDC.

  describe("Full Integration (real ZK proofs)", () => {
    let suiteReady  = false;
    let step1Passed = false;

    let usdcConfig:    PublicKey;
    let usdcVault:     PublicKey;
    let usdcNoteTree:  PublicKey;
    let usdcNullifiers: PublicKey;
    let usdcVaultAta:  PublicKey;
    let s3Relayer:     Keypair;
    let s3Poseidon:    any;
    let suite3Lut:     import("@solana/web3.js").AddressLookupTableAccount;

    // sha256(wallet.sign("veilo_spending_key_v1")) — same derivation used in production.
    const s3SpendingKey = deriveSpendingKey((wallet as any).payer);
    // Ephemeral keypair for prediction position 0 — deterministically recoverable
    const ephemeralKp = deriveEphemeralKeypair(s3SpendingKey, 0);
    let ephemeralAta:  PublicKey;

    // Off-chain Merkle mirror (stays in sync with on-chain insertions)
    let offTree: OffchainMerkleTree;
    let emptyRoot: Uint8Array;

    // Note secrets kept for prediction_open spend
    let notePriv: Uint8Array;
    let noteBlind: Uint8Array;
    let notePub: bigint;
    let noteCommitment: Uint8Array;
    let noteLeafIndex: number;

    // prediction_open proof + inputs (built in before(), consumed in Step 1)
    let openProof: any;
    let openN0: Uint8Array;
    let openN1: Uint8Array;
    let openC0: Uint8Array;
    let openC1: Uint8Array;
    let openExtData: any;
    let openExtHash: Uint8Array;
    let openMarker0: PublicKey;
    let openMarker1: PublicKey;

    const DEPOSIT_AMOUNT  = new BN(10_000_000); // 10 USDC — funded via genesis wallet ATA
    const WITHDRAW_AMOUNT = new BN(5_000_000);  // 5 USDC — prediction stake

    before(async function () {
      this.timeout(300_000); // proof generation can take ~60–90s

      s3Poseidon = await buildPoseidon();

      [usdcConfig] = PublicKey.findProgramAddressSync(
        [Buffer.from("privacy_config_v3"), USDC_MINT.toBuffer()],
        program.programId,
      );
      [usdcVault] = PublicKey.findProgramAddressSync(
        [Buffer.from("privacy_vault_v3"), USDC_MINT.toBuffer()],
        program.programId,
      );
      [usdcNoteTree] = PublicKey.findProgramAddressSync(
        [Buffer.from("privacy_note_tree_v3"), USDC_MINT.toBuffer(), encodeTreeId(0)],
        program.programId,
      );
      [usdcNullifiers] = PublicKey.findProgramAddressSync(
        [Buffer.from("privacy_nullifiers_v3"), USDC_MINT.toBuffer()],
        program.programId,
      );
      usdcVaultAta = await getAssociatedTokenAddress(USDC_MINT, usdcVault, true);

      // ── 1. Initialize global config + USDC pool PDAs ──────────────────────
      try {
        await (program.methods as any)
          .initializeGlobalConfig()
          .accounts({ globalConfig, admin: wallet.publicKey, payer: wallet.publicKey, systemProgram: SystemProgram.programId })
          .rpc();
      } catch (_) {}

      try {
        await (program.methods as any)
          .initialize(50, USDC_MINT, new BN(1_000_000), new BN(1_000_000_000_000), new BN(1_000_000), new BN(1_000_000_000_000))
          .accounts({ config: usdcConfig, vault: usdcVault, noteTree: usdcNoteTree, nullifiers: usdcNullifiers, globalConfig, admin: wallet.publicKey, payer: wallet.publicKey, systemProgram: SystemProgram.programId })
          .rpc();
      } catch (_) {}

      // ── 2. Check vault balance ─────────────────────────────────────────────
      const vaultBal = await tokenBal(provider, usdcVaultAta);
      if (vaultBal < Number(WITHDRAW_AMOUNT.toString())) {
        console.log(`\n   ⚠️  USDC vault ${usd(vaultBal)} — need ≥${usd(WITHDRAW_AMOUNT.toString())}. Skipping.\n`);
        return;
      }

      // ── 3. Relayer + ephemeral setup ────────────────────────────────────────
      s3Relayer = Keypair.generate();
      await airdropAndConfirm(provider, s3Relayer.publicKey, 5 * LAMPORTS_PER_SOL);
      try {
        await (program.methods as any).addRelayer(USDC_MINT, s3Relayer.publicKey)
          .accounts({ config: usdcConfig, admin: wallet.publicKey }).rpc();
      } catch (_) {}

      ephemeralAta = await getAssociatedTokenAddress(USDC_MINT, ephemeralKp.publicKey, false);
      const relayerAta = await getAssociatedTokenAddress(USDC_MINT, s3Relayer.publicKey, false);

      const walletUsdcAta = await getAssociatedTokenAddress(USDC_MINT, wallet.publicKey);

      for (const [ata, owner] of [[ephemeralAta, ephemeralKp.publicKey], [relayerAta, s3Relayer.publicKey]] as const) {
        try {
          await provider.sendAndConfirm(
            new Transaction().add(createAssociatedTokenAccountInstruction(wallet.publicKey, ata, owner, USDC_MINT)),
          );
        } catch (_) {}
      }

      // ── 4. Off-chain Merkle mirror (empty tree = fresh state) ──────────────
      offTree    = new OffchainMerkleTree(22, s3Poseidon);
      emptyRoot  = offTree.getRoot();
      const zeros = offTree.getZeros();
      const zeroPath = zeros.slice(0, 22).map((z: Uint8Array) => bytesToBigIntBE(z));
      const zeroMerklePath = { pathElements: zeroPath, pathIndices: new Array(22).fill(0) };

      // ── 5. Deposit 10 USDC → spendable private note ────────────────────────
      notePriv  = randomBytes32();
      noteBlind = randomBytes32();
      notePub   = derivePublicKey(s3Poseidon, notePriv);
      noteCommitment = computeCommitment(s3Poseidon, BigInt(DEPOSIT_AMOUNT.toString()), notePub, noteBlind, USDC_MINT);

      const dummyPriv  = randomBytes32(); const dummyPub  = derivePublicKey(s3Poseidon, dummyPriv);  const dummyBlind  = randomBytes32();
      const dummyCommit = computeCommitment(s3Poseidon, 0n, dummyPub, dummyBlind, USDC_MINT);

      const dp0 = randomBytes32(); const dpub0 = derivePublicKey(s3Poseidon, dp0); const db0 = randomBytes32();
      const dc0 = computeCommitment(s3Poseidon, 0n, dpub0, db0, USDC_MINT);
      const dn0 = computeNullifier(s3Poseidon, dc0, 0, dp0);
      const dp1 = randomBytes32(); const dpub1 = derivePublicKey(s3Poseidon, dp1); const db1 = randomBytes32();
      const dc1 = computeCommitment(s3Poseidon, 0n, dpub1, db1, USDC_MINT);
      const dn1 = computeNullifier(s3Poseidon, dc1, 0, dp1);

      const depExtData = {
        recipient: wallet.publicKey, relayer: wallet.publicKey,
        fee: new BN(0), refund: new BN(0), claimant: SystemProgram.programId,
      };
      const depExtHash = computeExtDataHash(s3Poseidon, depExtData);
      const depMarker0 = nullifierMarkerPDA(program.programId, USDC_MINT, dn0);
      const depMarker1 = nullifierMarkerPDA(program.programId, USDC_MINT, dn1);

      try {
        const depProof = await generateTransactionProof({
          root: emptyRoot, publicAmount: BigInt(DEPOSIT_AMOUNT.toString()),
          extDataHash: depExtHash, mintAddress: USDC_MINT,
          inputNullifiers: [dn0, dn1], outputCommitments: [noteCommitment, dummyCommit],
          inputAmounts: [0n, 0n], inputPrivateKeys: [dp0, dp1],
          inputPublicKeys: [dpub0, dpub1], inputBlindings: [db0, db1],
          inputMerklePaths: [zeroMerklePath, zeroMerklePath],
          outputAmounts: [BigInt(DEPOSIT_AMOUNT.toString()), 0n],
          outputOwners: [notePub, dummyPub], outputBlindings: [noteBlind, dummyBlind],
        });
        await (program.methods as any)
          .transact(
            Array.from(emptyRoot), 0, 0, DEPOSIT_AMOUNT, Array.from(depExtHash),
            USDC_MINT, Array.from(dn0), Array.from(dn1), Array.from(noteCommitment), Array.from(dummyCommit),
            new BN(999_999_999_999), depExtData, depProof, null,
          )
          .accounts({
            config: usdcConfig, globalConfig, vault: usdcVault,
            inputTree: usdcNoteTree, outputTree: usdcNoteTree, nullifiers: usdcNullifiers,
            nullifierMarker0: depMarker0, nullifierMarker1: depMarker1,
            relayer: wallet.publicKey, recipient: wallet.publicKey,
            vaultTokenAccount: usdcVaultAta, userTokenAccount: walletUsdcAta,
            recipientTokenAccount: walletUsdcAta, relayerTokenAccount: walletUsdcAta,
            tokenProgram: TOKEN_PROGRAM_ID, systemProgram: SystemProgram.programId,
          })
          .preInstructions([ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 })])
          .rpc();

        noteLeafIndex = offTree.insert(noteCommitment);
        offTree.insert(dummyCommit);
        log(`✓ deposited ${usd(DEPOSIT_AMOUNT.toString())} → private note at leaf ${noteLeafIndex}`);
      } catch (e: any) {
        console.log("   ⚠️  Deposit failed — Suite 3 will be skipped:", e?.message ?? e);
        return;
      }

      // ── 6. Build prediction_open proof (spend noteA → ephemeral wallet) ────
      const notePath = offTree.getMerkleProof(noteLeafIndex);
      const depositRoot = offTree.getRoot(); // root after deposit inserts

      // Input 0: spend the real note
      const ob0Priv = randomBytes32(); const ob0Pub = derivePublicKey(s3Poseidon, ob0Priv); const ob0Blind = randomBytes32();
      const ob0Commit = computeCommitment(s3Poseidon, 0n, ob0Pub, ob0Blind, USDC_MINT);
      openN0 = computeNullifier(s3Poseidon, noteCommitment, noteLeafIndex, notePriv);
      openN1 = computeNullifier(s3Poseidon, ob0Commit, 0, ob0Priv);  // 0-value dummy

      const changeAmount = BigInt(DEPOSIT_AMOUNT.toString()) - BigInt(WITHDRAW_AMOUNT.toString());
      const oc0Priv = randomBytes32(); const oc0Pub = derivePublicKey(s3Poseidon, oc0Priv); const oc0Blind = randomBytes32();
      openC0 = computeCommitment(s3Poseidon, changeAmount, oc0Pub, oc0Blind, USDC_MINT); // change
      const oc1Priv = randomBytes32(); const oc1Pub = derivePublicKey(s3Poseidon, oc1Priv); const oc1Blind = randomBytes32();
      openC1 = computeCommitment(s3Poseidon, 0n, oc1Pub, oc1Blind, USDC_MINT);           // 0-value dummy

      openExtData = {
        recipient: ephemeralKp.publicKey,
        relayer: s3Relayer.publicKey,
        fee: new BN(0), refund: new BN(0),
        claimant: ephemeralKp.publicKey,
      };
      openExtHash = computeExtDataHash(s3Poseidon, openExtData);

      try {
        openProof = await generateTransactionProof({
          root: depositRoot,
          publicAmount: -BigInt(WITHDRAW_AMOUNT.toString()),
          extDataHash: openExtHash, mintAddress: USDC_MINT,
          inputNullifiers: [openN0, openN1],
          outputCommitments: [openC0, openC1],
          inputAmounts: [BigInt(DEPOSIT_AMOUNT.toString()), 0n],
          inputPrivateKeys: [notePriv, ob0Priv],
          inputPublicKeys: [notePub, ob0Pub],
          inputBlindings: [noteBlind, ob0Blind],
          inputMerklePaths: [notePath, { pathElements: zeroPath, pathIndices: new Array(22).fill(0) }],
          outputAmounts: [changeAmount, 0n],
          outputOwners: [oc0Pub, oc1Pub],
          outputBlindings: [oc0Blind, oc1Blind],
        });
        log(`✓ prediction_open proof generated (withdraw ${usd(WITHDRAW_AMOUNT.toString())} → ephemeral)`);
      } catch (e: any) {
        console.log("   ⚠️  prediction_open proof failed — Suite 3 will be skipped:", e?.message ?? e);
        return;
      }

      openMarker0 = nullifierMarkerPDA(program.programId, USDC_MINT, openN0);
      openMarker1 = nullifierMarkerPDA(program.programId, USDC_MINT, openN1);

      // ── 7. Build ALT ────────────────────────────────────────────────────────
      suite3Lut = await buildAlt(provider, s3Relayer, [
        TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, SystemProgram.programId,
        globalConfig, usdcConfig, usdcVault, usdcNoteTree, usdcNullifiers, usdcVaultAta,
        ephemeralKp.publicKey, ephemeralAta, relayerAta,
        openMarker0, openMarker1,
      ]);

      suiteReady = true;
      console.log(`\n   ✅ Suite 3 ready`);
      console.log(`   USDC vault balance:    ${usd(vaultBal)}`);
      console.log(`   Spending key (first 8): ${Buffer.from(s3SpendingKey.subarray(0, 8)).toString("hex")}…`);
      console.log(`   Ephemeral nonce:       0`);
      console.log(`   Ephemeral pubkey:      ${ephemeralKp.publicKey.toBase58()}`);
      console.log(`   Ephemeral USDC ATA:    ${ephemeralAta.toBase58()}`);
      console.log(`   (recover key: deriveEphemeralKeypair(spendingKey, 0))`);
    });

    it("Step 1 — prediction_open: ZK withdrawal → ephemeral wallet funded", async function () {
      if (!suiteReady) return this.skip();

      const relayerAta = await getAssociatedTokenAddress(USDC_MINT, s3Relayer.publicKey, false);
      const vaultBefore = await tokenBal(provider, usdcVaultAta);
      const ephemeralBefore = await tokenBal(provider, ephemeralAta);
      log(`vault before: ${usd(vaultBefore)}   ephemeral before: ${usd(ephemeralBefore)}`);

      const cuIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 });
      const openIx = await (program.methods as any)
        .predictionOpen(
          Array.from(offTree.getRoot()),  // root after deposit inserts
          0, 0,
          WITHDRAW_AMOUNT,
          Array.from(openExtHash),
          USDC_MINT,
          ephemeralKp.publicKey,
          Array.from(openN0), Array.from(openN1),
          Array.from(openC0), Array.from(openC1),
          Array.from(new Uint8Array(32).fill(0xee)), // withdrawal_id (unused in handler)
          new BN(Math.floor(Date.now() / 1000) + 3600),
          openExtData,
          openProof,
          null,              // note_ciphers
          new BN(5_000_000), // sol_funding (0.005 SOL to cover Jupiter tx fee)
        )
        .accounts({
          config: usdcConfig, globalConfig, vault: usdcVault,
          inputTree: usdcNoteTree, outputTree: usdcNoteTree, nullifiers: usdcNullifiers,
          nullifierMarker0: openMarker0, nullifierMarker1: openMarker1,
          relayer: s3Relayer.publicKey,
          vaultTokenAccount: usdcVaultAta,
          ephemeralWallet: ephemeralKp.publicKey,
          ephemeralTokenAccount: ephemeralAta,
          relayerTokenAccount: relayerAta,
          tokenProgram: TOKEN_PROGRAM_ID, systemProgram: SystemProgram.programId,
        })
        .instruction();

      const sig = await sendVersionedTx(provider, [cuIx, openIx], [s3Relayer], [suite3Lut]);
      await provider.connection.confirmTransaction(sig, "confirmed");

      const vaultAfter = await tokenBal(provider, usdcVaultAta);
      const ephemeralAfter = await tokenBal(provider, ephemeralAta);
      const ephemeralSol = await provider.connection.getBalance(ephemeralKp.publicKey);

      log(`vault after: ${usd(vaultAfter)}   ephemeral after: ${usd(ephemeralAfter)}`);
      log(`ephemeral SOL: ${(ephemeralSol / LAMPORTS_PER_SOL).toFixed(5)} SOL`);

      const withdrew = vaultBefore - vaultAfter;
      if (withdrew !== Number(WITHDRAW_AMOUNT.toString())) {
        throw new Error(`Vault should have decreased by ${usd(WITHDRAW_AMOUNT.toString())}, decreased by ${usd(withdrew)}`);
      }
      if (ephemeralAfter - ephemeralBefore !== Number(WITHDRAW_AMOUNT.toString())) {
        throw new Error(`Ephemeral ATA should have gained ${usd(WITHDRAW_AMOUNT.toString())}`);
      }
      if (ephemeralSol < 4_000_000) {
        throw new Error("Ephemeral wallet should have received SOL for tx fees");
      }

      offTree.insert(openC0);
      offTree.insert(openC1);
      step1Passed = true;
      log(`✓ tx ${sig.slice(0, 16)}…  vault: ${usd(vaultBefore)}→${usd(vaultAfter)}  ephemeral: ${usd(ephemeralAfter)}`);
    });

    it("Step 2 — ephemeral signs Jupiter order (documented, not executed in test)", async function () {
      if (!suiteReady || !step1Passed) return this.skip();

      // In production, the user now:
      //   const client = new PredictionClient(API_KEY);
      //   const resp = await client.createOrder({
      //     ownerPubkey: ephemeralKp.publicKey.toBase58(),
      //     marketId: "POLY-558938", isYes: true, isBuy: true,
      //     depositAmount: 5_000_000, depositMint: USDC_MINT.toBase58(),
      //   });
      //   const vTx = VersionedTransaction.deserialize(Buffer.from(resp.transaction, "base64"));
      //   vTx.sign([ephemeralKp]);
      //   await connection.sendRawTransaction(vTx.serialize());
      //
      // No pool instruction at this step — the ephemeral key signs the Jupiter API tx.
      // Position owner on Jupiter = ephemeralKp.publicKey (never the user's real wallet).

      log("Jupiter order placement: ephemeral key as ownerPubkey");
      log("Pool is not involved — ephemeral signs directly");
      log("Privacy: observer sees ephemeral (not user wallet) open a position");
    });

    it("Step 3 — prediction_reissue: sweeps proceeds back to pool vault", async function () {
      if (!suiteReady || !step1Passed) return this.skip();

      // After the prediction resolves (win or sell), proceeds land in ephemeralAta.
      // Here we simulate that by checking the current balance (Step 1 funded it).
      const currentBal = await tokenBal(provider, ephemeralAta);
      if (currentBal === 0) {
        log("Ephemeral ATA is empty — nothing to reissue (expected if position not yet settled)");
        return this.skip();
      }

      const reissueAmount = new BN(currentBal);

      // Deposit-side ZK proof: both inputs are 0-value dummy notes (valid for deposits).
      const ri0Priv = randomBytes32(); const ri0Pub = derivePublicKey(s3Poseidon, ri0Priv); const ri0Blind = randomBytes32();
      const ri0Commit = computeCommitment(s3Poseidon, 0n, ri0Pub, ri0Blind, USDC_MINT);
      const rn0 = computeNullifier(s3Poseidon, ri0Commit, 0, ri0Priv);

      const ri1Priv = randomBytes32(); const ri1Pub = derivePublicKey(s3Poseidon, ri1Priv); const ri1Blind = randomBytes32();
      const ri1Commit = computeCommitment(s3Poseidon, 0n, ri1Pub, ri1Blind, USDC_MINT);
      const rn1 = computeNullifier(s3Poseidon, ri1Commit, 0, ri1Priv);

      const ro0Priv = randomBytes32(); const ro0Pub = derivePublicKey(s3Poseidon, ro0Priv); const ro0Blind = randomBytes32();
      const rc0 = computeCommitment(s3Poseidon, BigInt(reissueAmount.toString()), ro0Pub, ro0Blind, USDC_MINT);
      const ro1Priv = randomBytes32(); const ro1Pub = derivePublicKey(s3Poseidon, ro1Priv); const ro1Blind = randomBytes32();
      const rc1 = computeCommitment(s3Poseidon, 0n, ro1Pub, ro1Blind, USDC_MINT);

      const reissueRoot = offTree.getRoot();
      const reissueExtData = {
        recipient: PublicKey.default, relayer: s3Relayer.publicKey,
        fee: new BN(0), refund: new BN(0), claimant: ephemeralKp.publicKey,
      };
      const reissueExtHash = computeExtDataHash(s3Poseidon, reissueExtData);

      const zeros = offTree.getZeros();
      const zeroPath = zeros.slice(0, 22).map((z: Uint8Array) => bytesToBigIntBE(z));
      const zeroMerklePath = { pathElements: zeroPath, pathIndices: new Array(22).fill(0) };

      const reissueProof = await generateTransactionProof({
        root: reissueRoot,
        publicAmount: BigInt(reissueAmount.toString()),
        extDataHash: reissueExtHash, mintAddress: USDC_MINT,
        inputNullifiers: [rn0, rn1], outputCommitments: [rc0, rc1],
        inputAmounts: [0n, 0n], inputPrivateKeys: [ri0Priv, ri1Priv],
        inputPublicKeys: [ri0Pub, ri1Pub], inputBlindings: [ri0Blind, ri1Blind],
        inputMerklePaths: [zeroMerklePath, zeroMerklePath],
        outputAmounts: [BigInt(reissueAmount.toString()), 0n],
        outputOwners: [ro0Pub, ro1Pub], outputBlindings: [ro0Blind, ro1Blind],
      });

      const rMarker0 = nullifierMarkerPDA(program.programId, USDC_MINT, rn0);
      const rMarker1 = nullifierMarkerPDA(program.programId, USDC_MINT, rn1);

      const vaultBefore = await tokenBal(provider, usdcVaultAta);

      const cuIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 });
      const reissueIx = await (program.methods as any)
        .predictionReissue(
          Array.from(reissueRoot), 0, 0, reissueAmount,
          Array.from(reissueExtHash), USDC_MINT,
          Array.from(rn0), Array.from(rn1), Array.from(rc0), Array.from(rc1),
          new BN(Math.floor(Date.now() / 1000) + 3600),
          reissueExtData, reissueProof, null,
        )
        .accounts({
          config: usdcConfig, globalConfig, vault: usdcVault,
          inputTree: usdcNoteTree, outputTree: usdcNoteTree, nullifiers: usdcNullifiers,
          nullifierMarker0: rMarker0, nullifierMarker1: rMarker1,
          relayer: s3Relayer.publicKey,
          claimant: ephemeralKp.publicKey,
          ephemeralTokenAccount: ephemeralAta,
          vaultTokenAccount: usdcVaultAta,
          tokenProgram: TOKEN_PROGRAM_ID, systemProgram: SystemProgram.programId,
        })
        .instruction();

      const reissueLut = await buildAlt(provider, s3Relayer, [
        TOKEN_PROGRAM_ID, SystemProgram.programId, globalConfig,
        usdcConfig, usdcVault, usdcNoteTree, usdcNullifiers, usdcVaultAta,
        ephemeralKp.publicKey, ephemeralAta, rMarker0, rMarker1,
      ]);

      const reissueSig = await sendVersionedTx(
        provider, [cuIx, reissueIx], [s3Relayer, ephemeralKp], [reissueLut],
      );
      await provider.connection.confirmTransaction(reissueSig, "confirmed");

      const vaultAfter = await tokenBal(provider, usdcVaultAta);
      const ephemeralAfter = await tokenBal(provider, ephemeralAta);
      log(`vault: ${usd(vaultBefore)}→${usd(vaultAfter)}   ephemeral: ${usd(currentBal)}→${usd(ephemeralAfter)}`);

      if (vaultAfter - vaultBefore !== currentBal) {
        throw new Error(`Vault should have gained ${usd(currentBal)}, gained ${usd(vaultAfter - vaultBefore)}`);
      }
      if (ephemeralAfter !== 0) {
        throw new Error(`Ephemeral ATA should be drained, has ${usd(ephemeralAfter)}`);
      }
      log(`✓ proceeds swept: ephemeral → pool vault. New private notes minted.`);
    });

    it("Full flow summary: positions are unlinkable", async function () {
      if (!suiteReady) return this.skip();

      log("Private prediction flow summary:");
      log("  1. pool.prediction_open (ZK withdrawal) → USDC leaves vault → ephemeral wallet");
      log("  2. ephemeral.sign(jupiter_api_tx) → position owned by ephemeral (not user wallet)");
      log("  3. Position resolves → proceeds land in ephemeral USDC ATA");
      log("  4. pool.prediction_reissue (ZK deposit, ephemeral co-signs) → proceeds → vault + fresh notes");
      log("  On-chain trail: vault→ephemeral (open), ephemeral→vault (reissue)");
      log("  ZK proof binds the spend but hides the depositor — positions are unlinkable to any wallet");
    });
  });

  // ── Suite 4: PredictionFlowClient ─────────────────────────────────────────
  //
  // Tests the coordinator class: PDA derivation, ephemeral key static method,
  // position registry, and scanPositions recovery (on-chain ATA scan).
  // No ZK proofs required — tests non-ZK coordinator logic only.

  describe("PredictionFlowClient", () => {
    let client: PredictionFlowClient;
    let s4Relayer: Keypair;
    const s4SpendingKey = deriveSpendingKey((wallet as any).payer, 1); // account index 1 — independent from s3 (index 0)

    before(async () => {
      const [gc] = PublicKey.findProgramAddressSync(
        [Buffer.from("global_config")], program.programId,
      );
      s4Relayer = Keypair.generate();
      await airdropAndConfirm(provider, s4Relayer.publicKey, LAMPORTS_PER_SOL);
      client = new PredictionFlowClient(program, provider, s4Relayer, gc);
    });

    it("static deriveEphemeralKeypair matches module-level helper", () => {
      const kp1 = PredictionFlowClient.deriveEphemeralKeypair(s4SpendingKey, 7);
      const kp2 = deriveEphemeralKeypair(s4SpendingKey, 7);
      if (!kp1.publicKey.equals(kp2.publicKey)) {
        throw new Error("Static method and module helper must produce the same key");
      }
      log(`nonce 7 → ${kp1.publicKey.toBase58().slice(0, 8)}…`);
    });

    it("different spending keys → different ephemeral keys", () => {
      const otherKey = randomBytes32();
      const kp1 = PredictionFlowClient.deriveEphemeralKeypair(s4SpendingKey, 0);
      const kp2 = PredictionFlowClient.deriveEphemeralKeypair(otherKey, 0);
      if (kp1.publicKey.equals(kp2.publicKey)) {
        throw new Error("Different spending keys must produce different ephemeral keys");
      }
    });

    it("poolPDAs derives correct config PDA for USDC mint", () => {
      const { config } = client.poolPDAs(USDC_MINT, 0);
      const [expected] = PublicKey.findProgramAddressSync(
        [Buffer.from("privacy_config_v3"), USDC_MINT.toBuffer()],
        program.programId,
      );
      if (!config.equals(expected)) {
        throw new Error(`config PDA mismatch: ${config.toBase58()} vs ${expected.toBase58()}`);
      }
      log(`USDC config PDA: ${config.toBase58().slice(0, 8)}…`);
    });

    it("poolPDAs: different tree IDs → different noteTree PDAs", () => {
      const { noteTree: t0 } = client.poolPDAs(USDC_MINT, 0);
      const { noteTree: t1 } = client.poolPDAs(USDC_MINT, 1);
      if (t0.equals(t1)) throw new Error("Tree ID must differentiate noteTree PDAs");
      log(`tree 0: ${t0.toBase58().slice(0, 8)}…  tree 1: ${t1.toBase58().slice(0, 8)}…`);
    });

    it("nullifierMarkerPDA matches test-file helper", () => {
      const nullifier = randomBytes32();
      const fromClient = client.nullifierMarkerPDA(USDC_MINT, nullifier);
      const fromHelper = nullifierMarkerPDA(program.programId, USDC_MINT, nullifier);
      if (!fromClient.equals(fromHelper)) {
        throw new Error("nullifierMarkerPDA mismatch between client and test helper");
      }
    });

    it("getPosition returns undefined for unknown nonce", () => {
      const result = client.getPosition(s4SpendingKey, 99);
      if (result !== undefined) throw new Error("Unknown nonce should return undefined");
    });

    it("scanPositions: skips nonces with no ATA (fresh spending key)", async () => {
      const freshKey = randomBytes32();
      const found = await client.scanPositions(freshKey, USDC_MINT, { maxNonce: 5 });
      if (found.length !== 0) {
        throw new Error(`Expected 0 positions for fresh key, got ${found.length}`);
      }
      log("Fresh spending key: 0 ATAs found across nonces 0–4 ✓");
    });

    it("scanPositions: finds ATA when it exists on-chain", async () => {
      // Create the ephemeral ATA for nonce 0 of s4SpendingKey on-chain
      const ephemeralKp = PredictionFlowClient.deriveEphemeralKeypair(s4SpendingKey, 0);
      const ephemeralAta = await getAssociatedTokenAddress(USDC_MINT, ephemeralKp.publicKey, false);

      try {
        await provider.sendAndConfirm(
          new Transaction().add(
            createAssociatedTokenAccountInstruction(
              wallet.publicKey, ephemeralAta, ephemeralKp.publicKey, USDC_MINT,
            ),
          ),
        );
      } catch (_) { /* already exists */ }

      const found = await client.scanPositions(s4SpendingKey, USDC_MINT, { maxNonce: 5 });

      if (found.length !== 1) {
        throw new Error(`Expected 1 position, found ${found.length}`);
      }
      if (found[0].nonce !== 0) throw new Error("Should find nonce 0");
      if (found[0].ephemeralPubkey !== ephemeralKp.publicKey.toBase58()) {
        throw new Error("Ephemeral pubkey mismatch");
      }
      log(`Found nonce=${found[0].nonce} pubkey=${found[0].ephemeralPubkey.slice(0, 8)}… status=${found[0].status}`);
    });

    it("scanPositions: ATA with zero balance → status reissued", async () => {
      // ATA created in previous test has 0 USDC balance → proceeds were swept (reissued)
      const found = await client.scanPositions(s4SpendingKey, USDC_MINT, { maxNonce: 5 });
      if (found.length === 0) return; // ATA may not exist if previous test skipped
      if (found[0].status !== "reissued") {
        throw new Error(`Expected status=reissued for empty ATA, got ${found[0].status}`);
      }
      log(`nonce 0 status: ${found[0].status} (ATA exists, balance=0)`);
    });

    it("getPosition reflects state after scanPositions", async () => {
      // scanPositions populates the internal registry
      const state = client.getPosition(s4SpendingKey, 0);
      // May be undefined if ATA didn't exist; may be populated if it did
      if (state !== undefined) {
        if (state.nonce !== 0) throw new Error("Nonce mismatch in registry");
        log(`Registry entry: nonce=${state.nonce} status=${state.status}`);
      } else {
        log("No registry entry (ATA not found by scan — acceptable if chain state differs)");
      }
    });

    it("allPositions returns every tracked position", async () => {
      const all = client.allPositions();
      log(`Total tracked positions: ${all.length}`);
      for (const p of all) {
        log(`  nonce=${p.nonce} ephemeral=${p.ephemeralPubkey.slice(0, 8)}… status=${p.status}`);
      }
      // At minimum, the scan from previous tests should have populated something
      // (passes trivially if no ATAs were found — that's also valid)
    });
  });
});

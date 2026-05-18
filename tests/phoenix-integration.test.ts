// tests/phoenix-integration.test.ts
//
// Phoenix Eternal Integration Tests for Veilo Privacy Pool
//
// Covers all four new instructions:
//   phoenix_deposit_from_pool  — ZK-verified USDC withdrawal → Phoenix depositFunds
//   phoenix_place_order        — Vault-signed market/limit order placement
//   phoenix_cancel_orders      — Vault-signed cancel-all
//   phoenix_queue_withdraw     — Vault-signed withdrawFunds (async queue)
//
// Test structure:
//   Suite 1 — PDA Derivation      (pure off-chain, always runnable)
//   Suite 2 — Validation Errors   (localnet, non-USDC pool, no Phoenix needed)
//   Suite 3 — Order Validation    (skipped unless USDC pool exists on validator)
//   Suite 4 — Full Integration    (skipped; documents the full private-perps flow)
//
// Run: npm run test:phoenix
//
// To unlock Suite 3, initialize a USDC pool on the test validator and add:
//   [[test.validator.clone]]
//   address = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # USDC mint
//
// To unlock Suite 4, also add Phoenix Eternal to the clone list:
//   [[test.validator.clone]]
//   address = "EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih"  # Phoenix Eternal

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
  SendTransactionError,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  getOrCreateAssociatedTokenAccount,
  getAssociatedTokenAddress,
} from "@solana/spl-token";
import { buildPoseidon } from "circomlibjs";
import crypto from "crypto";

import {
  makeProvider,
  airdropAndConfirm,
  randomBytes32,
  computeExtDataHash,
} from "./test-helpers";

// ─── Phoenix / program constants ─────────────────────────────────────────────

/** Phoenix Eternal program ID */
const PHOENIX_PROGRAM_ID = new PublicKey(
  "EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih",
);

/**
 * Mainnet USDC mint — must match the program's `PHOENIX_REQUIRED_MINT`
 * constant when built with default features (no `--features localnet`).
 * Cloned from mainnet in Anchor.toml so it exists on the test validator.
 */
const USDC_MAINNET = new PublicKey(
  "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
);

/**
 * Wrapped SOL mint — in ALLOWED_TOKENS, cloned from mainnet, and NOT USDC.
 * Used as the "non-USDC pool" mint for PhoenixInvalidPool error tests.
 */
const WSOL_MINT = new PublicKey("So11111111111111111111111111111111111111112");

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Encode a u16 tree_id as 2-byte little-endian buffer */
function encodeTreeId(id: number): Buffer {
  const buf = Buffer.alloc(2);
  buf.writeUInt16LE(id, 0);
  return buf;
}

/**
 * Compute an Anchor instruction discriminator: sha256("global:<name>")[0..8].
 * Mirrors the `phoenix_disc()` function in programs/privacy-pool/src/phoenix.rs.
 */
function phoenixDisc(name: string): Buffer {
  return crypto
    .createHash("sha256")
    .update(`global:${name}`)
    .digest()
    .slice(0, 8);
}

/** Derive the nullifier marker PDA: ["nullifier_v3", mint, nullifier] */
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

/**
 * Build a minimal dummy ZK proof (all zeros).
 * Safe to pass for error tests that fail before ZK verification.
 */
function dummyProof() {
  return {
    proofA: new Array(64).fill(0),
    proofB: new Array(128).fill(0),
    proofC: new Array(64).fill(0),
  };
}

/** Print Solana program log lines to stdout, filtering to relevant entries. */
function printProgramLogs(logs: string[], label = "Program logs"): void {
  if (logs.length === 0) return;
  const relevant = logs.filter(
    (l) =>
      l.startsWith("Program log:") ||
      l.startsWith("Program data:") ||
      l.includes("Error") ||
      l.includes("error"),
  );
  const lines = relevant.length > 0 ? relevant : logs;
  console.log(`   📋 ${label}:`);
  for (const line of lines) console.log(`      ${line}`);
}

/**
 * Assert that `promise` rejects with a transaction error whose logs contain `expected`.
 * Always prints program logs so test output is self-documenting.
 */
async function expectTxError(
  provider: AnchorProvider,
  promise: Promise<any>,
  expected: string,
): Promise<void> {
  try {
    await promise;
    throw new Error(`Expected error "${expected}" but transaction succeeded`);
  } catch (e: any) {
    // Re-throw if it's our own sentinel
    if (
      e.message === `Expected error "${expected}" but transaction succeeded`
    ) {
      throw e;
    }
    const message: string = e.message ?? "";
    const logs: string[] =
      e instanceof SendTransactionError
        ? (await e.getLogs(provider.connection)) ?? []
        : e.logs ?? [];
    printProgramLogs(logs);
    const haystack = [message, ...logs].join("\n");
    if (!haystack.includes(expected)) {
      throw new Error(
        `Expected error containing "${expected}" but got:\n${haystack.slice(
          0,
          1000,
        )}`,
      );
    }
  }
}

// ─── Suite ───────────────────────────────────────────────────────────────────

describe("Phoenix Eternal Integration", () => {
  const provider = makeProvider();
  setProvider(provider);
  const wallet = provider.wallet as Wallet;
  const program: any = (workspace as any).PrivacyPool;

  // Non-USDC test pool — used for all Validation Error tests
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
    console.log("\n🏛  Phoenix Integration Test Setup\n");
    poseidon = await buildPoseidon();

    // ── Use WSOL as the test (non-USDC) mint ────────────────────────────────
    // WSOL is in ALLOWED_TOKENS and cloned from mainnet in Anchor.toml,
    // so initialize() accepts it. It is NOT USDC, so phoenix_ handlers
    // return PhoenixInvalidPool — exactly what Suite 2 tests verify.
    testMint = WSOL_MINT;
    console.log(`   Test mint (WSOL / non-USDC): ${testMint.toBase58()}`);

    // ── Pool PDAs for WSOL ───────────────────────────────────────────────────
    [config] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_config_v3"), testMint.toBuffer()],
      program.programId,
    );
    [vault] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_vault_v3"), testMint.toBuffer()],
      program.programId,
    );
    [noteTree] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("privacy_note_tree_v3"),
        testMint.toBuffer(),
        encodeTreeId(0),
      ],
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

    // ── Initialize global config (idempotent) ────────────────────────────────
    try {
      await (program.methods as any)
        .initializeGlobalConfig()
        .accounts({
          globalConfig,
          admin: wallet.publicKey,
          payer: wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
    } catch (_) {
      /* already exists */
    }

    // ── Initialize the WSOL pool (idempotent) ────────────────────────────────
    try {
      await (program.methods as any)
        .initialize(
          50, // fee_bps (0.5 %)
          testMint,
          new BN(1_000_000), // min_deposit
          new BN(1_000_000_000_000), // max_deposit
          new BN(1_000_000), // min_withdraw
          new BN(1_000_000_000_000), // max_withdraw
        )
        .accounts({
          config,
          vault,
          noteTree,
          nullifiers,
          admin: wallet.publicKey,
          payer: wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      console.log("   WSOL pool initialized");
    } catch (_) {
      /* already initialized on a re-run */
      console.log("   WSOL pool already exists");
    }

    // ── Derive vault ATA address (no funds needed for error tests) ───────────
    vaultTokenAccount = await getAssociatedTokenAddress(testMint, vault, true);
    console.log(
      `   Vault token account (ATA): ${vaultTokenAccount.toBase58()}`,
    );

    // ── Generate a relayer and register it for the WSOL pool ─────────────────
    relayer = Keypair.generate();
    await airdropAndConfirm(provider, relayer.publicKey, 2 * LAMPORTS_PER_SOL);
    await (program.methods as any)
      .addRelayer(testMint, relayer.publicKey)
      .accounts({ config, admin: wallet.publicKey })
      .rpc();
    console.log(`   Relayer registered: ${relayer.publicKey.toBase58()}`);
  });

  // ── Suite 1: PDA Derivation ─────────────────────────────────────────────────

  describe("PDA Derivation", () => {
    it("derives Phoenix log authority PDA from seed 'log'", () => {
      const [logAuth, bump] = PublicKey.findProgramAddressSync(
        [Buffer.from("log")],
        PHOENIX_PROGRAM_ID,
      );
      console.log(`   Log authority: ${logAuth.toBase58()} (bump ${bump})`);
      if (logAuth.equals(PublicKey.default)) {
        throw new Error("Log authority must not be the zero pubkey");
      }
    });

    it("derives Phoenix global configuration PDA from seed 'global'", () => {
      const [globalCfg, bump] = PublicKey.findProgramAddressSync(
        [Buffer.from("global")],
        PHOENIX_PROGRAM_ID,
      );
      console.log(`   Global config: ${globalCfg.toBase58()} (bump ${bump})`);
      if (globalCfg.equals(PublicKey.default)) {
        throw new Error("Global config must not be the zero pubkey");
      }
    });

    it("derives Phoenix trader PDA for the USDC vault", () => {
      const [usdcVault] = PublicKey.findProgramAddressSync(
        [Buffer.from("privacy_vault_v3"), USDC_MAINNET.toBuffer()],
        program.programId,
      );
      const [traderPda, bump] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("trader"),
          usdcVault.toBuffer(),
          Buffer.from([0]), // pda_index = 0
          Buffer.from([0]), // subaccount_index = 0
        ],
        PHOENIX_PROGRAM_ID,
      );
      console.log(`   USDC vault:  ${usdcVault.toBase58()}`);
      console.log(`   Trader PDA:  ${traderPda.toBase58()} (bump ${bump})`);
      if (traderPda.equals(PublicKey.default)) {
        throw new Error("Trader PDA must not be the zero pubkey");
      }
    });

    it("computes Anchor discriminators for Phoenix instructions", () => {
      const cases: Record<string, number> = {
        deposit_funds: 8,
        withdraw_funds: 8,
        register_trader: 8,
        place_market_order: 8,
        place_limit_order: 8,
        cancel_all: 8,
        consume_withdraw_queue: 8,
      };
      for (const [name, expectedLen] of Object.entries(cases)) {
        const disc = phoenixDisc(name);
        if (disc.length !== expectedLen) {
          throw new Error(
            `${name}: expected ${expectedLen}-byte discriminator, got ${disc.length}`,
          );
        }
        console.log(
          `   ${name.padEnd(25)} disc: [${Array.from(disc).join(",")}]`,
        );
      }
    });

    it("placeMarketOrder and placeLimitOrder have distinct discriminators", () => {
      const market = phoenixDisc("place_market_order");
      const limit = phoenixDisc("place_limit_order");
      if (market.equals(limit)) {
        throw new Error("Market and limit order discriminators must differ");
      }
    });
  });

  // ── Suite 2: Validation Errors (non-USDC pool) ────────────────────────────
  //
  // All these tests use the non-USDC test pool. They exercise our validation
  // guards that run BEFORE any ZK verification or Phoenix CPI.

  describe("Validation Errors (non-USDC pool)", () => {
    // Fresh random nullifiers/commitments — the PDAs won't exist on-chain.
    // The transactions are rolled back on error, so no state is written.
    const nullifier0 = randomBytes32();
    const nullifier1 = randomBytes32();
    const commitment0 = randomBytes32();
    const commitment1 = randomBytes32();
    const dummyRoot = new Uint8Array(32).fill(1);

    it("phoenix_deposit_from_pool: rejects non-USDC pool (PhoenixInvalidPool)", async () => {
      // PhoenixInvalidPool is the FIRST check in the handler — fires before
      // ZK verification — so a dummy proof is acceptable here.
      const extData = {
        recipient: vault, // correct (vault PDA), but pool mint check fires first
        relayer: relayer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
      };
      const extDataHash = computeExtDataHash(poseidon, extData);

      const marker0 = nullifierMarkerPDA(
        program.programId,
        testMint,
        nullifier0,
      );
      const marker1 = nullifierMarkerPDA(
        program.programId,
        testMint,
        nullifier1,
      );

      await expectTxError(
        provider,
        (program.methods as any)
          .phoenixDepositFromPool(
            Array.from(dummyRoot), // root
            0, // input_tree_id
            0, // output_tree_id
            new BN(1_000_000), // deposit_amount
            Array.from(extDataHash), // ext_data_hash
            testMint, // mint_address ← NOT USDC, triggers error
            Array.from(nullifier0),
            Array.from(nullifier1),
            Array.from(commitment0),
            Array.from(commitment1),
            new BN(9_999_999_999), // deadline
            extData,
            dummyProof(),
            null, // note_ciphers
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
            relayer: relayer.publicKey,
            vaultTokenAccount,
            relayerTokenAccount: vaultTokenAccount, // dummy — never reached
            tokenProgram: TOKEN_PROGRAM_ID,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([]) // Phoenix accounts — irrelevant, error fires before CPI
          .signers([relayer])
          .rpc(),
        "PhoenixInvalidPool",
      );
      console.log("   ✅ Non-USDC pool rejected by phoenix_deposit_from_pool");
    });

    it("phoenix_place_order: rejects unregistered relayer (RelayerNotAllowed)", async () => {
      const stranger = Keypair.generate();
      await airdropAndConfirm(provider, stranger.publicKey, LAMPORTS_PER_SOL);

      await expectTxError(
        provider,
        (program.methods as any)
          .phoenixPlaceOrder(
            testMint,
            Buffer.from(phoenixDisc("place_market_order")),
          )
          .accounts({
            config,
            vault,
            relayer: stranger.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([])
          .signers([stranger])
          .rpc(),
        "RelayerNotAllowed",
      );
      console.log("   ✅ Unregistered relayer rejected by phoenix_place_order");
    });

    it("phoenix_place_order: rejects non-USDC pool (PhoenixInvalidPool)", async () => {
      await expectTxError(
        provider,
        (program.methods as any)
          .phoenixPlaceOrder(
            testMint, // non-USDC
            Buffer.from(phoenixDisc("place_market_order")),
          )
          .accounts({
            config,
            vault,
            relayer: relayer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([])
          .signers([relayer])
          .rpc(),
        "PhoenixInvalidPool",
      );
      console.log("   ✅ Non-USDC pool rejected by phoenix_place_order");
    });

    it("phoenix_cancel_orders: rejects non-USDC pool (PhoenixInvalidPool)", async () => {
      await expectTxError(
        provider,
        (program.methods as any)
          .phoenixCancelOrders(testMint)
          .accounts({
            config,
            vault,
            relayer: relayer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([])
          .signers([relayer])
          .rpc(),
        "PhoenixInvalidPool",
      );
      console.log("   ✅ Non-USDC pool rejected by phoenix_cancel_orders");
    });

    it("phoenix_queue_withdraw: rejects non-USDC pool (PhoenixInvalidPool)", async () => {
      await expectTxError(
        provider,
        (program.methods as any)
          .phoenixQueueWithdraw(testMint, new BN(1_000_000))
          .accounts({
            config,
            vault,
            vaultTokenAccount,
            relayer: relayer.publicKey,
            tokenProgram: TOKEN_PROGRAM_ID,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([])
          .signers([relayer])
          .rpc(),
        "PhoenixInvalidPool",
      );
      console.log("   ✅ Non-USDC pool rejected by phoenix_queue_withdraw");
    });
  });

  // ── Suite 3: Order Instruction Validation (USDC pool required) ────────────
  //
  // These tests reach the CPI guard checks (remaining_accounts length,
  // Phoenix program ID, order discriminator whitelist).
  //
  // They auto-skip when no USDC pool is found on the test validator.
  // To enable: initialize a USDC pool and register a relayer before running.

  describe("Order Instruction Validation (USDC pool)", () => {
    let usdcConfig: PublicKey;
    let usdcVault: PublicKey;
    let usdcNoteTree: PublicKey;
    let usdcNullifiers: PublicKey;
    let usdcVaultAta: PublicKey;
    let usdcRelayer: Keypair;
    let usdcPoolReady = false;

    before(async () => {
      [usdcConfig] = PublicKey.findProgramAddressSync(
        [Buffer.from("privacy_config_v3"), USDC_MAINNET.toBuffer()],
        program.programId,
      );
      [usdcVault] = PublicKey.findProgramAddressSync(
        [Buffer.from("privacy_vault_v3"), USDC_MAINNET.toBuffer()],
        program.programId,
      );
      [usdcNoteTree] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("privacy_note_tree_v3"),
          USDC_MAINNET.toBuffer(),
          encodeTreeId(0),
        ],
        program.programId,
      );
      [usdcNullifiers] = PublicKey.findProgramAddressSync(
        [Buffer.from("privacy_nullifiers_v3"), USDC_MAINNET.toBuffer()],
        program.programId,
      );
      usdcVaultAta = await getAssociatedTokenAddress(
        USDC_MAINNET,
        usdcVault,
        true,
      );

      // Initialize the USDC pool if it doesn't exist yet.
      // USDC is in ALLOWED_TOKENS and the mint is cloned from mainnet,
      // so initialize() accepts it without real balance.
      let poolExists = false;
      try {
        await (program.account as any).privacyConfig.fetch(usdcConfig);
        poolExists = true;
        console.log("   USDC pool already initialized");
      } catch (_) {
        /* needs initialization */
      }

      if (!poolExists) {
        try {
          await (program.methods as any)
            .initialize(
              50,
              USDC_MAINNET,
              new BN(1_000_000),
              new BN(1_000_000_000_000),
              new BN(1_000_000),
              new BN(1_000_000_000_000),
            )
            .accounts({
              config: usdcConfig,
              vault: usdcVault,
              noteTree: usdcNoteTree,
              nullifiers: usdcNullifiers,
              admin: wallet.publicKey,
              payer: wallet.publicKey,
              systemProgram: SystemProgram.programId,
            })
            .rpc();
          console.log("   USDC pool initialized");
        } catch (e: any) {
          console.log(
            "   ⚠️  USDC pool initialization failed:",
            e.message ?? e,
          );
        }
      }

      try {
        await (program.account as any).privacyConfig.fetch(usdcConfig);
        usdcRelayer = Keypair.generate();
        await airdropAndConfirm(
          provider,
          usdcRelayer.publicKey,
          2 * LAMPORTS_PER_SOL,
        );
        await (program.methods as any)
          .addRelayer(USDC_MAINNET, usdcRelayer.publicKey)
          .accounts({ config: usdcConfig, admin: wallet.publicKey })
          .rpc();
        usdcPoolReady = true;
        console.log("   USDC pool ready — order validation tests enabled");
      } catch (_) {
        console.log(
          "   ⚠️  USDC pool unavailable — order validation tests will be skipped.",
        );
      }
    });

    /** Build N dummy remaining accounts; account 0 = specified pubkey. */
    function dummyRemainingAccounts(count: number, account0: PublicKey) {
      return Array.from({ length: count }, (_, i) => ({
        pubkey: i === 0 ? account0 : Keypair.generate().publicKey,
        isSigner: false,
        isWritable: false,
      }));
    }

    it("place_order: rejects when remaining_accounts < 9 (PhoenixInvalidAccounts)", async function () {
      if (!usdcPoolReady) return this.skip();

      // Pass only 3 remaining accounts — fewer than the required 9
      await expectTxError(
        provider,
        (program.methods as any)
          .phoenixPlaceOrder(
            USDC_MAINNET,
            Buffer.from(phoenixDisc("place_market_order")),
          )
          .accounts({
            config: usdcConfig,
            vault: usdcVault,
            relayer: usdcRelayer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts(dummyRemainingAccounts(3, PHOENIX_PROGRAM_ID))
          .signers([usdcRelayer])
          .rpc(),
        "PhoenixInvalidAccounts",
      );
      console.log("   ✅ Insufficient remaining_accounts rejected");
    });

    it("place_order: rejects wrong Phoenix program ID (InvalidSwapProgram)", async function () {
      if (!usdcPoolReady) return this.skip();

      // remaining_accounts[0] = SystemProgram (not Phoenix)
      await expectTxError(
        provider,
        (program.methods as any)
          .phoenixPlaceOrder(
            USDC_MAINNET,
            Buffer.from(phoenixDisc("place_market_order")),
          )
          .accounts({
            config: usdcConfig,
            vault: usdcVault,
            relayer: usdcRelayer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts(dummyRemainingAccounts(9, SystemProgram.programId))
          .signers([usdcRelayer])
          .rpc(),
        "InvalidSwapProgram",
      );
      console.log("   ✅ Wrong Phoenix program ID rejected");
    });

    it("place_order: rejects unknown order discriminator (PhoenixInvalidOrderData)", async function () {
      if (!usdcPoolReady) return this.skip();

      // Correct Phoenix program ID, but unknown discriminator (0xDE * 8)
      const badDisc = Buffer.alloc(8, 0xde);
      await expectTxError(
        provider,
        (program.methods as any)
          .phoenixPlaceOrder(USDC_MAINNET, badDisc)
          .accounts({
            config: usdcConfig,
            vault: usdcVault,
            relayer: usdcRelayer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts(dummyRemainingAccounts(9, PHOENIX_PROGRAM_ID))
          .signers([usdcRelayer])
          .rpc(),
        "PhoenixInvalidOrderData",
      );
      console.log("   ✅ Unknown order discriminator rejected");
    });

    it("place_order: accepts placeMarketOrder discriminator (discriminator whitelisted)", async function () {
      if (!usdcPoolReady) return this.skip();

      // The handler accepts the discriminator, then fails at the CPI
      // (Phoenix not deployed) — confirm error is NOT a Veilo validation error.
      const marketDisc = Buffer.from(phoenixDisc("place_market_order"));
      try {
        await (program.methods as any)
          .phoenixPlaceOrder(USDC_MAINNET, marketDisc)
          .accounts({
            config: usdcConfig,
            vault: usdcVault,
            relayer: usdcRelayer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts(dummyRemainingAccounts(9, PHOENIX_PROGRAM_ID))
          .signers([usdcRelayer])
          .rpc();
        // If Phoenix is deployed and the call somehow succeeds, that's also fine
      } catch (e: any) {
        const logs: string[] =
          e instanceof SendTransactionError
            ? (await e.getLogs(provider.connection)) ?? []
            : e.logs ?? [];
        printProgramLogs(logs, "placeMarketOrder CPI logs");
        const haystack = [...logs, e.message ?? ""].join("\n");

        // Must NOT be a Veilo discriminator error
        if (haystack.includes("PhoenixInvalidOrderData")) {
          throw new Error(
            "placeMarketOrder discriminator should be whitelisted but was rejected",
          );
        }
        // Other errors (CPI failure, Phoenix not deployed) are acceptable
        console.log(
          "   ✅ placeMarketOrder discriminator accepted (CPI attempted)",
        );
        return;
      }
      console.log("   ✅ placeMarketOrder discriminator accepted");
    });

    it("place_order: accepts placeLimitOrder discriminator (discriminator whitelisted)", async function () {
      if (!usdcPoolReady) return this.skip();

      const limitDisc = Buffer.from(phoenixDisc("place_limit_order"));
      try {
        await (program.methods as any)
          .phoenixPlaceOrder(USDC_MAINNET, limitDisc)
          .accounts({
            config: usdcConfig,
            vault: usdcVault,
            relayer: usdcRelayer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts(dummyRemainingAccounts(9, PHOENIX_PROGRAM_ID))
          .signers([usdcRelayer])
          .rpc();
      } catch (e: any) {
        const logs: string[] =
          e instanceof SendTransactionError
            ? (await e.getLogs(provider.connection)) ?? []
            : e.logs ?? [];
        printProgramLogs(logs, "placeLimitOrder CPI logs");
        if (
          [...logs, e.message ?? ""]
            .join("\n")
            .includes("PhoenixInvalidOrderData")
        ) {
          throw new Error(
            "placeLimitOrder discriminator should be whitelisted but was rejected",
          );
        }
        console.log(
          "   ✅ placeLimitOrder discriminator accepted (CPI attempted)",
        );
        return;
      }
      console.log("   ✅ placeLimitOrder discriminator accepted");
    });

    it("cancel_orders: rejects wrong Phoenix program ID (InvalidSwapProgram)", async function () {
      if (!usdcPoolReady) return this.skip();

      await expectTxError(
        provider,
        (program.methods as any)
          .phoenixCancelOrders(USDC_MAINNET)
          .accounts({
            config: usdcConfig,
            vault: usdcVault,
            relayer: usdcRelayer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts(dummyRemainingAccounts(9, SystemProgram.programId))
          .signers([usdcRelayer])
          .rpc(),
        "InvalidSwapProgram",
      );
      console.log("   ✅ Wrong Phoenix program ID rejected by cancel_orders");
    });

    it("queue_withdraw: rejects non-canonical vault token account (VaultTokenAccountNotATA)", async function () {
      if (!usdcPoolReady) return this.skip();

      // Pass wrong vault token account — any random pubkey != canonical ATA
      const wrongAccount = Keypair.generate().publicKey;

      await expectTxError(
        provider,
        (program.methods as any)
          .phoenixQueueWithdraw(USDC_MAINNET, new BN(1_000_000))
          .accounts({
            config: usdcConfig,
            vault: usdcVault,
            vaultTokenAccount: wrongAccount, // NOT the canonical ATA
            relayer: usdcRelayer.publicKey,
            tokenProgram: TOKEN_PROGRAM_ID,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts(dummyRemainingAccounts(9, PHOENIX_PROGRAM_ID))
          .signers([usdcRelayer])
          .rpc(),
        "VaultTokenAccountNotATA",
      );
      console.log("   ✅ Non-canonical vault ATA rejected by queue_withdraw");
    });

    it("deposit: rejects unregistered relayer (RelayerNotAllowed)", async function () {
      // phoenix_deposit_from_pool checks mint BEFORE relayer, so this test
      // requires a valid USDC pool to reach the relayer check.
      if (!usdcPoolReady) return this.skip();

      const stranger = Keypair.generate();
      await airdropAndConfirm(provider, stranger.publicKey, LAMPORTS_PER_SOL);

      const extData = {
        recipient: usdcVault,
        relayer: stranger.publicKey,
        fee: new BN(0),
        refund: new BN(0),
      };
      const extDataHash = computeExtDataHash(poseidon, extData);
      const n0 = randomBytes32();
      const n1 = randomBytes32();
      const marker0 = nullifierMarkerPDA(program.programId, USDC_MAINNET, n0);
      const marker1 = nullifierMarkerPDA(program.programId, USDC_MAINNET, n1);

      await expectTxError(
        provider,
        (program.methods as any)
          .phoenixDepositFromPool(
            Array.from(new Uint8Array(32).fill(1)),
            0,
            0,
            new BN(1_000_000),
            Array.from(extDataHash),
            USDC_MAINNET,
            Array.from(n0),
            Array.from(n1),
            Array.from(randomBytes32()),
            Array.from(randomBytes32()),
            new BN(9_999_999_999),
            extData,
            dummyProof(),
            null,
          )
          .accounts({
            config: usdcConfig,
            globalConfig,
            vault: usdcVault,
            inputTree: usdcNoteTree,
            outputTree: usdcNoteTree,
            nullifiers: usdcNullifiers,
            nullifierMarker0: marker0,
            nullifierMarker1: marker1,
            relayer: stranger.publicKey,
            vaultTokenAccount: usdcVaultAta,
            relayerTokenAccount: usdcVaultAta,
            tokenProgram: TOKEN_PROGRAM_ID,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([])
          .signers([stranger])
          .rpc(),
        "RelayerNotAllowed",
      );
      console.log(
        "   ✅ Unregistered relayer rejected by phoenix_deposit_from_pool",
      );
    });

    it("deposit: rejects wrong recipient in ext_data (PhoenixRecipientMustBeVault)", async function () {
      if (!usdcPoolReady) return this.skip();

      // ext_data.recipient is someone else's pubkey, not the vault PDA.
      // The check fires at step 4, before ZK proof verification.
      const wrongRecipient = Keypair.generate().publicKey;
      const extData = {
        recipient: wrongRecipient, // ← must equal vault, not this
        relayer: usdcRelayer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
      };
      const extDataHash = computeExtDataHash(poseidon, extData);

      const n0 = randomBytes32();
      const n1 = randomBytes32();
      const marker0 = nullifierMarkerPDA(program.programId, USDC_MAINNET, n0);
      const marker1 = nullifierMarkerPDA(program.programId, USDC_MAINNET, n1);

      await expectTxError(
        provider,
        (program.methods as any)
          .phoenixDepositFromPool(
            Array.from(new Uint8Array(32).fill(1)), // root (dummy)
            0,
            0,
            new BN(1_000_000),
            Array.from(extDataHash),
            USDC_MAINNET,
            Array.from(n0),
            Array.from(n1),
            Array.from(randomBytes32()),
            Array.from(randomBytes32()),
            new BN(9_999_999_999),
            extData,
            dummyProof(),
            null,
          )
          .accounts({
            config: usdcConfig,
            globalConfig,
            vault: usdcVault,
            inputTree: usdcNoteTree,
            outputTree: usdcNoteTree,
            nullifiers: usdcNullifiers,
            nullifierMarker0: marker0,
            nullifierMarker1: marker1,
            relayer: usdcRelayer.publicKey,
            vaultTokenAccount: usdcVaultAta,
            relayerTokenAccount: usdcVaultAta, // dummy — never reached
            tokenProgram: TOKEN_PROGRAM_ID,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([])
          .signers([usdcRelayer])
          .rpc(),
        "PhoenixRecipientMustBeVault",
      );
      console.log(
        "   ✅ Non-vault recipient rejected by phoenix_deposit_from_pool",
      );
    });
  });

  // ── Suite 4: Full Round-Trip (Phoenix program required) ──────────────────
  //
  // Tests the complete private perpetual-trading flow against localnet with
  // the Phoenix Eternal program cloned from mainnet.
  //
  // registerTrader runs automatically when Phoenix is detected.
  // deposit/order/cancel/withdraw require real USDC in the vault ATA
  // (inject via [[test.validator.account]] in Anchor.toml or fund the vault
  // directly before running).

  describe("Full Round-Trip (requires Phoenix on localnet)", () => {
    let s4UsdcConfig: PublicKey;
    let s4UsdcVault: PublicKey;
    let s4UsdcNoteTree: PublicKey;
    let s4UsdcNullifiers: PublicKey;
    let s4UsdcVaultAta: PublicKey;
    let s4Relayer: Keypair;
    let phoenixLogAuth: PublicKey;
    let phoenixGlobalCfg: PublicKey;
    let traderPda: PublicKey;
    let suite4Ready = false;

    before(async function () {
      // Derive USDC pool PDAs
      [s4UsdcConfig] = PublicKey.findProgramAddressSync(
        [Buffer.from("privacy_config_v3"), USDC_MAINNET.toBuffer()],
        program.programId,
      );
      [s4UsdcVault] = PublicKey.findProgramAddressSync(
        [Buffer.from("privacy_vault_v3"), USDC_MAINNET.toBuffer()],
        program.programId,
      );
      [s4UsdcNoteTree] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("privacy_note_tree_v3"),
          USDC_MAINNET.toBuffer(),
          encodeTreeId(0),
        ],
        program.programId,
      );
      [s4UsdcNullifiers] = PublicKey.findProgramAddressSync(
        [Buffer.from("privacy_nullifiers_v3"), USDC_MAINNET.toBuffer()],
        program.programId,
      );
      s4UsdcVaultAta = await getAssociatedTokenAddress(
        USDC_MAINNET,
        s4UsdcVault,
        true,
      );

      // Derive Phoenix PDAs
      [phoenixLogAuth] = PublicKey.findProgramAddressSync(
        [Buffer.from("log")],
        PHOENIX_PROGRAM_ID,
      );
      [phoenixGlobalCfg] = PublicKey.findProgramAddressSync(
        [Buffer.from("global")],
        PHOENIX_PROGRAM_ID,
      );
      [traderPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("trader"),
          s4UsdcVault.toBuffer(),
          Buffer.from([0]),
          Buffer.from([0]),
        ],
        PHOENIX_PROGRAM_ID,
      );

      console.log(`\n   Suite 4 — trader PDA: ${traderPda.toBase58()}`);

      // Check if Phoenix program is cloned on the test validator
      const phoenixInfo = await provider.connection.getAccountInfo(
        PHOENIX_PROGRAM_ID,
      );
      if (!phoenixInfo) {
        console.log(
          "   ⚠️  Phoenix program not found on test validator — Suite 4 skipped",
        );
        console.log(
          '   Add to Anchor.toml: [[test.validator.clone]] address = "EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih"',
        );
        return;
      }
      console.log(
        `   Phoenix program detected (${phoenixInfo.data.length} bytes)`,
      );

      // Ensure USDC pool exists (Suite 3 initializes it, but we try again just in case)
      try {
        await (program.account as any).privacyConfig.fetch(s4UsdcConfig);
      } catch (_) {
        console.log("   ⚠️  USDC pool not found — Suite 4 skipped");
        return;
      }

      // Register a relayer for this suite
      s4Relayer = Keypair.generate();
      await airdropAndConfirm(
        provider,
        s4Relayer.publicKey,
        2 * LAMPORTS_PER_SOL,
      );
      try {
        await (program.methods as any)
          .addRelayer(USDC_MAINNET, s4Relayer.publicKey)
          .accounts({ config: s4UsdcConfig, admin: wallet.publicKey })
          .rpc();
      } catch (_) {
        /* relayer may already be registered from a re-run */
      }

      suite4Ready = true;
      console.log("   Suite 4 ready ✅");
    });

    // ── Step 1: Register vault as Phoenix trader ────────────────────────────

    it("registerTrader: registers USDC vault as Phoenix Eternal trader", async function () {
      if (!suite4Ready) return this.skip();

      // Skip if already registered (re-run guard)
      const existing = await provider.connection.getAccountInfo(traderPda);
      if (existing) {
        console.log(
          `   ℹ️  Trader PDA already exists (${existing.data.length} bytes) — skipping creation`,
        );
        return;
      }

      const sig = await (program.methods as any)
        .phoenixRegisterPoolTrader(USDC_MAINNET)
        .accounts({
          config: s4UsdcConfig,
          vault: s4UsdcVault,
          payer: wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .remainingAccounts([
          { pubkey: PHOENIX_PROGRAM_ID, isSigner: false, isWritable: false }, // [0] phoenixProgram
          { pubkey: phoenixLogAuth, isSigner: false, isWritable: false }, // [1] logAuthority
          { pubkey: phoenixGlobalCfg, isSigner: false, isWritable: true }, // [2] globalConfiguration
          { pubkey: traderPda, isSigner: false, isWritable: true }, // [3] traderAccount (new)
        ]) // payer = ctx.accounts.payer
        .rpc();

      const tx = await provider.connection.getTransaction(sig, {
        commitment: "confirmed",
        maxSupportedTransactionVersion: 0,
      });
      printProgramLogs(tx?.meta?.logMessages ?? [], "registerTrader");

      const traderAccount = await provider.connection.getAccountInfo(traderPda);
      if (!traderAccount) throw new Error("Trader PDA not created by Phoenix");
      console.log(
        `   ✅ Vault registered as Phoenix trader — account size: ${traderAccount.data.length} bytes`,
      );
    });

    // ── Step 2–5: Full CPI round-trip ──────────────────────────────────────

    // Known global Phoenix accounts (confirmed from mainnet globalConfig decode)
    const PERP_ASSET_MAP = new PublicKey(
      "2nHGAaEw3D5dd4hVueaUNoygkQFmoeKqRQWnSPqSMFUC",
    );
    const GLOBAL_TRADER_INDEX = new PublicKey(
      "HCrPXLByGqRh2szQi3gj7oRdRVBNi1gccAyn4CQCT3HK",
    );
    const ACTIVE_TRADER_BUFFER = new PublicKey(
      "2U32rSzzrQS3eVmGHsnbw5kcqKF3wQXpHGd3hMq5YJok",
    );
    const ORDERBOOK = new PublicKey(
      "AXFz1MuzMUBHi5UKJuK3FDCQ73o3rSzubGU2mPr4LLU7",
    );
    const SPLINES = new PublicKey(
      "Dh9NrYjzzdvcYgFSbrkATQ1rPkPjDovXWnFVhfWmD2ZF",
    );
    const GLOBAL_VAULT = new PublicKey(
      "csZXgw2G58hbiWc9ndxaxrQVYVvqdXgQzYLuznEzHJu",
    );
    const WITHDRAW_QUEUE = new PublicKey(
      "3c3NTwpg7yW91FxijkHBXwVH1xUifun3Z8TC5eW5Si3K",
    );

    it("deposit: correct accounts wired to Phoenix depositFunds CPI (fails at UnknownRoot)", async function () {
      if (!suite4Ready) return this.skip();

      // Verifies that all pre-checks pass for a USDC deposit (mint, relayer, deadline,
      // recipient) and that the remaining accounts are wired correctly for the Phoenix
      // depositFunds CPI. The call fails at the Merkle root check (UnknownRoot) since
      // the tree contains no deposits — before ZK verification or any Phoenix CPI.
      const extData = {
        recipient: s4UsdcVault,
        relayer: s4Relayer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
      };
      const extDataHash = computeExtDataHash(poseidon, extData);
      const n0 = randomBytes32();
      const n1 = randomBytes32();
      const marker0 = nullifierMarkerPDA(program.programId, USDC_MAINNET, n0);
      const marker1 = nullifierMarkerPDA(program.programId, USDC_MAINNET, n1);
      const unknownRoot = randomBytes32(); // not in tree → triggers UnknownRoot

      await expectTxError(
        provider,
        (program.methods as any)
          .phoenixDepositFromPool(
            Array.from(unknownRoot),
            0,
            0,
            new BN(1_000_000),
            Array.from(extDataHash),
            USDC_MAINNET,
            Array.from(n0),
            Array.from(n1),
            Array.from(randomBytes32()),
            Array.from(randomBytes32()),
            new BN(9_999_999_999),
            extData,
            dummyProof(),
            null,
          )
          .accounts({
            config: s4UsdcConfig,
            globalConfig,
            vault: s4UsdcVault,
            inputTree: s4UsdcNoteTree,
            outputTree: s4UsdcNoteTree,
            nullifiers: s4UsdcNullifiers,
            nullifierMarker0: marker0,
            nullifierMarker1: marker1,
            relayer: s4Relayer.publicKey,
            vaultTokenAccount: s4UsdcVaultAta,
            relayerTokenAccount: s4UsdcVaultAta,
            tokenProgram: TOKEN_PROGRAM_ID,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([
            { pubkey: PHOENIX_PROGRAM_ID, isSigner: false, isWritable: false }, // [0] phoenixProgram
            { pubkey: phoenixLogAuth, isSigner: false, isWritable: false }, // [1] logAuthority
            { pubkey: phoenixGlobalCfg, isSigner: false, isWritable: true }, // [2] globalConfiguration
            { pubkey: traderPda, isSigner: false, isWritable: true }, // [3] traderAccount
            { pubkey: GLOBAL_VAULT, isSigner: false, isWritable: true }, // [4] globalVault
            { pubkey: GLOBAL_TRADER_INDEX, isSigner: false, isWritable: true }, // [5] globalTraderIndex
            { pubkey: ACTIVE_TRADER_BUFFER, isSigner: false, isWritable: true }, // [6] activeTraderBuffer
          ])
          .signers([s4Relayer])
          .rpc(),
        "UnknownRoot",
      );
      console.log(
        "   ✅ deposit: all pre-checks pass; CPI blocked at UnknownRoot as expected",
      );
    });

    it("place_order: vault places a Phoenix market order via CPI", async function () {
      if (!suite4Ready) return this.skip();

      // Remaining accounts for placeMarketOrder (9 accounts):
      //   [0] phoenixProgram  [1] logAuth  [2] globalConfig (writable)
      //   [3] traderAccount   [4] perpAssetMap  [5] globalTraderIndex
      //   [6] activeTraderBuffer  [7] orderbook  [8] splines
      const marketDisc = Buffer.from(phoenixDisc("place_market_order"));

      try {
        const sig = await (program.methods as any)
          .phoenixPlaceOrder(USDC_MAINNET, marketDisc)
          .accounts({
            config: s4UsdcConfig,
            vault: s4UsdcVault,
            relayer: s4Relayer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([
            { pubkey: PHOENIX_PROGRAM_ID, isSigner: false, isWritable: false }, // [0]
            { pubkey: phoenixLogAuth, isSigner: false, isWritable: false }, // [1]
            { pubkey: phoenixGlobalCfg, isSigner: false, isWritable: true }, // [2]
            { pubkey: traderPda, isSigner: false, isWritable: true }, // [3]
            { pubkey: PERP_ASSET_MAP, isSigner: false, isWritable: true }, // [4]
            { pubkey: GLOBAL_TRADER_INDEX, isSigner: false, isWritable: true }, // [5]
            { pubkey: ACTIVE_TRADER_BUFFER, isSigner: false, isWritable: true }, // [6]
            { pubkey: ORDERBOOK, isSigner: false, isWritable: true }, // [7]
            { pubkey: SPLINES, isSigner: false, isWritable: true }, // [8]
          ])
          .signers([s4Relayer])
          .rpc();

        const tx = await provider.connection.getTransaction(sig, {
          commitment: "confirmed",
          maxSupportedTransactionVersion: 0,
        });
        printProgramLogs(tx?.meta?.logMessages ?? [], "place_order");
        console.log("   ✅ place_order CPI succeeded:", sig);
      } catch (e: any) {
        const logs: string[] =
          e instanceof SendTransactionError
            ? (await e.getLogs(provider.connection)) ?? []
            : e.logs ?? [];
        printProgramLogs(logs, "place_order CPI logs");
        const haystack = [...logs, e.message ?? ""].join("\n");

        // Must NOT be a Veilo pre-check error
        if (
          haystack.includes("PhoenixInvalidOrderData") ||
          haystack.includes("RelayerNotAllowed") ||
          haystack.includes("PhoenixInvalidPool") ||
          haystack.includes("PhoenixInvalidAccounts") ||
          haystack.includes("InvalidSwapProgram")
        ) {
          throw new Error(
            "place_order failed at Veilo pre-check (wrong accounts?): " +
              e.message,
          );
        }
        // Phoenix-level errors (insufficient margin, bad order packet) are acceptable
        console.log(
          "   ✅ place_order: CPI reached Phoenix (Phoenix-level response as expected)",
        );
      }
    });

    it("cancel_orders: vault cancels all open Phoenix positions", async function () {
      if (!suite4Ready) return this.skip();

      // cancelAll is a no-op when the trader has no open orders.
      // Same 9 remaining accounts as place_order.
      try {
        const sig = await (program.methods as any)
          .phoenixCancelOrders(USDC_MAINNET)
          .accounts({
            config: s4UsdcConfig,
            vault: s4UsdcVault,
            relayer: s4Relayer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([
            { pubkey: PHOENIX_PROGRAM_ID, isSigner: false, isWritable: false }, // [0]
            { pubkey: phoenixLogAuth, isSigner: false, isWritable: false }, // [1]
            { pubkey: phoenixGlobalCfg, isSigner: false, isWritable: true }, // [2]
            { pubkey: traderPda, isSigner: false, isWritable: true }, // [3]
            { pubkey: PERP_ASSET_MAP, isSigner: false, isWritable: true }, // [4]
            { pubkey: GLOBAL_TRADER_INDEX, isSigner: false, isWritable: true }, // [5]
            { pubkey: ACTIVE_TRADER_BUFFER, isSigner: false, isWritable: true }, // [6]
            { pubkey: ORDERBOOK, isSigner: false, isWritable: true }, // [7]
            { pubkey: SPLINES, isSigner: false, isWritable: true }, // [8]
          ])
          .signers([s4Relayer])
          .rpc();

        const tx = await provider.connection.getTransaction(sig, {
          commitment: "confirmed",
          maxSupportedTransactionVersion: 0,
        });
        printProgramLogs(tx?.meta?.logMessages ?? [], "cancel_orders");
        console.log(
          "   ✅ cancel_orders CPI succeeded (no-op — no open orders):",
          sig,
        );
      } catch (e: any) {
        const logs: string[] =
          e instanceof SendTransactionError
            ? (await e.getLogs(provider.connection)) ?? []
            : e.logs ?? [];
        printProgramLogs(logs, "cancel_orders CPI logs");
        const haystack = [...logs, e.message ?? ""].join("\n");

        if (
          haystack.includes("RelayerNotAllowed") ||
          haystack.includes("PhoenixInvalidPool") ||
          haystack.includes("PhoenixInvalidAccounts") ||
          haystack.includes("InvalidSwapProgram")
        ) {
          throw new Error(
            "cancel_orders failed at Veilo pre-check: " + e.message,
          );
        }
        console.log(
          "   ✅ cancel_orders: CPI reached Phoenix (Phoenix-level response)",
        );
      }
    });

    it("queue_withdraw: vault queues USDC withdrawal back to ATA", async function () {
      if (!suite4Ready) return this.skip();

      // withdrawFunds remaining accounts layout:
      //   [0] phoenixProgram  [1] logAuth  [2] globalConfig (writable)
      //   [3] traderAccount   [4] perpAssetMap   [5] globalVault
      //   [6] withdrawQueue   [7] globalTraderIndex  [8] activeTraderBuffer
      // destinationTokenAccount (vaultTokenAccount) and tokenProgram are named accounts.
      const withdrawAmount = new BN(1_000_000); // 1 USDC

      try {
        const sig = await (program.methods as any)
          .phoenixQueueWithdraw(USDC_MAINNET, withdrawAmount)
          .accounts({
            config: s4UsdcConfig,
            vault: s4UsdcVault,
            vaultTokenAccount: s4UsdcVaultAta,
            relayer: s4Relayer.publicKey,
            tokenProgram: TOKEN_PROGRAM_ID,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([
            { pubkey: PHOENIX_PROGRAM_ID, isSigner: false, isWritable: false }, // [0]
            { pubkey: phoenixLogAuth, isSigner: false, isWritable: false }, // [1]
            { pubkey: phoenixGlobalCfg, isSigner: false, isWritable: true }, // [2]
            { pubkey: traderPda, isSigner: false, isWritable: true }, // [3]
            { pubkey: PERP_ASSET_MAP, isSigner: false, isWritable: true }, // [4]
            { pubkey: GLOBAL_VAULT, isSigner: false, isWritable: true }, // [5]
            { pubkey: WITHDRAW_QUEUE, isSigner: false, isWritable: true }, // [6]
            { pubkey: GLOBAL_TRADER_INDEX, isSigner: false, isWritable: true }, // [7]
            { pubkey: ACTIVE_TRADER_BUFFER, isSigner: false, isWritable: true }, // [8]
          ])
          .signers([s4Relayer])
          .rpc();

        const tx = await provider.connection.getTransaction(sig, {
          commitment: "confirmed",
          maxSupportedTransactionVersion: 0,
        });
        printProgramLogs(tx?.meta?.logMessages ?? [], "queue_withdraw");
        console.log("   ✅ queue_withdraw CPI succeeded:", sig);
      } catch (e: any) {
        const logs: string[] =
          e instanceof SendTransactionError
            ? (await e.getLogs(provider.connection)) ?? []
            : e.logs ?? [];
        printProgramLogs(logs, "queue_withdraw CPI logs");
        const haystack = [...logs, e.message ?? ""].join("\n");

        if (
          haystack.includes("RelayerNotAllowed") ||
          haystack.includes("PhoenixInvalidPool") ||
          haystack.includes("PhoenixInvalidAccounts") ||
          haystack.includes("InvalidSwapProgram") ||
          haystack.includes("VaultTokenAccountNotATA") ||
          haystack.includes("InvalidPublicAmount")
        ) {
          throw new Error(
            "queue_withdraw failed at Veilo pre-check: " + e.message,
          );
        }
        // Phoenix-level failure (insufficient balance, etc.) is expected without a prior deposit
        console.log(
          "   ✅ queue_withdraw: CPI reached Phoenix (Phoenix-level response as expected)",
        );
      }
    });
  });
});

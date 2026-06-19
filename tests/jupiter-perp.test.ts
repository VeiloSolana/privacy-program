// tests/jupiter-perp.test.ts
//
// Jupiter Perpetuals Integration Tests for Veilo Privacy Pool
//
// Covers all five new instructions:
//   jperp_open_position  — ZK-verified USDC withdrawal → createIncreasePositionMarketRequest
//   jperp_set_tpsl       — createDecreasePositionRequest2 (Trigger type, TP or SL)
//   jperp_update_tpsl    — updateDecreasePositionRequest2
//   jperp_close_position — createDecreasePositionRequest2 (Market type)
//   jperp_reissue_notes  — executor ATA → vault transfer + ZK deposit
//
// Test structure:
//   Suite 1 — PDA Derivation       (pure off-chain; always runnable)
//   Suite 2 — Validation Errors    (localnet; verifies on-chain guards fire before any CPI)
//   Suite 3 — Full Integration     (skipped; documents complete private-perps flow)
//
// Run: npm run test:jperp
//
// Suite 3 requires Jupiter Perpetuals cloned on the test validator.
// Add to Anchor.toml:
//   [[test.validator.clone]]
//   address = "PERPHjGBqRHArX4DySjwM6UJHiR3sWAatqfdBS2qQJu"   # Jupiter Perps
//   [[test.validator.clone]]
//   address = "5BUwFW4nRbftYTDMbgxykoFWqWHPzahFSNAaaaJtVKsq"   # JLP pool
//   [[test.validator.clone]]
//   address = "7xS2gz2bTp3fwCC7knJvUWTEU9Tycczu6VhJYKgi1wdz"   # SOL custody
//   [[test.validator.clone]]
//   address = "G18jKKXQwBbrHeiK3C9MRXhkHsLHf7XgCSisykV46EZa"   # USDC custody

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
  Transaction,
  AddressLookupTableProgram,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  getAssociatedTokenAddress,
  ASSOCIATED_TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import { buildPoseidon } from "circomlibjs";
import * as crypto from "crypto";

import {
  makeProvider,
  airdropAndConfirm,
  randomBytes32,
  computeExtDataHash,
} from "./test-helpers";

// ─── Jupiter Perps constants (mirrors perps/src/perps.rs) ────────────────────

const JUPITER_PERP_PROGRAM_ID = new PublicKey(
  "PERPHjGBqRHArX4DySjwM6UJHiR3sWAatqfdBS2qQJu",
);
const PERPS_EVENT_AUTHORITY = new PublicKey(
  "37hJBDnntwqhGbK7L6M1bLyvccj4u55CCUiLPdYkiqBN",
);
const JLP_POOL = new PublicKey("5BUwFW4nRbftYTDMbgxykoFWqWHPzahFSNAaaaJtVKsq");

// Custodies from perps-playground/lib/setup.ts
const CUSTODIES = {
  SOL: new PublicKey("7xS2gz2bTp3fwCC7knJvUWTEU9Tycczu6VhJYKgi1wdz"),
  USDC: new PublicKey("G18jKKXQwBbrHeiK3C9MRXhkHsLHf7XgCSisykV46EZa"),
};

const USDC_MINT = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
const WSOL_MINT = new PublicKey("So11111111111111111111111111111111111111112");

/** Side enum discriminants (None=0, Long=1, Short=2) */
const SIDE_LONG = 1;
const SIDE_SHORT = 2;

/** RequestType enum discriminants (Market=0, Trigger=1) */
const REQUEST_TYPE_MARKET = 0;
const REQUEST_TYPE_TRIGGER = 1;

/** RequestChange enum discriminants (None=0, Increase=1, Decrease=2) */
const CHANGE_INCREASE = 1;
const CHANGE_DECREASE = 2;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function encodeTreeId(id: number): Buffer {
  const buf = Buffer.alloc(2);
  buf.writeUInt16LE(id, 0);
  return buf;
}

/**
 * Anchor instruction discriminator: sha256("global:<snake_case_name>")[0..8]
 * Mirrors jperp_disc() in perps.rs.
 */
function jperpDisc(name: string): Buffer {
  return crypto
    .createHash("sha256")
    .update(`global:${name}`)
    .digest()
    .slice(0, 8);
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

/** Executor PDA: ["jperp_executor", mint, claimant] on our program */
function executorPDA(
  programId: PublicKey,
  mint: PublicKey,
  claimant: PublicKey,
): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("jperp_executor"), mint.toBuffer(), claimant.toBuffer()],
    programId,
  );
  return pda;
}

/** Slot PDA: ["jperp_slot_v1", mint, withdrawal_id] on our program */
function slotPDA(
  programId: PublicKey,
  mint: PublicKey,
  withdrawalId: Uint8Array,
): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [
      Buffer.from("jperp_slot_v1"),
      mint.toBuffer(),
      Buffer.from(withdrawalId),
    ],
    programId,
  );
  return pda;
}

/**
 * Jupiter Perps position PDA.
 * Seeds: ["position", owner, JLP_POOL, custody, collateralCustody, side_byte]
 * on JUPITER_PERP_PROGRAM_ID.
 *
 * For private perps, owner = executorPDA (not the user's wallet).
 */
function positionPDA(
  owner: PublicKey,
  custody: PublicKey,
  collateralCustody: PublicKey,
  side: number, // 1=Long, 2=Short
): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [
      Buffer.from("position"),
      owner.toBuffer(),
      JLP_POOL.toBuffer(),
      custody.toBuffer(),
      collateralCustody.toBuffer(),
      Buffer.from([side]),
    ],
    JUPITER_PERP_PROGRAM_ID,
  );
  return pda;
}

/**
 * Jupiter Perps positionRequest PDA.
 * Seeds: ["position_request", position, counter_le8, change_byte]
 * on JUPITER_PERP_PROGRAM_ID.
 */
function positionRequestPDA(
  position: PublicKey,
  counter: BN,
  change: number, // CHANGE_INCREASE=1, CHANGE_DECREASE=2
): PublicKey {
  const counterBuf = Buffer.alloc(8);
  // BN little-endian 8 bytes
  const counterBytes = counter.toArrayLike(Buffer, "le", 8);
  counterBytes.copy(counterBuf);
  const [pda] = PublicKey.findProgramAddressSync(
    [
      Buffer.from("position_request"),
      position.toBuffer(),
      counterBuf,
      Buffer.from([change]),
    ],
    JUPITER_PERP_PROGRAM_ID,
  );
  return pda;
}

/** Perpetuals global PDA on Jupiter Perps program. */
function perpetualsPDA(): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("perpetuals")],
    JUPITER_PERP_PROGRAM_ID,
  );
  return pda;
}

function dummyProof() {
  return {
    proofA: new Array(64).fill(0),
    proofB: new Array(128).fill(0),
    proofC: new Array(64).fill(0),
  };
}

function tinyProof() {
  return { proofA: [] as number[], proofB: [] as number[], proofC: [] as number[] };
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
  // Wait one slot for activation
  await new Promise((r) => setTimeout(r, 600));
  const lutAccount = await provider.connection.getAddressLookupTable(lutAddress);
  return lutAccount.value!;
}

async function sendVersionedTx(
  provider: AnchorProvider,
  ixs: import("@solana/web3.js").TransactionInstruction[],
  signers: Keypair[],
  luts: import("@solana/web3.js").AddressLookupTableAccount[],
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
    if (
      !msg.includes(expectedFragment) &&
      !logs.includes(expectedFragment)
    ) {
      throw new Error(
        `Expected "${expectedFragment}" but got: ${msg}\nLogs: ${logs}`,
      );
    }
  }
}

// ─── Suite ────────────────────────────────────────────────────────────────────

describe("Jupiter Perpetuals Integration", () => {
  const provider = makeProvider();
  setProvider(provider);
  const wallet = provider.wallet as Wallet;
  const program: any = (workspace as any).PrivacyPool;

  // Non-USDC pool for validation error tests
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
    console.log("\n⚡  Jupiter Perps Integration Test Setup\n");
    poseidon = await buildPoseidon();

    // Use WSOL as the non-USDC test pool mint (cloned in Anchor.toml, not USDC)
    testMint = WSOL_MINT;

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
        .initialize(50, testMint, new BN(1_000_000), new BN(1_000_000_000_000), new BN(1_000_000), new BN(1_000_000_000_000))
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

  // ── Suite 1: PDA Derivation ────────────────────────────────────────────────

  describe("PDA Derivation", () => {
    it("derives executor PDA from [jperp_executor, mint, claimant]", () => {
      const claimant = Keypair.generate().publicKey;
      const [pda, bump] = PublicKey.findProgramAddressSync(
        [Buffer.from("jperp_executor"), USDC_MINT.toBuffer(), claimant.toBuffer()],
        program.programId,
      );
      console.log(`      executor PDA:  ${pda.toBase58()}  (bump ${bump})`);

      // Different claimants → different executor PDAs
      const claimant2 = Keypair.generate().publicKey;
      const [pda2] = PublicKey.findProgramAddressSync(
        [Buffer.from("jperp_executor"), USDC_MINT.toBuffer(), claimant2.toBuffer()],
        program.programId,
      );
      if (pda.equals(pda2)) throw new Error("Different claimants must produce different executor PDAs");
    });

    it("derives slot PDA from [jperp_slot_v1, mint, withdrawal_id]", () => {
      const withdrawalId = randomBytes32();
      const pda = slotPDA(program.programId, USDC_MINT, withdrawalId);
      console.log(`      slot PDA: ${pda.toBase58()}`);

      // Different withdrawal_ids → different slot PDAs
      const pda2 = slotPDA(program.programId, USDC_MINT, randomBytes32());
      if (pda.equals(pda2)) throw new Error("Different withdrawal_ids must produce different slot PDAs");
    });

    it("derives position PDA on Jupiter Perps program (owner = executor PDA)", () => {
      const claimant = Keypair.generate().publicKey;
      const executor = executorPDA(program.programId, USDC_MINT, claimant);
      const position = positionPDA(executor, CUSTODIES.SOL, CUSTODIES.USDC, SIDE_SHORT);
      console.log(`      executor:  ${executor.toBase58()}`);
      console.log(`      position:  ${position.toBase58()}`);

      // Long uses same market token as collateral
      const posLong = positionPDA(executor, CUSTODIES.SOL, CUSTODIES.SOL, SIDE_LONG);
      if (position.equals(posLong)) throw new Error("Long and short positions must be distinct PDAs");
    });

    it("derives positionRequest PDA (Increase) from [position_request, position, counter_le8, 0x01]", () => {
      const counter = new BN(Math.floor(Math.random() * 1_000_000_000));
      const claimant = Keypair.generate().publicKey;
      const executor = executorPDA(program.programId, USDC_MINT, claimant);
      const position = positionPDA(executor, CUSTODIES.SOL, CUSTODIES.USDC, SIDE_SHORT);
      const req = positionRequestPDA(position, counter, CHANGE_INCREASE);
      console.log(`      positionRequest (increase): ${req.toBase58()}  (counter ${counter.toString()})`);
    });

    it("derives positionRequest PDA (Decrease) from [position_request, position, counter_le8, 0x02]", () => {
      const counter = new BN(Math.floor(Math.random() * 1_000_000_000));
      const claimant = Keypair.generate().publicKey;
      const executor = executorPDA(program.programId, USDC_MINT, claimant);
      const position = positionPDA(executor, CUSTODIES.SOL, CUSTODIES.USDC, SIDE_SHORT);
      const reqIncrease = positionRequestPDA(position, counter, CHANGE_INCREASE);
      const reqDecrease = positionRequestPDA(position, counter, CHANGE_DECREASE);
      if (reqIncrease.equals(reqDecrease))
        throw new Error("Increase and decrease requests with same counter must be distinct");
    });

    it("derives perpetuals global PDA from [perpetuals] on PERP program", () => {
      const perps = perpetualsPDA();
      console.log(`      perpetuals PDA: ${perps.toBase58()}`);
    });

    it("computes Anchor discriminators for Jupiter Perps instructions", () => {
      const disc = (name: string) =>
        jperpDisc(name).toString("hex").toUpperCase();

      const open   = disc("create_increase_position_market_request");
      const dec    = disc("create_decrease_position_request2");
      const update = disc("update_decrease_position_request2");

      console.log(`      create_increase_position_market_request: ${open}`);
      console.log(`      create_decrease_position_request2:       ${dec}`);
      console.log(`      update_decrease_position_request2:       ${update}`);

      // All three must be distinct 8-byte values
      const all = [open, dec, update];
      const unique = new Set(all);
      if (unique.size !== all.length) throw new Error("Discriminators must be unique");
    });

    it("side and request-type byte constants match IDL ordering", () => {
      // From IDL: Side[0]=None, Side[1]=Long, Side[2]=Short
      //           RequestType[0]=Market, RequestType[1]=Trigger
      if (SIDE_LONG !== 1) throw new Error("SIDE_LONG must be 1");
      if (SIDE_SHORT !== 2) throw new Error("SIDE_SHORT must be 2");
      if (REQUEST_TYPE_MARKET !== 0) throw new Error("REQUEST_TYPE_MARKET must be 0");
      if (REQUEST_TYPE_TRIGGER !== 1) throw new Error("REQUEST_TYPE_TRIGGER must be 1");
      if (CHANGE_INCREASE !== 1) throw new Error("CHANGE_INCREASE must be 1");
      if (CHANGE_DECREASE !== 2) throw new Error("CHANGE_DECREASE must be 2");
    });

    it("multiple TP/SL requests on the same position use different counters", () => {
      const claimant = Keypair.generate().publicKey;
      const executor = executorPDA(program.programId, USDC_MINT, claimant);
      const position = positionPDA(executor, CUSTODIES.SOL, CUSTODIES.USDC, SIDE_SHORT);

      const tpCounter = new BN(111_111);
      const slCounter = new BN(222_222);

      const tpRequest = positionRequestPDA(position, tpCounter, CHANGE_DECREASE);
      const slRequest = positionRequestPDA(position, slCounter, CHANGE_DECREASE);

      if (tpRequest.equals(slRequest))
        throw new Error("TP and SL requests must be distinct PDAs (different counters)");

      console.log(`      TP request PDA: ${tpRequest.toBase58()}`);
      console.log(`      SL request PDA: ${slRequest.toBase58()}`);
    });
  });

  // ── Suite 2: Validation Errors ─────────────────────────────────────────────

  describe("Validation Errors", () => {
    let testExecutor: PublicKey;
    let testSlot: PublicKey;
    let suite2Lut: import("@solana/web3.js").AddressLookupTableAccount;

    const withdrawalId = new Uint8Array(32).fill(0xab);
    const n0 = randomBytes32();
    const n1 = randomBytes32();
    const c0 = randomBytes32();
    const c1 = randomBytes32();

    before(async () => {
      testExecutor = executorPDA(
        program.programId,
        testMint,
        SystemProgram.programId,
      );
      testSlot = slotPDA(program.programId, testMint, withdrawalId);

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
        testExecutor,
        testSlot,
      ]);
    });

    it("jperp_open_position: rejects invalid side byte (JperpInvalidSide)", async () => {
      const marker0 = nullifierMarkerPDA(program.programId, testMint, n0);
      const marker1 = nullifierMarkerPDA(program.programId, testMint, n1);
      const claimant = SystemProgram.programId;
      const extData = {
        recipient: testExecutor,
        relayer: relayer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
        claimant,
      };
      const extDataHash = computeExtDataHash(poseidon, extData);

      await assertError(
        (program.methods as any)
          .jperpOpenPosition(
            Array.from(new Uint8Array(32).fill(1)), // root
            0, 0,                                    // tree IDs
            new BN(1_000_000),                       // deposit_amount
            Array.from(extDataHash),
            testMint,
            claimant,
            Array.from(n0), Array.from(n1),
            Array.from(c0), Array.from(c1),
            Array.from(withdrawalId),
            new BN(Math.floor(Date.now() / 1000) + 3600),
            extData,
            tinyProof(),
            null,       // note_ciphers
            new BN(10_000_000), // size_usd_delta
            new BN(1_000_000),  // collateral_token_delta
            99,                 // side = 99 — invalid
            new BN(0),          // price_slippage
            new BN(0),          // counter
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
            executor: testExecutor,
            executorTokenAccount: vaultTokenAccount, // dummy
            relayerTokenAccount: vaultTokenAccount,  // dummy
            jperpSlot: testSlot,
            tokenProgram: TOKEN_PROGRAM_ID,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([])
          .signers([relayer])
          .rpc(),
        "JperpInvalidSide",
      );
    });

    it("jperp_open_position: rejects unregistered relayer (RelayerNotAllowed)", async () => {
      const badRelayer = Keypair.generate();
      await airdropAndConfirm(provider, badRelayer.publicKey, LAMPORTS_PER_SOL);

      const claimant = SystemProgram.programId;
      const extData = {
        recipient: testExecutor,
        relayer: badRelayer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
        claimant,
      };
      const extDataHash = computeExtDataHash(poseidon, extData);
      const marker0 = nullifierMarkerPDA(program.programId, testMint, randomBytes32());
      const marker1 = nullifierMarkerPDA(program.programId, testMint, randomBytes32());
      const badSlot = slotPDA(program.programId, testMint, randomBytes32());

      await assertError(
        (program.methods as any)
          .jperpOpenPosition(
            Array.from(new Uint8Array(32).fill(1)),
            0, 0,
            new BN(1_000_000),
            Array.from(extDataHash),
            testMint,
            claimant,
            Array.from(randomBytes32()), Array.from(randomBytes32()),
            Array.from(c0), Array.from(c1),
            Array.from(randomBytes32()),
            new BN(Math.floor(Date.now() / 1000) + 3600),
            extData,
            tinyProof(),
            null,
            new BN(10_000_000),
            new BN(1_000_000),
            SIDE_SHORT,
            new BN(0),
            new BN(0),
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
            relayer: badRelayer.publicKey,
            vaultTokenAccount,
            executor: testExecutor,
            executorTokenAccount: vaultTokenAccount,
            relayerTokenAccount: vaultTokenAccount,
            jperpSlot: badSlot,
            tokenProgram: TOKEN_PROGRAM_ID,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([])
          .signers([badRelayer])
          .rpc(),
        "RelayerNotAllowed",
      );
    });

    it("jperp_open_position: rejects when recipient != executor PDA (JperpRecipientMustBeExecutor)", async () => {
      const claimant = SystemProgram.programId;
      const wrongRecipient = Keypair.generate().publicKey; // not the executor PDA
      const extData = {
        recipient: wrongRecipient,
        relayer: relayer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
        claimant,
      };
      const extDataHash = computeExtDataHash(poseidon, extData);
      const marker0 = nullifierMarkerPDA(program.programId, testMint, randomBytes32());
      const marker1 = nullifierMarkerPDA(program.programId, testMint, randomBytes32());
      const badSlot = slotPDA(program.programId, testMint, randomBytes32());

      await assertError(
        (program.methods as any)
          .jperpOpenPosition(
            Array.from(new Uint8Array(32).fill(1)),
            0, 0,
            new BN(1_000_000),
            Array.from(extDataHash),
            testMint,
            claimant,
            Array.from(randomBytes32()), Array.from(randomBytes32()),
            Array.from(c0), Array.from(c1),
            Array.from(randomBytes32()),
            new BN(Math.floor(Date.now() / 1000) + 3600),
            extData,
            tinyProof(),
            null,
            new BN(10_000_000),
            new BN(1_000_000),
            SIDE_SHORT,
            new BN(0),
            new BN(0),
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
            executor: testExecutor,
            executorTokenAccount: vaultTokenAccount,
            relayerTokenAccount: vaultTokenAccount,
            jperpSlot: badSlot,
            tokenProgram: TOKEN_PROGRAM_ID,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([])
          .signers([relayer])
          .rpc(),
        "JperpRecipientMustBeExecutor",
      );
    });

    it("jperp_set_tpsl: rejects unregistered relayer (RelayerNotAllowed)", async () => {
      const badRelayer = Keypair.generate();
      await airdropAndConfirm(provider, badRelayer.publicKey, LAMPORTS_PER_SOL);
      const executor = executorPDA(program.programId, testMint, Keypair.generate().publicKey);
      const executorAta = await getAssociatedTokenAddress(testMint, executor, true);

      await assertError(
        (program.methods as any)
          .jperpSetTpsl(
            testMint,
            Keypair.generate().publicKey,
            new BN(0),          // collateral_usd_delta
            new BN(5_000_000),  // size_usd_delta
            new BN(200_000_000), // trigger_price ($200)
            true,               // trigger_above_threshold (TP)
            false,              // entire_position
            new BN(42),         // counter
          )
          .accounts({
            config,
            executor,
            executorTokenAccount: executorAta,
            relayer: badRelayer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([])
          .signers([badRelayer])
          .rpc(),
        "RelayerNotAllowed",
      );
    });

    it("jperp_update_tpsl: rejects unregistered relayer (RelayerNotAllowed)", async () => {
      const badRelayer = Keypair.generate();
      await airdropAndConfirm(provider, badRelayer.publicKey, LAMPORTS_PER_SOL);
      const executor = executorPDA(program.programId, testMint, Keypair.generate().publicKey);

      await assertError(
        (program.methods as any)
          .jperpUpdateTpsl(
            testMint,
            Keypair.generate().publicKey,
            new BN(5_000_000),   // size_usd_delta
            new BN(210_000_000), // trigger_price
          )
          .accounts({
            config,
            executor,
            relayer: badRelayer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([])
          .signers([badRelayer])
          .rpc(),
        "RelayerNotAllowed",
      );
    });

    it("jperp_close_position: rejects unregistered relayer (RelayerNotAllowed)", async () => {
      const badRelayer = Keypair.generate();
      await airdropAndConfirm(provider, badRelayer.publicKey, LAMPORTS_PER_SOL);
      const claimant = Keypair.generate().publicKey;
      const executor = executorPDA(program.programId, testMint, claimant);
      const executorAta = await getAssociatedTokenAddress(testMint, executor, true);

      await assertError(
        (program.methods as any)
          .jperpClosePosition(
            testMint,
            claimant,
            new BN(0),         // collateral_usd_delta
            new BN(0),         // size_usd_delta (entirePosition=true)
            true,              // entire_position
            new BN(0),         // price_slippage
            new BN(99),        // counter
          )
          .accounts({
            config,
            executor,
            executorTokenAccount: executorAta,
            relayer: badRelayer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([])
          .signers([badRelayer])
          .rpc(),
        "RelayerNotAllowed",
      );
    });

    it("jperp_set_tpsl: rejects < 16 remaining_accounts (JperpInvalidAccounts)", async () => {
      const claimant = Keypair.generate().publicKey;
      const executor = executorPDA(program.programId, testMint, claimant);
      const executorAta = await getAssociatedTokenAddress(testMint, executor, true);

      await assertError(
        (program.methods as any)
          .jperpSetTpsl(
            testMint,
            claimant,
            new BN(0),
            new BN(5_000_000),
            new BN(200_000_000),
            true,
            false,
            new BN(1),
          )
          .accounts({
            config,
            executor,
            executorTokenAccount: executorAta,
            relayer: relayer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([
            // Pass only 1 account (PERP program) — should fire JperpInvalidAccounts
            { pubkey: JUPITER_PERP_PROGRAM_ID, isSigner: false, isWritable: false },
          ])
          .signers([relayer])
          .rpc(),
        "JperpInvalidAccounts",
      );
    });

    it("jperp_set_tpsl: rejects wrong program ID in remaining[0] (JperpInvalidAccounts)", async () => {
      const claimant = Keypair.generate().publicKey;
      const executor = executorPDA(program.programId, testMint, claimant);
      const executorAta = await getAssociatedTokenAddress(testMint, executor, true);

      // Build 16 dummy accounts with wrong program at [0]
      const dummyAccounts = Array.from({ length: 16 }, () => ({
        pubkey: SystemProgram.programId, // wrong — must be JUPITER_PERP_PROGRAM_ID
        isSigner: false,
        isWritable: false,
      }));

      await assertError(
        (program.methods as any)
          .jperpSetTpsl(
            testMint,
            claimant,
            new BN(0),
            new BN(5_000_000),
            new BN(200_000_000),
            true,
            false,
            new BN(1),
          )
          .accounts({
            config,
            executor,
            executorTokenAccount: executorAta,
            relayer: relayer.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts(dummyAccounts)
          .signers([relayer])
          .rpc(),
        "JperpInvalidAccounts",
      );
    });
  });

  // ── Suite 3: Full Integration (skipped — documents the complete flow) ───────
  //
  // Unlock by cloning Jupiter Perps + JLP pool accounts in Anchor.toml.
  // The flow below is the authoritative reference for client-side construction.

  describe("Full Integration Flow (reference — skipped)", () => {
    const SKIP = process.env.RUN_JPERP_INTEGRATION !== "1";

    before(function () {
      if (SKIP) this.skip();
    });

    // Shared state across steps
    let usdcConfig: PublicKey;
    let usdcVault: PublicKey;
    let usdcNoteTree: PublicKey;
    let usdcNullifiers: PublicKey;
    let usdcVaultAta: PublicKey;
    let s3Relayer: Keypair;
    let claimantKp: Keypair;
    let executor: PublicKey;
    let executorUsdcAta: PublicKey;
    let jperpSlot: PublicKey;
    const withdrawalId = randomBytes32();

    before(async () => {
      if (SKIP) return;

      s3Relayer = Keypair.generate();
      claimantKp = Keypair.generate(); // ephemeral — user generates fresh per deposit
      await airdropAndConfirm(provider, s3Relayer.publicKey, 10 * LAMPORTS_PER_SOL);

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

      executor = executorPDA(program.programId, USDC_MINT, claimantKp.publicKey);
      executorUsdcAta = await getAssociatedTokenAddress(USDC_MINT, executor, true);
      jperpSlot = slotPDA(program.programId, USDC_MINT, withdrawalId);

      // Register relayer (assumes USDC pool already initialized)
      await (program.methods as any)
        .addRelayer(USDC_MINT, s3Relayer.publicKey)
        .accounts({ config: usdcConfig, admin: wallet.publicKey })
        .rpc();
    });

    it("Step 1: jperp_open_position — ZK withdrawal → position request submitted", async function () {
      if (SKIP) return this.skip();

      // Client constructs these from the ZK circuit:
      const n0 = randomBytes32();
      const n1 = randomBytes32();
      const c0 = randomBytes32();
      const c1 = randomBytes32();
      const depositAmount = new BN(10_000_000); // $10 USDC
      const extData = {
        recipient: executor,
        relayer: s3Relayer.publicKey,
        fee: new BN(100_000), // $0.10
        refund: new BN(0),
        claimant: claimantKp.publicKey,
      };
      const extDataHash = computeExtDataHash(poseidon, extData);

      // For a short SOL position: collateralCustody = USDC custody
      const counter = new BN(Math.floor(Math.random() * 1_000_000_000));
      const position = positionPDA(executor, CUSTODIES.SOL, CUSTODIES.USDC, SIDE_SHORT);
      const positionRequest = positionRequestPDA(position, counter, CHANGE_INCREASE);
      const positionRequestAta = await getAssociatedTokenAddress(USDC_MINT, positionRequest, true);
      const perpetuals = perpetualsPDA();

      const marker0 = nullifierMarkerPDA(program.programId, USDC_MINT, n0);
      const marker1 = nullifierMarkerPDA(program.programId, USDC_MINT, n1);

      // remaining_accounts layout — 14 accounts for createIncreasePositionMarketRequest
      const remainingAccounts = [
        { pubkey: JUPITER_PERP_PROGRAM_ID, isSigner: false, isWritable: false }, // [0]
        { pubkey: perpetuals,              isSigner: false, isWritable: false }, // [1]
        { pubkey: JLP_POOL,                isSigner: false, isWritable: false }, // [2]
        { pubkey: position,                isSigner: false, isWritable: true  }, // [3]
        { pubkey: positionRequest,         isSigner: false, isWritable: true  }, // [4]
        { pubkey: positionRequestAta,      isSigner: false, isWritable: true  }, // [5]
        { pubkey: CUSTODIES.SOL,           isSigner: false, isWritable: false }, // [6] custody
        { pubkey: CUSTODIES.USDC,          isSigner: false, isWritable: false }, // [7] collateralCustody
        { pubkey: USDC_MINT,               isSigner: false, isWritable: false }, // [8] inputMint
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, // [9] referral (null)
        { pubkey: TOKEN_PROGRAM_ID,        isSigner: false, isWritable: false }, // [10]
        { pubkey: ASSOCIATED_TOKEN_PROGRAM_ID, isSigner: false, isWritable: false }, // [11]
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, // [12]
        { pubkey: PERPS_EVENT_AUTHORITY,   isSigner: false, isWritable: false }, // [13]
      ];

      // In a real tx you'd use a real ZK proof. Here we pass dummyProof().
      // The CPI to Jupiter Perps would also need the executor ATA pre-funded.
      await (program.methods as any)
        .jperpOpenPosition(
          Array.from(new Uint8Array(32).fill(1)),
          0, 0,
          depositAmount,
          Array.from(extDataHash),
          USDC_MINT,
          claimantKp.publicKey,
          Array.from(n0), Array.from(n1),
          Array.from(c0), Array.from(c1),
          Array.from(withdrawalId),
          new BN(Math.floor(Date.now() / 1000) + 3600),
          extData,
          dummyProof(),
          null,
          new BN(20_000_000), // size $20 (2x leverage on $10)
          new BN(10_000_000), // collateral $10 USDC
          SIDE_SHORT,
          new BN(0),          // price_slippage
          counter,
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
          relayer: s3Relayer.publicKey,
          vaultTokenAccount: usdcVaultAta,
          executor,
          executorTokenAccount: executorUsdcAta,
          relayerTokenAccount: await getAssociatedTokenAddress(USDC_MINT, s3Relayer.publicKey),
          jperpSlot,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .remainingAccounts(remainingAccounts)
        .signers([s3Relayer])
        .rpc();
    });

    it("Step 2: jperp_set_tpsl — place a SL trigger at $90 below entry", async function () {
      if (SKIP) return this.skip();

      const counter = new BN(Math.floor(Math.random() * 1_000_000_000));
      const position = positionPDA(executor, CUSTODIES.SOL, CUSTODIES.USDC, SIDE_SHORT);
      const positionRequest = positionRequestPDA(position, counter, CHANGE_DECREASE);
      const positionRequestAta = await getAssociatedTokenAddress(USDC_MINT, positionRequest, true);
      const perpetuals = perpetualsPDA();

      // SL for short: price rises above trigger → triggers above threshold = true
      const triggerPrice = new BN(90_000_000); // $90 (SOL price in 6 decimals)
      const triggerAboveThreshold = true;

      const remainingAccounts = [
        { pubkey: JUPITER_PERP_PROGRAM_ID, isSigner: false, isWritable: false }, // [0]
        { pubkey: perpetuals,              isSigner: false, isWritable: false }, // [1]
        { pubkey: JLP_POOL,                isSigner: false, isWritable: false }, // [2]
        { pubkey: position,                isSigner: false, isWritable: true  }, // [3]
        { pubkey: positionRequest,         isSigner: false, isWritable: true  }, // [4]
        { pubkey: positionRequestAta,      isSigner: false, isWritable: true  }, // [5]
        { pubkey: CUSTODIES.SOL,           isSigner: false, isWritable: false }, // [6] custody
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, // [7] dovesPriceAccount
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, // [8] pythnetPriceAccount
        { pubkey: CUSTODIES.USDC,          isSigner: false, isWritable: false }, // [9] collateralCustody
        { pubkey: USDC_MINT,               isSigner: false, isWritable: false }, // [10] desiredMint
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, // [11] referral
        { pubkey: TOKEN_PROGRAM_ID,        isSigner: false, isWritable: false }, // [12]
        { pubkey: ASSOCIATED_TOKEN_PROGRAM_ID, isSigner: false, isWritable: false }, // [13]
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, // [14]
        { pubkey: PERPS_EVENT_AUTHORITY,   isSigner: false, isWritable: false }, // [15]
      ];

      await (program.methods as any)
        .jperpSetTpsl(
          USDC_MINT,
          claimantKp.publicKey,
          new BN(0),          // collateral_usd_delta
          new BN(0),          // size_usd_delta (0 = entire_position)
          triggerPrice,
          triggerAboveThreshold,
          true,               // entire_position
          counter,
        )
        .accounts({
          config: usdcConfig,
          executor,
          executorTokenAccount: executorUsdcAta,
          relayer: s3Relayer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .remainingAccounts(remainingAccounts)
        .signers([s3Relayer])
        .rpc();
    });

    it("Step 3: jperp_close_position — market close; keeper settles, USDC arrives at executor ATA", async function () {
      if (SKIP) return this.skip();

      // After calling this, Jupiter's keeper fires decreasePosition4 asynchronously.
      // USDC proceeds land in executorUsdcAta. Then call jperp_reissue_notes.
      const counter = new BN(Math.floor(Math.random() * 1_000_000_000));
      const position = positionPDA(executor, CUSTODIES.SOL, CUSTODIES.USDC, SIDE_SHORT);
      const positionRequest = positionRequestPDA(position, counter, CHANGE_DECREASE);
      const positionRequestAta = await getAssociatedTokenAddress(USDC_MINT, positionRequest, true);
      const perpetuals = perpetualsPDA();

      const remainingAccounts = [
        { pubkey: JUPITER_PERP_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: perpetuals,              isSigner: false, isWritable: false },
        { pubkey: JLP_POOL,                isSigner: false, isWritable: false },
        { pubkey: position,                isSigner: false, isWritable: true  },
        { pubkey: positionRequest,         isSigner: false, isWritable: true  },
        { pubkey: positionRequestAta,      isSigner: false, isWritable: true  },
        { pubkey: CUSTODIES.SOL,           isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, // doves
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, // pyth
        { pubkey: CUSTODIES.USDC,          isSigner: false, isWritable: false },
        { pubkey: USDC_MINT,               isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, // referral
        { pubkey: TOKEN_PROGRAM_ID,        isSigner: false, isWritable: false },
        { pubkey: ASSOCIATED_TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        { pubkey: PERPS_EVENT_AUTHORITY,   isSigner: false, isWritable: false },
      ];

      await (program.methods as any)
        .jperpClosePosition(
          USDC_MINT,
          claimantKp.publicKey,
          new BN(0),   // collateral_usd_delta
          new BN(0),   // size_usd_delta (0 = entirePosition)
          true,        // entire_position
          new BN(0),   // price_slippage
          counter,
        )
        .accounts({
          config: usdcConfig,
          executor,
          executorTokenAccount: executorUsdcAta,
          relayer: s3Relayer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .remainingAccounts(remainingAccounts)
        .signers([s3Relayer])
        .rpc();
    });

    it("Step 4: jperp_reissue_notes — re-mint private notes from settled USDC", async function () {
      if (SKIP) return this.skip();

      // At this point executorUsdcAta has USDC from the closed position.
      // Claimant must co-sign; amount capped at jperp_slot.amount.
      const n0 = randomBytes32();
      const n1 = randomBytes32();
      const c0 = randomBytes32();
      const c1 = randomBytes32();
      const reissueAmount = new BN(9_900_000); // $9.90 (after P&L and fees)

      const extData = {
        recipient: usdcVault,
        relayer: s3Relayer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
        claimant: claimantKp.publicKey,
      };
      const extDataHash = computeExtDataHash(poseidon, extData);
      const marker0 = nullifierMarkerPDA(program.programId, USDC_MINT, n0);
      const marker1 = nullifierMarkerPDA(program.programId, USDC_MINT, n1);

      await (program.methods as any)
        .jperpReissueNotes(
          Array.from(new Uint8Array(32).fill(1)),
          0, 0,
          reissueAmount,
          Array.from(extDataHash),
          USDC_MINT,
          Array.from(n0), Array.from(n1),
          Array.from(c0), Array.from(c1),
          Array.from(withdrawalId),
          new BN(Math.floor(Date.now() / 1000) + 3600),
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
          relayer: s3Relayer.publicKey,
          jperpSlot,
          claimant: claimantKp.publicKey,
          executor,
          executorTokenAccount: executorUsdcAta,
          vaultTokenAccount: usdcVaultAta,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .signers([s3Relayer, claimantKp])
        .rpc();
    });

    it("jperp_reissue_notes: rejects over-reissue (JperpSlotOverdraft)", async function () {
      if (SKIP) return this.skip();

      // The slot.amount is $10 (deposit_amount from Step 1).
      // Step 4 already reissued $9.90 → available = $0.10.
      // Trying to reissue $5 should fail.
      const n0 = randomBytes32();
      const n1 = randomBytes32();
      const c0 = randomBytes32();
      const c1 = randomBytes32();
      const tooMuch = new BN(5_000_000); // $5 > available $0.10

      const extData = {
        recipient: usdcVault,
        relayer: s3Relayer.publicKey,
        fee: new BN(0),
        refund: new BN(0),
        claimant: claimantKp.publicKey,
      };
      const extDataHash = computeExtDataHash(poseidon, extData);
      const marker0 = nullifierMarkerPDA(program.programId, USDC_MINT, n0);
      const marker1 = nullifierMarkerPDA(program.programId, USDC_MINT, n1);

      await assertError(
        (program.methods as any)
          .jperpReissueNotes(
            Array.from(new Uint8Array(32).fill(1)),
            0, 0,
            tooMuch,
            Array.from(extDataHash),
            USDC_MINT,
            Array.from(n0), Array.from(n1),
            Array.from(c0), Array.from(c1),
            Array.from(withdrawalId),
            new BN(Math.floor(Date.now() / 1000) + 3600),
            extData,
            tinyProof(),
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
            relayer: s3Relayer.publicKey,
            jperpSlot,
            claimant: claimantKp.publicKey,
            executor,
            executorTokenAccount: executorUsdcAta,
            vaultTokenAccount: usdcVaultAta,
            tokenProgram: TOKEN_PROGRAM_ID,
            systemProgram: SystemProgram.programId,
          })
          .signers([s3Relayer, claimantKp])
          .rpc(),
        "JperpSlotOverdraft",
      );
    });
  });
});

// tests/note-ciphers.test.ts
//
// Confirms the NoteCiphers on-chain encrypted note recovery feature works
// end-to-end the way the production relayer will use it.
//
// The relayer encrypts note secrets with NaCl box (Curve25519 ECDH) and passes
// them as Some(NoteCiphers{...}) in the last arg of transact(). These bytes
// are stored verbatim in CommitmentEvent.  A user who lost their off-chain DB
// can scan chain history, find CommitmentEvents addressed to them, and decrypt
// to recover blinding + amount.
//
// Tests:
//   1. Pool / global-config init (silent no-op if already done by another suite)
//   2. Relayer deposits with Some(NoteCiphers) — cipher bytes round-trip through
//      the on-chain event and can be decrypted back to the original secrets
//   3. null (None) still accepted — event emits zero bytes for both cipher fields

import "mocha";
import * as anchor from "@coral-xyz/anchor";

const anchorVal = (anchor as any).default || anchor;
const BN = anchorVal.BN;
const setProvider = anchorVal.setProvider;
const workspace = anchorVal.workspace;
const Wallet = anchorVal.Wallet;

type AnchorProvider = anchor.AnchorProvider;
type Wallet = anchor.Wallet;

import {
  PublicKey,
  Keypair,
  SystemProgram,
  LAMPORTS_PER_SOL,
  SendTransactionError,
  Connection,
  ComputeBudgetProgram,
  Transaction,
  VersionedTransaction,
  TransactionMessage,
  AddressLookupTableProgram,
  AddressLookupTableAccount,
} from "@solana/web3.js";
import nacl from "tweetnacl";
import fs from "fs";
import os from "os";
import path from "path";
import { buildPoseidon } from "circomlibjs";
import { groth16 } from "snarkjs";
import assert from "assert";
import {
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  getOrCreateAssociatedTokenAccount,
  getAssociatedTokenAddress,
  NATIVE_MINT,
} from "@solana/spl-token";

// =============================================================================
// ZK circuit paths
// =============================================================================

const WASM_PATH = path.join(
  process.cwd(),
  "zk/circuits/transaction/transaction_js/transaction.wasm",
);
const ZKEY_PATH = path.join(
  process.cwd(),
  "zk/circuits/transaction/transaction_final.zkey",
);
const VK_PATH = path.join(
  process.cwd(),
  "zk/circuits/transaction/transaction_verification_key.json",
);

const SWAP_WASM_PATH = path.join(
  process.cwd(),
  "zk/circuits/swap/swap_js/swap.wasm",
);
const SWAP_ZKEY_PATH = path.join(
  process.cwd(),
  "zk/circuits/swap/swap_final.zkey",
);
const SWAP_VK_PATH = path.join(
  process.cwd(),
  "zk/circuits/swap/swap_verification_key.json",
);

// =============================================================================
// AMM constants (Raydium V4 SOL/USDC — cloned from mainnet in Anchor.toml)
// =============================================================================

const RAYDIUM_AMM_V4_PROGRAM = new PublicKey(
  "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8",
);
const SERUM_PROGRAM = new PublicKey(
  "srmqPvymJeFKQ4zGQed1GFppgkRHL9kaELCbyksJtPX",
);
const USDC_MINT = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

const AMM_POOL_STATE = new PublicKey(
  "58oQChx4yWmvKdwLLZzBi4ChoCc2fqCUWBkwMihLYQo2",
);
const AMM_AUTHORITY = new PublicKey(
  "5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1",
);
const AMM_OPEN_ORDERS = new PublicKey(
  "HmiHHzq4Fym9e1D4qzLS6LDDM3tNsCTBPDWHTLZ763jY",
);
const AMM_TARGET_ORDERS = new PublicKey(
  "CZza3Ej4Mc58MnxWA385itCC9jCo3L1D7zc3LKy1bZMR",
);
const AMM_BASE_VAULT = new PublicKey(
  "DQyrAcCrDXQ7NeoqGgDCZwBvWDcYmFCjSb9JtteuvPpz",
);
const AMM_QUOTE_VAULT = new PublicKey(
  "HLmqeL62xR1QoZ1HKKbXRrdN1p3phKpxRMb2VVopvBBz",
);

const SERUM_MARKET = new PublicKey(
  "8BnEgHoWFysVcuFFX7QztDmzuH8r5ZFvyP3sYwn1XTh6",
);
const SERUM_BIDS = new PublicKey(
  "5jWUncPNBMZJ3sTHKmMLszypVkoRK6bfEQMQUHweeQnh",
);
const SERUM_ASKS = new PublicKey(
  "EaXdHx7x3mdGA38j5RSmKYSXMzAFzzUXCLNBEDXDn1d5",
);
const SERUM_EVENT_QUEUE = new PublicKey(
  "8CvwxZ9Db6XbLD46NZwwmVDZZRDy7eydFcAGkXKh9axa",
);
const SERUM_BASE_VAULT = new PublicKey(
  "CKxTHwM9fPMRRvZmFnFoqKNd9pQR21c5Aq9bh5h9oghX",
);
const SERUM_QUOTE_VAULT = new PublicKey(
  "6A5NHCj1yF6urc9wZNe6Bcjj4LVszQNj5DwAWG97yzMu",
);

/** Map SOL_MINT (all-zeros) to NATIVE_MINT for SPL token operations. */
function splMint(mint: PublicKey): PublicKey {
  return mint.equals(PublicKey.default) ? NATIVE_MINT : mint;
}

/** Build Raydium AMM V4 swap_base_in instruction data: [0x09 | amountIn LE8 | minOut LE8]. */
function buildAmmSwapData(amountIn: bigint, minOut: bigint): Buffer {
  const buf = Buffer.alloc(17);
  buf.writeUInt8(9, 0);
  buf.writeBigUInt64LE(amountIn, 1);
  buf.writeBigUInt64LE(minOut, 9);
  return buf;
}

const SOL_MINT = PublicKey.default;
const TREE_HEIGHT = 22;

// =============================================================================
// Low-level helpers (self-contained copy so the file runs independently)
// =============================================================================

function makeProvider(): AnchorProvider {
  const url = process.env.ANCHOR_PROVIDER_URL ?? "http://127.0.0.1:8899";
  const connection = new Connection(url, "confirmed");
  const keypairPath =
    process.env.ANCHOR_WALLET ??
    path.join(os.homedir(), ".config", "solana", "id.json");
  const secret = JSON.parse(fs.readFileSync(keypairPath, "utf8"));
  const kp = Keypair.fromSecretKey(Uint8Array.from(secret));
  return new anchorVal.AnchorProvider(connection, new Wallet(kp), {
    commitment: "confirmed",
  });
}

async function airdropAndConfirm(
  provider: AnchorProvider,
  pubkey: PublicKey,
  amount: number,
) {
  const sig = await provider.connection.requestAirdrop(pubkey, amount);
  const bh = await provider.connection.getLatestBlockhash();
  await provider.connection.confirmTransaction({ signature: sig, ...bh });
}

function randomBytes32(): Uint8Array {
  return Keypair.generate().publicKey.toBytes();
}

function bytesToBigIntBE(bytes: Uint8Array): bigint {
  return BigInt("0x" + Buffer.from(bytes).toString("hex"));
}

function reduceToField(bytes: Uint8Array): bigint {
  const FR = BigInt(
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
  );
  return BigInt("0x" + Buffer.from(bytes).toString("hex")) % FR;
}

function derivePublicKey(poseidon: any, privateKey: Uint8Array): bigint {
  return poseidon.F.toObject(
    poseidon([poseidon.F.e(bytesToBigIntBE(privateKey))]),
  );
}

function computeCommitment(
  poseidon: any,
  amount: bigint,
  ownerPubkey: bigint,
  blinding: Uint8Array,
  mint: PublicKey,
): Uint8Array {
  const h = poseidon([
    poseidon.F.e(amount.toString()),
    poseidon.F.e(ownerPubkey.toString()),
    poseidon.F.e(bytesToBigIntBE(blinding)),
    poseidon.F.e(reduceToField(mint.toBytes()).toString()),
  ]);
  return Uint8Array.from(
    Buffer.from(poseidon.F.toString(h, 16).padStart(64, "0"), "hex"),
  );
}

function computeNullifier(
  poseidon: any,
  commitment: Uint8Array,
  leafIndex: number,
  privateKey: Uint8Array,
): Uint8Array {
  const cF = poseidon.F.e(bytesToBigIntBE(commitment));
  const iF = poseidon.F.e(BigInt(leafIndex));
  const kF = poseidon.F.e(bytesToBigIntBE(privateKey));
  const sig = poseidon([kF, cF, iF]);
  const h = poseidon([cF, iF, sig]);
  return Uint8Array.from(
    Buffer.from(poseidon.F.toString(h, 16).padStart(64, "0"), "hex"),
  );
}

function computeExtDataHash(
  poseidon: any,
  extData: { recipient: PublicKey; relayer: PublicKey; fee: any; refund: any },
): Uint8Array {
  const h1 = poseidon([
    poseidon.F.e(reduceToField(extData.recipient.toBytes())),
    poseidon.F.e(reduceToField(extData.relayer.toBytes())),
  ]);
  const h2 = poseidon([
    poseidon.F.e(extData.fee.toString()),
    poseidon.F.e(extData.refund.toString()),
  ]);
  const final = poseidon([h1, h2]);
  return Uint8Array.from(
    Buffer.from(poseidon.F.toString(final, 16).padStart(64, "0"), "hex"),
  );
}

function extractRootFromAccount(acc: any): Uint8Array {
  const root = acc.rootHistory[acc.rootIndex];
  return new Uint8Array(root);
}

// =============================================================================
// Swap ZK helpers (self-contained mirror of test-helpers.ts equivalents)
// =============================================================================

function computeSwapParamsHash(
  poseidon: any,
  sourceMint: PublicKey,
  destMint: PublicKey,
  minAmountOut: bigint,
  deadline: bigint,
  destAmount: bigint,
): Uint8Array {
  const FR = BigInt(
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
  );
  function reduce(bytes: Uint8Array): bigint {
    return BigInt("0x" + Buffer.from(bytes).toString("hex")) % FR;
  }
  const mintPairHash = poseidon([
    poseidon.F.e(reduce(sourceMint.toBytes())),
    poseidon.F.e(reduce(destMint.toBytes())),
  ]);
  const swapTermsHash = poseidon([
    poseidon.F.e(minAmountOut.toString()),
    poseidon.F.e(deadline.toString()),
    poseidon.F.e(destAmount.toString()),
  ]);
  const paramsHash = poseidon([mintPairHash, swapTermsHash]);
  return Uint8Array.from(
    Buffer.from(poseidon.F.toString(paramsHash, 16).padStart(64, "0"), "hex"),
  );
}

async function generateSwapProof(inputs: {
  sourceRoot: Uint8Array;
  swapParamsHash: Uint8Array;
  extDataHash: Uint8Array;
  sourceMint: PublicKey;
  destMint: PublicKey;
  inputNullifiers: [Uint8Array, Uint8Array];
  changeCommitment: Uint8Array;
  destCommitment: Uint8Array;
  swapAmount: bigint;
  inputAmounts: [bigint, bigint];
  inputPrivateKeys: [Uint8Array, Uint8Array];
  inputPublicKeys: [bigint, bigint];
  inputBlindings: [Uint8Array, Uint8Array];
  inputMerklePaths: [
    { pathElements: bigint[]; pathIndices: number[] },
    { pathElements: bigint[]; pathIndices: number[] },
  ];
  changeAmount: bigint;
  changePubkey: bigint;
  changeBlinding: Uint8Array;
  destAmount: bigint;
  destPubkey: bigint;
  destBlinding: Uint8Array;
  minAmountOut: bigint;
  deadline: bigint;
}) {
  const FR = BigInt(
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
  );
  function reduce(bytes: Uint8Array): bigint {
    return BigInt("0x" + Buffer.from(bytes).toString("hex")) % FR;
  }
  const circuitInputs = {
    sourceRoot: bytesToBigIntBE(inputs.sourceRoot).toString(),
    swapParamsHash: bytesToBigIntBE(inputs.swapParamsHash).toString(),
    extDataHash: bytesToBigIntBE(inputs.extDataHash).toString(),
    sourceMint: reduce(inputs.sourceMint.toBytes()).toString(),
    destMint: reduce(inputs.destMint.toBytes()).toString(),
    inputNullifier: inputs.inputNullifiers.map((n) =>
      bytesToBigIntBE(n).toString(),
    ),
    changeCommitment: bytesToBigIntBE(inputs.changeCommitment).toString(),
    destCommitment: bytesToBigIntBE(inputs.destCommitment).toString(),
    swapAmount: inputs.swapAmount.toString(),
    inAmount: inputs.inputAmounts.map((a) => a.toString()),
    inPubkey: inputs.inputPublicKeys.map((pk) => pk.toString()),
    inBlinding: inputs.inputBlindings.map((b) => bytesToBigIntBE(b).toString()),
    inPathIndex: inputs.inputMerklePaths.map((p) =>
      p.pathIndices.reduce((acc, bit, i) => acc + (bit << i), 0),
    ),
    inPathElements: inputs.inputMerklePaths.map((p) =>
      p.pathElements.map((e) => e.toString()),
    ),
    inPrivateKey: inputs.inputPrivateKeys.map((pk) =>
      bytesToBigIntBE(pk).toString(),
    ),
    changeAmount: inputs.changeAmount.toString(),
    changePubkey: inputs.changePubkey.toString(),
    changeBlinding: bytesToBigIntBE(inputs.changeBlinding).toString(),
    destAmount: inputs.destAmount.toString(),
    destPubkey: inputs.destPubkey.toString(),
    destBlinding: bytesToBigIntBE(inputs.destBlinding).toString(),
    minAmountOut: inputs.minAmountOut.toString(),
    deadline: inputs.deadline.toString(),
  };

  const { proof, publicSignals } = await groth16.fullProve(
    circuitInputs,
    SWAP_WASM_PATH,
    SWAP_ZKEY_PATH,
  );
  const vKey = JSON.parse(fs.readFileSync(SWAP_VK_PATH, "utf8"));
  if (!(await groth16.verify(vKey, publicSignals, proof)))
    throw new Error("Swap proof invalid!");

  return convertProofToBytes(proof);
}

function encodeTreeId(treeId: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(treeId, 0);
  return b;
}

function deriveNullifierMarkerPDA(
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

// =============================================================================
// Off-chain Merkle tree (zero-knowledge proof helper)
// =============================================================================

class OffchainMerkleTree {
  private leaves: Map<number, Uint8Array> = new Map();
  private zeros: Uint8Array[] = [];
  private levels: number;
  private poseidon: any;
  constructor(levels: number, poseidon: any) {
    this.levels = levels;
    this.poseidon = poseidon;
    let z = new Uint8Array(32);
    this.zeros.push(z);
    for (let i = 0; i < levels; i++) {
      const h = poseidon([
        poseidon.F.e(bytesToBigIntBE(z)),
        poseidon.F.e(bytesToBigIntBE(z)),
      ]);
      z = Uint8Array.from(
        Buffer.from(poseidon.F.toString(h, 16).padStart(64, "0"), "hex"),
      );
      this.zeros.push(z);
    }
  }
  getZeros() {
    return this.zeros;
  }
  get nextIndex() {
    return this.leaves.size;
  }
  insert(c: Uint8Array): number {
    const i = this.leaves.size;
    this.leaves.set(i, c);
    return i;
  }
  private getNode(level: number, index: number): Uint8Array {
    if (level === 0) return this.leaves.get(index) ?? this.zeros[0];
    if (index * Math.pow(2, level) >= this.leaves.size)
      return this.zeros[level];
    const l = this.getNode(level - 1, 2 * index);
    const r = this.getNode(level - 1, 2 * index + 1);
    const h = this.poseidon([
      this.poseidon.F.e(bytesToBigIntBE(l)),
      this.poseidon.F.e(bytesToBigIntBE(r)),
    ]);
    return Uint8Array.from(
      Buffer.from(this.poseidon.F.toString(h, 16).padStart(64, "0"), "hex"),
    );
  }
  getMerkleProof(leafIndex: number) {
    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];
    let cur = leafIndex;
    for (let level = 0; level < this.levels; level++) {
      const sib = cur % 2 === 0 ? cur + 1 : cur - 1;
      pathElements.push(bytesToBigIntBE(this.getNode(level, sib)));
      pathIndices.push(cur % 2 === 0 ? 0 : 1);
      cur = Math.floor(cur / 2);
    }
    return { pathElements, pathIndices };
  }
  getRoot() {
    return this.getNode(this.levels, 0);
  }
}

// =============================================================================
// ZK proof generation (matches circuit signal names from transaction.circom)
// =============================================================================

function convertProofToBytes(proof: any) {
  function b32(x: bigint): number[] {
    const o = new Array(32).fill(0);
    let v = x;
    for (let i = 31; i >= 0; i--) {
      o[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    return o;
  }
  const [ax, ay] = [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])];
  const [bx0, bx1, by0, by1] = [
    BigInt(proof.pi_b[0][0]),
    BigInt(proof.pi_b[0][1]),
    BigInt(proof.pi_b[1][0]),
    BigInt(proof.pi_b[1][1]),
  ];
  const [cx, cy] = [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])];
  return {
    proofA: [...b32(ax), ...b32(ay)],
    proofB: [...b32(bx1), ...b32(bx0), ...b32(by1), ...b32(by0)],
    proofC: [...b32(cx), ...b32(cy)],
  };
}

async function generateTransactionProof(inputs: {
  root: Uint8Array;
  publicAmount: bigint;
  extDataHash: Uint8Array;
  mintAddress: PublicKey;
  inputNullifiers: [Uint8Array, Uint8Array];
  outputCommitments: [Uint8Array, Uint8Array];
  inputAmounts: [bigint, bigint];
  inputPrivateKeys: [Uint8Array, Uint8Array];
  inputPublicKeys: [bigint, bigint];
  inputBlindings: [Uint8Array, Uint8Array];
  inputMerklePaths: [
    { pathElements: bigint[]; pathIndices: number[] },
    { pathElements: bigint[]; pathIndices: number[] },
  ];
  outputAmounts: [bigint, bigint];
  outputOwners: [bigint, bigint];
  outputBlindings: [Uint8Array, Uint8Array];
}) {
  const FR = BigInt(
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
  );
  const circuitInputs = {
    root: bytesToBigIntBE(inputs.root).toString(),
    publicAmount: (inputs.publicAmount < 0n
      ? FR + inputs.publicAmount
      : inputs.publicAmount
    ).toString(),
    extDataHash: bytesToBigIntBE(inputs.extDataHash).toString(),
    mintAddress: reduceToField(inputs.mintAddress.toBytes()).toString(),
    inputNullifier: inputs.inputNullifiers.map((n) =>
      bytesToBigIntBE(n).toString(),
    ),
    outputCommitment: inputs.outputCommitments.map((c) =>
      bytesToBigIntBE(c).toString(),
    ),
    inAmount: inputs.inputAmounts.map((a) => a.toString()),
    inPubkey: inputs.inputPublicKeys.map((pk) => pk.toString()),
    inBlinding: inputs.inputBlindings.map((b) => bytesToBigIntBE(b).toString()),
    inPathIndex: inputs.inputMerklePaths.map((p) =>
      p.pathIndices.reduce((acc, bit, i) => acc + (bit << i), 0),
    ),
    inPathElements: inputs.inputMerklePaths.map((p) =>
      p.pathElements.map((e) => e.toString()),
    ),
    inPrivateKey: inputs.inputPrivateKeys.map((pk) =>
      bytesToBigIntBE(pk).toString(),
    ),
    outAmount: inputs.outputAmounts.map((a) => a.toString()),
    outPubkey: inputs.outputOwners.map((o) => o.toString()),
    outBlinding: inputs.outputBlindings.map((b) =>
      bytesToBigIntBE(b).toString(),
    ),
  };

  const { proof, publicSignals } = await groth16.fullProve(
    circuitInputs,
    WASM_PATH,
    ZKEY_PATH,
  );
  const vKey = JSON.parse(fs.readFileSync(VK_PATH, "utf8"));
  if (!(await groth16.verify(vKey, publicSignals, proof)))
    throw new Error("Proof invalid!");
  return convertProofToBytes(proof);
}

// =============================================================================
// NaCl helper: encrypt / decrypt note secrets (matches relayer pattern)
//
// Plaintext:       blinding[32] || amount_le[8]          = 40 bytes
// Encrypted blob:  nonce[24] || nacl.box(plaintext)[56]  = 80 bytes
//   where nacl.box output = MAC[16] + ciphertext[40]     = 56 bytes
// Ephemeral key:   fresh Curve25519 public key           = 32 bytes
// =============================================================================

function encryptNoteSecrets(
  recipientX25519Pubkey: Uint8Array, // user's X25519 public key
  blinding: Uint8Array, // 32-byte note blinding factor
  amount: bigint, // note amount
): { ephemeralKey: Uint8Array; encryptedBlob: Uint8Array } {
  const ephemeral = nacl.box.keyPair();
  const nonce = nacl.randomBytes(24);

  // Build 40-byte plaintext: blinding[32] || amount LE[8]
  const plaintext = new Uint8Array(40);
  plaintext.set(blinding, 0);
  const amountBuf = Buffer.allocUnsafe(8);
  amountBuf.writeBigUInt64LE(amount);
  plaintext.set(amountBuf, 32);

  // Encrypt: nacl.box returns MAC[16] + ciphertext[40] = 56 bytes
  const boxed = nacl.box(
    plaintext,
    nonce,
    recipientX25519Pubkey,
    ephemeral.secretKey,
  );

  // Store as nonce[24] + box[56] = 80 bytes
  const encryptedBlob = new Uint8Array(80);
  encryptedBlob.set(nonce, 0);
  encryptedBlob.set(boxed, 24);

  return { ephemeralKey: ephemeral.publicKey, encryptedBlob };
}

function decryptNoteSecrets(
  recipientX25519SecretKey: Uint8Array, // user's X25519 secret key
  ephemeralKey: Uint8Array, // ephemeral public key from event
  encryptedBlob: Uint8Array, // 80-byte blob from event
): { blinding: Uint8Array; amount: bigint } {
  const nonce = encryptedBlob.slice(0, 24);
  const boxed = encryptedBlob.slice(24);
  const plaintext = nacl.box.open(
    boxed,
    nonce,
    ephemeralKey,
    recipientX25519SecretKey,
  );
  if (!plaintext)
    throw new Error("Note decryption failed — wrong key or corrupted data");
  return {
    blinding: plaintext.slice(0, 32),
    amount: Buffer.from(plaintext.slice(32)).readBigUInt64LE(0),
  };
}

// =============================================================================
// CommitmentEvent parser — uses Anchor's EventParser so the discriminator and
// field layout are derived from the IDL, not hardcoded Borsh offsets.
// This mirrors how parseCommitmentEventsFromTx works in the production relayer.
// =============================================================================

interface ParsedCommitmentEvent {
  commitment: Buffer;
  leafIndex: bigint;
  mintAddress: PublicKey;
  treeId: number;
  ephemeralPublicKey: Buffer;
  encryptedBlob: Buffer;
}

function parseCommitmentEvents(
  logMessages: string[],
  program: any,
): ParsedCommitmentEvent[] {
  const EventParser = (anchor as any).EventParser;
  const BorshCoder = (anchor as any).BorshCoder;
  const eventParser = new EventParser(
    program.programId,
    new BorshCoder(program.idl),
  );
  const events: ParsedCommitmentEvent[] = [];
  for (const event of eventParser.parseLogs(logMessages)) {
    if (event.name !== "commitmentEvent") continue;
    const d = event.data as any;
    events.push({
      commitment: Buffer.from(d.commitment),
      leafIndex: BigInt(d.leafIndex ?? d.leaf_index),
      mintAddress: d.mintAddress ?? d.mint_address,
      treeId: Number(d.treeId ?? d.tree_id),
      ephemeralPublicKey: Buffer.from(
        d.ephemeralPublicKey ?? d.ephemeral_public_key,
      ),
      encryptedBlob: Buffer.from(d.encryptedBlob ?? d.encrypted_blob),
    });
  }
  return events;
}

/** Polls until the ALT is active (requires ≥ 1 slot after creation). */
async function pollAlt(
  connection: Connection,
  altAddress: PublicKey,
  minAddresses = 1,
): Promise<AddressLookupTableAccount> {
  for (let attempt = 0; attempt < 20; attempt++) {
    await new Promise((r) => setTimeout(r, 500));
    const { value } = await connection.getAddressLookupTable(altAddress);
    if (value && value.state.addresses.length >= minAddresses) return value;
  }
  throw new Error("Address Lookup Table did not become active within 10 s");
}

// =============================================================================
// Main suite
// =============================================================================

describe("NoteCiphers — on-chain encrypted note recovery (relayer path)", () => {
  const provider = makeProvider();
  setProvider(provider);
  const wallet = provider.wallet as Wallet;
  const program: any = workspace.PrivacyPool as any;

  let poseidon: any;
  let config: PublicKey;
  let vault: PublicKey;
  let noteTree: PublicKey;
  let nullifiers: PublicKey;
  let globalConfig: PublicKey;
  let offchainTree: OffchainMerkleTree;

  // X25519 keypair representing the user who will receive / decrypt notes
  let userX25519: nacl.BoxKeyPair;

  // Shared relayer — created once in before(), registered on-chain, reused across tests
  let sharedRelayer: Keypair;
  // ALT compresses repeated account references so Some(NoteCiphers) fits in a v0 tx
  let swapAlt: AddressLookupTableAccount;

  // ---- USDC / swap state (used by test 4) ----------------------------------
  let destConfig: PublicKey;
  let destVault: PublicKey;
  let destNoteTree: PublicKey;
  let destNullifiers: PublicKey;
  let destOffchainTree: OffchainMerkleTree;
  // Note deposited to SOL pool and then swapped in test 4
  let swapSourceNote: {
    amount: bigint;
    commitment: Uint8Array;
    nullifier: Uint8Array;
    blinding: Uint8Array;
    privateKey: Uint8Array;
    publicKey: bigint;
    leafIndex: number;
    merklePath: { pathElements: bigint[]; pathIndices: number[] };
  } | null = null;
  // Serum vault signer for AMM (derived from serum market nonce)
  let serumVaultSigner: PublicKey;

  before(async () => {
    console.log("\n⚙️  before(): building Poseidon hasher...");
    poseidon = await buildPoseidon();
    offchainTree = new OffchainMerkleTree(TREE_HEIGHT, poseidon);
    userX25519 = nacl.box.keyPair();
    console.log(
      `🔐 User X25519 pubkey: ${Buffer.from(userX25519.publicKey).toString(
        "hex",
      )}`,
    );

    [config] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_config_v3"), SOL_MINT.toBuffer()],
      program.programId,
    );
    [vault] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_vault_v3"), SOL_MINT.toBuffer()],
      program.programId,
    );
    [noteTree] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("privacy_note_tree_v3"),
        SOL_MINT.toBuffer(),
        encodeTreeId(0),
      ],
      program.programId,
    );
    [nullifiers] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_nullifiers_v3"), SOL_MINT.toBuffer()],
      program.programId,
    );
    [globalConfig] = PublicKey.findProgramAddressSync(
      [Buffer.from("global_config_v1")],
      program.programId,
    );
    console.log(`📍 PDAs derived:`);
    console.log(`   config:       ${config.toBase58()}`);
    console.log(`   vault:        ${vault.toBase58()}`);
    console.log(`   noteTree:     ${noteTree.toBase58()}`);
    console.log(`   nullifiers:   ${nullifiers.toBase58()}`);
    console.log(`   globalConfig: ${globalConfig.toBase58()}`);

    // ---- Pool + global config init (idempotent) ----------------------------
    try {
      await (program.methods as any)
        .initialize(
          50,
          SOL_MINT,
          new BN(10_000_000),
          new BN(1_000_000_000_000),
          new BN(10_000_000),
          new BN(1_000_000_000_000),
        )
        .accounts({
          config,
          vault,
          noteTree,
          nullifiers,
          admin: wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      console.log("✅ Pool initialized");
    } catch (_) {
      console.log("ℹ️  Pool already initialized — continuing");
    }
    try {
      await (program.methods as any)
        .initializeGlobalConfig()
        .accounts({
          globalConfig,
          admin: wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      console.log("✅ Global config initialized");
    } catch (_) {
      console.log("ℹ️  Global config already initialized — continuing");
    }

    // ---- Shared relayer (registered once, reused across all tests) ---------
    sharedRelayer = Keypair.generate();
    console.log(`\n👤 Shared relayer: ${sharedRelayer.publicKey.toBase58()}`);
    console.log(`   Airdropping 10 SOL...`);
    await airdropAndConfirm(
      provider,
      sharedRelayer.publicKey,
      10 * LAMPORTS_PER_SOL,
    );
    console.log(`   Airdrop confirmed`);
    try {
      await (program.methods as any)
        .addRelayer(SOL_MINT, sharedRelayer.publicKey)
        .accounts({ config, admin: wallet.publicKey })
        .rpc();
      console.log(`   Registered as relayer ✓`);
    } catch (_) {
      console.log(`   Already registered as relayer`);
    }

    // ---- Address Lookup Table (ALT) ----------------------------------------
    // Compresses repeated account references (relayer, noteTree, SystemProgram)
    // so that the Some(NoteCiphers) payload (+225 bytes) fits within the 1232-byte
    // VersionedTransaction limit.
    console.log(`\n🗂️  Creating Address Lookup Table...`);
    const slot = await provider.connection.getSlot("finalized");
    console.log(`   Using finalized slot: ${slot}`);
    const [createAltIx, altAddress] =
      AddressLookupTableProgram.createLookupTable({
        authority: wallet.publicKey,
        payer: wallet.publicKey,
        recentSlot: slot,
      });
    const extendAltIx = AddressLookupTableProgram.extendLookupTable({
      payer: wallet.publicKey,
      authority: wallet.publicKey,
      lookupTable: altAddress,
      addresses: [
        config,
        vault,
        noteTree,
        nullifiers,
        globalConfig,
        sharedRelayer.publicKey,
        SystemProgram.programId,
      ],
    });
    await provider.sendAndConfirm(
      new Transaction().add(createAltIx, extendAltIx),
    );
    console.log(`   ALT address: ${altAddress.toBase58()}`);
    console.log(`   Waiting for ALT to become active...`);
    swapAlt = await pollAlt(provider.connection, altAddress);
    console.log(
      `✅ ALT ready: ${altAddress.toBase58().slice(0, 16)}… (${
        swapAlt.state.addresses.length
      } addresses loaded)`,
    );

    // ---- USDC pool init (needed for test 4: transact_swap with NoteCiphers) ---
    console.log(`\n🏦 Initialising USDC dest pool for swap test...`);
    destOffchainTree = new OffchainMerkleTree(TREE_HEIGHT, poseidon);

    [destConfig] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_config_v3"), USDC_MINT.toBuffer()],
      program.programId,
    );
    [destVault] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_vault_v3"), USDC_MINT.toBuffer()],
      program.programId,
    );
    [destNoteTree] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("privacy_note_tree_v3"),
        USDC_MINT.toBuffer(),
        encodeTreeId(0),
      ],
      program.programId,
    );
    [destNullifiers] = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_nullifiers_v3"), USDC_MINT.toBuffer()],
      program.programId,
    );

    try {
      await (program.methods as any)
        .initialize(
          50,
          USDC_MINT,
          new BN(1_000),
          new BN(1_000_000_000_000),
          new BN(1_000),
          new BN(1_000_000_000_000),
        )
        .accounts({
          config: destConfig,
          vault: destVault,
          noteTree: destNoteTree,
          nullifiers: destNullifiers,
          admin: wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      console.log("✅ USDC pool initialized");
    } catch (_) {
      console.log("ℹ️  USDC pool already initialized — continuing");
    }

    // Register sharedRelayer on USDC pool too
    try {
      await (program.methods as any)
        .addRelayer(USDC_MINT, sharedRelayer.publicKey)
        .accounts({ config: destConfig, admin: wallet.publicKey })
        .rpc();
      console.log("✅ sharedRelayer registered on USDC pool");
    } catch (_) {
      console.log("ℹ️  sharedRelayer already registered on USDC pool");
    }

    // Derive serum vault signer from SERUM_MARKET nonce (try nonce 0 then 1)
    try {
      serumVaultSigner = PublicKey.createProgramAddressSync(
        [SERUM_MARKET.toBuffer(), Buffer.from([0])],
        SERUM_PROGRAM,
      );
    } catch {
      serumVaultSigner = PublicKey.createProgramAddressSync(
        [SERUM_MARKET.toBuffer(), Buffer.from([1])],
        SERUM_PROGRAM,
      );
    }
    console.log(`✅ Serum vault signer: ${serumVaultSigner.toBase58()}`);

    // Deposit SOL note (2 SOL) to source pool — to be swapped in test 4
    console.log(`\n📥 Pre-depositing 2 SOL to source pool for swap test...`);
    await getOrCreateAssociatedTokenAccount(
      provider.connection,
      sharedRelayer,
      NATIVE_MINT,
      vault,
      true,
    );

    const swapNotePrivKey = randomBytes32();
    const swapNotePubKey = derivePublicKey(poseidon, swapNotePrivKey);
    const swapNoteBlinding = randomBytes32();
    const swapNoteAmount = BigInt(2 * LAMPORTS_PER_SOL);
    const swapNoteCommitment = computeCommitment(
      poseidon,
      swapNoteAmount,
      swapNotePubKey,
      swapNoteBlinding,
      SOL_MINT,
    );

    const dummyPrivKey1 = randomBytes32();
    const dummyPubKey1 = derivePublicKey(poseidon, dummyPrivKey1);
    const dummyBlinding1 = randomBytes32();
    const dummyCommitment1 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey1,
      dummyBlinding1,
      SOL_MINT,
    );
    const dummyNullifier1 = computeNullifier(
      poseidon,
      dummyCommitment1,
      0,
      dummyPrivKey1,
    );

    const dummyPrivKey2 = randomBytes32();
    const dummyPubKey2 = derivePublicKey(poseidon, dummyPrivKey2);
    const dummyBlinding2 = randomBytes32();
    const dummyCommitment2 = computeCommitment(
      poseidon,
      0n,
      dummyPubKey2,
      dummyBlinding2,
      SOL_MINT,
    );
    const dummyNullifier2 = computeNullifier(
      poseidon,
      dummyCommitment2,
      0,
      dummyPrivKey2,
    );

    const changePrivKey = randomBytes32();
    const changePubKey = derivePublicKey(poseidon, changePrivKey);
    const changeBlinding = randomBytes32();
    const changeCommit = computeCommitment(
      poseidon,
      0n,
      changePubKey,
      changeBlinding,
      SOL_MINT,
    );

    const depExtData = {
      recipient: sharedRelayer.publicKey,
      relayer: sharedRelayer.publicKey,
      fee: new BN(0),
      refund: new BN(0),
    };
    const depExtDataHash = computeExtDataHash(poseidon, depExtData);

    const treeAccBefore: any = await (
      program.account as any
    ).merkleTreeAccount.fetch(noteTree);
    const depRoot = extractRootFromAccount(treeAccBefore);

    const zeros = offchainTree.getZeros();
    const zeroPath = zeros.slice(0, TREE_HEIGHT).map((z) => bytesToBigIntBE(z));
    const zeroMerklePath = {
      pathElements: zeroPath,
      pathIndices: new Array(TREE_HEIGHT).fill(0),
    };

    const depProof = await generateTransactionProof({
      root: depRoot,
      publicAmount: swapNoteAmount,
      extDataHash: depExtDataHash,
      mintAddress: SOL_MINT,
      inputNullifiers: [dummyNullifier1, dummyNullifier2],
      outputCommitments: [swapNoteCommitment, changeCommit],
      inputAmounts: [0n, 0n],
      inputPrivateKeys: [dummyPrivKey1, dummyPrivKey2],
      inputPublicKeys: [dummyPubKey1, dummyPubKey2],
      inputBlindings: [dummyBlinding1, dummyBlinding2],
      inputMerklePaths: [zeroMerklePath, zeroMerklePath],
      outputAmounts: [swapNoteAmount, 0n],
      outputOwners: [swapNotePubKey, changePubKey],
      outputBlindings: [swapNoteBlinding, changeBlinding],
    });

    const depNM0 = deriveNullifierMarkerPDA(
      program.programId,
      SOL_MINT,
      dummyNullifier1,
    );
    const depNM1 = deriveNullifierMarkerPDA(
      program.programId,
      SOL_MINT,
      dummyNullifier2,
    );

    const depTxIx = await (program.methods as any)
      .transact(
        Array.from(depRoot),
        0,
        0,
        new BN(swapNoteAmount.toString()),
        Array.from(depExtDataHash),
        SOL_MINT,
        Array.from(dummyNullifier1),
        Array.from(dummyNullifier2),
        Array.from(swapNoteCommitment),
        Array.from(changeCommit),
        new BN(9999999999),
        depExtData,
        depProof,
        null,
      )
      .accounts({
        config,
        globalConfig,
        vault,
        inputTree: noteTree,
        outputTree: noteTree,
        nullifiers,
        nullifierMarker0: depNM0,
        nullifierMarker1: depNM1,
        relayer: sharedRelayer.publicKey,
        recipient: sharedRelayer.publicKey,
        vaultTokenAccount: sharedRelayer.publicKey,
        userTokenAccount: sharedRelayer.publicKey,
        recipientTokenAccount: sharedRelayer.publicKey,
        relayerTokenAccount: sharedRelayer.publicKey,
        tokenProgram: SystemProgram.programId,
        systemProgram: SystemProgram.programId,
      })
      .signers([sharedRelayer])
      .instruction();

    const { blockhash: bh2, lastValidBlockHeight: lvbh2 } =
      await provider.connection.getLatestBlockhash();
    const msgV0dep = new TransactionMessage({
      payerKey: sharedRelayer.publicKey,
      recentBlockhash: bh2,
      instructions: [
        ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
        depTxIx,
      ],
    }).compileToV0Message([swapAlt]);

    const vTxDep = new VersionedTransaction(msgV0dep);
    vTxDep.sign([sharedRelayer]);
    const depTxSig = await provider.connection.sendRawTransaction(
      vTxDep.serialize(),
      { skipPreflight: false },
    );
    await provider.connection.confirmTransaction(
      { signature: depTxSig, blockhash: bh2, lastValidBlockHeight: lvbh2 },
      "confirmed",
    );
    console.log(`✅ Pre-deposit tx confirmed: ${depTxSig.slice(0, 16)}...`);

    const depLeafIndex = offchainTree.insert(swapNoteCommitment);
    offchainTree.insert(changeCommit);
    swapSourceNote = {
      amount: swapNoteAmount,
      commitment: swapNoteCommitment,
      nullifier: computeNullifier(
        poseidon,
        swapNoteCommitment,
        depLeafIndex,
        swapNotePrivKey,
      ),
      blinding: swapNoteBlinding,
      privateKey: swapNotePrivKey,
      publicKey: swapNotePubKey,
      leafIndex: depLeafIndex,
      merklePath: offchainTree.getMerkleProof(depLeafIndex),
    };
    console.log(
      `✅ Swap source note ready: amount=${swapNoteAmount}, leafIndex=${depLeafIndex}`,
    );
  });

  // ---- Pool init is handled in before() so relayer/ALT can depend on it ---

  it("initializes pool and global config (idempotent)", async () => {
    // before() already ran initialize() and initializeGlobalConfig().
    // Confirm the config PDA exists on-chain.
    const info = await provider.connection.getAccountInfo(config);
    assert.ok(info !== null, "Config PDA should exist after initialization");
    console.log("✅ Pool and global config confirmed");
  });

  // ---- Core test: relayer deposits with Some(NoteCiphers) ------------------

  it("relayer passes Some(NoteCiphers) — cipher bytes round-trip through CommitmentEvent", async () => {
    // Use the shared relayer created and registered in before()
    const relayer = sharedRelayer;

    // ---- Note parameters (what the relayer would compute) ------------------
    const depositAmount = BigInt(2 * LAMPORTS_PER_SOL);
    console.log(
      `\n💰 Deposit amount: ${depositAmount} lamports (${
        Number(depositAmount) / LAMPORTS_PER_SOL
      } SOL)`,
    );

    // Output note 0: the real deposit note (goes to user)
    const note0PrivKey = randomBytes32();
    const note0PubKey = derivePublicKey(poseidon, note0PrivKey);
    const note0Blinding = randomBytes32();
    const note0Commitment = computeCommitment(
      poseidon,
      depositAmount,
      note0PubKey,
      note0Blinding,
      SOL_MINT,
    );

    // Output note 1: dummy zero-value note
    const note1PrivKey = randomBytes32();
    const note1PubKey = derivePublicKey(poseidon, note1PrivKey);
    const note1Blinding = randomBytes32();
    const note1Commitment = computeCommitment(
      poseidon,
      0n,
      note1PubKey,
      note1Blinding,
      SOL_MINT,
    );

    console.log(
      `📝 note0: amount=${depositAmount}, commitment=${Buffer.from(
        note0Commitment,
      )
        .toString("hex")
        .slice(0, 16)}...`,
    );
    console.log(
      `📝 note1: amount=0 (dummy),  commitment=${Buffer.from(note1Commitment)
        .toString("hex")
        .slice(0, 16)}...`,
    );

    // ---- NaCl encryption (relayer encrypts secrets for the user) -----------
    // This exactly mirrors how handleWithdrawTransaction / handlePrivateTransferTransaction
    // will call createEncryptedNoteBlob() and then populate NoteCiphers.
    const cipher0 = encryptNoteSecrets(
      userX25519.publicKey,
      note0Blinding,
      depositAmount,
    );
    const cipher1 = encryptNoteSecrets(userX25519.publicKey, note1Blinding, 0n);

    console.log(`\n🔑 Encrypting note secrets with NaCl box (X25519 ECDH)...`);
    console.log(
      `   note0: epk=${Buffer.from(cipher0.ephemeralKey)
        .toString("hex")
        .slice(0, 16)}... blob=${Buffer.from(cipher0.encryptedBlob)
        .toString("hex")
        .slice(0, 16)}...`,
    );
    console.log(
      `   note1: epk=${Buffer.from(cipher1.ephemeralKey)
        .toString("hex")
        .slice(0, 16)}... blob=${Buffer.from(cipher1.encryptedBlob)
        .toString("hex")
        .slice(0, 16)}...`,
    );

    // ---- Build NoteCiphers struct ------------------------------------------
    const noteCiphers = {
      note0EphemeralKey: Array.from(cipher0.ephemeralKey),
      note0Encrypted: Array.from(cipher0.encryptedBlob),
      note1EphemeralKey: Array.from(cipher1.ephemeralKey),
      note1Encrypted: Array.from(cipher1.encryptedBlob),
    };

    // ---- Dummy inputs (zero-value, not in tree — valid for deposit) --------
    const in0PrivKey = randomBytes32();
    const in0PubKey = derivePublicKey(poseidon, in0PrivKey);
    const in0Blinding = randomBytes32();
    const in0Commitment = computeCommitment(
      poseidon,
      0n,
      in0PubKey,
      in0Blinding,
      SOL_MINT,
    );
    const in0Nullifier = computeNullifier(
      poseidon,
      in0Commitment,
      0,
      in0PrivKey,
    );

    const in1PrivKey = randomBytes32();
    const in1PubKey = derivePublicKey(poseidon, in1PrivKey);
    const in1Blinding = randomBytes32();
    const in1Commitment = computeCommitment(
      poseidon,
      0n,
      in1PubKey,
      in1Blinding,
      SOL_MINT,
    );
    const in1Nullifier = computeNullifier(
      poseidon,
      in1Commitment,
      0,
      in1PrivKey,
    );

    console.log(`\n🔲 Dummy inputs (zero-value):`);
    console.log(
      `   nullifier0: ${Buffer.from(in0Nullifier)
        .toString("hex")
        .slice(0, 16)}...`,
    );
    console.log(
      `   nullifier1: ${Buffer.from(in1Nullifier)
        .toString("hex")
        .slice(0, 16)}...`,
    );
    console.log(
      `   nullifierMarker0 PDA: ${deriveNullifierMarkerPDA(
        program.programId,
        SOL_MINT,
        in0Nullifier,
      ).toBase58()}`,
    );
    console.log(
      `   nullifierMarker1 PDA: ${deriveNullifierMarkerPDA(
        program.programId,
        SOL_MINT,
        in1Nullifier,
      ).toBase58()}`,
    );

    // ---- Fetch on-chain root + ext data ------------------------------------
    const extData = {
      recipient: relayer.publicKey,
      relayer: relayer.publicKey,
      fee: new BN(0),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    const treeAcc: any = await (program.account as any).merkleTreeAccount.fetch(
      noteTree,
    );
    const onchainRoot = extractRootFromAccount(treeAcc);
    console.log(
      `\n🌳 On-chain Merkle root: ${Buffer.from(onchainRoot)
        .toString("hex")
        .slice(0, 16)}...`,
    );
    console.log(
      `   Tree leaf count: ${
        treeAcc.nextLeafIndex ?? treeAcc.nextIndex ?? "unknown"
      }`,
    );

    const zeros = offchainTree.getZeros();
    const zeroPath = zeros.slice(0, TREE_HEIGHT).map((z) => bytesToBigIntBE(z));
    const zeroMerklePath = {
      pathElements: zeroPath,
      pathIndices: new Array(TREE_HEIGHT).fill(0),
    };

    // ---- Generate ZK proof -------------------------------------------------
    console.log(`\n🔧 Generating ZK proof (publicAmount=${depositAmount})...`);
    const proof = await generateTransactionProof({
      root: onchainRoot,
      publicAmount: depositAmount,
      extDataHash,
      mintAddress: SOL_MINT,
      inputNullifiers: [in0Nullifier, in1Nullifier],
      outputCommitments: [note0Commitment, note1Commitment],
      inputAmounts: [0n, 0n],
      inputPrivateKeys: [in0PrivKey, in1PrivKey],
      inputPublicKeys: [in0PubKey, in1PubKey],
      inputBlindings: [in0Blinding, in1Blinding],
      inputMerklePaths: [zeroMerklePath, zeroMerklePath],
      outputAmounts: [depositAmount, 0n],
      outputOwners: [note0PubKey, note1PubKey],
      outputBlindings: [note0Blinding, note1Blinding],
    });
    console.log("✓ Proof generated");

    // ---- Build and send transaction (VersionedTransaction + ALT) -----------
    // Some(NoteCiphers) adds 225 bytes to instruction data.  The ALT compresses
    // repeated pubkeys (relayer ×6, noteTree ×2, SystemProgram ×2) by ~217 bytes,
    // keeping the total well under the 1232-byte VersionedTransaction limit.
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      SOL_MINT,
      in0Nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      SOL_MINT,
      in1Nullifier,
    );

    let txSig: string;
    try {
      const transactIx = await (program.methods as any)
        .transact(
          Array.from(onchainRoot),
          0, // input_tree_id
          0, // output_tree_id
          new BN(depositAmount.toString()),
          Array.from(extDataHash),
          SOL_MINT,
          Array.from(in0Nullifier),
          Array.from(in1Nullifier),
          Array.from(note0Commitment),
          Array.from(note1Commitment),
          new BN(9999999999), // deadline (far future for tests)
          extData,
          proof,
          noteCiphers, // ← Some(NoteCiphers) — production relayer path
        )
        .accounts({
          config,
          globalConfig,
          vault,
          inputTree: noteTree,
          outputTree: noteTree,
          nullifiers,
          nullifierMarker0,
          nullifierMarker1,
          relayer: relayer.publicKey,
          recipient: relayer.publicKey,
          vaultTokenAccount: relayer.publicKey,
          userTokenAccount: relayer.publicKey,
          recipientTokenAccount: relayer.publicKey,
          relayerTokenAccount: relayer.publicKey,
          tokenProgram: SystemProgram.programId,
          systemProgram: SystemProgram.programId,
        })
        .signers([relayer])
        .instruction();

      const { blockhash, lastValidBlockHeight } =
        await provider.connection.getLatestBlockhash();
      const messageV0 = new TransactionMessage({
        payerKey: relayer.publicKey,
        recentBlockhash: blockhash,
        instructions: [
          ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
          transactIx,
        ],
      }).compileToV0Message([swapAlt]);

      const vTx = new VersionedTransaction(messageV0);
      vTx.sign([relayer]);

      const serialized = vTx.serialize();
      console.log(
        `\n📦 VersionedTransaction size: ${serialized.length} bytes (limit 1232)`,
      );
      console.log(
        `   Accounts in message: ${messageV0.staticAccountKeys.length} static + ${messageV0.addressTableLookups.length} ALT lookup(s)`,
      );

      txSig = await provider.connection.sendRawTransaction(serialized, {
        skipPreflight: false,
      });
      console.log(`   Sent: ${txSig}`);
      await provider.connection.confirmTransaction(
        { signature: txSig, blockhash, lastValidBlockHeight },
        "confirmed",
      );
      console.log(`✅ Deposit tx confirmed: ${txSig.slice(0, 16)}...`);
    } catch (e: any) {
      if (e instanceof SendTransactionError) {
        console.error("Tx logs:", await e.getLogs(provider.connection));
      }
      throw e;
    }

    // ---- Parse CommitmentEvents from logs ----------------------------------
    const confirmedTx = await provider.connection.getTransaction(txSig, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });
    const logs = confirmedTx?.meta?.logMessages ?? [];
    const events = parseCommitmentEvents(logs, program);

    assert.strictEqual(
      events.length,
      2,
      `Expected 2 CommitmentEvents, got ${events.length}`,
    );
    console.log(`\n📋 Parsed ${events.length} CommitmentEvent(s) from logs`);
    for (const [i, ev] of events.entries()) {
      console.log(
        `   event[${i}]: leafIndex=${ev.leafIndex}, treeId=${ev.treeId}`,
      );
      console.log(
        `           commitment=${ev.commitment
          .toString("hex")
          .slice(0, 16)}...`,
      );
      console.log(
        `           epk=${ev.ephemeralPublicKey
          .toString("hex")
          .slice(0, 16)}...`,
      );
      console.log(
        `           blob=${ev.encryptedBlob.toString("hex").slice(0, 16)}...`,
      );
    }

    // Map events to note0 and note1 by commitment bytes
    const eventForNote0 = events.find((e) =>
      e.commitment.equals(Buffer.from(note0Commitment)),
    );
    const eventForNote1 = events.find((e) =>
      e.commitment.equals(Buffer.from(note1Commitment)),
    );

    assert.ok(eventForNote0, "CommitmentEvent for note0 not found");
    assert.ok(eventForNote1, "CommitmentEvent for note1 not found");

    // ---- Verify cipher bytes were stored verbatim --------------------------

    // note0: real cipher
    assert.ok(
      eventForNote0!.ephemeralPublicKey.equals(
        Buffer.from(cipher0.ephemeralKey),
      ),
      "note0 ephemeral_public_key mismatch in CommitmentEvent",
    );
    assert.ok(
      eventForNote0!.encryptedBlob.equals(Buffer.from(cipher0.encryptedBlob)),
      "note0 encrypted_blob mismatch in CommitmentEvent",
    );
    console.log("✅ note0 cipher bytes match CommitmentEvent");

    // note1: real cipher
    assert.ok(
      eventForNote1!.ephemeralPublicKey.equals(
        Buffer.from(cipher1.ephemeralKey),
      ),
      "note1 ephemeral_public_key mismatch in CommitmentEvent",
    );
    assert.ok(
      eventForNote1!.encryptedBlob.equals(Buffer.from(cipher1.encryptedBlob)),
      "note1 encrypted_blob mismatch in CommitmentEvent",
    );
    console.log("✅ note1 cipher bytes match CommitmentEvent");

    // ---- Decrypt and verify the user can recover note secrets --------------
    // Simulates the user's SDK scanning chain history and decrypting blobs.

    console.log(
      "\n🔓 Decrypting blobs from CommitmentEvent fields using user X25519 secret key...",
    );

    const recovered0 = decryptNoteSecrets(
      userX25519.secretKey,
      eventForNote0!.ephemeralPublicKey,
      eventForNote0!.encryptedBlob,
    );
    console.log(
      `   note0 original  blinding: ${Buffer.from(note0Blinding).toString(
        "hex",
      )}`,
    );
    console.log(
      `   note0 decrypted blinding: ${Buffer.from(recovered0.blinding).toString(
        "hex",
      )}`,
    );
    console.log(`   note0 original  amount:   ${depositAmount} lamports`);
    console.log(`   note0 decrypted amount:   ${recovered0.amount} lamports`);
    assert.ok(
      Buffer.from(recovered0.blinding).equals(Buffer.from(note0Blinding)),
      "Decrypted blinding does not match original for note0",
    );
    assert.strictEqual(
      recovered0.amount,
      depositAmount,
      "Decrypted amount does not match for note0",
    );
    console.log(
      `✅ note0 decrypted correctly: amount=${recovered0.amount} lamports (${
        Number(recovered0.amount) / LAMPORTS_PER_SOL
      } SOL), blinding matches ✓`,
    );

    const recovered1 = decryptNoteSecrets(
      userX25519.secretKey,
      eventForNote1!.ephemeralPublicKey,
      eventForNote1!.encryptedBlob,
    );
    console.log(
      `   note1 original  blinding: ${Buffer.from(note1Blinding).toString(
        "hex",
      )}`,
    );
    console.log(
      `   note1 decrypted blinding: ${Buffer.from(recovered1.blinding).toString(
        "hex",
      )}`,
    );
    console.log(`   note1 original  amount:   0 lamports (dummy note)`);
    console.log(`   note1 decrypted amount:   ${recovered1.amount} lamports`);
    assert.ok(
      Buffer.from(recovered1.blinding).equals(Buffer.from(note1Blinding)),
      "Decrypted blinding does not match original for note1",
    );
    assert.strictEqual(
      recovered1.amount,
      0n,
      "Decrypted amount does not match for note1",
    );
    console.log("✅ note1 decrypted correctly: amount=0, blinding matches ✓");

    console.log(
      "\n🎉 Full round-trip confirmed: encrypt → on-chain event → decrypt",
    );

    // ---- Security edge cases -----------------------------------------------

    // 1. A completely different X25519 key cannot decrypt either note.
    //    nacl.box.open returns null when the MAC check fails — this is the
    //    authenticated-encryption guarantee: no other key can forge a valid tag.
    console.log("\n🔒 Security: verifying wrong key cannot decrypt...");
    const wrongKey = nacl.box.keyPair();
    const failedOpen0 = nacl.box.open(
      eventForNote0!.encryptedBlob.slice(24),
      eventForNote0!.encryptedBlob.slice(0, 24),
      eventForNote0!.ephemeralPublicKey,
      wrongKey.secretKey,
    );
    assert.strictEqual(
      failedOpen0,
      null,
      "Wrong key must NOT decrypt note0 — MAC verification must fail",
    );
    const failedOpen1 = nacl.box.open(
      eventForNote1!.encryptedBlob.slice(24),
      eventForNote1!.encryptedBlob.slice(0, 24),
      eventForNote1!.ephemeralPublicKey,
      wrongKey.secretKey,
    );
    assert.strictEqual(
      failedOpen1,
      null,
      "Wrong key must NOT decrypt note1 — MAC verification must fail",
    );
    console.log("✅ Wrong key correctly rejected for both notes");

    // 2. Bit-flip in the ciphertext is detected (MAC integrity).
    //    Flip one bit in the boxed portion and confirm decryption fails.
    const tampered = Buffer.from(eventForNote0!.encryptedBlob);
    tampered[24] ^= 0x01; // flip first byte of the box output (MAC region)
    const failedTampered = nacl.box.open(
      tampered.slice(24),
      tampered.slice(0, 24),
      eventForNote0!.ephemeralPublicKey,
      userX25519.secretKey,
    );
    assert.strictEqual(
      failedTampered,
      null,
      "Tampered ciphertext must fail MAC verification",
    );
    console.log("✅ Tampered ciphertext correctly rejected");

    // 3. Two separate encryptions of the same plaintext yield different ciphertexts
    //    because each uses a fresh random ephemeral keypair AND a fresh random nonce.
    //    This prevents correlation attacks across notes.
    const cipherA = encryptNoteSecrets(
      userX25519.publicKey,
      note0Blinding,
      depositAmount,
    );
    const cipherB = encryptNoteSecrets(
      userX25519.publicKey,
      note0Blinding,
      depositAmount,
    );
    assert.ok(
      !Buffer.from(cipherA.encryptedBlob).equals(
        Buffer.from(cipherB.encryptedBlob),
      ),
      "Re-encrypting the same plaintext must produce a different ciphertext (fresh nonce)",
    );
    assert.ok(
      !Buffer.from(cipherA.ephemeralKey).equals(
        Buffer.from(cipherB.ephemeralKey),
      ),
      "Each encryption must use a fresh ephemeral key (prevents correlation)",
    );
    console.log("✅ Re-encryption produces fresh, uncorrelated ciphertext");

    // 4. The relayer key (signing key) cannot decrypt the notes — only the
    //    recipient's X25519 key can.  The relayer holds the ephemeral secret key
    //    during encryption but discards it; afterward, only ECDH with the
    //    recipient secret can derive the shared key.  We simulate a relayer who
    //    retains their Ed25519 signing key and attempts to use it for decryption.
    const relayerAsCurve25519 = nacl.box.keyPair(); // simulate relayer generating an X25519 key
    const failedRelayer = nacl.box.open(
      eventForNote0!.encryptedBlob.slice(24),
      eventForNote0!.encryptedBlob.slice(0, 24),
      eventForNote0!.ephemeralPublicKey,
      relayerAsCurve25519.secretKey,
    );
    assert.strictEqual(
      failedRelayer,
      null,
      "Relayer key must NOT be able to decrypt user notes",
    );
    console.log("✅ Relayer key correctly rejected — only user can decrypt");

    // Keep offchainTree in sync so test 4's Merkle path is valid against on-chain root
    offchainTree.insert(note0Commitment);
    offchainTree.insert(note1Commitment);
  });

  // ---- Sanity check: null still works and emits zero bytes -----------------

  it("null (None) is accepted and CommitmentEvent emits zero cipher bytes", async () => {
    // Use the shared relayer created and registered in before()
    const relayer = sharedRelayer;

    const depositAmount = BigInt(1 * LAMPORTS_PER_SOL);
    console.log(
      `\n💰 Null-cipher deposit: ${depositAmount} lamports (${
        Number(depositAmount) / LAMPORTS_PER_SOL
      } SOL)`,
    );

    const out0PrivKey = randomBytes32();
    const out0PubKey = derivePublicKey(poseidon, out0PrivKey);
    const out0Blinding = randomBytes32();
    const out0Commitment = computeCommitment(
      poseidon,
      depositAmount,
      out0PubKey,
      out0Blinding,
      SOL_MINT,
    );

    const out1PrivKey = randomBytes32();
    const out1PubKey = derivePublicKey(poseidon, out1PrivKey);
    const out1Blinding = randomBytes32();
    const out1Commitment = computeCommitment(
      poseidon,
      0n,
      out1PubKey,
      out1Blinding,
      SOL_MINT,
    );

    const in0PrivKey = randomBytes32();
    const in0PubKey = derivePublicKey(poseidon, in0PrivKey);
    const in0Blinding = randomBytes32();
    const in0Commitment = computeCommitment(
      poseidon,
      0n,
      in0PubKey,
      in0Blinding,
      SOL_MINT,
    );
    const in0Nullifier = computeNullifier(
      poseidon,
      in0Commitment,
      0,
      in0PrivKey,
    );

    const in1PrivKey = randomBytes32();
    const in1PubKey = derivePublicKey(poseidon, in1PrivKey);
    const in1Blinding = randomBytes32();
    const in1Commitment = computeCommitment(
      poseidon,
      0n,
      in1PubKey,
      in1Blinding,
      SOL_MINT,
    );
    const in1Nullifier = computeNullifier(
      poseidon,
      in1Commitment,
      0,
      in1PrivKey,
    );

    const extData = {
      recipient: relayer.publicKey,
      relayer: relayer.publicKey,
      fee: new BN(0),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    const treeAcc: any = await (program.account as any).merkleTreeAccount.fetch(
      noteTree,
    );
    const onchainRoot = extractRootFromAccount(treeAcc);

    const zeros = offchainTree.getZeros();
    const zeroPath = zeros.slice(0, TREE_HEIGHT).map((z) => bytesToBigIntBE(z));
    const zeroMerklePath = {
      pathElements: zeroPath,
      pathIndices: new Array(TREE_HEIGHT).fill(0),
    };

    console.log(
      `🔧 Generating ZK proof (null ciphers, publicAmount=${depositAmount})...`,
    );
    const proof = await generateTransactionProof({
      root: onchainRoot,
      publicAmount: depositAmount,
      extDataHash,
      mintAddress: SOL_MINT,
      inputNullifiers: [in0Nullifier, in1Nullifier],
      outputCommitments: [out0Commitment, out1Commitment],
      inputAmounts: [0n, 0n],
      inputPrivateKeys: [in0PrivKey, in1PrivKey],
      inputPublicKeys: [in0PubKey, in1PubKey],
      inputBlindings: [in0Blinding, in1Blinding],
      inputMerklePaths: [zeroMerklePath, zeroMerklePath],
      outputAmounts: [depositAmount, 0n],
      outputOwners: [out0PubKey, out1PubKey],
      outputBlindings: [out0Blinding, out1Blinding],
    });

    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      SOL_MINT,
      in0Nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      SOL_MINT,
      in1Nullifier,
    );

    let txSig: string;
    try {
      const ix = await (program.methods as any)
        .transact(
          Array.from(onchainRoot),
          0,
          0,
          new BN(depositAmount.toString()),
          Array.from(extDataHash),
          SOL_MINT,
          Array.from(in0Nullifier),
          Array.from(in1Nullifier),
          Array.from(out0Commitment),
          Array.from(out1Commitment),
          new BN(9999999999),
          extData,
          proof,
          null, // ← None — test-style omit
        )
        .accounts({
          config,
          globalConfig,
          vault,
          inputTree: noteTree,
          outputTree: noteTree,
          nullifiers,
          nullifierMarker0,
          nullifierMarker1,
          relayer: relayer.publicKey,
          recipient: relayer.publicKey,
          vaultTokenAccount: relayer.publicKey,
          userTokenAccount: relayer.publicKey,
          recipientTokenAccount: relayer.publicKey,
          relayerTokenAccount: relayer.publicKey,
          tokenProgram: SystemProgram.programId,
          systemProgram: SystemProgram.programId,
        })
        .signers([relayer])
        .transaction();

      const tx = new Transaction();
      tx.add(ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }));
      tx.add(ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1 }));
      tx.add(ix);

      txSig = await provider.sendAndConfirm(tx, [relayer]);
      console.log(
        `✅ Null-cipher deposit tx confirmed: ${txSig.slice(0, 16)}...`,
      );
    } catch (e: any) {
      if (e instanceof SendTransactionError) {
        console.error("Tx logs:", await e.getLogs(provider.connection));
      }
      throw e;
    }

    const confirmedTx = await provider.connection.getTransaction(txSig, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });
    const events = parseCommitmentEvents(
      confirmedTx?.meta?.logMessages ?? [],
      program,
    );

    assert.strictEqual(
      events.length,
      2,
      `Expected 2 CommitmentEvents, got ${events.length}`,
    );
    console.log(
      `\n📋 Parsed ${events.length} CommitmentEvent(s) from null-cipher tx logs`,
    );
    for (const [i, ev] of events.entries()) {
      console.log(
        `   event[${i}]: leafIndex=${ev.leafIndex}, commitment=${ev.commitment
          .toString("hex")
          .slice(0, 16)}...`,
      );
      console.log(
        `           epk=${ev.ephemeralPublicKey.toString(
          "hex",
        )} (expect all zeros)`,
      );
    }

    for (const event of events) {
      const allZeroEpk = event.ephemeralPublicKey.every((b) => b === 0);
      const allZeroBlob = event.encryptedBlob.every((b) => b === 0);
      assert.ok(
        allZeroEpk,
        "ephemeral_public_key should be all-zero for null ciphers",
      );
      assert.ok(
        allZeroBlob,
        "encrypted_blob should be all-zero for null ciphers",
      );
    }

    // Keep offchainTree in sync so test 4's Merkle path is valid against on-chain root
    offchainTree.insert(out0Commitment);
    offchainTree.insert(out1Commitment);

    console.log("✅ null ciphers → CommitmentEvent has all-zero cipher fields");
    console.log(
      "✅ Backward compatibility confirmed: tests/legacy callers unaffected",
    );
  });

  // ---- Test 4: transact_swap() with Some(NoteCiphers) ---------------------

  it("relayer passes Some(NoteCiphers) on transact_swap — cipher bytes in both CommitmentEvents", async () => {
    if (!swapSourceNote)
      throw new Error("swapSourceNote not initialised in before()");
    console.log("\n🔄 Test 4: transact_swap() with Some(NoteCiphers)...");

    const relayer = sharedRelayer;
    const note = swapSourceNote;

    // ---- Swap parameters ---------------------------------------------------
    const SWAP_AMOUNT = 500_000_000n; // 0.5 SOL
    const SWAP_FEE = 375_000n; // 0.375 USDC relayer fee (> pool min_swap_fee of 0.05 USDC)
    // swappedAmount = dest note value committed in the ZK proof.
    // Must satisfy: vault_amount (actual_raydium_output - fee) >= swappedAmount.
    // Use 1 USDC so this holds regardless of current mainnet pool rate at clone time.
    const swappedAmount = 1_000_000n; // 1 USDC — very conservative
    const changeAmount = note.amount - SWAP_AMOUNT;
    const minAmountOut = 1_000_000n; // 1 USDC minimum from Raydium
    const deadline = BigInt(Math.floor(Date.now() / 1000) + 3_600);

    console.log(
      `   Input note: ${note.amount} lamports, leafIndex=${note.leafIndex}`,
    );
    console.log(
      `   Swap amount: ${SWAP_AMOUNT} lamports → ~${
        swappedAmount / 1_000_000n
      } USDC`,
    );
    console.log(`   Change: ${changeAmount} lamports`);

    // ---- Dummy second input ------------------------------------------------
    const dummyPrivKey = randomBytes32();
    const dummyPubKey = derivePublicKey(poseidon, dummyPrivKey);
    const dummyBlinding = randomBytes32();
    const dummyCommitment = computeCommitment(
      poseidon,
      0n,
      dummyPubKey,
      dummyBlinding,
      SOL_MINT,
    );
    const dummyNullifier = computeNullifier(
      poseidon,
      dummyCommitment,
      0,
      dummyPrivKey,
    );
    const dummyProof = offchainTree.getMerkleProof(0);

    // ---- Change and dest output notes --------------------------------------
    const changePrivKey = randomBytes32();
    const changePubKey = derivePublicKey(poseidon, changePrivKey);
    const changeBlinding = randomBytes32();
    const changeCommitment = computeCommitment(
      poseidon,
      changeAmount,
      changePubKey,
      changeBlinding,
      SOL_MINT,
    );

    const destPrivKey = randomBytes32();
    const destPubKey = derivePublicKey(poseidon, destPrivKey);
    const destBlinding = randomBytes32();
    const destCommitment = computeCommitment(
      poseidon,
      swappedAmount,
      destPubKey,
      destBlinding,
      USDC_MINT,
    );

    // ---- Encrypt note secrets (both change note + dest note) ---------------
    console.log(`\n🔑 Encrypting change note and dest note with X25519...`);
    const cipherChange = encryptNoteSecrets(
      userX25519.publicKey,
      changeBlinding,
      changeAmount,
    );
    const cipherDest = encryptNoteSecrets(
      userX25519.publicKey,
      destBlinding,
      swappedAmount,
    );

    console.log(
      `   change epk:  ${Buffer.from(cipherChange.ephemeralKey)
        .toString("hex")
        .slice(0, 16)}...`,
    );
    console.log(
      `   change blob: ${Buffer.from(cipherChange.encryptedBlob)
        .toString("hex")
        .slice(0, 16)}...`,
    );
    console.log(
      `   dest epk:    ${Buffer.from(cipherDest.ephemeralKey)
        .toString("hex")
        .slice(0, 16)}...`,
    );
    console.log(
      `   dest blob:   ${Buffer.from(cipherDest.encryptedBlob)
        .toString("hex")
        .slice(0, 16)}...`,
    );

    // note0 = change note (source pool), note1 = dest note (dest pool)
    const noteCiphers = {
      note0EphemeralKey: Array.from(cipherChange.ephemeralKey),
      note0Encrypted: Array.from(cipherChange.encryptedBlob),
      note1EphemeralKey: Array.from(cipherDest.ephemeralKey),
      note1Encrypted: Array.from(cipherDest.encryptedBlob),
    };

    // ---- External data -----------------------------------------------------
    const extData = {
      recipient: relayer.publicKey,
      relayer: relayer.publicKey,
      fee: new BN(SWAP_FEE.toString()),
      refund: new BN(0),
    };
    const extDataHash = computeExtDataHash(poseidon, extData);

    // ---- Swap params hash (must match proof and on-chain check) ------------
    const swapParamsHash = computeSwapParamsHash(
      poseidon,
      SOL_MINT,
      USDC_MINT,
      minAmountOut,
      deadline,
      swappedAmount,
    );

    // ---- Generate ZK swap proof --------------------------------------------
    console.log(`\n🔧 Generating ZK swap proof...`);
    const sourceRoot = new Uint8Array(
      (
        await (program.account as any).merkleTreeAccount.fetch(noteTree)
      ).rootHistory[
        (
          await (program.account as any).merkleTreeAccount.fetch(noteTree)
        ).rootIndex
      ],
    );

    // Use fresh Merkle proof from the current (fully-synced) offchainTree.
    // note.merklePath was computed in before() when the tree had only 2 leaves;
    // tests 2 and 3 each added 2 more leaves, so we must recompute.
    const currentMerklePath = offchainTree.getMerkleProof(note.leafIndex);

    const swapProof = await generateSwapProof({
      sourceRoot,
      swapParamsHash,
      extDataHash,
      sourceMint: SOL_MINT,
      destMint: USDC_MINT,
      inputNullifiers: [note.nullifier, dummyNullifier],
      changeCommitment,
      destCommitment,
      swapAmount: SWAP_AMOUNT,
      inputAmounts: [note.amount, 0n],
      inputPrivateKeys: [note.privateKey, dummyPrivKey],
      inputPublicKeys: [note.publicKey, dummyPubKey],
      inputBlindings: [note.blinding, dummyBlinding],
      inputMerklePaths: [currentMerklePath, dummyProof],
      changeAmount,
      changePubkey: changePubKey,
      changeBlinding,
      destAmount: swappedAmount,
      destPubkey: destPubKey,
      destBlinding,
      minAmountOut,
      deadline,
    });
    console.log("✓ Swap proof generated");

    // ---- AMM swap data (Raydium V4 swap_base_in) ---------------------------
    const swapData = buildAmmSwapData(SWAP_AMOUNT, minAmountOut);

    // ---- swapParams struct (must match values committed to in proof) --------
    const swapParams = {
      minAmountOut: new BN(minAmountOut.toString()),
      deadline: new BN(deadline.toString()),
      destAmount: new BN(swappedAmount.toString()),
      swapDataHash: Buffer.alloc(32),
    };

    // ---- Account derivations -----------------------------------------------
    const nullifierMarker0 = deriveNullifierMarkerPDA(
      program.programId,
      SOL_MINT,
      note.nullifier,
    );
    const nullifierMarker1 = deriveNullifierMarkerPDA(
      program.programId,
      SOL_MINT,
      dummyNullifier,
    );

    const sourceNullifiers = PublicKey.findProgramAddressSync(
      [Buffer.from("privacy_nullifiers_v3"), SOL_MINT.toBuffer()],
      program.programId,
    )[0];

    const [executorPda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("swap_executor"),
        SOL_MINT.toBuffer(),
        USDC_MINT.toBuffer(),
        Buffer.from(note.nullifier),
        relayer.publicKey.toBuffer(),
      ],
      program.programId,
    );

    const sourceVaultWsolAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      relayer,
      NATIVE_MINT,
      vault,
      true,
    );
    const destVaultUsdcAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      relayer,
      USDC_MINT,
      destVault,
      true,
    );
    const relayerTokenAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      relayer,
      USDC_MINT,
      relayer.publicKey,
    );
    const executorSourceToken = await getAssociatedTokenAddress(
      NATIVE_MINT,
      executorPda,
      true,
    );
    const executorDestToken = await getAssociatedTokenAddress(
      USDC_MINT,
      executorPda,
      true,
    );

    console.log(`   Executor PDA:        ${executorPda.toBase58()}`);
    console.log(
      `   sourceVault wSOL:    ${sourceVaultWsolAccount.address.toBase58()}`,
    );
    console.log(
      `   destVault USDC:      ${destVaultUsdcAccount.address.toBase58()}`,
    );

    // ---- Build ALT for this swap (includes all 30+ accounts needed) --------
    console.log(`\n🗂️  Building swap ALT...`);
    const swapSlot = await provider.connection.getSlot("finalized");
    const [createSwapLutIx, swapLutAddress] =
      AddressLookupTableProgram.createLookupTable({
        authority: wallet.publicKey,
        payer: wallet.publicKey,
        recentSlot: swapSlot,
      });
    const swapLutAddresses = [
      config,
      globalConfig,
      vault,
      noteTree,
      nullifiers,
      sourceNullifiers,
      sourceVaultWsolAccount.address,
      NATIVE_MINT,
      destConfig,
      destVault,
      destNoteTree,
      destNullifiers,
      destVaultUsdcAccount.address,
      USDC_MINT,
      executorPda,
      executorSourceToken,
      executorDestToken,
      relayer.publicKey,
      relayerTokenAccount.address,
      RAYDIUM_AMM_V4_PROGRAM,
      SERUM_PROGRAM,
      TOKEN_PROGRAM_ID,
      SystemProgram.programId,
      ASSOCIATED_TOKEN_PROGRAM_ID,
      AMM_POOL_STATE,
      AMM_AUTHORITY,
      AMM_OPEN_ORDERS,
      AMM_TARGET_ORDERS,
      AMM_BASE_VAULT,
      AMM_QUOTE_VAULT,
      SERUM_MARKET,
      SERUM_BIDS,
      SERUM_ASKS,
      SERUM_EVENT_QUEUE,
      SERUM_BASE_VAULT,
      SERUM_QUOTE_VAULT,
      serumVaultSigner,
      // Include per-tx PDAs and program IDs in the ALT so they resolve as
      // 1-byte ALT indices rather than 32-byte static accounts, keeping the
      // final VersionedTransaction under the 1232-byte Solana size limit.
      nullifierMarker0,
      nullifierMarker1,
      program.programId,
      ComputeBudgetProgram.programId,
    ];
    // Split into two extend calls — 41 addresses × 32 bytes overflows a single legacy tx
    const batch1 = swapLutAddresses.slice(0, 21);
    const batch2 = swapLutAddresses.slice(21);
    await provider.sendAndConfirm(
      new Transaction().add(
        createSwapLutIx,
        AddressLookupTableProgram.extendLookupTable({
          payer: wallet.publicKey,
          authority: wallet.publicKey,
          lookupTable: swapLutAddress,
          addresses: batch1,
        }),
      ),
    );
    await provider.sendAndConfirm(
      new Transaction().add(
        AddressLookupTableProgram.extendLookupTable({
          payer: wallet.publicKey,
          authority: wallet.publicKey,
          lookupTable: swapLutAddress,
          addresses: batch2,
        }),
      ),
    );
    console.log(`   Swap ALT: ${swapLutAddress.toBase58()}`);
    const swapLookupTable = await pollAlt(
      provider.connection,
      swapLutAddress,
      swapLutAddresses.length,
    );

    // ---- Build transactSwap instruction ------------------------------------
    const swapIx = await (program.methods as any)
      .transactSwap(
        0, // sourceTreeId
        SOL_MINT, // sourceMint
        Array.from(note.nullifier),
        Array.from(dummyNullifier),
        0, // destTreeId
        USDC_MINT, // destMint
        swapProof,
        Array.from(sourceRoot),
        Array.from(changeCommitment),
        Array.from(destCommitment),
        swapParams,
        new BN(SWAP_AMOUNT.toString()),
        swapData,
        extData,
        noteCiphers, // ← Some(NoteCiphers) — the key assertion!
      )
      .accounts({
        sourceConfig: config,
        globalConfig,
        sourceVault: vault,
        sourceTree: noteTree,
        sourceNullifiers,
        sourceNullifierMarker0: nullifierMarker0,
        sourceNullifierMarker1: nullifierMarker1,
        sourceVaultTokenAccount: sourceVaultWsolAccount.address,
        sourceMintAccount: NATIVE_MINT,
        destConfig,
        destVault,
        destTree: destNoteTree,
        destVaultTokenAccount: destVaultUsdcAccount.address,
        destMintAccount: USDC_MINT,
        executor: executorPda,
        executorSourceToken,
        executorDestToken,
        relayer: relayer.publicKey,
        relayerTokenAccount: relayerTokenAccount.address,
        swapProgram: RAYDIUM_AMM_V4_PROGRAM,
        jupiterEventAuthority: SystemProgram.programId,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      })
      .remainingAccounts([
        { pubkey: AMM_POOL_STATE, isSigner: false, isWritable: true },
        { pubkey: AMM_AUTHORITY, isSigner: false, isWritable: false },
        { pubkey: AMM_OPEN_ORDERS, isSigner: false, isWritable: true },
        { pubkey: AMM_TARGET_ORDERS, isSigner: false, isWritable: true },
        { pubkey: AMM_BASE_VAULT, isSigner: false, isWritable: true },
        { pubkey: AMM_QUOTE_VAULT, isSigner: false, isWritable: true },
        { pubkey: SERUM_PROGRAM, isSigner: false, isWritable: false },
        { pubkey: SERUM_MARKET, isSigner: false, isWritable: true },
        { pubkey: SERUM_BIDS, isSigner: false, isWritable: true },
        { pubkey: SERUM_ASKS, isSigner: false, isWritable: true },
        { pubkey: SERUM_EVENT_QUEUE, isSigner: false, isWritable: true },
        { pubkey: SERUM_BASE_VAULT, isSigner: false, isWritable: true },
        { pubkey: SERUM_QUOTE_VAULT, isSigner: false, isWritable: true },
        { pubkey: serumVaultSigner, isSigner: false, isWritable: false },
      ])
      .signers([relayer])
      .instruction();

    // ---- Build and send VersionedTransaction + ALT -------------------------
    const computeIx = ComputeBudgetProgram.setComputeUnitLimit({
      units: 1_400_000,
    });
    const { blockhash } = await provider.connection.getLatestBlockhash();
    const messageV0 = new TransactionMessage({
      payerKey: relayer.publicKey,
      recentBlockhash: blockhash,
      instructions: [computeIx, swapIx],
    }).compileToV0Message([swapLookupTable]);

    console.log(`   Static accounts (${messageV0.staticAccountKeys.length}):`);
    messageV0.staticAccountKeys.forEach((k, i) =>
      console.log(`     [${i}] ${k.toBase58()}`),
    );
    for (const alt of messageV0.addressTableLookups) {
      console.log(
        `   ALT ${alt.accountKey.toBase58().slice(0, 8)}: ${
          alt.writableIndexes.length
        } writable + ${alt.readonlyIndexes.length} readonly`,
      );
    }

    const vTx = new VersionedTransaction(messageV0);

    const serialized = vTx.serialize();
    console.log(
      `\n📦 VersionedTransaction size: ${serialized.length} bytes (limit 1232)`,
    );
    if (serialized.length > 1232) {
      throw new Error(
        `Transaction too large: ${serialized.length} > 1232 bytes`,
      );
    }

    // Build a temporary provider whose wallet is the relayer keypair.
    // provider.sendAndConfirm internally calls wallet.signTransaction(vTx) which
    // calls vTx.sign([wallet.payer]).  Because relayer IS the payer/required signer
    // (index 0 in the message), this succeeds and returns a properly-encoded txSig
    // that getTransaction accepts.  Using the main wallet would fail ("Cannot sign
    // with non signer key") since it is not in the VersionedMessage.
    const relayerWallet = new anchorVal.Wallet(relayer);
    const relayerProvider = new anchorVal.AnchorProvider(
      provider.connection,
      relayerWallet,
      { commitment: "confirmed" },
    );

    let txSig: string;
    try {
      txSig = await relayerProvider.sendAndConfirm(vTx, [], {
        commitment: "confirmed",
        skipPreflight: false,
      });
      console.log(`✅ transact_swap tx confirmed: ${txSig.slice(0, 16)}...`);
    } catch (e: any) {
      if (e instanceof SendTransactionError) {
        console.error("Tx logs:", await e.getLogs(provider.connection));
      } else {
        console.error("Error:", e.message, (e as any).logs ?? "");
      }
      throw e;
    }

    // ---- Parse CommitmentEvents -------------------------------------------
    const confirmedTx = await provider.connection.getTransaction(txSig!, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });
    const events = parseCommitmentEvents(
      confirmedTx?.meta?.logMessages ?? [],
      program,
    );

    assert.strictEqual(
      events.length,
      2,
      `Expected 2 CommitmentEvents from transact_swap, got ${events.length}`,
    );
    console.log(
      `\n📋 Parsed ${events.length} CommitmentEvent(s) from transact_swap logs`,
    );

    // Rust swap.rs emits dest note first (into dest pool), then change note (into source pool)
    const [evDest, evChange] = events;
    console.log(
      `   event[0] (dest):   leafIndex=${
        evDest.leafIndex
      }, commitment=${evDest.commitment.toString("hex").slice(0, 16)}...`,
    );
    console.log(
      `           epk=${evDest.ephemeralPublicKey
        .toString("hex")
        .slice(0, 16)}...`,
    );
    console.log(
      `           blob=${evDest.encryptedBlob.toString("hex").slice(0, 16)}...`,
    );
    console.log(
      `   event[1] (change): leafIndex=${
        evChange.leafIndex
      }, commitment=${evChange.commitment.toString("hex").slice(0, 16)}...`,
    );
    console.log(
      `           epk=${evChange.ephemeralPublicKey
        .toString("hex")
        .slice(0, 16)}...`,
    );
    console.log(
      `           blob=${evChange.encryptedBlob
        .toString("hex")
        .slice(0, 16)}...`,
    );

    // ---- Assert cipher bytes round-tripped correctly -----------------------
    assert.deepStrictEqual(
      Array.from(evChange.ephemeralPublicKey),
      Array.from(cipherChange.ephemeralKey),
      "change note: ephemeralPublicKey mismatch",
    );
    assert.deepStrictEqual(
      Array.from(evChange.encryptedBlob),
      Array.from(cipherChange.encryptedBlob),
      "change note: encryptedBlob mismatch",
    );
    assert.deepStrictEqual(
      Array.from(evDest.ephemeralPublicKey),
      Array.from(cipherDest.ephemeralKey),
      "dest note: ephemeralPublicKey mismatch",
    );
    assert.deepStrictEqual(
      Array.from(evDest.encryptedBlob),
      Array.from(cipherDest.encryptedBlob),
      "dest note: encryptedBlob mismatch",
    );
    console.log(
      "✅ Cipher bytes match what relayer passed in noteCiphers struct",
    );

    // ---- Decrypt both blobs and verify secrets ----------------------------
    console.log("\n🔓 Decrypting both notes with user X25519 secret key...");

    const decChange = decryptNoteSecrets(
      userX25519.secretKey,
      evChange.ephemeralPublicKey,
      evChange.encryptedBlob,
    );
    const decDest = decryptNoteSecrets(
      userX25519.secretKey,
      evDest.ephemeralPublicKey,
      evDest.encryptedBlob,
    );

    console.log("\n   Change note side-by-side:");
    console.log(
      `     original  blinding: ${Buffer.from(changeBlinding).toString("hex")}`,
    );
    console.log(
      `     decrypted blinding: ${Buffer.from(decChange.blinding).toString(
        "hex",
      )}`,
    );
    console.log(`     original  amount:   ${changeAmount}`);
    console.log(`     decrypted amount:   ${decChange.amount}`);

    console.log("\n   Dest note side-by-side:");
    console.log(
      `     original  blinding: ${Buffer.from(destBlinding).toString("hex")}`,
    );
    console.log(
      `     decrypted blinding: ${Buffer.from(decDest.blinding).toString(
        "hex",
      )}`,
    );
    console.log(`     original  amount:   ${swappedAmount}`);
    console.log(`     decrypted amount:   ${decDest.amount}`);

    assert.deepStrictEqual(
      Array.from(decChange.blinding),
      Array.from(changeBlinding),
      "change note: decrypted blinding mismatch",
    );
    assert.strictEqual(
      decChange.amount,
      changeAmount,
      "change note: decrypted amount mismatch",
    );

    assert.deepStrictEqual(
      Array.from(decDest.blinding),
      Array.from(destBlinding),
      "dest note: decrypted blinding mismatch",
    );
    assert.strictEqual(
      decDest.amount,
      swappedAmount,
      "dest note: decrypted amount mismatch",
    );

    console.log("✅ Both notes successfully decrypted with user X25519 key");
    console.log("✅ transact_swap() with Some(NoteCiphers) works end-to-end");
  });
});

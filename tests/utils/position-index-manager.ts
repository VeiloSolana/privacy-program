/**
 * tests/utils/position-index-manager.ts
 *
 * PositionIndexManager — tracks which position index `n` values are in use for a wallet.
 *
 * Background:
 *   Each position is derived from a wallet private key and a monotonically increasing
 *   index `n`. The derivation is:
 *     rootSecret      = sha256(walletPrivkey || "veilo_v1")
 *     positionSecretN = Poseidon(rootSecretField, n)
 *     positionPdaKey  = Poseidon(positionSecretN)  → seeds the on-chain PositionPDA
 *
 *   `n` must never be reused after a position at that index is closed, because the
 *   same `n` → same secret → same blinding → commitment collision risk.
 *
 * Usage:
 *   const mgr = new PositionIndexManager(poseidon, walletPrivkey);
 *   const n = mgr.allocateN();                // claim next unused n
 *   mgr.recordOpen(n, { mint, amount, commitment, leafIndex, treeId });
 *   // ... later
 *   mgr.recordClose(n);
 *
 *   // On app restart — recover from chain:
 *   await mgr.recover(connection, programId);
 */

import * as crypto from "crypto";
import { Connection, PublicKey } from "@solana/web3.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface PositionEntry {
  n: number;
  /** On-chain position PDA key (32-byte big-endian Poseidon of positionPubkey) */
  positionPdaKeyBytes: Uint8Array;
  mint: PublicKey;
  /** Token amount committed in the ZK proof */
  amount: bigint;
  /** Commitment hash in the position Merkle tree */
  commitment: Uint8Array;
  /** Leaf index in the position tree */
  leafIndex: number;
  /** Position Merkle tree ID */
  treeId: number;
  status: "open" | "closed";
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const b of bytes) result = (result << 8n) | BigInt(b);
  return result;
}

function bigIntToBytes32BE(n: bigint): Uint8Array {
  const hex = n.toString(16).padStart(64, "0");
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

function reduceToField(bytes: Uint8Array): Uint8Array {
  const FR_MODULUS = BigInt(
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
  );
  const val = bytesToBigIntBE(bytes);
  const reduced = val % FR_MODULUS;
  return bigIntToBytes32BE(reduced);
}

// ─── PositionIndexManager ─────────────────────────────────────────────────────

export class PositionIndexManager {
  private readonly poseidon: any;
  private readonly walletPrivkey: Uint8Array;
  /** Monotonically increasing counter: next n value to allocate */
  private nextN: number;
  /** Registry of all known positions (open and closed) */
  private readonly registry: Map<number, PositionEntry>;

  constructor(poseidon: any, walletPrivkey: Uint8Array) {
    this.poseidon = poseidon;
    this.walletPrivkey = walletPrivkey;
    this.nextN = 0;
    this.registry = new Map();
  }

  // ── Key derivation ─────────────────────────────────────────────────────────

  /**
   * Derive all position keys for index `n`.
   * This is the same derivation used in `derivePositionKeys` in the test file,
   * kept here so the manager is self-contained.
   */
  deriveKeys(n: number): {
    positionSecretN: bigint;
    positionBlinding: bigint;
    positionPubkey: bigint;
    positionPdaKeyBytes: Uint8Array;
  } {
    const poseidon = this.poseidon;
    const preimage = Buffer.concat([
      Buffer.from(this.walletPrivkey),
      Buffer.from("veilo_v1"),
    ]);
    const rootSecretBytes = crypto
      .createHash("sha256")
      .update(preimage)
      .digest();
    const rootSecretField = poseidon.F.e(
      reduceToField(rootSecretBytes).toString(),
    );

    const secretHash = poseidon([rootSecretField, poseidon.F.e(BigInt(n))]);
    const positionSecretN: bigint = poseidon.F.toObject(secretHash);

    const blindingHash = poseidon([
      poseidon.F.e(positionSecretN),
      poseidon.F.e(BigInt(1)),
    ]);
    const positionBlinding: bigint = poseidon.F.toObject(blindingHash);

    const pubkeyHash = poseidon([poseidon.F.e(positionSecretN)]);
    const positionPubkey: bigint = poseidon.F.toObject(pubkeyHash);

    const positionPdaKeyBytes = bigIntToBytes32BE(positionPubkey);
    return { positionSecretN, positionBlinding, positionPubkey, positionPdaKeyBytes };
  }

  // ── Index management ───────────────────────────────────────────────────────

  /**
   * Claim the next unused `n` and return it.
   * Advances the internal counter — never reuses a value.
   */
  allocateN(): number {
    const n = this.nextN;
    this.nextN++;
    return n;
  }

  /**
   * Record that position `n` was successfully opened on-chain.
   */
  recordOpen(
    n: number,
    data: {
      mint: PublicKey;
      amount: bigint;
      commitment: Uint8Array;
      leafIndex: number;
      treeId: number;
    },
  ): void {
    const keys = this.deriveKeys(n);
    this.registry.set(n, {
      n,
      positionPdaKeyBytes: keys.positionPdaKeyBytes,
      mint: data.mint,
      amount: data.amount,
      commitment: data.commitment,
      leafIndex: data.leafIndex,
      treeId: data.treeId,
      status: "open",
    });
  }

  /**
   * Mark position `n` as closed. The `n` value is permanently retired —
   * `nextN` is never decremented, so it will never be reused.
   */
  recordClose(n: number): void {
    const entry = this.registry.get(n);
    if (entry) entry.status = "closed";
  }

  /**
   * Return all currently open positions.
   */
  openPositions(): PositionEntry[] {
    return Array.from(this.registry.values()).filter(
      (e) => e.status === "open",
    );
  }

  /**
   * Return the entry for a specific `n`, or undefined if not yet registered.
   */
  get(n: number): PositionEntry | undefined {
    return this.registry.get(n);
  }

  // ── Chain recovery ─────────────────────────────────────────────────────────

  /**
   * Scan the chain for active PositionPDAs derived from this wallet's private key.
   * Starts at n=0 and stops after `gapThreshold` consecutive missing PDAs.
   *
   * On recovery:
   *   - Found active PDAs are added to the registry with status "open"
   *   - `nextN` is advanced past the highest found `n`
   *   - PDAs that exist but `is_active == false` are recorded as "closed"
   *
   * @param connection  Solana RPC connection
   * @param programId   Veilo Privacy Pool program ID
   * @param gapThreshold  Stop after this many consecutive missing PDAs (default 20)
   */
  async recover(
    connection: Connection,
    programId: PublicKey,
    gapThreshold = 20,
  ): Promise<{ found: number; recovered: PositionEntry[] }> {
    const recovered: PositionEntry[] = [];
    let consecutive = 0;
    let n = 0;
    let highestFound = -1;

    while (consecutive < gapThreshold) {
      const keys = this.deriveKeys(n);
      const [pdaAddr] = PublicKey.findProgramAddressSync(
        [Buffer.from("position_pda_v1"), Buffer.from(keys.positionPdaKeyBytes)],
        programId,
      );

      const info = await connection.getAccountInfo(pdaAddr, "confirmed");
      if (!info) {
        consecutive++;
        n++;
        continue;
      }

      // Decode PositionPDA account:
      // Layout: discriminator(8) + bump(1) + mint(32) + balance(8) + leaf_index(8) + tree_id(2) + is_active(1)
      const d = Buffer.from(info.data);
      if (d.length < 8 + 1 + 32 + 8 + 8 + 2 + 1) {
        consecutive++;
        n++;
        continue;
      }
      let offset = 8; // skip discriminator
      offset += 1; // bump
      const mint = new PublicKey(d.subarray(offset, offset + 32));
      offset += 32;
      const balance = d.readBigUInt64LE(offset);
      offset += 8;
      const leafIndex = Number(d.readBigUInt64LE(offset));
      offset += 8;
      const treeId = d.readUInt16LE(offset);
      offset += 2;
      const isActive = d.readUInt8(offset) !== 0;

      const entry: PositionEntry = {
        n,
        positionPdaKeyBytes: keys.positionPdaKeyBytes,
        mint,
        amount: balance,
        commitment: new Uint8Array(32), // commitment not stored on-chain; caller must reconstruct
        leafIndex,
        treeId,
        status: isActive ? "open" : "closed",
      };
      this.registry.set(n, entry);

      if (isActive) {
        recovered.push(entry);
        highestFound = n;
      }

      consecutive = 0;
      n++;
    }

    // Advance nextN past the highest found index so we never reuse
    if (highestFound >= this.nextN) {
      this.nextN = highestFound + 1;
    }

    return { found: recovered.length, recovered };
  }
}

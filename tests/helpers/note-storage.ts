// Helper for managing deposit notes in tests and production
//
// This bridges the gap between immediate deposits and delayed withdrawals

import { PublicKey } from '@solana/web3.js';

/**
 * Deposit note - the private information you need to withdraw
 */
export interface DepositNote {
  // Essential for spending
  amount: bigint;
  commitment: Uint8Array;
  nullifier: Uint8Array;
  blinding: Uint8Array;
  privateKey: Uint8Array;
  publicKey: bigint;
  leafIndex: number;
  
  // Merkle proof (can be recomputed from tree)
  merklePath: {
    pathElements: bigint[];
    pathIndices: number[];
  };
  
  // Metadata
  mintAddress?: PublicKey;
  timestamp?: number;
  spent?: boolean;
}

/**
 * Simple in-memory note storage for testing
 * In production, use encrypted file storage or database
 */
export class InMemoryNoteStorage {
  private notes: Map<string, DepositNote> = new Map();

  /**
   * Save a note after deposit
   * Returns a unique ID for retrieval
   */
  save(note: DepositNote): string {
    const id = this.computeNoteId(note.commitment);
    this.notes.set(id, {
      ...note,
      timestamp: Date.now(),
      spent: false,
    });
    console.log(`\n💾 Note saved: ${id}`);
    console.log(`   Amount: ${note.amount} lamports`);
    console.log(`   Leaf index: ${note.leafIndex}`);
    return id;
  }

  /**
   * Get a note by ID
   */
  get(id: string): DepositNote | null {
    return this.notes.get(id) || null;
  }

  /**
   * Find note by commitment
   */
  findByCommitment(commitment: Uint8Array): DepositNote | null {
    const id = this.computeNoteId(commitment);
    return this.notes.get(id) || null;
  }

  /**
   * Get all unspent notes
   */
  getUnspent(): DepositNote[] {
    return Array.from(this.notes.values()).filter(n => !n.spent);
  }

  /**
   * Mark note as spent
   */
  markSpent(id: string): void {
    const note = this.notes.get(id);
    if (note) {
      note.spent = true;
      console.log(`\n✅ Note marked as spent: ${id}`);
    }
  }

  /**
   * Get total balance from unspent notes
   */
  getBalance(): bigint {
    return this.getUnspent().reduce((sum, note) => sum + note.amount, 0n);
  }

  /**
   * Clear all notes
   */
  clear(): void {
    this.notes.clear();
  }

  /**
   * Get count of notes
   */
  count(): { total: number; unspent: number; spent: number } {
    const all = Array.from(this.notes.values());
    return {
      total: all.length,
      unspent: all.filter(n => !n.spent).length,
      spent: all.filter(n => n.spent).length,
    };
  }

  private computeNoteId(commitment: Uint8Array): string {
    return Buffer.from(commitment).toString('hex').slice(0, 16);
  }
}

/**
 * Example: How to use in tests
 */
export function exampleUsage() {
  const storage = new InMemoryNoteStorage();

  // After deposit:
  const noteId = storage.save({
    amount: BigInt(1_500_000_000),
    commitment: new Uint8Array(32),
    nullifier: new Uint8Array(32),
    blinding: new Uint8Array(32),
    privateKey: new Uint8Array(32),
    publicKey: 0n,
    leafIndex: 0,
    merklePath: { pathElements: [], pathIndices: [] },
  });

  // Later, when withdrawing:
  const note = storage.get(noteId);
  if (note && !note.spent) {
    // Generate proof and withdraw...
    console.log(`Withdrawing ${note.amount} lamports`);
    
    // After successful withdrawal:
    storage.markSpent(noteId);
  }

  // Check balance:
  const balance = storage.getBalance();
  console.log(`Total balance: ${balance} lamports`);

  // List all unspent notes:
  const unspent = storage.getUnspent();
  console.log(`You have ${unspent.length} unspent notes`);
}

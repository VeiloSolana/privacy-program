// Example: Note Management for Production Use
//
// This shows how to store and retrieve notes for deposits/withdrawals

import fs from "fs";
import crypto from "crypto";
import { PublicKey } from "@solana/web3.js";

/**
 * A note represents a deposit in the privacy pool
 * This is the private information you must keep to spend it later
 */
interface Note {
  id: string; // Unique identifier
  amount: bigint; // Amount in lamports
  commitment: string; // Hex-encoded commitment (public, on-chain)
  nullifier: string; // Hex-encoded nullifier
  blinding: string; // Hex-encoded blinding factor (secret!)
  privateKey: string; // Hex-encoded private key (secret!)
  publicKey: string; // Derived public key
  leafIndex: number; // Position in Merkle tree
  mintAddress: string; // Token mint (SOL = default)
  timestamp: number; // When deposited
  spent: boolean; // Has it been withdrawn?
  spentAt?: number; // When withdrawn
  txSignature?: string; // Deposit transaction signature
}

/**
 * Encrypted note storage
 * In production, use a proper key management system (KMS)
 */
export class NoteManager {
  private notesFile: string;
  private encryptionKey: Buffer;

  constructor(notesFile: string, password: string) {
    this.notesFile = notesFile;
    // In production, use proper key derivation (PBKDF2, Argon2, etc.)
    this.encryptionKey = crypto.scryptSync(password, "salt", 32);
  }

  /**
   * Save a new note after deposit
   */
  async saveNote(
    note: Omit<Note, "id" | "timestamp" | "spent">
  ): Promise<string> {
    const noteWithMetadata: Note = {
      ...note,
      id: crypto.randomUUID(),
      timestamp: Date.now(),
      spent: false,
    };

    const notes = await this.loadAllNotes();
    notes.push(noteWithMetadata);
    await this.saveAllNotes(notes);

    console.log(`✅ Note saved: ${noteWithMetadata.id}`);
    console.log(`   Amount: ${note.amount} lamports`);
    console.log(`   Commitment: ${note.commitment.slice(0, 16)}...`);

    return noteWithMetadata.id;
  }

  /**
   * Get all unspent notes
   */
  async getUnspentNotes(): Promise<Note[]> {
    const notes = await this.loadAllNotes();
    return notes.filter((n) => !n.spent);
  }

  /**
   * Get a specific note by ID
   */
  async getNote(id: string): Promise<Note | null> {
    const notes = await this.loadAllNotes();
    return notes.find((n) => n.id === id) || null;
  }

  /**
   * Get notes by commitment (to check if you own a specific deposit)
   */
  async getNoteByCommitment(commitment: string): Promise<Note | null> {
    const notes = await this.loadAllNotes();
    return notes.find((n) => n.commitment === commitment) || null;
  }

  /**
   * Mark a note as spent after withdrawal
   */
  async markAsSpent(id: string, txSignature: string): Promise<void> {
    const notes = await this.loadAllNotes();
    const note = notes.find((n) => n.id === id);

    if (!note) {
      throw new Error(`Note not found: ${id}`);
    }

    note.spent = true;
    note.spentAt = Date.now();
    note.txSignature = txSignature;

    await this.saveAllNotes(notes);
    console.log(`✅ Note marked as spent: ${id}`);
  }

  /**
   * Get total balance (unspent notes)
   */
  async getBalance(): Promise<bigint> {
    const unspent = await this.getUnspentNotes();
    return unspent.reduce((sum, note) => sum + note.amount, 0n);
  }

  /**
   * Export note for sharing or backup (encrypted)
   */
  async exportNote(id: string, recipientPassword: string): Promise<string> {
    const note = await this.getNote(id);
    if (!note) {
      throw new Error(`Note not found: ${id}`);
    }

    const recipientKey = crypto.scryptSync(recipientPassword, "salt", 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", recipientKey, iv);

    const encrypted = Buffer.concat([
      cipher.update(JSON.stringify(note), "utf8"),
      cipher.final(),
    ]);

    return JSON.stringify({
      version: 1,
      iv: iv.toString("hex"),
      data: encrypted.toString("hex"),
    });
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  private async loadAllNotes(): Promise<Note[]> {
    if (!fs.existsSync(this.notesFile)) {
      return [];
    }

    try {
      const encryptedData = fs.readFileSync(this.notesFile, "utf8");
      const { iv, data } = JSON.parse(encryptedData);

      const decipher = crypto.createDecipheriv(
        "aes-256-cbc",
        this.encryptionKey,
        Buffer.from(iv, "hex")
      );

      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(data, "hex")),
        decipher.final(),
      ]);

      return JSON.parse(decrypted.toString("utf8"), (key, value) => {
        // Deserialize BigInt
        if (typeof value === "string" && value.startsWith("BIGINT::")) {
          return BigInt(value.slice(8));
        }
        return value;
      });
    } catch (e) {
      console.error("Failed to load notes:", e);
      return [];
    }
  }

  private async saveAllNotes(notes: Note[]): Promise<void> {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", this.encryptionKey, iv);

    // Serialize BigInt as string
    const serialized = JSON.stringify(notes, (key, value) =>
      typeof value === "bigint" ? `BIGINT::${value}` : value
    );

    const encrypted = Buffer.concat([
      cipher.update(serialized, "utf8"),
      cipher.final(),
    ]);

    const payload = JSON.stringify({
      version: 1,
      iv: iv.toString("hex"),
      data: encrypted.toString("hex"),
    });

    fs.writeFileSync(this.notesFile, payload, "utf8");
  }
}

// ============================================================================
// Usage Example
// ============================================================================

async function exampleUsage() {
  const noteManager = new NoteManager("./my-notes.enc", "my-secure-password");

  // ============================================================================
  // DEPOSIT: Save the note
  // ============================================================================

  console.log("\n📥 DEPOSIT: Saving note after deposit...\n");

  const noteId = await noteManager.saveNote({
    amount: BigInt(1_500_000_000), // 1.5 SOL
    commitment:
      "2631629564907575682067817082035046758016688012791841467097672159838466498206",
    nullifier:
      "20075866202930306543283605368649334042349425360307971816324202943365295467876",
    blinding: "a1b2c3d4e5f6...", // hex string
    privateKey: "x9y8z7w6v5u4...", // hex string
    publicKey:
      "7284404223354621962093858213819494674292176833442429614404443677948605291262",
    leafIndex: 0,
    mintAddress: "11111111111111111111111111111111", // SOL
    txSignature: "ABC123...",
  });

  // ============================================================================
  // CHECK BALANCE
  // ============================================================================

  console.log("\n💰 Checking balance...\n");

  const balance = await noteManager.getBalance();
  console.log(
    `Total balance: ${balance} lamports (${Number(balance) / 1e9} SOL)`
  );

  const unspent = await noteManager.getUnspentNotes();
  console.log(`Unspent notes: ${unspent.length}`);

  // ============================================================================
  // WITHDRAW: Load the note later
  // ============================================================================

  console.log("\n📤 WITHDRAW: Loading note for withdrawal...\n");

  // Option 1: Get by ID
  const note = await noteManager.getNote(noteId);

  // Option 2: Get all unspent and pick one
  const unspentNotes = await noteManager.getUnspentNotes();
  const noteToSpend = unspentNotes[0];

  if (noteToSpend) {
    console.log(`Found note to spend:`);
    console.log(`  Amount: ${noteToSpend.amount} lamports`);
    console.log(`  Leaf index: ${noteToSpend.leafIndex}`);

    // Generate proof and submit withdrawal...
    // const proof = await generateWithdrawalProof(noteToSpend);
    // const sig = await submitWithdrawal(proof);

    // Mark as spent
    await noteManager.markAsSpent(noteToSpend.id, "withdrawal-signature-xyz");
  }

  // ============================================================================
  // EXPORT NOTE (for sharing or backup)
  // ============================================================================

  console.log("\n📤 Exporting note...\n");

  const exported = await noteManager.exportNote(noteId, "recipient-password");
  console.log("Exported note (encrypted):");
  console.log(exported);
}

// Uncomment to run example:
// exampleUsage().catch(console.error);

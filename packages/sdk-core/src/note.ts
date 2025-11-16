import { sha256 } from "@noble/hashes/sha256";
import { PublicKey } from "@solana/web3.js";
import { randomBytes } from "crypto";

export type Note = {
	value: bigint;        // u64, but keep bigint on client
	owner: PublicKey;     // owner public key (or later: spend key)
	rho: Uint8Array;      // 32 bytes random
	r: Uint8Array;        // 32 bytes random blinding
};

export type SerializedNote = {
	value: bigint;
	owner: PublicKey;
	rho: Uint8Array;
	r: Uint8Array;
	commitment: Uint8Array;  // 32 bytes
};

export function createRandomNote(params: {
	value: bigint;
	owner: PublicKey;
}): Note {
	return {
		value: params.value,
		owner: params.owner,
		rho: randomBytes(32),
		r: randomBytes(32),
	};
}

/**
 * Deterministic encoding of a note into bytes:
 * value (8 bytes, LE) || owner (32 bytes) || rho (32) || r (32)
 */
export function encodeNoteToBytes(note: Note): Uint8Array {
	const valueBuf = Buffer.alloc(8);
	valueBuf.writeBigUInt64LE(note.value);

	const ownerBuf = note.owner.toBytes(); // 32 bytes
	if (ownerBuf.length !== 32) {
		throw new Error("Owner pubkey must be 32 bytes");
	}

	if (note.rho.length !== 32 || note.r.length !== 32) {
		throw new Error("rho and r must be 32 bytes each");
	}

	return Buffer.concat([
		valueBuf,
		Buffer.from(ownerBuf),
		Buffer.from(note.rho),
		Buffer.from(note.r),
	]);
}

/**
 * Placeholder commitment function.
 * Later this must exactly match your zk circuit’s hash function (e.g. Poseidon).
 */
export function commitNote(note: Note): Uint8Array {
	const encoded = encodeNoteToBytes(note);
	return sha256(encoded); // 32 bytes
}

/**
 * Convenience: build a random note and its commitment in one go.
 */
export function createNoteWithCommitment(params: {
	value: bigint;
	owner: PublicKey;
}): SerializedNote {
	const note = createRandomNote(params);
	const commitment = commitNote(note);

	return {
		...note,
		commitment,
	};
}
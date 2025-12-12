// src/zkWithdraw.ts
import fs from "fs";
import path from "path";
import { groth16 } from "snarkjs";

export type WithdrawPublicInputs = {
	root: string[];       // 32 bytes as decimal strings
	nullifier: string[];  // 32 bytes
	denomIndex: number;
	recipient: string[];  // 32 bytes
	relayer: string[];    // 32 bytes
	feeBps: number;
};

export type WithdrawPrivateInputs = {
	noteValue: bigint;
	noteOwner: Uint8Array;  // 32
	noteRho: Uint8Array;    // 32
	noteR: Uint8Array;      // 32
	pathElements: Uint8Array[][]; // [treeHeight][32]
	pathIndex: number[];    // [treeHeight]
};

function toFieldBytes32(x: Uint8Array): string[] {
	if (x.length !== 32) throw new Error("expected 32 bytes");
	return Array.from(x, (b) => b.toString());
}

export async function proveWithdraw(
	publicInputs: WithdrawPublicInputs,
	privateInputs: WithdrawPrivateInputs,
) {
	const wasmPath = path.join(__dirname, "..", "artifacts", "withdraw.wasm");
	const zkeyPath = path.join(__dirname, "..", "artifacts", "withdraw_final.zkey");

	const input = {
		// Map your types to whatever your circom expects.
		// E.g. root[32], nullifier[32], etc.
		root: publicInputs.root,
		nullifier: publicInputs.nullifier,
		denomIndex: publicInputs.denomIndex,
		recipient: publicInputs.recipient,
		relayer: publicInputs.relayer,
		feeBps: publicInputs.feeBps,
		noteValue: publicInputs.denomIndex, // or actual value
		// plus path + note randomness from privateInputs...
	};

	const { proof, publicSignals } = await groth16.fullProve(
		input,
		wasmPath,
		zkeyPath,
	);

	return {
		proof,
		publicSignals,
	};
}

export async function verifyWithdrawProof(
	proof: any,
	publicSignals: any,
): Promise<boolean> {
	const vkPath = path.join(__dirname, "..", "artifacts", "verification_key.json");
	const vk = JSON.parse(fs.readFileSync(vkPath, "utf8"));

	return groth16.verify(vk, publicSignals, proof);
}
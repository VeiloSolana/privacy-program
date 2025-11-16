import * as anchor from "@coral-xyz/anchor";
import { Program, BN } from "@coral-xyz/anchor";
import {
	Connection,
	PublicKey,
	SystemProgram,
} from "@solana/web3.js";
import {
	getOrCreateAssociatedTokenAccount,
} from "@solana/spl-token";

import { PrivacyPool } from "../../target/types/privacy_pool"; // adjust relative path if needed
import {
	createNoteWithCommitment,
	SerializedNote,
} from "./note";

export class PrivacyPoolClient {
	readonly connection: Connection;
	readonly provider: anchor.AnchorProvider;
	readonly program: Program<PrivacyPool>;
	readonly programId: PublicKey;

	constructor(provider: anchor.AnchorProvider) {
		this.provider = provider;
		this.connection = provider.connection;
		// Anchor workspace wiring
		this.program = anchor.workspace.PrivacyPool as Program<PrivacyPool>;
		this.programId = this.program.programId;
	}

	// === PDA helpers ===

	derivePoolStatePda(mint: PublicKey): [PublicKey, number] {
		return PublicKey.findProgramAddressSync(
			[Buffer.from("pool_state"), mint.toBuffer()],
			this.programId
		);
	}

	deriveCommitmentsPda(poolState: PublicKey): [PublicKey, number] {
		return PublicKey.findProgramAddressSync(
			[Buffer.from("commitments"), poolState.toBuffer()],
			this.programId
		);
	}

	derivePoolVaultAta(mint: PublicKey, poolState: PublicKey): PublicKey {
		return anchor.utils.token.associatedAddress({
			mint,
			owner: poolState,
		});
	}

	// === High-level flows ===

	/**
	 * Initialize a new pool for a given mint.
	 * Returns PDAs and accounts used.
	 */
	async initializePool(params: {
		mint: PublicKey;
	}) {
		const wallet = this.provider.wallet as anchor.Wallet;
		const [poolStatePda, poolStateBump] = this.derivePoolStatePda(params.mint);
		const [commitmentsPda] = this.deriveCommitmentsPda(poolStatePda);
		const poolVaultAta = this.derivePoolVaultAta(params.mint, poolStatePda);

		await this.program.methods
			.initializePool(poolStateBump)
			.accounts({
				poolState: poolStatePda,
				mint: params.mint,
				poolTokenVault: poolVaultAta,
				commitments: commitmentsPda,
				authority: wallet.publicKey,
				systemProgram: SystemProgram.programId,
				tokenProgram: anchor.utils.token.TOKEN_PROGRAM_ID,
				associatedTokenProgram: anchor.utils.token.ASSOCIATED_PROGRAM_ID,
				rent: anchor.web3.SYSVAR_RENT_PUBKEY,
			})
			.rpc();

		return {
			poolStatePda,
			poolStateBump,
			commitmentsPda,
			poolVaultAta,
		};
	}

	/**
	 * Deposit from public SPL account into shielded pool,
	 * generating a fresh note + on-chain commitment.
	 */
	async deposit(params: {
		mint: PublicKey;
		amount: bigint;
	}): Promise<SerializedNote> {
		const wallet = this.provider.wallet as anchor.Wallet;
		const owner = wallet.publicKey;

		const [poolStatePda, _poolStateBump] = this.derivePoolStatePda(params.mint);
		const [commitmentsPda] = this.deriveCommitmentsPda(poolStatePda);
		const poolVaultAta = this.derivePoolVaultAta(params.mint, poolStatePda);

		// Ensure user has ATA for the mint
		const ata = await getOrCreateAssociatedTokenAccount(
			this.connection,
			wallet.payer as anchor.web3.Keypair,
			params.mint,
			owner
		);

		const note = createNoteWithCommitment({
			value: params.amount,
			owner,
		});

		await this.program.methods
			.depositPublicToShielded(new BN(params.amount.toString()), [...note.commitment])
			.accounts({
				poolState: poolStatePda,
				mint: params.mint,
				poolTokenVault: poolVaultAta,
				userTokenAccount: ata.address,
				user: owner,
				commitments: commitmentsPda,
				tokenProgram: anchor.utils.token.TOKEN_PROGRAM_ID,
			})
			.rpc();

		return note;
	}

	/**
	 * Withdraw from shielded pool to public SPL account.
	 * Currently uses fake proof + nullifier until zk is implemented.
	 */
	async withdrawFake(params: {
		mint: PublicKey;
		amount: bigint;
	}) {
		const wallet = this.provider.wallet as anchor.Wallet;
		const owner = wallet.publicKey;

		const [poolStatePda, _poolStateBump] = this.derivePoolStatePda(params.mint);
		const poolVaultAta = this.derivePoolVaultAta(params.mint, poolStatePda);

		// Ensure user has ATA for the mint
		const ata = await getOrCreateAssociatedTokenAccount(
			this.connection,
			wallet.payer as anchor.web3.Keypair,
			params.mint,
			owner
		);

		const fakeProof = Buffer.alloc(32, 7);
		const fakeNullifier = Array(32).fill(3); // just a placeholder

		await this.program.methods
			.withdrawShieldedToPublic(
				new BN(params.amount.toString()),
				[...fakeProof],
				fakeNullifier as number[]
			)
			.accounts({
				poolState: poolStatePda,
				mint: params.mint,
				poolTokenVault: poolVaultAta,
				userTokenAccount: ata.address,
				user: owner,
				tokenProgram: anchor.utils.token.TOKEN_PROGRAM_ID,
			})
			.rpc();
	}
}
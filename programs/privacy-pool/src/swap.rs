use anchor_lang::prelude::*;
use anchor_lang::solana_program::{instruction::Instruction, program::invoke_signed};
use anchor_spl::token::{self, CloseAccount, Transfer};

use crate::zk::{verify_swap_transaction_groth16, SwapProof};
use crate::{ExtData, MerkleTree, PoseidonHasher, PrivacyError, TransactSwap};

/// Ephemeral PDA that holds tokens during swap, created and closed atomically
#[account]
pub struct SwapExecutor {
    pub source_mint: Pubkey,
    pub dest_mint: Pubkey,
    pub nullifier: [u8; 32],
    /// Slot when this executor was created (for stale detection)
    pub created_slot: u64,
    pub bump: u8,
}

impl SwapExecutor {
    pub const LEN: usize = 8 + 32 + 32 + 32 + 8 + 1;

    /// Number of slots after which an executor is considered stale and can be reclaimed
    /// ~2 minutes at 400ms slot time (enough for any reasonable transaction)
    pub const STALE_THRESHOLD_SLOTS: u64 = 300;
}

/// Swap parameters committed to in the ZK proof
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SwapParams {
    pub min_amount_out: u64,
    pub deadline: i64,
    pub source_mint: Pubkey,
    pub dest_mint: Pubkey,
}

impl SwapParams {
    /// Reduce 32-byte value modulo BN254 Fr field
    fn reduce_to_field(bytes: [u8; 32]) -> [u8; 32] {
        use num_bigint::BigUint;

        // BN254 Fr modulus as 32-byte BE
        const FR_MODULUS: [u8; 32] = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
            0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93,
            0xf0, 0x00, 0x00, 0x01,
        ];

        // Quick check: if bytes < modulus, no reduction needed
        let mut needs_reduction = false;
        for i in 0..32 {
            if bytes[i] < FR_MODULUS[i] {
                break;
            }
            if bytes[i] > FR_MODULUS[i] {
                needs_reduction = true;
                break;
            }
        }

        if !needs_reduction {
            return bytes;
        }

        // Use BigUint for proper modulo reduction
        let val = BigUint::from_bytes_be(&bytes);
        let modulus = BigUint::from_bytes_be(&FR_MODULUS);
        let reduced = val % modulus;

        let mut result = [0u8; 32];
        let reduced_bytes = reduced.to_bytes_be();
        let offset = 32 - reduced_bytes.len();
        result[offset..].copy_from_slice(&reduced_bytes);
        result
    }

    pub fn hash(&self) -> Result<[u8; 32]> {
        use light_hasher::Hasher;

        // Reduce mints to field elements (pubkeys may exceed Fr modulus)
        let source_mint_bytes = Self::reduce_to_field(self.source_mint.to_bytes());
        let dest_mint_bytes = Self::reduce_to_field(self.dest_mint.to_bytes());

        let mut min_out_bytes = [0u8; 32];
        min_out_bytes[24..].copy_from_slice(&self.min_amount_out.to_be_bytes());

        let mut deadline_bytes = [0u8; 32];
        deadline_bytes[24..].copy_from_slice(&self.deadline.to_be_bytes());

        let hash1 = PoseidonHasher::hashv(&[&source_mint_bytes, &dest_mint_bytes])
            .map_err(|_| error!(PrivacyError::MerkleHashFailed))?;

        let hash2 = PoseidonHasher::hashv(&[&min_out_bytes, &deadline_bytes])
            .map_err(|_| error!(PrivacyError::MerkleHashFailed))?;

        PoseidonHasher::hashv(&[&hash1, &hash2]).map_err(|_| error!(PrivacyError::MerkleHashFailed))
    }
}

/// Public inputs for swap ZK proof
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SwapPublicInputs {
    pub source_root: [u8; 32],
    pub swap_params_hash: [u8; 32],
    pub ext_data_hash: [u8; 32],
    pub source_mint: Pubkey,
    pub dest_mint: Pubkey,
    pub input_nullifiers: [[u8; 32]; 2],
    pub output_commitments: [[u8; 32]; 2],
    pub swap_amount: u64,
}

/// Atomic cross-pool swap: source pool → DEX → destination pool
pub fn transact_swap<'info>(
    ctx: Context<'_, '_, 'info, 'info, TransactSwap<'info>>,
    proof: SwapProof,
    source_root: [u8; 32],
    source_tree_id: u16,
    source_mint: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    dest_tree_id: u16,
    dest_mint: Pubkey,
    output_commitment_0: [u8; 32],
    output_commitment_1: [u8; 32],
    swap_params: SwapParams,
    swap_amount: u64,
    swap_data: Vec<u8>,
    ext_data: ExtData,
) -> Result<()> {
    // Prevents arbitrary CPI to malicious programs
    require!(
        ctx.accounts.swap_program.key() == crate::RAYDIUM_CPMM_PROGRAM_ID
            || ctx.accounts.swap_program.key() == crate::RAYDIUM_AMM_PROGRAM_ID
            || ctx.accounts.swap_program.key() == crate::JUPITER_PROGRAM_ID,
        PrivacyError::InvalidSwapProgram
    );

    // Validate pools and mints
    require!(
        ctx.accounts.source_config.mint_address == source_mint,
        PrivacyError::InvalidMintAddress
    );
    require!(
        ctx.accounts.dest_config.mint_address == dest_mint,
        PrivacyError::InvalidMintAddress
    );
    require!(source_mint != dest_mint, PrivacyError::InvalidMintAddress);

    // Validate tree IDs are within bounds before proof verification
    require!(
        source_tree_id < ctx.accounts.source_config.num_trees,
        PrivacyError::InvalidTreeId
    );
    require!(
        dest_tree_id < ctx.accounts.dest_config.num_trees,
        PrivacyError::InvalidTreeId
    );

    // Check relayer is whitelisted in BOTH source and dest pools
    // This prevents relayers authorized only for one pool from facilitating
    // swaps across pool boundaries they shouldn't access
    require!(
        ctx.accounts
            .source_config
            .is_relayer(&ctx.accounts.relayer.key()),
        PrivacyError::RelayerNotAllowed
    );
    require!(
        ctx.accounts
            .dest_config
            .is_relayer(&ctx.accounts.relayer.key()),
        PrivacyError::RelayerNotAllowed
    );

    let clock = Clock::get()?;
    require!(
        clock.unix_timestamp <= swap_params.deadline,
        PrivacyError::InvalidPublicAmount
    );

    let input_nullifiers = [input_nullifier_0, input_nullifier_1];
    let output_commitments = [output_commitment_0, output_commitment_1];

    require!(
        input_nullifiers[0] != input_nullifiers[1],
        PrivacyError::DuplicateNullifiers
    );
    require!(
        output_commitments[0] != output_commitments[1],
        PrivacyError::DuplicateCommitments
    );

    let zero = [0u8; 32];
    require!(
        input_nullifiers[0] != zero && input_nullifiers[1] != zero,
        PrivacyError::ZeroNullifier
    );
    require!(
        output_commitments[0] != zero && output_commitments[1] != zero,
        PrivacyError::ZeroCommitment
    );

    // ╔══════════════════════════════════════════════════════════════════════════╗
    // ║ ZK PROOF VERIFICATION - ALWAYS ENABLED                                  ║
    // ║ This verification MUST NEVER be disabled via feature flags              ║
    // ║ Verifies:                                                                ║
    // ║   1. User owns input notes (knows preimages for nullifiers)              ║
    // ║   2. Input notes exist in source Merkle tree (root membership)           ║
    // ║   3. Output commitments are correctly formed                             ║
    // ║   4. swap_amount + change = sum(input_notes)                             ║
    // ║   5. ext_data_hash matches Poseidon(relayer, fee)                        ║
    // ║   6. swap_params_hash matches committed swap parameters                  ║
    // ╚══════════════════════════════════════════════════════════════════════════╝
    let swap_params_hash = swap_params.hash()?;
    let ext_data_hash_val = ext_data.hash()?;

    let public_inputs = SwapPublicInputs {
        source_root,
        swap_params_hash,
        ext_data_hash: ext_data_hash_val,
        source_mint,
        dest_mint,
        input_nullifiers,
        output_commitments,
        swap_amount,
    };

    // CRITICAL: ZK verification consumes ~400K CUs (4 pairings + 10 scalar muls)
    // This verification is MANDATORY and cannot be disabled
    verify_swap_transaction_groth16(proof, &public_inputs)?;

    // Verify root is known
    let source_tree = ctx.accounts.source_tree.load()?;
    require!(
        MerkleTree::is_known_root(&*source_tree, source_root),
        PrivacyError::UnknownRoot
    );

    // Upfront capacity check for both trees before any state changes
    // While Solana transactions are atomic (failures revert all state), this:
    // 1. Provides clearer error messages by failing early
    // 2. Saves compute units by avoiding partial processing
    // 3. Improves UX with predictable behavior
    let source_max_capacity = 1u64 << (source_tree.height as u64);
    let source_remaining = source_max_capacity.saturating_sub(source_tree.next_index);
    require!(source_remaining >= 1, PrivacyError::MerkleTreeFull);
    drop(source_tree);

    let dest_tree = ctx.accounts.dest_tree.load()?;
    let dest_max_capacity = 1u64 << (dest_tree.height as u64);
    let dest_remaining = dest_max_capacity.saturating_sub(dest_tree.next_index);
    require!(dest_remaining >= 1, PrivacyError::MerkleTreeFull);
    drop(dest_tree);

    // Check if nullifiers were already marked to prevent double-spend
    // The PDA derivation includes tree_id in seeds, so cross-tree reuse is already impossible
    // (Anchor enforces the account matches the PDA seeds during instruction processing)
    require!(
        ctx.accounts.source_nullifier_marker_0.nullifier == [0u8; 32],
        PrivacyError::NullifierAlreadyUsed
    );
    require!(
        ctx.accounts.source_nullifier_marker_1.nullifier == [0u8; 32],
        PrivacyError::NullifierAlreadyUsed
    );

    // Mark nullifiers as spent
    crate::mark_nullifier_spent(
        &mut ctx.accounts.source_nullifier_marker_0,
        &mut ctx.accounts.source_nullifiers,
        input_nullifiers[0],
        ctx.bumps.source_nullifier_marker_0,
        source_mint,
        source_tree_id,
    )?;
    crate::mark_nullifier_spent(
        &mut ctx.accounts.source_nullifier_marker_1,
        &mut ctx.accounts.source_nullifiers,
        input_nullifiers[1],
        ctx.bumps.source_nullifier_marker_1,
        source_mint,
        source_tree_id,
    )?;

    // Initialize executor PDA (uses 'init' so always fresh, no staleness check needed)
    let executor = &mut ctx.accounts.executor;
    let current_slot = Clock::get()?.slot;

    executor.source_mint = source_mint;
    executor.dest_mint = dest_mint;
    executor.nullifier = input_nullifiers[0];
    executor.created_slot = current_slot;
    executor.bump = ctx.bumps.executor;

    // Transfer from source vault to executor
    require!(swap_amount > 0, PrivacyError::InvalidPublicAmount);

    // Validate vault has sufficient balance before transfer
    let vault_token_data = crate::deserialize_token_account(
        &ctx.accounts.source_vault_token_account.to_account_info(),
    )?;
    require!(
        vault_token_data.amount >= swap_amount,
        PrivacyError::InsufficientFundsForWithdrawal
    );

    let source_vault_seeds: &[&[u8]] = &[
        b"privacy_vault_v3",
        source_mint.as_ref(),
        &[ctx.accounts.source_config.vault_bump],
    ];

    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.source_vault_token_account.to_account_info(),
                to: ctx.accounts.executor_source_token.to_account_info(),
                authority: ctx.accounts.source_vault.to_account_info(),
            },
            &[source_vault_seeds],
        ),
        swap_amount,
    )?;

    // Update source pool TVL (decrease by swap_amount)
    ctx.accounts.source_config.total_tvl = ctx
        .accounts
        .source_config
        .total_tvl
        .checked_sub(swap_amount)
        .ok_or(PrivacyError::ArithmeticOverflow)?;

    // CPI to Swap Program (Raydium CPMM or AMM)
    // AUDIT-001: Include relayer key in seeds to match PDA derivation and prevent front-running
    let relayer_key = ctx.accounts.relayer.key();
    let executor_seeds: &[&[u8]] = &[
        b"swap_executor",
        source_mint.as_ref(),
        dest_mint.as_ref(),
        input_nullifiers[0].as_ref(),
        relayer_key.as_ref(),
        &[executor.bump],
    ];

    let remaining = &ctx.remaining_accounts;

    // Detect generic Swap Program type based on Instruction Discriminator
    // Raydium CPMM: 8-byte discriminator (0x8fbe5adac41e33de for swap_base_input)
    // Raydium AMM V4: 1-byte discriminator (0x09 for swap_base_in)
    let is_cpmm = swap_data.len() >= 8
        && swap_data[0] == 0x8f
        && swap_data[1] == 0xbe
        && swap_data[2] == 0x5a
        && swap_data[3] == 0xda;

    let is_amm = !is_cpmm && swap_data.len() >= 1 && swap_data[0] == 9;

    // Detect Jupiter V6 "route" instruction
    let is_jupiter = !is_cpmm
        && !is_amm
        && swap_data.len() >= 8
        && (swap_data[0..8] == [0xe5, 0x17, 0xcb, 0x97, 0x7a, 0xe3, 0xad, 0x2a] // Route
            || swap_data[0..8] == [0xc1, 0x20, 0x9b, 0x33, 0x41, 0xd6, 0x9c, 0x81] // SharedAccountsRoute
            || swap_data[0..8] == [0xd0, 0x33, 0xef, 0x97, 0x7b, 0x2b, 0xed, 0x5c] // ExactOutRoute
            || swap_data[0..8] == [0xb0, 0xd1, 0x69, 0xa8, 0x9a, 0x7d, 0x45, 0x3e]); // SharedAccountsExactOutRoute

    if is_cpmm {
        require!(swap_data.len() >= 24, PrivacyError::InvalidPublicAmount);
        require!(remaining.len() >= 8, PrivacyError::InvalidRemainingAccounts);

        // CPMM account layout in remaining_accounts:
        // [0] = authority (PDA, not owned by CPMM - skip validation)
        // [1] = config (owned by CPMM)
        // [2] = pool_state (owned by CPMM)
        // [3] = token_vault_0 (owned by Token Program)
        // [4] = token_vault_1 (owned by Token Program)
        // [5] = source_mint
        // [6] = dest_mint
        // [7] = observation_state (owned by CPMM)

        // Validate config is owned by CPMM program
        require!(
            remaining[1].owner == &crate::RAYDIUM_CPMM_PROGRAM_ID,
            PrivacyError::InvalidRemainingAccounts
        );
        // Validate pool state is owned by CPMM program
        require!(
            remaining[2].owner == &crate::RAYDIUM_CPMM_PROGRAM_ID,
            PrivacyError::InvalidRemainingAccounts
        );
        // Validate token vaults are owned by Token program
        require!(
            remaining[3].owner == &anchor_spl::token::ID,
            PrivacyError::InvalidRemainingAccounts
        );
        require!(
            remaining[4].owner == &anchor_spl::token::ID,
            PrivacyError::InvalidRemainingAccounts
        );
        // Validate observation state is owned by CPMM program
        require!(
            remaining[7].owner == &crate::RAYDIUM_CPMM_PROGRAM_ID,
            PrivacyError::InvalidRemainingAccounts
        );

        // Build CPMM swap instruction accounts
        let cpmm_accounts = vec![
            AccountMeta::new_readonly(executor.key(), true),
            AccountMeta::new_readonly(remaining[0].key(), false),
            AccountMeta::new_readonly(remaining[1].key(), false),
            AccountMeta::new(remaining[2].key(), false),
            AccountMeta::new(ctx.accounts.executor_source_token.key(), false),
            AccountMeta::new(ctx.accounts.executor_dest_token.key(), false),
            AccountMeta::new(remaining[3].key(), false),
            AccountMeta::new(remaining[4].key(), false),
            AccountMeta::new_readonly(ctx.accounts.token_program.key(), false),
            AccountMeta::new_readonly(ctx.accounts.token_program.key(), false),
            AccountMeta::new_readonly(remaining[5].key(), false),
            AccountMeta::new_readonly(remaining[6].key(), false),
            AccountMeta::new(remaining[7].key(), false),
        ];

        let swap_ix = Instruction {
            program_id: ctx.accounts.swap_program.key(),
            accounts: cpmm_accounts,
            data: swap_data.clone(),
        };

        msg!("Raydium CPMM: Executing Swap...");

        let account_infos = &[
            executor.to_account_info(),
            remaining[0].to_account_info(),
            remaining[1].to_account_info(),
            remaining[2].to_account_info(),
            ctx.accounts.executor_source_token.to_account_info(),
            ctx.accounts.executor_dest_token.to_account_info(),
            remaining[3].to_account_info(),
            remaining[4].to_account_info(),
            ctx.accounts.token_program.to_account_info(),
            remaining[5].to_account_info(),
            remaining[6].to_account_info(),
            remaining[7].to_account_info(),
            ctx.accounts.swap_program.to_account_info(),
        ];

        invoke_signed(&swap_ix, account_infos, &[executor_seeds])?;
    } else if is_amm {
        // Raydium AMM V4 Swap
        // Accounts:
        // 0. Token Program
        // 1. Amm Id
        // 2. Amm Authority
        // 3. Amm Open Orders
        // 4. Amm Target Orders
        // 5. Pool Coin Token Account
        // 6. Pool Pc Token Account
        // 7. Serum Program
        // 8. Serum Market
        // 9. Serum Bids
        // 10. Serum Asks
        // 11. Serum Event Queue
        // 12. Serum Coin Vault
        // 13. Serum Pc Vault
        // 14. Serum Vault Signer
        // 15. User Source Token
        // 16. User Dest Token
        // 17. User Owner

        // We expect remaining accounts to contain indices 1..15 (14 accounts)
        // Token Program is known (ctx.accounts.token_program)
        // User accounts are known
        require!(
            remaining.len() >= 14,
            PrivacyError::InvalidRemainingAccounts
        );

        // remaining[0] = AMM Id - must be owned by AMM program
        require!(
            remaining[0].owner == &crate::RAYDIUM_AMM_PROGRAM_ID,
            PrivacyError::InvalidRemainingAccounts
        );
        // remaining[4], remaining[5] = Pool token accounts - must be owned by Token program
        require!(
            remaining[4].owner == &anchor_spl::token::ID,
            PrivacyError::InvalidRemainingAccounts
        );
        require!(
            remaining[5].owner == &anchor_spl::token::ID,
            PrivacyError::InvalidRemainingAccounts
        );
        // remaining[11], remaining[12] = Serum vaults - must be owned by Token program
        require!(
            remaining[11].owner == &anchor_spl::token::ID,
            PrivacyError::InvalidRemainingAccounts
        );
        require!(
            remaining[12].owner == &anchor_spl::token::ID,
            PrivacyError::InvalidRemainingAccounts
        );

        let amm_accounts = vec![
            AccountMeta::new_readonly(ctx.accounts.token_program.key(), false), // 0
            AccountMeta::new(remaining[0].key(), false),                        // 1: Amm Id
            AccountMeta::new_readonly(remaining[1].key(), false),               // 2: Amm Authority
            AccountMeta::new(remaining[2].key(), false),                        // 3: Open Orders
            AccountMeta::new(remaining[3].key(), false),                        // 4: Target Orders
            AccountMeta::new(remaining[4].key(), false),                        // 5: Pool Coin
            AccountMeta::new(remaining[5].key(), false),                        // 6: Pool Pc
            AccountMeta::new_readonly(remaining[6].key(), false),               // 7: Serum Program
            AccountMeta::new(remaining[7].key(), false),                        // 8: Serum Market
            AccountMeta::new(remaining[8].key(), false),                        // 9: Bids
            AccountMeta::new(remaining[9].key(), false),                        // 10: Asks
            AccountMeta::new(remaining[10].key(), false),                       // 11: Event Queue
            AccountMeta::new(remaining[11].key(), false),                       // 12: Coin Vault
            AccountMeta::new(remaining[12].key(), false),                       // 13: Pc Vault
            AccountMeta::new_readonly(remaining[13].key(), false),              // 14: Vault Signer
            AccountMeta::new(ctx.accounts.executor_source_token.key(), false),  // 15
            AccountMeta::new(ctx.accounts.executor_dest_token.key(), false),    // 16
            AccountMeta::new_readonly(executor.key(), true),                    // 17
        ];

        let swap_ix = Instruction {
            program_id: ctx.accounts.swap_program.key(),
            accounts: amm_accounts,
            data: swap_data.clone(),
        };

        msg!("Raydium AMM: Executing Swap...");

        // Construct account_infos including all dependencies
        let mut account_infos = vec![
            ctx.accounts.token_program.to_account_info(),
            ctx.accounts.executor_source_token.to_account_info(),
            ctx.accounts.executor_dest_token.to_account_info(),
            executor.to_account_info(),
            ctx.accounts.swap_program.to_account_info(),
        ];

        for acc in remaining.iter().take(14) {
            account_infos.push(acc.to_account_info());
        }

        invoke_signed(&swap_ix, &account_infos, &[executor_seeds])?;
    } else if is_jupiter {
        // Jupiter V6 Route Swap
        msg!("Jupiter V6: Executing Route Swap...");

        // Security: Verify Jupiter Event Authority matches expected constant
        require!(
            ctx.accounts.jupiter_event_authority.key() == crate::JUPITER_EVENT_AUTHORITY,
            PrivacyError::Unauthorized
        );

        msg!(
            "Jupiter Event Authority: {}",
            ctx.accounts.jupiter_event_authority.key()
        );

        let mut jupiter_accounts = Vec::new();
        let mut account_infos = Vec::new();

        let is_shared_accounts = swap_data[0..8]
            == [0xc1, 0x20, 0x9b, 0x33, 0x41, 0xd6, 0x9c, 0x81]
            || swap_data[0..8] == [0xb0, 0xd1, 0x69, 0xa8, 0x9a, 0x7d, 0x45, 0x3e];

        if is_shared_accounts {
            // SharedAccountsRoute Layout:
            // 0: TokenProgram
            // 1: ProgramAuthority (from remaining[0])
            // 2: UserTransferAuthority (signer) -> Protocol Authority (our executor)
            // 3: UserSourceTokenAccount -> Executor Source Token
            // 4: ProgramSourceTokenAccount (from remaining[1])
            // 5: ProgramDestTokenAccount (from remaining[2])
            // 6: UserDestTokenAccount -> Executor Dest Token
            // 7: SourceMint
            // 8: DestMint
            // ...

            // Minimum account count check - Jupiter will validate account correctness
            require!(
                remaining.len() >= 9,
                PrivacyError::JupiterInsufficientAccounts
            );

            // We need to inject our executor accounts at indices 2, 3, and 6
            // The `remaining` array contains the accounts Jupiter expects, so we iterate through them
            // and replace the user-specific ones with our executor ones.

            for (i, acc) in remaining.iter().enumerate() {
                match i {
                    2 => {
                        // Index 2: User Transfer Authority -> Executor (Signer)
                        jupiter_accounts.push(AccountMeta::new_readonly(executor.key(), true));
                        account_infos.push(executor.to_account_info());
                    }
                    3 => {
                        // Index 3: User Source Token Account -> Executor Source Token
                        jupiter_accounts.push(AccountMeta::new(
                            ctx.accounts.executor_source_token.key(),
                            false,
                        ));
                        account_infos.push(ctx.accounts.executor_source_token.to_account_info());
                    }
                    6 => {
                        // Index 6: User Destination Token Account -> Executor Dest Token
                        jupiter_accounts.push(AccountMeta::new(
                            ctx.accounts.executor_dest_token.key(),
                            false,
                        ));
                        account_infos.push(ctx.accounts.executor_dest_token.to_account_info());
                    }
                    _ => {
                        // Pass through other accounts (Project Authority, Mints, etc.)
                        jupiter_accounts.push(if acc.is_writable {
                            AccountMeta::new(acc.key(), false)
                        } else {
                            AccountMeta::new_readonly(acc.key(), false)
                        });
                        account_infos.push(acc.to_account_info());
                    }
                }
            }
        } else {
            // Standard Route / ExactOutRoute Layout:
            // 0: TokenProgram
            // 1: UserTransferAuthority -> Executor
            // 2: UserSourceTokenAccount -> Executor Source Token
            // 3: UserDestTokenAccount -> Executor Dest Token
            // 4: DestMint (or other optional)
            // ...

            // Minimum account count check - Jupiter will validate account correctness
            require!(
                remaining.len() >= 4,
                PrivacyError::JupiterInsufficientAccounts
            );

            for (i, acc) in remaining.iter().enumerate() {
                match i {
                    1 => {
                        // Replace account #1 with executor PDA (marked as signer)
                        jupiter_accounts.push(AccountMeta::new_readonly(executor.key(), true));
                        account_infos.push(executor.to_account_info());
                    }
                    2 => {
                        // Replace account #2 with executor's source token account
                        jupiter_accounts.push(AccountMeta::new(
                            ctx.accounts.executor_source_token.key(),
                            false,
                        ));
                        account_infos.push(ctx.accounts.executor_source_token.to_account_info());
                    }
                    3 => {
                        // Replace account #3 with executor's dest token account
                        jupiter_accounts.push(AccountMeta::new(
                            ctx.accounts.executor_dest_token.key(),
                            false,
                        ));
                        account_infos.push(ctx.accounts.executor_dest_token.to_account_info());
                    }
                    _ => {
                        // Use account from remaining_accounts as-is
                        jupiter_accounts.push(if acc.is_writable {
                            AccountMeta::new(acc.key(), false)
                        } else {
                            AccountMeta::new_readonly(acc.key(), false)
                        });
                        account_infos.push(acc.to_account_info());
                    }
                }
            }
        }

        // Construct instruction
        let swap_ix = Instruction {
            program_id: ctx.accounts.swap_program.key(),
            accounts: jupiter_accounts,
            data: swap_data.clone(),
        };

        // Execute CPI with executor PDA signing
        invoke_signed(&swap_ix, &account_infos, &[executor_seeds])?
    } else {
        msg!(
            "Unknown Swap Program detected. Requires CPMM (0x8fbe..), AMM (0x09), or Jupiter (0xe517cb97..) discriminator."
        );
        return err!(PrivacyError::InvalidPublicAmount);
    }

    // Transfer swapped tokens to dest vault (minus fee)
    ctx.accounts.executor_dest_token.reload()?;
    let swapped_amount = ctx.accounts.executor_dest_token.amount;

    require!(
        swapped_amount >= swap_params.min_amount_out,
        PrivacyError::InvalidPublicAmount
    );

    let relayer_fee = ext_data.fee;
    require!(
        swapped_amount > relayer_fee,
        PrivacyError::InvalidPublicAmount
    );

    // Validate fee meets pool requirements
    let dest_config = &ctx.accounts.dest_config;
    let percentage_fee = (swapped_amount as u128)
        .checked_mul(dest_config.swap_fee_bps as u128)
        .and_then(|x| x.checked_div(10_000))
        .ok_or(PrivacyError::ArithmeticOverflow)? as u64;
    let min_required_fee = std::cmp::max(dest_config.min_swap_fee, percentage_fee);
    require!(
        relayer_fee >= min_required_fee,
        PrivacyError::InsufficientFee
    );

    let vault_amount = swapped_amount.saturating_sub(relayer_fee);

    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.executor_dest_token.to_account_info(),
                to: ctx.accounts.dest_vault_token_account.to_account_info(),
                authority: executor.to_account_info(),
            },
            &[executor_seeds],
        ),
        vault_amount,
    )?;

    // Update dest pool TVL (increase by vault_amount)
    ctx.accounts.dest_config.total_tvl = ctx
        .accounts
        .dest_config
        .total_tvl
        .checked_add(vault_amount)
        .ok_or(PrivacyError::ArithmeticOverflow)?;

    // Pay relayer fee
    if relayer_fee > 0 {
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.executor_dest_token.to_account_info(),
                    to: ctx.accounts.relayer_token_account.to_account_info(),
                    authority: executor.to_account_info(),
                },
                &[executor_seeds],
            ),
            relayer_fee,
        )?;
    }

    // Insert swap output (commitment 0) into destination tree
    // Insert commitments into trees
    // output_commitments[0] = changeCommitment (goes back to source tree)
    // output_commitments[1] = destCommitment (goes to dest tree)

    // Insert dest note (commitment 1) into dest tree
    let mut dest_tree = ctx.accounts.dest_tree.load_mut()?;

    let max_capacity = 1u64 << (dest_tree.height as u64);
    let remaining = max_capacity.saturating_sub(dest_tree.next_index);
    require!(remaining >= 1, PrivacyError::MerkleTreeFull);

    let leaf_index_dest = dest_tree.next_index;
    MerkleTree::append::<PoseidonHasher>(output_commitments[1], &mut *dest_tree)?;

    let dest_new_root = dest_tree.root;
    drop(dest_tree);

    emit!(crate::CommitmentEvent {
        commitment: output_commitments[1],
        leaf_index: leaf_index_dest,
        new_root: dest_new_root,
        timestamp: clock.unix_timestamp,
        mint_address: dest_mint,
        tree_id: dest_tree_id,
    });

    // Insert change note (commitment 0) back into source tree
    let mut source_tree = ctx.accounts.source_tree.load_mut()?;

    let max_capacity = 1u64 << (source_tree.height as u64);
    let remaining = max_capacity.saturating_sub(source_tree.next_index);
    require!(remaining >= 1, PrivacyError::MerkleTreeFull);

    let leaf_index_change = source_tree.next_index;
    MerkleTree::append::<PoseidonHasher>(output_commitments[0], &mut *source_tree)?;

    let source_new_root = source_tree.root;
    drop(source_tree);

    emit!(crate::CommitmentEvent {
        commitment: output_commitments[0],
        leaf_index: leaf_index_change,
        new_root: source_new_root,
        timestamp: clock.unix_timestamp,
        mint_address: source_mint,
        tree_id: source_tree_id,
    });

    // Close executor accounts
    token::close_account(CpiContext::new_with_signer(
        ctx.accounts.token_program.to_account_info(),
        CloseAccount {
            account: ctx.accounts.executor_source_token.to_account_info(),
            destination: ctx.accounts.relayer.to_account_info(),
            authority: executor.to_account_info(),
        },
        &[executor_seeds],
    ))?;
    token::close_account(CpiContext::new_with_signer(
        ctx.accounts.token_program.to_account_info(),
        CloseAccount {
            account: ctx.accounts.executor_dest_token.to_account_info(),
            destination: ctx.accounts.relayer.to_account_info(),
            authority: executor.to_account_info(),
        },
        &[executor_seeds],
    ))?;

    // Return executor PDA rent to relayer
    let executor_lamports = executor.to_account_info().lamports();
    **executor.to_account_info().try_borrow_mut_lamports()? = 0;
    **ctx
        .accounts
        .relayer
        .to_account_info()
        .try_borrow_mut_lamports()? = ctx
        .accounts
        .relayer
        .to_account_info()
        .lamports()
        .checked_add(executor_lamports)
        .ok_or(PrivacyError::MathOverflow)?;

    emit!(SwapExecutedEvent {
        source_mint,
        dest_mint,
        source_tree_id,
        dest_tree_id,
        nullifiers: input_nullifiers,
        commitments: output_commitments,
        timestamp: clock.unix_timestamp,
    });

    Ok(())
}

#[event]
pub struct SwapExecutedEvent {
    pub source_mint: Pubkey,
    pub dest_mint: Pubkey,
    pub source_tree_id: u16,
    pub dest_tree_id: u16,
    pub nullifiers: [[u8; 32]; 2],
    pub commitments: [[u8; 32]; 2],
    pub timestamp: i64,
}

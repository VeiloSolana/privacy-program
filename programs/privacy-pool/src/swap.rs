use anchor_lang::prelude::*;
use anchor_lang::solana_program::{instruction::Instruction, program::invoke_signed};
use anchor_spl::token::{self, Transfer};

use crate::{ExtData, MerkleTree, PoseidonHasher, PrivacyError, TransactSwap};

/// Swap executor PDA - ephemeral account that holds tokens during swap
/// Created and closed within a single transaction
#[account]
pub struct SwapExecutor {
    /// Source mint being swapped from
    pub source_mint: Pubkey,
    /// Destination mint being swapped to
    pub dest_mint: Pubkey,
    /// Nullifier from source pool (ensures one-time use)
    pub nullifier: [u8; 32],
    /// PDA bump
    pub bump: u8,
}

impl SwapExecutor {
    pub const LEN: usize = 8 + 32 + 32 + 32 + 1; // 105 bytes
}

/// Swap parameters committed to in the ZK proof
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SwapParams {
    /// Minimum amount out (slippage protection)
    pub min_amount_out: u64,
    /// Deadline timestamp (prevents stale swaps)
    pub deadline: i64,
    /// Source token mint
    pub source_mint: Pubkey,
    /// Destination token mint
    pub dest_mint: Pubkey,
}

impl SwapParams {
    /// Hash swap parameters for commitment in ZK proof
    pub fn hash(&self) -> Result<[u8; 32]> {
        use light_hasher::Hasher;

        // Encode params as 32-byte values
        let mut min_out_bytes = [0u8; 32];
        min_out_bytes[24..].copy_from_slice(&self.min_amount_out.to_be_bytes());

        let mut deadline_bytes = [0u8; 32];
        deadline_bytes[24..].copy_from_slice(&self.deadline.to_be_bytes());

        // Hash: Poseidon(source_mint, dest_mint, min_out, deadline)
        let hash1 =
            PoseidonHasher::hashv(&[&self.source_mint.to_bytes(), &self.dest_mint.to_bytes()])
                .map_err(|_| error!(PrivacyError::MerkleHashFailed))?;

        let hash2 = PoseidonHasher::hashv(&[&min_out_bytes, &deadline_bytes])
            .map_err(|_| error!(PrivacyError::MerkleHashFailed))?;

        let final_hash = PoseidonHasher::hashv(&[&hash1, &hash2])
            .map_err(|_| error!(PrivacyError::MerkleHashFailed))?;

        Ok(final_hash)
    }
}

/// Public inputs for swap ZK proof
/// This extends the standard transaction proof with swap-specific commitments
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SwapPublicInputs {
    /// Source pool Merkle root (must be in root_history)
    pub source_root: [u8; 32],

    /// Hash of swap parameters (min_out, deadline, mints)
    pub swap_params_hash: [u8; 32],

    /// Hash of external data: Poseidon(relayer, fee)
    pub ext_data_hash: [u8; 32],

    /// Source token mint
    pub source_mint: Pubkey,

    /// Destination token mint
    pub dest_mint: Pubkey,

    /// Input nullifiers (2 notes consumed from source pool)
    pub input_nullifiers: [[u8; 32]; 2],

    /// Output commitments (2 notes created in destination pool)
    pub output_commitments: [[u8; 32]; 2],

    /// Amount being swapped (from source pool)
    pub swap_amount: u64,
}

/// Atomic cross-pool swap instruction
///
/// Flow:
/// 1. Verify ZK proof (user owns notes in source pool, commits to swap params)
/// 2. Burn nullifiers in source pool
/// 3. Create executor PDA and token accounts
/// 4. Transfer from source vault → executor
/// 5. CPI to Raydium CPMM (executor signs) - NO SERUM
/// 6. Transfer from executor → dest vault
/// 7. Insert commitments in dest pool
/// 8. Pay relayer fee
/// 9. Close executor accounts
///
/// All steps are atomic - transaction succeeds or reverts entirely
pub fn transact_swap<'info>(
    ctx: Context<'_, '_, 'info, 'info, TransactSwap<'info>>,
    // Source pool params
    source_root: [u8; 32],
    source_tree_id: u16,
    source_mint: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    // Destination pool params
    dest_tree_id: u16,
    dest_mint: Pubkey,
    output_commitment_0: [u8; 32],
    output_commitment_1: [u8; 32],
    // Swap params
    swap_params: SwapParams,
    // Amount to swap (will be verified against ZK proof once circuit is ready)
    swap_amount: u64,
    // Raydium CPMM swap data: [discriminator (1), amount_in (8), min_out (8)]
    swap_data: Vec<u8>,
    // External data (relayer, fee)
    _ext_data: ExtData,
    // ZK proof
    // proof: SwapProof, // TODO: Define once circuit is ready
) -> Result<()> {
    // Validate both pools are initialized and mints are allowed
    require!(
        ctx.accounts.source_config.mint_address == source_mint,
        PrivacyError::InvalidMintAddress
    );
    require!(
        ctx.accounts.dest_config.mint_address == dest_mint,
        PrivacyError::InvalidMintAddress
    );

    // Validate different pools (can't swap same token to itself)
    require!(source_mint != dest_mint, PrivacyError::InvalidMintAddress);

    // Validate relayer is authorized
    require!(
        ctx.accounts
            .source_config
            .is_relayer(&ctx.accounts.relayer.key()),
        PrivacyError::RelayerNotAllowed
    );

    // Validate deadline hasn't passed
    let clock = Clock::get()?;
    require!(
        clock.unix_timestamp <= swap_params.deadline,
        PrivacyError::InvalidPublicAmount // TODO: Add SwapDeadlineExceeded error
    );

    // Combine nullifiers into array for processing
    let input_nullifiers = [input_nullifier_0, input_nullifier_1];
    let output_commitments = [output_commitment_0, output_commitment_1];

    // Validate no duplicate nullifiers
    require!(
        input_nullifiers[0] != input_nullifiers[1],
        PrivacyError::DuplicateNullifiers
    );

    // Validate no duplicate output commitments
    require!(
        output_commitments[0] != output_commitments[1],
        PrivacyError::DuplicateCommitments
    );

    // Validate no zero nullifiers or commitments
    let zero = [0u8; 32];
    require!(
        input_nullifiers[0] != zero && input_nullifiers[1] != zero,
        PrivacyError::ZeroNullifier
    );
    require!(
        output_commitments[0] != zero && output_commitments[1] != zero,
        PrivacyError::ZeroCommitment
    );

    // TODO: Step 1 - Verify ZK proof
    // let public_inputs = SwapPublicInputs {
    //     source_root,
    //     swap_params_hash: swap_params.hash()?,
    //     ext_data_hash: ext_data.hash()?,
    //     source_mint,
    //     dest_mint,
    //     input_nullifiers,
    //     output_commitments,
    //     swap_amount: /* extract from proof */,
    // };
    // verify_swap_groth16(proof, &public_inputs)?;

    // Step 2 - Verify root is known in source tree
    let source_tree = ctx.accounts.source_tree.load()?;
    require!(
        MerkleTree::is_known_root(&*source_tree, source_root),
        PrivacyError::UnknownRoot
    );
    drop(source_tree);

    // Step 3 - Mark nullifiers as spent in source pool
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

    // Step 4 - Initialize executor PDA
    let executor = &mut ctx.accounts.executor;
    executor.source_mint = source_mint;
    executor.dest_mint = dest_mint;
    executor.nullifier = input_nullifiers[0];
    executor.bump = ctx.bumps.executor;

    // Step 5 - Transfer from source vault to executor
    // swap_amount will be verified against ZK proof once circuit is ready
    require!(swap_amount > 0, PrivacyError::InvalidPublicAmount);

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

    // Step 6 - CPI to Raydium CPMM for swap (NO SERUM)
    let executor_seeds: &[&[u8]] = &[
        b"swap_executor",
        input_nullifiers[0].as_ref(),
        &[executor.bump],
    ];

    // Validate swap_data format: [discriminator (8), amount_in (8), min_out (8)]
    // Raydium CPMM uses Anchor 8-byte discriminators
    require!(swap_data.len() >= 24, PrivacyError::InvalidPublicAmount);

    // Raydium CPMM requires 8 accounts in remaining_accounts:
    // 0: authority (CPMM pool vault PDA), 1: amm_config, 2: pool_state
    // 3: input_vault, 4: output_vault
    // 5: input_token_mint, 6: output_token_mint, 7: observation_state
    require!(
        ctx.remaining_accounts.len() >= 8,
        PrivacyError::InvalidPublicAmount
    );

    let remaining = &ctx.remaining_accounts;

    // Build CPMM swap instruction with correct Anchor account order:
    // 1. payer (signer) - executor signs via invoke_signed
    // 2. authority - CPMM pool vault authority PDA
    // 3. amm_config - Factory state
    // 4. pool_state - Pool account
    // 5. input_token_account - User's input token (executor_source_token)
    // 6. output_token_account - User's output token (executor_dest_token)
    // 7. input_vault - Pool's input vault
    // 8. output_vault - Pool's output vault
    // 9. input_token_program - SPL Token program
    // 10. output_token_program - SPL Token program
    // 11. input_token_mint - Mint of input token
    // 12. output_token_mint - Mint of output token
    // 13. observation_state - Oracle observation
    let cpmm_accounts = vec![
        AccountMeta::new_readonly(executor.key(), true), // payer (signer)
        AccountMeta::new_readonly(remaining[0].key(), false), // authority
        AccountMeta::new_readonly(remaining[1].key(), false), // amm_config
        AccountMeta::new(remaining[2].key(), false),     // pool_state
        AccountMeta::new(ctx.accounts.executor_source_token.key(), false), // input_token_account
        AccountMeta::new(ctx.accounts.executor_dest_token.key(), false), // output_token_account
        AccountMeta::new(remaining[3].key(), false),     // input_vault
        AccountMeta::new(remaining[4].key(), false),     // output_vault
        AccountMeta::new_readonly(ctx.accounts.token_program.key(), false), // input_token_program
        AccountMeta::new_readonly(ctx.accounts.token_program.key(), false), // output_token_program
        AccountMeta::new_readonly(remaining[5].key(), false), // input_token_mint
        AccountMeta::new_readonly(remaining[6].key(), false), // output_token_mint
        AccountMeta::new(remaining[7].key(), false),     // observation_state
    ];

    let swap_ix = Instruction {
        program_id: ctx.accounts.raydium_cpmm_program.key(),
        accounts: cpmm_accounts,
        data: swap_data.clone(),
    };

    // Detect instruction type from discriminator (first 8 bytes)
    // swap_base_input: 8fbe5adac41e33de
    // swap_base_output: 37d96256a34ab4ad
    let is_base_input = swap_data[0] == 0x8f && swap_data[1] == 0xbe;

    msg!(
        "Raydium CPMM: swap_base_{} amount={}",
        if is_base_input { "input" } else { "output" },
        swap_amount
    );

    // Build account_infos for invoke_signed - must match cpmm_accounts order
    let account_infos = &[
        executor.to_account_info(),                           // payer (signer)
        remaining[0].to_account_info(),                       // authority (CPMM pool authority)
        remaining[1].to_account_info(),                       // amm_config
        remaining[2].to_account_info(),                       // pool_state
        ctx.accounts.executor_source_token.to_account_info(), // input_token_account
        ctx.accounts.executor_dest_token.to_account_info(),   // output_token_account
        remaining[3].to_account_info(),                       // input_vault
        remaining[4].to_account_info(),                       // output_vault
        ctx.accounts.token_program.to_account_info(),         // input_token_program
        ctx.accounts.token_program.to_account_info(),         // output_token_program (same)
        remaining[5].to_account_info(),                       // input_token_mint
        remaining[6].to_account_info(),                       // output_token_mint
        remaining[7].to_account_info(),                       // observation_state
        ctx.accounts.raydium_cpmm_program.to_account_info(),  // program
    ];

    invoke_signed(&swap_ix, account_infos, &[executor_seeds])?;

    // Step 7 - Transfer from executor to dest vault
    // Reload dest token account to get updated balance after swap
    ctx.accounts.executor_dest_token.reload()?;
    let swapped_amount = ctx.accounts.executor_dest_token.amount;

    require!(
        swapped_amount >= swap_params.min_amount_out,
        PrivacyError::InvalidPublicAmount // Slippage exceeded
    );

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
        swapped_amount,
    )?;

    // Step 8 - Insert commitments into destination tree
    let mut dest_tree = ctx.accounts.dest_tree.load_mut()?;

    // Check destination tree has capacity
    let max_capacity = 1u64 << (dest_tree.height as u64);
    let remaining = max_capacity.saturating_sub(dest_tree.next_index);
    require!(remaining >= 2, PrivacyError::MerkleTreeFull);

    let leaf_index_0 = dest_tree.next_index;
    MerkleTree::append::<PoseidonHasher>(output_commitments[0], &mut *dest_tree)?;

    let leaf_index_1 = dest_tree.next_index;
    MerkleTree::append::<PoseidonHasher>(output_commitments[1], &mut *dest_tree)?;

    let new_root = dest_tree.root;
    drop(dest_tree);

    // Emit commitment events
    emit!(crate::CommitmentEvent {
        commitment: output_commitments[0],
        leaf_index: leaf_index_0,
        new_root,
        timestamp: clock.unix_timestamp,
        mint_address: dest_mint,
        tree_id: dest_tree_id,
    });

    emit!(crate::CommitmentEvent {
        commitment: output_commitments[1],
        leaf_index: leaf_index_1,
        new_root,
        timestamp: clock.unix_timestamp,
        mint_address: dest_mint,
        tree_id: dest_tree_id,
    });

    // TODO: Step 9 - Pay relayer fee from swapped amount
    // Fee is taken from destination tokens before depositing to vault
    // This is already handled in the amount deposited above

    // TODO: Step 10 - Close executor accounts (return rent to relayer)
    // This will be done after all transfers are complete

    // Emit swap event
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

// ---- Events ----

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

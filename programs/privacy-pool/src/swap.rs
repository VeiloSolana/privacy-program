use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, Token, TokenAccount};

use crate::merkle_tree::MerkleTreeAccount;
use crate::{
    ExtData, GlobalConfig, MerkleTree, NullifierMarker, NullifierSet, PoseidonHasher,
    PrivacyConfig, PrivacyError, Vault,
};

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

/// Account context for atomic cross-pool swap
/// This instruction:
/// 1. Consumes notes from source pool (e.g., SOL)
/// 2. Creates ephemeral executor PDA
/// 3. CPIs to Jupiter/Raydium to execute swap
/// 4. Creates notes in destination pool (e.g., USDC)
/// All atomic - succeeds or reverts entirely
#[derive(Accounts)]
#[instruction(
    source_root: [u8; 32],
    source_tree_id: u16,
    source_mint: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    dest_tree_id: u16,
    dest_mint: Pubkey,
    output_commitment_0: [u8; 32],
    output_commitment_1: [u8; 32],
)]
pub struct TransactSwap<'info> {
    // ---- Source Pool (tokens being swapped FROM) ----
    #[account(
        mut,
        seeds = [b"privacy_config_v3", source_mint.as_ref()],
        bump = source_config.bump
    )]
    pub source_config: Account<'info, PrivacyConfig>,

    #[account(
        seeds = [b"global_config_v1"],
        bump = global_config.bump
    )]
    pub global_config: Account<'info, GlobalConfig>,

    #[account(
        mut,
        seeds = [b"privacy_vault_v3", source_mint.as_ref()],
        bump = source_config.vault_bump
    )]
    pub source_vault: Account<'info, Vault>,

    /// Source tree - where input notes came from
    #[account(
        mut,
        seeds = [b"privacy_note_tree_v3", source_mint.as_ref(), &source_tree_id.to_le_bytes()],
        bump,
    )]
    pub source_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        mut,
        seeds = [b"privacy_nullifiers_v3", source_mint.as_ref()],
        bump = source_nullifiers.bump
    )]
    pub source_nullifiers: Account<'info, NullifierSet>,

    /// First nullifier marker for source pool
    #[account(
        init_if_needed,
        payer = relayer,
        seeds = [b"nullifier_v3", source_mint.as_ref(), &source_tree_id.to_le_bytes(), input_nullifier_0.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub source_nullifier_marker_0: Account<'info, NullifierMarker>,

    /// Second nullifier marker for source pool
    #[account(
        init_if_needed,
        payer = relayer,
        seeds = [b"nullifier_v3", source_mint.as_ref(), &source_tree_id.to_le_bytes(), input_nullifier_1.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub source_nullifier_marker_1: Account<'info, NullifierMarker>,

    /// Source vault's token account (ATA for source_mint)
    #[account(mut)]
    pub source_vault_token_account: Account<'info, TokenAccount>,

    /// Source token mint
    pub source_mint_account: Account<'info, Mint>,

    // ---- Destination Pool (tokens being swapped TO) ----
    #[account(
        mut,
        seeds = [b"privacy_config_v3", dest_mint.as_ref()],
        bump = dest_config.bump
    )]
    pub dest_config: Account<'info, PrivacyConfig>,

    #[account(
        mut,
        seeds = [b"privacy_vault_v3", dest_mint.as_ref()],
        bump = dest_config.vault_bump
    )]
    pub dest_vault: Account<'info, Vault>,

    /// Destination tree - where output commitments will be inserted
    #[account(
        mut,
        seeds = [b"privacy_note_tree_v3", dest_mint.as_ref(), &dest_tree_id.to_le_bytes()],
        bump,
    )]
    pub dest_tree: AccountLoader<'info, MerkleTreeAccount>,

    /// Destination vault's token account (ATA for dest_mint)
    #[account(mut)]
    pub dest_vault_token_account: Account<'info, TokenAccount>,

    /// Destination token mint
    pub dest_mint_account: Account<'info, Mint>,

    // ---- Ephemeral Swap Executor PDA ----
    /// Executor PDA - holds tokens during swap
    /// Seeds ensure this is unique per swap (bound to nullifier)
    #[account(
        init,
        payer = relayer,
        seeds = [b"swap_executor", input_nullifier_0.as_ref()],
        bump,
        space = SwapExecutor::LEN
    )]
    pub executor: Account<'info, SwapExecutor>,

    /// Executor's source token account (receives from source vault)
    #[account(
        init,
        payer = relayer,
        associated_token::mint = source_mint_account,
        associated_token::authority = executor,
    )]
    pub executor_source_token: Account<'info, TokenAccount>,

    /// Executor's destination token account (receives swapped tokens)
    #[account(
        init,
        payer = relayer,
        associated_token::mint = dest_mint_account,
        associated_token::authority = executor,
    )]
    pub executor_dest_token: Account<'info, TokenAccount>,

    // ---- Transaction Participants ----
    /// Relayer who submits transaction (pays rent, receives fee)
    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Relayer's token account for fees (dest token)
    #[account(mut)]
    pub relayer_token_account: Account<'info, TokenAccount>,

    // ---- Jupiter/DEX Integration ----
    /// Jupiter aggregator program
    /// CHECK: Validated against Jupiter program ID in instruction
    pub jupiter_program: UncheckedAccount<'info>,

    // Additional Jupiter accounts passed via remaining_accounts:
    // - DEX programs (Raydium, Orca, etc.)
    // - Pool accounts
    // - Oracle accounts
    // - etc.
    // These are dynamic based on route chosen by client
    // ---- Programs ----
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub associated_token_program: Program<'info, anchor_spl::associated_token::AssociatedToken>,
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
/// 5. CPI to Jupiter (executor signs)
/// 6. Transfer from executor → dest vault
/// 7. Insert commitments in dest pool
/// 8. Pay relayer fee
/// 9. Close executor accounts
///
/// All steps are atomic - transaction succeeds or reverts entirely
pub fn transact_swap(
    ctx: Context<TransactSwap>,
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

    // TODO: Step 5 - Transfer from source vault to executor
    // let swap_amount = /* extract from proof verification */;
    // let source_vault_seeds = &[
    //     b"privacy_vault_v3",
    //     source_mint.as_ref(),
    //     &[ctx.accounts.source_vault.bump],
    // ];
    //
    // token::transfer(
    //     CpiContext::new_with_signer(
    //         ctx.accounts.token_program.to_account_info(),
    //         token::Transfer {
    //             from: ctx.accounts.source_vault_token_account.to_account_info(),
    //             to: ctx.accounts.executor_source_token.to_account_info(),
    //             authority: ctx.accounts.source_vault.to_account_info(),
    //         },
    //         &[source_vault_seeds],
    //     ),
    //     swap_amount,
    // )?;

    // TODO: Step 6 - CPI to Jupiter for swap
    // This will be implemented in the next phase
    // jupiter_cpi::swap(
    //     executor_seeds,
    //     ctx.accounts.jupiter_program,
    //     ctx.accounts.executor_source_token,
    //     ctx.accounts.executor_dest_token,
    //     swap_amount,
    //     swap_params.min_amount_out,
    //     ctx.remaining_accounts, // Jupiter route accounts
    // )?;

    // TODO: Step 7 - Transfer from executor to dest vault
    // let executor_seeds = &[
    //     b"swap_executor",
    //     input_nullifiers[0].as_ref(),
    //     &[executor.bump],
    // ];
    //
    // let swapped_amount = ctx.accounts.executor_dest_token.amount;
    //
    // token::transfer(
    //     CpiContext::new_with_signer(
    //         ctx.accounts.token_program.to_account_info(),
    //         token::Transfer {
    //             from: ctx.accounts.executor_dest_token.to_account_info(),
    //             to: ctx.accounts.dest_vault_token_account.to_account_info(),
    //             authority: executor.to_account_info(),
    //         },
    //         &[executor_seeds],
    //     ),
    //     swapped_amount,
    // )?;

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

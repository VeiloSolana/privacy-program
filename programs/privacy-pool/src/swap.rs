use anchor_lang::prelude::*;
use anchor_lang::solana_program::{instruction::Instruction, program::invoke_signed};
use anchor_spl::token::{self, CloseAccount, Transfer};

use crate::{ExtData, MerkleTree, PoseidonHasher, PrivacyError, TransactSwap};

/// Ephemeral PDA that holds tokens during swap, created and closed atomically
#[account]
pub struct SwapExecutor {
    pub source_mint: Pubkey,
    pub dest_mint: Pubkey,
    pub nullifier: [u8; 32],
    pub bump: u8,
}

impl SwapExecutor {
    pub const LEN: usize = 8 + 32 + 32 + 32 + 1;
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
    pub fn hash(&self) -> Result<[u8; 32]> {
        use light_hasher::Hasher;

        let mut min_out_bytes = [0u8; 32];
        min_out_bytes[24..].copy_from_slice(&self.min_amount_out.to_be_bytes());

        let mut deadline_bytes = [0u8; 32];
        deadline_bytes[24..].copy_from_slice(&self.deadline.to_be_bytes());

        let hash1 =
            PoseidonHasher::hashv(&[&self.source_mint.to_bytes(), &self.dest_mint.to_bytes()])
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

    require!(
        ctx.accounts
            .source_config
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
    // ║ CRITICAL TODO: ZK PROOF VERIFICATION                                     ║
    // ║ Without this, the swap is NOT privacy-preserving!                        ║
    // ║                                                                          ║
    // ║ The proof must verify:                                                   ║
    // ║   1. User owns input notes (knows preimages for nullifiers)              ║
    // ║   2. Input notes exist in source Merkle tree (root membership)           ║
    // ║   3. Output commitments are correctly formed                             ║
    // ║   4. swap_amount + change = sum(input_notes)                             ║
    // ║   5. ext_data_hash matches Poseidon(relayer, fee)                        ║
    // ║   6. swap_params_hash matches committed swap parameters                  ║
    // ╚══════════════════════════════════════════════════════════════════════════╝
    // let public_inputs = SwapPublicInputs {
    //     source_root,
    //     swap_params_hash: swap_params.hash()?,
    //     ext_data_hash: ext_data.hash()?,
    //     source_mint,
    //     dest_mint,
    //     input_nullifiers,
    //     output_commitments,
    //     swap_amount,
    // };
    // verify_swap_groth16(proof, &public_inputs)?;

    // Verify root is known
    let source_tree = ctx.accounts.source_tree.load()?;
    require!(
        MerkleTree::is_known_root(&*source_tree, source_root),
        PrivacyError::UnknownRoot
    );
    drop(source_tree);

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

    // Initialize executor PDA
    let executor = &mut ctx.accounts.executor;
    executor.source_mint = source_mint;
    executor.dest_mint = dest_mint;
    executor.nullifier = input_nullifiers[0];
    executor.bump = ctx.bumps.executor;

    // Transfer from source vault to executor
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

    // CPI to Raydium CPMM for swap
    let executor_seeds: &[&[u8]] = &[
        b"swap_executor",
        input_nullifiers[0].as_ref(),
        &[executor.bump],
    ];

    require!(swap_data.len() >= 24, PrivacyError::InvalidPublicAmount);
    require!(
        ctx.remaining_accounts.len() >= 8,
        PrivacyError::InvalidPublicAmount
    );

    let remaining = &ctx.remaining_accounts;

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
        program_id: ctx.accounts.raydium_cpmm_program.key(),
        accounts: cpmm_accounts,
        data: swap_data.clone(),
    };

    let is_base_input = swap_data[0] == 0x8f && swap_data[1] == 0xbe;
    msg!(
        "Raydium CPMM: swap_base_{} amount={}",
        if is_base_input { "input" } else { "output" },
        swap_amount
    );

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
        ctx.accounts.token_program.to_account_info(),
        remaining[5].to_account_info(),
        remaining[6].to_account_info(),
        remaining[7].to_account_info(),
        ctx.accounts.raydium_cpmm_program.to_account_info(),
    ];

    invoke_signed(&swap_ix, account_infos, &[executor_seeds])?;

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
        .unwrap_or(0) as u64;
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

    // Insert commitments into destination tree
    let mut dest_tree = ctx.accounts.dest_tree.load_mut()?;

    let max_capacity = 1u64 << (dest_tree.height as u64);
    let remaining = max_capacity.saturating_sub(dest_tree.next_index);
    require!(remaining >= 2, PrivacyError::MerkleTreeFull);

    let leaf_index_0 = dest_tree.next_index;
    MerkleTree::append::<PoseidonHasher>(output_commitments[0], &mut *dest_tree)?;

    let leaf_index_1 = dest_tree.next_index;
    MerkleTree::append::<PoseidonHasher>(output_commitments[1], &mut *dest_tree)?;

    let new_root = dest_tree.root;
    drop(dest_tree);

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

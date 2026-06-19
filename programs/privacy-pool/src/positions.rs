use anchor_lang::prelude::*;
use anchor_lang::solana_program::{instruction::Instruction, program::invoke, program::invoke_signed};
use anchor_lang::solana_program::sysvar::instructions::{load_current_index_checked, load_instruction_at_checked};
use anchor_spl::associated_token::get_associated_token_address;
use anchor_spl::token::{self, CloseAccount, SyncNative, Transfer};

use crate::merkle_tree::{MerkleTree, MERKLE_TREE_HEIGHT, ROOT_HISTORY_SIZE};
use crate::swap::{SwapParams, SwapPublicInputs};
use crate::zk::{verify_swap_transaction_groth16, verify_transaction_groth16, SwapProof, TransactionProof};
use crate::{
    mark_nullifier_spent, ClosePosition, CommitmentEvent, ExtData, InitPositionPool,
    MergePositions, NoteCiphers, NullifierSpent,
    OpenPosition, PositionNullifierMarker, PrivacyError, TransactionPublicInputs,
    MAX_RELAYERS, MAX_SWAP_FEE_BPS,
};
use crate::PoseidonHasher;

/// Token-2022 program ID
pub const TOKEN_2022_PROGRAM_ID: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

/// Associated Token Program ID
pub const ASSOCIATED_TOKEN_PROGRAM_ID: Pubkey =
    pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

fn is_token_2022(mint_info: &AccountInfo) -> bool {
    *mint_info.owner == TOKEN_2022_PROGRAM_ID
}

/// Read decimals from an SPL Mint or Token-2022 Mint account (same offset for both).
fn get_mint_decimals(mint_info: &AccountInfo) -> Result<u8> {
    let data = mint_info.try_borrow_data()?;
    // Mint layout: mint_authority(36) + supply(8) + decimals(1) = offset 44
    require!(data.len() >= 45, PrivacyError::InvalidMintAddress);
    Ok(data[44])
}

/// Derive the ATA address for a given authority + mint + token_program.
fn get_ata_address(authority: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[authority.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ASSOCIATED_TOKEN_PROGRAM_ID,
    )
    .0
}

/// Emit NullifierSpent for a position nullifier (no NullifierSet counter needed).
fn emit_position_nullifier_spent(
    marker: &mut Account<PositionNullifierMarker>,
    nullifier: [u8; 32],
    bump: u8,
    source_mint: Pubkey,
    tree_id: u16,
) -> Result<()> {
    marker.is_spent = true;
    marker.bump = bump;
    emit!(NullifierSpent {
        nullifier,
        timestamp: Clock::get()?.unix_timestamp,
        mint_address: source_mint,
        tree_id,
    });
    Ok(())
}

/// Create an ATA idempotently (no-op if already exists) for Token or Token-2022.
fn create_ata_idempotent<'info>(
    payer: AccountInfo<'info>,
    authority: AccountInfo<'info>,
    mint: AccountInfo<'info>,
    ata: AccountInfo<'info>,
    token_program_id: Pubkey,
    system_program: AccountInfo<'info>,
    ata_program: AccountInfo<'info>,
) -> Result<()> {
    // create_associated_token_account_idempotent instruction
    // Discriminator: 0x01 (idempotent variant)
    let ix = Instruction {
        program_id: ASSOCIATED_TOKEN_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(payer.key(), true),
            AccountMeta::new(ata.key(), false),
            AccountMeta::new_readonly(authority.key(), false),
            AccountMeta::new_readonly(mint.key(), false),
            AccountMeta::new_readonly(system_program.key(), false),
            AccountMeta::new_readonly(token_program_id, false),
        ],
        data: vec![1u8], // 0x01 = idempotent
    };

    invoke(
        &ix,
        &[payer, ata, authority, mint, system_program, ata_program],
    )?;

    Ok(())
}

// ============================================================================
// init_position_pool
// ============================================================================

pub fn init_position_pool(
    ctx: Context<InitPositionPool>,
    min_swap_fee: u64,
    swap_fee_bps: u16,
) -> Result<()> {
    require!(swap_fee_bps <= MAX_SWAP_FEE_BPS, PrivacyError::ExcessiveFeeBps);

    let cfg = &mut ctx.accounts.config;
    cfg.bump = ctx.bumps.config;
    cfg.authority = ctx.accounts.admin.key();
    cfg.num_relayers = 0;
    cfg.relayers = [Pubkey::default(); MAX_RELAYERS];
    cfg.num_trees = 1;
    cfg.next_tree_index = 0;
    cfg.min_swap_fee = min_swap_fee;
    cfg.swap_fee_bps = swap_fee_bps;

    let mut tree = ctx.accounts.tree.load_init()?;
    tree.authority = ctx.accounts.admin.key();
    tree.height = MERKLE_TREE_HEIGHT as u8;
    tree.root_history_size = ROOT_HISTORY_SIZE as u16;
    tree.next_index = 0;
    tree.root_index = 0;
    MerkleTree::initialize::<PoseidonHasher>(&mut *tree)?;

    Ok(())
}

// ============================================================================
// open_position
// ============================================================================
//
// Flow:
// 1. Validate + ZK proof verify
// 2. Mark USDC nullifiers spent
// 3. Transfer USDC from source vault → executor ATA
// 4. Execute Jupiter/Raydium swap: USDC → stock
// 5. Lazy-init position vault ATA if needed
// 6. Transfer stock from executor → position vault ATA (fee deducted)
// 7. Insert position commitment into position tree
// 8. Insert USDC change commitment into source tree
// 9. Init PositionPDA + update PositionVaultRecord
// 10. Cleanup executor

#[inline(never)]
pub fn open_position<'info>(
    ctx: Context<'_, '_, 'info, 'info, OpenPosition<'info>>,
    source_tree_id: u16,
    source_mint: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    position_tree_id: u16,
    dest_mint: Pubkey,
    position_pda_key: [u8; 32],
    proof: SwapProof,
    source_root: [u8; 32],
    output_commitment_0: [u8; 32], // USDC change note → source tree
    output_commitment_1: [u8; 32], // position note → position tree
    swap_params: SwapParams,
    swap_amount: u64,
    swap_data: Vec<u8>,
    ext_data: ExtData,
    note_ciphers: Option<NoteCiphers>,
) -> Result<()> {
    let (note0_epk, note0_enc, note0_vt, note1_epk, note1_enc, note1_vt) = match note_ciphers {
        Some(c) => (
            c.note0_ephemeral_key,
            c.note0_encrypted,
            c.note0_view_tag,
            c.note1_ephemeral_key,
            c.note1_encrypted,
            c.note1_view_tag,
        ),
        None => ([0u8; 32], [0u8; 80], 0u8, [0u8; 32], [0u8; 80], 0u8),
    };

    // Validate swap program
    require!(
        ctx.accounts.swap_program.key() == crate::RAYDIUM_CPMM_PROGRAM_ID
            || ctx.accounts.swap_program.key() == crate::RAYDIUM_AMM_PROGRAM_ID
            || ctx.accounts.swap_program.key() == crate::JUPITER_PROGRAM_ID,
        PrivacyError::InvalidSwapProgram
    );

    // Validate pool/mint configuration
    require!(
        ctx.accounts.source_config.mint_address == source_mint,
        PrivacyError::InvalidMintAddress
    );
    require!(source_mint != dest_mint, PrivacyError::InvalidMintAddress);

    // Validate tree IDs within bounds
    require!(
        source_tree_id < ctx.accounts.source_config.num_trees,
        PrivacyError::InvalidTreeId
    );
    require!(
        position_tree_id < ctx.accounts.position_config.num_trees,
        PrivacyError::InvalidTreeId
    );

    // Relayer must be whitelisted in both source and position pools
    require!(
        ctx.accounts.source_config.is_relayer(&ctx.accounts.relayer.key()),
        PrivacyError::RelayerNotAllowed
    );
    require!(
        ctx.accounts.position_config.is_relayer(&ctx.accounts.relayer.key()),
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

    let proof = Box::new(proof);
    let swap_params = Box::new(swap_params);
    let ext_data = Box::new(ext_data);

    let swap_params_hash = swap_params.hash(&source_mint, &dest_mint)?;
    let ext_data_hash_val = ext_data.hash()?;

    let public_inputs = Box::new(SwapPublicInputs {
        source_root,
        swap_params_hash,
        ext_data_hash: ext_data_hash_val,
        source_mint,
        dest_mint,
        input_nullifiers,
        output_commitments,
        swap_amount,
    });

    verify_swap_transaction_groth16(&proof, &public_inputs)?;

    // Verify source tree root is in history
    let source_tree = ctx.accounts.source_tree.load()?;
    require!(
        MerkleTree::is_known_root(&*source_tree, source_root),
        PrivacyError::UnknownRoot
    );
    let source_cap = 1u64 << (source_tree.height as u64);
    require!(
        source_cap.saturating_sub(source_tree.next_index) >= 1,
        PrivacyError::MerkleTreeFull
    );
    drop(source_tree);

    // Verify position tree has capacity
    let pos_tree = ctx.accounts.position_tree.load()?;
    let pos_cap = 1u64 << (pos_tree.height as u64);
    require!(
        pos_cap.saturating_sub(pos_tree.next_index) >= 1,
        PrivacyError::MerkleTreeFull
    );
    drop(pos_tree);

    // Mark USDC nullifiers spent
    require!(
        !ctx.accounts.source_nullifier_marker_0.is_spent,
        PrivacyError::NullifierAlreadyUsed
    );
    require!(
        !ctx.accounts.source_nullifier_marker_1.is_spent,
        PrivacyError::NullifierAlreadyUsed
    );

    mark_nullifier_spent(
        &mut ctx.accounts.source_nullifier_marker_0,
        &mut ctx.accounts.source_nullifiers,
        input_nullifiers[0],
        ctx.bumps.source_nullifier_marker_0,
        source_mint,
        source_tree_id,
    )?;
    mark_nullifier_spent(
        &mut ctx.accounts.source_nullifier_marker_1,
        &mut ctx.accounts.source_nullifiers,
        input_nullifiers[1],
        ctx.bumps.source_nullifier_marker_1,
        source_mint,
        source_tree_id,
    )?;

    // Executor PDA is ephemeral — only the bump is needed for signing
    ctx.accounts.executor.bump = ctx.bumps.executor;

    require!(swap_amount > 0, PrivacyError::InvalidPublicAmount);

    let source_is_native = !crate::is_token_mint(&source_mint);

    if source_is_native {
        // For native SOL: fund_native_open_position (preceding instruction in same tx)
        // already debited the vault and credited the executor WSOL ATA with swap_amount.
        // Here we just sync_native to materialise the WSOL token balance.
        require!(ctx.accounts.executor.is_prefunded == 1, PrivacyError::InvalidSwapParams);
        token::sync_native(
            CpiContext::new(ctx.accounts.token_program.to_account_info(), SyncNative {
                account: ctx.accounts.executor_source_token.to_account_info(),
            })
        )?;
    } else {
        // SPL token vault: validate ATA and do token::transfer
        let expected_source_ata = get_associated_token_address(
            &ctx.accounts.source_vault.key(),
            &crate::effective_mint(&source_mint),
        );
        require!(
            ctx.accounts.source_vault_token_account.key() == expected_source_ata,
            PrivacyError::InvalidMintAddress
        );

        let source_vault_token_data = crate::deserialize_token_account(
            &ctx.accounts.source_vault_token_account.to_account_info(),
        )?;
        require!(
            source_vault_token_data.amount >= swap_amount,
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
    }

    ctx.accounts.source_config.total_tvl = ctx.accounts.source_config.total_tvl
        .checked_sub(swap_amount)
        .ok_or(PrivacyError::ArithmeticOverflow)?;

    // Detect dest mint token program (Token vs Token-2022)
    let dest_is_t22 = is_token_2022(&ctx.accounts.dest_mint_info);
    let dest_decimals = get_mint_decimals(&ctx.accounts.dest_mint_info)?;
    let dest_token_program_id = if dest_is_t22 {
        TOKEN_2022_PROGRAM_ID
    } else {
        anchor_spl::token::ID
    };

    // Ensure executor_dest_token ATA exists (idempotent create)
    let expected_executor_dest_ata =
        get_ata_address(&ctx.accounts.executor.key(), &dest_mint, &dest_token_program_id);
    require!(
        ctx.accounts.executor_dest_token.key() == expected_executor_dest_ata,
        PrivacyError::InvalidMintAddress
    );

    let dest_token_program_ai = if dest_is_t22 {
        ctx.accounts.token_2022_program.to_account_info()
    } else {
        ctx.accounts.token_program.to_account_info()
    };

    create_ata_idempotent(
        ctx.accounts.relayer.to_account_info(),
        ctx.accounts.executor.to_account_info(),
        ctx.accounts.dest_mint_info.to_account_info(),
        ctx.accounts.executor_dest_token.to_account_info(),
        dest_token_program_id,
        ctx.accounts.system_program.to_account_info(),
        ctx.accounts.associated_token_program.to_account_info(),
    )?;

    // Execute DEX swap via executor PDA
    let relayer_key = ctx.accounts.relayer.key();
    let executor_seeds: &[&[u8]] = &[
        b"swap_executor",
        source_mint.as_ref(),
        dest_mint.as_ref(),
        input_nullifiers[0].as_ref(),
        relayer_key.as_ref(),
        &[ctx.bumps.executor],
    ];

    execute_dex_swap(
        &ctx.accounts.swap_program,
        &ctx.accounts.jupiter_event_authority,
        ctx.accounts.executor.to_account_info(),
        &ctx.accounts.executor_source_token.to_account_info(),
        &ctx.accounts.executor_dest_token.to_account_info(),
        &ctx.accounts.token_program,
        executor_seeds,
        &swap_data,
        &swap_params,
        swap_amount,
        source_mint,
        dest_mint,
        ctx.remaining_accounts,
    )?;

    // Read amount received
    let received_amount = if dest_is_t22 {
        read_token_2022_amount(&ctx.accounts.executor_dest_token.to_account_info())?
    } else {
        read_token_amount_unchecked(&ctx.accounts.executor_dest_token.to_account_info())?
    };

    require!(
        received_amount >= swap_params.min_amount_out,
        PrivacyError::InvalidPublicAmount
    );

    let relayer_fee = ext_data.fee;
    require!(received_amount > relayer_fee, PrivacyError::InvalidPublicAmount);

    // Fee validation against position pool config
    let pos_cfg = &ctx.accounts.position_config;
    let pct_fee = (received_amount as u128)
        .checked_mul(pos_cfg.swap_fee_bps as u128)
        .and_then(|x| x.checked_div(10_000))
        .ok_or(PrivacyError::ArithmeticOverflow)? as u64;
    let min_fee = std::cmp::max(pos_cfg.min_swap_fee, pct_fee);
    require!(relayer_fee >= min_fee, PrivacyError::InsufficientFee);

    let vault_amount = received_amount.saturating_sub(relayer_fee);
    require!(vault_amount >= swap_params.dest_amount, PrivacyError::InvalidPublicAmount);

    // Lazy-init position vault ATA
    let vault_pda_bump = ctx.bumps.position_vault_pda;
    let expected_vault_ata =
        get_ata_address(&ctx.accounts.position_vault_pda.key(), &dest_mint, &dest_token_program_id);
    require!(
        ctx.accounts.position_vault_ata.key() == expected_vault_ata,
        PrivacyError::InvalidMintAddress
    );

    create_ata_idempotent(
        ctx.accounts.relayer.to_account_info(),
        ctx.accounts.position_vault_pda.to_account_info(),
        ctx.accounts.dest_mint_info.to_account_info(),
        ctx.accounts.position_vault_ata.to_account_info(),
        dest_token_program_id,
        ctx.accounts.system_program.to_account_info(),
        ctx.accounts.associated_token_program.to_account_info(),
    )?;

    // Transfer vault_amount from executor_dest_token → position_vault_ata
    let executor_ai = ctx.accounts.executor.to_account_info();
    if dest_is_t22 {
        token_2022_transfer_checked(
            &ctx.accounts.executor_dest_token.to_account_info(),
            &ctx.accounts.dest_mint_info.to_account_info(),
            &ctx.accounts.position_vault_ata.to_account_info(),
            &executor_ai,
            executor_seeds,
            vault_amount,
            dest_decimals,
            &ctx.accounts.token_2022_program.to_account_info(),
        )?;
    } else {
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.executor_dest_token.to_account_info(),
                    to: ctx.accounts.position_vault_ata.to_account_info(),
                    authority: executor_ai.clone(),
                },
                &[executor_seeds],
            ),
            vault_amount,
        )?;
    }

    // Pay relayer fee from executor_dest_token
    if relayer_fee > 0 {
        let expected_relayer_ata =
            get_ata_address(&ctx.accounts.relayer.key(), &dest_mint, &dest_token_program_id);
        require!(
            ctx.accounts.relayer_dest_token.key() == expected_relayer_ata,
            PrivacyError::InvalidMintAddress
        );

        if dest_is_t22 {
            token_2022_transfer_checked(
                &ctx.accounts.executor_dest_token.to_account_info(),
                &ctx.accounts.dest_mint_info.to_account_info(),
                &ctx.accounts.relayer_dest_token.to_account_info(),
                &executor_ai,
                executor_seeds,
                relayer_fee,
                dest_decimals,
                &ctx.accounts.token_2022_program.to_account_info(),
            )?;
        } else {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from: ctx.accounts.executor_dest_token.to_account_info(),
                        to: ctx.accounts.relayer_dest_token.to_account_info(),
                        authority: executor_ai.clone(),
                    },
                    &[executor_seeds],
                ),
                relayer_fee,
            )?;
        }
    }

    // Init position_vault_record (lazy)
    let vault_record = &mut ctx.accounts.position_vault_record;
    if vault_record.mint == Pubkey::default() {
        vault_record.bump = ctx.bumps.position_vault_record;
        vault_record.vault_bump = vault_pda_bump;
        vault_record.mint = dest_mint;
        vault_record.is_token_2022 = dest_is_t22;
    }
    vault_record.total_balance = vault_record.total_balance
        .checked_add(vault_amount)
        .ok_or(PrivacyError::ArithmeticOverflow)?;
    vault_record.position_count = vault_record.position_count
        .checked_add(1)
        .ok_or(PrivacyError::ArithmeticOverflow)?;

    // Insert position note (output_commitment_1) into position tree
    let mut pos_tree = ctx.accounts.position_tree.load_mut()?;
    let pos_leaf_idx = pos_tree.next_index;
    MerkleTree::append::<PoseidonHasher>(output_commitments[1], &mut *pos_tree)?;
    let pos_new_root = pos_tree.root;
    drop(pos_tree);

    emit!(CommitmentEvent {
        commitment: output_commitments[1],
        leaf_index: pos_leaf_idx,
        new_root: pos_new_root,
        timestamp: clock.unix_timestamp,
        mint_address: dest_mint,
        tree_id: position_tree_id,
        ephemeral_public_key: note1_epk,
        encrypted_blob: note1_enc,
        view_tag: note1_vt,
    });

    // Insert USDC change note (output_commitment_0) into source tree
    let mut src_tree = ctx.accounts.source_tree.load_mut()?;
    let src_leaf_idx = src_tree.next_index;
    MerkleTree::append::<PoseidonHasher>(output_commitments[0], &mut *src_tree)?;
    let src_new_root = src_tree.root;
    drop(src_tree);

    emit!(CommitmentEvent {
        commitment: output_commitments[0],
        leaf_index: src_leaf_idx,
        new_root: src_new_root,
        timestamp: clock.unix_timestamp,
        mint_address: source_mint,
        tree_id: source_tree_id,
        ephemeral_public_key: note0_epk,
        encrypted_blob: note0_enc,
        view_tag: note0_vt,
    });

    // Init PositionPDA
    let pos_pda = &mut ctx.accounts.position_pda;
    pos_pda.bump = ctx.bumps.position_pda;
    pos_pda.mint = dest_mint;
    pos_pda.balance = swap_params.dest_amount;
    pos_pda.leaf_index = pos_leaf_idx;
    pos_pda.tree_id = position_tree_id;
    pos_pda.is_active = true;

    // Cleanup: verify executor_source_token is empty, then close accounts + reclaim rent
    let source_token_data =
        crate::deserialize_token_account(&ctx.accounts.executor_source_token.to_account_info())?;
    require!(source_token_data.amount == 0, PrivacyError::SwapLeftoverTokens);

    token::close_account(CpiContext::new_with_signer(
        ctx.accounts.token_program.to_account_info(),
        CloseAccount {
            account: ctx.accounts.executor_source_token.to_account_info(),
            destination: ctx.accounts.relayer.to_account_info(),
            authority: executor_ai.clone(),
        },
        &[executor_seeds],
    ))?;

    // Close executor_dest_token
    if dest_is_t22 {
        close_token_2022_account(
            &ctx.accounts.executor_dest_token.to_account_info(),
            &ctx.accounts.relayer.to_account_info(),
            &executor_ai,
            executor_seeds,
            &ctx.accounts.token_2022_program.to_account_info(),
        )?;
    } else {
        token::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            CloseAccount {
                account: ctx.accounts.executor_dest_token.to_account_info(),
                destination: ctx.accounts.relayer.to_account_info(),
                authority: executor_ai.clone(),
            },
            &[executor_seeds],
        ))?;
    }

    // Return executor rent to relayer
    let executor_lamports = executor_ai.lamports();
    **executor_ai.try_borrow_mut_lamports()? = 0;
    **ctx.accounts.relayer.to_account_info().try_borrow_mut_lamports()? = ctx.accounts.relayer
        .to_account_info()
        .lamports()
        .checked_add(executor_lamports)
        .ok_or(PrivacyError::ArithmeticOverflow)?;

    Ok(())
}

// ============================================================================
// close_position
// ============================================================================
//
// Flow:
// 1. Validate + ZK proof verify (swap circuit in reverse: stock → USDC)
// 2. Mark position nullifiers spent
// 3. Transfer stock from position vault → executor
// 4. Execute Jupiter/Raydium swap: stock → USDC
// 5. Transfer USDC from executor → USDC pool vault (fee deducted)
// 6. Insert USDC notes into USDC tree
// 7. Insert position change note (usually 0-amount) into position tree
// 8. Close PositionPDA, update PositionVaultRecord
// 9. Cleanup executor

#[inline(never)]
pub fn close_position<'info>(
    ctx: Context<'_, '_, 'info, 'info, ClosePosition<'info>>,
    position_tree_id: u16,
    source_mint: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    usdc_tree_id: u16,
    dest_mint: Pubkey,
    position_pda_key: [u8; 32],
    proof: SwapProof,
    position_root: [u8; 32],
    output_commitment_0: [u8; 32], // position change note → position tree
    output_commitment_1: [u8; 32], // USDC output note → USDC tree
    swap_params: SwapParams,
    swap_amount: u64,
    swap_data: Vec<u8>,
    ext_data: ExtData,
    note_ciphers: Option<NoteCiphers>,
) -> Result<()> {
    let (note0_epk, note0_enc, note0_vt, note1_epk, note1_enc, note1_vt) = match note_ciphers {
        Some(c) => (
            c.note0_ephemeral_key,
            c.note0_encrypted,
            c.note0_view_tag,
            c.note1_ephemeral_key,
            c.note1_encrypted,
            c.note1_view_tag,
        ),
        None => ([0u8; 32], [0u8; 80], 0u8, [0u8; 32], [0u8; 80], 0u8),
    };

    // Validate swap program
    require!(
        ctx.accounts.swap_program.key() == crate::RAYDIUM_CPMM_PROGRAM_ID
            || ctx.accounts.swap_program.key() == crate::RAYDIUM_AMM_PROGRAM_ID
            || ctx.accounts.swap_program.key() == crate::JUPITER_PROGRAM_ID,
        PrivacyError::InvalidSwapProgram
    );

    // Validate pool config
    require!(
        ctx.accounts.usdc_config.mint_address == dest_mint,
        PrivacyError::InvalidMintAddress
    );
    require!(source_mint != dest_mint, PrivacyError::InvalidMintAddress);

    // Validate PositionPDA consistency
    let pos_pda = &ctx.accounts.position_pda;
    require!(pos_pda.is_active, PrivacyError::Unauthorized);
    require!(pos_pda.mint == source_mint, PrivacyError::InvalidMintAddress);
    require!(pos_pda.tree_id == position_tree_id, PrivacyError::InvalidTreeId);

    // Tree ID bounds
    require!(
        position_tree_id < ctx.accounts.position_config.num_trees,
        PrivacyError::InvalidTreeId
    );
    require!(
        usdc_tree_id < ctx.accounts.usdc_config.num_trees,
        PrivacyError::InvalidTreeId
    );

    // Relayer whitelisting
    require!(
        ctx.accounts.position_config.is_relayer(&ctx.accounts.relayer.key()),
        PrivacyError::RelayerNotAllowed
    );
    require!(
        ctx.accounts.usdc_config.is_relayer(&ctx.accounts.relayer.key()),
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

    let proof = Box::new(proof);
    let swap_params = Box::new(swap_params);
    let ext_data = Box::new(ext_data);

    // source = position token, dest = USDC
    let swap_params_hash = swap_params.hash(&source_mint, &dest_mint)?;
    let ext_data_hash_val = ext_data.hash()?;

    let public_inputs = Box::new(SwapPublicInputs {
        source_root: position_root,
        swap_params_hash,
        ext_data_hash: ext_data_hash_val,
        source_mint,
        dest_mint,
        input_nullifiers,
        output_commitments,
        swap_amount,
    });

    verify_swap_transaction_groth16(&proof, &public_inputs)?;

    // Verify position tree root is in history
    let pos_tree = ctx.accounts.position_tree.load()?;
    require!(
        MerkleTree::is_known_root(&*pos_tree, position_root),
        PrivacyError::UnknownRoot
    );
    let pos_cap = 1u64 << (pos_tree.height as u64);
    require!(
        pos_cap.saturating_sub(pos_tree.next_index) >= 1,
        PrivacyError::MerkleTreeFull
    );
    drop(pos_tree);

    // Verify USDC tree has capacity
    let usdc_tree = ctx.accounts.usdc_tree.load()?;
    let usdc_cap = 1u64 << (usdc_tree.height as u64);
    require!(
        usdc_cap.saturating_sub(usdc_tree.next_index) >= 1,
        PrivacyError::MerkleTreeFull
    );
    drop(usdc_tree);

    // Mark position nullifiers spent
    require!(
        !ctx.accounts.position_nullifier_marker_0.is_spent,
        PrivacyError::NullifierAlreadyUsed
    );
    require!(
        !ctx.accounts.position_nullifier_marker_1.is_spent,
        PrivacyError::NullifierAlreadyUsed
    );

    emit_position_nullifier_spent(
        &mut ctx.accounts.position_nullifier_marker_0,
        input_nullifiers[0],
        ctx.bumps.position_nullifier_marker_0,
        source_mint,
        position_tree_id,
    )?;
    emit_position_nullifier_spent(
        &mut ctx.accounts.position_nullifier_marker_1,
        input_nullifiers[1],
        ctx.bumps.position_nullifier_marker_1,
        source_mint,
        position_tree_id,
    )?;

    // Detect source mint token program
    let src_is_t22 = is_token_2022(&ctx.accounts.source_mint_info);
    let src_decimals = get_mint_decimals(&ctx.accounts.source_mint_info)?;
    let src_token_program_id = if src_is_t22 {
        TOKEN_2022_PROGRAM_ID
    } else {
        anchor_spl::token::ID
    };

    // Executor PDA is ephemeral — only the bump is needed for signing
    ctx.accounts.executor.bump = ctx.bumps.executor;

    require!(swap_amount > 0, PrivacyError::InvalidPublicAmount);

    // Create executor_source_token ATA (for stock) idempotently
    let expected_exec_src_ata =
        get_ata_address(&ctx.accounts.executor.key(), &source_mint, &src_token_program_id);
    require!(
        ctx.accounts.executor_source_token.key() == expected_exec_src_ata,
        PrivacyError::InvalidMintAddress
    );

    let src_token_prog_ai = if src_is_t22 {
        ctx.accounts.token_2022_program.to_account_info()
    } else {
        ctx.accounts.token_program.to_account_info()
    };

    create_ata_idempotent(
        ctx.accounts.relayer.to_account_info(),
        ctx.accounts.executor.to_account_info(),
        ctx.accounts.source_mint_info.to_account_info(),
        ctx.accounts.executor_source_token.to_account_info(),
        src_token_program_id,
        ctx.accounts.system_program.to_account_info(),
        ctx.accounts.associated_token_program.to_account_info(),
    )?;

    // Validate position_vault_ata
    let vault_pda_bump = ctx.bumps.position_vault_pda;
    let expected_vault_ata = get_ata_address(
        &ctx.accounts.position_vault_pda.key(),
        &source_mint,
        &src_token_program_id,
    );
    require!(
        ctx.accounts.position_vault_ata.key() == expected_vault_ata,
        PrivacyError::InvalidMintAddress
    );

    // Check vault has sufficient balance
    let vault_balance = read_token_amount_unchecked(&ctx.accounts.position_vault_ata.to_account_info())?;
    require!(
        vault_balance >= swap_amount,
        PrivacyError::InsufficientFundsForWithdrawal
    );

    // Transfer swap_amount from position_vault_ata → executor_source_token
    let vault_pda_seeds: &[&[u8]] = &[
        b"position_vault_token_v1",
        source_mint.as_ref(),
        &[vault_pda_bump],
    ];

    if src_is_t22 {
        token_2022_transfer_checked(
            &ctx.accounts.position_vault_ata.to_account_info(),
            &ctx.accounts.source_mint_info.to_account_info(),
            &ctx.accounts.executor_source_token.to_account_info(),
            &ctx.accounts.position_vault_pda.to_account_info(),
            vault_pda_seeds,
            swap_amount,
            src_decimals,
            &ctx.accounts.token_2022_program.to_account_info(),
        )?;
    } else {
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.position_vault_ata.to_account_info(),
                    to: ctx.accounts.executor_source_token.to_account_info(),
                    authority: ctx.accounts.position_vault_pda.to_account_info(),
                },
                &[vault_pda_seeds],
            ),
            swap_amount,
        )?;
    }

    // Execute DEX swap: stock → USDC
    let relayer_key = ctx.accounts.relayer.key();
    let executor_seeds: &[&[u8]] = &[
        b"swap_executor",
        source_mint.as_ref(),
        dest_mint.as_ref(),
        input_nullifiers[0].as_ref(),
        relayer_key.as_ref(),
        &[ctx.bumps.executor],
    ];

    execute_dex_swap(
        &ctx.accounts.swap_program,
        &ctx.accounts.jupiter_event_authority,
        ctx.accounts.executor.to_account_info(),
        &ctx.accounts.executor_source_token.to_account_info(),
        &ctx.accounts.executor_dest_token.to_account_info(),
        &ctx.accounts.token_program,
        executor_seeds,
        &swap_data,
        &swap_params,
        swap_amount,
        source_mint,
        dest_mint,
        ctx.remaining_accounts,
    )?;

    ctx.accounts.executor_dest_token.reload()?;
    let usdc_received = ctx.accounts.executor_dest_token.amount;

    require!(
        usdc_received >= swap_params.min_amount_out,
        PrivacyError::InvalidPublicAmount
    );

    let relayer_fee = ext_data.fee;
    require!(usdc_received > relayer_fee, PrivacyError::InvalidPublicAmount);

    // Fee validation against USDC pool config
    let usdc_cfg = &ctx.accounts.usdc_config;
    let pct_fee = (usdc_received as u128)
        .checked_mul(usdc_cfg.swap_fee_bps as u128)
        .and_then(|x| x.checked_div(10_000))
        .ok_or(PrivacyError::ArithmeticOverflow)? as u64;
    let min_fee = std::cmp::max(usdc_cfg.min_swap_fee, pct_fee);
    require!(relayer_fee >= min_fee, PrivacyError::InsufficientFee);

    let vault_usdc = usdc_received.saturating_sub(relayer_fee);
    require!(vault_usdc >= swap_params.dest_amount, PrivacyError::InvalidPublicAmount);

    // Validate USDC vault ATA
    let expected_usdc_vault_ata =
        get_associated_token_address(&ctx.accounts.usdc_vault.key(), &crate::effective_mint(&dest_mint));
    require!(
        ctx.accounts.usdc_vault_token_account.key() == expected_usdc_vault_ata,
        PrivacyError::InvalidMintAddress
    );

    let executor_ai = ctx.accounts.executor.to_account_info();

    // Transfer USDC from executor_dest_token → usdc_vault_token_account
    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.executor_dest_token.to_account_info(),
                to: ctx.accounts.usdc_vault_token_account.to_account_info(),
                authority: executor_ai.clone(),
            },
            &[executor_seeds],
        ),
        vault_usdc,
    )?;

    // Pay relayer fee
    if relayer_fee > 0 {
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.executor_dest_token.to_account_info(),
                    to: ctx.accounts.relayer_usdc_token.to_account_info(),
                    authority: executor_ai.clone(),
                },
                &[executor_seeds],
            ),
            relayer_fee,
        )?;
    }

    ctx.accounts.usdc_config.total_tvl = ctx.accounts.usdc_config.total_tvl
        .checked_add(vault_usdc)
        .ok_or(PrivacyError::ArithmeticOverflow)?;

    // Insert USDC output note (output_commitment_1) into USDC tree
    let mut usdc_tree = ctx.accounts.usdc_tree.load_mut()?;
    let usdc_leaf_idx = usdc_tree.next_index;
    MerkleTree::append::<PoseidonHasher>(output_commitments[1], &mut *usdc_tree)?;
    let usdc_new_root = usdc_tree.root;
    drop(usdc_tree);

    emit!(CommitmentEvent {
        commitment: output_commitments[1],
        leaf_index: usdc_leaf_idx,
        new_root: usdc_new_root,
        timestamp: clock.unix_timestamp,
        mint_address: dest_mint,
        tree_id: usdc_tree_id,
        ephemeral_public_key: note1_epk,
        encrypted_blob: note1_enc,
        view_tag: note1_vt,
    });

    // Insert position change note (output_commitment_0) into position tree
    let mut pos_tree = ctx.accounts.position_tree.load_mut()?;
    let pos_leaf_idx = pos_tree.next_index;
    MerkleTree::append::<PoseidonHasher>(output_commitments[0], &mut *pos_tree)?;
    let pos_new_root = pos_tree.root;
    drop(pos_tree);

    emit!(CommitmentEvent {
        commitment: output_commitments[0],
        leaf_index: pos_leaf_idx,
        new_root: pos_new_root,
        timestamp: clock.unix_timestamp,
        mint_address: source_mint,
        tree_id: position_tree_id,
        ephemeral_public_key: note0_epk,
        encrypted_blob: note0_enc,
        view_tag: note0_vt,
    });

    // Update PositionVaultRecord
    let vault_record = &mut ctx.accounts.position_vault_record;
    vault_record.total_balance = vault_record.total_balance.saturating_sub(swap_amount);
    vault_record.position_count = vault_record.position_count.saturating_sub(1);

    // PositionPDA is auto-closed by Anchor `close = relayer` constraint

    // Cleanup executor
    let source_exec_balance = read_token_amount_unchecked(
        &ctx.accounts.executor_source_token.to_account_info(),
    )?;
    require!(source_exec_balance == 0, PrivacyError::SwapLeftoverTokens);

    // Close executor_source_token (stock ATA)
    if src_is_t22 {
        close_token_2022_account(
            &ctx.accounts.executor_source_token.to_account_info(),
            &ctx.accounts.relayer.to_account_info(),
            &executor_ai,
            executor_seeds,
            &ctx.accounts.token_2022_program.to_account_info(),
        )?;
    } else {
        token::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            CloseAccount {
                account: ctx.accounts.executor_source_token.to_account_info(),
                destination: ctx.accounts.relayer.to_account_info(),
                authority: executor_ai.clone(),
            },
            &[executor_seeds],
        ))?;
    }

    // Close executor_dest_token (USDC ATA — always legacy SPL)
    token::close_account(CpiContext::new_with_signer(
        ctx.accounts.token_program.to_account_info(),
        CloseAccount {
            account: ctx.accounts.executor_dest_token.to_account_info(),
            destination: ctx.accounts.relayer.to_account_info(),
            authority: executor_ai.clone(),
        },
        &[executor_seeds],
    ))?;

    // Return executor rent to relayer
    let executor_lamports = executor_ai.lamports();
    **executor_ai.try_borrow_mut_lamports()? = 0;
    **ctx.accounts.relayer.to_account_info().try_borrow_mut_lamports()? = ctx.accounts.relayer
        .to_account_info()
        .lamports()
        .checked_add(executor_lamports)
        .ok_or(PrivacyError::ArithmeticOverflow)?;

    Ok(())
}

// ============================================================================
// DEX execution helper (mirrors swap.rs logic)
// ============================================================================

#[inline(never)]
fn execute_dex_swap<'info>(
    swap_program: &UncheckedAccount<'info>,
    jupiter_event_authority: &UncheckedAccount<'info>,
    executor: AccountInfo<'info>,
    executor_source_token: &AccountInfo<'info>,
    executor_dest_token: &AccountInfo<'info>,
    token_program: &Program<'info, anchor_spl::token::Token>,
    executor_seeds: &[&[u8]],
    swap_data: &[u8],
    swap_params: &SwapParams,
    swap_amount: u64,
    source_mint: Pubkey,
    dest_mint: Pubkey,
    remaining: &[AccountInfo<'info>],
) -> Result<()> {
    let is_cpmm = swap_data.len() >= 8
        && swap_data[0] == 0x8f
        && swap_data[1] == 0xbe
        && swap_data[2] == 0x5a
        && swap_data[3] == 0xda;

    let is_amm = !is_cpmm && swap_data.len() >= 1 && swap_data[0] == 9;

    let is_jupiter = !is_cpmm
        && !is_amm
        && swap_data.len() >= 8
        && (swap_data[0..8] == [0xe5, 0x17, 0xcb, 0x97, 0x7a, 0xe3, 0xad, 0x2a]
            || swap_data[0..8] == [0xc1, 0x20, 0x9b, 0x33, 0x41, 0xd6, 0x9c, 0x81]
            || swap_data[0..8] == [0xd0, 0x33, 0xef, 0x97, 0x7b, 0x2b, 0xed, 0x5c]
            || swap_data[0..8] == [0xb0, 0xd1, 0x69, 0xa8, 0x9a, 0x7d, 0x45, 0x3e]);

    if is_cpmm {
        require!(swap_data.len() >= 24, PrivacyError::InvalidPublicAmount);
        let dex_amount_in = u64::from_le_bytes(
            swap_data[8..16]
                .try_into()
                .map_err(|_| error!(PrivacyError::InvalidPublicAmount))?,
        );
        require!(dex_amount_in == swap_amount, PrivacyError::InvalidSwapParams);
        let dex_min_out = u64::from_le_bytes(
            swap_data[16..24]
                .try_into()
                .map_err(|_| error!(PrivacyError::InvalidPublicAmount))?,
        );
        require!(
            dex_min_out >= swap_params.min_amount_out,
            PrivacyError::InvalidPublicAmount
        );
        require!(remaining.len() >= 8, PrivacyError::InvalidRemainingAccounts);

        require!(
            remaining[5].key() == source_mint || remaining[6].key() == source_mint,
            PrivacyError::InvalidMintAddress
        );
        require!(
            remaining[5].key() == dest_mint || remaining[6].key() == dest_mint,
            PrivacyError::InvalidMintAddress
        );

        let cpmm_accounts = vec![
            AccountMeta::new_readonly(executor.key(), true),
            AccountMeta::new_readonly(remaining[0].key(), false),
            AccountMeta::new_readonly(remaining[1].key(), false),
            AccountMeta::new(remaining[2].key(), false),
            AccountMeta::new(executor_source_token.key(), false),
            AccountMeta::new(executor_dest_token.key(), false),
            AccountMeta::new(remaining[3].key(), false),
            AccountMeta::new(remaining[4].key(), false),
            AccountMeta::new_readonly(token_program.key(), false),
            AccountMeta::new_readonly(token_program.key(), false),
            AccountMeta::new_readonly(remaining[5].key(), false),
            AccountMeta::new_readonly(remaining[6].key(), false),
            AccountMeta::new(remaining[7].key(), false),
        ];

        let swap_ix = Instruction {
            program_id: swap_program.key(),
            accounts: cpmm_accounts,
            data: swap_data.to_vec(),
        };

        let account_infos = vec![
            executor.clone(),
            remaining[0].clone(),
            remaining[1].clone(),
            remaining[2].clone(),
            executor_source_token.clone(),
            executor_dest_token.clone(),
            remaining[3].clone(),
            remaining[4].clone(),
            token_program.to_account_info(),
            remaining[5].clone(),
            remaining[6].clone(),
            remaining[7].clone(),
            swap_program.to_account_info(),
        ];

        invoke_signed(&swap_ix, &account_infos, &[executor_seeds])?;
    } else if is_amm {
        require!(remaining.len() >= 14, PrivacyError::InvalidRemainingAccounts);
        require!(swap_data.len() >= 17, PrivacyError::InvalidPublicAmount);
        let dex_amount_in = u64::from_le_bytes(
            swap_data[1..9]
                .try_into()
                .map_err(|_| error!(PrivacyError::InvalidPublicAmount))?,
        );
        require!(dex_amount_in == swap_amount, PrivacyError::InvalidSwapParams);
        let dex_min_out = u64::from_le_bytes(
            swap_data[9..17]
                .try_into()
                .map_err(|_| error!(PrivacyError::InvalidPublicAmount))?,
        );
        require!(
            dex_min_out >= swap_params.min_amount_out,
            PrivacyError::InvalidPublicAmount
        );
        require!(
            remaining[6].key() == crate::OPENBOOK_PROGRAM_ID,
            PrivacyError::InvalidRemainingAccounts
        );

        let amm_accounts = vec![
            AccountMeta::new_readonly(token_program.key(), false),
            AccountMeta::new(remaining[0].key(), false),
            AccountMeta::new_readonly(remaining[1].key(), false),
            AccountMeta::new(remaining[2].key(), false),
            AccountMeta::new(remaining[3].key(), false),
            AccountMeta::new(remaining[4].key(), false),
            AccountMeta::new(remaining[5].key(), false),
            AccountMeta::new_readonly(remaining[6].key(), false),
            AccountMeta::new(remaining[7].key(), false),
            AccountMeta::new(remaining[8].key(), false),
            AccountMeta::new(remaining[9].key(), false),
            AccountMeta::new(remaining[10].key(), false),
            AccountMeta::new(remaining[11].key(), false),
            AccountMeta::new(remaining[12].key(), false),
            AccountMeta::new_readonly(remaining[13].key(), false),
            AccountMeta::new(executor_source_token.key(), false),
            AccountMeta::new(executor_dest_token.key(), false),
            AccountMeta::new_readonly(executor.key(), true),
        ];

        let swap_ix = Instruction {
            program_id: swap_program.key(),
            accounts: amm_accounts,
            data: swap_data.to_vec(),
        };

        let mut account_infos = vec![
            token_program.to_account_info(),
            executor_source_token.clone(),
            executor_dest_token.clone(),
            executor.clone(),
            swap_program.to_account_info(),
        ];
        for acc in remaining.iter().take(14) {
            account_infos.push(acc.clone());
        }

        invoke_signed(&swap_ix, &account_infos, &[executor_seeds])?;
    } else if is_jupiter {
        require!(
            jupiter_event_authority.key() == crate::JUPITER_EVENT_AUTHORITY,
            PrivacyError::Unauthorized
        );

        let mut jupiter_accounts = Vec::new();
        let mut account_infos = Vec::new();

        let is_shared = swap_data[0..8] == [0xc1, 0x20, 0x9b, 0x33, 0x41, 0xd6, 0x9c, 0x81]
            || swap_data[0..8] == [0xb0, 0xd1, 0x69, 0xa8, 0x9a, 0x7d, 0x45, 0x3e];

        if is_shared {
            require!(remaining.len() >= 9, PrivacyError::JupiterInsufficientAccounts);
            require!(remaining[7].key() == crate::effective_mint(&source_mint), PrivacyError::InvalidMintAddress);
            require!(remaining[8].key() == crate::effective_mint(&dest_mint), PrivacyError::InvalidMintAddress);

            for (i, acc) in remaining.iter().enumerate() {
                match i {
                    2 => {
                        jupiter_accounts.push(AccountMeta::new_readonly(executor.key(), true));
                        account_infos.push(executor.clone());
                    }
                    3 => {
                        jupiter_accounts.push(AccountMeta::new(executor_source_token.key(), false));
                        account_infos.push(executor_source_token.clone());
                    }
                    6 => {
                        jupiter_accounts.push(AccountMeta::new(executor_dest_token.key(), false));
                        account_infos.push(executor_dest_token.clone());
                    }
                    _ => {
                        jupiter_accounts.push(if acc.is_writable {
                            AccountMeta::new(acc.key(), false)
                        } else {
                            AccountMeta::new_readonly(acc.key(), false)
                        });
                        account_infos.push(acc.clone());
                    }
                }
            }
        } else {
            require!(remaining.len() >= 4, PrivacyError::JupiterInsufficientAccounts);

            for (i, acc) in remaining.iter().enumerate() {
                match i {
                    1 => {
                        jupiter_accounts.push(AccountMeta::new_readonly(executor.key(), true));
                        account_infos.push(executor.clone());
                    }
                    2 => {
                        jupiter_accounts.push(AccountMeta::new(executor_source_token.key(), false));
                        account_infos.push(executor_source_token.clone());
                    }
                    3 => {
                        jupiter_accounts.push(AccountMeta::new(executor_dest_token.key(), false));
                        account_infos.push(executor_dest_token.clone());
                    }
                    _ => {
                        jupiter_accounts.push(if acc.is_writable {
                            AccountMeta::new(acc.key(), false)
                        } else {
                            AccountMeta::new_readonly(acc.key(), false)
                        });
                        account_infos.push(acc.clone());
                    }
                }
            }
        }

        // Bind swap_data to the hash in the proof
        let computed: [u8; 32] = solana_sha256_hasher::hash(swap_data).to_bytes();
        require!(computed == swap_params.swap_data_hash, PrivacyError::InvalidSwapParams);

        let swap_ix = Instruction {
            program_id: swap_program.key(),
            accounts: jupiter_accounts,
            data: swap_data.to_vec(),
        };

        invoke_signed(&swap_ix, &account_infos, &[executor_seeds])?;
    } else {
        return err!(PrivacyError::InvalidPublicAmount);
    }

    Ok(())
}

// ============================================================================
// Token-2022 helpers (raw CPI — avoid anchor_spl::token_2022 dependency)
// ============================================================================

/// transfer_checked CPI to Token-2022 program.
fn token_2022_transfer_checked<'info>(
    from: &AccountInfo<'info>,
    mint: &AccountInfo<'info>,
    to: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    signer_seeds: &[&[u8]],
    amount: u64,
    decimals: u8,
    token_2022_program: &AccountInfo<'info>,
) -> Result<()> {
    // Token-2022 transfer_checked discriminator is 0x0C (12)
    let mut data = vec![12u8]; // transfer_checked
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);

    let ix = Instruction {
        program_id: TOKEN_2022_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(from.key(), false),
            AccountMeta::new_readonly(mint.key(), false),
            AccountMeta::new(to.key(), false),
            AccountMeta::new_readonly(authority.key(), true),
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[from.clone(), mint.clone(), to.clone(), authority.clone(), token_2022_program.clone()],
        &[signer_seeds],
    )?;

    Ok(())
}

/// close_account CPI to Token-2022 program.
fn close_token_2022_account<'info>(
    account: &AccountInfo<'info>,
    destination: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    signer_seeds: &[&[u8]],
    token_2022_program: &AccountInfo<'info>,
) -> Result<()> {
    // Token-2022 close_account discriminator is 0x09 (9)
    let ix = Instruction {
        program_id: TOKEN_2022_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(account.key(), false),
            AccountMeta::new(destination.key(), false),
            AccountMeta::new_readonly(authority.key(), true),
        ],
        data: vec![9u8],
    };

    invoke_signed(
        &ix,
        &[
            account.clone(),
            destination.clone(),
            authority.clone(),
            token_2022_program.clone(),
        ],
        &[signer_seeds],
    )?;

    Ok(())
}

/// Read token amount from a raw account info (works for Token and Token-2022).
/// TokenAccount amount is stored at bytes 64..72.
fn read_token_amount_unchecked(account: &AccountInfo) -> Result<u64> {
    let data = account.try_borrow_data()?;
    require!(data.len() >= 72, PrivacyError::MissingTokenAccount);
    Ok(u64::from_le_bytes(data[64..72].try_into().map_err(|_| error!(PrivacyError::MissingTokenAccount))?))
}

/// Read Token-2022 token amount (same layout as SPL TokenAccount at bytes 64..72).
fn read_token_2022_amount(account: &AccountInfo) -> Result<u64> {
    read_token_amount_unchecked(account)
}

// ============================================================================
// merge_positions
// ============================================================================

/// Merge two position notes of the same mint into one using the existing
/// transaction circuit (publicAmount=0). No vault token movement occurs.
///
/// Circuit equation: inAmount[0] + inAmount[1] = 0 + outAmount[0] + outAmount[1]
/// Where outAmount[0] = inAmount[0] + inAmount[1] (merged note) and outAmount[1] = 0.
pub fn merge_positions<'info>(
    ctx: Context<'_, '_, 'info, 'info, MergePositions<'info>>,
    input_tree_id: u16,
    mint: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    output_tree_id: u16,
    _position_pda_key_0: [u8; 32],
    _position_pda_key_1: [u8; 32],
    _new_position_pda_key: [u8; 32],
    proof: TransactionProof,
    position_root: [u8; 32],
    output_commitment_0: [u8; 32],
    output_commitment_1: [u8; 32],
    ext_data: ExtData,
    merged_amount: u64,
) -> Result<()> {
    // Validate both PDAs are active and same mint
    require!(ctx.accounts.position_pda_0.is_active, PrivacyError::Unauthorized);
    require!(ctx.accounts.position_pda_1.is_active, PrivacyError::Unauthorized);
    require!(ctx.accounts.position_pda_0.mint == mint, PrivacyError::InvalidMintAddress);
    require!(ctx.accounts.position_pda_1.mint == mint, PrivacyError::InvalidMintAddress);
    require!(ctx.accounts.position_pda_0.tree_id == input_tree_id, PrivacyError::InvalidTreeId);
    require!(ctx.accounts.position_pda_1.tree_id == input_tree_id, PrivacyError::InvalidTreeId);

    // Tree ID bounds
    require!(
        input_tree_id < ctx.accounts.position_config.num_trees,
        PrivacyError::InvalidTreeId
    );
    require!(
        output_tree_id < ctx.accounts.position_config.num_trees,
        PrivacyError::InvalidTreeId
    );

    // Relayer whitelisting
    require!(
        ctx.accounts.position_config.is_relayer(&ctx.accounts.relayer.key()),
        PrivacyError::RelayerNotAllowed
    );

    // Nullifier sanity checks
    let input_nullifiers = [input_nullifier_0, input_nullifier_1];
    let output_commitments = [output_commitment_0, output_commitment_1];
    let zero = [0u8; 32];
    require!(
        input_nullifiers[0] != input_nullifiers[1],
        PrivacyError::DuplicateNullifiers
    );
    require!(
        input_nullifiers[0] != zero && input_nullifiers[1] != zero,
        PrivacyError::ZeroNullifier
    );
    require!(output_commitments[0] != zero, PrivacyError::ZeroCommitment);

    // Verify position tree root is in history
    let in_tree = ctx.accounts.input_tree.load()?;
    require!(
        MerkleTree::is_known_root(&*in_tree, position_root),
        PrivacyError::UnknownRoot
    );
    drop(in_tree);

    // Verify output tree has capacity for 2 new leaves
    let out_tree = ctx.accounts.output_tree.load()?;
    let out_cap = 1u64 << (out_tree.height as u64);
    require!(
        out_cap.saturating_sub(out_tree.next_index) >= 2,
        PrivacyError::MerkleTreeFull
    );
    drop(out_tree);

    // Double-spend protection (Anchor init constraint already enforces uniqueness,
    // but check is_spent for belt-and-suspenders)
    require!(
        !ctx.accounts.position_nullifier_marker_0.is_spent,
        PrivacyError::NullifierAlreadyUsed
    );
    require!(
        !ctx.accounts.position_nullifier_marker_1.is_spent,
        PrivacyError::NullifierAlreadyUsed
    );

    // Verify ZK proof: transaction circuit with publicAmount=0
    let ext_data_hash_val = ext_data.hash()?;
    let public_inputs = TransactionPublicInputs {
        root: position_root,
        public_amount: 0i64,
        ext_data_hash: ext_data_hash_val,
        mint_address: mint,
        input_nullifiers,
        output_commitments,
    };
    verify_transaction_groth16(proof, &public_inputs)?;

    // Mark both input nullifiers as spent
    emit_position_nullifier_spent(
        &mut ctx.accounts.position_nullifier_marker_0,
        input_nullifiers[0],
        ctx.bumps.position_nullifier_marker_0,
        mint,
        input_tree_id,
    )?;
    emit_position_nullifier_spent(
        &mut ctx.accounts.position_nullifier_marker_1,
        input_nullifiers[1],
        ctx.bumps.position_nullifier_marker_1,
        mint,
        input_tree_id,
    )?;

    let clock = Clock::get()?;

    // Insert both output commitments into the output position tree
    let mut out_tree = ctx.accounts.output_tree.load_mut()?;
    let merged_leaf_idx = out_tree.next_index;
    MerkleTree::append::<PoseidonHasher>(output_commitments[0], &mut *out_tree)?;
    let root_after_0 = out_tree.root;
    MerkleTree::append::<PoseidonHasher>(output_commitments[1], &mut *out_tree)?;
    let root_after_1 = out_tree.root;
    drop(out_tree);

    emit!(CommitmentEvent {
        commitment: output_commitments[0],
        leaf_index: merged_leaf_idx,
        new_root: root_after_0,
        timestamp: clock.unix_timestamp,
        mint_address: mint,
        tree_id: output_tree_id,
        ephemeral_public_key: [0u8; 32],
        encrypted_blob: [0u8; 80],
        view_tag: 0,
    });
    emit!(CommitmentEvent {
        commitment: output_commitments[1],
        leaf_index: merged_leaf_idx + 1,
        new_root: root_after_1,
        timestamp: clock.unix_timestamp,
        mint_address: mint,
        tree_id: output_tree_id,
        ephemeral_public_key: [0u8; 32],
        encrypted_blob: [0u8; 80],
        view_tag: 0,
    });

    // Validate merged_amount matches the sum of both input PDA balances
    let expected_merged = ctx.accounts.position_pda_0.balance
        .checked_add(ctx.accounts.position_pda_1.balance)
        .ok_or(PrivacyError::ArithmeticOverflow)?;
    require!(merged_amount == expected_merged, PrivacyError::InvalidPublicAmount);

    // Create merged PositionPDA
    let new_pda = &mut ctx.accounts.new_position_pda;
    new_pda.bump = ctx.bumps.new_position_pda;
    new_pda.mint = mint;
    new_pda.balance = merged_amount;
    new_pda.leaf_index = merged_leaf_idx;
    new_pda.tree_id = output_tree_id;
    new_pda.is_active = true;

    // Two positions consumed, one created — net -1
    let vault_record = &mut ctx.accounts.position_vault_record;
    vault_record.position_count = vault_record.position_count.saturating_sub(1);
    // total_balance unchanged (no token movement)

    // Both input PositionPDAs auto-closed by Anchor `close = relayer` constraint
    Ok(())
}

/// Pre-fund the executor WSOL ATA for a native-SOL open_position.
/// Debits the SOL vault directly (raw lamport mutation) and credits the executor WSOL ATA,
/// then the following open_position instruction calls sync_native and runs Jupiter.
/// Must be the instruction immediately preceding open_position in the same transaction.
pub fn fund_native_open_position(
    ctx: Context<crate::FundNativeOpenPosition>,
    source_mint: Pubkey,
    dest_mint: Pubkey,
    input_nullifier_0: [u8; 32],
    swap_amount: u64,
) -> Result<()> {
    require!(!crate::is_token_mint(&source_mint), PrivacyError::InvalidMintAddress);
    require!(
        ctx.accounts.source_config.is_relayer(&ctx.accounts.relayer.key()),
        PrivacyError::RelayerNotAllowed
    );
    require!(swap_amount > 0, PrivacyError::InvalidPublicAmount);

    // Verify the immediately following instruction is open_position referencing this executor.
    let hash = solana_sha256_hasher::hash(b"global:open_position");
    let disc: [u8; 8] = hash.to_bytes()[..8].try_into().map_err(|_| error!(PrivacyError::MissingTransactSwapInstruction))?;
    let ix_sysvar = ctx.accounts.instructions_sysvar.to_account_info();
    let current_idx = load_current_index_checked(&ix_sysvar)? as usize;
    let next_ix = load_instruction_at_checked(current_idx + 1, &ix_sysvar)
        .map_err(|_| error!(PrivacyError::MissingTransactSwapInstruction))?;
    require_keys_eq!(next_ix.program_id, crate::ID, PrivacyError::MissingTransactSwapInstruction);
    require!(
        next_ix.data.len() >= 8 && next_ix.data[..8] == disc,
        PrivacyError::MissingTransactSwapInstruction
    );
    // executor is at fixed index 15 in OpenPosition's account list (positional check, not scan)
    const OPEN_POSITION_EXECUTOR_IDX: usize = 15;
    require!(
        next_ix.accounts.len() > OPEN_POSITION_EXECUTOR_IDX
            && next_ix.accounts[OPEN_POSITION_EXECUTOR_IDX].pubkey == ctx.accounts.executor.key(),
        PrivacyError::MissingTransactSwapInstruction
    );

    let vault_ai = ctx.accounts.source_vault.to_account_info();
    let rent_exempt_min = anchor_lang::solana_program::rent::Rent::get()?
        .minimum_balance(vault_ai.data_len());
    require!(
        vault_ai.lamports() >= swap_amount + rent_exempt_min,
        PrivacyError::InsufficientFundsForWithdrawal
    );

    let executor = &mut ctx.accounts.executor;
    executor.bump = ctx.bumps.executor;
    executor.is_prefunded = 1;

    **vault_ai.try_borrow_mut_lamports()? = vault_ai
        .lamports()
        .checked_sub(swap_amount)
        .ok_or(PrivacyError::ArithmeticOverflow)?;
    **ctx.accounts.executor_source_token.to_account_info().try_borrow_mut_lamports()? =
        ctx.accounts.executor_source_token
            .to_account_info()
            .lamports()
            .checked_add(swap_amount)
            .ok_or(PrivacyError::ArithmeticOverflow)?;

    Ok(())
}

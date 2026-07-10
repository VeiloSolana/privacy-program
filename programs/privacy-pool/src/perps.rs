/// Jupiter Perpetuals integration: the pool's executor PDA owns the position so the
/// user's wallet never appears on-chain (private perp trading). Jupiter's keeper settles
/// requests off-chain. Handlers: `jperp_open_position`, `jperp_set_tpsl`,
/// `jperp_update_tpsl`, `jperp_close_position`, `jperp_cancel_trigger`,
/// `jperp_reissue_notes`, `jperp_recover_native` (+ `fund_native_jperp_open` for SOL pools).
/// Per-handler CPI account layouts are documented inline at each `account_metas`/`cpi_infos`.
///
/// Conventions: Side enum None=0/Long=1/Short=2, RequestType Market=0/Trigger=1; CPI args are
/// Borsh-encoded with an 8-byte sha256("global:<name>") discriminator and `0x00`/`0x01` Option markers.
///
/// Trigger lifecycle: each pending TP/SL is a standalone Jupiter-owned `positionRequest`
/// holding ~0.0051 SOL rent that the per-op sweep cannot reach. The keeper refunds rent only
/// when that specific trigger fires; cancel every trigger that never fires via
/// `jperp_cancel_trigger` (when one of TP/SL fires, cancel the other; on manual close or
/// liquidation, cancel all). Run cancels BEFORE `jperp_reissue_notes` (reissue closes the
/// executor collateral ATA that cancel needs as Jupiter's `ownerAta`). A cancel that races the
/// keeper just fails harmlessly (wasted fee, no fund risk).

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::Instruction,
    program::{ invoke, invoke_signed },
    system_instruction,
};
use anchor_spl::associated_token::get_associated_token_address;
use anchor_spl::token;

use crate::{
    PrivacyError,
    MerkleTree,
    PoseidonHasher,
    ExtData,
    TransactionPublicInputs,
    NoteCiphers,
    CommitmentEvent,
    NullifierSpent,
    mark_nullifier_spent,
    deserialize_token_account,
    zk::{ verify_transaction_groth16, TransactionProof },
};

pub const JUPITER_PERP_PROGRAM_ID: Pubkey =
    pubkey!("PERPHjGBqRHArX4DySjwM6UJHiR3sWAatqfdBS2qQJu");

pub const PERPS_EVENT_AUTHORITY: Pubkey =
    pubkey!("37hJBDnntwqhGbK7L6M1bLyvccj4u55CCUiLPdYkiqBN");

pub const JLP_POOL: Pubkey = pubkey!("5BUwFW4nRbftYTDMbgxykoFWqWHPzahFSNAaaaJtVKsq");

/// Side enum discriminants (matches Jupiter Perps IDL: None=0, Long=1, Short=2)
pub const SIDE_LONG: u8 = 1;
pub const SIDE_SHORT: u8 = 2;

/// RequestType enum discriminants (Market=0, Trigger=1)
pub const REQUEST_TYPE_MARKET: u8 = 0;
pub const REQUEST_TYPE_TRIGGER: u8 = 1;

/// Relayer-fronted SOL the executor PDA must hold so Jupiter can pay positionRequest+ATA rent
/// via `system_program::transfer(from = executor)` — legal only because the executor is
/// SYSTEM-OWNED. Above the ~7.5M-lamport open floor it's swept back same-tx; don't trim below ~8M.
pub const EXECUTOR_JUPITER_RENT_FUNDING: u64 = 9_000_000; // 0.009 SOL

/// Defense-in-depth ceiling on the rent `jperp_recover_native` sweeps to the relayer. Exactness
/// comes from `recover_amount = settled proceeds` (claimant-co-signed); this just bounds skim.
/// Set above a close's two request-rent refunds (~10.2M) so it never blocks a claim. Decoupled
/// from EXECUTOR_JUPITER_RENT_FUNDING (which also funds opens) to avoid re-inflating the overpay.
pub const JPERP_RECOVER_RENT_CAP: u64 = 15_000_000; // 0.015 SOL

/// Native SOL positions (longs) use WSOL as the actual collateral token for Jupiter CPIs.
pub const WSOL_MINT: Pubkey = pubkey!("So11111111111111111111111111111111111111112");

/// Sweep the executor PDA's residual lamports (relayer-fronted rent + Jupiter refunds) back to
/// the relayer. No-op when empty.
fn sweep_jperp_executor_lamports<'info>(
    system_program: &AccountInfo<'info>,
    executor: &AccountInfo<'info>,
    relayer: &AccountInfo<'info>,
    executor_seeds: &[&[u8]],
) -> Result<()> {
    let residual = executor.lamports();
    if residual == 0 {
        return Ok(());
    }
    invoke_signed(
        &system_instruction::transfer(&executor.key(), &relayer.key(), residual),
        &[executor.clone(), relayer.clone(), system_program.clone()],
        &[executor_seeds],
    )?;
    Ok(())
}

fn jperp_disc(name: &str) -> [u8; 8] {
    use sha2::{ Digest, Sha256 };
    let preimage = format!("global:{}", name);
    let hash = Sha256::digest(preimage.as_bytes());
    hash[..8].try_into().expect("sha256 output is 32 bytes")
}

fn encode_create_increase_request(
    size_usd_delta: u64,
    collateral_token_delta: u64,
    side: u8,
    price_slippage: u64,
    counter: u64,
) -> Vec<u8> {
    let mut data = jperp_disc("create_increase_position_market_request").to_vec();
    data.extend_from_slice(&size_usd_delta.to_le_bytes());
    data.extend_from_slice(&collateral_token_delta.to_le_bytes());
    data.push(side); // Borsh u8 enum discriminant
    data.extend_from_slice(&price_slippage.to_le_bytes());
    data.push(0x00); // jupiter_minimum_out: Option<u64> = None
    data.extend_from_slice(&counter.to_le_bytes());
    data
}

fn encode_create_decrease_request(
    collateral_usd_delta: u64,
    size_usd_delta: u64,
    request_type: u8,
    price_slippage: Option<u64>,
    trigger_price: Option<u64>,
    trigger_above_threshold: Option<bool>,
    entire_position: Option<bool>,
    counter: u64,
) -> Vec<u8> {
    let mut data = jperp_disc("create_decrease_position_request2").to_vec();
    data.extend_from_slice(&collateral_usd_delta.to_le_bytes());
    data.extend_from_slice(&size_usd_delta.to_le_bytes());
    data.push(request_type);
    // price_slippage: Option<u64>
    match price_slippage {
        Some(v) => { data.push(0x01); data.extend_from_slice(&v.to_le_bytes()); }
        None => data.push(0x00),
    }
    // jupiter_minimum_out: Option<u64> = always None
    data.push(0x00);
    // trigger_price: Option<u64>
    match trigger_price {
        Some(v) => { data.push(0x01); data.extend_from_slice(&v.to_le_bytes()); }
        None => data.push(0x00),
    }
    // trigger_above_threshold: Option<bool>
    match trigger_above_threshold {
        Some(v) => { data.push(0x01); data.push(v as u8); }
        None => data.push(0x00),
    }
    // entire_position: Option<bool>
    match entire_position {
        Some(v) => { data.push(0x01); data.push(v as u8); }
        None => data.push(0x00),
    }
    data.extend_from_slice(&counter.to_le_bytes());
    data
}

fn encode_update_decrease_request(size_usd_delta: u64, trigger_price: u64) -> Vec<u8> {
    let mut data = jperp_disc("update_decrease_position_request2").to_vec();
    data.extend_from_slice(&size_usd_delta.to_le_bytes());
    data.extend_from_slice(&trigger_price.to_le_bytes());
    data
}

// sha256("global:jperp_open_position")[..8]
const JPERP_OPEN_POSITION_DISC: [u8; 8] = [115, 245, 185, 220, 121, 57, 231, 147];

/// Pre-funding step for native SOL pool opens: moves `deposit_amount` lamports from the
/// native-SOL vault into the executor's WSOL ATA. Must immediately precede
/// `jperp_open_position` (which calls sync_native to materialise the WSOL balance).
pub fn fund_native_jperp_open(
    ctx: Context<crate::FundNativeJperpOpen>,
    mint_address: Pubkey,
    _claimant: Pubkey,
    _withdrawal_id: [u8; 32],
    deposit_amount: u64,
) -> Result<()> {
    use anchor_lang::solana_program::sysvar::instructions as ix_sysvar;

    // Pairing guard: immediately-following instruction must be jperp_open_position.
    let ixs = ctx.accounts.instructions_sysvar.to_account_info();
    let current_idx = ix_sysvar::load_current_index_checked(&ixs)? as usize;
    let next_ix = ix_sysvar::load_instruction_at_checked(current_idx + 1, &ixs)
        .map_err(|_| error!(PrivacyError::Unauthorized))?;
    require_keys_eq!(next_ix.program_id, crate::ID, PrivacyError::Unauthorized);
    require!(
        next_ix.data.len() >= 8 && next_ix.data[..8] == JPERP_OPEN_POSITION_DISC,
        PrivacyError::Unauthorized
    );
    // Bind the funded executor to the paired jperp_open_position's executor — else a relayer could
    // strand vault lamports in an unrelated executor's WSOL ATA. Index 10 = executor in JperpOpenPosition.
    const JPERP_OPEN_EXECUTOR_IDX: usize = 10;
    require!(
        next_ix.accounts.len() > JPERP_OPEN_EXECUTOR_IDX
            && next_ix.accounts[JPERP_OPEN_EXECUTOR_IDX].pubkey == ctx.accounts.executor.key(),
        PrivacyError::Unauthorized
    );

    // Bind the funded amount to the paired open's proof-verified deposit_amount, else the
    // debit here and the notes burned there are independent. Offset into jperp_open_position's
    // fixed args: 8 disc + 32 root + 2 in_tree + 2 out_tree -> deposit_amount at 44.
    const JPERP_OPEN_DEPOSIT_OFFSET: usize = 44;
    require!(
        next_ix.data.len() >= JPERP_OPEN_DEPOSIT_OFFSET + 8,
        PrivacyError::Unauthorized
    );
    let open_deposit_amount = u64::from_le_bytes(
        next_ix.data[JPERP_OPEN_DEPOSIT_OFFSET..JPERP_OPEN_DEPOSIT_OFFSET + 8]
            .try_into()
            .unwrap()
    );
    require!(open_deposit_amount == deposit_amount, PrivacyError::InvalidPublicAmount);

    require!(!crate::is_token_mint(&mint_address), PrivacyError::InvalidMintAddress);
    require!(
        ctx.accounts.source_config.is_relayer(&ctx.accounts.relayer.key()),
        PrivacyError::RelayerNotAllowed
    );
    require!(deposit_amount > 0, PrivacyError::InvalidPublicAmount);

    let vault_info = ctx.accounts.vault.to_account_info();
    let rent_exempt_min = anchor_lang::solana_program::rent::Rent::get()?
        .minimum_balance(vault_info.data_len());
    require!(
        vault_info.lamports() >= deposit_amount + rent_exempt_min,
        PrivacyError::InsufficientFundsForWithdrawal
    );

    **vault_info.try_borrow_mut_lamports()? -= deposit_amount;
    **ctx.accounts.executor_wsol_ata.to_account_info().try_borrow_mut_lamports()? += deposit_amount;

    Ok(())
}

/// ZK-verified withdrawal → executor PDA funded → `createIncreasePositionMarketRequest`
/// CPI (atomic); Jupiter's keeper settles off-chain, leaving the executor PDA as owner.
/// `ext_data.recipient` must equal the executor PDA (committed in the ZK proof).
#[allow(clippy::too_many_arguments)]
pub fn jperp_open_position<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::JperpOpenPosition<'info>>,
    root: [u8; 32],
    input_tree_id: u16,
    output_tree_id: u16,
    deposit_amount: u64,
    ext_data_hash: [u8; 32],
    mint_address: Pubkey,
    claimant: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    output_commitment_0: [u8; 32],
    output_commitment_1: [u8; 32],
    withdrawal_id: [u8; 32],
    deadline: i64,
    ext_data: ExtData,
    proof: TransactionProof,
    note_ciphers: Option<NoteCiphers>,
    size_usd_delta: u64,
    collateral_token_delta: u64,
    side: u8,
    price_slippage: u64,
    counter: u64,
) -> Result<()> {
    let (note0_epk, note0_enc, note0_vt, note1_epk, note1_enc, note1_vt) = match note_ciphers {
        Some(c) => (
            c.note0_ephemeral_key, c.note0_encrypted, c.note0_view_tag,
            c.note1_ephemeral_key, c.note1_encrypted, c.note1_view_tag,
        ),
        None => ([0u8; 32], [0u8; 80], 0u8, [0u8; 32], [0u8; 80], 0u8),
    };

    let is_native_sol_pool = mint_address == Pubkey::default();

    let cfg = &mut ctx.accounts.config;

    require!(
        side == SIDE_LONG || side == SIDE_SHORT,
        PrivacyError::JperpInvalidSide
    );
    require!(deposit_amount > 0, PrivacyError::InvalidPublicAmount);
    require!(size_usd_delta > 0, PrivacyError::InvalidPublicAmount);
    // collateral_token_delta is encoded directly into the Jupiter CPI; without this
    // check a relayer could open a zero-size position while keeping deposit_amount in
    // the executor ATA and immediately reissue it — making jperp a fee-free note split.
    require!(
        collateral_token_delta == deposit_amount,
        PrivacyError::JperpCollateralMismatch
    );

    require_keys_eq!(cfg.mint_address, mint_address, PrivacyError::InvalidMintAddress);
    require!(input_tree_id < cfg.num_trees, PrivacyError::InvalidTreeId);
    require!(output_tree_id < cfg.num_trees, PrivacyError::InvalidTreeId);

    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require_keys_eq!(ctx.accounts.relayer.key(), ext_data.relayer, PrivacyError::RelayerMismatch);
    let clock = Clock::get()?;
    require!(clock.unix_timestamp <= deadline, PrivacyError::DeadlineExpired);

    require_keys_eq!(
        ext_data.recipient,
        ctx.accounts.executor.key(),
        PrivacyError::JperpRecipientMustBeExecutor
    );
    require_keys_eq!(claimant, ext_data.claimant, PrivacyError::InvalidClaimant);

    let zero = [0u8; 32];
    let input_nullifiers = [input_nullifier_0, input_nullifier_1];
    let output_commitments = [output_commitment_0, output_commitment_1];

    require!(input_nullifiers[0] != input_nullifiers[1], PrivacyError::DuplicateNullifiers);
    require!(
        input_nullifiers[0] != zero && input_nullifiers[1] != zero,
        PrivacyError::ZeroNullifier
    );
    require!(output_commitments[0] != output_commitments[1], PrivacyError::DuplicateCommitments);
    require!(
        output_commitments[0] != zero && output_commitments[1] != zero,
        PrivacyError::ZeroCommitment
    );

    let computed_ext_hash = ext_data.hash()?;
    require!(computed_ext_hash == ext_data_hash, PrivacyError::InvalidExtData);

    let total_outflow = deposit_amount
        .checked_add(ext_data.fee)
        .ok_or(error!(PrivacyError::ArithmeticOverflow))?;
    if is_native_sol_pool {
        require!(
            ctx.accounts.vault_token_account.key() == ctx.accounts.vault.key(),
            PrivacyError::VaultTokenAccountNotATA
        );
        require!(
            ctx.accounts.vault.to_account_info().lamports() >= total_outflow,
            PrivacyError::InsufficientFundsForWithdrawal
        );
    } else {
        let expected_vault_ata =
            get_associated_token_address(&ctx.accounts.vault.key(), &mint_address);
        require!(
            ctx.accounts.vault_token_account.key() == expected_vault_ata,
            PrivacyError::VaultTokenAccountNotATA
        );
        let vault_token_data = deserialize_token_account(
            &ctx.accounts.vault_token_account.to_account_info()
        )?;
        require!(
            vault_token_data.amount >= total_outflow,
            PrivacyError::InsufficientFundsForWithdrawal
        );
    }

    // Relayer fee upper-bound (mirrors transact's max_fee cap): without it a relayer could
    // set ext_data.fee to drain the vault. The fee is bound into the proof below. fee == 0 ok.
    let max_fee_u128 = (deposit_amount as u128)
        .checked_mul(cfg.fee_bps as u128)
        .ok_or(error!(PrivacyError::ArithmeticOverflow))? / 10_000;
    require!(max_fee_u128 <= u64::MAX as u128, PrivacyError::ExcessiveFee);
    let max_fee_with_margin = (max_fee_u128 as u64)
        .checked_mul((10_000u64).saturating_add(cfg.fee_error_margin_bps as u64))
        .map(|x| x / 10_000)
        .unwrap_or(max_fee_u128 as u64);
    require!(ext_data.fee <= max_fee_with_margin, PrivacyError::InvalidFeeAmount);

    // public_amount binds the FULL outflow (deposit_amount + fee) so the consumed
    // notes burn the fee too — it can no longer be drawn from other users' funds.
    require!(total_outflow <= i64::MAX as u64, PrivacyError::ArithmeticOverflow);
    let public_inputs = TransactionPublicInputs {
        root,
        public_amount: -(total_outflow as i64),
        ext_data_hash,
        mint_address,
        input_nullifiers,
        output_commitments,
    };
    verify_transaction_groth16(proof, &public_inputs)?;

    {
        let input_tree = ctx.accounts.input_tree.load()?;
        require!(MerkleTree::is_known_root(&*input_tree, root), PrivacyError::UnknownRoot);
    }

    require!(!ctx.accounts.nullifier_marker_0.is_spent, PrivacyError::NullifierAlreadyUsed);
    require!(!ctx.accounts.nullifier_marker_1.is_spent, PrivacyError::NullifierAlreadyUsed);

    mark_nullifier_spent(
        &mut ctx.accounts.nullifier_marker_0,
        &mut ctx.accounts.nullifiers,
        input_nullifiers[0],
        ctx.bumps.nullifier_marker_0,
        mint_address,
        input_tree_id,
    )?;
    mark_nullifier_spent(
        &mut ctx.accounts.nullifier_marker_1,
        &mut ctx.accounts.nullifiers,
        input_nullifiers[1],
        ctx.bumps.nullifier_marker_1,
        mint_address,
        input_tree_id,
    )?;

    let (leaf_index_0, leaf_index_1, new_root) = {
        let mut output_tree = ctx.accounts.output_tree.load_mut()?;
        let max_capacity = 1u64 << (output_tree.height as u64);
        let remaining_capacity = max_capacity.saturating_sub(output_tree.next_index);
        require!(remaining_capacity >= 2, PrivacyError::MerkleTreeFull);
        let idx0 = output_tree.next_index;
        MerkleTree::append::<PoseidonHasher>(output_commitments[0], &mut *output_tree)?;
        let idx1 = output_tree.next_index;
        MerkleTree::append::<PoseidonHasher>(output_commitments[1], &mut *output_tree)?;
        (idx0, idx1, output_tree.root)
    };

    // Emit before the Jupiter Perps CPI — the keeper-request CPI generates enough
    // logs that events emitted after it can be truncated (same root cause as positions.rs).
    emit!(NullifierSpent {
        nullifier: input_nullifiers[0],
        mint_address,
        tree_id: input_tree_id,
        timestamp: clock.unix_timestamp,
    });
    emit!(NullifierSpent {
        nullifier: input_nullifiers[1],
        mint_address,
        tree_id: input_tree_id,
        timestamp: clock.unix_timestamp,
    });
    emit!(CommitmentEvent {
        commitment: output_commitments[0],
        leaf_index: leaf_index_0,
        tree_id: output_tree_id,
        mint_address,
        new_root,
        ephemeral_public_key: note0_epk,
        encrypted_blob: note0_enc,
        view_tag: note0_vt,
        timestamp: clock.unix_timestamp,
    });
    emit!(CommitmentEvent {
        commitment: output_commitments[1],
        leaf_index: leaf_index_1,
        tree_id: output_tree_id,
        mint_address,
        new_root,
        ephemeral_public_key: note1_epk,
        encrypted_blob: note1_enc,
        view_tag: note1_vt,
        timestamp: clock.unix_timestamp,
    });

    let vault_seeds: &[&[u8]] = &[
        b"privacy_vault_v3",
        mint_address.as_ref(),
        &[cfg.vault_bump],
    ];

    let executor_key = ctx.accounts.executor.key();
    let executor_bump = ctx.bumps.executor;
    let executor_seeds: &[&[u8]] = &[
        b"jperp_executor",
        mint_address.as_ref(),
        claimant.as_ref(),
        withdrawal_id.as_ref(),
        &[executor_bump],
    ];

    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 14, PrivacyError::JperpInvalidAccounts);
    require_keys_eq!(
        remaining[0].key(),
        JUPITER_PERP_PROGRAM_ID,
        PrivacyError::JperpInvalidAccounts
    );

    if is_native_sol_pool {
        // remaining[8] = inputMint (WSOL for SOL longs).
        let collateral_mint_key = remaining[8].key();
        let expected_executor_ata =
            get_associated_token_address(&executor_key, &collateral_mint_key);
        require!(
            ctx.accounts.executor_token_account.key() == expected_executor_ata,
            PrivacyError::VaultTokenAccountNotATA
        );
        // fund_native_jperp_open already moved the lamports here; materialise them as WSOL.
        token::sync_native(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::SyncNative {
                account: ctx.accounts.executor_token_account.to_account_info(),
            },
            &[executor_seeds],
        ))?;
        let wsol_data = deserialize_token_account(&ctx.accounts.executor_token_account.to_account_info())?;
        require!(
            wsol_data.amount == deposit_amount,
            PrivacyError::InsufficientFundsForWithdrawal
        );
    } else {
        let expected_executor_ata = get_associated_token_address(&executor_key, &mint_address);
        require!(
            ctx.accounts.executor_token_account.key() == expected_executor_ata,
            PrivacyError::VaultTokenAccountNotATA
        );
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.vault_token_account.to_account_info(),
                    to: ctx.accounts.executor_token_account.to_account_info(),
                    authority: ctx.accounts.vault.to_account_info(),
                },
                &[vault_seeds],
            ),
            deposit_amount,
        )?;
    }

    // Pre-fund executor rent (see EXECUTOR_JUPITER_RENT_FUNDING).
    invoke(
        &system_instruction::transfer(
            &ctx.accounts.relayer.key(),
            &executor_key,
            EXECUTOR_JUPITER_RENT_FUNDING,
        ),
        &[
            ctx.accounts.relayer.to_account_info(),
            ctx.accounts.executor.to_account_info(),
            ctx.accounts.system_program.to_account_info(),
        ],
    )?;

    let ix_data = encode_create_increase_request(
        size_usd_delta,
        collateral_token_delta,
        side,
        price_slippage,
        counter,
    );

    let account_metas = vec![
        AccountMeta::new(executor_key, true),                      // owner [mut] [signer]
        AccountMeta::new(ctx.accounts.executor_token_account.key(), false), // fundingAccount [mut]
        AccountMeta::new_readonly(remaining[1].key(), false),       // perpetuals
        AccountMeta::new_readonly(remaining[2].key(), false),       // pool
        AccountMeta::new(remaining[3].key(), false),               // position [mut]
        AccountMeta::new(remaining[4].key(), false),               // positionRequest [mut]
        AccountMeta::new(remaining[5].key(), false),               // positionRequestAta [mut]
        AccountMeta::new_readonly(remaining[6].key(), false),       // custody
        AccountMeta::new_readonly(remaining[7].key(), false),       // collateralCustody
        AccountMeta::new_readonly(remaining[8].key(), false),       // inputMint
        AccountMeta::new_readonly(remaining[9].key(), false),       // referral
        AccountMeta::new_readonly(remaining[10].key(), false),      // tokenProgram
        AccountMeta::new_readonly(remaining[11].key(), false),      // associatedTokenProgram
        AccountMeta::new_readonly(remaining[12].key(), false),      // systemProgram
        AccountMeta::new_readonly(remaining[13].key(), false),      // eventAuthority
        AccountMeta::new_readonly(remaining[0].key(), false),       // program
    ];

    let ix = Instruction {
        program_id: JUPITER_PERP_PROGRAM_ID,
        accounts: account_metas,
        data: ix_data,
    };

    let cpi_infos = vec![
        ctx.accounts.executor.to_account_info(),
        ctx.accounts.executor_token_account.to_account_info(),
        remaining[1].to_account_info(),  // perpetuals
        remaining[2].to_account_info(),  // pool
        remaining[3].to_account_info(),  // position
        remaining[4].to_account_info(),  // positionRequest
        remaining[5].to_account_info(),  // positionRequestAta
        remaining[6].to_account_info(),  // custody
        remaining[7].to_account_info(),  // collateralCustody
        remaining[8].to_account_info(),  // inputMint
        remaining[9].to_account_info(),  // referral
        remaining[10].to_account_info(), // tokenProgram
        remaining[11].to_account_info(), // associatedTokenProgram
        remaining[12].to_account_info(), // systemProgram
        remaining[13].to_account_info(), // eventAuthority
        remaining[0].to_account_info(),  // program
    ];

    invoke_signed(&ix, &cpi_infos, &[executor_seeds])?;

    // Reclaim the leftover rent same-tx. Must run BEFORE the native-SOL fee's direct lamport
    // move (CPI-then-direct ordering, see below). Touches only executor lamports, never the ATA
    // collateral; Jupiter's async post-settlement refund is swept by the next op or reissue.
    sweep_jperp_executor_lamports(
        &ctx.accounts.system_program.to_account_info(),
        &ctx.accounts.executor.to_account_info(),
        &ctx.accounts.relayer.to_account_info(),
        executor_seeds,
    )?;

    // Relayer fee — paid AFTER every CPI. For native SOL the fee moves vault → relayer as raw
    // lamports; doing it before the rent-funding CPI (which spends from the relayer) would mix a
    // direct lamport credit with a later CPI on the same account and break the runtime's
    // lamport-balance invariant. SPL pools transfer from the vault's collateral ATA instead.
    if ext_data.fee > 0 {
        if is_native_sol_pool {
            let vault_ai = ctx.accounts.vault.to_account_info();
            let relayer_ai = ctx.accounts.relayer.to_account_info();
            let mut vault_lamports = vault_ai.try_borrow_mut_lamports()?;
            let mut relayer_lamports = relayer_ai.try_borrow_mut_lamports()?;
            **vault_lamports = vault_lamports
                .checked_sub(ext_data.fee)
                .ok_or(error!(PrivacyError::ArithmeticOverflow))?;
            **relayer_lamports = relayer_lamports
                .checked_add(ext_data.fee)
                .ok_or(error!(PrivacyError::ArithmeticOverflow))?;
        } else {
            let expected_relayer_ata =
                get_associated_token_address(&ctx.accounts.relayer.key(), &mint_address);
            require!(
                ctx.accounts.relayer_token_account.key() == expected_relayer_ata,
                PrivacyError::RelayerTokenAccountMismatch
            );
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    token::Transfer {
                        from: ctx.accounts.vault_token_account.to_account_info(),
                        to: ctx.accounts.relayer_token_account.to_account_info(),
                        authority: ctx.accounts.vault.to_account_info(),
                    },
                    &[vault_seeds],
                ),
                ext_data.fee,
            )?;
        }
    }

    let slot = &mut ctx.accounts.jperp_slot;
    slot.bump = ctx.bumps.jperp_slot;
    slot.amount = deposit_amount;
    slot.reissued = 0;
    slot.claimant_pubkey = claimant;

    cfg.total_tvl = cfg.total_tvl
        .checked_sub(total_outflow)
        .ok_or(error!(PrivacyError::ArithmeticOverflow))?;

    Ok(())
}

/// Create a TP or SL trigger on an open position (`createDecreasePositionRequest2`, `Trigger`
/// type; executor signs as owner). Multiple triggers coexist, each keyed by `counter`.
/// `trigger_above_threshold`: true for TP-long/SL-short, false for SL-long/TP-short.
#[allow(clippy::too_many_arguments)]
pub fn jperp_set_tpsl<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::JperpSetTpsl<'info>>,
    mint_address: Pubkey,
    withdrawal_id: [u8; 32],
    collateral_usd_delta: u64,
    size_usd_delta: u64,
    trigger_price: u64,
    trigger_above_threshold: bool,
    entire_position: bool,
    counter: u64,
) -> Result<()> {
    let cfg = &ctx.accounts.config;
    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);

    // Anti-theft: claimant must be the ephemeral key committed at open time.
    require_keys_eq!(
        ctx.accounts.claimant.key(),
        ctx.accounts.jperp_slot.claimant_pubkey,
        PrivacyError::InvalidClaimant
    );

    let claimant_key = ctx.accounts.claimant.key();
    let executor_key = ctx.accounts.executor.key();
    let executor_bump = ctx.bumps.executor;
    let executor_seeds: &[&[u8]] = &[
        b"jperp_executor",
        mint_address.as_ref(),
        claimant_key.as_ref(),
        withdrawal_id.as_ref(),
        &[executor_bump],
    ];

    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 16, PrivacyError::JperpInvalidAccounts);
    require_keys_eq!(
        remaining[0].key(),
        JUPITER_PERP_PROGRAM_ID,
        PrivacyError::JperpInvalidAccounts
    );

    // receivingAccount = executor's collateral ATA (proceeds land here when trigger fires).
    // For SOL pools the collateral is WSOL (not the all-zero native mint).
    let collateral_mint = if mint_address == Pubkey::default() { WSOL_MINT } else { mint_address };
    let expected_executor_ata = get_associated_token_address(&executor_key, &collateral_mint);
    require!(
        ctx.accounts.executor_token_account.key() == expected_executor_ata,
        PrivacyError::VaultTokenAccountNotATA
    );

    let ix_data = encode_create_decrease_request(
        collateral_usd_delta,
        size_usd_delta,
        REQUEST_TYPE_TRIGGER,
        None,
        Some(trigger_price),
        Some(trigger_above_threshold),
        Some(entire_position),
        counter,
    );

    let receiving_account = ctx.accounts.executor_token_account.key();

    let account_metas = build_decrease_request_metas(
        executor_key,
        receiving_account,
        &remaining,
    );

    let ix = Instruction {
        program_id: JUPITER_PERP_PROGRAM_ID,
        accounts: account_metas,
        data: ix_data,
    };

    // Pre-fund executor rent (see jperp_open_position).
    invoke(
        &system_instruction::transfer(
            &ctx.accounts.relayer.key(),
            &executor_key,
            EXECUTOR_JUPITER_RENT_FUNDING,
        ),
        &[
            ctx.accounts.relayer.to_account_info(),
            ctx.accounts.executor.to_account_info(),
            ctx.accounts.system_program.to_account_info(),
        ],
    )?;

    invoke_signed(&ix, &build_decrease_request_infos(
        &ctx.accounts.executor,
        &ctx.accounts.executor_token_account,
        remaining,
    ), &[executor_seeds])?;

    // Reclaim leftover rent + any Jupiter refund same-tx (see jperp_open_position).
    sweep_jperp_executor_lamports(
        &ctx.accounts.system_program.to_account_info(),
        &ctx.accounts.executor.to_account_info(),
        &ctx.accounts.relayer.to_account_info(),
        executor_seeds,
    )?;

    Ok(())
}

/// Update the trigger price or size on a pending TP/SL request (`updateDecreasePositionRequest2`).
/// `counter` selects the request (positionRequest PDA passed in remaining_accounts[4]).
pub fn jperp_update_tpsl<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::JperpUpdateTpsl<'info>>,
    mint_address: Pubkey,
    withdrawal_id: [u8; 32],
    size_usd_delta: u64,
    trigger_price: u64,
) -> Result<()> {
    let cfg = &ctx.accounts.config;
    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);

    // Anti-theft: claimant must be the ephemeral key committed at open time.
    require_keys_eq!(
        ctx.accounts.claimant.key(),
        ctx.accounts.jperp_slot.claimant_pubkey,
        PrivacyError::InvalidClaimant
    );

    let claimant_key = ctx.accounts.claimant.key();
    let executor_key = ctx.accounts.executor.key();
    let executor_bump = ctx.bumps.executor;
    let executor_seeds: &[&[u8]] = &[
        b"jperp_executor",
        mint_address.as_ref(),
        claimant_key.as_ref(),
        withdrawal_id.as_ref(),
        &[executor_bump],
    ];

    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 8, PrivacyError::JperpInvalidAccounts);
    require_keys_eq!(
        remaining[0].key(),
        JUPITER_PERP_PROGRAM_ID,
        PrivacyError::JperpInvalidAccounts
    );

    let ix_data = encode_update_decrease_request(size_usd_delta, trigger_price);

    let account_metas = vec![
        AccountMeta::new_readonly(executor_key, true),         // owner [signer]
        AccountMeta::new_readonly(remaining[1].key(), false),  // perpetuals
        AccountMeta::new_readonly(remaining[2].key(), false),  // pool
        AccountMeta::new_readonly(remaining[3].key(), false),  // position
        AccountMeta::new(remaining[4].key(), false),           // positionRequest [mut]
        AccountMeta::new_readonly(remaining[5].key(), false),  // custody
        AccountMeta::new_readonly(remaining[6].key(), false),  // custodyDovesPriceAccount
        AccountMeta::new_readonly(remaining[7].key(), false),  // custodyPythnetPriceAccount
    ];

    let ix = Instruction {
        program_id: JUPITER_PERP_PROGRAM_ID,
        accounts: account_metas,
        data: ix_data,
    };

    let cpi_infos = vec![
        ctx.accounts.executor.to_account_info(),
        remaining[1].to_account_info(),
        remaining[2].to_account_info(),
        remaining[3].to_account_info(),
        remaining[4].to_account_info(),
        remaining[5].to_account_info(),
        remaining[6].to_account_info(),
        remaining[7].to_account_info(),
        remaining[0].to_account_info(), // program
    ];

    invoke_signed(&ix, &cpi_infos, &[executor_seeds])?;

    Ok(())
}

/// Create a market decrease (full or partial close) for an open position
/// (`createDecreasePositionRequest2`, `Market` type); keeper routes proceeds to the executor's
/// receiving ATA. Full close: `entire_position = true`, `size_usd_delta = 0`.
#[allow(clippy::too_many_arguments)]
pub fn jperp_close_position<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::JperpClosePosition<'info>>,
    mint_address: Pubkey,
    withdrawal_id: [u8; 32],
    collateral_usd_delta: u64,
    size_usd_delta: u64,
    entire_position: bool,
    price_slippage: u64,
    counter: u64,
) -> Result<()> {
    let cfg = &ctx.accounts.config;
    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);

    // Anti-theft: claimant must be the ephemeral key committed at open time.
    require_keys_eq!(
        ctx.accounts.claimant.key(),
        ctx.accounts.jperp_slot.claimant_pubkey,
        PrivacyError::InvalidClaimant
    );

    let claimant_key = ctx.accounts.claimant.key();
    let executor_key = ctx.accounts.executor.key();
    let executor_bump = ctx.bumps.executor;
    let executor_seeds: &[&[u8]] = &[
        b"jperp_executor",
        mint_address.as_ref(),
        claimant_key.as_ref(),
        withdrawal_id.as_ref(),
        &[executor_bump],
    ];

    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 16, PrivacyError::JperpInvalidAccounts);
    require_keys_eq!(
        remaining[0].key(),
        JUPITER_PERP_PROGRAM_ID,
        PrivacyError::JperpInvalidAccounts
    );

    // receivingAccount = executor's collateral ATA (close proceeds land here).
    // For SOL pools the collateral is WSOL (not the all-zero native mint).
    let collateral_mint = if mint_address == Pubkey::default() { WSOL_MINT } else { mint_address };
    let expected_executor_ata = get_associated_token_address(&executor_key, &collateral_mint);
    require!(
        ctx.accounts.executor_token_account.key() == expected_executor_ata,
        PrivacyError::VaultTokenAccountNotATA
    );

    let ix_data = encode_create_decrease_request(
        collateral_usd_delta,
        size_usd_delta,
        REQUEST_TYPE_MARKET,
        Some(price_slippage),
        None,
        None,
        Some(entire_position),
        counter,
    );

    let receiving_account = ctx.accounts.executor_token_account.key();

    let account_metas = build_decrease_request_metas(executor_key, receiving_account, remaining);

    let ix = Instruction {
        program_id: JUPITER_PERP_PROGRAM_ID,
        accounts: account_metas,
        data: ix_data,
    };

    // Pre-fund executor rent (see jperp_open_position).
    invoke(
        &system_instruction::transfer(
            &ctx.accounts.relayer.key(),
            &executor_key,
            EXECUTOR_JUPITER_RENT_FUNDING,
        ),
        &[
            ctx.accounts.relayer.to_account_info(),
            ctx.accounts.executor.to_account_info(),
            ctx.accounts.system_program.to_account_info(),
        ],
    )?;

    invoke_signed(&ix, &build_decrease_request_infos(
        &ctx.accounts.executor,
        &ctx.accounts.executor_token_account,
        remaining,
    ), &[executor_seeds])?;

    // Reclaim leftover rent + any Jupiter refund same-tx (see jperp_open_position).
    sweep_jperp_executor_lamports(
        &ctx.accounts.system_program.to_account_info(),
        &ctx.accounts.executor.to_account_info(),
        &ctx.accounts.relayer.to_account_info(),
        executor_seeds,
    )?;

    Ok(())
}

/// Cancel a pending TP/SL trigger that will never fire and reclaim its stranded rent (see the
/// module header for which to cancel). CPIs `closePositionRequest2` on the **owner-cancel path**
/// (mainnet-verified: `keeper` slot = program id / None, executor signs as `owner`); Jupiter
/// refunds rent to the executor, then we sweep it. Creates no accounts, so needs no rent
/// pre-funding. Run BEFORE `jperp_reissue_notes` (reissue closes the executor ATA used here as
/// `ownerAta`).
///
/// `remaining_accounts` (10 — `closePositionRequest2` minus owner/ownerAta, from the Accounts struct):
/// ```
/// [0] perpsProgram           — JUPITER_PERP_PROGRAM_ID; validated. Reused as the
///                              keeper None-marker and as the trailing `program`.
/// [1] pool                   — JLP_POOL; writable
/// [2] positionRequest        — the trigger to cancel (by its counter); writable
/// [3] positionRequestAta     — ATA(collateralMint, positionRequest); writable
/// [4] position               — readonly
/// [5] mint                   — collateral token mint; readonly
/// [6] tokenProgram           — readonly
/// [7] systemProgram          — readonly
/// [8] associatedTokenProgram — readonly
/// [9] eventAuthority         — PERPS_EVENT_AUTHORITY; readonly
/// ```
pub fn jperp_cancel_trigger<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::JperpCancelTrigger<'info>>,
    mint_address: Pubkey,
    withdrawal_id: [u8; 32],
) -> Result<()> {
    let cfg = &ctx.accounts.config;
    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);

    // Anti-theft: claimant must be the ephemeral key committed at open time.
    require_keys_eq!(
        ctx.accounts.claimant.key(),
        ctx.accounts.jperp_slot.claimant_pubkey,
        PrivacyError::InvalidClaimant
    );

    let claimant_key = ctx.accounts.claimant.key();
    let executor_key = ctx.accounts.executor.key();
    let executor_bump = ctx.bumps.executor;
    let executor_seeds: &[&[u8]] = &[
        b"jperp_executor",
        mint_address.as_ref(),
        claimant_key.as_ref(),
        withdrawal_id.as_ref(),
        &[executor_bump],
    ];

    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 10, PrivacyError::JperpInvalidAccounts);
    require_keys_eq!(
        remaining[0].key(),
        JUPITER_PERP_PROGRAM_ID,
        PrivacyError::JperpInvalidAccounts
    );

    // ownerAta = executor's collateral ATA (WSOL for native SOL pools, else the mint).
    let collateral_mint = if mint_address == Pubkey::default() { WSOL_MINT } else { mint_address };
    let expected_executor_ata = get_associated_token_address(&executor_key, &collateral_mint);
    require!(
        ctx.accounts.executor_token_account.key() == expected_executor_ata,
        PrivacyError::VaultTokenAccountNotATA
    );

    // closePositionRequest2 takes no args — just the discriminator.
    let ix_data = jperp_disc("close_position_request2").to_vec();

    let account_metas = vec![
        AccountMeta::new_readonly(remaining[0].key(), false),     // keeper (None = program id)
        AccountMeta::new(executor_key, true),                     // owner [mut] [signer]
        AccountMeta::new(ctx.accounts.executor_token_account.key(), false), // ownerAta [mut]
        AccountMeta::new(remaining[1].key(), false),              // pool [mut]
        AccountMeta::new(remaining[2].key(), false),              // positionRequest [mut]
        AccountMeta::new(remaining[3].key(), false),              // positionRequestAta [mut]
        AccountMeta::new_readonly(remaining[4].key(), false),     // position
        AccountMeta::new_readonly(remaining[5].key(), false),     // mint
        AccountMeta::new_readonly(remaining[6].key(), false),     // tokenProgram
        AccountMeta::new_readonly(remaining[7].key(), false),     // systemProgram
        AccountMeta::new_readonly(remaining[8].key(), false),     // associatedTokenProgram
        AccountMeta::new_readonly(remaining[9].key(), false),     // eventAuthority
        AccountMeta::new_readonly(remaining[0].key(), false),     // program
    ];

    let ix = Instruction {
        program_id: JUPITER_PERP_PROGRAM_ID,
        accounts: account_metas,
        data: ix_data,
    };

    let cpi_infos = vec![
        ctx.accounts.executor.to_account_info(),
        ctx.accounts.executor_token_account.to_account_info(),
        remaining[1].to_account_info(),  // pool
        remaining[2].to_account_info(),  // positionRequest
        remaining[3].to_account_info(),  // positionRequestAta
        remaining[4].to_account_info(),  // position
        remaining[5].to_account_info(),  // mint
        remaining[6].to_account_info(),  // tokenProgram
        remaining[7].to_account_info(),  // systemProgram
        remaining[8].to_account_info(),  // associatedTokenProgram
        remaining[9].to_account_info(),  // eventAuthority
        remaining[0].to_account_info(),  // perpsProgram (keeper None-marker + program)
    ];

    invoke_signed(&ix, &cpi_infos, &[executor_seeds])?;

    // Reclaim the rent Jupiter just refunded to the executor back to the relayer.
    sweep_jperp_executor_lamports(
        &ctx.accounts.system_program.to_account_info(),
        &ctx.accounts.executor.to_account_info(),
        &ctx.accounts.relayer.to_account_info(),
        executor_seeds,
    )?;

    Ok(())
}

/// Transfer settled proceeds from the executor ATA back into the vault, then ZK-verify and
/// mint new private notes (deposit circuit). Called after Jupiter's keeper settles a decrease
/// / TP / SL and proceeds have arrived in the executor ATA.
///
/// The claimant must co-sign (anti-theft). `reissue_amount` is bounded only by the ATA's
/// actual balance — winning positions reissue fully, since each note is backed by real
/// proceeds moved into the vault.
#[allow(clippy::too_many_arguments)]
pub fn jperp_reissue_notes(
    ctx: Context<crate::JperpReissueNotes>,
    root: [u8; 32],
    input_tree_id: u16,
    output_tree_id: u16,
    reissue_amount: u64,
    ext_data_hash: [u8; 32],
    mint_address: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    output_commitment_0: [u8; 32],
    output_commitment_1: [u8; 32],
    withdrawal_id: [u8; 32],
    deadline: i64,
    ext_data: ExtData,
    proof: TransactionProof,
    note_ciphers: Option<NoteCiphers>,
) -> Result<()> {
    let (note0_epk, note0_enc, note0_vt, note1_epk, note1_enc, note1_vt) = match note_ciphers {
        Some(c) => (
            c.note0_ephemeral_key, c.note0_encrypted, c.note0_view_tag,
            c.note1_ephemeral_key, c.note1_encrypted, c.note1_view_tag,
        ),
        None => ([0u8; 32], [0u8; 80], 0u8, [0u8; 32], [0u8; 80], 0u8),
    };

    let cfg = &mut ctx.accounts.config;

    require_keys_eq!(cfg.mint_address, mint_address, PrivacyError::InvalidMintAddress);

    require!(input_tree_id < cfg.num_trees, PrivacyError::InvalidTreeId);
    require!(output_tree_id < cfg.num_trees, PrivacyError::InvalidTreeId);
    require!(reissue_amount > 0, PrivacyError::InvalidPublicAmount);

    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require_keys_eq!(ctx.accounts.relayer.key(), ext_data.relayer, PrivacyError::RelayerMismatch);
    let clock = Clock::get()?;
    require!(clock.unix_timestamp <= deadline, PrivacyError::DeadlineExpired);

    require_keys_eq!(
        ctx.accounts.claimant.key(),
        ctx.accounts.jperp_slot.claimant_pubkey,
        PrivacyError::InvalidClaimant
    );

    // No profit cap: each reissue is backed by the executor-ATA→vault transfer (below) +
    // matching TVL bump, so winning positions reissue fully. The ATA balance check blocks
    // double-mint; `slot.reissued` is now just a cumulative audit counter.
    let slot = &mut ctx.accounts.jperp_slot;
    slot.reissued = slot.reissued
        .checked_add(reissue_amount)
        .ok_or(error!(PrivacyError::ArithmeticOverflow))?;

    let input_nullifiers = [input_nullifier_0, input_nullifier_1];
    let output_commitments = [output_commitment_0, output_commitment_1];
    let zero = [0u8; 32];
    require!(input_nullifiers[0] != input_nullifiers[1], PrivacyError::DuplicateNullifiers);
    require!(output_commitments[0] != output_commitments[1], PrivacyError::DuplicateCommitments);
    require!(
        output_commitments[0] != zero && output_commitments[1] != zero,
        PrivacyError::ZeroCommitment
    );

    let computed_ext_hash = ext_data.hash()?;
    require!(computed_ext_hash == ext_data_hash, PrivacyError::InvalidExtData);

    // Relayer fee upper-bound (mirrors jperp_open_position). SOL-pool reissues validate the
    // fee here but skip the transfer: close_account sweeps the full WSOL ATA to the vault.
    let max_fee_u128 = (reissue_amount as u128)
        .checked_mul(cfg.fee_bps as u128)
        .ok_or(error!(PrivacyError::ArithmeticOverflow))? / 10_000;
    require!(max_fee_u128 <= u64::MAX as u128, PrivacyError::ExcessiveFee);
    let max_fee_with_margin = (max_fee_u128 as u64)
        .checked_mul((10_000u64).saturating_add(cfg.fee_error_margin_bps as u64))
        .map(|x| x / 10_000)
        .unwrap_or(max_fee_u128 as u64);
    require!(ext_data.fee <= max_fee_with_margin, PrivacyError::InvalidFeeAmount);
    let gross_outflow = reissue_amount
        .checked_add(ext_data.fee)
        .ok_or(error!(PrivacyError::ArithmeticOverflow))?;

    let public_inputs = TransactionPublicInputs {
        root,
        public_amount: reissue_amount as i64,
        ext_data_hash,
        mint_address,
        input_nullifiers,
        output_commitments,
    };
    verify_transaction_groth16(proof, &public_inputs)?;

    {
        let input_tree = ctx.accounts.input_tree.load()?;
        require!(MerkleTree::is_known_root(&*input_tree, root), PrivacyError::UnknownRoot);
    }

    let claimant_key = ctx.accounts.claimant.key();
    let executor_key = ctx.accounts.executor.key();
    let executor_bump = ctx.bumps.executor;

    let executor_seeds: &[&[u8]] = &[
        b"jperp_executor",
        mint_address.as_ref(),
        claimant_key.as_ref(),
        withdrawal_id.as_ref(),
        &[executor_bump],
    ];

    let is_native_sol_pool = mint_address == Pubkey::default();
    if is_native_sol_pool {
        // SOL pool: vault_token_account == vault (no WSOL ATA); proceeds land in the executor WSOL ATA.
        require!(
            ctx.accounts.vault_token_account.key() == ctx.accounts.vault.key(),
            PrivacyError::VaultTokenAccountNotATA
        );
        let expected_executor_wsol = get_associated_token_address(&executor_key, &WSOL_MINT);
        require!(
            ctx.accounts.executor_token_account.key() == expected_executor_wsol,
            PrivacyError::VaultTokenAccountNotATA
        );
        let executor_wsol_data = deserialize_token_account(
            &ctx.accounts.executor_token_account.to_account_info()
        )?;
        require!(
            executor_wsol_data.amount >= reissue_amount,
            PrivacyError::InsufficientFundsForWithdrawal
        );
        // close_account transfers all lamports (WSOL balance + rent) to the vault, unwrapping to native SOL.
        token::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::CloseAccount {
                account: ctx.accounts.executor_token_account.to_account_info(),
                destination: ctx.accounts.vault.to_account_info(),
                authority: ctx.accounts.executor.to_account_info(),
            },
            &[executor_seeds],
        ))?;
    } else {
        let expected_executor_ata = get_associated_token_address(&executor_key, &mint_address);
        require!(
            ctx.accounts.executor_token_account.key() == expected_executor_ata,
            PrivacyError::VaultTokenAccountNotATA
        );
        let expected_vault_ata =
            get_associated_token_address(&ctx.accounts.vault.key(), &mint_address);
        require!(
            ctx.accounts.vault_token_account.key() == expected_vault_ata,
            PrivacyError::VaultTokenAccountNotATA
        );
        let executor_ata_data = deserialize_token_account(
            &ctx.accounts.executor_token_account.to_account_info()
        )?;
        require!(
            executor_ata_data.amount >= gross_outflow,
            PrivacyError::InsufficientFundsForWithdrawal
        );
        // Fee: executor → relayer ATA (before vault transfer so vault always gets reissue_amount).
        if ext_data.fee > 0 {
            let expected_relayer_ata =
                get_associated_token_address(&ctx.accounts.relayer.key(), &mint_address);
            require!(
                ctx.accounts.relayer_token_account.key() == expected_relayer_ata,
                PrivacyError::RelayerTokenAccountMismatch
            );
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    token::Transfer {
                        from: ctx.accounts.executor_token_account.to_account_info(),
                        to: ctx.accounts.relayer_token_account.to_account_info(),
                        authority: ctx.accounts.executor.to_account_info(),
                    },
                    &[executor_seeds],
                ),
                ext_data.fee,
            )?;
        }
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.executor_token_account.to_account_info(),
                    to: ctx.accounts.vault_token_account.to_account_info(),
                    authority: ctx.accounts.executor.to_account_info(),
                },
                &[executor_seeds],
            ),
            reissue_amount,
        )?;

        // If this reissue drains the ATA, close it and return the relayer-fronted ATA rent:
        // the executor is per-withdrawal_id, so a drained ATA is abandoned and its rent would
        // strand forever. A partial reissue leaves a balance, so the ATA must stay open.
        if executor_ata_data.amount == gross_outflow {
            token::close_account(CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::CloseAccount {
                    account: ctx.accounts.executor_token_account.to_account_info(),
                    destination: ctx.accounts.relayer.to_account_info(),
                    authority: ctx.accounts.executor.to_account_info(),
                },
                &[executor_seeds],
            ))?;
        }
    }

    // Reclaim the relayer-fronted SOL now that proceeds are pulled (executor is per-withdrawal_id).
    sweep_jperp_executor_lamports(
        &ctx.accounts.system_program.to_account_info(),
        &ctx.accounts.executor.to_account_info(),
        &ctx.accounts.relayer.to_account_info(),
        executor_seeds,
    )?;

    let (leaf_index_0, leaf_index_1, new_root) = {
        let mut output_tree = ctx.accounts.output_tree.load_mut()?;
        let max_capacity = 1u64 << (output_tree.height as u64);
        let remaining_capacity = max_capacity.saturating_sub(output_tree.next_index);
        require!(remaining_capacity >= 2, PrivacyError::MerkleTreeFull);
        let idx0 = output_tree.next_index;
        MerkleTree::append::<PoseidonHasher>(output_commitments[0], &mut *output_tree)?;
        let idx1 = output_tree.next_index;
        MerkleTree::append::<PoseidonHasher>(output_commitments[1], &mut *output_tree)?;
        (idx0, idx1, output_tree.root)
    };

    cfg.total_tvl = cfg.total_tvl
        .checked_add(reissue_amount)
        .ok_or(error!(PrivacyError::ArithmeticOverflow))?;

    emit!(CommitmentEvent {
        commitment: output_commitments[0],
        leaf_index: leaf_index_0,
        tree_id: output_tree_id,
        mint_address,
        new_root,
        ephemeral_public_key: note0_epk,
        encrypted_blob: note0_enc,
        view_tag: note0_vt,
        timestamp: clock.unix_timestamp,
    });
    emit!(CommitmentEvent {
        commitment: output_commitments[1],
        leaf_index: leaf_index_1,
        tree_id: output_tree_id,
        mint_address,
        new_root,
        ephemeral_public_key: note1_epk,
        encrypted_blob: note1_enc,
        view_tag: note1_vt,
        timestamp: clock.unix_timestamp,
    });

    Ok(())
}

/// Settle native-SOL proceeds that the keeper returned to the executor as **native lamports**
/// — both a **cancelled open** (collateral refunded) and a **native-SOL close** (proceeds
/// unwrapped to native; the WSOL ATA ends empty). In either case `jperp_reissue_notes` can't
/// act (it reads the WSOL ATA), and a plain sweep would hand the funds to the relayer.
///
/// This backs the user's note directly from the executor's own lamports (`executor → vault`,
/// signed by the executor PDA), needing **zero relayer float**, then sweeps the leftover —
/// the capped relayer **fee** + the relayer-fronted **rent** — back to the relayer. The note
/// (`recover_amount` = proceeds − fee) is claimant-co-signed, the fee is capped at `fee_bps`,
/// and the non-fee remainder is hard-capped at one rent unit (see below), so the relayer can
/// never sweep the user's collateral. Native mirror of `fund_native_jperp_open`. Native-SOL only.
#[allow(clippy::too_many_arguments)]
pub fn jperp_recover_native(
    ctx: Context<crate::JperpRecoverNative>,
    root: [u8; 32],
    input_tree_id: u16,
    output_tree_id: u16,
    recover_amount: u64,
    ext_data_hash: [u8; 32],
    mint_address: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    output_commitment_0: [u8; 32],
    output_commitment_1: [u8; 32],
    withdrawal_id: [u8; 32],
    deadline: i64,
    ext_data: ExtData,
    proof: TransactionProof,
    note_ciphers: Option<NoteCiphers>,
) -> Result<()> {
    let (note0_epk, note0_enc, note0_vt, note1_epk, note1_enc, note1_vt) = match note_ciphers {
        Some(c) => (
            c.note0_ephemeral_key, c.note0_encrypted, c.note0_view_tag,
            c.note1_ephemeral_key, c.note1_encrypted, c.note1_view_tag,
        ),
        None => ([0u8; 32], [0u8; 80], 0u8, [0u8; 32], [0u8; 80], 0u8),
    };

    let cfg = &mut ctx.accounts.config;

    require_keys_eq!(cfg.mint_address, mint_address, PrivacyError::InvalidMintAddress);
    // Native-SOL pool only — SPL refunds land in the executor ATA and use jperp_reissue_notes.
    require!(mint_address == Pubkey::default(), PrivacyError::InvalidMintAddress);
    require!(input_tree_id < cfg.num_trees, PrivacyError::InvalidTreeId);
    require!(output_tree_id < cfg.num_trees, PrivacyError::InvalidTreeId);
    require!(recover_amount > 0, PrivacyError::InvalidPublicAmount);

    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require_keys_eq!(ctx.accounts.relayer.key(), ext_data.relayer, PrivacyError::RelayerMismatch);
    let clock = Clock::get()?;
    require!(clock.unix_timestamp <= deadline, PrivacyError::DeadlineExpired);

    // Anti-theft: claimant co-signs and must equal the key committed at open time.
    require_keys_eq!(
        ctx.accounts.claimant.key(),
        ctx.accounts.jperp_slot.claimant_pubkey,
        PrivacyError::InvalidClaimant
    );

    // Relayer service fee, capped at fee_bps (+ margin) of the recovered amount — mirrors
    // jperp_reissue_notes / open. The fee is paid out of the recovered proceeds: the note is
    // recover_amount (= proceeds - fee) and the relayer collects the fee via the sweep below.
    let max_fee_u128 = (recover_amount as u128)
        .checked_mul(cfg.fee_bps as u128)
        .ok_or(error!(PrivacyError::ArithmeticOverflow))? / 10_000;
    require!(max_fee_u128 <= u64::MAX as u128, PrivacyError::ExcessiveFee);
    let max_fee_with_margin = (max_fee_u128 as u64)
        .checked_mul((10_000u64).saturating_add(cfg.fee_error_margin_bps as u64))
        .map(|x| x / 10_000)
        .unwrap_or(max_fee_u128 as u64);
    require!(ext_data.fee <= max_fee_with_margin, PrivacyError::InvalidFeeAmount);

    // recover_amount = proceeds (claimant-co-signed) → user gets exact funds; relayer sweeps the
    // rest (fee + rent), bounded by JPERP_RECOVER_RENT_CAP. checked_sub gives idempotency.
    let native = ctx.accounts.executor.lamports();
    let relayer_sweep = native
        .checked_sub(recover_amount)
        .ok_or(error!(PrivacyError::InsufficientFundsForWithdrawal))?;
    let rent_part = relayer_sweep
        .checked_sub(ext_data.fee)
        .ok_or(error!(PrivacyError::InvalidFeeAmount))?;
    require!(
        rent_part <= JPERP_RECOVER_RENT_CAP,
        PrivacyError::JperpRecoverRentExceeded
    );

    let input_nullifiers = [input_nullifier_0, input_nullifier_1];
    let output_commitments = [output_commitment_0, output_commitment_1];
    let zero = [0u8; 32];
    require!(input_nullifiers[0] != input_nullifiers[1], PrivacyError::DuplicateNullifiers);
    require!(output_commitments[0] != output_commitments[1], PrivacyError::DuplicateCommitments);
    require!(
        output_commitments[0] != zero && output_commitments[1] != zero,
        PrivacyError::ZeroCommitment
    );

    let computed_ext_hash = ext_data.hash()?;
    require!(computed_ext_hash == ext_data_hash, PrivacyError::InvalidExtData);

    // Deposit circuit: public_amount = +recover_amount binds the minted note to the collateral.
    let public_inputs = TransactionPublicInputs {
        root,
        public_amount: recover_amount as i64,
        ext_data_hash,
        mint_address,
        input_nullifiers,
        output_commitments,
    };
    verify_transaction_groth16(proof, &public_inputs)?;

    {
        let input_tree = ctx.accounts.input_tree.load()?;
        require!(MerkleTree::is_known_root(&*input_tree, root), PrivacyError::UnknownRoot);
    }

    // Cumulative audit counter (mirrors jperp_reissue_notes).
    let slot = &mut ctx.accounts.jperp_slot;
    slot.reissued = slot.reissued
        .checked_add(recover_amount)
        .ok_or(error!(PrivacyError::ArithmeticOverflow))?;

    let claimant_key = ctx.accounts.claimant.key();
    let executor_seeds: &[&[u8]] = &[
        b"jperp_executor",
        mint_address.as_ref(),
        claimant_key.as_ref(),
        withdrawal_id.as_ref(),
        &[ctx.bumps.executor],
    ];

    // Collateral: executor → vault (program signs as the system-owned executor PDA).
    invoke_signed(
        &system_instruction::transfer(
            &ctx.accounts.executor.key(),
            &ctx.accounts.vault.key(),
            recover_amount,
        ),
        &[
            ctx.accounts.executor.to_account_info(),
            ctx.accounts.vault.to_account_info(),
            ctx.accounts.system_program.to_account_info(),
        ],
        &[executor_seeds],
    )?;

    // Sweep the leftover (capped fee + relayer-fronted rent) back to the relayer.
    sweep_jperp_executor_lamports(
        &ctx.accounts.system_program.to_account_info(),
        &ctx.accounts.executor.to_account_info(),
        &ctx.accounts.relayer.to_account_info(),
        executor_seeds,
    )?;

    // Mint the user's private SOL note.
    let (leaf_index_0, leaf_index_1, new_root) = {
        let mut output_tree = ctx.accounts.output_tree.load_mut()?;
        let max_capacity = 1u64 << (output_tree.height as u64);
        let remaining_capacity = max_capacity.saturating_sub(output_tree.next_index);
        require!(remaining_capacity >= 2, PrivacyError::MerkleTreeFull);
        let idx0 = output_tree.next_index;
        MerkleTree::append::<PoseidonHasher>(output_commitments[0], &mut *output_tree)?;
        let idx1 = output_tree.next_index;
        MerkleTree::append::<PoseidonHasher>(output_commitments[1], &mut *output_tree)?;
        (idx0, idx1, output_tree.root)
    };

    cfg.total_tvl = cfg.total_tvl
        .checked_add(recover_amount)
        .ok_or(error!(PrivacyError::ArithmeticOverflow))?;

    emit!(CommitmentEvent {
        commitment: output_commitments[0],
        leaf_index: leaf_index_0,
        tree_id: output_tree_id,
        mint_address,
        new_root,
        ephemeral_public_key: note0_epk,
        encrypted_blob: note0_enc,
        view_tag: note0_vt,
        timestamp: clock.unix_timestamp,
    });
    emit!(CommitmentEvent {
        commitment: output_commitments[1],
        leaf_index: leaf_index_1,
        tree_id: output_tree_id,
        mint_address,
        new_root,
        ephemeral_public_key: note1_epk,
        encrypted_blob: note1_enc,
        view_tag: note1_vt,
        timestamp: clock.unix_timestamp,
    });

    Ok(())
}

fn build_decrease_request_metas(
    executor_key: Pubkey,
    receiving_account: Pubkey,
    remaining: &[AccountInfo],
) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(executor_key, true),                     // owner [mut] [signer]
        AccountMeta::new(receiving_account, false),               // receivingAccount [mut]
        AccountMeta::new_readonly(remaining[1].key(), false),     // perpetuals
        AccountMeta::new_readonly(remaining[2].key(), false),     // pool
        AccountMeta::new(remaining[3].key(), false),              // position [mut]
        AccountMeta::new(remaining[4].key(), false),              // positionRequest [mut]
        AccountMeta::new(remaining[5].key(), false),              // positionRequestAta [mut]
        AccountMeta::new_readonly(remaining[6].key(), false),     // custody
        AccountMeta::new_readonly(remaining[7].key(), false),     // custodyDovesPriceAccount
        AccountMeta::new_readonly(remaining[8].key(), false),     // custodyPythnetPriceAccount
        AccountMeta::new_readonly(remaining[9].key(), false),     // collateralCustody
        AccountMeta::new_readonly(remaining[10].key(), false),    // desiredMint
        AccountMeta::new_readonly(remaining[11].key(), false),    // referral
        AccountMeta::new_readonly(remaining[12].key(), false),    // tokenProgram
        AccountMeta::new_readonly(remaining[13].key(), false),    // associatedTokenProgram
        AccountMeta::new_readonly(remaining[14].key(), false),    // systemProgram
        AccountMeta::new_readonly(remaining[15].key(), false),    // eventAuthority
        AccountMeta::new_readonly(remaining[0].key(), false),     // program
    ]
}

fn build_decrease_request_infos<'info>(
    executor: &AccountInfo<'info>,
    executor_token_account: &AccountInfo<'info>,
    remaining: &'info [AccountInfo<'info>],
) -> Vec<AccountInfo<'info>> {
    vec![
        executor.clone(),
        executor_token_account.clone(),
        remaining[1].clone(), // perpetuals
        remaining[2].clone(), // pool
        remaining[3].clone(), // position
        remaining[4].clone(), // positionRequest
        remaining[5].clone(), // positionRequestAta
        remaining[6].clone(), // custody
        remaining[7].clone(), // custodyDovesPriceAccount
        remaining[8].clone(), // custodyPythnetPriceAccount
        remaining[9].clone(), // collateralCustody
        remaining[10].clone(), // desiredMint
        remaining[11].clone(), // referral
        remaining[12].clone(), // tokenProgram
        remaining[13].clone(), // associatedTokenProgram
        remaining[14].clone(), // systemProgram
        remaining[15].clone(), // eventAuthority
        remaining[0].clone(),  // program
    ]
}

// Only the shared NullifierSpent/CommitmentEvent are emitted; perp-specific telemetry events were
// dropped on purpose — broadcasting position size/side/amount leaks metadata the relayer already has.

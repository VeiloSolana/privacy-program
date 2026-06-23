/// Jupiter Perpetuals Integration for Veilo Privacy Pool
///
/// Jupiter Perpetuals (PERPHjGBqRHArX4DySjwM6UJHiR3sWAatqfdBS2qQJu) is a leveraged
/// perpetual-futures DEX on Solana backed by the JLP liquidity pool.
///
/// This module lets the pool's executor PDA act as the position owner, enabling
/// **private perp trading** — the user's wallet never appears on-chain as a position holder.
///
/// ## Flow
///
/// 1. `jperp_open_position` — ZK-verified USDC withdrawal → executor PDA funded →
///    `createIncreasePositionMarketRequest` CPI (executor = position owner).
///    Jupiter's keeper picks up the request and settles it atomically.
///
/// 2. `jperp_set_tpsl` — `createDecreasePositionRequest2` CPI with `Trigger` request type.
///    Each call creates one pending trigger (TP or SL) identified by its `counter`.
///    Multiple triggers can coexist on the same position.
///
/// 3. `jperp_update_tpsl` — `updateDecreasePositionRequest2` CPI.
///    Adjusts the trigger price or size on a pending trigger request.
///
/// 4. `jperp_close_position` — `createDecreasePositionRequest2` CPI with `Market` type.
///    Full or partial immediate market close; keeper settles and routes proceeds
///    to the executor's USDC ATA.
///
/// 5. `jperp_reissue_notes` — executor USDC ATA → vault transfer + ZK deposit.
///    Re-mints private notes from settled proceeds; claimant must co-sign (anti-theft).
///
/// ## Account roles
///
/// - `JupiterPerpExecutor` PDA (`[b"jperp_executor", mint, claimant, withdrawal_id]`):
///   signs all Jupiter Perps CPIs as the position owner. The user's wallet is never
///   exposed. Including `withdrawal_id` makes the executor unique **per open**, so each
///   position gets its own executor/ATA/Jupiter-position and positions are mutually
///   unlinkable on-chain (and same-market opens don't aggregate into one position).
/// - `JupiterPerpSlot` PDA (`[b"jperp_slot_v1", mint, withdrawal_id]`): created at
///   deposit time; tracks deposited amount and the claimant key for anti-theft protection.
///
/// ## remaining_accounts layouts
///
/// `jperp_open_position` (14 accounts — createIncreasePositionMarketRequest):
/// ```
/// [0]  perpsProgram           — JUPITER_PERP_PROGRAM_ID; validated
/// [1]  perpetuals             — PDA ["perpetuals"] on PERP program; readonly
/// [2]  pool                   — JLP_POOL; readonly
/// [3]  position               — PDA on PERP; writable (created by keeper on settle)
/// [4]  positionRequest        — PDA ["position_request", position, counter_le8, 0x01]; writable
/// [5]  positionRequestAta     — ATA(inputMint, positionRequest); writable
/// [6]  custody                — market custody PDA; readonly
/// [7]  collateralCustody      — collateral custody PDA (same as custody for longs); readonly
/// [8]  inputMint              — collateral token mint; readonly
/// [9]  referral               — null (SystemProgram pubkey); readonly
/// [10] tokenProgram           — SPL Token; readonly
/// [11] associatedTokenProgram — AToken; readonly
/// [12] systemProgram          — System; readonly
/// [13] eventAuthority         — PERPS_EVENT_AUTHORITY; readonly
/// ```
///
/// `jperp_set_tpsl` / `jperp_close_position` (16 accounts — createDecreasePositionRequest2):
/// ```
/// [0]  perpsProgram
/// [1]  perpetuals
/// [2]  pool
/// [3]  position               — writable
/// [4]  positionRequest        — PDA ["position_request", position, counter_le8, 0x02]; writable
/// [5]  positionRequestAta     — ATA(desiredMint, positionRequest); writable
/// [6]  custody
/// [7]  custodyDovesPriceAccount — Doves price oracle for custody
/// [8]  custodyPythnetPriceAccount — Pyth price oracle for custody
/// [9]  collateralCustody
/// [10] desiredMint            — output token mint (USDC for close proceeds)
/// [11] referral               — null
/// [12] tokenProgram
/// [13] associatedTokenProgram
/// [14] systemProgram
/// [15] eventAuthority
/// ```
///
/// `jperp_update_tpsl` (8 accounts — updateDecreasePositionRequest2):
/// ```
/// [0]  perpsProgram
/// [1]  perpetuals
/// [2]  pool
/// [3]  position               — readonly
/// [4]  positionRequest        — writable
/// [5]  custody
/// [6]  custodyDovesPriceAccount
/// [7]  custodyPythnetPriceAccount
/// ```

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

// ── Constants ─────────────────────────────────────────────────────────────────

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

/// SOL transferred from the relayer into the executor PDA before the Jupiter CPI.
///
/// Jupiter's `createIncreasePositionMarketRequest` funds the `positionRequest`
/// account + its ATA rent via `system_program::transfer(from = owner)`, where
/// `owner` is our executor PDA. The executor is a SYSTEM-OWNED PDA (no data) so
/// that transfer is legal — but it must hold enough lamports. 0.02 SOL comfortably
/// covers the positionRequest account + 165-byte ATA rent; Jupiter refunds the
/// rent to the executor when the request settles, so the excess is reclaimable.
pub const EXECUTOR_JUPITER_RENT_FUNDING: u64 = 20_000_000; // 0.02 SOL

// ── Discriminator helper ──────────────────────────────────────────────────────

fn jperp_disc(name: &str) -> [u8; 8] {
    use sha2::{ Digest, Sha256 };
    let preimage = format!("global:{}", name);
    let hash = Sha256::digest(preimage.as_bytes());
    hash[..8].try_into().expect("sha256 output is 32 bytes")
}

// ── Instruction data builders ─────────────────────────────────────────────────

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

// ── Instruction handlers ──────────────────────────────────────────────────────

/// ZK-verified USDC withdrawal → executor PDA funded →
/// `createIncreasePositionMarketRequest` CPI (atomic).
///
/// Consumes private notes, routes USDC to the executor PDA, and submits a
/// position-open request to Jupiter Perps. Jupiter's keeper settles the request
/// off-chain; once settled the position is owned by the executor PDA.
///
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

    let expected_vault_ata = get_associated_token_address(&ctx.accounts.vault.key(), &mint_address);
    require!(
        ctx.accounts.vault_token_account.key() == expected_vault_ata,
        PrivacyError::VaultTokenAccountNotATA
    );
    let vault_token_data = deserialize_token_account(
        &ctx.accounts.vault_token_account.to_account_info()
    )?;
    let total_outflow = deposit_amount
        .checked_add(ext_data.fee)
        .ok_or(error!(PrivacyError::ArithmeticOverflow))?;
    require!(
        vault_token_data.amount >= total_outflow,
        PrivacyError::InsufficientFundsForWithdrawal
    );

    // Relayer fee upper-bound (mirrors transact's max_fee cap). The fee is paid
    // from the vault on top of deposit_amount and is bound into the proof below
    // (public_amount covers deposit_amount + fee). Without an upper cap a relayer
    // could set ext_data.fee to drain the entire vault. fee == 0 remains valid.
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

    let vault_seeds: &[&[u8]] = &[
        b"privacy_vault_v3",
        mint_address.as_ref(),
        &[cfg.vault_bump],
    ];
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
                    from: ctx.accounts.vault_token_account.to_account_info(),
                    to: ctx.accounts.relayer_token_account.to_account_info(),
                    authority: ctx.accounts.vault.to_account_info(),
                },
                &[vault_seeds],
            ),
            ext_data.fee,
        )?;
    }

    let executor_key = ctx.accounts.executor.key();
    let executor_bump = ctx.bumps.executor;
    let executor_seeds: &[&[u8]] = &[
        b"jperp_executor",
        mint_address.as_ref(),
        claimant.as_ref(),
        withdrawal_id.as_ref(),
        &[executor_bump],
    ];

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

    // Jupiter funds the positionRequest account + ATA via
    // `system_program::transfer(from = owner = executor)`. The executor is a
    // system-owned PDA (no Anchor data), so this transfer is legal — but it must
    // hold enough lamports first. The relayer fronts this SOL (recovered via fee).
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

    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 14, PrivacyError::JperpInvalidAccounts);
    require_keys_eq!(
        remaining[0].key(),
        JUPITER_PERP_PROGRAM_ID,
        PrivacyError::JperpInvalidAccounts
    );

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

    let slot = &mut ctx.accounts.jperp_slot;
    slot.bump = ctx.bumps.jperp_slot;
    slot.amount = deposit_amount;
    slot.reissued = 0;
    slot.claimant_pubkey = claimant;

    cfg.total_tvl = cfg.total_tvl
        .checked_sub(total_outflow)
        .ok_or(error!(PrivacyError::ArithmeticOverflow))?;

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

    emit!(JperpOpenPositionEvent {
        deposit_amount,
        size_usd_delta,
        side,
        mint_address,
        relayer: ctx.accounts.relayer.key(),
        timestamp: clock.unix_timestamp,
    });

    Ok(())
}

/// Create a TP or SL trigger on an open Jupiter Perps position.
///
/// Calls `createDecreasePositionRequest2` with `Trigger` request type.
/// The executor PDA signs as position owner.
///
/// - **TP long**: `trigger_above_threshold = true`, `trigger_price` = take-profit level
/// - **SL long**: `trigger_above_threshold = false`, `trigger_price` = stop-loss level
/// - **TP short**: `trigger_above_threshold = false`
/// - **SL short**: `trigger_above_threshold = true`
///
/// Multiple triggers can exist simultaneously — each uses a different `counter`.
/// remaining_accounts: 16 accounts (see module docs).
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

    // Claimant must be the ephemeral key committed at open time.
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

    // receivingAccount = executor's USDC ATA (proceeds land here when trigger fires).
    // Bind it to the canonical executor ATA so a relayer cannot redirect trigger
    // proceeds to an account that jperp_reissue_notes can never recover from.
    let expected_executor_ata = get_associated_token_address(&executor_key, &mint_address);
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

    // Fund executor PDA so Jupiter can pay the new positionRequest rent via
    // system_program::transfer(from = executor). See jperp_open_position §14b.
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

    emit!(JperpTpslSetEvent {
        trigger_price,
        trigger_above_threshold,
        size_usd_delta,
        entire_position,
        mint_address,
        relayer: ctx.accounts.relayer.key(),
        timestamp: Clock::get()?.unix_timestamp,
    });

    Ok(())
}

/// Update the trigger price or size on a pending TP/SL position request.
///
/// Calls `updateDecreasePositionRequest2`. Only the `trigger_price` and
/// `size_usd_delta` can be changed; the `counter` identifies which request to update
/// (the positionRequest PDA must be passed in remaining_accounts[4]).
///
/// remaining_accounts: 8 accounts (see module docs).
pub fn jperp_update_tpsl<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::JperpUpdateTpsl<'info>>,
    mint_address: Pubkey,
    withdrawal_id: [u8; 32],
    size_usd_delta: u64,
    trigger_price: u64,
) -> Result<()> {
    let cfg = &ctx.accounts.config;
    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);

    // Claimant must be the ephemeral key committed at open time.
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

    emit!(JperpTpslUpdatedEvent {
        trigger_price,
        size_usd_delta,
        mint_address,
        relayer: ctx.accounts.relayer.key(),
        timestamp: Clock::get()?.unix_timestamp,
    });

    Ok(())
}

/// Create a market decrease (full or partial close) for an open position.
///
/// Calls `createDecreasePositionRequest2` with `Market` request type.
/// Jupiter's keeper executes the decrease and routes proceeds to the
/// executor's receiving ATA.
///
/// - Full close: `entire_position = true`, `size_usd_delta = 0`
/// - Partial: `entire_position = false`, `size_usd_delta` = USD to close
///
/// remaining_accounts: 16 accounts (see module docs).
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

    // Claimant must be the ephemeral key committed at open time.
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

    // receivingAccount = executor's USDC ATA (close proceeds land here). Bind it to
    // the canonical executor ATA so a relayer cannot redirect proceeds to an account
    // that jperp_reissue_notes can never recover from.
    let expected_executor_ata = get_associated_token_address(&executor_key, &mint_address);
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

    // Fund executor PDA for the new positionRequest rent (see jperp_open_position §14b).
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

    emit!(JperpCloseRequestEvent {
        entire_position,
        size_usd_delta,
        collateral_usd_delta,
        mint_address,
        relayer: ctx.accounts.relayer.key(),
        timestamp: Clock::get()?.unix_timestamp,
    });

    Ok(())
}

/// Transfer settled USDC from the executor PDA back into the vault,
/// then ZK-verify and mint new private notes (deposit circuit).
///
/// Called after a position decrease / TP / SL has been executed by Jupiter's keeper
/// and proceeds have arrived in the executor's USDC ATA.
///
/// The claimant must co-sign to prevent a malicious relayer from stealing proceeds.
/// `reissue_amount` must not exceed `jperp_slot.amount - jperp_slot.reissued`.
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

    let slot = &mut ctx.accounts.jperp_slot;
    let available = slot.amount
        .checked_sub(slot.reissued)
        .ok_or(error!(PrivacyError::ArithmeticOverflow))?;
    require!(reissue_amount <= available, PrivacyError::JperpSlotOverdraft);
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

    // Executor seeds are validated by the Accounts struct; sign the ATA→vault transfer with its bump.
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

    let expected_executor_ata = get_associated_token_address(&executor_key, &mint_address);
    require!(
        ctx.accounts.executor_token_account.key() == expected_executor_ata,
        PrivacyError::VaultTokenAccountNotATA
    );
    let expected_vault_ata = get_associated_token_address(&ctx.accounts.vault.key(), &mint_address);
    require!(
        ctx.accounts.vault_token_account.key() == expected_vault_ata,
        PrivacyError::VaultTokenAccountNotATA
    );

    // Verify executor ATA has enough to cover reissue
    let executor_ata_data = deserialize_token_account(
        &ctx.accounts.executor_token_account.to_account_info()
    )?;
    require!(
        executor_ata_data.amount >= reissue_amount,
        PrivacyError::InsufficientFundsForWithdrawal
    );

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

    emit!(JperpReissueEvent {
        reissue_amount,
        mint_address,
        timestamp: clock.unix_timestamp,
    });

    Ok(())
}

// ── Shared helpers ────────────────────────────────────────────────────────────

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

// ── Events ────────────────────────────────────────────────────────────────────

/// Emitted when a Jupiter Perps position request is submitted.
#[event]
pub struct JperpOpenPositionEvent {
    pub deposit_amount: u64,
    pub size_usd_delta: u64,
    /// 1 = Long, 2 = Short
    pub side: u8,
    pub mint_address: Pubkey,
    pub relayer: Pubkey,
    pub timestamp: i64,
}

/// Emitted when a TP or SL trigger request is created.
#[event]
pub struct JperpTpslSetEvent {
    pub trigger_price: u64,
    pub trigger_above_threshold: bool,
    pub size_usd_delta: u64,
    pub entire_position: bool,
    pub mint_address: Pubkey,
    pub relayer: Pubkey,
    pub timestamp: i64,
}

/// Emitted when a pending TP/SL trigger is updated.
#[event]
pub struct JperpTpslUpdatedEvent {
    pub trigger_price: u64,
    pub size_usd_delta: u64,
    pub mint_address: Pubkey,
    pub relayer: Pubkey,
    pub timestamp: i64,
}

/// Emitted when a market close/decrease request is submitted.
#[event]
pub struct JperpCloseRequestEvent {
    pub entire_position: bool,
    pub size_usd_delta: u64,
    pub collateral_usd_delta: u64,
    pub mint_address: Pubkey,
    pub relayer: Pubkey,
    pub timestamp: i64,
}

/// Emitted when settled proceeds are re-minted as private notes.
#[event]
pub struct JperpReissueEvent {
    pub reissue_amount: u64,
    pub mint_address: Pubkey,
    pub timestamp: i64,
}

/// Jupiter Prediction Market integration.
///
/// Jupiter's `CreateOrder` requires a co-signature from authority
/// `5uFXJogUEqBTsVT8AcfuWbC9ZFM1tSzTFJ3eKVeB14yi` (obtainable only via REST API),
/// making direct CPI impossible.  Instead we fund an ephemeral keypair via ZK withdrawal
/// (`prediction_open`) and sweep proceeds back via ZK deposit (`prediction_reissue`).
///
/// Ephemeral key derivation (must match client-side):
///   `seed = sha256("prediction_ephemeral" || spending_key || nonce_le64)`
///   `ephemeral_keypair = nacl.sign.keyPair.fromSeed(seed)`

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::Instruction,
    program::invoke,
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

/// SOL sent to the ephemeral wallet to cover Jupiter API tx fees (~3 txs with priority).
pub const PREDICTION_EPHEMERAL_SOL_FUNDING: u64 = 5_000_000; // 0.005 SOL

// ── Events ────────────────────────────────────────────────────────────────────

#[event]
pub struct PredictionOpenEvent {
    pub deposit_amount: u64,
    pub mint_address: Pubkey,
    pub claimant: Pubkey,
    pub relayer: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct PredictionReissueEvent {
    pub reissue_amount: u64,
    pub mint_address: Pubkey,
    pub claimant: Pubkey,
    pub relayer: Pubkey,
    pub timestamp: i64,
}

// ── Instruction handlers ──────────────────────────────────────────────────────

/// ZK withdrawal → ephemeral wallet funded.
///
/// `ext_data.recipient` must equal `claimant` (binds the proof to this ephemeral key).
/// The ephemeral USDC ATA must already exist before calling (create idempotently in the
/// same tx to avoid adding AssociatedTokenProgram as a dependency here).
#[allow(clippy::too_many_arguments)]
pub fn prediction_open<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::PredictionOpen<'info>>,
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
    _withdrawal_id: [u8; 32],
    deadline: i64,
    ext_data: ExtData,
    proof: TransactionProof,
    note_ciphers: Option<NoteCiphers>,
    sol_funding: u64,
) -> Result<()> {
    let (note0_epk, note0_enc, note0_vt, note1_epk, note1_enc, note1_vt) = match note_ciphers {
        Some(c) => (
            c.note0_ephemeral_key, c.note0_encrypted, c.note0_view_tag,
            c.note1_ephemeral_key, c.note1_encrypted, c.note1_view_tag,
        ),
        None => ([0u8; 32], [0u8; 80], 0u8, [0u8; 32], [0u8; 80], 0u8),
    };

    let cfg = &mut ctx.accounts.config;

    // ── 1. Pool match ─────────────────────────────────────────────────────────
    require_keys_eq!(cfg.mint_address, mint_address, PrivacyError::InvalidMintAddress);

    // ── 2. Tree bounds ────────────────────────────────────────────────────────
    require!(input_tree_id < cfg.num_trees, PrivacyError::InvalidTreeId);
    require!(output_tree_id < cfg.num_trees, PrivacyError::InvalidTreeId);
    require!(deposit_amount > 0, PrivacyError::InvalidPublicAmount);

    // ── 3. Relayer and deadline ───────────────────────────────────────────────
    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require_keys_eq!(ctx.accounts.relayer.key(), ext_data.relayer, PrivacyError::RelayerMismatch);
    let clock = Clock::get()?;
    require!(clock.unix_timestamp <= deadline, PrivacyError::DeadlineExpired);

    // ── 4. Recipient must be the ephemeral wallet (claimant) ─────────────────
    require_keys_eq!(ext_data.recipient, claimant, PrivacyError::PredictionRecipientMustBeClaimant);
    require_keys_eq!(claimant, ext_data.claimant, PrivacyError::InvalidClaimant);

    // ── 5. Nullifier / commitment sanity ─────────────────────────────────────
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

    // ── 6. ext_data hash ──────────────────────────────────────────────────────
    let computed_ext_hash = ext_data.hash()?;
    require!(computed_ext_hash == ext_data_hash, PrivacyError::InvalidExtData);

    // ── 7. Vault ATA and balance check ────────────────────────────────────────
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

    // ── 7a. Relayer fee upper-bound (mirrors transact's max_fee cap) ──────────
    // The fee is paid from the vault on top of deposit_amount and is bound into
    // the ZK proof below (public_amount covers deposit_amount + fee). Without an
    // upper cap, a relayer could set ext_data.fee to drain the entire vault. The
    // fee is capped at fee_bps (+ margin) of deposit_amount, exactly as a normal
    // withdrawal. fee == 0 remains valid (no minimum is imposed here).
    let max_fee_u128 = (deposit_amount as u128)
        .checked_mul(cfg.fee_bps as u128)
        .ok_or(error!(PrivacyError::ArithmeticOverflow))? / 10_000;
    require!(max_fee_u128 <= u64::MAX as u128, PrivacyError::ExcessiveFee);
    let max_fee_with_margin = (max_fee_u128 as u64)
        .checked_mul((10_000u64).saturating_add(cfg.fee_error_margin_bps as u64))
        .map(|x| x / 10_000)
        .unwrap_or(max_fee_u128 as u64);
    require!(ext_data.fee <= max_fee_with_margin, PrivacyError::InvalidFeeAmount);

    // ── 8. ZK proof (withdrawal: public_amount negative) ─────────────────────
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

    // ── 9. Known root ─────────────────────────────────────────────────────────
    {
        let input_tree = ctx.accounts.input_tree.load()?;
        require!(MerkleTree::is_known_root(&*input_tree, root), PrivacyError::UnknownRoot);
    }

    // ── 10. Nullifiers not already spent ─────────────────────────────────────
    require!(!ctx.accounts.nullifier_marker_0.is_spent, PrivacyError::NullifierAlreadyUsed);
    require!(!ctx.accounts.nullifier_marker_1.is_spent, PrivacyError::NullifierAlreadyUsed);

    // ── 11. Mark nullifiers spent ─────────────────────────────────────────────
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

    // ── 12. Insert change commitments into output tree ────────────────────────
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

    // ── 13. TVL decrease ──────────────────────────────────────────────────────
    cfg.total_tvl = cfg.total_tvl
        .checked_sub(total_outflow)
        .ok_or(error!(PrivacyError::ArithmeticOverflow))?;

    // ── 13a. Record the per-deposit slot (pairs open↔reissue, binds claimant) ─
    let slot = &mut ctx.accounts.prediction_slot;
    slot.amount = deposit_amount;
    slot.reissued = 0;
    slot.claimant_pubkey = claimant;
    slot.bump = ctx.bumps.prediction_slot;

    // ── 14. Transfer relayer fee: vault → relayer ATA ─────────────────────────
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

    // ── 15. Transfer USDC: vault → ephemeral ATA ──────────────────────────────
    let expected_ephemeral_ata = get_associated_token_address(&claimant, &mint_address);
    require!(
        ctx.accounts.ephemeral_token_account.key() == expected_ephemeral_ata,
        PrivacyError::VaultTokenAccountNotATA
    );

    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.vault_token_account.to_account_info(),
                to: ctx.accounts.ephemeral_token_account.to_account_info(),
                authority: ctx.accounts.vault.to_account_info(),
            },
            &[vault_seeds],
        ),
        deposit_amount,
    )?;

    // ── 16. Fund ephemeral wallet with SOL ────────────────────────────────────
    let sol_to_send = sol_funding.min(PREDICTION_EPHEMERAL_SOL_FUNDING);
    if sol_to_send > 0 {
        invoke(
            &system_instruction::transfer(
                &ctx.accounts.relayer.key(),
                &claimant,
                sol_to_send,
            ),
            &[
                ctx.accounts.relayer.to_account_info(),
                ctx.accounts.ephemeral_wallet.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;
    }

    // ── 17. Emit events ───────────────────────────────────────────────────────
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
    emit!(PredictionOpenEvent {
        deposit_amount,
        mint_address,
        claimant,
        relayer: ctx.accounts.relayer.key(),
        timestamp: clock.unix_timestamp,
    });

    Ok(())
}

/// Sweeps settled prediction proceeds from the ephemeral wallet back into the pool.
///
/// `claimant` (the ephemeral keypair) **must co-sign** — it is the ATA authority.
/// This eliminates relayer theft risk without a slot-cap PDA.
/// Uses the deposit ZK circuit: `public_amount > 0`, dummy zero nullifiers for inputs.
#[allow(clippy::too_many_arguments)]
pub fn prediction_reissue<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::PredictionReissue<'info>>,
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
    _withdrawal_id: [u8; 32],
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

    // ── 1. Pool match ─────────────────────────────────────────────────────────
    require_keys_eq!(cfg.mint_address, mint_address, PrivacyError::InvalidMintAddress);

    // ── 2. Tree bounds ────────────────────────────────────────────────────────
    require!(input_tree_id < cfg.num_trees, PrivacyError::InvalidTreeId);
    require!(output_tree_id < cfg.num_trees, PrivacyError::InvalidTreeId);
    require!(reissue_amount > 0, PrivacyError::InvalidPublicAmount);

    // ── 3. Relayer and deadline ───────────────────────────────────────────────
    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require_keys_eq!(ctx.accounts.relayer.key(), ext_data.relayer, PrivacyError::RelayerMismatch);
    let clock = Clock::get()?;
    require!(clock.unix_timestamp <= deadline, PrivacyError::DeadlineExpired);

    // ── 4. Commitment / nullifier sanity ─────────────────────────────────────
    let input_nullifiers = [input_nullifier_0, input_nullifier_1];
    let output_commitments = [output_commitment_0, output_commitment_1];
    let zero = [0u8; 32];
    require!(input_nullifiers[0] != input_nullifiers[1], PrivacyError::DuplicateNullifiers);
    require!(output_commitments[0] != output_commitments[1], PrivacyError::DuplicateCommitments);
    require!(
        output_commitments[0] != zero && output_commitments[1] != zero,
        PrivacyError::ZeroCommitment
    );

    // ── 5. ext_data hash ──────────────────────────────────────────────────────
    let computed_ext_hash = ext_data.hash()?;
    require!(computed_ext_hash == ext_data_hash, PrivacyError::InvalidExtData);

    // ── 6. ZK proof (deposit: public_amount positive) ─────────────────────────
    let public_inputs = TransactionPublicInputs {
        root,
        public_amount: reissue_amount as i64,
        ext_data_hash,
        mint_address,
        input_nullifiers,
        output_commitments,
    };
    verify_transaction_groth16(proof, &public_inputs)?;

    // ── 7. Known root ─────────────────────────────────────────────────────────
    {
        let input_tree = ctx.accounts.input_tree.load()?;
        require!(MerkleTree::is_known_root(&*input_tree, root), PrivacyError::UnknownRoot);
    }

    // ── 7a. Slot reconciliation (validated manually, post-proof) ──────────────
    // The slot PDA address is enforced by the Accounts seeds; here we require it to
    // actually exist (created only by `prediction_open` — can't reissue a non-existent
    // deposit) and bind the committed claimant. No profit cap — see jperp_reissue_notes.
    // Checked after the ZK proof so cheaper validations and the proof guard run first.
    {
        let slot_ai = ctx.accounts.prediction_slot.to_account_info();
        require_keys_eq!(*slot_ai.owner, crate::ID, PrivacyError::InvalidClaimant);
        let mut data = slot_ai.try_borrow_mut_data()?;
        let mut slot = crate::PredictionSlot::try_deserialize(&mut &data[..])?;
        require_keys_eq!(
            ctx.accounts.claimant.key(),
            slot.claimant_pubkey,
            PrivacyError::InvalidClaimant
        );
        slot.reissued = slot.reissued
            .checked_add(reissue_amount)
            .ok_or(error!(PrivacyError::ArithmeticOverflow))?;
        slot.try_serialize(&mut &mut data[..])?;
    }

    // ── 8. Validate ephemeral ATA and vault ATA ───────────────────────────────
    let claimant_key = ctx.accounts.claimant.key();
    let expected_ephemeral_ata = get_associated_token_address(&claimant_key, &mint_address);
    require!(
        ctx.accounts.ephemeral_token_account.key() == expected_ephemeral_ata,
        PrivacyError::VaultTokenAccountNotATA
    );
    let expected_vault_ata = get_associated_token_address(&ctx.accounts.vault.key(), &mint_address);
    require!(
        ctx.accounts.vault_token_account.key() == expected_vault_ata,
        PrivacyError::VaultTokenAccountNotATA
    );

    // ── 9. Ephemeral ATA balance check ────────────────────────────────────────
    let ephemeral_ata_data = deserialize_token_account(
        &ctx.accounts.ephemeral_token_account.to_account_info()
    )?;
    require!(
        ephemeral_ata_data.amount >= reissue_amount,
        PrivacyError::InsufficientFundsForWithdrawal
    );

    // ── 10. Transfer USDC: ephemeral ATA → vault ATA ─────────────────────────
    // claimant is a Signer and the ATA authority — no invoke_signed needed.
    token::transfer(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.ephemeral_token_account.to_account_info(),
                to: ctx.accounts.vault_token_account.to_account_info(),
                authority: ctx.accounts.claimant.to_account_info(),
            },
        ),
        reissue_amount,
    )?;

    // ── 11. Insert output commitments into tree ───────────────────────────────
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

    // ── 12. TVL increase ──────────────────────────────────────────────────────
    cfg.total_tvl = cfg.total_tvl
        .checked_add(reissue_amount)
        .ok_or(error!(PrivacyError::ArithmeticOverflow))?;

    // ── 13. Emit events ───────────────────────────────────────────────────────
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
    emit!(PredictionReissueEvent {
        reissue_amount,
        mint_address,
        claimant: claimant_key,
        relayer: ctx.accounts.relayer.key(),
        timestamp: clock.unix_timestamp,
    });

    Ok(())
}

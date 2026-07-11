/// Phoenix Eternal Integration for Veilo Privacy Pool
///
/// Phoenix Eternal (program: EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih) is a
/// USDC-collateralised perpetual futures DEX on Solana. This module lets the pool
/// vault PDA act as a Phoenix trader, enabling **private perps trading**:
///
/// 1. `phoenix_deposit_from_pool` — ZK-verified withdrawal of USDC private notes
///    that routes funds directly into the vault's Phoenix trader account (atomic).
///
/// 2. `phoenix_place_order` — Relayer-submitted market or limit order placement
///    signed by the vault PDA (no ZK proof needed).
///
/// 3. `phoenix_cancel_orders` — Cancel all open orders for the vault's trader.
///
/// 4. `phoenix_queue_withdraw` — Queue a Phoenix withdrawal back to the vault's
///    USDC ATA. Once `consumeWithdrawQueue` is cranked (permissionless, on-chain),
///    the USDC is returned. Users then call the standard `transact` deposit to
///    re-mint private notes.
///
/// Architecture:
/// - The pool vault PDA (`["privacy_vault_v3", mint]`) is registered as the
///   Phoenix trader wallet. All Phoenix CPIs are signed with its PDA seeds.
/// - Phoenix trader PDA = `["trader", vault_key, 0u8, 0u8]` on Phoenix program.
/// - Only USDC pools are supported (Phoenix only accepts USDC collateral).
/// - Phoenix-specific accounts are passed via `remaining_accounts` to keep
///   named account counts within Anchor/Solana limits.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{ instruction::Instruction, program::invoke_signed };
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

// Phoenix Eternal constants
/// Phoenix Eternal program ID (perpetual futures DEX)
pub const PHOENIX_PROGRAM_ID: Pubkey = pubkey!("EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih");

/// Phoenix PDA seed — log authority: `["log"]`
pub const PHOENIX_LOG_SEED: &[u8] = b"log";

/// Phoenix PDA seed — global configuration: `["global"]`
pub const PHOENIX_GLOBAL_SEED: &[u8] = b"global";

/// Phoenix PDA seed prefix — trader accounts: `["trader", wallet, pda_idx, sub_idx]`
pub const PHOENIX_TRADER_SEED: &[u8] = b"trader";

/// USDC mainnet mint — used on mainnet and localnet (localnet clones mainnet USDC).
#[cfg(not(feature = "devnet"))]
pub const PHOENIX_REQUIRED_MINT: Pubkey = pubkey!("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

/// USDC devnet mint (Circle devnet only — localnet uses mainnet USDC clone)
#[cfg(feature = "devnet")]
pub const PHOENIX_REQUIRED_MINT: Pubkey = pubkey!("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU");

// EMBER Protocol constants
/// EMBER protocol program — wraps USDC ↔ PhUSD (1:1 synthetic collateral for Phoenix Eternal)
pub const EMBER_PROGRAM_ID: Pubkey = pubkey!("EMBERpYNE6ehWmXymZZS2skiFmCa9V5dp14e1iduM5qy");

/// PhUSD mint — Phoenix Eternal's canonical collateral token (minted/burned by EMBER)
pub const PHUSD_MINT: Pubkey = pubkey!("PhUsd11YkbjSaWjFncfAAmatntsjx3MgDR9B6g1ks3A");

/// EMBER PDA that controls PhUSD mint/burn authority
pub const PHUSD_MINT_AUTHORITY: Pubkey = pubkey!("6ur7v6AXNpnHeEb6xuk7PyezvZ1i5GrgYyWZkNCpzbRz");

/// EMBER USDC reserve — holds the USDC backing the PhUSD supply
pub const EMBER_USDC_RESERVE: Pubkey = pubkey!("FKcEb4TdPDTRuMnQDpSEPQBcrm15S73xiUD6Qf8ZLUkq");

// Discriminator helper

/// Compute an Anchor instruction discriminator: `sha256("global:<name>")[0..8]`
///
/// Both Phoenix Eternal and EMBER use the standard Anchor discriminator scheme.
fn phoenix_disc(name: &str) -> [u8; 8] {
    use sha2::{ Digest, Sha256 };
    let preimage = format!("global:{}", name);
    let hash = Sha256::digest(preimage.as_bytes());
    hash[..8].try_into().expect("sha256 output is 32 bytes")
}

/// Compute an Anchor instruction discriminator for EMBER instructions.
/// EMBER uses the same `sha256("global:<name>")[0..8]` scheme as Phoenix.
#[inline(always)]
fn ember_disc(name: &str) -> [u8; 8] {
    phoenix_disc(name)
}

// ─── Instruction handlers ─────────────────────────────────────────────────────

/// **ZK-verified USDC withdrawal → Phoenix `depositFunds` CPI** (atomic).
///
/// Consumes private USDC notes from the pool and deposits the exact amount
/// into the vault's Phoenix Eternal trader account in the same transaction.
///
/// ZK constraints:
/// - `public_amount` = `−deposit_amount` (withdrawal from pool)
/// - `ext_data.recipient` **must** equal the vault PDA key (committed in proof)
///   — this ensures the proof cannot be reused to withdraw to an arbitrary address.
///
/// `remaining_accounts` layout (13 accounts):
/// ```
/// [0]  phoenixProgram            — readonly; validated == PHOENIX_PROGRAM_ID
/// [1]  phoenixLogAuthority       — PDA ["log"] on Phoenix; readonly
/// [2]  globalConfiguration       — PDA ["global"] on Phoenix; writable
/// [3]  phoenixTraderAccount      — PDA ["trader", vault, 0, 0] on Phoenix; writable
/// [4]  phoenixGlobalVault        — Phoenix's PhUSD token account; writable
/// [5]  phoenixGlobalTraderIndex  — writable
/// [6]  phoenixActiveTraderBuffer — writable
/// [7]  emberProgram              — EMBER_PROGRAM_ID; readonly; validated
/// [8]  phUsdMintAuthPda          — PHUSD_MINT_AUTHORITY; readonly
/// [9]  phUsdMint                 — PHUSD_MINT; writable (supply increases on EMBER wrap)
/// [10] vaultPhUsdAta             — vault's PhUSD ATA; writable (EMBER conduit → Phoenix)
/// [11] emberUsdcReserve          — EMBER_USDC_RESERVE; writable (receives USDC)
/// [12] usdcMint                  — PHOENIX_REQUIRED_MINT; readonly (AccountInfo for EMBER CPI)
/// ```
/// `vault_token_account` (named) = vault's USDC ATA (source of USDC sent to EMBER).
#[allow(clippy::too_many_arguments)]
pub fn phoenix_deposit_from_pool<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::PhoenixDepositFromPool<'info>>,
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
    note_ciphers: Option<NoteCiphers>
) -> Result<()> {
    let (note0_epk, note0_enc, note0_vt, note1_epk, note1_enc, note1_vt) = match note_ciphers {
        Some(c) =>
            (
                c.note0_ephemeral_key,
                c.note0_encrypted,
                c.note0_view_tag,
                c.note1_ephemeral_key,
                c.note1_encrypted,
                c.note1_view_tag,
            ),
        None => ([0u8; 32], [0u8; 80], 0u8, [0u8; 32], [0u8; 80], 0u8),
    };

    let cfg = &mut ctx.accounts.config;

    // ── 1. Phoenix-specific validation ────────────────────────────────────────
    // Only USDC pools can interface with Phoenix Eternal
    require_keys_eq!(mint_address, PHOENIX_REQUIRED_MINT, PrivacyError::PhoenixInvalidPool);
    require_keys_eq!(cfg.mint_address, mint_address, PrivacyError::InvalidMintAddress);
    require!(deposit_amount > 0, PrivacyError::InvalidPublicAmount);

    // ── 2. Tree ID bounds ─────────────────────────────────────────────────────
    require!(input_tree_id < cfg.num_trees, PrivacyError::InvalidTreeId);
    require!(output_tree_id < cfg.num_trees, PrivacyError::InvalidTreeId);

    // ── 3. Relayer and deadline ───────────────────────────────────────────────
    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require_keys_eq!(ctx.accounts.relayer.key(), ext_data.relayer, PrivacyError::RelayerMismatch);
    let clock = Clock::get()?;
    require!(clock.unix_timestamp <= deadline, PrivacyError::DeadlineExpired);

    // ── 4. Recipient must be executor PDA (ZK proof binds destination) ───────
    require_keys_eq!(
        ext_data.recipient,
        ctx.accounts.executor.key(),
        PrivacyError::PhoenixRecipientMustBeVault
    );

    // ── 4a. Claimant must match ext_data (ZK proof binds claimant) ────────────
    require_keys_eq!(claimant, ext_data.claimant, PrivacyError::InvalidClaimant);

    // ── 5. Nullifier sanity ───────────────────────────────────────────────────
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

    // ── 6. ext_data hash ─────────────────────────────────────────────────────
    let computed_ext_hash = ext_data.hash()?;
    require!(computed_ext_hash == ext_data_hash, PrivacyError::InvalidExtData);

    // ── 7. Vault USDC ATA check ───────────────────────────────────────────────
    let expected_ata = get_associated_token_address(&ctx.accounts.vault.key(), &mint_address);
    require!(
        ctx.accounts.vault_token_account.key() == expected_ata,
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
    // upper cap, a relayer could set ext_data.fee too high. The fee is capped at
    // fee_bps (+ margin) of deposit_amount, exactly as a normal
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

    // ── 8. ZK proof verification ──────────────────────────────────────────────
    // public_amount is NEGATIVE (pool is losing USDC): circuit: sumIns + pubAmt = sumOuts.
    // It binds the FULL outflow (deposit_amount + fee) so the consumed notes burn the
    // fee too — the fee can no longer be drawn from other users' collateral.
    require!(total_outflow <= i64::MAX as u64, PrivacyError::ArithmeticOverflow);
    let public_amount_signed = -(total_outflow as i64);
    let public_inputs = TransactionPublicInputs {
        root,
        public_amount: public_amount_signed,
        ext_data_hash,
        mint_address,
        input_nullifiers,
        output_commitments,
    };
    verify_transaction_groth16(proof, &public_inputs)?;

    // ── 9. Known root check ───────────────────────────────────────────────────
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
        input_tree_id
    )?;
    mark_nullifier_spent(
        &mut ctx.accounts.nullifier_marker_1,
        &mut ctx.accounts.nullifiers,
        input_nullifiers[1],
        ctx.bumps.nullifier_marker_1,
        mint_address,
        input_tree_id
    )?;

    // ── 12. Insert commitments and emit events BEFORE the EMBER/Phoenix CPIs ──
    // EMBER + Phoenix generate enough log data to hit Solana's truncation limit;
    // events emitted after them would be silently dropped (same as positions.rs).
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

    let timestamp = clock.unix_timestamp;

    emit!(NullifierSpent {
        nullifier: input_nullifiers[0],
        timestamp,
        mint_address,
        tree_id: input_tree_id,
    });
    emit!(NullifierSpent {
        nullifier: input_nullifiers[1],
        timestamp,
        mint_address,
        tree_id: input_tree_id,
    });
    emit!(CommitmentEvent {
        commitment: output_commitments[0],
        leaf_index: leaf_index_0,
        new_root,
        timestamp,
        mint_address,
        tree_id: output_tree_id,
        ephemeral_public_key: note0_epk,
        encrypted_blob: note0_enc,
        view_tag: note0_vt,
    });
    emit!(CommitmentEvent {
        commitment: output_commitments[1],
        leaf_index: leaf_index_1,
        new_root,
        timestamp,
        mint_address,
        tree_id: output_tree_id,
        ephemeral_public_key: note1_epk,
        encrypted_blob: note1_enc,
        view_tag: note1_vt,
    });
    emit!(PhoenixDepositEvent {
        deposit_amount,
        relayer_fee: ext_data.fee,
        mint_address,
        timestamp,
    });

    // ── 13. CPI: EMBER wrap (USDC → PhUSD) + Phoenix depositFunds ────────────
    // Phoenix Eternal uses PhUSD as canonical collateral, not USDC. EMBER (EMBERpYNE6...)
    // wraps USDC 1:1 into PhUSD before the Phoenix deposit in the same atomic transaction.
    //
    // EMBER deposit account layout:
    //   [0] traderWallet (signer)       — vault PDA
    //   [1] phUsdMintAuthPda (readonly) — remaining[8]
    //   [2] usdcMint (readonly)         — remaining[12]
    //   [3] phUsdMint (writable)        — remaining[9]  (supply increases via mint_to)
    //   [4] traderUsdcAta (writable)    — vault_token_account (source)
    //   [5] traderPhUsdAta (writable)   — remaining[10] (intermediate PhUSD ATA)
    //   [6] emberUsdcReserve (writable) — remaining[11]
    //   [7] tokenProgram (readonly)
    //
    // Phoenix depositFunds account layout (IDL):
    //   [0] phoenixProgram (readonly)
    //   [1] phoenixLogAuthority (readonly)
    //   [2] globalConfiguration (writable)
    //   [3] traderWallet (signer)          — vault PDA
    //   [4] traderTokenAccount (writable)  — remaining[10] (vault PhUSD ATA, not USDC)
    //   [5] traderAccount (writable)       — remaining[3]
    //   [6] globalVault (writable)         — remaining[4] (Phoenix's PhUSD vault)
    //   [7] tokenProgram (readonly)
    //   [8] globalTraderIndex (writable)   — remaining[5]
    //   [9] activeTraderBuffer (writable)  — remaining[6]
    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 13, PrivacyError::PhoenixInvalidAccounts);
    require_keys_eq!(remaining[0].key(), PHOENIX_PROGRAM_ID, PrivacyError::InvalidSwapProgram);
    require_keys_eq!(remaining[7].key(), EMBER_PROGRAM_ID, PrivacyError::InvalidSwapProgram);
    // Pin the EMBER/PhUSD system accounts to their canonical addresses.
    require_keys_eq!(remaining[8].key(), PHUSD_MINT_AUTHORITY, PrivacyError::PhoenixInvalidAccounts);
    require_keys_eq!(remaining[9].key(), PHUSD_MINT, PrivacyError::PhoenixInvalidAccounts);
    require_keys_eq!(remaining[11].key(), EMBER_USDC_RESERVE, PrivacyError::PhoenixInvalidAccounts);

    let _vault_key = ctx.accounts.vault.key();
    let vault_seeds: &[&[u8]] = &[b"privacy_vault_v3", mint_address.as_ref(), &[cfg.vault_bump]];

    let executor_key = ctx.accounts.executor.key();
    let executor_bump = ctx.bumps.executor;
    let executor_seeds: &[&[u8]] = &[
        b"phoenix_executor",
        mint_address.as_ref(),
        claimant.as_ref(),
        &[executor_bump],
    ];

    // Validate executor_token_account is the executor's canonical USDC ATA
    let expected_executor_usdc_ata = get_associated_token_address(&executor_key, &mint_address);
    require!(
        ctx.accounts.executor_token_account.key() == expected_executor_usdc_ata,
        PrivacyError::VaultTokenAccountNotATA
    );

    // Validate remaining[10] is the executor's canonical PhUSD ATA
    let expected_phusd_ata = get_associated_token_address(&executor_key, &PHUSD_MINT);
    require_keys_eq!(
        remaining[10].key(),
        expected_phusd_ata,
        PrivacyError::VaultTokenAccountNotATA
    );

    // ── 12a. Vault → Executor: transfer USDC ─────────────────────────────────
    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.vault_token_account.to_account_info(),
                to: ctx.accounts.executor_token_account.to_account_info(),
                authority: ctx.accounts.vault.to_account_info(),
            },
            &[vault_seeds]
        ),
        deposit_amount
    )?;

    // ── 12b. EMBER deposit: executor USDC → executor PhUSD ───────────────────
    let mut ember_wrap_data = ember_disc("deposit").to_vec();
    ember_wrap_data.extend_from_slice(&deposit_amount.to_le_bytes());

    let ember_wrap_metas = vec![
        AccountMeta::new_readonly(executor_key, true), // [0] traderWallet (executor signs)
        AccountMeta::new_readonly(remaining[8].key(), false), // [1] phUsdMintAuthPda
        AccountMeta::new_readonly(remaining[12].key(), false), // [2] usdcMint
        AccountMeta::new(remaining[9].key(), false), // [3] phUsdMint (writable)
        AccountMeta::new(ctx.accounts.executor_token_account.key(), false), // [4] traderUsdcAta
        AccountMeta::new(remaining[10].key(), false), // [5] traderPhUsdAta (executor PhUSD ATA)
        AccountMeta::new(remaining[11].key(), false), // [6] emberUsdcReserve
        AccountMeta::new_readonly(ctx.accounts.token_program.key(), false) // [7] tokenProgram
    ];

    let ember_wrap_ix = Instruction {
        program_id: EMBER_PROGRAM_ID,
        accounts: ember_wrap_metas,
        data: ember_wrap_data,
    };

    let ember_wrap_cpi_infos = vec![
        ctx.accounts.executor.to_account_info(), // traderWallet (executor)
        remaining[8].to_account_info(), // phUsdMintAuthPda
        remaining[12].to_account_info(), // usdcMint
        remaining[9].to_account_info(), // phUsdMint
        ctx.accounts.executor_token_account.to_account_info(), // traderUsdcAta
        remaining[10].to_account_info(), // traderPhUsdAta (executor PhUSD ATA)
        remaining[11].to_account_info(), // emberUsdcReserve
        ctx.accounts.token_program.to_account_info(), // tokenProgram
        remaining[7].to_account_info() // emberProgram (must be in list)
    ];

    invoke_signed(&ember_wrap_ix, &ember_wrap_cpi_infos, &[executor_seeds])?;

    // ── 12c. Phoenix depositFunds: executor PhUSD ATA → globalVault ──────────
    let mut ix_data = phoenix_disc("deposit_funds").to_vec();
    ix_data.extend_from_slice(&deposit_amount.to_le_bytes());

    let phoenix_account_metas = vec![
        AccountMeta::new_readonly(remaining[0].key(), false), // phoenixProgram
        AccountMeta::new_readonly(remaining[1].key(), false), // phoenixLogAuthority
        AccountMeta::new(remaining[2].key(), false), // globalConfiguration
        AccountMeta::new_readonly(executor_key, true), // traderWallet (executor signs)
        AccountMeta::new(remaining[10].key(), false), // traderTokenAccount (executor PhUSD ATA)
        AccountMeta::new(remaining[3].key(), false), // traderAccount
        AccountMeta::new(remaining[4].key(), false), // globalVault (PhUSD)
        AccountMeta::new_readonly(ctx.accounts.token_program.key(), false), // tokenProgram
        AccountMeta::new(remaining[5].key(), false), // globalTraderIndex
        AccountMeta::new(remaining[6].key(), false) // activeTraderBuffer
    ];

    let deposit_ix = Instruction {
        program_id: PHOENIX_PROGRAM_ID,
        accounts: phoenix_account_metas,
        data: ix_data,
    };

    let cpi_infos = vec![
        remaining[1].to_account_info(), // phoenixLogAuthority
        remaining[2].to_account_info(), // globalConfiguration
        ctx.accounts.executor.to_account_info(), // traderWallet (executor)
        remaining[10].to_account_info(), // traderTokenAccount (executor PhUSD ATA)
        remaining[3].to_account_info(), // traderAccount
        remaining[4].to_account_info(), // globalVault (PhUSD)
        ctx.accounts.token_program.to_account_info(), // tokenProgram
        remaining[5].to_account_info(), // globalTraderIndex
        remaining[6].to_account_info(), // activeTraderBuffer
        remaining[0].to_account_info() // phoenixProgram (must be in list)
    ];

    invoke_signed(&deposit_ix, &cpi_infos, &[executor_seeds])?;

    // ── 13. Pay relayer fee from vault ATA ────────────────────────────────────
    if ext_data.fee > 0 {
        let relayer_token_data = deserialize_token_account(
            &ctx.accounts.relayer_token_account.to_account_info()
        )?;
        require_keys_eq!(relayer_token_data.mint, mint_address, PrivacyError::InvalidMintAddress);
        require_keys_eq!(
            relayer_token_data.owner,
            ext_data.relayer,
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
                &[vault_seeds]
            ),
            ext_data.fee
        )?;
    }

    // ── 14. Update TVL (USDC left the vault) ──────────────────────────────────
    cfg.total_tvl = cfg.total_tvl
        .checked_sub(total_outflow)
        .ok_or(error!(PrivacyError::ArithmeticOverflow))?;

    // ── 15. Initialize the per-deposit slot ───────────────────────────────────
    // Records the deposited amount and claim key so the exit flow can enforce
    // per-user withdrawal caps and prevent relayer theft.
    // `claimant_pubkey` comes from `ext_data.claimant`, which is committed to by
    // the Groth16 proof via `ext_data_hash`.  A relayer cannot substitute their
    // own key without invalidating the proof (AUDIT-005 fix).
    let slot = &mut ctx.accounts.phoenix_slot;
    slot.bump = ctx.bumps.phoenix_slot;
    slot.amount = deposit_amount;
    slot.withdrawn = 0;
    slot.claimant_pubkey = ext_data.claimant;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────

/// **Place a market or limit order on Phoenix using the vault's trader account.**
///
/// The caller supplies `order_data` — the full Anchor-encoded instruction bytes
/// (discriminator + borsh-serialised `OrderPacket`). Only `placeMarketOrder`
/// and `placeLimitOrder` discriminators are accepted.
///
/// No ZK proof is required. The relayer is responsible for constructing the
/// correct order packet off-chain and signing the transaction.
///
/// `remaining_accounts` layout (9 accounts):
/// ```
/// [0] phoenixProgram            — readonly; validated == PHOENIX_PROGRAM_ID
/// [1] phoenixLogAuthority       — PDA ["log"] on Phoenix; readonly
/// [2] globalConfiguration       — PDA ["global"] on Phoenix; writable
/// [3] phoenixTraderAccount      — PDA ["trader", vault, 0, 0]; writable
/// [4] perpAssetMap              — writable
/// [5] phoenixGlobalTraderIndex  — writable
/// [6] phoenixActiveTraderBuffer — writable
/// [7] orderbook                 — writable
/// [8] splines                   — writable
/// ```
pub fn phoenix_place_order<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::PhoenixPlaceOrder<'info>>,
    mint_address: Pubkey,
    claimant: Pubkey,
    order_data: Vec<u8>,
    // When Some(amount), a TransferCollateral (cross → isolated) CPI is executed
    // atomically before the order. The first 8 remaining_accounts must then be
    // the transfer accounts; the following 9 are the order accounts.
    // When None, only the 9 order accounts are required.
    transfer_amount: Option<u64>
) -> Result<()> {
    let cfg = &ctx.accounts.config;

    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require_keys_eq!(mint_address, PHOENIX_REQUIRED_MINT, PrivacyError::PhoenixInvalidPool);

    // Validate discriminator — only market or limit orders are accepted.
    require!(order_data.len() >= 8, PrivacyError::PhoenixInvalidOrderData);
    let disc_bytes: [u8; 8] = order_data[..8].try_into().unwrap();
    let market_disc = phoenix_disc("place_market_order");
    let limit_disc = phoenix_disc("place_limit_order");
    require!(
        disc_bytes == market_disc || disc_bytes == limit_disc,
        PrivacyError::PhoenixInvalidOrderData
    );

    let executor_key = ctx.accounts.executor.key();
    let executor_bump = ctx.bumps.executor;
    let executor_seeds: &[&[u8]] = &[
        b"phoenix_executor",
        mint_address.as_ref(),
        claimant.as_ref(),
        &[executor_bump],
    ];

    let remaining = ctx.remaining_accounts;

    // ── Optional pre-order collateral transfer ────────────────────────────
    // remaining_accounts layout when transfer_amount is Some:
    //   [0..8]  transferCollateral accounts (see below)
    //   [8..17] placeMarketOrder / placeLimitOrder accounts
    //
    // transferCollateral layout (Phoenix IDL):
    //   0. phoenixProgram      (readonly)
    //   1. logAuthority        (readonly)
    //   2. globalConfiguration (readonly — differs from place_order!)
    //   3. srcTraderAccount    (writable)
    //   4. dstTraderAccount    (writable)
    //   5. perpAssetMap        (readonly — differs from place_order!)
    //   6. globalTraderIndex   (writable)
    //   7. activeTraderBuffer  (writable)
    //   traderWallet           ← executor PDA (ctx.accounts.executor)
    let order_offset: usize = if let Some(amount) = transfer_amount {
        require!(amount > 0, PrivacyError::InvalidPublicAmount);
        require!(remaining.len() >= 17, PrivacyError::PhoenixInvalidAccounts);
        require_keys_eq!(remaining[0].key(), PHOENIX_PROGRAM_ID, PrivacyError::InvalidSwapProgram);

        let transfer_metas = vec![
            AccountMeta::new_readonly(remaining[0].key(), false), // phoenixProgram
            AccountMeta::new_readonly(remaining[1].key(), false), // logAuthority
            AccountMeta::new_readonly(remaining[2].key(), false), // globalConfig (readonly)
            AccountMeta::new_readonly(executor_key, true), // traderWallet (executor)
            AccountMeta::new(remaining[3].key(), false), // srcTraderAccount
            AccountMeta::new(remaining[4].key(), false), // dstTraderAccount
            AccountMeta::new_readonly(remaining[5].key(), false), // perpAssetMap (readonly)
            AccountMeta::new(remaining[6].key(), false), // globalTraderIndex
            AccountMeta::new(remaining[7].key(), false) // activeTraderBuffer
        ];

        let mut ix_data = phoenix_disc("transfer_collateral").to_vec();
        ix_data.extend_from_slice(&amount.to_le_bytes());

        invoke_signed(
            &(Instruction {
                program_id: PHOENIX_PROGRAM_ID,
                accounts: transfer_metas,
                data: ix_data,
            }),
            &[
                remaining[1].to_account_info(), // logAuthority
                remaining[2].to_account_info(), // globalConfig
                ctx.accounts.executor.to_account_info(), // traderWallet
                remaining[3].to_account_info(), // srcTraderAccount
                remaining[4].to_account_info(), // dstTraderAccount
                remaining[5].to_account_info(), // perpAssetMap
                remaining[6].to_account_info(), // globalTraderIndex
                remaining[7].to_account_info(), // activeTraderBuffer
                remaining[0].to_account_info(), // phoenixProgram
            ],
            &[executor_seeds]
        )?;

        8 // order accounts start after the 8 transfer accounts
    } else {
        require!(remaining.len() >= 9, PrivacyError::PhoenixInvalidAccounts);
        require_keys_eq!(remaining[0].key(), PHOENIX_PROGRAM_ID, PrivacyError::InvalidSwapProgram);
        0
    };

    // ── Place order CPI ───────────────────────────────────────────────────
    // placeMarketOrder / placeLimitOrder account layout (from Phoenix IDL):
    //   0. phoenixProgram      (readonly)
    //   1. phoenixLogAuthority (readonly)
    //   2. globalConfiguration (writable)
    //   3. traderWallet        (signer) ← executor PDA
    //   4. traderAccount       (writable)
    //   5. perpAssetMap        (writable)
    //   6. globalTraderIndex   (writable)
    //   7. activeTraderBuffer  (writable)
    //   8. orderbook           (writable)
    //   9. splines             (writable)
    let r = &remaining[order_offset..];

    let phoenix_account_metas = vec![
        AccountMeta::new_readonly(r[0].key(), false), // phoenixProgram
        AccountMeta::new_readonly(r[1].key(), false), // phoenixLogAuthority
        AccountMeta::new(r[2].key(), false), // globalConfiguration
        AccountMeta::new_readonly(executor_key, true), // traderWallet (executor signs)
        AccountMeta::new(r[3].key(), false), // traderAccount
        AccountMeta::new(r[4].key(), false), // perpAssetMap
        AccountMeta::new(r[5].key(), false), // globalTraderIndex
        AccountMeta::new(r[6].key(), false), // activeTraderBuffer
        AccountMeta::new(r[7].key(), false), // orderbook
        AccountMeta::new(r[8].key(), false) // splines
    ];

    invoke_signed(
        &(Instruction {
            program_id: PHOENIX_PROGRAM_ID,
            accounts: phoenix_account_metas,
            data: order_data,
        }),
        &[
            r[1].to_account_info(),
            r[2].to_account_info(),
            ctx.accounts.executor.to_account_info(), // traderWallet (executor)
            r[3].to_account_info(),
            r[4].to_account_info(),
            r[5].to_account_info(),
            r[6].to_account_info(),
            r[7].to_account_info(),
            r[8].to_account_info(),
            r[0].to_account_info(), // phoenixProgram
        ],
        &[executor_seeds]
    )?;

    emit!(PhoenixOrderEvent {
        mint_address,
        relayer: ctx.accounts.relayer.key(),
        timestamp: Clock::get()?.unix_timestamp,
    });

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────

/// **Cancel all open orders for the vault's Phoenix trader account.**
///
/// `remaining_accounts` layout — same 9 accounts as `phoenix_place_order`.
pub fn phoenix_cancel_orders<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::PhoenixCancelOrders<'info>>,
    mint_address: Pubkey,
    claimant: Pubkey
) -> Result<()> {
    let cfg = &ctx.accounts.config;

    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require_keys_eq!(mint_address, PHOENIX_REQUIRED_MINT, PrivacyError::PhoenixInvalidPool);

    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 9, PrivacyError::PhoenixInvalidAccounts);
    require_keys_eq!(remaining[0].key(), PHOENIX_PROGRAM_ID, PrivacyError::InvalidSwapProgram);

    let executor_key = ctx.accounts.executor.key();
    let executor_bump = ctx.bumps.executor;
    let executor_seeds: &[&[u8]] = &[
        b"phoenix_executor",
        mint_address.as_ref(),
        claimant.as_ref(),
        &[executor_bump],
    ];

    // cancelAll account layout (same as placeMarketOrder):
    //   0..9: same as place_market_order
    let phoenix_account_metas = vec![
        AccountMeta::new_readonly(remaining[0].key(), false),
        AccountMeta::new_readonly(remaining[1].key(), false),
        AccountMeta::new(remaining[2].key(), false),
        AccountMeta::new_readonly(executor_key, true), // traderWallet (executor signs)
        AccountMeta::new(remaining[3].key(), false),
        AccountMeta::new(remaining[4].key(), false),
        AccountMeta::new(remaining[5].key(), false),
        AccountMeta::new(remaining[6].key(), false),
        AccountMeta::new(remaining[7].key(), false),
        AccountMeta::new(remaining[8].key(), false)
    ];

    let cancel_ix = Instruction {
        program_id: PHOENIX_PROGRAM_ID,
        accounts: phoenix_account_metas,
        data: phoenix_disc("cancel_all").to_vec(),
    };

    let cpi_infos = vec![
        remaining[1].to_account_info(),
        remaining[2].to_account_info(),
        ctx.accounts.executor.to_account_info(), // traderWallet (executor)
        remaining[3].to_account_info(),
        remaining[4].to_account_info(),
        remaining[5].to_account_info(),
        remaining[6].to_account_info(),
        remaining[7].to_account_info(),
        remaining[8].to_account_info(),
        remaining[0].to_account_info()
    ];

    invoke_signed(&cancel_ix, &cpi_infos, &[executor_seeds])?;

    Ok(())
}

/// **Cancel specific resting orders by their FIFO order IDs.**
///
/// Each pair `(price_in_ticks[i], sequence_numbers[i])` identifies a resting
/// order on the Phoenix orderbook. Both slices must have the same length and
/// contain at least one entry (max 100 per call).
///
/// Encoding sent to Phoenix (per rise-public `rust/ix/src/cancel_orders.rs`):
/// ```
/// disc(8) + u32_le(num_orders) + N × [u32_le(nodePointer=0) + u64_le(priceInTicks) + u64_le(seqNum)]
/// ```
///
/// `remaining_accounts` layout — identical to `phoenix_cancel_orders` (9 accounts):
/// ```
/// [0] phoenixProgram            — readonly; validated == PHOENIX_PROGRAM_ID
/// [1] phoenixLogAuthority       — readonly
/// [2] globalConfiguration       — PDA ["global"]; writable
/// [3] phoenixTraderAccount      — PDA ["trader", executor, 0, 0]; writable
/// [4] perpAssetMap              — writable
/// [5] phoenixGlobalTraderIndex  — writable
/// [6] phoenixActiveTraderBuffer — writable
/// [7] orderbook                 — writable
/// [8] splines                   — writable
/// ```
pub fn phoenix_cancel_orders_by_id<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::PhoenixCancelOrdersById<'info>>,
    mint_address: Pubkey,
    claimant: Pubkey,
    price_in_ticks: Vec<u64>,
    sequence_numbers: Vec<u64>
) -> Result<()> {
    let cfg = &ctx.accounts.config;

    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require_keys_eq!(mint_address, PHOENIX_REQUIRED_MINT, PrivacyError::PhoenixInvalidPool);
    require!(!price_in_ticks.is_empty(), PrivacyError::PhoenixInvalidOrderData);
    require!(price_in_ticks.len() == sequence_numbers.len(), PrivacyError::PhoenixInvalidOrderData);
    require!(price_in_ticks.len() <= 100, PrivacyError::PhoenixInvalidOrderData);

    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 9, PrivacyError::PhoenixInvalidAccounts);
    require_keys_eq!(remaining[0].key(), PHOENIX_PROGRAM_ID, PrivacyError::InvalidSwapProgram);

    let executor_key = ctx.accounts.executor.key();
    let executor_bump = ctx.bumps.executor;
    let executor_seeds: &[&[u8]] = &[
        b"phoenix_executor",
        mint_address.as_ref(),
        claimant.as_ref(),
        &[executor_bump],
    ];

    // Encode: disc(8) + u32_le(len) + N × [u32_le(nodePointer=0) + u64_le(priceInTicks) + u64_le(seqNum)]
    let num = price_in_ticks.len() as u32;
    let mut ix_data = phoenix_disc("cancel_orders_by_id").to_vec();
    ix_data.extend_from_slice(&num.to_le_bytes());
    for i in 0..price_in_ticks.len() {
        ix_data.extend_from_slice(&(0u32).to_le_bytes()); // nodePointer = 0
        ix_data.extend_from_slice(&price_in_ticks[i].to_le_bytes()); // priceInTicks
        ix_data.extend_from_slice(&sequence_numbers[i].to_le_bytes()); // orderSequenceNumber
    }

    let phoenix_account_metas = vec![
        AccountMeta::new_readonly(remaining[0].key(), false),
        AccountMeta::new_readonly(remaining[1].key(), false),
        AccountMeta::new(remaining[2].key(), false),
        AccountMeta::new_readonly(executor_key, true), // traderWallet (executor signs)
        AccountMeta::new(remaining[3].key(), false),
        AccountMeta::new(remaining[4].key(), false),
        AccountMeta::new(remaining[5].key(), false),
        AccountMeta::new(remaining[6].key(), false),
        AccountMeta::new(remaining[7].key(), false),
        AccountMeta::new(remaining[8].key(), false)
    ];

    let cancel_ix = Instruction {
        program_id: PHOENIX_PROGRAM_ID,
        accounts: phoenix_account_metas,
        data: ix_data,
    };

    let cpi_infos = vec![
        remaining[1].to_account_info(),
        remaining[2].to_account_info(),
        ctx.accounts.executor.to_account_info(), // traderWallet (executor)
        remaining[3].to_account_info(),
        remaining[4].to_account_info(),
        remaining[5].to_account_info(),
        remaining[6].to_account_info(),
        remaining[7].to_account_info(),
        remaining[8].to_account_info(),
        remaining[0].to_account_info()
    ];

    invoke_signed(&cancel_ix, &cpi_infos, &[executor_seeds])?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────

/// **Transfer collateral between two Phoenix trader sub-accounts owned by the same executor.**
///
/// Moves `amount` PhUSD (6-decimal) from `srcTraderAccount` to `dstTraderAccount`.
/// Typically used to fund an isolated sub-account from the cross sub-account
/// before placing an isolated position.
///
/// `remaining_accounts` layout (8 accounts):
/// ```
/// [0] phoenixProgram            — readonly; validated == PHOENIX_PROGRAM_ID
/// [1] phoenixLogAuthority       — readonly
/// [2] globalConfiguration       — PDA ["global"]; readonly (unlike place_order)
/// [3] srcTraderAccount          — writable (source, typically cross sub-account)
/// [4] dstTraderAccount          — writable (destination, typically isolated sub-account)
/// [5] perpAssetMap              — readonly (unlike place_order)
/// [6] phoenixGlobalTraderIndex  — writable
/// [7] phoenixActiveTraderBuffer — writable
/// ```
pub fn phoenix_transfer_collateral<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::PhoenixTransferCollateral<'info>>,
    mint_address: Pubkey,
    claimant: Pubkey,
    amount: u64
) -> Result<()> {
    let cfg = &ctx.accounts.config;

    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require_keys_eq!(mint_address, PHOENIX_REQUIRED_MINT, PrivacyError::PhoenixInvalidPool);
    require!(amount > 0, PrivacyError::InvalidPublicAmount);

    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 8, PrivacyError::PhoenixInvalidAccounts);
    require_keys_eq!(remaining[0].key(), PHOENIX_PROGRAM_ID, PrivacyError::InvalidSwapProgram);

    let executor_key = ctx.accounts.executor.key();
    let executor_bump = ctx.bumps.executor;
    let executor_seeds: &[&[u8]] = &[
        b"phoenix_executor",
        mint_address.as_ref(),
        claimant.as_ref(),
        &[executor_bump],
    ];

    // transferCollateral account layout (Phoenix IDL):
    //   0. phoenixProgram      (readonly)
    //   1. logAuthority        (readonly)
    //   2. globalConfiguration (readonly — not writable)
    //   3. traderWallet        (readonly signer) ← executor PDA
    //   4. srcTraderAccount    (writable)
    //   5. dstTraderAccount    (writable)
    //   6. perpAssetMap        (readonly — not writable)
    //   7. globalTraderIndex   (writable)
    //   8. activeTraderBuffer  (writable)
    let account_metas = vec![
        AccountMeta::new_readonly(remaining[0].key(), false), // phoenixProgram
        AccountMeta::new_readonly(remaining[1].key(), false), // logAuthority
        AccountMeta::new_readonly(remaining[2].key(), false), // globalConfiguration (readonly)
        AccountMeta::new_readonly(executor_key, true), // traderWallet (executor signs)
        AccountMeta::new(remaining[3].key(), false), // srcTraderAccount
        AccountMeta::new(remaining[4].key(), false), // dstTraderAccount
        AccountMeta::new_readonly(remaining[5].key(), false), // perpAssetMap (readonly)
        AccountMeta::new(remaining[6].key(), false), // globalTraderIndex
        AccountMeta::new(remaining[7].key(), false) // activeTraderBuffer
    ];

    // transferCollateral data: disc(8) || amount_u64_le(8)
    let mut ix_data = phoenix_disc("transfer_collateral").to_vec();
    ix_data.extend_from_slice(&amount.to_le_bytes());

    let transfer_ix = Instruction {
        program_id: PHOENIX_PROGRAM_ID,
        accounts: account_metas,
        data: ix_data,
    };

    let cpi_infos = vec![
        remaining[1].to_account_info(), // logAuthority
        remaining[2].to_account_info(), // globalConfiguration
        ctx.accounts.executor.to_account_info(), // traderWallet (executor signs)
        remaining[3].to_account_info(), // srcTraderAccount
        remaining[4].to_account_info(), // dstTraderAccount
        remaining[5].to_account_info(), // perpAssetMap
        remaining[6].to_account_info(), // globalTraderIndex
        remaining[7].to_account_info(), // activeTraderBuffer
        remaining[0].to_account_info() // phoenixProgram
    ];

    invoke_signed(&transfer_ix, &cpi_infos, &[executor_seeds])?;

    emit!(PhoenixTransferCollateralEvent {
        mint_address,
        amount,
        relayer: ctx.accounts.relayer.key(),
        timestamp: Clock::get()?.unix_timestamp,
    });

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────

/// **Place a market close/reduce order — risk management before withdrawal.**
///
/// Must be called before `phoenix_queue_withdraw` whenever an open position
/// consumes margin that exceeds the free `traderQuoteLotCollateral`. Without
/// first reducing the position, `phoenix_queue_withdraw` will fail with an
/// `InsufficientMargin` error from Phoenix.
///
/// Only `place_market_order` is accepted. Limit orders would not execute
/// immediately, leaving margin tied up and not freeing collateral for the
/// subsequent withdrawal.
///
/// `remaining_accounts` layout — identical to `phoenix_place_order` (9 accounts):
/// ```
/// [0] phoenixProgram            — readonly; validated == PHOENIX_PROGRAM_ID
/// [1] phoenixLogAuthority       — readonly
/// [2] globalConfiguration       — PDA ["global"]; writable
/// [3] phoenixTraderAccount      — PDA ["trader", executor, 0, 0]; writable
/// [4] perpAssetMap              — writable
/// [5] phoenixGlobalTraderIndex  — writable
/// [6] phoenixActiveTraderBuffer — writable
/// [7] orderbook                 — writable
/// [8] splines                   — writable
/// ```
pub fn phoenix_close_position<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::PhoenixClosePosition<'info>>,
    mint_address: Pubkey,
    claimant: Pubkey,
    order_data: Vec<u8>
) -> Result<()> {
    let cfg = &ctx.accounts.config;

    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require_keys_eq!(mint_address, PHOENIX_REQUIRED_MINT, PrivacyError::PhoenixInvalidPool);

    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 9, PrivacyError::PhoenixInvalidAccounts);
    require_keys_eq!(remaining[0].key(), PHOENIX_PROGRAM_ID, PrivacyError::InvalidSwapProgram);

    // Only market orders are accepted — they execute immediately, freeing margin.
    // Limit orders would leave the position partially open and would not solve
    // an InsufficientMargin failure at queue_withdraw time.
    require!(order_data.len() >= 8, PrivacyError::PhoenixInvalidOrderData);
    let disc_bytes: [u8; 8] = order_data[..8].try_into().unwrap();
    require!(
        disc_bytes == phoenix_disc("place_market_order"),
        PrivacyError::PhoenixInvalidOrderData
    );

    let executor_key = ctx.accounts.executor.key();
    let executor_bump = ctx.bumps.executor;
    let executor_seeds: &[&[u8]] = &[
        b"phoenix_executor",
        mint_address.as_ref(),
        claimant.as_ref(),
        &[executor_bump],
    ];

    let phoenix_account_metas = vec![
        AccountMeta::new_readonly(remaining[0].key(), false),
        AccountMeta::new_readonly(remaining[1].key(), false),
        AccountMeta::new(remaining[2].key(), false),
        AccountMeta::new_readonly(executor_key, true), // traderWallet (executor signs)
        AccountMeta::new(remaining[3].key(), false),
        AccountMeta::new(remaining[4].key(), false),
        AccountMeta::new(remaining[5].key(), false),
        AccountMeta::new(remaining[6].key(), false),
        AccountMeta::new(remaining[7].key(), false),
        AccountMeta::new(remaining[8].key(), false)
    ];

    let close_ix = Instruction {
        program_id: PHOENIX_PROGRAM_ID,
        accounts: phoenix_account_metas,
        data: order_data,
    };

    let cpi_infos = vec![
        remaining[1].to_account_info(),
        remaining[2].to_account_info(),
        ctx.accounts.executor.to_account_info(), // traderWallet (executor)
        remaining[3].to_account_info(),
        remaining[4].to_account_info(),
        remaining[5].to_account_info(),
        remaining[6].to_account_info(),
        remaining[7].to_account_info(),
        remaining[8].to_account_info(),
        remaining[0].to_account_info()
    ];

    invoke_signed(&close_ix, &cpi_infos, &[executor_seeds])?;

    emit!(PhoenixClosePositionEvent {
        mint_address,
        relayer: ctx.accounts.relayer.key(),
        timestamp: Clock::get()?.unix_timestamp,
    });

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────

/// **Queue a Phoenix withdrawal to the vault's PhUSD ATA.**
///
/// Calls `withdrawFunds` on Phoenix, which enqueues the withdrawal. A permissionless
/// on-chain crank (`consumeWithdrawQueue`) must be called afterward to transfer PhUSD
/// from the Phoenix global vault to `remaining[9]` (vault's PhUSD ATA). Once the PhUSD
/// arrives, call `phoenix_ember_unwrap` to convert it back to USDC.
///
/// `remaining_accounts` layout (10 accounts):
/// ```
/// [0] phoenixProgram            — readonly; validated == PHOENIX_PROGRAM_ID
/// [1] phoenixLogAuthority       — PDA ["log"]; readonly
/// [2] globalConfiguration       — PDA ["global"]; writable
/// [3] phoenixTraderAccount      — PDA ["trader", vault, 0, 0]; writable
/// [4] perpAssetMap              — writable
/// [5] phoenixGlobalVault        — Phoenix's PhUSD token account; writable
/// [6] withdrawQueue             — writable
/// [7] phoenixGlobalTraderIndex  — writable
/// [8] phoenixActiveTraderBuffer — writable
/// [9] vaultPhUsdAta             — vault's PhUSD ATA; writable (receives PhUSD from Phoenix)
/// ```
/// `vault_token_account` (named) = vault's USDC ATA (validated; destination after `phoenix_ember_unwrap`).
pub fn phoenix_queue_withdraw<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::PhoenixQueueWithdraw<'info>>,
    mint_address: Pubkey,
    claimant: Pubkey,
    amount: u64,
    _withdrawal_id: [u8; 32]
) -> Result<()> {
    let cfg = &ctx.accounts.config;

    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require_keys_eq!(mint_address, PHOENIX_REQUIRED_MINT, PrivacyError::PhoenixInvalidPool);
    require!(amount > 0, PrivacyError::InvalidPublicAmount);

    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 10, PrivacyError::PhoenixInvalidAccounts);
    require_keys_eq!(remaining[0].key(), PHOENIX_PROGRAM_ID, PrivacyError::InvalidSwapProgram);

    let executor_key = ctx.accounts.executor.key();
    let executor_bump = ctx.bumps.executor;
    let executor_seeds: &[&[u8]] = &[
        b"phoenix_executor",
        mint_address.as_ref(),
        claimant.as_ref(),
        &[executor_bump],
    ];

    // Validate remaining[9] is the executor's canonical PhUSD ATA (Phoenix withdrawal destination)
    let expected_phusd_ata = get_associated_token_address(&executor_key, &PHUSD_MINT);
    require_keys_eq!(remaining[9].key(), expected_phusd_ata, PrivacyError::VaultTokenAccountNotATA);

    // ── Slot cap enforcement ──────────────────────────────────────────────────
    // Prevents any single deposit slot from withdrawing more than it deposited.
    // Placed after CPI pre-checks so unit tests (non-USDC pool, wrong ATA) still
    // fail on their expected errors without requiring a real slot PDA.
    {
        let slot_info = ctx.accounts.phoenix_slot.to_account_info();
        let mut slot_data = slot_info.data.borrow_mut();
        let mut slot = crate::PhoenixSlot::try_deserialize(&mut &slot_data[..])?;
        require_keys_eq!(slot.claimant_pubkey, claimant, PrivacyError::InvalidClaimant);
        let new_withdrawn = slot.withdrawn
            .checked_add(amount)
            .ok_or(error!(PrivacyError::ArithmeticOverflow))?;
        require!(new_withdrawn <= slot.amount, PrivacyError::SlotOverdraft);
        // Write updated slot back
        let updated = crate::PhoenixSlot { withdrawn: new_withdrawn, ..slot };
        let mut cursor = &mut slot_data[..];
        updated.try_serialize(&mut cursor)?;
    }

    // withdrawFunds instruction data: discriminator (8 bytes) || amount (u64 LE = 8 bytes)
    let mut ix_data = phoenix_disc("withdraw_funds").to_vec();
    ix_data.extend_from_slice(&amount.to_le_bytes());

    // withdrawFunds account layout (from Phoenix IDL):
    //   0. phoenixProgram (readonly)
    //   1. phoenixLogAuthority (readonly)
    //   2. globalConfiguration (writable)
    //   3. traderWallet (signer)
    //   4. traderAccount (writable)
    //   5. perpAssetMap (writable)
    //   6. globalVault (writable)         — Phoenix's PhUSD token account
    //   7. destinationTokenAccount (writable) — executor's PhUSD ATA (remaining[9])
    //   8. tokenProgram (readonly)
    //   9. globalTraderIndex (writable)
    //  10. activeTraderBuffer (writable)
    //  11. withdrawQueue (writable)
    let phoenix_account_metas = vec![
        AccountMeta::new_readonly(remaining[0].key(), false), // phoenixProgram
        AccountMeta::new_readonly(remaining[1].key(), false), // phoenixLogAuthority
        AccountMeta::new(remaining[2].key(), false), // globalConfiguration
        AccountMeta::new_readonly(executor_key, true), // traderWallet (executor signs)
        AccountMeta::new(remaining[3].key(), false), // traderAccount
        AccountMeta::new(remaining[4].key(), false), // perpAssetMap
        AccountMeta::new(remaining[5].key(), false), // globalVault (PhUSD)
        AccountMeta::new(remaining[9].key(), false), // destinationTokenAccount (executor PhUSD ATA)
        AccountMeta::new_readonly(ctx.accounts.token_program.key(), false), // tokenProgram
        AccountMeta::new(remaining[7].key(), false), // globalTraderIndex
        AccountMeta::new(remaining[8].key(), false), // activeTraderBuffer
        AccountMeta::new(remaining[6].key(), false) // withdrawQueue
    ];

    let withdraw_ix = Instruction {
        program_id: PHOENIX_PROGRAM_ID,
        accounts: phoenix_account_metas,
        data: ix_data,
    };

    let cpi_infos = vec![
        remaining[1].to_account_info(), // phoenixLogAuthority
        remaining[2].to_account_info(), // globalConfiguration
        ctx.accounts.executor.to_account_info(), // traderWallet (executor)
        remaining[3].to_account_info(), // traderAccount
        remaining[4].to_account_info(), // perpAssetMap
        remaining[5].to_account_info(), // globalVault (PhUSD)
        remaining[9].to_account_info(), // destinationTokenAccount (executor PhUSD ATA)
        ctx.accounts.token_program.to_account_info(), // tokenProgram
        remaining[7].to_account_info(), // globalTraderIndex
        remaining[8].to_account_info(), // activeTraderBuffer
        remaining[6].to_account_info(), // withdrawQueue
        remaining[0].to_account_info() // phoenixProgram
    ];

    invoke_signed(&withdraw_ix, &cpi_infos, &[executor_seeds])?;

    emit!(PhoenixWithdrawQueuedEvent {
        amount,
        mint_address,
        timestamp: Clock::get()?.unix_timestamp,
    });

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────

/// **Register the pool vault as a Phoenix Eternal trader (one-time setup).**
///
/// Must be called once before `phoenix_deposit_from_pool` or
/// `phoenix_place_order` can be used. Creates the vault's Phoenix trader
/// account (PDA: `["trader", vault, 0, 0]` on Phoenix).
///
/// The vault PDA is the registered trader (signs via `invoke_signed`).
/// The `payer` account (remaining[4]) pays the rent for the new trader account.
///
/// `remaining_accounts` layout (5 accounts):
/// ```
/// [0] phoenixProgram          — readonly; validated == PHOENIX_PROGRAM_ID
/// [1] phoenixLogAuthority     — PDA ["log"] on Phoenix; readonly
/// [2] globalConfiguration     — PDA ["global"] on Phoenix; writable
/// [3] traderAccount           — PDA ["trader", vault, 0, 0] on Phoenix; writable (new)
/// [4] payer                   — writable signer; pays trader account rent
/// ```
/// `system_program` comes from the named account (not remaining_accounts).
pub fn phoenix_register_pool_trader<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::PhoenixRegisterTrader<'info>>,
    mint_address: Pubkey,
    claimant: Pubkey,
    // 0 = Cross (max_positions=128, subaccount=0), 1 = Isolated (max_positions=1, subaccount=1)
    margin_type: u8
) -> Result<()> {
    require_keys_eq!(mint_address, PHOENIX_REQUIRED_MINT, PrivacyError::PhoenixInvalidPool);
    require!(margin_type <= 1, PrivacyError::PhoenixInvalidOrderData);

    let remaining = ctx.remaining_accounts;
    // remaining: [phoenixProgram, logAuthority, globalConfiguration, traderAccount]
    require!(remaining.len() >= 4, PrivacyError::PhoenixInvalidAccounts);
    require_keys_eq!(remaining[0].key(), PHOENIX_PROGRAM_ID, PrivacyError::InvalidSwapProgram);

    // Initialize executor fields (idempotent — safe to set on every call).
    // On first call the account is freshly allocated; on re-runs the values are unchanged.
    let executor_bump = ctx.bumps.executor;
    {
        let executor = &mut ctx.accounts.executor;
        executor.mint_address = mint_address;
        executor.claimant = claimant;
        executor.bump = executor_bump;
    }

    let executor_key = ctx.accounts.executor.key();
    let executor_seeds: &[&[u8]] = &[
        b"phoenix_executor",
        mint_address.as_ref(),
        claimant.as_ref(),
        &[executor_bump],
    ];

    // Cross: max_positions=128, subaccount_index=0
    // Isolated: max_positions=1,  subaccount_index=1
    let (max_positions, subaccount_index): (u64, u8) = if margin_type == 0 {
        (128, 0)
    } else {
        (1, 1)
    };

    // RegisterTraderParams { max_positions: u64, trader_pda_index: u8, subaccount_index: u8 }
    let mut ix_data = phoenix_disc("register_trader").to_vec();
    ix_data.extend_from_slice(&max_positions.to_le_bytes());
    ix_data.push(0u8); // trader_pda_index = 0
    ix_data.push(subaccount_index);

    // registerTrader account layout (Phoenix IDL order):
    //   [0] phoenixProgram        (readonly)         — remaining[0]
    //   [1] phoenixLogAuthority   (readonly)         — remaining[1]
    //   [2] globalConfiguration   (writable)         — remaining[2]
    //   [3] payer                 (writable, signer) — ctx.accounts.payer
    //   [4] traderWallet          (signer, PDA)      — ctx.accounts.executor
    //   [5] traderAccount         (writable, init)   — remaining[3]
    //   [6] systemProgram         (readonly)         — ctx.accounts.system_program
    let phoenix_account_metas = vec![
        AccountMeta::new_readonly(remaining[0].key(), false), // [0] phoenixProgram
        AccountMeta::new_readonly(remaining[1].key(), false), // [1] phoenixLogAuthority
        AccountMeta::new(remaining[2].key(), false), // [2] globalConfiguration
        AccountMeta::new(ctx.accounts.payer.key(), true), // [3] payer
        AccountMeta::new_readonly(executor_key, true), // [4] traderWallet (executor, PDA signer)
        AccountMeta::new(remaining[3].key(), false), // [5] traderAccount
        AccountMeta::new_readonly(ctx.accounts.system_program.key(), false) // [6] systemProgram
    ];

    let register_ix = Instruction {
        program_id: PHOENIX_PROGRAM_ID,
        accounts: phoenix_account_metas,
        data: ix_data,
    };

    let cpi_infos = vec![
        remaining[0].to_account_info(), // phoenixProgram
        remaining[1].to_account_info(), // phoenixLogAuthority
        remaining[2].to_account_info(), // globalConfiguration
        ctx.accounts.payer.to_account_info(), // payer
        ctx.accounts.executor.to_account_info(), // traderWallet (executor)
        remaining[3].to_account_info(), // traderAccount
        ctx.accounts.system_program.to_account_info() // systemProgram
    ];

    invoke_signed(&register_ix, &cpi_infos, &[executor_seeds])?;

    emit!(PhoenixRegisterTraderEvent {
        mint_address,
        vault: executor_key,
        trader_account: remaining[3].key(),
        timestamp: Clock::get()?.unix_timestamp,
    });

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────

/// **Wrap vault USDC → PhUSD via EMBER deposit CPI.**
///
/// Calls EMBER's `deposit` instruction with the vault PDA as `traderWallet`.
/// USDC is drawn from the vault's USDC ATA and PhUSD is minted 1:1 into the
/// vault's PhUSD ATA. No TVL change — the value stays inside the vault.
///
/// `remaining_accounts` layout (5 accounts):
/// ```
/// [0] emberProgram       — EMBER_PROGRAM_ID; validated
/// [1] phUsdMintAuthPda   — PHUSD_MINT_AUTHORITY; readonly
/// [2] usdcMint           — PHOENIX_REQUIRED_MINT; readonly
/// [3] phUsdMint          — PHUSD_MINT; writable (supply increases via mint_to)
/// [4] emberUsdcReserve   — EMBER_USDC_RESERVE; writable (receives USDC)
/// ```
pub fn phoenix_ember_wrap<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::PhoenixEmberWrap<'info>>,
    mint_address: Pubkey,
    claimant: Pubkey,
    amount: u64
) -> Result<()> {
    let cfg = &ctx.accounts.config;

    require_keys_eq!(mint_address, PHOENIX_REQUIRED_MINT, PrivacyError::PhoenixInvalidPool);
    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require!(amount > 0, PrivacyError::InvalidPublicAmount);

    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 5, PrivacyError::PhoenixInvalidAccounts);
    require_keys_eq!(remaining[0].key(), EMBER_PROGRAM_ID, PrivacyError::InvalidSwapProgram);

    let executor_key = ctx.accounts.executor.key();
    let executor_bump = ctx.bumps.executor;
    let executor_seeds: &[&[u8]] = &[
        b"phoenix_executor",
        mint_address.as_ref(),
        claimant.as_ref(),
        &[executor_bump],
    ];

    // Validate executor PhUSD ATA
    let expected_phusd_ata = get_associated_token_address(&executor_key, &PHUSD_MINT);
    require_keys_eq!(
        ctx.accounts.executor_ph_usd_ata.key(),
        expected_phusd_ata,
        PrivacyError::VaultTokenAccountNotATA
    );

    // Validate executor USDC ATA
    let expected_usdc_ata = get_associated_token_address(&executor_key, &mint_address);
    require_keys_eq!(
        ctx.accounts.executor_token_account.key(),
        expected_usdc_ata,
        PrivacyError::VaultTokenAccountNotATA
    );

    // EMBER deposit account layout:
    //   [0] traderWallet (signer)       — executor PDA
    //   [1] phUsdMintAuthPda (readonly) — remaining[1]
    //   [2] usdcMint (readonly)         — remaining[2]
    //   [3] phUsdMint (writable)        — remaining[3] (supply increases)
    //   [4] traderUsdcAta (writable)    — executor_token_account (source)
    //   [5] traderPhUsdAta (writable)   — executor_ph_usd_ata (destination)
    //   [6] emberUsdcReserve (writable) — remaining[4] (receives USDC)
    //   [7] tokenProgram (readonly)
    let mut ember_wrap_data = ember_disc("deposit").to_vec();
    ember_wrap_data.extend_from_slice(&amount.to_le_bytes());

    let ember_wrap_metas = vec![
        AccountMeta::new_readonly(executor_key, true), // [0] traderWallet (executor signs)
        AccountMeta::new_readonly(remaining[1].key(), false), // [1] phUsdMintAuthPda
        AccountMeta::new_readonly(remaining[2].key(), false), // [2] usdcMint
        AccountMeta::new(remaining[3].key(), false), // [3] phUsdMint
        AccountMeta::new(ctx.accounts.executor_token_account.key(), false), // [4] traderUsdcAta
        AccountMeta::new(ctx.accounts.executor_ph_usd_ata.key(), false), // [5] traderPhUsdAta
        AccountMeta::new(remaining[4].key(), false), // [6] emberUsdcReserve
        AccountMeta::new_readonly(ctx.accounts.token_program.key(), false) // [7] tokenProgram
    ];

    let ember_wrap_ix = Instruction {
        program_id: EMBER_PROGRAM_ID,
        accounts: ember_wrap_metas,
        data: ember_wrap_data,
    };

    let ember_wrap_cpi_infos = vec![
        ctx.accounts.executor.to_account_info(), // traderWallet (executor)
        remaining[1].to_account_info(), // phUsdMintAuthPda
        remaining[2].to_account_info(), // usdcMint
        remaining[3].to_account_info(), // phUsdMint
        ctx.accounts.executor_token_account.to_account_info(), // traderUsdcAta
        ctx.accounts.executor_ph_usd_ata.to_account_info(), // traderPhUsdAta
        remaining[4].to_account_info(), // emberUsdcReserve
        ctx.accounts.token_program.to_account_info(), // tokenProgram
        remaining[0].to_account_info() // emberProgram (must be in list)
    ];

    invoke_signed(&ember_wrap_ix, &ember_wrap_cpi_infos, &[executor_seeds])?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────

/// **Crank the Phoenix withdraw queue then convert PhUSD → USDC via EMBER (combined exit step).**
///
/// Atomically performs what was previously two separate instructions:
///   1. Phoenix `consumeWithdrawQueue` — flushes any pending PhUSD from Phoenix
///      globalVault → executor PhUSD ATA (permissionless, no executor signature).
///   2. EMBER `withdraw` — burns PhUSD from executor PhUSD ATA, returns USDC 1:1
///      to executor USDC ATA, which is then SPL-transferred to vault USDC ATA.
///
/// Phoenix processes withdrawals synchronously in `withdrawFunds`, so the consume
/// CPI is effectively a no-op in normal conditions but is included as a safety net
/// for edge cases (high-load cranking scenarios).
///
/// TVL is updated upward by `amount` to reflect USDC arriving in the vault.
///
/// `remaining_accounts` layout (14 accounts):
/// ```
/// ─── Phoenix consumeWithdrawQueue (9 accounts) ───
/// [0]  phoenixProgram        — readonly; validated == PHOENIX_PROGRAM_ID
/// [1]  phoenixLogAuthority   — readonly
/// [2]  globalConfiguration   — PDA ["global"]; writable
/// [3]  perpAssetMap          — writable
/// [4]  globalVault           — Phoenix PhUSD vault; writable
/// [5]  globalTraderIndex     — writable
/// [6]  activeTraderBuffer    — writable
/// [7]  withdrawQueue         — writable
/// [8]  traderAccount         — PDA ["trader", executor, 0, 0]; writable
/// ─── EMBER withdraw (5 accounts) ────────────────
/// [9]  emberProgram          — EMBER_PROGRAM_ID; validated
/// [10] phUsdMintAuthPda      — PHUSD_MINT_AUTHORITY; readonly
/// [11] usdcMint              — PHOENIX_REQUIRED_MINT; readonly
/// [12] phUsdMint             — PHUSD_MINT; writable (supply decreases via burn)
/// [13] emberUsdcReserve      — EMBER_USDC_RESERVE; writable (releases USDC)
/// ```
pub fn phoenix_ember_unwrap<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::PhoenixEmberUnwrap<'info>>,
    mint_address: Pubkey,
    claimant: Pubkey,
    _withdrawal_id: [u8; 32],
    amount: u64
) -> Result<()> {
    let cfg = &mut ctx.accounts.config;

    require_keys_eq!(mint_address, PHOENIX_REQUIRED_MINT, PrivacyError::PhoenixInvalidPool);
    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require!(amount > 0, PrivacyError::InvalidPublicAmount);

    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 14, PrivacyError::PhoenixInvalidAccounts);
    require_keys_eq!(remaining[0].key(), PHOENIX_PROGRAM_ID, PrivacyError::InvalidSwapProgram);
    require_keys_eq!(remaining[9].key(), EMBER_PROGRAM_ID, PrivacyError::InvalidSwapProgram);

    let vault_key = ctx.accounts.vault.key();

    let executor_key = ctx.accounts.executor.key();
    let executor_bump = ctx.bumps.executor;
    let executor_seeds: &[&[u8]] = &[
        b"phoenix_executor",
        mint_address.as_ref(),
        claimant.as_ref(),
        &[executor_bump],
    ];
    let _vault_seeds: &[&[u8]] = &[b"privacy_vault_v3", mint_address.as_ref(), &[cfg.vault_bump]];

    // Validate executor PhUSD ATA (source of PhUSD to burn)
    let expected_phusd_ata = get_associated_token_address(&executor_key, &PHUSD_MINT);
    require_keys_eq!(
        ctx.accounts.executor_ph_usd_ata.key(),
        expected_phusd_ata,
        PrivacyError::VaultTokenAccountNotATA
    );

    // Validate executor USDC ATA (receives USDC from EMBER)
    let expected_executor_usdc_ata = get_associated_token_address(&executor_key, &mint_address);
    require_keys_eq!(
        ctx.accounts.executor_token_account.key(),
        expected_executor_usdc_ata,
        PrivacyError::VaultTokenAccountNotATA
    );

    // Validate vault USDC ATA (final destination)
    let expected_vault_usdc_ata = get_associated_token_address(&vault_key, &mint_address);
    require_keys_eq!(
        ctx.accounts.vault_token_account.key(),
        expected_vault_usdc_ata,
        PrivacyError::VaultTokenAccountNotATA
    );

    // ── Slot cap: pending_reissue cannot exceed the amount queued for withdrawal ──
    // We check against slot.withdrawn (not slot.amount) to commit-bind ember_unwrap
    // to phoenix_queue_withdraw. If queue_withdraw was never called for this slot
    // (slot.withdrawn == 0), any positive amount fails this check automatically.
    // This prevents cross-slot PhUSD contamination: a relayer cannot use PhUSD
    // that arrived from slot B to inflate slot A's pending_reissue beyond
    // what slot A actually queued via phoenix_queue_withdraw.
    {
        let slot_info = ctx.accounts.phoenix_slot.to_account_info();
        let slot_data = slot_info.data.borrow();
        let slot = crate::PhoenixSlot::try_deserialize(&mut &slot_data[..])?;
        require_keys_eq!(slot.claimant_pubkey, claimant, PrivacyError::InvalidClaimant);
        let pending = &ctx.accounts.pending_reissue;
        if pending.claimant_pubkey != Pubkey::default() {
            require_keys_eq!(pending.claimant_pubkey, claimant, PrivacyError::InvalidClaimant);
        }
        let new_pending = pending.amount
            .checked_add(amount)
            .ok_or(error!(PrivacyError::ArithmeticOverflow))?;
        require!(new_pending <= slot.withdrawn, PrivacyError::SlotOverdraft);
    }

    // ── 0. Phoenix consumeWithdrawQueue: flush any pending PhUSD to executor PhUSD ATA ──
    // This is permissionless — executor does NOT need to sign.
    // Phoenix normally processes withdrawals synchronously in withdrawFunds, so
    // this CPI is a no-op in typical conditions but acts as a safety net.
    //
    // consumeWithdrawQueue account layout (Phoenix IDL):
    //   [0]  phoenixProgram (readonly)          — remaining[0]
    //   [1]  phoenixLogAuthority (readonly)     — remaining[1]
    //   [2]  globalConfiguration (writable)     — remaining[2]
    //   [3]  perpAssetMap (writable)            — remaining[3]
    //   [4]  globalVault (writable)             — remaining[4]
    //   [5]  globalTraderIndex (writable)       — remaining[5]
    //   [6]  activeTraderBuffer (writable)      — remaining[6]
    //   [7]  withdrawQueue (writable)           — remaining[7]
    //   [8]  tokenProgram (readonly)
    //   [9]  traderWallet (readonly, no signer) — executor
    //  [10]  destinationTokenAccount (writable) — executor PhUSD ATA
    //  [11]  traderAccount (writable)           — remaining[8]
    let consume_disc = phoenix_disc("consume_withdraw_queue");
    let consume_metas = vec![
        AccountMeta::new_readonly(remaining[0].key(), false), // [0] phoenixProgram
        AccountMeta::new_readonly(remaining[1].key(), false), // [1] phoenixLogAuthority
        AccountMeta::new(remaining[2].key(), false), // [2] globalConfiguration
        AccountMeta::new(remaining[3].key(), false), // [3] perpAssetMap
        AccountMeta::new(remaining[4].key(), false), // [4] globalVault
        AccountMeta::new(remaining[5].key(), false), // [5] globalTraderIndex
        AccountMeta::new(remaining[6].key(), false), // [6] activeTraderBuffer
        AccountMeta::new(remaining[7].key(), false), // [7] withdrawQueue
        AccountMeta::new_readonly(ctx.accounts.token_program.key(), false), // [8] tokenProgram
        AccountMeta::new_readonly(executor_key, false), // [9] traderWallet (not a signer)
        AccountMeta::new(ctx.accounts.executor_ph_usd_ata.key(), false), // [10] destination
        AccountMeta::new(remaining[8].key(), false) // [11] traderAccount
    ];
    let consume_ix = Instruction {
        program_id: PHOENIX_PROGRAM_ID,
        accounts: consume_metas,
        data: consume_disc.to_vec(),
    };
    // Best-effort: Phoenix returns an error when the queue is already empty
    // (which is the normal case — withdrawFunds is synchronous). Ignore the
    // result so the EMBER unwrap below can proceed regardless.
    let _ = anchor_lang::solana_program::program::invoke(
        &consume_ix,
        &[
            remaining[1].to_account_info(), // phoenixLogAuthority
            remaining[2].to_account_info(), // globalConfiguration
            remaining[3].to_account_info(), // perpAssetMap
            remaining[4].to_account_info(), // globalVault
            remaining[5].to_account_info(), // globalTraderIndex
            remaining[6].to_account_info(), // activeTraderBuffer
            remaining[7].to_account_info(), // withdrawQueue
            ctx.accounts.token_program.to_account_info(), // tokenProgram
            ctx.accounts.executor.to_account_info(), // traderWallet (readonly)
            ctx.accounts.executor_ph_usd_ata.to_account_info(), // destination
            remaining[8].to_account_info(), // traderAccount
            remaining[0].to_account_info(), // phoenixProgram
        ]
    );

    // ── 1. EMBER withdraw: burn PhUSD → USDC ─────────────────────────────────
    // EMBER withdraw account layout — identical slot ordering to deposit;
    // only the instruction discriminator changes direction.
    //   [0] traderWallet (signer)       — executor PDA
    //   [1] phUsdMintAuthPda (readonly) — remaining[10]
    //   [2] usdcMint (readonly)         — remaining[11]
    //   [3] phUsdMint (writable)        — remaining[12] (supply decreases via burn)
    //   [4] traderUsdcAta (writable)    — executor_token_account (receives USDC)
    //   [5] traderPhUsdAta (writable)   — executor_ph_usd_ata (source, burned)
    //   [6] emberUsdcReserve (writable) — remaining[13] (releases USDC)
    //   [7] tokenProgram (readonly)
    // EMBER withdraw takes Option<u64>; Borsh: Some(n) = [1_u8 || n_le_bytes]
    let mut ember_unwrap_data = ember_disc("withdraw").to_vec();
    ember_unwrap_data.push(1u8); // Some() discriminant
    ember_unwrap_data.extend_from_slice(&amount.to_le_bytes());

    let ember_unwrap_metas = vec![
        AccountMeta::new_readonly(executor_key, true), // [0] traderWallet (executor signs)
        AccountMeta::new_readonly(remaining[10].key(), false), // [1] phUsdMintAuthPda
        AccountMeta::new_readonly(remaining[11].key(), false), // [2] usdcMint
        AccountMeta::new(remaining[12].key(), false), // [3] phUsdMint
        AccountMeta::new(ctx.accounts.executor_token_account.key(), false), // [4] traderUsdcAta
        AccountMeta::new(ctx.accounts.executor_ph_usd_ata.key(), false), // [5] traderPhUsdAta
        AccountMeta::new(remaining[13].key(), false), // [6] emberUsdcReserve
        AccountMeta::new_readonly(ctx.accounts.token_program.key(), false) // [7] tokenProgram
    ];

    let ember_unwrap_ix = Instruction {
        program_id: EMBER_PROGRAM_ID,
        accounts: ember_unwrap_metas,
        data: ember_unwrap_data,
    };

    let ember_unwrap_cpi_infos = vec![
        ctx.accounts.executor.to_account_info(), // traderWallet (executor)
        remaining[10].to_account_info(), // phUsdMintAuthPda
        remaining[11].to_account_info(), // usdcMint
        remaining[12].to_account_info(), // phUsdMint
        ctx.accounts.executor_token_account.to_account_info(), // traderUsdcAta
        ctx.accounts.executor_ph_usd_ata.to_account_info(), // traderPhUsdAta
        remaining[13].to_account_info(), // emberUsdcReserve
        ctx.accounts.token_program.to_account_info(), // tokenProgram
        remaining[9].to_account_info() // emberProgram (must be in list)
    ];

    invoke_signed(&ember_unwrap_ix, &ember_unwrap_cpi_infos, &[executor_seeds])?;

    // Transfer USDC from executor_token_account to vault_token_account
    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.executor_token_account.to_account_info(),
                to: ctx.accounts.vault_token_account.to_account_info(),
                authority: ctx.accounts.executor.to_account_info(),
            },
            &[executor_seeds]
        ),
        amount
    )?;

    // Update TVL: USDC has arrived back in the vault
    cfg.total_tvl = cfg.total_tvl
        .checked_add(amount)
        .ok_or(error!(PrivacyError::ArithmeticOverflow))?;

    // Record proceeds so phoenix_reissue_notes can verify the exact amount
    // and is blocked from minting more than Phoenix actually returned.
    let pending = &mut ctx.accounts.pending_reissue;
    pending.bump = ctx.bumps.pending_reissue;
    if pending.claimant_pubkey == Pubkey::default() {
        pending.claimant_pubkey = claimant;
    }
    require_keys_eq!(pending.claimant_pubkey, claimant, PrivacyError::InvalidClaimant);
    pending.amount = pending.amount
        .checked_add(amount)
        .ok_or(error!(PrivacyError::ArithmeticOverflow))?;

    emit!(PhoenixEmberUnwrapEvent {
        amount,
        mint_address,
        timestamp: Clock::get()?.unix_timestamp,
    });

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────

/// **Re-mint private USDC notes from funds returned to the vault by Phoenix.**
///
/// This is Step 4 of the Phoenix exit flow — the final step after:
///   1. `phoenix_queue_withdraw`   — enqueue collateral
///   2. `consumeWithdrawQueue`     — permissionless crank; PhUSD → vault PhUSD ATA
///   3. `phoenix_ember_unwrap`     — burn PhUSD; USDC → vault USDC ATA; TVL updated
///   4. **`phoenix_reissue_notes`** — ZK verify; insert commitments; **no token transfer**
///
/// TVL was already updated in `phoenix_ember_unwrap`. This instruction only verifies
/// the ZK proof and inserts the output commitments into the Merkle tree.
///
/// The ZK proof format is identical to a standard deposit (public_amount = +amount,
/// dummy zero-value input notes, two output notes that sum to `amount`).
pub fn phoenix_reissue_notes(
    ctx: Context<crate::PhoenixReissueNotes>,
    root: [u8; 32],
    input_tree_id: u16,
    output_tree_id: u16,
    amount: u64,
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
    note_ciphers: Option<NoteCiphers>
) -> Result<()> {
    let (note0_epk, note0_enc, note0_vt, note1_epk, note1_enc, note1_vt) = match note_ciphers {
        Some(c) =>
            (
                c.note0_ephemeral_key,
                c.note0_encrypted,
                c.note0_view_tag,
                c.note1_ephemeral_key,
                c.note1_encrypted,
                c.note1_view_tag,
            ),
        None => ([0u8; 32], [0u8; 80], 0u8, [0u8; 32], [0u8; 80], 0u8),
    };

    let cfg = &ctx.accounts.config;

    // ── 1. Phoenix USDC only ──────────────────────────────────────────────────
    require_keys_eq!(mint_address, PHOENIX_REQUIRED_MINT, PrivacyError::PhoenixInvalidPool);
    require_keys_eq!(cfg.mint_address, mint_address, PrivacyError::InvalidMintAddress);

    // ── 2. Tree ID bounds ─────────────────────────────────────────────────────
    require!(input_tree_id < cfg.num_trees, PrivacyError::InvalidTreeId);
    require!(output_tree_id < cfg.num_trees, PrivacyError::InvalidTreeId);

    // ── 3. Amount must be positive ────────────────────────────────────────────
    require!(amount > 0, PrivacyError::InvalidPublicAmount);

    // ── 4. Relayer authorisation ──────────────────────────────────────────────
    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require_keys_eq!(ctx.accounts.relayer.key(), ext_data.relayer, PrivacyError::RelayerMismatch);

    // ── 5. Deadline ───────────────────────────────────────────────────────────
    let clock = Clock::get()?;
    require!(clock.unix_timestamp <= deadline, PrivacyError::DeadlineExpired);

    // ── 6. Commitment / nullifier sanity ──────────────────────────────────────
    let input_nullifiers = [input_nullifier_0, input_nullifier_1];
    let output_commitments = [output_commitment_0, output_commitment_1];
    let zero = [0u8; 32];
    require!(input_nullifiers[0] != input_nullifiers[1], PrivacyError::DuplicateNullifiers);
    require!(output_commitments[0] != output_commitments[1], PrivacyError::DuplicateCommitments);
    require!(
        output_commitments[0] != zero && output_commitments[1] != zero,
        PrivacyError::ZeroCommitment
    );

    // ── 7. ext_data hash ──────────────────────────────────────────────────────
    let computed_ext_hash = ext_data.hash()?;
    require!(computed_ext_hash == ext_data_hash, PrivacyError::InvalidExtData);

    // ── 8. Phoenix pending reissue — only proceeds from phoenix_ember_unwrap can be minted ──
    // This binds the reissued amount to the exact USDC that Phoenix returned.
    // Binds the reissued amount to the returned proceeds and blocks stale repeat calls.
    let pending = &mut ctx.accounts.pending_reissue;
    pending.bump = ctx.bumps.pending_reissue;
    require_keys_eq!(
        pending.claimant_pubkey,
        ctx.accounts.claimant.key(),
        PrivacyError::InvalidClaimant
    );
    require!(pending.amount >= amount, PrivacyError::InsufficientFundsForWithdrawal);
    pending.amount = pending.amount
        .checked_sub(amount)
        .ok_or(error!(PrivacyError::ArithmeticOverflow))?;

    // ── 8b. Claimant verification — prevents relayer theft ───────────────────
    // The claimant_pubkey was set at deposit time as an ephemeral key held by the user.
    // By requiring its signature on this transaction, we guarantee that only the original
    // depositor can claim the exit proceeds — even if a malicious relayer controls the
    // queue_withdraw and ember_unwrap steps.
    require_keys_eq!(
        ctx.accounts.claimant.key(),
        ctx.accounts.phoenix_slot.claimant_pubkey,
        PrivacyError::InvalidClaimant
    );

    // ── 9. ZK proof verification ──────────────────────────────────────────────
    // public_amount is POSITIVE: circuit constraint is sumIns + pubAmt = sumOuts.
    // With dummy zero-value input notes, the two output notes must sum to `amount`.
    require!(amount <= i64::MAX as u64, PrivacyError::ArithmeticOverflow);
    let public_inputs = TransactionPublicInputs {
        root,
        public_amount: amount as i64,
        ext_data_hash,
        mint_address,
        input_nullifiers,
        output_commitments,
    };
    verify_transaction_groth16(proof, &public_inputs)?;

    // ── 10. Known root check ──────────────────────────────────────────────────
    {
        let input_tree = ctx.accounts.input_tree.load()?;
        require!(MerkleTree::is_known_root(&*input_tree, root), PrivacyError::UnknownRoot);
    }

    // ── 10b. Consume the input nullifiers (each spent exactly once) ──
    require!(
        input_nullifiers[0] != zero && input_nullifiers[1] != zero,
        PrivacyError::ZeroNullifier
    );
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

    // ── 11. Insert output commitments into output tree ────────────────────────
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

    // ── 12. Emit events ───────────────────────────────────────────────────────
    // Dummy-input deposits do not mark nullifiers spent (same as transact deposits).
    let timestamp = clock.unix_timestamp;

    emit!(CommitmentEvent {
        commitment: output_commitments[0],
        leaf_index: leaf_index_0,
        new_root,
        timestamp,
        mint_address,
        tree_id: output_tree_id,
        ephemeral_public_key: note0_epk,
        encrypted_blob: note0_enc,
        view_tag: note0_vt,
    });
    emit!(CommitmentEvent {
        commitment: output_commitments[1],
        leaf_index: leaf_index_1,
        new_root,
        timestamp,
        mint_address,
        tree_id: output_tree_id,
        ephemeral_public_key: note1_epk,
        encrypted_blob: note1_enc,
        view_tag: note1_vt,
    });
    emit!(PhoenixReissueEvent {
        amount,
        mint_address,
        timestamp,
    });

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────

/// **Initialize the conditional-orders collection account for the executor PDA.**
///
/// Creates the `traderConditionalOrders` PDA (seeds `["conditional_orders", traderAccount]`
/// on Phoenix) that is required before calling `phoenix_place_position_conditional_order`.
/// Safe to call multiple times — Phoenix is idempotent if the account already exists.
///
/// `capacity` controls how many concurrent conditional orders the account holds (default: 8).
///
/// `remaining_accounts` layout (6 accounts):
/// ```text
/// [0]  phoenixProgram          — readonly
/// [1]  phoenixLogAuthority     — readonly
/// [2]  globalConfiguration     — readonly
/// [3]  traderAccount           — readonly  (DynamicTrader PDA: seeds=["trader", executor, 0, 0])
/// [4]  traderConditionalOrders — writable  (PDA: seeds=["conditional_orders", traderAccount])
/// [5]  systemProgram           — readonly
/// ```
pub fn phoenix_create_conditional_orders_account<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::PhoenixCreateConditionalOrdersAccount<'info>>,
    mint_address: Pubkey,
    claimant: Pubkey,
    capacity: u8
) -> Result<()> {
    let cfg = &ctx.accounts.config;

    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require_keys_eq!(mint_address, PHOENIX_REQUIRED_MINT, PrivacyError::PhoenixInvalidPool);

    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 6, PrivacyError::PhoenixInvalidAccounts);
    require_keys_eq!(remaining[0].key(), PHOENIX_PROGRAM_ID, PrivacyError::InvalidSwapProgram);

    let executor_key = ctx.accounts.executor.key();
    let executor_bump = ctx.bumps.executor;
    let executor_seeds: &[&[u8]] = &[
        b"phoenix_executor",
        mint_address.as_ref(),
        claimant.as_ref(),
        &[executor_bump],
    ];

    // Build instruction data: disc (8) + capacity (1) = 9 bytes
    let disc = phoenix_disc("create_conditional_orders_account");
    let mut data = Vec::with_capacity(9);
    data.extend_from_slice(&disc);
    data.push(capacity);

    let account_metas = vec![
        AccountMeta::new_readonly(remaining[0].key(), false), // phoenixProgram
        AccountMeta::new_readonly(remaining[1].key(), false), // logAuthority
        AccountMeta::new_readonly(remaining[2].key(), false), // globalConfiguration
        AccountMeta::new(ctx.accounts.relayer.key(), true), // payer (relayer, writable signer)
        AccountMeta::new_readonly(executor_key, false), // traderWallet (executor, readonly non-signer)
        AccountMeta::new_readonly(remaining[3].key(), false), // traderAccount (readonly)
        AccountMeta::new(remaining[4].key(), false), // traderConditionalOrders (writable)
        AccountMeta::new_readonly(remaining[5].key(), false) // systemProgram
    ];

    let ix = Instruction {
        program_id: PHOENIX_PROGRAM_ID,
        accounts: account_metas,
        data,
    };

    let cpi_infos = vec![
        remaining[1].to_account_info(), // logAuthority
        remaining[2].to_account_info(), // globalConfiguration
        ctx.accounts.relayer.to_account_info(), // payer
        ctx.accounts.executor.to_account_info(), // traderWallet (executor)
        remaining[3].to_account_info(), // traderAccount
        remaining[4].to_account_info(), // traderConditionalOrders
        remaining[5].to_account_info(), // systemProgram
        remaining[0].to_account_info() // phoenixProgram (last = program invoked)
    ];

    invoke_signed(&ix, &cpi_infos, &[executor_seeds])?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────

/// **Place an atomic bracket order (SL + TP) using the new conditional-orders API.**
///
/// Unlike the old two-call approach which places each leg separately (causing
/// `PositionSequenceInvalidated` when both SL and TP are set), this instruction
/// calls Phoenix's `PlacePositionConditionalOrder` to place both legs **atomically**
/// in a single instruction, avoiding any position-sequence race condition.
///
/// Set `has_greater = true` to include a take-profit (TP) trigger, and
/// `has_less = true` to include a stop-loss (SL) trigger.  At least one must be set.
/// Both trigger direction fields in the encoded payload are implied by their slot
/// (greaterTrigger = GreaterThan=1, lessTrigger = LessThan=0).
///
/// `size_percent`: percentage of the current position size to close (1–100; use 100 for full).
///
/// `remaining_accounts` layout (11 accounts):
/// ```text
/// [0]  phoenixProgram          — readonly
/// [1]  phoenixLogAuthority     — readonly
/// [2]  globalConfiguration     — readonly
/// [3]  traderAccount           — writable   (DynamicTrader PDA)
/// [4]  perpAssetMap            — writable
/// [5]  globalTraderIndex       — writable
/// [6]  activeTraderBuffer      — writable
/// [7]  orderbook               — writable
/// [8]  splineCollection        — writable
/// [9]  traderConditionalOrders — writable   (PDA: seeds=["conditional_orders", traderAccount])
/// [10] systemProgram           — readonly
/// ```
pub fn phoenix_place_position_conditional_order<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::PhoenixPlacePositionConditionalOrder<'info>>,
    mint_address: Pubkey,
    claimant: Pubkey,
    asset_id: u32,
    // TP (greaterTrigger) — fires when price rises above trigger
    has_greater: bool,
    greater_trigger_price: u64,
    greater_execution_price: u64,
    greater_trade_side: u8,
    greater_order_kind: u8,
    // SL (lessTrigger) — fires when price falls below trigger
    has_less: bool,
    less_trigger_price: u64,
    less_execution_price: u64,
    less_trade_side: u8,
    less_order_kind: u8,
    // Size
    size_percent: u8
) -> Result<()> {
    let cfg = &ctx.accounts.config;

    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require_keys_eq!(mint_address, PHOENIX_REQUIRED_MINT, PrivacyError::PhoenixInvalidPool);
    require!(has_greater || has_less, PrivacyError::PhoenixInvalidAccounts); // at least one leg
    require!(size_percent >= 1 && size_percent <= 100, PrivacyError::PhoenixInvalidAccounts);

    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 11, PrivacyError::PhoenixInvalidAccounts);
    require_keys_eq!(remaining[0].key(), PHOENIX_PROGRAM_ID, PrivacyError::InvalidSwapProgram);

    let executor_key = ctx.accounts.executor.key();
    let executor_bump = ctx.bumps.executor;
    let executor_seeds: &[&[u8]] = &[
        b"phoenix_executor",
        mint_address.as_ref(),
        claimant.as_ref(),
        &[executor_bump],
    ];

    // Encode TriggerOrderParams: direction(1) + tradeSide(1) + orderKind(1) + triggerPrice(8) + executionPrice(8) = 19 bytes
    let encode_trigger = |
        direction: u8,
        trade_side: u8,
        order_kind: u8,
        trigger_price: u64,
        execution_price: u64
    | -> Vec<u8> {
        let mut v = Vec::with_capacity(19);
        v.push(direction);
        v.push(trade_side);
        v.push(order_kind);
        v.extend_from_slice(&trigger_price.to_le_bytes());
        v.extend_from_slice(&execution_price.to_le_bytes());
        v
    };

    // Build instruction data:
    //   disc(8) + assetId(4) + greaterOption(1|20) + lessOption(1|20) + sizeBaseLots(1) + sizePercent(2)
    let disc = phoenix_disc("place_position_conditional_order");
    let mut data = Vec::with_capacity(55);
    data.extend_from_slice(&disc);
    data.extend_from_slice(&asset_id.to_le_bytes());

    // greaterTriggerOrder option — GreaterThan direction = 0 (Phoenix convention: 0=GreaterThan, 1=LessThan)
    if has_greater {
        data.push(0x01);
        data.extend_from_slice(
            &encode_trigger(
                0,
                greater_trade_side,
                greater_order_kind,
                greater_trigger_price,
                greater_execution_price
            )
        );
    } else {
        data.push(0x00);
    }

    // lessTriggerOrder option — LessThan direction = 1 (Phoenix convention: 0=GreaterThan, 1=LessThan)
    if has_less {
        data.push(0x01);
        data.extend_from_slice(
            &encode_trigger(
                1,
                less_trade_side,
                less_order_kind,
                less_trigger_price,
                less_execution_price
            )
        );
    } else {
        data.push(0x00);
    }

    // sizeBaseLots: None (always use sizePercent)
    data.push(0x00);

    // sizePercent: Some(size_percent)
    data.push(0x01);
    data.push(size_percent);

    let account_metas = vec![
        AccountMeta::new_readonly(remaining[0].key(), false), // phoenixProgram
        AccountMeta::new_readonly(remaining[1].key(), false), // logAuthority
        AccountMeta::new_readonly(remaining[2].key(), false), // globalConfiguration (readonly!)
        AccountMeta::new(ctx.accounts.relayer.key(), true), // payer (relayer, writable signer)
        AccountMeta::new(remaining[3].key(), false), // traderAccount
        AccountMeta::new(remaining[4].key(), false), // perpAssetMap
        AccountMeta::new(remaining[5].key(), false), // globalTraderIndex
        AccountMeta::new(remaining[6].key(), false), // activeTraderBuffer
        AccountMeta::new(remaining[7].key(), false), // orderbook
        AccountMeta::new(remaining[8].key(), false), // splineCollection
        AccountMeta::new_readonly(executor_key, true), // traderWallet (executor, readonly signer)
        AccountMeta::new(remaining[9].key(), false), // traderConditionalOrders
        AccountMeta::new_readonly(remaining[10].key(), false) // systemProgram
    ];

    let ix = Instruction {
        program_id: PHOENIX_PROGRAM_ID,
        accounts: account_metas,
        data,
    };

    let cpi_infos = vec![
        remaining[1].to_account_info(), // logAuthority
        remaining[2].to_account_info(), // globalConfiguration
        ctx.accounts.relayer.to_account_info(), // payer
        remaining[3].to_account_info(), // traderAccount
        remaining[4].to_account_info(), // perpAssetMap
        remaining[5].to_account_info(), // globalTraderIndex
        remaining[6].to_account_info(), // activeTraderBuffer
        remaining[7].to_account_info(), // orderbook
        remaining[8].to_account_info(), // splineCollection
        ctx.accounts.executor.to_account_info(), // traderWallet (executor, signer via PDA)
        remaining[9].to_account_info(), // traderConditionalOrders
        remaining[10].to_account_info(), // systemProgram
        remaining[0].to_account_info() // phoenixProgram (last = program invoked)
    ];

    invoke_signed(&ix, &cpi_infos, &[executor_seeds])?;

    emit!(PhoenixPlacePositionConditionalOrderEvent {
        mint_address,
        asset_id,
        has_greater,
        greater_trigger_price,
        greater_execution_price,
        has_less,
        less_trigger_price,
        less_execution_price,
        size_percent,
        relayer: ctx.accounts.relayer.key(),
        timestamp: Clock::get()?.unix_timestamp,
    });

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────

/// **Atomically place a resting PostOnly limit order with attached TP/SL conditionals.**
///
/// Unlike `place_position_conditional_order` (which requires an existing filled position),
/// this instruction places the limit order AND wires TP/SL to it in one Phoenix CPI.
/// The conditionals become children of the parent order: they share its size while resting,
/// become independent when the parent fully fills, and cancel automatically if the parent
/// is cancelled.
///
/// `order_packet_bytes`: raw 38-byte Borsh bytes of `OrderPacketKind::PostOnly`
///   (the full Veilo order-data buffer with the 8-byte disc prefix stripped).
/// `slot`: pass 0 (used by Phoenix only for time-based order expiry).
///
/// `remaining_accounts` layout (11 accounts):
/// ```text
/// [0]  phoenixProgram          — readonly
/// [1]  logAuthority            — readonly
/// [2]  globalConfiguration     — writable  ← differs from place_position_conditional_order
/// [3]  traderAccount           — writable
/// [4]  perpAssetMap            — writable
/// [5]  globalTraderIndex       — writable
/// [6]  activeTraderBuffer      — writable
/// [7]  orderbook               — writable
/// [8]  splineCollection        — writable
/// [9]  traderConditionalOrders — writable
/// [10] systemProgram           — readonly
/// ```
/// executor (traderWallet) and relayer (payer) come from named Veilo accounts.
pub fn phoenix_place_limit_order_with_conditionals<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::PhoenixPlaceLimitOrderWithConditionals<'info>>,
    mint_address: Pubkey,
    claimant: Pubkey,
    order_packet_bytes: Vec<u8>,
    slot: u64,
    // TP (greaterTrigger) — fires when price rises above trigger
    has_greater: bool,
    greater_trigger_price: u64,
    greater_execution_price: u64,
    greater_trade_side: u8,
    greater_order_kind: u8,
    // SL (lessTrigger) — fires when price falls below trigger
    has_less: bool,
    less_trigger_price: u64,
    less_execution_price: u64,
    less_trade_side: u8,
    less_order_kind: u8,
) -> Result<()> {
    let cfg = &ctx.accounts.config;

    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require_keys_eq!(mint_address, PHOENIX_REQUIRED_MINT, PrivacyError::PhoenixInvalidPool);
    require!(has_greater || has_less, PrivacyError::PhoenixInvalidAccounts); // at least one leg
    require!(order_packet_bytes.len() == 38, PrivacyError::PhoenixInvalidAccounts);

    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 11, PrivacyError::PhoenixInvalidAccounts);
    require_keys_eq!(remaining[0].key(), PHOENIX_PROGRAM_ID, PrivacyError::InvalidSwapProgram);

    let executor_key = ctx.accounts.executor.key();
    let executor_bump = ctx.bumps.executor;
    let executor_seeds: &[&[u8]] = &[
        b"phoenix_executor",
        mint_address.as_ref(),
        claimant.as_ref(),
        &[executor_bump],
    ];

    let encode_trigger = |
        direction: u8,
        trade_side: u8,
        order_kind: u8,
        trigger_price: u64,
        execution_price: u64
    | -> Vec<u8> {
        let mut v = Vec::with_capacity(19);
        v.push(direction);
        v.push(trade_side);
        v.push(order_kind);
        v.extend_from_slice(&trigger_price.to_le_bytes());
        v.extend_from_slice(&execution_price.to_le_bytes());
        v
    };

    // disc(8) + order_packet(38) + slot(8) + greaterOption(1|20) + lessOption(1|20)
    let disc = phoenix_disc("place_limit_order_with_conditionals");
    let mut data = Vec::with_capacity(96);
    data.extend_from_slice(&disc);
    data.extend_from_slice(&order_packet_bytes);
    data.extend_from_slice(&slot.to_le_bytes());

    // greaterTriggerOrder — Direction::GreaterThan = 0
    if has_greater {
        data.push(0x01);
        data.extend_from_slice(
            &encode_trigger(
                0,
                greater_trade_side,
                greater_order_kind,
                greater_trigger_price,
                greater_execution_price
            )
        );
    } else {
        data.push(0x00);
    }

    // lessTriggerOrder — Direction::LessThan = 1
    if has_less {
        data.push(0x01);
        data.extend_from_slice(
            &encode_trigger(
                1,
                less_trade_side,
                less_order_kind,
                less_trigger_price,
                less_execution_price
            )
        );
    } else {
        data.push(0x00);
    }

    // Phoenix account order for place_limit_order_with_conditionals:
    //   [3]=traderWallet(executor, signer), [10]=payer(relayer, writable signer)
    // This is the REVERSE of place_position_conditional_order.
    let account_metas = vec![
        AccountMeta::new_readonly(remaining[0].key(), false), // phoenixProgram
        AccountMeta::new_readonly(remaining[1].key(), false), // logAuthority
        AccountMeta::new(remaining[2].key(), false),          // globalConfiguration (writable!)
        AccountMeta::new_readonly(executor_key, true),        // traderWallet (executor, signer)
        AccountMeta::new(remaining[3].key(), false),          // traderAccount
        AccountMeta::new(remaining[4].key(), false),          // perpAssetMap
        AccountMeta::new(remaining[5].key(), false),          // globalTraderIndex
        AccountMeta::new(remaining[6].key(), false),          // activeTraderBuffer
        AccountMeta::new(remaining[7].key(), false),          // orderbook
        AccountMeta::new(remaining[8].key(), false),          // splineCollection
        AccountMeta::new(ctx.accounts.relayer.key(), true),   // payer (relayer, writable signer)
        AccountMeta::new(remaining[9].key(), false),          // traderConditionalOrders
        AccountMeta::new_readonly(remaining[10].key(), false), // systemProgram
    ];

    let ix = Instruction {
        program_id: PHOENIX_PROGRAM_ID,
        accounts: account_metas,
        data,
    };

    let cpi_infos = vec![
        remaining[1].to_account_info(), // logAuthority
        remaining[2].to_account_info(), // globalConfiguration
        ctx.accounts.executor.to_account_info(), // traderWallet (executor, signer via PDA)
        remaining[3].to_account_info(), // traderAccount
        remaining[4].to_account_info(), // perpAssetMap
        remaining[5].to_account_info(), // globalTraderIndex
        remaining[6].to_account_info(), // activeTraderBuffer
        remaining[7].to_account_info(), // orderbook
        remaining[8].to_account_info(), // splineCollection
        ctx.accounts.relayer.to_account_info(), // payer (relayer)
        remaining[9].to_account_info(), // traderConditionalOrders
        remaining[10].to_account_info(), // systemProgram
        remaining[0].to_account_info(), // phoenixProgram (last = program invoked)
    ];

    invoke_signed(&ix, &cpi_infos, &[executor_seeds])?;

    emit!(PhoenixPlaceLimitOrderWithConditionalsEvent {
        mint_address,
        has_greater,
        greater_trigger_price,
        greater_execution_price,
        has_less,
        less_trigger_price,
        less_execution_price,
        relayer: ctx.accounts.relayer.key(),
        timestamp: Clock::get()?.unix_timestamp,
    });

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────

/// **Cancel a conditional order by index from the conditional-orders collection.**
///
/// Calls Phoenix's `CancelConditionalOrder` instruction. The `conditional_order_index`
/// is the slot index (1–191) assigned when the order was placed. Use `disable_first`
/// and/or `disable_second` to cancel the individual legs (first = lessTrigger/SL,
/// second = greaterTrigger/TP).
///
/// `remaining_accounts` layout (6 accounts):
/// ```text
/// [0]  phoenixProgram          — readonly
/// [1]  phoenixLogAuthority     — readonly
/// [2]  globalConfiguration     — readonly
/// [3]  traderAccount           — writable
/// [4]  orderbook               — writable
/// [5]  traderConditionalOrders — writable
/// ```
pub fn phoenix_cancel_conditional_order<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::PhoenixCancelConditionalOrder<'info>>,
    mint_address: Pubkey,
    claimant: Pubkey,
    conditional_order_index: u8,
    disable_first: bool,
    disable_second: bool
) -> Result<()> {
    let cfg = &ctx.accounts.config;

    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require_keys_eq!(mint_address, PHOENIX_REQUIRED_MINT, PrivacyError::PhoenixInvalidPool);
    require!(conditional_order_index >= 1, PrivacyError::PhoenixInvalidAccounts);
    require!(disable_first || disable_second, PrivacyError::PhoenixInvalidAccounts);

    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 6, PrivacyError::PhoenixInvalidAccounts);
    require_keys_eq!(remaining[0].key(), PHOENIX_PROGRAM_ID, PrivacyError::InvalidSwapProgram);

    let executor_key = ctx.accounts.executor.key();
    let executor_bump = ctx.bumps.executor;
    let executor_seeds: &[&[u8]] = &[
        b"phoenix_executor",
        mint_address.as_ref(),
        claimant.as_ref(),
        &[executor_bump],
    ];

    // Build instruction data: disc(8) + conditionalOrderIndex(1) + disableFirst(1) + disableSecond(1) = 11 bytes
    let disc = phoenix_disc("cancel_conditional_order");
    let mut data = Vec::with_capacity(11);
    data.extend_from_slice(&disc);
    data.push(conditional_order_index);
    data.push(disable_first as u8);
    data.push(disable_second as u8);

    let account_metas = vec![
        AccountMeta::new_readonly(remaining[0].key(), false), // phoenixProgram
        AccountMeta::new_readonly(remaining[1].key(), false), // logAuthority
        AccountMeta::new_readonly(remaining[2].key(), false), // globalConfiguration
        AccountMeta::new(remaining[3].key(), false), // traderAccount (writable)
        AccountMeta::new_readonly(executor_key, true), // traderWallet (executor, readonly signer)
        AccountMeta::new(remaining[4].key(), false), // orderbook (writable)
        AccountMeta::new(remaining[5].key(), false) // traderConditionalOrders (writable)
    ];

    let ix = Instruction {
        program_id: PHOENIX_PROGRAM_ID,
        accounts: account_metas,
        data,
    };

    let cpi_infos = vec![
        remaining[1].to_account_info(), // logAuthority
        remaining[2].to_account_info(), // globalConfiguration
        remaining[3].to_account_info(), // traderAccount
        ctx.accounts.executor.to_account_info(), // traderWallet (executor, signer via PDA)
        remaining[4].to_account_info(), // orderbook
        remaining[5].to_account_info(), // traderConditionalOrders
        remaining[0].to_account_info() // phoenixProgram (last = program invoked)
    ];

    invoke_signed(&ix, &cpi_infos, &[executor_seeds])?;

    emit!(PhoenixCancelConditionalOrderEvent {
        mint_address,
        conditional_order_index,
        disable_first,
        disable_second,
        relayer: ctx.accounts.relayer.key(),
        timestamp: Clock::get()?.unix_timestamp,
    });

    Ok(())
}

// ─── Events ──────────────────────────────────────────────────────────────────

/// Emitted when private USDC notes are consumed and deposited into Phoenix.
#[event]
pub struct PhoenixDepositEvent {
    /// Amount deposited into Phoenix (lamports / token base units)
    pub deposit_amount: u64,
    /// Relayer fee paid from vault ATA
    pub relayer_fee: u64,
    /// Token mint (always PHOENIX_REQUIRED_MINT)
    pub mint_address: Pubkey,
    pub timestamp: i64,
}

/// Emitted when an order is placed or cancelled on Phoenix.
#[event]
pub struct PhoenixOrderEvent {
    pub mint_address: Pubkey,
    pub relayer: Pubkey,
    pub timestamp: i64,
}

/// Emitted when a market close/reduce order is placed via `phoenix_close_position`.
/// Distinct from `PhoenixOrderEvent` to allow indexers to track position-close events.
#[event]
pub struct PhoenixClosePositionEvent {
    pub mint_address: Pubkey,
    pub relayer: Pubkey,
    pub timestamp: i64,
}

/// Emitted when a Phoenix withdrawal is queued for the vault.
#[event]
pub struct PhoenixWithdrawQueuedEvent {
    /// Amount queued for withdrawal (will arrive at vault ATA after crank)
    pub amount: u64,
    pub mint_address: Pubkey,
    pub timestamp: i64,
}

/// Emitted when the vault is successfully registered as a Phoenix Eternal trader.
#[event]
pub struct PhoenixRegisterTraderEvent {
    pub mint_address: Pubkey,
    pub vault: Pubkey,
    pub trader_account: Pubkey,
    pub timestamp: i64,
}

/// Emitted when vault PhUSD is unwrapped back to USDC via EMBER.
#[event]
pub struct PhoenixEmberUnwrapEvent {
    /// Amount of PhUSD burned and USDC received (1:1, reflecting P&L)
    pub amount: u64,
    pub mint_address: Pubkey,
    pub timestamp: i64,
}

/// Emitted when the relayer calls the `consumeWithdrawQueue` Phoenix crank.
#[event]
pub struct PhoenixConsumeWithdrawQueueEvent {
    /// Token mint (always PHOENIX_REQUIRED_MINT)
    pub mint_address: Pubkey,
    pub vault: Pubkey,
    pub timestamp: i64,
}

/// Emitted when private notes are re-issued from Phoenix-returned USDC.
/// Step 4 (final) of the Phoenix exit flow.
#[event]
pub struct PhoenixReissueEvent {
    /// USDC amount backed by the newly minted notes (no token transfer — already in vault)
    pub amount: u64,
    /// Token mint (always PHOENIX_REQUIRED_MINT)
    pub mint_address: Pubkey,
    pub timestamp: i64,
}

/// Emitted when an atomic bracket order (SL+TP) is placed via the new conditional-orders API.
#[event]
pub struct PhoenixPlacePositionConditionalOrderEvent {
    pub mint_address: Pubkey,
    pub asset_id: u32,
    pub has_greater: bool,
    pub greater_trigger_price: u64,
    pub greater_execution_price: u64,
    pub has_less: bool,
    pub less_trigger_price: u64,
    pub less_execution_price: u64,
    /// Percentage of position size to close (1–100)
    pub size_percent: u8,
    pub relayer: Pubkey,
    pub timestamp: i64,
}

/// Emitted when a conditional order is cancelled from the collection.
#[event]
pub struct PhoenixCancelConditionalOrderEvent {
    pub mint_address: Pubkey,
    pub conditional_order_index: u8,
    pub disable_first: bool,
    pub disable_second: bool,
    pub relayer: Pubkey,
    pub timestamp: i64,
}

/// Emitted when a limit order with attached TP/SL conditionals is placed atomically.
#[event]
pub struct PhoenixPlaceLimitOrderWithConditionalsEvent {
    pub mint_address: Pubkey,
    pub has_greater: bool,
    pub greater_trigger_price: u64,
    pub greater_execution_price: u64,
    pub has_less: bool,
    pub less_trigger_price: u64,
    pub less_execution_price: u64,
    pub relayer: Pubkey,
    pub timestamp: i64,
}

/// Emitted when collateral is transferred between Phoenix trader sub-accounts.
#[event]
pub struct PhoenixTransferCollateralEvent {
    pub mint_address: Pubkey,
    pub amount: u64,
    pub relayer: Pubkey,
    pub timestamp: i64,
}

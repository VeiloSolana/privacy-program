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

// ─── Phoenix Eternal constants ───────────────────────────────────────────────

/// Phoenix Eternal program ID (perpetual futures DEX)
pub const PHOENIX_PROGRAM_ID: Pubkey = pubkey!("EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih");

/// Phoenix PDA seed — log authority: `["log"]`
pub const PHOENIX_LOG_SEED: &[u8] = b"log";

/// Phoenix PDA seed — global configuration: `["global"]`
pub const PHOENIX_GLOBAL_SEED: &[u8] = b"global";

/// Phoenix PDA seed prefix — trader accounts: `["trader", wallet, pda_idx, sub_idx]`
pub const PHOENIX_TRADER_SEED: &[u8] = b"trader";

/// USDC mainnet mint — the only accepted collateral on Phoenix Eternal.
#[cfg(not(any(feature = "devnet", feature = "localnet")))]
pub const PHOENIX_REQUIRED_MINT: Pubkey = pubkey!("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

/// USDC devnet/localnet mint
#[cfg(any(feature = "devnet", feature = "localnet"))]
pub const PHOENIX_REQUIRED_MINT: Pubkey = pubkey!("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU");

// ─── Discriminator helper ─────────────────────────────────────────────────────

/// Compute an Anchor instruction discriminator: `sha256("global:<name>")[0..8]`
///
/// Phoenix Eternal uses the standard Anchor discriminator scheme.
fn phoenix_disc(name: &str) -> [u8; 8] {
    use sha2::{ Digest, Sha256 };
    let preimage = format!("global:{}", name);
    let hash = Sha256::digest(preimage.as_bytes());
    hash[..8].try_into().expect("sha256 output is 32 bytes")
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
/// `remaining_accounts` layout (7 accounts):
/// ```
/// [0] phoenixProgram            — readonly; validated == PHOENIX_PROGRAM_ID
/// [1] phoenixLogAuthority       — PDA ["log"] on Phoenix; readonly
/// [2] globalConfiguration       — PDA ["global"] on Phoenix; writable
/// [3] phoenixTraderAccount      — PDA ["trader", vault, 0, 0] on Phoenix; writable
/// [4] phoenixGlobalVault        — Phoenix's USDC token account; writable
/// [5] phoenixGlobalTraderIndex  — writable
/// [6] phoenixActiveTraderBuffer — writable
/// ```
/// `vault_token_account` (named) = vault's USDC ATA (source of funds for Phoenix).
#[allow(clippy::too_many_arguments)]
pub fn phoenix_deposit_from_pool<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::PhoenixDepositFromPool<'info>>,
    root: [u8; 32],
    input_tree_id: u16,
    output_tree_id: u16,
    deposit_amount: u64,
    ext_data_hash: [u8; 32],
    mint_address: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    output_commitment_0: [u8; 32],
    output_commitment_1: [u8; 32],
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

    // ── 4. Recipient must be vault PDA (ZK proof binds destination) ──────────
    require_keys_eq!(
        ext_data.recipient,
        ctx.accounts.vault.key(),
        PrivacyError::PhoenixRecipientMustBeVault
    );

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

    // ── 8. ZK proof verification ──────────────────────────────────────────────
    // public_amount is NEGATIVE (pool is losing USDC): circuit: sumIns + pubAmt = sumOuts
    let public_amount_signed = -(deposit_amount as i64);
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

    // ── 12. CPI: Phoenix depositFunds ─────────────────────────────────────────
    // Account layout expected by Phoenix depositFunds (from IDL):
    //   0. phoenixProgram (readonly)      — self-reference for on-chain validation
    //   1. phoenixLogAuthority (readonly)  — PDA ["log"]
    //   2. globalConfiguration (writable) — PDA ["global"]
    //   3. traderWallet (signer)          — vault PDA
    //   4. traderTokenAccount (writable)  — vault USDC ATA
    //   5. traderAccount (writable)       — Phoenix trader PDA for vault
    //   6. globalVault (writable)         — Phoenix's USDC token account
    //   7. tokenProgram (readonly)
    //   8. globalTraderIndex (writable)
    //   9. activeTraderBuffer (writable)
    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 7, PrivacyError::PhoenixInvalidAccounts);
    require_keys_eq!(remaining[0].key(), PHOENIX_PROGRAM_ID, PrivacyError::InvalidSwapProgram);

    let vault_key = ctx.accounts.vault.key();
    let vault_seeds: &[&[u8]] = &[b"privacy_vault_v3", mint_address.as_ref(), &[cfg.vault_bump]];

    // Instruction data: discriminator (8 bytes) || borsh-serialized amount (u64 LE = 8 bytes)
    let mut ix_data = phoenix_disc("deposit_funds").to_vec();
    ix_data.extend_from_slice(&deposit_amount.to_le_bytes());

    let phoenix_account_metas = vec![
        AccountMeta::new_readonly(remaining[0].key(), false), // phoenixProgram
        AccountMeta::new_readonly(remaining[1].key(), false), // phoenixLogAuthority
        AccountMeta::new(remaining[2].key(), false), // globalConfiguration
        AccountMeta::new_readonly(vault_key, true), // traderWallet (vault signs)
        AccountMeta::new(ctx.accounts.vault_token_account.key(), false), // traderTokenAccount
        AccountMeta::new(remaining[3].key(), false), // traderAccount
        AccountMeta::new(remaining[4].key(), false), // globalVault
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
        ctx.accounts.vault.to_account_info(), // traderWallet
        ctx.accounts.vault_token_account.to_account_info(), // traderTokenAccount
        remaining[3].to_account_info(), // traderAccount
        remaining[4].to_account_info(), // globalVault
        ctx.accounts.token_program.to_account_info(), // tokenProgram
        remaining[5].to_account_info(), // globalTraderIndex
        remaining[6].to_account_info(), // activeTraderBuffer
        remaining[0].to_account_info() // phoenixProgram (must be in account list)
    ];

    invoke_signed(&deposit_ix, &cpi_infos, &[vault_seeds])?;

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

    // ── 15. Insert output commitments (change notes) into Merkle tree ─────────
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

    // ── 16. Emit events ───────────────────────────────────────────────────────
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
        nullifiers: input_nullifiers,
        commitments: output_commitments,
        timestamp,
    });

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
    order_data: Vec<u8>
) -> Result<()> {
    let cfg = &ctx.accounts.config;

    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require_keys_eq!(mint_address, PHOENIX_REQUIRED_MINT, PrivacyError::PhoenixInvalidPool);

    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 9, PrivacyError::PhoenixInvalidAccounts);
    require_keys_eq!(remaining[0].key(), PHOENIX_PROGRAM_ID, PrivacyError::InvalidSwapProgram);

    // Validate discriminator — only market or limit orders are accepted
    require!(order_data.len() >= 8, PrivacyError::PhoenixInvalidOrderData);
    let disc_bytes: [u8; 8] = order_data[..8].try_into().unwrap();
    let market_disc = phoenix_disc("place_market_order");
    let limit_disc = phoenix_disc("place_limit_order");
    require!(
        disc_bytes == market_disc || disc_bytes == limit_disc,
        PrivacyError::PhoenixInvalidOrderData
    );

    let vault_key = ctx.accounts.vault.key();
    let vault_seeds: &[&[u8]] = &[b"privacy_vault_v3", mint_address.as_ref(), &[cfg.vault_bump]];

    // placeMarketOrder / placeLimitOrder account layout (from Phoenix IDL):
    //   0. phoenixProgram (readonly)
    //   1. phoenixLogAuthority (readonly)
    //   2. globalConfiguration (writable)
    //   3. traderWallet (signer)
    //   4. traderAccount (writable)
    //   5. perpAssetMap (writable)
    //   6. globalTraderIndex (writable)
    //   7. activeTraderBuffer (writable)
    //   8. orderbook (writable)
    //   9. splines (writable)
    let phoenix_account_metas = vec![
        AccountMeta::new_readonly(remaining[0].key(), false), // phoenixProgram
        AccountMeta::new_readonly(remaining[1].key(), false), // phoenixLogAuthority
        AccountMeta::new(remaining[2].key(), false), // globalConfiguration
        AccountMeta::new_readonly(vault_key, true), // traderWallet (vault signs)
        AccountMeta::new(remaining[3].key(), false), // traderAccount
        AccountMeta::new(remaining[4].key(), false), // perpAssetMap
        AccountMeta::new(remaining[5].key(), false), // globalTraderIndex
        AccountMeta::new(remaining[6].key(), false), // activeTraderBuffer
        AccountMeta::new(remaining[7].key(), false), // orderbook
        AccountMeta::new(remaining[8].key(), false) // splines
    ];

    let order_ix = Instruction {
        program_id: PHOENIX_PROGRAM_ID,
        accounts: phoenix_account_metas,
        data: order_data,
    };

    let cpi_infos = vec![
        remaining[1].to_account_info(),
        remaining[2].to_account_info(),
        ctx.accounts.vault.to_account_info(), // traderWallet
        remaining[3].to_account_info(),
        remaining[4].to_account_info(),
        remaining[5].to_account_info(),
        remaining[6].to_account_info(),
        remaining[7].to_account_info(),
        remaining[8].to_account_info(),
        remaining[0].to_account_info() // phoenixProgram
    ];

    invoke_signed(&order_ix, &cpi_infos, &[vault_seeds])?;

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
    mint_address: Pubkey
) -> Result<()> {
    let cfg = &ctx.accounts.config;

    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require_keys_eq!(mint_address, PHOENIX_REQUIRED_MINT, PrivacyError::PhoenixInvalidPool);

    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 9, PrivacyError::PhoenixInvalidAccounts);
    require_keys_eq!(remaining[0].key(), PHOENIX_PROGRAM_ID, PrivacyError::InvalidSwapProgram);

    let vault_key = ctx.accounts.vault.key();
    let vault_seeds: &[&[u8]] = &[b"privacy_vault_v3", mint_address.as_ref(), &[cfg.vault_bump]];

    // cancelAll account layout (same as placeMarketOrder):
    //   0..9: same as place_market_order
    let phoenix_account_metas = vec![
        AccountMeta::new_readonly(remaining[0].key(), false),
        AccountMeta::new_readonly(remaining[1].key(), false),
        AccountMeta::new(remaining[2].key(), false),
        AccountMeta::new_readonly(vault_key, true),
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
        ctx.accounts.vault.to_account_info(),
        remaining[3].to_account_info(),
        remaining[4].to_account_info(),
        remaining[5].to_account_info(),
        remaining[6].to_account_info(),
        remaining[7].to_account_info(),
        remaining[8].to_account_info(),
        remaining[0].to_account_info()
    ];

    invoke_signed(&cancel_ix, &cpi_infos, &[vault_seeds])?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────

/// **Queue a Phoenix withdrawal back to the vault's USDC ATA.**
///
/// Calls `withdrawFunds` on Phoenix, which enqueues the withdrawal. A permissionless
/// on-chain crank (`consumeWithdrawQueue`) must be called afterward to settle the
/// USDC to `vault_token_account`. Once credited, users call `transact` (deposit) to
/// create new private notes.
///
/// `remaining_accounts` layout (10 accounts):
/// ```
/// [0] phoenixProgram            — readonly; validated == PHOENIX_PROGRAM_ID
/// [1] phoenixLogAuthority       — PDA ["log"]; readonly
/// [2] globalConfiguration       — PDA ["global"]; writable
/// [3] phoenixTraderAccount      — PDA ["trader", vault, 0, 0]; writable
/// [4] perpAssetMap              — writable
/// [5] phoenixGlobalVault        — Phoenix's USDC token account; writable
/// [6] withdrawQueue             — writable
/// [7] phoenixGlobalTraderIndex  — writable
/// [8] phoenixActiveTraderBuffer — writable
/// [9] (reserved / unused — kept for future Phoenix IDL extension)
/// ```
/// `vault_token_account` (named) = destination — vault's USDC ATA.
pub fn phoenix_queue_withdraw<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::PhoenixQueueWithdraw<'info>>,
    mint_address: Pubkey,
    amount: u64
) -> Result<()> {
    let cfg = &ctx.accounts.config;

    require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require_keys_eq!(mint_address, PHOENIX_REQUIRED_MINT, PrivacyError::PhoenixInvalidPool);
    require!(amount > 0, PrivacyError::InvalidPublicAmount);

    let remaining = ctx.remaining_accounts;
    require!(remaining.len() >= 9, PrivacyError::PhoenixInvalidAccounts);
    require_keys_eq!(remaining[0].key(), PHOENIX_PROGRAM_ID, PrivacyError::InvalidSwapProgram);

    // vault_token_account must be vault's canonical ATA for mint
    let expected_ata = get_associated_token_address(&ctx.accounts.vault.key(), &mint_address);
    require!(
        ctx.accounts.vault_token_account.key() == expected_ata,
        PrivacyError::VaultTokenAccountNotATA
    );

    let vault_key = ctx.accounts.vault.key();
    let vault_seeds: &[&[u8]] = &[b"privacy_vault_v3", mint_address.as_ref(), &[cfg.vault_bump]];

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
    //   6. globalVault (writable)
    //   7. destinationTokenAccount (writable) — vault's USDC ATA
    //   8. tokenProgram (readonly)
    //   9. globalTraderIndex (writable)
    //  10. activeTraderBuffer (writable)
    //  11. withdrawQueue (writable)
    let phoenix_account_metas = vec![
        AccountMeta::new_readonly(remaining[0].key(), false), // phoenixProgram
        AccountMeta::new_readonly(remaining[1].key(), false), // phoenixLogAuthority
        AccountMeta::new(remaining[2].key(), false), // globalConfiguration
        AccountMeta::new_readonly(vault_key, true), // traderWallet
        AccountMeta::new(remaining[3].key(), false), // traderAccount
        AccountMeta::new(remaining[4].key(), false), // perpAssetMap
        AccountMeta::new(remaining[5].key(), false), // globalVault
        AccountMeta::new(ctx.accounts.vault_token_account.key(), false), // destinationTokenAccount
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
        ctx.accounts.vault.to_account_info(), // traderWallet
        remaining[3].to_account_info(), // traderAccount
        remaining[4].to_account_info(), // perpAssetMap
        remaining[5].to_account_info(), // globalVault
        ctx.accounts.vault_token_account.to_account_info(), // destinationTokenAccount
        ctx.accounts.token_program.to_account_info(), // tokenProgram
        remaining[7].to_account_info(), // globalTraderIndex
        remaining[8].to_account_info(), // activeTraderBuffer
        remaining[6].to_account_info(), // withdrawQueue
        remaining[0].to_account_info() // phoenixProgram
    ];

    invoke_signed(&withdraw_ix, &cpi_infos, &[vault_seeds])?;

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
    mint_address: Pubkey
) -> Result<()> {
    require_keys_eq!(mint_address, PHOENIX_REQUIRED_MINT, PrivacyError::PhoenixInvalidPool);

    let cfg = &ctx.accounts.config;
    let remaining = ctx.remaining_accounts;
    // remaining: [phoenixProgram, logAuthority, globalConfiguration, traderAccount]
    require!(remaining.len() >= 4, PrivacyError::PhoenixInvalidAccounts);
    require_keys_eq!(remaining[0].key(), PHOENIX_PROGRAM_ID, PrivacyError::InvalidSwapProgram);

    let vault_key = ctx.accounts.vault.key();
    let vault_seeds: &[&[u8]] = &[b"privacy_vault_v3", mint_address.as_ref(), &[cfg.vault_bump]];

    // RegisterTraderParams { max_positions: u64, trader_pda_index: u8, trader_subaccount_index: u8 }
    let mut ix_data = phoenix_disc("register_trader").to_vec();
    ix_data.extend_from_slice(&(100u64).to_le_bytes()); // max_positions = 100
    ix_data.push(0u8); // trader_pda_index = 0
    ix_data.push(0u8); // trader_subaccount_index = 0

    // registerTrader account layout (Phoenix IDL order):
    //   [0] phoenixProgram        (readonly)         — remaining[0]
    //   [1] phoenixLogAuthority   (readonly)         — remaining[1]
    //   [2] globalConfiguration   (writable)         — remaining[2]
    //   [3] payer                 (writable, signer) — ctx.accounts.payer
    //   [4] traderWallet          (signer, PDA)      — ctx.accounts.vault
    //   [5] traderAccount         (writable, init)   — remaining[3]
    //   [6] systemProgram         (readonly)         — ctx.accounts.system_program
    let phoenix_account_metas = vec![
        AccountMeta::new_readonly(remaining[0].key(), false), // [0] phoenixProgram
        AccountMeta::new_readonly(remaining[1].key(), false), // [1] phoenixLogAuthority
        AccountMeta::new(remaining[2].key(), false), // [2] globalConfiguration
        AccountMeta::new(ctx.accounts.payer.key(), true), // [3] payer
        AccountMeta::new_readonly(vault_key, true), // [4] traderWallet (vault, PDA signer)
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
        ctx.accounts.vault.to_account_info(), // traderWallet (vault)
        remaining[3].to_account_info(), // traderAccount
        ctx.accounts.system_program.to_account_info() // systemProgram
    ];

    invoke_signed(&register_ix, &cpi_infos, &[vault_seeds])?;

    emit!(PhoenixRegisterTraderEvent {
        mint_address,
        vault: vault_key,
        trader_account: remaining[3].key(),
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
    /// Nullifiers consumed (notes burned)
    pub nullifiers: [[u8; 32]; 2],
    /// New commitments inserted (change notes)
    pub commitments: [[u8; 32]; 2],
    pub timestamp: i64,
}

/// Emitted when an order is placed or cancelled on Phoenix.
#[event]
pub struct PhoenixOrderEvent {
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

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::Instruction,
    program::invoke,
    program::invoke_signed,
};
use anchor_spl::associated_token::get_associated_token_address;
use anchor_spl::token::{ self, CloseAccount, SyncNative, Transfer };

use crate::merkle_tree::{ MerkleTree, MerkleTreeAccount, MERKLE_TREE_HEIGHT, ROOT_HISTORY_SIZE };
use crate::swap::{ SwapParams, SwapPublicInputs };
use crate::zk::{
    verify_swap_transaction_groth16,
    verify_transaction_groth16,
    SwapProof,
    TransactionProof,
};
use crate::{
    mark_nullifier_spent,
    ClosePosition,
    CommitmentEvent,
    ExtData,
    InitPositionPool,
    MergePositions,
    NoteCiphers,
    NullifierSpent,
    OpenPosition,
    PrivacyError,
    TransactionPublicInputs,
    MAX_RELAYERS,
    MAX_SWAP_FEE_BPS,
};
use crate::PoseidonHasher;

/// Token-2022 program ID
pub const TOKEN_2022_PROGRAM_ID: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

/// Associated Token Program ID
pub const ASSOCIATED_TOKEN_PROGRAM_ID: Pubkey = pubkey!(
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
);

// ============================================================================
// Position-pool data structs (re-exported from lib.rs via `pub use positions::{...}`)
// ============================================================================

/// Global config for the cross-mint position pool (one pool for all tokens).
///
/// Seeds: [b"position_config_v1"]
#[account]
pub struct PositionPoolConfig {
    pub bump: u8,
    pub authority: Pubkey,
    pub num_relayers: u8,
    pub relayers: [Pubkey; MAX_RELAYERS],
    pub num_trees: u16,
    pub next_tree_index: u16,
    pub min_swap_fee: u64,
    pub swap_fee_bps: u16,
}

impl PositionPoolConfig {
    pub const LEN: usize = 8 + 1 + 32 + 1 + 32 * MAX_RELAYERS + 2 + 2 + 8 + 2; // 568 bytes

    pub fn is_relayer(&self, key: &Pubkey) -> bool {
        let n = self.num_relayers as usize;
        self.relayers[..n].iter().any(|k| k == key)
    }
}

/// Per-nullifier marker for the position pool.
///
/// Seeds: [b"position_nullifier_v1", mint, nullifier]
/// No mint in seeds — the position pool is cross-mint.
#[account]
pub struct PositionNullifierMarker {
    pub is_spent: bool,
    pub bump: u8,
}

impl PositionNullifierMarker {
    pub const LEN: usize = 8 + 1 + 1; // 10 bytes
}

/// Per-mint vault record. Lazy-created on first deposit of each mint.
/// Stores the vault bump so the vault PDA can sign CPIs.
///
/// Seeds: [b"position_vault_v1", mint]
#[account]
pub struct PositionVaultRecord {
    pub bump: u8,
    pub vault_bump: u8,
    pub mint: Pubkey,
    pub is_token_2022: bool,
    pub total_balance: u64,
    pub position_count: u32,
}

impl PositionVaultRecord {
    pub const LEN: usize = 8 + 1 + 1 + 32 + 1 + 8 + 4; // 55 bytes
}

/// Per-position PDA keyed by poseidon(position_secret_n).
/// The key is derived client-side from the wallet private key — always recoverable.
///
/// Seeds: [b"position_pda_v1", position_pda_key]
#[account]
pub struct PositionPDA {
    pub bump: u8,
    pub mint: Pubkey,
    pub balance: u64,
    pub leaf_index: u64,
    pub tree_id: u16,
    pub is_active: bool,
    /// Ephemeral pubkey committed via ext_data.claimant in the open_position ZK proof.
    /// Must sign close_position / close_position_to_sol to prevent a whitelisted relayer
    /// from closing a victim's PDA using a different user's valid proof.
    pub claimant: Pubkey,
}

impl PositionPDA {
    pub const LEN: usize = 8 + 1 + 32 + 8 + 8 + 2 + 1 + 32; // 92 bytes
}

/// Staging buffer for a Jupiter-legs swap blob. The legs (Jupiter's setup/route/cleanup) are too
/// large to carry in `open_position`'s instruction data alongside the ZK proof, so they're written
/// here in a preceding instruction and read back. Bound to the proof via
/// `swap_params.swap_data_hash == sha256(legs)`.
///
/// Seeds: [b"swap_legs_v1", input_nullifier_0]
#[account]
pub struct SwapLegsBuffer {
    pub bump: u8,
    pub owner: Pubkey,        // relayer that staged it
    pub nullifier: [u8; 32],  // input_nullifier_0 it is bound to
    pub legs: Vec<u8>,        // full JUP_LEGS_SENTINEL ++ borsh(Vec<JupLeg>) blob
}

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
        &ASSOCIATED_TOKEN_PROGRAM_ID
    ).0
}

/// Native-SOL buffer pre-funded to the (system-owned) executor PDA so DEXs that charge a native
/// protocol fee from the swap signer (e.g. Pump.fun) can pull it. Swept back after the swap, so
/// the only real cost is the actual DEX fee. 0.05 SOL comfortably covers Pump.fun's fee.
const EXECUTOR_FEE_BUFFER_LAMPORTS: u64 = 50_000_000;

/// Transfer the native-SOL fee buffer from the relayer to the executor PDA (ordinary CPI).
fn fund_executor_fee_buffer<'info>(
    system_program: &Program<'info, System>,
    relayer: &AccountInfo<'info>,
    executor: &AccountInfo<'info>,
) -> Result<()> {
    anchor_lang::system_program::transfer(
        CpiContext::new(
            system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: relayer.clone(),
                to: executor.clone(),
            },
        ),
        EXECUTOR_FEE_BUFFER_LAMPORTS,
    )
}

/// Sweep all residual native lamports from the (system-owned) executor PDA back to the relayer,
/// signing with the executor seeds. No-op when the executor holds nothing.
fn sweep_executor_lamports<'info>(
    system_program: &Program<'info, System>,
    executor: &AccountInfo<'info>,
    relayer: &AccountInfo<'info>,
    executor_seeds: &[&[u8]],
) -> Result<()> {
    let residual = executor.lamports();
    if residual == 0 {
        return Ok(());
    }
    anchor_lang::system_program::transfer(
        CpiContext::new_with_signer(
            system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: executor.clone(),
                to: relayer.clone(),
            },
            &[executor_seeds],
        ),
        residual,
    )
}

/// Rent buffer handed to the ephemeral cosigner on top of swap_amount (covers Jupiter's WSOL-ATA
/// rent for createIdempotent; reclaimed by Jupiter's cleanup close + the post-swap cosigner sweep).
const COSIGNER_RENT_BUFFER_LAMPORTS: u64 = 20_000_000;

/// Move swap funds (swap_amount + rent buffer) from the executor PDA to the ephemeral cosigner so
/// Jupiter's wrap leg (native→WSOL from the cosigner) and ATA creation are covered. invoke_signed
/// with the executor seeds; the cosigner then signs the swap legs as a real wallet.
fn fund_cosigner<'info>(
    system_program: &AccountInfo<'info>,
    executor: &AccountInfo<'info>,
    cosigner: &AccountInfo<'info>,
    executor_seeds: &[&[u8]],
    swap_amount: u64,
) -> Result<()> {
    let amount = swap_amount
        .checked_add(COSIGNER_RENT_BUFFER_LAMPORTS)
        .ok_or(PrivacyError::ArithmeticOverflow)?;
    anchor_lang::system_program::transfer(
        CpiContext::new_with_signer(
            system_program.clone(),
            anchor_lang::system_program::Transfer { from: executor.clone(), to: cosigner.clone() },
            &[executor_seeds],
        ),
        amount,
    )
}

/// Fund the ephemeral cosigner with just the rent buffer (relayer-sourced) — used by the SELL/close
/// path, where the cosigner provides MEME (not SOL) and only needs rent for the WSOL ATA Jupiter
/// creates for the unwrap. `before`/`sol_received` is measured after this so the buffer is excluded.
fn fund_cosigner_rent<'info>(
    system_program: &AccountInfo<'info>,
    relayer: &AccountInfo<'info>,
    cosigner: &AccountInfo<'info>,
) -> Result<()> {
    anchor_lang::system_program::transfer(
        CpiContext::new(
            system_program.clone(),
            anchor_lang::system_program::Transfer { from: relayer.clone(), to: cosigner.clone() },
        ),
        COSIGNER_RENT_BUFFER_LAMPORTS,
    )
}

/// Sweep the ephemeral cosigner's residual native lamports back to the relayer. The cosigner signed
/// the outer tx, so this transfer's signature is satisfied (ordinary CPI, no invoke_signed).
fn sweep_cosigner_lamports<'info>(
    system_program: &AccountInfo<'info>,
    cosigner: &AccountInfo<'info>,
    relayer: &AccountInfo<'info>,
) -> Result<()> {
    let residual = cosigner.lamports();
    if residual == 0 {
        return Ok(());
    }
    anchor_lang::system_program::transfer(
        CpiContext::new(
            system_program.clone(),
            anchor_lang::system_program::Transfer { from: cosigner.clone(), to: relayer.clone() },
        ),
        residual,
    )
}

/// Emit NullifierSpent for a position nullifier (no NullifierSet counter needed).
fn emit_position_nullifier_spent(
    marker: &mut Account<PositionNullifierMarker>,
    nullifier: [u8; 32],
    bump: u8,
    source_mint: Pubkey,
    tree_id: u16
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
    ata_program: AccountInfo<'info>
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
            AccountMeta::new_readonly(token_program_id, false)
        ],
        data: vec![1u8], // 0x01 = idempotent
    };

    invoke(&ix, &[payer, ata, authority, mint, system_program, ata_program])?;

    Ok(())
}

/// Append a commitment to a Merkle tree and emit its `CommitmentEvent`. Shared by every
/// open/close/merge handler (they each do this 1–2×).
#[allow(clippy::too_many_arguments)]
fn append_and_emit<'info>(
    tree: &AccountLoader<'info, MerkleTreeAccount>,
    commitment: [u8; 32],
    timestamp: i64,
    mint_address: Pubkey,
    tree_id: u16,
    ephemeral_public_key: [u8; 32],
    encrypted_blob: [u8; 80],
    view_tag: u8,
) -> Result<u64> {
    let mut t = tree.load_mut()?;
    let leaf_index = t.next_index;
    MerkleTree::append::<PoseidonHasher>(commitment, &mut *t)?;
    let new_root = t.root;
    drop(t);
    emit!(CommitmentEvent {
        commitment,
        leaf_index,
        new_root,
        timestamp,
        mint_address,
        tree_id,
        ephemeral_public_key,
        encrypted_blob,
        view_tag,
    });
    Ok(leaf_index)
}

/// Validate the relayer fee against a pool's fee config and return the net amount that goes to the
/// vault. `swap_fee_bps`/`min_swap_fee` are passed as values so it works for any pool config type.
fn validate_fee_to_vault(
    received: u64,
    min_amount_out: u64,
    relayer_fee: u64,
    dest_amount: u64,
    swap_fee_bps: u16,
    min_swap_fee: u64,
) -> Result<u64> {
    require!(received >= min_amount_out, PrivacyError::InvalidPublicAmount);
    require!(received > relayer_fee, PrivacyError::InvalidPublicAmount);
    let pct_fee = (received as u128)
        .checked_mul(swap_fee_bps as u128)
        .and_then(|x| x.checked_div(10_000))
        .ok_or(PrivacyError::ArithmeticOverflow)? as u64;
    let min_fee = std::cmp::max(min_swap_fee, pct_fee);
    require!(relayer_fee >= min_fee, PrivacyError::InsufficientFee);
    let vault_amount = received.saturating_sub(relayer_fee);
    require!(vault_amount >= dest_amount, PrivacyError::InvalidPublicAmount);
    Ok(vault_amount)
}

// ============================================================================
// init_position_pool
// ============================================================================

pub fn init_position_pool(
    ctx: Context<InitPositionPool>,
    min_swap_fee: u64,
    swap_fee_bps: u16
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
// open_position — swap a source (USDC/SOL) note into a private position via Jupiter
// ============================================================================

#[inline(never)]
pub fn open_position<'info>(
    ctx: Context<'_, '_, 'info, 'info, OpenPosition<'info>>,
    source_tree_id: u16,
    source_mint: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    position_tree_id: u16,
    dest_mint: Pubkey,
    _position_pda_key: [u8; 32],
    proof: SwapProof,
    source_root: [u8; 32],
    output_commitment_0: [u8; 32], // USDC change note → source tree
    output_commitment_1: [u8; 32], // position note → position tree
    swap_params: SwapParams,
    swap_amount: u64,
    swap_data: Vec<u8>,
    ext_data: ExtData,
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

    // Validate swap program
    require!(
        ctx.accounts.swap_program.key() == crate::JUPITER_PROGRAM_ID,
        PrivacyError::InvalidSwapProgram
    );

    require!(
        ctx.accounts.source_config.mint_address == source_mint,
        PrivacyError::InvalidMintAddress
    );
    require!(source_mint != dest_mint, PrivacyError::InvalidMintAddress);

    require!(source_tree_id < ctx.accounts.source_config.num_trees, PrivacyError::InvalidTreeId);
    require!(
        position_tree_id < ctx.accounts.position_config.num_trees,
        PrivacyError::InvalidTreeId
    );

    // Relayer must be whitelisted in BOTH source and position pools.
    require!(
        ctx.accounts.source_config.is_relayer(&ctx.accounts.relayer.key()),
        PrivacyError::RelayerNotAllowed
    );
    require!(
        ctx.accounts.position_config.is_relayer(&ctx.accounts.relayer.key()),
        PrivacyError::RelayerNotAllowed
    );

    let clock = Clock::get()?;
    require!(clock.unix_timestamp <= swap_params.deadline, PrivacyError::InvalidPublicAmount);

    let input_nullifiers = [input_nullifier_0, input_nullifier_1];
    let output_commitments = [output_commitment_0, output_commitment_1];

    require!(input_nullifiers[0] != input_nullifiers[1], PrivacyError::DuplicateNullifiers);
    require!(output_commitments[0] != output_commitments[1], PrivacyError::DuplicateCommitments);
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

    // Source root must be in history; both trees must have capacity.
    let source_tree = ctx.accounts.source_tree.load()?;
    require!(MerkleTree::is_known_root(&*source_tree, source_root), PrivacyError::UnknownRoot);
    let source_cap = 1u64 << (source_tree.height as u64);
    require!(source_cap.saturating_sub(source_tree.next_index) >= 1, PrivacyError::MerkleTreeFull);
    drop(source_tree);

    let pos_tree = ctx.accounts.position_tree.load()?;
    let pos_cap = 1u64 << (pos_tree.height as u64);
    require!(pos_cap.saturating_sub(pos_tree.next_index) >= 1, PrivacyError::MerkleTreeFull);
    drop(pos_tree);

    require!(!ctx.accounts.source_nullifier_marker_0.is_spent, PrivacyError::NullifierAlreadyUsed);
    require!(!ctx.accounts.source_nullifier_marker_1.is_spent, PrivacyError::NullifierAlreadyUsed);

    mark_nullifier_spent(
        &mut ctx.accounts.source_nullifier_marker_0,
        &mut ctx.accounts.source_nullifiers,
        input_nullifiers[0],
        ctx.bumps.source_nullifier_marker_0,
        source_mint,
        source_tree_id
    )?;
    mark_nullifier_spent(
        &mut ctx.accounts.source_nullifier_marker_1,
        &mut ctx.accounts.source_nullifiers,
        input_nullifiers[1],
        ctx.bumps.source_nullifier_marker_1,
        source_mint,
        source_tree_id
    )?;

    // Executor is a system-owned PDA — ephemeral, holds no Anchor data. Signing uses ctx.bumps.

    require!(swap_amount > 0, PrivacyError::InvalidPublicAmount);

    let source_is_native = !crate::is_token_mint(&source_mint);
    // The Jupiter-legs path keeps the SOL as native lamports on the executor PDA (not WSOL) and skips
    // the WSOL sync — Jupiter's own setup (via the cosigner) wraps native→WSOL.
    let is_jup_legs =
        swap_data.len() >= 8 && swap_data[0..8] == JUP_LEGS_BUFFER_SENTINEL;

    if source_is_native && is_jup_legs {
        // fund_native_open_position(to_executor_native=true) already debited the vault and credited
        // the executor PDA with native lamports (moved to the cosigner for Jupiter's wrap setup).
        require!(
            ctx.accounts.executor.to_account_info().lamports() >= swap_amount,
            PrivacyError::InvalidSwapParams
        );
    } else if source_is_native {
        // Native SOL (WSOL-pool route): fund_native_open_position already credited the executor's
        // WSOL ATA. sync_native materialises the balance; assert it covers swap_amount.
        token::sync_native(
            CpiContext::new(ctx.accounts.token_program.to_account_info(), SyncNative {
                account: ctx.accounts.executor_source_token.to_account_info(),
            })
        )?;
        ctx.accounts.executor_source_token.reload()?;
        require!(
            ctx.accounts.executor_source_token.amount >= swap_amount,
            PrivacyError::InvalidSwapParams
        );
    } else {
        // SPL source vault → executor ATA.
        let expected_source_ata = get_associated_token_address(
            &ctx.accounts.source_vault.key(),
            &crate::effective_mint(&source_mint)
        );
        require!(
            ctx.accounts.source_vault_token_account.key() == expected_source_ata,
            PrivacyError::InvalidMintAddress
        );

        let source_vault_token_data = crate::deserialize_token_account(
            &ctx.accounts.source_vault_token_account.to_account_info()
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
                &[source_vault_seeds]
            ),
            swap_amount
        )?;
    }

    ctx.accounts.source_config.total_tvl = ctx.accounts.source_config.total_tvl
        .checked_sub(swap_amount)
        .ok_or(PrivacyError::ArithmeticOverflow)?;

    let dest_is_t22 = is_token_2022(&ctx.accounts.dest_mint_info);
    let dest_decimals = get_mint_decimals(&ctx.accounts.dest_mint_info)?;
    let dest_token_program_id = if dest_is_t22 {
        TOKEN_2022_PROGRAM_ID
    } else {
        anchor_spl::token::ID
    };

    let expected_executor_dest_ata = get_ata_address(
        &ctx.accounts.executor.key(),
        &dest_mint,
        &dest_token_program_id
    );
    require!(
        ctx.accounts.executor_dest_token.key() == expected_executor_dest_ata,
        PrivacyError::InvalidMintAddress
    );

    create_ata_idempotent(
        ctx.accounts.relayer.to_account_info(),
        ctx.accounts.executor.to_account_info(),
        ctx.accounts.dest_mint_info.to_account_info(),
        ctx.accounts.executor_dest_token.to_account_info(),
        dest_token_program_id,
        ctx.accounts.system_program.to_account_info(),
        ctx.accounts.associated_token_program.to_account_info()
    )?;

    let relayer_key = ctx.accounts.relayer.key();
    let executor_seeds: &[&[u8]] = &[
        b"position_executor",
        source_mint.as_ref(),
        dest_mint.as_ref(),
        input_nullifiers[0].as_ref(),
        relayer_key.as_ref(),
        &[ctx.bumps.executor],
    ];

    // Pre-fund the executor's native fee buffer (swept back after the swap); see helper.
    fund_executor_fee_buffer(
        &ctx.accounts.system_program,
        &ctx.accounts.relayer.to_account_info(),
        &ctx.accounts.executor.to_account_info(),
    )?;

    // Staged Jupiter-legs path: route through an ephemeral cosigner (remaining[1]) instead of the
    // executor PDA (Jupiter's bonding-curve route rejects a PDA swap signer). Move the swap funds
    // executor→cosigner so the cosigner's own wrap leg can run; swept back after the swap.
    let is_buffer_legs = swap_data.len() >= 8 && swap_data[0..8] == JUP_LEGS_BUFFER_SENTINEL;
    if is_buffer_legs {
        let cosigner = ctx.remaining_accounts
            .get(1)
            .ok_or(error!(PrivacyError::InvalidRemainingAccounts))?;
        fund_cosigner(
            &ctx.accounts.system_program.to_account_info(),
            &ctx.accounts.executor.to_account_info(),
            cosigner,
            executor_seeds,
            swap_amount,
        )?;
    }

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
        ctx.remaining_accounts
    )?;

    // Staged-legs (cosigner) path: Jupiter sends the swap output to the route's user — the cosigner's
    // dest ATA, not the executor's (Jupiter Ultra/multi-hop routes don't take a destinationTokenAccount).
    // Move it into the executor's dest ATA so the deposit/fee/close logic below is byte-for-byte the
    // same as the non-cosigner path. The cosigner co-signed the tx, so it authorizes the token move
    // (ordinary CPI). Then sweep the cosigner's leftover native lamports back to the relayer.
    if is_buffer_legs {
        let cosigner = ctx.remaining_accounts
            .get(1)
            .ok_or(error!(PrivacyError::InvalidRemainingAccounts))?
            .clone();
        let cosigner_dest_ata_key = get_ata_address(&cosigner.key(), &dest_mint, &dest_token_program_id);
        let cosigner_dest_ata = ctx.remaining_accounts.iter()
            .find(|a| a.key() == cosigner_dest_ata_key)
            .ok_or(error!(PrivacyError::InvalidRemainingAccounts))?
            .clone();
        let out_amt = if dest_is_t22 {
            read_token_2022_amount(&cosigner_dest_ata)?
        } else {
            read_token_amount_unchecked(&cosigner_dest_ata)?
        };
        require!(out_amt > 0, PrivacyError::InvalidPublicAmount);
        transfer_from_signer(
            dest_is_t22,
            &cosigner_dest_ata,
            &ctx.accounts.dest_mint_info.to_account_info(),
            &ctx.accounts.executor_dest_token.to_account_info(),
            &cosigner,
            out_amt,
            dest_decimals,
            &ctx.accounts.token_program.to_account_info(),
            &ctx.accounts.token_2022_program.to_account_info(),
        )?;
        sweep_cosigner_lamports(
            &ctx.accounts.system_program.to_account_info(),
            &cosigner,
            &ctx.accounts.relayer.to_account_info(),
        )?;
    }

    // Sweep residual native SOL (fee buffer minus any DEX fee) back to the relayer.
    sweep_executor_lamports(
        &ctx.accounts.system_program,
        &ctx.accounts.executor.to_account_info(),
        &ctx.accounts.relayer.to_account_info(),
        executor_seeds,
    )?;

    // Read amount received
    let received_amount = if dest_is_t22 {
        read_token_2022_amount(&ctx.accounts.executor_dest_token.to_account_info())?
    } else {
        read_token_amount_unchecked(&ctx.accounts.executor_dest_token.to_account_info())?
    };

    let relayer_fee = ext_data.fee;
    let vault_amount = validate_fee_to_vault(
        received_amount,
        swap_params.min_amount_out,
        relayer_fee,
        swap_params.dest_amount,
        ctx.accounts.position_config.swap_fee_bps,
        ctx.accounts.position_config.min_swap_fee,
    )?;

    // Lazy-init position vault ATA
    let vault_pda_bump = ctx.bumps.position_vault_pda;
    let expected_vault_ata = get_ata_address(
        &ctx.accounts.position_vault_pda.key(),
        &dest_mint,
        &dest_token_program_id
    );
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
        ctx.accounts.associated_token_program.to_account_info()
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
            &ctx.accounts.token_2022_program.to_account_info()
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
                &[executor_seeds]
            ),
            vault_amount
        )?;
    }

    // Pay relayer fee from executor_dest_token
    if relayer_fee > 0 {
        let expected_relayer_ata = get_ata_address(
            &ctx.accounts.relayer.key(),
            &dest_mint,
            &dest_token_program_id
        );
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
                &ctx.accounts.token_2022_program.to_account_info()
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
                    &[executor_seeds]
                ),
                relayer_fee
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

    // Insert position note (output_commitment_1) into position tree, USDC change note into source tree.
    let pos_leaf_idx = append_and_emit(
        &ctx.accounts.position_tree, output_commitments[1], clock.unix_timestamp,
        dest_mint, position_tree_id, note1_epk, note1_enc, note1_vt,
    )?;
    append_and_emit(
        &ctx.accounts.source_tree, output_commitments[0], clock.unix_timestamp,
        source_mint, source_tree_id, note0_epk, note0_enc, note0_vt,
    )?;

    // Init PositionPDA
    require!(ext_data.claimant != Pubkey::default(), PrivacyError::InvalidClaimant);
    let pos_pda = &mut ctx.accounts.position_pda;
    pos_pda.bump = ctx.bumps.position_pda;
    pos_pda.mint = dest_mint;
    pos_pda.balance = swap_params.dest_amount;
    pos_pda.leaf_index = pos_leaf_idx;
    pos_pda.tree_id = position_tree_id;
    pos_pda.is_active = true;
    pos_pda.claimant = ext_data.claimant;

    // Cleanup: verify executor_source_token is empty, then close accounts + reclaim rent
    let source_token_data = crate::deserialize_token_account(
        &ctx.accounts.executor_source_token.to_account_info()
    )?;
    require!(source_token_data.amount == 0, PrivacyError::SwapLeftoverTokens);

    token::close_account(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            CloseAccount {
                account: ctx.accounts.executor_source_token.to_account_info(),
                destination: ctx.accounts.relayer.to_account_info(),
                authority: executor_ai.clone(),
            },
            &[executor_seeds]
        )
    )?;

    // Close executor_dest_token
    if dest_is_t22 {
        close_token_2022_account(
            &ctx.accounts.executor_dest_token.to_account_info(),
            &ctx.accounts.relayer.to_account_info(),
            &executor_ai,
            executor_seeds,
            &ctx.accounts.token_2022_program.to_account_info()
        )?;
    } else {
        token::close_account(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                CloseAccount {
                    account: ctx.accounts.executor_dest_token.to_account_info(),
                    destination: ctx.accounts.relayer.to_account_info(),
                    authority: executor_ai.clone(),
                },
                &[executor_seeds]
            )
        )?;
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
    _position_pda_key: [u8; 32],
    proof: SwapProof,
    position_root: [u8; 32],
    output_commitment_0: [u8; 32], // position change note → position tree
    output_commitment_1: [u8; 32], // USDC output note → USDC tree
    swap_params: SwapParams,
    swap_amount: u64,
    swap_data: Vec<u8>,
    ext_data: ExtData,
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

    // Validate swap program
    require!(
        ctx.accounts.swap_program.key() == crate::JUPITER_PROGRAM_ID,
        PrivacyError::InvalidSwapProgram
    );

    // Validate pool config
    require!(ctx.accounts.usdc_config.mint_address == dest_mint, PrivacyError::InvalidMintAddress);
    require!(source_mint != dest_mint, PrivacyError::InvalidMintAddress);

    // Validate PositionPDA consistency
    let pos_pda = &ctx.accounts.position_pda;
    require!(pos_pda.is_active, PrivacyError::Unauthorized);
    require!(pos_pda.mint == source_mint, PrivacyError::InvalidMintAddress);
    require!(pos_pda.tree_id == position_tree_id, PrivacyError::InvalidTreeId);
    require_keys_eq!(ctx.accounts.claimant.key(), pos_pda.claimant, PrivacyError::InvalidClaimant);

    // Tree ID bounds
    require!(
        position_tree_id < ctx.accounts.position_config.num_trees,
        PrivacyError::InvalidTreeId
    );
    require!(usdc_tree_id < ctx.accounts.usdc_config.num_trees, PrivacyError::InvalidTreeId);

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
    require!(clock.unix_timestamp <= swap_params.deadline, PrivacyError::InvalidPublicAmount);

    let input_nullifiers = [input_nullifier_0, input_nullifier_1];
    let output_commitments = [output_commitment_0, output_commitment_1];

    require!(input_nullifiers[0] != input_nullifiers[1], PrivacyError::DuplicateNullifiers);
    require!(output_commitments[0] != output_commitments[1], PrivacyError::DuplicateCommitments);
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
    require!(MerkleTree::is_known_root(&*pos_tree, position_root), PrivacyError::UnknownRoot);
    let pos_cap = 1u64 << (pos_tree.height as u64);
    require!(pos_cap.saturating_sub(pos_tree.next_index) >= 1, PrivacyError::MerkleTreeFull);
    drop(pos_tree);

    // Verify USDC tree has capacity
    let usdc_tree = ctx.accounts.usdc_tree.load()?;
    let usdc_cap = 1u64 << (usdc_tree.height as u64);
    require!(usdc_cap.saturating_sub(usdc_tree.next_index) >= 1, PrivacyError::MerkleTreeFull);
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
        position_tree_id
    )?;
    emit_position_nullifier_spent(
        &mut ctx.accounts.position_nullifier_marker_1,
        input_nullifiers[1],
        ctx.bumps.position_nullifier_marker_1,
        source_mint,
        position_tree_id
    )?;

    // Detect source mint token program
    let src_is_t22 = is_token_2022(&ctx.accounts.source_mint_info);
    let src_decimals = get_mint_decimals(&ctx.accounts.source_mint_info)?;
    let src_token_program_id = if src_is_t22 {
        TOKEN_2022_PROGRAM_ID
    } else {
        anchor_spl::token::ID
    };

    // Executor is a system-owned PDA — ephemeral, holds no Anchor data. Signing uses ctx.bumps.

    require!(swap_amount > 0, PrivacyError::InvalidPublicAmount);

    // Create executor_source_token ATA (for stock) idempotently
    let expected_exec_src_ata = get_ata_address(
        &ctx.accounts.executor.key(),
        &source_mint,
        &src_token_program_id
    );
    require!(
        ctx.accounts.executor_source_token.key() == expected_exec_src_ata,
        PrivacyError::InvalidMintAddress
    );

    create_ata_idempotent(
        ctx.accounts.relayer.to_account_info(),
        ctx.accounts.executor.to_account_info(),
        ctx.accounts.source_mint_info.to_account_info(),
        ctx.accounts.executor_source_token.to_account_info(),
        src_token_program_id,
        ctx.accounts.system_program.to_account_info(),
        ctx.accounts.associated_token_program.to_account_info()
    )?;

    // Validate position_vault_ata
    let vault_pda_bump = ctx.bumps.position_vault_pda;
    let expected_vault_ata = get_ata_address(
        &ctx.accounts.position_vault_pda.key(),
        &source_mint,
        &src_token_program_id
    );
    require!(
        ctx.accounts.position_vault_ata.key() == expected_vault_ata,
        PrivacyError::InvalidMintAddress
    );

    // Check vault has sufficient balance
    let vault_balance = read_token_amount_unchecked(
        &ctx.accounts.position_vault_ata.to_account_info()
    )?;
    require!(vault_balance >= swap_amount, PrivacyError::InsufficientFundsForWithdrawal);

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
            &ctx.accounts.token_2022_program.to_account_info()
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
                &[vault_pda_seeds]
            ),
            swap_amount
        )?;
    }

    // Execute DEX swap: stock → USDC
    let relayer_key = ctx.accounts.relayer.key();
    let executor_seeds: &[&[u8]] = &[
        b"position_executor",
        source_mint.as_ref(),
        dest_mint.as_ref(),
        input_nullifiers[0].as_ref(),
        relayer_key.as_ref(),
        &[ctx.bumps.executor],
    ];

    // Pre-fund the executor PDA with native SOL for DEXs that charge a native protocol fee from
    // the swap signer (e.g. Pump.fun). Swept back to the relayer after the swap. See open_position.
    fund_executor_fee_buffer(
        &ctx.accounts.system_program,
        &ctx.accounts.relayer.to_account_info(),
        &ctx.accounts.executor.to_account_info(),
    )?;

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
        ctx.remaining_accounts
    )?;

    // Sweep residual native SOL (fee buffer minus any DEX fee) back to the relayer.
    sweep_executor_lamports(
        &ctx.accounts.system_program,
        &ctx.accounts.executor.to_account_info(),
        &ctx.accounts.relayer.to_account_info(),
        executor_seeds,
    )?;

    ctx.accounts.executor_dest_token.reload()?;
    let usdc_received = ctx.accounts.executor_dest_token.amount;

    let relayer_fee = ext_data.fee;
    let vault_usdc = validate_fee_to_vault(
        usdc_received,
        swap_params.min_amount_out,
        relayer_fee,
        swap_params.dest_amount,
        ctx.accounts.usdc_config.swap_fee_bps,
        ctx.accounts.usdc_config.min_swap_fee,
    )?;

    // Validate USDC vault ATA
    let expected_usdc_vault_ata = get_associated_token_address(
        &ctx.accounts.usdc_vault.key(),
        &crate::effective_mint(&dest_mint)
    );
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
            &[executor_seeds]
        ),
        vault_usdc
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
                &[executor_seeds]
            ),
            relayer_fee
        )?;
    }

    ctx.accounts.usdc_config.total_tvl = ctx.accounts.usdc_config.total_tvl
        .checked_add(vault_usdc)
        .ok_or(PrivacyError::ArithmeticOverflow)?;

    // Insert USDC output note (commitment_1) into USDC tree, position change note (commitment_0) into position tree.
    append_and_emit(
        &ctx.accounts.usdc_tree, output_commitments[1], clock.unix_timestamp,
        dest_mint, usdc_tree_id, note1_epk, note1_enc, note1_vt,
    )?;
    append_and_emit(
        &ctx.accounts.position_tree, output_commitments[0], clock.unix_timestamp,
        source_mint, position_tree_id, note0_epk, note0_enc, note0_vt,
    )?;

    // Update PositionVaultRecord
    let vault_record = &mut ctx.accounts.position_vault_record;
    vault_record.total_balance = vault_record.total_balance.saturating_sub(swap_amount);
    vault_record.position_count = vault_record.position_count.saturating_sub(1);

    // PositionPDA is auto-closed by Anchor `close = relayer` constraint

    // Cleanup executor
    let source_exec_balance = read_token_amount_unchecked(
        &ctx.accounts.executor_source_token.to_account_info()
    )?;
    require!(source_exec_balance == 0, PrivacyError::SwapLeftoverTokens);

    // Close executor_source_token (stock ATA)
    if src_is_t22 {
        close_token_2022_account(
            &ctx.accounts.executor_source_token.to_account_info(),
            &ctx.accounts.relayer.to_account_info(),
            &executor_ai,
            executor_seeds,
            &ctx.accounts.token_2022_program.to_account_info()
        )?;
    } else {
        token::close_account(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                CloseAccount {
                    account: ctx.accounts.executor_source_token.to_account_info(),
                    destination: ctx.accounts.relayer.to_account_info(),
                    authority: executor_ai.clone(),
                },
                &[executor_seeds]
            )
        )?;
    }

    // Close executor_dest_token (USDC ATA — always legacy SPL)
    token::close_account(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            CloseAccount {
                account: ctx.accounts.executor_dest_token.to_account_info(),
                destination: ctx.accounts.relayer.to_account_info(),
                authority: executor_ai.clone(),
            },
            &[executor_seeds]
        )
    )?;

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

/// Close a position MEME→SOL via Jupiter (staged-legs cosigner sell), depositing the native SOL into
/// the SOL privacy pool. Symmetric with the SOL→MEME open. `dest_mint` is the SOL sentinel;
/// `output_commitment_1` is the SOL output note, `output_commitment_0` the position change note.
pub fn close_position_to_sol<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::ClosePositionToSol<'info>>,
    position_tree_id: u16,
    source_mint: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    sol_tree_id: u16,
    dest_mint: Pubkey,
    _position_pda_key: [u8; 32],
    proof: SwapProof,
    position_root: [u8; 32],
    output_commitment_0: [u8; 32], // position change note → position tree
    output_commitment_1: [u8; 32], // SOL output note → SOL tree
    swap_params: SwapParams,
    swap_amount: u64,
    swap_data: Vec<u8>,
    ext_data: ExtData,
    note_ciphers: Option<NoteCiphers>
) -> Result<()> {
    let (note0_epk, note0_enc, note0_vt, note1_epk, note1_enc, note1_vt) = match note_ciphers {
        Some(c) => (c.note0_ephemeral_key, c.note0_encrypted, c.note0_view_tag, c.note1_ephemeral_key, c.note1_encrypted, c.note1_view_tag),
        None => ([0u8; 32], [0u8; 80], 0u8, [0u8; 32], [0u8; 80], 0u8),
    };

    // dest must be the SOL sentinel (native), source must be a token (meme)
    require!(!crate::is_token_mint(&dest_mint), PrivacyError::InvalidMintAddress);
    require!(crate::is_token_mint(&source_mint), PrivacyError::InvalidMintAddress);
    require!(source_mint != dest_mint, PrivacyError::InvalidMintAddress);

    // Bonding-curve sells route through Jupiter only (staged-legs cosigner) — no direct pump CPI.
    require!(
        ctx.accounts.swap_program.key() == crate::JUPITER_PROGRAM_ID,
        PrivacyError::InvalidSwapProgram
    );

    let pos_pda = &ctx.accounts.position_pda;
    require!(pos_pda.is_active, PrivacyError::Unauthorized);
    require!(pos_pda.mint == source_mint, PrivacyError::InvalidMintAddress);
    require!(pos_pda.tree_id == position_tree_id, PrivacyError::InvalidTreeId);
    require_keys_eq!(ctx.accounts.claimant.key(), pos_pda.claimant, PrivacyError::InvalidClaimant);
    require!(position_tree_id < ctx.accounts.position_config.num_trees, PrivacyError::InvalidTreeId);
    require!(sol_tree_id < ctx.accounts.sol_config.num_trees, PrivacyError::InvalidTreeId);
    require!(ctx.accounts.position_config.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
    require!(ctx.accounts.sol_config.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);

    let clock = Clock::get()?;
    require!(clock.unix_timestamp <= swap_params.deadline, PrivacyError::InvalidPublicAmount);
    require!(swap_amount > 0, PrivacyError::InvalidPublicAmount);

    let input_nullifiers = [input_nullifier_0, input_nullifier_1];
    let output_commitments = [output_commitment_0, output_commitment_1];
    require!(input_nullifiers[0] != input_nullifiers[1], PrivacyError::DuplicateNullifiers);
    require!(output_commitments[0] != output_commitments[1], PrivacyError::DuplicateCommitments);
    let zero = [0u8; 32];
    require!(input_nullifiers[0] != zero && input_nullifiers[1] != zero, PrivacyError::ZeroNullifier);
    require!(output_commitments[0] != zero && output_commitments[1] != zero, PrivacyError::ZeroCommitment);

    let proof = Box::new(proof);
    let swap_params = Box::new(swap_params);
    let ext_data = Box::new(ext_data);

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

    // Tree roots / capacity
    let pos_tree = ctx.accounts.position_tree.load()?;
    require!(MerkleTree::is_known_root(&*pos_tree, position_root), PrivacyError::UnknownRoot);
    let pos_cap = 1u64 << (pos_tree.height as u64);
    require!(pos_cap.saturating_sub(pos_tree.next_index) >= 1, PrivacyError::MerkleTreeFull);
    drop(pos_tree);
    let sol_tree = ctx.accounts.sol_tree.load()?;
    let sol_cap = 1u64 << (sol_tree.height as u64);
    require!(sol_cap.saturating_sub(sol_tree.next_index) >= 1, PrivacyError::MerkleTreeFull);
    drop(sol_tree);

    require!(!ctx.accounts.position_nullifier_marker_0.is_spent, PrivacyError::NullifierAlreadyUsed);
    require!(!ctx.accounts.position_nullifier_marker_1.is_spent, PrivacyError::NullifierAlreadyUsed);
    emit_position_nullifier_spent(&mut ctx.accounts.position_nullifier_marker_0, input_nullifiers[0], ctx.bumps.position_nullifier_marker_0, source_mint, position_tree_id)?;
    emit_position_nullifier_spent(&mut ctx.accounts.position_nullifier_marker_1, input_nullifiers[1], ctx.bumps.position_nullifier_marker_1, source_mint, position_tree_id)?;

    // Source mint token program (memes are Token-2022, but support both)
    let src_is_t22 = is_token_2022(&ctx.accounts.source_mint_info);
    let src_decimals = get_mint_decimals(&ctx.accounts.source_mint_info)?;
    let src_token_program_id = if src_is_t22 { TOKEN_2022_PROGRAM_ID } else { anchor_spl::token::ID };

    // Create executor MEME ATA + validate vault ATA
    let expected_exec_src_ata = get_ata_address(&ctx.accounts.executor.key(), &source_mint, &src_token_program_id);
    require!(ctx.accounts.executor_source_token.key() == expected_exec_src_ata, PrivacyError::InvalidMintAddress);
    create_ata_idempotent(
        ctx.accounts.relayer.to_account_info(),
        ctx.accounts.executor.to_account_info(),
        ctx.accounts.source_mint_info.to_account_info(),
        ctx.accounts.executor_source_token.to_account_info(),
        src_token_program_id,
        ctx.accounts.system_program.to_account_info(),
        ctx.accounts.associated_token_program.to_account_info()
    )?;

    let vault_pda_bump = ctx.bumps.position_vault_pda;
    let expected_vault_ata = get_ata_address(&ctx.accounts.position_vault_pda.key(), &source_mint, &src_token_program_id);
    require!(ctx.accounts.position_vault_ata.key() == expected_vault_ata, PrivacyError::InvalidMintAddress);
    let vault_balance = read_token_amount_unchecked(&ctx.accounts.position_vault_ata.to_account_info())?;
    require!(vault_balance >= swap_amount, PrivacyError::InsufficientFundsForWithdrawal);

    let relayer_key = ctx.accounts.relayer.key();
    let executor_seeds: &[&[u8]] = &[
        b"position_executor", source_mint.as_ref(), dest_mint.as_ref(),
        input_nullifiers[0].as_ref(), relayer_key.as_ref(), &[ctx.bumps.executor],
    ];
    let vault_pda_seeds: &[&[u8]] = &[b"position_vault_token_v1", source_mint.as_ref(), &[vault_pda_bump]];

    // Bonding-curve sells route through Jupiter (staged-legs cosigner) — no direct pump CPI (see
    // docs/pumpfun-direct-cpi.md). Jupiter's route signer/source must be a real wallet, so the MEME
    // goes to the ephemeral cosigner's ATA (remaining[1]); the cosigner sells it and Jupiter unwraps
    // the proceeds to the cosigner as native SOL, which we then deposit into the SOL vault.
    let is_buffer_legs = swap_data.len() >= 8 && swap_data[0..8] == JUP_LEGS_BUFFER_SENTINEL;
    require!(is_buffer_legs, PrivacyError::InvalidSwapParams);
    let sol_received: u64;
    {
        let cosigner = ctx.remaining_accounts.get(1)
            .ok_or(error!(PrivacyError::InvalidRemainingAccounts))?.clone();
        let cosigner_meme_ata_key = get_ata_address(&cosigner.key(), &source_mint, &src_token_program_id);
        let cosigner_meme_ata = ctx.remaining_accounts.iter()
            .find(|a| a.key() == cosigner_meme_ata_key)
            .ok_or(error!(PrivacyError::InvalidRemainingAccounts))?.clone();
        // Jupiter doesn't create the sell SOURCE ATA — create it and move the MEME in from the vault.
        create_ata_idempotent(
            ctx.accounts.relayer.to_account_info(), cosigner.clone(),
            ctx.accounts.source_mint_info.to_account_info(), cosigner_meme_ata.clone(),
            src_token_program_id, ctx.accounts.system_program.to_account_info(),
            ctx.accounts.associated_token_program.to_account_info(),
        )?;
        if src_is_t22 {
            token_2022_transfer_checked(
                &ctx.accounts.position_vault_ata.to_account_info(), &ctx.accounts.source_mint_info.to_account_info(),
                &cosigner_meme_ata, &ctx.accounts.position_vault_pda.to_account_info(),
                vault_pda_seeds, swap_amount, src_decimals, &ctx.accounts.token_2022_program.to_account_info(),
            )?;
        } else {
            token::transfer(CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer { from: ctx.accounts.position_vault_ata.to_account_info(), to: cosigner_meme_ata.clone(), authority: ctx.accounts.position_vault_pda.to_account_info() },
                &[vault_pda_seeds],
            ), swap_amount)?;
        }
        // Cover the cosigner's WSOL-ATA rent (Jupiter creates it for the unwrap); relayer-sourced.
        fund_cosigner_rent(&ctx.accounts.system_program.to_account_info(), &ctx.accounts.relayer.to_account_info(), &cosigner)?;
        let before = cosigner.lamports();
        execute_dex_swap(
            &ctx.accounts.swap_program, &ctx.accounts.jupiter_event_authority,
            ctx.accounts.executor.to_account_info(),
            &ctx.accounts.executor_source_token.to_account_info(),
            &ctx.accounts.executor_source_token.to_account_info(),
            &ctx.accounts.token_program, executor_seeds, &swap_data, &swap_params, swap_amount, source_mint, dest_mint,
            ctx.remaining_accounts,
        )?;
        sol_received = cosigner.lamports().checked_sub(before).ok_or(PrivacyError::ArithmeticOverflow)?;
    }

    let relayer_fee = ext_data.fee;
    let vault_sol = validate_fee_to_vault(
        sol_received,
        swap_params.min_amount_out,
        relayer_fee,
        swap_params.dest_amount,
        ctx.accounts.sol_config.swap_fee_bps,
        ctx.accounts.sol_config.min_swap_fee,
    )?;

    // Deposit the SOL proceeds (from the cosigner) into the SOL vault, then sweep its leftover.
    let cosigner = ctx.remaining_accounts.get(1)
        .ok_or(error!(PrivacyError::InvalidRemainingAccounts))?.clone();
    anchor_lang::system_program::transfer(
        CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer { from: cosigner.clone(), to: ctx.accounts.sol_vault.to_account_info() },
        ),
        vault_sol,
    )?;
    sweep_cosigner_lamports(&ctx.accounts.system_program.to_account_info(), &cosigner, &ctx.accounts.relayer.to_account_info())?;

    ctx.accounts.sol_config.total_tvl = ctx.accounts.sol_config.total_tvl.checked_add(vault_sol).ok_or(PrivacyError::ArithmeticOverflow)?;

    // Insert SOL output note (commitment_1) into the SOL tree, position change note (commitment_0) into the position tree.
    append_and_emit(
        &ctx.accounts.sol_tree, output_commitments[1], clock.unix_timestamp,
        dest_mint, sol_tree_id, note1_epk, note1_enc, note1_vt,
    )?;
    append_and_emit(
        &ctx.accounts.position_tree, output_commitments[0], clock.unix_timestamp,
        source_mint, position_tree_id, note0_epk, note0_enc, note0_vt,
    )?;

    // Update vault record
    let vault_record = &mut ctx.accounts.position_vault_record;
    vault_record.total_balance = vault_record.total_balance.saturating_sub(swap_amount);
    vault_record.position_count = vault_record.position_count.saturating_sub(1);

    // Close executor MEME ATA (must be drained by the sell)
    let executor_ai = ctx.accounts.executor.to_account_info();
    let src_exec_balance = read_token_amount_unchecked(&ctx.accounts.executor_source_token.to_account_info())?;
    require!(src_exec_balance == 0, PrivacyError::SwapLeftoverTokens);
    if src_is_t22 {
        close_token_2022_account(&ctx.accounts.executor_source_token.to_account_info(), &ctx.accounts.relayer.to_account_info(), &executor_ai, executor_seeds, &ctx.accounts.token_2022_program.to_account_info())?;
    } else {
        token::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            CloseAccount { account: ctx.accounts.executor_source_token.to_account_info(), destination: ctx.accounts.relayer.to_account_info(), authority: executor_ai.clone() },
            &[executor_seeds]
        ))?;
    }
    // PositionPDA auto-closed by Anchor `close = relayer`.
    Ok(())
}

// ============================================================================
// Staged Jupiter-legs execution: run Jupiter's setup+route+cleanup instructions via invoke_signed.
// Supports any route Jupiter emits (incl. native-SOL bonding curves) without hand-building the inner
// instruction or tracking rotating fee accounts. Bound to the proof via swap_data_hash.
// ============================================================================

/// swap_data sentinel that marks the "Jupiter legs" encoding (not a real Anchor discriminator).
const JUP_LEGS_SENTINEL: [u8; 8] = [0x6a, 0x75, 0x70, 0x6c, 0x65, 0x67, 0x73, 0x00]; // "juplegs\0"
/// swap_data sentinel marking "Jupiter legs staged in a SwapLegsBuffer" — open_position's swap_data
/// is just this 8-byte tag; the real legs blob lives in remaining[0] (the buffer PDA).
const JUP_LEGS_BUFFER_SENTINEL: [u8; 8] = [0x6a, 0x75, 0x70, 0x6c, 0x65, 0x67, 0x62, 0x00]; // "juplegb\0"

/// One Jupiter instruction to execute. `account_indices` index into remaining_accounts.
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct JupLeg {
    pub program_id: Pubkey,
    pub account_indices: Vec<u8>,
    pub data: Vec<u8>,
}

/// Only these programs may appear as a leg program (defense-in-depth on top of the proof binding).
fn is_allowed_leg_program(p: &Pubkey) -> bool {
    *p == anchor_lang::solana_program::system_program::ID ||
        *p == anchor_spl::token::ID ||
        *p == TOKEN_2022_PROGRAM_ID ||
        *p == ASSOCIATED_TOKEN_PROGRAM_ID ||
        *p == crate::JUPITER_PROGRAM_ID ||
        *p == pubkey!("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
}

/// Execute a serialized list of Jupiter legs (swap_data = sentinel ++ borsh(Vec<JupLeg>)).
/// The executor PDA is marked signer wherever it appears; every other account is non-signer, so a
/// relayer cannot make an arbitrary account sign. swap_data is bound to the proof hash by the caller.
fn execute_jup_legs<'info>(
    executor: &AccountInfo<'info>,
    executor_seeds: &[&[u8]],
    cosigner: Pubkey,
    swap_data: &[u8],
    remaining: &[AccountInfo<'info>],
) -> Result<()> {
    let legs: Vec<JupLeg> = Vec::<JupLeg>::try_from_slice(&swap_data[8..])
        .map_err(|_| error!(PrivacyError::InvalidSwapParams))?;
    let exec_key = executor.key();
    for leg in legs.iter() {
        require!(is_allowed_leg_program(&leg.program_id), PrivacyError::InvalidSwapProgram);
        let mut metas = Vec::with_capacity(leg.account_indices.len());
        let mut infos = Vec::with_capacity(leg.account_indices.len());
        for &idx in leg.account_indices.iter() {
            let acc = remaining
                .get(idx as usize)
                .ok_or(error!(PrivacyError::InvalidRemainingAccounts))?;
            // The executor PDA signs via invoke_signed; the ephemeral cosigner signed the outer tx,
            // so its signature propagates into this CPI. Jupiter's bonding-curve route then sees a
            // real wallet signer (not a PDA), avoiding the route's PDA-signer rejection.
            let is_signer = acc.key() == exec_key || acc.key() == cosigner;
            metas.push(if acc.is_writable {
                AccountMeta::new(acc.key(), is_signer)
            } else {
                AccountMeta::new_readonly(acc.key(), is_signer)
            });
            infos.push(acc.clone());
        }
        let ix = Instruction { program_id: leg.program_id, accounts: metas, data: leg.data.clone() };
        invoke_signed(&ix, &infos, &[executor_seeds])?;
    }
    Ok(())
}

// ============================================================================
// Jupiter swap execution — dispatches to the staged-legs path or a single Jupiter route.
// ============================================================================

#[inline(never)]
fn execute_dex_swap<'info>(
    swap_program: &UncheckedAccount<'info>,
    jupiter_event_authority: &UncheckedAccount<'info>,
    executor: AccountInfo<'info>,
    executor_source_token: &AccountInfo<'info>,
    executor_dest_token: &AccountInfo<'info>,
    // token_program + swap_amount were used by the removed direct Raydium/pump CPI branches; the
    // Jupiter path binds the swap via swap_data_hash and the handlers enforce amounts. Kept in the
    // signature for call-site stability.
    _token_program: &Program<'info, anchor_spl::token::Token>,
    executor_seeds: &[&[u8]],
    swap_data: &[u8],
    swap_params: &SwapParams,
    _swap_amount: u64,
    source_mint: Pubkey,
    dest_mint: Pubkey,
    remaining: &[AccountInfo<'info>]
) -> Result<()> {
    // Staged legs: swap_data is just JUP_LEGS_BUFFER_SENTINEL; the real legs blob lives in the
    // SwapLegsBuffer PDA at remaining[0] (keeps it out of the proof-carrying instruction data).
    if swap_data.len() >= 8 && swap_data[0..8] == JUP_LEGS_BUFFER_SENTINEL {
        // remaining[0] = SwapLegsBuffer PDA, remaining[1] = ephemeral cosigner, remaining[2..] = legs.
        let buffer_acc = remaining.get(0).ok_or(error!(PrivacyError::InvalidRemainingAccounts))?;
        require!(buffer_acc.owner == &crate::ID, PrivacyError::InvalidRemainingAccounts);
        let cosigner = remaining.get(1).ok_or(error!(PrivacyError::InvalidRemainingAccounts))?.key();
        let buf = SwapLegsBuffer::try_deserialize(
            &mut &buffer_acc.try_borrow_data()?[..]
        ).map_err(|_| error!(PrivacyError::InvalidSwapParams))?;
        let computed: [u8; 32] = solana_sha256_hasher::hash(&buf.legs).to_bytes();
        require!(computed == swap_params.swap_data_hash, PrivacyError::InvalidSwapParams);
        return execute_jup_legs(&executor, executor_seeds, cosigner, &buf.legs, &remaining[2..]);
    }

    // Position swaps route exclusively through Jupiter (route / shared-accounts-route, + the
    // staged-legs cosigner branch handled above). Direct Raydium CPMM/AMM and Pump.fun CPI paths
    // were removed — the position pool never produces those swap_data forms. See
    // docs/pumpfun-direct-cpi.md for the removed pump direct-CPI recipe.
    let is_jupiter =
        swap_data.len() >= 8 &&
        (swap_data[0..8] == [0xe5, 0x17, 0xcb, 0x97, 0x7a, 0xe3, 0xad, 0x2a] ||
            swap_data[0..8] == [0xc1, 0x20, 0x9b, 0x33, 0x41, 0xd6, 0x9c, 0x81] ||
            swap_data[0..8] == [0xd0, 0x33, 0xef, 0x97, 0x7b, 0x2b, 0xed, 0x5c] ||
            swap_data[0..8] == [0xb0, 0xd1, 0x69, 0xa8, 0x9a, 0x7d, 0x45, 0x3e]);

    if is_jupiter {
        require!(
            jupiter_event_authority.key() == crate::JUPITER_EVENT_AUTHORITY,
            PrivacyError::Unauthorized
        );

        let mut jupiter_accounts = Vec::new();
        let mut account_infos = Vec::new();

        let is_shared =
            swap_data[0..8] == [0xc1, 0x20, 0x9b, 0x33, 0x41, 0xd6, 0x9c, 0x81] ||
            swap_data[0..8] == [0xb0, 0xd1, 0x69, 0xa8, 0x9a, 0x7d, 0x45, 0x3e];

        if is_shared {
            require!(remaining.len() >= 9, PrivacyError::JupiterInsufficientAccounts);
            require!(
                remaining[7].key() == crate::effective_mint(&source_mint),
                PrivacyError::InvalidMintAddress
            );
            require!(
                remaining[8].key() == crate::effective_mint(&dest_mint),
                PrivacyError::InvalidMintAddress
            );

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
                        jupiter_accounts.push(
                            if acc.is_writable {
                                AccountMeta::new(acc.key(), false)
                            } else {
                                AccountMeta::new_readonly(acc.key(), false)
                            }
                        );
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
                        jupiter_accounts.push(
                            if acc.is_writable {
                                AccountMeta::new(acc.key(), false)
                            } else {
                                AccountMeta::new_readonly(acc.key(), false)
                            }
                        );
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
    token_2022_program: &AccountInfo<'info>
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
            AccountMeta::new_readonly(authority.key(), true)
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[from.clone(), mint.clone(), to.clone(), authority.clone(), token_2022_program.clone()],
        &[signer_seeds]
    )?;

    Ok(())
}

/// close_account CPI to Token-2022 program.
fn close_token_2022_account<'info>(
    account: &AccountInfo<'info>,
    destination: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    signer_seeds: &[&[u8]],
    token_2022_program: &AccountInfo<'info>
) -> Result<()> {
    // Token-2022 close_account discriminator is 0x09 (9)
    let ix = Instruction {
        program_id: TOKEN_2022_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(account.key(), false),
            AccountMeta::new(destination.key(), false),
            AccountMeta::new_readonly(authority.key(), true)
        ],
        data: vec![9u8],
    };

    invoke_signed(
        &ix,
        &[account.clone(), destination.clone(), authority.clone(), token_2022_program.clone()],
        &[signer_seeds]
    )?;

    Ok(())
}

/// Transfer tokens where `authority` is a **real transaction signer** (not a PDA) — e.g. the
/// ephemeral cosigner moving the Jupiter swap output into the executor's dest ATA. Uses `invoke`
/// (the authority's signature comes from the outer tx), so no signer seeds. Handles Token + Token-2022.
#[allow(clippy::too_many_arguments)]
fn transfer_from_signer<'info>(
    is_t22: bool,
    from: &AccountInfo<'info>,
    mint: &AccountInfo<'info>,
    to: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    amount: u64,
    decimals: u8,
    token_program: &AccountInfo<'info>,
    token_2022_program: &AccountInfo<'info>,
) -> Result<()> {
    if is_t22 {
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
        invoke(&ix, &[from.clone(), mint.clone(), to.clone(), authority.clone(), token_2022_program.clone()])?;
    } else {
        let mut data = vec![3u8]; // SPL Token transfer
        data.extend_from_slice(&amount.to_le_bytes());
        let ix = Instruction {
            program_id: anchor_spl::token::ID,
            accounts: vec![
                AccountMeta::new(from.key(), false),
                AccountMeta::new(to.key(), false),
                AccountMeta::new_readonly(authority.key(), true),
            ],
            data,
        };
        invoke(&ix, &[from.clone(), to.clone(), authority.clone(), token_program.clone()])?;
    }
    Ok(())
}

/// Read token amount from a raw account info (works for Token and Token-2022).
/// TokenAccount amount is stored at bytes 64..72.
fn read_token_amount_unchecked(account: &AccountInfo) -> Result<u64> {
    require!(
        account.owner == &anchor_spl::token::ID || account.owner == &TOKEN_2022_PROGRAM_ID,
        PrivacyError::InvalidTokenAccountOwner
    );
    let data = account.try_borrow_data()?;
    require!(data.len() >= 72, PrivacyError::MissingTokenAccount);
    Ok(
        u64::from_le_bytes(
            data[64..72].try_into().map_err(|_| error!(PrivacyError::MissingTokenAccount))?
        )
    )
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
    merged_amount: u64
) -> Result<()> {
    // Validate both PDAs are active and same mint
    require!(ctx.accounts.position_pda_0.is_active, PrivacyError::Unauthorized);
    require!(ctx.accounts.position_pda_1.is_active, PrivacyError::Unauthorized);
    require!(ctx.accounts.position_pda_0.mint == mint, PrivacyError::InvalidMintAddress);
    require!(ctx.accounts.position_pda_1.mint == mint, PrivacyError::InvalidMintAddress);
    require!(ctx.accounts.position_pda_0.tree_id == input_tree_id, PrivacyError::InvalidTreeId);
    require!(ctx.accounts.position_pda_1.tree_id == input_tree_id, PrivacyError::InvalidTreeId);

    // Tree ID bounds
    require!(input_tree_id < ctx.accounts.position_config.num_trees, PrivacyError::InvalidTreeId);
    require!(output_tree_id < ctx.accounts.position_config.num_trees, PrivacyError::InvalidTreeId);

    // Relayer whitelisting
    require!(
        ctx.accounts.position_config.is_relayer(&ctx.accounts.relayer.key()),
        PrivacyError::RelayerNotAllowed
    );

    // Nullifier sanity checks
    let input_nullifiers = [input_nullifier_0, input_nullifier_1];
    let output_commitments = [output_commitment_0, output_commitment_1];
    let zero = [0u8; 32];
    require!(input_nullifiers[0] != input_nullifiers[1], PrivacyError::DuplicateNullifiers);
    require!(
        input_nullifiers[0] != zero && input_nullifiers[1] != zero,
        PrivacyError::ZeroNullifier
    );
    require!(
        output_commitments[0] != zero && output_commitments[1] != zero,
        PrivacyError::ZeroCommitment
    );

    // Verify position tree root is in history
    let in_tree = ctx.accounts.input_tree.load()?;
    require!(MerkleTree::is_known_root(&*in_tree, position_root), PrivacyError::UnknownRoot);
    drop(in_tree);

    // Verify output tree has capacity for 2 new leaves
    let out_tree = ctx.accounts.output_tree.load()?;
    let out_cap = 1u64 << (out_tree.height as u64);
    require!(out_cap.saturating_sub(out_tree.next_index) >= 2, PrivacyError::MerkleTreeFull);
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
        input_tree_id
    )?;
    emit_position_nullifier_spent(
        &mut ctx.accounts.position_nullifier_marker_1,
        input_nullifiers[1],
        ctx.bumps.position_nullifier_marker_1,
        mint,
        input_tree_id
    )?;

    let clock = Clock::get()?;

    // Insert both output commitments into the output position tree (same tree, sequential leaves).
    let merged_leaf_idx = append_and_emit(
        &ctx.accounts.output_tree, output_commitments[0], clock.unix_timestamp,
        mint, output_tree_id, [0u8; 32], [0u8; 80], 0,
    )?;
    append_and_emit(
        &ctx.accounts.output_tree, output_commitments[1], clock.unix_timestamp,
        mint, output_tree_id, [0u8; 32], [0u8; 80], 0,
    )?;

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

// sha256("global:open_position")[..8]
const OPEN_POSITION_DISCRIMINATOR: [u8; 8] = [0x87, 0x80, 0x2f, 0x4d, 0x0f, 0x98, 0xf0, 0x31];

/// Debit the SOL vault and credit the executor before open_position.
/// Raw lamport mutation — must be a separate instruction from open_position to avoid
/// Solana's per-instruction balance conservation check.
/// Pairing guard enforces open_position follows atomically in the same tx, so the
/// executor is validated there and any failure rolls back the vault deduction.
pub fn fund_native_open_position(
    ctx: Context<crate::FundNativeOpenPosition>,
    source_mint: Pubkey,
    swap_amount: u64,
    to_executor_native: bool, // false → WSOL ATA (AMM), true → native lamports (Pump.fun)
) -> Result<()> {
    {
        use anchor_lang::solana_program::sysvar::instructions as ix_sysvar;
        let ixs = ctx.accounts.instructions_sysvar.to_account_info();
        let current_idx = ix_sysvar::load_current_index_checked(&ixs)? as usize;
        let next_ix = ix_sysvar::load_instruction_at_checked(current_idx + 1, &ixs)
            .map_err(|_| error!(PrivacyError::Unauthorized))?;
        require_keys_eq!(next_ix.program_id, crate::ID, PrivacyError::Unauthorized);
        require!(
            next_ix.data.len() >= 8 && next_ix.data[..8] == OPEN_POSITION_DISCRIMINATOR,
            PrivacyError::Unauthorized
        );
    }
    require!(!crate::is_token_mint(&source_mint), PrivacyError::InvalidMintAddress);
    require!(
        ctx.accounts.source_config.is_relayer(&ctx.accounts.relayer.key()),
        PrivacyError::RelayerNotAllowed
    );
    require!(swap_amount > 0, PrivacyError::InvalidPublicAmount);

    let vault_ai = ctx.accounts.source_vault.to_account_info();
    let rent_exempt_min = anchor_lang::solana_program::rent::Rent
        ::get()?
        .minimum_balance(vault_ai.data_len());
    require!(
        vault_ai.lamports() >= swap_amount + rent_exempt_min,
        PrivacyError::InsufficientFundsForWithdrawal
    );

    **vault_ai.try_borrow_mut_lamports()? = vault_ai
        .lamports()
        .checked_sub(swap_amount)
        .ok_or(PrivacyError::ArithmeticOverflow)?;

    let credit_to = if to_executor_native {
        ctx.accounts.executor.to_account_info()
    } else {
        ctx.accounts.executor_source_token.to_account_info()
    };
    **credit_to.try_borrow_mut_lamports()? = credit_to
        .lamports()
        .checked_add(swap_amount)
        .ok_or(PrivacyError::ArithmeticOverflow)?;

    Ok(())
}

/// Write a Jupiter-legs blob into the buffer PDA (see `SwapLegsBuffer`). Called before
/// `open_position`; the blob is read back there and bound to the proof via `swap_data_hash`.
pub fn stage_swap_legs(
    ctx: Context<crate::StageSwapLegs>,
    input_nullifier_0: [u8; 32],
    legs: Vec<u8>,
) -> Result<()> {
    require!(legs.len() >= 8, PrivacyError::InvalidSwapParams);
    require!(legs[0..8] == JUP_LEGS_SENTINEL, PrivacyError::InvalidSwapParams);
    let buffer = &mut ctx.accounts.buffer;
    buffer.bump = ctx.bumps.buffer;
    buffer.owner = ctx.accounts.relayer.key();
    buffer.nullifier = input_nullifier_0;
    buffer.legs = legs;
    Ok(())
}

/// Reclaim a staged buffer's rent (the `close` constraint handles the lamport refund + close).
pub fn close_swap_legs(_ctx: Context<crate::CloseSwapLegs>) -> Result<()> {
    Ok(())
}

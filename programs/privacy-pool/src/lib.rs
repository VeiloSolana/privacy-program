use anchor_lang::prelude::*;
use anchor_lang::system_program;
use light_hasher::Poseidon;

pub mod groth16;
pub mod merkle_tree;
pub mod vk_constants;
pub mod zk;

use merkle_tree::{MerkleTree, MerkleTreeAccount, MERKLE_TREE_HEIGHT, ROOT_HISTORY_SIZE};
use zk::{verify_withdraw_groth16, WithdrawProof};

declare_id!("8o61scVoCHLQij6s9E4EXzbXJg58Bku9C16frkVociwP");

// ---- Constants ----

pub type PoseidonHasher = Poseidon;
pub const MAX_DENOMS: usize = 4;
pub const MAX_RELAYERS: usize = 16;

/// Only kept as a conceptual cap on leaves in the old design.
pub const TREE_DEPTH: usize = 32;

// ---- Accounts ----

#[account]
pub struct PrivacyConfig {
    /// PDA bump for this config
    pub bump: u8,
    /// PDA bump for vault
    pub vault_bump: u8,
    /// Admin who can configure pool and relayers
    pub admin: Pubkey,
    /// Is pool paused?
    pub paused: bool,
    /// Fee in basis points (0–10_000)
    pub fee_bps: u16,

    /// Number of active denominations
    pub num_denoms: u8,
    /// Supported fixed denominations (in lamports)
    pub denoms: [u64; MAX_DENOMS],

    /// Total value locked per denom index
    pub tvl: [u64; MAX_DENOMS],

    /// Relayer registry
    pub num_relayers: u8,
    pub relayers: [Pubkey; MAX_RELAYERS],
}

impl PrivacyConfig {
    pub const LEN: usize = 8 +   // discriminator
        1 +   // bump
        1 +   // vault_bump
        32 +  // admin
        1 +   // paused
        2 +   // fee_bps
        1 +   // num_denoms
        8 * MAX_DENOMS + // denoms
        8 * MAX_DENOMS + // tvl
        1 +   // num_relayers
        32 * MAX_RELAYERS; // relayers

    pub fn is_relayer(&self, key: &Pubkey) -> bool {
        let n = self.num_relayers as usize;
        self.relayers[..n].iter().any(|k| k == key)
    }
}

#[account]
pub struct Vault {
    /// PDA bump for this vault
    pub bump: u8,
}

impl Vault {
    pub const LEN: usize = 8 + 1;
}

/// Nullifier set metadata (actual nullifiers stored as individual PDAs).
#[account]
pub struct NullifierSet {
    pub bump: u8,
    pub count: u32,
}

impl NullifierSet {
    pub const LEN: usize = 8 + 1 + 4; // 13 bytes
}

/// Per-nullifier PDA marker (created when nullifier is spent)
#[account]
pub struct NullifierMarker {
    /// The nullifier that was spent
    pub nullifier: [u8; 32],
    /// Unix timestamp when spent
    pub timestamp: i64,
    /// Sequential withdrawal index
    pub withdrawal_index: u32,
    /// PDA bump
    pub bump: u8,
}

impl NullifierMarker {
    pub const LEN: usize = 8 + 32 + 8 + 4 + 1; // 53 bytes
}

// ---- ZK public inputs (for withdraw circuit) ----

/// Public inputs passed to the zk circuit for a withdraw.
///
/// Circom `WithdrawCircuit(DEPTH)` must use:
///   0: Merkle root
///   1: nullifier
///   2: denom index
///   3: recipient pubkey
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct WithdrawPublicInputs {
    pub root: [u8; 32],
    pub nullifier: [u8; 32],
    pub denom_index: u8,
    pub recipient: Pubkey,
}

// ---- Instruction contexts ----

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = admin,
        seeds = [b"privacy_config_v3"],
        bump,
        space = PrivacyConfig::LEN
    )]
    pub config: Account<'info, PrivacyConfig>,

    #[account(
        init,
        payer = admin,
        seeds = [b"privacy_vault_v3"],
        bump,
        space = Vault::LEN
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        init,
        payer = admin,
        seeds = [b"privacy_note_tree_v3"],
        bump,
        space = MerkleTreeAccount::LEN,
    )]
    pub note_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        init,
        payer = admin,
        seeds = [b"privacy_nullifiers_v3"],
        bump,
        space = NullifierSet::LEN
    )]
    pub nullifiers: Account<'info, NullifierSet>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ConfigAdmin<'info> {
    #[account(
        mut,
        seeds = [b"privacy_config_v3"],
        bump = config.bump,
        has_one = admin
    )]
    pub config: Account<'info, PrivacyConfig>,

    #[account(mut)]
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct DepositFixed<'info> {
    #[account(
        mut,
        seeds = [b"privacy_config_v3"],
        bump = config.bump
    )]
    pub config: Account<'info, PrivacyConfig>,

    #[account(
        mut,
        seeds = [b"privacy_vault_v3"],
        bump = config.vault_bump
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        mut,
        seeds = [b"privacy_note_tree_v3"],
        bump,
    )]
    pub note_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(mut)]
    pub depositor: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(root: [u8; 32], nullifier: [u8; 32], denom_index: u8, recipient_pk: Pubkey)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"privacy_config_v3"],
        bump = config.bump
    )]
    pub config: Account<'info, PrivacyConfig>,

    #[account(
        mut,
        seeds = [b"privacy_vault_v3"],
        bump = config.vault_bump
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        mut,
        seeds = [b"privacy_note_tree_v3"],
        bump,
    )]
    pub note_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        mut,
        seeds = [b"privacy_nullifiers_v3"],
        bump = nullifiers.bump
    )]
    pub nullifiers: Account<'info, NullifierSet>,

    /// Per-nullifier PDA marker (must not exist - ensures nullifier is fresh)
    #[account(
        init,
        payer = relayer,
        seeds = [b"nullifier_v3", nullifier.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub nullifier_marker: Account<'info, NullifierMarker>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// CHECK: Just a normal system-owned recipient account
    #[account(mut)]
    pub recipient: SystemAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct TransferPublicInputs {
    pub old_root: [u8; 32],
    pub old_nullifier: [u8; 32],
    pub new_commitment: [u8; 32],
    pub denom_index: u8,
}

#[derive(Accounts)]
#[instruction(old_root: [u8; 32], old_nullifier: [u8; 32], new_commitment: [u8; 32], denom_index: u8)]
pub struct PrivateTransfer<'info> {
    #[account(
        mut,
        seeds = [b"privacy_config_v3"],
        bump = config.bump
    )]
    pub config: Account<'info, PrivacyConfig>,

    #[account(
        mut,
        seeds = [b"privacy_note_tree_v3"],
        bump,
    )]
    pub note_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        mut,
        seeds = [b"privacy_nullifiers_v3"],
        bump = nullifiers.bump
    )]
    pub nullifiers: Account<'info, NullifierSet>,

    /// Per-nullifier PDA marker for old nullifier (must not exist)
    #[account(
        init,
        payer = sender,
        seeds = [b"nullifier_v3", old_nullifier.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub nullifier_marker: Account<'info, NullifierMarker>,

    #[account(mut)]
    pub sender: Signer<'info>, // Could be relayer

    pub system_program: Program<'info, System>,
}

pub struct TransferHint {
    pub old_root: [u8; 32],
    pub old_nullifier: [u8; 32],
    pub new_commitment: [u8; 32],
    pub denom_index: u8,
}

// ---- Program ----

#[program]
pub mod privacy_pool {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, denoms: Vec<u64>, fee_bps: u16) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        let vault = &mut ctx.accounts.vault;
        let nulls = &mut ctx.accounts.nullifiers;

        let mut tree = ctx.accounts.note_tree.load_init()?;
        tree.authority = ctx.accounts.admin.key();
        tree.height = MERKLE_TREE_HEIGHT as u8;
        tree.root_history_size = ROOT_HISTORY_SIZE as u16;
        tree.next_index = 0;
        tree.root_index = 0;

        MerkleTree::initialize::<PoseidonHasher>(&mut *tree)?;

        // Bumps
        cfg.bump = ctx.bumps.config;
        cfg.vault_bump = ctx.bumps.vault;
        vault.bump = ctx.bumps.vault;
        nulls.bump = ctx.bumps.nullifiers;

        cfg.admin = ctx.accounts.admin.key();
        cfg.paused = false;
        cfg.fee_bps = fee_bps;

        require!(!denoms.is_empty(), PrivacyError::NoDenoms);
        require!(denoms.len() <= MAX_DENOMS, PrivacyError::TooManyDenoms);

        cfg.num_denoms = denoms.len() as u8;

        cfg.denoms = [0u64; MAX_DENOMS];
        cfg.tvl = [0u64; MAX_DENOMS];
        cfg.num_relayers = 0;
        cfg.relayers = [Pubkey::default(); MAX_RELAYERS];

        for (i, d) in denoms.into_iter().enumerate() {
            cfg.denoms[i] = d;
        }

        // ---- Nullifier set init ----
        nulls.count = 0;

        Ok(())
    }

    pub fn set_paused(ctx: Context<ConfigAdmin>, paused: bool) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.paused = paused;
        Ok(())
    }

    pub fn add_relayer(ctx: Context<ConfigAdmin>, new_relayer: Pubkey) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        if cfg.is_relayer(&new_relayer) {
            return Ok(());
        }
        let n = cfg.num_relayers as usize;
        require!(n < MAX_RELAYERS, PrivacyError::TooManyRelayers);
        cfg.relayers[n] = new_relayer;
        cfg.num_relayers += 1;
        Ok(())
    }

    pub fn deposit_fixed(
        ctx: Context<DepositFixed>,
        denom_index: u8,
        commitment: [u8; 32],
    ) -> Result<()> {
        let mut tree = ctx.accounts.note_tree.load_mut()?;
        MerkleTree::append::<PoseidonHasher>(commitment, &mut *tree)?;

        let cfg = &mut ctx.accounts.config;
        require!(!cfg.paused, PrivacyError::Paused);

        let idx = denom_index as usize;
        require!(idx < cfg.num_denoms as usize, PrivacyError::BadDenomIndex);

        let amount = cfg.denoms[idx];

        // 1) Move SOL from depositor to vault PDA via CPI
        let depositor = &ctx.accounts.depositor;
        let vault_ai = ctx.accounts.vault.to_account_info();

        let cpi_ctx = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            system_program::Transfer {
                from: depositor.to_account_info(),
                to: vault_ai,
            },
        );
        system_program::transfer(cpi_ctx, amount)?;

        // 2) Update TVL
        cfg.tvl[idx] = cfg.tvl[idx]
            .checked_add(amount)
            .ok_or(PrivacyError::MathOverflow)?;

        Ok(())
    }

    pub fn private_transfer(
        ctx: Context<PrivateTransfer>,
        old_root: [u8; 32],
        old_nullifier: [u8; 32],
        new_commitment: [u8; 32],
        denom_index: u8,
        proof: Vec<u8>, // TransferProof
    ) -> Result<()> {
        let cfg = &ctx.accounts.config;
        let mut tree = ctx.accounts.note_tree.load_mut()?;

        require!(!cfg.paused, PrivacyError::Paused);
        require!(
            (denom_index as usize) < cfg.num_denoms as usize,
            PrivacyError::BadDenomIndex
        );

        // 1. Verify ZK proof for transfer
        let public_inputs = TransferPublicInputs {
            old_root,
            old_nullifier,
            new_commitment,
            denom_index,
        };
        // verify_transfer_groth16(proof, &public_inputs)?;

        // 2. Check old root is known
        require!(
            MerkleTree::is_known_root(&*tree, old_root),
            PrivacyError::UnknownRoot
        );

        // 3. Mark old nullifier as spent
        // Note: The 'init' constraint on nullifier_marker already ensures the nullifier is fresh
        let nulls = &mut ctx.accounts.nullifiers;
        let marker = &mut ctx.accounts.nullifier_marker;

        marker.nullifier = old_nullifier;
        marker.timestamp = Clock::get()?.unix_timestamp;
        marker.withdrawal_index = nulls.count;
        marker.bump = ctx.bumps.nullifier_marker;

        nulls.count = nulls
            .count
            .checked_add(1)
            .ok_or(PrivacyError::MathOverflow)?;

        // 4. Insert new commitment into tree
        MerkleTree::append::<PoseidonHasher>(new_commitment, &mut *tree)?;

        // Note: No SOL moves, just commitment ownership transfer

        Ok(())
    }

    pub fn withdraw(
        ctx: Context<Withdraw>,
        root: [u8; 32],
        nullifier: [u8; 32],
        denom_index: u8,
        recipient_pk: Pubkey,
        proof: WithdrawProof,
    ) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        let tree = ctx.accounts.note_tree.load_mut()?;
        require!(!cfg.paused, PrivacyError::Paused);

        // ---- 0) Verify Groth16 proof (stub or real, depending on groth16.rs) ----
        let public_inputs = WithdrawPublicInputs {
            root,
            nullifier,
            denom_index,
            recipient: recipient_pk,
        };
        verify_withdraw_groth16(proof, &public_inputs)?;

        // ---- 1) Check that root is known in Merkle tree ----
        require!(
            MerkleTree::is_known_root(&*tree, public_inputs.root),
            PrivacyError::UnknownRoot
        );

        // ---- 2) Mark nullifier as spent ----
        // Note: The 'init' constraint on nullifier_marker already ensures the nullifier is fresh
        let nulls = &mut ctx.accounts.nullifiers;
        let marker = &mut ctx.accounts.nullifier_marker;

        marker.nullifier = public_inputs.nullifier;
        marker.timestamp = Clock::get()?.unix_timestamp;
        marker.withdrawal_index = nulls.count;
        marker.bump = ctx.bumps.nullifier_marker;

        nulls.count = nulls
            .count
            .checked_add(1)
            .ok_or(PrivacyError::MathOverflow)?;

        // ---- 3) Denom & fee math ----
        let idx = public_inputs.denom_index as usize;
        require!(idx < cfg.num_denoms as usize, PrivacyError::BadDenomIndex);
        let amount = cfg.denoms[idx];

        let fee = amount
            .checked_mul(cfg.fee_bps as u64)
            .ok_or(PrivacyError::MathOverflow)?
            / 10_000;

        let to_user = amount.checked_sub(fee).ok_or(PrivacyError::MathOverflow)?;

        // ---- 4) Relayer must be authorized ----
        let relayer_key = ctx.accounts.relayer.key();
        require!(
            cfg.is_relayer(&relayer_key),
            PrivacyError::RelayerNotAllowed
        );

        // ---- 5) Vault balance & TVL ----
        let vault_ai = ctx.accounts.vault.to_account_info();
        let vault_balance = **vault_ai.lamports.borrow();

        require!(
            vault_balance >= amount,
            PrivacyError::InsufficientVaultBalance
        );

        cfg.tvl[idx] = cfg.tvl[idx]
            .checked_sub(amount)
            .ok_or(PrivacyError::MathOverflow)?;

        // ---- 6) Recipient sanity check ----
        require_keys_eq!(ctx.accounts.recipient.key(), public_inputs.recipient);

        // ---- 7) Manual lamport moves from vault -> user + relayer ----
        {
            let recipient_ai = ctx.accounts.recipient.to_account_info();
            let relayer_ai = ctx.accounts.relayer.to_account_info();

            let mut vault_lamports = vault_ai.try_borrow_mut_lamports()?;
            let mut recipient_lamports = recipient_ai.try_borrow_mut_lamports()?;
            let mut relayer_lamports = relayer_ai.try_borrow_mut_lamports()?;

            **vault_lamports = vault_lamports
                .checked_sub(amount)
                .ok_or(PrivacyError::MathOverflow)?;

            **recipient_lamports = recipient_lamports
                .checked_add(to_user)
                .ok_or(PrivacyError::MathOverflow)?;

            **relayer_lamports = relayer_lamports
                .checked_add(fee)
                .ok_or(PrivacyError::MathOverflow)?;
        }

        Ok(())
    }
}

// ---- Errors ----

#[error_code]
pub enum PrivacyError {
    #[msg("Pool is paused")]
    Paused,
    #[msg("No denominations configured")]
    NoDenoms,
    #[msg("Too many denominations")]
    TooManyDenoms,
    #[msg("Bad denomination index")]
    BadDenomIndex,
    #[msg("Math overflow")]
    MathOverflow,
    #[msg("Nullifier already used")]
    NullifierAlreadyUsed,
    #[msg("Nullifier table is full")]
    NullifierTableFull,
    #[msg("Unknown root")]
    UnknownRoot,
    #[msg("Relayer not allowed")]
    RelayerNotAllowed,
    #[msg("Vault balance too low")]
    InsufficientVaultBalance,
    #[msg("Too many relayers")]
    TooManyRelayers,
    #[msg("Invalid proof encoding")]
    InvalidProof,
    #[msg("Groth16 verification failed")]
    VerifyFailed,
    #[msg("Merkle tree is full")]
    MerkleTreeFull,
    #[msg("Merkle hash failed")]
    MerkleHashFailed,
}

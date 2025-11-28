use anchor_lang::prelude::*;
use anchor_lang::solana_program::{program::invoke, system_instruction};

declare_id!("G7m7QCf2m6VsaDs7GJC9wMmxCiWxmAjKN6BhakkWYi32");

// Storage bounds
pub const MAX_ROOTS: usize = 16;
pub const MAX_NULLIFIERS: usize = 32;

// Fixed denominations in lamports (1 / 5 / 10 SOL)
pub const ALLOWED_DENOMS: [u64; 3] = [
    1_000_000_000,  // 1 SOL
    5_000_000_000,  // 5 SOL
    10_000_000_000, // 10 SOL
];

#[program]
pub mod privacy_pool {
    use super::*;

    /// Bootstrap everything: config, note tree, nullifier set, SOL vault.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.bump = ctx.bumps.config;
        cfg.vault_bump = ctx.bumps.vault;
        cfg.admin = ctx.accounts.payer.key();
        cfg.relayer = ctx.accounts.payer.key();
        cfg.paused = false;

        let tree = &mut ctx.accounts.note_tree;
        tree.bump = ctx.bumps.note_tree;
        tree.current_root_index = 0;

        let nulls = &mut ctx.accounts.nullifiers;
        nulls.bump = ctx.bumps.nullifiers;
        nulls.count = 0;

        let vault = &mut ctx.accounts.vault;
        vault.bump = ctx.bumps.vault;

        Ok(())
    }

    /// Admin can pause/unpause the pool.
    pub fn set_paused(ctx: Context<SetPaused>, paused: bool) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.paused = paused;
        Ok(())
    }

    /// Admin can rotate relayer.
    pub fn set_relayer(ctx: Context<SetRelayer>, new_relayer: Pubkey) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.relayer = new_relayer;
        Ok(())
    }

    /// Append a new Merkle root (off-chain builds tree; we only store rotating roots).
    pub fn append_root(ctx: Context<AppendRoot>, new_root: [u8; 32]) -> Result<()> {
        let cfg = &ctx.accounts.config;
        require!(!cfg.paused, PrivacyError::PoolPaused);
        require_keys_eq!(
            cfg.admin,
            ctx.accounts.authority.key(),
            PrivacyError::UnauthorizedAdmin
        );

        let tree = &mut ctx.accounts.note_tree;
        let idx = (tree.current_root_index as usize + 1) % MAX_ROOTS;
        tree.roots[idx] = new_root;
        tree.current_root_index = idx as u32;

        emit!(RootAppended {
            root: new_root,
            index: tree.current_root_index,
        });

        Ok(())
    }

    /// User deposits a fixed SOL denomination into the vault.
    /// Off-chain you generate a note commitment for this deposit.
    pub fn deposit_fixed(
        ctx: Context<DepositFixed>,
        denom_index: u8,
        commitment: [u8; 32],
    ) -> Result<()> {
        let cfg = &ctx.accounts.config;
        require!(!cfg.paused, PrivacyError::PoolPaused);

        let i = denom_index as usize;
        require!(i < ALLOWED_DENOMS.len(), PrivacyError::InvalidDenomination);
        let amount = ALLOWED_DENOMS[i];

        // Transfer SOL from depositor → vault PDA account.
        let ix = system_instruction::transfer(
            &ctx.accounts.depositor.key(),
            &ctx.accounts.vault.key(),
            amount,
        );
        invoke(
            &ix,
            &[
                ctx.accounts.depositor.to_account_info(),
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;

        emit!(NotePublished {
            commitment,
            denom_index,
        });

        Ok(())
    }

    /// Optional explicit nullifier registration. Only relayer is allowed.
    pub fn register_nullifier(
        ctx: Context<RegisterNullifier>,
        nullifier: [u8; 32],
    ) -> Result<()> {
        let cfg = &ctx.accounts.config;
        require!(!cfg.paused, PrivacyError::PoolPaused);
        require_keys_eq!(
            cfg.relayer,
            ctx.accounts.authority.key(),
            PrivacyError::UnauthorizedRelayer
        );

        let nulls = &mut ctx.accounts.nullifiers;
        require!(
            !nulls.contains(&nullifier),
            PrivacyError::NullifierAlreadyUsed
        );
        nulls.push(nullifier)?;

        emit!(NullifierRegistered { nullifier });
        Ok(())
    }

    /// Relayer-based withdrawal:
    /// - checks root membership
    /// - enforces one-time nullifier
    /// - pays a fixed SOL denom from vault → recipient
    /// ZK proof is still a placeholder (`_proof`).
    pub fn verify_and_nullify(
        ctx: Context<VerifyAndNullify>,
        root: [u8; 32],
        nullifier: [u8; 32],
        denom_index: u8,
        _proof: Vec<u8>,
    ) -> Result<()> {
        let cfg = &ctx.accounts.config;
        require!(!cfg.paused, PrivacyError::PoolPaused);
        require_keys_eq!(
            cfg.relayer,
            ctx.accounts.relayer.key(),
            PrivacyError::UnauthorizedRelayer
        );

        let tree = &ctx.accounts.note_tree;
        require!(tree.contains_root(&root), PrivacyError::UnknownRoot);

        let nulls = &mut ctx.accounts.nullifiers;
        require!(
            !nulls.contains(&nullifier),
            PrivacyError::NullifierAlreadyUsed
        );
        nulls.push(nullifier)?;

        let i = denom_index as usize;
        require!(i < ALLOWED_DENOMS.len(), PrivacyError::InvalidDenomination);
        let amount = ALLOWED_DENOMS[i];

        let vault_info = ctx.accounts.vault.to_account_info();
        let recipient_info = ctx.accounts.recipient.to_account_info();

        require!(
            vault_info.lamports() >= amount,
            PrivacyError::VaultInsufficientBalance
        );

        // Move SOL from vault → recipient by mutating lamports directly
        **vault_info.try_borrow_mut_lamports()? -= amount;
        **recipient_info.try_borrow_mut_lamports()? += amount;

        emit!(NoteSpent {
            root,
            nullifier,
            denom_index,
            recipient: recipient_info.key(),
        });

        Ok(())
    }
}

// =======================
// Accounts
// =======================

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = payer,
        seeds = [b"config"],
        bump,
        space = 8 + PrivacyConfig::SIZE
    )]
    pub config: Account<'info, PrivacyConfig>,

    #[account(
        init,
        payer = payer,
        seeds = [b"note_tree"],
        bump,
        space = 8 + NoteTree::SIZE
    )]
    pub note_tree: Account<'info, NoteTree>,

    #[account(
        init,
        payer = payer,
        seeds = [b"nullifiers"],
        bump,
        space = 8 + Nullifiers::SIZE
    )]
    pub nullifiers: Account<'info, Nullifiers>,

    #[account(
        init,
        payer = payer,
        seeds = [b"vault"],
        bump,
        space = 8 + Vault::SIZE
    )]
    pub vault: Account<'info, Vault>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetPaused<'info> {
    #[account(mut, has_one = admin)]
    pub config: Account<'info, PrivacyConfig>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetRelayer<'info> {
    #[account(mut, has_one = admin)]
    pub config: Account<'info, PrivacyConfig>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct AppendRoot<'info> {
    #[account(
        seeds = [b"config"],
        bump = config.bump
    )]
    pub config: Account<'info, PrivacyConfig>,

    #[account(
        mut,
        seeds = [b"note_tree"],
        bump = note_tree.bump
    )]
    pub note_tree: Account<'info, NoteTree>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct DepositFixed<'info> {
    #[account(
        seeds = [b"config"],
        bump = config.bump
    )]
    pub config: Account<'info, PrivacyConfig>,

    #[account(
        mut,
        seeds = [b"vault"],
        bump = config.vault_bump
    )]
    pub vault: Account<'info, Vault>,

    #[account(mut)]
    pub depositor: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RegisterNullifier<'info> {
    #[account(
        seeds = [b"config"],
        bump = config.bump
    )]
    pub config: Account<'info, PrivacyConfig>,

    #[account(
        mut,
        seeds = [b"nullifiers"],
        bump = nullifiers.bump
    )]
    pub nullifiers: Account<'info, Nullifiers>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct VerifyAndNullify<'info> {
    #[account(
        seeds = [b"config"],
        bump = config.bump
    )]
    pub config: Account<'info, PrivacyConfig>,

    #[account(
        seeds = [b"note_tree"],
        bump = note_tree.bump
    )]
    pub note_tree: Account<'info, NoteTree>,

    #[account(
        mut,
        seeds = [b"nullifiers"],
        bump = nullifiers.bump
    )]
    pub nullifiers: Account<'info, Nullifiers>,

    #[account(
        mut,
        seeds = [b"vault"],
        bump = config.vault_bump
    )]
    pub vault: Account<'info, Vault>,

    /// CHECK: any SOL recipient
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,

    /// Relayer that submits withdrawals; must match config.relayer
    pub relayer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

// =======================
// State
// =======================

#[account]
pub struct PrivacyConfig {
    pub bump: u8,
    pub vault_bump: u8,
    pub admin: Pubkey,
    pub relayer: Pubkey,
    pub paused: bool,
}

impl PrivacyConfig {
    pub const SIZE: usize = 1 + 1 + 32 + 32 + 1;
}

#[account]
pub struct Vault {
    pub bump: u8,
}

impl Vault {
    pub const SIZE: usize = 1;
}

#[account]
pub struct NoteTree {
    pub bump: u8,
    pub current_root_index: u32,
    pub roots: [[u8; 32]; MAX_ROOTS],
}

impl NoteTree {
    pub const SIZE: usize = 1 + 4 + (32 * MAX_ROOTS);

    pub fn contains_root(&self, target: &[u8; 32]) -> bool {
        self.roots.iter().any(|r| r == target)
    }
}

#[account]
pub struct Nullifiers {
    pub bump: u8,
    pub count: u32,
    pub values: [[u8; 32]; MAX_NULLIFIERS],
}

impl Nullifiers {
    pub const SIZE: usize = 1 + 4 + (32 * MAX_NULLIFIERS);

    pub fn contains(&self, target: &[u8; 32]) -> bool {
        let count = self.count as usize;
        for i in 0..count {
            if &self.values[i] == target {
                return true;
            }
        }
        false
    }

    pub fn push(&mut self, n: [u8; 32]) -> Result<()> {
        let idx = self.count as usize;
        require!(idx < MAX_NULLIFIERS, PrivacyError::NullifiersFull);
        self.values[idx] = n;
        self.count += 1;
        Ok(())
    }
}

// =======================
// Events
// =======================

#[event]
pub struct RootAppended {
    pub root: [u8; 32],
    pub index: u32,
}

#[event]
pub struct NotePublished {
    pub commitment: [u8; 32],
    pub denom_index: u8,
}

#[event]
pub struct NullifierRegistered {
    pub nullifier: [u8; 32],
}

#[event]
pub struct NoteSpent {
    pub root: [u8; 32],
    pub nullifier: [u8; 32],
    pub denom_index: u8,
    pub recipient: Pubkey,
}

// =======================
// Errors
// =======================

#[error_code]
pub enum PrivacyError {
    #[msg("Pool is paused")]
    PoolPaused,
    #[msg("Unauthorized admin call")]
    UnauthorizedAdmin,
    #[msg("Unauthorized relayer")]
    UnauthorizedRelayer,
    #[msg("Unknown Merkle root")]
    UnknownRoot,
    #[msg("Nullifier already used")]
    NullifierAlreadyUsed,
    #[msg("Nullifier storage is full")]
    NullifiersFull,
    #[msg("Invalid denomination index")]
    InvalidDenomination,
    #[msg("Vault has insufficient balance")]
    VaultInsufficientBalance,
}
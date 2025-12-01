use anchor_lang::prelude::*;
use anchor_lang::system_program;

declare_id!("G7m7QCf2m6VsaDs7GJC9wMmxCiWxmAjKN6BhakkWYi32");

// ---- Constants ----

pub const MAX_DENOMS: usize = 4;
pub const MAX_RELAYERS: usize = 16;
pub const MAX_ROOTS: usize = 32;
pub const MAX_NULLIFIERS: usize = 256;

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
    pub const LEN: usize =
        8 +   // discriminator
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

#[account]
pub struct NoteTree {
    pub bump: u8,
    /// Next index to write (ring buffer)
    pub current_index: u16,
    pub roots: [[u8; 32]; MAX_ROOTS],
}

impl NoteTree {
    pub const LEN: usize = 8 + 1 + 2 + 32 * MAX_ROOTS;

    pub fn append_root(&mut self, root: [u8; 32]) {
        let idx = (self.current_index as usize) % MAX_ROOTS;
        self.roots[idx] = root;
        self.current_index = self.current_index.wrapping_add(1);
    }

    pub fn contains_root(&self, root: &[u8; 32]) -> bool {
        self.roots.iter().any(|r| r == root)
    }
}

#[account]
pub struct NullifierSet {
    pub bump: u8,
    pub count: u32,
    pub values: [[u8; 32]; MAX_NULLIFIERS],
}

impl NullifierSet {
    pub const LEN: usize = 8 + 1 + 4 + 32 * MAX_NULLIFIERS;

    pub fn is_spent(&self, n: &[u8; 32]) -> bool {
        let cnt = self.count as usize;
        self.values[..cnt].iter().any(|v| v == n)
    }

    pub fn insert(&mut self, n: [u8; 32]) -> Result<()> {
        if self.is_spent(&n) {
            return err!(PrivacyError::NullifierAlreadyUsed);
        }
        let idx = self.count as usize;
        if idx >= MAX_NULLIFIERS {
            return err!(PrivacyError::NullifierTableFull);
        }
        self.values[idx] = n;
        self.count += 1;
        Ok(())
    }
}

// ---- Instruction contexts ----

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = admin,
        seeds = [b"config"],
        bump,
        space = PrivacyConfig::LEN
    )]
    pub config: Account<'info, PrivacyConfig>,

    #[account(
        init,
        payer = admin,
        seeds = [b"vault"],
        bump,
        space = Vault::LEN
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        init,
        payer = admin,
        seeds = [b"note_tree"],
        bump,
        space = NoteTree::LEN
    )]
    pub note_tree: Account<'info, NoteTree>,

    #[account(
        init,
        payer = admin,
        seeds = [b"nullifiers"],
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
        seeds = [b"config"],
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

    #[account(
        mut,
        seeds = [b"note_tree"],
        bump = note_tree.bump
    )]
    pub note_tree: Account<'info, NoteTree>,

    #[account(mut)]
    pub depositor: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
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

    #[account(
        mut,
        seeds = [b"note_tree"],
        bump = note_tree.bump
    )]
    pub note_tree: Account<'info, NoteTree>,

    #[account(
        mut,
        seeds = [b"nullifiers"],
        bump = nullifiers.bump
    )]
    pub nullifiers: Account<'info, NullifierSet>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// CHECK: Just a normal system-owned recipient account
    #[account(mut)]
    pub recipient: SystemAccount<'info>,

    pub system_program: Program<'info, System>,
}

// ---- Program ----

#[program]
pub mod privacy_pool {
    use super::*;

    /// Initialize config, vault, Merkle root set, and nullifier table.
    /// Assumes a fresh validator / empty PDAs (standard `anchor test` flow).
    pub fn initialize(
        ctx: Context<Initialize>,
        denoms: Vec<u64>,
        fee_bps: u16,
    ) -> Result<()> {
        let cfg   = &mut ctx.accounts.config;
        let vault = &mut ctx.accounts.vault;
        let tree  = &mut ctx.accounts.note_tree;
        let nulls = &mut ctx.accounts.nullifiers;

        // Bumps from Anchor's auto-generated bump struct
        cfg.bump       = ctx.bumps.config;
        cfg.vault_bump = ctx.bumps.vault;
        vault.bump     = ctx.bumps.vault;
        tree.bump      = ctx.bumps.note_tree;
        nulls.bump     = ctx.bumps.nullifiers;

        // Basic config
        cfg.admin   = ctx.accounts.admin.key();
        cfg.paused  = false;
        cfg.fee_bps = fee_bps;

        require!(!denoms.is_empty(), PrivacyError::NoDenoms);
        require!(denoms.len() <= MAX_DENOMS, PrivacyError::TooManyDenoms);

        // Reset denoms + tvl
        for i in 0..MAX_DENOMS {
            cfg.denoms[i] = 0;
            cfg.tvl[i] = 0;
        }

        // Set active denominations
        let len = denoms.len();
        for (i, d) in denoms.into_iter().enumerate() {
            cfg.denoms[i] = d;
        }
        cfg.num_denoms = len as u8;

        // Reset relayers
        cfg.num_relayers = 0;
        for i in 0..MAX_RELAYERS {
            cfg.relayers[i] = Pubkey::default();
        }

        // Reset note tree
        tree.current_index = 0;
        for i in 0..MAX_ROOTS {
            tree.roots[i] = [0u8; 32];
        }

        // Reset nullifiers
        nulls.count = 0;
        for i in 0..MAX_NULLIFIERS {
            nulls.values[i] = [0u8; 32];
        }

        Ok(())
    }

    /// Pause/unpause the pool
    pub fn set_paused(ctx: Context<ConfigAdmin>, paused: bool) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.paused = paused;
        Ok(())
    }

    /// Add a relayer to the registry
    pub fn add_relayer(ctx: Context<ConfigAdmin>, new_relayer: Pubkey) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        if cfg.is_relayer(&new_relayer) {
            // already present; no-op
            return Ok(());
        }
        let n = cfg.num_relayers as usize;
        require!(n < MAX_RELAYERS, PrivacyError::TooManyRelayers);
        cfg.relayers[n] = new_relayer;
        cfg.num_relayers += 1;
        Ok(())
    }

    /// Fixed-denom deposit of SOL into the vault.
    /// `denom_index` must match one of the configured denominations.
    /// `commitment` is placeholder for note commitment (not enforced yet).
    /// `new_root` is appended to the rolling Merkle root set.
    pub fn deposit_fixed(
        ctx: Context<DepositFixed>,
        denom_index: u8,
        _commitment: [u8; 32],
        new_root: [u8; 32],
    ) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        require!(!cfg.paused, PrivacyError::Paused);

        let idx = denom_index as usize;
        require!(idx < cfg.num_denoms as usize, PrivacyError::BadDenomIndex);

        let amount = cfg.denoms[idx];

        // Move SOL from depositor to vault PDA via CPI
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

        // Update TVL
        cfg.tvl[idx] = cfg
            .tvl[idx]
            .checked_add(amount)
            .ok_or(PrivacyError::MathOverflow)?;

        // Update note tree root ring buffer
        ctx.accounts.note_tree.append_root(new_root);

        Ok(())
    }

    /// Withdraw via relayer:
    /// - checks root is known
    /// - checks & inserts nullifier
    /// - enforces denom & fee
    /// - pays user + relayer from vault
    /// `proof` is placeholder for future zk verification.
    pub fn withdraw(
        ctx: Context<Withdraw>,
        root: [u8; 32],
        nullifier: [u8; 32],
        denom_index: u8,
        recipient_pk: Pubkey,
        _proof: Vec<u8>,
    ) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        require!(!cfg.paused, PrivacyError::Paused);

        // Make sure the root is one of the recent ones
        require!(
            ctx.accounts.note_tree.contains_root(&root),
            PrivacyError::UnknownRoot
        );

        // Nullifier must be fresh
        let nulls = &mut ctx.accounts.nullifiers;
        nulls.insert(nullifier)?;

        // Denomination math
        let idx = denom_index as usize;
        require!(idx < cfg.num_denoms as usize, PrivacyError::BadDenomIndex);
        let amount = cfg.denoms[idx];

        let fee = amount
            .checked_mul(cfg.fee_bps as u64)
            .ok_or(PrivacyError::MathOverflow)?
            / 10_000;
        let to_user = amount
            .checked_sub(fee)
            .ok_or(PrivacyError::MathOverflow)?;

        // Check relayer is authorized
        let relayer_key = ctx.accounts.relayer.key();
        require!(
            cfg.is_relayer(&relayer_key),
            PrivacyError::RelayerNotAllowed
        );

        // Check vault has enough SOL and tvl accounting
        let vault_ai = ctx.accounts.vault.to_account_info();
        let vault_balance = **vault_ai.lamports.borrow();
        require!(
            vault_balance >= amount,
            PrivacyError::InsufficientVaultBalance
        );

        cfg.tvl[idx] = cfg.tvl[idx]
            .checked_sub(amount)
            .ok_or(PrivacyError::MathOverflow)?;

        // Sanity: recipient passed in matches the argument
        require_keys_eq!(ctx.accounts.recipient.key(), recipient_pk);

        // PDA signer seeds for vault transfers
        let seeds: &[&[u8]] = &[b"vault", &[cfg.vault_bump]];
        let signer_seeds: &[&[&[u8]]] = &[seeds];

        // Transfer to recipient (user)
        {
            let cpi_ctx = CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: vault_ai.clone(),
                    to: ctx.accounts.recipient.to_account_info(),
                },
                signer_seeds,
            );
            system_program::transfer(cpi_ctx, to_user)?;
        }

        // Transfer fee to relayer
        {
            let cpi_ctx = CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: vault_ai,
                    to: ctx.accounts.relayer.to_account_info(),
                },
                signer_seeds,
            );
            system_program::transfer(cpi_ctx, fee)?;
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
}
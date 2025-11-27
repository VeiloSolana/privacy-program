use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

declare_id!("G7m7QCf2m6VsaDs7GJC9wMmxCiWxmAjKN6BhakkWYi32");

/// Merkle tree + nullifier configs
pub const TREE_DEPTH: u8 = 24;
pub const ROOT_HISTORY: usize = 32;        // how many roots to remember
pub const NULLIFIER_CAPACITY: usize = 1024; // max nullifiers stored

/// Fixed denominations for deposits / withdrawals (in smallest units of the SPL mint).
/// For dev / localnet you can set them to 1, 5, 10, etc.
/// In production you’d probably use 1e9, 5e9, 10e9 or similar.
pub const ALLOWED_DENOMS: [u64; 3] = [1, 5, 10];

fn is_allowed_denom(amount: u64) -> bool {
    ALLOWED_DENOMS.iter().any(|d| *d == amount)
}

#[program]
pub mod privacy_pool {
    use super::*;

    /// Create the pool:
    /// - PoolState PDA (binds mint + admin + bump)
    /// - Vault token account owned by PoolState
    /// - NoteTree PDA (Merkle root ring buffer)
    /// - Nullifiers PDA (used nullifiers)
    pub fn initialize_pool(ctx: Context<InitializePool>) -> Result<()> {
        let pool = &mut ctx.accounts.pool_state;
        pool.admin = ctx.accounts.payer.key();
        pool.mint = ctx.accounts.mint.key();
        pool.bump = ctx.bumps.pool_state;

        let tree = &mut ctx.accounts.note_tree;
        tree.depth = TREE_DEPTH;
        tree.current_root_index = 0;
        tree.num_roots = 0;
        tree.bump = ctx.bumps.note_tree;

        let nulls = &mut ctx.accounts.nullifiers;
        nulls.count = 0;
        nulls.bump = ctx.bumps.nullifiers;

        Ok(())
    }

    /// Public → shielded deposit in a **fixed denomination**.
    ///
    /// - Checks `amount` is in ALLOWED_DENOMS
    /// - Transfers SPL tokens from user → pool vault
    /// - Emits a NoteDeposited event with `note_commitment`
    ///
    /// The commitment itself (hash(secret || poolId || amount || …)) is **created off-chain**
    /// and just passed as a `[u8; 32]`.
    pub fn deposit_fixed(
        ctx: Context<DepositFixed>,
        amount: u64,
        note_commitment: [u8; 32],
    ) -> Result<()> {
        require!(is_allowed_denom(amount), PrivacyError::InvalidDenomination);

        // Transfer tokens from user → pool vault
        let cpi_accounts = Transfer {
            from: ctx.accounts.user_token_account.to_account_info(),
            to: ctx.accounts.pool_vault.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        let cpi_ctx =
            CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer(cpi_ctx, amount)?;

        // Emit event so an off-chain indexer can update the Merkle tree & compute new root
        emit!(NoteDeposited {
            pool: ctx.accounts.pool_state.key(),
            owner: ctx.accounts.user.key(),
            amount,
            note_commitment,
        });

        Ok(())
    }

    /// Append a new Merkle root into the ring buffer.
    ///
    /// This is meant to be called by an off-chain relayer / indexer after it recomputes
    /// the Merkle tree over all commitments.
    pub fn append_root(ctx: Context<AppendRoot>, new_root: [u8; 32]) -> Result<()> {
        let pool = &ctx.accounts.pool_state;
        require_keys_eq!(
            ctx.accounts.authority.key(),
            pool.admin,
            PrivacyError::Unauthorized
        );

        let tree = &mut ctx.accounts.note_tree;

        let idx = (tree.current_root_index as usize) % ROOT_HISTORY;
        tree.roots[idx] = new_root;

        tree.current_root_index = tree.current_root_index.wrapping_add(1);
        if tree.num_roots < ROOT_HISTORY as u32 {
            tree.num_roots += 1;
        }

        emit!(RootAppended {
            pool: pool.key(),
            root: new_root,
        });

        Ok(())
    }

    /// Directly register a nullifier without proof (useful for migration/backfill).
    pub fn register_nullifier(
        ctx: Context<RegisterNullifier>,
        nullifier: [u8; 32],
    ) -> Result<()> {
        let pool = &ctx.accounts.pool_state;
        require_keys_eq!(
            ctx.accounts.authority.key(),
            pool.admin,
            PrivacyError::Unauthorized
        );

        let nulls = &mut ctx.accounts.nullifiers;
        let count = nulls.count as usize;

        // Ensure not already used
        for i in 0..count {
            require!(
                nulls.values[i] != nullifier,
                PrivacyError::NullifierAlreadyUsed
            );
        }
        require!(
            count < NULLIFIER_CAPACITY,
            PrivacyError::NullifierSetFull
        );

        nulls.values[count] = nullifier;
        nulls.count = (count + 1) as u32;

        emit!(NullifierUsed {
            pool: pool.key(),
            nullifier,
        });

        Ok(())
    }

    /// Shielded → public withdraw with note.
    ///
    /// This is the **zk entry point** (for now `_proof` is ignored):
    ///
    /// Inputs:
    /// - `root`: Merkle root the note belongs to
    /// - `nullifier`: derived from secret; must be unused
    /// - `amount`: must be in ALLOWED_DENOMS
    /// - `_proof`: zk proof bytes (Groth16/Plonk etc, TODO)
    ///
    /// Checks:
    /// - `root` is in NoteTree recent history
    /// - `nullifier` not already in Nullifiers
    /// - `amount` is allowed
    ///
    /// Effects:
    /// - writes `nullifier` into Nullifiers (no double spend)
    /// - transfers `amount` tokens from pool vault → recipient's token account
    pub fn withdraw_with_note(
        ctx: Context<WithdrawWithNote>,
        root: [u8; 32],
        nullifier: [u8; 32],
        amount: u64,
        _proof: Vec<u8>,
    ) -> Result<()> {
        require!(is_allowed_denom(amount), PrivacyError::InvalidDenomination);

        // ----- 1) Check root in history -----
        let tree = &ctx.accounts.note_tree;
        let max = tree.num_roots.min(ROOT_HISTORY as u32) as usize;
        let mut found = false;
        for i in 0..max {
            if tree.roots[i] == root {
                found = true;
                break;
            }
        }
        require!(found, PrivacyError::UnknownRoot);

        // ----- 2) Check + mark nullifier -----
        let nulls = &mut ctx.accounts.nullifiers;
        let count = nulls.count as usize;

        for i in 0..count {
            require!(
                nulls.values[i] != nullifier,
                PrivacyError::NullifierAlreadyUsed
            );
        }
        require!(
            count < NULLIFIER_CAPACITY,
            PrivacyError::NullifierSetFull
        );

        nulls.values[count] = nullifier;
        nulls.count = (count + 1) as u32;

        emit!(NullifierUsed {
            pool: ctx.accounts.pool_state.key(),
            nullifier,
        });

        // ----- 3) Move tokens from vault → recipient ATA -----
        let pool = &ctx.accounts.pool_state;

        let seeds: &[&[u8]] = &[
            b"pool_state",
            pool.mint.as_ref(),
            &[pool.bump],
        ];
        let signer_seeds = &[seeds];

        let cpi_accounts = Transfer {
            from: ctx.accounts.pool_vault.to_account_info(),
            to: ctx.accounts.user_token_account.to_account_info(),
            authority: ctx.accounts.pool_state.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
            signer_seeds,
        );
        token::transfer(cpi_ctx, amount)?;

        Ok(())
    }
}

// ================== ACCOUNTS ==================

#[derive(Accounts)]
pub struct InitializePool<'info> {
    /// Pool state PDA: binds mint + admin + bump
    #[account(
        init,
        payer = payer,
        space = 8 + PoolState::SIZE,
        seeds = [b"pool_state", mint.key().as_ref()],
        bump
    )]
    pub pool_state: Account<'info, PoolState>,

    pub mint: Account<'info, Mint>,

    /// SPL token vault owned by pool_state
    #[account(
        init,
        payer = payer,
        token::mint = mint,
        token::authority = pool_state,
    )]
    pub pool_vault: Account<'info, TokenAccount>,

    /// Note tree PDA (per pool_state)
    #[account(
        init,
        payer = payer,
        space = 8 + NoteTree::SIZE,
        seeds = [b"note_tree", pool_state.key().as_ref()],
        bump
    )]
    pub note_tree: Account<'info, NoteTree>,

    /// Nullifiers PDA (per pool_state)
    #[account(
        init,
        payer = payer,
        space = 8 + Nullifiers::SIZE,
        seeds = [b"nullifiers", pool_state.key().as_ref()],
        bump
    )]
    pub nullifiers: Account<'info, Nullifiers>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct DepositFixed<'info> {
    #[account(
        mut,
        has_one = mint,
        seeds = [b"pool_state", mint.key().as_ref()],
        bump = pool_state.bump,
    )]
    pub pool_state: Account<'info, PoolState>,

    pub mint: Account<'info, Mint>,

    #[account(
        mut,
        constraint = pool_vault.mint == mint.key(),
        constraint = pool_vault.owner == pool_state.key(),
    )]
    pub pool_vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = user_token_account.mint == mint.key(),
        constraint = user_token_account.owner == user.key(),
    )]
    pub user_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub user: Signer<'info>,

    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct AppendRoot<'info> {
    #[account(
        mut,
        has_one = mint,
        seeds = [b"pool_state", mint.key().as_ref()],
        bump = pool_state.bump,
    )]
    pub pool_state: Account<'info, PoolState>,

    pub mint: Account<'info, Mint>,

    #[account(
        mut,
        seeds = [b"note_tree", pool_state.key().as_ref()],
        bump = note_tree.bump,
    )]
    pub note_tree: Account<'info, NoteTree>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct RegisterNullifier<'info> {
    #[account(
        mut,
        has_one = mint,
        seeds = [b"pool_state", mint.key().as_ref()],
        bump = pool_state.bump,
    )]
    pub pool_state: Account<'info, PoolState>,

    pub mint: Account<'info, Mint>,

    #[account(
        mut,
        seeds = [b"nullifiers", pool_state.key().as_ref()],
        bump = nullifiers.bump,
    )]
    pub nullifiers: Account<'info, Nullifiers>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct WithdrawWithNote<'info> {
    #[account(
        has_one = mint,
        seeds = [b"pool_state", mint.key().as_ref()],
        bump = pool_state.bump,
    )]
    pub pool_state: Account<'info, PoolState>,

    pub mint: Account<'info, Mint>,

    #[account(
        seeds = [b"note_tree", pool_state.key().as_ref()],
        bump = note_tree.bump,
    )]
    pub note_tree: Account<'info, NoteTree>,

    #[account(
        mut,
        seeds = [b"nullifiers", pool_state.key().as_ref()],
        bump = nullifiers.bump,
    )]
    pub nullifiers: Account<'info, Nullifiers>,

    #[account(
        mut,
        constraint = pool_vault.mint == mint.key(),
        constraint = pool_vault.owner == pool_state.key(),
    )]
    pub pool_vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = user_token_account.mint == mint.key(),
        constraint = user_token_account.owner == recipient.key(),
    )]
    pub user_token_account: Account<'info, TokenAccount>,

    /// Recipient of withdrawn funds; zk proof “decides” this off-chain.
    #[account()]
    pub recipient: SystemAccount<'info>,

    /// Relayer / tx sender (for fee logic later).
    #[account(mut)]
    pub relayer: Signer<'info>,

    pub token_program: Program<'info, Token>,
}

// ================== STATE ==================

#[account]
pub struct PoolState {
    pub admin: Pubkey,
    pub mint: Pubkey,
    pub bump: u8,
}

impl PoolState {
    pub const SIZE: usize = 32 + 32 + 1;
}

#[account]
pub struct NoteTree {
    pub depth: u8,
    pub current_root_index: u32,
    pub num_roots: u32,
    pub bump: u8,
    pub roots: [[u8; 32]; ROOT_HISTORY],
}

impl NoteTree {
    pub const SIZE: usize = 1 + 4 + 4 + 1 + (32 * ROOT_HISTORY);
}

#[account]
pub struct Nullifiers {
    pub count: u32,
    pub bump: u8,
    pub values: [[u8; 32]; NULLIFIER_CAPACITY],
}

impl Nullifiers {
    pub const SIZE: usize = 4 + 1 + (32 * NULLIFIER_CAPACITY);
}

// ================== EVENTS ==================

#[event]
pub struct NoteDeposited {
    #[index]
    pub pool: Pubkey,
    #[index]
    pub owner: Pubkey,
    pub amount: u64,
    pub note_commitment: [u8; 32],
}

#[event]
pub struct RootAppended {
    #[index]
    pub pool: Pubkey,
    pub root: [u8; 32],
}

#[event]
pub struct NullifierUsed {
    #[index]
    pub pool: Pubkey,
    pub nullifier: [u8; 32],
}

// ================== ERRORS ==================

#[error_code]
pub enum PrivacyError {
    #[msg("Merkle root not found in recent history")]
    UnknownRoot,
    #[msg("Nullifier already used")]
    NullifierAlreadyUsed,
    #[msg("Nullifier set full")]
    NullifierSetFull,
    #[msg("Amount not in allowed fixed denominations")]
    InvalidDenomination,
    #[msg("Not authorized")]
    Unauthorized,
}
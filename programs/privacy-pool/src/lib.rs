use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

declare_id!("G7m7QCf2m6VsaDs7GJC9wMmxCiWxmAjKN6BhakkWYi32");

#[program]
pub mod privacy_pool {
    use super::*;

    pub fn initialize_pool(
        ctx: Context<InitializePool>,
        _bump: u8,
    ) -> Result<()> {
        let state = &mut ctx.accounts.pool_state;
        state.admin = ctx.accounts.authority.key();
        state.mint = ctx.accounts.mint.key();
        state.bump = *ctx.bumps.get("pool_state").unwrap();

        let commitments = &mut ctx.accounts.commitments;
        commitments.bump = *ctx.bumps.get("commitments").unwrap();
        commitments.len = 0;

        Ok(())
    }

    /// V1: public → shielded deposit (no zk yet)
    /// Later: require a zk-proof that the commitment matches internal note data.
    pub fn deposit_public_to_shielded(
        ctx: Context<DepositPublicToShielded>,
        amount: u64,
        commitment: [u8; 32],
    ) -> Result<()> {
        // Transfer SPL tokens from user to pool vault
        let cpi_accounts = Transfer {
            from: ctx.accounts.user_token_account.to_account_info(),
            to: ctx.accounts.pool_token_vault.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer(cpi_ctx, amount)?;

        // For now, store commitments in a simple vector account.
        // Later: you’ll switch to a Merkle tree structure or paginated commitments.
        let commitments = &mut ctx.accounts.commitments;
        require!(
            (commitments.len as usize) < commitments.values.len(),
            PrivacyError::CommitmentsFull
        );
        commitments.values[commitments.len as usize] = commitment;
        commitments.len += 1;

        Ok(())
    }

    /// V1: shielded → public withdraw (fake proof bytes for now)
    /// Later: verify zk-proof and nullifiers before allowing withdraw.
    pub fn withdraw_shielded_to_public(
        ctx: Context<WithdrawShieldedToPublic>,
        amount: u64,
        _fake_proof: Vec<u8>,     // placeholder, to be replaced with real proof bytes
        _nullifier: [u8; 32],     // placeholder, will be checked against nullifier set
    ) -> Result<()> {
        // TODO: later:
        // - verify zk proof
        // - check nullifier not used, then mark it used

        // Transfer SPL tokens from pool vault to user
        let pool_state = &ctx.accounts.pool_state;
        let seeds: &[&[u8]] = &[
            b"pool_state",
            pool_state.mint.as_ref(),
            &[pool_state.bump],
        ];
        let signer_seeds = &[seeds];

        let cpi_accounts = Transfer {
            from: ctx.accounts.pool_token_vault.to_account_info(),
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

// === Accounts ===

#[derive(Accounts)]
#[instruction(bump: u8)]
pub struct InitializePool<'info> {
    #[account(
        init,
        payer = authority,
        seeds = [b"pool_state", mint.key().as_ref()],
        bump,
        space = 8 + PoolState::SIZE
    )]
    pub pool_state: Account<'info, PoolState>,

    pub mint: Account<'info, Mint>,

    #[account(
        init,
        payer = authority,
        token::mint = mint,
        token::authority = pool_state,
    )]
    pub pool_token_vault: Account<'info, TokenAccount>,

    #[account(
        init,
        payer = authority,
        seeds = [b"commitments", pool_state.key().as_ref()],
        bump,
        space = 8 + Commitments::SIZE
    )]
    pub commitments: Account<'info, Commitments>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct DepositPublicToShielded<'info> {
    #[account(mut, has_one = mint)]
    pub pool_state: Account<'info, PoolState>,

    pub mint: Account<'info, Mint>,

    #[account(
        mut,
        constraint = pool_token_vault.mint == mint.key(),
        constraint = pool_token_vault.owner == pool_state.key(),
    )]
    pub pool_token_vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = user_token_account.mint == mint.key(),
        constraint = user_token_account.owner == user.key(),
    )]
    pub user_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        mut,
        seeds = [b"commitments", pool_state.key().as_ref()],
        bump = commitments.bump,
    )]
    pub commitments: Account<'info, Commitments>,

    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct WithdrawShieldedToPublic<'info> {
    #[account(mut, has_one = mint)]
    pub pool_state: Account<'info, PoolState>,

    pub mint: Account<'info, Mint>,

    #[account(
        mut,
        constraint = pool_token_vault.mint == mint.key(),
        constraint = pool_token_vault.owner == pool_state.key(),
    )]
    pub pool_token_vault: Account<'info, TokenAccount>,

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

// === State ===

#[account]
pub struct PoolState {
    pub admin: Pubkey,
    pub mint: Pubkey,
    pub bump: u8,
}

impl PoolState {
    pub const SIZE: usize = 32 + 32 + 1;
}

/// Extremely rough V1 storage for commitments
/// Later: replace this with a more scalable structure (Merkle tree / paginated).
#[account]
pub struct Commitments {
    pub bump: u8,
    pub len: u32,
    pub values: [[u8; 32]; 1024], // up to 1024 commitments for V1
}

impl Commitments {
    pub const SIZE: usize = 1 + 4 + (32 * 1024);
}

// === Errors ===

#[error_code]
pub enum PrivacyError {
    #[msg("Commitments storage account is full")]
    CommitmentsFull,
}
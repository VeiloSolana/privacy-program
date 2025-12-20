use anchor_lang::prelude::*;
use anchor_lang::system_program;
use solana_program::hash::hash;

declare_id!("62trUGD4Th5AooSDfkowYMQ7QqjoAYATbJQ4QY3UpPDo");

// ---- Constants ----

pub const MAX_DENOMS: usize = 4;
pub const MAX_RELAYERS: usize = 16;

/// Logical capacity for the note tree (max leaves = 2^TREE_DEPTH).
/// We don't store the full Merkle tree on-chain anymore, only a rolling root,
/// but we still keep this as a bound on how many notes we "conceptually" support.
pub const TREE_DEPTH: usize = 32;

// ---- Helpers ----

fn hash_two(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(a);
    data[32..].copy_from_slice(b);
    hash(&data).to_bytes()
}

// ---- Accounts ----

/// Minimal on-chain Merkle state:
/// - we track the next leaf index
/// - we track a single "current root"
///
/// The full Merkle tree (leaves + paths) lives off-chain in your relayer / SDK.
/// On-chain we only check that a provided root matches this current_root.
#[account]
pub struct NoteTree {
    pub bump: u8,

    /// Next leaf index to insert (0-based)
    pub next_index: u32,

    /// Current Merkle root (or a placeholder until first deposit)
    pub current_root: [u8; 32],
}

impl NoteTree {
    pub const LEN: usize =
        8 +  // discriminator
        1 +  // bump
        4 +  // next_index
        32;  // current_root

    pub fn init(&mut self) {
        self.next_index = 0;
        self.current_root = [0u8; 32]; // all-zero "empty tree" root
    }

    /// Append a leaf commitment and roll the root forward.
    ///
    /// This is a *toy* update rule:
    ///   new_root = H(old_root || commitment)
    ///
    /// In a real system you'd ensure this matches your off-chain Merkle
    /// function, but for now it's just "some deterministic 32-byte hash".
    pub fn append_leaf(&mut self, leaf_commitment: [u8; 32]) -> Result<[u8; 32]> {
        let index = self.next_index as u64;
        require!(
            index < (1u64 << TREE_DEPTH),
            PrivacyError::NullifierTableFull
        );

        let new_root = hash_two(&self.current_root, &leaf_commitment);
        self.current_root = new_root;

        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or(PrivacyError::MathOverflow)?;

        Ok(new_root)
    }

    pub fn current_root(&self) -> [u8; 32] {
        self.current_root
    }

    pub fn contains_root(&self, root: &[u8; 32]) -> bool {
        &self.current_root == root
    }
}

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

/// Simplified nullifier set: only stores the *last* nullifier.
/// This is intentionally tiny & demo-only. Real-world would need a full set.
#[account]
pub struct NullifierSet {
    pub bump: u8,
    pub count: u32,
    pub last: [u8; 32],
}

impl NullifierSet {
    pub const LEN: usize = 8 + 1 + 4 + 32;

    pub fn is_spent(&self, n: &[u8; 32]) -> bool {
        self.count > 0 && &self.last == n
    }

    pub fn insert(&mut self, n: [u8; 32]) -> Result<()> {
        if self.is_spent(&n) {
            return err!(PrivacyError::NullifierAlreadyUsed);
        }
        self.last = n;
        self.count = self
            .count
            .checked_add(1)
            .ok_or(PrivacyError::MathOverflow)?;
        Ok(())
    }
}

// ---- ZK public inputs ----

/// Public inputs passed to the zk circuit for a withdraw.
///
/// Your Groth16 circuit MUST use exactly these as public inputs:
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

// ---- ZK verification hook ----

// Default: no-op, tests run fast, no heavy crypto.
#[cfg(not(feature = "zk-verify"))]
fn verify_withdraw_proof(
    _proof: &Vec<u8>,
    _inputs: &WithdrawPublicInputs,
) -> Result<()> {
    Ok(())
}

// With `zk-verify` enabled we still stub on-chain verification for now.
#[cfg(feature = "zk-verify")]
fn verify_withdraw_proof(
    _proof: &Vec<u8>,
    _inputs: &WithdrawPublicInputs,
) -> Result<()> {
    Ok(())
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
        space = NoteTree::LEN
    )]
    pub note_tree: Account<'info, NoteTree>,

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
        bump = note_tree.bump
    )]
    pub note_tree: Account<'info, NoteTree>,

    #[account(
        mut,
        seeds = [b"privacy_nullifiers_v3"],
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

    pub fn initialize(
        ctx: Context<Initialize>,
        denoms: Vec<u64>,
        fee_bps: u16,
    ) -> Result<()> {
        let cfg   = &mut ctx.accounts.config;
        let vault = &mut ctx.accounts.vault;
        let tree  = &mut ctx.accounts.note_tree;
        let nulls = &mut ctx.accounts.nullifiers;

        // Bumps
        cfg.bump       = ctx.bumps.config;
        cfg.vault_bump = ctx.bumps.vault;
        vault.bump     = ctx.bumps.vault;
        tree.bump      = ctx.bumps.note_tree;
        nulls.bump     = ctx.bumps.nullifiers;

        cfg.admin   = ctx.accounts.admin.key();
        cfg.paused  = false;
        cfg.fee_bps = fee_bps;

        require!(!denoms.is_empty(), PrivacyError::NoDenoms);
        require!(denoms.len() <= MAX_DENOMS, PrivacyError::TooManyDenoms);

        cfg.num_denoms = denoms.len() as u8;

        // Clear small arrays
        cfg.denoms = [0u64; MAX_DENOMS];
        cfg.tvl    = [0u64; MAX_DENOMS];
        cfg.num_relayers = 0;
        cfg.relayers = [Pubkey::default(); MAX_RELAYERS];

        // Fill configured denoms
        for (i, d) in denoms.into_iter().enumerate() {
            cfg.denoms[i] = d;
        }

        // Initialize note tree & nullifier set
        tree.init();
        nulls.count = 0;
        nulls.last  = [0u8; 32];

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
        let cfg  = &mut ctx.accounts.config;
        let tree = &mut ctx.accounts.note_tree;

        require!(!cfg.paused, PrivacyError::Paused);

        let idx = denom_index as usize;
        require!(idx < cfg.num_denoms as usize, PrivacyError::BadDenomIndex);

        let amount = cfg.denoms[idx];

        // Move SOL from depositor to vault PDA via CPI
        let depositor = &ctx.accounts.depositor;
        let vault_ai  = ctx.accounts.vault.to_account_info();

        let cpi_ctx = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            system_program::Transfer {
                from: depositor.to_account_info(),
                to: vault_ai,
            },
        );
        system_program::transfer(cpi_ctx, amount)?;

        // Update TVL
        cfg.tvl[idx] = cfg.tvl[idx]
            .checked_add(amount)
            .ok_or(PrivacyError::MathOverflow)?;

        // Append leaf to Merkle-ish rolling root
        let _new_root = tree.append_leaf(commitment)?;

        Ok(())
    }

    pub fn withdraw(
        ctx: Context<Withdraw>,
        root: [u8; 32],
        nullifier: [u8; 32],
        denom_index: u8,
        recipient_pk: Pubkey,
        proof: Vec<u8>,
    ) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        require!(!cfg.paused, PrivacyError::Paused);

        // 0) ZK proof verification hook
        let public_inputs = WithdrawPublicInputs {
            root,
            nullifier,
            denom_index,
            recipient: recipient_pk,
        };
        verify_withdraw_proof(&proof, &public_inputs)?;

        // 1) Root must be known (in this toy model: equal to current_root)
        require!(
            ctx.accounts.note_tree.contains_root(&public_inputs.root),
            PrivacyError::UnknownRoot
        );

        // 2) Nullifier must be fresh
        let nulls = &mut ctx.accounts.nullifiers;
        nulls.insert(public_inputs.nullifier)?;

        // 3) Denom & fee math
        let idx = public_inputs.denom_index as usize;
        require!(idx < cfg.num_denoms as usize, PrivacyError::BadDenomIndex);
        let amount = cfg.denoms[idx];

        let fee = amount
            .checked_mul(cfg.fee_bps as u64)
            .ok_or(PrivacyError::MathOverflow)?
            / 10_000;

        let to_user = amount
            .checked_sub(fee)
            .ok_or(PrivacyError::MathOverflow)?;

        // 4) Relayer must be authorized
        let relayer_key = ctx.accounts.relayer.key();
        require!(
            cfg.is_relayer(&relayer_key),
            PrivacyError::RelayerNotAllowed
        );

        // 5) Vault balance & TVL
        let vault_ai = ctx.accounts.vault.to_account_info();
        let vault_balance = **vault_ai.lamports.borrow();

        require!(
            vault_balance >= amount,
            PrivacyError::InsufficientVaultBalance
        );

        cfg.tvl[idx] = cfg.tvl[idx]
            .checked_sub(amount)
            .ok_or(PrivacyError::MathOverflow)?;

        // 6) Recipient sanity check
        require_keys_eq!(ctx.accounts.recipient.key(), public_inputs.recipient);

        // 7) Manual lamport moves
        {
            let recipient_ai = ctx.accounts.recipient.to_account_info();
            let relayer_ai   = ctx.accounts.relayer.to_account_info();

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
}
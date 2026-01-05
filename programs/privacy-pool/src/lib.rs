use anchor_lang::prelude::*;
use light_hasher::Poseidon;

pub mod groth16;
pub mod merkle_tree;
pub mod vk_constants;
pub mod zk;

use merkle_tree::{MerkleTree, MerkleTreeAccount, MERKLE_TREE_HEIGHT, ROOT_HISTORY_SIZE};

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
    /// Fee in basis points (0–10_000) for withdrawals
    pub fee_bps: u16,

    /// Minimum fee for withdrawals (in lamports) to ensure relayer compensation
    pub min_withdrawal_fee: u64,

    /// Total value locked (all deposits combined)
    pub total_tvl: u64,

    /// Token mint address (for now: SOL, future: multi-token support)
    pub mint_address: Pubkey,

    /// Maximum amount allowed per deposit (in lamports/token units)
    pub max_deposit_amount: u64,

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
        8 +   // min_withdrawal_fee
        8 +   // total_tvl
        32 +  // mint_address
        8 +   // max_deposit_amount
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

// ---- ZK public inputs (for transaction circuit) ----

/// Public inputs for Transaction(16, 2, 2) circuit
///
/// Circuit proves:
/// 1. Two input notes exist in Merkle tree at `root`
/// 2. User knows secrets for both input notes
/// 3. sum(inputs) + publicAmount = sum(outputs)
/// 4. Input notes haven't been spent (nullifiers fresh)
/// 5. extDataHash commits to (recipient, relayer, fee, refund)
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct TransactionPublicInputs {
    /// Merkle root (must be in root_history)
    pub root: [u8; 32],

    /// Net public amount (i64 - can be negative for deposits)
    /// Positive = withdrawal, Negative = deposit, Zero = private transfer
    pub public_amount: i64,

    /// Hash of external data: Poseidon(recipient, relayer, fee, refund)
    pub ext_data_hash: [u8; 32],

    /// Token mint (for now: use SOL pubkey constant)
    pub mint_address: Pubkey,

    /// Input nullifiers (2 notes consumed)
    pub input_nullifiers: [[u8; 32]; 2],

    /// Output commitments (2 notes created)
    pub output_commitments: [[u8; 32]; 2],
}

/// External data that gets hashed into ext_data_hash
/// These are public parameters that affect financial flows
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ExtData {
    /// Who receives withdrawal
    pub recipient: Pubkey,
    /// Who submits tx (gets fee)
    pub relayer: Pubkey,
    /// Fee to relayer in lamports
    pub fee: u64,
    /// Refund to user in lamports
    pub refund: u64,
}

impl ExtData {
    /// Reduce 32-byte value modulo BN254 Fr field (copied from zk.rs)
    fn reduce_to_field(bytes: [u8; 32]) -> [u8; 32] {
        use num_bigint::BigUint;

        // BN254 Fr modulus as 32-byte BE
        const FR_MODULUS: [u8; 32] = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
            0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93,
            0xf0, 0x00, 0x00, 0x01,
        ];

        // Quick check: if bytes < modulus, no reduction needed
        let mut needs_reduction = false;
        for i in 0..32 {
            if bytes[i] < FR_MODULUS[i] {
                break;
            }
            if bytes[i] > FR_MODULUS[i] {
                needs_reduction = true;
                break;
            }
        }

        if !needs_reduction {
            return bytes;
        }

        // Use BigUint for proper modulo reduction
        let val = BigUint::from_bytes_be(&bytes);
        let modulus = BigUint::from_bytes_be(&FR_MODULUS);
        let reduced = val % modulus;

        let mut result = [0u8; 32];
        let reduced_bytes = reduced.to_bytes_be();
        let start = 32 - reduced_bytes.len();
        result[start..].copy_from_slice(&reduced_bytes);

        result
    }

    /// Compute Poseidon hash of external data
    /// Returns 32-byte field element
    pub fn hash(&self) -> Result<[u8; 32]> {
        use light_hasher::Hasher;

        // Convert PublicKeys to bytes and reduce modulo field
        let recipient_bytes = Self::reduce_to_field(self.recipient.to_bytes());
        let relayer_bytes = Self::reduce_to_field(self.relayer.to_bytes());

        // Encode u64 values as 32-byte big-endian (these are already < Fr)
        let mut fee_bytes = [0u8; 32];
        fee_bytes[24..].copy_from_slice(&self.fee.to_be_bytes());

        let mut refund_bytes = [0u8; 32];
        refund_bytes[24..].copy_from_slice(&self.refund.to_be_bytes());

        // Hash in pairs to match binary Merkle tree pattern
        // extDataHash = Poseidon(Poseidon(recipient, relayer), Poseidon(fee, refund))
        let hash1 = PoseidonHasher::hashv(&[&recipient_bytes, &relayer_bytes])
            .map_err(|_| error!(PrivacyError::MerkleHashFailed))?;

        let hash2 = PoseidonHasher::hashv(&[&fee_bytes, &refund_bytes])
            .map_err(|_| error!(PrivacyError::MerkleHashFailed))?;

        let final_hash = PoseidonHasher::hashv(&[&hash1, &hash2])
            .map_err(|_| error!(PrivacyError::MerkleHashFailed))?;

        Ok(final_hash)
    }
}

// ---- Legacy: Keep for backwards compatibility, will be removed ----

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

// ---- New UTXO Transaction Instruction ----

#[derive(Accounts)]
#[instruction(
    root: [u8; 32],
    public_amount: i64,
    ext_data_hash: [u8; 32],
    mint_address: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    output_commitment_0: [u8; 32],
    output_commitment_1: [u8; 32]
)]
pub struct Transact<'info> {
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

    /// First nullifier marker (must not exist - ensures nullifier is fresh)
    #[account(
        init,
        payer = relayer,
        seeds = [b"nullifier_v3", input_nullifier_0.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub nullifier_marker_0: Account<'info, NullifierMarker>,

    /// Second nullifier marker (must not exist - ensures nullifier is fresh)
    #[account(
        init,
        payer = relayer,
        seeds = [b"nullifier_v3", input_nullifier_1.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub nullifier_marker_1: Account<'info, NullifierMarker>,

    /// Relayer who submits transaction (pays rent, receives fee)
    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Recipient (receives withdrawal amount if public_amount > 0)
    /// CHECK: Validated via ext_data_hash in proof
    #[account(mut)]
    pub recipient: SystemAccount<'info>,

    pub system_program: Program<'info, System>,
}

// ---- Legacy Withdraw (will be removed) ----

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

    pub fn initialize(ctx: Context<Initialize>, fee_bps: u16, mint_address: Pubkey) -> Result<()> {
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
        cfg.min_withdrawal_fee = 1_000_000; // Default: 0.001 SOL minimum fee

        // UTXO model: no fixed denominations
        cfg.total_tvl = 0;
        cfg.mint_address = mint_address;
        cfg.max_deposit_amount = 1_000_000_000_000; // Default: 1000 SOL/tokens

        cfg.num_relayers = 0;
        cfg.relayers = [Pubkey::default(); MAX_RELAYERS];

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

    /// Unified UTXO transaction instruction
    /// Handles deposits (publicAmount < 0), withdrawals (publicAmount > 0), and transfers (publicAmount = 0)
    pub fn transact(
        ctx: Context<Transact>,
        root: [u8; 32],
        public_amount: i64,
        ext_data_hash: [u8; 32],
        mint_address: Pubkey,
        input_nullifier_0: [u8; 32],
        input_nullifier_1: [u8; 32],
        output_commitment_0: [u8; 32],
        output_commitment_1: [u8; 32],
        ext_data: ExtData,
        proof: zk::TransactionProof,
    ) -> Result<()> {
        // Combine individual nullifiers/commitments into arrays for processing
        let input_nullifiers = [input_nullifier_0, input_nullifier_1];
        let output_commitments = [output_commitment_0, output_commitment_1];
        let cfg = &mut ctx.accounts.config;
        let tree = ctx.accounts.note_tree.load()?;

        require!(!cfg.paused, PrivacyError::Paused);

        // Validate no duplicate nullifiers (prevents trying to spend same note twice in one tx)
        require!(
            input_nullifiers[0] != input_nullifiers[1],
            PrivacyError::DuplicateNullifiers
        );

        // Validate no duplicate output commitments (prevents creating identical notes)
        require!(
            output_commitments[0] != output_commitments[1],
            PrivacyError::DuplicateCommitments
        );

        // 1. Verify ext_data_hash matches provided ext_data
        let computed_ext_hash = ext_data.hash()?;
        require!(
            computed_ext_hash == ext_data_hash,
            PrivacyError::InvalidExtData
        );

        // 2. Verify relayer is authorized (only for withdrawals/transfers, not deposits)
        // For deposits (public_amount < 0), anyone can deposit without being a relayer
        if public_amount >= 0 {
            require!(
                cfg.is_relayer(&ctx.accounts.relayer.key()),
                PrivacyError::RelayerNotAllowed
            );
        }

        // 3. Verify recipient matches ext_data
        require_keys_eq!(
            ctx.accounts.recipient.key(),
            ext_data.recipient,
            PrivacyError::RecipientMismatch
        );

        // 4. Verify mint address matches config
        require_keys_eq!(
            mint_address,
            cfg.mint_address,
            PrivacyError::InvalidMintAddress
        );

        // 5. Build public inputs for ZK proof
        let public_inputs = TransactionPublicInputs {
            root,
            public_amount,
            ext_data_hash,
            mint_address,
            input_nullifiers,
            output_commitments,
        };

        // 6. Verify Groth16 proof
        zk::verify_transaction_groth16(proof, &public_inputs)?;

        // 7. Check root is known in tree
        require!(
            MerkleTree::is_known_root(&*tree, root),
            PrivacyError::UnknownRoot
        );

        drop(tree); // Release immutable borrow

        // 8. Mark both input nullifiers as spent
        mark_nullifier_spent(
            &mut ctx.accounts.nullifier_marker_0,
            &mut ctx.accounts.nullifiers,
            input_nullifiers[0],
            ctx.bumps.nullifier_marker_0,
        )?;

        mark_nullifier_spent(
            &mut ctx.accounts.nullifier_marker_1,
            &mut ctx.accounts.nullifiers,
            input_nullifiers[1],
            ctx.bumps.nullifier_marker_1,
        )?;

        // 9. Insert both output commitments into tree
        let mut tree = ctx.accounts.note_tree.load_mut()?;
        MerkleTree::append::<PoseidonHasher>(output_commitments[0], &mut *tree)?;
        MerkleTree::append::<PoseidonHasher>(output_commitments[1], &mut *tree)?;

        drop(tree); // Release mutable borrow

        // 10. Handle public amount (deposits/withdrawals)
        handle_public_amount(
            cfg,
            &ctx.accounts.vault,
            &ctx.accounts.recipient,
            &ctx.accounts.relayer,
            &ctx.accounts.system_program,
            public_amount,
            &ext_data,
        )?;

        Ok(())
    }
}

// ---- Helper Functions ----

/// Mark a nullifier as spent
fn mark_nullifier_spent(
    marker: &mut Account<NullifierMarker>,
    nullifier_set: &mut Account<NullifierSet>,
    nullifier: [u8; 32],
    bump: u8,
) -> Result<()> {
    marker.nullifier = nullifier;
    marker.timestamp = Clock::get()?.unix_timestamp;
    marker.withdrawal_index = nullifier_set.count;
    marker.bump = bump;

    nullifier_set.count = nullifier_set
        .count
        .checked_add(1)
        .ok_or(PrivacyError::ArithmeticOverflow)?;

    Ok(())
}

/// Handle lamport flows based on public_amount
///
/// public_amount < 0: Deposit (user -> vault)
/// public_amount > 0: Withdrawal (vault -> recipient + relayer)
/// public_amount = 0: Private transfer (no SOL movement)
fn handle_public_amount<'info>(
    config: &mut PrivacyConfig,
    vault: &Account<'info, Vault>,
    recipient: &SystemAccount<'info>,
    relayer: &Signer<'info>,
    system_program: &Program<'info, System>,
    public_amount: i64,
    ext_data: &ExtData,
) -> Result<()> {
    // Validate ext_data values are non-negative
    require!(ext_data.fee < i64::MAX as u64, PrivacyError::InvalidFeeAmount);
    require!(
        ext_data.refund < i64::MAX as u64,
        PrivacyError::InvalidPublicAmount
    );

    if public_amount < 0 {
        // DEPOSIT: user deposits |public_amount| lamports
        let deposit_amount = public_amount.abs() as u64;

        // For deposits, fee and refund should be zero
        require!(
            ext_data.fee == 0 && ext_data.refund == 0,
            PrivacyError::InvalidPublicAmount
        );

        // Check deposit limit
        require!(
            deposit_amount <= config.max_deposit_amount,
            PrivacyError::DepositLimitExceeded
        );

        // Use system_program::transfer for deposits (safer, with built-in validations)
        anchor_lang::system_program::transfer(
            CpiContext::new(
                system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: relayer.to_account_info(),
                    to: vault.to_account_info(),
                },
            ),
            deposit_amount,
        )?;

        // Update TVL
        config.total_tvl = config
            .total_tvl
            .checked_add(deposit_amount)
            .ok_or(PrivacyError::ArithmeticOverflow)?;
    } else if public_amount > 0 {
        // WITHDRAWAL: vault pays out public_amount
        let withdrawal_amount = public_amount as u64;

        // Validate that fee + refund doesn't exceed withdrawal amount
        let fee = ext_data.fee;
        let refund = ext_data.refund;
        let fee_plus_refund = fee
            .checked_add(refund)
            .ok_or(PrivacyError::ArithmeticOverflow)?;
        require!(
            fee_plus_refund <= withdrawal_amount,
            PrivacyError::InvalidPublicAmount
        );

        // Calculate amount to recipient
        let to_recipient = withdrawal_amount
            .checked_sub(fee)
            .and_then(|x| x.checked_sub(refund))
            .ok_or(PrivacyError::ArithmeticOverflow)?;

        // Verify fee is within acceptable range
        // 1. Check minimum fee to ensure relayer compensation
        require!(
            fee >= config.min_withdrawal_fee,
            PrivacyError::InsufficientFee
        );

        // 2. Check maximum fee (prevent malicious relayer from overcharging)
        let max_fee = withdrawal_amount
            .checked_mul(config.fee_bps as u64)
            .ok_or(PrivacyError::ArithmeticOverflow)?
            / 10_000;
        require!(fee <= max_fee, PrivacyError::ExcessiveFee);

        // Ensure vault maintains rent exemption after withdrawal
        let vault_ai = vault.to_account_info();
        let rent = Rent::get()?;
        let rent_exempt_minimum = rent.minimum_balance(vault_ai.data_len());

        let total_required = withdrawal_amount
            .checked_add(rent_exempt_minimum)
            .ok_or(PrivacyError::ArithmeticOverflow)?;

        require!(
            vault_ai.lamports() >= total_required,
            PrivacyError::InsufficientFundsForWithdrawal
        );

        // Transfer lamports using manual manipulation (vault is a PDA we control)
        let recipient_ai = recipient.to_account_info();
        let relayer_ai = relayer.to_account_info();

        **vault_ai.try_borrow_mut_lamports()? = vault_ai
            .lamports()
            .checked_sub(withdrawal_amount)
            .ok_or(PrivacyError::ArithmeticOverflow)?;

        **recipient_ai.try_borrow_mut_lamports()? = recipient_ai
            .lamports()
            .checked_add(to_recipient)
            .ok_or(PrivacyError::ArithmeticOverflow)?;

        **relayer_ai.try_borrow_mut_lamports()? = relayer_ai
            .lamports()
            .checked_add(fee)
            .and_then(|x| x.checked_add(refund))
            .ok_or(PrivacyError::ArithmeticOverflow)?;

        // Update TVL
        config.total_tvl = config
            .total_tvl
            .checked_sub(withdrawal_amount)
            .ok_or(PrivacyError::ArithmeticOverflow)?;
    }
    // else: public_amount == 0, no lamport movement (pure private transfer)

    Ok(())
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
    // New UTXO errors
    #[msg("Invalid external data hash")]
    InvalidExtData,
    #[msg("Recipient mismatch")]
    RecipientMismatch,
    #[msg("Invalid mint address")]
    InvalidMintAddress,
    #[msg("Excessive fee")]
    ExcessiveFee,
    #[msg("Fee below minimum required for withdrawal")]
    InsufficientFee,
    #[msg("Arithmetic overflow/underflow occurred")]
    ArithmeticOverflow,
    #[msg("Insufficient funds for withdrawal (including rent exemption)")]
    InsufficientFundsForWithdrawal,
    #[msg("Insufficient funds for fee payment")]
    InsufficientFundsForFee,
    #[msg("Deposit limit exceeded")]
    DepositLimitExceeded,
    #[msg("Invalid public amount data")]
    InvalidPublicAmount,
    #[msg("Invalid fee amount")]
    InvalidFeeAmount,
    #[msg("Duplicate nullifiers detected")]
    DuplicateNullifiers,
    #[msg("Duplicate output commitments detected")]
    DuplicateCommitments,
}

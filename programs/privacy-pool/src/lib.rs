use anchor_lang::prelude::*;
use anchor_spl::associated_token::get_associated_token_address;
use anchor_spl::token::{self, Mint, Token, TokenAccount};
use light_hasher::Poseidon;

pub mod groth16;
pub mod merkle_tree;
pub mod swap;
pub mod vk_constants;
pub mod zk;

// Re-export swap types for Anchor
pub use swap::{SwapExecutor, SwapParams, SwapPublicInputs};
pub use zk::SwapProof;

use merkle_tree::{MerkleTree, MerkleTreeAccount, MERKLE_TREE_HEIGHT, ROOT_HISTORY_SIZE};

declare_id!("6Cq2rfH7hcreu6Lz4LFoVvZC37Q5uzNq1cStuTnjFdBU");

// ---- Constants ----

// AUDIT-015: Compute Budget Requirements for ZK Verification
// Groth16 verification performs 4 BN254 pairings + scalar multiplications
// Transaction circuit (8 public inputs): ~350,000 CUs
// Swap circuit (10 public inputs): ~400,000 CUs
// Clients MUST prepend ComputeBudgetInstruction::SetComputeUnitLimit
// with at least 500,000 CUs before calling transact() or transact_swap()
pub const RECOMMENDED_COMPUTE_UNITS_TRANSACTION: u32 = 500_000;
pub const RECOMMENDED_COMPUTE_UNITS_SWAP: u32 = 500_000;

/// Authorized admin address that can initialize pools
/// For localnet/test: None (any wallet can initialize for testing)
/// For devnet/mainnet: Specific authorized wallet only
#[cfg(any(feature = "localnet", test))]
pub const AUTHORIZED_ADMIN: Option<Pubkey> = None;

#[cfg(not(any(feature = "localnet", test)))]
pub const AUTHORIZED_ADMIN: Option<Pubkey> =
    Some(pubkey!("H6QRuiRsguQgpRSJpP79h75EfDYRS2wN78oj7a4auZtP"));

pub type PoseidonHasher = Poseidon;
pub const MAX_RELAYERS: usize = 16;

/// Maximum number of Merkle trees per pool
/// Multiple trees improve performance through parallelism
/// and reduce congestion on single tree updates
pub const MAX_MERKLE_TREES: u16 = 10000;

/// Maximum fee basis points: 100 = 1%
pub const MAX_FEE_BPS: u16 = 100;

/// Allow all SPL tokens for testing on localnet
/// TODO: For production, set this to false and use ALLOWED_TOKENS whitelist
pub const ALLOW_ALL_SPL_TOKENS: bool = true;

/// Devnet/Localnet allowed tokens (test networks)
#[cfg(any(feature = "devnet", feature = "localnet"))]
pub const ALLOWED_TOKENS: &[Pubkey] = &[
    pubkey!("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"), // USDC (devnet)
    pubkey!("EcFc2cMyZxaKBkFK1XooxiyDyCPneLXiMwSJiVY6eTad"), // USDT (devnet)
    pubkey!("6zxkY8UygHKBf64LJDXnzcYr9wdvyqScmj7oGPBFw58Z"), // ORE (devnet)
    pubkey!("Vu3Lcx3chdCHmy9KCCdd19DdJsLejHAZxm1E1bTgE16"),  // ZEC (devnet)
    pubkey!("5MvqBFU5zeHaEfRuAFW2RhqidHLb7Ejsa6sUwPQQXcj1"), // stORE (devnet)
];

/// Mainnet allowed tokens (production)
#[cfg(not(any(feature = "devnet", feature = "localnet")))]
pub const ALLOWED_TOKENS: &[Pubkey] = &[
    pubkey!("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"), // USDC
    pubkey!("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"), // USDT
    pubkey!("oreoU2P8bN6jkk3jbaiVxYnG1dCXcYxwhwyK9jSybcp"),  // ORE
    pubkey!("A7bdiYdS5GjqGFtxf17ppRHtDKPkkRqbKtR27dxvQXaS"), // ZEC
    pubkey!("sTorERYB6xAZ1SSbwpK3zoK2EEwbBrc7TZAzg1uCGiH"),  // stORE
];

/// Raydium CPMM program ID (mainnet)
pub const RAYDIUM_CPMM_PROGRAM_ID: Pubkey = pubkey!("CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C");

/// Raydium AMM V4 program ID (mainnet)
pub const RAYDIUM_AMM_PROGRAM_ID: Pubkey = pubkey!("675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8");

// ---- Accounts ----

#[account]
pub struct PrivacyConfig {
    /// PDA bump for this config
    pub bump: u8,
    /// PDA bump for vault
    pub vault_bump: u8,
    /// Admin who can configure pool and relayers
    pub admin: Pubkey,
    /// Fee in basis points (0–10_000) for withdrawals
    pub fee_bps: u16,

    /// Minimum fee for withdrawals (in lamports) to ensure relayer compensation
    pub min_withdrawal_fee: u64,

    /// Fee error margin in basis points (e.g., 500 = 5%)
    /// Allows fee variance to prevent timing attacks where identical fees
    /// could correlate deposits/withdrawals
    pub fee_error_margin_bps: u16,

    /// Total value locked (all deposits combined)
    pub total_tvl: u64,

    /// Token mint address (for now: SOL, future: multi-token support)
    pub mint_address: Pubkey,

    /// Minimum amount allowed per deposit (in lamports/token units)
    pub min_deposit_amount: u64,

    /// Maximum amount allowed per deposit (in lamports/token units)
    pub max_deposit_amount: u64,

    /// Minimum amount allowed per withdrawal (in lamports/token units)
    pub min_withdraw_amount: u64,

    /// Maximum amount allowed per withdrawal (in lamports/token units)
    pub max_withdraw_amount: u64,

    /// Relayer registry
    pub num_relayers: u8,
    pub relayers: [Pubkey; MAX_RELAYERS],

    /// Multi-tree support: number of active Merkle trees
    pub num_trees: u16,

    /// Suggested tree index for next deposit (round-robin)
    pub next_tree_index: u16,

    /// Minimum swap fee in destination token units (e.g., 100000 = 0.1 USDC)
    /// Ensures relayer compensation for swap transactions
    pub min_swap_fee: u64,

    /// Swap fee in basis points (0-10_000) of swap output amount
    /// Used with min_swap_fee: actual fee must be >= max(min_swap_fee, output * swap_fee_bps / 10000)
    pub swap_fee_bps: u16,
}

impl PrivacyConfig {
    pub const LEN: usize = 8 +   // discriminator
        1 +   // bump
        1 +   // vault_bump
        32 +  // admin
        2 +   // fee_bps
        8 +   // min_withdrawal_fee
        2 +   // fee_error_margin_bps
        8 +   // total_tvl
        32 +  // mint_address
        8 +   // min_deposit_amount
        8 +   // max_deposit_amount
        8 +   // min_withdraw_amount
        8 +   // max_withdraw_amount
        1 +   // num_relayers
        32 * MAX_RELAYERS +  // relayers
        2 +   // num_trees (u16)
        2 +   // next_tree_index (u16)
        8 +   // min_swap_fee
        2; // swap_fee_bps (661 bytes total)

    pub fn is_relayer(&self, key: &Pubkey) -> bool {
        let n = self.num_relayers as usize;
        self.relayers[..n].iter().any(|k| k == key)
    }

    /// Get the next suggested tree_id for deposits (round-robin distribution)
    /// Updates next_tree_index for the next call
    ///
    /// Note: Clients should check tree capacity before submitting deposits.
    /// If a tree is full (next_index + 2 >= 2^height), use a different tree_id
    /// or call add_merkle_tree to create a new tree.
    pub fn get_next_tree_id(&mut self) -> u16 {
        let tree_id = self.next_tree_index;
        self.next_tree_index = (self.next_tree_index + 1) % self.num_trees;
        tree_id
    }

    /// Check if a specific tree has capacity for N new leaves
    pub fn tree_has_capacity(tree: &MerkleTreeAccount, required_leaves: u64) -> bool {
        let max_capacity = 1u64 << (tree.height as u64);
        let remaining = max_capacity.saturating_sub(tree.next_index);
        remaining >= required_leaves
    }
}

#[account]
pub struct GlobalConfig {
    /// PDA bump
    pub bump: u8,

    /// Admin who can configure global settings
    pub admin: Pubkey,
}

impl GlobalConfig {
    pub const LEN: usize = 8 + 1 + 32; // 41 bytes
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
    /// Tree ID this nullifier belongs to (prevents cross-tree double-spend)
    pub tree_id: u16,
    /// PDA bump
    pub bump: u8,
}

impl NullifierMarker {
    pub const LEN: usize = 8 + 32 + 8 + 4 + 2 + 1; // 55 bytes (tree_id is now u16)
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

    /// Net public amount (i64 - signed for deposits/withdrawals)
    /// Circuit equation: sumIns + publicAmount = sumOuts
    /// POSITIVE = DEPOSIT (adding to pool: 0 + amount = outputs)
    /// NEGATIVE = WITHDRAWAL (removing from pool: inputs + negative = smaller outputs)
    /// ZERO = PRIVATE TRANSFER (no value crossing pool boundary)
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

// ---- Instruction contexts ----

#[derive(Accounts)]
#[instruction(fee_bps: u16, mint_address: Pubkey)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = admin,
        seeds = [b"privacy_config_v3", mint_address.as_ref()],
        bump,
        space = PrivacyConfig::LEN
    )]
    pub config: Account<'info, PrivacyConfig>,

    #[account(
        init,
        payer = admin,
        seeds = [b"privacy_vault_v3", mint_address.as_ref()],
        bump,
        space = Vault::LEN
    )]
    pub vault: Account<'info, Vault>,

    /// Initial tree (tree_id = 0)
    #[account(
        init,
        payer = admin,
        seeds = [b"privacy_note_tree_v3", mint_address.as_ref(), &0u16.to_le_bytes()],
        bump,
        space = MerkleTreeAccount::LEN,
    )]
    pub note_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        init,
        payer = admin,
        seeds = [b"privacy_nullifiers_v3", mint_address.as_ref()],
        bump,
        space = NullifierSet::LEN
    )]
    pub nullifiers: Account<'info, NullifierSet>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(mint_address: Pubkey)]
pub struct ConfigAdmin<'info> {
    #[account(
        mut,
        seeds = [b"privacy_config_v3", mint_address.as_ref()],
        bump = config.bump,
        has_one = admin
    )]
    pub config: Account<'info, PrivacyConfig>,

    #[account(mut)]
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(mint_address: Pubkey)]
pub struct UpdatePoolConfig<'info> {
    #[account(
        mut,
        seeds = [b"privacy_config_v3", mint_address.as_ref()],
        bump = config.bump,
        has_one = admin
    )]
    pub config: Account<'info, PrivacyConfig>,

    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeGlobalConfig<'info> {
    #[account(
        init,
        payer = admin,
        seeds = [b"global_config_v1"],
        bump,
        space = GlobalConfig::LEN
    )]
    pub global_config: Account<'info, GlobalConfig>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct GlobalConfigAdmin<'info> {
    #[account(
        mut,
        seeds = [b"global_config_v1"],
        bump = global_config.bump,
        has_one = admin
    )]
    pub global_config: Account<'info, GlobalConfig>,

    pub admin: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(mint_address: Pubkey, tree_id: u16)]
pub struct AddMerkleTree<'info> {
    #[account(
        mut,
        seeds = [b"privacy_config_v3", mint_address.as_ref()],
        bump = config.bump
    )]
    pub config: Account<'info, PrivacyConfig>,

    #[account(
        init,
        payer = payer,
        seeds = [b"privacy_note_tree_v3", mint_address.as_ref(), &tree_id.to_le_bytes()],
        bump,
        space = MerkleTreeAccount::LEN,
    )]
    pub note_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}
// ---- New UTXO Transaction Instruction ----

#[derive(Accounts)]
#[instruction(
    root: [u8; 32],
    input_tree_id: u16,
    output_tree_id: u16,
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
        seeds = [b"privacy_config_v3", mint_address.as_ref()],
        bump = config.bump
    )]
    pub config: Account<'info, PrivacyConfig>,

    #[account(
        seeds = [b"global_config_v1"],
        bump = global_config.bump
    )]
    pub global_config: Account<'info, GlobalConfig>,

    #[account(
        mut,
        seeds = [b"privacy_vault_v3", mint_address.as_ref()],
        bump = config.vault_bump
    )]
    pub vault: Account<'info, Vault>,

    /// Input tree - where input notes came from (for root validation)
    #[account(
        mut,
        seeds = [b"privacy_note_tree_v3", mint_address.as_ref(), &input_tree_id.to_le_bytes()],
        bump,
    )]
    pub input_tree: AccountLoader<'info, MerkleTreeAccount>,

    /// Output tree - where new output commitments will be inserted
    #[account(
        mut,
        seeds = [b"privacy_note_tree_v3", mint_address.as_ref(), &output_tree_id.to_le_bytes()],
        bump,
    )]
    pub output_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        mut,
        seeds = [b"privacy_nullifiers_v3", mint_address.as_ref()],
        bump = nullifiers.bump
    )]
    pub nullifiers: Account<'info, NullifierSet>,

    /// First nullifier marker (must not exist for withdrawals - ensures nullifier is fresh)
    /// For deposits (public_amount > 0), this should be the zero nullifier marker (reusable)
    #[account(
        init,
        payer = relayer,
        seeds = [b"nullifier_v3", mint_address.as_ref(), &input_tree_id.to_le_bytes(), input_nullifier_0.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub nullifier_marker_0: Account<'info, NullifierMarker>,

    /// Second nullifier marker (must not exist for withdrawals - ensures nullifier is fresh)
    /// For deposits (public_amount > 0), this should be the zero nullifier marker (reusable)
    #[account(
        init,
        payer = relayer,
        seeds = [b"nullifier_v3", mint_address.as_ref(), &input_tree_id.to_le_bytes(), input_nullifier_1.as_ref()],
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

    /// Vault's token account (ATA for mint_address)
    /// CHECK: Validated in instruction logic for token operations
    #[account(mut)]
    pub vault_token_account: UncheckedAccount<'info>,

    /// User's token account (for deposits)
    /// CHECK: Validated in instruction logic for token operations
    #[account(mut)]
    pub user_token_account: UncheckedAccount<'info>,

    /// Recipient's token account (for withdrawals)
    /// CHECK: Validated in instruction logic for token operations
    #[account(mut)]
    pub recipient_token_account: UncheckedAccount<'info>,

    /// Relayer's token account (for fees)
    /// CHECK: Validated in instruction logic for token operations
    #[account(mut)]
    pub relayer_token_account: UncheckedAccount<'info>,

    /// SPL Token program
    /// CHECK: Validated in instruction logic for token operations
    pub token_program: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

/// Check if mint is a token (not native SOL)
fn is_token_mint(mint: &Pubkey) -> bool {
    mint != &Pubkey::default()
}

/// Safely deserialize a token account with owner validation
/// Prevents malicious programs from passing fake token accounts
fn deserialize_token_account(account: &AccountInfo) -> Result<TokenAccount> {
    // Verify account is owned by SPL Token Program
    require_keys_eq!(
        *account.owner,
        token::ID,
        PrivacyError::InvalidTokenAccountOwner
    );

    let data = account.try_borrow_data()?;
    TokenAccount::try_deserialize(&mut &data[..])
        .map_err(|_| error!(PrivacyError::MissingTokenAccount))
}

// ---- Swap Transaction Accounts ----

/// Account context for atomic cross-pool swap
/// This instruction:
/// 1. Consumes notes from source pool (e.g., SOL)
/// 2. Creates ephemeral executor PDA
/// 3. CPIs to Raydium CPMM to execute swap (NO SERUM)
/// 4. Creates notes in destination pool (e.g., USDC)
/// All atomic - succeeds or reverts entirely
#[derive(Accounts)]
#[instruction(
    proof: zk::SwapProof,
    source_root: [u8; 32],
    source_tree_id: u16,
    source_mint: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    dest_tree_id: u16,
    dest_mint: Pubkey,
    output_commitment_0: [u8; 32],
    output_commitment_1: [u8; 32],
)]
pub struct TransactSwap<'info> {
    // ---- Source Pool (tokens being swapped FROM) ----
    #[account(
        mut,
        seeds = [b"privacy_config_v3", source_mint.as_ref()],
        bump = source_config.bump
    )]
    pub source_config: Box<Account<'info, PrivacyConfig>>,

    #[account(
        seeds = [b"global_config_v1"],
        bump = global_config.bump
    )]
    pub global_config: Box<Account<'info, GlobalConfig>>,

    #[account(
        mut,
        seeds = [b"privacy_vault_v3", source_mint.as_ref()],
        bump = source_config.vault_bump
    )]
    pub source_vault: Box<Account<'info, Vault>>,

    /// Source tree - where input notes came from
    #[account(
        mut,
        seeds = [b"privacy_note_tree_v3", source_mint.as_ref(), &source_tree_id.to_le_bytes()],
        bump,
    )]
    pub source_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        mut,
        seeds = [b"privacy_nullifiers_v3", source_mint.as_ref()],
        bump = source_nullifiers.bump
    )]
    pub source_nullifiers: Box<Account<'info, NullifierSet>>,

    /// First nullifier marker for source pool
    #[account(
        init,
        payer = relayer,
        seeds = [b"nullifier_v3", source_mint.as_ref(), &source_tree_id.to_le_bytes(), input_nullifier_0.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub source_nullifier_marker_0: Box<Account<'info, NullifierMarker>>,

    /// Second nullifier marker for source pool
    #[account(
        init,
        payer = relayer,
        seeds = [b"nullifier_v3", source_mint.as_ref(), &source_tree_id.to_le_bytes(), input_nullifier_1.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub source_nullifier_marker_1: Box<Account<'info, NullifierMarker>>,

    /// Source vault's token account (ATA for source_mint)
    #[account(mut)]
    pub source_vault_token_account: Box<Account<'info, TokenAccount>>,

    /// Source token mint
    pub source_mint_account: Box<Account<'info, Mint>>,

    // ---- Destination Pool (tokens being swapped TO) ----
    #[account(
        mut,
        seeds = [b"privacy_config_v3", dest_mint.as_ref()],
        bump = dest_config.bump
    )]
    pub dest_config: Box<Account<'info, PrivacyConfig>>,

    #[account(
        mut,
        seeds = [b"privacy_vault_v3", dest_mint.as_ref()],
        bump = dest_config.vault_bump
    )]
    pub dest_vault: Box<Account<'info, Vault>>,

    /// Destination tree - where output commitments will be inserted
    #[account(
        mut,
        seeds = [b"privacy_note_tree_v3", dest_mint.as_ref(), &dest_tree_id.to_le_bytes()],
        bump,
    )]
    pub dest_tree: AccountLoader<'info, MerkleTreeAccount>,

    /// Destination vault's token account (ATA for dest_mint)
    #[account(mut)]
    pub dest_vault_token_account: Box<Account<'info, TokenAccount>>,

    /// Destination token mint
    pub dest_mint_account: Box<Account<'info, Mint>>,

    // ---- Ephemeral Swap Executor PDA ----
    /// Executor PDA - holds tokens during swap
    /// Seeds ensure this is unique per swap (bound to nullifier)
    /// AUDIT-003 fix: Use init instead of init_if_needed to prevent griefing/front-running
    #[account(
        init,
        payer = relayer,
        seeds = [b"swap_executor", input_nullifier_0.as_ref()],
        bump,
        space = SwapExecutor::LEN
    )]
    pub executor: Box<Account<'info, SwapExecutor>>,

    /// Executor's source token account (receives from source vault)
    #[account(
        init,
        payer = relayer,
        associated_token::mint = source_mint_account,
        associated_token::authority = executor,
    )]
    pub executor_source_token: Box<Account<'info, TokenAccount>>,

    /// Executor's destination token account (receives swapped tokens)
    #[account(
        init,
        payer = relayer,
        associated_token::mint = dest_mint_account,
        associated_token::authority = executor,
    )]
    pub executor_dest_token: Box<Account<'info, TokenAccount>>,

    // ---- Transaction Participants ----
    /// Relayer who submits transaction (pays rent, receives fee)
    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Relayer's token account for fees (dest token)
    #[account(mut)]
    pub relayer_token_account: Box<Account<'info, TokenAccount>>,

    // ---- Raydium Integration (CPMM or AMM) ----
    /// Raydium Swap program (CPMM or AMM)
    /// CHECK: Validated against Raydium program ID in instruction
    pub swap_program: UncheckedAccount<'info>,

    // Additional Raydium CPMM accounts passed via remaining_accounts:
    // 0: pool_state - The CPMM pool state account
    // 1: pool_authority - The pool authority PDA
    // 2: token_vault_0 - Pool's first token vault
    // 3: token_vault_1 - Pool's second token vault
    // 4: observation_state - Oracle observation (optional)
    //
    // Only 5 accounts needed! Much simpler than legacy AMM.
    // ---- Programs ----
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub associated_token_program: Program<'info, anchor_spl::associated_token::AssociatedToken>,
}

// ---- Program ----

#[program]
pub mod privacy_pool {
    use super::*;

    pub fn initialize(
        ctx: Context<Initialize>,
        fee_bps: u16,
        mint_address: Pubkey,
        min_deposit_amount: Option<u64>,
        max_deposit_amount: Option<u64>,
        min_withdraw_amount: Option<u64>,
        max_withdraw_amount: Option<u64>,
    ) -> Result<()> {
        // Check authorization
        if let Some(admin_key) = AUTHORIZED_ADMIN {
            require!(
                ctx.accounts.admin.key().eq(&admin_key),
                PrivacyError::UnauthorizedAdmin
            );
        }

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

        // Validate fee_bps does not exceed 100%
        require!(fee_bps <= MAX_FEE_BPS, PrivacyError::ExcessiveFeeBps);

        cfg.fee_bps = fee_bps;
        cfg.min_withdrawal_fee = 1_000_000; // Default: 0.001 SOL minimum fee
        cfg.fee_error_margin_bps = 500; // Default: 5% margin to prevent timing attacks

        // UTXO model: no fixed denominations
        cfg.total_tvl = 0;
        cfg.mint_address = mint_address;

        // Set deposit/withdraw limits with sensible defaults
        cfg.min_deposit_amount = min_deposit_amount.unwrap_or(1_000_000); // Default: 0.001 SOL
        cfg.max_deposit_amount = max_deposit_amount.unwrap_or(1_000_000_000_000); // Default: 1000 SOL
        cfg.min_withdraw_amount = min_withdraw_amount.unwrap_or(1_000_000); // Default: 0.001 SOL
        cfg.max_withdraw_amount = max_withdraw_amount.unwrap_or(1_000_000_000_000); // Default: 1000 SOL

        // Validate ranges
        require!(
            cfg.min_deposit_amount <= cfg.max_deposit_amount,
            PrivacyError::InvalidPoolConfigRange
        );
        require!(
            cfg.min_withdraw_amount <= cfg.max_withdraw_amount,
            PrivacyError::InvalidPoolConfigRange
        );

        cfg.num_relayers = 0;
        cfg.relayers = [Pubkey::default(); MAX_RELAYERS];

        // ---- Multi-tree initialization ----
        cfg.num_trees = 1; // Start with one tree (tree_id = 0)
        cfg.next_tree_index = 0;

        // ---- Swap fee initialization ----
        cfg.min_swap_fee = 50_000; // Default: 0.05 USDC (6 decimals) minimum swap fee
        cfg.swap_fee_bps = 10; // Default: 0.1% of swap output

        // ---- Nullifier set init ----
        nulls.count = 0;

        Ok(())
    }

    pub fn add_merkle_tree(
        ctx: Context<AddMerkleTree>,
        _mint_address: Pubkey,
        tree_id: u16,
    ) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        let payer = &ctx.accounts.payer;

        // Validate payer is either admin or relayer
        require!(
            payer.key() == cfg.admin || cfg.is_relayer(&payer.key()),
            PrivacyError::Unauthorized
        );

        // Validate tree_id is sequential
        require!(tree_id == cfg.num_trees, PrivacyError::InvalidTreeId);

        // Validate max trees not exceeded
        require!(cfg.num_trees < MAX_MERKLE_TREES, PrivacyError::TooManyTrees);

        // Initialize the new tree
        let mut tree = ctx.accounts.note_tree.load_init()?;
        tree.authority = cfg.admin;
        tree.height = MERKLE_TREE_HEIGHT as u8;
        tree.root_history_size = ROOT_HISTORY_SIZE as u16;
        tree.next_index = 0;
        tree.root_index = 0;

        MerkleTree::initialize::<PoseidonHasher>(&mut *tree)?;

        // Update pool config
        cfg.num_trees = cfg
            .num_trees
            .checked_add(1)
            .ok_or(PrivacyError::ArithmeticOverflow)?;

        Ok(())
    }

    pub fn add_relayer(
        ctx: Context<ConfigAdmin>,
        _mint_address: Pubkey,
        new_relayer: Pubkey,
    ) -> Result<()> {
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

    pub fn update_pool_config(
        ctx: Context<UpdatePoolConfig>,
        _mint_address: Pubkey,
        min_deposit_amount: Option<u64>,
        max_deposit_amount: Option<u64>,
        min_withdraw_amount: Option<u64>,
        max_withdraw_amount: Option<u64>,
        fee_bps: Option<u16>,
        min_withdrawal_fee: Option<u64>,
        fee_error_margin_bps: Option<u16>,
        min_swap_fee: Option<u64>,
        swap_fee_bps: Option<u16>,
    ) -> Result<()> {
        let cfg = &mut ctx.accounts.config;

        if let Some(val) = min_deposit_amount {
            cfg.min_deposit_amount = val;
        }
        if let Some(val) = max_deposit_amount {
            cfg.max_deposit_amount = val;
        }
        if let Some(val) = min_withdraw_amount {
            cfg.min_withdraw_amount = val;
        }
        if let Some(val) = max_withdraw_amount {
            cfg.max_withdraw_amount = val;
        }
        if let Some(val) = fee_bps {
            // Validate fee_bps does not exceed 100%
            require!(val <= MAX_FEE_BPS, PrivacyError::ExcessiveFeeBps);
            cfg.fee_bps = val;
        }
        if let Some(val) = min_withdrawal_fee {
            cfg.min_withdrawal_fee = val;
        }
        if let Some(val) = fee_error_margin_bps {
            // Validate fee_error_margin_bps is reasonable (max 50% = 5000 bps)
            require!(val <= 5000, PrivacyError::ExcessiveFeeMargin);
            cfg.fee_error_margin_bps = val;
        }
        if let Some(val) = min_swap_fee {
            cfg.min_swap_fee = val;
        }
        if let Some(val) = swap_fee_bps {
            // Validate swap_fee_bps does not exceed 10% (1000 bps)
            require!(val <= 1000, PrivacyError::ExcessiveFeeBps);
            cfg.swap_fee_bps = val;
        }

        // Validate ranges after updates
        require!(
            cfg.min_deposit_amount <= cfg.max_deposit_amount,
            PrivacyError::InvalidPoolConfigRange
        );
        require!(
            cfg.min_withdraw_amount <= cfg.max_withdraw_amount,
            PrivacyError::InvalidPoolConfigRange
        );

        Ok(())
    }

    pub fn initialize_global_config(ctx: Context<InitializeGlobalConfig>) -> Result<()> {
        // Check authorization
        if let Some(admin_key) = AUTHORIZED_ADMIN {
            require!(
                ctx.accounts.admin.key().eq(&admin_key),
                PrivacyError::UnauthorizedAdmin
            );
        }

        let global_cfg = &mut ctx.accounts.global_config;

        global_cfg.bump = ctx.bumps.global_config;
        global_cfg.admin = ctx.accounts.admin.key();

        Ok(())
    }

    pub fn update_global_config(_ctx: Context<GlobalConfigAdmin>) -> Result<()> {
        // Reserved for future global configuration updates
        // Currently no mutable global settings
        Ok(())
    }

    /// Unified UTXO transaction instruction
    /// Circuit equation: sumIns + publicAmount = sumOuts
    /// Handles deposits (publicAmount > 0), withdrawals (publicAmount < 0), and transfers (publicAmount = 0)
    ///
    /// Cross-tree transactions:
    /// - input_tree_id: Tree containing input notes (for root validation)
    /// - output_tree_id: Tree for new output commitments
    /// - Can be the same tree or different trees
    /// - Allows withdrawals even when input tree is full (outputs go to new tree)
    pub fn transact(
        ctx: Context<Transact>,
        root: [u8; 32],
        input_tree_id: u16,
        output_tree_id: u16,
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

        // Validate both tree IDs are valid
        require!(input_tree_id < cfg.num_trees, PrivacyError::InvalidTreeId);
        require!(output_tree_id < cfg.num_trees, PrivacyError::InvalidTreeId);

        let input_tree = ctx.accounts.input_tree.load()?;

        // For deposits (public_amount > 0), no notes are consumed
        // Nullifier validation is handled by the ZK circuit
        let zero_nullifier = [0u8; 32];
        if public_amount > 0 {
            // Deposits don't consume notes, so we skip nullifier marker validation entirely
            // The ZK circuit ensures the proof is valid with whatever nullifiers it uses
        } else {
            // For withdrawals/transfers, validate no duplicate nullifiers
            require!(
                input_nullifiers[0] != input_nullifiers[1],
                PrivacyError::DuplicateNullifiers
            );

            // Also ensure neither nullifier is zero (must be real notes)
            require!(
                input_nullifiers[0] != zero_nullifier && input_nullifiers[1] != zero_nullifier,
                PrivacyError::ZeroNullifier
            );
        }

        // Validate no duplicate output commitments (prevents creating identical notes)
        require!(
            output_commitments[0] != output_commitments[1],
            PrivacyError::DuplicateCommitments
        );

        // SECURITY: Validate output commitments are not zero
        // Zero commitments could break privacy (trivially identifiable notes)
        // and cause issues with note recovery/indexing
        let zero_commitment = [0u8; 32];
        require!(
            output_commitments[0] != zero_commitment && output_commitments[1] != zero_commitment,
            PrivacyError::ZeroCommitment
        );

        // 1. Verify ext_data_hash matches provided ext_data
        let computed_ext_hash = ext_data.hash()?;
        require!(
            computed_ext_hash == ext_data_hash,
            PrivacyError::InvalidExtData
        );

        // 2. Verify relayer is authorized (only for withdrawals/transfers, not deposits)
        // For deposits (public_amount > 0), anyone can facilitate deposit without being authorized
        // For withdrawals (public_amount < 0) and transfers (public_amount = 0), require authorized relayer
        if public_amount <= 0 {
            // Check if this specific relayer is authorized
            require!(
                cfg.is_relayer(&ctx.accounts.relayer.key()),
                PrivacyError::RelayerNotAllowed
            );
        }

        // 2a. Bind relayer account to ext_data.relayer to prevent fee theft
        // This ensures the relayer submitting the transaction is the one entitled to fees
        require_keys_eq!(
            ctx.accounts.relayer.key(),
            ext_data.relayer,
            PrivacyError::RelayerMismatch
        );

        // 3. Verify recipient matches ext_data
        require_keys_eq!(
            ctx.accounts.recipient.key(),
            ext_data.recipient,
            PrivacyError::RecipientMismatch
        );

        // 4. Verify mint address matches config
        msg!("DEBUG: mint_address param = {}", mint_address);
        msg!("DEBUG: cfg.mint_address   = {}", cfg.mint_address);
        require_keys_eq!(
            mint_address,
            cfg.mint_address,
            PrivacyError::InvalidMintAddress
        );

        // 4a. Validate SPL token is allowed (if not SOL)
        if is_token_mint(&mint_address) {
            require!(
                ALLOW_ALL_SPL_TOKENS || ALLOWED_TOKENS.contains(&mint_address),
                PrivacyError::InvalidMintAddress
            );
        }

        // 4b. Validate token accounts if using SPL tokens
        if is_token_mint(&mint_address) {
            // Verify token program is provided
            require_keys_eq!(
                ctx.accounts.token_program.key(),
                token::ID,
                PrivacyError::MissingTokenProgram
            );

            // Deserialize and validate vault token account
            let vault_token =
                deserialize_token_account(&ctx.accounts.vault_token_account.to_account_info())?;

            // Verify vault_token_account is the canonical ATA
            let expected_vault_ata =
                get_associated_token_address(&ctx.accounts.vault.key(), &cfg.mint_address);
            require_keys_eq!(
                ctx.accounts.vault_token_account.key(),
                expected_vault_ata,
                PrivacyError::VaultTokenAccountNotATA
            );

            // Verify vault token account mint matches config
            require_keys_eq!(
                vault_token.mint,
                cfg.mint_address,
                PrivacyError::InvalidMintAddress
            );

            // Verify vault is the authority
            require_keys_eq!(
                vault_token.owner,
                ctx.accounts.vault.key(),
                PrivacyError::InvalidTokenAuthority
            );

            // For deposits (public_amount > 0), user token account required
            if public_amount > 0 {
                let user_token =
                    deserialize_token_account(&ctx.accounts.user_token_account.to_account_info())?;
                require_keys_eq!(
                    user_token.mint,
                    cfg.mint_address,
                    PrivacyError::InvalidMintAddress
                );

                // For deposits, only the owner can authorize transfers (no delegation)
                require_keys_eq!(
                    user_token.owner,
                    ctx.accounts.relayer.key(),
                    PrivacyError::DepositorTokenAccountMismatch
                );

                // AUDIT-004 fix: Prevent delegation bypass - deposits must use direct ownership
                require!(
                    user_token.delegate.is_none() || user_token.delegated_amount == 0,
                    PrivacyError::InvalidTokenAuthority
                );
            }

            // For withdrawals (public_amount < 0), recipient/relayer token accounts required
            if public_amount < 0 {
                let recipient_token = deserialize_token_account(
                    &ctx.accounts.recipient_token_account.to_account_info(),
                )?;
                let relayer_token = deserialize_token_account(
                    &ctx.accounts.relayer_token_account.to_account_info(),
                )?;

                require_keys_eq!(
                    recipient_token.mint,
                    cfg.mint_address,
                    PrivacyError::InvalidMintAddress
                );
                require_keys_eq!(
                    relayer_token.mint,
                    cfg.mint_address,
                    PrivacyError::InvalidMintAddress
                );

                // This prevents withdrawals to token accounts not controlled by the intended recipient
                require_keys_eq!(
                    recipient_token.owner,
                    ext_data.recipient,
                    PrivacyError::RecipientTokenAccountMismatch
                );

                require_keys_eq!(
                    relayer_token.owner,
                    ext_data.relayer,
                    PrivacyError::RelayerTokenAccountMismatch
                );
            }
        }

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
        // AUDIT-015: ZK verification consumes ~350K CUs (4 pairings + 8 scalar muls)
        // Clients must prepend ComputeBudgetInstruction::SetComputeUnitLimit(500_000)
        // to prevent ComputeBudgetExceeded failures during network congestion
        zk::verify_transaction_groth16(proof, &public_inputs)?;

        // 7. Check root is known in input tree
        require!(
            MerkleTree::is_known_root(&*input_tree, root),
            PrivacyError::UnknownRoot
        );

        drop(input_tree); // Release immutable borrow

        // 8. Mark both input nullifiers as spent (only for withdrawals/transfers)
        // For deposits (public_amount > 0), no notes are consumed so nullifiers shouldn't be marked
        if public_amount <= 0 {
            // Verify marker accounts match the input tree to prevent cross-tree reuse
            require!(
                ctx.accounts.nullifier_marker_0.tree_id == 0
                    || ctx.accounts.nullifier_marker_0.tree_id == input_tree_id,
                PrivacyError::NullifierTreeMismatch
            );
            require!(
                ctx.accounts.nullifier_marker_1.tree_id == 0
                    || ctx.accounts.nullifier_marker_1.tree_id == input_tree_id,
                PrivacyError::NullifierTreeMismatch
            );

            // Check that nullifier markers don't already exist (prevents double-spend)
            require!(
                ctx.accounts.nullifier_marker_0.nullifier == [0u8; 32],
                PrivacyError::NullifierAlreadyUsed
            );
            require!(
                ctx.accounts.nullifier_marker_1.nullifier == [0u8; 32],
                PrivacyError::NullifierAlreadyUsed
            );

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
        }

        // 9. Insert both output commitments into output tree
        let mut output_tree = ctx.accounts.output_tree.load_mut()?;

        // Check if output tree has capacity for 2 new leaves
        let max_capacity = 1u64 << (output_tree.height as u64);
        let remaining_capacity: u64 = max_capacity.saturating_sub(output_tree.next_index);
        require!(remaining_capacity >= 2, PrivacyError::MerkleTreeFull);

        let leaf_index_0 = output_tree.next_index;
        MerkleTree::append::<PoseidonHasher>(output_commitments[0], &mut *output_tree)?;
        let leaf_index_1 = output_tree.next_index;
        MerkleTree::append::<PoseidonHasher>(output_commitments[1], &mut *output_tree)?;
        let new_root = output_tree.root;

        drop(output_tree); // Release mutable borrow

        // Emit commitment events for both outputs
        let timestamp = Clock::get()?.unix_timestamp;
        emit!(CommitmentEvent {
            commitment: output_commitments[0],
            leaf_index: leaf_index_0,
            new_root,
            timestamp,
            mint_address,
            tree_id: output_tree_id,
        });
        emit!(CommitmentEvent {
            commitment: output_commitments[1],
            leaf_index: leaf_index_1,
            new_root,
            timestamp,
            mint_address,
            tree_id: output_tree_id,
        });

        // 10. Handle public amount (deposits/withdrawals)
        handle_public_amount(
            cfg,
            &ctx.accounts.global_config,
            &ctx.accounts.vault,
            &ctx.accounts.recipient,
            &ctx.accounts.relayer,
            &ctx.accounts.system_program,
            public_amount,
            &ext_data,
            &ctx.accounts.vault_token_account,
            &ctx.accounts.user_token_account,
            &ctx.accounts.recipient_token_account,
            &ctx.accounts.relayer_token_account,
            &ctx.accounts.token_program,
        )?;

        Ok(())
    }

    /// Atomic cross-pool private swap
    /// Consumes notes from source pool, swaps via Raydium CPMM (no Serum), creates notes in dest pool
    /// All in one transaction - see swap.rs for implementation details
    pub fn transact_swap<'info>(
        ctx: Context<'_, '_, 'info, 'info, TransactSwap<'info>>,
        proof: zk::SwapProof,
        source_root: [u8; 32],
        source_tree_id: u16,
        source_mint: Pubkey,
        input_nullifier_0: [u8; 32],
        input_nullifier_1: [u8; 32],
        dest_tree_id: u16,
        dest_mint: Pubkey,
        output_commitment_0: [u8; 32],
        output_commitment_1: [u8; 32],
        swap_params: SwapParams,
        swap_amount: u64,
        swap_data: Vec<u8>,
        ext_data: ExtData,
    ) -> Result<()> {
        swap::transact_swap(
            ctx,
            proof,
            source_root,
            source_tree_id,
            source_mint,
            input_nullifier_0,
            input_nullifier_1,
            dest_tree_id,
            dest_mint,
            output_commitment_0,
            output_commitment_1,
            swap_params,
            swap_amount,
            swap_data,
            ext_data,
        )
    }
}

// ---- Helper Functions ----

/// Mark a nullifier as spent (tree-specific to prevent cross-tree reuse)
pub fn mark_nullifier_spent(
    marker: &mut Account<NullifierMarker>,
    nullifier_set: &mut Account<NullifierSet>,
    nullifier: [u8; 32],
    bump: u8,
    mint_address: Pubkey,
    tree_id: u16,
) -> Result<()> {
    let timestamp = Clock::get()?.unix_timestamp;

    marker.nullifier = nullifier;
    marker.timestamp = timestamp;
    marker.withdrawal_index = nullifier_set.count;
    marker.tree_id = tree_id;
    marker.bump = bump;

    nullifier_set.count = nullifier_set
        .count
        .checked_add(1)
        .ok_or(PrivacyError::ArithmeticOverflow)?;

    // Emit event when nullifier is spent
    emit!(NullifierSpent {
        nullifier,
        timestamp,
        mint_address,
        tree_id,
    });

    Ok(())
}

/// Handle lamport/token flows based on public_amount
///
/// Circuit equation: sumIns + publicAmount = sumOuts
/// public_amount > 0: DEPOSIT (user -> vault, funds entering pool)
/// public_amount < 0: WITHDRAWAL (vault -> recipient + relayer, funds leaving pool)
/// public_amount = 0: PRIVATE TRANSFER (no SOL/token crosses pool boundary)
fn handle_public_amount<'info>(
    config: &mut PrivacyConfig,
    _global_config: &GlobalConfig,
    vault: &Account<'info, Vault>,
    recipient: &SystemAccount<'info>,
    relayer: &Signer<'info>,
    system_program: &Program<'info, System>,
    public_amount: i64,
    ext_data: &ExtData,
    vault_token_account: &UncheckedAccount<'info>,
    user_token_account: &UncheckedAccount<'info>,
    recipient_token_account: &UncheckedAccount<'info>,
    relayer_token_account: &UncheckedAccount<'info>,
    token_program: &UncheckedAccount<'info>,
) -> Result<()> {
    // Validate ext_data values are non-negative
    require!(
        ext_data.fee < i64::MAX as u64,
        PrivacyError::InvalidFeeAmount
    );
    require!(
        ext_data.refund < i64::MAX as u64,
        PrivacyError::InvalidPublicAmount
    );

    // Circuit convention: sumIns + publicAmount = sumOuts
    // - Positive publicAmount = DEPOSIT (adding to pool: 0 + amount = outputs)
    // - Negative publicAmount = WITHDRAWAL (removing from pool: inputs + negative = 0)

    // Determine if using SPL tokens or native SOL
    let is_token = is_token_mint(&config.mint_address);

    if public_amount > 0 {
        // DEPOSIT: user deposits public_amount lamports/tokens
        let deposit_amount = public_amount as u64;

        // For deposits, fee and refund should be zero
        require!(
            ext_data.fee == 0 && ext_data.refund == 0,
            PrivacyError::InvalidPublicAmount
        );

        // Check PrivacyConfig pool-specific limits
        require!(
            deposit_amount >= config.min_deposit_amount,
            PrivacyError::DepositBelowMinimum
        );
        require!(
            deposit_amount <= config.max_deposit_amount,
            PrivacyError::DepositLimitExceeded
        );

        if is_token {
            // SPL Token deposit: user -> vault ATA
            token::transfer(
                CpiContext::new(
                    token_program.to_account_info(),
                    token::Transfer {
                        from: user_token_account.to_account_info(),
                        to: vault_token_account.to_account_info(),
                        authority: relayer.to_account_info(),
                    },
                ),
                deposit_amount,
            )?;
        } else {
            // Native SOL deposit
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
        }

        // Update TVL
        config.total_tvl = config
            .total_tvl
            .checked_add(deposit_amount)
            .ok_or(PrivacyError::ArithmeticOverflow)?;
    } else if public_amount < 0 {
        // WITHDRAWAL: vault pays out |public_amount| lamports
        // Use unsigned_abs() to safely handle i64::MIN without overflow
        let withdrawal_amount = public_amount.unsigned_abs();

        // Check PrivacyConfig pool-specific limits
        require!(
            withdrawal_amount >= config.min_withdraw_amount,
            PrivacyError::WithdrawalBelowMinimum
        );
        require!(
            withdrawal_amount <= config.max_withdraw_amount,
            PrivacyError::WithdrawalLimitExceeded
        );

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

        // Fee validation with error margin for timing attack protection
        // Use u128 for intermediate calculation to prevent overflow on large withdrawals
        let max_fee_u128 = (withdrawal_amount as u128)
            .checked_mul(config.fee_bps as u128)
            .ok_or(PrivacyError::ArithmeticOverflow)?
            / 10_000;

        // Ensure the result fits in u64 (should always be true since withdrawal_amount is u64)
        require!(max_fee_u128 <= u64::MAX as u128, PrivacyError::ExcessiveFee);
        let max_fee = max_fee_u128 as u64;

        // Apply fee error margin: allow fees up to max_fee * (1 + margin)
        // This provides flexibility for timing attack resistance while capping maximum fee
        let max_fee_with_margin = max_fee
            .checked_mul(10_000u64.saturating_add(config.fee_error_margin_bps as u64))
            .map(|x| x / 10_000)
            .unwrap_or(max_fee);

        // Ensure withdrawal amount is large enough that max_fee >= min_withdrawal_fee
        // This prevents fee evasion via small withdrawals where truncation would
        // make max_fee < min_withdrawal_fee, creating an impossible fee range
        require!(
            max_fee >= config.min_withdrawal_fee,
            PrivacyError::WithdrawalTooSmallForMinFee
        );

        // 1. Check minimum fee to ensure relayer compensation
        require!(
            fee >= config.min_withdrawal_fee,
            PrivacyError::InsufficientFee
        );

        // 2. Check maximum fee with margin (prevent malicious relayer from overcharging)
        // The margin allows variance for timing attack protection
        require!(fee <= max_fee_with_margin, PrivacyError::ExcessiveFee);

        if is_token {
            // SPL Token withdrawal: vault ATA -> recipient/relayer ATAs
            // Deserialize vault token account to check balance
            let vault_token_data =
                deserialize_token_account(&vault_token_account.to_account_info())?;

            // Check vault has sufficient tokens
            require!(
                vault_token_data.amount >= withdrawal_amount,
                PrivacyError::InsufficientFundsForWithdrawal
            );

            // Transfer to recipient
            token::transfer(
                CpiContext::new_with_signer(
                    token_program.to_account_info(),
                    token::Transfer {
                        from: vault_token_account.to_account_info(),
                        to: recipient_token_account.to_account_info(),
                        authority: vault.to_account_info(),
                    },
                    &[&[
                        b"privacy_vault_v3",
                        config.mint_address.as_ref(),
                        &[vault.bump],
                    ]],
                ),
                to_recipient,
            )?;

            // Transfer fee + refund to relayer
            let to_relayer = fee
                .checked_add(refund)
                .ok_or(PrivacyError::ArithmeticOverflow)?;

            if to_relayer > 0 {
                token::transfer(
                    CpiContext::new_with_signer(
                        token_program.to_account_info(),
                        token::Transfer {
                            from: vault_token_account.to_account_info(),
                            to: relayer_token_account.to_account_info(),
                            authority: vault.to_account_info(),
                        },
                        &[&[
                            b"privacy_vault_v3",
                            config.mint_address.as_ref(),
                            &[vault.bump],
                        ]],
                    ),
                    to_relayer,
                )?;
            }
        } else {
            // Native SOL withdrawal (existing logic)
            let vault_ai = vault.to_account_info();
            let rent = Rent::get()?;
            let rent_exempt_minimum = rent.minimum_balance(vault_ai.data_len());

            // Ensure vault maintains operational buffer above rent exemption
            let total_required = withdrawal_amount
                .checked_add(rent_exempt_minimum)
                .and_then(|x| x.checked_add(1))
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
        }

        // Update TVL
        config.total_tvl = config
            .total_tvl
            .checked_sub(withdrawal_amount)
            .ok_or(PrivacyError::ArithmeticOverflow)?;
    } else {
        // PRIVATE TRANSFER: public_amount == 0, no value crosses pool boundary
        // since no funds move on-chain. This prevents semantic inconsistency
        // between ext_data (committed in proof) and actual on-chain effects.
        require!(
            ext_data.fee == 0 && ext_data.refund == 0,
            PrivacyError::InvalidPrivateTransferFee
        );
    }
    // Note: When public_amount == 0, no lamport/token movement occurs

    Ok(())
}

// ---- Events ----

#[event]
pub struct CommitmentEvent {
    pub commitment: [u8; 32],
    pub leaf_index: u64,
    pub new_root: [u8; 32],
    pub timestamp: i64,
    pub mint_address: Pubkey,
    pub tree_id: u16,
}

#[event]
pub struct NullifierSpent {
    pub nullifier: [u8; 32],
    pub timestamp: i64,
    pub mint_address: Pubkey,
    pub tree_id: u16,
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
    #[msg("Merkle tree is full - use a different tree_id or add a new tree with add_merkle_tree")]
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
    #[msg("Invalid public amount data")]
    InvalidPublicAmount,
    #[msg("Invalid fee amount")]
    InvalidFeeAmount,
    #[msg("Duplicate nullifiers detected")]
    DuplicateNullifiers,
    #[msg("Duplicate output commitments detected")]
    DuplicateCommitments,
    #[msg("Token account required for SPL token operations")]
    MissingTokenAccount,
    #[msg("Token program required for SPL token operations")]
    MissingTokenProgram,
    #[msg("Invalid token account authority")]
    InvalidTokenAuthority,
    #[msg("Relayer account does not match ext_data.relayer")]
    RelayerMismatch,
    #[msg("Relayer token account not owned by ext_data.relayer")]
    RelayerTokenAccountMismatch,
    #[msg("Recipient token account not owned by ext_data.recipient")]
    RecipientTokenAccountMismatch,
    #[msg("Depositor token account not owned/delegated to relayer")]
    DepositorTokenAccountMismatch,
    #[msg("Private transfer (public_amount == 0) must have fee == 0 and refund == 0")]
    InvalidPrivateTransferFee,
    #[msg("Deposit amount below pool minimum")]
    DepositBelowMinimum,
    #[msg("Deposit amount exceeds pool maximum")]
    DepositLimitExceeded,
    #[msg("Withdrawal amount below pool minimum")]
    WithdrawalBelowMinimum,
    #[msg("Withdrawal amount exceeds pool maximum")]
    WithdrawalLimitExceeded,
    #[msg("Invalid PoolConfig range (min > max)")]
    InvalidPoolConfigRange,
    #[msg("Fee basis points exceeds maximum (100 = 1%)")]
    ExcessiveFeeBps,
    #[msg("Fee error margin exceeds maximum (5000 = 50%)")]
    ExcessiveFeeMargin,
    #[msg("Only authorized admin can initialize")]
    UnauthorizedAdmin,
    #[msg("Unauthorized: only admin or relayers can perform this action")]
    Unauthorized,
    #[msg("Invalid tree_id (tree does not exist or exceeds num_trees)")]
    InvalidTreeId,
    #[msg("Maximum number of Merkle trees reached for this pool")]
    TooManyTrees,
    #[msg("Deposits must use zero nullifiers (no notes consumed)")]
    InvalidNullifiersForDeposit,
    #[msg("Nullifier cannot be zero for withdrawals/transfers")]
    ZeroNullifier,
    #[msg("Output commitment cannot be zero")]
    ZeroCommitment,
    #[msg("Token account must be owned by SPL Token Program")]
    InvalidTokenAccountOwner,
    #[msg("Vault token account must be the canonical Associated Token Account")]
    VaultTokenAccountNotATA,
    #[msg("Withdrawal amount too small: max fee based on fee_bps would be less than min_withdrawal_fee")]
    WithdrawalTooSmallForMinFee,
    #[msg("Nullifier marker account does not correspond to zero nullifier for deposits")]
    InvalidNullifierMarkerForDeposit,
    #[msg("Token account delegation amount insufficient for deposit")]
    InsufficientDelegation,
    #[msg("Nullifier marker tree_id mismatch - nullifier already used in different tree")]
    NullifierTreeMismatch,
    #[msg("Invalid swap program: must be Raydium CPMM or AMM")]
    InvalidSwapProgram,
    #[msg("Executor PDA exists and is not stale - cannot reclaim yet")]
    ExecutorNotStale,
    #[msg("Invalid remaining accounts: wrong count or ownership")]
    InvalidRemainingAccounts,
}

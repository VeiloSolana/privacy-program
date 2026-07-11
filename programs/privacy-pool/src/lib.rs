use anchor_lang::prelude::*;
use anchor_spl::associated_token::get_associated_token_address;
use anchor_spl::token::{ self, Mint, Token, TokenAccount };
use light_hasher::Poseidon;

pub mod groth16;
pub mod perps;
pub mod merkle_tree;
pub mod phoenix;
pub mod positions;
pub mod predictions;
pub mod swap;
pub mod vk_constants;
pub mod zk;

pub use phoenix::PHOENIX_PROGRAM_ID;

// Re-export swap types for Anchor
pub use swap::{ SwapExecutor, SwapParams, SwapPublicInputs };
pub use zk::{ SwapProof, TransactionProof };
// Re-export position-pool data structs (defined in positions.rs alongside their handlers)
pub use positions::{
    PositionPoolConfig,
    PositionNullifierMarker,
    PositionVaultRecord,
    PositionPDA,
    SwapLegsBuffer,
};

use merkle_tree::{ MerkleTree, MerkleTreeAccount, MERKLE_TREE_HEIGHT, ROOT_HISTORY_SIZE };

declare_id!("GYy4kM6GHhpgLCUscuABbzkD2ZbJ2fneYryaZ6Ch7fFU");

// Custom bump allocator that uses the FULL heap frame (default Solana allocator caps at 32KB and
// ignores `requestHeapFrame`). The position-open path that runs Jupiter's multi-leg bonding-curve
// route in-program needs more than 32KB; pair this with `ComputeBudgetProgram.requestHeapFrame`
// (up to 256KB) in the transaction. Same bump logic as the SDK default, just a larger length; it
// never frees (fine for single-instruction execution).
#[cfg(target_os = "solana")]
#[global_allocator]
static ALLOC: BumpAllocator = BumpAllocator;

#[cfg(target_os = "solana")]
struct BumpAllocator;

#[cfg(target_os = "solana")]
unsafe impl std::alloc::GlobalAlloc for BumpAllocator {
    // Bump UPWARD from the bottom of the heap (unlike Solana's default which bumps down from the
    // top of a fixed 32KB). Bumping up keeps allocations within whatever physical heap frame the
    // transaction actually requested: instructions on the default 32KB frame stay < 32KB (they
    // allocate little), while the position-open path that requests a 256KB frame can grow up to
    // 256KB. Bumping down from a 256KB top would write past the 32KB frame on normal instructions.
    //
    // INVARIANT: Every instruction that calls ZK verification (verify_transaction_groth16) or
    // processes Jupiter CPI legs MUST prepend ComputeBudgetProgram::requestHeapFrame(262144)
    // to its transaction. Without it the runtime provides only the default 32 KB heap; if
    // allocations exceed that threshold the BPF VM traps with an unmapped-memory fault before
    // `next > HEAP_END` can fire. Client SDKs MUST include this budget instruction — the program
    // cannot enforce it from within alloc().
    #[inline]
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        const HEAP_START: usize = 0x300000000;
        const HEAP_END: usize = HEAP_START + 256 * 1024;
        let pos_ptr = HEAP_START as *mut usize;
        let mut pos = *pos_ptr;
        if pos == 0 {
            pos = HEAP_START + std::mem::size_of::<usize>(); // reserve first word for the cursor
        }
        let align = layout.align();
        pos = pos.wrapping_add(align.wrapping_sub(1)) & !align.wrapping_sub(1);
        let next = pos.wrapping_add(layout.size());
        if next > HEAP_END {
            return std::ptr::null_mut();
        }
        *pos_ptr = next;
        pos as *mut u8
    }
    #[inline]
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: std::alloc::Layout) {}
}

// ---- Constants ----

pub type PoseidonHasher = Poseidon;
pub const MAX_RELAYERS: usize = 16;

/// Maximum number of Merkle trees per pool
/// Multiple trees improve performance through parallelism
/// and reduce congestion on single tree updates
pub const MAX_MERKLE_TREES: u16 = 10000;

/// Maximum withdrawal fee basis points: 500 = 5%
/// Withdrawal fees are kept low to ensure users can always exit the pool affordably
pub const MAX_FEE_BPS: u16 = 500;

/// Maximum swap fee basis points: 1000 = 10%
pub const MAX_SWAP_FEE_BPS: u16 = 1000;

/// Raydium CPMM program ID (mainnet)
pub const RAYDIUM_CPMM_PROGRAM_ID: Pubkey = pubkey!("CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C");

/// Raydium AMM V4 program ID (mainnet)
pub const RAYDIUM_AMM_PROGRAM_ID: Pubkey = pubkey!("675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8");

/// OpenBook (Serum V3) DEX Program ID (mainnet)
/// Used by Raydium AMM V4 for orderbook-based swaps
pub const OPENBOOK_PROGRAM_ID: Pubkey = pubkey!("srmqPvymJeFKQ4zGQed1GFppgkRHL9kaELCbyksJtPX");

/// Jupiter V6 Aggregator Program ID (mainnet)
pub const JUPITER_PROGRAM_ID: Pubkey = pubkey!("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");

/// Pump.fun bonding-curve Program ID (mainnet). No longer used by the position pool (meme trading
/// routes through Jupiter); kept for an easy restore of direct CPI — see docs/pumpfun-direct-cpi.md.
pub const PUMP_FUN_PROGRAM_ID: Pubkey = pubkey!("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P");

/// Jupiter V6 Event Authority (for validation)
pub const JUPITER_EVENT_AUTHORITY: Pubkey = pubkey!("D8cy77BBepLMngZx6ZukaTff5hCt1HrWyKk3Hnd9oitf");

/// Wrapped SOL (NATIVE_MINT) — the SPL token representation of native SOL.
/// Pools registered with Pubkey::default() (native SOL) use this for SPL operations in swaps.
pub const NATIVE_SOL_MINT: Pubkey = pubkey!("So11111111111111111111111111111111111111112");

/// Map a pool's stored mint to its effective SPL mint.
/// Pools that store Pubkey::default() for native SOL use WSOL for any SPL token operations.
pub fn effective_mint(mint: &Pubkey) -> Pubkey {
    if *mint == Pubkey::default() { NATIVE_SOL_MINT } else { *mint }
}

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
    pub const LEN: usize =
        8 + // discriminator
        1 + // bump
        1 + // vault_bump
        32 + // admin
        2 + // fee_bps
        8 + // min_withdrawal_fee
        2 + // fee_error_margin_bps
        8 + // total_tvl
        32 + // mint_address
        8 + // min_deposit_amount
        8 + // max_deposit_amount
        8 + // min_withdraw_amount
        8 + // max_withdraw_amount
        1 + // num_relayers
        32 * MAX_RELAYERS + // relayers
        2 + // num_trees (u16)
        2 + // next_tree_index (u16)
        8 + // min_swap_fee
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

/// Tracks USDC proceeds from `phoenix_ember_unwrap` that have not yet been
/// re-minted as private notes via `phoenix_reissue_notes`.
///
/// Bookkeeping: the relayer can only reissue the exact amount
/// that Phoenix returned. Each `phoenix_ember_unwrap` increments this; each
/// `phoenix_reissue_notes` decrements it by the requested amount.
///
/// Seeds: [b"phoenix_pending_v1", mint_address, claimant, withdrawal_id]
#[account]
pub struct PhoenixPendingReissue {
    pub bump: u8,
    /// Claimant bound to this exit bucket. Mirrors the PhoenixSlot claimant.
    pub claimant_pubkey: Pubkey,
    /// USDC (in token base units) available for reissuance. Zero after full reissue.
    pub amount: u64,
}

impl PhoenixPendingReissue {
    pub const LEN: usize = 8 + 1 + 32 + 8; // 49 bytes
}

/// Per-deposit slot — created when USDC enters Phoenix, consumed across the exit flow.
///
/// Enforces that a single deposit can only withdraw as much as it deposited, and that
/// only the user who made the deposit (holding `claim_key`) can reclaim the proceeds.
///
/// Seeds: [b"phoenix_slot_v1", mint_address, claimant, withdrawal_id]
#[account]
pub struct PhoenixSlot {
    /// Total USDC deposited into Phoenix via this slot (in token base units).
    pub amount: u64,
    /// USDC already queued for withdrawal from Phoenix for this slot.
    /// Invariant enforced at `phoenix_queue_withdraw`: `withdrawn <= amount`.
    pub withdrawn: u64,
    /// Ephemeral keypair public key generated by the user at deposit time.
    /// Must be a signer of the `phoenix_reissue_notes` transaction.
    /// Required as co-signer so only the depositor can claim exit proceeds.
    pub claimant_pubkey: Pubkey,
    pub bump: u8,
}

impl PhoenixSlot {
    pub const LEN: usize = 8 + 8 + 8 + 32 + 1; // 57 bytes
}

/// Persistent executor PDA — the Phoenix Eternal trader wallet for a pool.
///
/// Seeds: [b"phoenix_executor", mint_address]
///
/// All Phoenix and EMBER CPIs are signed by the executor (not the vault).
/// This confines the vault's signing authority to SPL token transfers only.
#[account]
pub struct PhoenixExecutor {
    pub mint_address: Pubkey,
    /// Ephemeral claimant key committed in the ZK proof at deposit time.
    /// Used as a PDA seed so each deposit gets its own isolated executor.
    pub claimant: Pubkey,
    pub bump: u8,
}

impl PhoenixExecutor {
    pub const LEN: usize = 8 + 32 + 32 + 1;
}

/// Executor PDA that signs all Jupiter Perpetuals CPIs as the position owner.
///
/// Seeds: [b"jperp_executor", mint_address, claimant, withdrawal_id]
///
/// `withdrawal_id` makes the executor unique per open, so each position gets its
/// own executor/ATA/Jupiter-position. The user's wallet never appears on-chain as
/// a position owner — only this PDA does.
#[account]
pub struct JupiterPerpExecutor {
    pub mint_address: Pubkey,
    pub claimant: Pubkey,
    pub bump: u8,
}

impl JupiterPerpExecutor {
    pub const LEN: usize = 8 + 32 + 32 + 1; // 73 bytes
}

/// Per-deposit slot for Jupiter Perps — created at `jperp_open_position`,
/// consumed across one or more `jperp_reissue_notes` calls.
///
/// Enforces:
/// 1. Only the holder of `claimant_pubkey` (the ephemeral key committed in the ZK proof)
///    can sign `jperp_reissue_notes`, preventing relayer theft.
///
/// `reissued` is a cumulative audit counter of USDC re-minted across partial reissues.
/// It is NOT an enforced ceiling: a winning position legitimately reissues more than was
/// deposited, and each note minted is fully backed by the real USDC transferred into the
/// vault during reissue (bounded by the executor ATA balance check).
///
/// Seeds: [b"jperp_slot_v1", mint_address, withdrawal_id]
#[account]
pub struct JupiterPerpSlot {
    /// USDC deposited into the perp position via this slot.
    pub amount: u64,
    /// USDC already re-minted as private notes (cumulative across partial reissues).
    pub reissued: u64,
    /// Ephemeral keypair committed in the ZK proof at deposit time.
    pub claimant_pubkey: Pubkey,
    pub bump: u8,
}

impl JupiterPerpSlot {
    pub const LEN: usize = 8 + 8 + 8 + 32 + 1; // 57 bytes
}

/// Per-deposit slot for Jupiter Predictions — created at `prediction_open`,
/// consumed across one or more `prediction_reissue` calls. Mirrors `JupiterPerpSlot`.
///
/// Enforces: only the holder of `claimant_pubkey` (the ephemeral key committed in the
/// ZK proof) can sign `prediction_reissue`, preventing relayer theft. It also pairs every
/// open to its reissue(s) on-chain (via `withdrawal_id` in the seeds) for reconciliation
/// and blocks reissuing against a non-existent open.
///
/// `reissued` is a cumulative audit counter of USDC re-minted across partial reissues —
/// NOT an enforced ceiling, since a winning bet legitimately reissues more than was staked
/// and each note minted is backed by the real USDC transferred into the vault.
///
/// Seeds: [b"prediction_slot_v1", mint_address, withdrawal_id]
#[account]
pub struct PredictionSlot {
    /// USDC staked into the prediction position via this slot.
    pub amount: u64,
    /// USDC already re-minted as private notes (cumulative across partial reissues).
    pub reissued: u64,
    /// Ephemeral keypair committed in the ZK proof at deposit time.
    pub claimant_pubkey: Pubkey,
    pub bump: u8,
}

impl PredictionSlot {
    pub const LEN: usize = 8 + 8 + 8 + 32 + 1; // 57 bytes
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

/// Per-nullifier PDA marker (created when nullifier is spent).
/// The nullifier itself is encoded in the PDA seeds; metadata is emitted via events.
#[account]
pub struct NullifierMarker {
    pub is_spent: bool,
    pub bump: u8,
}

impl NullifierMarker {
    pub const LEN: usize = 8 + 1 + 1; // 10 bytes
}

// ---- Position Pool Accounts ----
// The position-pool data structs (PositionPoolConfig, PositionNullifierMarker, PositionVaultRecord,
// PositionPDA, SwapLegsBuffer) live in positions.rs alongside their handlers (mirroring swap.rs),
// and are re-exported near the top of this file via `pub use positions::{...}`.

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
    /// Ephemeral claim key committed by the depositor at proof-generation time.
    /// By including this field in the Poseidon hash that is verified against the
    /// Groth16 public input `ext_data_hash`, the ZK proof cryptographically binds
    /// the claimant identity — a relayer cannot substitute their own key without
    /// invalidating the proof.  For non-Phoenix flows set to `Pubkey::default()`.
    pub claimant: Pubkey,
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
    #[inline(never)]
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

        let claimant_bytes = Self::reduce_to_field(self.claimant.to_bytes());

        // extDataHash = Poseidon(Poseidon(recipient, relayer), Poseidon(fee, refund), claimant)
        // The claimant field was added to bind the claim key into the Groth16 public input,
        // preventing a malicious relayer from substituting their own key (AUDIT-005).
        let hash1 = PoseidonHasher::hashv(&[&recipient_bytes, &relayer_bytes]).map_err(|_|
            error!(PrivacyError::MerkleHashFailed)
        )?;

        let hash2 = PoseidonHasher::hashv(&[&fee_bytes, &refund_bytes]).map_err(|_|
            error!(PrivacyError::MerkleHashFailed)
        )?;

        let final_hash = PoseidonHasher::hashv(&[&hash1, &hash2, &claimant_bytes]).map_err(|_|
            error!(PrivacyError::MerkleHashFailed)
        )?;

        Ok(final_hash)
    }
}

// ---- Instruction contexts ----

#[derive(Accounts)]
#[instruction(fee_bps: u16, mint_address: Pubkey)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = payer,
        seeds = [b"privacy_config_v3", mint_address.as_ref()],
        bump,
        space = PrivacyConfig::LEN
    )]
    pub config: Account<'info, PrivacyConfig>,

    #[account(
        init,
        payer = payer,
        seeds = [b"privacy_vault_v3", mint_address.as_ref()],
        bump,
        space = Vault::LEN
    )]
    pub vault: Account<'info, Vault>,

    /// Initial tree (tree_id = 0)
    #[account(
        init,
        payer = payer,
        seeds = [b"privacy_note_tree_v3", mint_address.as_ref(), &(0u16).to_le_bytes()],
        bump,
        space = MerkleTreeAccount::LEN
    )]
    pub note_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        init,
        payer = payer,
        seeds = [b"privacy_nullifiers_v3", mint_address.as_ref()],
        bump,
        space = NullifierSet::LEN
    )]
    pub nullifiers: Account<'info, NullifierSet>,

    /// Global protocol config — constrains pool creation to the protocol authority.
    /// The `admin` signer must match `global_config.admin`, ensuring only the
    /// protocol authority (or its Squads delegate) can initialize new pools.
    /// Authority can be rotated on-chain via `update_global_config` without a redeploy.
    #[account(
        seeds = [b"global_config_v1"],
        bump = global_config.bump,
        constraint = admin.key() == global_config.admin @ PrivacyError::Unauthorized
    )]
    pub global_config: Account<'info, GlobalConfig>,

    /// CHECK: Squads vault PDA that becomes the pool admin.
    /// Must equal global_config.admin — enforced by the constraint above.
    pub admin: Signer<'info>,

    /// Transaction fee payer (can be anyone, separate from admin authority)
    #[account(mut)]
    pub payer: Signer<'info>,

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

    /// CHECK: Squads vault PDA (or direct admin).
    /// has_one = admin ensures this matches config.admin.
    /// When using Squads, the vault PDA signs after multisig approval.
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
    #[account(init, payer = payer, seeds = [b"global_config_v1"], bump, space = GlobalConfig::LEN)]
    pub global_config: Account<'info, GlobalConfig>,

    /// CHECK: Squads vault PDA that becomes the global admin.
    /// When using Squads multisig, this should be the vault PDA.
    pub admin: Signer<'info>,

    /// Transaction fee payer (can be anyone, separate from admin authority)
    #[account(mut)]
    pub payer: Signer<'info>,

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

    /// CHECK: Squads vault PDA (or direct admin).
    /// has_one = admin ensures this matches global_config.admin.
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
        payer = relayer,
        seeds = [b"privacy_note_tree_v3", mint_address.as_ref(), &tree_id.to_le_bytes()],
        bump,
        space = MerkleTreeAccount::LEN
    )]
    pub note_tree: AccountLoader<'info, MerkleTreeAccount>,

    /// Relayer who can add trees (must be registered in config.relayers)
    #[account(mut)]
    pub relayer: Signer<'info>,

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

    #[account(seeds = [b"global_config_v1"], bump = global_config.bump)]
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

    /// Nullifier marker for input 0 — single-use, created here and never reusable.
    /// init (not init_if_needed) ensures the transaction fails if this PDA already exists,
    /// which means the nullifier has been seen before (reuse blocked at account resolution).
    /// NOTE: Nullifier markers are global (no tree_id) to prevent cross-tree reuse
    #[account(
        init,
        payer = relayer,
        seeds = [b"nullifier_v3", mint_address.as_ref(), input_nullifier_0.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub nullifier_marker_0: Account<'info, NullifierMarker>,

    /// Nullifier marker for input 1 — single-use, created here and never reusable.
    /// init (not init_if_needed) ensures the transaction fails if this PDA already exists,
    /// which means the nullifier has been seen before (reuse blocked at account resolution).
    /// NOTE: Nullifier markers are global (no tree_id) to prevent cross-tree reuse
    #[account(
        init,
        payer = relayer,
        seeds = [b"nullifier_v3", mint_address.as_ref(), input_nullifier_1.as_ref()],
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
pub fn is_token_mint(mint: &Pubkey) -> bool {
    mint != &Pubkey::default()
}

/// Safely deserialize a token account with owner validation
/// Prevents malicious programs from passing fake token accounts
pub(crate) fn deserialize_token_account(account: &AccountInfo) -> Result<TokenAccount> {
    // Verify account is owned by SPL Token Program
    require_keys_eq!(*account.owner, token::ID, PrivacyError::InvalidTokenAccountOwner);

    let data = account.try_borrow_data()?;
    TokenAccount::try_deserialize(&mut &data[..]).map_err(|_|
        error!(PrivacyError::MissingTokenAccount)
    )
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
    source_tree_id: u16,
    source_mint: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    dest_tree_id: u16,
    dest_mint: Pubkey,
)]
pub struct TransactSwap<'info> {
    // ---- Source Pool (tokens being swapped FROM) ----
    #[account(
        mut,
        seeds = [b"privacy_config_v3", source_mint.as_ref()],
        bump = source_config.bump
    )]
    pub source_config: Box<Account<'info, PrivacyConfig>>,

    #[account(seeds = [b"global_config_v1"], bump = global_config.bump)]
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
    /// NOTE: Nullifier markers are global (no tree_id) to prevent cross-tree reuse
    #[account(
        init,
        payer = relayer,
        seeds = [b"nullifier_v3", source_mint.as_ref(), input_nullifier_0.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub source_nullifier_marker_0: Box<Account<'info, NullifierMarker>>,

    /// Second nullifier marker for source pool
    /// NOTE: Nullifier markers are global (no tree_id) to prevent cross-tree reuse
    #[account(
        init,
        payer = relayer,
        seeds = [b"nullifier_v3", source_mint.as_ref(), input_nullifier_1.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub source_nullifier_marker_1: Box<Account<'info, NullifierMarker>>,

    /// Source vault's token account
    /// For native SOL pools (mint_address == Pubkey::default), this may be unused — pass any mut account.
    /// For SPL pools, must be the canonical ATA of the source vault for the source mint.
    /// CHECK: Validated in handler — for SPL: address == ATA(vault, mint); for native SOL: unused.
    #[account(mut)]
    pub source_vault_token_account: UncheckedAccount<'info>,

    /// Source token mint — for native SOL pools, pass the WSOL (NATIVE_MINT) account.
    /// Must match effective_mint(source_mint) so executor ATAs are created with WSOL.
    #[account(
        address = effective_mint(&source_mint) @ PrivacyError::InvalidMintAddress
    )]
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

    /// Destination vault's token account
    /// For native SOL pools (mint_address == Pubkey::default), may be unused — pass any mut account.
    /// For SPL pools, must be the canonical ATA of the dest vault for the dest mint.
    /// CHECK: Validated in handler — for SPL: address == ATA(vault, mint); for native SOL: unused.
    #[account(mut)]
    pub dest_vault_token_account: UncheckedAccount<'info>,

    /// Destination token mint — for native SOL pools, pass the WSOL (NATIVE_MINT) account.
    /// Must match effective_mint(dest_mint) so executor ATAs are created with WSOL.
    #[account(
        address = effective_mint(&dest_mint) @ PrivacyError::InvalidMintAddress
    )]
    pub dest_mint_account: Box<Account<'info, Mint>>,

    // ---- Ephemeral Swap Executor PDA ----
    /// Executor PDA - holds tokens during swap
    /// Seeds include source_mint, dest_mint, nullifier, AND relayer key to prevent front-running DoS
    /// Uses init_if_needed: for native SOL swaps the executor is pre-created by fund_native_source.
    #[account(
        init_if_needed,
        payer = relayer,
        seeds = [
            b"swap_executor",
            source_mint.as_ref(),
            dest_mint.as_ref(),
            input_nullifier_0.as_ref(),
            relayer.key().as_ref(),
        ],
        bump,
        space = SwapExecutor::LEN
    )]
    pub executor: Box<Account<'info, SwapExecutor>>,

    /// Executor's source token account (receives from source vault)
    /// Uses init_if_needed: pre-created by fund_native_source for native SOL swaps.
    #[account(
        init_if_needed,
        payer = relayer,
        associated_token::mint = source_mint_account,
        associated_token::authority = executor
    )]
    pub executor_source_token: Box<Account<'info, TokenAccount>>,

    /// Executor's destination token account (receives swapped tokens)
    #[account(
        init_if_needed,
        payer = relayer,
        associated_token::mint = dest_mint_account,
        associated_token::authority = executor
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

    // ---- Jupiter Integration ----
    /// Jupiter Event Authority (required for Jupiter V6 swaps)
    /// CHECK: Validated in handler if Jupiter swap is detected
    pub jupiter_event_authority: UncheckedAccount<'info>,

    // ---- Programs ----
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub associated_token_program: Program<'info, anchor_spl::associated_token::AssociatedToken>,
}

/// Option B: fund_native_source instruction context.
///
/// First instruction of an atomic pair for native SOL swaps.
/// Creates the executor PDA + WSOL ATA and transfers swap_amount from vault.
/// Must be sent in the same transaction as `transact_swap`.
#[derive(Accounts)]
#[instruction(source_mint: Pubkey, dest_mint: Pubkey, input_nullifier_0: [u8; 32], swap_amount: u64)]
pub struct FundNativeSource<'info> {
    /// Executor PDA — created here, validated in the following transact_swap instruction.
    #[account(
        init,
        payer = relayer,
        seeds = [
            b"swap_executor",
            source_mint.as_ref(),
            dest_mint.as_ref(),
            input_nullifier_0.as_ref(),
            relayer.key().as_ref(),
        ],
        bump,
        space = SwapExecutor::LEN
    )]
    pub executor: Box<Account<'info, SwapExecutor>>,

    /// Executor's WSOL ATA — created here, funded with swap_amount from source vault.
    /// This is executor_source_token for the following transact_swap instruction.
    #[account(
        init,
        payer = relayer,
        associated_token::mint = source_mint_account,
        associated_token::authority = executor
    )]
    pub executor_source_token: Box<Account<'info, TokenAccount>>,

    /// Source vault PDA (native SOL pool — program-owned, stores raw lamports).
    #[account(
        mut,
        seeds = [b"privacy_vault_v3", source_mint.as_ref()],
        bump = source_config.vault_bump
    )]
    pub source_vault: Box<Account<'info, Vault>>,

    /// Source pool config — checked for vault_bump and relayer authorisation.
    #[account(seeds = [b"privacy_config_v3", source_mint.as_ref()], bump = source_config.bump)]
    pub source_config: Box<Account<'info, PrivacyConfig>>,

    /// WSOL mint (So111…1112) — required for executor_source_token ATA constraint.
    /// Must equal effective_mint(source_mint), i.e., source_mint must be native SOL.
    #[account(address = effective_mint(&source_mint) @ PrivacyError::InvalidMintAddress)]
    pub source_mint_account: Box<Account<'info, Mint>>,

    /// Relayer — pays rent for created accounts, must be whitelisted in source pool.
    #[account(mut)]
    pub relayer: Signer<'info>,

    /// CHECK: Instructions sysvar — used to verify this instruction is paired
    /// with a `transact_swap` call in the same transaction; a standalone call
    /// is rejected.
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID @ PrivacyError::Unauthorized)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub associated_token_program: Program<'info, anchor_spl::associated_token::AssociatedToken>,
}

// ---- Position Pool Account Contexts ----

#[derive(Accounts)]
#[instruction(source_mint: Pubkey)]
pub struct FundNativeOpenPosition<'info> {
    /// CHECK: validated by the immediately-following open_position (pairing guard + atomic rollback).
    #[account(mut)]
    pub executor: UncheckedAccount<'info>,

    /// Executor's WSOL ATA — created and funded for AMM routes (to_executor_native=false).
    #[account(
        init,
        payer = relayer,
        associated_token::mint = source_mint_account,
        associated_token::authority = executor
    )]
    pub executor_source_token: Box<Account<'info, TokenAccount>>,

    #[account(mut, seeds = [b"privacy_vault_v3", source_mint.as_ref()], bump = source_config.vault_bump)]
    pub source_vault: Box<Account<'info, Vault>>,

    #[account(seeds = [b"privacy_config_v3", source_mint.as_ref()], bump = source_config.bump)]
    pub source_config: Box<Account<'info, PrivacyConfig>>,

    #[account(address = effective_mint(&source_mint) @ PrivacyError::InvalidMintAddress)]
    pub source_mint_account: Box<Account<'info, Mint>>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// CHECK: Instructions sysvar for the pairing guard.
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID @ PrivacyError::Unauthorized)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub associated_token_program: Program<'info, anchor_spl::associated_token::AssociatedToken>,
}

#[derive(Accounts)]
#[instruction(input_nullifier_0: [u8; 32], legs: Vec<u8>)]
pub struct StageSwapLegs<'info> {
    #[account(
        init,
        payer = relayer,
        seeds = [b"swap_legs_v1", input_nullifier_0.as_ref()],
        bump,
        space = 8 + 1 + 32 + 32 + 4 + legs.len()
    )]
    pub buffer: Box<Account<'info, SwapLegsBuffer>>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(input_nullifier_0: [u8; 32])]
pub struct CloseSwapLegs<'info> {
    #[account(
        mut,
        close = relayer,
        seeds = [b"swap_legs_v1", input_nullifier_0.as_ref()],
        bump = buffer.bump,
        has_one = owner @ PrivacyError::Unauthorized,
    )]
    pub buffer: Box<Account<'info, SwapLegsBuffer>>,

    /// CHECK: must equal the relayer that staged the buffer (enforced by has_one = owner).
    pub owner: UncheckedAccount<'info>,

    #[account(mut, address = owner.key() @ PrivacyError::Unauthorized)]
    pub relayer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitPositionPool<'info> {
    #[account(
        init,
        payer = payer,
        seeds = [b"position_config_v1"],
        bump,
        space = PositionPoolConfig::LEN
    )]
    pub config: Box<Account<'info, PositionPoolConfig>>,

    /// Initial position Merkle tree (tree_id = 0)
    #[account(
        init,
        payer = payer,
        seeds = [b"position_tree_v1", (0u16).to_le_bytes().as_ref()],
        bump,
        space = MerkleTreeAccount::LEN
    )]
    pub tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        seeds = [b"global_config_v1"],
        bump = global_config.bump,
        constraint = admin.key() == global_config.admin @ PrivacyError::Unauthorized
    )]
    pub global_config: Box<Account<'info, GlobalConfig>>,

    #[account(constraint = admin.key() == global_config.admin @ PrivacyError::Unauthorized)]
    pub admin: Signer<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct PositionPoolAdmin<'info> {
    #[account(
        mut,
        seeds = [b"position_config_v1"],
        bump = config.bump,
        has_one = authority
    )]
    pub config: Box<Account<'info, PositionPoolConfig>>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(
    source_tree_id: u16,
    source_mint: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    position_tree_id: u16,
    dest_mint: Pubkey,
    position_pda_key: [u8; 32],
)]
pub struct OpenPosition<'info> {
    // ---- Source Pool (USDC or other privacy pool) ----
    #[account(
        mut,
        seeds = [b"privacy_config_v3", source_mint.as_ref()],
        bump = source_config.bump,
    )]
    pub source_config: Box<Account<'info, PrivacyConfig>>,

    #[account(seeds = [b"global_config_v1"], bump = global_config.bump)]
    pub global_config: Box<Account<'info, GlobalConfig>>,

    #[account(
        mut,
        seeds = [b"privacy_vault_v3", source_mint.as_ref()],
        bump = source_config.vault_bump,
    )]
    pub source_vault: Box<Account<'info, Vault>>,

    #[account(
        mut,
        seeds = [b"privacy_note_tree_v3", source_mint.as_ref(), &source_tree_id.to_le_bytes()],
        bump,
    )]
    pub source_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        mut,
        seeds = [b"privacy_nullifiers_v3", source_mint.as_ref()],
        bump = source_nullifiers.bump,
    )]
    pub source_nullifiers: Box<Account<'info, NullifierSet>>,

    #[account(
        init,
        payer = relayer,
        seeds = [b"nullifier_v3", source_mint.as_ref(), input_nullifier_0.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub source_nullifier_marker_0: Box<Account<'info, NullifierMarker>>,

    #[account(
        init,
        payer = relayer,
        seeds = [b"nullifier_v3", source_mint.as_ref(), input_nullifier_1.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub source_nullifier_marker_1: Box<Account<'info, NullifierMarker>>,

    /// CHECK: Validated in handler — canonical ATA of source_vault for source_mint
    #[account(mut)]
    pub source_vault_token_account: UncheckedAccount<'info>,

    /// Source mint account (USDC) — for executor ATA creation
    #[account(address = effective_mint(&source_mint) @ PrivacyError::InvalidMintAddress)]
    pub source_mint_account: Box<Account<'info, Mint>>,

    // ---- Position Pool ----
    #[account(seeds = [b"position_config_v1"], bump = position_config.bump)]
    pub position_config: Box<Account<'info, PositionPoolConfig>>,

    #[account(
        mut,
        seeds = [b"position_tree_v1", &position_tree_id.to_le_bytes()],
        bump,
    )]
    pub position_tree: AccountLoader<'info, MerkleTreeAccount>,

    /// Per-mint vault record — lazy-created on first deposit of this mint
    #[account(
        init_if_needed,
        payer = relayer,
        seeds = [b"position_vault_v1", dest_mint.as_ref()],
        bump,
        space = PositionVaultRecord::LEN
    )]
    pub position_vault_record: Box<Account<'info, PositionVaultRecord>>,

    /// CHECK: PDA authority for position_vault_ata, derived from seeds
    #[account(seeds = [b"position_vault_token_v1", dest_mint.as_ref()], bump)]
    pub position_vault_pda: UncheckedAccount<'info>,

    /// CHECK: Token (or Token-2022) ATA owned by position_vault_pda — created lazily in handler
    #[account(mut)]
    pub position_vault_ata: UncheckedAccount<'info>,

    /// Per-position PDA keyed by poseidon(position_secret_n)
    #[account(
        init,
        payer = relayer,
        seeds = [b"position_pda_v1", position_pda_key.as_ref()],
        bump,
        space = PositionPDA::LEN
    )]
    pub position_pda: Box<Account<'info, PositionPDA>>,

    // ---- Ephemeral Swap Executor (system-owned PDA) ----
    /// System-owned executor PDA — signs swap CPIs and holds native SOL for DEX protocol fees
    /// (e.g. Pump.fun pays its fee via system transfer from the signer, which a data-carrying
    /// account is forbidden to do). Carries no Anchor data; validated by seeds only.
    /// CHECK: address-checked via seeds; no data.
    #[account(
        mut,
        seeds = [
            b"position_executor",
            source_mint.as_ref(),
            dest_mint.as_ref(),
            input_nullifier_0.as_ref(),
            relayer.key().as_ref(),
        ],
        bump,
    )]
    pub executor: UncheckedAccount<'info>,

    /// Executor's source token ATA (USDC — always legacy SPL)
    #[account(
        init_if_needed,
        payer = relayer,
        associated_token::mint = source_mint_account,
        associated_token::authority = executor
    )]
    pub executor_source_token: Box<Account<'info, TokenAccount>>,

    /// CHECK: Executor's dest token ATA (Token or Token-2022) — created in handler
    #[account(mut)]
    pub executor_dest_token: UncheckedAccount<'info>,

    // ---- Mints ----
    /// CHECK: Dest mint account — used to detect Token-2022 vs legacy SPL
    pub dest_mint_info: UncheckedAccount<'info>,

    // ---- Participants ----
    #[account(mut)]
    pub relayer: Signer<'info>,

    /// CHECK: Relayer's token account for swap fee (dest token — checked in handler)
    #[account(mut)]
    pub relayer_dest_token: UncheckedAccount<'info>,

    // ---- Swap Program ----
    /// CHECK: must be the Jupiter program (validated in handler).
    pub swap_program: UncheckedAccount<'info>,

    /// CHECK: Jupiter event authority (for Jupiter V6 swaps)
    pub jupiter_event_authority: UncheckedAccount<'info>,

    // ---- Programs ----
    pub token_program: Program<'info, Token>,
    /// CHECK: address-constrained to the canonical Token-2022 program.
    #[account(address = crate::positions::TOKEN_2022_PROGRAM_ID @ PrivacyError::MissingTokenProgram)]
    pub token_2022_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
    pub associated_token_program: Program<'info, anchor_spl::associated_token::AssociatedToken>,
}

#[derive(Accounts)]
#[instruction(
    position_tree_id: u16,
    source_mint: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    usdc_tree_id: u16,
    dest_mint: Pubkey,
    position_pda_key: [u8; 32],
)]
pub struct ClosePosition<'info> {
    // ---- Position Pool (Source) ----
    #[account(seeds = [b"position_config_v1"], bump = position_config.bump)]
    pub position_config: Box<Account<'info, PositionPoolConfig>>,

    #[account(
        mut,
        seeds = [b"position_tree_v1", &position_tree_id.to_le_bytes()],
        bump,
    )]
    pub position_tree: AccountLoader<'info, MerkleTreeAccount>,

    /// PositionPDA — closed at end of instruction; rent returned to relayer
    #[account(
        mut,
        seeds = [b"position_pda_v1", position_pda_key.as_ref()],
        bump = position_pda.bump,
        close = relayer,
    )]
    pub position_pda: Box<Account<'info, PositionPDA>>,

    #[account(
        init,
        payer = relayer,
        seeds = [b"position_nullifier_v1", source_mint.as_ref(), input_nullifier_0.as_ref()],
        bump,
        space = PositionNullifierMarker::LEN
    )]
    pub position_nullifier_marker_0: Box<Account<'info, PositionNullifierMarker>>,

    #[account(
        init,
        payer = relayer,
        seeds = [b"position_nullifier_v1", source_mint.as_ref(), input_nullifier_1.as_ref()],
        bump,
        space = PositionNullifierMarker::LEN
    )]
    pub position_nullifier_marker_1: Box<Account<'info, PositionNullifierMarker>>,

    #[account(
        mut,
        seeds = [b"position_vault_v1", source_mint.as_ref()],
        bump = position_vault_record.bump,
    )]
    pub position_vault_record: Box<Account<'info, PositionVaultRecord>>,

    /// CHECK: PDA authority for position_vault_ata
    #[account(seeds = [b"position_vault_token_v1", source_mint.as_ref()], bump)]
    pub position_vault_pda: UncheckedAccount<'info>,

    /// CHECK: Token/Token-2022 ATA owned by position_vault_pda
    #[account(mut)]
    pub position_vault_ata: UncheckedAccount<'info>,

    // ---- USDC Pool (Dest) ----
    #[account(
        mut,
        seeds = [b"privacy_config_v3", dest_mint.as_ref()],
        bump = usdc_config.bump,
    )]
    pub usdc_config: Box<Account<'info, PrivacyConfig>>,

    #[account(
        mut,
        seeds = [b"privacy_vault_v3", dest_mint.as_ref()],
        bump = usdc_config.vault_bump,
    )]
    pub usdc_vault: Box<Account<'info, Vault>>,

    #[account(
        mut,
        seeds = [b"privacy_note_tree_v3", dest_mint.as_ref(), &usdc_tree_id.to_le_bytes()],
        bump,
    )]
    pub usdc_tree: AccountLoader<'info, MerkleTreeAccount>,

    /// CHECK: Canonical ATA of usdc_vault for dest_mint (USDC)
    #[account(mut)]
    pub usdc_vault_token_account: UncheckedAccount<'info>,

    /// USDC mint — for executor dest ATA creation
    #[account(address = effective_mint(&dest_mint) @ PrivacyError::InvalidMintAddress)]
    pub usdc_mint_account: Box<Account<'info, Mint>>,

    // ---- Ephemeral Swap Executor (system-owned PDA) ----
    /// System-owned executor PDA — signs swap CPIs and holds native SOL for DEX protocol fees
    /// (e.g. Pump.fun). Carries no Anchor data; validated by seeds only.
    /// CHECK: address-checked via seeds; no data.
    #[account(
        mut,
        seeds = [
            b"position_executor",
            source_mint.as_ref(),
            dest_mint.as_ref(),
            input_nullifier_0.as_ref(),
            relayer.key().as_ref(),
        ],
        bump,
    )]
    pub executor: UncheckedAccount<'info>,

    /// CHECK: Executor's source token ATA (Token or Token-2022) — created in handler
    #[account(mut)]
    pub executor_source_token: UncheckedAccount<'info>,

    /// Executor's USDC token account (always legacy SPL)
    #[account(
        init_if_needed,
        payer = relayer,
        associated_token::mint = usdc_mint_account,
        associated_token::authority = executor
    )]
    pub executor_dest_token: Box<Account<'info, TokenAccount>>,

    // ---- Mints ----
    /// CHECK: Source mint account — used to detect Token-2022 vs legacy SPL
    pub source_mint_info: UncheckedAccount<'info>,

    // ---- Participants ----
    /// Ephemeral key committed in the open_position ZK proof via ext_data.claimant.
    /// Must sign to prove ownership — prevents a malicious relayer from closing a
    /// victim's PositionPDA using a proof generated for a different position.
    pub claimant: Signer<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Relayer's USDC token account for swap fee
    #[account(mut)]
    pub relayer_usdc_token: Box<Account<'info, TokenAccount>>,

    // ---- Swap Program ----
    /// CHECK: must be the Jupiter program (validated in handler).
    pub swap_program: UncheckedAccount<'info>,

    /// CHECK: Jupiter event authority (for Jupiter V6 swaps)
    pub jupiter_event_authority: UncheckedAccount<'info>,

    // ---- Programs ----
    pub token_program: Program<'info, Token>,
    /// CHECK: address-constrained to the canonical Token-2022 program.
    #[account(address = crate::positions::TOKEN_2022_PROGRAM_ID @ PrivacyError::MissingTokenProgram)]
    pub token_2022_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
    pub associated_token_program: Program<'info, anchor_spl::associated_token::AssociatedToken>,
}

// ---- Close Position To SOL Account Context ----

/// Close a position MEME→SOL via Jupiter (staged-legs cosigner sell) then deposit the SOL into the
/// SOL privacy pool. Symmetric with the SOL→MEME open. dest_mint = SOL sentinel.
#[derive(Accounts)]
#[instruction(
    position_tree_id: u16,
    source_mint: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    sol_tree_id: u16,
    dest_mint: Pubkey,
    position_pda_key: [u8; 32],
)]
pub struct ClosePositionToSol<'info> {
    // ---- Position Pool (Source) ----
    #[account(seeds = [b"position_config_v1"], bump = position_config.bump)]
    pub position_config: Box<Account<'info, PositionPoolConfig>>,

    #[account(mut, seeds = [b"position_tree_v1", &position_tree_id.to_le_bytes()], bump)]
    pub position_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        mut,
        seeds = [b"position_pda_v1", position_pda_key.as_ref()],
        bump = position_pda.bump,
        close = relayer,
    )]
    pub position_pda: Box<Account<'info, PositionPDA>>,

    #[account(
        init,
        payer = relayer,
        seeds = [b"position_nullifier_v1", source_mint.as_ref(), input_nullifier_0.as_ref()],
        bump,
        space = PositionNullifierMarker::LEN
    )]
    pub position_nullifier_marker_0: Box<Account<'info, PositionNullifierMarker>>,

    #[account(
        init,
        payer = relayer,
        seeds = [b"position_nullifier_v1", source_mint.as_ref(), input_nullifier_1.as_ref()],
        bump,
        space = PositionNullifierMarker::LEN
    )]
    pub position_nullifier_marker_1: Box<Account<'info, PositionNullifierMarker>>,

    #[account(mut, seeds = [b"position_vault_v1", source_mint.as_ref()], bump = position_vault_record.bump)]
    pub position_vault_record: Box<Account<'info, PositionVaultRecord>>,

    /// CHECK: PDA authority for position_vault_ata
    #[account(seeds = [b"position_vault_token_v1", source_mint.as_ref()], bump)]
    pub position_vault_pda: UncheckedAccount<'info>,

    /// CHECK: Token/Token-2022 ATA owned by position_vault_pda
    #[account(mut)]
    pub position_vault_ata: UncheckedAccount<'info>,

    // ---- SOL Pool (Dest) ----
    #[account(mut, seeds = [b"privacy_config_v3", dest_mint.as_ref()], bump = sol_config.bump)]
    pub sol_config: Box<Account<'info, PrivacyConfig>>,

    #[account(mut, seeds = [b"privacy_vault_v3", dest_mint.as_ref()], bump = sol_config.vault_bump)]
    pub sol_vault: Box<Account<'info, Vault>>,

    #[account(mut, seeds = [b"privacy_note_tree_v3", dest_mint.as_ref(), &sol_tree_id.to_le_bytes()], bump)]
    pub sol_tree: AccountLoader<'info, MerkleTreeAccount>,

    // ---- Ephemeral Swap Executor (system-owned PDA) ----
    /// System-owned executor PDA — funds the cosigner and holds the position's MEME ATA for the sell.
    /// CHECK: address-checked via seeds; no data.
    #[account(
        mut,
        seeds = [
            b"position_executor",
            source_mint.as_ref(),
            dest_mint.as_ref(),
            input_nullifier_0.as_ref(),
            relayer.key().as_ref(),
        ],
        bump,
    )]
    pub executor: UncheckedAccount<'info>,

    /// CHECK: Executor's MEME ATA (Token-2022) — created in handler; source of the sell.
    #[account(mut)]
    pub executor_source_token: UncheckedAccount<'info>,

    // ---- Mints ----
    /// CHECK: Source (meme) mint — used to detect Token-2022 vs legacy SPL.
    pub source_mint_info: UncheckedAccount<'info>,

    // ---- Participants ----
    /// Ephemeral key committed in the open_position ZK proof via ext_data.claimant.
    /// Must sign to prove ownership — prevents a malicious relayer from closing a
    /// victim's PositionPDA using a proof generated for a different position.
    pub claimant: Signer<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    // ---- Swap Program ----
    /// CHECK: must be the Jupiter program (validated in handler).
    pub swap_program: UncheckedAccount<'info>,

    /// CHECK: Jupiter event authority (unused on the staged-legs path; kept for the execute_dex_swap signature).
    pub jupiter_event_authority: UncheckedAccount<'info>,

    // ---- Programs ----
    pub token_program: Program<'info, Token>,
    /// CHECK: address-constrained to the canonical Token-2022 program.
    #[account(address = crate::positions::TOKEN_2022_PROGRAM_ID @ PrivacyError::MissingTokenProgram)]
    pub token_2022_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
    pub associated_token_program: Program<'info, anchor_spl::associated_token::AssociatedToken>,
}

// ---- Merge Positions Account Context ----

/// Merge two position notes of the same mint into one.
///
/// Uses the existing transaction circuit with publicAmount=0: both inputs are
/// real position notes; output[0] is the merged note; output[1] is the zero
/// change note. No vault token movement occurs — only Merkle tree updates.
///
/// Seeds for nullifiers: [b"position_nullifier_v1", mint, nullifier]
#[derive(Accounts)]
#[instruction(
    input_tree_id: u16,
    mint: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    output_tree_id: u16,
    position_pda_key_0: [u8; 32],
    position_pda_key_1: [u8; 32],
    new_position_pda_key: [u8; 32],
)]
pub struct MergePositions<'info> {
    #[account(seeds = [b"position_config_v1"], bump = position_config.bump)]
    pub position_config: Box<Account<'info, PositionPoolConfig>>,

    /// Input tree — validated against the provided position_root
    #[account(seeds = [b"position_tree_v1", &input_tree_id.to_le_bytes()], bump)]
    pub input_tree: AccountLoader<'info, MerkleTreeAccount>,

    /// Output tree — receives both merged output commitments
    #[account(
        mut,
        seeds = [b"position_tree_v1", &output_tree_id.to_le_bytes()],
        bump,
    )]
    pub output_tree: AccountLoader<'info, MerkleTreeAccount>,

    /// First input PositionPDA — closed at end, rent → relayer.
    #[account(
        mut,
        seeds = [b"position_pda_v1", position_pda_key_0.as_ref()],
        bump = position_pda_0.bump,
        has_one = claimant @ PrivacyError::Unauthorized,
        close = relayer,
    )]
    pub position_pda_0: Box<Account<'info, PositionPDA>>,

    /// Second input PositionPDA — closed at end, rent → relayer.
    /// has_one = claimant: both input positions are owned by the co-signing claimant.
    #[account(
        mut,
        seeds = [b"position_pda_v1", position_pda_key_1.as_ref()],
        bump = position_pda_1.bump,
        has_one = claimant @ PrivacyError::Unauthorized,
        close = relayer,
    )]
    pub position_pda_1: Box<Account<'info, PositionPDA>>,

    /// Merged output PositionPDA — created here
    #[account(
        init,
        payer = relayer,
        seeds = [b"position_pda_v1", new_position_pda_key.as_ref()],
        bump,
        space = PositionPDA::LEN
    )]
    pub new_position_pda: Box<Account<'info, PositionPDA>>,

    #[account(
        init,
        payer = relayer,
        seeds = [b"position_nullifier_v1", mint.as_ref(), input_nullifier_0.as_ref()],
        bump,
        space = PositionNullifierMarker::LEN
    )]
    pub position_nullifier_marker_0: Box<Account<'info, PositionNullifierMarker>>,

    #[account(
        init,
        payer = relayer,
        seeds = [b"position_nullifier_v1", mint.as_ref(), input_nullifier_1.as_ref()],
        bump,
        space = PositionNullifierMarker::LEN
    )]
    pub position_nullifier_marker_1: Box<Account<'info, PositionNullifierMarker>>,

    /// Per-mint vault record — position_count decremented by net 1
    #[account(
        mut,
        seeds = [b"position_vault_v1", mint.as_ref()],
        bump = position_vault_record.bump,
    )]
    pub position_vault_record: Box<Account<'info, PositionVaultRecord>>,

    /// Must co-sign to prove ownership of both input PositionPDAs.
    pub claimant: Signer<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

// ---- Phoenix Integration Account Contexts ----

/// ZK-verified USDC note withdrawal → Phoenix Eternal `depositFunds` CPI.
/// Phoenix-specific accounts are supplied via `remaining_accounts` (see `phoenix.rs`).
#[derive(Accounts)]
#[instruction(
    root: [u8; 32],
    input_tree_id: u16,
    output_tree_id: u16,
    deposit_amount: u64,
    ext_data_hash: [u8; 32],
    mint_address: Pubkey,
    claimant: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    output_commitment_0: [u8; 32],
    output_commitment_1: [u8; 32],
    withdrawal_id: [u8; 32],
)]
pub struct PhoenixDepositFromPool<'info> {
    #[account(
        mut,
        seeds = [b"privacy_config_v3", mint_address.as_ref()],
        bump = config.bump
    )]
    pub config: Box<Account<'info, PrivacyConfig>>,

    #[account(seeds = [b"global_config_v1"], bump = global_config.bump)]
    pub global_config: Box<Account<'info, GlobalConfig>>,

    #[account(
        mut,
        seeds = [b"privacy_vault_v3", mint_address.as_ref()],
        bump = config.vault_bump
    )]
    pub vault: Box<Account<'info, Vault>>,

    #[account(
        mut,
        seeds = [b"privacy_note_tree_v3", mint_address.as_ref(), &input_tree_id.to_le_bytes()],
        bump
    )]
    pub input_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        mut,
        seeds = [b"privacy_note_tree_v3", mint_address.as_ref(), &output_tree_id.to_le_bytes()],
        bump
    )]
    pub output_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        mut,
        seeds = [b"privacy_nullifiers_v3", mint_address.as_ref()],
        bump = nullifiers.bump
    )]
    pub nullifiers: Box<Account<'info, NullifierSet>>,

    #[account(
        init,
        payer = relayer,
        seeds = [b"nullifier_v3", mint_address.as_ref(), input_nullifier_0.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub nullifier_marker_0: Box<Account<'info, NullifierMarker>>,

    #[account(
        init,
        payer = relayer,
        seeds = [b"nullifier_v3", mint_address.as_ref(), input_nullifier_1.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub nullifier_marker_1: Box<Account<'info, NullifierMarker>>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Vault's USDC ATA — source of funds; vault SPL-transfers to executor first.
    /// CHECK: Must be the canonical ATA of the vault for `mint_address`; validated in handler.
    #[account(mut)]
    pub vault_token_account: UncheckedAccount<'info>,

    /// Executor PDA — signs all EMBER and Phoenix CPIs on behalf of the pool.
    /// CHECK: Validated as seeds=[b"phoenix_executor", mint_address, claimant]; address only.
    #[account(seeds = [b"phoenix_executor", mint_address.as_ref(), claimant.as_ref()], bump)]
    pub executor: UncheckedAccount<'info>,

    /// Executor's USDC ATA — receives USDC from vault; EMBER pulls from here.
    /// CHECK: Validated as ATA(executor, mint_address) in handler.
    #[account(mut)]
    pub executor_token_account: UncheckedAccount<'info>,

    /// Relayer's USDC ATA — receives the relayer fee.
    /// CHECK: Must be owned by `ext_data.relayer`; validated in handler.
    #[account(mut)]
    pub relayer_token_account: UncheckedAccount<'info>,

    /// Per-deposit slot — created here and consumed across the exit flow.
    /// Caps per-user withdrawals and records the claim key for anti-theft protection.
    #[account(
        init,
        payer = relayer,
        seeds = [
            b"phoenix_slot_v1",
            mint_address.as_ref(),
            claimant.as_ref(),
            withdrawal_id.as_ref(),
        ],
        bump,
        space = PhoenixSlot::LEN
    )]
    pub phoenix_slot: Box<Account<'info, PhoenixSlot>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    // Phoenix accounts supplied via remaining_accounts — see phoenix::phoenix_deposit_from_pool
}

/// Relayer-submitted order placement on Phoenix using the executor's trader account.
/// Phoenix accounts supplied via remaining_accounts.
#[derive(Accounts)]
#[instruction(mint_address: Pubkey, claimant: Pubkey)]
pub struct PhoenixPlaceOrder<'info> {
    #[account(seeds = [b"privacy_config_v3", mint_address.as_ref()], bump = config.bump)]
    pub config: Box<Account<'info, PrivacyConfig>>,

    /// Executor PDA — signs the Phoenix CPI.
    /// CHECK: Validated as seeds=[b"phoenix_executor", mint_address, claimant]; address only.
    #[account(seeds = [b"phoenix_executor", mint_address.as_ref(), claimant.as_ref()], bump)]
    pub executor: UncheckedAccount<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Ephemeral claim key must co-sign so only the depositor can drive their executor.
    #[account(constraint = claimant_signer.key() == claimant @ PrivacyError::InvalidClaimant)]
    pub claimant_signer: Signer<'info>,

    pub system_program: Program<'info, System>,
    // Phoenix accounts supplied via remaining_accounts — see phoenix::phoenix_place_order
}

/// Relayer-submitted market close/reduce order on Phoenix before withdrawal.
///
/// Identical account layout to `PhoenixPlaceOrder`; only `place_market_order`
/// is accepted. Used to reduce a perp position before `phoenix_queue_withdraw`
/// when the open position's margin requirement exceeds free collateral.
/// Phoenix accounts supplied via remaining_accounts.
#[derive(Accounts)]
#[instruction(mint_address: Pubkey, claimant: Pubkey)]
pub struct PhoenixClosePosition<'info> {
    #[account(seeds = [b"privacy_config_v3", mint_address.as_ref()], bump = config.bump)]
    pub config: Box<Account<'info, PrivacyConfig>>,

    /// Executor PDA — signs the Phoenix CPI.
    /// CHECK: Validated as seeds=[b"phoenix_executor", mint_address, claimant]; address only.
    #[account(seeds = [b"phoenix_executor", mint_address.as_ref(), claimant.as_ref()], bump)]
    pub executor: UncheckedAccount<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Ephemeral claim key must co-sign so only the depositor can drive their executor.
    #[account(constraint = claimant_signer.key() == claimant @ PrivacyError::InvalidClaimant)]
    pub claimant_signer: Signer<'info>,

    pub system_program: Program<'info, System>,
    // Phoenix accounts supplied via remaining_accounts — see phoenix::phoenix_close_position
}

/// Cancel all open Phoenix orders for the executor's trader account.
/// Phoenix accounts supplied via remaining_accounts.
#[derive(Accounts)]
#[instruction(mint_address: Pubkey, claimant: Pubkey)]
pub struct PhoenixCancelOrders<'info> {
    #[account(seeds = [b"privacy_config_v3", mint_address.as_ref()], bump = config.bump)]
    pub config: Box<Account<'info, PrivacyConfig>>,

    /// Executor PDA — signs the Phoenix CPI.
    /// CHECK: Validated as seeds=[b"phoenix_executor", mint_address, claimant]; address only.
    #[account(seeds = [b"phoenix_executor", mint_address.as_ref(), claimant.as_ref()], bump)]
    pub executor: UncheckedAccount<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Ephemeral claim key must co-sign so only the depositor can drive their executor.
    #[account(constraint = claimant_signer.key() == claimant @ PrivacyError::InvalidClaimant)]
    pub claimant_signer: Signer<'info>,

    pub system_program: Program<'info, System>,
    // Phoenix accounts supplied via remaining_accounts — see phoenix::phoenix_cancel_orders
}

/// Cancel specific resting Phoenix orders by FIFO order IDs.
/// Identical account layout to `PhoenixCancelOrders`; only the instruction data differs.
/// Phoenix accounts supplied via remaining_accounts.
#[derive(Accounts)]
#[instruction(mint_address: Pubkey, claimant: Pubkey)]
pub struct PhoenixCancelOrdersById<'info> {
    #[account(seeds = [b"privacy_config_v3", mint_address.as_ref()], bump = config.bump)]
    pub config: Box<Account<'info, PrivacyConfig>>,

    /// Executor PDA — signs the Phoenix CPI.
    /// CHECK: Validated as seeds=[b"phoenix_executor", mint_address, claimant]; address only.
    #[account(seeds = [b"phoenix_executor", mint_address.as_ref(), claimant.as_ref()], bump)]
    pub executor: UncheckedAccount<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Ephemeral claim key must co-sign so only the depositor can drive their executor.
    #[account(constraint = claimant_signer.key() == claimant @ PrivacyError::InvalidClaimant)]
    pub claimant_signer: Signer<'info>,

    pub system_program: Program<'info, System>,
    // Phoenix accounts supplied via remaining_accounts — see phoenix::phoenix_cancel_orders_by_id
}

/// Transfer collateral between two Phoenix trader sub-accounts owned by the same executor.
/// Typically used to move collateral from cross (subaccount 0) to isolated (subaccount 1).
/// Phoenix accounts supplied via remaining_accounts.
#[derive(Accounts)]
#[instruction(mint_address: Pubkey, claimant: Pubkey)]
pub struct PhoenixTransferCollateral<'info> {
    #[account(seeds = [b"privacy_config_v3", mint_address.as_ref()], bump = config.bump)]
    pub config: Box<Account<'info, PrivacyConfig>>,

    /// Executor PDA — signs the Phoenix transferCollateral CPI.
    /// CHECK: Validated as seeds=[b"phoenix_executor", mint_address, claimant]; address only.
    #[account(seeds = [b"phoenix_executor", mint_address.as_ref(), claimant.as_ref()], bump)]
    pub executor: UncheckedAccount<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Ephemeral claim key must co-sign so only the depositor can drive their executor.
    #[account(constraint = claimant_signer.key() == claimant @ PrivacyError::InvalidClaimant)]
    pub claimant_signer: Signer<'info>,

    pub system_program: Program<'info, System>,
    // Phoenix accounts supplied via remaining_accounts — see phoenix::phoenix_transfer_collateral
}

/// Initialize the conditional-orders collection account for the executor PDA.
/// The relayer pays rent. Phoenix accounts supplied via remaining_accounts.
#[derive(Accounts)]
#[instruction(mint_address: Pubkey, claimant: Pubkey)]
pub struct PhoenixCreateConditionalOrdersAccount<'info> {
    #[account(seeds = [b"privacy_config_v3", mint_address.as_ref()], bump = config.bump)]
    pub config: Box<Account<'info, PrivacyConfig>>,

    /// Executor PDA — identified as traderWallet in the Phoenix CPI (non-signer for account creation).
    /// CHECK: Validated as seeds=[b"phoenix_executor", mint_address, claimant]; address only.
    #[account(seeds = [b"phoenix_executor", mint_address.as_ref(), claimant.as_ref()], bump)]
    pub executor: UncheckedAccount<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Ephemeral claim key must co-sign so only the depositor can drive their executor.
    #[account(constraint = claimant_signer.key() == claimant @ PrivacyError::InvalidClaimant)]
    pub claimant_signer: Signer<'info>,

    pub system_program: Program<'info, System>,
    // Phoenix accounts supplied via remaining_accounts — see phoenix::phoenix_create_conditional_orders_account
}

/// Place an atomic bracket order (SL+TP) via PlacePositionConditionalOrder.
/// The executor PDA signs as traderWallet. Phoenix accounts supplied via remaining_accounts.
#[derive(Accounts)]
#[instruction(mint_address: Pubkey, claimant: Pubkey)]
pub struct PhoenixPlacePositionConditionalOrder<'info> {
    #[account(seeds = [b"privacy_config_v3", mint_address.as_ref()], bump = config.bump)]
    pub config: Box<Account<'info, PrivacyConfig>>,

    /// Executor PDA — signs as traderWallet (readonly signer) in the Phoenix CPI.
    /// CHECK: Validated as seeds=[b"phoenix_executor", mint_address, claimant]; address only.
    #[account(mut, seeds = [b"phoenix_executor", mint_address.as_ref(), claimant.as_ref()], bump)]
    pub executor: UncheckedAccount<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Ephemeral claim key must co-sign so only the depositor can drive their executor.
    #[account(constraint = claimant_signer.key() == claimant @ PrivacyError::InvalidClaimant)]
    pub claimant_signer: Signer<'info>,

    pub system_program: Program<'info, System>,
    // Phoenix accounts supplied via remaining_accounts — see phoenix::phoenix_place_position_conditional_order
}

/// Atomically place a resting PostOnly limit order with attached TP/SL conditionals.
/// The executor PDA signs as traderWallet. Phoenix accounts supplied via remaining_accounts.
#[derive(Accounts)]
#[instruction(mint_address: Pubkey, claimant: Pubkey)]
pub struct PhoenixPlaceLimitOrderWithConditionals<'info> {
    #[account(seeds = [b"privacy_config_v3", mint_address.as_ref()], bump = config.bump)]
    pub config: Box<Account<'info, PrivacyConfig>>,

    /// Executor PDA — signs as traderWallet (readonly signer) in the Phoenix CPI.
    /// CHECK: Validated as seeds=[b"phoenix_executor", mint_address, claimant]; address only.
    #[account(mut, seeds = [b"phoenix_executor", mint_address.as_ref(), claimant.as_ref()], bump)]
    pub executor: UncheckedAccount<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Ephemeral claim key must co-sign so only the depositor can drive their executor.
    #[account(constraint = claimant_signer.key() == claimant @ PrivacyError::InvalidClaimant)]
    pub claimant_signer: Signer<'info>,

    pub system_program: Program<'info, System>,
    // Phoenix accounts supplied via remaining_accounts — see phoenix::phoenix_place_limit_order_with_conditionals
}

/// Cancel a conditional order from the collection by index.
/// The executor PDA signs as traderWallet. Phoenix accounts supplied via remaining_accounts.
#[derive(Accounts)]
#[instruction(mint_address: Pubkey, claimant: Pubkey)]
pub struct PhoenixCancelConditionalOrder<'info> {
    #[account(seeds = [b"privacy_config_v3", mint_address.as_ref()], bump = config.bump)]
    pub config: Box<Account<'info, PrivacyConfig>>,

    /// Executor PDA — signs as traderWallet (readonly signer) in the Phoenix CPI.
    /// CHECK: Validated as seeds=[b"phoenix_executor", mint_address, claimant]; address only.
    #[account(mut, seeds = [b"phoenix_executor", mint_address.as_ref(), claimant.as_ref()], bump)]
    pub executor: UncheckedAccount<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Ephemeral claim key must co-sign so only the depositor can drive their executor.
    #[account(constraint = claimant_signer.key() == claimant @ PrivacyError::InvalidClaimant)]
    pub claimant_signer: Signer<'info>,

    pub system_program: Program<'info, System>,
    // Phoenix accounts supplied via remaining_accounts — see phoenix::phoenix_cancel_conditional_order
}

/// Queue a Phoenix withdrawal back to the executor's PhUSD ATA.
/// After this, call `phoenix_ember_unwrap` to atomically crank the withdraw queue
/// and convert PhUSD→USDC. Phoenix accounts supplied via remaining_accounts.
#[derive(Accounts)]
#[instruction(mint_address: Pubkey, claimant: Pubkey, amount: u64, withdrawal_id: [u8; 32])]
pub struct PhoenixQueueWithdraw<'info> {
    #[account(seeds = [b"privacy_config_v3", mint_address.as_ref()], bump = config.bump)]
    pub config: Box<Account<'info, PrivacyConfig>>,

    /// Executor PDA — signs the Phoenix withdrawFunds CPI.
    /// CHECK: Validated as seeds=[b"phoenix_executor", mint_address, claimant]; address only.
    #[account(seeds = [b"phoenix_executor", mint_address.as_ref(), claimant.as_ref()], bump)]
    pub executor: UncheckedAccount<'info>,

    /// Per-deposit slot — enforces that withdrawal cannot exceed the deposit amount.
    /// CHECK: Validated in handler as [b"phoenix_slot_v1", mint, withdrawal_id] PDA;
    ///        deserialized and cap-checked after basic pre-validations.
    #[account(
        mut,
        seeds = [b"phoenix_slot_v1", mint_address.as_ref(), claimant.as_ref(), withdrawal_id.as_ref()],
        bump
    )]
    pub phoenix_slot: UncheckedAccount<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    // Phoenix accounts supplied via remaining_accounts — see phoenix::phoenix_queue_withdraw
}

/// Crank the Phoenix withdraw queue — step 2 of the exit flow.
///
/// Fully permissionless: any signer may call this to advance the queue.
/// After this succeeds, PhUSD arrives in the executor’s PhUSD ATA.
///
/// remaining_accounts: [0]=phoenixProgram, [1]=logAuth, [2]=globalConfig,
///                     [3]=perpAssetMap, [4]=globalVault, [5]=globalTraderIndex,
///                     [6]=activeTraderBuffer, [7]=withdrawQueue, [8]=traderAccount
#[derive(Accounts)]
#[instruction(mint_address: Pubkey, claimant: Pubkey)]
pub struct PhoenixConsumeWithdrawQueue<'info> {
    #[account(seeds = [b"privacy_config_v3", mint_address.as_ref()], bump = config.bump)]
    pub config: Box<Account<'info, PrivacyConfig>>,

    /// Executor PDA — referenced as traderWallet in the Phoenix CPI (readonly, not signer).
    /// CHECK: Validated as seeds=[b"phoenix_executor", mint_address, claimant]; address only.
    #[account(seeds = [b"phoenix_executor", mint_address.as_ref(), claimant.as_ref()], bump)]
    pub executor: UncheckedAccount<'info>,

    /// Executor's PhUSD ATA — destination for PhUSD released by Phoenix.
    /// CHECK: Validated as ATA(executor, PHUSD) in handler.
    #[account(mut)]
    pub executor_ph_usd_ata: UncheckedAccount<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    pub token_program: Program<'info, Token>,
}

/// Wrap executor USDC → PhUSD 1:1 via EMBER deposit CPI.
///
/// The executor holds USDC (received from vault) and wraps it to PhUSD,
/// ready for `phoenix_deposit_from_pool`.
///
/// remaining_accounts: [0]=emberProgram, [1]=phUsdMintAuthPda, [2]=usdcMint,
///                     [3]=phUsdMint(mut), [4]=emberUsdcReserve(mut)
#[derive(Accounts)]
#[instruction(mint_address: Pubkey, claimant: Pubkey)]
pub struct PhoenixEmberWrap<'info> {
    #[account(seeds = [b"privacy_config_v3", mint_address.as_ref()], bump = config.bump)]
    pub config: Box<Account<'info, PrivacyConfig>>,

    /// Executor PDA — signs the EMBER deposit CPI.
    /// CHECK: Validated as seeds=[b"phoenix_executor", mint_address, claimant]; address only.
    #[account(seeds = [b"phoenix_executor", mint_address.as_ref(), claimant.as_ref()], bump)]
    pub executor: UncheckedAccount<'info>,

    /// Executor's USDC ATA — source of USDC; EMBER pulls from here.
    /// CHECK: Validated as ATA(executor, mint_address) in handler.
    #[account(mut)]
    pub executor_token_account: UncheckedAccount<'info>,

    /// Executor's PhUSD ATA — destination for PhUSD minted by EMBER.
    /// CHECK: Validated as ATA(executor, PhUSD) in handler.
    #[account(mut)]
    pub executor_ph_usd_ata: UncheckedAccount<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    pub token_program: Program<'info, Token>,
}

/// After Phoenix sends PhUSD to `executor_ph_usd_ata` via the withdraw queue crank,
/// the executor invokes EMBER to burn the PhUSD and return USDC 1:1 to itself,
/// then SPL-transfers the USDC to the vault's USDC ATA. TVL is updated upward by `amount`.
///
/// This instruction atomically: (1) cranks `consumeWithdrawQueue` on Phoenix to flush
/// any pending PhUSD, then (2) burns the PhUSD via EMBER and returns USDC to the vault.
///
/// remaining_accounts layout (14 accounts):
///   Phoenix consumeWithdrawQueue:
///     [0]=phoenixProgram, [1]=logAuth, [2]=globalConfig, [3]=perpAssetMap,
///     [4]=globalVault, [5]=globalTraderIndex, [6]=activeTraderBuffer,
///     [7]=withdrawQueue, [8]=traderAccount
///   EMBER withdraw:
///     [9]=emberProgram, [10]=phUsdMintAuthPda, [11]=usdcMint,
///     [12]=phUsdMint(mut), [13]=emberUsdcReserve(mut)
#[derive(Accounts)]
#[instruction(mint_address: Pubkey, claimant: Pubkey, withdrawal_id: [u8; 32])]
pub struct PhoenixEmberUnwrap<'info> {
    #[account(
        mut,
        seeds = [b"privacy_config_v3", mint_address.as_ref()],
        bump = config.bump
    )]
    pub config: Box<Account<'info, PrivacyConfig>>,

    #[account(seeds = [b"privacy_vault_v3", mint_address.as_ref()], bump = config.vault_bump)]
    pub vault: Box<Account<'info, Vault>>,

    /// Executor PDA — signs the EMBER withdraw CPI and the USDC transfer to vault.
    /// CHECK: Validated as seeds=[b"phoenix_executor", mint_address, claimant]; address only.
    #[account(seeds = [b"phoenix_executor", mint_address.as_ref(), claimant.as_ref()], bump)]
    pub executor: UncheckedAccount<'info>,

    /// Executor's PhUSD ATA — source of PhUSD to burn via EMBER.
    /// CHECK: Validated as ATA(executor, PhUSD) in handler.
    #[account(mut)]
    pub executor_ph_usd_ata: UncheckedAccount<'info>,

    /// Executor's USDC ATA — receives USDC from EMBER, then sends to vault.
    /// CHECK: Validated as ATA(executor, mint_address) in handler.
    #[account(mut)]
    pub executor_token_account: UncheckedAccount<'info>,

    /// Vault's USDC ATA — final destination for USDC returned from Phoenix.
    /// CHECK: Validated as ATA(vault, mint_address) in handler.
    #[account(mut)]
    pub vault_token_account: UncheckedAccount<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Per-exit escrow — accumulates USDC amount returned from Phoenix so
    /// `phoenix_reissue_notes` can verify and consume exactly that amount.
    /// Seeds include `withdrawal_id` to isolate concurrent exits per user.
    #[account(
        init_if_needed,
        payer = relayer,
        seeds = [
            b"phoenix_pending_v1",
            mint_address.as_ref(),
            claimant.as_ref(),
            withdrawal_id.as_ref(),
        ],
        bump,
        space = PhoenixPendingReissue::LEN
    )]
    pub pending_reissue: Box<Account<'info, PhoenixPendingReissue>>,

    /// Per-deposit slot — read here to enforce ember_unwrap cannot exceed slot.amount.
    /// CHECK: Validated in handler as [b"phoenix_slot_v1", mint, withdrawal_id] PDA;
    ///        deserialized and cap-checked after basic pre-validations.
    #[account(
        mut,
        seeds = [b"phoenix_slot_v1", mint_address.as_ref(), claimant.as_ref(), withdrawal_id.as_ref()],
        bump
    )]
    pub phoenix_slot: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

/// Accounts for `phoenix_register_pool_trader`.
///
/// Registers the vault PDA as a trader on Phoenix Eternal (one-time setup).
/// Creates the `PhoenixExecutor` PDA if it does not yet exist, then calls
/// Phoenix `registerTrader` CPI. Idempotent on re-runs.
/// All Phoenix-specific accounts (log authority, global config, trader PDA)
/// are supplied via `remaining_accounts` — see `phoenix::phoenix_register_pool_trader`.
#[derive(Accounts)]
#[instruction(mint_address: Pubkey, claimant: Pubkey, margin_type: u8)]
pub struct PhoenixRegisterTrader<'info> {
    #[account(seeds = [b"privacy_config_v3", mint_address.as_ref()], bump = config.bump)]
    pub config: Box<Account<'info, PrivacyConfig>>,

    /// Executor PDA — created here on first call, then registered as the Phoenix Eternal trader wallet.
    #[account(
        init_if_needed,
        payer = payer,
        seeds = [b"phoenix_executor", mint_address.as_ref(), claimant.as_ref()],
        bump,
        space = PhoenixExecutor::LEN
    )]
    pub executor: Box<Account<'info, PhoenixExecutor>>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
    // Phoenix accounts: [0]=phoenixProgram, [1]=logAuthority, [2]=globalConfig,
    //                   [3]=traderAccount (new)
    // supplied via remaining_accounts — see phoenix::phoenix_register_pool_trader
}

/// Re-mint private USDC notes from funds already returned to the vault by Phoenix.
///
/// This is the final step of the Phoenix exit flow:
///   1. `phoenix_queue_withdraw`   — enqueue collateral for withdrawal
///   2. `phoenix_ember_unwrap`     — crank queue + burn PhUSD; USDC → vault USDC ATA; TVL updated
///   3. `phoenix_reissue_notes`    — verify ZK proof; insert commitments; **no token transfer**
///
/// Unlike a standard `transact` deposit, no USDC is pulled from an external account.
/// The USDC was already placed in the vault by `phoenix_ember_unwrap` and TVL was
/// updated there. This instruction only inserts the output commitments into the Merkle
/// tree so the user can spend their private notes.
///
/// The ZK proof format is identical to a standard deposit (public_amount = +amount,
/// dummy zero-value input notes, output notes sum to amount).
#[derive(Accounts)]
#[instruction(
    root: [u8; 32],
    input_tree_id: u16,
    output_tree_id: u16,
    amount: u64,
    ext_data_hash: [u8; 32],
    mint_address: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    output_commitment_0: [u8; 32],
    output_commitment_1: [u8; 32],
    withdrawal_id: [u8; 32],
)]
pub struct PhoenixReissueNotes<'info> {
    #[account(seeds = [b"privacy_config_v3", mint_address.as_ref()], bump = config.bump)]
    pub config: Box<Account<'info, PrivacyConfig>>,

    #[account(seeds = [b"global_config_v1"], bump = global_config.bump)]
    pub global_config: Box<Account<'info, GlobalConfig>>,

    #[account(seeds = [b"privacy_vault_v3", mint_address.as_ref()], bump = config.vault_bump)]
    pub vault: Box<Account<'info, Vault>>,

    /// Input tree — for root validation of the dummy input notes (same as transact deposit).
    #[account(
        seeds = [b"privacy_note_tree_v3", mint_address.as_ref(), &input_tree_id.to_le_bytes()],
        bump
    )]
    pub input_tree: AccountLoader<'info, MerkleTreeAccount>,

    /// Output tree — where the new output commitments will be inserted.
    #[account(
        mut,
        seeds = [b"privacy_note_tree_v3", mint_address.as_ref(), &output_tree_id.to_le_bytes()],
        bump
    )]
    pub output_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        mut,
        seeds = [b"privacy_nullifiers_v3", mint_address.as_ref()],
        bump = nullifiers.bump
    )]
    pub nullifiers: Box<Account<'info, NullifierSet>>,

    /// Dummy-input nullifier marker 0. init_if_needed: deposits reuse dummy witnesses.
    #[account(
        init_if_needed,
        payer = relayer,
        seeds = [b"nullifier_v3", mint_address.as_ref(), input_nullifier_0.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub nullifier_marker_0: Box<Account<'info, NullifierMarker>>,

    /// Dummy-input nullifier marker 1. init_if_needed: deposits reuse dummy witnesses.
    #[account(
        init_if_needed,
        payer = relayer,
        seeds = [b"nullifier_v3", mint_address.as_ref(), input_nullifier_1.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub nullifier_marker_1: Box<Account<'info, NullifierMarker>>,

    /// Authorized relayer — must be registered in config.relayers.
    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Per-exit escrow — must match the `withdrawal_id` used in `phoenix_ember_unwrap`.
    /// Decremented by `amount` on success — binds reissues to the returned proceeds.
    #[account(
        init_if_needed,
        payer = relayer,
        seeds = [
            b"phoenix_pending_v1",
            mint_address.as_ref(),
            claimant.key().as_ref(),
            withdrawal_id.as_ref(),
        ],
        bump,
        space = PhoenixPendingReissue::LEN
    )]
    pub pending_reissue: Box<Account<'info, PhoenixPendingReissue>>,

    /// Per-deposit slot — checked here to validate the claimant_pubkey.
    #[account(
        seeds = [
            b"phoenix_slot_v1",
            mint_address.as_ref(),
            claimant.key().as_ref(),
            withdrawal_id.as_ref(),
        ],
        bump
    )]
    pub phoenix_slot: Box<Account<'info, PhoenixSlot>>,

    /// Ephemeral claim key — must match `phoenix_slot.claimant_pubkey`.
    /// The user co-signs this transaction to prove they own the exit proceeds.
    pub claimant: Signer<'info>,

    pub system_program: Program<'info, System>,
}

// ---- Jupiter Perpetuals Instruction Contexts ----

/// Pre-funding step for native SOL pool jperp opens.
///
/// Moves `deposit_amount` lamports from the native-SOL vault directly into the executor's
/// Separating the lamport move from `jperp_open_position` is required because Solana's
/// SVM checks lamport conservation at the end of each instruction; wrapping (sync_native)
/// in the same instruction as the lamport spend creates an apparent imbalance.
#[derive(Accounts)]
#[instruction(mint_address: Pubkey, claimant: Pubkey, withdrawal_id: [u8; 32], deposit_amount: u64)]
pub struct FundNativeJperpOpen<'info> {
    /// Source vault (native SOL pool — holds raw lamports).
    #[account(
        mut,
        seeds = [b"privacy_vault_v3", mint_address.as_ref()],
        bump = source_config.vault_bump
    )]
    pub vault: Box<Account<'info, Vault>>,

    #[account(seeds = [b"privacy_config_v3", mint_address.as_ref()], bump = source_config.bump)]
    pub source_config: Box<Account<'info, PrivacyConfig>>,

    /// Executor PDA — system-owned, no data; validated by the following jperp_open_position.
    /// CHECK: seeds validated in handler; further validated by jperp_open_position.
    #[account(
        mut,
        seeds = [b"jperp_executor", mint_address.as_ref(), claimant.as_ref(), withdrawal_id.as_ref()],
        bump
    )]
    pub executor: UncheckedAccount<'info>,

    /// Executor's WSOL ATA — created here, funded with deposit_amount lamports from vault.
    #[account(
        init,
        payer = relayer,
        associated_token::mint = wsol_mint,
        associated_token::authority = executor
    )]
    pub executor_wsol_ata: Box<Account<'info, TokenAccount>>,

    /// WSOL mint (So11111…1112).
    #[account(address = crate::perps::WSOL_MINT @ PrivacyError::InvalidMintAddress)]
    pub wsol_mint: Box<Account<'info, Mint>>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// CHECK: Instructions sysvar — used to verify this is paired with jperp_open_position.
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID @ PrivacyError::Unauthorized)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub associated_token_program: Program<'info, anchor_spl::associated_token::AssociatedToken>,
}

/// ZK-verified USDC withdrawal → executor PDA funded → `createIncreasePositionMarketRequest`.
#[derive(Accounts)]
#[instruction(
    root: [u8; 32],
    input_tree_id: u16,
    output_tree_id: u16,
    deposit_amount: u64,
    ext_data_hash: [u8; 32],
    mint_address: Pubkey,
    claimant: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    output_commitment_0: [u8; 32],
    output_commitment_1: [u8; 32],
    withdrawal_id: [u8; 32]
)]
pub struct JperpOpenPosition<'info> {
    #[account(
        mut,
        seeds = [b"privacy_config_v3", mint_address.as_ref()],
        bump = config.bump
    )]
    pub config: Box<Account<'info, PrivacyConfig>>,

    #[account(seeds = [b"global_config_v1"], bump = global_config.bump)]
    pub global_config: Box<Account<'info, GlobalConfig>>,

    #[account(
        mut,
        seeds = [b"privacy_vault_v3", mint_address.as_ref()],
        bump = config.vault_bump
    )]
    pub vault: Box<Account<'info, Vault>>,

    #[account(
        seeds = [b"privacy_note_tree_v3", mint_address.as_ref(), &input_tree_id.to_le_bytes()],
        bump
    )]
    pub input_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        mut,
        seeds = [b"privacy_note_tree_v3", mint_address.as_ref(), &output_tree_id.to_le_bytes()],
        bump
    )]
    pub output_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        mut,
        seeds = [b"privacy_nullifiers_v3", mint_address.as_ref()],
        bump = nullifiers.bump
    )]
    pub nullifiers: Box<Account<'info, NullifierSet>>,

    #[account(
        init,
        payer = relayer,
        seeds = [b"nullifier_v3", mint_address.as_ref(), input_nullifier_0.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub nullifier_marker_0: Box<Account<'info, NullifierMarker>>,

    #[account(
        init,
        payer = relayer,
        seeds = [b"nullifier_v3", mint_address.as_ref(), input_nullifier_1.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub nullifier_marker_1: Box<Account<'info, NullifierMarker>>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Vault's collateral ATA — source of funds; vault transfers to executor.
    /// CHECK: Validated as ATA(vault, mint_address) in handler.
    #[account(mut)]
    pub vault_token_account: UncheckedAccount<'info>,

    /// Executor PDA — signs all Jupiter Perps CPIs as the position owner.
    ///
    /// MUST be a SYSTEM-OWNED PDA (no Anchor data): Jupiter's
    /// `createIncreasePositionMarketRequest` funds the positionRequest rent via
    /// `system_program::transfer(from = executor)`, which Solana rejects if the
    /// source carries data. The handler funds it with SOL before the CPI.
    /// CHECK: Seeds validated as [b"jperp_executor", mint_address, claimant, withdrawal_id].
    #[account(
        mut,
        seeds = [b"jperp_executor", mint_address.as_ref(), claimant.as_ref(), withdrawal_id.as_ref()],
        bump
    )]
    pub executor: UncheckedAccount<'info>,

    /// Executor's collateral ATA — receives tokens from vault; fundingAccount for Jupiter.
    /// CHECK: Validated as ATA(executor, mint_address) in handler.
    #[account(mut)]
    pub executor_token_account: UncheckedAccount<'info>,

    /// Relayer's ATA for the fee payment.
    /// CHECK: Validated as ATA(relayer, mint_address) in handler.
    #[account(mut)]
    pub relayer_token_account: UncheckedAccount<'info>,

    /// Per-deposit slot — tracks deposited amount and claimant for anti-theft protection.
    #[account(
        init,
        payer = relayer,
        seeds = [b"jperp_slot_v1", mint_address.as_ref(), withdrawal_id.as_ref()],
        bump,
        space = JupiterPerpSlot::LEN
    )]
    pub jperp_slot: Box<Account<'info, JupiterPerpSlot>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    // Jupiter Perps accounts via remaining_accounts — see jupiter_perp::jperp_open_position
}

/// Create a TP or SL trigger on an open Jupiter Perps position.
///
/// Calls `createDecreasePositionRequest2` with `Trigger` request type.
/// remaining_accounts: 16 accounts.
#[derive(Accounts)]
#[instruction(mint_address: Pubkey, withdrawal_id: [u8; 32])]
pub struct JperpSetTpsl<'info> {
    #[account(seeds = [b"privacy_config_v3", mint_address.as_ref()], bump = config.bump)]
    pub config: Box<Account<'info, PrivacyConfig>>,

    /// Per-deposit slot — read to validate the claimant co-signer.
    #[account(
        seeds = [b"jperp_slot_v1", mint_address.as_ref(), withdrawal_id.as_ref()],
        bump = jperp_slot.bump
    )]
    pub jperp_slot: Box<Account<'info, JupiterPerpSlot>>,

    /// Ephemeral claim key — must match jperp_slot.claimant_pubkey.
    /// Co-signing ensures only the position owner can set TP/SL.
    pub claimant: Signer<'info>,

    /// Executor PDA — signs the Jupiter Perps CPI and funds the positionRequest rent.
    /// Must be `mut` + system-owned: Jupiter funds the new positionRequest via
    /// `system_program::transfer(from = executor)`. The handler tops it up with SOL.
    /// CHECK: Seeds validated as [b"jperp_executor", mint_address, claimant, withdrawal_id].
    #[account(mut, seeds = [b"jperp_executor", mint_address.as_ref(), claimant.key().as_ref(), withdrawal_id.as_ref()], bump)]
    pub executor: UncheckedAccount<'info>,

    /// Executor's receiving ATA for close proceeds (desiredMint = collateral token).
    /// CHECK: Validated as ATA(executor, collateral_mint) by Jupiter Perps program.
    #[account(mut)]
    pub executor_token_account: UncheckedAccount<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Update trigger price / size on a pending TP or SL request.
///
/// Calls `updateDecreasePositionRequest2`.
/// remaining_accounts: 8 accounts.
#[derive(Accounts)]
#[instruction(mint_address: Pubkey, withdrawal_id: [u8; 32])]
pub struct JperpUpdateTpsl<'info> {
    #[account(seeds = [b"privacy_config_v3", mint_address.as_ref()], bump = config.bump)]
    pub config: Box<Account<'info, PrivacyConfig>>,

    /// Per-deposit slot — read to validate the claimant co-signer.
    #[account(
        seeds = [b"jperp_slot_v1", mint_address.as_ref(), withdrawal_id.as_ref()],
        bump = jperp_slot.bump
    )]
    pub jperp_slot: Box<Account<'info, JupiterPerpSlot>>,

    /// Ephemeral claim key — must match jperp_slot.claimant_pubkey.
    /// Co-signing ensures only the position owner can update TP/SL.
    pub claimant: Signer<'info>,

    /// CHECK: Seeds validated as [b"jperp_executor", mint_address, claimant, withdrawal_id].
    #[account(
        seeds = [
            b"jperp_executor",
            mint_address.as_ref(),
            claimant.key().as_ref(),
            withdrawal_id.as_ref(),
        ],
        bump
    )]
    pub executor: UncheckedAccount<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Create a market close/decrease on an open Jupiter Perps position.
///
/// Calls `createDecreasePositionRequest2` with `Market` request type.
/// remaining_accounts: 16 accounts.
#[derive(Accounts)]
#[instruction(mint_address: Pubkey, withdrawal_id: [u8; 32])]
pub struct JperpClosePosition<'info> {
    #[account(seeds = [b"privacy_config_v3", mint_address.as_ref()], bump = config.bump)]
    pub config: Box<Account<'info, PrivacyConfig>>,

    /// Per-deposit slot — read to validate the claimant co-signer.
    #[account(
        seeds = [b"jperp_slot_v1", mint_address.as_ref(), withdrawal_id.as_ref()],
        bump = jperp_slot.bump
    )]
    pub jperp_slot: Box<Account<'info, JupiterPerpSlot>>,

    /// Ephemeral claim key — must match jperp_slot.claimant_pubkey.
    /// Co-signing ensures only the position owner can close the position.
    pub claimant: Signer<'info>,

    /// Executor PDA — signs the Jupiter Perps CPI and funds the positionRequest rent.
    /// Must be `mut` + system-owned (see JperpSetTpsl).
    /// CHECK: Seeds validated as [b"jperp_executor", mint_address, claimant, withdrawal_id].
    #[account(mut, seeds = [b"jperp_executor", mint_address.as_ref(), claimant.key().as_ref(), withdrawal_id.as_ref()], bump)]
    pub executor: UncheckedAccount<'info>,

    /// Executor's receiving ATA — proceeds land here after keeper settles.
    /// CHECK: Validated as ATA(executor, desired_mint) by Jupiter Perps program.
    #[account(mut)]
    pub executor_token_account: UncheckedAccount<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Cancel a pending TP/SL trigger (`closePositionRequest2`, owner-cancel path).
///
/// No funds move except the rent refund: Jupiter closes the trigger's
/// positionRequest + ATA and returns their lamports to the executor (owner),
/// which the handler then sweeps back to the relayer.
/// remaining_accounts: 10 accounts (see `perps::jperp_cancel_trigger`).
#[derive(Accounts)]
#[instruction(mint_address: Pubkey, withdrawal_id: [u8; 32])]
pub struct JperpCancelTrigger<'info> {
    #[account(seeds = [b"privacy_config_v3", mint_address.as_ref()], bump = config.bump)]
    pub config: Box<Account<'info, PrivacyConfig>>,

    /// Per-deposit slot — read to validate the claimant co-signer.
    #[account(
        seeds = [b"jperp_slot_v1", mint_address.as_ref(), withdrawal_id.as_ref()],
        bump = jperp_slot.bump
    )]
    pub jperp_slot: Box<Account<'info, JupiterPerpSlot>>,

    /// Ephemeral claim key — must match jperp_slot.claimant_pubkey.
    /// Co-signing ensures only the position owner can cancel a trigger.
    pub claimant: Signer<'info>,

    /// Executor PDA — signs the Jupiter `closePositionRequest2` CPI as `owner`.
    /// Must be `mut`: Jupiter refunds the closed request's rent here.
    /// CHECK: Seeds validated as [b"jperp_executor", mint_address, claimant, withdrawal_id].
    #[account(mut, seeds = [b"jperp_executor", mint_address.as_ref(), claimant.key().as_ref(), withdrawal_id.as_ref()], bump)]
    pub executor: UncheckedAccount<'info>,

    /// Executor's collateral ATA = Jupiter's `ownerAta` (receives any request-ATA dust).
    /// CHECK: Validated as ATA(executor, collateral_mint) in the handler.
    #[account(mut)]
    pub executor_token_account: UncheckedAccount<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Re-mint private notes from settled Jupiter Perps proceeds.
///
/// Transfers USDC from executor ATA → vault, then ZK-verifies and inserts
/// output commitments into the Merkle tree.
///
/// The claimant (ephemeral key from the original deposit) must co-sign.
#[derive(Accounts)]
#[instruction(
    root: [u8; 32],
    input_tree_id: u16,
    output_tree_id: u16,
    reissue_amount: u64,
    ext_data_hash: [u8; 32],
    mint_address: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    output_commitment_0: [u8; 32],
    output_commitment_1: [u8; 32],
    withdrawal_id: [u8; 32]
)]
pub struct JperpReissueNotes<'info> {
    #[account(
        mut,
        seeds = [b"privacy_config_v3", mint_address.as_ref()],
        bump = config.bump
    )]
    pub config: Box<Account<'info, PrivacyConfig>>,

    #[account(seeds = [b"global_config_v1"], bump = global_config.bump)]
    pub global_config: Box<Account<'info, GlobalConfig>>,

    #[account(mut, seeds = [b"privacy_vault_v3", mint_address.as_ref()], bump = config.vault_bump)]
    pub vault: Box<Account<'info, Vault>>,

    #[account(
        seeds = [b"privacy_note_tree_v3", mint_address.as_ref(), &input_tree_id.to_le_bytes()],
        bump
    )]
    pub input_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        mut,
        seeds = [b"privacy_note_tree_v3", mint_address.as_ref(), &output_tree_id.to_le_bytes()],
        bump
    )]
    pub output_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        mut,
        seeds = [b"privacy_nullifiers_v3", mint_address.as_ref()],
        bump = nullifiers.bump
    )]
    pub nullifiers: Box<Account<'info, NullifierSet>>,

    /// init_if_needed: deposit circuit reuses dummy zero-value witnesses.
    #[account(
        init_if_needed,
        payer = relayer,
        seeds = [b"nullifier_v3", mint_address.as_ref(), input_nullifier_0.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub nullifier_marker_0: Box<Account<'info, NullifierMarker>>,

    #[account(
        init_if_needed,
        payer = relayer,
        seeds = [b"nullifier_v3", mint_address.as_ref(), input_nullifier_1.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub nullifier_marker_1: Box<Account<'info, NullifierMarker>>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Per-deposit slot — checked for claimant + slot cap enforcement.
    #[account(
        mut,
        seeds = [b"jperp_slot_v1", mint_address.as_ref(), withdrawal_id.as_ref()],
        bump = jperp_slot.bump
    )]
    pub jperp_slot: Box<Account<'info, JupiterPerpSlot>>,

    /// Ephemeral claim key — must match jperp_slot.claimant_pubkey.
    pub claimant: Signer<'info>,

    /// Executor PDA — authority on the executor_token_account.
    /// `mut` so its residual SOL can be swept back to the relayer at the end of the reissue.
    /// CHECK: Seeds validated as [b"jperp_executor", mint_address, claimant, withdrawal_id].
    #[account(
        mut,
        seeds = [b"jperp_executor", mint_address.as_ref(), claimant.key().as_ref(), withdrawal_id.as_ref()],
        bump
    )]
    pub executor: UncheckedAccount<'info>,

    /// Executor's collateral ATA — source of settled USDC proceeds.
    /// CHECK: Validated as ATA(executor, mint_address) in handler.
    #[account(mut)]
    pub executor_token_account: UncheckedAccount<'info>,

    /// Vault's collateral ATA — destination for reissued tokens.
    /// CHECK: Validated as ATA(vault, mint_address) in handler.
    #[account(mut)]
    pub vault_token_account: UncheckedAccount<'info>,

    /// Relayer's ATA for the reissue fee (SPL pools only; unused when fee = 0).
    /// CHECK: Validated as ATA(relayer, mint_address) in handler when fee > 0.
    #[account(mut)]
    pub relayer_token_account: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

/// Recover collateral stranded in the executor by a keeper-cancelled native-SOL open.
///
/// Same shape as `JperpReissueNotes` minus all token plumbing: the backing moves as a
/// native `executor → vault` system transfer, so there are no token accounts. Native-SOL
/// pool only (`mint_address == Pubkey::default()`).
#[derive(Accounts)]
#[instruction(
    root: [u8; 32],
    input_tree_id: u16,
    output_tree_id: u16,
    recover_amount: u64,
    ext_data_hash: [u8; 32],
    mint_address: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    output_commitment_0: [u8; 32],
    output_commitment_1: [u8; 32],
    withdrawal_id: [u8; 32]
)]
pub struct JperpRecoverNative<'info> {
    #[account(
        mut,
        seeds = [b"privacy_config_v3", mint_address.as_ref()],
        bump = config.bump
    )]
    pub config: Box<Account<'info, PrivacyConfig>>,

    #[account(seeds = [b"global_config_v1"], bump = global_config.bump)]
    pub global_config: Box<Account<'info, GlobalConfig>>,

    /// Native-SOL vault — destination for the recovered collateral (mut: receives lamports).
    #[account(mut, seeds = [b"privacy_vault_v3", mint_address.as_ref()], bump = config.vault_bump)]
    pub vault: Box<Account<'info, Vault>>,

    #[account(
        seeds = [b"privacy_note_tree_v3", mint_address.as_ref(), &input_tree_id.to_le_bytes()],
        bump
    )]
    pub input_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        mut,
        seeds = [b"privacy_note_tree_v3", mint_address.as_ref(), &output_tree_id.to_le_bytes()],
        bump
    )]
    pub output_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        mut,
        seeds = [b"privacy_nullifiers_v3", mint_address.as_ref()],
        bump = nullifiers.bump
    )]
    pub nullifiers: Box<Account<'info, NullifierSet>>,

    /// init_if_needed: deposit circuit reuses dummy zero-value witnesses (mirrors reissue).
    #[account(
        init_if_needed,
        payer = relayer,
        seeds = [b"nullifier_v3", mint_address.as_ref(), input_nullifier_0.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub nullifier_marker_0: Box<Account<'info, NullifierMarker>>,

    #[account(
        init_if_needed,
        payer = relayer,
        seeds = [b"nullifier_v3", mint_address.as_ref(), input_nullifier_1.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub nullifier_marker_1: Box<Account<'info, NullifierMarker>>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Per-deposit slot — checked for the claimant co-signer; reissued counter bumped.
    #[account(
        mut,
        seeds = [b"jperp_slot_v1", mint_address.as_ref(), withdrawal_id.as_ref()],
        bump = jperp_slot.bump
    )]
    pub jperp_slot: Box<Account<'info, JupiterPerpSlot>>,

    /// Ephemeral claim key — must match jperp_slot.claimant_pubkey (anti-theft).
    pub claimant: Signer<'info>,

    /// Executor PDA — system-owned; signs the `executor → vault` transfer and the rent sweep.
    /// `mut` so its lamports can be moved.
    /// CHECK: Seeds validated as [b"jperp_executor", mint_address, claimant, withdrawal_id].
    #[account(
        mut,
        seeds = [b"jperp_executor", mint_address.as_ref(), claimant.key().as_ref(), withdrawal_id.as_ref()],
        bump
    )]
    pub executor: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

/// Fund an ephemeral wallet from the pool via a ZK withdrawal proof.
///
/// The relayer must pre-create the ephemeral's USDC ATA (e.g., via
/// `createAssociatedTokenAccountIdempotent`) in the same transaction before this
/// instruction.  The ephemeral wallet address passed as `claimant` must match
/// `ext_data.recipient` in the ZK proof.
#[derive(Accounts)]
#[instruction(
    root: [u8; 32],
    input_tree_id: u16,
    output_tree_id: u16,
    deposit_amount: u64,
    ext_data_hash: [u8; 32],
    mint_address: Pubkey,
    claimant: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    output_commitment_0: [u8; 32],
    output_commitment_1: [u8; 32],
    withdrawal_id: [u8; 32]
)]
pub struct PredictionOpen<'info> {
    #[account(
        mut,
        seeds = [b"privacy_config_v3", mint_address.as_ref()],
        bump = config.bump
    )]
    pub config: Box<Account<'info, PrivacyConfig>>,

    #[account(seeds = [b"global_config_v1"], bump = global_config.bump)]
    pub global_config: Box<Account<'info, GlobalConfig>>,

    #[account(seeds = [b"privacy_vault_v3", mint_address.as_ref()], bump = config.vault_bump)]
    pub vault: Box<Account<'info, Vault>>,

    #[account(
        seeds = [b"privacy_note_tree_v3", mint_address.as_ref(), &input_tree_id.to_le_bytes()],
        bump
    )]
    pub input_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        mut,
        seeds = [b"privacy_note_tree_v3", mint_address.as_ref(), &output_tree_id.to_le_bytes()],
        bump
    )]
    pub output_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        mut,
        seeds = [b"privacy_nullifiers_v3", mint_address.as_ref()],
        bump = nullifiers.bump
    )]
    pub nullifiers: Box<Account<'info, NullifierSet>>,

    #[account(
        init,
        payer = relayer,
        seeds = [b"nullifier_v3", mint_address.as_ref(), input_nullifier_0.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub nullifier_marker_0: Box<Account<'info, NullifierMarker>>,

    #[account(
        init,
        payer = relayer,
        seeds = [b"nullifier_v3", mint_address.as_ref(), input_nullifier_1.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub nullifier_marker_1: Box<Account<'info, NullifierMarker>>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Per-deposit slot — records staked amount + claimant for reissue reconciliation.
    #[account(
        init,
        payer = relayer,
        seeds = [b"prediction_slot_v1", mint_address.as_ref(), withdrawal_id.as_ref()],
        bump,
        space = PredictionSlot::LEN
    )]
    pub prediction_slot: Box<Account<'info, PredictionSlot>>,

    /// Vault's USDC ATA — source of funds.
    /// CHECK: Validated as ATA(vault, mint_address) in handler.
    #[account(mut)]
    pub vault_token_account: UncheckedAccount<'info>,

    /// Ephemeral wallet — receives the SOL fee funding.
    /// CHECK: Must equal `claimant` param and `ext_data.recipient`; validated in handler.
    #[account(mut)]
    pub ephemeral_wallet: UncheckedAccount<'info>,

    /// Ephemeral wallet's USDC ATA — receives the USDC deposit.
    /// Must be pre-created by the relayer before this instruction.
    /// CHECK: Validated as ATA(claimant, mint_address) in handler.
    #[account(mut)]
    pub ephemeral_token_account: UncheckedAccount<'info>,

    /// Relayer's USDC ATA — receives the protocol fee.
    /// CHECK: Validated as ATA(relayer, mint_address) in handler.
    #[account(mut)]
    pub relayer_token_account: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

/// Sweep prediction proceeds from the ephemeral wallet back into the pool.
///
/// The ephemeral keypair (`claimant`) must co-sign as it is the USDC ATA authority.
/// Uses the deposit ZK circuit: `public_amount > 0`, dummy zero nullifiers allowed.
#[derive(Accounts)]
#[instruction(
    root: [u8; 32],
    input_tree_id: u16,
    output_tree_id: u16,
    reissue_amount: u64,
    ext_data_hash: [u8; 32],
    mint_address: Pubkey,
    input_nullifier_0: [u8; 32],
    input_nullifier_1: [u8; 32],
    output_commitment_0: [u8; 32],
    output_commitment_1: [u8; 32],
    withdrawal_id: [u8; 32]
)]
pub struct PredictionReissue<'info> {
    #[account(
        mut,
        seeds = [b"privacy_config_v3", mint_address.as_ref()],
        bump = config.bump
    )]
    pub config: Box<Account<'info, PrivacyConfig>>,

    #[account(seeds = [b"global_config_v1"], bump = global_config.bump)]
    pub global_config: Box<Account<'info, GlobalConfig>>,

    #[account(seeds = [b"privacy_vault_v3", mint_address.as_ref()], bump = config.vault_bump)]
    pub vault: Box<Account<'info, Vault>>,

    #[account(
        seeds = [b"privacy_note_tree_v3", mint_address.as_ref(), &input_tree_id.to_le_bytes()],
        bump
    )]
    pub input_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        mut,
        seeds = [b"privacy_note_tree_v3", mint_address.as_ref(), &output_tree_id.to_le_bytes()],
        bump
    )]
    pub output_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        mut,
        seeds = [b"privacy_nullifiers_v3", mint_address.as_ref()],
        bump = nullifiers.bump
    )]
    pub nullifiers: Box<Account<'info, NullifierSet>>,

    /// init_if_needed: deposit circuit uses dummy zero nullifiers shared across all deposits.
    #[account(
        init_if_needed,
        payer = relayer,
        seeds = [b"nullifier_v3", mint_address.as_ref(), input_nullifier_0.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub nullifier_marker_0: Box<Account<'info, NullifierMarker>>,

    #[account(
        init_if_needed,
        payer = relayer,
        seeds = [b"nullifier_v3", mint_address.as_ref(), input_nullifier_1.as_ref()],
        bump,
        space = NullifierMarker::LEN
    )]
    pub nullifier_marker_1: Box<Account<'info, NullifierMarker>>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Ephemeral keypair — co-signs as USDC ATA authority. Must match ext_data.claimant.
    pub claimant: Signer<'info>,

    /// Per-deposit slot — claimant binding + cumulative reissue audit counter.
    /// CHECK: PDA address validated by seeds; existence, owner, and claimant are verified
    /// in the handler AFTER the ZK proof (mirrors the ephemeral-ATA check) so cheaper
    /// validations and the proof run first.
    #[account(
        mut,
        seeds = [b"prediction_slot_v1", mint_address.as_ref(), withdrawal_id.as_ref()],
        bump
    )]
    pub prediction_slot: UncheckedAccount<'info>,

    /// Ephemeral wallet's USDC ATA — source of proceeds.
    /// CHECK: Validated as ATA(claimant, mint_address) in handler.
    #[account(mut)]
    pub ephemeral_token_account: UncheckedAccount<'info>,

    /// Vault's USDC ATA — destination for swept proceeds.
    /// CHECK: Validated as ATA(vault, mint_address) in handler.
    #[account(mut)]
    pub vault_token_account: UncheckedAccount<'info>,

    /// Relayer's ATA for the reissue fee (unused when fee = 0).
    /// CHECK: Validated as ATA(relayer, mint_address) in handler when fee > 0.
    #[account(mut)]
    pub relayer_token_account: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
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
        max_withdraw_amount: Option<u64>
    ) -> Result<()> {
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

        cfg.bump = ctx.bumps.config;
        cfg.vault_bump = ctx.bumps.vault;
        vault.bump = ctx.bumps.vault;
        nulls.bump = ctx.bumps.nullifiers;

        cfg.admin = ctx.accounts.admin.key();

        // Validate fee_bps: must be >= 1 (zero causes division-by-zero in withdrawal) and <= 100 bps
        require!(fee_bps >= 1 && fee_bps <= MAX_FEE_BPS, PrivacyError::ExcessiveFeeBps);

        cfg.fee_bps = fee_bps;
        cfg.min_withdrawal_fee = 1_000_000; // Default: 0.001 SOL minimum fee
        cfg.fee_error_margin_bps = 500; // Default: 5% margin to prevent timing attacks

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
        tree_id: u16
    ) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        let relayer = &ctx.accounts.relayer;

        // Admin OR any registered relayer can add trees
        let caller = relayer.key();
        require!(cfg.admin == caller || cfg.is_relayer(&caller), PrivacyError::RelayerNotAllowed);

        require!(tree_id == cfg.num_trees, PrivacyError::InvalidTreeId);
        require!(cfg.num_trees < MAX_MERKLE_TREES, PrivacyError::TooManyTrees);

        let mut tree = ctx.accounts.note_tree.load_init()?;
        tree.authority = cfg.admin;
        tree.height = MERKLE_TREE_HEIGHT as u8;
        tree.root_history_size = ROOT_HISTORY_SIZE as u16;
        tree.next_index = 0;
        tree.root_index = 0;

        MerkleTree::initialize::<PoseidonHasher>(&mut *tree)?;

        cfg.num_trees = cfg.num_trees.checked_add(1).ok_or(PrivacyError::ArithmeticOverflow)?;

        Ok(())
    }

    pub fn add_relayer(
        ctx: Context<ConfigAdmin>,
        _mint_address: Pubkey,
        new_relayer: Pubkey
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

    pub fn remove_relayer(
        ctx: Context<ConfigAdmin>,
        _mint_address: Pubkey,
        relayer: Pubkey
    ) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        let n = cfg.num_relayers as usize;
        let idx = cfg.relayers[..n].iter().position(|k| k == &relayer);
        require!(idx.is_some(), PrivacyError::RelayerNotFound);
        let idx = idx.unwrap();
        // swap-remove: move the last entry into the removed slot, then clear the tail
        cfg.relayers[idx] = cfg.relayers[n - 1];
        cfg.relayers[n - 1] = Pubkey::default();
        cfg.num_relayers -= 1;
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
        swap_fee_bps: Option<u16>
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
            // Validate fee_bps: must be >= 1 (zero causes division-by-zero in withdrawal) and <= 100 bps
            require!(val >= 1 && val <= MAX_FEE_BPS, PrivacyError::ExcessiveFeeBps);
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
            require!(val <= MAX_SWAP_FEE_BPS, PrivacyError::ExcessiveFeeBps);
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
        deadline: i64,
        ext_data: ExtData,
        proof: zk::TransactionProof,
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
        let input_nullifiers = [input_nullifier_0, input_nullifier_1];
        let output_commitments = [output_commitment_0, output_commitment_1];
        let cfg = &mut ctx.accounts.config;

        // Validate tree IDs are valid before loading trees to prevent compute waste
        require!(input_tree_id < cfg.num_trees, PrivacyError::InvalidTreeId);
        require!(output_tree_id < cfg.num_trees, PrivacyError::InvalidTreeId);

        let input_tree = ctx.accounts.input_tree.load()?;

        // For deposits (public_amount > 0), no notes are consumed
        // The circuit skips Merkle proof verification when inAmount=0, but still computes
        // a nullifier from the dummy input witness. The computed nullifiers are deterministic
        // but not zero - they depend on the dummy witness values.
        //
        // A deposit input that references a real note still binds to that note's single-use
        // marker, so it cannot be replayed later.
        //
        // The circuit always computes nullifiers as Poseidon(commitment, pathIndex, signature)
        // which are never zero. Deposits use dummy witnesses that produce non-zero but harmless nullifiers.
        // Validate nullifiers on ALL paths (deposits and withdrawals alike).
        // Dummy deposit witnesses produce non-zero Poseidon outputs, so this is always satisfiable
        // by honest clients, and any input referencing a real note stays bound to its marker.
        let zero_nullifier = [0u8; 32];
        require!(input_nullifiers[0] != input_nullifiers[1], PrivacyError::DuplicateNullifiers);
        require!(
            input_nullifiers[0] != zero_nullifier && input_nullifiers[1] != zero_nullifier,
            PrivacyError::ZeroNullifier
        );

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
        require!(computed_ext_hash == ext_data_hash, PrivacyError::InvalidExtData);

        // 1a. Enforce deadline - prevents relayer from holding and executing transactions
        // at an economically favorable time (fee spikes, price drops, timing attacks).
        // Mirror of the same check in transact_swap.
        let clock = Clock::get()?;
        require!(clock.unix_timestamp <= deadline, PrivacyError::DeadlineExpired);

        // 2. Verify relayer is authorized (only for withdrawals/transfers, not deposits)
        // For deposits (public_amount > 0), anyone can facilitate deposit without being authorized
        // For withdrawals (public_amount < 0) and transfers (public_amount = 0), require authorized relayer
        if public_amount <= 0 {
            // Check if this specific relayer is authorized
            require!(cfg.is_relayer(&ctx.accounts.relayer.key()), PrivacyError::RelayerNotAllowed);
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
        require_keys_eq!(mint_address, cfg.mint_address, PrivacyError::InvalidMintAddress);

        // 4a. mint_address has been verified to equal cfg.mint_address above (require_keys_eq),
        // and pool creation is gated by GlobalConfig authority, so the mint is implicitly trusted.

        // 4b. Validate token accounts if using SPL tokens
        if is_token_mint(&mint_address) {
            // Verify token program is provided
            require_keys_eq!(
                ctx.accounts.token_program.key(),
                token::ID,
                PrivacyError::MissingTokenProgram
            );

            // Deserialize and validate vault token account
            let vault_token = deserialize_token_account(
                &ctx.accounts.vault_token_account.to_account_info()
            )?;

            // Verify vault_token_account is the canonical ATA
            let expected_vault_ata = get_associated_token_address(
                &ctx.accounts.vault.key(),
                &cfg.mint_address
            );
            require_keys_eq!(
                ctx.accounts.vault_token_account.key(),
                expected_vault_ata,
                PrivacyError::VaultTokenAccountNotATA
            );

            // Verify vault token account mint matches config
            require_keys_eq!(vault_token.mint, cfg.mint_address, PrivacyError::InvalidMintAddress);

            // Verify vault is the authority
            require_keys_eq!(
                vault_token.owner,
                ctx.accounts.vault.key(),
                PrivacyError::InvalidTokenAuthority
            );

            // For deposits (public_amount > 0), user token account required
            if public_amount > 0 {
                let user_token = deserialize_token_account(
                    &ctx.accounts.user_token_account.to_account_info()
                )?;
                require_keys_eq!(
                    user_token.mint,
                    cfg.mint_address,
                    PrivacyError::InvalidMintAddress
                );

                // The relayer must own the source token account outright (user pre-transferred
                // tokens before calling transact).
                require!(
                    user_token.owner == ctx.accounts.relayer.key(),
                    PrivacyError::DepositorTokenAccountMismatch
                );
                require!(user_token.delegate.is_none(), PrivacyError::InvalidTokenAuthority);
            }

            // For withdrawals (public_amount < 0), recipient/relayer token accounts required
            if public_amount < 0 {
                let recipient_token = deserialize_token_account(
                    &ctx.accounts.recipient_token_account.to_account_info()
                )?;
                let relayer_token = deserialize_token_account(
                    &ctx.accounts.relayer_token_account.to_account_info()
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
        zk::verify_transaction_groth16(proof, &public_inputs)?;

        // 7. Check root is known in input tree
        require!(MerkleTree::is_known_root(&*input_tree, root), PrivacyError::UnknownRoot);

        drop(input_tree);

        // 8. Mark both input nullifiers as spent on ALL paths (deposits and withdrawals).
        // The `init` constraint on the marker accounts already blocks reuse at account resolution,
        // but setting is_spent provides a defence-in-depth layer and keeps state consistent.
        // Dummy deposit nullifiers are Poseidon outputs of random witnesses — they are fresh
        // per transaction and safe to burn. A nullifier that already has a marker from a
        // prior spend is rejected here.
        require!(!ctx.accounts.nullifier_marker_0.is_spent, PrivacyError::NullifierAlreadyUsed);
        require!(!ctx.accounts.nullifier_marker_1.is_spent, PrivacyError::NullifierAlreadyUsed);

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

        drop(output_tree);

        // Emit commitment events for both outputs
        let timestamp = Clock::get()?.unix_timestamp;
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
            &ctx.accounts.token_program
        )?;

        Ok(())
    }

    /// Option B: Create executor PDA + WSOL ATA and transfer swap_amount from vault.
    /// Must be invoked as the FIRST instruction in an atomic transaction whose SECOND
    /// instruction is `transact_swap`.  Both instructions are sent together so that
    /// failure in `transact_swap` reverts the vault debit atomically.
    ///
    /// Only for native SOL source pools.  SPL-source swaps use `transact_swap` directly.
    #[inline(never)]
    pub fn fund_native_source(
        ctx: Context<FundNativeSource>,
        source_mint: Pubkey,
        dest_mint: Pubkey,
        input_nullifier_0: [u8; 32],
        swap_amount: u64
    ) -> Result<()> {
        swap::fund_native_source(ctx, source_mint, dest_mint, input_nullifier_0, swap_amount)
    }

    /// Atomic cross-pool private swap
    /// Consumes notes from source pool, swaps via Raydium CPMM (no Serum), creates notes in dest pool
    /// All in one transaction - see swap.rs for implementation details
    #[inline(never)]
    pub fn transact_swap<'info>(
        ctx: Context<'_, '_, 'info, 'info, TransactSwap<'info>>,
        source_tree_id: u16,
        source_mint: Pubkey,
        input_nullifier_0: [u8; 32],
        input_nullifier_1: [u8; 32],
        dest_tree_id: u16,
        dest_mint: Pubkey,
        proof: zk::SwapProof,
        source_root: [u8; 32],
        output_commitment_0: [u8; 32],
        output_commitment_1: [u8; 32],
        swap_params: SwapParams,
        swap_amount: u64,
        swap_data: Vec<u8>,
        ext_data: ExtData,
        note_ciphers: Option<NoteCiphers>
    ) -> Result<()> {
        swap::transact_swap(
            ctx,
            source_tree_id,
            source_mint,
            input_nullifier_0,
            input_nullifier_1,
            dest_tree_id,
            dest_mint,
            proof,
            source_root,
            output_commitment_0,
            output_commitment_1,
            swap_params,
            swap_amount,
            swap_data,
            ext_data,
            note_ciphers
        )
    }

    // ---- Position Pool (Private Stock & Meme Trading) ----

    /// Pre-fund a native-SOL open_position: debits the SOL vault, credits the executor's WSOL ATA
    /// (`to_executor_native=false`) or native lamports (`true`). Must run as a separate instruction
    /// before open_position (raw lamport move can't share an instruction with a CPI).
    pub fn fund_native_open_position(
        ctx: Context<FundNativeOpenPosition>,
        source_mint: Pubkey,
        swap_amount: u64,
        to_executor_native: bool
    ) -> Result<()> {
        positions::fund_native_open_position(ctx, source_mint, swap_amount, to_executor_native)
    }

    /// Stage a Jupiter-legs swap blob in a buffer PDA so `open_position` can read it without
    /// carrying it in instruction data (which would overflow the 1232-byte tx limit alongside the
    /// ZK proof). Send before `open_position`; bound to the proof via `swap_data_hash`.
    pub fn stage_swap_legs(
        ctx: Context<StageSwapLegs>,
        input_nullifier_0: [u8; 32],
        legs: Vec<u8>
    ) -> Result<()> {
        positions::stage_swap_legs(ctx, input_nullifier_0, legs)
    }

    /// Reclaim the rent from a staged Jupiter-legs buffer after `open_position`.
    pub fn close_swap_legs(
        ctx: Context<CloseSwapLegs>,
        _input_nullifier_0: [u8; 32]
    ) -> Result<()> {
        positions::close_swap_legs(ctx)
    }

    /// Initialize the cross-mint position pool and first Merkle tree.
    /// Admin-only, called once.
    #[inline(never)]
    pub fn init_position_pool(
        ctx: Context<InitPositionPool>,
        min_swap_fee: u64,
        swap_fee_bps: u16
    ) -> Result<()> {
        positions::init_position_pool(ctx, min_swap_fee, swap_fee_bps)
    }

    /// Add a whitelisted relayer to the position pool.
    pub fn add_position_relayer(
        ctx: Context<PositionPoolAdmin>,
        new_relayer: Pubkey
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

    /// Remove a whitelisted relayer from the position pool.
    pub fn remove_position_relayer(ctx: Context<PositionPoolAdmin>, relayer: Pubkey) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        let n = cfg.num_relayers as usize;
        let idx = cfg.relayers[..n].iter().position(|k| k == &relayer);
        require!(idx.is_some(), PrivacyError::RelayerNotFound);
        let idx = idx.unwrap();
        // swap-remove: move the last entry into the removed slot, then clear the tail
        cfg.relayers[idx] = cfg.relayers[n - 1];
        cfg.relayers[n - 1] = Pubkey::default();
        cfg.num_relayers -= 1;
        Ok(())
    }

    /// Update the position pool's swap fees (admin only). Pass `None` to leave a field unchanged.
    pub fn update_position_pool(
        ctx: Context<PositionPoolAdmin>,
        min_swap_fee: Option<u64>,
        swap_fee_bps: Option<u16>
    ) -> Result<()> {
        positions::update_position_pool(ctx, min_swap_fee, swap_fee_bps)
    }

    /// Open a private stock/meme position.
    /// Spends USDC notes from the source pool, swaps USDC → stock via Jupiter,
    /// deposits stock into a per-mint position vault, inserts position note into
    /// the position Merkle tree, and creates a PositionPDA recoverable from the
    /// user's wallet key.
    #[inline(never)]
    pub fn open_position<'info>(
        ctx: Context<'_, '_, 'info, 'info, OpenPosition<'info>>,
        source_tree_id: u16,
        source_mint: Pubkey,
        input_nullifier_0: [u8; 32],
        input_nullifier_1: [u8; 32],
        position_tree_id: u16,
        dest_mint: Pubkey,
        position_pda_key: [u8; 32],
        proof: SwapProof,
        source_root: [u8; 32],
        output_commitment_0: [u8; 32],
        output_commitment_1: [u8; 32],
        swap_params: SwapParams,
        swap_amount: u64,
        swap_data: Vec<u8>,
        ext_data: ExtData,
        note_ciphers: Option<NoteCiphers>
    ) -> Result<()> {
        positions::open_position(
            ctx,
            source_tree_id,
            source_mint,
            input_nullifier_0,
            input_nullifier_1,
            position_tree_id,
            dest_mint,
            position_pda_key,
            proof,
            source_root,
            output_commitment_0,
            output_commitment_1,
            swap_params,
            swap_amount,
            swap_data,
            ext_data,
            note_ciphers
        )
    }

    /// Close a private stock/meme position.
    /// Proves ownership of a position note in the position tree, withdraws stock
    /// from the vault, swaps stock → USDC via Jupiter, and inserts USDC output
    /// notes into the USDC pool Merkle tree.
    #[inline(never)]
    pub fn close_position<'info>(
        ctx: Context<'_, '_, 'info, 'info, ClosePosition<'info>>,
        position_tree_id: u16,
        source_mint: Pubkey,
        input_nullifier_0: [u8; 32],
        input_nullifier_1: [u8; 32],
        usdc_tree_id: u16,
        dest_mint: Pubkey,
        position_pda_key: [u8; 32],
        proof: SwapProof,
        position_root: [u8; 32],
        output_commitment_0: [u8; 32],
        output_commitment_1: [u8; 32],
        swap_params: SwapParams,
        swap_amount: u64,
        swap_data: Vec<u8>,
        ext_data: ExtData,
        note_ciphers: Option<NoteCiphers>
    ) -> Result<()> {
        positions::close_position(
            ctx,
            position_tree_id,
            source_mint,
            input_nullifier_0,
            input_nullifier_1,
            usdc_tree_id,
            dest_mint,
            position_pda_key,
            proof,
            position_root,
            output_commitment_0,
            output_commitment_1,
            swap_params,
            swap_amount,
            swap_data,
            ext_data,
            note_ciphers
        )
    }

    /// Close a position MEME→SOL via Jupiter (staged-legs cosigner sell) → deposit SOL into the SOL pool.
    pub fn close_position_to_sol<'info>(
        ctx: Context<'_, '_, 'info, 'info, ClosePositionToSol<'info>>,
        position_tree_id: u16,
        source_mint: Pubkey,
        input_nullifier_0: [u8; 32],
        input_nullifier_1: [u8; 32],
        sol_tree_id: u16,
        dest_mint: Pubkey,
        position_pda_key: [u8; 32],
        proof: SwapProof,
        position_root: [u8; 32],
        output_commitment_0: [u8; 32],
        output_commitment_1: [u8; 32],
        swap_params: SwapParams,
        swap_amount: u64,
        swap_data: Vec<u8>,
        ext_data: ExtData,
        note_ciphers: Option<NoteCiphers>
    ) -> Result<()> {
        positions::close_position_to_sol(
            ctx,
            position_tree_id,
            source_mint,
            input_nullifier_0,
            input_nullifier_1,
            sol_tree_id,
            dest_mint,
            position_pda_key,
            proof,
            position_root,
            output_commitment_0,
            output_commitment_1,
            swap_params,
            swap_amount,
            swap_data,
            ext_data,
            note_ciphers
        )
    }

    /// Merge two position notes of the same mint into one.
    ///
    /// Uses the existing transaction circuit (publicAmount=0): both inputs are real
    /// position notes; output[0] is the merged note (sum of amounts); output[1] is
    /// the zero change note. No vault token movement — only Merkle tree updates.
    #[inline(never)]
    pub fn merge_positions<'info>(
        ctx: Context<'_, '_, 'info, 'info, MergePositions<'info>>,
        input_tree_id: u16,
        mint: Pubkey,
        input_nullifier_0: [u8; 32],
        input_nullifier_1: [u8; 32],
        output_tree_id: u16,
        position_pda_key_0: [u8; 32],
        position_pda_key_1: [u8; 32],
        new_position_pda_key: [u8; 32],
        proof: TransactionProof,
        position_root: [u8; 32],
        output_commitment_0: [u8; 32],
        output_commitment_1: [u8; 32],
        ext_data: ExtData,
        merged_amount: u64
    ) -> Result<()> {
        positions::merge_positions(
            ctx,
            input_tree_id,
            mint,
            input_nullifier_0,
            input_nullifier_1,
            output_tree_id,
            position_pda_key_0,
            position_pda_key_1,
            new_position_pda_key,
            proof,
            position_root,
            output_commitment_0,
            output_commitment_1,
            ext_data,
            merged_amount
        )
    }

    // ---- Phoenix Eternal Integration ----

    /// ZK-verified USDC withdrawal from pool → Phoenix Eternal `depositFunds` CPI.
    ///
    /// Atomically burns private USDC notes and deposits the amount into the
    /// executor's Phoenix Eternal perpetual trading account. Output change notes
    /// are inserted into the Merkle tree in the same transaction.
    ///
    /// `ext_data.recipient` **must** equal the executor PDA (enforced on-chain and
    /// committed in the ZK proof).
    ///
    /// See `phoenix::phoenix_deposit_from_pool` for full documentation.
    #[inline(never)]
    pub fn phoenix_deposit_from_pool<'info>(
        ctx: Context<'_, '_, 'info, 'info, PhoenixDepositFromPool<'info>>,
        root: [u8; 32],
        input_tree_id: u16,
        output_tree_id: u16,
        deposit_amount: u64,
        ext_data_hash: [u8; 32],
        mint_address: Pubkey,
        claimant: Pubkey,
        input_nullifier_0: [u8; 32],
        input_nullifier_1: [u8; 32],
        output_commitment_0: [u8; 32],
        output_commitment_1: [u8; 32],
        withdrawal_id: [u8; 32],
        deadline: i64,
        ext_data: ExtData,
        proof: zk::TransactionProof,
        note_ciphers: Option<NoteCiphers>
    ) -> Result<()> {
        phoenix::phoenix_deposit_from_pool(
            ctx,
            root,
            input_tree_id,
            output_tree_id,
            deposit_amount,
            ext_data_hash,
            mint_address,
            claimant,
            input_nullifier_0,
            input_nullifier_1,
            output_commitment_0,
            output_commitment_1,
            withdrawal_id,
            deadline,
            ext_data,
            proof,
            note_ciphers
        )
    }

    /// Place a market or limit order on Phoenix using the vault's trader account.
    ///
    /// `order_data` is the full Anchor-encoded instruction: discriminator (8 bytes)
    /// + borsh-serialised `OrderPacket`. Only `placeMarketOrder` and `placeLimitOrder`
    /// discriminators are accepted.
    ///
    /// See `phoenix::phoenix_place_order` for full documentation.
    #[inline(never)]
    pub fn phoenix_place_order<'info>(
        ctx: Context<'_, '_, 'info, 'info, PhoenixPlaceOrder<'info>>,
        mint_address: Pubkey,
        claimant: Pubkey,
        order_data: Vec<u8>,
        transfer_amount: Option<u64>
    ) -> Result<()> {
        phoenix::phoenix_place_order(ctx, mint_address, claimant, order_data, transfer_amount)
    }

    /// Cancel all open orders for the vault's Phoenix trader account.
    ///
    /// See `phoenix::phoenix_cancel_orders` for full documentation.
    #[inline(never)]
    pub fn phoenix_cancel_orders<'info>(
        ctx: Context<'_, '_, 'info, 'info, PhoenixCancelOrders<'info>>,
        mint_address: Pubkey,
        claimant: Pubkey
    ) -> Result<()> {
        phoenix::phoenix_cancel_orders(ctx, mint_address, claimant)
    }

    /// **Cancel specific resting Phoenix orders by their FIFO order IDs.**
    ///
    /// `price_in_ticks` and `sequence_numbers` must have the same length (1..=100).
    /// Each pair `(price_in_ticks[i], sequence_numbers[i])` identifies a resting order.
    ///
    /// See `phoenix::phoenix_cancel_orders_by_id` for full documentation.
    #[inline(never)]
    pub fn phoenix_cancel_orders_by_id<'info>(
        ctx: Context<'_, '_, 'info, 'info, PhoenixCancelOrdersById<'info>>,
        mint_address: Pubkey,
        claimant: Pubkey,
        price_in_ticks: Vec<u64>,
        sequence_numbers: Vec<u64>
    ) -> Result<()> {
        phoenix::phoenix_cancel_orders_by_id(
            ctx,
            mint_address,
            claimant,
            price_in_ticks,
            sequence_numbers
        )
    }

    /// **Transfer collateral between Phoenix sub-accounts (cross ↔ isolated).**
    ///
    /// Moves `amount` PhUSD from `srcTraderAccount` to `dstTraderAccount`.
    /// Both accounts must be owned by the same executor PDA.
    /// Typically: cross sub-account → isolated sub-account before an isolated position.
    ///
    /// See `phoenix::phoenix_transfer_collateral` for full documentation.
    #[inline(never)]
    pub fn phoenix_transfer_collateral<'info>(
        ctx: Context<'_, '_, 'info, 'info, PhoenixTransferCollateral<'info>>,
        mint_address: Pubkey,
        claimant: Pubkey,
        amount: u64
    ) -> Result<()> {
        phoenix::phoenix_transfer_collateral(ctx, mint_address, claimant, amount)
    }

    /// **Initialize the conditional-orders collection account for the executor PDA.**
    ///
    /// Must be called once (idempotent) before using `phoenix_place_position_conditional_order`.
    /// `capacity`: maximum concurrent conditional orders (default: 8).
    ///
    /// See `phoenix::phoenix_create_conditional_orders_account` for full documentation.
    #[inline(never)]
    pub fn phoenix_create_conditional_orders_account<'info>(
        ctx: Context<'_, '_, 'info, 'info, PhoenixCreateConditionalOrdersAccount<'info>>,
        mint_address: Pubkey,
        claimant: Pubkey,
        capacity: u8
    ) -> Result<()> {
        phoenix::phoenix_create_conditional_orders_account(ctx, mint_address, claimant, capacity)
    }

    /// **Place an atomic bracket order (SL + TP) using the conditional-orders API.**
    ///
    /// Replaces two sequential `phoenix_place_stop_loss` calls with a single atomic instruction
    /// that avoids `PositionSequenceInvalidated` errors on mainnet.
    ///
    /// Set `has_greater = true` for a take-profit (TP) and `has_less = true` for a stop-loss (SL).
    /// `size_percent`: 1–100, percentage of position to close (use 100 for full close).
    ///
    /// See `phoenix::phoenix_place_position_conditional_order` for full documentation.
    #[inline(never)]
    pub fn phoenix_place_position_conditional_order<'info>(
        ctx: Context<'_, '_, 'info, 'info, PhoenixPlacePositionConditionalOrder<'info>>,
        mint_address: Pubkey,
        claimant: Pubkey,
        asset_id: u32,
        has_greater: bool,
        greater_trigger_price: u64,
        greater_execution_price: u64,
        greater_trade_side: u8,
        greater_order_kind: u8,
        has_less: bool,
        less_trigger_price: u64,
        less_execution_price: u64,
        less_trade_side: u8,
        less_order_kind: u8,
        size_percent: u8
    ) -> Result<()> {
        phoenix::phoenix_place_position_conditional_order(
            ctx,
            mint_address,
            claimant,
            asset_id,
            has_greater,
            greater_trigger_price,
            greater_execution_price,
            greater_trade_side,
            greater_order_kind,
            has_less,
            less_trigger_price,
            less_execution_price,
            less_trade_side,
            less_order_kind,
            size_percent
        )
    }

    /// **Atomically place a resting PostOnly limit order with attached TP/SL conditionals.**
    ///
    /// Solves the problem where `place_position_conditional_order` fails for resting
    /// limit orders (no position exists yet when the order is resting).
    ///
    /// See `phoenix::phoenix_place_limit_order_with_conditionals` for full documentation.
    #[inline(never)]
    pub fn phoenix_place_limit_order_with_conditionals<'info>(
        ctx: Context<'_, '_, 'info, 'info, PhoenixPlaceLimitOrderWithConditionals<'info>>,
        mint_address: Pubkey,
        claimant: Pubkey,
        order_packet_bytes: Vec<u8>,
        slot: u64,
        has_greater: bool,
        greater_trigger_price: u64,
        greater_execution_price: u64,
        greater_trade_side: u8,
        greater_order_kind: u8,
        has_less: bool,
        less_trigger_price: u64,
        less_execution_price: u64,
        less_trade_side: u8,
        less_order_kind: u8
    ) -> Result<()> {
        phoenix::phoenix_place_limit_order_with_conditionals(
            ctx,
            mint_address,
            claimant,
            order_packet_bytes,
            slot,
            has_greater,
            greater_trigger_price,
            greater_execution_price,
            greater_trade_side,
            greater_order_kind,
            has_less,
            less_trigger_price,
            less_execution_price,
            less_trade_side,
            less_order_kind
        )
    }

    /// **Cancel a conditional order from the collection by slot index.**
    ///
    /// `conditional_order_index`: 1–191, the slot index assigned at placement.
    /// `disable_first`: cancel the SL (lessTrigger) leg.
    /// `disable_second`: cancel the TP (greaterTrigger) leg.
    ///
    /// See `phoenix::phoenix_cancel_conditional_order` for full documentation.
    #[inline(never)]
    pub fn phoenix_cancel_conditional_order<'info>(
        ctx: Context<'_, '_, 'info, 'info, PhoenixCancelConditionalOrder<'info>>,
        mint_address: Pubkey,
        claimant: Pubkey,
        conditional_order_index: u8,
        disable_first: bool,
        disable_second: bool
    ) -> Result<()> {
        phoenix::phoenix_cancel_conditional_order(
            ctx,
            mint_address,
            claimant,
            conditional_order_index,
            disable_first,
            disable_second
        )
    }

    /// **Place a market close/reduce order — risk management before withdrawal.**
    ///
    /// Must be called before `phoenix_queue_withdraw` if an open position
    /// consumes more margin than the free `traderQuoteLotCollateral`. Only
    /// `place_market_order` data is accepted (immediate execution).
    ///
    /// See `phoenix::phoenix_close_position` for full documentation.
    #[inline(never)]
    pub fn phoenix_close_position<'info>(
        ctx: Context<'_, '_, 'info, 'info, PhoenixClosePosition<'info>>,
        mint_address: Pubkey,
        claimant: Pubkey,
        order_data: Vec<u8>
    ) -> Result<()> {
        phoenix::phoenix_close_position(ctx, mint_address, claimant, order_data)
    }

    /// **Wrap executor USDC → PhUSD 1:1 via EMBER deposit CPI.**
    ///
    /// The executor holds USDC (received from vault) and wraps it to PhUSD,
    /// ready for `phoenix_deposit_from_pool`.
    ///
    /// See `phoenix::phoenix_ember_wrap` for full documentation.
    #[inline(never)]
    pub fn phoenix_ember_wrap<'info>(
        ctx: Context<'_, '_, 'info, 'info, PhoenixEmberWrap<'info>>,
        mint_address: Pubkey,
        claimant: Pubkey,
        amount: u64
    ) -> Result<()> {
        phoenix::phoenix_ember_wrap(ctx, mint_address, claimant, amount)
    }

    /// Queue a USDC withdrawal from the vault's Phoenix account back to the vault ATA.
    ///
    /// After calling this, call `phoenix_ember_unwrap` (step 2, which atomically cranks
    /// the withdraw queue and converts PhUSD→USDC), then `phoenix_reissue_notes` (step 3).
    ///
    /// See `phoenix::phoenix_queue_withdraw` for full documentation.
    #[inline(never)]
    pub fn phoenix_queue_withdraw<'info>(
        ctx: Context<'_, '_, 'info, 'info, PhoenixQueueWithdraw<'info>>,
        mint_address: Pubkey,
        claimant: Pubkey,
        amount: u64,
        withdrawal_id: [u8; 32]
    ) -> Result<()> {
        phoenix::phoenix_queue_withdraw(ctx, mint_address, claimant, amount, withdrawal_id)
    }

    /// **Crank withdraw queue + convert vault's PhUSD back to USDC via EMBER (step 2 of exit flow).**
    ///
    /// Atomically cranks Phoenix's `consumeWithdrawQueue` (flushes PhUSD to executor ATA),
    /// then calls EMBER `withdraw` to burn PhUSD and return USDC to the vault.
    ///
    /// See `phoenix::phoenix_ember_unwrap` for full documentation.
    #[inline(never)]
    pub fn phoenix_ember_unwrap<'info>(
        ctx: Context<'_, '_, 'info, 'info, PhoenixEmberUnwrap<'info>>,
        mint_address: Pubkey,
        claimant: Pubkey,
        withdrawal_id: [u8; 32],
        amount: u64
    ) -> Result<()> {
        phoenix::phoenix_ember_unwrap(ctx, mint_address, claimant, withdrawal_id, amount)
    }

    /// **Register the pool vault as a Phoenix Eternal trader (one-time setup).**
    ///
    /// Must be called once before `phoenix_deposit_from_pool` or
    /// `phoenix_place_order` can be used for a USDC pool.
    ///
    /// See `phoenix::phoenix_register_pool_trader` for full documentation.
    #[inline(never)]
    pub fn phoenix_register_pool_trader<'info>(
        ctx: Context<'_, '_, 'info, 'info, PhoenixRegisterTrader<'info>>,
        mint_address: Pubkey,
        claimant: Pubkey,
        // 0 = Cross margin (max_positions=128), 1 = Isolated margin (max_positions=1)
        margin_type: u8
    ) -> Result<()> {
        phoenix::phoenix_register_pool_trader(ctx, mint_address, claimant, margin_type)
    }

    /// **Re-mint private notes after Phoenix exit — final step of the Phoenix round-trip.**
    ///
    /// `withdrawal_id` must match the one used in the preceding `phoenix_ember_unwrap`
    /// call so the correct per-exit `pending_reissue` PDA is found.
    ///
    /// See `phoenix::phoenix_reissue_notes` for full documentation.
    #[inline(never)]
    pub fn phoenix_reissue_notes(
        ctx: Context<PhoenixReissueNotes>,
        root: [u8; 32],
        input_tree_id: u16,
        output_tree_id: u16,
        amount: u64,
        ext_data_hash: [u8; 32],
        mint_address: Pubkey,
        input_nullifier_0: [u8; 32],
        input_nullifier_1: [u8; 32],
        output_commitment_0: [u8; 32],
        output_commitment_1: [u8; 32],
        withdrawal_id: [u8; 32],
        deadline: i64,
        ext_data: ExtData,
        proof: zk::TransactionProof,
        note_ciphers: Option<NoteCiphers>
    ) -> Result<()> {
        phoenix::phoenix_reissue_notes(
            ctx,
            root,
            input_tree_id,
            output_tree_id,
            amount,
            ext_data_hash,
            mint_address,
            input_nullifier_0,
            input_nullifier_1,
            output_commitment_0,
            output_commitment_1,
            withdrawal_id,
            deadline,
            ext_data,
            proof,
            note_ciphers
        )
    }

    // ---- Jupiter Perpetuals Integration ----

    /// ZK-verified USDC withdrawal → executor PDA funded →
    /// `createIncreasePositionMarketRequest` CPI (atomic).
    ///
    /// Fund step for native SOL pool jperp opens.
    /// Must immediately precede `jperp_open_position` in the same transaction.
    pub fn fund_native_jperp_open(
        ctx: Context<FundNativeJperpOpen>,
        mint_address: Pubkey,
        claimant: Pubkey,
        withdrawal_id: [u8; 32],
        deposit_amount: u64
    ) -> Result<()> {
        crate::perps::fund_native_jperp_open(
            ctx,
            mint_address,
            claimant,
            withdrawal_id,
            deposit_amount
        )
    }

    /// The executor PDA becomes the Jupiter Perps position owner; the user's
    /// wallet never appears on-chain. Jupiter's keeper settles the request.
    ///
    /// See `jupiter_perp::jperp_open_position` for full documentation.
    #[inline(never)]
    pub fn jperp_open_position<'info>(
        ctx: Context<'_, '_, 'info, 'info, JperpOpenPosition<'info>>,
        root: [u8; 32],
        input_tree_id: u16,
        output_tree_id: u16,
        deposit_amount: u64,
        ext_data_hash: [u8; 32],
        mint_address: Pubkey,
        claimant: Pubkey,
        input_nullifier_0: [u8; 32],
        input_nullifier_1: [u8; 32],
        output_commitment_0: [u8; 32],
        output_commitment_1: [u8; 32],
        withdrawal_id: [u8; 32],
        deadline: i64,
        ext_data: ExtData,
        proof: zk::TransactionProof,
        note_ciphers: Option<NoteCiphers>,
        size_usd_delta: u64,
        collateral_token_delta: u64,
        side: u8,
        price_slippage: u64,
        counter: u64
    ) -> Result<()> {
        perps::jperp_open_position(
            ctx,
            root,
            input_tree_id,
            output_tree_id,
            deposit_amount,
            ext_data_hash,
            mint_address,
            claimant,
            input_nullifier_0,
            input_nullifier_1,
            output_commitment_0,
            output_commitment_1,
            withdrawal_id,
            deadline,
            ext_data,
            proof,
            note_ciphers,
            size_usd_delta,
            collateral_token_delta,
            side,
            price_slippage,
            counter
        )
    }

    /// Create a TP or SL trigger on an open Jupiter Perps position.
    ///
    /// Calls `createDecreasePositionRequest2` with `Trigger` request type.
    /// Multiple triggers can coexist by using different `counter` values.
    ///
    /// See `jupiter_perp::jperp_set_tpsl` for full documentation.
    #[inline(never)]
    pub fn jperp_set_tpsl<'info>(
        ctx: Context<'_, '_, 'info, 'info, JperpSetTpsl<'info>>,
        mint_address: Pubkey,
        withdrawal_id: [u8; 32],
        collateral_usd_delta: u64,
        size_usd_delta: u64,
        trigger_price: u64,
        trigger_above_threshold: bool,
        entire_position: bool,
        counter: u64
    ) -> Result<()> {
        perps::jperp_set_tpsl(
            ctx,
            mint_address,
            withdrawal_id,
            collateral_usd_delta,
            size_usd_delta,
            trigger_price,
            trigger_above_threshold,
            entire_position,
            counter
        )
    }

    /// Update the trigger price or size on a pending TP/SL request.
    ///
    /// Calls `updateDecreasePositionRequest2`. The positionRequest PDA to update
    /// must be passed as remaining_accounts[4].
    ///
    /// See `jupiter_perp::jperp_update_tpsl` for full documentation.
    #[inline(never)]
    pub fn jperp_update_tpsl<'info>(
        ctx: Context<'_, '_, 'info, 'info, JperpUpdateTpsl<'info>>,
        mint_address: Pubkey,
        withdrawal_id: [u8; 32],
        size_usd_delta: u64,
        trigger_price: u64
    ) -> Result<()> {
        perps::jperp_update_tpsl(ctx, mint_address, withdrawal_id, size_usd_delta, trigger_price)
    }

    /// Create a market close (full or partial) on an open Jupiter Perps position.
    ///
    /// Calls `createDecreasePositionRequest2` with `Market` request type.
    /// Jupiter's keeper executes the close; proceeds arrive at the executor's
    /// receiving ATA and can then be re-minted via `jperp_reissue_notes`.
    ///
    /// See `jupiter_perp::jperp_close_position` for full documentation.
    #[inline(never)]
    pub fn jperp_close_position<'info>(
        ctx: Context<'_, '_, 'info, 'info, JperpClosePosition<'info>>,
        mint_address: Pubkey,
        withdrawal_id: [u8; 32],
        collateral_usd_delta: u64,
        size_usd_delta: u64,
        entire_position: bool,
        price_slippage: u64,
        counter: u64
    ) -> Result<()> {
        perps::jperp_close_position(
            ctx,
            mint_address,
            withdrawal_id,
            collateral_usd_delta,
            size_usd_delta,
            entire_position,
            price_slippage,
            counter
        )
    }

    /// Cancel a pending TP/SL trigger and reclaim its ~0.0051 SOL rent.
    ///
    /// CPIs Jupiter's `closePositionRequest2` on the owner-cancel path (executor
    /// signs as `owner`, keeper slot = program id / None), then sweeps the
    /// refunded rent back to the relayer. Call this for any trigger that will
    /// never fire — see `jupiter_perp::jperp_cancel_trigger` for the full flow.
    #[inline(never)]
    pub fn jperp_cancel_trigger<'info>(
        ctx: Context<'_, '_, 'info, 'info, JperpCancelTrigger<'info>>,
        mint_address: Pubkey,
        withdrawal_id: [u8; 32]
    ) -> Result<()> {
        perps::jperp_cancel_trigger(ctx, mint_address, withdrawal_id)
    }

    /// Transfer settled proceeds from executor ATA → vault, then ZK-deposit
    /// to re-mint private notes.
    ///
    /// The claimant (ephemeral key from the original deposit) must co-sign to
    /// prevent relayer theft. Supports partial reissues across multiple calls;
    /// reissued totals may exceed the original deposit when the position profits,
    /// since each reissue is backed by real USDC moved into the vault.
    ///
    /// See `jupiter_perp::jperp_reissue_notes` for full documentation.
    #[inline(never)]
    pub fn jperp_reissue_notes(
        ctx: Context<JperpReissueNotes>,
        root: [u8; 32],
        input_tree_id: u16,
        output_tree_id: u16,
        reissue_amount: u64,
        ext_data_hash: [u8; 32],
        mint_address: Pubkey,
        input_nullifier_0: [u8; 32],
        input_nullifier_1: [u8; 32],
        output_commitment_0: [u8; 32],
        output_commitment_1: [u8; 32],
        withdrawal_id: [u8; 32],
        deadline: i64,
        ext_data: ExtData,
        proof: zk::TransactionProof,
        note_ciphers: Option<NoteCiphers>
    ) -> Result<()> {
        perps::jperp_reissue_notes(
            ctx,
            root,
            input_tree_id,
            output_tree_id,
            reissue_amount,
            ext_data_hash,
            mint_address,
            input_nullifier_0,
            input_nullifier_1,
            output_commitment_0,
            output_commitment_1,
            withdrawal_id,
            deadline,
            ext_data,
            proof,
            note_ciphers
        )
    }

    /// Recover collateral stranded in the executor by a keeper-cancelled native-SOL open,
    /// backing the user's note directly from the executor's lamports (zero relayer float).
    /// See `jupiter_perp::jperp_recover_native`.
    #[inline(never)]
    pub fn jperp_recover_native(
        ctx: Context<JperpRecoverNative>,
        root: [u8; 32],
        input_tree_id: u16,
        output_tree_id: u16,
        recover_amount: u64,
        ext_data_hash: [u8; 32],
        mint_address: Pubkey,
        input_nullifier_0: [u8; 32],
        input_nullifier_1: [u8; 32],
        output_commitment_0: [u8; 32],
        output_commitment_1: [u8; 32],
        withdrawal_id: [u8; 32],
        deadline: i64,
        ext_data: ExtData,
        proof: zk::TransactionProof,
        note_ciphers: Option<NoteCiphers>
    ) -> Result<()> {
        perps::jperp_recover_native(
            ctx,
            root,
            input_tree_id,
            output_tree_id,
            recover_amount,
            ext_data_hash,
            mint_address,
            input_nullifier_0,
            input_nullifier_1,
            output_commitment_0,
            output_commitment_1,
            withdrawal_id,
            deadline,
            ext_data,
            proof,
            note_ciphers
        )
    }

    // ── Jupiter Prediction Market ────────────────────────────────────────────

    /// ZK withdrawal → ephemeral wallet funded for Jupiter Prediction trading.
    ///
    /// Nullifies USDC notes, routes funds to the ephemeral wallet's USDC ATA, and
    /// optionally funds the wallet with SOL for Jupiter API tx fees.  The actual
    /// Jupiter Prediction `CreateOrder` call is signed externally by the user with
    /// the ephemeral keypair after this instruction confirms.
    ///
    /// See `predictions::prediction_open` for full documentation.
    #[inline(never)]
    pub fn prediction_open<'info>(
        ctx: Context<'_, '_, 'info, 'info, PredictionOpen<'info>>,
        root: [u8; 32],
        input_tree_id: u16,
        output_tree_id: u16,
        deposit_amount: u64,
        ext_data_hash: [u8; 32],
        mint_address: Pubkey,
        claimant: Pubkey,
        input_nullifier_0: [u8; 32],
        input_nullifier_1: [u8; 32],
        output_commitment_0: [u8; 32],
        output_commitment_1: [u8; 32],
        withdrawal_id: [u8; 32],
        deadline: i64,
        ext_data: ExtData,
        proof: zk::TransactionProof,
        note_ciphers: Option<NoteCiphers>,
        sol_funding: u64
    ) -> Result<()> {
        predictions::prediction_open(
            ctx,
            root,
            input_tree_id,
            output_tree_id,
            deposit_amount,
            ext_data_hash,
            mint_address,
            claimant,
            input_nullifier_0,
            input_nullifier_1,
            output_commitment_0,
            output_commitment_1,
            withdrawal_id,
            deadline,
            ext_data,
            proof,
            note_ciphers,
            sol_funding
        )
    }

    /// Sweep settled prediction proceeds from ephemeral wallet → pool vault.
    ///
    /// The ephemeral keypair must co-sign as it is the USDC ATA authority.
    /// Uses the deposit ZK circuit to mint new private USDC notes.
    /// The `reissue_amount` may exceed the original deposit (prediction winnings).
    ///
    /// See `predictions::prediction_reissue` for full documentation.
    #[inline(never)]
    pub fn prediction_reissue<'info>(
        ctx: Context<'_, '_, 'info, 'info, PredictionReissue<'info>>,
        root: [u8; 32],
        input_tree_id: u16,
        output_tree_id: u16,
        reissue_amount: u64,
        ext_data_hash: [u8; 32],
        mint_address: Pubkey,
        input_nullifier_0: [u8; 32],
        input_nullifier_1: [u8; 32],
        output_commitment_0: [u8; 32],
        output_commitment_1: [u8; 32],
        withdrawal_id: [u8; 32],
        deadline: i64,
        ext_data: ExtData,
        proof: zk::TransactionProof,
        note_ciphers: Option<NoteCiphers>
    ) -> Result<()> {
        predictions::prediction_reissue(
            ctx,
            root,
            input_tree_id,
            output_tree_id,
            reissue_amount,
            ext_data_hash,
            mint_address,
            input_nullifier_0,
            input_nullifier_1,
            output_commitment_0,
            output_commitment_1,
            withdrawal_id,
            deadline,
            ext_data,
            proof,
            note_ciphers
        )
    }

    /// Withdraw private notes to an ephemeral wallet whose key is committed in the proof.
    #[inline(never)]
    pub fn ephemeral_withdraw<'info>(
        ctx: Context<'_, '_, 'info, 'info, PredictionOpen<'info>>,
        root: [u8; 32],
        input_tree_id: u16,
        output_tree_id: u16,
        deposit_amount: u64,
        ext_data_hash: [u8; 32],
        mint_address: Pubkey,
        claimant: Pubkey,
        input_nullifier_0: [u8; 32],
        input_nullifier_1: [u8; 32],
        output_commitment_0: [u8; 32],
        output_commitment_1: [u8; 32],
        withdrawal_id: [u8; 32],
        deadline: i64,
        ext_data: ExtData,
        proof: zk::TransactionProof,
        note_ciphers: Option<NoteCiphers>,
        sol_funding: u64
    ) -> Result<()> {
        predictions::prediction_open(
            ctx,
            root,
            input_tree_id,
            output_tree_id,
            deposit_amount,
            ext_data_hash,
            mint_address,
            claimant,
            input_nullifier_0,
            input_nullifier_1,
            output_commitment_0,
            output_commitment_1,
            withdrawal_id,
            deadline,
            ext_data,
            proof,
            note_ciphers,
            sol_funding
        )
    }

    /// Deposit proceeds from the ephemeral wallet back into the pool, minting fresh private
    /// notes. The ephemeral keypair co-signs (it is the ATA authority).
    #[inline(never)]
    pub fn ephemeral_deposit<'info>(
        ctx: Context<'_, '_, 'info, 'info, PredictionReissue<'info>>,
        root: [u8; 32],
        input_tree_id: u16,
        output_tree_id: u16,
        reissue_amount: u64,
        ext_data_hash: [u8; 32],
        mint_address: Pubkey,
        input_nullifier_0: [u8; 32],
        input_nullifier_1: [u8; 32],
        output_commitment_0: [u8; 32],
        output_commitment_1: [u8; 32],
        withdrawal_id: [u8; 32],
        deadline: i64,
        ext_data: ExtData,
        proof: zk::TransactionProof,
        note_ciphers: Option<NoteCiphers>
    ) -> Result<()> {
        predictions::prediction_reissue(
            ctx,
            root,
            input_tree_id,
            output_tree_id,
            reissue_amount,
            ext_data_hash,
            mint_address,
            input_nullifier_0,
            input_nullifier_1,
            output_commitment_0,
            output_commitment_1,
            withdrawal_id,
            deadline,
            ext_data,
            proof,
            note_ciphers
        )
    }
}

// ---- Helper Functions ----

/// Mark a nullifier as spent. Metadata is emitted via event.
#[inline(never)]
pub fn mark_nullifier_spent(
    marker: &mut Account<NullifierMarker>,
    nullifier_set: &mut Account<NullifierSet>,
    nullifier: [u8; 32],
    bump: u8,
    mint_address: Pubkey,
    tree_id: u16
) -> Result<()> {
    let timestamp = Clock::get()?.unix_timestamp;

    marker.is_spent = true;
    marker.bump = bump;

    nullifier_set.count = nullifier_set.count
        .checked_add(1)
        .ok_or(PrivacyError::ArithmeticOverflow)?;

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
#[inline(never)]
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
    token_program: &UncheckedAccount<'info>
) -> Result<()> {
    // Validate ext_data values are non-negative
    require!(ext_data.fee < (i64::MAX as u64), PrivacyError::InvalidFeeAmount);
    require!(ext_data.refund < (i64::MAX as u64), PrivacyError::InvalidPublicAmount);

    // Circuit convention: sumIns + publicAmount = sumOuts
    // - Positive publicAmount = DEPOSIT (adding to pool: 0 + amount = outputs)
    // - Negative publicAmount = WITHDRAWAL (removing from pool: inputs + negative = 0)

    // Determine if using SPL tokens or native SOL
    let is_token = is_token_mint(&config.mint_address);

    if public_amount > 0 {
        // DEPOSIT: user deposits public_amount lamports/tokens
        let deposit_amount = public_amount as u64;

        // For deposits, fee and refund should be zero
        require!(ext_data.fee == 0 && ext_data.refund == 0, PrivacyError::InvalidPublicAmount);

        // Check PrivacyConfig pool-specific limits
        require!(deposit_amount >= config.min_deposit_amount, PrivacyError::DepositBelowMinimum);
        require!(deposit_amount <= config.max_deposit_amount, PrivacyError::DepositLimitExceeded);

        if is_token {
            // SPL Token deposit: user -> vault ATA
            token::transfer(
                CpiContext::new(token_program.to_account_info(), token::Transfer {
                    from: user_token_account.to_account_info(),
                    to: vault_token_account.to_account_info(),
                    authority: relayer.to_account_info(),
                }),
                deposit_amount
            )?;
        } else {
            // Native SOL deposit
            anchor_lang::system_program::transfer(
                CpiContext::new(
                    system_program.to_account_info(),
                    anchor_lang::system_program::Transfer {
                        from: relayer.to_account_info(),
                        to: vault.to_account_info(),
                    }
                ),
                deposit_amount
            )?;
        }

        // Update TVL
        config.total_tvl = config.total_tvl
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
        let fee_plus_refund = fee.checked_add(refund).ok_or(PrivacyError::ArithmeticOverflow)?;
        require!(fee_plus_refund <= withdrawal_amount, PrivacyError::InvalidPublicAmount);

        // Calculate amount to recipient
        let to_recipient = withdrawal_amount
            .checked_sub(fee)
            .and_then(|x| x.checked_sub(refund))
            .ok_or(PrivacyError::ArithmeticOverflow)?;

        // Calculate minimum valid withdrawal amount to prevent fee bypass
        // Guard: fee_bps >= 1 is enforced at initialization and update, but defend-in-depth here.
        if config.fee_bps == 0 {
            return err!(PrivacyError::ArithmeticOverflow);
        }
        let min_valid_withdrawal = (config.min_withdrawal_fee as u128)
            .checked_mul(10_000)
            .and_then(|x| x.checked_div(config.fee_bps as u128))
            .and_then(|x| u64::try_from(x).ok())
            .ok_or(PrivacyError::ArithmeticOverflow)?;

        // Reject withdrawals too small for minimum fee - prevents fee evasion and timing attacks
        require!(
            withdrawal_amount >= min_valid_withdrawal,
            PrivacyError::WithdrawalTooSmallForMinFee
        );

        // Fee validation with error margin for timing attack protection
        // Use u128 for intermediate calculation to prevent overflow on large withdrawals
        let max_fee_u128 =
            (withdrawal_amount as u128)
                .checked_mul(config.fee_bps as u128)
                .ok_or(PrivacyError::ArithmeticOverflow)? / 10_000;

        // Ensure the result fits in u64 (should always be true since withdrawal_amount is u64)
        require!(max_fee_u128 <= (u64::MAX as u128), PrivacyError::ExcessiveFee);
        let max_fee = max_fee_u128 as u64;

        // Apply fee error margin: allow fees up to max_fee * (1 + margin)
        // This provides flexibility for timing attack resistance while capping maximum fee
        let max_fee_with_margin = max_fee
            .checked_mul((10_000u64).saturating_add(config.fee_error_margin_bps as u64))
            .map(|x| x / 10_000)
            .unwrap_or(max_fee);

        // At this point, max_fee >= min_withdrawal_fee is guaranteed by the check above
        // Enforce fee range: [min_withdrawal_fee, max_fee_with_margin]
        require!(
            fee >= config.min_withdrawal_fee && fee <= max_fee_with_margin,
            PrivacyError::InvalidFeeAmount
        );

        if is_token {
            // SPL Token withdrawal: vault ATA -> recipient/relayer ATAs
            // Deserialize vault token account to check balance
            let vault_token_data = deserialize_token_account(
                &vault_token_account.to_account_info()
            )?;

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
                    &[&[b"privacy_vault_v3", config.mint_address.as_ref(), &[vault.bump]]]
                ),
                to_recipient
            )?;

            // Transfer fee + refund to relayer
            let to_relayer = fee.checked_add(refund).ok_or(PrivacyError::ArithmeticOverflow)?;

            if to_relayer > 0 {
                token::transfer(
                    CpiContext::new_with_signer(
                        token_program.to_account_info(),
                        token::Transfer {
                            from: vault_token_account.to_account_info(),
                            to: relayer_token_account.to_account_info(),
                            authority: vault.to_account_info(),
                        },
                        &[&[b"privacy_vault_v3", config.mint_address.as_ref(), &[vault.bump]]]
                    ),
                    to_relayer
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
                .and_then(|x| x.checked_add(10_000_000)) // 0.01 SOL buffer
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
        config.total_tvl = config.total_tvl
            .checked_sub(withdrawal_amount)
            .ok_or(PrivacyError::ArithmeticOverflow)?;
    } else {
        // PRIVATE TRANSFER: public_amount == 0, no value crosses pool boundary
        //
        // Fee/refund must be zero because these fields control ON-CHAIN transfers from the vault.
        // Since no vault funds are accessed in private transfers, these must be zero.
        //
        // RELAYER INCENTIVES: For private transfers, relayer fees are handled WITHIN the note system:
        // - User consumes input notes (e.g., 10 SOL)
        // - User creates output note for recipient (e.g., 9.95 SOL)
        // - User creates output note for relayer as fee (e.g., 0.05 SOL)
        // This maintains privacy while providing economic incentives - the relayer receives
        // a private note they can later withdraw, not an on-chain payment.
        require!(
            ext_data.fee == 0 && ext_data.refund == 0,
            PrivacyError::InvalidPrivateTransferFee
        );
    }
    // Note: When public_amount == 0, no lamport/token movement occurs

    Ok(())
}

// ---- Events ----

/// Encrypted note data passed by the relayer so users can recover funds
/// from chain history alone if the off-chain note DB is lost.
/// `ephemeral_public_key`: fresh Curve25519 pubkey for ECDH — reveals nothing
/// `encrypted_blob`: NaCl secretbox of (blinding[32] || amount[8]); 40-byte
///   plaintext → 80-byte ciphertext (24-byte nonce + 16-byte MAC)
#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct NoteCiphers {
    pub note0_ephemeral_key: [u8; 32],
    pub note0_encrypted: [u8; 80],
    pub note0_view_tag: u8,
    pub note1_ephemeral_key: [u8; 32],
    pub note1_encrypted: [u8; 80],
    pub note1_view_tag: u8,
}

#[event]
pub struct CommitmentEvent {
    pub commitment: [u8; 32],
    pub leaf_index: u64,
    pub new_root: [u8; 32],
    pub timestamp: i64,
    pub mint_address: Pubkey,
    pub tree_id: u16,
    /// Ephemeral Curve25519 public key for ECDH — generated fresh per note
    pub ephemeral_public_key: [u8; 32],
    /// NaCl secretbox ciphertext of (blinding[32] || amount[8])
    /// Zero bytes when relayer passes None (tests / non-recovery mode)
    pub encrypted_blob: [u8; 80],
    /// sha256(X25519SharedSecret)[0] — one-byte scan filter; 0 when None
    pub view_tag: u8,
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
    #[msg("Relayer not found")]
    RelayerNotFound,
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
    #[msg(
        "Withdrawal amount too small: max fee based on fee_bps would be less than min_withdrawal_fee"
    )]
    WithdrawalTooSmallForMinFee,
    #[msg("Nullifier marker account does not correspond to zero nullifier for deposits")]
    InvalidNullifierMarkerForDeposit,
    #[msg("Token account delegation amount insufficient for deposit")]
    InsufficientDelegation,
    #[msg("Invalid swap program: must be Raydium CPMM or AMM")]
    InvalidSwapProgram,
    #[msg("Invalid remaining accounts: wrong count or ownership")]
    InvalidRemainingAccounts,
    #[msg("Jupiter swap requires additional routing accounts")]
    JupiterInsufficientAccounts,
    #[msg("Jupiter instruction data invalid or unsupported version")]
    JupiterInvalidInstruction,
    #[msg("Swap params mints do not match instruction mints")]
    InvalidSwapParams,
    #[msg("Swap program left tokens in source account; potential amount_in manipulation")]
    SwapLeftoverTokens,
    #[msg(
        "fund_native_source must be immediately followed by transact_swap in the same transaction"
    )]
    MissingTransactSwapInstruction,
    #[msg("Transaction deadline has expired")]
    DeadlineExpired,
    // ---- Phoenix Eternal errors ----
    #[msg("Phoenix integration requires a USDC pool (only USDC is accepted as Phoenix collateral)")]
    PhoenixInvalidPool,
    #[msg("Phoenix deposit: ext_data.recipient must equal the vault PDA")]
    PhoenixRecipientMustBeVault,
    #[msg("Phoenix CPI: insufficient or incorrect remaining_accounts")]
    PhoenixInvalidAccounts,
    #[msg("Phoenix order data is invalid or uses an unsupported instruction discriminator")]
    PhoenixInvalidOrderData,
    #[msg(
        "Phoenix slot cap exceeded: total unwrapped would exceed the amount queued for withdrawal via phoenix_queue_withdraw"
    )]
    SlotOverdraft,
    #[msg("Reissue claimant key does not match the one committed at deposit time")]
    InvalidClaimant,
    // ---- Jupiter Perpetuals errors ----
    #[msg("Jupiter Perps CPI: insufficient or incorrect remaining_accounts")]
    JperpInvalidAccounts,
    #[msg("Jupiter Perps open: ext_data.recipient must equal the executor PDA")]
    JperpRecipientMustBeExecutor,
    #[msg("Jupiter Perps side must be 1 (Long) or 2 (Short)")]
    JperpInvalidSide,
    #[msg("Jupiter Perps open: collateral_token_delta must equal deposit_amount")]
    JperpCollateralMismatch,
    #[msg("Jupiter Perps slot cap: reissue amount would exceed original deposit")]
    JperpSlotOverdraft,
    // ---- Jupiter Prediction errors ----
    #[msg("Prediction open: ext_data.recipient must equal the ephemeral wallet (claimant)")]
    PredictionRecipientMustBeClaimant,
    // Appended at the END so existing error numbers are not renumbered (relayer maps codes).
    #[msg("Jupiter Perps recover: relayer rent sweep exceeds JPERP_RECOVER_RENT_CAP")]
    JperpRecoverRentExceeded,
    #[msg("Field element is not in canonical form (>= BN254 Fr)")]
    NonCanonicalFieldElement,
}

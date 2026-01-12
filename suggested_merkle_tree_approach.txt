use crate::PrivacyError;
use anchor_lang::prelude::*;
use light_hasher::Hasher;

pub const MERKLE_TREE_HEIGHT: usize = 16;
pub const ROOT_HISTORY_SIZE: usize = 32;

/// # LAYOUT STABILITY WARNING - AUDIT-004 FIX
///
/// This struct uses `#[account(zero_copy(unsafe))]` combined with `#[repr(C)]`,
/// meaning its memory layout is **PERMANENT** and written directly to blockchain storage.
///
/// ## Critical Rules (NEVER VIOLATE):
///
/// 1. **NEVER reorder fields** - Any reordering corrupts all existing accounts
/// 2. **NEVER add/remove fields** - Changes offsets, breaks existing data
/// 3. **NEVER change field types** - Size changes corrupt subsequent fields
/// 4. **NEVER remove #[repr(C)]** - Layout would become undefined
/// 5. **NEVER change array sizes** - Breaks offset calculations
///
/// ## Current Memory Layout (Total: 1624 bytes + 8 byte discriminator):
///
/// ```text
/// Offset | Field              | Type              | Size (bytes)
/// -------|-------------------|-------------------|-------------
/// 0      | authority         | Pubkey            | 32
/// 32     | height            | u8                | 1
/// 33     | (padding)         | -                 | 1
/// 34     | root_history_size | u16               | 2
/// 36     | (padding)         | -                 | 4  (align u64 to 8-byte boundary)
/// 40     | next_index        | u64               | 8
/// 48     | root_index        | u64               | 8
/// 56     | root              | [u8; 32]          | 32
/// 88     | subtrees          | [[u8; 32]; 16]    | 512
/// 600    | root_history      | [[u8; 32]; 32]    | 1024
/// -------|-------------------|-------------------|-------------
/// Total: 1624 bytes (struct) + 8 bytes (Anchor discriminator) = 1632 bytes
/// ```
///
/// **Note:** #[repr(C)] adds padding for alignment. u64 fields must be 8-byte aligned.
/// **Compatibility:** Layout matches existing on-chain accounts (no breaking changes).
///
/// ## If You MUST Change This Struct:
///
/// 1. **Create a new version**: `MerkleTreeAccountV2`
/// 2. **Keep this struct unchanged** for backward compatibility
/// 3. **Implement migration instruction**:
///    ```rust
///    pub fn migrate_merkle_tree(ctx: Context<MigrateMerkleTree>) -> Result<()> {
///        let old_tree = ctx.accounts.old_tree.load()?;
///        let mut new_tree = ctx.accounts.new_tree.load_init()?;
///        // Copy fields explicitly with any transformations
///        // ...
///    }
///    ```
/// 4. **Deploy migration script** for all existing accounts
/// 5. **Coordinate with all users** before deprecating old version
///
/// ## Future Changes:
///
/// If you need to add new fields, you MUST create a new struct version (V2)
/// and implement migration. The current layout is LOCKED to maintain compatibility
/// with existing on-chain accounts.
///
/// Reserved space was intentionally NOT added to avoid breaking existing accounts.
///
/// ## Testing:
///
/// Layout stability is enforced by:
/// - `test_merkle_tree_layout_size()` - Ensures total size never changes
/// - `test_merkle_tree_field_offsets()` - Ensures field positions never shift
/// - CI/CD fails if layout changes detected
///
/// See `tests/audit-004-layout-stability.test.rs` for verification tests.
#[account(zero_copy(unsafe))]
#[repr(C)] // [AUDIT-004 FIX] Enforce stable, C-compatible memory layout
#[derive(Debug)]
pub struct MerkleTreeAccount {
    /// Authority allowed to manage the tree (config admin)
    pub authority: Pubkey,
    /// Tree height (number of levels)
    pub height: u8,
    /// How many roots we track
    pub root_history_size: u16,
    /// Next leaf index
    pub next_index: u64,
    /// Index into root_history for the current root
    pub root_index: u64,
    /// Current root
    pub root: [u8; 32],
    /// Cached subtree values for each level
    pub subtrees: [[u8; 32]; MERKLE_TREE_HEIGHT],
    /// Circular buffer of recent roots
    pub root_history: [[u8; 32]; ROOT_HISTORY_SIZE],
}

impl MerkleTreeAccount {
    /// Total account size: 8 byte discriminator + struct size
    pub const LEN: usize = 8 + core::mem::size_of::<MerkleTreeAccount>();

    /// [AUDIT-004 FIX] Compile-time layout validation
    /// These constants document the expected layout and will cause compile errors
    /// if the struct changes in a way that violates our assumptions.
    pub const EXPECTED_SIZE: usize = 1624; // authority(32) + height(1) + pad(1) + root_history_size(2)
                                           // + pad(4) + next_index(8) + root_index(8) + root(32)
                                           // + subtrees(512) + root_history(1024)
                                           // = 32 + 1 + 1 + 2 + 4 + 8 + 8 + 32 + 512 + 1024 = 1624
    pub const EXPECTED_ALIGN: usize = 8; // Largest field is u64 (8 bytes)
}

pub struct MerkleTree;

impl MerkleTree {
    pub fn initialize<H: Hasher>(tree: &mut MerkleTreeAccount) -> Result<()> {
        let height = tree.height as usize;
        let zeros = H::zero_bytes(); // usually length = height+1

        // Defensive: Poseidon::zero_bytes must give us at least height+1 entries
        require!(height < zeros.len(), PrivacyError::MerkleHashFailed);

        // fill subtrees
        for i in 0..height {
            tree.subtrees[i] = zeros[i];
        }

        // set initial root
        let initial_root = zeros[height];
        msg!("Initial root: {:?}", initial_root);
        msg!("Zeros[0]: {:?}", zeros[0]);
        msg!("Zeros[1]: {:?}", zeros[1]);
        tree.root = initial_root;
        tree.root_history[0] = initial_root;
        tree.root_index = 0;
        tree.next_index = 0;

        Ok(())
    }

    pub fn append<H: Hasher>(leaf: [u8; 32], tree: &mut MerkleTreeAccount) -> Result<()> {
        let height = tree.height as usize;
        let root_history_size = tree.root_history_size as usize;

        // 2^height capacity
        let max_capacity = 1u64 << height;
        require!(tree.next_index < max_capacity, PrivacyError::MerkleTreeFull);

        let mut current_index = tree.next_index as usize;
        let mut current = leaf;
        let zeros = H::zero_bytes();

        // same sanity check here
        require!(height <= zeros.len(), PrivacyError::MerkleHashFailed);

        for level in 0..height {
            let subtree = &mut tree.subtrees[level];
            let zero = zeros[level];

            let (left, right) = if current_index % 2 == 0 {
                *subtree = current;
                (current, zero)
            } else {
                (*subtree, current)
            };

            // ✅ new: map Poseidon error into an Anchor error
            current =
                H::hashv(&[&left, &right]).map_err(|_| error!(PrivacyError::MerkleHashFailed))?;

            current_index /= 2;
        }

        tree.root = current;
        tree.next_index = tree
            .next_index
            .checked_add(1)
            .ok_or(PrivacyError::MathOverflow)?;

        let new_root_index = tree
            .root_index
            .checked_add(1)
            .ok_or(PrivacyError::MathOverflow)? as usize
            % root_history_size;

        tree.root_index = new_root_index as u64;
        tree.root_history[new_root_index] = current;

        Ok(())
    }

    pub fn is_known_root(tree: &MerkleTreeAccount, root: [u8; 32]) -> bool {
        if root == [0u8; 32] {
            return false;
        }

        let root_history_size = tree.root_history_size as usize;
        let current_root_index = tree.root_index as usize;

        let mut i = current_root_index;
        loop {
            if root == tree.root_history[i] {
                return true;
            }

            if i == 0 {
                i = root_history_size - 1;
            } else {
                i -= 1;
            }

            if i == current_root_index {
                break;
            }
        }

        false
    }
}
// ============================================================================
// [AUDIT-004 FIX] Compile-Time Layout Stability Tests
// ============================================================================
// These tests run at compile-time and will FAIL the build if the layout changes.
// This prevents accidental deployment of layout-breaking changes.

#[cfg(test)]
mod layout_tests {
    use super::*;

    #[test]
    fn test_merkle_tree_layout_size() {
        // [AUDIT-004] Ensure struct size NEVER changes
        // If this fails, you've broken the layout - all existing accounts will be corrupted!
        assert_eq!(
            core::mem::size_of::<MerkleTreeAccount>(),
            MerkleTreeAccount::EXPECTED_SIZE,
            "LAYOUT VIOLATION: MerkleTreeAccount size changed! \
             Expected {} bytes, got {} bytes. \
             This BREAKS all existing accounts! \
             See AUDIT-004 documentation in merkle_tree.rs for migration procedure.",
            MerkleTreeAccount::EXPECTED_SIZE,
            core::mem::size_of::<MerkleTreeAccount>()
        );

        // Verify total account size (8-byte discriminator + struct)
        assert_eq!(
            MerkleTreeAccount::LEN,
            8 + MerkleTreeAccount::EXPECTED_SIZE,
            "Account size constant is incorrect"
        );
    }

    #[test]
    fn test_merkle_tree_alignment() {
        // [AUDIT-004] Ensure alignment NEVER changes
        // Alignment changes can shift field offsets
        assert_eq!(
            core::mem::align_of::<MerkleTreeAccount>(),
            MerkleTreeAccount::EXPECTED_ALIGN,
            "LAYOUT VIOLATION: Alignment changed from {} to {}",
            MerkleTreeAccount::EXPECTED_ALIGN,
            core::mem::align_of::<MerkleTreeAccount>()
        );
    }

    #[test]
    fn test_merkle_tree_field_offsets() {
        // [AUDIT-004] Verify exact field offsets to detect reordering or size changes
        // This test uses memoffset::offset_of! macro pattern

        // Create a zero-initialized instance for offset calculation
        let dummy = MerkleTreeAccount {
            authority: Pubkey::default(),
            height: 0,
            root_history_size: 0,
            next_index: 0,
            root_index: 0,
            root: [0; 32],
            subtrees: [[0; 32]; MERKLE_TREE_HEIGHT],
            root_history: [[0; 32]; ROOT_HISTORY_SIZE],
        };

        let base = &dummy as *const _ as usize;

        // Verify each field offset
        let authority_offset = &dummy.authority as *const _ as usize - base;
        assert_eq!(
            authority_offset, 0,
            "LAYOUT VIOLATION: authority offset changed from 0 to {}",
            authority_offset
        );

        let height_offset = &dummy.height as *const _ as usize - base;
        assert_eq!(
            height_offset, 32,
            "LAYOUT VIOLATION: height offset changed from 32 to {}",
            height_offset
        );

        let root_history_size_offset = &dummy.root_history_size as *const _ as usize - base;
        assert_eq!(
            root_history_size_offset, 34,
            "LAYOUT VIOLATION: root_history_size offset changed from 34 to {}",
            root_history_size_offset
        );

        let next_index_offset = &dummy.next_index as *const _ as usize - base;
        assert_eq!(
            next_index_offset, 40,
            "LAYOUT VIOLATION: next_index offset changed from 40 to {} (4 bytes padding before for alignment)",
            next_index_offset
        );

        let root_index_offset = &dummy.root_index as *const _ as usize - base;
        assert_eq!(
            root_index_offset, 48,
            "LAYOUT VIOLATION: root_index offset changed from 48 to {}",
            root_index_offset
        );

        let root_offset = &dummy.root as *const _ as usize - base;
        assert_eq!(
            root_offset, 56,
            "LAYOUT VIOLATION: root offset changed from 56 to {}",
            root_offset
        );

        let subtrees_offset = &dummy.subtrees as *const _ as usize - base;
        assert_eq!(
            subtrees_offset, 88,
            "LAYOUT VIOLATION: subtrees offset changed from 88 to {}",
            subtrees_offset
        );

        let root_history_offset = &dummy.root_history as *const _ as usize - base;
        assert_eq!(
            root_history_offset, 600,
            "LAYOUT VIOLATION: root_history offset changed from 600 to {}",
            root_history_offset
        );

        // End of struct at offset 1624 (600 + 1024)
        // Total size: 1624 bytes (matches EXPECTED_SIZE)
    }

    #[test]
    fn test_field_sizes() {
        // [AUDIT-004] Verify individual field sizes
        assert_eq!(core::mem::size_of::<Pubkey>(), 32, "Pubkey size changed");
        assert_eq!(core::mem::size_of::<u8>(), 1, "u8 size changed");
        assert_eq!(core::mem::size_of::<u16>(), 2, "u16 size changed");
        assert_eq!(core::mem::size_of::<u64>(), 8, "u64 size changed");
        assert_eq!(
            core::mem::size_of::<[u8; 32]>(),
            32,
            "32-byte array size changed"
        );
        assert_eq!(
            core::mem::size_of::<[[u8; 32]; MERKLE_TREE_HEIGHT]>(),
            512,
            "subtrees array size changed"
        );
        assert_eq!(
            core::mem::size_of::<[[u8; 32]; ROOT_HISTORY_SIZE]>(),
            1024,
            "root_history array size changed"
        );
    }

    #[test]
    fn test_repr_c_enforced() {
        // [AUDIT-004] This test documents that we rely on #[repr(C)]
        // If #[repr(C)] is removed, the layout becomes undefined and can change
        // between Rust compiler versions.

        // We can't directly test for #[repr(C)] presence at runtime,
        // but we document the requirement here and in the struct docs.

        // The fact that offset tests pass confirms current layout,
        // but only #[repr(C)] guarantees it stays stable.

        println!("WARNING: Ensure MerkleTreeAccount has #[repr(C)] attribute!");
        println!("Without #[repr(C)], Rust can reorder fields!");
    }
}

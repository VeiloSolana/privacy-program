use crate::PrivacyError;
use anchor_lang::prelude::*;
use light_hasher::Hasher;

pub const MERKLE_TREE_HEIGHT: usize = 26;
pub const ROOT_HISTORY_SIZE: usize = 256;

/// Layout tests verify 9107 bytes total with 1-byte alignment. Breaking this corrupts all accounts.
#[account(zero_copy(unsafe))]
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
    /// Expected size - DO NOT CHANGE (breaks all existing accounts)
    pub const EXPECTED_SIZE: usize = 9107;

    /// Expected alignment (packed layout = 1 byte)
    pub const EXPECTED_ALIGN: usize = 1;

    pub const LEN: usize = 8 + core::mem::size_of::<MerkleTreeAccount>();
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
        let mut checks = 0;
        loop {
            if root == tree.root_history[i] {
                return true;
            }

            checks += 1;
            if checks > root_history_size {
                break;
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

#[cfg(test)]
mod tests {
    use super::*;
    use light_hasher::Hasher;
    use light_hasher::Poseidon;

    #[test]
    fn print_zero_bytes() {
        let zeros = Poseidon::zero_bytes();
        println!("Rust Level 0 zero: {:?}", zeros[0]);
        println!("Rust Level 1 zero: {:?}", zeros[1]);
        if zeros.len() > 26 {
            println!("Rust Level 26 zero: {:?}", zeros[26]);
        }
    }

    // Layout stability tests - verifies struct size/offsets never change.
    #[test]
    fn test_merkle_tree_layout_size() {
        assert_eq!(
            core::mem::size_of::<MerkleTreeAccount>(),
            MerkleTreeAccount::EXPECTED_SIZE,
            "LAYOUT VIOLATION: MerkleTreeAccount size changed! \
             Expected {} bytes, got {} bytes. \
             This BREAKS all existing accounts! \
             See comments in merkle_tree.rs for migration procedure.",
            MerkleTreeAccount::EXPECTED_SIZE,
            core::mem::size_of::<MerkleTreeAccount>()
        );

        assert_eq!(MerkleTreeAccount::LEN, 8 + MerkleTreeAccount::EXPECTED_SIZE);
    }

    #[test]
    fn test_merkle_tree_alignment() {
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
        use core::ptr;
        let base = core::ptr::null::<MerkleTreeAccount>() as usize;

        // Calculate offsets using addr_of! which works with packed structs
        let authority_offset = unsafe {
            ptr::addr_of!((*core::ptr::null::<MerkleTreeAccount>()).authority) as usize - base
        };
        assert_eq!(
            authority_offset, 0,
            "LAYOUT VIOLATION: authority offset changed from 0 to {}",
            authority_offset
        );

        let height_offset = unsafe {
            ptr::addr_of!((*core::ptr::null::<MerkleTreeAccount>()).height) as usize - base
        };
        assert_eq!(
            height_offset, 32,
            "LAYOUT VIOLATION: height offset changed from 32 to {}",
            height_offset
        );

        let root_history_size_offset = unsafe {
            ptr::addr_of!((*core::ptr::null::<MerkleTreeAccount>()).root_history_size) as usize
                - base
        };
        assert_eq!(
            root_history_size_offset, 33,
            "LAYOUT VIOLATION: root_history_size offset changed from 33 to {}",
            root_history_size_offset
        );

        let next_index_offset = unsafe {
            ptr::addr_of!((*core::ptr::null::<MerkleTreeAccount>()).next_index) as usize - base
        };
        assert_eq!(
            next_index_offset, 35,
            "LAYOUT VIOLATION: next_index offset changed from 35 to {}",
            next_index_offset
        );

        let root_index_offset = unsafe {
            ptr::addr_of!((*core::ptr::null::<MerkleTreeAccount>()).root_index) as usize - base
        };
        assert_eq!(
            root_index_offset, 43,
            "LAYOUT VIOLATION: root_index offset changed from 43 to {}",
            root_index_offset
        );

        let root_offset = unsafe {
            ptr::addr_of!((*core::ptr::null::<MerkleTreeAccount>()).root) as usize - base
        };
        assert_eq!(
            root_offset, 51,
            "LAYOUT VIOLATION: root offset changed from 51 to {}",
            root_offset
        );

        let subtrees_offset = unsafe {
            ptr::addr_of!((*core::ptr::null::<MerkleTreeAccount>()).subtrees) as usize - base
        };
        assert_eq!(
            subtrees_offset, 83,
            "LAYOUT VIOLATION: subtrees offset changed from 83 to {}",
            subtrees_offset
        );

        let root_history_offset = unsafe {
            ptr::addr_of!((*core::ptr::null::<MerkleTreeAccount>()).root_history) as usize - base
        };
        assert_eq!(
            root_history_offset, 915,
            "LAYOUT VIOLATION: root_history offset changed from 915 to {}",
            root_history_offset
        );
    }

    #[test]
    fn test_field_sizes() {
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
            32 * MERKLE_TREE_HEIGHT,
            "subtrees array size changed (26 * 32 = 832 bytes)"
        );
        assert_eq!(
            core::mem::size_of::<[[u8; 32]; ROOT_HISTORY_SIZE]>(),
            32 * ROOT_HISTORY_SIZE,
            "root_history array size changed (256 * 32 = 8192 bytes)"
        );
    }

    #[test]
    fn test_layout_documentation() {
        println!("\n=== MerkleTreeAccount Layout ===");
        println!(
            "Size: {} bytes, Align: {} byte",
            core::mem::size_of::<MerkleTreeAccount>(),
            core::mem::align_of::<MerkleTreeAccount>()
        );
        println!("Packed layout (no padding): authority(0) height(32) root_history_size(33) next_index(35) root_index(43) root(51) subtrees(83) root_history(915)");
    }
}

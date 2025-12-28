use anchor_lang::prelude::*;
use light_hasher::Hasher;
use crate::PrivacyError;

pub const MERKLE_TREE_HEIGHT: usize = 16;
pub const ROOT_HISTORY_SIZE: usize = 32;

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
    pub const LEN: usize = 8 + core::mem::size_of::<MerkleTreeAccount>();
}

pub struct MerkleTree;

impl MerkleTree {
    pub fn initialize<H: Hasher>(tree: &mut MerkleTreeAccount) -> Result<()> {
        let height = tree.height as usize;
        let zeros = H::zero_bytes(); // usually length = height+1

        // Defensive: Poseidon::zero_bytes must give us at least height+1 entries
        require!(
            height < zeros.len(),
            PrivacyError::MerkleHashFailed
        );

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

    pub fn append<H: Hasher>(
        leaf: [u8; 32],
        tree: &mut MerkleTreeAccount,
    ) -> Result<()> {
        let height = tree.height as usize;
        let root_history_size = tree.root_history_size as usize;

        // 2^height capacity
        let max_capacity = 1u64 << height;
        require!(
            tree.next_index < max_capacity,
            PrivacyError::MerkleTreeFull
        );

        let mut current_index = tree.next_index as usize;
        let mut current = leaf;
        let zeros = H::zero_bytes();

        // same sanity check here
        require!(
            height <= zeros.len(),
            PrivacyError::MerkleHashFailed
        );

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
            current = H::hashv(&[&left, &right])
                .map_err(|_| error!(PrivacyError::MerkleHashFailed))?;

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
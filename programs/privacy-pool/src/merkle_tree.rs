use anchor_lang::prelude::*;
use light_hasher::Hasher;
use crate::PrivacyError;

pub const MERKLE_TREE_HEIGHT: usize = 16;
pub const ROOT_HISTORY_SIZE: usize = 100;

#[account]
pub struct MerkleTreeAccount {
    pub authority: Pubkey,
    pub next_index: u64,
    pub subtrees: [[u8; 32]; MERKLE_TREE_HEIGHT],
    pub root: [u8; 32],
    pub root_history: [[u8; 32]; ROOT_HISTORY_SIZE],
    pub root_index: u64,
    pub height: u8,
    pub root_history_size: u8,
    pub bump: u8,
    pub _padding: [u8; 5],
}

pub struct MerkleTree;

impl MerkleTree {
    pub fn initialize<H: Hasher>(tree_account: &mut MerkleTreeAccount) -> Result<()> {
        let height = tree_account.height as usize;
        let zero_bytes = H::zero_bytes();

        for i in 0..height {
            tree_account.subtrees[i] = zero_bytes[i];
        }

        let initial_root = zero_bytes[height];
        tree_account.root = initial_root;
        tree_account.root_history[0] = initial_root;
        tree_account.root_index = 0;

        Ok(())
    }

    pub fn append<H: Hasher>(
        leaf: [u8; 32],
        tree_account: &mut MerkleTreeAccount,
    ) -> Result<Vec<[u8; 32]>> {
        let height = tree_account.height as usize;
        let root_history_size = tree_account.root_history_size as usize;

        let max_capacity = 1u64 << height;
        require!(
            tree_account.next_index < max_capacity,
            PrivacyError::NullifierTableFull // or define a dedicated MerkleTreeFull
        );

        let mut current_index = tree_account.next_index as usize;
        let mut current_level_hash = leaf;
        let mut proof: Vec<[u8; 32]> = vec![[0u8; 32]; height];

        for level in 0..height {
            let subtree = &mut tree_account.subtrees[level];
            let zero_byte = H::zero_bytes()[level];

            let (left, right);

            if current_index % 2 == 0 {
                left = current_level_hash;
                right = zero_byte;
                *subtree = current_level_hash;
                proof[level] = right;
            } else {
                left = *subtree;
                right = current_level_hash;
                proof[level] = left;
            }

            current_level_hash = H::hashv(&[&left, &right])
                .map_err(|_| error!(PrivacyError::VerifyFailed))?;
            current_index /= 2;
        }

        tree_account.root = current_level_hash;
        tree_account.next_index = tree_account
            .next_index
            .checked_add(1)
            .ok_or(PrivacyError::MathOverflow)?;

        let new_root_index = (tree_account.root_index as usize + 1) % root_history_size;
        tree_account.root_index = new_root_index as u64;
        tree_account.root_history[new_root_index] = current_level_hash;

        Ok(proof)
    }

    pub fn is_known_root(tree_account: &MerkleTreeAccount, root: [u8; 32]) -> bool {
        if root == [0u8; 32] {
            return false;
        }

        let size = tree_account.root_history_size as usize;
        if size == 0 {
            return false;
        }

        let current = tree_account.root_index as usize;
        let mut i = current;

        loop {
            if root == tree_account.root_history[i] {
                return true;
            }

            if i == 0 {
                i = size - 1;
            } else {
                i -= 1;
            }

            if i == current {
                break;
            }
        }

        false
    }
}
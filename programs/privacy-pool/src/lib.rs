use anchor_lang::prelude::*;

declare_id!("G7m7QCf2m6VsaDs7GJC9wMmxCiWxmAjKN6BhakkWYi32");

// --- parameters ---

/// Depth of the off-chain Merkle tree you maintain
const NOTE_TREE_DEPTH: u8 = 24;

/// Sliding window of recent roots stored on-chain
const MAX_ROOTS: usize = 64;

/// How many nullifiers we remember on-chain
const MAX_NULLIFIERS: usize = 1024;

// --- program ---

#[program]
pub mod privacy_pool {
    use super::*;

    /// One-time init: create global note tree & nullifier registry PDAs
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let tree = &mut ctx.accounts.note_tree;
        tree.bump = ctx.bumps.note_tree;
        tree.depth = NOTE_TREE_DEPTH;
        tree.next_index = 0;
        tree.current_root = [0u8; 32];
        tree.roots = [[0u8; 32]; MAX_ROOTS];
        tree.root_count = 0;

        let nulls = &mut ctx.accounts.nullifiers;
        nulls.bump = ctx.bumps.nullifiers;
        nulls.count = 0;
        nulls.values = [[0u8; 32]; MAX_NULLIFIERS];

        Ok(())
    }

    /// Append a new Merkle root (computed off-chain).
    ///
    /// Off-chain:
    /// - maintain the Merkle tree of commitments
    /// - after inserting a note, compute `new_root`
    /// - call `publish_note(new_root)` to advance on-chain root window
    pub fn publish_note(ctx: Context<PublishNote>, new_root: [u8; 32]) -> Result<()> {
        let tree = &mut ctx.accounts.note_tree;

        // These are just leaf indexes; actual tree is off-chain
        require!(
            tree.next_index < (1u32 << tree.depth),
            PrivacyError::TreeFull
        );

        // sliding-window root buffer
        let slot = (tree.root_count as usize) % MAX_ROOTS;
        tree.roots[slot] = new_root;
        tree.current_root = new_root;
        tree.root_count = tree
            .root_count
            .checked_add(1)
            .ok_or(PrivacyError::ArithmeticOverflow)?;
        let idx = tree.next_index;
        tree.next_index = tree
            .next_index
            .checked_add(1)
            .ok_or(PrivacyError::ArithmeticOverflow)?;

        emit!(NotePublished {
            root: new_root,
            index: idx,
        });

        Ok(())
    }

    /// Spend a note:
    /// - Off-chain zk proof proves:
    ///   * commitment is in Merkle tree (membership)
    ///   * caller knows secret for that commitment
    ///   * nullifier = H(secret, salt) (same as in proof)
    /// - On-chain:
    ///   * root must be in known roots
    ///   * nullifier must not be used yet
    ///   * then we mark nullifier as used
    ///
    /// `proof` is currently unused placeholder.
    pub fn verify_and_nullify(
        ctx: Context<VerifyAndNullify>,
        root: [u8; 32],
        nullifier: [u8; 32],
        _proof: Vec<u8>,
    ) -> Result<()> {
        let tree = &ctx.accounts.note_tree;
        let nulls = &mut ctx.accounts.nullifiers;

        // 1) root must be known (within sliding window)
        let mut found = false;
        let max = core::cmp::min(tree.root_count as usize, MAX_ROOTS);
        for i in 0..max {
            if tree.roots[i] == root {
                found = true;
                break;
            }
        }
        require!(found, PrivacyError::UnknownRoot);

        // 2) nullifier must not be used yet
        for i in 0..nulls.count as usize {
            if nulls.values[i] == nullifier {
                return err!(PrivacyError::NullifierAlreadyUsed);
            }
        }

        // 3) mark nullifier as used
        require!(
            (nulls.count as usize) < nulls.values.len(),
            PrivacyError::NullifierSetFull
        );

        // take a snapshot of count first to avoid overlapping borrows
        let idx = nulls.count as usize;
        nulls.values[idx] = nullifier;
        nulls.count = nulls.count + 1;

        emit!(NullifierUsed { nullifier });

        Ok(())
    }
}

// --- accounts ---

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = payer,
        seeds = [b"note_tree"],
        bump,
        space = 8 + NoteTree::SIZE
    )]
    pub note_tree: Account<'info, NoteTree>,

    #[account(
        init,
        payer = payer,
        seeds = [b"nullifiers"],
        bump,
        space = 8 + NullifierRegistry::SIZE
    )]
    pub nullifiers: Account<'info, NullifierRegistry>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct PublishNote<'info> {
    #[account(
        mut,
        seeds = [b"note_tree"],
        bump = note_tree.bump,
    )]
    pub note_tree: Account<'info, NoteTree>,

    /// Who can append roots (for now: any signer; later: pool admin)
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct VerifyAndNullify<'info> {
    #[account(
        seeds = [b"note_tree"],
        bump = note_tree.bump,
    )]
    pub note_tree: Account<'info, NoteTree>,

    #[account(
        mut,
        seeds = [b"nullifiers"],
        bump = nullifiers.bump,
    )]
    pub nullifiers: Account<'info, NullifierRegistry>,

    /// Relayer / caller who pays tx fees
    pub relayer: Signer<'info>,
}

// --- state ---

#[account]
pub struct NoteTree {
    pub bump: u8,
    pub depth: u8,
    pub next_index: u32,
    pub current_root: [u8; 32],
    pub roots: [[u8; 32]; MAX_ROOTS],
    pub root_count: u32,
}

impl NoteTree {
    pub const SIZE: usize =
        1 + // bump
        1 + // depth
        4 + // next_index
        32 + // current_root
        (32 * MAX_ROOTS) + // roots
        4; // root_count
}

#[account]
pub struct NullifierRegistry {
    pub bump: u8,
    pub count: u32,
    pub values: [[u8; 32]; MAX_NULLIFIERS],
}

impl NullifierRegistry {
    pub const SIZE: usize =
        1 + // bump
        4 + // count
        (32 * MAX_NULLIFIERS); // values
}

// --- events ---

#[event]
pub struct NotePublished {
    pub root: [u8; 32],
    pub index: u32,
}

#[event]
pub struct NullifierUsed {
    pub nullifier: [u8; 32],
}

// --- errors ---

#[error_code]
pub enum PrivacyError {
    #[msg("Merkle tree is full")]
    TreeFull,
    #[msg("Unknown Merkle root")]
    UnknownRoot,
    #[msg("Nullifier already used")]
    NullifierAlreadyUsed,
    #[msg("Nullifier set full")]
    NullifierSetFull,
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
}
use anchor_lang::prelude::*;

declare_id!("G7m7QCf2m6VsaDs7GJC9wMmxCiWxmAjKN6BhakkWYi32");

#[program]
pub mod privacy_pool {
    use super::*;

    /// Publish a new secret note:
    /// - `commitment_bytes`: hash of the note (value, blinding, etc.)
    /// - `owner_hint`: can be real recipient pubkey or Pubkey::default()
    /// - `ciphertext`: encrypted envelope for off-chain decryption
    pub fn publish_note(
        ctx: Context<PublishNote>,
        commitment_bytes: [u8; 32],
        owner_hint: Pubkey,
        ciphertext: Vec<u8>,
    ) -> Result<()> {
        let note = &mut ctx.accounts.note;

        note.author = ctx.accounts.sender.key();
        note.owner_hint = owner_hint;
        note.commitment = commitment_bytes;
        note.ciphertext = ciphertext;
        note.nullified = false;
        note.created_at_slot = Clock::get()?.slot;

        emit!(NotePublished {
            note: ctx.accounts.note.key(),
            commitment: commitment_bytes,
            owner_hint,
            author: ctx.accounts.sender.key(),
        });

        Ok(())
    }

    /// Mark a nullifier as used.
    /// Later you'll likely combine this with zk-proof verification.
    pub fn register_nullifier(
        ctx: Context<RegisterNullifier>,
        nullifier_bytes: [u8; 32],
    ) -> Result<()> {
        let record = &mut ctx.accounts.nullifier;

        require!(!record.used, ZkError::NullifierAlreadyUsed);

        record.nullifier = nullifier_bytes;
        record.used = true;

        emit!(NullifierRegistered { nullifier: nullifier_bytes });

        Ok(())
    }
}

// === Accounts ===

#[derive(Accounts)]
#[instruction(commitment_bytes: [u8; 32])]
pub struct PublishNote<'info> {
    /// PDA that holds this note:
    /// seeds = ["note", commitment_bytes]
    #[account(
        init,
        payer = sender,
        seeds = [b"note".as_ref(), &commitment_bytes],
        bump,
        space = 8 + NoteAccount::SIZE
    )]
    pub note: Account<'info, NoteAccount>,

    #[account(mut)]
    pub sender: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(nullifier_bytes: [u8; 32])]
pub struct RegisterNullifier<'info> {
    /// PDA that records the nullifier:
    /// seeds = ["nullifier", nullifier_bytes]
    #[account(
        init,
        payer = payer,
        seeds = [b"nullifier".as_ref(), &nullifier_bytes],
        bump,
        space = 8 + NullifierAccount::SIZE
    )]
    pub nullifier: Account<'info, NullifierAccount>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

// === State ===

#[account]
pub struct NoteAccount {
    pub author: Pubkey,         // who published the note
    pub owner_hint: Pubkey,     // optional (Pubkey::default if none)
    pub commitment: [u8; 32],   // zk commitment to secret note
    pub nullified: bool,        // optional: whether this specific note is known-spent
    pub created_at_slot: u64,   // for ordering / proving freshness
    pub ciphertext: Vec<u8>,    // encrypted envelope
}

impl NoteAccount {
    // Upper bound on ciphertext size (bytes) we allow in this account.
    pub const MAX_CIPHERTEXT_LEN: usize = 512;

    // Layout:
    // author (32) + owner_hint (32) + commitment (32) + nullified (1)
    // + created_at_slot (8) + ciphertext vec header (4) + data (MAX)
    pub const SIZE: usize =
        32 + 32 + 32 + 1 + 8 + 4 + Self::MAX_CIPHERTEXT_LEN;
}

#[account]
pub struct NullifierAccount {
    pub nullifier: [u8; 32],
    pub used: bool,
}

impl NullifierAccount {
    pub const SIZE: usize = 32 + 1;
}

// === Events ===

#[event]
pub struct NotePublished {
    pub note: Pubkey,
    pub commitment: [u8; 32],
    pub owner_hint: Pubkey,
    pub author: Pubkey,
}

#[event]
pub struct NullifierRegistered {
    pub nullifier: [u8; 32],
}

// === Errors ===

#[error_code]
pub enum ZkError {
    #[msg("Nullifier already used")]
    NullifierAlreadyUsed,
}
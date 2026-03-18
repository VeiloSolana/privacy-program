use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions::{
    load_current_index_checked,
    load_instruction_at_checked,
};
use sha2::{ Sha256, Digest };
use anchor_lang::solana_program::{ instruction::Instruction, program::invoke_signed };
use anchor_spl::associated_token::get_associated_token_address;
use anchor_spl::token::{ self, CloseAccount, Transfer, SyncNative };

use crate::zk::{ verify_swap_transaction_groth16, SwapProof };
use crate::{
    ExtData,
    MerkleTree,
    PoseidonHasher,
    PrivacyError,
    TransactSwap,
    FundNativeSource,
    is_token_mint,
};

/// Ephemeral PDA that holds tokens during swap, created and closed atomically
#[account]
pub struct SwapExecutor {
    pub source_mint: Pubkey,
    pub dest_mint: Pubkey,
    pub nullifier: [u8; 32],
    pub bump: u8,
    /// Swap amount stored by fund_native_source for validation in transact_swap.
    /// Zero when executor was created directly in transact_swap (relayer-float path).
    pub swap_amount: u64,
    /// 1 when executor was pre-funded by fund_native_source (vault already debited).
    /// 0 for the single-instruction relayer-float path (backward compatible).
    pub is_prefunded: u8,
    /// Relayer who created this executor — only they may call reclaim_stale_executor.
    pub relayer: Pubkey,
}

impl SwapExecutor {
    pub const LEN: usize = 8 + 32 + 32 + 32 + 1 + 8 + 1 + 32;
}

/// Swap parameters committed to in the ZK proof
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SwapParams {
    pub min_amount_out: u64,
    pub deadline: i64,
    pub source_mint: Pubkey,
    pub dest_mint: Pubkey,
    /// Amount of destination tokens the user commits to receiving.
    /// Included in swapParamsHash — cryptographically binds the ZK circuit's
    /// destAmount to the on-chain vault deposit, preventing an attacker from
    /// encoding an inflated destination note while receiving a tiny swap output.
    pub dest_amount: u64,
    /// SHA-256 hash of the raw swap instruction data (swap_data).
    /// Binds the exact DEX instruction bytes into the ZK proof so the relayer
    /// cannot substitute different swap_data (e.g. 0% slippage) after the user
    /// has generated their proof.  Set to [0u8;32] for CPMM/AMM swaps, which
    /// already enforce dex_min_out by direct instruction decoding.
    pub swap_data_hash: [u8; 32],
}

impl SwapParams {
    /// Reduce 32-byte value modulo BN254 Fr field
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
        let offset = 32 - reduced_bytes.len();
        result[offset..].copy_from_slice(&reduced_bytes);
        result
    }

    pub fn hash(&self) -> Result<[u8; 32]> {
        use light_hasher::Hasher;

        // Reduce mints to field elements (pubkeys may exceed Fr modulus)
        let source_mint_bytes = Self::reduce_to_field(self.source_mint.to_bytes());
        let dest_mint_bytes = Self::reduce_to_field(self.dest_mint.to_bytes());

        let mut min_out_bytes = [0u8; 32];
        min_out_bytes[24..].copy_from_slice(&self.min_amount_out.to_be_bytes());

        let mut deadline_bytes = [0u8; 32];
        deadline_bytes[24..].copy_from_slice(&self.deadline.to_be_bytes());

        let hash1 = PoseidonHasher::hashv(&[&source_mint_bytes, &dest_mint_bytes]).map_err(|_|
            error!(PrivacyError::MerkleHashFailed)
        )?;

        let mut dest_amount_bytes = [0u8; 32];
        dest_amount_bytes[24..].copy_from_slice(&self.dest_amount.to_be_bytes());

        let hash2 = PoseidonHasher::hashv(
            &[&min_out_bytes, &deadline_bytes, &dest_amount_bytes]
        ).map_err(|_| error!(PrivacyError::MerkleHashFailed))?;

        PoseidonHasher::hashv(&[&hash1, &hash2]).map_err(|_| error!(PrivacyError::MerkleHashFailed))
    }
}

/// Public inputs for swap ZK proof
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SwapPublicInputs {
    pub source_root: [u8; 32],
    pub swap_params_hash: [u8; 32],
    pub ext_data_hash: [u8; 32],
    pub source_mint: Pubkey,
    pub dest_mint: Pubkey,
    pub input_nullifiers: [[u8; 32]; 2],
    pub output_commitments: [[u8; 32]; 2],
    pub swap_amount: u64,
}

/// Solana ordering rule satisfied because:
///   - Anchor init pre-flights (create_account + initialize_account CPIs) run BEFORE the
///     function body  →  CPIs first
///   - Function body contains ONLY raw lamport edits  →  raw edits last
///
/// This instruction must be the FIRST instruction in an atomic tx whose SECOND instruction
/// is `transact_swap`.  Atomicity guarantees the vault debit reverts if the swap fails.
pub fn fund_native_source(
    ctx: Context<FundNativeSource>,
    source_mint: Pubkey,
    dest_mint: Pubkey,
    input_nullifier_0: [u8; 32],
    swap_amount: u64
) -> Result<()> {
    // Must be a native SOL pool (mint == Pubkey::default())
    require!(!crate::is_token_mint(&source_mint), PrivacyError::InvalidMintAddress);

    // Relayer must be whitelisted in the source pool
    require!(
        ctx.accounts.source_config.is_relayer(&ctx.accounts.relayer.key()),
        PrivacyError::RelayerNotAllowed
    );

    require!(swap_amount > 0, PrivacyError::InvalidPublicAmount);

    // Anchor discriminator = sha256("global:transact_swap")[0..8]
    let transact_swap_disc: [u8; 8] = Sha256::digest(b"global:transact_swap")[..8]
        .try_into()
        .map_err(|_| error!(PrivacyError::MissingTransactSwapInstruction))?;

    let ix_sysvar = ctx.accounts.instructions_sysvar.to_account_info();
    let current_idx = load_current_index_checked(&ix_sysvar)? as usize;
    let next_ix = load_instruction_at_checked(current_idx + 1, &ix_sysvar).map_err(|_|
        error!(PrivacyError::MissingTransactSwapInstruction)
    )?;

    require_keys_eq!(next_ix.program_id, crate::ID, PrivacyError::MissingTransactSwapInstruction);
    require!(
        next_ix.data.len() >= 8 && next_ix.data[..8] == transact_swap_disc,
        PrivacyError::MissingTransactSwapInstruction
    );

    let vault_ai = ctx.accounts.source_vault.to_account_info();
    let rent_exempt_min = anchor_lang::solana_program::rent::Rent
        ::get()?
        .minimum_balance(vault_ai.data_len());
    require!(
        vault_ai.lamports() >= swap_amount + rent_exempt_min,
        PrivacyError::InsufficientFundsForWithdrawal
    );

    // Populate executor fields before the raw edits so they are readable by transact_swap.
    let executor = &mut ctx.accounts.executor;
    executor.source_mint = source_mint;
    executor.dest_mint = dest_mint;
    executor.nullifier = input_nullifier_0;
    executor.bump = ctx.bumps.executor;
    executor.swap_amount = swap_amount;
    executor.is_prefunded = 1;
    executor.relayer = ctx.accounts.relayer.key();

    // ── Pure raw lamport transfer: vault → executor_source_token ─────────────────────────
    // This is the ONLY code in the function body; no CPIs appear here.
    // Anchor's init pre-flights (above) are the CPIs; raw edits come after them.
    **vault_ai.try_borrow_mut_lamports()? = vault_ai
        .lamports()
        .checked_sub(swap_amount)
        .ok_or(PrivacyError::ArithmeticOverflow)?;

    **ctx.accounts.executor_source_token.to_account_info().try_borrow_mut_lamports()? =
        ctx.accounts.executor_source_token
            .to_account_info()
            .lamports()
            .checked_add(swap_amount)
            .ok_or(PrivacyError::ArithmeticOverflow)?;

    Ok(())
}

/// Atomic cross-pool swap: source pool → DEX → destination pool
pub fn transact_swap<'info>(
    ctx: Context<'_, '_, 'info, 'info, TransactSwap<'info>>,
    proof: SwapProof,
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
    ext_data: ExtData
) -> Result<()> {
    // Prevents arbitrary CPI to malicious programs
    require!(
        ctx.accounts.swap_program.key() == crate::RAYDIUM_CPMM_PROGRAM_ID ||
            ctx.accounts.swap_program.key() == crate::RAYDIUM_AMM_PROGRAM_ID ||
            ctx.accounts.swap_program.key() == crate::JUPITER_PROGRAM_ID,
        PrivacyError::InvalidSwapProgram
    );

    // Validate pools and mints
    require!(
        ctx.accounts.source_config.mint_address == source_mint,
        PrivacyError::InvalidMintAddress
    );
    require!(ctx.accounts.dest_config.mint_address == dest_mint, PrivacyError::InvalidMintAddress);
    require!(source_mint != dest_mint, PrivacyError::InvalidMintAddress);

    // Validate tree IDs are within bounds before proof verification
    require!(source_tree_id < ctx.accounts.source_config.num_trees, PrivacyError::InvalidTreeId);
    require!(dest_tree_id < ctx.accounts.dest_config.num_trees, PrivacyError::InvalidTreeId);

    // Check relayer is whitelisted in BOTH source and dest pools
    // This prevents relayers authorized only for one pool from facilitating
    // swaps across pool boundaries they shouldn't access
    require!(
        ctx.accounts.source_config.is_relayer(&ctx.accounts.relayer.key()),
        PrivacyError::RelayerNotAllowed
    );
    require!(
        ctx.accounts.dest_config.is_relayer(&ctx.accounts.relayer.key()),
        PrivacyError::RelayerNotAllowed
    );

    let clock = Clock::get()?;
    require!(clock.unix_timestamp <= swap_params.deadline, PrivacyError::InvalidPublicAmount);

    // Ensure swap_params mints match instruction mints so the ZK-committed hash
    // binds to the actual swap direction.
    require!(swap_params.source_mint == source_mint, PrivacyError::InvalidSwapParams);
    require!(swap_params.dest_mint == dest_mint, PrivacyError::InvalidSwapParams);

    let input_nullifiers = [input_nullifier_0, input_nullifier_1];
    let output_commitments = [output_commitment_0, output_commitment_1];

    require!(input_nullifiers[0] != input_nullifiers[1], PrivacyError::DuplicateNullifiers);
    require!(output_commitments[0] != output_commitments[1], PrivacyError::DuplicateCommitments);

    let zero = [0u8; 32];
    require!(
        input_nullifiers[0] != zero && input_nullifiers[1] != zero,
        PrivacyError::ZeroNullifier
    );
    require!(
        output_commitments[0] != zero && output_commitments[1] != zero,
        PrivacyError::ZeroCommitment
    );

    let swap_params_hash: [u8; 32] = swap_params.hash()?;
    let ext_data_hash_val = ext_data.hash()?;

    let public_inputs = SwapPublicInputs {
        source_root,
        swap_params_hash,
        ext_data_hash: ext_data_hash_val,
        source_mint,
        dest_mint,
        input_nullifiers,
        output_commitments,
        swap_amount,
    };

    verify_swap_transaction_groth16(proof, &public_inputs)?;

    // Verify root is known
    let source_tree = ctx.accounts.source_tree.load()?;
    require!(MerkleTree::is_known_root(&*source_tree, source_root), PrivacyError::UnknownRoot);

    // Upfront capacity check for both trees
    let source_max_capacity = 1u64 << (source_tree.height as u64);
    let source_remaining = source_max_capacity.saturating_sub(source_tree.next_index);
    require!(source_remaining >= 1, PrivacyError::MerkleTreeFull);
    drop(source_tree);

    let dest_tree = ctx.accounts.dest_tree.load()?;
    let dest_max_capacity = 1u64 << (dest_tree.height as u64);
    let dest_remaining = dest_max_capacity.saturating_sub(dest_tree.next_index);
    require!(dest_remaining >= 1, PrivacyError::MerkleTreeFull);
    drop(dest_tree);

    require!(!ctx.accounts.source_nullifier_marker_0.is_spent, PrivacyError::NullifierAlreadyUsed);
    require!(!ctx.accounts.source_nullifier_marker_1.is_spent, PrivacyError::NullifierAlreadyUsed);

    // Mark nullifiers as spent
    crate::mark_nullifier_spent(
        &mut ctx.accounts.source_nullifier_marker_0,
        &mut ctx.accounts.source_nullifiers,
        input_nullifiers[0],
        ctx.bumps.source_nullifier_marker_0,
        source_mint,
        source_tree_id
    )?;
    crate::mark_nullifier_spent(
        &mut ctx.accounts.source_nullifier_marker_1,
        &mut ctx.accounts.source_nullifiers,
        input_nullifiers[1],
        ctx.bumps.source_nullifier_marker_1,
        source_mint,
        source_tree_id
    )?;

    let executor = &mut ctx.accounts.executor;
    let is_prefunded = executor.is_prefunded;

    if is_prefunded == 0 {
        executor.source_mint = source_mint;
        executor.dest_mint = dest_mint;
        executor.nullifier = input_nullifiers[0];
        executor.bump = ctx.bumps.executor;
        executor.swap_amount = swap_amount;
        executor.is_prefunded = 0;
        executor.relayer = ctx.accounts.relayer.key();
    } else {
        // Pre-initialized by fund_native_source — verify fields are consistent with this proof
        require!(executor.source_mint == source_mint, PrivacyError::InvalidSwapParams);
        require!(executor.dest_mint == dest_mint, PrivacyError::InvalidSwapParams);
        require!(executor.nullifier == input_nullifiers[0], PrivacyError::InvalidSwapParams);
        // swap_amount is cross-checked later inside the source_is_native block
    }

    // Transfer from source vault to executor
    require!(swap_amount > 0, PrivacyError::InvalidPublicAmount);

    let source_is_native = !is_token_mint(&source_mint);

    let source_vault_seeds: &[&[u8]] = &[
        b"privacy_vault_v3",
        source_mint.as_ref(),
        &[ctx.accounts.source_config.vault_bump],
    ];

    if source_is_native {
        if executor.is_prefunded == 1 {
            require!(executor.swap_amount == swap_amount, PrivacyError::InvalidSwapParams);

            token::sync_native(
                CpiContext::new(ctx.accounts.token_program.to_account_info(), SyncNative {
                    account: ctx.accounts.executor_source_token.to_account_info(),
                })
            )?;
        } else {
            let vault_ai = ctx.accounts.source_vault.to_account_info();
            let rent_exempt_min = anchor_lang::solana_program::rent::Rent
                ::get()?
                .minimum_balance(vault_ai.data_len());
            require!(
                vault_ai.lamports() >= swap_amount + rent_exempt_min,
                PrivacyError::InsufficientFundsForWithdrawal
            );
            require!(
                ctx.accounts.relayer.lamports() >= swap_amount,
                PrivacyError::InsufficientFundsForWithdrawal
            );

            anchor_lang::system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.to_account_info(),
                    anchor_lang::system_program::Transfer {
                        from: ctx.accounts.relayer.to_account_info(),
                        to: ctx.accounts.executor_source_token.to_account_info(),
                    }
                ),
                swap_amount
            )?;

            token::sync_native(
                CpiContext::new(ctx.accounts.token_program.to_account_info(), SyncNative {
                    account: ctx.accounts.executor_source_token.to_account_info(),
                })
            )?;
        }
    } else {
        // Validate source vault token account is the canonical ATA
        let expected_ata = get_associated_token_address(
            &ctx.accounts.source_vault.key(),
            &source_mint
        );
        require!(
            ctx.accounts.source_vault_token_account.key() == expected_ata,
            PrivacyError::InvalidMintAddress
        );

        // Validate vault has sufficient balance before transfer
        let vault_token_data = crate::deserialize_token_account(
            &ctx.accounts.source_vault_token_account.to_account_info()
        )?;
        require!(
            vault_token_data.amount >= swap_amount,
            PrivacyError::InsufficientFundsForWithdrawal
        );

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.source_vault_token_account.to_account_info(),
                    to: ctx.accounts.executor_source_token.to_account_info(),
                    authority: ctx.accounts.source_vault.to_account_info(),
                },
                &[source_vault_seeds]
            ),
            swap_amount
        )?;
    }

    // Update source pool TVL (decrease by swap_amount)
    ctx.accounts.source_config.total_tvl = ctx.accounts.source_config.total_tvl
        .checked_sub(swap_amount)
        .ok_or(PrivacyError::ArithmeticOverflow)?;

    // CPI to Swap Program (Jupiter / Raydium)
    let relayer_key = ctx.accounts.relayer.key();
    let executor_seeds: &[&[u8]] = &[
        b"swap_executor",
        source_mint.as_ref(),
        dest_mint.as_ref(),
        input_nullifiers[0].as_ref(),
        relayer_key.as_ref(),
        &[executor.bump],
    ];

    let remaining = &ctx.remaining_accounts;

    // Detect generic Swap Program type based on Instruction Discriminator
    // Raydium CPMM: 8-byte discriminator (0x8fbe5adac41e33de for swap_base_input)
    // Raydium AMM V4: 1-byte discriminator (0x09 for swap_base_in)
    let is_cpmm =
        swap_data.len() >= 8 &&
        swap_data[0] == 0x8f &&
        swap_data[1] == 0xbe &&
        swap_data[2] == 0x5a &&
        swap_data[3] == 0xda;

    let is_amm = !is_cpmm && swap_data.len() >= 1 && swap_data[0] == 9;

    // Detect Jupiter V6 "route" instruction
    let is_jupiter =
        !is_cpmm &&
        !is_amm &&
        swap_data.len() >= 8 &&
        (swap_data[0..8] == [0xe5, 0x17, 0xcb, 0x97, 0x7a, 0xe3, 0xad, 0x2a] || // Route
            swap_data[0..8] == [0xc1, 0x20, 0x9b, 0x33, 0x41, 0xd6, 0x9c, 0x81] || // SharedAccountsRoute
            swap_data[0..8] == [0xd0, 0x33, 0xef, 0x97, 0x7b, 0x2b, 0xed, 0x5c] || // ExactOutRoute
            swap_data[0..8] == [0xb0, 0xd1, 0x69, 0xa8, 0x9a, 0x7d, 0x45, 0x3e]); // SharedAccountsExactOutRoute

    if is_cpmm {
        require!(swap_data.len() >= 24, PrivacyError::InvalidPublicAmount);
        // Enforce DEX-level minimum_amount_out matches ZK-committed value (defense-in-depth).
        // CPMM swap_base_input layout: [8-byte discriminator][8-byte amount_in][8-byte minimum_amount_out]
        let dex_min_out = u64::from_le_bytes(
            swap_data[16..24].try_into().map_err(|_| error!(PrivacyError::InvalidPublicAmount))?
        );
        require!(dex_min_out >= swap_params.min_amount_out, PrivacyError::InvalidPublicAmount);
        require!(remaining.len() >= 8, PrivacyError::InvalidRemainingAccounts);

        // CPMM account layout in remaining_accounts:
        // [0] = authority (PDA derived from pool_state)
        // [1] = config (owned by CPMM)
        // [2] = pool_state (owned by CPMM)
        // [3] = token_vault_0 (owned by Token Program)
        // [4] = token_vault_1 (owned by Token Program)
        // [5] = source_mint
        // [6] = dest_mint
        // [7] = observation_state (owned by CPMM)

        // Validate mints match expected - ensures swap is for intended token pair
        // (CPMM will validate all other account ownership/derivations)
        require!(
            remaining[5].key() == source_mint || remaining[6].key() == source_mint,
            PrivacyError::InvalidMintAddress
        );
        require!(
            remaining[5].key() == dest_mint || remaining[6].key() == dest_mint,
            PrivacyError::InvalidMintAddress
        );

        // Build CPMM swap instruction accounts
        let cpmm_accounts = vec![
            AccountMeta::new_readonly(executor.key(), true),
            AccountMeta::new_readonly(remaining[0].key(), false),
            AccountMeta::new_readonly(remaining[1].key(), false),
            AccountMeta::new(remaining[2].key(), false),
            AccountMeta::new(ctx.accounts.executor_source_token.key(), false),
            AccountMeta::new(ctx.accounts.executor_dest_token.key(), false),
            AccountMeta::new(remaining[3].key(), false),
            AccountMeta::new(remaining[4].key(), false),
            AccountMeta::new_readonly(ctx.accounts.token_program.key(), false),
            AccountMeta::new_readonly(ctx.accounts.token_program.key(), false),
            AccountMeta::new_readonly(remaining[5].key(), false),
            AccountMeta::new_readonly(remaining[6].key(), false),
            AccountMeta::new(remaining[7].key(), false)
        ];

        let swap_ix = Instruction {
            program_id: ctx.accounts.swap_program.key(),
            accounts: cpmm_accounts,
            data: swap_data.clone(),
        };

        msg!("Raydium CPMM: Executing Swap...");

        let account_infos = &[
            executor.to_account_info(),
            remaining[0].to_account_info(),
            remaining[1].to_account_info(),
            remaining[2].to_account_info(),
            ctx.accounts.executor_source_token.to_account_info(),
            ctx.accounts.executor_dest_token.to_account_info(),
            remaining[3].to_account_info(),
            remaining[4].to_account_info(),
            ctx.accounts.token_program.to_account_info(),
            remaining[5].to_account_info(),
            remaining[6].to_account_info(),
            remaining[7].to_account_info(),
            ctx.accounts.swap_program.to_account_info(),
        ];

        invoke_signed(&swap_ix, account_infos, &[executor_seeds])?;
    } else if is_amm {
        // Raydium AMM V4 Swap
        // Accounts layout in remaining_accounts:
        // [0] = Amm Id (owned by AMM program)
        // [1] = Amm Authority (PDA derived from Amm Id)
        // [2] = Amm Open Orders (owned by OpenBook)
        // [3] = Amm Target Orders (owned by AMM program)
        // [4] = Pool Coin Token Account (owned by Token program)
        // [5] = Pool Pc Token Account (owned by Token program)
        // [6] = Serum/OpenBook Program
        // [7] = Serum Market (owned by OpenBook)
        // [8] = Serum Bids (owned by OpenBook)
        // [9] = Serum Asks (owned by OpenBook)
        // [10] = Serum Event Queue (owned by OpenBook)
        // [11] = Serum Coin Vault (owned by Token program)
        // [12] = Serum Pc Vault (owned by Token program)
        // [13] = Serum Vault Signer (PDA)

        require!(remaining.len() >= 14, PrivacyError::InvalidRemainingAccounts);
        // Enforce DEX-level minimum_amount_out matches ZK-committed value (defense-in-depth).
        // AMM V4 swap_base_in layout: [1-byte discriminator][8-byte amount_in][8-byte minimum_amount_out]
        require!(swap_data.len() >= 17, PrivacyError::InvalidPublicAmount);
        let dex_amount_in = u64::from_le_bytes(
            swap_data[1..9].try_into().map_err(|_| error!(PrivacyError::InvalidPublicAmount))?
        );
        require!(dex_amount_in == swap_amount, PrivacyError::InvalidSwapParams);
        let dex_min_out = u64::from_le_bytes(
            swap_data[9..17].try_into().map_err(|_| error!(PrivacyError::InvalidPublicAmount))?
        );
        require!(dex_min_out >= swap_params.min_amount_out, PrivacyError::InvalidPublicAmount);

        // Validate Serum/OpenBook Program ID - this is the critical check
        // (AMM will validate all other account ownership/derivations internally)
        require!(
            remaining[6].key() == crate::OPENBOOK_PROGRAM_ID,
            PrivacyError::InvalidRemainingAccounts
        );

        let amm_accounts = vec![
            AccountMeta::new_readonly(ctx.accounts.token_program.key(), false), // 0
            AccountMeta::new(remaining[0].key(), false), // 1: Amm Id
            AccountMeta::new_readonly(remaining[1].key(), false), // 2: Amm Authority
            AccountMeta::new(remaining[2].key(), false), // 3: Open Orders
            AccountMeta::new(remaining[3].key(), false), // 4: Target Orders
            AccountMeta::new(remaining[4].key(), false), // 5: Pool Coin
            AccountMeta::new(remaining[5].key(), false), // 6: Pool Pc
            AccountMeta::new_readonly(remaining[6].key(), false), // 7: Serum Program
            AccountMeta::new(remaining[7].key(), false), // 8: Serum Market
            AccountMeta::new(remaining[8].key(), false), // 9: Bids
            AccountMeta::new(remaining[9].key(), false), // 10: Asks
            AccountMeta::new(remaining[10].key(), false), // 11: Event Queue
            AccountMeta::new(remaining[11].key(), false), // 12: Coin Vault
            AccountMeta::new(remaining[12].key(), false), // 13: Pc Vault
            AccountMeta::new_readonly(remaining[13].key(), false), // 14: Vault Signer
            AccountMeta::new(ctx.accounts.executor_source_token.key(), false), // 15
            AccountMeta::new(ctx.accounts.executor_dest_token.key(), false), // 16
            AccountMeta::new_readonly(executor.key(), true) // 17
        ];

        let swap_ix = Instruction {
            program_id: ctx.accounts.swap_program.key(),
            accounts: amm_accounts,
            data: swap_data.clone(),
        };

        msg!("Raydium AMM: Executing Swap...");

        // Construct account_infos including all dependencies
        let mut account_infos = vec![
            ctx.accounts.token_program.to_account_info(),
            ctx.accounts.executor_source_token.to_account_info(),
            ctx.accounts.executor_dest_token.to_account_info(),
            executor.to_account_info(),
            ctx.accounts.swap_program.to_account_info()
        ];

        for acc in remaining.iter().take(14) {
            account_infos.push(acc.to_account_info());
        }

        invoke_signed(&swap_ix, &account_infos, &[executor_seeds])?;
    } else if is_jupiter {
        // Jupiter V6 Route Swap
        msg!("Jupiter V6: Executing Route Swap...");

        // Security: Verify Jupiter Event Authority matches expected constant
        require!(
            ctx.accounts.jupiter_event_authority.key() == crate::JUPITER_EVENT_AUTHORITY,
            PrivacyError::Unauthorized
        );

        msg!("Jupiter Event Authority: {}", ctx.accounts.jupiter_event_authority.key());

        let mut jupiter_accounts = Vec::new();
        let mut account_infos = Vec::new();

        let is_shared_accounts =
            swap_data[0..8] == [0xc1, 0x20, 0x9b, 0x33, 0x41, 0xd6, 0x9c, 0x81] ||
            swap_data[0..8] == [0xb0, 0xd1, 0x69, 0xa8, 0x9a, 0x7d, 0x45, 0x3e];

        if is_shared_accounts {
            // SharedAccountsRoute Layout:
            // 0: TokenProgram
            // 1: ProgramAuthority (from remaining[0]) - Jupiter's authority PDA
            // 2: UserTransferAuthority (signer) -> Protocol Authority (our executor)
            // 3: UserSourceTokenAccount -> Executor Source Token
            // 4: ProgramSourceTokenAccount (from remaining[1])
            // 5: ProgramDestTokenAccount (from remaining[2])
            // 6: UserDestTokenAccount -> Executor Dest Token
            // 7: SourceMint
            // 8: DestMint
            // ...

            // Minimum account count check
            require!(remaining.len() >= 9, PrivacyError::JupiterInsufficientAccounts);

            // Validate source and dest mints match expected - ensures correct token pair
            // (Jupiter will validate all other account ownership/derivations)
            require!(remaining[7].key() == source_mint, PrivacyError::InvalidMintAddress);
            require!(remaining[8].key() == dest_mint, PrivacyError::InvalidMintAddress);

            // We need to inject our executor accounts at indices 2, 3, and 6
            // The `remaining` array contains the accounts Jupiter expects, so we iterate through them
            // and replace the user-specific ones with our executor ones.

            for (i, acc) in remaining.iter().enumerate() {
                match i {
                    2 => {
                        // Index 2: User Transfer Authority -> Executor (Signer)
                        jupiter_accounts.push(AccountMeta::new_readonly(executor.key(), true));
                        account_infos.push(executor.to_account_info());
                    }
                    3 => {
                        // Index 3: User Source Token Account -> Executor Source Token
                        jupiter_accounts.push(
                            AccountMeta::new(ctx.accounts.executor_source_token.key(), false)
                        );
                        account_infos.push(ctx.accounts.executor_source_token.to_account_info());
                    }
                    6 => {
                        // Index 6: User Destination Token Account -> Executor Dest Token
                        jupiter_accounts.push(
                            AccountMeta::new(ctx.accounts.executor_dest_token.key(), false)
                        );
                        account_infos.push(ctx.accounts.executor_dest_token.to_account_info());
                    }
                    _ => {
                        // Pass through other accounts (Project Authority, Mints, etc.)
                        jupiter_accounts.push(
                            if acc.is_writable {
                                AccountMeta::new(acc.key(), false)
                            } else {
                                AccountMeta::new_readonly(acc.key(), false)
                            }
                        );
                        account_infos.push(acc.to_account_info());
                    }
                }
            }
        } else {
            // Standard Route / ExactOutRoute Layout:
            // 0: TokenProgram
            // 1: UserTransferAuthority -> Executor
            // 2: UserSourceTokenAccount -> Executor Source Token
            // 3: UserDestTokenAccount -> Executor Dest Token
            // 4: DestMint (or other optional)
            // ...

            // Minimum account count check
            require!(remaining.len() >= 4, PrivacyError::JupiterInsufficientAccounts);

            // Jupiter validates its own accounts - we just ensure basic structure

            for (i, acc) in remaining.iter().enumerate() {
                match i {
                    1 => {
                        // Replace account #1 with executor PDA (marked as signer)
                        jupiter_accounts.push(AccountMeta::new_readonly(executor.key(), true));
                        account_infos.push(executor.to_account_info());
                    }
                    2 => {
                        // Replace account #2 with executor's source token account
                        jupiter_accounts.push(
                            AccountMeta::new(ctx.accounts.executor_source_token.key(), false)
                        );
                        account_infos.push(ctx.accounts.executor_source_token.to_account_info());
                    }
                    3 => {
                        // Replace account #3 with executor's dest token account
                        jupiter_accounts.push(
                            AccountMeta::new(ctx.accounts.executor_dest_token.key(), false)
                        );
                        account_infos.push(ctx.accounts.executor_dest_token.to_account_info());
                    }
                    _ => {
                        // Use account from remaining_accounts as-is
                        jupiter_accounts.push(
                            if acc.is_writable {
                                AccountMeta::new(acc.key(), false)
                            } else {
                                AccountMeta::new_readonly(acc.key(), false)
                            }
                        );
                        account_infos.push(acc.to_account_info());
                    }
                }
            }
        }

        // Verify swap_data matches the hash committed in the ZK proof to prevent
        // relayer substitution of swap instructions.
        {
            use sha2::{ Sha256, Digest };
            let computed: [u8; 32] = Sha256::digest(&swap_data).into();
            require!(computed == swap_params.swap_data_hash, PrivacyError::InvalidSwapParams);
        }

        // Construct instruction
        let swap_ix = Instruction {
            program_id: ctx.accounts.swap_program.key(),
            accounts: jupiter_accounts,
            data: swap_data.clone(),
        };

        // Execute CPI with executor PDA signing
        invoke_signed(&swap_ix, &account_infos, &[executor_seeds])?;
    } else {
        msg!(
            "Unknown Swap Program detected. Requires CPMM (0x8fbe..), AMM (0x09), or Jupiter (0xe517cb97..) discriminator."
        );
        return err!(PrivacyError::InvalidPublicAmount);
    }

    // Transfer swapped tokens to dest vault (minus fee)
    ctx.accounts.executor_dest_token.reload()?;
    let swapped_amount = ctx.accounts.executor_dest_token.amount;

    require!(swapped_amount >= swap_params.min_amount_out, PrivacyError::InvalidPublicAmount);

    let relayer_fee = ext_data.fee;
    require!(swapped_amount > relayer_fee, PrivacyError::InvalidPublicAmount);

    // Validate fee meets pool requirements
    let dest_config = &ctx.accounts.dest_config;
    let percentage_fee = (swapped_amount as u128)
        .checked_mul(dest_config.swap_fee_bps as u128)
        .and_then(|x| x.checked_div(10_000))
        .ok_or(PrivacyError::ArithmeticOverflow)? as u64;
    let min_required_fee = std::cmp::max(dest_config.min_swap_fee, percentage_fee);
    require!(relayer_fee >= min_required_fee, PrivacyError::InsufficientFee);

    let vault_amount = swapped_amount.saturating_sub(relayer_fee);

    // Critical: the ZK circuit commits to swap_params.dest_amount as the value encoded
    // in the destination note (output_commitments[1]).  If vault_amount < dest_amount,
    // the dest note would claim more value than actually entered the vault — a solvency
    // violation.  This check binds the on-chain token flow to the ZK-proven amount.
    require!(vault_amount >= swap_params.dest_amount, PrivacyError::InvalidPublicAmount);

    let dest_is_native = !is_token_mint(&dest_mint);

    if dest_is_native {
        // Native SOL dest: transfer WSOL from executor → relayer fee (SPL), then close
        // executor_dest_token to vault PDA to unwrap remaining WSOL → lamports.

        // Pay relayer fee first (still in WSOL, relayer's token account is WSOL ATA)
        if relayer_fee > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from: ctx.accounts.executor_dest_token.to_account_info(),
                        to: ctx.accounts.relayer_token_account.to_account_info(),
                        authority: executor.to_account_info(),
                    },
                    &[executor_seeds]
                ),
                relayer_fee
            )?;
        }

        // Close executor dest token → vault gets remaining lamports (unwraps WSOL)
        token::close_account(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                CloseAccount {
                    account: ctx.accounts.executor_dest_token.to_account_info(),
                    destination: ctx.accounts.dest_vault.to_account_info(),
                    authority: executor.to_account_info(),
                },
                &[executor_seeds]
            )
        )?;
    } else {
        // Validate dest vault token account is the canonical ATA
        let expected_dest_ata = get_associated_token_address(
            &ctx.accounts.dest_vault.key(),
            &dest_mint
        );
        require!(
            ctx.accounts.dest_vault_token_account.key() == expected_dest_ata,
            PrivacyError::InvalidMintAddress
        );

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.executor_dest_token.to_account_info(),
                    to: ctx.accounts.dest_vault_token_account.to_account_info(),
                    authority: executor.to_account_info(),
                },
                &[executor_seeds]
            ),
            vault_amount
        )?;

        // Pay relayer fee
        if relayer_fee > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from: ctx.accounts.executor_dest_token.to_account_info(),
                        to: ctx.accounts.relayer_token_account.to_account_info(),
                        authority: executor.to_account_info(),
                    },
                    &[executor_seeds]
                ),
                relayer_fee
            )?;
        }
    }

    // Update dest pool TVL (increase by vault_amount)
    ctx.accounts.dest_config.total_tvl = ctx.accounts.dest_config.total_tvl
        .checked_add(vault_amount)
        .ok_or(PrivacyError::ArithmeticOverflow)?;

    // Insert dest note (commitment 1) into dest tree
    let mut dest_tree = ctx.accounts.dest_tree.load_mut()?;

    let max_capacity = 1u64 << (dest_tree.height as u64);
    let remaining = max_capacity.saturating_sub(dest_tree.next_index);
    require!(remaining >= 1, PrivacyError::MerkleTreeFull);

    let leaf_index_dest = dest_tree.next_index;
    MerkleTree::append::<PoseidonHasher>(output_commitments[1], &mut *dest_tree)?;

    let dest_new_root = dest_tree.root;
    drop(dest_tree);

    emit!(crate::CommitmentEvent {
        commitment: output_commitments[1],
        leaf_index: leaf_index_dest,
        new_root: dest_new_root,
        timestamp: clock.unix_timestamp,
        mint_address: dest_mint,
        tree_id: dest_tree_id,
    });

    // Insert change note (commitment 0) back into source tree
    let mut source_tree = ctx.accounts.source_tree.load_mut()?;

    let max_capacity = 1u64 << (source_tree.height as u64);
    let remaining = max_capacity.saturating_sub(source_tree.next_index);
    require!(remaining >= 1, PrivacyError::MerkleTreeFull);

    let leaf_index_change = source_tree.next_index;
    MerkleTree::append::<PoseidonHasher>(output_commitments[0], &mut *source_tree)?;

    let source_new_root = source_tree.root;
    drop(source_tree);

    emit!(crate::CommitmentEvent {
        commitment: output_commitments[0],
        leaf_index: leaf_index_change,
        new_root: source_new_root,
        timestamp: clock.unix_timestamp,
        mint_address: source_mint,
        tree_id: source_tree_id,
    });

    // Close executor token accounts (CPIs — must come before any raw lamport edits)
    token::close_account(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            CloseAccount {
                account: ctx.accounts.executor_source_token.to_account_info(),
                destination: ctx.accounts.relayer.to_account_info(),
                authority: executor.to_account_info(),
            },
            &[executor_seeds]
        )
    )?;
    // Only close executor_dest_token if it wasn't already closed (native SOL dest closes it during unwrap)
    if !dest_is_native {
        token::close_account(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                CloseAccount {
                    account: ctx.accounts.executor_dest_token.to_account_info(),
                    destination: ctx.accounts.relayer.to_account_info(),
                    authority: executor.to_account_info(),
                },
                &[executor_seeds]
            )
        )?;
    }

    if source_is_native && is_prefunded == 0 {
        let vault_ai = ctx.accounts.source_vault.to_account_info();
        **vault_ai.try_borrow_mut_lamports()? = vault_ai
            .lamports()
            .checked_sub(swap_amount)
            .ok_or(PrivacyError::ArithmeticOverflow)?;
        **ctx.accounts.relayer.to_account_info().try_borrow_mut_lamports()? = ctx.accounts.relayer
            .to_account_info()
            .lamports()
            .checked_add(swap_amount)
            .ok_or(PrivacyError::ArithmeticOverflow)?;
    }
    // Return executor PDA rent to relayer (raw edit — after all CPIs)
    let executor_lamports = executor.to_account_info().lamports();
    **executor.to_account_info().try_borrow_mut_lamports()? = 0;
    **ctx.accounts.relayer.to_account_info().try_borrow_mut_lamports()? = ctx.accounts.relayer
        .to_account_info()
        .lamports()
        .checked_add(executor_lamports)
        .ok_or(PrivacyError::ArithmeticOverflow)?;

    emit!(SwapExecutedEvent {
        source_mint,
        dest_mint,
        source_tree_id,
        dest_tree_id,
        nullifiers: input_nullifiers,
        commitments: output_commitments,
        timestamp: clock.unix_timestamp,
    });

    Ok(())
}

#[event]
pub struct SwapExecutedEvent {
    pub source_mint: Pubkey,
    pub dest_mint: Pubkey,
    pub source_tree_id: u16,
    pub dest_tree_id: u16,
    pub nullifiers: [[u8; 32]; 2],
    pub commitments: [[u8; 32]; 2],
    pub timestamp: i64,
}

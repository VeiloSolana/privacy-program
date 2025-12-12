use anchor_lang::prelude::*;

pub fn verify_withdraw_proof(
    _root: &[u8; 32],
    _nullifier: &[u8; 32],
    _denom_index: u8,
    _recipient: &Pubkey,
    _relayer: &Pubkey,
    _fee_bps: u16,
    _proof: &[u8],
) -> Result<bool> {
    // v1: stub
    // v2: this will be wired to a real Groth16 verifier over bn254, or just removed
    // when we keep verification off-chain only.
    Ok(true)
}
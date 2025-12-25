use anchor_lang::prelude::*;
use ark_bn254::G1Affine as G1;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use std::ops::Neg;

use crate::{PrivacyError, WithdrawPublicInputs};
use crate::groth16::Groth16Verifier;
use crate::vk_constants::WITHDRAW_VK;

/// Proof broken into (a, b, c) parts.
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct WithdrawProof {
    pub proof_a: [u8; 64],
    pub proof_b: [u8; 128],
    pub proof_c: [u8; 64],
}

/// Reverse 32-byte chunks (for bn254 endianness dance).
pub fn change_endianness(bytes: &[u8]) -> Vec<u8> {
    let mut vec = Vec::with_capacity(bytes.len());
    for chunk in bytes.chunks(32) {
        for b in chunk.iter().rev() {
            vec.push(*b);
        }
    }
    vec
}

pub fn verify_withdraw_groth16(
    proof: WithdrawProof,
    inputs: &WithdrawPublicInputs,
) -> Result<()> {
    // ----- 1. Build public input array -----
    // We know nPublic == 4 from the JSON, but keep it generic.
    let mut public_inputs: [[u8; 32]; 4] = [[0u8; 32]; 4];

    // root, nullifier already 32-byte BE
    public_inputs[0] = inputs.root;
    public_inputs[1] = inputs.nullifier;

    // denom_index -> Fr element encoded as BE: put u8 in the last byte
    let mut denom_bytes = [0u8; 32];
    denom_bytes[31] = inputs.denom_index;
    public_inputs[2] = denom_bytes;

    // recipient Pubkey is 32-byte BE already
    public_inputs[3] = inputs.recipient.to_bytes();

    // ----- 2. Re-encode proof_a: G1 -> 64-byte alt_bn128 layout -----
    let g1_point = G1::deserialize_with_mode(
        &*[&change_endianness(&proof.proof_a[..]), &[0u8][..]].concat(),
        Compress::No,
        Validate::Yes,
    )
    .map_err(|_| PrivacyError::InvalidProof)?;

    let g1_neg = g1_point.neg();
    let mut proof_a_neg = [0u8; 65]; // 32 x, 32 y, 1 dummy
    g1_neg
        .x
        .serialize_with_mode(&mut proof_a_neg[..32], Compress::No)
        .map_err(|_| PrivacyError::InvalidProof)?;
    g1_neg
        .y
        .serialize_with_mode(&mut proof_a_neg[32..64], Compress::No)
        .map_err(|_| PrivacyError::InvalidProof)?;

    let proof_a: [u8; 64] = change_endianness(&proof_a_neg[..64])
        .try_into()
        .map_err(|_| PrivacyError::InvalidProof)?;

    let mut verifier = Groth16Verifier::<4>::new(
        &proof_a,
        &proof.proof_b,
        &proof.proof_c,
        &public_inputs,
        &WITHDRAW_VK,
    )
    .map_err(|_| PrivacyError::InvalidProof)?;

    let ok = verifier
        .verify()
        .map_err(|_| PrivacyError::VerifyFailed)?;

    require!(ok, PrivacyError::VerifyFailed);
    Ok(())
}
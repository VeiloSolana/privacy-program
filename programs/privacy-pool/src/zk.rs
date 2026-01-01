use anchor_lang::prelude::*;
use ark_bn254::G1Affine as G1;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use num_bigint::BigUint;
use std::ops::Neg;

use crate::groth16::Groth16Verifier;
use crate::vk_constants::WITHDRAW_VK;
use crate::{PrivacyError, WithdrawPublicInputs};

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

/// Reduce a 32-byte big-endian value modulo BN254 Fr field modulus.
///
/// Optimized for Solana's compute budget by checking if reduction is needed first.
/// BN254 Fr modulus = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
/// Most values (Poseidon outputs) are already < Fr, so we avoid expensive math when possible.
fn reduce_to_field_be(bytes: [u8; 32]) -> [u8; 32] {
    // BN254 Fr modulus as 32-byte BE
    const FR_MODULUS: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];

    // Quick check: if bytes < modulus, no reduction needed (common case)
    if is_less_than(&bytes, &FR_MODULUS) {
        return bytes;
    }

    // Use BigUint for proper modulo reduction
    let val = BigUint::from_bytes_be(&bytes);
    let modulus = BigUint::from_bytes_be(&FR_MODULUS);
    let reduced = val % modulus;

    let mut result = [0u8; 32];
    let reduced_bytes = reduced.to_bytes_be();
    // Copy into the end of the array (padding with zeros at start if needed)
    let start = 32 - reduced_bytes.len();
    result[start..].copy_from_slice(&reduced_bytes);

    result
}

/// Compare two 32-byte big-endian values: returns true if a < b
#[inline]
fn is_less_than(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
    }
    false // equal
}

/// Subtract b from a (a >= b assumed, returns a - b)
#[inline]
fn subtract_mod(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow = 0i32;

    for i in (0..32).rev() {
        let diff = (a[i] as i32) - (b[i] as i32) - borrow;
        if diff < 0 {
            result[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[i] = diff as u8;
            borrow = 0;
        }
    }

    result
}

/// Verify withdraw Groth16 proof.
///
/// CRITICAL: Public inputs are reduced mod Fr to match Circom's behavior.
/// Solana public keys (256 bits) can exceed BN254 Fr modulus (~254 bits).
pub fn verify_withdraw_groth16(proof: WithdrawProof, inputs: &WithdrawPublicInputs) -> Result<()> {
    // ----- 1. Build public input array -----
    // Apply modular reduction to ensure all values are valid field elements
    let mut public_inputs: [[u8; 32]; 4] = [[0u8; 32]; 4];

    // root, nullifier - reduce mod Fr for safety (Poseidon output should already be < Fr)
    public_inputs[0] = reduce_to_field_be(inputs.root);
    public_inputs[1] = reduce_to_field_be(inputs.nullifier);

    // denom_index -> Fr element encoded as BE: put u8 in the last byte (u8 always < Fr)
    let mut denom_bytes = [0u8; 32];
    denom_bytes[31] = inputs.denom_index;
    public_inputs[2] = denom_bytes;

    // recipient Pubkey - MUST reduce as public keys can exceed Fr modulus
    public_inputs[3] = reduce_to_field_be(inputs.recipient.to_bytes());

    // DEBUG: Convert bytes to hex for comparison with TypeScript
    use num_bigint::BigUint;
    let root_bigint = BigUint::from_bytes_be(&public_inputs[0]);
    let nullifier_bigint = BigUint::from_bytes_be(&public_inputs[1]);
    let denom_bigint = BigUint::from_bytes_be(&public_inputs[2]);
    let recipient_bigint = BigUint::from_bytes_be(&public_inputs[3]);
    msg!("[DEBUG] Rust public inputs as BigInt:");
    msg!("  root: {}", root_bigint);
    msg!("  nullifier: {}", nullifier_bigint);
    msg!("  denomIndex: {}", denom_bigint);
    msg!("  recipient: {}", recipient_bigint);

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

    let ok = verifier.verify().map_err(|_| PrivacyError::VerifyFailed)?;

    require!(ok, PrivacyError::VerifyFailed);
    Ok(())
}

use anchor_lang::prelude::*;
use ark_bn254::G1Affine as G1;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use num_bigint::BigUint;
use std::ops::Neg;

use crate::groth16::Groth16Verifier;
use crate::vk_constants::TRANSACTION_VK;
use crate::{PrivacyError, TransactionPublicInputs};

/// Proof broken into (a, b, c) parts - for legacy withdraw
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct WithdrawProof {
    pub proof_a: [u8; 64],
    pub proof_b: [u8; 128],
    pub proof_c: [u8; 64],
}

/// Proof for new UTXO transaction circuit (same structure, different VK)
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct TransactionProof {
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

// ============================================================================
// Legacy withdraw verification - DEPRECATED
// ============================================================================
// The old withdraw circuit used 4 public inputs (root, nullifier, denomIndex, recipient)
// This has been replaced by the Transaction circuit with 8 public inputs
//
// pub fn verify_withdraw_groth16(proof: WithdrawProof, inputs: &WithdrawPublicInputs) -> Result<()> {
//     // ... deprecated implementation ...
// }

/// Convert i64 to field element (handles negative values)
/// Negative values use field arithmetic: -x ≡ Fr - x (mod Fr)
fn i64_to_field_be(value: i64) -> [u8; 32] {
    const FR_MODULUS: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];

    let mut bytes = [0u8; 32];
    if value >= 0 {
        // Positive: just encode as big-endian
        bytes[24..].copy_from_slice(&(value as u64).to_be_bytes());
    } else {
        // Negative: compute Fr - |value|
        // Use unsigned_abs() to safely handle i64::MIN without overflow
        let abs_val = value.unsigned_abs();

        // Create abs_bytes with value in last 8 bytes
        let mut abs_bytes = [0u8; 32];
        abs_bytes[24..].copy_from_slice(&abs_val.to_be_bytes());

        // Compute Fr - abs_val using BigUint (necessary for field arithmetic)
        let modulus = BigUint::from_bytes_be(&FR_MODULUS);
        let abs = BigUint::from_bytes_be(&abs_bytes);
        let result = modulus - abs;

        let result_bytes = result.to_bytes_be();
        let start = 32 - result_bytes.len();
        bytes[start..].copy_from_slice(&result_bytes);
    }
    bytes
}

/// Verify transaction Groth16 proof (2-in-2-out UTXO model)
///
/// Public inputs (8 total):
/// 1. root
/// 2. publicAmount (i64 - can be negative)
/// 3. extDataHash
/// 4. mintAddress
/// 5. inputNullifiers[0]
/// 6. inputNullifiers[1]
/// 7. outputCommitments[0]
/// 8. outputCommitments[1]
pub fn verify_transaction_groth16(
    proof: TransactionProof,
    inputs: &TransactionPublicInputs,
) -> Result<()> {
    // ----- 1. Build public input array (8 inputs) -----
    let mut public_inputs: [[u8; 32]; 8] = [[0u8; 32]; 8];

    // 1. root - reduce mod Fr for safety
    public_inputs[0] = reduce_to_field_be(inputs.root);

    // 2. publicAmount (i64 -> field element, handle negative)
    public_inputs[1] = i64_to_field_be(inputs.public_amount);

    // 3. extDataHash
    public_inputs[2] = reduce_to_field_be(inputs.ext_data_hash);

    // 4. mintAddress
    public_inputs[3] = reduce_to_field_be(inputs.mint_address.to_bytes());

    // 5-6. inputNullifiers[2]
    public_inputs[4] = reduce_to_field_be(inputs.input_nullifiers[0]);
    public_inputs[5] = reduce_to_field_be(inputs.input_nullifiers[1]);

    // 7-8. outputCommitments[2]
    public_inputs[6] = reduce_to_field_be(inputs.output_commitments[0]);
    public_inputs[7] = reduce_to_field_be(inputs.output_commitments[1]);

    // AUDIT-008 FIX: Debug logging removed to prevent compute budget exhaustion
    // The zk-verify-debug feature was removed as compile-time debug flags can be
    // accidentally enabled in production, allowing attackers to spam failed proofs
    // and exhaust compute budget. For debugging, use off-chain verification tools instead.

    // ----- 2. Re-encode proof_a: G1 -> 64-byte alt_bn128 layout -----
    let g1_point = G1::deserialize_with_mode(
        &*[&change_endianness(&proof.proof_a[..]), &[0u8][..]].concat(),
        Compress::No,
        Validate::Yes,
    )
    .map_err(|_| PrivacyError::InvalidProof)?;

    let g1_neg = g1_point.neg();
    let mut proof_a_neg = [0u8; 65];
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

    // ----- 3. Verify with Groth16Verifier<8> -----
    let mut verifier = Groth16Verifier::<8>::new(
        &proof_a,
        &proof.proof_b,
        &proof.proof_c,
        &public_inputs,
        &TRANSACTION_VK,
    )
    .map_err(|_| PrivacyError::InvalidProof)?;

    let ok = verifier.verify().map_err(|_| PrivacyError::VerifyFailed)?;

    require!(ok, PrivacyError::VerifyFailed);
    Ok(())
}

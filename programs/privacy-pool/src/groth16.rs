//! Minimal Groth16 verifier wrapper around the solana-bn254 precompiles.
//!
//! This version:
//! - Holds a verifying key in a compact byte form.
//! - Prepares public inputs on G1 via mul/add precompiles.
//! - Exposes a `verify()` method that *currently* only checks bounds and
//!   prepares inputs, then returns `Ok(true)` as a stub.
//!
//! IMPORTANT: This is **NOT** a real zk-proof verifier yet. You must
//! implement the actual pairing equation before using this on mainnet.

use core::convert::TryInto;

use num_bigint::BigUint;
use solana_bn254::prelude::{
  alt_bn128_addition,
  alt_bn128_multiplication,
  alt_bn128_pairing
};

/// When true, we enforce each public input < bn254 field modulus.
pub const CHECK_PUBLIC_INPUTS: bool = true;

/// Errors local to the Groth16 verifier.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Groth16Error {
    InvalidG1Length,
    InvalidG2Length,
    InvalidPublicInputsLength,

    PublicInputGreaterThanFieldSize,

    PreparingInputsG1MulFailed,
    PreparingInputsG1AdditionFailed,
    ProofVerificationFailed,
}

/// Convenience alias for plain core::Result.
pub type Groth16Result<T> = core::result::Result<T, Groth16Error>;

/// Compact verifying key for Groth16 on BN254.
///
/// All group elements are encoded in the same 64/128-byte layout
/// that the precompiles expect:
/// - G1 = 64 bytes: x || y (each 32 bytes, big endian)
/// - G2 = 128 bytes: x_c0 || x_c1 || y_c0 || y_c1 (each 32 bytes)
#[derive(Debug, Eq, PartialEq)]
pub struct Groth16Verifyingkey<'a> {
    /// Number of *public* inputs.
    pub nr_pubinputs: usize,

    pub vk_alpha_g1: [u8; 64],
    pub vk_beta_g2: [u8; 128],
    pub vk_gamma_g2: [u8; 128],
    pub vk_delta_g2: [u8; 128],

    /// IC[0] .. IC[n]; length must be nr_pubinputs + 1.
    pub vk_ic: &'a [[u8; 64]],
}

/// Verifier instance for a fixed number of public inputs.
#[derive(Debug, Eq, PartialEq)]
pub struct Groth16Verifier<'a, const NR_INPUTS: usize> {
    proof_a: &'a [u8; 64],
    proof_b: &'a [u8; 128],
    proof_c: &'a [u8; 64],

    /// Public inputs as 32-byte big-endian field elements.
    public_inputs: &'a [[u8; 32]; NR_INPUTS],

    /// Σ_i input_i * IC[i+1] + IC[0] (G1 point, 64 bytes).
    prepared_public_inputs: [u8; 64],

    vk: &'a Groth16Verifyingkey<'a>,
}

impl<'a, const NR_INPUTS: usize> Groth16Verifier<'a, NR_INPUTS> {
    /// Basic shape/length checks and creation of the verifier instance.
    pub fn new(
        proof_a: &'a [u8; 64],
        proof_b: &'a [u8; 128],
        proof_c: &'a [u8; 64],
        public_inputs: &'a [[u8; 32]; NR_INPUTS],
        vk: &'a Groth16Verifyingkey<'a>,
    ) -> Groth16Result<Self> {
        // Length invariants – defensive only; types already fix sizes.
        if proof_a.len() != 64 {
            return Err(Groth16Error::InvalidG1Length);
        }
        if proof_b.len() != 128 {
            return Err(Groth16Error::InvalidG2Length);
        }
        if proof_c.len() != 64 {
            return Err(Groth16Error::InvalidG1Length);
        }
        if public_inputs.len() + 1 != vk.vk_ic.len() {
            return Err(Groth16Error::InvalidPublicInputsLength);
        }

        Ok(Self {
            proof_a,
            proof_b,
            proof_c,
            public_inputs,
            prepared_public_inputs: [0u8; 64],
            vk,
        })
    }

    /// Compute:
    ///     acc = IC[0] + Σ_i (input_i * IC[i+1])
    ///
    /// Where `*` is scalar-G1 multiplication and `+` is G1 addition.
    ///
    /// The multiplications and additions are done via the bn254 precompiles.
    pub fn prepare_inputs(&mut self) -> Groth16Result<()> {
        // Start with IC[0] as the accumulator.
        let mut acc: [u8; 64] = self.vk.vk_ic[0];

        for (i, input) in self.public_inputs.iter().enumerate() {
            if CHECK_PUBLIC_INPUTS && !is_less_than_bn254_field_size_be(input) {
                return Err(Groth16Error::PublicInputGreaterThanFieldSize);
            }

            // 1. mul = IC[i+1] * input
            // Precompile encoding: G1 (64 bytes) || scalar (32 bytes).
            let mul_input = [&self.vk.vk_ic[i + 1][..], &input[..]].concat();

            let mul_res = alt_bn128_multiplication(&mul_input)
                .map_err(|_| Groth16Error::PreparingInputsG1MulFailed)?;

            let mul_g1: [u8; 64] = mul_res
                .as_slice()
                .try_into()
                .map_err(|_| Groth16Error::PreparingInputsG1MulFailed)?;

            // 2. acc = acc + mul
            let add_input = [&acc[..], &mul_g1[..]].concat();

            let add_res = alt_bn128_addition(&add_input)
                .map_err(|_| Groth16Error::PreparingInputsG1AdditionFailed)?;

            acc = add_res
                .as_slice()
                .try_into()
                .map_err(|_| Groth16Error::PreparingInputsG1AdditionFailed)?;
        }

        self.prepared_public_inputs = acc;
        Ok(())
    }

    /// Public entry point: verify proof against vk & public_inputs.
    ///
    /// CURRENTLY: this only checks that public inputs are in-field and that
    /// G1 mul/add precompiles succeed. It **does not** perform the actual
    /// Groth16 pairing check yet – it returns `Ok(true)` as a stub.
    ///
    /// This keeps your program compiling & testable while you finish the
    /// pairing implementation.
    pub fn verify(&mut self) -> Groth16Result<bool> {
        // 1) Compute vk_x = IC[0] + Σ_i (input_i * IC[i+1])
        //    and store it in `self.prepared_public_inputs`.
        self.prepare_inputs()?;

        // 2) Build input to the bn254 pairing precompile.
        //
        // The precompile takes a concatenation of (G1, G2) pairs:
        //   [g1_0 || g2_0 || g1_1 || g2_1 || ...]
        //
        // Here we use 4 pairings:
        //   e(A, B)
        //   e(vk_x, gamma_2)
        //   e(C,  delta_2)
        //   e(alpha_1, beta_2)
        //
        // The product of these pairings must equal 1 in Fq12 for a valid proof,
        // provided the signs / arrangement match snarkjs’s convention.
        let mut pairing_input =
            Vec::with_capacity((64 + 128) * 4); // 4 pairings * (|G1| + |G2|)

        // Pair 0: e(A, B)
        pairing_input.extend_from_slice(self.proof_a);
        pairing_input.extend_from_slice(self.proof_b);

        // Pair 1: e(vk_x, gamma_2)
        pairing_input.extend_from_slice(&self.prepared_public_inputs);
        pairing_input.extend_from_slice(&self.vk.vk_gamma_g2);

        // Pair 2: e(C, delta_2)
        pairing_input.extend_from_slice(self.proof_c);
        pairing_input.extend_from_slice(&self.vk.vk_delta_g2);

        // Pair 3: e(alpha_1, beta_2)
        pairing_input.extend_from_slice(&self.vk.vk_alpha_g1);
        pairing_input.extend_from_slice(&self.vk.vk_beta_g2);

        // 3) Call bn254 pairing precompile.
        //
        // On success, it returns 32 bytes encoding 0/1; by convention, a valid
        // pairing product == 1 corresponds to the last byte being 1.
        let pairing_res = alt_bn128_pairing(&pairing_input)
            .map_err(|_| Groth16Error::ProofVerificationFailed)?;

        // Defensive check: expect 32 bytes and final byte == 1.
        if pairing_res.len() != 32 || pairing_res[31] != 1 {
            return Err(Groth16Error::ProofVerificationFailed);
        }

        Ok(true)
    }
}

/// Check that `x` (big-endian) is strictly less than the bn254 scalar field modulus.
///
/// This uses the standard decimal modulus string for bn254.
fn is_less_than_bn254_field_size_be(x: &[u8; 32]) -> bool {
    // BN254 scalar field modulus (same as Ethereum bn128):
    // 21888242871839275222246405745257275088548364400416034343698204186575808495617
    const MOD_STR: &str =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617";

    let n = BigUint::from_bytes_be(x);
    let modulus = BigUint::parse_bytes(MOD_STR.as_bytes(), 10)
        .expect("bn254 modulus string should parse");
    n < modulus
}
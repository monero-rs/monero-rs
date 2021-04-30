//! Bulletproof
//!
//! Copied from https://github.com/dalek-cryptography/bulletproofs and
//! modified to mimic Monero's `bulletproof_PROVE` and `bulletproof_VERIFY` algorithms.

#![allow(non_snake_case)]

use core::iter;

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};
use rand_core::{CryptoRng, RngCore};
use thiserror;
use tiny_keccak::{Hasher, Keccak};

use inner_product_proof::InnerProductProof;

pub use generators::{BulletproofGens, PedersenGens};

mod dealer;
mod generators;
mod inner_product_proof;
mod messages;
mod party;
mod util;

lazy_static::lazy_static! {
    pub (crate) static ref INV_EIGHT: Scalar = {
        Scalar::from(8u8).invert()
    };
}

/// The `RangeProof` struct represents a proof that one or more values
/// are in a range.
///
/// The `RangeProof` struct contains functions for creating and
/// verifying aggregated range proofs.  The single-value case is
/// implemented as a special case of aggregated range proofs.
///
/// The bitsize of the range, as well as the list of commitments to
/// the values, are not included in the proof, and must be known to
/// the verifier.
///
/// This implementation requires that both the bitsize `n` and the
/// aggregation size `m` be powers of two, so that `n = 8, 16, 32, 64`
/// and `m = 1, 2, 4, 8, 16, ...`.  Note that the aggregation size is
/// not given as an explicit parameter, but is determined by the
/// number of values or commitments passed to the prover or verifier.
#[derive(Clone, Debug)]
pub struct RangeProof {
    /// Commitment to the bits of the value
    A: CompressedEdwardsY,
    /// Commitment to the blinding factors
    S: CompressedEdwardsY,
    /// Commitment to the \\(t_1\\) coefficient of \\( t(x) \\)
    T_1: CompressedEdwardsY,
    /// Commitment to the \\(t_2\\) coefficient of \\( t(x) \\)
    T_2: CompressedEdwardsY,
    /// Evaluation of the polynomial \\(t(x)\\) at the challenge point \\(x\\)
    t_x: Scalar,
    /// Blinding factor for the synthetic commitment to \\(t(x)\\)
    t_x_blinding: Scalar,
    /// Blinding factor for the synthetic commitment to the inner-product arguments
    e_blinding: Scalar,
    /// Proof data for the inner-product argument.
    ipp_proof: InnerProductProof,
}

impl From<RangeProof> for crate::util::ringct::Bulletproof {
    fn from(from: RangeProof) -> Self {
        use crate::util::ringct::Key;

        Self {
            A: Key {
                key: from.A.to_bytes(),
            },
            S: Key {
                key: from.S.to_bytes(),
            },
            T1: Key {
                key: from.T_1.to_bytes(),
            },
            T2: Key {
                key: from.T_2.to_bytes(),
            },
            taux: Key {
                key: from.t_x_blinding.to_bytes(),
            },
            mu: Key {
                key: from.e_blinding.to_bytes(),
            },
            L: from
                .ipp_proof
                .L_vec
                .iter()
                .map(|l| Key { key: l.to_bytes() })
                .collect(),
            R: from
                .ipp_proof
                .R_vec
                .iter()
                .map(|r| Key { key: r.to_bytes() })
                .collect(),
            a: Key {
                key: from.ipp_proof.a.to_bytes(),
            },
            b: Key {
                key: from.ipp_proof.b.to_bytes(),
            },
            t: Key {
                key: from.t_x.to_bytes(),
            },
        }
    }
}

impl RangeProof {
    /// Create a rangeproof for a given pair of value `v` and blinding
    /// scalar `v_blinding`.
    ///
    /// This is a convenience wrapper around
    /// [`RangeProof::prove_multiple`].
    ///
    /// # Example
    /// ```
    /// use curve25519_dalek::scalar::Scalar;
    ///
    /// use monero::bulletproof::{RangeProof, BulletproofGens, PedersenGens};
    ///
    /// # fn main() {
    /// // Generators for Pedersen commitments.  These can be selected
    /// // independently of the Bulletproofs generators.
    /// let pc_gens = PedersenGens::default();
    ///
    /// // Generators for Bulletproofs, valid for proofs up to bitsize 64
    /// // and aggregation size up to 1.
    /// let bp_gens = BulletproofGens::new(64, 1);
    ///
    /// // A secret value we want to prove lies in the range [0, 2^32)
    /// let secret_value = 1037578891u64;
    ///
    /// // The API takes a blinding factor for the commitment.
    /// let blinding = Scalar::random(&mut rand::thread_rng());
    ///
    /// // Create a 32-bit rangeproof.
    /// let (proof, committed_value) = RangeProof::prove_single(
    ///     &bp_gens,
    ///     &pc_gens,
    ///     secret_value,
    ///     &blinding,
    ///     32,
    /// ).expect("A real program could handle errors");
    ///
    /// assert!(
    ///     proof
    ///         .verify_single(&bp_gens, &pc_gens, &committed_value, 32)
    ///         .is_ok()
    /// );
    /// # }
    /// ```
    pub fn prove_single_with_rng<T: RngCore + CryptoRng>(
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        v: u64,
        v_blinding: &Scalar,
        n: usize,
        rng: &mut T,
    ) -> Result<(RangeProof, CompressedEdwardsY), ProofError> {
        let (p, Vs) =
            RangeProof::prove_multiple_with_rng(bp_gens, pc_gens, &[v], &[*v_blinding], n, rng)?;
        Ok((p, Vs[0]))
    }

    /// Create a rangeproof for a given pair of value `v` and blinding
    /// scalar `v_blinding`.
    ///
    /// This is a convenience wrapper around
    /// [`RangeProof::prove_single_with_rng`], passing in a threadsafe
    /// RNG.
    pub fn prove_single(
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        v: u64,
        v_blinding: &Scalar,
        n: usize,
    ) -> Result<(RangeProof, CompressedEdwardsY), ProofError> {
        RangeProof::prove_single_with_rng(
            bp_gens,
            pc_gens,
            v,
            v_blinding,
            n,
            &mut rand::thread_rng(),
        )
    }

    /// Create a rangeproof for a set of values.
    ///
    /// # Example
    /// ```
    /// use rand::thread_rng;
    ///
    /// use curve25519_dalek::scalar::Scalar;
    ///
    /// use monero::bulletproof::{BulletproofGens, PedersenGens, RangeProof};
    ///
    /// # fn main() {
    /// // Generators for Pedersen commitments.  These can be selected
    /// // independently of the Bulletproofs generators.
    /// let pc_gens = PedersenGens::default();
    ///
    /// // Generators for Bulletproofs, valid for proofs up to bitsize 64
    /// // and aggregation size up to 16.
    /// let bp_gens = BulletproofGens::new(64, 16);
    ///
    /// // Four secret values we want to prove lie in the range [0, 2^32)
    /// let secrets = [4242344947u64, 3718732727u64, 2255562556u64, 2526146994u64];
    ///
    /// // The API takes blinding factors for the commitments.
    /// let blindings: Vec<_> = (0..4).map(|_| Scalar::random(&mut thread_rng())).collect();
    ///
    /// // Create an aggregated 32-bit rangeproof and corresponding commitments.
    /// let (proof, commitments) = RangeProof::prove_multiple(
    ///     &bp_gens,
    ///     &pc_gens,
    ///     &secrets,
    ///     &blindings,
    ///     32,
    /// ).expect("A real program could handle errors");
    ///
    /// assert!(
    ///     proof
    ///         .verify_multiple(&bp_gens, &pc_gens, &commitments, 32)
    ///         .is_ok()
    /// );
    /// # }
    /// ```
    pub fn prove_multiple_with_rng<T: RngCore + CryptoRng>(
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        values: &[u64],
        blindings: &[Scalar],
        n: usize,
        rng: &mut T,
    ) -> Result<(RangeProof, Vec<CompressedEdwardsY>), ProofError> {
        use self::dealer::*;
        use self::party::*;

        if values.len() != blindings.len() {
            return Err(ProofError::WrongNumBlindingFactors);
        }

        let dealer = Dealer::new(bp_gens, pc_gens, n, values.len())?;

        let parties: Vec<_> = values
            .iter()
            .zip(blindings.iter())
            .map(|(&v, &v_blinding)| Party::new(bp_gens, pc_gens, v, v_blinding, n))
            .collect::<Result<Vec<_>, _>>()?;

        let (parties, bit_commitments): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .enumerate()
            .map(|(j, p)| {
                p.assign_position_with_rng(j, rng)
                    .expect("We already checked the parameters, so this should never happen")
            })
            .unzip();

        let value_commitments: Vec<_> = bit_commitments.iter().map(|c| c.V_j).collect();

        let (dealer, bit_challenge) = dealer.receive_bit_commitments(bit_commitments)?;

        let (parties, poly_commitments): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .map(|p| p.apply_challenge_with_rng(&bit_challenge, rng))
            .unzip();

        let (dealer, poly_challenge) = dealer.receive_poly_commitments(poly_commitments)?;

        let proof_shares: Vec<_> = parties
            .into_iter()
            .map(|p| p.apply_challenge(&poly_challenge))
            .collect::<Result<Vec<_>, _>>()?;

        let proof = dealer.receive_trusted_shares(&proof_shares)?;

        Ok((proof, value_commitments))
    }

    /// Create a rangeproof for a set of values.
    ///
    /// This is a convenience wrapper around
    /// [`RangeProof::prove_multiple_with_rng`], passing in a
    /// threadsafe RNG.
    pub fn prove_multiple(
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        values: &[u64],
        blindings: &[Scalar],
        n: usize,
    ) -> Result<(RangeProof, Vec<CompressedEdwardsY>), ProofError> {
        RangeProof::prove_multiple_with_rng(
            bp_gens,
            pc_gens,
            values,
            blindings,
            n,
            &mut rand::thread_rng(),
        )
    }

    /// Verifies a rangeproof for a given value commitment \\(V\\).
    ///
    /// This is a convenience wrapper around `verify_multiple` for the
    /// `m=1` case.
    pub fn verify_single_with_rng<T: RngCore + CryptoRng>(
        &self,
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        V: &CompressedEdwardsY,
        n: usize,
        rng: &mut T,
    ) -> Result<(), ProofError> {
        self.verify_multiple_with_rng(bp_gens, pc_gens, &[*V], n, rng)
    }

    /// Verifies a rangeproof for a given value commitment \\(V\\).
    ///
    /// This is a convenience wrapper around
    /// [`RangeProof::verify_single_with_rng`], passing in a
    /// threadsafe RNG.
    pub fn verify_single(
        &self,
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        V: &CompressedEdwardsY,
        n: usize,
    ) -> Result<(), ProofError> {
        self.verify_single_with_rng(bp_gens, pc_gens, V, n, &mut rand::thread_rng())
    }

    /// Verifies an aggregated rangeproof for the given value
    /// commitments.
    pub fn verify_multiple_with_rng<T: RngCore + CryptoRng>(
        &self,
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        value_commitments: &[CompressedEdwardsY],
        n: usize,
        rng: &mut T,
    ) -> Result<(), ProofError> {
        let m = value_commitments.len();

        // First, replay the "interactive" protocol using the proof
        // data to recompute all challenges.
        if !(n == 8 || n == 16 || n == 32 || n == 64) {
            return Err(ProofError::InvalidBitsize);
        }
        if bp_gens.gens_capacity < n {
            return Err(ProofError::InvalidGeneratorsLength);
        }
        if bp_gens.party_capacity < m {
            return Err(ProofError::InvalidGeneratorsLength);
        }

        let mut keccak = Keccak::v256();
        for commitment in value_commitments.iter() {
            keccak.update(commitment.as_bytes());
        }
        let mut hash_commitments = [0u8; 32];
        keccak.finalize(&mut hash_commitments);
        let hash_commitments = Scalar::from_bytes_mod_order(hash_commitments);

        let mut keccak = Keccak::v256();
        keccak.update(hash_commitments.as_bytes());
        keccak.update(self.A.as_bytes());
        keccak.update(self.S.as_bytes());
        let mut y = [0u8; 32];
        keccak.finalize(&mut y);
        let y = Scalar::from_bytes_mod_order(y);

        if y == Scalar::zero() {
            return Err(ProofError::VerificationError);
        }

        let mut keccak = Keccak::v256();
        keccak.update(y.as_bytes());
        let mut z = [0u8; 32];
        keccak.finalize(&mut z);

        let z = Scalar::from_bytes_mod_order(z);

        if z == Scalar::zero() {
            return Err(ProofError::VerificationError);
        }

        let zz = z * z;
        let minus_z = -z;

        let mut keccak = Keccak::v256();
        keccak.update(z.as_bytes());
        keccak.update(z.as_bytes());
        keccak.update(self.T_1.as_bytes());
        keccak.update(self.T_2.as_bytes());
        let mut x = [0u8; 32];
        keccak.finalize(&mut x);
        let x = Scalar::from_bytes_mod_order(x);

        if x == Scalar::zero() {
            return Err(ProofError::VerificationError);
        }

        let mut keccak = Keccak::v256();
        keccak.update(x.as_bytes());
        keccak.update(x.as_bytes());
        keccak.update(self.t_x_blinding.as_bytes());
        keccak.update(self.e_blinding.as_bytes());
        keccak.update(self.t_x.as_bytes());
        let mut w = [0u8; 32];
        keccak.finalize(&mut w);
        let w = Scalar::from_bytes_mod_order(w);

        if w == Scalar::zero() {
            return Err(ProofError::VerificationError);
        }

        // Challenge value for batching statements to be verified
        let c = Scalar::random(rng);

        let (x_sq, x_inv_sq, s) = self.ipp_proof.verification_scalars(n * m, w)?;
        let s_inv = s.iter().rev();

        let a = self.ipp_proof.a;
        let b = self.ipp_proof.b;

        // Construct concat_z_and_2, an iterator of the values of
        // z^0 * \vec(2)^n || z^1 * \vec(2)^n || ... || z^(m-1) * \vec(2)^n
        let powers_of_2: Vec<Scalar> = util::exp_iter(Scalar::from(2u64)).take(n).collect();
        let concat_z_and_2: Vec<Scalar> = util::exp_iter(z)
            .take(m)
            .flat_map(|exp_z| powers_of_2.iter().map(move |exp_2| exp_2 * exp_z))
            .collect();

        let g = s.iter().map(|s_i| minus_z - a * s_i);
        let h = s_inv
            .zip(util::exp_iter(y.invert()))
            .zip(concat_z_and_2.iter())
            .map(|((s_i_inv, exp_y_inv), z_and_2)| z + exp_y_inv * (zz * z_and_2 - b * s_i_inv));

        let value_commitment_scalars = util::exp_iter(z).take(m).map(|z_exp| c * zz * z_exp);
        let basepoint_scalar = w * (self.t_x - a * b) + c * (delta(n, m, &y, &z) - self.t_x);

        let eight = Scalar::from(8u8);
        let mega_check = EdwardsPoint::optional_multiscalar_mul(
            iter::once(Scalar::one())
                .chain(iter::once(x))
                .chain(iter::once(c * x))
                .chain(iter::once(c * x * x))
                .chain(x_sq.iter().cloned())
                .chain(x_inv_sq.iter().cloned())
                .chain(iter::once(-self.e_blinding - c * self.t_x_blinding))
                .chain(iter::once(basepoint_scalar))
                .chain(g)
                .chain(h)
                .chain(value_commitment_scalars),
            iter::once(self.A.decompress().map(|A| eight * A))
                .chain(iter::once(self.S.decompress().map(|S| eight * S)))
                .chain(iter::once(self.T_1.decompress().map(|T_1| eight * T_1)))
                .chain(iter::once(self.T_2.decompress().map(|T_2| eight * T_2)))
                .chain(
                    self.ipp_proof
                        .L_vec
                        .iter()
                        .map(|L| L.decompress().map(|L| eight * L)),
                )
                .chain(
                    self.ipp_proof
                        .R_vec
                        .iter()
                        .map(|R| R.decompress().map(|R| eight * R)),
                )
                .chain(iter::once(Some(pc_gens.B_blinding)))
                .chain(iter::once(Some(pc_gens.B)))
                .chain(bp_gens.G(n, m).map(|&x| Some(x)))
                .chain(bp_gens.H(n, m).map(|&x| Some(x)))
                .chain(
                    value_commitments
                        .iter()
                        .map(|V| V.decompress().map(|V| eight * V)),
                ),
        )
        .ok_or_else(|| ProofError::VerificationError)?;

        if mega_check.is_identity() {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }

    /// Verifies an aggregated rangeproof for the given value
    /// commitments.
    ///
    /// This is a convenience wrapper around
    /// [`RangeProof::verify_multiple_with_rng`], passing in a
    /// threadsafe RNG.
    pub fn verify_multiple(
        &self,
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        value_commitments: &[CompressedEdwardsY],
        n: usize,
    ) -> Result<(), ProofError> {
        self.verify_multiple_with_rng(
            bp_gens,
            pc_gens,
            value_commitments,
            n,
            &mut rand::thread_rng(),
        )
    }

    /// Serializes the proof into a byte array of \\(2 \lg n + 9\\)
    /// 32-byte elements, where \\(n\\) is the number of secret bits.
    ///
    /// # Layout
    ///
    /// The layout of the range proof encoding is:
    ///
    /// * four compressed Edwards points \\(A,S,T_1,T_2\\),
    /// * three scalars \\(t_x, \tilde{t}_x, \tilde{e}\\),
    /// * \\(n\\) pairs of compressed Edwards points \\(L_0,R_0\dots,L_{n-1},R_{n-1}\\),
    /// * two scalars \\(a, b\\).
    pub fn to_bytes(&self) -> Vec<u8> {
        // 7 elements: points A, S, T1, T2, scalars tx, tx_bl, e_bl.
        let mut buf = Vec::with_capacity(7 * 32 + self.ipp_proof.serialized_size());
        buf.extend_from_slice(self.A.as_bytes());
        buf.extend_from_slice(self.S.as_bytes());
        buf.extend_from_slice(self.T_1.as_bytes());
        buf.extend_from_slice(self.T_2.as_bytes());
        buf.extend_from_slice(self.t_x.as_bytes());
        buf.extend_from_slice(self.t_x_blinding.as_bytes());
        buf.extend_from_slice(self.e_blinding.as_bytes());
        buf.extend(self.ipp_proof.to_bytes_iter());
        buf
    }

    /// Deserializes the proof from a byte slice.
    ///
    /// Returns an error if the byte slice cannot be parsed into a `RangeProof`.
    pub fn from_bytes(slice: &[u8]) -> Result<RangeProof, ProofError> {
        if slice.len() % 32 != 0 {
            return Err(ProofError::FormatError);
        }
        if slice.len() < 7 * 32 {
            return Err(ProofError::FormatError);
        }

        use crate::bulletproof::util::read32;

        let A = CompressedEdwardsY(read32(&slice[0..]));
        let S = CompressedEdwardsY(read32(&slice[1 * 32..]));
        let T_1 = CompressedEdwardsY(read32(&slice[2 * 32..]));
        let T_2 = CompressedEdwardsY(read32(&slice[3 * 32..]));

        let t_x = Scalar::from_canonical_bytes(read32(&slice[4 * 32..]))
            .ok_or(ProofError::FormatError)?;
        let t_x_blinding = Scalar::from_canonical_bytes(read32(&slice[5 * 32..]))
            .ok_or(ProofError::FormatError)?;
        let e_blinding = Scalar::from_canonical_bytes(read32(&slice[6 * 32..]))
            .ok_or(ProofError::FormatError)?;

        let ipp_proof = InnerProductProof::from_bytes(&slice[7 * 32..])?;

        Ok(RangeProof {
            A,
            S,
            T_1,
            T_2,
            t_x,
            t_x_blinding,
            e_blinding,
            ipp_proof,
        })
    }
}

/// Compute
/// \\[
/// \delta(y,z) = (z - z^{2}) \langle \mathbf{1}, {\mathbf{y}}^{n \cdot m} \rangle - \sum_{j=0}^{m-1} z^{j+3} \cdot \langle \mathbf{1}, {\mathbf{2}}^{n \cdot m} \rangle
/// \\]
fn delta(n: usize, m: usize, y: &Scalar, z: &Scalar) -> Scalar {
    let sum_y = util::sum_of_powers(y, n * m);
    let sum_2 = util::sum_of_powers(&Scalar::from(2u64), n);
    let sum_z = util::sum_of_powers(z, m);

    (z - z * z) * sum_y - z * z * z * sum_2 * sum_z
}

/// Represents an error in proof creation, verification, or parsing.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProofError {
    /// This error occurs when a proof failed to verify.
    #[error("Proof verification failed.")]
    VerificationError,
    /// This error occurs when the proof encoding is malformed.
    #[error("Proof data could not be parsed.")]
    FormatError,
    /// This error occurs during proving if the number of blinding
    /// factors does not match the number of values.
    #[error("Wrong number of blinding factors supplied.")]
    WrongNumBlindingFactors,
    /// This error occurs when attempting to create a proof with
    /// bitsize other than \\(8\\), \\(16\\), \\(32\\), or \\(64\\).
    #[error("Invalid bitsize, must have n = 8,16,32,64.")]
    InvalidBitsize,
    /// This error occurs when attempting to create an aggregated
    /// proof with non-power-of-two aggregation size.
    #[error("Invalid aggregation size, m must be a power of 2.")]
    InvalidAggregation,
    /// This error occurs when there are insufficient generators for the proof.
    #[error("Invalid generators size, too few generators for proof")]
    InvalidGeneratorsLength,
    /// This error results from an internal error during proving.
    ///
    /// The single-party prover is implemented by performing
    /// multiparty computation with ourselves.  However, because the
    /// MPC protocol is not exposed by the single-party API, we
    /// consider its errors to be internal errors.
    #[error("Internal error during proof creation: {0}")]
    ProvingError(MPCError),
}

impl From<MPCError> for ProofError {
    fn from(e: MPCError) -> ProofError {
        match e {
            MPCError::InvalidBitsize => ProofError::InvalidBitsize,
            MPCError::InvalidAggregation => ProofError::InvalidAggregation,
            MPCError::InvalidGeneratorsLength => ProofError::InvalidGeneratorsLength,
            _ => ProofError::ProvingError(e),
        }
    }
}

/// Represents an error during the multiparty computation protocol for
/// proof aggregation.
///
/// This is a separate type from the `ProofError` to allow a layered
/// API: although the MPC protocol is used internally for single-party
/// proving, its API should not expose the complexity of the MPC
/// protocol.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MPCError {
    /// This error occurs when the dealer gives a zero challenge,
    /// which would annihilate the blinding factors.
    #[error("Dealer gave a malicious challenge value.")]
    MaliciousDealer,
    /// This error occurs when attempting to create a proof with
    /// bitsize other than \\(8\\), \\(16\\), \\(32\\), or \\(64\\).
    #[error("Invalid bitsize, must have n = 8,16,32,64")]
    InvalidBitsize,
    /// This error occurs when attempting to create an aggregated
    /// proof with non-power-of-two aggregation size.
    #[error("Invalid aggregation size, m must be a power of 2")]
    InvalidAggregation,
    /// This error occurs when there are insufficient generators for the proof.
    #[error("Invalid generators size, too few generators for proof")]
    InvalidGeneratorsLength,
    /// This error occurs when the dealer is given the wrong number of
    /// value commitments.
    #[error("Wrong number of value commitments")]
    WrongNumBitCommitments,
    /// This error occurs when the dealer is given the wrong number of
    /// polynomial commitments.
    #[error("Wrong number of value commitments")]
    WrongNumPolyCommitments,
    /// This error occurs when the dealer is given the wrong number of
    /// proof shares.
    #[error("Wrong number of proof shares")]
    WrongNumProofShares,
    /// This error occurs when one or more parties submit malformed
    /// proof shares.
    #[error("Malformed proof shares from parties {bad_shares:?}")]
    MalformedProofShares {
        /// A vector with the indexes of the parties whose shares were malformed.
        bad_shares: Vec<usize>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delta() {
        let mut rng = rand::thread_rng();
        let y = Scalar::random(&mut rng);
        let z = Scalar::random(&mut rng);

        // Choose n = 256 to ensure we overflow the group order during
        // the computation, to check that that's done correctly
        let n = 256;

        // code copied from previous implementation
        let z2 = z * z;
        let z3 = z2 * z;
        let mut power_g = Scalar::zero();
        let mut exp_y = Scalar::one(); // start at y^0 = 1
        let mut exp_2 = Scalar::one(); // start at 2^0 = 1
        for _ in 0..n {
            power_g += (z - z2) * exp_y - z3 * exp_2;

            exp_y = exp_y * y; // y^i -> y^(i+1)
            exp_2 = exp_2 + exp_2; // 2^i -> 2^(i+1)
        }

        assert_eq!(power_g, delta(n, 1, &y, &z),);
    }

    /// Given a bitsize `n`, test the following:
    ///
    /// 1. Generate `m` random values and create a proof they are all in range;
    /// 2. Serialize to wire format;
    /// 3. Deserialize from wire format;
    /// 4. Verify the proof.
    fn singleparty_create_and_verify_helper(n: usize, m: usize) {
        // Split the test into two scopes, so that it's explicit what
        // data is shared between the prover and the verifier.

        // Use bincode for serialization
        //use bincode; // already present in lib.rs

        // Both prover and verifier have access to the generators and the proof
        let max_bitsize = 64;
        let max_parties = 16;
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(max_bitsize, max_parties);

        // Prover's scope
        let (proof, value_commitments) = {
            use rand::Rng;
            let mut rng = rand::thread_rng();

            // 0. Create witness data
            let (min, max) = (0u64, ((1u128 << n) - 1) as u64);
            let values: Vec<u64> = (0..m).map(|_| rng.gen_range(min, max)).collect();
            let blindings: Vec<Scalar> = (0..m).map(|_| Scalar::random(&mut rng)).collect();

            // 1. Create and return the proof
            RangeProof::prove_multiple(&bp_gens, &pc_gens, &values, &blindings, n).unwrap()
        };

        // Verifier's scope
        {
            assert!(proof
                .verify_multiple(&bp_gens, &pc_gens, &value_commitments, n)
                .is_ok());
        }
    }

    #[test]
    fn create_and_verify_n_32_m_1() {
        singleparty_create_and_verify_helper(32, 1);
    }

    #[test]
    fn create_and_verify_n_32_m_2() {
        singleparty_create_and_verify_helper(32, 2);
    }

    #[test]
    fn create_and_verify_n_32_m_4() {
        singleparty_create_and_verify_helper(32, 4);
    }

    #[test]
    fn create_and_verify_n_32_m_8() {
        singleparty_create_and_verify_helper(32, 8);
    }

    #[test]
    fn create_and_verify_n_64_m_1() {
        singleparty_create_and_verify_helper(64, 1);
    }

    #[test]
    fn create_and_verify_n_64_m_2() {
        singleparty_create_and_verify_helper(64, 2);
    }

    #[test]
    fn create_and_verify_n_64_m_4() {
        singleparty_create_and_verify_helper(64, 4);
    }

    #[test]
    fn create_and_verify_n_64_m_8() {
        singleparty_create_and_verify_helper(64, 8);
    }

    #[test]
    fn create_and_verify_n_64_m_16() {
        singleparty_create_and_verify_helper(64, 16);
    }

    #[test]
    fn detect_dishonest_dealer_during_aggregation() {
        use self::dealer::*;
        use self::party::*;
        use crate::bulletproof::MPCError;

        // Simulate one party
        let m = 1;
        let n = 32;

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(n, m);

        use rand::Rng;
        let mut rng = rand::thread_rng();

        let v0 = rng.gen::<u32>() as u64;
        let v0_blinding = Scalar::random(&mut rng);
        let party0 = Party::new(&bp_gens, &pc_gens, v0, v0_blinding, n).unwrap();

        let dealer = Dealer::new(&bp_gens, &pc_gens, n, m).unwrap();

        // Now do the protocol flow as normal....

        let (party0, bit_com0) = party0.assign_position(0).unwrap();

        let (dealer, bit_challenge) = dealer.receive_bit_commitments(vec![bit_com0]).unwrap();

        let (party0, poly_com0) = party0.apply_challenge(&bit_challenge);

        let (_dealer, mut poly_challenge) =
            dealer.receive_poly_commitments(vec![poly_com0]).unwrap();

        // But now simulate a malicious dealer choosing x = 0
        poly_challenge.x = Scalar::zero();

        let maybe_share0 = party0.apply_challenge(&poly_challenge);

        assert!(maybe_share0.unwrap_err() == MPCError::MaliciousDealer);
    }
}

//! The `dealer` module contains the API for the dealer state while
//! the dealer is engaging in an aggregated multiparty computation
//! protocol.

use core::iter;

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use tiny_keccak::{Hasher, Keccak};

use crate::bulletproof::generators::{BulletproofGens, PedersenGens};
use crate::bulletproof::inner_product_proof;
use crate::bulletproof::messages::*;
use crate::bulletproof::util;
use crate::bulletproof::MPCError;
use crate::bulletproof::RangeProof;

/// Used to construct a dealer for the aggregated rangeproof MPC protocol.
pub struct Dealer {}

impl Dealer {
    /// Creates a new dealer coordinating `m` parties proving `n`-bit ranges.
    pub fn new<'a>(
        bp_gens: &'a BulletproofGens,
        pc_gens: &'a PedersenGens,
        n: usize,
        m: usize,
    ) -> Result<DealerAwaitingBitCommitments<'a>, MPCError> {
        if !(n == 8 || n == 16 || n == 32 || n == 64) {
            return Err(MPCError::InvalidBitsize);
        }
        if !m.is_power_of_two() {
            return Err(MPCError::InvalidAggregation);
        }
        if bp_gens.gens_capacity < n {
            return Err(MPCError::InvalidGeneratorsLength);
        }
        if bp_gens.party_capacity < m {
            return Err(MPCError::InvalidGeneratorsLength);
        }

        Ok(DealerAwaitingBitCommitments {
            bp_gens,
            pc_gens,
            n,
            m,
        })
    }
}

/// A dealer waiting for the parties to send their [`BitCommitment`]s.
pub struct DealerAwaitingBitCommitments<'a> {
    bp_gens: &'a BulletproofGens,
    pc_gens: &'a PedersenGens,
    n: usize,
    m: usize,
}

impl<'a> DealerAwaitingBitCommitments<'a> {
    /// Receive each party's [`BitCommitment`]s and compute the [`BitChallenge`].
    pub fn receive_bit_commitments(
        self,
        bit_commitments: Vec<BitCommitment>,
    ) -> Result<(DealerAwaitingPolyCommitments<'a>, BitChallenge), MPCError> {
        if self.m != bit_commitments.len() {
            return Err(MPCError::WrongNumBitCommitments);
        }

        // Commit aggregated A_j, S_j
        let A: EdwardsPoint = bit_commitments.iter().map(|vc| vc.A_j).sum();
        let S: EdwardsPoint = bit_commitments.iter().map(|vc| vc.S_j).sum();

        let mut keccak = Keccak::v256();
        for bit_commitment in bit_commitments.iter() {
            keccak.update(bit_commitment.V_j.as_bytes());
        }
        let mut hash_commitments = [0u8; 32];
        keccak.finalize(&mut hash_commitments);
        let hash_commitments = Scalar::from_bytes_mod_order(hash_commitments);

        let mut keccak = Keccak::v256();
        keccak.update(hash_commitments.as_bytes());
        keccak.update(A.compress().as_bytes());
        keccak.update(S.compress().as_bytes());
        let mut y = [0u8; 32];
        keccak.finalize(&mut y);
        let y = Scalar::from_bytes_mod_order(y);

        let mut keccak = Keccak::v256();
        keccak.update(y.as_bytes());
        let mut z = [0u8; 32];
        keccak.finalize(&mut z);

        // TODO: Must check if scalars are equal to zero and abort if so (or retry)

        let z = Scalar::from_bytes_mod_order(z);

        let bit_challenge = BitChallenge { y, z };

        Ok((
            DealerAwaitingPolyCommitments {
                n: self.n,
                m: self.m,
                bp_gens: self.bp_gens,
                pc_gens: self.pc_gens,
                bit_challenge,
                A,
                S,
            },
            bit_challenge,
        ))
    }
}

/// A dealer which has sent the [`BitChallenge`] to the parties and
/// is waiting for their [`PolyCommitment`]s.
pub struct DealerAwaitingPolyCommitments<'a> {
    n: usize,
    m: usize,
    bp_gens: &'a BulletproofGens,
    pc_gens: &'a PedersenGens,
    bit_challenge: BitChallenge,
    /// Aggregated commitment to the parties' bits
    A: EdwardsPoint,
    /// Aggregated commitment to the parties' bit blindings
    S: EdwardsPoint,
}

impl<'a> DealerAwaitingPolyCommitments<'a> {
    /// Receive [`PolyCommitment`]s from the parties and compute the
    /// [`PolyChallenge`].
    pub fn receive_poly_commitments(
        self,
        poly_commitments: Vec<PolyCommitment>,
    ) -> Result<(DealerAwaitingProofShares<'a>, PolyChallenge), MPCError> {
        if self.m != poly_commitments.len() {
            return Err(MPCError::WrongNumPolyCommitments);
        }

        // Commit sums of T_1_j's and T_2_j's
        let T_1: EdwardsPoint = poly_commitments.iter().map(|pc| pc.T_1_j).sum();
        let T_2: EdwardsPoint = poly_commitments.iter().map(|pc| pc.T_2_j).sum();

        let mut keccak = Keccak::v256();
        keccak.update(self.bit_challenge.z.as_bytes());
        keccak.update(self.bit_challenge.z.as_bytes());
        keccak.update(T_1.compress().as_bytes());
        keccak.update(T_2.compress().as_bytes());
        let mut x = [0u8; 32];
        keccak.finalize(&mut x);
        let x = Scalar::from_bytes_mod_order(x);

        let poly_challenge = PolyChallenge { x };

        Ok((
            DealerAwaitingProofShares {
                n: self.n,
                m: self.m,
                bp_gens: self.bp_gens,
                pc_gens: self.pc_gens,
                bit_challenge: self.bit_challenge,
                A: self.A,
                S: self.S,
                poly_challenge,
                T_1,
                T_2,
            },
            poly_challenge,
        ))
    }
}

/// A dealer which has sent the [`PolyChallenge`] to the parties and
/// is waiting to aggregate their [`ProofShare`]s into a
/// [`RangeProof`].
pub struct DealerAwaitingProofShares<'a> {
    n: usize,
    m: usize,
    bp_gens: &'a BulletproofGens,
    pc_gens: &'a PedersenGens,
    bit_challenge: BitChallenge,
    poly_challenge: PolyChallenge,
    A: EdwardsPoint,
    S: EdwardsPoint,
    T_1: EdwardsPoint,
    T_2: EdwardsPoint,
}

impl<'a> DealerAwaitingProofShares<'a> {
    /// Assembles proof shares into an `RangeProof`.
    fn assemble_shares(&mut self, proof_shares: &[ProofShare]) -> Result<RangeProof, MPCError> {
        if self.m != proof_shares.len() {
            return Err(MPCError::WrongNumProofShares);
        }

        // Validate lengths for each share
        let mut bad_shares = Vec::<usize>::new(); // no allocations until we append
        for (j, share) in proof_shares.iter().enumerate() {
            share
                .check_size(self.n, &self.bp_gens, j)
                .unwrap_or_else(|_| {
                    bad_shares.push(j);
                });
        }

        if bad_shares.len() > 0 {
            return Err(MPCError::MalformedProofShares { bad_shares });
        }

        let t_x: Scalar = proof_shares.iter().map(|ps| ps.t_x).sum();
        let t_x_blinding: Scalar = proof_shares.iter().map(|ps| ps.t_x_blinding).sum();
        let e_blinding: Scalar = proof_shares.iter().map(|ps| ps.e_blinding).sum();

        // Get a challenge value to combine statements for the IPP
        let mut keccak = Keccak::v256();
        keccak.update(self.poly_challenge.x.as_bytes());
        keccak.update(self.poly_challenge.x.as_bytes());
        keccak.update(t_x_blinding.as_bytes());
        keccak.update(e_blinding.as_bytes());
        keccak.update(t_x.as_bytes());
        let mut w = [0u8; 32];
        keccak.finalize(&mut w);
        // TODO: Monero checks if w is equal to zero and aborts if so (bulletproof.cc:720)
        let w = Scalar::from_bytes_mod_order(w);
        let Q = w * self.pc_gens.B;

        let G_factors: Vec<Scalar> = iter::repeat(Scalar::one()).take(self.n * self.m).collect();
        let H_factors: Vec<Scalar> = util::exp_iter(self.bit_challenge.y.invert())
            .take(self.n * self.m)
            .collect();

        let l_vec: Vec<Scalar> = proof_shares
            .iter()
            .flat_map(|ps| ps.l_vec.clone().into_iter())
            .collect();
        let r_vec: Vec<Scalar> = proof_shares
            .iter()
            .flat_map(|ps| ps.r_vec.clone().into_iter())
            .collect();

        let ipp_proof = inner_product_proof::InnerProductProof::create(
            &w,
            &Q,
            &G_factors,
            &H_factors,
            self.bp_gens.G(self.n, self.m).cloned().collect(),
            self.bp_gens.H(self.n, self.m).cloned().collect(),
            l_vec,
            r_vec,
        );

        Ok(RangeProof {
            A: self.A.compress(),
            S: self.S.compress(),
            T_1: self.T_1.compress(),
            T_2: self.T_2.compress(),
            t_x,
            t_x_blinding,
            e_blinding,
            ipp_proof,
        })
    }

    /// Assemble the final aggregated [`RangeProof`] from the given
    /// `proof_shares`, but skip validation of the proof.
    ///
    /// ## WARNING
    ///
    /// This function does **NOT** validate the proof shares.  It is
    /// suitable for creating aggregated proofs when all parties are
    /// known by the dealer to be honest (for instance, when there's
    /// only one party playing all roles).
    pub fn receive_trusted_shares(
        mut self,
        proof_shares: &[ProofShare],
    ) -> Result<RangeProof, MPCError> {
        self.assemble_shares(proof_shares)
    }
}

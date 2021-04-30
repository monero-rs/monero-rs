//! The `messages` module contains the API for the messages passed
//! between the parties and the dealer in an aggregated multiparty
//! computation protocol.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;

use crate::bulletproof::generators::BulletproofGens;

/// A commitment to the bits of a party's value.
#[derive(Copy, Clone, Debug)]
pub struct BitCommitment {
    pub(super) V_j: CompressedEdwardsY,
    pub(super) A_j: EdwardsPoint,
    pub(super) S_j: EdwardsPoint,
}

/// Challenge values derived from all parties' [`BitCommitment`]s.
#[derive(Copy, Clone, Debug)]
pub struct BitChallenge {
    pub(super) y: Scalar,
    pub(super) z: Scalar,
}

/// A commitment to a party's polynomial coefficents.
#[derive(Copy, Clone, Debug)]
pub struct PolyCommitment {
    pub(super) T_1_j: EdwardsPoint,
    pub(super) T_2_j: EdwardsPoint,
}

/// Challenge values derived from all parties' [`PolyCommitment`]s.
#[derive(Copy, Clone, Debug)]
pub struct PolyChallenge {
    pub(super) x: Scalar,
}

/// A party's proof share, ready for aggregation into the final
/// [`RangeProof`](::RangeProof).
#[derive(Clone, Debug)]
pub struct ProofShare {
    pub(super) t_x: Scalar,
    pub(super) t_x_blinding: Scalar,
    pub(super) e_blinding: Scalar,
    pub(super) l_vec: Vec<Scalar>,
    pub(super) r_vec: Vec<Scalar>,
}

impl ProofShare {
    /// Checks consistency of all sizes in the proof share and returns the size of the l/r vector.
    pub(super) fn check_size(
        &self,
        expected_n: usize,
        bp_gens: &BulletproofGens,
        j: usize,
    ) -> Result<(), ()> {
        if self.l_vec.len() != expected_n {
            return Err(());
        }

        if self.r_vec.len() != expected_n {
            return Err(());
        }

        if expected_n > bp_gens.gens_capacity {
            return Err(());
        }

        if j >= bp_gens.party_capacity {
            return Err(());
        }

        Ok(())
    }
}

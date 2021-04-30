//! The `generators` module contains API for producing a set of
//! generators for a rangeproof.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use hash_edwards_to_edwards::hash_to_point;
use tiny_keccak::{Hasher, Keccak};

lazy_static::lazy_static! {
    /// Alternate generator of ed25519.
    ///
    /// Obtained by hashing `curve25519_dalek::constants::ED25519_BASEPOINT_POINT`.
    /// Originally used in Monero Ring Confidential Transactions.
    pub static ref H: EdwardsPoint = {
        CompressedEdwardsY(hex_literal::hex!(
            "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"
        ))
        .decompress()
        .expect("edwards point")
    };
}

/// Represents a pair of base points for Pedersen commitments.
///
/// The Bulletproofs implementation and API is designed to support
/// pluggable bases for Pedersen commitments, so that the choice of
/// bases is not hard-coded.
///
/// The default generators are:
///
/// * `B`: Monero's `H` basepoint;
/// * `B_blinding`: the ed25519 basepoint
/// hash-to-group on input `B_bytes`.
#[derive(Copy, Clone)]
pub struct PedersenGens {
    /// Base for the committed value
    pub B: EdwardsPoint,
    /// Base for the blinding factor
    pub B_blinding: EdwardsPoint,
}

impl PedersenGens {
    /// Creates a Pedersen commitment using the value scalar and a blinding factor.
    pub fn commit(&self, value: Scalar, blinding: Scalar) -> EdwardsPoint {
        EdwardsPoint::multiscalar_mul(&[value, blinding], &[self.B, self.B_blinding])
    }
}

impl Default for PedersenGens {
    fn default() -> Self {
        PedersenGens {
            B: *H,
            B_blinding: ED25519_BASEPOINT_POINT,
        }
    }
}

/// The `BulletproofGens` struct contains all the generators needed
/// for aggregating up to `m` range proofs of up to `n` bits each.
#[derive(Clone, Debug)]
pub struct BulletproofGens {
    /// The maximum number of usable generators for each party.
    pub gens_capacity: usize,
    /// Number of values or parties
    pub party_capacity: usize,
    /// Precomputed \\(\mathbf G\\) generators for each party.
    pub G_vec: Vec<Vec<EdwardsPoint>>,
    /// Precomputed \\(\mathbf H\\) generators for each party.
    pub H_vec: Vec<Vec<EdwardsPoint>>,
}

impl BulletproofGens {
    /// Create a new `BulletproofGens` object.
    ///
    /// # Inputs
    ///
    /// * `gens_capacity` is the number of generators to precompute
    ///    for each party.  For rangeproofs, it is sufficient to pass
    ///    `64`, the maximum bitsize of the rangeproofs.
    ///
    /// * `party_capacity` is the maximum number of parties that can
    ///    produce an aggregated proof.
    pub fn new(gens_capacity: usize, party_capacity: usize) -> Self {
        fn varint_to_bytes(n: usize) -> Vec<u8> {
            use integer_encoding::VarInt;
            n.encode_var_vec()
        }

        let mut gens = BulletproofGens {
            gens_capacity,
            party_capacity,
            G_vec: Vec::new(),
            H_vec: Vec::new(),
        };

        let max_index = party_capacity * gens_capacity;
        for i in 0..max_index {
            if i % gens_capacity == 0 {
                gens.H_vec.push(Vec::new());
            }

            let mut keccak = Keccak::v256();
            keccak.update(H.compress().as_bytes());
            keccak.update(b"bulletproof");
            keccak.update(&varint_to_bytes(i * 2));

            let mut output = [0u8; 32];
            keccak.finalize(&mut output);

            let edwards_point = hash_to_point(&output);

            let last_index = gens.H_vec.len() - 1;
            gens.H_vec[last_index].push(edwards_point)
        }

        for i in 0..max_index {
            if i % gens_capacity == 0 {
                gens.G_vec.push(Vec::new());
            }

            let mut keccak = Keccak::v256();
            keccak.update(H.compress().as_bytes());
            keccak.update(b"bulletproof");
            keccak.update(&varint_to_bytes((i * 2) + 1));

            let mut output = [0u8; 32];
            keccak.finalize(&mut output);

            let edwards_point = hash_to_point(&output);

            let last_index = gens.G_vec.len() - 1;
            gens.G_vec[last_index].push(edwards_point)
        }

        gens
    }

    /// Returns j-th share of generators, with an appropriate
    /// slice of vectors G and H for the j-th range proof.
    pub fn share(&self, j: usize) -> BulletproofGensShare<'_> {
        BulletproofGensShare {
            gens: &self,
            share: j,
        }
    }

    /// Return an iterator over the aggregation of the parties' G generators with given size `n`.
    pub(crate) fn G(&self, n: usize, m: usize) -> impl Iterator<Item = &EdwardsPoint> {
        AggregatedGensIter {
            n,
            m,
            array: &self.G_vec,
            party_idx: 0,
            gen_idx: 0,
        }
    }

    /// Return an iterator over the aggregation of the parties' H generators with given size `n`.
    pub(crate) fn H(&self, n: usize, m: usize) -> impl Iterator<Item = &EdwardsPoint> {
        AggregatedGensIter {
            n,
            m,
            array: &self.H_vec,
            party_idx: 0,
            gen_idx: 0,
        }
    }
}

struct AggregatedGensIter<'a> {
    array: &'a Vec<Vec<EdwardsPoint>>,
    n: usize,
    m: usize,
    party_idx: usize,
    gen_idx: usize,
}

impl<'a> Iterator for AggregatedGensIter<'a> {
    type Item = &'a EdwardsPoint;

    fn next(&mut self) -> Option<Self::Item> {
        if self.gen_idx >= self.n {
            self.gen_idx = 0;
            self.party_idx += 1;
        }

        if self.party_idx >= self.m {
            None
        } else {
            let cur_gen = self.gen_idx;
            self.gen_idx += 1;
            Some(&self.array[self.party_idx][cur_gen])
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.n * (self.m - self.party_idx) - self.gen_idx;
        (size, Some(size))
    }
}

/// Represents a view of the generators used by a specific party in an
/// aggregated proof.
///
/// The `BulletproofGens` struct represents generators for an aggregated
/// range proof `m` proofs of `n` bits each; the `BulletproofGensShare`
/// provides a view of the generators for one of the `m` parties' shares.
///
/// The `BulletproofGensShare` is produced by [`BulletproofGens::share()`].
#[derive(Copy, Clone)]
pub struct BulletproofGensShare<'a> {
    /// The parent object that this is a view into
    gens: &'a BulletproofGens,
    /// Which share we are
    share: usize,
}

impl<'a> BulletproofGensShare<'a> {
    /// Return an iterator over this party's G generators with given size `n`.
    pub(crate) fn G(&self, n: usize) -> impl Iterator<Item = &'a EdwardsPoint> {
        self.gens.G_vec[self.share].iter().take(n)
    }

    /// Return an iterator over this party's H generators with given size `n`.
    pub(crate) fn H(&self, n: usize) -> impl Iterator<Item = &'a EdwardsPoint> {
        self.gens.H_vec[self.share].iter().take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregated_gens_iter_matches_flat_map() {
        let gens = BulletproofGens::new(64, 8);

        let helper = |n: usize, m: usize| {
            let agg_G: Vec<EdwardsPoint> = gens.G(n, m).cloned().collect();
            let flat_G: Vec<EdwardsPoint> = gens
                .G_vec
                .iter()
                .take(m)
                .flat_map(move |G_j| G_j.iter().take(n))
                .cloned()
                .collect();

            let agg_H: Vec<EdwardsPoint> = gens.H(n, m).cloned().collect();
            let flat_H: Vec<EdwardsPoint> = gens
                .H_vec
                .iter()
                .take(m)
                .flat_map(move |H_j| H_j.iter().take(n))
                .cloned()
                .collect();

            assert_eq!(agg_G, flat_G);
            assert_eq!(agg_H, flat_H);
        };

        helper(64, 8);
        helper(64, 4);
        helper(64, 2);
        helper(64, 1);
        helper(32, 8);
        helper(32, 4);
        helper(32, 2);
        helper(32, 1);
        helper(16, 8);
        helper(16, 4);
        helper(16, 2);
        helper(16, 1);
    }
}

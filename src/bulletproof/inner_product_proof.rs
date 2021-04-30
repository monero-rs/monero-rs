#![allow(non_snake_case)]

use core::borrow::Borrow;
use core::iter;

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use tiny_keccak::{Hasher, Keccak};

use crate::bulletproof::ProofError;
use crate::bulletproof::INV_EIGHT;

#[derive(Clone, Debug)]
pub struct InnerProductProof {
    pub(crate) L_vec: Vec<CompressedEdwardsY>,
    pub(crate) R_vec: Vec<CompressedEdwardsY>,
    pub(crate) a: Scalar,
    pub(crate) b: Scalar,
}

impl InnerProductProof {
    /// Create an inner-product proof.
    ///
    /// The proof is created with respect to the bases \\(G\\), \\(H'\\),
    /// where \\(H'\_i = H\_i \cdot \texttt{Hprime\\_factors}\_i\\).
    ///
    /// The lengths of the vectors must all be the same, and must all
    /// be either 0 or a power of 2.
    #[allow(clippy::many_single_char_names)]
    pub fn create(
        w: &Scalar,
        Q: &EdwardsPoint,
        G_factors: &[Scalar],
        H_factors: &[Scalar],
        mut G_vec: Vec<EdwardsPoint>,
        mut H_vec: Vec<EdwardsPoint>,
        mut a_vec: Vec<Scalar>,
        mut b_vec: Vec<Scalar>,
    ) -> InnerProductProof {
        // Create slices G, H, a, b backed by their respective
        // vectors.  This lets us reslice as we compress the lengths
        // of the vectors in the main loop below.
        // Gprime
        let mut G = &mut G_vec[..];
        // Hprime
        let mut H = &mut H_vec[..];
        // a_prime
        let mut a = &mut a_vec[..];
        // b_prime
        let mut b = &mut b_vec[..];

        let mut n = G.len();

        // All of the input vectors must have the same length.
        assert_eq!(G.len(), n);
        assert_eq!(H.len(), n);
        assert_eq!(a.len(), n);
        assert_eq!(b.len(), n);
        assert_eq!(G_factors.len(), n);
        assert_eq!(H_factors.len(), n);

        // All of the input vectors must have a length that is a power of two.
        assert!(n.is_power_of_two());

        let lg_n = n.next_power_of_two().trailing_zeros() as usize;
        let mut L_vec = Vec::with_capacity(lg_n);
        let mut R_vec = Vec::with_capacity(lg_n);

        let mut prev_u = Scalar::zero();

        // If it's the first iteration, unroll the Hprime = H*y_inv scalar mults
        // into multiscalar muls, for performance.
        // line 727 in bulletproof.cc
        if n != 1 {
            n = n / 2;
            let (a_L, a_R) = a.split_at_mut(n);
            let (b_L, b_R) = b.split_at_mut(n);
            let (G_L, G_R) = G.split_at_mut(n);
            let (H_L, H_R) = H.split_at_mut(n);

            // line 734 bulletproof.cc
            let c_L = inner_product(&a_L, &b_R);
            let c_R = inner_product(&a_R, &b_L);

            let L = EdwardsPoint::vartime_multiscalar_mul(
                a_L.iter()
                    .zip(G_factors[n..2 * n].into_iter())
                    .map(|(a_L_i, g)| a_L_i * g)
                    .chain(
                        b_R.iter()
                            .zip(H_factors[0..n].into_iter())
                            .map(|(b_R_i, h)| b_R_i * h),
                    )
                    .chain(iter::once(c_L))
                    .map(|s| s * *INV_EIGHT),
                G_R.iter().chain(H_L.iter()).chain(iter::once(Q)),
            )
            .compress();

            let R = EdwardsPoint::vartime_multiscalar_mul(
                a_R.iter()
                    .zip(G_factors[0..n].into_iter())
                    .map(|(a_R_i, g)| a_R_i * g)
                    .chain(
                        b_L.iter()
                            .zip(H_factors[n..2 * n].into_iter())
                            .map(|(b_L_i, h)| b_L_i * h),
                    )
                    .chain(iter::once(c_R))
                    .map(|s| s * *INV_EIGHT),
                G_L.iter().chain(H_R.iter()).chain(iter::once(Q)),
            )
            .compress();

            L_vec.push(L);
            R_vec.push(R);

            let mut keccak = Keccak::v256();
            keccak.update(w.as_bytes());
            keccak.update(L.as_bytes());
            keccak.update(R.as_bytes());

            let mut u = [0u8; 32];
            keccak.finalize(&mut u);
            let u = Scalar::from_bytes_mod_order(u);
            let u_inv = u.invert();

            prev_u = u;

            for i in 0..n {
                a_L[i] = a_L[i] * u + u_inv * a_R[i];
                b_L[i] = b_L[i] * u_inv + u * b_R[i];
                G_L[i] = EdwardsPoint::vartime_multiscalar_mul(
                    &[u_inv * G_factors[i], u * G_factors[n + i]],
                    &[G_L[i], G_R[i]],
                );
                H_L[i] = EdwardsPoint::vartime_multiscalar_mul(
                    &[u * H_factors[i], u_inv * H_factors[n + i]],
                    &[H_L[i], H_R[i]],
                )
            }

            a = a_L;
            b = b_L;
            G = G_L;
            H = H_L;
        }

        while n != 1 {
            n = n / 2;
            let (a_L, a_R) = a.split_at_mut(n);
            let (b_L, b_R) = b.split_at_mut(n);
            let (G_L, G_R) = G.split_at_mut(n);
            let (H_L, H_R) = H.split_at_mut(n);

            let c_L = inner_product(&a_L, &b_R);
            let c_R = inner_product(&a_R, &b_L);

            let L = EdwardsPoint::vartime_multiscalar_mul(
                a_L.iter()
                    .chain(b_R.iter())
                    .chain(iter::once(&c_L))
                    .map(|s| s * *INV_EIGHT),
                G_R.iter().chain(H_L.iter()).chain(iter::once(Q)),
            )
            .compress();

            let R = EdwardsPoint::vartime_multiscalar_mul(
                a_R.iter()
                    .chain(b_L.iter())
                    .chain(iter::once(&c_R))
                    .map(|s| s * *INV_EIGHT),
                G_L.iter().chain(H_R.iter()).chain(iter::once(Q)),
            )
            .compress();

            L_vec.push(L);
            R_vec.push(R);

            let mut keccak = Keccak::v256();
            keccak.update(prev_u.as_bytes());
            keccak.update(L.as_bytes());
            keccak.update(R.as_bytes());

            let mut u = [0u8; 32];
            keccak.finalize(&mut u);
            let u = Scalar::from_bytes_mod_order(u);
            let u_inv = u.invert();

            prev_u = u;

            for i in 0..n {
                a_L[i] = a_L[i] * u + u_inv * a_R[i];
                b_L[i] = b_L[i] * u_inv + u * b_R[i];
                G_L[i] = EdwardsPoint::vartime_multiscalar_mul(&[u_inv, u], &[G_L[i], G_R[i]]);
                H_L[i] = EdwardsPoint::vartime_multiscalar_mul(&[u, u_inv], &[H_L[i], H_R[i]]);
            }

            a = a_L;
            b = b_L;
            G = G_L;
            H = H_L;
        }

        InnerProductProof {
            L_vec,
            R_vec,
            a: a[0],
            b: b[0],
        }
    }

    /// Computes three vectors of verification scalars
    /// \\([u\_{i}^{2}]\\), \\([u\_{i}^{-2}]\\) and \\([s\_{i}]\\) for
    /// combined multiscalar multiplication in a parent protocol.
    ///
    /// The verifier must provide the input length \\(n\\) explicitly
    /// to avoid unbounded allocation within the inner product proof.
    pub(crate) fn verification_scalars(
        &self,
        n: usize,
        w: Scalar,
    ) -> Result<(Vec<Scalar>, Vec<Scalar>, Vec<Scalar>), ProofError> {
        let lg_n = self.L_vec.len();
        if lg_n >= 32 {
            // 4 billion multiplications should be enough for anyone
            // and this check prevents overflow in 1<<lg_n below.
            return Err(ProofError::VerificationError);
        }
        if n != (1 << lg_n) {
            return Err(ProofError::VerificationError);
        }

        // 1. Recompute x_k,...,x_1 based on the proof transcript

        let mut prev_u = w;
        let mut challenges = Vec::with_capacity(lg_n);
        for (L, R) in self.L_vec.iter().zip(self.R_vec.iter()) {
            let mut keccak = Keccak::v256();
            keccak.update(prev_u.as_bytes());
            keccak.update(L.as_bytes());
            keccak.update(R.as_bytes());

            let mut u = [0u8; 32];
            keccak.finalize(&mut u);
            let u = Scalar::from_bytes_mod_order(u);

            challenges.push(u);
            prev_u = u;
        }

        // 2. Compute 1/(u_k...u_1) and 1/u_k, ..., 1/u_1

        let mut challenges_inv = challenges.clone();
        let allinv = Scalar::batch_invert(&mut challenges_inv);

        // 3. Compute u_i^2 and (1/u_i)^2

        for i in 0..lg_n {
            // XXX missing square fn upstream
            challenges[i] = challenges[i] * challenges[i];
            challenges_inv[i] = challenges_inv[i] * challenges_inv[i];
        }
        let challenges_sq = challenges;
        let challenges_inv_sq = challenges_inv;

        // 4. Compute s values inductively.

        let mut s = Vec::with_capacity(n);
        s.push(allinv);
        for i in 1..n {
            let lg_i = (32 - 1 - (i as u32).leading_zeros()) as usize;
            let k = 1 << lg_i;
            // The challenges are stored in "creation order" as [u_k,...,u_1],
            // so u_{lg(i)+1} = is indexed by (lg_n-1) - lg_i
            let u_lg_i_sq = challenges_sq[(lg_n - 1) - lg_i];
            s.push(s[i - k] * u_lg_i_sq);
        }

        Ok((challenges_sq, challenges_inv_sq, s))
    }

    /// This method is for testing that proof generation works, but
    /// for efficiency the actual protocols would use the
    /// `verification_scalars` method to combine inner product
    /// verification with other checks in a single multiscalar
    /// multiplication.
    #[allow(dead_code)]
    pub fn verify<IG, IH>(
        &self,
        n: usize,
        G_factors: IG,
        H_factors: IH,
        P: &EdwardsPoint,
        Q: &EdwardsPoint,
        G: &[EdwardsPoint],
        H: &[EdwardsPoint],
        w: Scalar,
    ) -> Result<(), ProofError>
    where
        IG: IntoIterator,
        IG::Item: Borrow<Scalar>,
        IH: IntoIterator,
        IH::Item: Borrow<Scalar>,
    {
        let (u_sq, u_inv_sq, s) = self.verification_scalars(n, w)?;

        let g_times_a_times_s = G_factors
            .into_iter()
            .zip(s.iter())
            .map(|(g_i, s_i)| (self.a * s_i) * g_i.borrow())
            .take(G.len());

        // 1/s[i] is s[!i], and !i runs from n-1 to 0 as i runs from 0 to n-1
        let inv_s = s.iter().rev();

        let h_times_b_div_s = H_factors
            .into_iter()
            .zip(inv_s)
            .map(|(h_i, s_i_inv)| (self.b * s_i_inv) * h_i.borrow());

        let neg_u_sq = u_sq.iter().map(|ui| -ui);
        let neg_u_inv_sq = u_inv_sq.iter().map(|ui| -ui);

        let eight = Scalar::from(8u8);
        let Ls = self
            .L_vec
            .iter()
            .map(|p| {
                p.decompress()
                    .map(|p| eight * p)
                    .ok_or(ProofError::VerificationError)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let Rs = self
            .R_vec
            .iter()
            .map(|p| {
                p.decompress()
                    .map(|p| eight * p)
                    .ok_or(ProofError::VerificationError)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let expect_P = EdwardsPoint::vartime_multiscalar_mul(
            iter::once(self.a * self.b)
                .chain(g_times_a_times_s)
                .chain(h_times_b_div_s)
                .chain(neg_u_sq)
                .chain(neg_u_inv_sq),
            iter::once(Q)
                .chain(G.iter())
                .chain(H.iter())
                .chain(Ls.iter())
                .chain(Rs.iter()),
        );

        if expect_P == *P {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }

    /// Returns the size in bytes required to serialize the inner
    /// product proof.
    ///
    /// For vectors of length `n` the proof size is
    /// \\(32 \cdot (2\lg n+2)\\) bytes.
    pub fn serialized_size(&self) -> usize {
        (self.L_vec.len() * 2 + 2) * 32
    }

    /// Serializes the proof into a byte array of \\(2n+2\\) 32-byte elements.
    /// The layout of the inner product proof is:
    /// * \\(n\\) pairs of compressed Edwards points \\(L_0, R_0 \dots, L_{n-1}, R_{n-1}\\),
    /// * two scalars \\(a, b\\).
    #[cfg(test)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.serialized_size());
        for (l, r) in self.L_vec.iter().zip(self.R_vec.iter()) {
            buf.extend_from_slice(l.as_bytes());
            buf.extend_from_slice(r.as_bytes());
        }
        buf.extend_from_slice(self.a.as_bytes());
        buf.extend_from_slice(self.b.as_bytes());
        buf
    }

    /// Converts the proof into a byte iterator over serialized view of the proof.
    /// The layout of the inner product proof is:
    /// * \\(n\\) pairs of compressed Edwards points \\(L_0, R_0 \dots, L_{n-1}, R_{n-1}\\),
    /// * two scalars \\(a, b\\).
    #[inline]
    pub(crate) fn to_bytes_iter(&self) -> impl Iterator<Item = u8> + '_ {
        self.L_vec
            .iter()
            .zip(self.R_vec.iter())
            .flat_map(|(l, r)| l.as_bytes().iter().chain(r.as_bytes()))
            .chain(self.a.as_bytes())
            .chain(self.b.as_bytes())
            .copied()
    }

    /// Deserializes the proof from a byte slice.
    /// Returns an error in the following cases:
    /// * the slice does not have \\(2n+2\\) 32-byte elements,
    /// * \\(n\\) is larger or equal to 32 (proof is too big),
    /// * any of \\(2n\\) points are not valid compressed Edwards points,
    /// * any of 2 scalars are not canonical scalars modulo the Ed25519 group order.
    pub fn from_bytes(slice: &[u8]) -> Result<InnerProductProof, ProofError> {
        let b = slice.len();
        if b % 32 != 0 {
            return Err(ProofError::FormatError);
        }
        let num_elements = b / 32;
        if num_elements < 2 {
            return Err(ProofError::FormatError);
        }
        if (num_elements - 2) % 2 != 0 {
            return Err(ProofError::FormatError);
        }
        let lg_n = (num_elements - 2) / 2;
        if lg_n >= 32 {
            return Err(ProofError::FormatError);
        }

        use crate::bulletproof::util::read32;

        let mut L_vec: Vec<CompressedEdwardsY> = Vec::with_capacity(lg_n);
        let mut R_vec: Vec<CompressedEdwardsY> = Vec::with_capacity(lg_n);
        for i in 0..lg_n {
            let pos = 2 * i * 32;
            L_vec.push(CompressedEdwardsY(read32(&slice[pos..])));
            R_vec.push(CompressedEdwardsY(read32(&slice[pos + 32..])));
        }

        let pos = 2 * lg_n * 32;
        let a =
            Scalar::from_canonical_bytes(read32(&slice[pos..])).ok_or(ProofError::FormatError)?;
        let b = Scalar::from_canonical_bytes(read32(&slice[pos + 32..]))
            .ok_or(ProofError::FormatError)?;

        Ok(InnerProductProof { L_vec, R_vec, a, b })
    }
}

/// Computes an inner product of two vectors
/// \\[
///    {\langle {\mathbf{a}}, {\mathbf{b}} \rangle} = \sum\_{i=0}^{n-1} a\_i \cdot b\_i.
/// \\]
/// Panics if the lengths of \\(\mathbf{a}\\) and \\(\mathbf{b}\\) are not equal.
pub fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    let mut out = Scalar::zero();
    if a.len() != b.len() {
        panic!("inner_product(a,b): lengths of vectors do not match");
    }
    for i in 0..a.len() {
        out += a[i] * b[i];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::bulletproof::util;
    use crate::bulletproof::BulletproofGens;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

    #[allow(clippy::many_single_char_names)]
    fn test_helper_create(n: usize) {
        let mut rng = rand::thread_rng();

        let bp_gens = BulletproofGens::new(n, 1);
        let G: Vec<EdwardsPoint> = bp_gens.share(0).G(n).cloned().collect();
        let H: Vec<EdwardsPoint> = bp_gens.share(0).H(n).cloned().collect();

        // Q would be determined upstream in the protocol, so we pick a random one.
        let w = Scalar::from(6u32);
        let Q = ED25519_BASEPOINT_POINT * w;

        // a and b are the vectors for which we want to prove c = <a,b>
        let a: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let b: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let c = inner_product(&a, &b);

        let G_factors: Vec<Scalar> = iter::repeat(Scalar::one()).take(n).collect();

        // y_inv is (the inverse of) a random challenge
        let y_inv = Scalar::random(&mut rng);
        let H_factors: Vec<Scalar> = util::exp_iter(y_inv).take(n).collect();

        // P would be determined upstream, but we need a correct P to check the proof.
        //
        // To generate P = <a,G> + <b,H'> + <a,b> Q, compute
        //             P = <a,G> + <b',H> + <a,b> Q,
        // where b' = b \circ y^(-n)
        let b_prime = b.iter().zip(util::exp_iter(y_inv)).map(|(bi, yi)| bi * yi);
        // a.iter() has Item=&Scalar, need Item=Scalar to chain with b_prime
        let a_prime = a.iter().cloned();

        let P = EdwardsPoint::vartime_multiscalar_mul(
            a_prime.chain(b_prime).chain(iter::once(c)),
            G.iter().chain(H.iter()).chain(iter::once(&Q)),
        );

        let proof = InnerProductProof::create(
            &w,
            &Q,
            &G_factors,
            &H_factors,
            G.clone(),
            H.clone(),
            a.clone(),
            b.clone(),
        );

        assert!(proof
            .verify(
                n,
                iter::repeat(Scalar::one()).take(n),
                util::exp_iter(y_inv).take(n),
                &P,
                &Q,
                &G,
                &H,
                w
            )
            .is_ok());

        let proof = InnerProductProof::from_bytes(proof.to_bytes().as_slice()).unwrap();
        assert!(proof
            .verify(
                n,
                iter::repeat(Scalar::one()).take(n),
                util::exp_iter(y_inv).take(n),
                &P,
                &Q,
                &G,
                &H,
                w
            )
            .is_ok());
    }

    #[test]
    fn make_ipp_1() {
        test_helper_create(1);
    }

    #[test]
    fn make_ipp_2() {
        test_helper_create(2);
    }

    #[test]
    fn make_ipp_4() {
        test_helper_create(4);
    }

    #[test]
    fn make_ipp_32() {
        test_helper_create(32);
    }

    #[test]
    fn make_ipp_64() {
        test_helper_create(64);
    }

    #[test]
    fn test_inner_product() {
        let a = vec![
            Scalar::from(1u64),
            Scalar::from(2u64),
            Scalar::from(3u64),
            Scalar::from(4u64),
        ];
        let b = vec![
            Scalar::from(2u64),
            Scalar::from(3u64),
            Scalar::from(4u64),
            Scalar::from(5u64),
        ];
        assert_eq!(Scalar::from(40u64), inner_product(&a, &b));
    }
}

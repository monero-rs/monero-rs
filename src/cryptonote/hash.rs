// Rust Monero Library
// Written in 2019-2022 by
//   Monero Rust Contributors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//

//! Hash functions and types (32-bytes hash and 8-bytes hash) used in [`blockdata`].
//!
//! Support for (de)serializable hashes (Keccak-256) and [`Hn()`] (hash to number, or hash to
//! scalar).
//!
//! [`blockdata`]: crate::blockdata
//! [`Hn()`]: Hashable::hash_to_scalar()
//!

use curve25519_dalek::scalar::Scalar;
use sealed::sealed;
use tiny_keccak::{Hasher, Keccak};

use std::io;

use crate::consensus::encode::{self, Decodable};
use crate::util::key::PrivateKey;
#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};

fixed_hash::construct_fixed_hash!(
    /// Result of the Keccak-256 hashing function.
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
    pub struct Hash(32);
);

impl Hash {
    /// Create a null hash with all zeros.
    pub fn null() -> Hash {
        Hash([0u8; 32])
    }

    /// Hash a stream of bytes with the Keccak-256 hash function.
    pub fn new(input: impl AsRef<[u8]>) -> Hash {
        Hash(keccak_256(input.as_ref()))
    }

    /// Return the 32-bytes hash array.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Return the scalar of the hash as a little endian number modulo `l` (curve order).
    pub fn as_scalar(&self) -> PrivateKey {
        PrivateKey::from_scalar(Scalar::from_bytes_mod_order(self.0))
    }

    /// Hash a stream of bytes and return its scalar representation.
    ///
    /// The hash function `H` is the same Keccak function that is used in CryptoNote. When the
    /// value of the hash function is interpreted as a scalar, it is converted into a little-endian
    /// integer and taken modulo `l`.
    pub fn hash_to_scalar(input: impl AsRef<[u8]>) -> PrivateKey {
        Self::new(input).as_scalar()
    }
}

impl Decodable for Hash {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Hash, encode::Error> {
        Ok(Hash(Decodable::consensus_decode(r)?))
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for Hash {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

/// Capacity of an object to hash itself and return the result as a plain [`struct@Hash`] or as an
/// interpreted scalar value into [`PrivateKey`].
pub trait Hashable {
    /// Return its own hash.
    fn hash(&self) -> Hash;

    /// Apply [`hash()`] on itself and return the interpreted scalar returned by the hash result.
    ///
    /// [`hash()`]: Hashable::hash()
    fn hash_to_scalar(&self) -> PrivateKey {
        self.hash().as_scalar()
    }
}

fixed_hash::construct_fixed_hash!(
    /// An 8-bytes hash result.
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
    pub struct Hash8(8);
);

impl Decodable for Hash8 {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Hash8, encode::Error> {
        Ok(Hash8(Decodable::consensus_decode(r)?))
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for Hash8 {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

/// Compute the Keccak256 hash of the provided byte-slice.
pub fn keccak_256(input: &[u8]) -> [u8; 32] {
    let mut keccak = Keccak::v256();

    let mut out = [0u8; 32];
    keccak.update(input);
    keccak.finalize(&mut out);

    out
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "serde")]
    use super::*;

    #[cfg(feature = "serde")]
    use serde_test::{assert_tokens, Token};

    #[test]
    #[cfg(feature = "serde")]
    fn test_ser_de_hash_null() {
        let hash = Hash::null();

        assert_tokens(
            &hash,
            &[
                Token::NewtypeStruct { name: "Hash" },
                Token::Tuple { len: 32 },
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::TupleEnd,
            ],
        );

        let hash = Hash8([0u8; 8]);

        assert_tokens(
            &hash,
            &[
                Token::NewtypeStruct { name: "Hash8" },
                Token::Tuple { len: 8 },
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_ser_de_hash() {
        let hash = Hash::new("");

        assert_tokens(
            &hash,
            &[
                Token::NewtypeStruct { name: "Hash" },
                Token::Tuple { len: 32 },
                Token::U8(197),
                Token::U8(210),
                Token::U8(70),
                Token::U8(1),
                Token::U8(134),
                Token::U8(247),
                Token::U8(35),
                Token::U8(60),
                Token::U8(146),
                Token::U8(126),
                Token::U8(125),
                Token::U8(178),
                Token::U8(220),
                Token::U8(199),
                Token::U8(3),
                Token::U8(192),
                Token::U8(229),
                Token::U8(0),
                Token::U8(182),
                Token::U8(83),
                Token::U8(202),
                Token::U8(130),
                Token::U8(39),
                Token::U8(59),
                Token::U8(123),
                Token::U8(250),
                Token::U8(216),
                Token::U8(4),
                Token::U8(93),
                Token::U8(133),
                Token::U8(164),
                Token::U8(112),
                Token::TupleEnd,
            ],
        );
    }
}

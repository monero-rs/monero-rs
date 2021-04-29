// Rust Monero Library
// Written in 2019 by
//   h4sh3d <h4sh3d@protonmail.com>
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
use keccak_hash::keccak_256;

use std::io;

use crate::consensus::encode::{self, Decodable, Encodable};
use crate::util::key::PrivateKey;
#[cfg(feature = "serde_support")]
use serde::{Deserialize, Serialize};

fixed_hash::construct_fixed_hash!(
    /// Result of the Keccak-256 hashing function.
    #[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
    pub struct Hash(32);
);

impl Hash {
    /// Create a null hash with all zeros.
    pub fn null_hash() -> Hash {
        Hash([0u8; 32])
    }

    /// Hash a stream of bytes with the Keccak-256 hash function.
    pub fn hash(input: &[u8]) -> Hash {
        let mut out = [0u8; 32];
        keccak_256(input, &mut out);
        Hash(out)
    }

    /// Return the 32-bytes hash array.
    pub fn to_bytes(&self) -> [u8; 32] {
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
    pub fn hash_to_scalar(input: &[u8]) -> PrivateKey {
        Self::hash(input).as_scalar()
    }
}

impl Decodable for Hash {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Hash, encode::Error> {
        Ok(Hash(Decodable::consensus_decode(d)?))
    }
}

impl Encodable for Hash {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        self.0.consensus_encode(s)
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
    #[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
    pub struct Hash8(8);
);

impl Decodable for Hash8 {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Hash8, encode::Error> {
        Ok(Hash8(Decodable::consensus_decode(d)?))
    }
}

impl Encodable for Hash8 {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        self.0.consensus_encode(s)
    }
}

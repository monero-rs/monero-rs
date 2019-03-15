// Rust Monero Library
// Written in 2019 by
//   h4sh3d <h4sh3d@truelevel.io>
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

//! Hash support
//!
//! Support for (de)serializable hashes (Keccak 256) and `H_n` (hash to number, or hash to scalar).
//!

use std::fmt;

use keccak_hash::keccak_256;
use curve25519_dalek::scalar::Scalar;

use crate::util::key::PrivateKey;
use crate::consensus::encode::{self, Encoder, Decoder, Encodable, Decodable};

/// Result of a keccak 256
#[derive(PartialEq)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    /// Create a null hash with all zeros
    pub fn null_hash() -> Hash {
        Hash([0u8; 32])
    }

    /// Hash a stream of bytes with Keccak 256
    pub fn hash(input: &[u8]) -> Hash {
        let mut out = [0u8; 32];
        keccak_256(input, &mut out);
        Hash(out)
    }

    /// Return the hash value
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Return the scalar of the hash as a little endian number modulo l (curve order)
    pub fn as_scalar(&self) -> PrivateKey {
        PrivateKey::from_scalar(Scalar::from_bytes_mod_order(self.0))
    }

    /// Hash a stream of bytes and return its scalar representation
    ///
    /// The hash function H is the same Keccak function that is used in CryptoNote. When the
    /// value of the hash function is interpreted as a scalar, it is converted into a
    /// little-endian integer and taken modulo l.
    pub fn hash_to_scalar(input: &[u8]) -> PrivateKey {
        Self::hash(input).as_scalar()
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl<D: Decoder> Decodable<D> for Hash {
    fn consensus_decode(d: &mut D) -> Result<Hash, encode::Error> {
        Ok(Hash(Decodable::consensus_decode(d)?))
    }
}

impl<S: Encoder> Encodable<S> for Hash {
    fn consensus_encode(&self, s: &mut S) -> Result <(), encode::Error> {
        self.0.consensus_encode(s)
    }
}

/// Capacity of an object to hash itself
pub trait Hashable {
    /// Return its own hash
    fn hash(&self) -> Hash;

    /// Apply `hash_to_scalar` on itself and return the scalar
    fn hash_to_scalar(&self) -> PrivateKey {
        self.hash().as_scalar()
    }
}

/// 8 bytes hash
#[derive(PartialEq)]
pub struct Hash8(pub [u8; 8]);

impl fmt::Display for Hash8 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Hash8 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl<D: Decoder> Decodable<D> for Hash8 {
    fn consensus_decode(d: &mut D) -> Result<Hash8, encode::Error> {
        Ok(Hash8(Decodable::consensus_decode(d)?))
    }
}

impl<S: Encoder> Encodable<S> for Hash8 {
    fn consensus_encode(&self, s: &mut S) -> Result <(), encode::Error> {
        self.0.consensus_encode(s)
    }
}

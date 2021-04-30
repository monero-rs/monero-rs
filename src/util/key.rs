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

//! # Monero public and private keys
//!
//! Support for (de)serializable and manipulation of Monero public and private keys.
//!
//! ## Parsing
//!
//! ```rust
//! use std::str::FromStr;
//! use monero::util::key::{Error, PrivateKey, PublicKey};
//!
//! // parse private key from hex
//! let privkey = PrivateKey::from_str("77916d0cd56ed1920aef6ca56d8a41bac915b68e4c46a589e0956e27a7b77404")?;
//! // parse public key from hex
//! let pubkey_parsed = PublicKey::from_str("eac2cc96e0ae684388e3185d5277e51313bff98b9ad4a12dcd9205f20d37f1a3")?;
//!
//! // or get the public key from private key
//! let pubkey = PublicKey::from_private_key(&privkey);
//!
//! assert_eq!(pubkey_parsed, pubkey);
//! # Ok::<(), Error>(())
//! ```
//!
//! ## Arithmetic
//!
//! Support for private key addition and public key addition.
//!
//! ```rust
//! use std::str::FromStr;
//! use monero::util::key::{Error, PrivateKey, PublicKey};
//!
//! let priv1 = PrivateKey::from_str("77916d0cd56ed1920aef6ca56d8a41bac915b68e4c46a589e0956e27a7b77404")?;
//! let priv2 = PrivateKey::from_str("8163466f1883598e6dd14027b8da727057165da91485834314f5500a65846f09")?;
//! let priv_res = priv1 + priv2;
//! assert_eq!("f8f4b37bedf12a2178c0adcc2565b42a212c133861cb28cdf48abf310c3ce40d", priv_res.to_string());
//!
//! let pub1 = PublicKey::from_private_key(&priv1);
//! let pub2 = PublicKey::from_private_key(&priv2);
//! let pub_res = pub1 + pub2;
//! assert_eq!("d35ad191b220a627977bb2912ea21fd59b24937f46c1d3814dbcb7943ff1f9f2", pub_res.to_string());
//!
//! let pubkey = PublicKey::from_private_key(&priv_res);
//! assert_eq!(pubkey, pub_res);
//! # Ok::<(), Error>(())
//! ```
//!

use std::convert::TryFrom;
use std::hash::{Hash, Hasher};
use std::ops::{Add, Mul, Sub};
use std::str::FromStr;
use std::{fmt, io, ops};

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;

use hex_literal::hex;

use crate::consensus::encode::{self, Decodable, Encodable};
use crate::cryptonote::hash;

use thiserror::Error;

#[cfg(feature = "serde_support")]
use serde::{Deserialize, Serialize};

/// Errors that might occur during key decoding
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    /// Invalid input length
    #[error("invalid length")]
    InvalidLength,
    /// Not a canonical representation of an ed25519 scalar
    #[error("not a canonical representation of an ed25519 scalar")]
    NotCanonicalScalar,
    /// Invalid point on the curve
    #[error("invalid point on the curve")]
    InvalidPoint,
    /// Hex parsing error
    #[error("Hex error: {0}")]
    Hex(#[from] hex::FromHexError),
}

/// Monero private key
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct PrivateKey {
    /// The actual Ed25519 scalar
    pub scalar: Scalar,
}

impl PrivateKey {
    /// Serialize a public key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.scalar.as_bytes()
    }

    /// Serialize a public key to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }

    /// Deserialize a private key from a slice
    pub fn from_slice(data: &[u8]) -> Result<PrivateKey, Error> {
        if data.len() != 32 {
            return Err(Error::InvalidLength);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(data);
        let scalar = match Scalar::from_canonical_bytes(bytes) {
            Some(scalar) => scalar,
            None => {
                return Err(Error::NotCanonicalScalar);
            }
        };
        Ok(PrivateKey { scalar })
    }

    /// Create a secret key from a raw curve25519 scalar
    pub fn from_scalar(scalar: Scalar) -> PrivateKey {
        PrivateKey { scalar }
    }
}

impl TryFrom<[u8; 32]> for PrivateKey {
    type Error = Error;

    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl<'a, 'b> Add<&'b PrivateKey> for &'a PrivateKey {
    type Output = PrivateKey;

    fn add(self, other: &'b PrivateKey) -> Self::Output {
        let scalar = self.scalar + other.scalar;
        PrivateKey { scalar }
    }
}

impl<'a> Add<PrivateKey> for &'a PrivateKey {
    type Output = PrivateKey;

    fn add(self, other: PrivateKey) -> Self::Output {
        let scalar = self.scalar + other.scalar;
        PrivateKey { scalar }
    }
}

impl<'b> Add<&'b PrivateKey> for PrivateKey {
    type Output = PrivateKey;

    fn add(self, other: &'b PrivateKey) -> Self::Output {
        let scalar = self.scalar + other.scalar;
        PrivateKey { scalar }
    }
}

impl Add<PrivateKey> for PrivateKey {
    type Output = PrivateKey;

    fn add(self, other: PrivateKey) -> Self::Output {
        let scalar = self.scalar + other.scalar;
        PrivateKey { scalar }
    }
}

impl Mul<u8> for PrivateKey {
    type Output = PrivateKey;

    fn mul(self, other: u8) -> Self::Output {
        let other: Scalar = other.into();
        PrivateKey {
            scalar: self.scalar * other,
        }
    }
}

impl Mul<PrivateKey> for PrivateKey {
    type Output = PrivateKey;

    fn mul(self, other: PrivateKey) -> Self::Output {
        PrivateKey {
            scalar: self.scalar * other.scalar,
        }
    }
}

impl<'b> Mul<&'b PublicKey> for PrivateKey {
    type Output = PublicKey;

    fn mul(self, other: &'b PublicKey) -> Self::Output {
        let point = self.scalar * other.point();
        PublicKey {
            point: point.compress(),
        }
    }
}

impl<'a, 'b> Mul<&'b PublicKey> for &'a PrivateKey {
    type Output = PublicKey;

    fn mul(self, other: &'b PublicKey) -> Self::Output {
        let point = self.scalar * other.point();
        PublicKey {
            point: point.compress(),
        }
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(&self[..]))
    }
}

impl FromStr for PrivateKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        Ok(Self::from_slice(&bytes[..])?)
    }
}

impl ops::Index<ops::RangeFull> for PrivateKey {
    type Output = [u8];
    fn index(&self, _: ops::RangeFull) -> &[u8] {
        self.as_bytes()
    }
}

impl Decodable for PrivateKey {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<PrivateKey, encode::Error> {
        let bytes: [u8; 32] = Decodable::consensus_decode(d)?;
        Ok(PrivateKey::from_slice(&bytes)?)
    }
}

impl Encodable for PrivateKey {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        self.to_bytes().consensus_encode(s)
    }
}

/// Monero public key
#[derive(PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct PublicKey {
    /// The actual Ed25519 point
    pub point: CompressedEdwardsY,
}

impl PublicKey {
    /// Serialize a public key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.point.as_bytes()
    }

    /// Serialize a public key to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.to_bytes()
    }

    /// Deserialize a public key from a slice
    pub fn from_slice(data: &[u8]) -> Result<PublicKey, Error> {
        if data.len() != 32 {
            return Err(Error::InvalidLength);
        }
        let point = CompressedEdwardsY::from_slice(data);
        match point.decompress() {
            Some(_) => (),
            None => {
                return Err(Error::InvalidPoint);
            }
        };
        Ok(PublicKey { point })
    }

    /// Generate a public key from the private key
    pub fn from_private_key(privkey: &PrivateKey) -> PublicKey {
        let point = &privkey.scalar * &ED25519_BASEPOINT_TABLE;
        PublicKey {
            point: point.compress(),
        }
    }

    /// Get the decompressed Edward point of the public key
    fn point(&self) -> EdwardsPoint {
        self.point
            .decompress()
            .expect("PublicKey Can only be created if a valid point is found. QED")
    }
}

impl TryFrom<[u8; 32]> for PublicKey {
    type Error = Error;

    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl<'a, 'b> Add<&'b PublicKey> for &'a PublicKey {
    type Output = PublicKey;

    fn add(self, other: &'b PublicKey) -> Self::Output {
        let point = self.point() + other.point();
        PublicKey {
            point: point.compress(),
        }
    }
}

impl<'a> Add<PublicKey> for &'a PublicKey {
    type Output = PublicKey;

    fn add(self, other: PublicKey) -> Self::Output {
        let point = self.point() + other.point();
        PublicKey {
            point: point.compress(),
        }
    }
}

impl<'b> Add<&'b PublicKey> for PublicKey {
    type Output = PublicKey;

    fn add(self, other: &'b PublicKey) -> Self::Output {
        let point = self.point() + other.point();
        PublicKey {
            point: point.compress(),
        }
    }
}

impl Add<PublicKey> for PublicKey {
    type Output = PublicKey;

    fn add(self, other: PublicKey) -> Self::Output {
        let point = self.point() + other.point();
        PublicKey {
            point: point.compress(),
        }
    }
}

impl<'a, 'b> Sub<&'b PublicKey> for &'a PublicKey {
    type Output = PublicKey;

    fn sub(self, other: &'b PublicKey) -> Self::Output {
        let point = self.point() - other.point();
        PublicKey {
            point: point.compress(),
        }
    }
}

impl<'a> Sub<PublicKey> for &'a PublicKey {
    type Output = PublicKey;

    fn sub(self, other: PublicKey) -> Self::Output {
        let point = self.point() - other.point();
        PublicKey {
            point: point.compress(),
        }
    }
}

impl<'b> Sub<&'b PublicKey> for PublicKey {
    type Output = PublicKey;

    fn sub(self, other: &'b PublicKey) -> Self::Output {
        let point = self.point() - other.point();
        PublicKey {
            point: point.compress(),
        }
    }
}

impl Sub<PublicKey> for PublicKey {
    type Output = PublicKey;

    fn sub(self, other: PublicKey) -> Self::Output {
        let point = self.point() - other.point();
        PublicKey {
            point: point.compress(),
        }
    }
}

impl<'b> Mul<&'b PrivateKey> for PublicKey {
    type Output = PublicKey;

    fn mul(self, other: &'b PrivateKey) -> Self::Output {
        let point = self.point() * other.scalar;
        PublicKey {
            point: point.compress(),
        }
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(&self[..]))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(&self[..]))
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl FromStr for PublicKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        Ok(Self::from_slice(&bytes[..])?)
    }
}

impl ops::Index<ops::RangeFull> for PublicKey {
    type Output = [u8];
    fn index(&self, _: ops::RangeFull) -> &[u8] {
        self.as_bytes()
    }
}

impl Decodable for PublicKey {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<PublicKey, encode::Error> {
        let bytes: [u8; 32] = Decodable::consensus_decode(d)?;
        Ok(PublicKey::from_slice(&bytes)?)
    }
}

impl Encodable for PublicKey {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        self.to_bytes().consensus_encode(s)
    }
}

impl hash::Hashable for PublicKey {
    fn hash(&self) -> hash::Hash {
        hash::Hash::hash(self.as_bytes())
    }
}

/// Alternative generator `H` used for pedersen commitments, as defined in
/// [rctTypes.h](https://github.com/monero-project/monero/blob/master/src/ringct/rctTypes.h#L555)
pub const H: PublicKey = PublicKey {
    point: CompressedEdwardsY(hex!(
        "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"
    )),
};

/// Two Monero private keys, view and spend key
#[derive(Debug)]
pub struct KeyPair {
    /// The view key needed to recognize owned outputs
    pub view: PrivateKey,
    /// The spend key needed to spend outputs
    pub spend: PrivateKey,
}

/// View pair can scan transaction outputs and retreive amounts, but can't spend outputs
#[derive(Debug)]
pub struct ViewPair {
    /// The private view key
    pub view: PrivateKey,
    /// The public spend key
    pub spend: PublicKey,
}

impl From<KeyPair> for ViewPair {
    fn from(k: KeyPair) -> ViewPair {
        let spend = PublicKey::from_private_key(&k.spend);
        ViewPair {
            view: k.view,
            spend,
        }
    }
}

impl From<&KeyPair> for ViewPair {
    fn from(k: &KeyPair) -> ViewPair {
        let spend = PublicKey::from_private_key(&k.spend);
        ViewPair {
            view: k.view,
            spend,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{PrivateKey, PublicKey};

    #[test]
    fn public_key_from_secret() {
        let privkey = PrivateKey::from_str(
            "77916d0cd56ed1920aef6ca56d8a41bac915b68e4c46a589e0956e27a7b77404",
        )
        .unwrap();
        assert_eq!(
            "eac2cc96e0ae684388e3185d5277e51313bff98b9ad4a12dcd9205f20d37f1a3",
            PublicKey::from_private_key(&privkey).to_string()
        );
    }

    #[test]
    fn parse_public_key() {
        assert!(PublicKey::from_str(
            "eac2cc96e0ae684388e3185d5277e51313bff98b9ad4a12dcd9205f20d37f1a3"
        )
        .is_ok());
    }

    #[test]
    fn add_privkey_and_pubkey() {
        let priv1 = PrivateKey::from_str(
            "77916d0cd56ed1920aef6ca56d8a41bac915b68e4c46a589e0956e27a7b77404",
        )
        .unwrap();
        let priv2 = PrivateKey::from_str(
            "8163466f1883598e6dd14027b8da727057165da91485834314f5500a65846f09",
        )
        .unwrap();
        let priv_res = priv1 + priv2;
        assert_eq!(
            "f8f4b37bedf12a2178c0adcc2565b42a212c133861cb28cdf48abf310c3ce40d",
            priv_res.to_string()
        );

        let pub1 = PublicKey::from_private_key(&priv1);
        let pub2 = PublicKey::from_private_key(&priv2);
        let pub_res = pub1 + pub2;
        assert_eq!(
            "d35ad191b220a627977bb2912ea21fd59b24937f46c1d3814dbcb7943ff1f9f2",
            pub_res.to_string()
        );

        let pubkey = PublicKey::from_private_key(&priv_res);
        assert_eq!(pubkey, pub_res);
    }
}

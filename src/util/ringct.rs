// Rust Monero Library
// Written in 2019-2023 by
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

//! Ring Confidential Transaction primitive types.
//!
//! Support for parsing Ring Confidential Transaction signature within [`Transaction`].
//!
//! [`Transaction`]: crate::blockdata::transaction::Transaction
//!

use crate::consensus::encode::{
    self, consensus_decode_sized_vec, serialize, Decodable, Encodable, VarInt,
};
use crate::cryptonote::hash;
use crate::cryptonote::onetime_key::KeyGenerator;
use crate::util::amount::Amount;
use crate::util::key::H;
use crate::{PublicKey, ViewPair};
use std::array::TryFromSliceError;
use std::{fmt, io};

use crate::cryptonote::hash::HashError;
use crate::util::address::AddressError;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use sealed::sealed;
#[cfg(feature = "serde")]
use serde_big_array::BigArray;
#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};
use std::convert::TryInto;
use thiserror::Error;

/// Ring Confidential Transaction potential errors.
#[derive(Error, Debug, PartialEq)]
pub enum RingCtError {
    /// Invalid RingCt type.
    #[error("Unknown RingCt type")]
    UnknownRctType,
    /// Network error.
    #[error("Address error: {0}")]
    AddressError(#[from] AddressError),
    /// Conversion error.
    #[error("Conversion error: {0}")]
    Conversion(String),
}

// ====================================================================
/// Raw 32 bytes key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct Key {
    /// The actual key.
    pub key: [u8; 32],
}

impl_hex_display!(Key, key);

impl_consensus_encoding!(Key, key);

impl Key {
    fn new() -> Key {
        Key { key: [0; 32] }
    }
}

impl From<[u8; 32]> for Key {
    fn from(key: [u8; 32]) -> Self {
        Self { key }
    }
}

// ====================================================================
/// Raw 64 bytes key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct Key64 {
    /// The actual key.
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    pub keys: [Key; 64],
}

impl Key64 {
    fn new() -> Key64 {
        Key64 {
            keys: [Key::new(); 64],
        }
    }
}

impl From<[Key; 64]> for Key64 {
    fn from(keys: [Key; 64]) -> Self {
        Self { keys }
    }
}

impl Decodable for Key64 {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Key64, encode::EncodeError> {
        let mut key64 = Key64::new();
        for i in 0..64 {
            let key: Key = Decodable::consensus_decode(r)?;
            key64.keys[i] = key;
        }
        Ok(key64)
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for Key64 {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        for i in 0..64 {
            len += self.keys[i].consensus_encode(w)?;
        }
        Ok(len)
    }
}

impl fmt::Display for Key64 {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        for key in self.keys.iter() {
            writeln!(fmt, "{}", key)?;
        }
        Ok(())
    }
}

// ====================================================================
/// Confidential transaction key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct CtKey {
    //pub dest: Key,
    /// Mask.
    pub mask: Key,
}

impl fmt::Display for CtKey {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(fmt, "Mask: {}", self.mask)
    }
}

impl_consensus_encoding!(CtKey, mask);

// ====================================================================
/// Multisig.
#[derive(Debug)]
#[allow(non_snake_case)]
pub struct MultisigKlrki {
    /// K value.
    pub K: Key,
    /// L value.
    pub L: Key,
    /// R value.
    pub R: Key,
    /// ki value.
    pub ki: Key,
}

impl_consensus_encoding!(MultisigKlrki, K, L, R, ki);

// ====================================================================
/// Vector of multisig output keys.
#[derive(Debug)]
pub struct MultisigOut {
    /// Vector of keys.
    pub c: Vec<Key>,
}

impl_consensus_encoding!(MultisigOut, c);

// ====================================================================
/// Diffie-Hellman info, mask and amount for transaction before `Bulletproof2` and only 8-bytes
/// hash for the amount in `Bulletproof2` type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub enum EcdhInfo {
    /// Standard format, before `Bulletproof2`.
    Standard {
        /// Mask value.
        mask: Key,
        /// Amount value.
        amount: Key,
    },
    /// Bulletproof format.
    Bulletproof {
        /// Amount value.
        amount: hash::Hash8,
    },
}

impl EcdhInfo {
    /// Opens the commitment and verifies it against the given one.
    pub fn open_commitment(
        &self,
        view_pair: &ViewPair,
        tx_pubkey: &PublicKey,
        index: usize,
        candidate_commitment: &EdwardsPoint,
    ) -> Result<Option<Opening>, RingCtError> {
        let shared_key = KeyGenerator::from_key(view_pair, *tx_pubkey).get_rvn_scalar(index)?;

        let (amount, blinding_factor) = match self {
            // ecdhDecode in rctOps.cpp else
            EcdhInfo::Standard { mask, amount } => {
                let shared_sec1 = hash::Hash::new(shared_key.as_bytes()).to_bytes();
                let shared_sec2 = hash::Hash::new(shared_sec1).to_bytes();
                let mask_scalar = Scalar::from_bytes_mod_order(mask.key)
                    - Scalar::from_bytes_mod_order(shared_sec1);

                let amount_scalar = Scalar::from_bytes_mod_order(amount.key)
                    - Scalar::from_bytes_mod_order(shared_sec2);
                // get first 64 bits (d2b in rctTypes.cpp)
                let amount_significant_bytes = amount_scalar.to_bytes()[0..8]
                    .try_into()
                    .map_err(|e: TryFromSliceError| RingCtError::Conversion(e.to_string()))?;
                let amount = u64::from_le_bytes(amount_significant_bytes);
                (amount, mask_scalar)
            }
            // ecdhDecode in rctOps.cpp if (v2)
            EcdhInfo::Bulletproof { amount } => {
                let amount = xor_amount(amount.0, shared_key.scalar);
                let mask = mask(shared_key.scalar);

                (u64::from_le_bytes(amount), mask)
            }
        };

        let amount_scalar = Scalar::from(amount);

        let expected_commitment = if let Some(h_point) = H.point.decompress() {
            ED25519_BASEPOINT_POINT * blinding_factor + h_point * amount_scalar
        } else {
            return Ok(None);
        };

        if &expected_commitment != candidate_commitment {
            return Ok(None);
        }

        Ok(Some(Opening {
            amount: Amount::from_pico(amount),
            blinding_factor,
            commitment: expected_commitment,
        }))
    }
}

/// The result of opening the commitment inside the transaction.
#[derive(Debug)]
pub struct Opening {
    /// The original amount of the output.
    pub amount: Amount,
    /// The blinding factor used to blind the amount.
    pub blinding_factor: Scalar,
    /// The commitment used to verify the blinded amount.
    pub commitment: EdwardsPoint,
}

fn xor_amount(amount: [u8; 8], shared_key: Scalar) -> [u8; 8] {
    // ecdhHash in .cpp
    let mut amount_key = b"amount".to_vec();
    amount_key.extend(shared_key.as_bytes());

    // Hn("amount", Hn(rKbv,t))
    let hash_shared_key = hash::Hash::new(&amount_key).to_fixed_bytes();
    let hash_shared_key_significant_bytes = hash_shared_key[0..8]
        .try_into()
        .expect("hash_shared_key create above has 32 bytes");

    // amount_t = bt XOR Hn("amount", Hn("amount", Hn(rKbv,t)))
    // xor8(masked.amount, ecdhHash(sharedSec)); in .cpp
    (u64::from_le_bytes(amount) ^ u64::from_le_bytes(hash_shared_key_significant_bytes))
        .to_le_bytes()
}

fn mask(scalar: Scalar) -> Scalar {
    let mut commitment_key = b"commitment_mask".to_vec();
    commitment_key.extend(scalar.as_bytes());

    // yt in Z2M p 53
    hash::Hash::hash_to_scalar(&commitment_key).scalar
}

impl fmt::Display for EcdhInfo {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            EcdhInfo::Standard { mask, amount } => {
                writeln!(fmt, "Standard")?;
                writeln!(fmt, "Mask: {}", mask)?;
                writeln!(fmt, "Amount: {}", amount)?;
            }
            EcdhInfo::Bulletproof { amount } => {
                writeln!(fmt, "Bulletproof2")?;
                writeln!(fmt, "Amount: {}", amount)?;
            }
        };
        Ok(())
    }
}

impl EcdhInfo {
    /// Decode Diffie-Hellman info given the RingCt type.
    fn consensus_decode<R: io::Read + ?Sized>(
        r: &mut R,
        rct_type: RctType,
    ) -> Result<EcdhInfo, encode::EncodeError> {
        match rct_type {
            RctType::Full | RctType::Simple | RctType::Bulletproof | RctType::Null => {
                Ok(EcdhInfo::Standard {
                    mask: Decodable::consensus_decode(r)?,
                    amount: Decodable::consensus_decode(r)?,
                })
            }
            RctType::Bulletproof2 | RctType::Clsag | RctType::BulletproofPlus => {
                Ok(EcdhInfo::Bulletproof {
                    amount: Decodable::consensus_decode(r)?,
                })
            }
        }
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for EcdhInfo {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        match self {
            EcdhInfo::Standard { mask, amount } => {
                len += mask.consensus_encode(w)?;
                len += amount.consensus_encode(w)?;
            }
            EcdhInfo::Bulletproof { amount } => {
                len += amount.consensus_encode(w)?;
            }
        }
        Ok(len)
    }
}

// ====================================================================
/// Borromean signature for range commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct BoroSig {
    /// s0 value.
    pub s0: Key64,
    /// s1 value.
    pub s1: Key64,
    /// ee value.
    pub ee: Key,
}

impl_consensus_encoding!(BoroSig, s0, s1, ee);

// ====================================================================
/// Contains the necessary keys to represent Mlsag signature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct MgSig {
    /// Matrice of keys.
    pub ss: Vec<Vec<Key>>,
    /// cc value.
    pub cc: Key,
}

#[sealed]
impl crate::consensus::encode::Encodable for MgSig {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        for ss in self.ss.iter() {
            len += encode_sized_vec!(ss, w);
        }
        len += self.cc.consensus_encode(w)?;
        Ok(len)
    }
}

// ====================================================================
/// Clsag signature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(non_snake_case)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct Clsag {
    /// scalars.
    pub s: Vec<Key>,
    /// c1 value.
    pub c1: Key,
    /// commitment key image.
    pub D: Key,
}

#[sealed]
impl crate::consensus::encode::Encodable for Clsag {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        // Encode the vector without prefix lenght
        len += encode_sized_vec!(self.s, w);
        len += self.c1.consensus_encode(w)?;
        len += self.D.consensus_encode(w)?;
        Ok(len)
    }
}

// ====================================================================
/// Range signature for range commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(non_snake_case)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct RangeSig {
    /// asig value
    pub asig: BoroSig,
    /// Ci value
    pub Ci: Key64,
}

impl_consensus_encoding!(RangeSig, asig, Ci);

// ====================================================================
/// Bulletproof format.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(non_snake_case)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct Bulletproof {
    /// A value.
    pub A: Key,
    /// S value.
    pub S: Key,
    /// T1 value.
    pub T1: Key,
    /// T2 value.
    pub T2: Key,
    /// taux value.
    pub taux: Key,
    /// mu value.
    pub mu: Key,
    /// L value.
    pub L: Vec<Key>,
    /// R value.
    pub R: Vec<Key>,
    /// a value.
    pub a: Key,
    /// b value.
    pub b: Key,
    /// t value.
    pub t: Key,
}

impl_consensus_encoding!(Bulletproof, A, S, T1, T2, taux, mu, L, R, a, b, t);

// ====================================================================
/// BulletproofPlus format.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(non_snake_case)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct BulletproofPlus {
    /// A value.
    pub A: Key,
    /// A1 value.
    pub A1: Key,
    /// B value.
    pub B: Key,
    /// r1 value.
    pub r1: Key,
    /// s1 value.
    pub s1: Key,
    /// d1 value.
    pub d1: Key,
    /// L value.
    pub L: Vec<Key>,
    /// R value.
    pub R: Vec<Key>,
}

impl_consensus_encoding!(BulletproofPlus, A, A1, B, r1, s1, d1, L, R);

// ====================================================================
/// RingCt base signature format.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct RctSigBase {
    /// The RingCt type of signatures.
    pub rct_type: RctType,
    /// Transaction fee.
    #[cfg_attr(feature = "serde", serde(with = "crate::util::amount::serde::as_pico"))]
    pub txn_fee: Amount,
    /// Pseudo outs key vector.
    pub pseudo_outs: Vec<Key>,
    /// Ecdh info vector.
    pub ecdh_info: Vec<EcdhInfo>,
    /// Out pk vector.
    pub out_pk: Vec<CtKey>,
}

impl fmt::Display for RctSigBase {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(fmt, "RCT type: {}", self.rct_type)?;
        writeln!(fmt, "Tx fee: {}", self.txn_fee)?;
        for out in &self.pseudo_outs {
            writeln!(fmt, "Pseudo out: {}", out)?;
        }
        for ecdh in &self.ecdh_info {
            writeln!(fmt, "Ecdh info: {}", ecdh)?;
        }
        for out in &self.out_pk {
            writeln!(fmt, "Out pk: {}", out)?;
        }
        Ok(())
    }
}

impl RctSigBase {
    /// Decode a RingCt base signature given the number of inputs and outputs of the transaction.
    pub fn consensus_decode<R: io::Read + ?Sized>(
        r: &mut R,
        inputs: usize,
        outputs: usize,
    ) -> Result<Option<RctSigBase>, encode::EncodeError> {
        let rct_type: RctType = Decodable::consensus_decode(r)?;
        match rct_type {
            RctType::Null => Ok(Some(RctSigBase {
                rct_type: RctType::Null,
                txn_fee: Default::default(),
                pseudo_outs: vec![],
                ecdh_info: vec![],
                out_pk: vec![],
            })),
            RctType::Full
            | RctType::Simple
            | RctType::Bulletproof
            | RctType::Bulletproof2
            | RctType::Clsag
            | RctType::BulletproofPlus => {
                let mut pseudo_outs: Vec<Key> = vec![];
                // TxnFee
                let txn_fee: VarInt = Decodable::consensus_decode(r)?;
                let txn_fee = Amount::from_pico(*txn_fee);
                // RctType
                if rct_type == RctType::Simple {
                    pseudo_outs = consensus_decode_sized_vec(r, inputs)?;
                }
                // EcdhInfo
                let mut ecdh_info: Vec<EcdhInfo> = vec![];
                for _ in 0..outputs {
                    ecdh_info.push(EcdhInfo::consensus_decode(r, rct_type)?);
                }
                // OutPk
                let out_pk: Vec<CtKey> = consensus_decode_sized_vec(r, outputs)?;
                Ok(Some(RctSigBase {
                    rct_type,
                    txn_fee,
                    pseudo_outs,
                    ecdh_info,
                    out_pk,
                }))
            }
        }
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for RctSigBase {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.rct_type.consensus_encode(w)?;
        match self.rct_type {
            RctType::Null => Ok(len),
            RctType::Full
            | RctType::Simple
            | RctType::Bulletproof
            | RctType::Bulletproof2
            | RctType::Clsag
            | RctType::BulletproofPlus => {
                let txn_fee: VarInt = VarInt(self.txn_fee.as_pico());
                len += txn_fee.consensus_encode(w)?;
                if self.rct_type == RctType::Simple {
                    len += encode_sized_vec!(self.pseudo_outs, w);
                }
                len += encode_sized_vec!(self.ecdh_info, w);
                len += encode_sized_vec!(self.out_pk, w);
                Ok(len)
            }
        }
    }
}

impl hash::Hashable for RctSigBase {
    fn hash(&self) -> Result<hash::Hash, HashError> {
        Ok(hash::Hash::new(serialize(self)?))
    }
}

// ====================================================================
/// Types of Ring Confidential Transaction signatures.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub enum RctType {
    /// Null type.
    Null,
    /// Full type.
    Full,
    /// Simple type.
    Simple,
    /// First Bulletproof type.
    Bulletproof,
    /// Bulletproof2 type.
    Bulletproof2,
    /// Clsag Ring signatures.
    Clsag,
    /// Bulletproof+ type, used in the current network.
    BulletproofPlus,
}

impl fmt::Display for RctType {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let rct_type = match self {
            RctType::Null => "Null",
            RctType::Full => "Full",
            RctType::Simple => "Simple",
            RctType::Bulletproof => "Bulletproof",
            RctType::Bulletproof2 => "Bulletproof2",
            RctType::Clsag => "Clsag",
            RctType::BulletproofPlus => "Bulletproof+",
        };
        write!(fmt, "{}", rct_type)
    }
}

impl RctType {
    /// Return if the format use one of the bulletproof format.
    pub fn is_rct_bp(self) -> bool {
        matches!(
            self,
            RctType::Bulletproof | RctType::Bulletproof2 | RctType::Clsag
        )
    }
    /// Return if the format use one of the bulletproofPlus format.
    pub fn is_rct_bp_plus(self) -> bool {
        matches!(self, RctType::BulletproofPlus)
    }
}

impl Decodable for RctType {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<RctType, encode::EncodeError> {
        let rct_type: u8 = Decodable::consensus_decode(r)?;
        match rct_type {
            0 => Ok(RctType::Null),
            1 => Ok(RctType::Full),
            2 => Ok(RctType::Simple),
            3 => Ok(RctType::Bulletproof),
            4 => Ok(RctType::Bulletproof2),
            5 => Ok(RctType::Clsag),
            6 => Ok(RctType::BulletproofPlus),
            _ => Err(RingCtError::UnknownRctType.into()),
        }
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for RctType {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        match self {
            RctType::Null => 0u8.consensus_encode(w),
            RctType::Full => 1u8.consensus_encode(w),
            RctType::Simple => 2u8.consensus_encode(w),
            RctType::Bulletproof => 3u8.consensus_encode(w),
            RctType::Bulletproof2 => 4u8.consensus_encode(w),
            RctType::Clsag => 5u8.consensus_encode(w),
            RctType::BulletproofPlus => 6u8.consensus_encode(w),
        }
    }
}

// ====================================================================
/// Prunable part of RingCt signature format.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(non_snake_case)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct RctSigPrunable {
    /// Range signatures.
    pub range_sigs: Vec<RangeSig>,
    /// Bulletproofs.
    pub bulletproofs: Vec<Bulletproof>,
    /// BulletproofPlus
    pub bulletproofplus: Vec<BulletproofPlus>,
    /// MSLAG signatures, simple rct has N, full has 1.
    pub MGs: Vec<MgSig>,
    /// CSLAG signatures.
    pub Clsags: Vec<Clsag>,
    /// Pseudo out vector.
    pub pseudo_outs: Vec<Key>,
}

impl RctSigPrunable {
    /// Decode a prunable RingCt signature given the number of inputs and outputs in the
    /// transaction, the RingCt type and the number of mixins.
    #[allow(non_snake_case)]
    pub fn consensus_decode<R: io::Read + ?Sized>(
        r: &mut R,
        rct_type: RctType,
        inputs: usize,
        outputs: usize,
        mixin: usize,
    ) -> Result<Option<RctSigPrunable>, encode::EncodeError> {
        match rct_type {
            RctType::Null => Ok(None),
            RctType::Full
            | RctType::Simple
            | RctType::Bulletproof
            | RctType::Bulletproof2
            | RctType::Clsag
            | RctType::BulletproofPlus => {
                let mut bulletproofs: Vec<Bulletproof> = vec![];
                let mut bulletproofplus: Vec<BulletproofPlus> = vec![];
                let mut range_sigs: Vec<RangeSig> = vec![];
                if rct_type.is_rct_bp() {
                    match rct_type {
                        RctType::Bulletproof2 | RctType::Clsag => {
                            bulletproofs = Decodable::consensus_decode(r)?;
                        }
                        _ => {
                            let size: u32 = Decodable::consensus_decode(r)?;
                            bulletproofs = consensus_decode_sized_vec(r, size as usize)?;
                        }
                    }
                } else if rct_type.is_rct_bp_plus() {
                    let size: u8 = Decodable::consensus_decode(r)?;
                    bulletproofplus = consensus_decode_sized_vec(r, size as usize)?;
                } else {
                    range_sigs = consensus_decode_sized_vec(r, outputs)?;
                }

                let mut Clsags: Vec<Clsag> = vec![];
                let mut MGs: Vec<MgSig> = vec![];

                match rct_type {
                    RctType::Clsag | RctType::BulletproofPlus => {
                        for _ in 0..inputs {
                            let mut s: Vec<Key> = vec![];
                            for _ in 0..=mixin {
                                let s_elems: Key = Decodable::consensus_decode(r)?;
                                s.push(s_elems);
                            }
                            let c1 = Decodable::consensus_decode(r)?;
                            let D = Decodable::consensus_decode(r)?;
                            Clsags.push(Clsag { s, c1, D });
                        }
                    }
                    _ => {
                        let is_simple_or_bp = rct_type == RctType::Simple
                            || rct_type == RctType::Bulletproof
                            || rct_type == RctType::Bulletproof2;
                        let mg_elements = if is_simple_or_bp { inputs } else { 1 };
                        for _ in 0..mg_elements {
                            let mut ss: Vec<Vec<Key>> = vec![];
                            for _ in 0..=mixin {
                                let mg_ss2_elements = if is_simple_or_bp { 2 } else { 1 + inputs };
                                let ss_elems: Vec<Key> =
                                    consensus_decode_sized_vec(r, mg_ss2_elements)?;
                                ss.push(ss_elems);
                            }
                            let cc = Decodable::consensus_decode(r)?;
                            MGs.push(MgSig { ss, cc });
                        }
                    }
                }

                let mut pseudo_outs: Vec<Key> = vec![];
                match rct_type {
                    RctType::Bulletproof
                    | RctType::Bulletproof2
                    | RctType::Clsag
                    | RctType::BulletproofPlus => {
                        pseudo_outs = consensus_decode_sized_vec(r, inputs)?;
                    }
                    _ => (),
                }

                Ok(Some(RctSigPrunable {
                    range_sigs,
                    bulletproofs,
                    bulletproofplus,
                    MGs,
                    Clsags,
                    pseudo_outs,
                }))
            }
        }
    }

    /// Encode the prunable RingCt signature part given the RingCt type of the transaction.
    pub fn consensus_encode<W: io::Write + ?Sized>(
        &self,
        w: &mut W,
        rct_type: RctType,
    ) -> Result<usize, io::Error> {
        match rct_type {
            RctType::Null => Ok(0),
            RctType::Full
            | RctType::Simple
            | RctType::Bulletproof
            | RctType::Bulletproof2
            | RctType::Clsag
            | RctType::BulletproofPlus => {
                let mut len = 0;
                if rct_type.is_rct_bp() {
                    match rct_type {
                        RctType::Bulletproof2 | RctType::Clsag => {
                            len += self.bulletproofs.consensus_encode(w)?;
                        }
                        _ => {
                            let size: u32 = self.bulletproofs.len() as u32;
                            len += size.consensus_encode(w)?;
                            len += encode_sized_vec!(self.bulletproofs, w);
                        }
                    }
                } else if rct_type.is_rct_bp_plus() {
                    let size: u8 = self.bulletproofplus.len() as u8;
                    len += size.consensus_encode(w)?;
                    len += encode_sized_vec!(self.bulletproofplus, w);
                } else {
                    len += encode_sized_vec!(self.range_sigs, w);
                }

                match rct_type {
                    RctType::Clsag | RctType::BulletproofPlus => {
                        len += encode_sized_vec!(self.Clsags, w)
                    }
                    _ => len += encode_sized_vec!(self.MGs, w),
                }

                match rct_type {
                    RctType::Bulletproof
                    | RctType::Bulletproof2
                    | RctType::Clsag
                    | RctType::BulletproofPlus => {
                        len += encode_sized_vec!(self.pseudo_outs, w);
                    }
                    _ => (),
                }
                Ok(len)
            }
        }
    }
}

// ====================================================================
/// A RingCt signature.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct RctSig {
    /// The base part.
    pub sig: Option<RctSigBase>,
    /// The prunable part.
    pub p: Option<RctSigPrunable>,
}

impl fmt::Display for RctSig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match &self.sig {
            Some(v) => writeln!(fmt, "Signature: {}", v)?,
            None => writeln!(fmt, "Signature: None")?,
        };
        Ok(())
    }
}

// ====================================================================
/// A raw signature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct Signature {
    /// c value.
    pub c: Key,
    /// r value.
    pub r: Key,
}

impl fmt::Display for Signature {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(fmt, "C: {}", self.c)?;
        writeln!(fmt, "R: {}", self.r)
    }
}

impl_consensus_encoding!(Signature, c, r);

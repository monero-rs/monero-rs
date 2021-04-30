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

//! Ring Confidential Transaction primitive types.
//!
//! Support for parsing Ring Confidential Transaction signature within [`Transaction`].
//!
//! [`Transaction`]: crate::blockdata::transaction::Transaction
//!

use std::{fmt, io};

use crate::consensus::encode::{self, serialize, Decodable, Encodable, VarInt};
use crate::cryptonote::hash;

#[cfg(feature = "serde_support")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde_support")]
use serde_big_array_unchecked_docs::*;

use thiserror::Error;

/// Serde support for array's bigger than 32 items.
#[allow(missing_docs)]
#[cfg(feature = "serde_support")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde_support")))]
pub mod serde_big_array_unchecked_docs {
    use serde_big_array::big_array;
    big_array! { BigArray; }
}

/// Ring Confidential Transaction potential errors.
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    /// Invalid RingCt type.
    #[error("Unknown RingCt type")]
    UnknownRctType,
}

// ====================================================================
/// Raw 32 bytes key.
#[derive(Clone, Copy, PartialEq, Hash)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct Key {
    /// The actual key.
    pub key: [u8; 32],
}

impl_hex_display!(Key, key);

impl_consensus_encoding!(Key, key);

impl From<[u8; 32]> for Key {
    fn from(key: [u8; 32]) -> Self {
        Self { key }
    }
}

// ====================================================================
/// Raw 64 bytes key.
#[derive(Clone, Copy, PartialEq, Hash)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct Key64 {
    /// The actual key.
    #[cfg_attr(feature = "serde_support", serde(with = "BigArray"))]
    pub key: [u8; 64],
}

impl_hex_display!(Key64, key);

impl_consensus_encoding!(Key64, key);

impl From<[u8; 64]> for Key64 {
    fn from(key: [u8; 64]) -> Self {
        Self { key }
    }
}

// ====================================================================
/// Confidential transaction key.
#[derive(Debug, Clone, Copy, PartialEq, Hash)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
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
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
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
    fn consensus_decode<D: io::Read>(
        d: &mut D,
        rct_type: RctType,
    ) -> Result<EcdhInfo, encode::Error> {
        match rct_type {
            RctType::Full | RctType::Simple | RctType::Bulletproof | RctType::Null => {
                Ok(EcdhInfo::Standard {
                    mask: Decodable::consensus_decode(d)?,
                    amount: Decodable::consensus_decode(d)?,
                })
            }
            RctType::Bulletproof2 | RctType::Clsag => Ok(EcdhInfo::Bulletproof {
                amount: Decodable::consensus_decode(d)?,
            }),
        }
    }
}

impl Encodable for EcdhInfo {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        let mut len = 0;
        match self {
            EcdhInfo::Standard { mask, amount } => {
                len += mask.consensus_encode(s)?;
                len += amount.consensus_encode(s)?;
            }
            EcdhInfo::Bulletproof { amount } => {
                len += amount.consensus_encode(s)?;
            }
        }
        Ok(len)
    }
}

// ====================================================================
/// Borromean signature for range commitment.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
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
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct MgSig {
    /// Matrice of keys.
    pub ss: Vec<Vec<Key>>,
    /// cc value.
    pub cc: Key,
}

impl Encodable for MgSig {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        let mut len = 0;
        for ss in self.ss.iter() {
            len += encode_sized_vec!(ss, s);
        }
        len += self.cc.consensus_encode(s)?;
        Ok(len)
    }
}

// ====================================================================
/// Clsag signature.
#[derive(Debug, Clone)]
#[allow(non_snake_case)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct Clsag {
    /// scalars.
    pub s: Vec<Key>,
    /// c1 value.
    pub c1: Key,
    /// commitment key image.
    pub D: Key,
}

impl Encodable for Clsag {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        let mut len = 0;
        // Encode the vector without prefix lenght
        len += encode_sized_vec!(self.s, s);
        len += self.c1.consensus_encode(s)?;
        len += self.D.consensus_encode(s)?;
        Ok(len)
    }
}

// ====================================================================
/// Range signature for range commitment.
#[derive(Debug, Clone)]
#[allow(non_snake_case)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct RangeSig {
    /// asig value
    pub asig: BoroSig,
    /// Ci value
    pub Ci: Key64,
}

impl_consensus_encoding!(RangeSig, asig, Ci);

// ====================================================================
/// Bulletproof format.
#[derive(Debug, Clone)]
#[allow(non_snake_case)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
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
/// RingCt base signature format.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct RctSigBase {
    /// The RingCt type of signatures.
    pub rct_type: RctType,
    /// Transaction fee.
    pub txn_fee: VarInt,
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
    pub fn consensus_decode<D: io::Read>(
        d: &mut D,
        inputs: usize,
        outputs: usize,
    ) -> Result<Option<RctSigBase>, encode::Error> {
        let rct_type: RctType = Decodable::consensus_decode(d)?;
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
            | RctType::Clsag => {
                let mut pseudo_outs: Vec<Key> = vec![];
                // TxnFee
                let txn_fee: VarInt = Decodable::consensus_decode(d)?;
                // RctType
                if rct_type == RctType::Simple {
                    pseudo_outs = decode_sized_vec!(inputs, d);
                }
                // EcdhInfo
                let mut ecdh_info: Vec<EcdhInfo> = vec![];
                for _ in 0..outputs {
                    ecdh_info.push(EcdhInfo::consensus_decode(d, rct_type)?);
                }
                // OutPk
                let out_pk: Vec<CtKey> = decode_sized_vec!(outputs, d);
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

impl Encodable for RctSigBase {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.rct_type.consensus_encode(s)?;
        match self.rct_type {
            RctType::Null => Ok(len),
            RctType::Full
            | RctType::Simple
            | RctType::Bulletproof
            | RctType::Bulletproof2
            | RctType::Clsag => {
                len += self.txn_fee.consensus_encode(s)?;
                if self.rct_type == RctType::Simple {
                    len += encode_sized_vec!(self.pseudo_outs, s);
                }
                len += encode_sized_vec!(self.ecdh_info, s);
                len += encode_sized_vec!(self.out_pk, s);
                Ok(len)
            }
        }
    }
}

impl hash::Hashable for RctSigBase {
    fn hash(&self) -> hash::Hash {
        hash::Hash::hash(&serialize(self))
    }
}

// ====================================================================
/// Types of Ring Confidential Transaction signatures.
#[derive(Debug, PartialEq, Clone, Copy)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
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
    /// Clsag Ring signatures, used in the current network.
    Clsag,
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
}

impl Decodable for RctType {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<RctType, encode::Error> {
        let rct_type: u8 = Decodable::consensus_decode(d)?;
        match rct_type {
            0 => Ok(RctType::Null),
            1 => Ok(RctType::Full),
            2 => Ok(RctType::Simple),
            3 => Ok(RctType::Bulletproof),
            4 => Ok(RctType::Bulletproof2),
            5 => Ok(RctType::Clsag),
            _ => Err(Error::UnknownRctType.into()),
        }
    }
}

impl Encodable for RctType {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        match self {
            RctType::Null => 0u8.consensus_encode(s),
            RctType::Full => 1u8.consensus_encode(s),
            RctType::Simple => 2u8.consensus_encode(s),
            RctType::Bulletproof => 3u8.consensus_encode(s),
            RctType::Bulletproof2 => 4u8.consensus_encode(s),
            RctType::Clsag => 5u8.consensus_encode(s),
        }
    }
}

// ====================================================================
/// Prunable part of RingCt signature format.
#[derive(Debug, Clone)]
#[allow(non_snake_case)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct RctSigPrunable {
    /// Range signatures.
    pub range_sigs: Vec<RangeSig>,
    /// Bulletproofs.
    pub bulletproofs: Vec<Bulletproof>,
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
    pub fn consensus_decode<D: io::Read>(
        d: &mut D,
        rct_type: RctType,
        inputs: usize,
        outputs: usize,
        mixin: usize,
    ) -> Result<Option<RctSigPrunable>, encode::Error> {
        match rct_type {
            RctType::Null => Ok(None),
            RctType::Full
            | RctType::Simple
            | RctType::Bulletproof
            | RctType::Bulletproof2
            | RctType::Clsag => {
                let mut bulletproofs: Vec<Bulletproof> = vec![];
                let mut range_sigs: Vec<RangeSig> = vec![];
                if rct_type.is_rct_bp() {
                    match rct_type {
                        RctType::Bulletproof2 | RctType::Clsag => {
                            bulletproofs = Decodable::consensus_decode(d)?;
                        }
                        _ => {
                            let size: u32 = Decodable::consensus_decode(d)?;
                            bulletproofs = decode_sized_vec!(size, d);
                        }
                    }
                } else {
                    range_sigs = decode_sized_vec!(outputs, d);
                }

                let mut Clsags: Vec<Clsag> = vec![];
                let mut MGs: Vec<MgSig> = vec![];

                match rct_type {
                    RctType::Clsag => {
                        for _ in 0..inputs {
                            let mut s: Vec<Key> = vec![];
                            for _ in 0..=mixin {
                                let s_elems: Key = Decodable::consensus_decode(d)?;
                                s.push(s_elems);
                            }
                            let c1 = Decodable::consensus_decode(d)?;
                            let D = Decodable::consensus_decode(d)?;
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
                                let ss_elems: Vec<Key> = decode_sized_vec!(mg_ss2_elements, d);
                                ss.push(ss_elems);
                            }
                            let cc = Decodable::consensus_decode(d)?;
                            MGs.push(MgSig { ss, cc });
                        }
                    }
                }

                let mut pseudo_outs: Vec<Key> = vec![];
                match rct_type {
                    RctType::Bulletproof | RctType::Bulletproof2 | RctType::Clsag => {
                        pseudo_outs = decode_sized_vec!(inputs, d);
                    }
                    _ => (),
                }

                Ok(Some(RctSigPrunable {
                    range_sigs,
                    bulletproofs,
                    MGs,
                    Clsags,
                    pseudo_outs,
                }))
            }
        }
    }

    /// Encode the prunable RingCt signature part given the RingCt type of the transaction.
    pub fn consensus_encode<S: io::Write>(
        &self,
        s: &mut S,
        rct_type: RctType,
    ) -> Result<usize, io::Error> {
        match rct_type {
            RctType::Null => Ok(0),
            RctType::Full
            | RctType::Simple
            | RctType::Bulletproof
            | RctType::Bulletproof2
            | RctType::Clsag => {
                let mut len = 0;
                if rct_type.is_rct_bp() {
                    match rct_type {
                        RctType::Bulletproof2 | RctType::Clsag => {
                            len += self.bulletproofs.consensus_encode(s)?;
                        }
                        _ => {
                            let size: u32 = self.bulletproofs.len() as u32;
                            len += size.consensus_encode(s)?;
                            len += encode_sized_vec!(self.bulletproofs, s);
                        }
                    }
                } else {
                    len += encode_sized_vec!(self.range_sigs, s);
                }

                match rct_type {
                    RctType::Clsag => len += encode_sized_vec!(self.Clsags, s),
                    _ => len += encode_sized_vec!(self.MGs, s),
                }

                match rct_type {
                    RctType::Bulletproof | RctType::Bulletproof2 | RctType::Clsag => {
                        len += encode_sized_vec!(self.pseudo_outs, s);
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
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
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
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
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

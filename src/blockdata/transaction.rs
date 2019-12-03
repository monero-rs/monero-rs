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

//! Monero Transaction
//!
//! This module support (de)serializing Monero transaction and input/amount discovery with private
//! view key.
//!

use std::io::Cursor;
use std::ops::Range;

use crate::consensus::encode::{self, serialize, Decodable, Decoder, Encodable, Encoder, VarInt};
use crate::cryptonote::subaddress::Index;
use crate::cryptonote::{hash, onetime_key};
use crate::util::key::{PublicKey, ViewPair};
use crate::util::ringct::{RctSig, RctSigBase, RctSigPrunable, RctType, Signature};

#[cfg(feature = "serde_support")]
use serde::{Deserialize, Serialize};

/// Transaction error
#[derive(Debug)]
pub enum Error {
    /// No transaction public key found in extra
    NoTxPublicKey,
    /// Scripts input/output are not supported
    ScriptNotSupported,
}

/// Input key image
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct KeyImage {
    /// The actual key image
    pub image: hash::Hash,
}

impl_consensus_encoding!(KeyImage, image);

/// A transaction input, which defines the ring size and the key image to avoid
/// double spend.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub enum TxIn {
    /// A coinbase input
    Gen {
        /// Block height of where the coinbase transaction is included
        height: VarInt,
    },
    /// A key input from a key output
    ToKey {
        /// Amount spend from the output, 0 in case of CT
        amount: VarInt,
        /// Relative offsets of keys use in the ring
        key_offsets: Vec<VarInt>,
        /// The corresponding key image of the output
        k_image: KeyImage,
    },
    /// Input from script output
    ToScript,
    /// Input from script hash output
    ToScriptHash,
}

/// Output format, only output to key is used
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub enum TxOutTarget {
    /// Output to script
    ToScript {
        /// Keys
        keys: Vec<PublicKey>,
        /// Script
        script: Vec<u8>,
    },
    /// Output to one-time public key
    ToKey {
        /// The one-time public key
        key: PublicKey,
    },
    /// Output to script hash
    ToScriptHash {
        /// Script hash
        hash: hash::Hash,
    },
}

/// A transaction output, can be consumed by an input
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct TxOut {
    /// The amount sent to the associated key, can be 0 in case of CT
    pub amount: VarInt,
    /// The target format
    pub target: TxOutTarget,
}

impl_consensus_encoding!(TxOut, amount, target);

/// Transaction ouput that can be redeemed by a key pair at a given index
#[derive(Debug)]
pub struct OwnedTxOut<'a> {
    /// Index of the output in the transaction
    pub index: usize,
    /// The actual redeemable output
    pub out: &'a TxOut,
    /// Index of the key pair to use, can be 0/0 for main address
    pub sub_index: Index,
}

/// Every transaction contains an Extra field, which is a part of transaction prefix
///
/// Extra field is composed of typed sub fields of variable or fixed lenght.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct ExtraField(pub Vec<SubField>);

impl ExtraField {
    /// Return the transaction public key, if any, present in extra field
    pub fn tx_pubkey(&self) -> Option<PublicKey> {
        self.0.iter().find_map(|x| match x {
            SubField::TxPublicKey(pubkey) => Some(*pubkey),
            _ => None,
        })
    }

    /// Return the additional public keys, if any, present in extra field
    pub fn tx_additional_pubkeys(&self) -> Option<Vec<PublicKey>> {
        self.0.iter().find_map(|x| match x {
            SubField::AdditionalPublickKey(pubkeys) => Some(pubkeys.clone()),
            _ => None,
        })
    }
}

/// Each sub-field contains a sub-field tag followed by sub-field content of fixed or variable
/// lenght, in variable lenght case the lenght is encoded with a VarInt before the content itself.
#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub enum SubField {
    /// Transaction public key, fixed lenght of 32 bytes
    TxPublicKey(PublicKey),
    /// 255 bytes limited nonce, can contain an encrypted or unencrypted payment id, variable
    /// lenght
    Nonce(Vec<u8>),
    /// Padding size is limited to 255 null bytes, variable lenght
    Padding(u8),
    /// Merge mining infos: `depth` and `merkle_root`, fixed lenght of one VarInt and 32 bytes hash
    MergeMining(VarInt, hash::Hash),
    /// Additional public keys for Subaddresses outputs, variable lenght of `n` additional public keys
    AdditionalPublickKey(Vec<PublicKey>),
    /// Mysterious MinerGate, variable lenght
    MysteriousMinerGate(String),
}

/// The part of a transaction that contains all the data except signatures.
///
/// Can generate the transaction prefix hash with `tx_prefix.hash()`
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct TransactionPrefix {
    /// Transaction format version
    pub version: VarInt,
    /// UNIX timestamp
    pub unlock_time: VarInt,
    /// Array of inputs
    pub inputs: Vec<TxIn>,
    /// Array of outputs
    pub outputs: Vec<TxOut>,
    /// Additional data associated with a transaction
    pub extra: ExtraField,
}

impl_consensus_encoding!(
    TransactionPrefix,
    version,
    unlock_time,
    inputs,
    outputs,
    extra
);

impl TransactionPrefix {
    /// Return the transaction public key present in extra field
    pub fn tx_pubkey(&self) -> Option<PublicKey> {
        self.extra.tx_pubkey()
    }

    /// Return the additional public keys present in extra field
    pub fn tx_additional_pubkeys(&self) -> Option<Vec<PublicKey>> {
        self.extra.tx_additional_pubkeys()
    }

    /// Iterate over transaction outputs and find outputs related to view pair
    pub fn check_outputs(
        &self,
        pair: &ViewPair,
        major: Range<u32>,
        minor: Range<u32>,
    ) -> Result<Vec<OwnedTxOut>, Error> {
        match self.tx_additional_pubkeys() {
            Some(tx_additional_pubkeys) => {
                let checker = onetime_key::SubKeyChecker::new(&pair, major, minor);
                Ok((1..)
                    .zip(self.outputs.iter())
                    .zip(tx_additional_pubkeys.iter())
                    .filter_map(|((i, out), tx_random)| {
                        match out.target {
                            TxOutTarget::ToKey { key } => match checker.check(&key, tx_random) {
                                Some(sub_index) => Some(OwnedTxOut {
                                    index: i,
                                    out,
                                    sub_index: *sub_index,
                                }),
                                None => None,
                            },
                            // Reject all non-toKey outputs
                            _ => None,
                        }
                    })
                    .collect())
            }
            None => match self.tx_pubkey() {
                Some(tx_pubkey) => {
                    let generator = onetime_key::KeyGenerator::from_key(pair, tx_pubkey);
                    Ok((1..)
                        .zip(self.outputs.iter())
                        .filter_map(|(i, out)| {
                            match out.target {
                                TxOutTarget::ToKey { key } => {
                                    if generator.check(i, key) {
                                        Some(OwnedTxOut {
                                            index: i,
                                            out,
                                            sub_index: Index::default(),
                                        })
                                    } else {
                                        None
                                    }
                                }
                                // Reject all non-toKey outputs
                                _ => None,
                            }
                        })
                        .collect())
                }
                None => Err(Error::NoTxPublicKey),
            },
        }
    }
}

// To get transaction prefix hash
impl hash::Hashable for TransactionPrefix {
    fn hash(&self) -> hash::Hash {
        hash::Hash::hash(&serialize(self))
    }
}

/// A full transaction containing the prefix and all signing data
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct Transaction {
    /// The transaction prefix
    pub prefix: TransactionPrefix,
    /// The signatures
    pub signatures: Vec<Vec<Signature>>,
    /// RingCT signatures
    pub rct_signatures: RctSig,
}

impl hash::Hashable for Transaction {
    fn hash(&self) -> hash::Hash {
        match *self.prefix.version {
            1 => hash::Hash::hash(&serialize(self)),
            _ => {
                let mut hashes: Vec<hash::Hash> = vec![];
                hashes.push(self.prefix.hash());
                if let Some(sig_base) = &self.rct_signatures.sig {
                    hashes.push(sig_base.hash());
                    if sig_base.rct_type == RctType::Null {
                        hashes.push(hash::Hash::null_hash());
                    } else {
                        match &self.rct_signatures.p {
                            Some(p) => {
                                let mut encoder = Cursor::new(vec![]);
                                p.consensus_encode(&mut encoder, sig_base.rct_type).unwrap();
                                hashes.push(hash::Hash::hash(&encoder.into_inner()));
                            }
                            None => {
                                let empty_hash = hash::Hash::from_slice(&[
                                    0x70, 0xa4, 0x85, 0x5d, 0x04, 0xd8, 0xfa, 0x7b, 0x3b, 0x27,
                                    0x82, 0xca, 0x53, 0xb6, 0x00, 0xe5, 0xc0, 0x03, 0xc7, 0xdc,
                                    0xb2, 0x7d, 0x7e, 0x92, 0x3c, 0x23, 0xf7, 0x86, 0x01, 0x46,
                                    0xd2, 0xc5,
                                ]);
                                hashes.push(empty_hash);
                            }
                        }
                    }
                }
                let bytes: Vec<u8> = hashes
                    .into_iter()
                    .flat_map(|h| Vec::from(&h.to_bytes()[..]))
                    .collect();
                hash::Hash::hash(&bytes)
            }
        }
    }
}

// ----------------------------------------------------------------------------------------------------------------

impl<D: Decoder> Decodable<D> for ExtraField {
    fn consensus_decode(d: &mut D) -> Result<ExtraField, encode::Error> {
        let mut fields: Vec<SubField> = vec![];
        let bytes: Vec<u8> = Decodable::consensus_decode(d)?;
        let mut decoder = Cursor::new(&bytes[..]);
        // Decode each extra field
        while decoder.position() < bytes.len() as u64 {
            fields.push(Decodable::consensus_decode(&mut decoder)?);
        }
        // Fail if data are not consumed entirely.
        if decoder.position() as usize == bytes.len() {
            Ok(ExtraField(fields))
        } else {
            Err(encode::Error::ParseFailed(
                "data not consumed entirely when explicitly deserializing",
            ))
        }
    }
}

impl<S: Encoder> Encodable<S> for ExtraField {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        let mut encoder = Cursor::new(vec![]);
        for field in self.0.iter() {
            field.consensus_encode(&mut encoder)?;
        }
        encoder.into_inner().consensus_encode(s)
    }
}

impl<D: Decoder> Decodable<D> for SubField {
    fn consensus_decode(d: &mut D) -> Result<SubField, encode::Error> {
        let tag: u8 = Decodable::consensus_decode(d)?;

        match tag {
            0x0 => {
                let mut i = 0;
                loop {
                    // Consume all bytes until the end of cursor
                    // A new cursor must be created when parsing extra bytes otherwise
                    // transaction bytes will be consumed
                    //
                    // This works because extra padding must be the last one
                    let byte: Result<u8, encode::Error> = Decodable::consensus_decode(d);
                    match byte {
                        Ok(_) => {
                            i += 1;
                        }
                        Err(_) => break,
                    }
                }
                Ok(SubField::Padding(i))
            }
            0x1 => Ok(SubField::TxPublicKey(Decodable::consensus_decode(d)?)),
            0x2 => Ok(SubField::Nonce(Decodable::consensus_decode(d)?)),
            0x3 => Ok(SubField::MergeMining(
                Decodable::consensus_decode(d)?,
                Decodable::consensus_decode(d)?,
            )),
            0x4 => Ok(SubField::AdditionalPublickKey(Decodable::consensus_decode(
                d,
            )?)),
            0xde => Ok(SubField::MysteriousMinerGate(Decodable::consensus_decode(
                d,
            )?)),
            _ => Err(encode::Error::ParseFailed("Invalid sub-field type")),
        }
    }
}

impl<S: Encoder> Encodable<S> for SubField {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        match *self {
            SubField::Padding(nbytes) => {
                0x0u8.consensus_encode(s)?;
                for _ in 0..nbytes {
                    0u8.consensus_encode(s)?;
                }
                Ok(())
            }
            SubField::TxPublicKey(ref pubkey) => {
                0x1u8.consensus_encode(s)?;
                pubkey.consensus_encode(s)
            }
            SubField::Nonce(ref nonce) => {
                0x2u8.consensus_encode(s)?;
                nonce.consensus_encode(s)
            }
            SubField::MergeMining(ref depth, ref merkle_root) => {
                0x3u8.consensus_encode(s)?;
                depth.consensus_encode(s)?;
                merkle_root.consensus_encode(s)
            }
            SubField::AdditionalPublickKey(ref pubkeys) => {
                0x4u8.consensus_encode(s)?;
                pubkeys.consensus_encode(s)
            }
            SubField::MysteriousMinerGate(ref string) => {
                0xdeu8.consensus_encode(s)?;
                string.consensus_encode(s)
            }
        }
    }
}

impl<D: Decoder> Decodable<D> for TxIn {
    fn consensus_decode(d: &mut D) -> Result<TxIn, encode::Error> {
        let intype: u8 = Decodable::consensus_decode(d)?;
        match intype {
            0xff => Ok(TxIn::Gen {
                height: Decodable::consensus_decode(d)?,
            }),
            0x0 | 0x1 => Err(Error::ScriptNotSupported.into()),
            0x2 => Ok(TxIn::ToKey {
                amount: Decodable::consensus_decode(d)?,
                key_offsets: Decodable::consensus_decode(d)?,
                k_image: Decodable::consensus_decode(d)?,
            }),
            _ => Err(encode::Error::ParseFailed("Invalid input type")),
        }
    }
}

impl<S: Encoder> Encodable<S> for TxIn {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        match self {
            TxIn::Gen { height } => {
                0xffu8.consensus_encode(s)?;
                height.consensus_encode(s)
            }
            TxIn::ToKey {
                amount,
                key_offsets,
                k_image,
            } => {
                0x2u8.consensus_encode(s)?;
                amount.consensus_encode(s)?;
                key_offsets.consensus_encode(s)?;
                k_image.consensus_encode(s)
            }
            _ => Err(Error::ScriptNotSupported.into()),
        }
    }
}

impl<D: Decoder> Decodable<D> for TxOutTarget {
    fn consensus_decode(d: &mut D) -> Result<TxOutTarget, encode::Error> {
        let outtype: u8 = Decodable::consensus_decode(d)?;
        match outtype {
            0x2 => Ok(TxOutTarget::ToKey {
                key: Decodable::consensus_decode(d)?,
            }),
            _ => Err(encode::Error::ParseFailed("Invalid output type")),
        }
    }
}

impl<S: Encoder> Encodable<S> for TxOutTarget {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        match self {
            TxOutTarget::ToKey { key } => {
                0x2u8.consensus_encode(s)?;
                key.consensus_encode(s)
            }
            _ => Err(Error::ScriptNotSupported.into()),
        }
    }
}

#[allow(non_snake_case)]
impl<D: Decoder> Decodable<D> for Transaction {
    fn consensus_decode(d: &mut D) -> Result<Transaction, encode::Error> {
        let prefix: TransactionPrefix = Decodable::consensus_decode(d)?;

        let inputs = prefix.inputs.len();
        let outputs = prefix.outputs.len();

        match *prefix.version {
            1 => {
                let signatures: Result<Vec<Vec<Signature>>, encode::Error> = prefix
                    .inputs
                    .iter()
                    .filter_map(|input| match input {
                        TxIn::ToKey { key_offsets, .. } => {
                            let sigs: Result<Vec<Signature>, encode::Error> = key_offsets
                                .iter()
                                .map(|_| Decodable::consensus_decode(d))
                                .collect();
                            Some(sigs)
                        }
                        _ => None,
                    })
                    .collect();
                Ok(Transaction {
                    prefix,
                    signatures: signatures?,
                    rct_signatures: RctSig { sig: None, p: None },
                })
            }
            _ => {
                let signatures = vec![];
                let mut rct_signatures = RctSig { sig: None, p: None };
                if inputs == 0 {
                    return Ok(Transaction {
                        prefix,
                        signatures,
                        rct_signatures: RctSig { sig: None, p: None },
                    });
                }

                if let Some(sig) = RctSigBase::consensus_decode(d, inputs, outputs)? {
                    let p = {
                        if sig.rct_type != RctType::Null {
                            let mixin_size = if inputs > 0 {
                                match &prefix.inputs[0] {
                                    TxIn::ToKey { key_offsets, .. } => key_offsets.len() - 1,
                                    _ => 0,
                                }
                            } else {
                                0
                            };
                            RctSigPrunable::consensus_decode(
                                d,
                                sig.rct_type,
                                inputs,
                                outputs,
                                mixin_size,
                            )?
                        } else {
                            None
                        }
                    };
                    rct_signatures = RctSig { sig: Some(sig), p };
                }

                Ok(Transaction {
                    prefix,
                    signatures,
                    rct_signatures,
                })
            }
        }
    }
}

impl<S: Encoder> Encodable<S> for Transaction {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        self.prefix.consensus_encode(s)?;
        match *self.prefix.version {
            1 => {
                for sig in self.signatures.iter() {
                    encode_sized_vec!(sig, s);
                }
            }
            _ => {
                if let Some(sig) = &self.rct_signatures.sig {
                    sig.consensus_encode(s)?;
                    if let Some(p) = &self.rct_signatures.p {
                        p.consensus_encode(s, sig.rct_type)?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{Transaction, TransactionPrefix};
    use crate::consensus::encode::{deserialize, deserialize_partial, serialize};
    use crate::cryptonote::hash::Hashable;
    use crate::util::key::{PrivateKey, PublicKey, ViewPair};

    #[test]
    fn deserialize_transaction_prefix() {
        let hex = hex::decode("01f18d0601ffb58d0605efefead70202eb72f82bd8bdda51e0bdc25f04e99ffb90c6214e11b455abca7b116c7857738880e497d01202e87c65a22b78f4b7686ef3a30113674659a4fe769a7ded73d60e6f7c556a19858090dfc04a022ee52dca8845438995eb6d7af985ca07186cc34a7eb696937f78fc0fd9008e2280c0f9decfae0102cec392ffdcae05a370dc3c447465798d3688677f4a5937f1fef9661df99ac2fb80c0caf384a30202e2b6ce11475c2312d2de5c9f26fbd88b7fcac0dbbb7b31f49abe9bd631ed49e42b0104d46cf1a204ae727c14473d67ea95da3e97b250f3c63e0997198bfc812d7a81020800000000d8111b25").unwrap();
        let tx = deserialize::<TransactionPrefix>(&hex[..]);
        assert_eq!(true, tx.is_ok());
        let tx = tx.unwrap();
        assert_eq!(hex, serialize(&tx));
        assert_eq!(
            "3bc7ff015b227e7313cc2e8668bfbb3f3acbee274a9c201d6211cf681b5f6bb1",
            format!("{:02x}", tx.hash())
        );

        let tx = deserialize::<Transaction>(&hex[..]).unwrap();
        assert_eq!(
            "3bc7ff015b227e7313cc2e8668bfbb3f3acbee274a9c201d6211cf681b5f6bb1",
            format!("{:02x}", tx.hash())
        );
    }

    #[test]
    fn transaction_hash() {
        let hex = hex::decode("02000202000bc6aa98049bf603fcec06bd3ccbad04e807e328b5128f22a63bfb27b6e287e8d594664d5cddd6c89bc413d1bc607b242203a6eb3180041ff5ae679702000b90e4eb028298a101879110f5bc0383ad03cbfc03a750e52ace37d112c6064faf7d16e2d07c4cc979dccb858aa9b24e12479e4a2db8350a906ba7a1aec409020002ab6d783607d8e712bbd5aad54a412aec890fcdcc1b35bf0ca4a705c2159bfc32000262f4016d5d81ade9e555807a24d23d452f08b6400683da599abd7134fb75324a2c0209016631a2dee1d0f51f015fd9bf938cf132790bdc5c528037e347828c539e82da6e5921e3d1e6052cb25804d0b7ba81018a4cd5385ca23ff4f6d76dc41b5254abf579b1856d3fbd04e81ff97c113e318bf7e158fbb0db7adc6ece9c8d4ab94e91f68e9607667a858ddf3e6890b2835403db6dcc5a1c179a768bcf74d74ace86430176b0056de37f310884e8eed56ee86840f23f842f1db52945b2feef98f4b56b3d4407734e4e8d3b117b5fd78f0d94f6059b495f53cf855b3716bbe8614d51727556c8b2e5c303cffc694257a1e91372de2047c4e12381c1de8df46102cdd84a24692f68ada05d1ffc5122b655582c6307141e130a6963198085ddb67d304b0ddde87e62402a3cadcd07a315604607ddf1530bd85685e910aa879733549bde0d019edc36326d33edd6ccecc800395b7075e4959779bde803dd787c24bc25d40205071b180152dded8b0be1f48a6d6f8e97c3f934f866b1b697f73f73fc9f38c5d2082c610732c79b2f69f403f7e2d312399739dd8d4225a2914a3020bd88c362271df633e8387b5345b50f11c4f148f76c0c24ca5843580a02fe72d18f47dcf8d601e28bbef2cd6659e620179adad4dfa5a0c7b712d716c4e630fe40bbfc6184f76c401db4b801a7001f65a9c11053db919099f9a1a4fe575c6d783e041ee08222a46adb8a1f13b863d95da277b71ccdefbb32f713a13b5ac8d041bbbeed9df4ace5a6b730b871ad2fe14141dbb9c816a21fd7fc48cfba4d2cc3e5e5fba29f581c1507a6a36285a30344790b74d2212dd26178395cd96a18518ead5c59a410baf6ca0b9217865fff207d757bb465fdb053e8c80b2ec1a966ccc01f49096fb991b65cc160a5070532c47318720fb9a90f187ce53661b6ce1e29d6ccd2b131324101170bb87ef273f0e73d762e159264f0839c6b3b31f5264499bdeb029c66a7035108a84256aec2760e74c2e8e788b7747084da8953aa48696b7a46e6320a9534d6c06ddee1b26671f03ae70a30c76b8fbf268da16fbb685f1d3f602668afce2e3eaf089b8758069f398eaeccd01876cef623201dc46dd75f76dc2141a9a2071b2761eefbf735ca599ed15266acbd0f54f49de38b5c7b3b378c386767383396645778021b30910e6e06937d65dac82312968d4f63a0bb28c96b9a09ee1d95c4d3afbb021998a9e290647b51083a80d66e0a8900a89c1236214f2d7c0080e2c18cdc8c0b4bd66765c3c52a26b90ec549bc8358ff8aaac9ffaecb0f6c915113cc97147b06c007a1a6bcd536bddec7fba330877d80cb878c7c9f3da81f8eb3bfb07ac7a804d4d58faadfabc3421350b14af6500b931209b75813759509e8642574982d680632106041b2687bdaef1c2be67c63a0ccc427bf02dc1ba58b153f00f8fabc8c00d99934e3e835291b8fc5a0bd62a3059c22cbd6fc4ae403df254e17cb15f32b0b65a4ed1f0f5fff37e49417c5fee339c21bd4f1cdcb1c803df8cb4baa11fa210089b61e28fe42e112824ee705f13167bfd3e6c8d660f2307216f5eea91a6db505b70f38e4b1b72a8f1fa1dd90bf0a47ed9a71e2e11e4f20240c1dac370f2b18075c6537bb475897fdd90fae360afb0b6b02210c123a3ca8fae31e320639b5e00c91c821abe873c1aaee2c4ebb87b5ecc670bff65de191e1d8463ecf1367685c0f0d39efc20269e516f29b775060a0c7a1595e158e94f64407d8e22b16ff25ed00cd50c46fb95ab5a3ca60a04e222c83d26b11c08a678348c8cdad407a0d841c0a50e91e896cb4ff873e9fc81c35f4a146f25a64b294c07c6adf4e418a3f590f061a89267deea53d985b4576b70b95170970321e07c1397b6f7e1ed3d4629e8e0a81019a7c15ae6d252e856c761664862d7fd0620fbbc7020fcd675fc97dc7310420b0d428093b4a80012f7a46612161ee2eeec8996128876d093f71f954244004aded4185afeec305d104d3905e54ddfda59ce1f5d56cf078ff10a76b138db90789184149cab60dfb1491943a793e85c332b4b36f448b63e5f099e7beb11d07005a31ed1658251e9f880466e44c54357781c9cdaf17d48534b062de482ad94005cbdcf52d6fea2e70c20ecc62a339afbb971e455e38292b78b21393bce982ec06d3e6f3e27897877007283f5a9d44ae134efc0ff14a5ce2fbe711403b535413073c9769ddc0474d64643bd2d60f58e001717f0538e1cc1e6b211c5f06f6ddfa029ec10d7e949673c08cd71713728ff042948c5b75ea2b610f4b4db838696fa40e24d750aa75f910948af39de2eba2ff6864daf92004453e4fa5cdae2f553a460f9bc86073dd7d6d2ea0f31092d28110892d6077dcee3b6293e66867a7ae67c5048df756d253c768debf3989d7643ff8892b7f6f74bf2b36d01bd0b88760c9b30eb54d02aa5498e7b87e2d027ac2a449318deda9cabf356fcd07f4561e6370db09fbd0d081093d93a569f6968b291fb01995415293b7cd997d9367c352c75b230ee70de92efd35302572e9de2809cd8e25eb9f824cb559107a1b87dd8c365de106cc800350e1284d67555b8db9041dfd44b3d5bec42e2b186b6a72b5bc3df0470476c234277592f742c3bf3babd4759b115196117883434af1d014ba8aeca028054fb4e8d9dde6a0e4cca9388a9f4c6283cbf9ae89dd17e4dc2a2f511604b33f0ee6e42e4f9a20b556ebc66e18b6142bfdcd4bf3792d9659ca5f5ef041f5ba28053e752155263ea79bd65dd94157f9464625e6a2e1b1e6d8ff40b4af4cb3804606239b8370d69d14f5c9eb463f49b0e796efdf01ddc087cc710bae43968856000fdc3a6408861363a190edbf2ae3e13d2bc52f87d9f2e31c044698b79f37b75a03199c7585b880df73a362ff40a94ed1d6173998d247a8f74e28407ad933e8bb0cd91ee82b723b3f22152a53b3226e52b32b93b397b5b2c386d3468651e602360eba66e52a1844aac9bbbe1a7183e97fed0c8b4b649f1551bcb98248dd62ebec087d4020a042085d487c64ae3fcf25e11b443ff03eeb8345b6d45d5304fbba83030bce1bbe499a7f5aefff31fef134b3c2c85b2fd16e6a26133cdbf05069299f007e627036d5ce0536e10546ec3b0719c373e00792f45fa78ff62d543e204d9a0f54a2b1c934a1463620a5c789ed600792ace37bc0f79c84399018acd073e86309f16a4ee382baad3e98425be3dcea1fceb47e56d237a49a125a360f7eb56b0305632f3877c17e62204e5a2c2017a934be9e532c5d7fd14ed71c4a2d3947621d03373796d7ffd6c77a73a06e3cbb61e1d872fb012c9ea0327fb65c4ffa46f02507d4db98bd434a7e921130e8846e697da226cc85568aa83f95cdfc4ccbfbff8ab0653000211ee7438364596b53793f2dfc4705f6a491190b35960f9aec1ffaad8a").unwrap();
        let tx = deserialize_partial::<TransactionPrefix>(&hex[..]);
        assert_eq!(true, tx.is_ok());
        let tx = tx.unwrap().0;
        assert_eq!(
            "3b50349180b4a60e55187507746eabb7bee0de6b74168eac8720a449da28613b",
            format!("{:02x}", tx.hash())
        );

        let tx = deserialize::<Transaction>(&hex[..]);
        assert_eq!(true, tx.is_ok());
        let tx = tx.unwrap();
        assert_eq!(hex, serialize(&tx));
        assert_eq!(
            "5a420317e377d3d95b652fb93e65cfe97ef7d89e04be329a2ca94e73ec57b74e",
            format!("{:02x}", tx.hash())
        );
    }

    #[test]
    fn find_outputs() {
        let view = PrivateKey::from_str(
            "77916d0cd56ed1920aef6ca56d8a41bac915b68e4c46a589e0956e27a7b77404",
        )
        .unwrap();
        let b = PrivateKey::from_str(
            "8163466f1883598e6dd14027b8da727057165da91485834314f5500a65846f09",
        )
        .unwrap();
        let spend = PublicKey::from_private_key(&b);
        let viewpair = ViewPair { view, spend };

        let hex = hex::decode("01f18d0601ffb58d0605efefead70202eb72f82bd8bdda51e0bdc25f04e99ffb90c6214e11b455abca7b116c7857738880e497d01202e87c65a22b78f4b7686ef3a30113674659a4fe769a7ded73d60e6f7c556a19858090dfc04a022ee52dca8845438995eb6d7af985ca07186cc34a7eb696937f78fc0fd9008e2280c0f9decfae0102cec392ffdcae05a370dc3c447465798d3688677f4a5937f1fef9661df99ac2fb80c0caf384a30202e2b6ce11475c2312d2de5c9f26fbd88b7fcac0dbbb7b31f49abe9bd631ed49e42b0104d46cf1a204ae727c14473d67ea95da3e97b250f3c63e0997198bfc812d7a81020800000000d8111b25").unwrap();
        let tx = deserialize::<TransactionPrefix>(&hex[..]);
        assert_eq!(true, tx.is_ok());
        let tx = tx.unwrap();
        assert_eq!(
            "3bc7ff015b227e7313cc2e8668bfbb3f3acbee274a9c201d6211cf681b5f6bb1",
            format!("{:02x}", tx.hash())
        );
        assert_eq!(true, tx.check_outputs(&viewpair, 0..1, 0..200).is_ok());
        assert_eq!(hex, serialize(&tx));

        let tx = deserialize::<Transaction>(&hex[..]);
        assert_eq!(true, tx.is_ok());
        let tx = tx.unwrap();
        assert_eq!(
            "3bc7ff015b227e7313cc2e8668bfbb3f3acbee274a9c201d6211cf681b5f6bb1",
            format!("{:02x}", tx.hash())
        );
    }
}

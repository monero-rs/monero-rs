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

//! Transaction, transaction's prefix, inputs and outputs structures used to parse and create
//! transactions.
//!
//! This module support (de)serializing Monero transaction and input/amount discovery/recovery with
//! private view key and public spend key (view key-pair: [`ViewPair`]).
//!

use crate::consensus::encode::{self, serialize, Decodable, EncodeError, VarInt};
use crate::cryptonote::hash;
use crate::cryptonote::onetime_key::{KeyGenerator, KeyRecoverer, SubKeyChecker};
use crate::cryptonote::subaddress::Index;
use crate::util::amount::Amount;
use crate::util::key::{KeyPair, PrivateKey, PublicKey, ViewPair};
use crate::util::ringct::{
    Opening, RctSig, RctSigBase, RctSigPrunable, RctType, RingCtError, Signature,
};

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use hex::encode as hex_encode;
use sealed::sealed;
use thiserror::Error;

use std::ops::Range;
use std::{fmt, io};

use crate::cryptonote::hash::HashError;
use crate::util::address::AddressError;
#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};

/// Errors possible when manipulating transactions.
#[derive(Error, Debug, PartialEq)]
pub enum TransactionError {
    /// No transaction public key found in extra.
    #[error("No transaction public key found")]
    NoTxPublicKey,
    /// Scripts input/output are not supported.
    #[error("Script not supported")]
    ScriptNotSupported,
    /// Missing ECDH info for the output.
    #[error("Missing ECDH info for the output")]
    MissingEcdhInfo,
    /// Invalid commitment.
    #[error("Invalid commitment")]
    InvalidCommitment,
    /// Missing commitment.
    #[error("Missing commitment")]
    MissingCommitment,
    /// Transaction error.
    #[error("Encoding error: {0}")]
    EncodeError(#[from] EncodeError),
    /// Address error.
    #[error("Address error: {0}")]
    AddressError(#[from] AddressError),
    /// Address error.
    #[error("Ring Ct error: {0}")]
    RingCtError(#[from] RingCtError),
}

/// The key image used in transaction inputs [`TxIn`] to commit to the use of an output one-time
/// public key as in [`TxOutTarget::ToKey`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct KeyImage {
    /// The actual key image data.
    pub image: hash::Hash,
}

impl_consensus_encoding!(KeyImage, image);

/// A transaction input, either a coinbase spend or a one-time key spend which defines the ring
/// size and the key image to avoid double spend.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub enum TxIn {
    /// A coinbase input.
    Gen {
        /// Block height of where the coinbase transaction is included.
        height: VarInt,
    },
    /// A key input from a key output.
    ToKey {
        /// Amount spend from the output, 0 in case of CT.
        amount: VarInt,
        /// Relative offsets of keys use in the ring.
        key_offsets: Vec<VarInt>,
        /// The corresponding key image of the output.
        k_image: KeyImage,
    },
}

/// Type of output formats, only [`TxOutTarget::ToKey`] and [`TxOutTarget::ToTaggedKey`] are used, other formats are legacy to the
/// original cryptonote implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub enum TxOutTarget {
    /// A script output, not used.
    ToScript {
        /// A list of keys.
        keys: Vec<PublicKey>,
        /// The script.
        script: Vec<u8>,
    },
    /// A one-time public key output.
    ToKey {
        /// The one-time public key of that output.
        key: [u8; 32],
    },
    /// A one-time public key output with a view tag.
    ToTaggedKey {
        /// The one-time public key of that output.
        key: [u8; 32],
        /// The view tag of that output.
        view_tag: u8,
    },
    /// A script hash output, not used.
    ToScriptHash {
        /// The script hash
        hash: hash::Hash,
    },
}

impl TxOutTarget {
    /// Retrieve the public keys, if any.
    pub fn get_pubkeys(&self) -> Option<Vec<PublicKey>> {
        match self {
            TxOutTarget::ToScript { keys, .. } => Some(keys.clone()),
            TxOutTarget::ToKey { key } => {
                let key = PublicKey::from_slice(key);
                if let Ok(key) = key {
                    return Some(vec![key]);
                }
                None
            }
            TxOutTarget::ToTaggedKey { key, .. } => {
                let key = PublicKey::from_slice(key);
                if let Ok(key) = key {
                    return Some(vec![key]);
                }
                None
            }
            TxOutTarget::ToScriptHash { .. } => None,
        }
    }

    /// Returns the one-time public key if this is a [`TxOutTarget::ToKey`] or [`TxOutTarget::ToTaggedKey`] and `None` otherwise.
    pub fn as_one_time_key(&self) -> Option<PublicKey> {
        match self {
            TxOutTarget::ToKey { key } => {
                let key = PublicKey::from_slice(key);
                if let Ok(key) = key {
                    return Some(key);
                }
                None
            }
            TxOutTarget::ToTaggedKey { key, .. } => {
                let key = PublicKey::from_slice(key);
                if let Ok(key) = key {
                    return Some(key);
                }
                None
            }
            _ => None,
        }
    }

    /// Derives a view tag and checks if it matches the outputs view tag,
    /// if no view tag is present the default is true.
    pub fn check_view_tag(&self, rv: PublicKey, index: u8) -> bool {
        match self {
            TxOutTarget::ToTaggedKey { key: _, view_tag } => {
                // https://github.com/monero-project/monero/blob/b6a029f222abada36c7bc6c65899a4ac969d7dee/src/crypto/crypto.cpp#L753
                let salt: Vec<u8> = vec![118, 105, 101, 119, 95, 116, 97, 103];
                let rv = rv.as_bytes().to_vec();
                let buf = [salt, rv, Vec::from([index])].concat();
                *view_tag == hash::Hash::new(buf).as_bytes()[0]
            }
            _ => true,
        }
    }
}

/// A transaction output, can be consumed by a [`TxIn`] input of the matching format.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct TxOut {
    /// The amount sent to the associated key, can be 0 in case of Confidential Transaction (CT).
    pub amount: VarInt,
    /// The output target format.
    pub target: TxOutTarget,
}

impl_consensus_encoding!(TxOut, amount, target);

impl TxOut {
    /// Retreive the public keys, if any
    pub fn get_pubkeys(&self) -> Option<Vec<PublicKey>> {
        self.target.get_pubkeys()
    }
}

/// Transaction ouput that can be redeemed by a private key pair at a given index and are returned
/// by the [`check_outputs`] method.
///
/// [`check_outputs`]: TransactionPrefix::check_outputs
///
/// ```rust
/// use monero::blockdata::transaction::Transaction;
/// use monero::consensus::encode::deserialize;
/// use monero::util::key::{KeyPair, PrivateKey, PublicKey, ViewPair};
/// # use std::str::FromStr;
///
/// # let raw_tx = hex::decode("02000102000bb2e38c0189ea01a9bc02a533fe02a90705fd0540745f59f49374365304f8b4d5da63b444b2d74a40f8007ea44940c15cbbc80c9d106802000267f0f669ead579c1067cbffdf67c4af80b0287c549a10463122b4860fe215f490002b6a2e2f35a93d637ff7d25e20da326cee8e92005d3b18b3c425dabe8336568992c01d6c75cf8c76ac458123f2a498512eb65bb3cecba346c8fcfc516dc0c88518bb90209016f82359eb1fe71d604f0dce9470ed5fd4624bb9fce349a0e8317eabf4172f78a8b27dec6ea1a46da10ed8620fa8367c6391eaa8aabf4ebf660d9fe0eb7e9dfa08365a089ad2df7bce7ef776467898d5ca8947152923c54a1c5030e0c2f01035c555ff4285dcc44dfadd6bc37ec8b9354c045c6590446a81c7f53d8f199cace3faa7f17b3b8302a7cbb3881e8fdc23cca0275c9245fdc2a394b8d3ae73911e3541b10e7725cdeef5e0307bc218caefaafe97c102f39c8ce78f62cccf23c69baf0af55933c9d384ceaf07488f2f1ac7343a593449afd54d1065f6a1a4658845817e4b0e810afc4ca249096e463f9f368625fa37d5bbcbe87af68ce3c4d630f93a66defa4205b178f4e9fa04107bd535c7a4b2251df2dad255e470b611ffe00078c2916fc1eb2af1273e0df30dd1c74b6987b9885e7916b6ca711cbd4b7b50576e51af1439e9ed9e33eb97d8faba4e3bd46066a5026a1940b852d965c1db455d1401687ccaccc524e000b05966763564b7deb8fd64c7fb3d649897c94583dca1558893b071f5e6700dad139f3c6f973c7a43b207ee3e67dc7f7f18b52df442258200c7fe6d16685127da1df9b0d93d764c2659599bc6d300ae33bf8b7c2a504317da90ea2f0bb2af09bd531feae57cb4a0273d8add62fadfc6d43402372e5caf854e112b88417936f1a9c4045d48b5b0b7703d96801b35ff66c716cddbee1b92407aa069a162c163071710e28ccddf6fb560feea32485f2c54a477ae23fd8210427eabe4288cbe0ecbef4ed19ca049ceded424d9f839da957f56ffeb73060ea15498fcbc2d73606e85e963a667dafdb2641fb91862c07b98c1fdae8fadf514600225036dd63c22cdadb57d2125ebf30bc77f7ea0bc0dafb484bf01434954c5053b9c8a143f06972f80fa66788ea1e3425dc0104a9e3674729967b9819552ebb172418da0e4b3778ad4b3d6acd8f354ba09e54bbc8604540010e1e1e4d3066515aed457bd3399c0ce787236dbcd3923de4fb8faded10199b33c1251191612ab5526c1cf0cd55a0aeaed3f7a955ceced16dabdbeb0a2a19a9fdb5aa8c4fc8767cf70e4ad1838518bc6b9de7c420c1f57636579a14a5a8bdacd24e61a68adede8a2e07416c25409dd91ab78905bc99bab4ab4fb9e4ea628e09a271837769c4e67e580dcd5485e12e4e308cb4509686a7484a71f7dfe334499808c7122f07d45d89230b1f19ed86f675b7fec44ef5f3b178ae0af92ff114bd96baa264604fea5a762307bdce6cb483b7bc780d32ed5343fcc3aa306997f211dc075f6dfd66035c1db10bef8656fefbb45645264d401682e42fe3e05906f79d65481b87508f1a4c434e0d1dfc247d4276306f801a6b57e4e4a525177bae24e0bd88a216597d9db44f2604c29d8a5f74e7b934f55048690b5dcefd6489a81aa64c1edb49b320faab94130e603d99e455cfd828bca782176192ece95e9b967fe3dd698574cf0c0b6926970b156e1134658de657de42c4930e72b49c0d94da66c330ab188c10f0d2f578590f31bcac6fcff7e21f9ff67ae1a40d5a03b19301dcbbadc1aa9392795cf81f1401ec16d986a7f96fbb9e8e12ce04a2226e26b78117a4dfb757c6a44481ff68bb0909e7010988cd37146fb45d4cca4ba490aae323bb51a12b6864f88ea6897aa700ee9142eaf0880844083026f044a5e3dba4aae08578cb057976001beb27b5110c41fe336bf7879733739ce22fb31a1a6ac2c900d6d6c6facdbc60085e5c93d502542cfea90dbc62d4e061b7106f09f9c4f6c1b5506dd0550eb8b2bf17678b140de33a10ba676829092e6a13445d1857d06c715eea4492ff864f0b34d178a75a0f1353078f83cfee1440b0a20e64abbd0cab5c6e7083486002970a4904f8371805d1a0ee4aea8524168f0f39d2dfc55f545a98a031841a740e8422a62e123c8303021fb81afbb76d1120c0fbc4d3d97ba69f4e2fe086822ece2047c9ccea507008654c199238a5d17f009aa2dd081f7901d0688aa15311865a319ccba8de4023027235b5725353561c5f1185f6a063fb32fc65ef6e90339d406a6884d66be49d03daaf116ee4b65ef80dd3052a13157b929f98640c0bbe99c8323ce3419a136403dc3f7a95178c3966d2d7bdecf516a28eb2cf8cddb3a0463dc7a6248883f7be0a10aae1bb50728ec9b8880d6011b366a850798f6d7fe07103695dded3f371ca097c1d3596967320071d7f548938afe287cb9b8fae761fa592425623dcbf653028").unwrap();
/// # let tx = deserialize::<Transaction>(&raw_tx).expect("Raw tx deserialization failed");
/// # let secret_view_bytes =
/// #     hex::decode("bcfdda53205318e1c14fa0ddca1a45df363bb427972981d0249d0f4652a7df07").unwrap();
/// # let secret_view = PrivateKey::from_slice(&secret_view_bytes).unwrap();
/// # let public_view = PublicKey::from_private_key(&secret_view);
/// #
/// # let secret_spend_bytes =
/// #     hex::decode("e5f4301d32f3bdaef814a835a18aaaa24b13cc76cf01a832a7852faf9322e907").unwrap();
/// # let secret_spend = PrivateKey::from_slice(&secret_spend_bytes).unwrap();
/// # let public_spend = PublicKey::from_private_key(&secret_spend);
/// #
/// // Keypair used to recover the ephemeral spend key of an output
/// let keypair = KeyPair {
///     view: secret_view,
///     spend: secret_spend,
/// };
///
/// # let spend = public_spend;
/// #
/// // Viewpair used to scan a transaction to retreive owned outputs
/// let view_pair = ViewPair { view: secret_view, spend };
///
/// // Get all owned output for sub-addresses in range of 0-1 major index and 0-2 minor index
/// let owned_outputs = tx.check_outputs(&view_pair, 0..2, 0..3).unwrap();
///
/// for out in owned_outputs {
///     // Recover the ephemeral private spend key
///     let private_key = out.recover_key(&keypair);
/// }
/// ```
///
#[derive(Debug)]
pub struct OwnedTxOut<'a> {
    index: usize,
    out: &'a TxOut,
    sub_index: Index,
    tx_pubkey: PublicKey,
    opening: Option<Opening>,
}

impl<'a> OwnedTxOut<'a> {
    /// Returns the index of this output in the transaction
    pub fn index(&self) -> usize {
        self.index
    }

    /// Returns a reference to the actual redeemable output.
    pub fn out(&self) -> &'a TxOut {
        self.out
    }

    /// Returns the index of the key pair to use, can be `0/0` for main address.
    pub fn sub_index(&self) -> Index {
        self.sub_index
    }

    /// Returns the associated transaction public key.
    pub fn tx_pubkey(&self) -> PublicKey {
        self.tx_pubkey
    }

    /// Returns the unblinded or clear amount of this output.
    ///
    /// None if we didn't have enough information to unblind the output.
    pub fn amount(&self) -> Option<Amount> {
        match self.opening {
            Some(Opening { amount, .. }) => Some(amount),
            None => match self.out.amount {
                VarInt(0) => None,
                VarInt(a) => Some(Amount::from_pico(a)),
            },
        }
    }

    /// Returns the original blinding factor of this output.
    ///
    /// None if we didn't have enough information to unblind the output.
    pub fn blinding_factor(&self) -> Option<Scalar> {
        self.opening.as_ref().map(|o| o.blinding_factor)
    }

    /// Returns the original commitment of this output.
    ///
    /// None if we didn't have enough information to unblind the output.
    pub fn commitment(&self) -> Option<EdwardsPoint> {
        self.opening.as_ref().map(|o| o.commitment)
    }

    /// Retreive the public keys, if any.
    pub fn pubkeys(&self) -> Option<Vec<PublicKey>> {
        self.out.get_pubkeys()
    }

    /// Recover the ephemeral private key for spending the output, this requires access to the
    /// private spend key.
    pub fn recover_key(&self, keys: &KeyPair) -> Result<PrivateKey, TransactionError> {
        let recoverer = KeyRecoverer::new(keys, self.tx_pubkey);
        Ok(recoverer.recover(self.index, self.sub_index)?)
    }
}

/// Every transaction contains an extra field, which is a part of transaction prefix and allow
/// storing extra data inside the transaction. The most common use case is for the transaction
/// public key.
///
/// Extra field is composed of typed sub fields of variable or fixed length.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct ExtraField(pub Vec<SubField>);

impl fmt::Display for ExtraField {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        for field in &self.0 {
            writeln!(fmt, "Subfield: {}", field)?;
        }
        Ok(())
    }
}

impl ExtraField {
    /// Return the transaction public key, if any, present in extra field.
    pub fn tx_pubkey(&self) -> Option<PublicKey> {
        self.0.iter().find_map(|x| match x {
            SubField::TxPublicKey(pubkey) => Some(*pubkey),
            _ => None,
        })
    }

    /// Return the additional public keys, if any, present in extra field.
    pub fn tx_additional_pubkeys(&self) -> Option<Vec<PublicKey>> {
        self.0.iter().find_map(|x| match x {
            SubField::AdditionalPublickKey(pubkeys) => Some(pubkeys.clone()),
            _ => None,
        })
    }

    /// Attempts to parse the extra field
    pub fn try_parse(raw_extra: &RawExtraField) -> Result<Self, TransactionError> {
        let mut fields: Vec<SubField> = vec![];
        let bytes = &raw_extra.0;
        let mut decoder = io::Cursor::new(&bytes[..]);

        // Decode each extra field
        while decoder.position() < bytes.len() as u64 {
            let res: Result<SubField, encode::EncodeError> =
                Decodable::consensus_decode(&mut decoder);
            match res {
                Ok(sub_field) => fields.push(sub_field),
                Err(err) => return Err(TransactionError::from(err)),
            }
        }

        Ok(ExtraField(fields))
    }
}

/// Each sub-field contains a sub-field tag followed by sub-field content of fixed or variable
/// length, in variable length case the length is encoded with a [`VarInt`] before the content
/// itself.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub enum SubField {
    /// Transaction public key, fixed length of 32 bytes.
    TxPublicKey(PublicKey),
    /// 255 bytes limited nonce, can contain an encrypted or unencrypted payment id, variable
    /// length.
    Nonce(Vec<u8>),
    /// Padding size is limited to 255 null bytes, variable length.
    Padding(u8),
    /// Merge mining infos: `depth` and `merkle_root`, fixed length of one VarInt and 32 bytes
    /// hash.
    MergeMining(Option<VarInt>, hash::Hash),
    /// Additional public keys for [`Subaddresses`](crate::cryptonote::subaddress) outputs,
    /// variable length of `n` additional public keys.
    AdditionalPublickKey(Vec<PublicKey>),
    /// Mysterious `MinerGate`, variable length.
    MysteriousMinerGate(Vec<u8>),
}

impl fmt::Display for SubField {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            SubField::TxPublicKey(public_key) => writeln!(fmt, "Tx public Key: {}", public_key),
            SubField::Nonce(nonce) => {
                let nonce_str = hex_encode(serialize(nonce).map_err(|_| fmt::Error)?);
                writeln!(fmt, "Nonce: {}", nonce_str)
            }
            SubField::Padding(padding) => writeln!(fmt, "Padding: {}", padding),
            SubField::MergeMining(code, hash) => {
                writeln!(fmt, "Merge mining: {:?}, {}", code, hash)
            }
            SubField::AdditionalPublickKey(keys) => {
                writeln!(fmt, "Additional publick keys: ")?;
                for key in keys {
                    writeln!(fmt, "key: {}", key)?;
                }
                Ok(())
            }
            SubField::MysteriousMinerGate(miner_gate) => {
                writeln!(fmt, "Mysterious miner gate: {:?}", miner_gate)
            }
        }
    }
}

/// Raw extra data.
///
/// Exact contents of this field are not covered by consensus
/// therefore an additional best-effort parse method is provided separately.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate", transparent))]
pub struct RawExtraField(pub Vec<u8>);

impl RawExtraField {
    /// Try parsing extra data as collection of sub fields.
    pub fn try_parse(&self) -> Result<ExtraField, TransactionError> {
        ExtraField::try_parse(self)
    }
}

impl TryFrom<ExtraField> for RawExtraField {
    type Error = TransactionError;

    fn try_from(extra: ExtraField) -> Result<Self, Self::Error> {
        Ok(encode::deserialize(&serialize(&extra)?)?)
    }
}

#[sealed::sealed]
impl encode::Encodable for RawExtraField {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for RawExtraField {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::EncodeError> {
        Decodable::consensus_decode(r).map(Self)
    }
}

/// The part of the transaction that contains all the data except signatures.
///
/// As transaction prefix implements [`hash::Hashable`] it is possible to generate the transaction
/// prefix hash with `tx_prefix.hash()`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct TransactionPrefix {
    /// Transaction format version.
    pub version: VarInt,
    /// The transaction can not be spend until after a certain number of blocks, or until a certain
    /// time.
    pub unlock_time: VarInt,
    /// Array of inputs.
    pub inputs: Vec<TxIn>,
    /// Array of outputs.
    pub outputs: Vec<TxOut>,
    /// Additional data associated with a transaction.
    pub extra: RawExtraField,
}

impl fmt::Display for TransactionPrefix {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(fmt, "Version: {}", self.version)?;
        writeln!(fmt, "Unlock time: {}", self.unlock_time)?;
        writeln!(fmt, "Extra field: {}", hex::encode(&self.extra.0))
    }
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
    /// Return the number of transaction's inputs.
    pub fn nb_inputs(&self) -> usize {
        self.inputs.len()
    }

    /// Return the number of transaction's outputs.
    pub fn nb_outputs(&self) -> usize {
        self.outputs.len()
    }

    /// Iterate over transaction outputs and find outputs related to view pair.
    pub fn check_outputs(
        &self,
        pair: &ViewPair,
        major: Range<u32>,
        minor: Range<u32>,
        rct_sig_base: Option<&RctSigBase>,
    ) -> Result<Vec<OwnedTxOut>, TransactionError> {
        let checker = SubKeyChecker::new(pair, major, minor)?;
        self.check_outputs_with(&checker, rct_sig_base)
    }

    /// Iterate over transaction outputs using the provided [`SubKeyChecker`] to find outputs
    /// related to the `SubKeyChecker`'s view pair.
    pub fn check_outputs_with(
        &self,
        checker: &SubKeyChecker,
        rct_sig_base: Option<&RctSigBase>,
    ) -> Result<Vec<OwnedTxOut>, TransactionError> {
        let extra_field = self.extra.try_parse()?;
        let tx_pubkeys = match extra_field.tx_additional_pubkeys() {
            Some(additional_keys) => additional_keys,
            None => {
                let tx_pubkey = extra_field
                    .tx_pubkey()
                    .ok_or(TransactionError::NoTxPublicKey)?;

                // if we don't have additional_pubkeys, we check every output against the single `tx_pubkey`
                vec![tx_pubkey; self.outputs.len()]
            }
        };

        let owned_txouts = self
            .outputs
            .iter()
            .enumerate()
            .zip(tx_pubkeys.iter())
            .filter_map(|((i, out), tx_pubkey)| {
                let key = out.target.as_one_time_key()?;
                let keygen = KeyGenerator::from_key(checker.keys, *tx_pubkey);
                if !out.target.check_view_tag(keygen.rv, i as u8) {
                    return None;
                }
                let sub_index = checker.check_with_key_generator(keygen, i, &key).ok()??;

                Some((i, out, sub_index, tx_pubkey))
            })
            .map(|(i, out, sub_index, tx_pubkey)| {
                let opening = match rct_sig_base {
                    Some(RctSigBase {
                        rct_type: RctType::Null,
                        ..
                    }) => None,
                    Some(rct_sig_base) => {
                        let ecdh_info = rct_sig_base
                            .ecdh_info
                            .get(i)
                            .ok_or(TransactionError::MissingEcdhInfo)?;
                        let actual_commitment = rct_sig_base
                            .out_pk
                            .get(i)
                            .ok_or(TransactionError::MissingCommitment)?;
                        let actual_commitment = CompressedEdwardsY(actual_commitment.mask.key)
                            .decompress()
                            .ok_or(TransactionError::InvalidCommitment)?;

                        let opening = ecdh_info
                            .open_commitment(checker.keys, tx_pubkey, i, &actual_commitment)?
                            .ok_or(TransactionError::InvalidCommitment)?;

                        Some(opening)
                    }
                    None => None,
                };

                Ok(OwnedTxOut {
                    index: i,
                    out,
                    sub_index: *sub_index,
                    tx_pubkey: *tx_pubkey,
                    opening,
                })
            })
            .collect::<Result<Vec<_>, TransactionError>>()?;

        Ok(owned_txouts)
    }
}

// To get transaction prefix hash
impl hash::Hashable for TransactionPrefix {
    fn hash(&self) -> Result<hash::Hash, HashError> {
        Ok(hash::Hash::new(serialize(self)?))
    }
}

/// A full transaction containing the prefix and all the signing data.
///
/// As transaction implements [`hash::Hashable`] it is possible to generate the transaction hash
/// with `tx.hash()`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct Transaction {
    /// The transaction prefix.
    pub prefix: TransactionPrefix,
    /// The signatures.
    pub signatures: Vec<Vec<Signature>>,
    /// The RingCT signatures.
    pub rct_signatures: RctSig,
}

impl fmt::Display for Transaction {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(fmt, "Prefix: {}", self.prefix)?;
        for sigs in &self.signatures {
            for sig in sigs {
                writeln!(fmt, "Signature: {}", sig)?;
            }
        }
        writeln!(fmt, "RCT signature: {}", self.rct_signatures)
    }
}

impl Transaction {
    /// Return the transaction prefix.
    pub fn prefix(&self) -> &TransactionPrefix {
        &self.prefix
    }

    /// Return the number of transaction's inputs.
    pub fn nb_inputs(&self) -> usize {
        self.prefix().inputs.len()
    }

    /// Return the number of transaction's outputs.
    pub fn nb_outputs(&self) -> usize {
        self.prefix().outputs.len()
    }

    /// Iterate over transaction outputs and find outputs related to view pair.
    pub fn check_outputs(
        &self,
        pair: &ViewPair,
        major: Range<u32>,
        minor: Range<u32>,
    ) -> Result<Vec<OwnedTxOut>, TransactionError> {
        self.prefix()
            .check_outputs(pair, major, minor, self.rct_signatures.sig.as_ref())
    }

    /// Iterate over transaction outputs using the provided [`SubKeyChecker`] to find outputs
    /// related to the `SubKeyChecker`'s view pair.
    pub fn check_outputs_with(
        &self,
        checker: &SubKeyChecker,
    ) -> Result<Vec<OwnedTxOut>, TransactionError> {
        self.prefix()
            .check_outputs_with(checker, self.rct_signatures.sig.as_ref())
    }

    #[cfg(feature = "experimental")]
    #[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
    /// Compute the message to be signed by the CLSAG signature algorithm.
    ///
    /// The message consists of three parts:
    ///
    /// 1. The hash of the transaction prefix.
    /// 2. The hash of a consensus-encoded [`RctSigBase`].
    /// 3. The hash of all bulletproofs.
    pub fn signature_hash(&self) -> Result<hash::Hash, SignatureHashError> {
        let rct_type = self
            .rct_signatures
            .sig
            .as_ref()
            .ok_or(SignatureHashError::MissingRctSigBase)?
            .rct_type;

        if rct_type != RctType::Clsag {
            return Err(SignatureHashError::UnsupportedRctType(rct_type));
        }

        use tiny_keccak::Hasher as _;

        let mut keccak = tiny_keccak::Keccak::v256();
        keccak.update(&self.transaction_prefix_hash()?);
        keccak.update(&self.rct_sig_base_hash()?);
        keccak.update(&self.bulletproof_hash()?);

        let mut hash = [0u8; 32];
        keccak.finalize(&mut hash);

        Ok(hash::Hash(hash))
    }

    #[cfg(feature = "experimental")]
    fn transaction_prefix_hash(&self) -> Result<[u8; 32], HashError> {
        use crate::cryptonote::hash::Hashable as _;

        Ok(self.prefix.hash()?.to_bytes())
    }

    #[cfg(feature = "experimental")]
    fn rct_sig_base_hash(&self) -> Result<[u8; 32], SignatureHashError> {
        use crate::cryptonote::hash::keccak_256;

        let rct_sig_base = self
            .rct_signatures
            .sig
            .as_ref()
            .ok_or(SignatureHashError::MissingRctSigBase)?;
        let bytes = serialize(rct_sig_base)?;

        Ok(keccak_256(&bytes))
    }

    #[cfg(feature = "experimental")]
    fn bulletproof_hash(&self) -> Result<[u8; 32], SignatureHashError> {
        use tiny_keccak::Hasher as _;

        let bulletproofs = self
            .rct_signatures
            .p
            .as_ref()
            .ok_or(SignatureHashError::NoBulletproofs)?
            .bulletproofs
            .as_slice();
        if bulletproofs.is_empty() {
            return Err(SignatureHashError::NoBulletproofs);
        }

        let mut keccak = tiny_keccak::Keccak::v256();

        for bp in bulletproofs {
            keccak.update(&bp.A.key);
            keccak.update(&bp.S.key);
            keccak.update(&bp.T1.key);
            keccak.update(&bp.T2.key);
            keccak.update(&bp.taux.key);
            keccak.update(&bp.mu.key);

            for i in &bp.L {
                keccak.update(&i.key);
            }

            for i in &bp.R {
                keccak.update(&i.key);
            }

            keccak.update(&bp.a.key);
            keccak.update(&bp.b.key);
            keccak.update(&bp.t.key);
        }

        let mut hash = [0u8; 32];
        keccak.finalize(&mut hash);

        Ok(hash)
    }
}

/// Possible errors when calculating the signature hash of a transaction.
#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
#[derive(Debug, Error)]
pub enum SignatureHashError {
    /// [`RctSigBase`] was not set in [`Transaction`]
    #[error("`RctSigBase` is required for computing the signature hash")]
    MissingRctSigBase,
    /// Either all of [`RctSigPrunable`] was not set within [`Transaction`] or the list of bulletproofs was empty.
    #[error("Bulletproofs are required for computing the signature hash")]
    NoBulletproofs,
    /// The transaction's [`RctType`] is not supported.
    #[error("Computing the signature hash for RctType {0} is not supported")]
    UnsupportedRctType(RctType),
    /// Encoding error.
    #[error("Encode error: {0}")]
    EncodeError(#[from] EncodeError),
    /// Encoding error.
    #[error("Hash error: {0}")]
    HashError(#[from] HashError),
}

impl hash::Hashable for Transaction {
    fn hash(&self) -> Result<hash::Hash, HashError> {
        match *self.prefix.version {
            1 => Ok(hash::Hash::new(serialize(self)?)),
            _ => {
                let mut hashes: Vec<hash::Hash> = vec![self.prefix.hash()?];
                if let Some(sig_base) = &self.rct_signatures.sig {
                    hashes.push(sig_base.hash()?);
                    if sig_base.rct_type == RctType::Null {
                        hashes.push(hash::Hash::null());
                    } else {
                        match &self.rct_signatures.p {
                            Some(p) => {
                                let mut encoder = io::Cursor::new(vec![]);
                                p.consensus_encode(&mut encoder, sig_base.rct_type).unwrap();
                                hashes.push(hash::Hash::new(encoder.into_inner()));
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
                Ok(hash::Hash::new(bytes))
            }
        }
    }
}

// ----------------------------------------------------------------------------------------------------------------

#[sealed]
impl encode::Encodable for ExtraField {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut buffer = Vec::new();
        for field in self.0.iter() {
            field.consensus_encode(&mut buffer)?;
        }
        buffer.consensus_encode(w)
    }
}

impl Decodable for SubField {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<SubField, encode::EncodeError> {
        let tag: u8 = Decodable::consensus_decode(r)?;

        match tag {
            0x0 => {
                // Consume all bytes until the end of cursor or until 255 bytes have been consumed. Only
                // zero-valued bytes are valid, thus if a non-zero value has been read, it is an error condition.
                let mut len = 0;
                for _ in 1..=u8::MAX {
                    let byte: Result<u8, encode::EncodeError> = Decodable::consensus_decode(r);
                    match byte {
                        Ok(val) => {
                            if val != 0 {
                                return Err(EncodeError::ParseFailed(format!(
                                    "Invalid padding byte '{}' read after '{}' bytes",
                                    val,
                                    len + 1
                                )));
                            }
                            len += 1;
                        }
                        Err(_) => break, // This represents the end of the buffer, not a parsing error
                    }
                }

                Ok(SubField::Padding(len))
            }
            0x1 => Ok(SubField::TxPublicKey(Decodable::consensus_decode(r)?)),
            0x2 => Ok(SubField::Nonce(Decodable::consensus_decode(r)?)),
            0x3 => {
                let size = VarInt::consensus_decode(r)?;
                let mut depth = None;
                if size.0 == 33 {
                    depth = Some(VarInt::consensus_decode(r)?);
                }
                Ok(SubField::MergeMining(
                    depth,
                    Decodable::consensus_decode(r)?,
                ))
            }
            0x4 => Ok(SubField::AdditionalPublickKey(Decodable::consensus_decode(
                r,
            )?)),
            0xde => Ok(SubField::MysteriousMinerGate(Decodable::consensus_decode(
                r,
            )?)),
            _ => Err(encode::EncodeError::ParseFailed(
                "Invalid sub-field type".to_string(),
            )),
        }
    }
}

#[sealed]
impl encode::Encodable for SubField {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        match *self {
            SubField::Padding(nbytes) => {
                len += 0x0u8.consensus_encode(w)?;
                for _ in 0..nbytes {
                    len += 0u8.consensus_encode(w)?;
                }
                Ok(len)
            }
            SubField::TxPublicKey(ref pubkey) => {
                len += 0x1u8.consensus_encode(w)?;
                Ok(len + pubkey.consensus_encode(w)?)
            }
            SubField::Nonce(ref nonce) => {
                len += 0x2u8.consensus_encode(w)?;
                Ok(len + nonce.consensus_encode(w)?)
            }
            SubField::MergeMining(ref depth, ref merkle_root) => {
                len += 0x3u8.consensus_encode(w)?;
                match depth {
                    Some(dep) => {
                        len += VarInt(33).consensus_encode(w)?;
                        len += dep.consensus_encode(w)?;
                    }
                    None => len += VarInt(32).consensus_encode(w)?,
                }
                Ok(len + merkle_root.consensus_encode(w)?)
            }
            SubField::AdditionalPublickKey(ref pubkeys) => {
                len += 0x4u8.consensus_encode(w)?;
                Ok(len + pubkeys.consensus_encode(w)?)
            }
            SubField::MysteriousMinerGate(ref data) => {
                len += 0xdeu8.consensus_encode(w)?;
                Ok(len + data.consensus_encode(w)?)
            }
        }
    }
}

impl Decodable for TxIn {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<TxIn, encode::EncodeError> {
        let intype: u8 = Decodable::consensus_decode(r)?;
        match intype {
            0xff => Ok(TxIn::Gen {
                height: Decodable::consensus_decode(r)?,
            }),
            0x0 | 0x1 => Err(EncodeError::ConsensusEncodingFailed(
                "Scripts input/output are not supported".to_string(),
            )),
            0x2 => Ok(TxIn::ToKey {
                amount: Decodable::consensus_decode(r)?,
                key_offsets: Decodable::consensus_decode(r)?,
                k_image: Decodable::consensus_decode(r)?,
            }),
            _ => Err(encode::EncodeError::ParseFailed(
                "Invalid input type".to_string(),
            )),
        }
    }
}

#[sealed]
impl encode::Encodable for TxIn {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        match self {
            TxIn::Gen { height } => {
                let len = 0xffu8.consensus_encode(w)?;
                Ok(len + height.consensus_encode(w)?)
            }
            TxIn::ToKey {
                amount,
                key_offsets,
                k_image,
            } => {
                let mut len = 0x2u8.consensus_encode(w)?;
                len += amount.consensus_encode(w)?;
                len += key_offsets.consensus_encode(w)?;
                Ok(len + k_image.consensus_encode(w)?)
            }
        }
    }
}

impl Decodable for TxOutTarget {
    fn consensus_decode<R: io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<TxOutTarget, encode::EncodeError> {
        let outtype: u8 = Decodable::consensus_decode(r)?;
        match outtype {
            0x2 => Ok(TxOutTarget::ToKey {
                key: Decodable::consensus_decode(r)?,
            }),
            0x3 => Ok(TxOutTarget::ToTaggedKey {
                key: Decodable::consensus_decode(r)?,
                view_tag: Decodable::consensus_decode(r)?,
            }),
            _ => Err(encode::EncodeError::ParseFailed(
                "Invalid output type".to_string(),
            )),
        }
    }
}

#[sealed]
impl encode::Encodable for TxOutTarget {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        match self {
            TxOutTarget::ToKey { key } => {
                let len = 0x2u8.consensus_encode(w)?;
                Ok(len + key.consensus_encode(w)?)
            }
            TxOutTarget::ToTaggedKey { key, view_tag } => {
                let mut len = 0x3u8.consensus_encode(w)?;
                len += key.consensus_encode(w)?;
                Ok(len + view_tag.consensus_encode(w)?)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Interrupted,
                TransactionError::ScriptNotSupported,
            )),
        }
    }
}

#[allow(non_snake_case)]
impl Decodable for Transaction {
    fn consensus_decode<R: io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Transaction, encode::EncodeError> {
        let prefix: TransactionPrefix = Decodable::consensus_decode(r)?;

        let inputs = prefix.inputs.len();
        let outputs = prefix.outputs.len();

        match *prefix.version {
            1 => {
                let signatures: Result<Vec<Vec<Signature>>, encode::EncodeError> = prefix
                    .inputs
                    .iter()
                    .filter_map(|input| match input {
                        TxIn::ToKey { key_offsets, .. } => {
                            let sigs: Result<Vec<Signature>, encode::EncodeError> = key_offsets
                                .iter()
                                .map(|_| Decodable::consensus_decode(r))
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

                if let Some(sig) = RctSigBase::consensus_decode(r, inputs, outputs)? {
                    let p = {
                        if sig.rct_type != RctType::Null {
                            let mixin_size = if inputs > 0 {
                                match &prefix.inputs[0] {
                                    TxIn::ToKey { key_offsets, .. } => key_offsets
                                        .len()
                                        .checked_sub(1)
                                        .ok_or(encode::EncodeError::ParseFailed(
                                            "Invalid input type".to_string(),
                                        ))?,
                                    _ => 0,
                                }
                            } else {
                                0
                            };
                            RctSigPrunable::consensus_decode(
                                r,
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

#[sealed]
impl encode::Encodable for Transaction {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = self.prefix.consensus_encode(w)?;
        match *self.prefix.version {
            1 => {
                for sig in self.signatures.iter() {
                    len += encode_sized_vec!(sig, w);
                }
            }
            _ => {
                if let Some(sig) = &self.rct_signatures.sig {
                    len += sig.consensus_encode(w)?;
                    if let Some(p) = &self.rct_signatures.p {
                        len += p.consensus_encode(w, sig.rct_type)?;
                    }
                }
            }
        }
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{ExtraField, RawExtraField, Transaction, TransactionPrefix};
    use crate::consensus::encode::{deserialize, deserialize_partial, serialize, VarInt};
    use crate::cryptonote::hash::Hashable;
    use crate::util::key::{PrivateKey, PublicKey, ViewPair};
    use crate::util::ringct::{RctSig, RctSigBase, RctType};
    use crate::util::test_utils::{
        fuzz_transaction_deserialize, fuzz_transaction_prefix_deserialize,
    };
    use crate::{
        blockdata::transaction::{SubField, TxIn, TxOutTarget},
        cryptonote::onetime_key::SubKeyChecker,
    };
    use crate::{Hash, TxOut};

    #[test]
    fn deserialize_transaction_prefix() {
        let hex = hex::decode("01f18d0601ffb58d0605efefead70202eb72f82bd8bdda51e0bdc25f04e99ffb90c6214e11b455abca7b116c7857738880e497d01202e87c65a22b78f4b7686ef3a30113674659a4fe769a7ded73d60e6f7c556a19858090dfc04a022ee52dca8845438995eb6d7af985ca07186cc34a7eb696937f78fc0fd9008e2280c0f9decfae0102cec392ffdcae05a370dc3c447465798d3688677f4a5937f1fef9661df99ac2fb80c0caf384a30202e2b6ce11475c2312d2de5c9f26fbd88b7fcac0dbbb7b31f49abe9bd631ed49e42b0104d46cf1a204ae727c14473d67ea95da3e97b250f3c63e0997198bfc812d7a81020800000000d8111b25").unwrap();
        let tx = deserialize::<TransactionPrefix>(&hex[..]);
        assert!(tx.is_ok());
        let tx = tx.unwrap();
        assert_eq!(hex, serialize(&tx).unwrap());
        assert_eq!(
            "3bc7ff015b227e7313cc2e8668bfbb3f3acbee274a9c201d6211cf681b5f6bb1",
            format!("{:02x}", tx.hash().unwrap())
        );

        let tx = deserialize::<Transaction>(&hex[..]).unwrap();
        assert_eq!(
            "3bc7ff015b227e7313cc2e8668bfbb3f3acbee274a9c201d6211cf681b5f6bb1",
            format!("{:02x}", tx.hash().unwrap())
        );
    }

    #[test]
    fn transaction_hash() {
        let hex = hex::decode("02000202000bc6aa98049bf603fcec06bd3ccbad04e807e328b5128f22a63bfb27b6e287e8d594664d5cddd6c89bc413d1bc607b242203a6eb3180041ff5ae679702000b90e4eb028298a101879110f5bc0383ad03cbfc03a750e52ace37d112c6064faf7d16e2d07c4cc979dccb858aa9b24e12479e4a2db8350a906ba7a1aec409020002ab6d783607d8e712bbd5aad54a412aec890fcdcc1b35bf0ca4a705c2159bfc32000262f4016d5d81ade9e555807a24d23d452f08b6400683da599abd7134fb75324a2c0209016631a2dee1d0f51f015fd9bf938cf132790bdc5c528037e347828c539e82da6e5921e3d1e6052cb25804d0b7ba81018a4cd5385ca23ff4f6d76dc41b5254abf579b1856d3fbd04e81ff97c113e318bf7e158fbb0db7adc6ece9c8d4ab94e91f68e9607667a858ddf3e6890b2835403db6dcc5a1c179a768bcf74d74ace86430176b0056de37f310884e8eed56ee86840f23f842f1db52945b2feef98f4b56b3d4407734e4e8d3b117b5fd78f0d94f6059b495f53cf855b3716bbe8614d51727556c8b2e5c303cffc694257a1e91372de2047c4e12381c1de8df46102cdd84a24692f68ada05d1ffc5122b655582c6307141e130a6963198085ddb67d304b0ddde87e62402a3cadcd07a315604607ddf1530bd85685e910aa879733549bde0d019edc36326d33edd6ccecc800395b7075e4959779bde803dd787c24bc25d40205071b180152dded8b0be1f48a6d6f8e97c3f934f866b1b697f73f73fc9f38c5d2082c610732c79b2f69f403f7e2d312399739dd8d4225a2914a3020bd88c362271df633e8387b5345b50f11c4f148f76c0c24ca5843580a02fe72d18f47dcf8d601e28bbef2cd6659e620179adad4dfa5a0c7b712d716c4e630fe40bbfc6184f76c401db4b801a7001f65a9c11053db919099f9a1a4fe575c6d783e041ee08222a46adb8a1f13b863d95da277b71ccdefbb32f713a13b5ac8d041bbbeed9df4ace5a6b730b871ad2fe14141dbb9c816a21fd7fc48cfba4d2cc3e5e5fba29f581c1507a6a36285a30344790b74d2212dd26178395cd96a18518ead5c59a410baf6ca0b9217865fff207d757bb465fdb053e8c80b2ec1a966ccc01f49096fb991b65cc160a5070532c47318720fb9a90f187ce53661b6ce1e29d6ccd2b131324101170bb87ef273f0e73d762e159264f0839c6b3b31f5264499bdeb029c66a7035108a84256aec2760e74c2e8e788b7747084da8953aa48696b7a46e6320a9534d6c06ddee1b26671f03ae70a30c76b8fbf268da16fbb685f1d3f602668afce2e3eaf089b8758069f398eaeccd01876cef623201dc46dd75f76dc2141a9a2071b2761eefbf735ca599ed15266acbd0f54f49de38b5c7b3b378c386767383396645778021b30910e6e06937d65dac82312968d4f63a0bb28c96b9a09ee1d95c4d3afbb021998a9e290647b51083a80d66e0a8900a89c1236214f2d7c0080e2c18cdc8c0b4bd66765c3c52a26b90ec549bc8358ff8aaac9ffaecb0f6c915113cc97147b06c007a1a6bcd536bddec7fba330877d80cb878c7c9f3da81f8eb3bfb07ac7a804d4d58faadfabc3421350b14af6500b931209b75813759509e8642574982d680632106041b2687bdaef1c2be67c63a0ccc427bf02dc1ba58b153f00f8fabc8c00d99934e3e835291b8fc5a0bd62a3059c22cbd6fc4ae403df254e17cb15f32b0b65a4ed1f0f5fff37e49417c5fee339c21bd4f1cdcb1c803df8cb4baa11fa210089b61e28fe42e112824ee705f13167bfd3e6c8d660f2307216f5eea91a6db505b70f38e4b1b72a8f1fa1dd90bf0a47ed9a71e2e11e4f20240c1dac370f2b18075c6537bb475897fdd90fae360afb0b6b02210c123a3ca8fae31e320639b5e00c91c821abe873c1aaee2c4ebb87b5ecc670bff65de191e1d8463ecf1367685c0f0d39efc20269e516f29b775060a0c7a1595e158e94f64407d8e22b16ff25ed00cd50c46fb95ab5a3ca60a04e222c83d26b11c08a678348c8cdad407a0d841c0a50e91e896cb4ff873e9fc81c35f4a146f25a64b294c07c6adf4e418a3f590f061a89267deea53d985b4576b70b95170970321e07c1397b6f7e1ed3d4629e8e0a81019a7c15ae6d252e856c761664862d7fd0620fbbc7020fcd675fc97dc7310420b0d428093b4a80012f7a46612161ee2eeec8996128876d093f71f954244004aded4185afeec305d104d3905e54ddfda59ce1f5d56cf078ff10a76b138db90789184149cab60dfb1491943a793e85c332b4b36f448b63e5f099e7beb11d07005a31ed1658251e9f880466e44c54357781c9cdaf17d48534b062de482ad94005cbdcf52d6fea2e70c20ecc62a339afbb971e455e38292b78b21393bce982ec06d3e6f3e27897877007283f5a9d44ae134efc0ff14a5ce2fbe711403b535413073c9769ddc0474d64643bd2d60f58e001717f0538e1cc1e6b211c5f06f6ddfa029ec10d7e949673c08cd71713728ff042948c5b75ea2b610f4b4db838696fa40e24d750aa75f910948af39de2eba2ff6864daf92004453e4fa5cdae2f553a460f9bc86073dd7d6d2ea0f31092d28110892d6077dcee3b6293e66867a7ae67c5048df756d253c768debf3989d7643ff8892b7f6f74bf2b36d01bd0b88760c9b30eb54d02aa5498e7b87e2d027ac2a449318deda9cabf356fcd07f4561e6370db09fbd0d081093d93a569f6968b291fb01995415293b7cd997d9367c352c75b230ee70de92efd35302572e9de2809cd8e25eb9f824cb559107a1b87dd8c365de106cc800350e1284d67555b8db9041dfd44b3d5bec42e2b186b6a72b5bc3df0470476c234277592f742c3bf3babd4759b115196117883434af1d014ba8aeca028054fb4e8d9dde6a0e4cca9388a9f4c6283cbf9ae89dd17e4dc2a2f511604b33f0ee6e42e4f9a20b556ebc66e18b6142bfdcd4bf3792d9659ca5f5ef041f5ba28053e752155263ea79bd65dd94157f9464625e6a2e1b1e6d8ff40b4af4cb3804606239b8370d69d14f5c9eb463f49b0e796efdf01ddc087cc710bae43968856000fdc3a6408861363a190edbf2ae3e13d2bc52f87d9f2e31c044698b79f37b75a03199c7585b880df73a362ff40a94ed1d6173998d247a8f74e28407ad933e8bb0cd91ee82b723b3f22152a53b3226e52b32b93b397b5b2c386d3468651e602360eba66e52a1844aac9bbbe1a7183e97fed0c8b4b649f1551bcb98248dd62ebec087d4020a042085d487c64ae3fcf25e11b443ff03eeb8345b6d45d5304fbba83030bce1bbe499a7f5aefff31fef134b3c2c85b2fd16e6a26133cdbf05069299f007e627036d5ce0536e10546ec3b0719c373e00792f45fa78ff62d543e204d9a0f54a2b1c934a1463620a5c789ed600792ace37bc0f79c84399018acd073e86309f16a4ee382baad3e98425be3dcea1fceb47e56d237a49a125a360f7eb56b0305632f3877c17e62204e5a2c2017a934be9e532c5d7fd14ed71c4a2d3947621d03373796d7ffd6c77a73a06e3cbb61e1d872fb012c9ea0327fb65c4ffa46f02507d4db98bd434a7e921130e8846e697da226cc85568aa83f95cdfc4ccbfbff8ab0653000211ee7438364596b53793f2dfc4705f6a491190b35960f9aec1ffaad8a").unwrap();
        let tx = deserialize_partial::<TransactionPrefix>(&hex[..]);
        assert!(tx.is_ok());
        let tx = tx.unwrap().0;
        assert_eq!(
            "3b50349180b4a60e55187507746eabb7bee0de6b74168eac8720a449da28613b",
            format!("{:02x}", tx.hash().unwrap())
        );

        let tx = deserialize::<Transaction>(&hex[..]);
        assert!(tx.is_ok());
        let tx = tx.unwrap();
        assert_eq!(hex, serialize(&tx).unwrap());
        assert_eq!(
            "5a420317e377d3d95b652fb93e65cfe97ef7d89e04be329a2ca94e73ec57b74e",
            format!("{:02x}", tx.hash().unwrap())
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
        assert!(tx.is_ok());
        let tx = tx.unwrap();
        assert_eq!(
            "3bc7ff015b227e7313cc2e8668bfbb3f3acbee274a9c201d6211cf681b5f6bb1",
            format!("{:02x}", tx.hash().unwrap())
        );
        assert!(tx.check_outputs(&viewpair, 0..1, 0..200, None).is_ok());
        assert_eq!(hex, serialize(&tx).unwrap());

        let tx = deserialize::<Transaction>(&hex[..]);
        assert!(tx.is_ok());
        let tx = tx.unwrap();
        assert_eq!(
            "3bc7ff015b227e7313cc2e8668bfbb3f3acbee274a9c201d6211cf681b5f6bb1",
            format!("{:02x}", tx.hash().unwrap())
        );
    }

    #[test]
    fn find_outputs_with_checker() {
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
        let tx = deserialize::<Transaction>(&hex[..]);
        assert!(tx.is_ok());
        let tx = tx.unwrap();
        assert_eq!(
            "3bc7ff015b227e7313cc2e8668bfbb3f3acbee274a9c201d6211cf681b5f6bb1",
            format!("{:02x}", tx.hash().unwrap())
        );

        let checker = SubKeyChecker::new(&viewpair, 0..1, 0..200).unwrap();

        assert!(tx.check_outputs_with(&checker).is_ok());
        assert_eq!(hex, serialize(&tx).unwrap());
    }

    #[test]
    fn test_tx_hash() {
        let tx = "f8ad7c58e6fce1792dd78d764ce88a11db0e3c3bb484d868ae05a7321fb6c6b0";

        let pk_extra = vec![
            179, 155, 220, 223, 213, 23, 81, 160, 95, 232, 87, 102, 151, 63, 70, 249, 139, 40, 110,
            16, 51, 193, 175, 208, 38, 120, 65, 191, 155, 139, 1, 4,
        ];
        let transaction = Transaction {
            prefix: TransactionPrefix {
                version: VarInt(2),
                unlock_time: VarInt(2143845),
                inputs: vec![TxIn::Gen {
                    height: VarInt(2143785),
                }],
                outputs: vec![TxOut {
                    amount: VarInt(1550800739964),
                    target: TxOutTarget::ToKey {
                        key: PublicKey::from_slice(
                            hex::decode(
                                "e2e19d8badb15e77c8e1f441cf6acd9bcde34a07cae82bbe5ff9629bf88e6e81",
                            )
                            .unwrap()
                            .as_slice(),
                        )
                        .unwrap()
                        .to_bytes(),
                    },
                }],
                extra: ExtraField(vec![
                    SubField::TxPublicKey(PublicKey::from_slice(pk_extra.as_slice()).unwrap()),
                    SubField::Nonce(vec![
                        196, 37, 4, 0, 27, 37, 187, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ]),
                ])
                .try_into()
                .unwrap(),
            },
            signatures: vec![],
            rct_signatures: RctSig {
                sig: Option::from(RctSigBase {
                    rct_type: RctType::Null,
                    txn_fee: Default::default(),
                    pseudo_outs: vec![],
                    ecdh_info: vec![],
                    out_pk: vec![],
                }),
                p: None,
            },
        };
        assert_eq!(
            tx.as_bytes().to_vec(),
            hex::encode(transaction.hash().unwrap().0)
                .as_bytes()
                .to_vec()
        );
    }

    #[test]
    #[should_panic]
    fn test_tx_hash_fail() {
        let tx = "f8ad7c58e6fce1792dd78d764ce88a11db0e3c3bb484d868ae05a7321fb6c6b0";

        let pk_extra = vec![
            179, 155, 220, 223, 213, 23, 81, 160, 95, 232, 87, 102, 151, 63, 70, 249, 139, 40, 110,
            16, 51, 193, 175, 208, 38, 120, 65, 191, 155, 139, 1, 4,
        ];
        let transaction = Transaction {
            prefix: TransactionPrefix {
                version: VarInt(2),
                unlock_time: VarInt(2143845),
                inputs: vec![TxIn::Gen {
                    height: VarInt(2143785),
                }],
                outputs: vec![TxOut {
                    amount: VarInt(1550800739964),
                    target: TxOutTarget::ToKey {
                        key: PublicKey::from_slice(
                            hex::decode(
                                "e2e19d8badb15e77c8e1f441cf6acd9bcde34a07cae82bbe5ff9629bf88e6e81",
                            )
                            .unwrap()
                            .as_slice(),
                        )
                        .unwrap()
                        .to_bytes(),
                    },
                }],
                extra: ExtraField(vec![
                    SubField::TxPublicKey(PublicKey::from_slice(pk_extra.as_slice()).unwrap()),
                    SubField::Nonce(vec![
                        196, 37, 4, 0, 27, 37, 187, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ]),
                ])
                .try_into()
                .unwrap(),
            },
            signatures: vec![],
            rct_signatures: RctSig { sig: None, p: None },
        };
        assert_eq!(
            tx.as_bytes().to_vec(),
            hex::encode(transaction.hash().unwrap().0)
                .as_bytes()
                .to_vec()
        );
    }

    #[test]
    fn merge_mining() {
        // tx with MergeMining in extra field
        // hash: 36817336e72ecf7adcff92815de96a0893c1ef777701f1386ebce5f7d9272151
        let blob: &[u8] = &[
            87, 1, 148, 79, 157, 245, 14, 118, 157, 164, 156, 100, 224, 252, 180, 225, 215, 127,
            137, 5, 5, 101, 72, 235, 154, 127, 4, 145, 76, 45, 116, 177, 187, 175, 2, 17, 62, 19,
            29, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 33, 1, 98, 184, 83, 234, 127, 87, 79,
            180, 203, 221, 41, 173, 81, 137, 75, 171, 186, 235, 214, 142, 161, 82, 37, 80, 124, 82,
            217, 229, 81, 235, 25, 149,
        ];
        let parsed_extra_field = vec![
            SubField::TxPublicKey(
                PublicKey::from_slice(
                    hex::decode("944f9df50e769da49c64e0fcb4e1d77f8905056548eb9a7f04914c2d74b1bbaf")
                        .unwrap()
                        .as_slice(),
                )
                .unwrap(),
            ),
            SubField::Nonce(vec![62, 19, 29, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            SubField::MergeMining(
                Some(VarInt(1)),
                Hash::from_slice(
                    hex::decode("62b853ea7f574fb4cbdd29ad51894babbaebd68ea15225507c52d9e551eb1995")
                        .unwrap()
                        .as_slice(),
                ),
            ),
        ];

        let raw_extra_field = deserialize::<RawExtraField>(blob);
        assert!(raw_extra_field.is_ok());
        let extra_field = raw_extra_field.unwrap().try_parse().unwrap();
        assert_eq!(parsed_extra_field, extra_field.0);
        assert_eq!(blob, serialize(&extra_field).unwrap());
    }

    #[test]
    fn mysterious_miner_gate() {
        // tx with MysteriousMinerGate in extra field
        // hash: 550e9d2e1cc8d1940d0215e1fec33b4970b2f19520fe0c5bda26e9d4a4dc029d
        let blob: &[u8] = &[
            67, 1, 236, 193, 11, 242, 79, 176, 138, 91, 10, 64, 84, 148, 97, 72, 251, 45, 228, 99,
            152, 194, 246, 227, 241, 202, 198, 217, 26, 176, 237, 16, 20, 137, 222, 32, 207, 178,
            51, 151, 236, 243, 250, 53, 101, 231, 200, 74, 181, 168, 88, 192, 92, 120, 213, 36,
            147, 125, 53, 253, 90, 5, 164, 31, 186, 125, 50, 16,
        ];
        let parsed_extra_field = vec![
            SubField::TxPublicKey(
                PublicKey::from_slice(
                    hex::decode("ecc10bf24fb08a5b0a4054946148fb2de46398c2f6e3f1cac6d91ab0ed101489")
                        .unwrap()
                        .as_slice(),
                )
                .unwrap(),
            ),
            SubField::MysteriousMinerGate(vec![
                207, 178, 51, 151, 236, 243, 250, 53, 101, 231, 200, 74, 181, 168, 88, 192, 92,
                120, 213, 36, 147, 125, 53, 253, 90, 5, 164, 31, 186, 125, 50, 16,
            ]),
        ];
        let raw_extra_field = deserialize::<RawExtraField>(blob);
        assert!(raw_extra_field.is_ok());
        let extra_field = raw_extra_field.unwrap().try_parse().unwrap();
        assert_eq!(parsed_extra_field, extra_field.0);
        assert_eq!(blob, serialize(&extra_field).unwrap());
    }

    #[test]
    fn additional_public_keys() {
        // tx with AdditionalPublickKeys in extra field
        // hash: 23fbc9f5b8ac1b6f896756c4a1382658daf1e8d371c1e01c5baf66c1fbaf39bd
        let blob: &[u8] = &[
            163, 1, 1, 198, 185, 25, 5, 10, 65, 48, 68, 117, 110, 50, 143, 10, 181, 20, 111, 64,
            166, 2, 88, 181, 103, 30, 157, 108, 201, 114, 53, 124, 157, 250, 11, 4, 4, 242, 224,
            19, 160, 246, 150, 183, 175, 255, 128, 175, 129, 246, 83, 247, 75, 39, 6, 81, 48, 10,
            180, 15, 93, 21, 202, 5, 83, 205, 66, 79, 23, 114, 169, 134, 129, 169, 33, 57, 255,
            108, 140, 75, 243, 61, 145, 131, 76, 15, 167, 117, 87, 106, 97, 236, 120, 45, 193, 237,
            167, 21, 103, 154, 203, 113, 100, 26, 233, 137, 111, 149, 154, 72, 178, 134, 115, 143,
            127, 54, 160, 10, 201, 30, 215, 236, 172, 18, 232, 129, 72, 139, 72, 177, 139, 236,
            103, 244, 57, 193, 253, 117, 191, 34, 162, 247, 158, 8, 16, 150, 42, 219, 14, 207, 156,
            16, 231, 116, 147, 79, 76, 213, 186, 255, 53, 79, 171, 246, 22,
        ];

        let parsed_extra_field = vec![
            SubField::TxPublicKey(
                PublicKey::from_slice(
                    hex::decode("c6b919050a413044756e328f0ab5146f40a60258b5671e9d6cc972357c9dfa0b")
                        .unwrap()
                        .as_slice(),
                )
                .unwrap(),
            ),
            SubField::AdditionalPublickKey(vec![
                PublicKey::from_slice(
                    hex::decode("f2e013a0f696b7afff80af81f653f74b270651300ab40f5d15ca0553cd424f17")
                        .unwrap()
                        .as_slice(),
                )
                .unwrap(),
                PublicKey::from_slice(
                    hex::decode("72a98681a92139ff6c8c4bf33d91834c0fa775576a61ec782dc1eda715679acb")
                        .unwrap()
                        .as_slice(),
                )
                .unwrap(),
                PublicKey::from_slice(
                    hex::decode("71641ae9896f959a48b286738f7f36a00ac91ed7ecac12e881488b48b18bec67")
                        .unwrap()
                        .as_slice(),
                )
                .unwrap(),
                PublicKey::from_slice(
                    hex::decode("f439c1fd75bf22a2f79e0810962adb0ecf9c10e774934f4cd5baff354fabf616")
                        .unwrap()
                        .as_slice(),
                )
                .unwrap(),
            ]),
        ];

        let raw_extra_field = deserialize::<RawExtraField>(blob);
        assert!(raw_extra_field.is_ok());
        let extra_field = raw_extra_field.unwrap().try_parse().unwrap();
        assert_eq!(parsed_extra_field, extra_field.0);
        assert_eq!(blob, serialize(&extra_field).unwrap());
    }

    #[test]
    fn bad_extra() {
        // tx with a bad extra field
        // coinbase tx of block 2742099
        let blob: &[u8] = &hex_literal::hex!("3e01e3a5d36abb941d7472195f1cf94a7a8913655f07738fa542315caa004f1ec3d0027571776b78754b728e9275804d2b0000000001000000080000000100");

        let raw_extra_field = deserialize::<RawExtraField>(blob);
        assert!(raw_extra_field.is_ok());
        let extra_field = raw_extra_field.unwrap().try_parse();
        assert!(extra_field.is_err());
    }

    #[test]
    fn previous_fuzz_transaction_deserialize_failures() {
        let data = [];
        fuzz_transaction_deserialize(&data);
        let data = [
            80, 80, 1, 255, 255, 15, 0, 0, 3, 61, 3, 181, 181, 181, 181, 181, 181, 181, 181, 80,
            254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        ];
        fuzz_transaction_deserialize(&data);
        let data = [
            80, 80, 1, 255, 255, 255, 15, 0, 0, 3, 61, 3, 181, 181, 181, 181, 181, 255, 2, 0, 0,
            39, 74, 2, 0, 33, 247, 255, 255, 255, 255, 0, 13, 0, 0, 6, 1, 0, 39, 74, 2, 255, 255,
            255, 255, 255, 255, 15, 255, 255, 255,
        ];
        fuzz_transaction_deserialize(&data);
        let data = [
            80, 80, 1, 255, 255, 255, 15, 0, 0, 3, 61, 3, 181, 181, 181, 181, 181, 181, 255, 2, 13,
            1, 0, 2, 255, 255, 141, 255, 6, 0, 0, 1, 255, 25, 25, 25, 25, 25, 25, 25, 25, 25, 93,
            25, 25, 25, 25, 26, 25, 25, 25, 25, 25, 4, 4, 4, 4, 4, 4, 4, 4, 4, 255, 59, 176, 46, 1,
            0, 0, 0, 4, 4, 4, 4, 4, 4, 176, 25, 25, 191, 25, 25, 25, 176, 0, 0, 6, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 59, 0, 0, 0, 0, 0, 0, 181, 255, 2, 0, 181, 181, 2, 0, 0, 0, 39, 74, 2,
            255, 39, 0, 0, 0, 0,
        ];
        fuzz_transaction_deserialize(&data);
    }

    #[test]
    fn previous_fuzz_transaction_prefix_deserialize_failures() {
        let data = [
            65, 26, 1, 2, 0, 2, 0, 0, 0, 0, 0, 0, 45, 255, 0, 0, 0, 2, 6, 0, 0, 0, 253, 0, 0, 0,
            255, 0, 0, 0, 249, 2, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 3, 6, 0, 0, 0, 253, 255, 255, 0,
            0, 0, 0, 0, 0, 255, 0, 0, 0, 2, 6, 0, 0, 0, 253, 0, 0, 0, 255, 0, 0, 0, 249, 2, 0, 0,
            0, 0, 0, 0, 255, 0, 0, 0, 2, 6, 0, 0, 0, 253, 255, 255, 171, 38, 255, 255, 255, 80, 80,
            65, 255, 255, 255, 6, 0, 0, 0, 253, 0, 0, 0, 255, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 255, 0,
            0, 0, 2, 6, 0, 0, 0, 253, 255, 36, 79, 79, 44, 79, 171,
        ];
        fuzz_transaction_prefix_deserialize(&data);
        let data = [
            5, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 248, 1, 0,
            0, 0, 2, 2, 2, 1, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 37, 2, 2, 2, 2, 2, 2, 5, 2, 2, 2, 2,
            2, 2, 62, 62, 62, 62, 62, 65, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 255, 255, 255, 255, 255,
            251, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            3, 2, 1, 248, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 37, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3,
            3, 255, 255, 255, 93, 255, 255, 255, 255, 255, 255, 255, 255, 255, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            3, 2, 1, 248, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 37, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            168, 71, 251, 251, 8, 0, 1, 0, 0,
        ];
        fuzz_transaction_prefix_deserialize(&data);
        let data = [
            5, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 248, 1, 0,
            0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 37, 2, 2, 2, 2, 2, 2, 5, 2, 2, 2, 2, 2, 2, 62,
            62, 62, 62, 62, 62, 62, 2, 2, 2, 3, 0, 5, 255, 255, 255, 251, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 168, 71, 251, 251, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 37, 2, 2, 239, 2, 2, 2, 2, 5, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            255, 255, 255, 255, 255, 251, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 131, 3, 3, 3, 3, 247, 252, 252, 252, 3, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 248, 2, 2, 191, 191, 191, 191, 191, 191, 191,
            191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191,
            191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191,
            191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191,
            191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191,
            191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191,
            191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191,
            191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191,
            191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
        ];
        fuzz_transaction_prefix_deserialize(&data);
        let data = [
            5, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 248, 1, 0,
            0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 37, 2, 2, 2, 2, 2, 2, 5, 2, 2, 2, 33, 2, 2, 62,
            62, 62, 62, 62, 62, 62, 2, 2, 2, 3, 0, 5, 255, 255, 255, 251, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 168, 71, 251, 251, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 37, 2, 2, 239, 2, 2, 2, 2, 5, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            255, 255, 255, 255, 255, 251, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 3, 2, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 37, 2, 3, 3, 255, 199, 199, 199,
            199, 199, 199, 199, 199, 199, 199, 199, 199, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 6, 0,
            171, 181, 181, 181, 181, 181, 181, 255, 5, 181, 181, 181, 181, 181, 181, 181, 181, 0,
            0, 0, 0, 0, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149,
            149, 33, 0, 0, 0, 0, 0, 0, 227, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 149, 0, 0, 0, 0, 0,
            0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 34, 0, 0, 0, 0, 181, 181, 0, 0, 0, 0, 0, 0,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 168, 71, 251, 251, 8, 0, 1, 0, 0,
        ];
        fuzz_transaction_prefix_deserialize(&data);
    }
}

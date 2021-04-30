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

//! Transaction, transaction's prefix, inputs and outputs structures used to parse and create
//! transactions.
//!
//! This module support (de)serializing Monero transaction and input/amount discovery/recovery with
//! private view key and public spend key (view key-pair: [`ViewPair`]).
//!

use crate::consensus::encode::{self, serialize, Decodable, Encodable, VarInt};
use crate::cryptonote::hash;
use crate::cryptonote::onetime_key::{KeyGenerator, KeyRecoverer, SubKeyChecker};
use crate::cryptonote::subaddress::Index;
use crate::util::amount::RecoveryError;
use crate::util::key::{KeyPair, PrivateKey, PublicKey, ViewPair, H};
use crate::util::ringct::{EcdhInfo, RctSig, RctSigBase, RctSigPrunable, RctType, Signature};

use curve25519_dalek::scalar::Scalar;
use hex::encode as hex_encode;
use thiserror::Error;

use std::convert::TryInto;
use std::ops::Range;
use std::{fmt, io};

#[cfg(feature = "serde_support")]
use serde::{Deserialize, Serialize};

/// Errors possible when manipulating transactions.
#[derive(Error, Clone, Copy, Debug, PartialEq)]
pub enum Error {
    /// No transaction public key found in extra.
    #[error("No transaction public key found")]
    NoTxPublicKey,
    /// Scripts input/output are not supported.
    #[error("Script not supported")]
    ScriptNotSupported,
}

/// The key image used in transaction inputs [`TxIn`] to commit to the use of an output one-time
/// public key as in [`TxOutTarget::ToKey`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct KeyImage {
    /// The actual key image data.
    pub image: hash::Hash,
}

impl_consensus_encoding!(KeyImage, image);

/// A transaction input, either a coinbase spend or a one-time key spend which defines the ring
/// size and the key image to avoid double spend.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
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
    /// Input from script output, not used.
    ToScript,
    /// Input from script hash output, not used.
    ToScriptHash,
}

/// Type of output formats, only [`TxOutTarget::ToKey`] is used, other formats are legacy to the
/// original cryptonote implementation.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
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
        key: PublicKey,
    },
    /// A script hash output, not used.
    ToScriptHash {
        /// The script hash
        hash: hash::Hash,
    },
}

impl TxOutTarget {
    /// Retreive the public keys, if any.
    pub fn get_pubkeys(&self) -> Option<Vec<PublicKey>> {
        match self {
            TxOutTarget::ToScript { keys, .. } => Some(keys.clone()),
            TxOutTarget::ToKey { key } => Some(vec![*key]),
            TxOutTarget::ToScriptHash { .. } => None,
        }
    }
}

/// A transaction output, can be consumed by a [`TxIn`] input of the matching format.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
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
/// let owned_outputs = tx.prefix.check_outputs(&view_pair, 0..2, 0..3).unwrap();
///
/// for out in owned_outputs {
///     // Recover the ephemeral private spend key
///     let private_key = out.recover_key(&keypair);
/// }
/// ```
///
#[derive(Debug)]
pub struct OwnedTxOut<'a> {
    /// Index of the output in the transaction.
    pub index: usize,
    /// A reference to the actual redeemable output.
    pub out: &'a TxOut,
    /// Index of the key pair to use, can be `0/0` for main address.
    pub sub_index: Index,
    /// The associated transaction public key.
    pub tx_pubkey: PublicKey,
}

impl<'a> OwnedTxOut<'a> {
    /// Retreive the public keys, if any.
    pub fn get_pubkeys(&self) -> Option<Vec<PublicKey>> {
        self.out.get_pubkeys()
    }

    /// Recover the ephemeral private key for spending the output, this requires access to the
    /// private spend key.
    pub fn recover_key(&self, keys: &KeyPair) -> PrivateKey {
        let recoverer = KeyRecoverer::new(keys, self.tx_pubkey);
        recoverer.recover(self.index, self.sub_index)
    }
}

/// Every transaction contains an extra field, which is a part of transaction prefix and allow
/// storing extra data inside the transaction. The most common use case is for the transaction
/// public key.
///
/// Extra field is composed of typed sub fields of variable or fixed length.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
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
}

/// Each sub-field contains a sub-field tag followed by sub-field content of fixed or variable
/// length, in variable length case the length is encoded with a [`VarInt`] before the content
/// itself.
#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
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
    MergeMining(VarInt, hash::Hash),
    /// Additional public keys for [`Subaddresses`](crate::cryptonote::subaddress) outputs,
    /// variable length of `n` additional public keys.
    AdditionalPublickKey(Vec<PublicKey>),
    /// Mysterious `MinerGate`, variable length.
    MysteriousMinerGate(String),
}

impl fmt::Display for SubField {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            SubField::TxPublicKey(public_key) => writeln!(fmt, "Tx public Key: {}", public_key),
            SubField::Nonce(nonce) => {
                let nonce_str = hex_encode(serialize(nonce));
                writeln!(fmt, "Nonce: {}", nonce_str)
            }
            SubField::Padding(padding) => writeln!(fmt, "Padding: {}", padding),
            SubField::MergeMining(code, hash) => writeln!(fmt, "Merge mining: {}, {}", code, hash),
            SubField::AdditionalPublickKey(keys) => {
                writeln!(fmt, "Additional publick keys: ")?;
                for key in keys {
                    writeln!(fmt, "key: {}", key)?;
                }
                Ok(())
            }
            SubField::MysteriousMinerGate(miner_gate) => {
                writeln!(fmt, "Mysterious miner gate: {}", miner_gate)
            }
        }
    }
}

/// The part of the transaction that contains all the data except signatures.
///
/// As transaction prefix implements [`hash::Hashable`] it is possible to generate the transaction
/// prefix hash with `tx_prefix.hash()`.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
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
    pub extra: ExtraField,
}

impl fmt::Display for TransactionPrefix {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(fmt, "Version: {}", self.version)?;
        writeln!(fmt, "Unlock time: {}", self.unlock_time)?;
        writeln!(fmt, "Extra field: {}", self.extra)
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

    /// Return the transaction public key present in extra field.
    pub fn tx_pubkey(&self) -> Option<PublicKey> {
        self.extra.tx_pubkey()
    }

    /// Return the additional public keys present in extra field.
    pub fn tx_additional_pubkeys(&self) -> Option<Vec<PublicKey>> {
        self.extra.tx_additional_pubkeys()
    }

    /// Iterate over transaction outputs and find outputs related to view pair.
    pub fn check_outputs(
        &self,
        pair: &ViewPair,
        major: Range<u32>,
        minor: Range<u32>,
    ) -> Result<Vec<OwnedTxOut>, Error> {
        match self.tx_additional_pubkeys() {
            Some(tx_additional_pubkeys) => {
                let checker = SubKeyChecker::new(&pair, major, minor);
                Ok((0..)
                    .zip(self.outputs.iter())
                    .zip(tx_additional_pubkeys.iter())
                    .filter_map(|((i, out), tx_pubkey)| {
                        match out.target {
                            TxOutTarget::ToKey { key } => match checker.check(i, &key, tx_pubkey) {
                                Some(sub_index) => Some(OwnedTxOut {
                                    index: i,
                                    out,
                                    sub_index: *sub_index,
                                    tx_pubkey: *tx_pubkey,
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
                    let checker = SubKeyChecker::new(&pair, major, minor);
                    Ok((0..)
                        .zip(self.outputs.iter())
                        .filter_map(|(i, out)| {
                            match out.target {
                                TxOutTarget::ToKey { key } => {
                                    match checker.check(i, &key, &tx_pubkey) {
                                        Some(sub_index) => Some(OwnedTxOut {
                                            index: i,
                                            out,
                                            sub_index: *sub_index,
                                            tx_pubkey,
                                        }),
                                        None => None,
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

/// A full transaction containing the prefix and all the signing data.
///
/// As transaction implements [`hash::Hashable`] it is possible to generate the transaction hash
/// with `tx.hash()`.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
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

    /// Return the transaction public key present in extra field.
    pub fn tx_pubkey(&self) -> Option<PublicKey> {
        self.prefix().extra.tx_pubkey()
    }

    /// Return the additional public keys present in extra field.
    pub fn tx_additional_pubkeys(&self) -> Option<Vec<PublicKey>> {
        self.prefix().extra.tx_additional_pubkeys()
    }

    /// Iterate over transaction outputs and find outputs related to view pair.
    pub fn check_outputs(
        &self,
        pair: &ViewPair,
        major: Range<u32>,
        minor: Range<u32>,
    ) -> Result<Vec<OwnedTxOut>, Error> {
        self.prefix().check_outputs(pair, major, minor)
    }

    /// Calculate an output's amount.
    pub fn get_amount(&self, view_pair: &ViewPair, out: &OwnedTxOut) -> Result<u64, RecoveryError> {
        if out.index >= self.prefix.outputs.len() {
            return Err(RecoveryError::IndexOutOfRange);
        }

        let sig = self
            .rct_signatures
            .sig
            .as_ref()
            .ok_or(RecoveryError::MissingSignature)?;

        let ecdh_info = sig
            .ecdh_info
            .get(out.index)
            .ok_or(RecoveryError::IndexOutOfRange)?;

        let shared_key = KeyGenerator::from_key(view_pair, out.tx_pubkey).get_rvn_scalar(out.index);

        let (commitment_mask, amount) = match ecdh_info {
            // ecdhDecode in rctOps.cpp else
            EcdhInfo::Standard { mask, amount } => {
                let shared_sec1 = hash::Hash::hash(shared_key.as_bytes()).to_bytes();
                let shared_sec2 = hash::Hash::hash(&shared_sec1).to_bytes();
                let mask_scalar = Scalar::from_bytes_mod_order(mask.key)
                    - Scalar::from_bytes_mod_order(shared_sec1);

                let amount_scalar = Scalar::from_bytes_mod_order(amount.key)
                    - Scalar::from_bytes_mod_order(shared_sec2);
                // get first 64 bits (d2b in rctTypes.cpp)
                let amount_significant_bytes = amount_scalar.to_bytes()[0..8]
                    .try_into()
                    .expect("Can't fail");
                let amount = u64::from_le_bytes(amount_significant_bytes);
                (mask_scalar, amount)
            }
            // ecdhDecode in rctOps.cpp if (v2)
            EcdhInfo::Bulletproof { amount } => {
                // genCommitmentMask in .cpp
                let mut commitment_key = "commitment_mask".as_bytes().to_vec();
                commitment_key.extend(shared_key.as_bytes());
                // yt in Z2M p 53
                let mask_scalar = Scalar::from_bytes_mod_order(
                    hash::Hash::hash(&commitment_key).to_fixed_bytes(),
                );
                // ecdhHash in .cpp
                let mut amount_key = "amount".as_bytes().to_vec();
                amount_key.extend(shared_key.as_bytes());

                // Hn("amount", Hn(rKbv,t))
                let hash_shared_key = hash::Hash::hash(&amount_key).to_fixed_bytes();
                let hash_shared_key_significant_bytes = hash_shared_key[0..8]
                    .try_into()
                    .expect("hash_shared_key create above has 32 bytes");

                // bt in Z2M and masked.amount in .cpp
                let masked_amount = amount.0; // 8 bytes

                // amount_t = bt XOR Hn("amount", Hn("amount", Hn(rKbv,t)))
                // xor8(masked.amount, ecdhHash(sharedSec)); in .cpp
                let amount = u64::from_le_bytes(masked_amount)
                    ^ u64::from_le_bytes(hash_shared_key_significant_bytes);

                (mask_scalar, amount)
            }
        };

        let blinding_factor =
            PublicKey::from_private_key(&PrivateKey::from_scalar(commitment_mask));
        let committed_amount = H * &PrivateKey::from_scalar(Scalar::from(amount));
        let expected_commitment = blinding_factor + committed_amount;
        let actual_commitment = PublicKey::from_slice(&sig.out_pk[out.index].mask.key);

        if actual_commitment != Ok(expected_commitment) {
            return Err(RecoveryError::InvalidCommitment);
        }

        Ok(amount)
    }
}

impl hash::Hashable for Transaction {
    fn hash(&self) -> hash::Hash {
        match *self.prefix.version {
            1 => hash::Hash::hash(&serialize(self)),
            _ => {
                let mut hashes: Vec<hash::Hash> = vec![self.prefix.hash()];
                if let Some(sig_base) = &self.rct_signatures.sig {
                    hashes.push(sig_base.hash());
                    if sig_base.rct_type == RctType::Null {
                        hashes.push(hash::Hash::null_hash());
                    } else {
                        match &self.rct_signatures.p {
                            Some(p) => {
                                let mut encoder = io::Cursor::new(vec![]);
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

impl Decodable for ExtraField {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<ExtraField, encode::Error> {
        let mut fields: Vec<SubField> = vec![];
        let bytes: Vec<u8> = Decodable::consensus_decode(d)?;
        let mut decoder = io::Cursor::new(&bytes[..]);
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

impl Encodable for ExtraField {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        let mut encoder = io::Cursor::new(vec![]);
        for field in self.0.iter() {
            field.consensus_encode(&mut encoder)?;
        }
        encoder.into_inner().consensus_encode(s)
    }
}

impl Decodable for SubField {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<SubField, encode::Error> {
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

impl Encodable for SubField {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        let mut len = 0;
        match *self {
            SubField::Padding(nbytes) => {
                len += 0x0u8.consensus_encode(s)?;
                for _ in 0..nbytes {
                    len += 0u8.consensus_encode(s)?;
                }
                Ok(len)
            }
            SubField::TxPublicKey(ref pubkey) => {
                len += 0x1u8.consensus_encode(s)?;
                Ok(len + pubkey.consensus_encode(s)?)
            }
            SubField::Nonce(ref nonce) => {
                len += 0x2u8.consensus_encode(s)?;
                Ok(len + nonce.consensus_encode(s)?)
            }
            SubField::MergeMining(ref depth, ref merkle_root) => {
                len += 0x3u8.consensus_encode(s)?;
                len += depth.consensus_encode(s)?;
                Ok(len + merkle_root.consensus_encode(s)?)
            }
            SubField::AdditionalPublickKey(ref pubkeys) => {
                len += 0x4u8.consensus_encode(s)?;
                Ok(len + pubkeys.consensus_encode(s)?)
            }
            SubField::MysteriousMinerGate(ref string) => {
                len += 0xdeu8.consensus_encode(s)?;
                Ok(len + string.consensus_encode(s)?)
            }
        }
    }
}

impl Decodable for TxIn {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<TxIn, encode::Error> {
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

impl Encodable for TxIn {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        match self {
            TxIn::Gen { height } => {
                let len = 0xffu8.consensus_encode(s)?;
                Ok(len + height.consensus_encode(s)?)
            }
            TxIn::ToKey {
                amount,
                key_offsets,
                k_image,
            } => {
                let mut len = 0x2u8.consensus_encode(s)?;
                len += amount.consensus_encode(s)?;
                len += key_offsets.consensus_encode(s)?;
                Ok(len + k_image.consensus_encode(s)?)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Interrupted,
                Error::ScriptNotSupported,
            )),
        }
    }
}

impl Decodable for TxOutTarget {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<TxOutTarget, encode::Error> {
        let outtype: u8 = Decodable::consensus_decode(d)?;
        match outtype {
            0x2 => Ok(TxOutTarget::ToKey {
                key: Decodable::consensus_decode(d)?,
            }),
            _ => Err(encode::Error::ParseFailed("Invalid output type")),
        }
    }
}

impl Encodable for TxOutTarget {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        match self {
            TxOutTarget::ToKey { key } => {
                let len = 0x2u8.consensus_encode(s)?;
                Ok(len + key.consensus_encode(s)?)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Interrupted,
                Error::ScriptNotSupported,
            )),
        }
    }
}

#[allow(non_snake_case)]
impl Decodable for Transaction {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Transaction, encode::Error> {
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

impl Encodable for Transaction {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        let mut len = self.prefix.consensus_encode(s)?;
        match *self.prefix.version {
            1 => {
                for sig in self.signatures.iter() {
                    len += encode_sized_vec!(sig, s);
                }
            }
            _ => {
                if let Some(sig) = &self.rct_signatures.sig {
                    len += sig.consensus_encode(s)?;
                    if let Some(p) = &self.rct_signatures.p {
                        len += p.consensus_encode(s, sig.rct_type)?;
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

    use super::{ExtraField, Transaction, TransactionPrefix};
    use crate::blockdata::transaction::{SubField, TxIn, TxOutTarget};
    use crate::consensus::encode::{deserialize, deserialize_partial, serialize, VarInt};
    use crate::cryptonote::hash::Hashable;
    use crate::util::key::{PrivateKey, PublicKey, ViewPair};
    use crate::util::ringct::{RctSig, RctSigBase, RctType};
    use crate::TxOut;

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
                        .unwrap(),
                    },
                }],
                extra: ExtraField {
                    0: vec![
                        SubField::TxPublicKey(PublicKey::from_slice(pk_extra.as_slice()).unwrap()),
                        SubField::Nonce(vec![
                            196, 37, 4, 0, 27, 37, 187, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ]),
                    ],
                },
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
            hex::encode(transaction.hash().0.to_vec())
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
                        .unwrap(),
                    },
                }],
                extra: ExtraField {
                    0: vec![
                        SubField::TxPublicKey(PublicKey::from_slice(pk_extra.as_slice()).unwrap()),
                        SubField::Nonce(vec![
                            196, 37, 4, 0, 27, 37, 187, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ]),
                    ],
                },
            },
            signatures: vec![],
            rct_signatures: RctSig { sig: None, p: None },
        };
        assert_eq!(
            tx.as_bytes().to_vec(),
            hex::encode(transaction.hash().0.to_vec())
                .as_bytes()
                .to_vec()
        );
    }
}

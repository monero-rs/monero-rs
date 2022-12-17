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

//! Types for interacting with the Monero sub-databases that are associated with transactions
//!
use crate::consensus::encode::{self, deserialize, serialize, Decodable};
use crate::cryptonote::hash::{self, Hashable};
use crate::util::ringct::{Key, RctSig, RctSigBase, RctType};
use crate::{Hash, PublicKey, Transaction, TransactionPrefix};

use sealed::sealed;
use std::io;
use thiserror::Error;

#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};

/// Errors possible when manipulating transactions.
#[derive(Error, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrunedHashError {
    /// Can't get hash of pruned V1 transactions
    #[error("Can't get hash of pruned V1 transactions")]
    V1TransactionHash,
}

/// Used in table "txs_pruned"
///
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct TransactionPruned {
    /// The transaction prefix.
    pub prefix: TransactionPrefix,
    /// The RingCT signatures, will only contain the 'sig' felid.
    pub rct_signatures: RctSig,
}

impl TransactionPruned {
    /// Turns a pruned transaction to a normal transaction with the missing pruned data
    pub fn to_transaction(&self, prunable: &[u8]) -> Result<Transaction, encode::Error> {
        let tx_pruned = serialize(self);
        let tx = [tx_pruned, prunable.to_vec()].concat();
        deserialize::<Transaction>(&tx)
    }

    /// Calculates the transactions hash with the missing prunable hash
    /// Will Error if the transaction is version 1.
    pub fn hash(&self, prunable_hash: Hash) -> Result<Hash, PrunedHashError> {
        match self.prefix.version.0 {
            1 => Err(PrunedHashError::V1TransactionHash),
            _ => {
                let mut hashes: Vec<hash::Hash> = vec![self.prefix.hash()];
                if let Some(sig_base) = &self.rct_signatures.sig {
                    hashes.push(sig_base.hash());
                    if sig_base.rct_type == RctType::Null {
                        hashes.push(hash::Hash::null());
                    } else {
                        hashes.push(prunable_hash);
                    }
                }
                let bytes: Vec<u8> = hashes
                    .into_iter()
                    .flat_map(|h| Vec::from(&h.to_bytes()[..]))
                    .collect();
                Ok(hash::Hash::new(&bytes))
            }
        }
    }
}

impl From<Transaction> for TransactionPruned {
    fn from(transaction: Transaction) -> TransactionPruned {
        TransactionPruned {
            prefix: transaction.prefix,
            rct_signatures: RctSig {
                sig: transaction.rct_signatures.sig,
                p: None,
            },
        }
    }
}

impl Decodable for TransactionPruned {
    fn consensus_decode<R: io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<TransactionPruned, encode::Error> {
        let prefix: TransactionPrefix = Decodable::consensus_decode(r)?;

        let inputs = prefix.inputs.len();
        let outputs = prefix.outputs.len();

        match *prefix.version {
            1 => Ok(TransactionPruned {
                prefix,
                rct_signatures: RctSig { sig: None, p: None },
            }),
            _ => {
                let mut rct_signatures = RctSig { sig: None, p: None };
                if inputs == 0 {
                    return Ok(TransactionPruned {
                        prefix,
                        rct_signatures: RctSig { sig: None, p: None },
                    });
                }

                if let Some(sig) = RctSigBase::consensus_decode(r, inputs, outputs)? {
                    rct_signatures = RctSig {
                        sig: Some(sig),
                        p: None,
                    };
                }

                Ok(TransactionPruned {
                    prefix,
                    rct_signatures,
                })
            }
        }
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for TransactionPruned {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = self.prefix.consensus_encode(w)?;
        match *self.prefix.version {
            1 => {}
            _ => {
                if let Some(sig) = &self.rct_signatures.sig {
                    len += sig.consensus_encode(w)?;
                }
            }
        }
        Ok(len)
    }
}

/// Used in table "tx_outputs"
///
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct TxOutputIdx {
    /// The indexes of the transactions outputs
    pub indexes: Vec<u64>,
}

impl Decodable for TxOutputIdx {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let mut buf = vec![];
        let size = r.read_to_end(&mut buf)?;
        if size % 8 != 0 {
            return Err(encode::Error::ParseFailed("Invalid data length"));
        }
        let mut indexes = vec![];
        for i in (0..size).step_by(8) {
            indexes.push(deserialize::<u64>(&buf[i..i + 8])?);
        }
        Ok(TxOutputIdx { indexes })
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for TxOutputIdx {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        for index in self.indexes.iter() {
            len += index.consensus_encode(w)?;
        }
        Ok(len)
    }
}

/// Used in table "output_amounts"
/// pre_rct_outkey in the Monero codebase
///
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct PreRctOutkey {
    /// amount_index
    pub amount_index: u64,
    /// The output_id
    pub output_id: u64,
    /// The output's public key (for spend verification)
    pub pubkey: PublicKey,
    /// The output's unlock time (or height)
    pub unlock_time: u64,
    /// The height of the block which created the output
    pub height: u64,
}

impl_consensus_encoding!(
    PreRctOutkey,
    amount_index,
    output_id,
    pubkey,
    unlock_time,
    height
);

/// Used in table "output_amounts"
/// outkey in the Monero codebase
///
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct RctOutkey {
    /// amount_index
    pub amount_index: u64,
    /// The output_id
    pub output_id: u64,
    /// The output's public key (for spend verification)
    pub pubkey: PublicKey,
    /// The output's unlock time (or height)
    pub unlock_time: u64,
    /// The height of the block which created the output
    pub height: u64,
    /// The output's amount commitment (for spend verification)
    pub commitment: Key,
}

impl_consensus_encoding!(
    RctOutkey,
    amount_index,
    output_id,
    pubkey,
    unlock_time,
    height,
    commitment
);

/// Used in table "output_txs"
/// outtx in the Monero codebase
///
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct OutTx {
    /// output_id
    pub output_id: u64,
    /// tx_hash
    pub tx_hash: Hash,
    /// local_index
    pub local_index: u64,
}

impl_consensus_encoding!(OutTx, output_id, tx_hash, local_index);

/// Used in table "tx_indices"
/// outtx in the Monero codebase
///
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct TxIndex {
    /// key
    pub tx_hash: Hash,
    /// tx_id
    pub tx_id: u64,
    /// unlock_time
    pub unlock_time: u64,
    /// block_id
    pub block_id: u64,
}

impl_consensus_encoding!(TxIndex, tx_hash, tx_id, unlock_time, block_id);

/// Used in table "txpool_meta"
///
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct TxPoolPadding;

impl Decodable for TxPoolPadding {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let mut buf: Vec<u8> = vec![];
        r.read_to_end(&mut buf)?;
        if buf.len() != TxPoolMeta::SIZE - TxPoolMeta::SIZE_WITHOUT_PADDING {
            return Err(encode::Error::ParseFailed("Padding has incorrect length"));
        }
        Ok(TxPoolPadding)
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for TxPoolPadding {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        for _ in 0..TxPoolMeta::SIZE - TxPoolMeta::SIZE_WITHOUT_PADDING {
            len += 0_u8.consensus_encode(w)?;
        }
        Ok(len)
    }
}

/// Used in table "txpool_meta"
/// txpool_tx_meta_t in the Monero codebase
///
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct TxPoolMeta {
    /// block of most recent input
    pub max_used_block_id: Hash,
    /// the hash of the highest block the transaction referenced when last checking it failed
    /// if verifying a transaction's inputs fails, it's possible this is due to a reorg since
    /// it was created (if it used recently created outputs as inputs).
    pub last_failed_id: Hash,
    /// the transaction's weight
    pub weight: u64,
    /// the transaction's fee amount
    pub fee: u64,
    /// the height of the highest block referenced by an input
    pub max_used_block_height: u64,
    /// the id of the highest block the transaction referenced when last checking it failed
    pub last_failed_height: u64,
    /// the time when the transaction entered the pool
    pub receive_time: u64,
    /// the last time the transaction was relayed to the network
    pub last_relayed_time: u64,
    /// whether or not the transaction has been in a block before.
    /// if the transaction was returned to the pool from the blockchain
    /// due to a reorg, then this will be true
    pub kept_by_block: u8,
    /// whether or not the transaction has been relayed to the network
    pub relayed: u8,
    /// /// true is the relay method is none
    pub do_not_relay: u8,
    /// true if another tx was seen double spending this one
    pub double_spend_seen: u8,
    /// true if tx is pruned
    pub pruned: u8,
    /// true is the relay method is local
    pub is_local: u8,
    /// true is the relay method is dandelion stem
    pub dandelionpp_stem: u8,
    /// true is the relay method is forward
    pub is_forwarding: u8,
    /// Bitflags padding
    pub bf_padding: u8,
    /// padding
    pub padding: TxPoolPadding,
}

impl TxPoolMeta {
    /// The size of TxPoolMeta without padding
    pub const SIZE_WITHOUT_PADDING: usize = 121;
    /// The size of TxPoolMeta with padding
    pub const SIZE: usize = 192;
}

impl_consensus_encoding!(
    TxPoolMeta,
    max_used_block_id,
    last_failed_id,
    weight,
    fee,
    max_used_block_height,
    last_failed_height,
    receive_time,
    last_relayed_time,
    kept_by_block,
    relayed,
    do_not_relay,
    double_spend_seen,
    pruned,
    is_local,
    dandelionpp_stem,
    is_forwarding,
    bf_padding,
    padding
);

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{
        consensus::encode::{deserialize, serialize},
        cryptonote::hash::Hashable,
        Hash, PublicKey,
    };

    use super::{
        PreRctOutkey, RctOutkey, TransactionPruned, TxIndex, TxOutputIdx, TxPoolMeta, TxPoolPadding,
    };

    #[test]
    fn test_ser_tx_index() {
        let bytes = [
            80, 6, 36, 49, 229, 198, 163, 137, 203, 55, 157, 196, 210, 142, 23, 203, 231, 209, 93,
            241, 23, 97, 30, 69, 100, 103, 105, 54, 182, 143, 27, 93, 69, 196, 164, 1, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 200, 7, 41, 0, 0, 0, 0, 0,
        ];
        let tx_index = deserialize::<TxIndex>(&bytes).unwrap();

        let deserialized_tx_index = TxIndex {
            tx_hash: Hash::from_str(
                "50062431e5c6a389cb379dc4d28e17cbe7d15df117611e4564676936b68f1b5d",
            )
            .unwrap(),
            tx_id: 27575365,
            unlock_time: 0,
            block_id: 2688968,
        };

        assert_eq!(deserialized_tx_index, tx_index);
    }

    #[test]
    fn test_ser_tx_pruned() {
        let bytes = [
            2, 0, 1, 2, 0, 16, 215, 193, 197, 23, 151, 149, 157, 4, 255, 178, 67, 162, 150, 2, 205,
            190, 1, 197, 208, 2, 255, 218, 2, 176, 190, 1, 149, 10, 131, 60, 236, 150, 1, 251, 42,
            136, 5, 141, 114, 212, 5, 183, 3, 47, 48, 210, 224, 46, 112, 190, 46, 121, 208, 121,
            230, 137, 43, 29, 20, 68, 114, 19, 126, 73, 44, 110, 68, 53, 88, 182, 206, 94, 143, 2,
            33, 2, 0, 3, 74, 110, 206, 114, 95, 9, 139, 69, 132, 43, 112, 13, 176, 33, 7, 106, 117,
            43, 226, 251, 115, 105, 222, 106, 54, 111, 81, 110, 253, 108, 37, 41, 147, 0, 3, 238,
            10, 133, 65, 147, 241, 199, 39, 149, 187, 77, 208, 220, 17, 23, 138, 204, 253, 159,
            131, 178, 69, 185, 40, 207, 230, 126, 13, 73, 133, 143, 57, 247, 44, 1, 8, 129, 152,
            202, 169, 223, 13, 242, 7, 239, 52, 24, 184, 162, 157, 84, 196, 119, 121, 105, 180, 12,
            229, 125, 171, 134, 39, 137, 167, 158, 132, 246, 2, 9, 1, 200, 171, 169, 101, 43, 122,
            75, 233, 6, 160, 171, 207, 14, 45, 183, 194, 24, 193, 37, 15, 84, 105, 193, 175, 107,
            170, 237, 159, 160, 166, 253, 245, 90, 168, 98, 249, 43, 143, 93, 14, 55, 250, 2, 165,
            20, 206, 78, 191, 188, 110, 66, 26, 239, 21, 164, 0, 170, 0, 230, 110, 225, 116, 117,
            63, 9, 84, 172, 4, 159, 70, 196, 212, 71, 225, 166, 185, 133, 146, 242, 147, 55, 171,
            225, 105, 84, 142, 9, 181, 97, 252, 242, 8, 3,
        ];
        let tx_pruned = deserialize::<TransactionPruned>(&bytes).unwrap();
        let prunable_hash =
            Hash::from_str("7619231f200a76bbdbfde10f0c213732f7445b988d5c1e2bc10d5110c8eb50aa")
                .unwrap();
        let expected_hash =
            Hash::from_str("50062431e5c6a389cb379dc4d28e17cbe7d15df117611e4564676936b68f1b5d")
                .unwrap();
        assert_eq!(tx_pruned.hash(prunable_hash).unwrap(), expected_hash);
        assert_eq!(serialize(&tx_pruned), bytes);
    }

    #[test]
    fn tx_pruned_to_full() {
        let non_prunable_bytes = [
            2, 0, 1, 2, 0, 16, 215, 193, 197, 23, 151, 149, 157, 4, 255, 178, 67, 162, 150, 2, 205,
            190, 1, 197, 208, 2, 255, 218, 2, 176, 190, 1, 149, 10, 131, 60, 236, 150, 1, 251, 42,
            136, 5, 141, 114, 212, 5, 183, 3, 47, 48, 210, 224, 46, 112, 190, 46, 121, 208, 121,
            230, 137, 43, 29, 20, 68, 114, 19, 126, 73, 44, 110, 68, 53, 88, 182, 206, 94, 143, 2,
            33, 2, 0, 3, 74, 110, 206, 114, 95, 9, 139, 69, 132, 43, 112, 13, 176, 33, 7, 106, 117,
            43, 226, 251, 115, 105, 222, 106, 54, 111, 81, 110, 253, 108, 37, 41, 147, 0, 3, 238,
            10, 133, 65, 147, 241, 199, 39, 149, 187, 77, 208, 220, 17, 23, 138, 204, 253, 159,
            131, 178, 69, 185, 40, 207, 230, 126, 13, 73, 133, 143, 57, 247, 44, 1, 8, 129, 152,
            202, 169, 223, 13, 242, 7, 239, 52, 24, 184, 162, 157, 84, 196, 119, 121, 105, 180, 12,
            229, 125, 171, 134, 39, 137, 167, 158, 132, 246, 2, 9, 1, 200, 171, 169, 101, 43, 122,
            75, 233, 6, 160, 171, 207, 14, 45, 183, 194, 24, 193, 37, 15, 84, 105, 193, 175, 107,
            170, 237, 159, 160, 166, 253, 245, 90, 168, 98, 249, 43, 143, 93, 14, 55, 250, 2, 165,
            20, 206, 78, 191, 188, 110, 66, 26, 239, 21, 164, 0, 170, 0, 230, 110, 225, 116, 117,
            63, 9, 84, 172, 4, 159, 70, 196, 212, 71, 225, 166, 185, 133, 146, 242, 147, 55, 171,
            225, 105, 84, 142, 9, 181, 97, 252, 242, 8, 3,
        ];

        let prunable_bytes = [
            1, 101, 123, 123, 85, 243, 116, 10, 254, 113, 173, 78, 15, 123, 38, 183, 97, 165, 37,
            97, 156, 133, 16, 95, 47, 189, 39, 227, 158, 132, 145, 168, 90, 167, 129, 166, 171,
            170, 254, 39, 216, 210, 134, 12, 219, 188, 205, 69, 174, 72, 118, 179, 131, 242, 240,
            132, 176, 158, 74, 20, 158, 170, 22, 235, 21, 85, 168, 124, 134, 68, 155, 153, 25, 26,
            192, 99, 235, 149, 211, 200, 56, 173, 61, 252, 10, 3, 19, 227, 221, 208, 211, 1, 178,
            226, 211, 189, 12, 80, 203, 238, 218, 199, 216, 250, 171, 186, 37, 160, 185, 39, 90,
            21, 224, 84, 41, 159, 216, 113, 224, 192, 164, 189, 96, 146, 31, 186, 191, 138, 1, 188,
            247, 38, 136, 192, 21, 138, 109, 222, 208, 190, 117, 168, 100, 191, 208, 129, 8, 97,
            208, 191, 236, 252, 139, 116, 132, 47, 174, 68, 144, 244, 7, 182, 97, 95, 122, 187, 48,
            155, 247, 48, 211, 63, 110, 92, 64, 58, 205, 99, 250, 146, 245, 39, 145, 165, 179, 216,
            3, 207, 220, 234, 128, 215, 1, 7, 29, 216, 182, 86, 188, 251, 192, 248, 255, 46, 160,
            178, 169, 162, 18, 58, 216, 82, 174, 242, 193, 85, 199, 144, 243, 17, 10, 78, 189, 182,
            105, 104, 121, 122, 64, 182, 66, 157, 231, 190, 221, 204, 22, 253, 211, 182, 100, 162,
            48, 54, 137, 225, 183, 177, 141, 122, 116, 200, 150, 99, 93, 199, 35, 151, 153, 24,
            121, 155, 8, 64, 143, 202, 72, 36, 113, 139, 177, 39, 152, 249, 198, 237, 15, 202, 46,
            9, 49, 114, 71, 97, 224, 166, 51, 16, 110, 146, 190, 96, 60, 158, 1, 238, 99, 247, 70,
            154, 226, 28, 123, 99, 144, 140, 18, 223, 130, 19, 96, 206, 114, 12, 149, 29, 147, 59,
            188, 33, 20, 204, 11, 115, 169, 54, 251, 209, 160, 200, 62, 79, 29, 201, 92, 101, 207,
            111, 132, 58, 11, 205, 212, 56, 227, 152, 185, 93, 36, 203, 169, 184, 98, 15, 182, 127,
            11, 174, 204, 35, 34, 124, 193, 192, 40, 154, 94, 127, 247, 189, 111, 96, 146, 232,
            235, 77, 128, 237, 255, 74, 225, 167, 219, 180, 12, 155, 136, 249, 232, 180, 226, 189,
            182, 71, 92, 158, 53, 110, 223, 199, 122, 248, 200, 155, 198, 179, 151, 123, 99, 18,
            208, 226, 149, 128, 189, 191, 47, 126, 7, 185, 67, 170, 29, 198, 5, 213, 187, 85, 178,
            52, 85, 1, 208, 160, 147, 83, 28, 101, 54, 197, 188, 26, 185, 255, 41, 33, 160, 96, 33,
            206, 176, 72, 48, 199, 232, 45, 174, 123, 49, 172, 126, 2, 140, 58, 202, 181, 159, 165,
            239, 244, 176, 99, 130, 182, 121, 191, 107, 125, 158, 155, 44, 33, 171, 251, 68, 173,
            163, 243, 101, 34, 143, 2, 122, 203, 9, 134, 127, 32, 136, 13, 49, 22, 225, 127, 76,
            203, 202, 63, 48, 134, 197, 0, 161, 201, 126, 37, 29, 231, 139, 142, 225, 59, 221, 203,
            223, 41, 206, 57, 140, 213, 49, 9, 213, 110, 30, 182, 60, 81, 157, 246, 220, 25, 182,
            167, 167, 40, 118, 227, 176, 128, 99, 125, 46, 253, 95, 176, 45, 64, 157, 11, 108, 207,
            247, 129, 213, 140, 30, 164, 117, 39, 174, 35, 152, 201, 74, 28, 65, 109, 106, 254, 60,
            182, 10, 125, 62, 67, 92, 70, 186, 184, 100, 159, 121, 12, 134, 242, 228, 253, 84, 185,
            91, 80, 137, 201, 195, 130, 240, 81, 8, 190, 26, 180, 197, 170, 206, 197, 155, 129,
            149, 10, 199, 185, 102, 186, 221, 104, 197, 194, 187, 5, 103, 166, 41, 119, 48, 108,
            40, 148, 21, 159, 167, 92, 226, 252, 121, 251, 184, 20, 93, 17, 57, 21, 35, 117, 112,
            103, 156, 221, 123, 101, 16, 24, 194, 105, 54, 230, 143, 108, 172, 0, 87, 0, 33, 225,
            8, 248, 155, 18, 212, 246, 28, 108, 28, 85, 179, 7, 5, 1, 120, 203, 149, 101, 141, 196,
            9, 137, 144, 255, 212, 69, 139, 207, 215, 48, 237, 152, 12, 45, 91, 181, 61, 75, 227,
            8, 223, 200, 150, 204, 240, 6, 104, 151, 177, 121, 214, 183, 2, 22, 120, 165, 197, 52,
            87, 0, 217, 66, 200, 96, 9, 201, 149, 96, 53, 155, 30, 115, 92, 43, 162, 169, 203, 129,
            11, 220, 123, 197, 25, 88, 155, 42, 11, 10, 9, 38, 197, 151, 38, 229, 51, 235, 1, 113,
            112, 249, 245, 6, 249, 61, 49, 205, 160, 114, 38, 5, 67, 101, 48, 8, 188, 215, 223, 88,
            180, 52, 202, 54, 188, 128, 168, 195, 74, 118, 4, 251, 181, 180, 203, 46, 134, 108,
            224, 250, 0, 211, 184, 128, 127, 6, 255, 222, 11, 21, 131, 10, 3, 216, 210, 81, 68,
            118, 152, 139, 62, 185, 13, 182, 127, 189, 79, 1, 167, 177, 187, 231, 133, 119, 128,
            63, 201, 52, 36, 157, 48, 182, 210, 96, 20, 151, 189, 170, 21, 171, 153, 43, 37, 193,
            13, 86, 87, 8, 39, 160, 10, 251, 145, 115, 130, 116, 22, 90, 124, 16, 206, 91, 194,
            131, 247, 210, 30, 213, 45, 183, 250, 140, 115, 154, 96, 153, 0, 217, 88, 92, 229, 209,
            219, 6, 211, 243, 222, 12, 229, 200, 207, 185, 77, 144, 67, 200, 176, 142, 199, 187,
            77, 152, 129, 235, 74, 254, 25, 237, 3, 2, 183, 18, 206, 188, 229, 49, 98, 102, 176,
            184, 37, 224, 218, 55, 127, 175, 152, 176, 160, 147, 90, 157, 179, 151, 14, 16, 105,
            14, 33, 165, 7, 198, 232, 195, 86, 126, 98, 193, 195, 150, 174, 31, 201, 243, 33, 194,
            128, 71, 61, 172, 87, 215, 189, 6, 84, 11, 155, 217, 32, 209, 42, 155, 0, 223, 159,
            170, 101, 72, 154, 99, 209, 220, 94, 84, 197, 123, 137, 89, 122, 145, 194, 125, 207,
            140, 139, 249, 58, 97, 236, 61, 12, 184, 2, 127, 12, 35, 174, 236, 123, 129, 69, 49,
            128, 132, 79, 143, 158, 116, 111, 215, 161, 188, 220, 241, 112, 225, 49, 168, 246, 91,
            174, 123, 214, 2, 120, 13, 3, 24, 105, 213, 179, 20, 206, 149, 58, 98, 144, 52, 213,
            16, 244, 115, 156, 143, 51, 94, 80, 65, 99, 167, 170, 98, 147, 46, 72, 178, 143, 139,
            11, 229, 63, 230, 46, 238, 5, 105, 61, 202, 173, 0, 69, 161, 231, 98, 255, 127, 139,
            219, 71, 75, 84, 81, 55, 127, 77, 199, 175, 115, 153, 165, 8, 62, 250, 192, 138, 112,
            120, 1, 254, 145, 173, 250, 125, 234, 198, 108, 215, 47, 141, 91, 153, 131, 5, 104,
            178, 173, 170, 30, 148, 34, 221, 86, 15, 9, 249, 201, 255, 217, 33, 90, 107, 238, 209,
            143, 247, 75, 235, 26, 137, 133, 56, 140, 99, 15, 157, 252, 205, 38, 31, 232, 210, 131,
            134, 21, 8, 152, 19, 128, 116, 59, 39, 121, 34, 50, 61, 131, 50, 131, 189, 228, 128,
            194, 187, 161, 80, 240, 176, 250, 202, 22, 204, 17, 235, 13, 95, 128, 98, 171, 232,
            197, 111, 18, 193, 147, 210, 219, 77, 145, 93, 46, 148, 9, 195, 192, 39, 130, 106, 57,
            77, 107, 59, 22, 196, 150, 90, 101, 177, 231, 116,
        ];
        let tx_pruned = deserialize::<TransactionPruned>(&non_prunable_bytes).unwrap();
        let tx = tx_pruned.to_transaction(&prunable_bytes).unwrap();
        assert_eq!(
            tx.hash(),
            Hash::from_str("50062431e5c6a389cb379dc4d28e17cbe7d15df117611e4564676936b68f1b5d")
                .unwrap()
        );
    }

    #[test]
    fn test_ser_tx_output_idx() {
        let bytes = [30, 235, 140, 3, 0, 0, 0, 0, 31, 235, 140, 3, 0, 0, 0, 0];
        let tx_output_idxs = deserialize::<TxOutputIdx>(&bytes).unwrap();
        let deserialized_tx_out_idxs = TxOutputIdx {
            indexes: vec![59566878, 59566879],
        };
        assert_eq!(tx_output_idxs, deserialized_tx_out_idxs);
    }

    #[test]
    fn test_ser_output_key() {
        let rct_bytes = [
            31, 235, 140, 3, 0, 0, 0, 0, 77, 92, 218, 4, 0, 0, 0, 0, 238, 10, 133, 65, 147, 241,
            199, 39, 149, 187, 77, 208, 220, 17, 23, 138, 204, 253, 159, 131, 178, 69, 185, 40,
            207, 230, 126, 13, 73, 133, 143, 57, 0, 0, 0, 0, 0, 0, 0, 0, 200, 7, 41, 0, 0, 0, 0, 0,
            116, 117, 63, 9, 84, 172, 4, 159, 70, 196, 212, 71, 225, 166, 185, 133, 146, 242, 147,
            55, 171, 225, 105, 84, 142, 9, 181, 97, 252, 242, 8, 3,
        ];
        let rct_out_key = deserialize::<RctOutkey>(&rct_bytes).unwrap();
        let deserialized_rct_out_key = RctOutkey {
            amount_index: 59566879,
            output_id: 81419341,
            pubkey: PublicKey::from_str(
                "ee0a854193f1c72795bb4dd0dc11178accfd9f83b245b928cfe67e0d49858f39",
            )
            .unwrap(),
            unlock_time: 0,
            height: 2688968,
            commitment: crate::util::ringct::Key::from([
                116, 117, 63, 9, 84, 172, 4, 159, 70, 196, 212, 71, 225, 166, 185, 133, 146, 242,
                147, 55, 171, 225, 105, 84, 142, 9, 181, 97, 252, 242, 8, 3,
            ]),
        };

        assert_eq!(rct_out_key, deserialized_rct_out_key);
        assert_eq!(serialize(&rct_out_key), rct_bytes);

        let pre_rct_bytes = [
            0, 0, 0, 0, 0, 0, 0, 0, 99, 217, 0, 0, 0, 0, 0, 0, 169, 99, 102, 180, 197, 189, 49, 50,
            212, 182, 236, 133, 14, 85, 157, 120, 8, 249, 36, 135, 86, 0, 255, 25, 11, 205, 14,
            192, 135, 1, 162, 195, 134, 25, 0, 0, 0, 0, 0, 0, 74, 25, 0, 0, 0, 0, 0, 0,
        ];
        let pre_rct_out_key = deserialize::<PreRctOutkey>(&pre_rct_bytes).unwrap();
        let deserialized_pre_rct_out_key = PreRctOutkey {
            amount_index: 0,
            output_id: 55651,
            pubkey: PublicKey::from_str(
                "a96366b4c5bd3132d4b6ec850e559d7808f924875600ff190bcd0ec08701a2c3",
            )
            .unwrap(),
            unlock_time: 6534,
            height: 6474,
        };

        assert_eq!(pre_rct_out_key, deserialized_pre_rct_out_key);
        assert_eq!(serialize(&pre_rct_out_key), pre_rct_bytes);
    }

    #[test]
    fn test_ser_txpool_meta() {
        let bytes = [
            248, 123, 171, 75, 55, 47, 0, 154, 109, 33, 127, 22, 68, 114, 18, 171, 252, 189, 15,
            74, 197, 250, 146, 113, 112, 182, 78, 17, 57, 131, 238, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 251, 5, 0, 0, 0,
            0, 0, 0, 192, 67, 87, 14, 0, 0, 0, 0, 133, 104, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 171, 200, 157, 99, 0, 0, 0, 0, 171, 200, 157, 99, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let meta = deserialize::<TxPoolMeta>(&bytes).unwrap();
        let deserialized_meta = TxPoolMeta {
            max_used_block_id: Hash::from_str(
                "f87bab4b372f009a6d217f16447212abfcbd0f4ac5fa927170b64e113983ee20",
            )
            .unwrap(),
            last_failed_id: Hash::null(),
            weight: 1531,
            fee: 240600000,
            max_used_block_height: 2779269,
            last_failed_height: 0,
            receive_time: 1671284907,
            last_relayed_time: 1671284907,
            kept_by_block: 0,
            relayed: 1,
            do_not_relay: 0,
            double_spend_seen: 0,
            pruned: 0,
            is_local: 0,
            dandelionpp_stem: 0,
            is_forwarding: 0,
            bf_padding: 0,
            padding: TxPoolPadding,
        };
        assert_eq!(meta, deserialized_meta);
        assert_eq!(serialize(&meta), bytes);
    }
}

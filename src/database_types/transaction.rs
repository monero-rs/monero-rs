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
use crate::util::ringct::{Key, RctSig, RctSigBase};
use crate::{Hash, PublicKey, Transaction, TransactionPrefix};

use sealed::sealed;
use std::io;

#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};

/// Used in table "txs_pruned"
///
#[derive(Debug, Clone, Default)]
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
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct TxOutputIdx {
    /// The indexes of the transactions outputs
    pub indexes: Vec<u64>,
}

impl Decodable for TxOutputIdx {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let mut buf = vec![];
        let num_outputs = r.read_to_end(&mut buf)? / 8;
        let mut indexes = vec![];
        for i in 0..num_outputs {
            indexes.push(deserialize::<u64>(&buf[i * 8..i * 8 + 8])?)
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct TxPoolPadding(Vec<u8>);

impl Decodable for TxPoolPadding {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let mut buf: Vec<u8> = vec![];
        r.read_to_end(&mut buf)?;
        Ok(Self(buf))
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for TxPoolPadding {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        for i in self.0.iter() {
            len += i.consensus_encode(w)?;
        }
        Ok(len)
    }
}

/// Used in table "txpool_meta"
/// txpool_tx_meta_t in the Monero codebase
///
#[derive(Debug, Clone)]
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

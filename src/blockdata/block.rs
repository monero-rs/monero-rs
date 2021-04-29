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

//! Block and block header structures.
//!
//! This module defines structures for manipulating Monero blocks. A block is composed of an
//! [`Header`](BlockHeader), the miner [`Transaction`], and a list of transactions'
//! [`Hash`](hash::Hash) included in the block.
//!

use crate::blockdata::transaction::Transaction;
use crate::consensus::encode::VarInt;
use crate::cryptonote::hash;
#[cfg(feature = "serde_support")]
use serde::{Deserialize, Serialize};
use std::fmt;

/// A block header containing the version, the mining timestamp, the previous block hash and the
/// nonce.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct BlockHeader {
    /// Major version, defines the consensus rules.
    pub major_version: VarInt,
    /// Minor version, also used to vote.
    pub minor_version: VarInt,
    /// Block mining timestamp.
    pub timestamp: VarInt,
    /// Previous block hash.
    pub prev_id: hash::Hash,
    /// The nonce used for the proof of work.
    pub nonce: u32,
}

impl fmt::Display for BlockHeader {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(fmt, "Major version: {}", self.major_version,)?;
        writeln!(fmt, "Minor version: {}", self.minor_version,)?;
        writeln!(fmt, "Timestamp: {}", self.timestamp,)?;
        writeln!(fmt, "Previous id: {}", self.prev_id,)?;
        writeln!(fmt, "Nonce: {}", self.nonce,)
    }
}

impl_consensus_encoding!(
    BlockHeader,
    major_version,
    minor_version,
    timestamp,
    prev_id,
    nonce
);

/// A full block with the mining transaction and the commitments (hash) to all included
/// transaction.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct Block {
    /// The block header.
    pub header: BlockHeader,
    /// The coinbase transaction (mining transaction).
    pub miner_tx: Transaction,
    /// List of included transactions within this block, only hashes are store.
    pub tx_hashes: Vec<hash::Hash>,
}

impl fmt::Display for Block {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(fmt, "Block header: {}", self.header,)?;
        writeln!(fmt, "Miner tx: {}", self.miner_tx)?;
        for tx in &self.tx_hashes {
            writeln!(fmt, "tx: {}", tx,)?;
        }
        Ok(())
    }
}

impl_consensus_encoding!(Block, header, miner_tx, tx_hashes);

#[cfg(test)]
mod test {
    use super::*;
    use crate::consensus::encode::deserialize;
    use crate::consensus::encode::serialize;
    use crate::cryptonote::hash::Hashable;

    #[test]
    fn test_block_ser() {
        // block with only the miner tx and no other transactions
        let hex = "0c0c94debaf805beb3489c722a285c092a32e7c6893abfc7d069699c8326fc3445a749c5276b6200000000029b892201ffdf882201b699d4c8b1ec020223df524af2a2ef5f870adb6e1ceb03a475c39f8b9ef76aa50b46ddd2a18349402b012839bfa19b7524ec7488917714c216ca254b38ed0424ca65ae828a7c006aeaf10208f5316a7f6b99cca60000";
        // blockhashing blob for above block as accepted by monero
        let hex_blockhash_blob="0c0c94debaf805beb3489c722a285c092a32e7c6893abfc7d069699c8326fc3445a749c5276b6200000000602d0d4710e2c2d38da0cce097accdf5dc18b1d34323880c1aae90ab8f6be6e201";
        let bytes = hex::decode(hex).unwrap();
        let block = deserialize::<Block>(&bytes[..]).unwrap();
        let header = serialize::<BlockHeader>(&block.header);
        let mut count = serialize::<VarInt>(&VarInt(1 + block.tx_hashes.len() as u64));
        let mut root = block.miner_tx.hash().0.to_vec(); //tree_hash(hashes); // tree_hash.c used by monero, will be the miner tx hash here
        let mut encode2 = header;
        encode2.append(&mut root);
        encode2.append(&mut count);
        assert_eq!(hex::encode(encode2), hex_blockhash_blob);
        let bytes2 = serialize::<Block>(&block);
        assert_eq!(bytes, bytes2);
        let hex2 = hex::encode(bytes2);
        assert_eq!(hex, hex2);
    }
}

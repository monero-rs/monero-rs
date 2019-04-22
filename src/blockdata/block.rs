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

//! Block
//!
//! This module defines structures of blocks.
//!

use crate::blockdata::transaction::Transaction;
use crate::consensus::encode::VarInt;
use crate::cryptonote::hash;

/// Monero block header
pub struct BlockHeader {
    /// Major version, defines the consensus rules
    pub major_version: VarInt,
    /// Minor version, also used to vote
    pub minor_version: VarInt,
    /// Block timestamp
    pub timestamp: VarInt,
    /// Previous block hash
    pub prev_id: hash::Hash,
    /// Nonce
    pub nonce: u32,
}

impl_consensus_encoding!(
    BlockHeader,
    major_version,
    minor_version,
    timestamp,
    prev_id,
    nonce
);

/// Monero block with all transaction hashes
pub struct Block {
    /// The block header
    pub header: BlockHeader,
    /// Coinbase transaction
    pub miner_tx: Transaction,
    /// List of included transactions
    pub tx_hashes: Vec<hash::Hash>,
}

impl_consensus_encoding!(Block, header, miner_tx, tx_hashes);

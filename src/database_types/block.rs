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

//! Types for interacting with the Monero sub-databases that are associated with blocks
//!  

use crate::{Amount, Block, Hash};

#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};

/// Used in table "block_info"
/// mdb_block_info_4 in the Monero codebase
///
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct BlockInfo {
    /// bi_height
    pub block_height: u64,
    /// bi_timestamp
    pub timestamp: u64,
    /// bi_coins
    pub total_coins_generated: u64,
    /// bi_weight
    pub weight: u64,
    /// bi_diff_lo
    pub diff_lo: u64,
    /// bi_diff_hi
    pub diff_hi: u64,
    /// bi_hash
    pub block_hash: Hash,
    /// bi_cum_rct
    pub cum_rct: u64,
    /// bi_long_term_block_weight
    pub long_term_block_weight: u64,
}

impl BlockInfo {
    /// Returns the `total_coins_generated` field as [`Amount`]
    pub fn get_total_coins_generated_as_amount(&self) -> Amount {
        Amount::from_pico(self.total_coins_generated)
    }

    /// Returns the cumulative difficulty for this block
    pub fn cum_difficulty(&self) -> u128 {
        let mut ret: u128 = self.diff_hi as u128;
        ret <<= 64;
        ret | self.diff_lo as u128
    }
}

impl_consensus_encoding!(
    BlockInfo,
    block_height,
    timestamp,
    total_coins_generated,
    weight,
    diff_lo,
    diff_hi,
    block_hash,
    cum_rct,
    long_term_block_weight
);

/// Used in table "block_heights"
/// blk_height in the Monero codebase
///
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct BlockHeight {
    /// bh_hash
    pub block_hash: Hash,
    /// bh_height
    pub block_height: u64,
}

impl_consensus_encoding!(BlockHeight, block_hash, block_height);

/// Used in table "alt_blocks"
/// alt_block_data_t in the Monero codebase
///
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct AltBlock {
    /// height
    pub block_height: u64,
    /// cumulative_weight
    pub cumulative_weight: u64,
    /// cumulative_difficulty_low
    pub cumulative_difficulty_low: u64,
    /// cumulative_difficulty_high
    pub cumulative_difficulty_high: u64,
    /// already_generated_coins
    pub already_generated_coins: u64,
    /// the block - this is not in the struct alt_block_data_t
    /// however it is still in the table "alt_blocks"
    pub block: Block,
}

impl AltBlock {
    /// Returns the `total_coins_generated` field as [`Amount`]
    pub fn get_coins_generated_as_amount(&self) -> Amount {
        Amount::from_pico(self.already_generated_coins)
    }

    /// Returns the cumulative difficulty for this block
    pub fn cum_difficulty(&self) -> u128 {
        let mut ret: u128 = self.cumulative_difficulty_high as u128;
        ret <<= 64;
        ret | self.cumulative_difficulty_low as u128
    }
}

impl_consensus_encoding!(
    AltBlock,
    block_height,
    cumulative_weight,
    cumulative_difficulty_low,
    cumulative_difficulty_high,
    already_generated_coins,
    block
);

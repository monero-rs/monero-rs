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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
    pub fn cumulative_difficulty(&self) -> u128 {
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
/// This struct stores the alt block however alt_block_data_t in
/// the Monero codebase does not, this is done because the block
/// is still in the table alt_blocks.
///
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
    pub fn get_total_coins_generated_as_amount(&self) -> Amount {
        Amount::from_pico(self.already_generated_coins)
    }

    /// Returns the cumulative difficulty for this block
    pub fn cumulative_difficulty(&self) -> u128 {
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{
        consensus::{deserialize, serialize},
        database::block::BlockHeight,
        Hash,
    };

    use super::BlockInfo;

    #[test]
    fn test_ser_block_info() {
        let bytes = [
            50, 68, 42, 0, 0, 0, 0, 0, 176, 145, 140, 99, 0, 0, 0, 0, 98, 218, 225, 186, 8, 1, 180,
            252, 81, 84, 1, 0, 0, 0, 0, 0, 119, 64, 108, 206, 101, 202, 91, 3, 0, 0, 0, 0, 0, 0, 0,
            0, 173, 77, 90, 142, 119, 29, 98, 95, 222, 25, 30, 28, 223, 134, 138, 66, 0, 148, 65,
            190, 48, 139, 54, 84, 70, 107, 138, 53, 2, 220, 88, 114, 152, 72, 227, 3, 0, 0, 0, 0,
            86, 177, 2, 0, 0, 0, 0, 0,
        ];
        let block_info = deserialize::<BlockInfo>(&bytes).unwrap();
        let deserialized_block_info = BlockInfo {
            block_height: 2769970,
            timestamp: 1670156720,
            total_coins_generated: 18209180330372487778,
            weight: 87121,
            diff_lo: 242009543598162039,
            diff_hi: 0,
            block_hash: Hash::from_str(
                "ad4d5a8e771d625fde191e1cdf868a42009441be308b3654466b8a3502dc5872",
            )
            .unwrap(),
            cum_rct: 65226904,
            long_term_block_weight: 176470,
        };
        assert_eq!(block_info, deserialized_block_info);
        assert_eq!(block_info.cumulative_difficulty(), 242009543598162039);
        assert_eq!(serialize(&block_info), bytes);
    }

    #[test]
    fn test_ser_block_height() {
        let bytes = [
            173, 77, 90, 142, 119, 29, 98, 95, 222, 25, 30, 28, 223, 134, 138, 66, 0, 148, 65, 190,
            48, 139, 54, 84, 70, 107, 138, 53, 2, 220, 88, 114, 50, 68, 42, 0, 0, 0, 0, 0,
        ];
        let deserialized_block_height = BlockHeight {
            block_hash: Hash::from_str(
                "ad4d5a8e771d625fde191e1cdf868a42009441be308b3654466b8a3502dc5872",
            )
            .unwrap(),
            block_height: 2769970,
        };
        let block_height = deserialize::<BlockHeight>(&bytes).unwrap();
        assert_eq!(block_height, deserialized_block_height);
        assert_eq!(serialize(&block_height), bytes);
    }
}

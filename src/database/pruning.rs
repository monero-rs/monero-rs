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

//! Monero Pruning Scheme.
//!
//! This module contains functions to help with interacting with a pruned database or peer.
//!

use thiserror::Error;

/// The amount of blocks at the tip of the blockchain that don't get pruned
pub const CRYPTONOTE_PRUNING_TIP_BLOCKS: u64 = 5500;
/// log2 of the amount of "stripes" Monero uses for pruning (8)
pub const CRYPTONOTE_PRUNING_LOG_STRIPES: u32 = 3; // the higher, the more space saved

const CRYPTONOTE_PRUNING_STRIPE_SIZE: u64 = 4096; // the smaller, the smoother the increase

const PRUNING_SEED_LOG_STRIPES_SHIFT: u32 = 7;
const PRUNING_SEED_STRIPE_SHIFT: u32 = 0;
const PRUNING_SEED_LOG_STRIPES_MASK: u32 = 0x7;
const PRUNING_SEED_STRIPE_MASK: u32 = 127;

/// Pruning Errors
#[allow(missing_docs)]
#[derive(Error, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PruningError {
    /// Invalid log stripes.
    #[error("Invalid log stripes: {0}")]
    InvalidLogStripes(u32),
    /// Invalid stripe.
    #[error("Invalid stripe: {0}")]
    InvalidStripe(u32),
    /// Block Height Too High.
    #[error("Block height too high: {0}")]
    BlockHeightTooHigh(u64),
    /// Blockchain Height Too High.
    #[error("Blockchain height too high: {0}")]
    BlockchainHeightTooHigh(u64),
    /// h < Block height.
    #[error("h < Blockchain height. h: {h}, block height: {block_height}")]
    HIsLessThanBlockHeight { h: u64, block_height: u64 },
}

/// Makes a pruning seed for a specific pruning stripe.
///
/// The stripe must be between 0 and 2^log_stripes.
///
/// If you want to generate a pruning seed all you have to do is generate a
/// random number between 1 and 8 and pass it in as the stripe and pass in
/// [`CRYPTONOTE_PRUNING_LOG_STRIPES`] for the log stripes.
pub fn make_pruning_seed(stripe: u32, log_stripes: u32) -> Result<u32, PruningError> {
    if log_stripes > PRUNING_SEED_LOG_STRIPES_MASK {
        return Err(PruningError::InvalidLogStripes(log_stripes));
    }
    if !(stripe > 0 && stripe <= (1 << log_stripes)) {
        return Err(PruningError::InvalidStripe(stripe));
    }
    Ok((log_stripes << PRUNING_SEED_LOG_STRIPES_SHIFT)
        | ((stripe - 1) << PRUNING_SEED_STRIPE_SHIFT))
}

/// Gets the pruning stripe of a specific block.
///
/// The pruning stripe (for normal Monero pruning) is a number 1 to 8 which changes every [`CRYPTONOTE_PRUNING_STRIPE_SIZE`] blocks
/// so for blocks 0 to 4095 the pruning stripe is 1 then for 4096 to 8191 it is 2, looping
/// back to 1 when we reach block 32768.
///
/// For blocks where the block_height + [`CRYPTONOTE_PRUNING_TIP_BLOCKS`] >= blockchain_height
/// the pruning stripe is 0 meaning they shouldn't be pruned.
pub fn get_pruning_stripe_for_block(
    block_height: u64,
    blockchain_height: u64,
    log_stripes: u32,
) -> u32 {
    if block_height + CRYPTONOTE_PRUNING_TIP_BLOCKS >= blockchain_height {
        0
    } else {
        (((block_height / CRYPTONOTE_PRUNING_STRIPE_SIZE) & ((1 << log_stripes) - 1)) + 1) as u32
    }
}

/// Gets the pruning strip of a seed.
///
/// The pruning stripe for a normal Monero pruning seed is a number 1 to 8, it corresponds to the blocks you keep,
/// for example if the pruning stripe of a seed is 3 you would keep all blocks with
/// a block pruning stripe of 3 discarding the prunable data for all other blocks
/// (except blocks where the block_height + [`CRYPTONOTE_PRUNING_TIP_BLOCKS`] >= blockchain_height).
pub fn get_pruning_stripe_for_seed(pruning_seed: u32) -> u32 {
    if pruning_seed == 0 {
        0
    } else {
        1 + ((pruning_seed >> PRUNING_SEED_STRIPE_SHIFT) & PRUNING_SEED_STRIPE_MASK)
    }
}

/// Gets the pruning log stripes
///
/// will be [`CRYPTONOTE_PRUNING_LOG_STRIPES`] for default Monero pruning
pub fn get_pruning_log_stripes(pruning_seed: u32) -> u32 {
    (pruning_seed >> PRUNING_SEED_LOG_STRIPES_SHIFT) & PRUNING_SEED_LOG_STRIPES_MASK
}

/// Gets the pruning seed which corresponds to not pruning that block
///
/// for example for any block 0 to 4095 (with default pruning) this will return 384 as that is the seed that will
/// not prune those blocks.
///
/// Returns 0 if the block_height + [`CRYPTONOTE_PRUNING_TIP_BLOCKS`] >= blockchain_height.
pub fn get_pruning_seed_for_block(
    block_height: u64,
    blockchain_height: u64,
    log_stripes: u32,
) -> Result<u32, PruningError> {
    let stripe = get_pruning_stripe_for_block(block_height, blockchain_height, log_stripes);
    if stripe == 0 {
        Ok(0)
    } else {
        make_pruning_seed(stripe, log_stripes)
    }
}

/// Returns if the database pruned with a specific pruning seed contains an unpruned copy
/// of a specific block
pub fn has_unpruned_block(block_height: u64, blockchain_height: u64, pruning_seed: u32) -> bool {
    let stripe = get_pruning_stripe_for_seed(pruning_seed);
    if stripe == 0 {
        true
    } else {
        let log_stripes = get_pruning_log_stripes(pruning_seed);
        let block_stripe =
            get_pruning_stripe_for_block(block_height, blockchain_height, log_stripes);
        block_stripe == 0 || block_stripe == stripe
    }
}

/// Gets the next unpruned block given a specific block height, pruning seed and blockchain height
pub fn get_next_unpruned_block_height(
    block_height: u64,
    blockchain_height: u64,
    pruning_seed: u32,
) -> Result<u64, PruningError> {
    if block_height > super::CRYPTONOTE_MAX_BLOCK_NUMBER + 1 {
        return Err(PruningError::BlockHeightTooHigh(block_height));
    }
    if blockchain_height > super::CRYPTONOTE_MAX_BLOCK_NUMBER + 1 {
        return Err(PruningError::BlockHeightTooHigh(block_height));
    }
    let stripe = get_pruning_stripe_for_seed(pruning_seed);
    if stripe == 0 {
        Ok(block_height)
    } else if block_height + CRYPTONOTE_PRUNING_TIP_BLOCKS >= blockchain_height {
        return Ok(block_height);
    } else {
        let seed_log_stripes = get_pruning_log_stripes(pruning_seed);
        let mut log_stripes = seed_log_stripes;
        if log_stripes == 0 {
            log_stripes = CRYPTONOTE_PRUNING_LOG_STRIPES;
        }
        let mask: u64 = (1 << log_stripes) - 1;
        let block_pruning_stripe =
            (((block_height / CRYPTONOTE_PRUNING_STRIPE_SIZE) & mask) + 1) as u32;
        if block_pruning_stripe == stripe {
            return Ok(block_height);
        }
        let cycles = (block_height / CRYPTONOTE_PRUNING_STRIPE_SIZE) >> log_stripes;
        let mut cycles_start = cycles;
        if stripe <= block_pruning_stripe {
            cycles_start += 1;
        }
        let h = cycles_start * (CRYPTONOTE_PRUNING_STRIPE_SIZE << log_stripes as u64)
            + (stripe as u64 - 1) * CRYPTONOTE_PRUNING_STRIPE_SIZE;
        if h + CRYPTONOTE_PRUNING_TIP_BLOCKS > blockchain_height {
            if blockchain_height < CRYPTONOTE_PRUNING_TIP_BLOCKS {
                Ok(0)
            } else {
                Ok(block_height - CRYPTONOTE_PRUNING_TIP_BLOCKS)
            }
        } else {
            if h < block_height {
                return Err(PruningError::HIsLessThanBlockHeight { h, block_height });
            }
            Ok(h)
        }
    }
}

/// Gets the next pruned block given a specific block height, pruning seed and blockchain height
pub fn get_next_pruned_block_height(
    block_height: u64,
    blockchain_height: u64,
    pruning_seed: u32,
) -> Result<u64, PruningError> {
    let stripe = get_pruning_stripe_for_seed(pruning_seed);
    if stripe == 0 {
        Ok(blockchain_height)
    } else if block_height + CRYPTONOTE_PRUNING_TIP_BLOCKS >= blockchain_height {
        return Ok(blockchain_height);
    } else {
        let seed_log_stripes = get_pruning_log_stripes(pruning_seed);
        let mut log_stripes = seed_log_stripes;
        if log_stripes == 0 {
            log_stripes = CRYPTONOTE_PRUNING_LOG_STRIPES;
        }
        let mask: u64 = (1 << log_stripes) - 1;
        let block_pruning_seed =
            (((block_height / CRYPTONOTE_PRUNING_STRIPE_SIZE) & mask) + 1) as u32;
        if block_pruning_seed != stripe {
            Ok(block_height)
        } else {
            let next_stripe = 1 + (block_pruning_seed & mask as u32);
            get_next_unpruned_block_height(
                block_height,
                blockchain_height,
                make_pruning_seed(next_stripe, log_stripes)?,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::database::pruning::CRYPTONOTE_PRUNING_STRIPE_SIZE;

    use super::{
        get_next_pruned_block_height, get_next_unpruned_block_height, get_pruning_log_stripes,
        get_pruning_seed_for_block, get_pruning_stripe_for_block, get_pruning_stripe_for_seed,
        has_unpruned_block, make_pruning_seed, CRYPTONOTE_PRUNING_LOG_STRIPES,
    };

    #[test]
    fn test_make_pruning_seed() {
        let pruning_seed = make_pruning_seed(8, CRYPTONOTE_PRUNING_LOG_STRIPES).unwrap();
        assert_eq!(pruning_seed, 391);
        let pruning_seed = make_pruning_seed(1, CRYPTONOTE_PRUNING_LOG_STRIPES).unwrap();
        assert_eq!(pruning_seed, 384);
    }

    #[test]
    fn test_get_block_pruning_stripe() {
        let blockchain_height = 2500000;
        let block_pruning_stripe =
            get_pruning_stripe_for_block(0, blockchain_height, CRYPTONOTE_PRUNING_LOG_STRIPES);
        assert_eq!(block_pruning_stripe, 1);

        let block_pruning_stripe =
            get_pruning_stripe_for_block(4096, blockchain_height, CRYPTONOTE_PRUNING_LOG_STRIPES);
        assert_eq!(block_pruning_stripe, 2);

        let block_pruning_stripe =
            get_pruning_stripe_for_block(32768, blockchain_height, CRYPTONOTE_PRUNING_LOG_STRIPES);
        assert_eq!(block_pruning_stripe, 1);

        let block_pruning_stripe = get_pruning_stripe_for_block(
            2499900,
            blockchain_height,
            CRYPTONOTE_PRUNING_LOG_STRIPES,
        );
        assert_eq!(block_pruning_stripe, 0);
    }

    #[test]
    fn test_get_seed_pruning_stripe() {
        let seed_stripe = get_pruning_stripe_for_seed(384);
        assert_eq!(seed_stripe, 1);
        let seed_stripe = get_pruning_stripe_for_seed(385);
        assert_eq!(seed_stripe, 2);
        let seed_stripe = get_pruning_stripe_for_seed(386);
        assert_eq!(seed_stripe, 3);
        let seed_stripe = get_pruning_stripe_for_seed(387);
        assert_eq!(seed_stripe, 4);
        let seed_stripe = get_pruning_stripe_for_seed(388);
        assert_eq!(seed_stripe, 5);
        let seed_stripe = get_pruning_stripe_for_seed(389);
        assert_eq!(seed_stripe, 6);
        let seed_stripe = get_pruning_stripe_for_seed(390);
        assert_eq!(seed_stripe, 7);
        let seed_stripe = get_pruning_stripe_for_seed(391);
        assert_eq!(seed_stripe, 8);
    }

    #[test]
    fn test_get_pruning_log_stripes() {
        let pruning_seeds = [384, 385, 386, 387, 388, 389, 390, 391];
        for seed in pruning_seeds {
            assert_eq!(
                get_pruning_log_stripes(seed),
                CRYPTONOTE_PRUNING_LOG_STRIPES
            )
        }
    }

    #[test]
    fn test_get_pruning_seed() {
        let blockchain_height = 2500000;
        let block_pruning_stripe =
            get_pruning_seed_for_block(0, blockchain_height, CRYPTONOTE_PRUNING_LOG_STRIPES)
                .unwrap();
        assert_eq!(block_pruning_stripe, 384);

        let block_pruning_stripe =
            get_pruning_seed_for_block(4096, blockchain_height, CRYPTONOTE_PRUNING_LOG_STRIPES)
                .unwrap();
        assert_eq!(block_pruning_stripe, 385);

        let block_pruning_stripe =
            get_pruning_seed_for_block(32768, blockchain_height, CRYPTONOTE_PRUNING_LOG_STRIPES)
                .unwrap();
        assert_eq!(block_pruning_stripe, 384);

        let block_pruning_stripe =
            get_pruning_seed_for_block(2499900, blockchain_height, CRYPTONOTE_PRUNING_LOG_STRIPES)
                .unwrap();
        assert_eq!(block_pruning_stripe, 0);
    }

    #[test]
    fn test_has_unpruned_block() {
        let blockchain_height = 2500000;

        assert!(has_unpruned_block(0, blockchain_height, 384));
        assert!(!has_unpruned_block(4096, blockchain_height, 384));

        assert!(has_unpruned_block(4096, blockchain_height, 385));
        assert!(!has_unpruned_block(4096, blockchain_height, 391));

        assert!(has_unpruned_block(32768, blockchain_height, 384));

        let pruning_seeds = [384, 385, 386, 387, 388, 389, 390, 391];
        for seed in pruning_seeds {
            assert!(has_unpruned_block(2499900, blockchain_height, seed));
        }
    }

    #[test]
    fn test_get_next_unpruned_block_height() {
        let blockchain_height = 2500000;

        let pruning_seeds = [384, 385, 386, 387, 388, 389, 390, 391];
        let mut height = 0;
        for seed in pruning_seeds {
            assert_eq!(
                get_next_unpruned_block_height(0, blockchain_height, seed).unwrap(),
                height
            );
            height += CRYPTONOTE_PRUNING_STRIPE_SIZE;
        }
    }

    #[test]
    fn test_get_next_pruned_block_height() {
        let blockchain_height = 2500000;

        assert_eq!(
            get_next_pruned_block_height(0, blockchain_height, 384).unwrap(),
            4096
        );

        let pruning_seeds = [385, 386, 387, 388, 389, 390, 391];
        for seed in pruning_seeds {
            assert_eq!(
                get_next_pruned_block_height(0, blockchain_height, seed).unwrap(),
                0
            );
        }
    }
}

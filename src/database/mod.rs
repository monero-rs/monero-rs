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

//! Monero database structures.
//!
//! This module contains structures for interacting with a version 5 Monero database
//! previous versions are not supported.
//!

/// The maximum Monero block number as defined here:
/// https://github.com/monero-project/monero/blob/abe74fda35621f9895439379eb7e49b586fb0edb/src/cryptonote_config.h#L39
pub const CRYPTONOTE_MAX_BLOCK_NUMBER: u64 = 500000000;

pub mod block;
pub mod pruning;
pub mod transaction;

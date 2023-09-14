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

//! Utility functions to manipulate addresses, amounts, keys, or ringct data types.
//!
//! Shared functions needed in different part of the library or utility types for external
//! integrations.
//!

/// Public 'address' module
pub mod address;
/// Public 'amount' module
pub mod amount;
/// Public 'key' module
pub mod key;
/// Public 'ringct' module
pub mod ringct;
/// Public 'test_utils' module
pub mod test_utils;

use crate::blockdata::transaction::TransactionError;
use crate::network::NetworkError;
use crate::util::address::AddressError;
use crate::util::amount::AmountParsingError;
use crate::util::key::KeyError;
use crate::util::ringct::RingCtError;
use thiserror::Error;

/// A general error code, other errors should implement conversions to/from this if appropriate.
#[derive(Error, Debug, PartialEq)]
pub enum GeneralError {
    /// Monero network error.
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),
    /// Monero address error.
    #[error("Address error: {0}")]
    Address(#[from] AddressError),
    /// Monero key error.
    #[error("Key error: {0}")]
    Key(#[from] KeyError),
    /// Monero RingCt error.
    #[error("RingCt error: {0}")]
    RingCt(#[from] RingCtError),
    /// Monero transaction error.
    #[error("Transaction error: {0}")]
    Transaction(#[from] TransactionError),
    /// Monero amount parsing error.
    #[error("Amount parsing error: {0}")]
    AmountParsing(#[from] AmountParsingError),
}

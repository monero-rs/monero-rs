// Rust Monero Library
// Written in 2021 by
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

//! Amounts errors and helpers.

use thiserror::Error;

/// Potential errors encountered when recovering the amount of a transaction.
#[derive(Error, Debug, PartialEq)]
pub enum RecoveryError {
    /// Index of output is out of range.
    #[error("The index is out of range")]
    IndexOutOfRange,
    /// Missing signature for the output.
    #[error("Missing signature for the output")]
    MissingSignature,
    /// Invalid commitment.
    #[error("Invalid commitment")]
    InvalidCommitment,
}

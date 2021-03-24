//! Amounts

use thiserror::Error;

/// Error recovering the amount of a transaction
#[derive(Error, Debug, PartialEq)]
pub enum RecoveryError {
    /// Index of output is out of range
    #[error("The index is out of range")]
    IndexOutOfRange,
    /// Missing signature for the output
    #[error("Missing signature for the output")]
    MissingSignature,
    /// Invalid commitment
    #[error("Invalid commitment")]
    FalsifiedAmount,
}

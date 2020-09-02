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

//! # Rust Monero Library
//!
//! This is a library for which supports subsets of the Monero network protocol
//! and associated primitives. It is designed for Rust programs built to work with
//! the Monero network.
//!
//! It is also written entirely in Rust and is should compatible with `wasm32`
//! target to power web-based application with the benefits of strong type
//! safety, including ownership and lifetime, for financial and/or cryptographic
//! software.
//!
//! ## Caution
//!
//! The Software is provided “as is”, without warranty of any kind, express or
//! implied, including but not limited to the warranties of merchantability,
//! fitness for a particular purpose and noninfringement. In no event shall the
//! authors or copyright holders be liable for any claim, damages or other
//! liability, whether in an action of contract, tort or otherwise, arising
//! from, out of or in connection with the software or the use or other dealings
//! in the Software.
//!

// Coding conventions
#![forbid(unsafe_code)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(unused_mut)]
#![deny(missing_docs)]

#[macro_use]
mod internal_macros;
#[macro_use]
pub mod consensus;
pub mod blockdata;
pub mod cryptonote;
pub mod network;
pub mod util;

pub use blockdata::transaction::OwnedTxOut;
pub use blockdata::transaction::Transaction;
pub use blockdata::transaction::TxOut;
pub use network::Network;
pub use util::address::Address;
pub use util::key::PrivateKey;
pub use util::key::PublicKey;

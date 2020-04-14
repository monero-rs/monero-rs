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

//! Utility functions
//!
//! Shared functions needed in different part of the library.
//!

pub mod address;
pub mod key;
pub mod ringct;

use super::network;

/// A general error code, other errors should implement conversions to/from this
/// if appropriate.
#[derive(Fail, Debug, PartialEq)]
pub enum Error {
    /// Monero network error
    #[fail(display = "Network error: {:?}", _0)]
    Network(network::Error),
    /// Monero address error
    #[fail(display = "Address error: {:?}", _0)]
    Address(address::Error),
    /// Monero key error
    #[fail(display = "Key error: {:?}", _0)]
    Key(key::Error),
}

#[doc(hidden)]
impl From<network::Error> for Error {
    fn from(e: network::Error) -> Error {
        Error::Network(e)
    }
}

#[doc(hidden)]
impl From<address::Error> for Error {
    fn from(e: address::Error) -> Error {
        Error::Address(e)
    }
}

#[doc(hidden)]
impl From<key::Error> for Error {
    fn from(e: key::Error) -> Error {
        Error::Key(e)
    }
}

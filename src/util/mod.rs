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

use std::{error, fmt};

use super::network;

/// A general error code, other errors should implement conversions to/from this
/// if appropriate.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Monero network error
    Network(network::Error),
    /// Monero address error
    Address(address::Error),
    /// Monero key error
    Key(key::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Network(ref e) => fmt::Display::fmt(e, f),
            Error::Address(ref e) => fmt::Display::fmt(e, f),
            Error::Key(ref e) => fmt::Display::fmt(e, f),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::Network(ref e) => Some(e),
            Error::Address(ref e) => Some(e),
            Error::Key(ref e) => Some(e),
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::Network(ref e) => e.description(),
            Error::Address(ref e) => e.description(),
            Error::Key(ref e) => e.description(),
        }
    }
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

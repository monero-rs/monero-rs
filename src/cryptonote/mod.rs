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

//! CryptoNote primitive types and helper functions to hash, generate one-time addresses, or
//! manipulate sub-addresses.
//!
//! This module support CryptoNote protocols such as 'hash to number' [`Hn()`] with
//! [`hash::Hashable`], One-time keys, and Subaddresses.
//!
//! [`Hn()`]: hash::Hashable::hash_to_scalar()
//!

pub mod hash;
pub mod onetime_key;
pub mod subaddress;

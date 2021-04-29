// Rust Monero Library
// Written in 2021 by monero-rs contributors
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

//! Implements `StrictEncode` and `StrictDecode` for a few types that already implement consensus
//! [`Encodable`] and [`Decodable`].
//!
//! `strict_encoding` is a wrapper that allows multiple consensus encoding to work under the same
//! interface.

use crate::blockdata::block::{Block, BlockHeader};
use crate::blockdata::transaction::TransactionPrefix;
use crate::consensus::encode::{Decodable, Encodable, Error};
use crate::cryptonote::hash::{Hash, Hash8};
use crate::{PrivateKey, PublicKey, Transaction, TxIn, TxOut};

pub extern crate strict_encoding;

macro_rules! impl_strict_encoding {
    ( $thing:ident ) => {
        impl strict_encoding::StrictEncode for $thing {
            #[inline]
            fn strict_encode<E: std::io::Write>(
                &self,
                mut e: E,
            ) -> Result<usize, strict_encoding::Error> {
                self.consensus_encode(&mut e)
                    .map_err(strict_encoding::Error::from)
            }
        }

        impl strict_encoding::StrictDecode for $thing {
            #[inline]
            fn strict_decode<D: std::io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
                Ok(Self::consensus_decode(&mut d)
                    .map_err($crate::consensus::encode::Error::from)?)
            }
        }
    };
}

impl_strict_encoding!(PublicKey);
impl_strict_encoding!(PrivateKey);
impl_strict_encoding!(Transaction);
impl_strict_encoding!(TransactionPrefix);
impl_strict_encoding!(TxIn);
impl_strict_encoding!(TxOut);
impl_strict_encoding!(Block);
impl_strict_encoding!(BlockHeader);
impl_strict_encoding!(Hash);
impl_strict_encoding!(Hash8);

impl From<Error> for strict_encoding::Error {
    #[inline]
    fn from(e: Error) -> Self {
        strict_encoding::Error::DataIntegrityError(e.to_string())
    }
}

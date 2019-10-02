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

//! Internal Macros
//!
//! Macros meant to be used inside the Rust Monero library

macro_rules! impl_consensus_encoding {
    ( $thing:ident, $($field:ident),+ ) => (
        impl<S: crate::consensus::encode::Encoder> crate::consensus::encode::Encodable<S> for $thing {
            #[inline]
            fn consensus_encode(&self, s: &mut S) -> Result<(), crate::consensus::encode::Error> {
                $( self.$field.consensus_encode(s)?; )+
                Ok(())
            }
        }

        impl<D: crate::consensus::encode::Decoder> crate::consensus::encode::Decodable<D> for $thing {
            #[inline]
            fn consensus_decode(d: &mut D) -> Result<$thing, crate::consensus::encode::Error> {
                use crate::consensus::encode::Decodable;
                Ok($thing {
                    $( $field: Decodable::consensus_decode(d)?, )+
                })
            }
        }
    );
}

macro_rules! impl_hex_display {
    ( $data:ident, $field:ident ) => {
        impl fmt::Debug for $data {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{}", hex::encode(&self.$field[..]))
            }
        }

        impl fmt::Display for $data {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{}", hex::encode(&self.$field[..]))
            }
        }
    };
}

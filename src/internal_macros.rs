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
        #[sealed::sealed]
        impl $crate::consensus::encode::Encodable for $thing {
            #[inline]
            fn consensus_encode<S: ::std::io::Write>(
                &self,
                s: &mut S
            ) -> Result<usize, ::std::io::Error> {
                let mut len = 0;
                $( len += self.$field.consensus_encode(s)?; )+
                Ok(len)
            }
        }

        impl $crate::consensus::encode::Decodable for $thing {
            #[inline]
            fn consensus_decode<D: ::std::io::Read>(
                d: &mut D
            ) -> Result<$thing, $crate::consensus::encode::Error> {
                Ok($thing {
                    $( $field: crate::consensus::encode::Decodable::consensus_decode(d)?, )+
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

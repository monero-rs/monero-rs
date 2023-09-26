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

//! Internal Macros
//!
//! Macros meant to be used inside the Rust Monero library

macro_rules! impl_consensus_encoding {
    ( $thing:ident, $($field:ident),+ ) => (
        #[sealed::sealed]
        impl $crate::consensus::encode::Encodable for $thing {
            #[inline]
            fn consensus_encode<W: ::std::io::Write + ?Sized>(
                &self,
                w: &mut W
            ) -> Result<usize, ::std::io::Error> {
                let mut len = 0;
                $( len += self.$field.consensus_encode(w)?; )+
                Ok(len)
            }
        }

        impl $crate::consensus::encode::Decodable for $thing {
            #[inline]
            fn consensus_decode<R: ::std::io::Read + ?Sized>(
                r: &mut R,
            ) -> Result<$thing, $crate::consensus::encode::EncodeError> {
                Ok($thing {
                    $( $field: crate::consensus::encode::Decodable::consensus_decode(r)?, )+
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

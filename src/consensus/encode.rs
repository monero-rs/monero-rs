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

//! Consensus-encodable types and errors.
//!
//! This represent the core logic for (de)serializing object to conform to Monero consensus.
//! Essentially, anything that must go on the -disk- or -network- must be encoded using the
//! [`Encodable`] trait, since this data must be the same for all systems.
//!
//! The major change with `rust-bitcoin` implementation is [`VarInt`] that use the 7 least
//! significant bits to encode the number and the most significant as a flag if an other byte is
//! following.
//!

use hex::encode as hex_encode;

use std::io::{Cursor, Read, Write};
use std::ops::Deref;
use std::{fmt, io, mem, u32};

use thiserror::Error;

use super::endian;
use crate::blockdata::transaction;
use crate::util::{key, ringct};

#[cfg(feature = "serde_support")]
use serde::{Deserialize, Serialize};

/// Errors encountered when encoding or decoding data.
#[derive(Error, Debug)]
pub enum Error {
    /// And I/O error.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    /// Key error.
    #[error("Key error: {0}")]
    Key(#[from] key::Error),
    /// Transaction error.
    #[error("Transaction error: {0}")]
    Transaction(#[from] transaction::Error),
    /// RingCt error.
    #[error("RingCt error: {0}")]
    RingCt(#[from] ringct::Error),
    /// A generic parsing error.
    #[error("Parsing error: {0}")]
    ParseFailed(&'static str),
}

/// Encode an object into a vector of byte.
pub fn serialize<T: Encodable + std::fmt::Debug + ?Sized>(data: &T) -> Vec<u8> {
    let mut encoder = Vec::new();
    let len = data.consensus_encode(&mut encoder).unwrap();
    debug_assert_eq!(len, encoder.len());
    encoder
}

/// Encode an object into a hex-encoded string.
pub fn serialize_hex<T: Encodable + std::fmt::Debug + ?Sized>(data: &T) -> String {
    hex_encode(serialize(data))
}

/// Deserialize an object from a byte vector, will error if said deserialization doesn't consume
/// the entire vector.
pub fn deserialize<T: Decodable>(data: &[u8]) -> Result<T, Error> {
    let (rv, consumed) = deserialize_partial(data)?;

    // Fail if data are not consumed entirely.
    if consumed == data.len() {
        Ok(rv)
    } else {
        Err(Error::ParseFailed(
            "data not consumed entirely when explicitly deserializing",
        ))
    }
}

/// Deserialize an object from a vector, but will not report an error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize_partial<T: Decodable>(data: &[u8]) -> Result<(T, usize), Error> {
    let mut decoder = Cursor::new(data);
    let rv = Decodable::consensus_decode(&mut decoder)?;
    let consumed = decoder.position() as usize;

    Ok((rv, consumed))
}

/// Extensions of [`Write`] to encode data as per Monero consensus.
pub trait WriteExt {
    /// Output a 64-bit uint.
    fn emit_u64(&mut self, v: u64) -> Result<(), io::Error>;
    /// Output a 32-bit uint.
    fn emit_u32(&mut self, v: u32) -> Result<(), io::Error>;
    /// Output a 16-bit uint.
    fn emit_u16(&mut self, v: u16) -> Result<(), io::Error>;
    /// Output a 8-bit uint.
    fn emit_u8(&mut self, v: u8) -> Result<(), io::Error>;

    /// Output a 64-bit int.
    fn emit_i64(&mut self, v: i64) -> Result<(), io::Error>;
    /// Output a 32-bit int.
    fn emit_i32(&mut self, v: i32) -> Result<(), io::Error>;
    /// Output a 16-bit int.
    fn emit_i16(&mut self, v: i16) -> Result<(), io::Error>;
    /// Output a 8-bit int.
    fn emit_i8(&mut self, v: i8) -> Result<(), io::Error>;

    /// Output a boolean.
    fn emit_bool(&mut self, v: bool) -> Result<(), io::Error>;

    /// Output a byte slice.
    fn emit_slice(&mut self, v: &[u8]) -> Result<(), io::Error>;
}

/// Extensions of [`Read`] to decode data as per Monero consensus.
pub trait ReadExt {
    /// Read a 64-bit uint.
    fn read_u64(&mut self) -> Result<u64, Error>;
    /// Read a 32-bit uint.
    fn read_u32(&mut self) -> Result<u32, Error>;
    /// Read a 16-bit uint.
    fn read_u16(&mut self) -> Result<u16, Error>;
    /// Read a 8-bit uint.
    fn read_u8(&mut self) -> Result<u8, Error>;

    /// Read a 64-bit int.
    fn read_i64(&mut self) -> Result<i64, Error>;
    /// Read a 32-bit int.
    fn read_i32(&mut self) -> Result<i32, Error>;
    /// Read a 16-bit int.
    fn read_i16(&mut self) -> Result<i16, Error>;
    /// Read a 8-bit int.
    fn read_i8(&mut self) -> Result<i8, Error>;

    /// Read a boolean.
    fn read_bool(&mut self) -> Result<bool, Error>;

    /// Read a byte slice.
    fn read_slice(&mut self, slice: &mut [u8]) -> Result<(), Error>;
}

macro_rules! encoder_fn {
    ($name:ident, $val_type:ty, $writefn:ident) => {
        #[inline]
        fn $name(&mut self, v: $val_type) -> Result<(), io::Error> {
            self.write_all(&endian::$writefn(v))
        }
    };
}

macro_rules! decoder_fn {
    ($name:ident, $val_type:ty, $readfn:ident, $byte_len: expr) => {
        #[inline]
        fn $name(&mut self) -> Result<$val_type, Error> {
            let mut val = [0; $byte_len];
            self.read_exact(&mut val[..]).map_err(Error::Io)?;
            Ok(endian::$readfn(&val))
        }
    };
}

impl<W: Write> WriteExt for W {
    encoder_fn!(emit_u64, u64, u64_to_array_le);
    encoder_fn!(emit_u32, u32, u32_to_array_le);
    encoder_fn!(emit_u16, u16, u16_to_array_le);
    encoder_fn!(emit_i64, i64, i64_to_array_le);
    encoder_fn!(emit_i32, i32, i32_to_array_le);
    encoder_fn!(emit_i16, i16, i16_to_array_le);

    #[inline]
    fn emit_i8(&mut self, v: i8) -> Result<(), io::Error> {
        self.write_all(&[v as u8])
    }

    #[inline]
    fn emit_u8(&mut self, v: u8) -> Result<(), io::Error> {
        self.write_all(&[v])
    }

    #[inline]
    fn emit_bool(&mut self, v: bool) -> Result<(), io::Error> {
        self.write_all(&[v as u8])
    }

    #[inline]
    fn emit_slice(&mut self, v: &[u8]) -> Result<(), io::Error> {
        self.write_all(v)
    }
}

impl<R: Read> ReadExt for R {
    decoder_fn!(read_u64, u64, slice_to_u64_le, 8);
    decoder_fn!(read_u32, u32, slice_to_u32_le, 4);
    decoder_fn!(read_u16, u16, slice_to_u16_le, 2);
    decoder_fn!(read_i64, i64, slice_to_i64_le, 8);
    decoder_fn!(read_i32, i32, slice_to_i32_le, 4);
    decoder_fn!(read_i16, i16, slice_to_i16_le, 2);

    #[inline]
    fn read_u8(&mut self) -> Result<u8, Error> {
        let mut slice = [0u8; 1];
        self.read_exact(&mut slice)?;
        Ok(slice[0])
    }

    #[inline]
    fn read_i8(&mut self) -> Result<i8, Error> {
        let mut slice = [0u8; 1];
        self.read_exact(&mut slice)?;
        Ok(slice[0] as i8)
    }

    #[inline]
    fn read_bool(&mut self) -> Result<bool, Error> {
        ReadExt::read_i8(self).map(|bit| bit != 0)
    }

    #[inline]
    fn read_slice(&mut self, slice: &mut [u8]) -> Result<(), Error> {
        self.read_exact(slice).map_err(Error::Io)
    }
}

/// Data which can be encoded in a consensus-consistent way.
pub trait Encodable {
    /// Encode an object with a well-defined format, should only ever error if the underlying
    /// Encoder errors.
    ///
    /// The only errors returned are errors propagated from the writer.
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error>;
}

/// Data which can be decoded in a consensus-consistent way.
pub trait Decodable: Sized {
    /// Decode an object with a well-defined format.
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, Error>;
}

/// A variable-length unsigned integer type as defined by the Monero codebase.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Default)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct VarInt(pub u64);

impl fmt::Display for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Deref for VarInt {
    type Target = u64;

    fn deref(&self) -> &u64 {
        &self.0
    }
}

// Primitive types
macro_rules! impl_int_encodable {
    ($ty:ident, $meth_dec:ident, $meth_enc:ident) => {
        impl Decodable for $ty {
            #[inline]
            fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, Error> {
                ReadExt::$meth_dec(d).map($ty::from_le)
            }
        }
        impl Encodable for $ty {
            #[inline]
            fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
                s.$meth_enc(self.to_le())?;
                Ok(mem::size_of::<$ty>())
            }
        }
    };
}

impl_int_encodable!(u8, read_u8, emit_u8);
impl_int_encodable!(u16, read_u16, emit_u16);
impl_int_encodable!(u32, read_u32, emit_u32);
impl_int_encodable!(u64, read_u64, emit_u64);
impl_int_encodable!(i8, read_i8, emit_i8);
impl_int_encodable!(i16, read_i16, emit_i16);
impl_int_encodable!(i32, read_i32, emit_i32);
impl_int_encodable!(i64, read_i64, emit_i64);

impl Encodable for VarInt {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        let mut res: Vec<u8> = vec![];
        let mut n = self.0;
        loop {
            let bits = (n & 0b0111_1111) as u8;
            n >>= 7;
            res.push(bits);
            if n == 0u64 {
                break;
            }
        }
        match res.split_last() {
            Some((last, arr)) => {
                let a: Result<Vec<_>, io::Error> = arr
                    .iter()
                    .map(|bits| s.emit_u8(*bits | 0b1000_0000))
                    .collect();
                let len = a?.len();
                s.emit_u8(*last)?;
                Ok(len + 1)
            }
            None => {
                s.emit_u8(0x00)?;
                Ok(1)
            }
        }
    }
}

impl Decodable for VarInt {
    #[inline]
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, Error> {
        let mut res: Vec<u8> = vec![];
        loop {
            let n = d.read_u8()?;
            res.push(n & 0b0111_1111);
            if n & 0b1000_0000 == 0 {
                break;
            }
        }
        let mut int = 0u64;
        res.reverse();
        let (last, arr) = res.split_last().unwrap();
        arr.iter().for_each(|bits| {
            int |= *bits as u64;
            int <<= 7;
        });
        int |= *last as u64;
        Ok(VarInt(int))
    }
}

// Booleans
impl Encodable for bool {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        s.emit_bool(*self)?;
        Ok(1)
    }
}

impl Decodable for bool {
    #[inline]
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<bool, Error> {
        ReadExt::read_bool(d)
    }
}

// Strings
impl Encodable for String {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        let b = self.as_bytes();
        let vi_len = VarInt(b.len() as u64).consensus_encode(s)?;
        s.emit_slice(&b)?;
        Ok(vi_len + b.len())
    }
}

impl Decodable for String {
    #[inline]
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<String, Error> {
        String::from_utf8(Decodable::consensus_decode(d)?)
            .map_err(|_| self::Error::ParseFailed("String was not valid UTF8"))
    }
}

// Arrays
macro_rules! impl_array {
    ( $size:expr ) => {
        impl<T: Encodable> Encodable for [T; $size] {
            #[inline]
            fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
                let mut len = 0;
                for i in self.iter() {
                    len += i.consensus_encode(s)?;
                }
                Ok(len)
            }
        }

        impl<T: Decodable + Copy> Decodable for [T; $size] {
            #[inline]
            fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, Error> {
                // Set everything to the first decode
                let mut ret = [Decodable::consensus_decode(d)?; $size];
                // Set the rest
                for item in ret.iter_mut().take($size).skip(1) {
                    *item = Decodable::consensus_decode(d)?;
                }
                Ok(ret)
            }
        }
    };
}

impl_array!(8);
impl_array!(32);
impl_array!(64);

// Encode a slice
impl<T: Encodable> Encodable for [T] {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        let mut len = VarInt(self.len() as u64).consensus_encode(s)?;
        for c in self.iter() {
            len += c.consensus_encode(s)?;
        }
        Ok(len)
    }
}

// Cannot decode a slice

// Vectors
impl<T: Encodable> Encodable for Vec<T> {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        (&self[..]).consensus_encode(s)
    }
}

impl<T: Decodable> Decodable for Vec<T> {
    #[inline]
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, Error> {
        let len = VarInt::consensus_decode(d)?.0;
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(d)?);
        }
        Ok(ret)
    }
}

macro_rules! decode_sized_vec {
    ( $size:expr, $d:expr ) => {{
        let mut ret = Vec::with_capacity($size as usize);
        for _ in 0..$size {
            ret.push(Decodable::consensus_decode($d)?);
        }
        ret
    }};
}

macro_rules! encode_sized_vec {
    ( $vec:expr, $s:expr ) => {{
        let mut len = 0;
        for c in $vec.iter() {
            len += c.consensus_encode($s)?;
        }
        len
    }};
}

impl<T: Encodable> Encodable for Box<[T]> {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        (&self[..]).consensus_encode(s)
    }
}

impl<T: Decodable> Decodable for Box<[T]> {
    #[inline]
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, Error> {
        let len = VarInt::consensus_decode(d)?.0;
        let len = len as usize;
        let mut ret = Vec::with_capacity(len);
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(d)?);
        }
        Ok(ret.into_boxed_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::VarInt;
    use super::{deserialize, serialize};

    #[test]
    fn deserialize_varint() {
        let int: VarInt = deserialize(&[0b000_0001]).unwrap();
        assert_eq!(VarInt(1), int);

        let int: VarInt = deserialize(&[0b1010_1100, 0b0000_0010]).unwrap();
        assert_eq!(VarInt(300), int);
    }

    #[test]
    fn serialize_varint() {
        assert_eq!(vec![0b000_0001], serialize(&VarInt(1)));
        assert_eq!(vec![0b1010_1100, 0b0000_0010], serialize(&VarInt(300)));
        assert_eq!("80e497d012", hex::encode(serialize(&VarInt(5000000000))));
    }
}

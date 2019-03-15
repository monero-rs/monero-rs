// Rust Monero Library
// Written in 2019 by
//   h4sh3d <h4sh3d@truelevel.io>
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

//! Consensus-encodable types
//!
//! This represent the core logic for (de)serializing object to conform to Monero consensus.
//! Essentially, anything that must go on the -disk- or -network- must be encoded using the
//! Encodable trait, since this data must be the same for all systems.
//!
//! The major change with `rust-bitcoin` implementation is `VarInt` that use the 7 least
//! significant bits to encode the number and the most significant as a flag if an other byte
//! is following.
//!

use std::u32;
use std::io;
use std::fmt;
use std::ops::Deref;
use std::io::{Cursor, Read, Write};
use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt};
use hex::encode as hex_encode;

use crate::util::{key, ringct};
use crate::blockdata::transaction;

/// Encoding error
#[derive(Debug)]
pub enum Error {
    /// And I/O error
    Io(io::Error),
    /// Key error
    Key(key::Error),
    /// Transaction error
    Transaction(transaction::Error),
    /// RingCT error
    RingCT(ringct::Error),
    /// Error from the `byteorder` crate
    ByteOrder(io::Error),
    /// Parsing error
    ParseFailed(&'static str),
}

#[doc(hidden)]
impl From<key::Error> for Error {
    fn from(e: key::Error) -> Error {
        Error::Key(e)
    }
}

#[doc(hidden)]
impl From<transaction::Error> for Error {
    fn from(e: transaction::Error) -> Error {
        Error::Transaction(e)
    }
}

#[doc(hidden)]
impl From<ringct::Error> for Error {
    fn from(e: ringct::Error) -> Error {
        Error::RingCT(e)
    }
}

/// Encode an object into a vector
pub fn serialize<T: ?Sized>(data: &T) -> Vec<u8>
     where T: Encodable<Cursor<Vec<u8>>>,
{
    let mut encoder = Cursor::new(vec![]);
    data.consensus_encode(&mut encoder).unwrap();
    encoder.into_inner()
}

/// Encode an object into a hex-encoded string
pub fn serialize_hex<T: ?Sized>(data: &T) -> String
     where T: Encodable<Cursor<Vec<u8>>>
{
    hex_encode(serialize(data))
}

/// Deserialize an object from a vector, will error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize<'a, T>(data: &'a [u8]) -> Result<T, Error>
     where T: Decodable<Cursor<&'a [u8]>>
{
    let (rv, consumed) = deserialize_partial(data)?;

    // Fail if data are not consumed entirely.
    if consumed == data.len() {
        Ok(rv)
    } else {
        Err(Error::ParseFailed("data not consumed entirely when explicitly deserializing"))
    }
}

/// Deserialize an object from a vector, but will not report an error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize_partial<'a, T>(data: &'a [u8]) -> Result<(T, usize), Error>
    where T: Decodable<Cursor<&'a [u8]>>
{
    let mut decoder = Cursor::new(data);
    let rv = Decodable::consensus_decode(&mut decoder)?;
    let consumed = decoder.position() as usize;

    Ok((rv, consumed))
}


/// A simple Encoder trait
pub trait Encoder {
    /// Output a 64-bit uint
    fn emit_u64(&mut self, v: u64) -> Result<(), Error>;
    /// Output a 32-bit uint
    fn emit_u32(&mut self, v: u32) -> Result<(), Error>;
    /// Output a 16-bit uint
    fn emit_u16(&mut self, v: u16) -> Result<(), Error>;
    /// Output a 8-bit uint
    fn emit_u8(&mut self, v: u8) -> Result<(), Error>;

    /// Output a 64-bit int
    fn emit_i64(&mut self, v: i64) -> Result<(), Error>;
    /// Output a 32-bit int
    fn emit_i32(&mut self, v: i32) -> Result<(), Error>;
    /// Output a 16-bit int
    fn emit_i16(&mut self, v: i16) -> Result<(), Error>;
    /// Output a 8-bit int
    fn emit_i8(&mut self, v: i8) -> Result<(), Error>;

    /// Output a boolean
    fn emit_bool(&mut self, v: bool) -> Result<(), Error>;
}

/// A simple Decoder trait
pub trait Decoder {
    /// Read a 64-bit uint
    fn read_u64(&mut self) -> Result<u64, Error>;
    /// Read a 32-bit uint
    fn read_u32(&mut self) -> Result<u32, Error>;
    /// Read a 16-bit uint
    fn read_u16(&mut self) -> Result<u16, Error>;
    /// Read a 8-bit uint
    fn read_u8(&mut self) -> Result<u8, Error>;

    /// Read a 64-bit int
    fn read_i64(&mut self) -> Result<i64, Error>;
    /// Read a 32-bit int
    fn read_i32(&mut self) -> Result<i32, Error>;
    /// Read a 16-bit int
    fn read_i16(&mut self) -> Result<i16, Error>;
    /// Read a 8-bit int
    fn read_i8(&mut self) -> Result<i8, Error>;

    /// Read a boolean
    fn read_bool(&mut self) -> Result<bool, Error>;
}

macro_rules! encoder_fn {
    ($name:ident, $val_type:ty, $writefn:ident) => {
        #[inline]
        fn $name(&mut self, v: $val_type) -> Result<(), Error> {
            WriteBytesExt::$writefn::<LittleEndian>(self, v).map_err(Error::Io)
        }
    }
}

macro_rules! decoder_fn {
    ($name:ident, $val_type:ty, $readfn:ident) => {
        #[inline]
        fn $name(&mut self) -> Result<$val_type, Error> {
            ReadBytesExt::$readfn::<LittleEndian>(self).map_err(Error::Io)
        }
    }
}

impl<W: Write> Encoder for W {
    encoder_fn!(emit_u64, u64, write_u64);
    encoder_fn!(emit_u32, u32, write_u32);
    encoder_fn!(emit_u16, u16, write_u16);
    encoder_fn!(emit_i64, i64, write_i64);
    encoder_fn!(emit_i32, i32, write_i32);
    encoder_fn!(emit_i16, i16, write_i16);

    #[inline]
    fn emit_i8(&mut self, v: i8) -> Result<(), Error> {
        self.write_i8(v).map_err(Error::Io)
    }
    #[inline]
    fn emit_u8(&mut self, v: u8) -> Result<(), Error> {
        self.write_u8(v).map_err(Error::Io)
    }
    #[inline]
    fn emit_bool(&mut self, v: bool) -> Result<(), Error> {
        self.write_i8(if v {1} else {0}).map_err(Error::Io)
    }
}

impl<R: Read> Decoder for R {
    decoder_fn!(read_u64, u64, read_u64);
    decoder_fn!(read_u32, u32, read_u32);
    decoder_fn!(read_u16, u16, read_u16);
    decoder_fn!(read_i64, i64, read_i64);
    decoder_fn!(read_i32, i32, read_i32);
    decoder_fn!(read_i16, i16, read_i16);

    #[inline]
    fn read_u8(&mut self) -> Result<u8, Error> {
        ReadBytesExt::read_u8(self).map_err(Error::Io)
    }
    #[inline]
    fn read_i8(&mut self) -> Result<i8, Error> {
        ReadBytesExt::read_i8(self).map_err(Error::Io)
    }
    #[inline]
    fn read_bool(&mut self) -> Result<bool, Error> {
        Decoder::read_i8(self).map(|bit| bit != 0)
    }
}

/// Data which can be encoded in a consensus-consistent way
pub trait Encodable<S: Encoder> {
    /// Encode an object with a well-defined format, should only ever error if
    /// the underlying Encoder errors.
    fn consensus_encode(&self, e: &mut S) -> Result<(), self::Error>;
}

/// Data which can be encoded in a consensus-consistent way
pub trait Decodable<D: Decoder>: Sized {
    /// Decode an object with a well-defined format
    fn consensus_decode(d: &mut D) -> Result<Self, self::Error>;
}

/// A variable-length unsigned integer
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
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
macro_rules! impl_int_encodable{
    ($ty:ident, $meth_dec:ident, $meth_enc:ident) => (
        impl<D: Decoder> Decodable<D> for $ty {
            #[inline]
            fn consensus_decode(d: &mut D) -> Result<$ty, self::Error> { d.$meth_dec().map($ty::from_le) }
        }

        impl<S: Encoder> Encodable<S> for $ty {
            #[inline]
            fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> { s.$meth_enc(self.to_le()) }
        }
    )
}

impl_int_encodable!(u8,  read_u8,  emit_u8);
impl_int_encodable!(u16, read_u16, emit_u16);
impl_int_encodable!(u32, read_u32, emit_u32);
impl_int_encodable!(u64, read_u64, emit_u64);
impl_int_encodable!(i8,  read_i8,  emit_i8);
impl_int_encodable!(i16, read_i16, emit_i16);
impl_int_encodable!(i32, read_i32, emit_i32);
impl_int_encodable!(i64, read_i64, emit_i64);

impl<S: Encoder> Encodable<S> for VarInt {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> {
        let mut res: Vec<u8> = vec![];
        let mut n = self.0;
        loop {
            let bits = (n & 0b0111_1111) as u8;
            n = n >> 7;
            res.push(bits);
            if n == 0u64 { break }
        }
        match res.split_last() {
            Some((last, arr)) => {
                let a: Result<Vec<_>, self::Error> = arr.iter()
                    .map(|bits| s.emit_u8(*bits | 0b1000_0000))
                    .collect();
                a?;
                s.emit_u8(*last)
            },
            None => s.emit_u8(0x00),
        }
    }
}

impl<D: Decoder> Decodable<D> for VarInt {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<VarInt, self::Error> {
        let mut res: Vec<u8> = vec![];
        loop {
            let n = d.read_u8()?;
            res.push(n & 0b0111_1111);
            if n & 0b1000_0000 == 0 {
                break
            }
        }
        let mut int = 0u64;
        res.reverse();
        let (last, arr) = res.split_last().unwrap();
        arr.iter().for_each(|bits| {
            int = int | *bits as u64;
            int = int << 7;
        });
        int = int | *last as u64;
        Ok(VarInt(int))
    }
}

// Booleans
impl<S: Encoder> Encodable<S> for bool {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> { s.emit_u8(if *self {1} else {0}) }
}

impl<D: Decoder> Decodable<D> for bool {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<bool, self::Error> { d.read_u8().map(|n| n != 0) }
}

// Strings
impl<S: Encoder> Encodable<S> for String {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> {
        self.as_bytes().consensus_encode(s)
    }
}

impl<D: Decoder> Decodable<D> for String {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<String, self::Error> {
        String::from_utf8(Decodable::consensus_decode(d)?)
            .map_err(|_| self::Error::ParseFailed("String was not valid UTF8"))
    }
}


// Arrays
macro_rules! impl_array {
    ( $size:expr ) => (
        impl<S: Encoder, T: Encodable<S>> Encodable<S> for [T; $size] {
            #[inline]
            fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> {
                for i in self.iter() { i.consensus_encode(s)?; }
                Ok(())
            }
        }

        impl<D: Decoder, T:Decodable<D> + Copy> Decodable<D> for [T; $size] {
            #[inline]
            fn consensus_decode(d: &mut D) -> Result<[T; $size], self::Error> {
                // Set everything to the first decode
                let mut ret = [Decodable::consensus_decode(d)?; $size];
                // Set the rest
                for item in ret.iter_mut().take($size).skip(1) { *item = Decodable::consensus_decode(d)?; }
                Ok(ret)
            }
        }
    );
}

impl_array!(8);
impl_array!(32);
impl_array!(64);

impl<S: Encoder, T: Encodable<S>> Encodable<S> for [T] {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> {
        VarInt(self.len() as u64).consensus_encode(s)?;
        for c in self.iter() { c.consensus_encode(s)?; }
        Ok(())
    }
}

// Cannot decode a slice

// Vectors
impl<S: Encoder, T: Encodable<S>> Encodable<S> for Vec<T> {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> { (&self[..]).consensus_encode(s) }
}

impl<D: Decoder, T: Decodable<D>> Decodable<D> for Vec<T> {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<Vec<T>, self::Error> {
        let len = VarInt::consensus_decode(d)?.0;
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len { ret.push(Decodable::consensus_decode(d)?); }
        Ok(ret)
    }
}

macro_rules! decode_sized_vec {
    ( $size:expr, $d:expr ) => {
        {
            let mut ret = Vec::with_capacity($size as usize);
            for _ in 0..$size { ret.push(Decodable::consensus_decode($d)?); }
            ret
        }
    };
}

macro_rules! encode_sized_vec {
    ( $vec:expr, $s:expr ) => {
        {
            for c in $vec.iter() { c.consensus_encode($s)?; }
        }
    };
}

impl<S: Encoder, T: Encodable<S>> Encodable<S> for Box<[T]> {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> { (&self[..]).consensus_encode(s) }
}

impl<D: Decoder, T: Decodable<D>> Decodable<D> for Box<[T]> {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<Box<[T]>, self::Error> {
        let len = VarInt::consensus_decode(d)?.0;
        let len = len as usize;
        let mut ret = Vec::with_capacity(len);
        for _ in 0..len { ret.push(Decodable::consensus_decode(d)?); }
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

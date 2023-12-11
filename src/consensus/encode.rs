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

use std::convert::TryFrom;
use std::ops::Deref;
use std::{fmt, io, mem, u32};

use sealed::sealed;
use thiserror::Error;

use super::endian;
use crate::blockdata::transaction;
use crate::util::{address, key, ringct};

#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};

/// The maximum memory size of a vector that can be allocated during decoding.
pub const MAX_VEC_MEM_ALLOC_SIZE: usize = 32 * 1024 * 1024; // 32 MiB

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
    /// Address error.
    #[error("Address error: {0}")]
    Address(#[from] address::Error),
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
    let mut decoder = io::Cursor::new(data);
    let rv = Decodable::consensus_decode(&mut decoder)?;
    let consumed = decoder.position() as usize;

    Ok((rv, consumed))
}

/// Extensions of [`io::Write`] to encode data as per Monero consensus.
pub trait WriteExt: io::Write {
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

/// Extensions of [`io::Read`] to decode data as per Monero consensus.
pub trait ReadExt: io::Read {
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

impl<W: io::Write + ?Sized> WriteExt for W {
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

impl<R: io::Read + ?Sized> ReadExt for R {
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
///
/// ## Sealed trait
/// This trait is sealed and cannot be implemented for types outside of `monero` crate. This is
/// done to ensure implementations will not fail inconsistently and so unwrapping in [`serialize`]
/// is safe.
#[sealed(pub(crate))]
pub trait Encodable {
    /// Encode an object with a well-defined format, should only ever error if the underlying
    /// Encoder errors.
    ///
    /// The only errors returned are errors propagated from the writer.
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error>;
}

/// Data which can be decoded in a consensus-consistent way.
pub trait Decodable: Sized {
    /// Decode an object with a well-defined format.
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error>;
}

/// A variable-length unsigned integer type as defined by the Monero codebase.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
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
            fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
                ReadExt::$meth_dec(r).map($ty::from_le)
            }
        }
        #[sealed]
        impl Encodable for $ty {
            #[inline]
            fn consensus_encode<W: io::Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> Result<usize, io::Error> {
                w.$meth_enc(self.to_le())?;
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

#[sealed]
impl Encodable for VarInt {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
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
                    .map(|bits| w.emit_u8(*bits | 0b1000_0000))
                    .collect();
                let len = a?.len();
                w.emit_u8(*last)?;
                Ok(len + 1)
            }
            None => {
                w.emit_u8(0x00)?;
                Ok(1)
            }
        }
    }
}

impl Decodable for VarInt {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let mut res: Vec<u8> = vec![];
        loop {
            let n = r.read_u8()?;
            // Zero in any position other than the first is invalid
            // since it is not the shortest encoding.
            if n == 0 && !res.is_empty() {
                return Err(Error::ParseFailed("VarInt has a zero in a position other than the first. This is not the shortest encoding."));
            }
            res.push(n & 0b0111_1111);
            if n & 0b1000_0000 == 0 {
                break;
            }
        }
        let mut int = 0u64;
        res.reverse();
        let (last, arr) = res.split_last().unwrap();
        for bits in arr {
            int |= *bits as u64;
            int = if int.leading_zeros() >= 7 {
                int << 7
            } else {
                return Err(Error::ParseFailed("VarInt overflows u64"));
            };
        }
        int |= *last as u64;
        Ok(VarInt(int))
    }
}

// Booleans
#[sealed]
impl Encodable for bool {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        w.emit_bool(*self)?;
        Ok(1)
    }
}

impl Decodable for bool {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<bool, Error> {
        ReadExt::read_bool(r)
    }
}

// Strings
#[sealed]
impl Encodable for String {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let b = self.as_bytes();
        let vi_len = VarInt(b.len() as u64).consensus_encode(w)?;
        w.emit_slice(b)?;
        Ok(vi_len + b.len())
    }
}

impl Decodable for String {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<String, Error> {
        String::from_utf8(Decodable::consensus_decode(r)?)
            .map_err(|_| self::Error::ParseFailed("String was not valid UTF8"))
    }
}

// Arrays
macro_rules! impl_array {
    ( $size:expr ) => {
        #[sealed]
        impl<T: Encodable> Encodable for [T; $size] {
            #[inline]
            fn consensus_encode<W: io::Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> Result<usize, io::Error> {
                let mut len = 0;
                for i in self.iter() {
                    len += i.consensus_encode(w)?;
                }
                Ok(len)
            }
        }

        impl<T: Decodable + Copy> Decodable for [T; $size] {
            #[inline]
            fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
                // Set everything to the first decode
                let mut ret = [Decodable::consensus_decode(r)?; $size];
                // Set the rest
                for item in ret.iter_mut().take($size).skip(1) {
                    *item = Decodable::consensus_decode(r)?;
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
#[sealed]
impl<T: Encodable> Encodable for [T] {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = VarInt(self.len() as u64).consensus_encode(w)?;
        for c in self.iter() {
            len += c.consensus_encode(w)?;
        }
        Ok(len)
    }
}

// Cannot decode a slice

// Vectors
#[sealed]
impl<T: Encodable> Encodable for Vec<T> {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self[..].consensus_encode(w)
    }
}

impl<T: Decodable> Decodable for Vec<T> {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let len_decoded = match VarInt::consensus_decode(r) {
            Ok(len) => len,
            Err(_) => {
                return Err(Error::ParseFailed(
                    "consensus_decode for Vec<T>: VarInt decoding failed",
                ))
            }
        };
        #[cfg(target_pointer_width = "64")]
        let len = usize::try_from(*len_decoded).expect("usize on 64-bit platforms equals u64");

        // Prevent allocations larger than the maximum allowed size
        let layout_size = mem::size_of::<T>().saturating_mul(len);
        if layout_size > MAX_VEC_MEM_ALLOC_SIZE {
            return Err(self::Error::ParseFailed(
                "consensus_decode for Vec<T>: length exceeds maximum allocatable bytes",
            ));
        }

        let mut ret = Vec::with_capacity(len);
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(r)?);
        }
        Ok(ret)
    }
}

/// Decode a vector of a given size
pub fn consensus_decode_sized_vec<R: io::Read + ?Sized, T: Decodable>(
    r: &mut R,
    size: usize,
) -> Result<Vec<T>, Error> {
    // Prevent allocations larger than the maximum allowed size
    let layout_size = mem::size_of::<T>().saturating_mul(size);
    if layout_size > MAX_VEC_MEM_ALLOC_SIZE {
        return Err(Error::ParseFailed(
            "consensus_decode_sized_vec: length exceeds maximum allocatable bytes",
        ));
    }
    let mut ret = Vec::with_capacity(size);
    for _ in 0..size {
        let item = Decodable::consensus_decode(r)?;
        ret.push(item);
    }
    Ok(ret)
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

#[sealed]
impl<T: Encodable> Encodable for Box<[T]> {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self[..].consensus_encode(w)
    }
}

impl<T: Decodable> Decodable for Box<[T]> {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let len_decoded = match VarInt::consensus_decode(r) {
            Ok(len) => len,
            Err(_) => {
                return Err(Error::ParseFailed(
                    "consensus_decode for Box<T>: VarInt decoding failed",
                ));
            }
        };
        #[cfg(target_pointer_width = "64")]
        let len = usize::try_from(*len_decoded).expect("usize on 64-bit platforms equals u64");

        // Prevent allocations larger than the maximum allowed size
        let layout_size = mem::size_of::<T>().saturating_mul(len);
        if layout_size > MAX_VEC_MEM_ALLOC_SIZE {
            return Err(Error::ParseFailed(
                "consensus_decode for Box<T>: length exceeds maximum allocatable bytes",
            ));
        }

        let mut ret = Vec::with_capacity(len);
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(r)?);
        }
        Ok(ret.into_boxed_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        consensus_decode_sized_vec, deserialize, serialize, Error, VarInt, MAX_VEC_MEM_ALLOC_SIZE,
    };
    use crate::blockdata::transaction::SubField;
    use crate::consensus::{serialize_hex, Decodable, Encodable, ReadExt, WriteExt};
    use crate::{Block, PublicKey, Transaction, TxIn};
    use std::io::Cursor;

    #[test]
    fn deserialize_varint() {
        let int: VarInt = deserialize(&[0b000_0001]).unwrap();
        assert_eq!(VarInt(1), int);

        let int: VarInt = deserialize(&[0b1010_1100, 0b0000_0010]).unwrap();
        assert_eq!(VarInt(300), int);

        let max = VarInt(u64::MAX);
        let mut max_u64_data = serialize(&max);
        let len_max = max_u64_data.len();
        let int: VarInt = deserialize(&max_u64_data).unwrap();
        assert_eq!(max, int);

        // varint must be shortest encoding
        let res = deserialize::<VarInt>(&[152, 0]);
        assert!(matches!(res.unwrap_err(), Error::ParseFailed(_)));

        // If the last number is not a 0, it will error with an IO error (UnexpectedEof)
        let res = deserialize::<VarInt>(&[255u8; 1]);
        assert!(matches!(res.unwrap_err(), Error::Io(_)));

        // Add one to the max u64 data.
        assert_eq!(max_u64_data[len_max - 1], 0x01);
        max_u64_data[len_max - 1] += 1;
        let res = deserialize::<VarInt>(&max_u64_data);
        assert!(matches!(res.unwrap_err(), Error::ParseFailed(_)));

        let res = deserialize::<VarInt>(&[
            255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 1u8,
        ]);
        assert!(matches!(res.unwrap_err(), Error::ParseFailed(_)));
    }

    #[test]
    fn serialize_varint() {
        assert_eq!(vec![0b000_0001], serialize(&VarInt(1)));
        assert_eq!(vec![0b1010_1100, 0b0000_0010], serialize(&VarInt(300)));
        assert_eq!("80e497d012", hex::encode(serialize(&VarInt(5000000000))));
    }

    #[test]
    fn deserialize_vec() {
        // First byte is len = 8
        let vec = [0x08u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let data = deserialize::<Vec<u8>>(&vec).unwrap();
        assert_eq!(data, vec[1..]);

        let vec = vec![
            [0u8; 64], [1u8; 64], [2u8; 64], [3u8; 64], [4u8; 64], [5u8; 64], [6u8; 64], [7u8; 64],
        ];
        let vec_buffer = serialize(&vec);
        let data = deserialize::<Vec<[u8; 64]>>(&vec_buffer).unwrap();
        assert_eq!(data, vec);

        let tx_in = serialize(&TxIn::Gen { height: VarInt(1) });
        // First byte is len = 8
        let mut vec = vec![0x08u8];
        for _ in 0..8 {
            vec.extend(tx_in.clone());
        }
        let tx_ins = deserialize::<Vec<TxIn>>(&vec).unwrap();
        assert!(tx_ins.iter().all(|t| *t == TxIn::Gen { height: VarInt(1) }));
    }
    #[test]
    fn deserialize_voc_with_inadequate_buffer() {
        let err = deserialize::<Vec<[u8; 64]>>(&[]).unwrap_err();
        assert!(matches!(err, Error::ParseFailed(_)));
        let len = VarInt(1);
        let data = serialize(&len);
        let err = deserialize::<Vec<[u8; 64]>>(&data).unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn deserialize_varint_with_empty_buffer() {
        let err = deserialize::<VarInt>(&[]).unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn deserialize_vec_max_allocation() {
        for length in (0..10).chain(
            (MAX_VEC_MEM_ALLOC_SIZE / 64) as u64 - 10..=(MAX_VEC_MEM_ALLOC_SIZE / 64) as u64 + 10,
        ) {
            let len = VarInt(length);
            let data = serialize(&len);
            let res = deserialize::<Vec<[u8; 64]>>(&data);
            if length == 0 {
                assert!(res.is_ok());
            } else {
                let err = res.unwrap_err();
                println!("length: {}, {:?}", length, err);
                if length <= (MAX_VEC_MEM_ALLOC_SIZE / 64) as u64 {
                    assert!(matches!(err, Error::Io(_)));
                } else {
                    assert!(matches!(err, Error::ParseFailed(_)));
                }
            }
        }

        let data_len = 100u64;
        let mut data = serialize(&VarInt(data_len));
        for i in 0..data_len {
            data.push((i % 255) as u8);
        }
        assert_eq!(data[1..], deserialize::<Vec<u8>>(&data[..]).unwrap());

        for length in (0..10)
            .chain(data_len - 10..=data_len + 10)
            .chain(MAX_VEC_MEM_ALLOC_SIZE as u64 - 10..=MAX_VEC_MEM_ALLOC_SIZE as u64 + 10)
        {
            let replace_len = VarInt(length);
            let replace_len_bytes = serialize(&replace_len);
            for (i, val) in replace_len_bytes.iter().enumerate() {
                data[i] = *val;
            }
            let res = deserialize::<Vec<u8>>(&data[..]);
            if length == data_len {
                assert!(res.is_ok());
            } else {
                let err = res.unwrap_err();
                println!("length: {}, {:?}", length, err);
                if length < data_len {
                    assert!(matches!(err, Error::ParseFailed(_)));
                } else if length <= MAX_VEC_MEM_ALLOC_SIZE as u64 {
                    assert!(matches!(err, Error::Io(_)));
                } else {
                    assert!(matches!(err, Error::ParseFailed(_)));
                }
            }
        }

        for length in u64::MAX - 10..=u64::MAX {
            let replace_len = VarInt(length);
            let replace_len_bytes = serialize(&replace_len);
            for (i, val) in replace_len_bytes.iter().enumerate() {
                data[i] = *val;
            }
            let res = deserialize::<Vec<u8>>(&data[..]);
            let err = res.unwrap_err();
            println!("length: {}, {:?}", length, err);
            assert!(matches!(err, Error::ParseFailed(_)));
        }
    }

    #[test]
    fn deserialize_boxed_vec_max_allocation() {
        let data_len = 100u64;
        let mut data = serialize(&VarInt(data_len));
        for i in 0..data_len {
            data.push((i % 255) as u8);
        }

        for length in (0..10)
            .chain(data_len - 10..=data_len + 10)
            .chain(MAX_VEC_MEM_ALLOC_SIZE as u64 - 10..=MAX_VEC_MEM_ALLOC_SIZE as u64 + 10)
        {
            let replace_len = VarInt(length);
            let replace_len_bytes = serialize(&replace_len);
            for (i, val) in replace_len_bytes.iter().enumerate() {
                data[i] = *val;
            }
            let res = deserialize::<Box<[u8]>>(&data[..]);
            if length == data_len {
                assert!(res.is_ok());
            } else {
                let err = res.unwrap_err();
                println!("length: {}, {:?}", length, err);
                if length < data_len {
                    assert!(matches!(err, Error::ParseFailed(_)));
                } else if length <= MAX_VEC_MEM_ALLOC_SIZE as u64 {
                    assert!(matches!(err, Error::Io(_)));
                } else {
                    assert!(matches!(err, Error::ParseFailed(_)));
                }
            }
        }

        for length in u64::MAX - 10..=u64::MAX {
            let replace_len = VarInt(length);
            let replace_len_bytes = serialize(&replace_len);
            for (i, val) in replace_len_bytes.iter().enumerate() {
                data[i] = *val;
            }
            let res = deserialize::<Box<[u8]>>(&data[..]);
            let err = res.unwrap_err();
            println!("length: {}, {:?}", length, err);
            assert!(matches!(err, Error::ParseFailed(_)));
        }
    }

    #[test]
    fn deserialize_vec_overflow_does_not_panic() {
        let overflow_len = VarInt((isize::MAX as u64 / 64) + 1);
        let data = serialize(&overflow_len);
        let err = deserialize::<Vec<[u8; 64]>>(&data).unwrap_err();
        assert!(matches!(err, Error::ParseFailed(_)));
    }

    #[test]
    fn deserialize_string_overflow_does_not_panic() {
        let overflow_len = VarInt(isize::MAX as u64 + 1);
        let data = serialize(&overflow_len);
        let err = deserialize::<String>(&data).unwrap_err();
        assert!(matches!(err, Error::ParseFailed(_)));
    }

    #[test]
    fn panic_alloc_capacity_overflow_moneroblock_deserialize() {
        // Reproducer for https://github.com/monero-rs/monero-rs/issues/46
        let data = [
            0x0f, 0x9e, 0xa5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x04, 0x00, 0x08, 0x9e, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
            0x04, 0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0xe7, 0xaa, 0xfd, 0x8b,
            0x47, 0x06, 0x8d, 0xed, 0xe3, 0x00, 0xed, 0x44, 0xfc, 0x77, 0xd6, 0x58, 0xf6, 0xf2,
            0x69, 0x06, 0x8d, 0xed, 0xe3, 0x00, 0xed, 0x44, 0xfc, 0x77, 0xd6, 0x58, 0xf6, 0xf2,
            0x69, 0x62, 0x38, 0xdb, 0x5e, 0x4d, 0x6d, 0x9c, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x0f, 0x00, 0x8f, 0x74, 0x3c, 0xb3, 0x1b, 0x6e, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
        ];
        let _ = deserialize::<Block>(&data);
    }

    #[test]
    fn code_coverage_error_path() {
        let err = Vec::<u64>::consensus_decode(&mut Cursor::new(&Vec::new())).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Parsing error: consensus_decode for Vec<T>: VarInt decoding failed"
        );

        let mut buffer = Vec::new();
        let mut encoder = Cursor::new(&mut buffer);
        let data: Vec<u64> = vec![12345; MAX_VEC_MEM_ALLOC_SIZE + 1];
        data.consensus_encode(&mut encoder).unwrap();
        let err = Vec::<u64>::consensus_decode(&mut Cursor::new(&buffer)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Parsing error: consensus_decode for Vec<T>: length exceeds maximum allocatable bytes"
        );

        let err = Box::<[u64]>::consensus_decode(&mut Cursor::new(&Vec::new())).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Parsing error: consensus_decode for Box<T>: VarInt decoding failed"
        );

        let mut buffer = Vec::new();
        let mut encoder = Cursor::new(&mut buffer);
        let data: Vec<u64> = vec![12345; MAX_VEC_MEM_ALLOC_SIZE + 1];
        let boxed: Box<[u64]> = data.into_boxed_slice();
        boxed.consensus_encode(&mut encoder).unwrap();
        let err = Box::<[u64]>::consensus_decode(&mut Cursor::new(&buffer)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Parsing error: consensus_decode for Box<T>: length exceeds maximum allocatable bytes"
        );

        let mut encoder = Cursor::new(vec![]);
        let mut _len = 0;
        for c in vec![SubField::MysteriousMinerGate(vec![]); MAX_VEC_MEM_ALLOC_SIZE + 1].iter() {
            _len += c.consensus_encode(&mut encoder).unwrap();
        }
        let err =
            consensus_decode_sized_vec::<_, SubField>(&mut encoder, MAX_VEC_MEM_ALLOC_SIZE + 1)
                .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Parsing error: consensus_decode_sized_vec: length exceeds maximum allocatable bytes"
        );

        let raw_tx = hex::decode("02000102000bb2e38c0189ea01a9bc02a533fe02a90705fd0540745f59f49374365304f8b4d5da63b444b2d74a40f8007ea44940c15cbbc80c9d106802000267f0f669ead579c1067cbffdf67c4af80b0287c549a10463122b4860fe215f490002b6a2e2f35a93d637ff7d25e20da326cee8e92005d3b18b3c425dabe8336568992c01d6c75cf8c76ac458123f2a498512eb65bb3cecba346c8fcfc516dc0c88518bb90209016f82359eb1fe71d604f0dce9470ed5fd4624bb9fce349a0e8317eabf4172f78a8b27dec6ea1a46da10ed8620fa8367c6391eaa8aabf4ebf660d9fe0eb7e9dfa08365a089ad2df7bce7ef776467898d5ca8947152923c54a1c5030e0c2f01035c555ff4285dcc44dfadd6bc37ec8b9354c045c6590446a81c7f53d8f199cace3faa7f17b3b8302a7cbb3881e8fdc23cca0275c9245fdc2a394b8d3ae73911e3541b10e7725cdeef5e0307bc218caefaafe97c102f39c8ce78f62cccf23c69baf0af55933c9d384ceaf07488f2f1ac7343a593449afd54d1065f6a1a4658845817e4b0e810afc4ca249096e463f9f368625fa37d5bbcbe87af68ce3c4d630f93a66defa4205b178f4e9fa04107bd535c7a4b2251df2dad255e470b611ffe00078c2916fc1eb2af1273e0df30dd1c74b6987b9885e7916b6ca711cbd4b7b50576e51af1439e9ed9e33eb97d8faba4e3bd46066a5026a1940b852d965c1db455d1401687ccaccc524e000b05966763564b7deb8fd64c7fb3d649897c94583dca1558893b071f5e6700dad139f3c6f973c7a43b207ee3e67dc7f7f18b52df442258200c7fe6d16685127da1df9b0d93d764c2659599bc6d300ae33bf8b7c2a504317da90ea2f0bb2af09bd531feae57cb4a0273d8add62fadfc6d43402372e5caf854e112b88417936f1a9c4045d48b5b0b7703d96801b35ff66c716cddbee1b92407aa069a162c163071710e28ccddf6fb560feea32485f2c54a477ae23fd8210427eabe4288cbe0ecbef4ed19ca049ceded424d9f839da957f56ffeb73060ea15498fcbc2d73606e85e963a667dafdb2641fb91862c07b98c1fdae8fadf514600225036dd63c22cdadb57d2125ebf30bc77f7ea0bc0dafb484bf01434954c5053b9c8a143f06972f80fa66788ea1e3425dc0104a9e3674729967b9819552ebb172418da0e4b3778ad4b3d6acd8f354ba09e54bbc8604540010e1e1e4d3066515aed457bd3399c0ce787236dbcd3923de4fb8faded10199b33c1251191612ab5526c1cf0cd55a0aeaed3f7a955ceced16dabdbeb0a2a19a9fdb5aa8c4fc8767cf70e4ad1838518bc6b9de7c420c1f57636579a14a5a8bdacd24e61a68adede8a2e07416c25409dd91ab78905bc99bab4ab4fb9e4ea628e09a271837769c4e67e580dcd5485e12e4e308cb4509686a7484a71f7dfe334499808c7122f07d45d89230b1f19ed86f675b7fec44ef5f3b178ae0af92ff114bd96baa264604fea5a762307bdce6cb483b7bc780d32ed5343fcc3aa306997f211dc075f6dfd66035c1db10bef8656fefbb45645264d401682e42fe3e05906f79d65481b87508f1a4c434e0d1dfc247d4276306f801a6b57e4e4a525177bae24e0bd88a216597d9db44f2604c29d8a5f74e7b934f55048690b5dcefd6489a81aa64c1edb49b320faab94130e603d99e455cfd828bca782176192ece95e9b967fe3dd698574cf0c0b6926970b156e1134658de657de42c4930e72b49c0d94da66c330ab188c10f0d2f578590f31bcac6fcff7e21f9ff67ae1a40d5a03b19301dcbbadc1aa9392795cf81f1401ec16d986a7f96fbb9e8e12ce04a2226e26b78117a4dfb757c6a44481ff68bb0909e7010988cd37146fb45d4cca4ba490aae323bb51a12b6864f88ea6897aa700ee9142eaf0880844083026f044a5e3dba4aae08578cb057976001beb27b5110c41fe336bf7879733739ce22fb31a1a6ac2c900d6d6c6facdbc60085e5c93d502542cfea90dbc62d4e061b7106f09f9c4f6c1b5506dd0550eb8b2bf17678b140de33a10ba676829092e6a13445d1857d06c715eea4492ff864f0b34d178a75a0f1353078f83cfee1440b0a20e64abbd0cab5c6e7083486002970a4904f8371805d1a0ee4aea8524168f0f39d2dfc55f545a98a031841a740e8422a62e123c8303021fb81afbb76d1120c0fbc4d3d97ba69f4e2fe086822ece2047c9ccea507008654c199238a5d17f009aa2dd081f7901d0688aa15311865a319ccba8de4023027235b5725353561c5f1185f6a063fb32fc65ef6e90339d406a6884d66be49d03daaf116ee4b65ef80dd3052a13157b929f98640c0bbe99c8323ce3419a136403dc3f7a95178c3966d2d7bdecf516a28eb2cf8cddb3a0463dc7a6248883f7be0a10aae1bb50728ec9b8880d6011b366a850798f6d7fe07103695dded3f371ca097c1d3596967320071d7f548938afe287cb9b8fae761fa592425623dcbf653028000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let err = deserialize::<Transaction>(&raw_tx).unwrap_err();
        assert_eq!(
            format!("{}", err),
            "Parsing error: data not consumed entirely when explicitly deserializing"
        );
    }

    #[test]
    fn code_coverage_happy_path() {
        let key = PublicKey::from_slice(&[0u8; 32]).unwrap();
        assert_eq!(
            serialize_hex(&key),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );

        let mut buffer = Vec::new();
        let mut writer = Cursor::new(&mut buffer);
        let i8_value = 42_i8;
        let result = writer.emit_i8(i8_value);
        assert!(result.is_ok());
        let expected_bytes = vec![42u8];
        assert_eq!(&buffer, &expected_bytes);

        let mut reader = Cursor::new(&buffer);
        let result = reader.read_i8();
        assert!(result.is_ok());
        assert_eq!(i8_value, result.unwrap());

        let mut buffer = Vec::new();
        let mut writer = Cursor::new(&mut buffer);
        let bool_value = true;
        let result = writer.emit_bool(bool_value);
        assert!(result.is_ok());
        let expected_bytes = vec![true as u8];
        assert_eq!(buffer, expected_bytes);

        let mut reader = Cursor::new(&buffer);
        let result = reader.read_bool();
        assert!(result.is_ok());
        assert_eq!(bool_value, result.unwrap());

        let mut buffer = Vec::new();
        let mut writer = Cursor::new(&mut buffer);
        let slice_value = &[0u8, 1u8, 2u8, 3u8];
        let result = writer.emit_slice(slice_value);
        assert!(result.is_ok());
        let expected_bytes = vec![0u8, 1u8, 2u8, 3u8];
        assert_eq!(buffer, expected_bytes);

        let mut reader = Cursor::new(&buffer);
        let mut slice_read = Vec::new();
        let result = reader.read_slice(&mut slice_read);
        assert!(result.is_ok());
        // Note: This resutls in an error !!
        // assert_eq!(slice_value, slice_read.as_slice());

        let mut buffer = Vec::new();
        let mut writer = Cursor::new(&mut buffer);
        let var_int_value = VarInt(21);
        let result = var_int_value.consensus_encode(&mut writer);
        assert!(result.is_ok());
        let expected_bytes = vec![21];
        assert_eq!(&buffer, &expected_bytes);

        let mut reader = Cursor::new(&buffer);
        let result = VarInt::consensus_decode(&mut reader);
        assert!(result.is_ok());
        assert_eq!(var_int_value, result.unwrap());

        let mut buffer = Vec::new();
        let mut writer = Cursor::new(&mut buffer);
        let bool_value = true;
        let result = bool_value.consensus_encode(&mut writer);
        assert!(result.is_ok());
        let expected_bytes = vec![true as u8];
        assert_eq!(&buffer, &expected_bytes);

        let mut reader = Cursor::new(&buffer);
        let result = bool::consensus_decode(&mut reader);
        assert!(result.is_ok());
        assert_eq!(bool_value, result.unwrap());

        let mut buffer = Vec::new();
        let mut writer = Cursor::new(&mut buffer);
        let string_value = "crypto".to_string();
        let result = string_value.consensus_encode(&mut writer);
        assert!(result.is_ok());
        assert_eq!(buffer, [6, 99, 114, 121, 112, 116, 111]);

        let mut reader = Cursor::new(&buffer);
        let result = String::consensus_decode(&mut reader);
        assert!(result.is_ok());
        assert_eq!(string_value, result.unwrap());
    }
}

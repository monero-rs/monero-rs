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
use std::fmt::Debug;
use std::ops::Deref;
use std::{fmt, io, mem, u32};

use sealed::sealed;
use thiserror::Error;

use super::endian;

use crate::util::address::AddressError;
use crate::util::key::KeyError;
use crate::util::ringct::RingCtError;
#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};

/// The maximum memory size of a vector that can be allocated during decoding.
pub const MAX_VEC_MEM_ALLOC_SIZE: usize = 32 * 1024 * 1024; // 32 MiB

/// Errors encountered when encoding or decoding data.
#[derive(Error, Debug, PartialEq)]
pub enum EncodeError {
    /// And I/O error.
    #[error("IO error: {0}")]
    Io(String),
    /// Key error.
    #[error("Key error: {0}")]
    Key(#[from] KeyError),
    /// RingCt error.
    #[error("RingCt error: {0}")]
    RingCt(#[from] RingCtError),
    /// Address error.
    #[error("Address error: {0}")]
    Address(#[from] AddressError),
    /// A generic parsing error.
    #[error("Parsing error: {0}")]
    ParseFailed(String),
    /// A consensus encoding parsing error.
    #[error("Parsing error: {0}")]
    ConsensusEncodingFailed(String),
}

/// Encode an object into a vector of byte.
pub fn serialize<T: Encodable + std::fmt::Debug + ?Sized>(
    data: &T,
) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = Vec::new();
    let len = data.consensus_encode(&mut encoder).map_err(|e| {
        EncodeError::ConsensusEncodingFailed(format!("failed to encode object ({})", e))
    })?;
    debug_assert_eq!(len, encoder.len());
    Ok(encoder)
}

/// Encode an object into a hex-encoded string.
pub fn serialize_hex<T: Encodable + std::fmt::Debug + ?Sized>(
    data: &T,
) -> Result<String, EncodeError> {
    Ok(hex_encode(serialize(data)?))
}

/// Deserialize an object from a byte vector, will error if said deserialization doesn't consume
/// the entire vector.
pub fn deserialize<T: Decodable>(data: &[u8]) -> Result<T, EncodeError> {
    let (rv, consumed) = deserialize_partial(data)?;

    // Fail if data are not consumed entirely.
    if consumed == data.len() {
        Ok(rv)
    } else {
        Err(EncodeError::ParseFailed(format!(
            "data not consumed entirely when explicitly deserializing: input data {}, consumed {}",
            data.len(),
            consumed
        )))
    }
}

/// Deserialize an object from a vector, but will not report an error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize_partial<T: Decodable>(data: &[u8]) -> Result<(T, usize), EncodeError> {
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
    fn read_u64(&mut self) -> Result<u64, EncodeError>;
    /// Read a 32-bit uint.
    fn read_u32(&mut self) -> Result<u32, EncodeError>;
    /// Read a 16-bit uint.
    fn read_u16(&mut self) -> Result<u16, EncodeError>;
    /// Read a 8-bit uint.
    fn read_u8(&mut self) -> Result<u8, EncodeError>;

    /// Read a 64-bit int.
    fn read_i64(&mut self) -> Result<i64, EncodeError>;
    /// Read a 32-bit int.
    fn read_i32(&mut self) -> Result<i32, EncodeError>;
    /// Read a 16-bit int.
    fn read_i16(&mut self) -> Result<i16, EncodeError>;
    /// Read a 8-bit int.
    fn read_i8(&mut self) -> Result<i8, EncodeError>;

    /// Read a boolean.
    fn read_bool(&mut self) -> Result<bool, EncodeError>;

    /// Read a byte slice.
    fn read_slice(&mut self, slice: &mut [u8]) -> Result<(), EncodeError>;
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
        fn $name(&mut self) -> Result<$val_type, EncodeError> {
            let mut val = [0; $byte_len];
            self.read_exact(&mut val[..])
                .map_err(|e| EncodeError::Io(e.to_string()))?;
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
    fn read_u8(&mut self) -> Result<u8, EncodeError> {
        let mut slice = [0u8; 1];
        self.read_exact(&mut slice)
            .map_err(|e| EncodeError::Io(e.to_string()))?;
        Ok(slice[0])
    }

    #[inline]
    fn read_i8(&mut self) -> Result<i8, EncodeError> {
        let mut slice = [0u8; 1];
        self.read_exact(&mut slice)
            .map_err(|e| EncodeError::Io(e.to_string()))?;
        Ok(slice[0] as i8)
    }

    #[inline]
    fn read_bool(&mut self) -> Result<bool, EncodeError> {
        ReadExt::read_i8(self).map(|bit| bit != 0)
    }

    #[inline]
    fn read_slice(&mut self, slice: &mut [u8]) -> Result<(), EncodeError> {
        self.read_exact(slice)
            .map_err(|e| EncodeError::Io(e.to_string()))
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
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, EncodeError>;
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
            fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, EncodeError> {
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
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, EncodeError> {
        let mut res: Vec<u8> = vec![];
        loop {
            let n = r.read_u8()?;
            // Zero in any position other than the first is invalid
            // since it is not the shortest encoding.
            if n == 0 && !res.is_empty() {
                return Err(EncodeError::ParseFailed("VarInt has a zero in a position other than the first. This is not the shortest encoding.".to_string()));
            }
            res.push(n & 0b0111_1111);
            if n & 0b1000_0000 == 0 {
                break;
            }
        }
        let mut int = 0u64;
        res.reverse();
        let (last, arr) = match res.split_last() {
            Some((v1, v2)) => (v1, v2),
            None => {
                return Err(EncodeError::ParseFailed(
                    "VarInt has empty data.".to_string(),
                ))
            }
        };
        for bits in arr {
            int |= *bits as u64;
            int = if int.leading_zeros() >= 7 {
                int << 7
            } else {
                return Err(EncodeError::ParseFailed("VarInt overflows u64".to_string()));
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
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<bool, EncodeError> {
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
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<String, EncodeError> {
        String::from_utf8(Decodable::consensus_decode(r)?)
            .map_err(|_| self::EncodeError::ParseFailed("String was not valid UTF8".to_string()))
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
            fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, EncodeError> {
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
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, EncodeError> {
        let len = usize::try_from(*VarInt::consensus_decode(r)?).map_err(|e| {
            self::EncodeError::ParseFailed(format!("VarInt overflows usize ({})", e))
        })?;

        // Prevent allocations larger than the maximum allowed size
        let layout_size = mem::size_of::<T>().saturating_mul(len);
        if layout_size > MAX_VEC_MEM_ALLOC_SIZE {
            return Err(self::EncodeError::ParseFailed(format!(
                "length ({} x {} = {}) exceeds maximum allocatable bytes ({}) by {} bytes",
                mem::size_of::<T>(),
                len,
                layout_size,
                MAX_VEC_MEM_ALLOC_SIZE,
                layout_size.saturating_sub(MAX_VEC_MEM_ALLOC_SIZE),
            )));
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
) -> Result<Vec<T>, EncodeError> {
    let layout_size = mem::size_of::<T>().saturating_mul(size);
    if layout_size > MAX_VEC_MEM_ALLOC_SIZE {
        return Err(EncodeError::ParseFailed(format!(
            "length ({} x {} = {}) exceeds maximum allocatable bytes ({}) by {} bytes",
            mem::size_of::<T>(),
            size,
            layout_size,
            MAX_VEC_MEM_ALLOC_SIZE,
            layout_size.saturating_sub(MAX_VEC_MEM_ALLOC_SIZE),
        )));
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
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, EncodeError> {
        let len = usize::try_from(*VarInt::consensus_decode(r)?).map_err(|e| {
            self::EncodeError::ParseFailed(format!("VarInt overflows usize ({})", e))
        })?;

        // Prevent allocations larger than the maximum allowed size
        let layout_size = mem::size_of::<T>().saturating_mul(len);
        if layout_size > MAX_VEC_MEM_ALLOC_SIZE {
            return Err(self::EncodeError::ParseFailed(format!(
                "length ({} x {} = {}) exceeds maximum allocatable bytes ({}) by {} bytes",
                mem::size_of::<T>(),
                len,
                layout_size,
                MAX_VEC_MEM_ALLOC_SIZE,
                layout_size.saturating_sub(MAX_VEC_MEM_ALLOC_SIZE),
            )));
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
    use super::{deserialize, serialize, EncodeError, VarInt};
    use crate::blockdata::transaction::{ExtraField, SubField, TxOutTarget};
    use crate::consensus::encode::MAX_VEC_MEM_ALLOC_SIZE;
    use crate::consensus::Decodable;
    use crate::util::ringct::{Key, RctSig, RctSigBase, RctType};
    use crate::{Block, Hash, PublicKey, Transaction, TransactionPrefix, TxIn, TxOut};
    use std::{io, mem};

    #[test]
    fn deserialize_varint() {
        let int: VarInt = deserialize(&[0b000_0001]).unwrap();
        assert_eq!(VarInt(1), int);

        let int: VarInt = deserialize(&[0b1010_1100, 0b0000_0010]).unwrap();
        assert_eq!(VarInt(300), int);

        let max = VarInt(u64::MAX);
        let mut max_u64_data = serialize(&max).unwrap();
        let len_max = max_u64_data.len();
        let int: VarInt = deserialize(&max_u64_data).unwrap();
        assert_eq!(max, int);

        // varint must be shortest encoding
        let res = deserialize::<VarInt>(&[152, 0]);
        assert!(matches!(res.unwrap_err(), EncodeError::ParseFailed(_)));

        // If the last number is not a 0, it will error with an IO error (UnexpectedEof)
        let res = deserialize::<VarInt>(&[255u8; 1]);
        assert!(matches!(res.unwrap_err(), EncodeError::Io(_)));

        // Add one to the max u64 data.
        assert_eq!(max_u64_data[len_max - 1], 0x01);
        max_u64_data[len_max - 1] += 1;
        let res = deserialize::<VarInt>(&max_u64_data);
        assert!(matches!(res.unwrap_err(), EncodeError::ParseFailed(_)));

        let res = deserialize::<VarInt>(&[
            255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 1u8,
        ]);
        assert!(matches!(res.unwrap_err(), EncodeError::ParseFailed(_)));
    }

    #[test]
    fn serialize_varint() {
        assert_eq!(vec![0b000_0001], serialize(&VarInt(1)).unwrap());
        assert_eq!(
            vec![0b1010_1100, 0b0000_0010],
            serialize(&VarInt(300)).unwrap()
        );
        assert_eq!(
            "80e497d012",
            hex::encode(serialize(&VarInt(5000000000)).unwrap())
        );
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
        let vec_buffer = serialize(&vec).unwrap();
        let data = deserialize::<Vec<[u8; 64]>>(&vec_buffer).unwrap();
        assert_eq!(data, vec);

        let tx_in = serialize(&TxIn::Gen { height: VarInt(1) }).unwrap();
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
        assert!(matches!(err, EncodeError::Io(_)));
        let len = VarInt(1);
        let data = serialize(&len).unwrap();
        let err = deserialize::<Vec<[u8; 64]>>(&data).unwrap_err();
        assert!(matches!(err, EncodeError::Io(_)));
    }

    #[test]
    fn deserialize_varint_with_empty_buffer() {
        let err = deserialize::<VarInt>(&[]).unwrap_err();
        assert!(matches!(err, EncodeError::Io(_)));
    }

    #[test]
    fn deserialize_vec_max_allocation() {
        for length in (0..10).chain(
            (MAX_VEC_MEM_ALLOC_SIZE / 64) as u64 - 10..=(MAX_VEC_MEM_ALLOC_SIZE / 64) as u64 + 10,
        ) {
            let len = VarInt(length);
            let data = serialize(&len).unwrap();
            let res = deserialize::<Vec<[u8; 64]>>(&data);
            if length == 0 {
                assert!(res.is_ok());
            } else {
                let err = res.unwrap_err();
                if length <= (MAX_VEC_MEM_ALLOC_SIZE / 64) as u64 {
                    assert!(matches!(err, EncodeError::Io(_)));
                } else {
                    assert!(matches!(err, EncodeError::ParseFailed(_)));
                }
            }
        }

        let data_len = 100u64;
        let mut data = serialize(&VarInt(data_len)).unwrap();
        for i in 0..data_len {
            data.push((i % 255) as u8);
        }
        assert_eq!(data[1..], deserialize::<Vec<u8>>(&data[..]).unwrap());

        for length in (0..10)
            .chain(data_len - 10..=data_len + 10)
            .chain(MAX_VEC_MEM_ALLOC_SIZE as u64 - 10..=MAX_VEC_MEM_ALLOC_SIZE as u64 + 10)
        {
            let replace_len = VarInt(length);
            let replace_len_bytes = serialize(&replace_len).unwrap();
            for (i, val) in replace_len_bytes.iter().enumerate() {
                data[i] = *val;
            }
            let res = deserialize::<Vec<u8>>(&data[..]);
            if length == data_len {
                assert!(res.is_ok());
            } else {
                let err = res.unwrap_err();
                if length < data_len {
                    assert!(matches!(err, EncodeError::ParseFailed(_)));
                } else if length <= MAX_VEC_MEM_ALLOC_SIZE as u64 {
                    assert!(matches!(err, EncodeError::Io(_)));
                } else {
                    assert!(matches!(err, EncodeError::ParseFailed(_)));
                }
            }
        }
    }

    #[test]
    fn deserialize_vec_overflow_does_not_panic() {
        let overflow_len = VarInt((isize::MAX as u64 / 64) + 1);
        let data = serialize(&overflow_len).unwrap();
        let err = deserialize::<Vec<[u8; 64]>>(&data).unwrap_err();
        assert!(matches!(err, EncodeError::ParseFailed(_)));
    }

    #[test]
    fn deserialize_string_overflow_does_not_panic() {
        let overflow_len = VarInt(isize::MAX as u64 + 1);
        let data = serialize(&overflow_len).unwrap();
        let err = deserialize::<String>(&data).unwrap_err();
        assert!(matches!(err, EncodeError::ParseFailed(_)));
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
    fn decode_mem_size() {
        let byte_value_max = 100u8;
        let buffer_length = (mem::size_of::<Key>() * (byte_value_max as usize + 1)) + 1;
        for byte_value in 0..=byte_value_max {
            let serialized_bytes = vec![byte_value; buffer_length];
            let mut decoder = io::Cursor::new(&serialized_bytes[..]);
            let res: Result<Key, EncodeError> = Decodable::consensus_decode(&mut decoder);
            assert!(res.is_ok());
            let res: Result<Vec<Key>, EncodeError> = Decodable::consensus_decode(&mut decoder);
            assert!(res.is_ok());
        }
    }

    #[test]
    fn deserialize_vec_of_transactions() {
        let transaction = get_transaction();
        let mut transaction_vec = Vec::new();
        for _ in 0..1024 {
            transaction_vec.push(transaction.clone());
        }
        let buffer = serialize(&transaction_vec).unwrap();
        let deserialized = deserialize::<Vec<Transaction>>(&buffer).unwrap();
        assert_eq!(deserialized, transaction_vec);
    }

    fn get_transaction() -> Transaction {
        let pk_extra = vec![
            179, 155, 220, 223, 213, 23, 81, 160, 95, 232, 87, 102, 151, 63, 70, 249, 139, 40, 110,
            16, 51, 193, 175, 208, 38, 120, 65, 191, 155, 139, 1, 4,
        ];
        Transaction {
            prefix: TransactionPrefix {
                version: VarInt(2),
                unlock_time: VarInt(2143845),
                inputs: vec![
                    TxIn::Gen {
                        height: VarInt(2143785),
                    },
                    TxIn::Gen {
                        height: VarInt(2143786),
                    },
                    TxIn::Gen {
                        height: VarInt(2143787),
                    },
                    TxIn::Gen {
                        height: VarInt(2143788),
                    },
                    TxIn::Gen {
                        height: VarInt(2143789),
                    },
                    TxIn::Gen {
                        height: VarInt(2143790),
                    },
                    TxIn::Gen {
                        height: VarInt(2143791),
                    },
                ],
                outputs: vec![
                    TxOut {
                        amount: VarInt(1550800739964),
                        target: TxOutTarget::ToKey {
                            key: PublicKey::from_slice(
                                hex::decode(
                                    "e2e19d8badb15e77c8e1f441cf6acd9bcde34a07cae82bbe5ff9629bf88e6e81",
                                )
                                    .unwrap()
                                    .as_slice(),
                            )
                                .unwrap()
                                .to_bytes(),
                        },
                    },
                    TxOut {
                        amount: VarInt(1550800739964),
                        target: TxOutTarget::ToKey {
                            key: PublicKey::from_slice(
                                hex::decode(
                                    "e2e19d8badb15e77c8e1f441cf6acd9bcde34a07cae82bbe5ff9629bf88e6e81",
                                )
                                    .unwrap()
                                    .as_slice(),
                            )
                                .unwrap()
                                .to_bytes(),
                        },
                    },
                    TxOut {
                        amount: VarInt(1550800739964),
                        target: TxOutTarget::ToKey {
                            key: PublicKey::from_slice(
                                hex::decode(
                                    "e2e19d8badb15e77c8e1f441cf6acd9bcde34a07cae82bbe5ff9629bf88e6e81",
                                )
                                    .unwrap()
                                    .as_slice(),
                            )
                                .unwrap()
                                .to_bytes(),
                        },
                    },
                    TxOut {
                        amount: VarInt(1550800739964),
                        target: TxOutTarget::ToKey {
                            key: PublicKey::from_slice(
                                hex::decode(
                                    "e2e19d8badb15e77c8e1f441cf6acd9bcde34a07cae82bbe5ff9629bf88e6e81",
                                )
                                    .unwrap()
                                    .as_slice(),
                            )
                                .unwrap()
                                .to_bytes(),
                        },
                    },
                    TxOut {
                        amount: VarInt(1550800739964),
                        target: TxOutTarget::ToKey {
                            key: PublicKey::from_slice(
                                hex::decode(
                                    "e2e19d8badb15e77c8e1f441cf6acd9bcde34a07cae82bbe5ff9629bf88e6e81",
                                )
                                    .unwrap()
                                    .as_slice(),
                            )
                                .unwrap()
                                .to_bytes(),
                        },
                    },
                ],
                extra: ExtraField(vec![
                    SubField::TxPublicKey(PublicKey::from_slice(pk_extra.as_slice()).unwrap()),
                    SubField::Nonce(vec![
                        196, 37, 4, 0, 27, 37, 187, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ]),
                    SubField::MysteriousMinerGate(vec![
                        207, 178, 51, 151, 236, 243, 250, 53, 101, 231, 200, 74, 181, 168, 88, 192, 92,
                        120, 213, 36, 147, 125, 53, 253, 90, 5, 164, 31, 186, 125, 50, 16,
                    ]),
                    SubField::TxPublicKey(
                        PublicKey::from_slice(
                            hex::decode("944f9df50e769da49c64e0fcb4e1d77f8905056548eb9a7f04914c2d74b1bbaf")
                                .unwrap()
                                .as_slice(),
                        )
                            .unwrap(),
                    ),
                    SubField::Nonce(vec![62, 19, 29, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    SubField::MergeMining(
                        Some(VarInt(1)),
                        Hash::from_slice(
                            hex::decode("62b853ea7f574fb4cbdd29ad51894babbaebd68ea15225507c52d9e551eb1995")
                                .unwrap()
                                .as_slice(),
                        ),
                    ),
                    SubField::TxPublicKey(
                        PublicKey::from_slice(
                            hex::decode("c6b919050a413044756e328f0ab5146f40a60258b5671e9d6cc972357c9dfa0b")
                                .unwrap()
                                .as_slice(),
                        )
                            .unwrap(),
                    ),
                    SubField::AdditionalPublickKey(vec![
                        PublicKey::from_slice(
                            hex::decode("f2e013a0f696b7afff80af81f653f74b270651300ab40f5d15ca0553cd424f17")
                                .unwrap()
                                .as_slice(),
                        )
                            .unwrap(),
                        PublicKey::from_slice(
                            hex::decode("72a98681a92139ff6c8c4bf33d91834c0fa775576a61ec782dc1eda715679acb")
                                .unwrap()
                                .as_slice(),
                        )
                            .unwrap(),
                        PublicKey::from_slice(
                            hex::decode("71641ae9896f959a48b286738f7f36a00ac91ed7ecac12e881488b48b18bec67")
                                .unwrap()
                                .as_slice(),
                        )
                            .unwrap(),
                        PublicKey::from_slice(
                            hex::decode("f439c1fd75bf22a2f79e0810962adb0ecf9c10e774934f4cd5baff354fabf616")
                                .unwrap()
                                .as_slice(),
                        )
                            .unwrap(),
                    ]),
                ])
                    .try_into()
                    .unwrap(),
            },
            signatures: vec![],
            rct_signatures: RctSig {
                sig: Option::from(RctSigBase {
                    rct_type: RctType::Null,
                    txn_fee: Default::default(),
                    pseudo_outs: vec![],
                    ecdh_info: vec![],
                    out_pk: vec![],
                }),
                p: None,
            },
        }
    }
}

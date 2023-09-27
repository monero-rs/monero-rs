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

//! Monero addresses types and helper functions.
//!
//! Support for (de)serializable Monero addresses in Monero `base58` format (not equivalent to
//! Bitcoin `base58` format).
//!
//! ## Parsing an address
//!
//! ```rust
//! use std::str::FromStr;
//! use monero::{Address, Network};
//! use monero::util::address::{AddressType, Error};
//!
//! let addr = "4ADT1BtbxqEWeMKp9GgPr2NeyJXXtNxvoDawpyA4WpzFcGcoHUvXeijE66DNfohE9r1bQYaBiQjEtKE7CtkTdLwiDznFzra";
//! let address = Address::from_str(addr)?;
//!
//! assert_eq!(address.network, Network::Mainnet);
//! assert_eq!(address.addr_type, AddressType::Standard);
//!
//! let public_spend_key = address.public_spend;
//! let public_view_key = address.public_view;
//! # Ok::<(), Error>(())
//! ```
//!

// TODO: remove this when fixed-hash stop raising clippy errors...
#![allow(clippy::incorrect_clone_impl_on_copy_type)]

use std::fmt;
use std::str::FromStr;

use base58_monero::base58;

use crate::consensus::encode::{self, Decodable};
use crate::cryptonote::hash::keccak_256;
use crate::network::{self, Network};
use crate::util::key::{KeyPair, PublicKey, ViewPair};

use sealed::sealed;
use thiserror::Error;

/// Potential errors encountered when manipulating addresses.
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    /// Invalid address magic byte.
    #[error("Invalid magic byte")]
    InvalidMagicByte,
    /// Invalid payment id.
    #[error("Invalid payment ID")]
    InvalidPaymentId,
    /// Missmatch address checksums.
    #[error("Invalid checksum")]
    InvalidChecksum,
    /// Generic invalid format.
    #[error("Invalid format")]
    InvalidFormat,
    /// Monero base58 error.
    #[error("Base58 error: {0}")]
    Base58(#[from] base58::Error),
    /// Network error.
    #[error("Network error: {0}")]
    Network(#[from] network::Error),
}

/// Address type: standard, integrated, or sub-address.
///
/// AddressType implements [`Default`] and returns [`AddressType::Standard`].
#[derive(Default, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum AddressType {
    /// Standard address.
    #[default]
    Standard,
    /// Address with a short 8 bytes payment id.
    Integrated(PaymentId),
    /// Sub-address.
    SubAddress,
}

impl AddressType {
    /// Recover the address type given an address bytes and the network.
    pub fn from_slice(bytes: &[u8], net: Network) -> Result<AddressType, Error> {
        let byte = bytes[0];
        use AddressType::*;
        use Network::*;
        match net {
            Mainnet => match byte {
                18 => Ok(Standard),
                19 => {
                    let payment_id = PaymentId::from_slice(&bytes[65..73]);
                    Ok(Integrated(payment_id))
                }
                42 => Ok(SubAddress),
                _ => Err(Error::InvalidMagicByte),
            },
            Testnet => match byte {
                53 => Ok(Standard),
                54 => {
                    let payment_id = PaymentId::from_slice(&bytes[65..73]);
                    Ok(Integrated(payment_id))
                }
                63 => Ok(SubAddress),
                _ => Err(Error::InvalidMagicByte),
            },
            Stagenet => match byte {
                24 => Ok(Standard),
                25 => {
                    let payment_id = PaymentId::from_slice(&bytes[65..73]);
                    Ok(Integrated(payment_id))
                }
                36 => Ok(SubAddress),
                _ => Err(Error::InvalidMagicByte),
            },
        }
    }
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AddressType::Standard => write!(f, "Standard address"),
            AddressType::Integrated(_) => write!(f, "Integrated address"),
            AddressType::SubAddress => write!(f, "Subaddress"),
        }
    }
}

fixed_hash::construct_fixed_hash! {
    /// Short Payment Id for integrated address, a fixed 8-bytes array.
    pub struct PaymentId(8);
}

impl hex::FromHex for PaymentId {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let hex = hex.as_ref();
        let hex = hex.strip_prefix("0x".as_bytes()).unwrap_or(hex);

        let buffer = <[u8; 8]>::from_hex(hex)?;
        Ok(PaymentId(buffer))
    }
}

/// A complete Monero typed address valid for a specific network.
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub struct Address {
    /// The network on which the address is valid and should be used.
    pub network: Network,
    /// The address type.
    pub addr_type: AddressType,
    /// The address spend public key.
    pub public_spend: PublicKey,
    /// The address view public key.
    pub public_view: PublicKey,
}

impl Address {
    /// Create a standard address which is valid on the given network.
    pub fn standard(network: Network, public_spend: PublicKey, public_view: PublicKey) -> Address {
        Address {
            network,
            addr_type: AddressType::Standard,
            public_spend,
            public_view,
        }
    }

    /// Create a sub-address which is valid on the given network.
    pub fn subaddress(
        network: Network,
        public_spend: PublicKey,
        public_view: PublicKey,
    ) -> Address {
        Address {
            network,
            addr_type: AddressType::SubAddress,
            public_spend,
            public_view,
        }
    }

    /// Create an address with an integrated payment id which is valid on the given network.
    pub fn integrated(
        network: Network,
        public_spend: PublicKey,
        public_view: PublicKey,
        payment_id: PaymentId,
    ) -> Address {
        Address {
            network,
            addr_type: AddressType::Integrated(payment_id),
            public_spend,
            public_view,
        }
    }

    /// Create a standard address from a view pair which is valid on the given network.
    pub fn from_viewpair(network: Network, keys: &ViewPair) -> Address {
        let public_view = PublicKey::from_private_key(&keys.view);
        Address {
            network,
            addr_type: AddressType::Standard,
            public_spend: keys.spend,
            public_view,
        }
    }

    /// Create a standard address from a key pair which is valid on the given network.
    pub fn from_keypair(network: Network, keys: &KeyPair) -> Address {
        let public_spend = PublicKey::from_private_key(&keys.spend);
        let public_view = PublicKey::from_private_key(&keys.view);
        Address {
            network,
            addr_type: AddressType::Standard,
            public_spend,
            public_view,
        }
    }

    /// Parse an address from a vector of bytes, fail if the magic byte is incorrect, if public
    /// keys are not valid points, if payment id is invalid, and if checksums missmatch.
    pub fn from_bytes(bytes: &[u8]) -> Result<Address, Error> {
        let network = Network::from_u8(bytes[0])?;
        let addr_type = AddressType::from_slice(bytes, network)?;
        let public_spend =
            PublicKey::from_slice(&bytes[1..33]).map_err(|_| Error::InvalidFormat)?;
        let public_view =
            PublicKey::from_slice(&bytes[33..65]).map_err(|_| Error::InvalidFormat)?;

        let (checksum_bytes, checksum) = match addr_type {
            AddressType::Standard | AddressType::SubAddress => (&bytes[0..65], &bytes[65..69]),
            AddressType::Integrated(_) => (&bytes[0..73], &bytes[73..77]),
        };
        let verify_checksum = keccak_256(checksum_bytes);
        if &verify_checksum[0..4] != checksum {
            return Err(Error::InvalidChecksum);
        }

        Ok(Address {
            network,
            addr_type,
            public_spend,
            public_view,
        })
    }

    /// Serialize the address as a vector of bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![self.network.as_u8(&self.addr_type)];
        bytes.extend_from_slice(self.public_spend.as_bytes());
        bytes.extend_from_slice(self.public_view.as_bytes());
        if let AddressType::Integrated(payment_id) = &self.addr_type {
            bytes.extend_from_slice(&payment_id.0);
        }

        let checksum = keccak_256(bytes.as_slice());
        bytes.extend_from_slice(&checksum[0..4]);
        bytes
    }

    /// Serialize the address as an hexadecimal string.
    pub fn as_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }
}

impl hex::ToHex for Address {
    fn encode_hex<T: std::iter::FromIterator<char>>(&self) -> T {
        self.as_bytes().encode_hex()
    }

    fn encode_hex_upper<T: std::iter::FromIterator<char>>(&self) -> T {
        self.as_bytes().encode_hex_upper()
    }
}

impl hex::FromHex for Address {
    type Error = Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let hex = hex.as_ref();
        let hex = hex.strip_prefix("0x".as_bytes()).unwrap_or(hex);
        let bytes = hex::decode(hex).map_err(|_| Self::Error::InvalidFormat)?;
        Self::from_bytes(&bytes)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", base58::encode(self.as_bytes().as_slice()).unwrap())
    }
}

impl FromStr for Address {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(&base58::decode(s)?)
    }
}

#[cfg(feature = "serde")]
mod serde_impl {
    use super::*;

    use serde_crate::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

    impl Serialize for Address {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&self.to_string())
        }
    }

    impl<'de> Deserialize<'de> for Address {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            Address::from_str(&s).map_err(D::Error::custom)
        }
    }
}

impl Decodable for Address {
    fn consensus_decode<R: std::io::Read + ?Sized>(r: &mut R) -> Result<Address, encode::Error> {
        let address: Vec<u8> = Decodable::consensus_decode(r)?;
        Ok(Address::from_bytes(&address)?)
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for Address {
    fn consensus_encode<W: std::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, std::io::Error> {
        self.as_bytes().consensus_encode(w)
    }
}

#[cfg(test)]
mod tests {
    use crate::consensus::encode::{Decodable, Encodable};
    use hex::{FromHex, FromHexError, ToHex};
    use std::str::FromStr;

    use super::{base58, Address, AddressType, Network, PaymentId, PublicKey};

    #[test]
    fn deserialize_address() {
        let pub_spend = PublicKey::from_slice(&[
            226, 187, 17, 117, 6, 188, 105, 177, 58, 207, 205, 42, 205, 229, 251, 129, 118, 253,
            21, 245, 49, 67, 36, 75, 62, 12, 80, 90, 244, 194, 108, 210,
        ])
        .unwrap();
        let pub_view = PublicKey::from_slice(&[
            220, 115, 195, 55, 189, 88, 136, 78, 63, 32, 41, 33, 168, 205, 245, 3, 139, 234, 109,
            64, 198, 179, 53, 108, 247, 77, 183, 25, 172, 59, 113, 115,
        ])
        .unwrap();

        let address = "4ADT1BtbxqEWeMKp9GgPr2NeyJXXtNxvoDawpyA4WpzFcGcoHUvXeijE66DNfohE9r1bQYaBiQjEtKE7CtkTdLwiDznFzra";
        let add = Address::from_str(address);
        assert_eq!(
            Ok(Address::standard(Network::Mainnet, pub_spend, pub_view)),
            add
        );

        let bytes = base58::decode(address).unwrap();
        let add = Address::from_bytes(&bytes);
        assert_eq!(
            Ok(Address::standard(Network::Mainnet, pub_spend, pub_view)),
            add
        );

        let full_address = add.unwrap();
        let mut encoder = Vec::new();
        full_address.clone().consensus_encode(&mut encoder).unwrap();
        let mut res = std::io::Cursor::new(encoder);
        let addr_decoded = Address::consensus_decode(&mut res).unwrap();
        assert_eq!(full_address, addr_decoded);
    }

    #[test]
    fn deserialize_integrated_address() {
        let pub_spend = PublicKey::from_slice(&[
            17, 81, 127, 230, 166, 35, 81, 36, 161, 94, 154, 206, 60, 98, 195, 62, 12, 11, 234,
            133, 228, 196, 77, 3, 68, 188, 84, 78, 94, 109, 238, 44,
        ])
        .unwrap();
        let pub_view = PublicKey::from_slice(&[
            115, 212, 211, 204, 198, 30, 73, 70, 235, 52, 160, 200, 39, 215, 134, 239, 249, 129,
            47, 156, 14, 116, 18, 191, 112, 207, 139, 208, 54, 59, 92, 115,
        ])
        .unwrap();
        let payment_id = PaymentId([88, 118, 184, 183, 41, 150, 255, 151]);

        let address = "4Byr22j9M2878Mtyb3fEPcBNwBZf5EXqn1Yi6VzR46618SFBrYysab2Cs1474CVDbsh94AJq7vuV3Z2DRq4zLcY3LHzo1Nbv3d8J6VhvCV";
        let add = Address::from_str(address);
        assert_eq!(
            Ok(Address::integrated(
                Network::Mainnet,
                pub_spend,
                pub_view,
                payment_id
            )),
            add
        );
    }

    #[test]
    fn deserialize_sub_address() {
        let pub_spend = PublicKey::from_slice(&[
            212, 104, 103, 28, 131, 98, 226, 228, 37, 244, 133, 145, 213, 157, 184, 232, 6, 146,
            127, 69, 187, 95, 33, 143, 9, 102, 181, 189, 230, 223, 231, 7,
        ])
        .unwrap();
        let pub_view = PublicKey::from_slice(&[
            154, 155, 57, 25, 23, 70, 165, 134, 222, 126, 85, 60, 127, 96, 21, 243, 108, 152, 150,
            87, 66, 59, 161, 121, 206, 130, 170, 233, 69, 102, 128, 103,
        ])
        .unwrap();

        let address = "8AW7SotwFrqfAKnibspuuhfowW4g3asvpQvdrTmPcpNr2GmXPtBBSxUPZQATAt8Vw2hiX9GDyxB4tMNgHjwt8qYsCeFDVvn";
        let add = Address::from_str(address);
        assert_eq!(
            Ok(Address::subaddress(Network::Mainnet, pub_spend, pub_view)),
            add
        );
    }

    #[test]
    fn deserialize_address_with_paymentid() {
        let address = "4Byr22j9M2878Mtyb3fEPcBNwBZf5EXqn1Yi6VzR46618SFBrYysab2Cs1474CVDbsh94AJq7vuV3Z2DRq4zLcY3LHzo1Nbv3d8J6VhvCV";
        let addr = Address::from_str(address).unwrap();
        let payment_id = PaymentId([88, 118, 184, 183, 41, 150, 255, 151]);
        assert_eq!(addr.addr_type, AddressType::Integrated(payment_id));
    }

    #[test]
    fn serialize_address() {
        let address = "4ADT1BtbxqEWeMKp9GgPr2NeyJXXtNxvoDawpyA4WpzFcGcoHUvXeijE66DNfohE9r1bQYaBiQjEtKE7CtkTdLwiDznFzra";
        let add = Address::from_str(address).unwrap();
        let bytes = base58::decode(address).unwrap();
        assert_eq!(bytes, add.as_bytes());
    }

    #[test]
    fn serialize_integrated_address() {
        let address = "4Byr22j9M2878Mtyb3fEPcBNwBZf5EXqn1Yi6VzR46618SFBrYysab2Cs1474CVDbsh94AJq7vuV3Z2DRq4zLcY3LHzo1Nbv3d8J6VhvCV";
        let add = Address::from_str(address).unwrap();
        let bytes = base58::decode(address).unwrap();
        assert_eq!(bytes, add.as_bytes());
    }

    #[test]
    fn serialize_to_string() {
        let address = "4Byr22j9M2878Mtyb3fEPcBNwBZf5EXqn1Yi6VzR46618SFBrYysab2Cs1474CVDbsh94AJq7vuV3Z2DRq4zLcY3LHzo1Nbv3d8J6VhvCV";
        let add = Address::from_str(address).unwrap();
        assert_eq!(address, add.to_string());
    }

    #[test]
    fn test_to_from_hex_payment_id() {
        let payment_id_wrong_length_str = "abcd";
        assert_eq!(
            PaymentId::from_hex(payment_id_wrong_length_str).unwrap_err(),
            FromHexError::InvalidStringLength,
        );

        let payment_id_wrong_length_str = "a".repeat(10);
        assert_eq!(
            PaymentId::from_hex(payment_id_wrong_length_str).unwrap_err(),
            FromHexError::InvalidStringLength,
        );

        let payment_id = PaymentId::from_str("0123456789abcdef").unwrap();

        let payment_id_str: String = payment_id.encode_hex();
        assert_eq!(
            PaymentId::from_hex(payment_id_str.clone()).unwrap(),
            payment_id
        );

        let payment_id_str_with_0x = format!("0x{payment_id_str}");
        assert_eq!(
            PaymentId::from_hex(payment_id_str_with_0x).unwrap(),
            payment_id
        );
    }

    #[test]
    fn test_address_hex() {
        let address_str = "4Byr22j9M2878Mtyb3fEPcBNwBZf5EXqn1Yi6VzR46618SFBrYysab2Cs1474CVDbsh94AJq7vuV3Z2DRq4zLcY3LHzo1Nbv3d8J6VhvCV";

        let address_bytes = [
            19, 17, 81, 127, 230, 166, 35, 81, 36, 161, 94, 154, 206, 60, 98, 195, 62, 12, 11, 234,
            133, 228, 196, 77, 3, 68, 188, 84, 78, 94, 109, 238, 44, 115, 212, 211, 204, 198, 30,
            73, 70, 235, 52, 160, 200, 39, 215, 134, 239, 249, 129, 47, 156, 14, 116, 18, 191, 112,
            207, 139, 208, 54, 59, 92, 115, 88, 118, 184, 183, 41, 150, 255, 151, 133, 45, 85, 110,
        ];
        let address_hex_lower = hex::encode(address_bytes);
        let address_hex_lower_with_0x = format!("0x{}", address_hex_lower);
        let address_hex_upper = hex::encode_upper(address_bytes);

        let address = Address::from_str(address_str).unwrap();

        assert_eq!(address.as_hex(), address_hex_lower);
        assert_eq!(address.encode_hex::<String>(), address_hex_lower);
        assert_eq!(address.encode_hex_upper::<String>(), address_hex_upper);

        let address_from_hex = Address::from_hex(address_hex_lower).unwrap();
        assert_eq!(address_from_hex, address);
        let address_from_hex_with_0x = Address::from_hex(address_hex_lower_with_0x).unwrap();
        assert_eq!(address_from_hex_with_0x, address);
    }

    #[test]
    fn previous_fuzz_address_from_bytes_failures() {
        let data = [];
        let _ = Address::from_bytes(&data);
        let data = [63];
        let _ = Address::from_bytes(&data);
        let data = [
            25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];
        let _ = Address::from_bytes(&data);
    }

    #[test]
    fn previous_fuzz_address_from_slice_failures() {
        fn fuzz(data: &[u8]) -> bool {
            let network = if data.is_empty() {
                Network::Mainnet
            } else {
                match data.len() % 3 {
                    0 => Network::Mainnet,
                    1 => Network::Testnet,
                    2 => Network::Stagenet,
                    _ => unreachable!(),
                }
            };
            let _ = AddressType::from_slice(data, network);
            true
        }

        let data = [];
        fuzz(&data);
        let data = [25, 0, 0, 0, 0];
        fuzz(&data);
        let data = [25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        fuzz(&data);
    }
}

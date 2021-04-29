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

use std::fmt;
use std::str::FromStr;

use base58_monero::base58;
use keccak_hash::keccak_256;

use crate::network::{self, Network};
use crate::util::key::{KeyPair, PublicKey, ViewPair};

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
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum AddressType {
    /// Standard address.
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

impl Default for AddressType {
    fn default() -> AddressType {
        AddressType::Standard
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
        let addr_type = AddressType::from_slice(&bytes, network)?;
        let public_spend =
            PublicKey::from_slice(&bytes[1..33]).map_err(|_| Error::InvalidFormat)?;
        let public_view =
            PublicKey::from_slice(&bytes[33..65]).map_err(|_| Error::InvalidFormat)?;

        let mut verify_checksum = [0u8; 32];
        let (checksum_bytes, checksum) = match addr_type {
            AddressType::Standard | AddressType::SubAddress => (&bytes[0..65], &bytes[65..69]),
            AddressType::Integrated(_) => (&bytes[0..73], &bytes[73..77]),
        };
        keccak_256(checksum_bytes, &mut verify_checksum);
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

        let mut checksum = [0u8; 32];
        keccak_256(bytes.as_slice(), &mut checksum);
        bytes.extend_from_slice(&checksum[0..4]);
        bytes
    }

    /// Serialize the address as an hexadecimal string.
    pub fn as_hex(&self) -> String {
        hex::encode(self.as_bytes())
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

#[cfg(any(feature = "serde", feature = "serde_support"))]
mod serde_impl {
    use super::*;

    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

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

#[cfg(test)]
mod tests {
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
}

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

//! Sub-address index structure and key calculation helper functions for [`address`].
//!
//! Sub-addresses are grouped with index of sub-addresses as a pair of indices `(i,j)` with `i`,
//! the major index, representing a group of sub-addresses (called an _account_) and `j`, the minor
//! index, representing a particular sub-address within that account.
//!
//! [`address`]: crate::util::address
//!

#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};
use std::fmt;
use std::io::Cursor;

use crate::consensus::encode::Encodable;
use crate::cryptonote::hash;
use crate::network::Network;
use crate::util::address::{Address, AddressError};
use crate::util::key::{KeyPair, PrivateKey, PublicKey, ViewPair};

/// A sub-address index with `major` and `minor` indexes, primary address is `0/0`.
///
/// Index implements [`Default`] and returns `0/0`.
///
#[derive(Default, Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct Index {
    /// The major index, also account.
    pub major: u32,
    /// The minor index, the actual sub-address index.
    pub minor: u32,
}

impl Index {
    /// Return `true` if major and minor indexes are both equal to `0`, the zero case is a special
    /// case.
    pub fn is_zero(self) -> bool {
        self.major == 0 && self.minor == 0
    }
}

impl fmt::Display for Index {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.major, self.minor)
    }
}

/// Compute the scalar `m = Hn("SubAddr" || v || major_index || minor_index)` at index `i` from the
/// view secret key `v`.
pub fn get_secret_scalar(view: &PrivateKey, index: Index) -> Result<PrivateKey, AddressError> {
    // x = a || account_index || minor_index
    let mut encoder = Cursor::new(vec![]);
    view.consensus_encode(&mut encoder)
        .map_err(|e| AddressError::Encoding(e.to_string()))?;
    index
        .major
        .consensus_encode(&mut encoder)
        .map_err(|e| AddressError::Encoding(e.to_string()))?;
    index
        .minor
        .consensus_encode(&mut encoder)
        .map_err(|e| AddressError::Encoding(e.to_string()))?;
    // y = "SubAddr" || x
    let mut prefix: Vec<_> = b"SubAddr\x00"[..].into();
    prefix.extend_from_slice(&encoder.into_inner());
    // m = Hn(y)
    Ok(hash::Hash::hash_to_scalar(&prefix))
}

/// Compute the private spend key `s' = s + m` where `m` is computed with `get_secret_scalar` based
/// on `v`.
pub fn get_spend_secret_key(keys: &KeyPair, index: Index) -> Result<PrivateKey, AddressError> {
    // If index is equal to 0, then return s as s'
    if index.is_zero() {
        return Ok(keys.spend);
    }
    // ...otherwise compute s'
    Ok(keys.spend + get_secret_scalar(&keys.view, index)?)
}

/// Compute the private view key `v' = v * s'` where `s'` is computed with `get_spend_secret_key`.
pub fn get_view_secret_key(keys: &KeyPair, index: Index) -> Result<PrivateKey, AddressError> {
    // If index is equal to 0, then return v as v'
    if index.is_zero() {
        return Ok(keys.spend);
    }
    // ...otherwise compute v'
    Ok(keys.view * get_spend_secret_key(keys, index)?)
}

/// Compute a subkey pair `(v', s')` from a root keypair `(v, s)` for index `i`.
pub fn get_secret_keys(keys: &KeyPair, index: Index) -> Result<KeyPair, AddressError> {
    let view = get_view_secret_key(keys, index)?;
    let spend = get_spend_secret_key(keys, index)?;
    Ok(KeyPair { view, spend })
}

/// Compute the spend public key `S' = mG + S` at index `i` from the view pair `(v, S)`.
///
/// If index is equal to zero return `S` as `S'`.
///
pub fn get_spend_public_key(keys: &ViewPair, index: Index) -> Result<PublicKey, AddressError> {
    // If index is equal to 0, then return S as S'
    if index.is_zero() {
        return Ok(keys.spend);
    }
    // ...otherwise compute S'
    // m = Hn(v || index_major || index_minor)
    let m = get_secret_scalar(&keys.view, index)?;
    // S' = S + m*G
    Ok(keys.spend + PublicKey::from_private_key(&m))
}

/// Compute the view public key and spend public key `(V', S')` at index `i` from view pair `(v, S)`
/// where `V' = v*S'` and `S' = mG + S`.
///
/// If index is equal to zero return `(v, S)` as `(V', S')`.
///
pub fn get_public_keys(
    keys: &ViewPair,
    index: Index,
) -> Result<(PublicKey, PublicKey), AddressError> {
    // If index is equal to 0, then return (V, S) as (V', S')
    if index.is_zero() {
        // Get V from v
        let view = PublicKey::from_private_key(&keys.view);
        return Ok((view, keys.spend));
    }
    // ...otherwise compute (V', S')
    // Get S' from (v, S)
    let spend = get_spend_public_key(keys, index)?;
    // V' = v*S'
    let view = keys.view * &spend;
    Ok((view, spend))
}

/// Compute the sub-address at index `i` valid on the given network (by default
/// [`Network::Mainnet`]).
///
/// [`Network::Mainnet`]: crate::network::Network::Mainnet
///
pub fn get_subaddress(
    keys: &ViewPair,
    index: Index,
    network: Option<Network>,
) -> Result<Address, AddressError> {
    let net = network.unwrap_or_default();
    let (view, spend) = get_public_keys(keys, index)?;
    Ok(Address::subaddress(net, spend, view))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{get_public_keys, get_subaddress, Index};
    use crate::network::Network;
    use crate::util::key::{PrivateKey, PublicKey, ViewPair};

    #[test]
    #[allow(non_snake_case)]
    fn get_subkeys_test() {
        let a = PrivateKey::from_str(
            "77916d0cd56ed1920aef6ca56d8a41bac915b68e4c46a589e0956e27a7b77404",
        )
        .unwrap();
        let b = PrivateKey::from_str(
            "8163466f1883598e6dd14027b8da727057165da91485834314f5500a65846f09",
        )
        .unwrap();
        let B = PublicKey::from_private_key(&b);
        //let keypair = KeyPair { view: a, spend: b };
        let viewpair = ViewPair { view: a, spend: B };

        let index = Index {
            major: 2,
            minor: 18,
        };
        let (sub_view_pub, sub_spend_pub) = get_public_keys(&viewpair, index).unwrap();

        assert_eq!(
            "601782bdde614e9ba664048a27b7407df4b76ae2e50a85fcc168a4c1766b3edf",
            sub_view_pub.to_string()
        );
        assert_eq!(
            "c25179ddef2ca4728fb691dd71561dc9f2e7e6b2a14284a4fe5441d7757aea02",
            sub_spend_pub.to_string()
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn get_subaddress_test() {
        let a = PrivateKey::from_str(
            "77916d0cd56ed1920aef6ca56d8a41bac915b68e4c46a589e0956e27a7b77404",
        )
        .unwrap();
        let b = PrivateKey::from_str(
            "8163466f1883598e6dd14027b8da727057165da91485834314f5500a65846f09",
        )
        .unwrap();
        let B = PublicKey::from_private_key(&b);
        //let keypair = KeyPair { view: a, spend: b };
        let viewpair = ViewPair { view: a, spend: B };

        let index = Index {
            major: 2,
            minor: 18,
        };
        let address = get_subaddress(&viewpair, index, Some(Network::Mainnet)).unwrap();

        assert_eq!("89pMNxzcCo5LAPZDX4qaTeanA6ZiS3VRdUbeKHzbDZkD1Q3YsDDfmXbT2zyjLeHWuuN4vxKne8kNpjH3cMk7nmhwSALCxsd", address.to_string());
    }
}

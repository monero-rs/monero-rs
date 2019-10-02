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

//! Support for CryptoNote sub-address protocol.
//!
//! Sub-addresses are grouped with index of subaddresses as a pair of indices `(i,j)` with `i`, the
//! major index, representing a group of subaddresses (called an _account_) and `j`, the minor
//! index, representing a particular subaddress within that account.
//!

use std::fmt;
use std::io::Cursor;

use crate::consensus::encode::Encodable;
use crate::cryptonote::hash;
use crate::network::Network;
use crate::util::address::Address;
use crate::util::key::{PrivateKey, PublicKey, ViewPair};

/// A subaddress index with `major` and `minor` indexes
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Index {
    /// The major index, also account
    pub major: u32,
    /// The minor index, the actual subaddress index
    pub minor: u32,
}

impl Index {
    /// Return `true` if major and minor indexes are both equal to 0, the zero case is a special
    /// case
    pub fn is_zero(self) -> bool {
        self.major == 0 && self.minor == 0
    }
}

impl fmt::Display for Index {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.major, self.minor)
    }
}

impl Default for Index {
    fn default() -> Index {
        Index { major: 0, minor: 0 }
    }
}

/// Compute the scalar `m = Hn("SubAddr" || a || major_index || minor_index)` at index `i` from
/// the view secret key `a`
pub fn get_subaddress_secret_key(view: &PrivateKey, index: Index) -> PrivateKey {
    // x = a || account_index || minor_index
    let mut encoder = Cursor::new(vec![]);
    view.consensus_encode(&mut encoder).unwrap();
    index.major.consensus_encode(&mut encoder).unwrap();
    index.minor.consensus_encode(&mut encoder).unwrap();
    // y = "SubAddr" || x
    let mut prefix: Vec<_> = b"SubAddr\x00"[..].into();
    prefix.extend_from_slice(&encoder.into_inner());
    // m = Hn(y)
    hash::Hash::hash_to_scalar(&prefix)
}

/// Compute the spend public key `D = mG + B` at index `i` from the view pair `(a, B)`
pub fn get_subaddress_spend_public_key(keys: &ViewPair, index: Index) -> PublicKey {
    if index.is_zero() {
        return keys.spend;
    }
    // m = Hn(a || index_major || index_minor)
    let m = get_subaddress_secret_key(&keys.view, index);
    // M = m*G
    let m_pub = PublicKey::from_private_key(&m);
    // D = B + M
    keys.spend + m_pub
}

/// Compute the view public key and spend public key `(C, D)` at index `i` from view pair `(a, B)`
/// where `C = a*D` and `D = mG + B`
pub fn get_subkeys(keys: &ViewPair, index: Index) -> (PublicKey, PublicKey) {
    if index.is_zero() {
        let view = PublicKey::from_private_key(&keys.view);
        return (view, keys.spend);
    }
    let spend = get_subaddress_spend_public_key(keys, index);
    // C = a*D
    let view = keys.view * &spend;
    (view, spend)
}

/// Compute the subaddress at index `i` valid on the given network (by default mainnet)
pub fn get_subaddress(keys: &ViewPair, index: Index, network: Option<Network>) -> Address {
    let net = match network {
        Some(net) => net,
        None => Network::default(),
    };
    let (view, spend) = get_subkeys(keys, index);
    Address::subaddress(net, spend, view)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{get_subaddress, get_subkeys, Index};
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
        let (sub_view_pub, sub_spend_pub) = get_subkeys(&viewpair, index);

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
        let address = get_subaddress(&viewpair, index, Some(Network::Mainnet));

        assert_eq!("89pMNxzcCo5LAPZDX4qaTeanA6ZiS3VRdUbeKHzbDZkD1Q3YsDDfmXbT2zyjLeHWuuN4vxKne8kNpjH3cMk7nmhwSALCxsd", address.to_string());
    }
}

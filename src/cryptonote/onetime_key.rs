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

//! CryptoNote One-Time Keys protocol
//!
//! Support for CryptoNote one-time keys which the sender derives from random data and the
//! receiver's address. Upon receiving a transaction, user scans all output keys and checks if he
//! can recover the corresponding secret key. He succeeds if and only if that particular output was
//! sent to his address.
//!

use std::collections::HashMap;
use std::io::Cursor;
use std::ops::Range;

use crate::consensus::encode::{Encodable, VarInt};
use crate::cryptonote::hash;
use crate::cryptonote::hash::Hashable;
use crate::cryptonote::subaddress::{self, Index};
use crate::util::key::{KeyPair, PrivateKey, PublicKey, ViewPair};

/// Helper to generate One-Time Public keys in transactions
pub struct KeyGenerator {
    /// Spend public key `B`
    pub spend: PublicKey,
    /// Intermediate key `a*R` or `r*A` used during the generation process
    pub ra: PublicKey,
}

impl KeyGenerator {
    /// Construct a One-time key generator from public keys and secret random, this is used to
    /// generate One-time keys for output indexes from an address when sending funds
    pub fn from_random(view: PublicKey, spend: PublicKey, random: PrivateKey) -> Self {
        // Computes a*R
        let ra = random * &view;
        KeyGenerator { spend, ra }
    }

    /// Construct a One-time key generator from private keys and public random (tx pub key), this
    /// is used to scan if some outputs contains One-time keys owned by the view pair
    pub fn from_key(keys: &ViewPair, random: PublicKey) -> Self {
        // Computes a*R
        let ra = random * &keys.view;
        KeyGenerator {
            spend: keys.spend,
            ra,
        }
    }

    /// Compute the One-time public key `P = H(r*A || n)*G + B` for the indexed output `n`
    pub fn one_time_key(&self, index: usize) -> PublicKey {
        // Computes a one-time public key P = H(r*A || n)*G + B
        self.spend + PublicKey::from_private_key(&self.get_ran_scalar(index))
    }

    /// Check if key `P` is equal to indexed key `P'`, if true the output is own by the address,
    /// used when scanning transaction outputs, if true the One-time key is related to the keys
    pub fn check(&self, index: usize, key: PublicKey) -> bool {
        key == self.one_time_key(index)
    }

    // Computes `H(a*R || n)` and interpret it as a scalar
    fn get_ran_scalar(&self, index: usize) -> PrivateKey {
        // Serializes (a*R || n)
        let mut encoder = Cursor::new(vec![]);
        self.ra.consensus_encode(&mut encoder).unwrap();
        VarInt(index as u64).consensus_encode(&mut encoder).unwrap();
        // Computes H(a*R || n) and interpret as a scalar
        //
        // The hash function H is the same Keccak function that is used in CryptoNote. When the
        // value of the hash function is interpreted as a scalar, it is converted into a
        // little-endian integer and taken modulo l.
        hash::Hash::hash_to_scalar(&encoder.into_inner())
    }
}

/// Helper to generate one-time public key output and its additional transaction public key
pub struct SubKeyGenerator {
    /// Sub-address actual view public key
    pub view: PublicKey,
    /// Sub-address actual spend public key
    pub spend: PublicKey,
}

impl SubKeyGenerator {
    /// Create a new subkey generator
    pub fn new(view: PublicKey, spend: PublicKey) -> Self {
        SubKeyGenerator { view, spend }
    }

    /// Generate the one-time output public key and its additional transaction public key based on
    /// a random scalar
    pub fn one_time_keys(&self, random: &PrivateKey) -> (PublicKey, PublicKey) {
        let onetime_key = SubKeyChecker::get_ar_scalar(random, &self.view);
        let onetime_key = PublicKey::from_private_key(&onetime_key);
        let onetime_key = onetime_key + self.spend;
        let tx_random = random * &self.spend;
        (onetime_key, tx_random)
    }
}

/// Helper needed to check if a One-time sub address public key is related to a view pair
///
/// Generate a table of sub keys from a view pair for a sub address given a major range
/// and a minor range
pub struct SubKeyChecker<'a> {
    /// The actual table
    pub table: HashMap<PublicKey, Index>,
    /// The actual view pair `(a, B)`
    pub keys: &'a ViewPair,
}

impl<'a> SubKeyChecker<'a> {
    /// Create a new table of sub keys `K \in major x minor` from a view pair mapped to their
    /// Sub-address indexes
    pub fn new(keys: &'a ViewPair, major: Range<u32>, minor: Range<u32>) -> Self {
        let mut table = HashMap::new();
        major.for_each(|maj| {
            minor.clone().for_each(|min| {
                let index = Index {
                    major: maj,
                    minor: min,
                };
                let (_, spend) = subaddress::get_subkeys(keys, index);
                table.insert(spend, index);
            });
        });
        SubKeyChecker { table, keys }
    }

    /// Computes `H(a*R)` and interpret it as a scalar
    pub fn get_ar_scalar(view: &PrivateKey, tx_random: &PublicKey) -> PrivateKey {
        let ar = *view * tx_random;
        //// Computes H(a*R) and interpret as a scalar
        ar.hash_to_scalar()
    }

    /// Check if a output public key with its additional random tx public key is in the table, if
    /// found then the output is own by the view pair, otherwise the output might be own by someone
    /// else, or the table migth be too small
    pub fn check(&self, out_pk: &PublicKey, tx_random: &PublicKey) -> Option<&Index> {
        // Hs(a*R)
        let s = Self::get_ar_scalar(&self.keys.view, tx_random);
        // Hs(a*R)*G
        let s_pk = PublicKey::from_private_key(&s);
        // D' = P - Hs(a*R)*G
        self.table.get(&(out_pk - s_pk))
    }
}

/// Helper needed to compute One-Time Private keys
pub struct KeyRecoverer<'a> {
    /// Spend private key `b`
    pub spend: &'a PrivateKey,
    /// Key generator used to check and generate intermediate values
    pub checker: KeyGenerator,
}

impl<'a> KeyRecoverer<'a> {
    /// Construct a One-time key generator from private keys and public random, this is used when
    /// scanning transaction outputs to recover private One-time keys
    pub fn new(keys: &'a KeyPair, random: PublicKey) -> Self {
        let viewpair = keys.into();
        let checker = KeyGenerator::from_key(&viewpair, random);
        KeyRecoverer {
            spend: &keys.spend,
            checker,
        }
    }

    /// Recover the One-time private key `p = H(a*R || n) + b` for index `n`
    pub fn recover(&self, index: usize) -> PrivateKey {
        let scal = self.checker.get_ran_scalar(index);
        // Computes x = H(a*R || n) + b
        scal + self.spend
    }

    /// Recover the One-time private key associated with a Subaddress index `i` (major, minor
    /// indexes)
    ///
    /// ```text
    /// p = { Hs(a*R) + b                   i == 0
    ///     { Hs(a*R) + b + Hs(a || i)      otherwise
    /// ```
    pub fn recover_subkey(keys: &KeyPair, tx_random: &PublicKey, index: Index) -> PrivateKey {
        let b = if index.is_zero() {
            keys.spend
        } else {
            let sub_spend = subaddress::get_subaddress_secret_key(&keys.view, index);
            keys.spend + sub_spend
        };
        SubKeyChecker::get_ar_scalar(&keys.view, tx_random) + b
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{KeyGenerator, KeyRecoverer, SubKeyChecker, SubKeyGenerator};
    use crate::cryptonote::subaddress::{self, Index};
    use crate::util::key::{KeyPair, PrivateKey, PublicKey, ViewPair};

    #[test]
    #[allow(non_snake_case)]
    fn one_time_key() {
        let a = PrivateKey::from_str(
            "77916d0cd56ed1920aef6ca56d8a41bac915b68e4c46a589e0956e27a7b77404",
        )
        .unwrap();
        let b = PrivateKey::from_str(
            "8163466f1883598e6dd14027b8da727057165da91485834314f5500a65846f09",
        )
        .unwrap();
        let A = PublicKey::from_private_key(&a);
        let B = PublicKey::from_private_key(&b);
        let keypair = KeyPair { view: a, spend: b };

        let r = PrivateKey::from_str(
            "3398f55bb862aa2689888747421c466fa712f954b98a8bbd608bcd4988a3e30e",
        )
        .unwrap();
        let R = PublicKey::from_private_key(&r); // tx_pubkey

        let generator = KeyGenerator::from_random(A, B, r);
        // Generate P
        let one_time_pk = generator.one_time_key(1);
        assert_eq!(
            "07e94dcf0f2348d374da13fe575df11b5af739bf2cf962823e068a5297f47557",
            one_time_pk.to_string()
        );

        let recover = KeyRecoverer::new(&keypair, R);
        assert_eq!(true, recover.checker.check(1, one_time_pk));
        assert_eq!(false, recover.checker.check(2, one_time_pk));
        // Generate x : P = xG
        let one_time_sk = recover.recover(1);
        assert_eq!(
            "2e476527180a94328f86f1ba814603e65f99e7c1c44cbb2dbf4508c20879b200",
            one_time_sk.to_string()
        );
        assert_eq!(one_time_pk, PublicKey::from_private_key(&one_time_sk));
    }

    #[test]
    #[allow(non_snake_case)]
    fn one_time_subkey() {
        let a = PrivateKey::from_str(
            "77916d0cd56ed1920aef6ca56d8a41bac915b68e4c46a589e0956e27a7b77404",
        )
        .unwrap();
        let b = PrivateKey::from_str(
            "8163466f1883598e6dd14027b8da727057165da91485834314f5500a65846f09",
        )
        .unwrap();
        let B = PublicKey::from_private_key(&b);
        let keypair = KeyPair { view: a, spend: b };
        let viewpair = ViewPair { view: a, spend: B };

        let index = Index {
            major: 2,
            minor: 18,
        };
        let (sub_view_pub, sub_spend_pub) = subaddress::get_subkeys(&viewpair, index);

        let r = PrivateKey::from_str(
            "3398f55bb862aa2689888747421c466fa712f954b98a8bbd608bcd4988a3e30e",
        )
        .unwrap();

        let generator = SubKeyGenerator::new(sub_view_pub, sub_spend_pub);
        let (onetime_key, tx_random) = generator.one_time_keys(&r);

        let checker = SubKeyChecker::new(&viewpair, 0..10, 0..20);
        let check = checker.check(&onetime_key, &tx_random);
        assert_eq!(
            Some(&Index {
                major: 2,
                minor: 18
            }),
            check
        );

        // Recover p : P = p*G
        let privkey = KeyRecoverer::recover_subkey(&keypair, &tx_random, *check.unwrap());
        assert_eq!(onetime_key, PublicKey::from_private_key(&privkey));
    }
}

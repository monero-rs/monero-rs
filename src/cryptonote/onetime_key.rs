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

//! Onetime key generation and recovery helpers and functions.
//!
//! Support for CryptoNote onetime keys which the sender derives from random data and the
//! receiver's address. Upon receiving a transaction, user scans all output keys and checks if he
//! can recover the corresponding secret key. He succeeds if and only if that particular output was
//! sent to his address.
//!
//! ## Checking output ownership
//!
//! ```rust
//! use std::str::FromStr;
//! use monero::{PublicKey, PrivateKey};
//! use monero::cryptonote::onetime_key::SubKeyChecker;
//! use monero::cryptonote::subaddress::Index;
//! use monero::util::key::ViewPair;
//!
//! let view = PrivateKey::from_str("bcfdda53205318e1c14fa0ddca1a45df363bb427972981d0249d0f4652a7df07").unwrap();
//! let secret_spend = PrivateKey::from_str("e5f4301d32f3bdaef814a835a18aaaa24b13cc76cf01a832a7852faf9322e907").unwrap();
//! let spend = PublicKey::from_private_key(&secret_spend);
//!
//!  let viewpair = ViewPair {
//!      view,
//!      spend,
//!  };
//!
//! let one_time_pk =
//!     PublicKey::from_str("e3e77faca64b5997ac1f75763e87713d03d9e2896edec65843ffd2970ef1dde6")
//!         .unwrap();
//!
//! let tx_pubkey =
//!     PublicKey::from_str("5d1402db663eda8cef4f6782b66321e4a990f746aca249c973e098ba2c0837c1")
//!         .unwrap();
//!
//! let checker = SubKeyChecker::new(&viewpair, 0..3, 0..3).unwrap();
//!
//! assert_eq!(
//!     Some(&Index { major: 0, minor: 0 }),
//!     checker.check(1, &one_time_pk, &tx_pubkey).unwrap()
//! );
//! ```
//!

use std::collections::HashMap;
use std::io::Cursor;
use std::ops::Range;

use crate::consensus::encode::{Encodable, VarInt};
use crate::cryptonote::hash;
use crate::cryptonote::subaddress::{self, get_spend_secret_key, Index};
use crate::util::address::AddressError;
use crate::util::key::{KeyPair, PrivateKey, PublicKey, ViewPair};

/// Special factor used in all `vR` and `rV` multiplications.
pub const MONERO_MUL_FACTOR: u8 = 8;

/// Helper to generate onetime public keys (ephemeral keys) used in transactions.
#[derive(Debug, Clone)]
pub struct KeyGenerator {
    /// Spend public key `S`.
    pub spend: PublicKey,
    /// Intermediate key `v*8*R` or `r*8*V` used during the generation process.
    pub rv: PublicKey,
}

impl KeyGenerator {
    /// Construct a onetime key generator from public keys and secret random, this is used to
    /// generate onetime keys for output indexes from an address when sending funds.
    pub fn from_random(view: PublicKey, spend: PublicKey, random: PrivateKey) -> Self {
        // Computes r*8*V
        let rv = random * MONERO_MUL_FACTOR * &view;
        KeyGenerator { spend, rv }
    }

    /// Construct a onetime key generator from private keys and public random (tx pubkey), this is
    /// used to scan if some outputs contains onetime keys owned by the view pair.
    pub fn from_key(keys: &ViewPair, random: PublicKey) -> Self {
        // Computes v*8*R
        let rv = keys.view * MONERO_MUL_FACTOR * &random;
        KeyGenerator {
            spend: keys.spend,
            rv,
        }
    }

    /// Compute the onetime public key `P = Hn(r*8*V || n)*G + S` for the indexed output `n`.
    pub fn one_time_key(&self, index: usize) -> Result<PublicKey, AddressError> {
        // Computes a onetime public key P = Hn(r*8*V || n)*G + S
        Ok(PublicKey::from_private_key(&self.get_rvn_scalar(index)?) + self.spend)
    }

    /// Check if key `P` is equal to indexed key `P'`, if true the output is own by the address,
    /// used when scanning transaction outputs, if true the onetime key is related to the keys.
    pub fn check(&self, index: usize, key: PublicKey) -> Result<bool, AddressError> {
        Ok(key == self.one_time_key(index)?)
    }

    /// Computes `Hn(v*8*R || n)` and interpret it as a scalar.
    pub fn get_rvn_scalar(&self, index: usize) -> Result<PrivateKey, AddressError> {
        // Serializes (v*8*R || n)
        let mut encoder = Cursor::new(vec![]);
        self.rv.consensus_encode(&mut encoder).unwrap();
        VarInt(index as u64)
            .consensus_encode(&mut encoder)
            .map_err(|e| AddressError::Encoding(e.to_string()))?;
        // Computes Hn(v*8*R || n) and interpret as a scalar
        //
        // The hash function H is the same Keccak function that is used in CryptoNote. When the
        // value of the hash function is interpreted as a scalar, it is converted into a
        // little-endian integer and taken modulo l.
        Ok(hash::Hash::hash_to_scalar(encoder.into_inner()))
    }
}

/// Helper to check if a onetime sub-address public key is related to a view pair.
///
/// Generate a table of sub-keys from a view pair given a major range and a minor range. These
/// precomputed keys are used to check if an output is owned by the root view pair.
#[derive(Debug, Clone)]
pub struct SubKeyChecker<'a> {
    /// Table of public spend keys and their corresponding indexes.
    pub table: HashMap<PublicKey, Index>,
    /// The root view pair `(v, S)`.
    pub keys: &'a ViewPair,
}

impl<'a> SubKeyChecker<'a> {
    /// Generate the table of sub spend keys `K(S) \in major x minor` from a view pair mapped to
    /// their Sub-address indexes.
    pub fn new(
        keys: &'a ViewPair,
        major: Range<u32>,
        minor: Range<u32>,
    ) -> Result<Self, AddressError> {
        let mut table = HashMap::new();

        for maj in major {
            for min in minor.clone() {
                let index = Index {
                    major: maj,
                    minor: min,
                };
                match subaddress::get_spend_public_key(keys, index) {
                    Ok(spend) => {
                        table.insert(spend, index);
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
        }

        Ok(SubKeyChecker { table, keys })
    }

    /// Check if an output public key with its associated random tx public key at index `i` is in
    /// the table, if found then the output is own by the view pair, otherwise the output might be
    /// own by someone else, or the table migth be too small.
    pub fn check(
        &self,
        index: usize,
        key: &PublicKey,
        tx_pubkey: &PublicKey,
    ) -> Result<Option<&Index>, AddressError> {
        let keygen = KeyGenerator::from_key(self.keys, *tx_pubkey);
        // D' = P - Hs(v*8*R || n)*G
        Ok(self
            .table
            .get(&(key - PublicKey::from_private_key(&keygen.get_rvn_scalar(index)?))))
    }

    /// Same as check but uses a pre-generated KeyGenerator
    pub fn check_with_key_generator(
        &self,
        keygen: KeyGenerator,
        index: usize,
        key: &PublicKey,
    ) -> Result<Option<&Index>, AddressError> {
        // D' = P - Hs(v*8*R || n)*G
        Ok(self
            .table
            .get(&(key - PublicKey::from_private_key(&keygen.get_rvn_scalar(index)?))))
    }
}

/// Helper to compute onetime private keys.
#[derive(Debug, Clone)]
pub struct KeyRecoverer<'a> {
    /// Private key pair `(v, s)`.
    pub keys: &'a KeyPair,
    /// Key generator used to check and generate intermediate values.
    pub checker: KeyGenerator,
}

impl<'a> KeyRecoverer<'a> {
    /// Construct a onetime key generator from private keys, this is used when scanning transaction
    /// outputs to recover private onetime keys.
    pub fn new(keys: &'a KeyPair, tx_pubkey: PublicKey) -> Self {
        let viewpair = keys.into();
        let checker = KeyGenerator::from_key(&viewpair, tx_pubkey);
        KeyRecoverer { keys, checker }
    }

    /// Recover the onetime private key `p` at address index `i` (major, minor indexes) and
    /// output index `n` such as:
    ///
    /// ```text
    /// p = { Hn(v*8*R || n) + s                  i == 0
    ///     { Hn(v*8*R || n) + s + Hn(v || i)     otherwise
    /// ```
    ///
    /// See sub-address key derivation for more details on address index handling.
    ///
    pub fn recover(&self, oindex: usize, aindex: Index) -> Result<PrivateKey, AddressError> {
        // Hn(v*8*R || n)
        let scal = self.checker.get_rvn_scalar(oindex)?;
        // s' = { s                   i == 0
        //      { s + Hn(v || i)      otherwise
        let s = get_spend_secret_key(self.keys, aindex)?;
        // Hn(v*8*R || n) + s'
        Ok(scal + s)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{KeyGenerator, KeyRecoverer, SubKeyChecker};
    use crate::cryptonote::subaddress::Index;
    use crate::util::key::{KeyPair, PrivateKey, PublicKey, ViewPair};

    #[test]
    fn one_time_key_generator() {
        let secret_view = PrivateKey::from_str(
            "bcfdda53205318e1c14fa0ddca1a45df363bb427972981d0249d0f4652a7df07",
        )
        .unwrap();

        let secret_spend = PrivateKey::from_str(
            "e5f4301d32f3bdaef814a835a18aaaa24b13cc76cf01a832a7852faf9322e907",
        )
        .unwrap();

        let public_spend = PublicKey::from_private_key(&secret_spend);

        let viewpair = ViewPair {
            view: secret_view,
            spend: public_spend,
        };

        let one_time_pk =
            PublicKey::from_str("e3e77faca64b5997ac1f75763e87713d03d9e2896edec65843ffd2970ef1dde6")
                .unwrap();

        let tx_pubkey =
            PublicKey::from_str("5d1402db663eda8cef4f6782b66321e4a990f746aca249c973e098ba2c0837c1")
                .unwrap();

        let generator = KeyGenerator::from_key(&viewpair, tx_pubkey);

        assert!(!generator.check(0, one_time_pk).unwrap());
        assert!(generator.check(1, one_time_pk).unwrap());
        assert!(!generator.check(2, one_time_pk).unwrap());
    }

    #[test]
    fn one_time_key_recover() {
        let secret_view = PrivateKey::from_str(
            "bcfdda53205318e1c14fa0ddca1a45df363bb427972981d0249d0f4652a7df07",
        )
        .unwrap();

        let secret_spend = PrivateKey::from_str(
            "e5f4301d32f3bdaef814a835a18aaaa24b13cc76cf01a832a7852faf9322e907",
        )
        .unwrap();

        let keypair = KeyPair {
            view: secret_view,
            spend: secret_spend,
        };

        let one_time_sk = PrivateKey::from_str(
            "afaebe00bcb29e233c2717e4574c7c8b114890571430bd1427d835ed7339050e",
        )
        .unwrap();
        let one_time_pk = PublicKey::from_private_key(&one_time_sk);

        assert_eq!(
            "e3e77faca64b5997ac1f75763e87713d03d9e2896edec65843ffd2970ef1dde6",
            one_time_pk.to_string()
        );

        let tx_pubkey =
            PublicKey::from_str("5d1402db663eda8cef4f6782b66321e4a990f746aca249c973e098ba2c0837c1")
                .unwrap();

        let index = 1;
        let sub_index = Index::default();
        let recoverer = KeyRecoverer::new(&keypair, tx_pubkey);

        let rec_one_time_sk = recoverer.recover(index, sub_index).unwrap();

        assert_eq!(
            "afaebe00bcb29e233c2717e4574c7c8b114890571430bd1427d835ed7339050e",
            rec_one_time_sk.to_string()
        );

        assert_eq!(one_time_pk, PublicKey::from_private_key(&rec_one_time_sk));
    }

    #[test]
    fn one_time_subkey_recover() {
        let secret_view = PrivateKey::from_str(
            "bcfdda53205318e1c14fa0ddca1a45df363bb427972981d0249d0f4652a7df07",
        )
        .unwrap();

        let secret_spend = PrivateKey::from_str(
            "e5f4301d32f3bdaef814a835a18aaaa24b13cc76cf01a832a7852faf9322e907",
        )
        .unwrap();

        let keypair = KeyPair {
            view: secret_view,
            spend: secret_spend,
        };

        let one_time_sk = PrivateKey::from_str(
            "9650bef0bff89132c91f2244d909e0d65acd13415a46efcb933e6c10b7af4c01",
        )
        .unwrap();
        let one_time_pk = PublicKey::from_private_key(&one_time_sk);

        assert_eq!(
            "b6a2e2f35a93d637ff7d25e20da326cee8e92005d3b18b3c425dabe833656899",
            one_time_pk.to_string()
        );

        let tx_pubkey =
            PublicKey::from_str("d6c75cf8c76ac458123f2a498512eb65bb3cecba346c8fcfc516dc0c88518bb9")
                .unwrap();

        let index = 1;
        let sub_index = Index { major: 0, minor: 1 };
        let recoverer = KeyRecoverer::new(&keypair, tx_pubkey);

        let rec_one_time_sk = recoverer.recover(index, sub_index).unwrap();

        assert_eq!(
            "9650bef0bff89132c91f2244d909e0d65acd13415a46efcb933e6c10b7af4c01",
            rec_one_time_sk.to_string()
        );

        assert_eq!(one_time_pk, PublicKey::from_private_key(&rec_one_time_sk));
    }

    #[test]
    fn one_time_key_checker() {
        let secret_view = PrivateKey::from_str(
            "bcfdda53205318e1c14fa0ddca1a45df363bb427972981d0249d0f4652a7df07",
        )
        .unwrap();

        let secret_spend = PrivateKey::from_str(
            "e5f4301d32f3bdaef814a835a18aaaa24b13cc76cf01a832a7852faf9322e907",
        )
        .unwrap();

        let public_spend = PublicKey::from_private_key(&secret_spend);

        let viewpair = ViewPair {
            view: secret_view,
            spend: public_spend,
        };

        let one_time_pk =
            PublicKey::from_str("e3e77faca64b5997ac1f75763e87713d03d9e2896edec65843ffd2970ef1dde6")
                .unwrap();

        let tx_pubkey =
            PublicKey::from_str("5d1402db663eda8cef4f6782b66321e4a990f746aca249c973e098ba2c0837c1")
                .unwrap();

        let checker = SubKeyChecker::new(&viewpair, 0..3, 0..3).unwrap();

        assert_eq!(None, checker.check(0, &one_time_pk, &tx_pubkey).unwrap());
        assert_eq!(
            Some(&Index { major: 0, minor: 0 }),
            checker.check(1, &one_time_pk, &tx_pubkey).unwrap()
        );
        assert_eq!(None, checker.check(2, &one_time_pk, &tx_pubkey).unwrap());
    }

    #[test]
    fn one_time_subkey_checker() {
        let secret_view = PrivateKey::from_str(
            "bcfdda53205318e1c14fa0ddca1a45df363bb427972981d0249d0f4652a7df07",
        )
        .unwrap();

        let secret_spend = PrivateKey::from_str(
            "e5f4301d32f3bdaef814a835a18aaaa24b13cc76cf01a832a7852faf9322e907",
        )
        .unwrap();

        let public_spend = PublicKey::from_private_key(&secret_spend);

        let viewpair = ViewPair {
            view: secret_view,
            spend: public_spend,
        };

        let one_time_pk =
            PublicKey::from_str("b6a2e2f35a93d637ff7d25e20da326cee8e92005d3b18b3c425dabe833656899")
                .unwrap();

        let tx_pubkey =
            PublicKey::from_str("d6c75cf8c76ac458123f2a498512eb65bb3cecba346c8fcfc516dc0c88518bb9")
                .unwrap();

        let checker = SubKeyChecker::new(&viewpair, 0..3, 0..3).unwrap();

        assert_eq!(None, checker.check(0, &one_time_pk, &tx_pubkey).unwrap());
        assert_eq!(
            Some(&Index { major: 0, minor: 1 }),
            checker.check(1, &one_time_pk, &tx_pubkey).unwrap()
        );
        assert_eq!(None, checker.check(2, &one_time_pk, &tx_pubkey).unwrap());
    }
}

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

//! Hash functions and types (32-bytes hash and 8-bytes hash) used in [`blockdata`].
//!
//! Support for (de)serializable hashes (Keccak-256) and [`Hn()`] (hash to number, or hash to
//! scalar).
//!
//! [`blockdata`]: crate::blockdata
//! [`Hn()`]: Hashable::hash_to_scalar()
//!

// TODO: remove this when fixed-hash stop raising clippy errors...
#![allow(clippy::incorrect_clone_impl_on_copy_type)]

use curve25519_dalek::scalar::Scalar;
use sealed::sealed;
use tiny_keccak::{Hasher, Keccak};

use std::io;

use crate::consensus::encode::{self, Decodable, EncodeError};
use crate::util::key::PrivateKey;
#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};
use thiserror::Error;

fixed_hash::construct_fixed_hash!(
    /// Result of the Keccak-256 hashing function.
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
    pub struct Hash(32);
);

impl Hash {
    /// Create a null hash with all zeros.
    pub fn null() -> Hash {
        Hash([0u8; 32])
    }

    /// Hash a stream of bytes with the Keccak-256 hash function.
    pub fn new(input: impl AsRef<[u8]>) -> Hash {
        Hash(keccak_256(input.as_ref()))
    }

    /// Return the 32-bytes hash array.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Return the scalar of the hash as a little endian number modulo `l` (curve order).
    pub fn as_scalar(&self) -> PrivateKey {
        PrivateKey::from_scalar(Scalar::from_bytes_mod_order(self.0))
    }

    /// Hash a stream of bytes and return its scalar representation.
    ///
    /// The hash function `H` is the same Keccak function that is used in CryptoNote. When the
    /// value of the hash function is interpreted as a scalar, it is converted into a little-endian
    /// integer and taken modulo `l`.
    pub fn hash_to_scalar(input: impl AsRef<[u8]>) -> PrivateKey {
        Self::new(input).as_scalar()
    }
}

impl Decodable for Hash {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Hash, encode::EncodeError> {
        Ok(Hash(Decodable::consensus_decode(r)?))
    }
}

impl hex::FromHex for Hash {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let hex = hex.as_ref();
        let hex = hex.strip_prefix("0x".as_bytes()).unwrap_or(hex);

        let buffer = <[u8; 32]>::from_hex(hex)?;
        Ok(Hash(buffer))
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for Hash {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

/// Errors encountered when encoding or decoding data.
#[derive(Error, Debug, PartialEq)]
pub enum HashError {
    /// Encoding error.
    #[error("Encode error: {0}")]
    EncodeError(#[from] EncodeError),
}

/// Capacity of an object to hash itself and return the result as a plain [`struct@Hash`] or as an
/// interpreted scalar value into [`PrivateKey`].
pub trait Hashable {
    /// Return its own hash.
    fn hash(&self) -> Result<Hash, HashError>;

    /// Apply [`hash()`] on itself and return the interpreted scalar returned by the hash result.
    ///
    /// [`hash()`]: Hashable::hash()
    fn hash_to_scalar(&self) -> Result<PrivateKey, HashError> {
        Ok(self.hash()?.as_scalar())
    }
}

fixed_hash::construct_fixed_hash!(
    /// An 8-bytes hash result.
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
    pub struct Hash8(8);
);

impl Decodable for Hash8 {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Hash8, encode::EncodeError> {
        Ok(Hash8(Decodable::consensus_decode(r)?))
    }
}

impl hex::FromHex for Hash8 {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let hex = hex.as_ref();
        let hex = hex.strip_prefix("0x".as_bytes()).unwrap_or(hex);

        let buffer = <[u8; 8]>::from_hex(hex)?;
        Ok(Hash8(buffer))
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for Hash8 {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

/// Compute the Keccak256 hash of the provided byte-slice.
pub fn keccak_256(input: &[u8]) -> [u8; 32] {
    let mut keccak = Keccak::v256();

    let mut out = [0u8; 32];
    keccak.update(input);
    keccak.finalize(&mut out);

    out
}

/// Round to power of two, for count>=3 and for count being not too large (as reasonable for tree hash calculations)
fn tree_hash_cnt(count: usize) -> usize {
    // This algo has some bad history but all we are doing is 1 << floor(log2(count))
    // There are _many_ ways to do log2, for some reason the one selected was the most obscure one,
    // and fixing it made it even more obscure.
    //
    // Iterative method implemented below aims for clarity over speed, if performance is needed
    // then my advice is to use the BSR instruction on x86
    //
    // All the paranoid asserts have been removed since it is trivial to mathematically prove that
    // the return will always be a power of 2.
    // Problem space has been defined as 3 <= count <= 2^28. Of course quarter of a billion transactions
    // is not a sane upper limit for a block, so there will be tighter limits in other parts of the code

    assert!(count >= 3); // cases for 0,1,2 are handled elsewhere
    assert!(count <= 0x10000000); // sanity limit to 2^28, MSB=1 will cause an inf loop

    let mut pow = 2_usize;
    while pow < count {
        pow <<= 1
    }

    pow >> 1
}

fn hash_concat(a: Hash, b: Hash) -> Hash {
    let mut v = [0; Hash::len_bytes() * 2];
    v[..Hash::len_bytes()].copy_from_slice(&a[..]);
    v[Hash::len_bytes()..].copy_from_slice(&b[..]);
    Hash(keccak_256(&v))
}

/// Compute tree hash as defined by Cryptonote
pub fn tree_hash(root_hash: Hash, extra_hashes: &[Hash]) -> Hash {
    match extra_hashes.len() {
        0 => root_hash,
        1 => hash_concat(root_hash, extra_hashes[0]),
        other => {
            let count = other + 1;

            let mut cnt = tree_hash_cnt(count);

            let mut hashes = std::iter::once(root_hash)
                .chain(extra_hashes.iter().copied())
                .collect::<Vec<_>>();

            let mut i = 2 * cnt - count;
            let mut j = 2 * cnt - count;
            while j < cnt {
                hashes[j] = hash_concat(hashes[i], hashes[i + 1]);
                i += 2;
                j += 1;
            }
            assert_eq!(i, count);

            while cnt > 2 {
                cnt >>= 1;
                for i in 0..cnt {
                    hashes[i] = hash_concat(hashes[2 * i], hashes[2 * i + 1]);
                }
            }

            hash_concat(hashes[0], hashes[1])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use std::str::FromStr;

    use hex::{FromHex, FromHexError, ToHex};
    #[cfg(feature = "serde")]
    use serde_test::{assert_tokens, Token};

    #[test]
    #[cfg(feature = "serde")]
    fn test_ser_de_hash_null() {
        let hash = Hash::null();

        assert_tokens(
            &hash,
            &[
                Token::NewtypeStruct { name: "Hash" },
                Token::Tuple { len: 32 },
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::TupleEnd,
            ],
        );

        let hash = Hash8([0u8; 8]);

        assert_tokens(
            &hash,
            &[
                Token::NewtypeStruct { name: "Hash8" },
                Token::Tuple { len: 8 },
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::U8(0),
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_ser_de_hash() {
        let hash = Hash::new("");

        assert_tokens(
            &hash,
            &[
                Token::NewtypeStruct { name: "Hash" },
                Token::Tuple { len: 32 },
                Token::U8(197),
                Token::U8(210),
                Token::U8(70),
                Token::U8(1),
                Token::U8(134),
                Token::U8(247),
                Token::U8(35),
                Token::U8(60),
                Token::U8(146),
                Token::U8(126),
                Token::U8(125),
                Token::U8(178),
                Token::U8(220),
                Token::U8(199),
                Token::U8(3),
                Token::U8(192),
                Token::U8(229),
                Token::U8(0),
                Token::U8(182),
                Token::U8(83),
                Token::U8(202),
                Token::U8(130),
                Token::U8(39),
                Token::U8(59),
                Token::U8(123),
                Token::U8(250),
                Token::U8(216),
                Token::U8(4),
                Token::U8(93),
                Token::U8(133),
                Token::U8(164),
                Token::U8(112),
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    fn test_to_from_hex_hash() {
        let hash_wrong_length_str = "abcd";
        assert_eq!(
            Hash::from_hex(hash_wrong_length_str).unwrap_err(),
            FromHexError::InvalidStringLength,
        );

        let hash_wrong_length_str = "a".repeat(66);
        assert_eq!(
            Hash::from_hex(hash_wrong_length_str).unwrap_err(),
            FromHexError::InvalidStringLength,
        );

        let hash = Hash::new("");

        let hash_str: String = hash.encode_hex();
        assert_eq!(Hash::from_hex(hash_str.clone()).unwrap(), hash);

        let hash_str_with_0x = format!("0x{hash_str}");
        assert_eq!(Hash::from_hex(hash_str_with_0x).unwrap(), hash);
    }

    #[test]
    fn test_to_from_hex_hash8() {
        let hash8_wrong_length_str = "abcd";
        assert_eq!(
            Hash8::from_hex(hash8_wrong_length_str).unwrap_err(),
            FromHexError::InvalidStringLength,
        );

        let hash8_wrong_length_str = "a".repeat(10);
        assert_eq!(
            Hash8::from_hex(hash8_wrong_length_str).unwrap_err(),
            FromHexError::InvalidStringLength,
        );

        let hash8 = Hash8::from_str("0123456789abcdef").unwrap();

        let hash8_str: String = hash8.encode_hex();
        assert_eq!(Hash8::from_hex(hash8_str.clone()).unwrap(), hash8);

        let hash8_str_with_0x = format!("0x{hash8_str}");
        assert_eq!(Hash8::from_hex(hash8_str_with_0x).unwrap(), hash8);
    }

    #[test]
    fn compute_tree_hash() {
        for (expected_root, root_hash, extra_hashes) in [
            (
                hex!("676567f8b1b470207c20d8efbaacfa64b2753301b46139562111636f36304bb8"),
                hex!("676567f8b1b470207c20d8efbaacfa64b2753301b46139562111636f36304bb8"),
                &[] as &[_],
            ),
            (
                hex!("5077570fed2363a14fa978218185b914059e23517faf366f08a87cf3c47fd58e"),
                hex!("3124758667bc8e76e25403eee75a1044175d58fcd3b984e0745d0ab18f473984"),
                &[hex!(
                    "975ce54240407d80eedba2b395bcad5be99b5c920abc2423865e3066edd4847a"
                )],
            ),
            (
                hex!("f8e26aaa7c36523cea4c5202f2df159c62bf70d10670c96aed516dbfd5cb5227"),
                hex!("decc1e0aa505d7d5fbe8ed823d7f5da55307c4cc7008e306da82dbce492a0576"),
                &[
                    hex!("dbcf0c26646d36b36a92408941f5f2539f7715bcb1e2b1309cedb86ae4211554"),
                    hex!("f56f5e6b2fce16536e44c851d473d1f994793873996ba448dd59b3b4b922b183"),
                ],
            ),
            (
                hex!("45f6e06fc0263e667caddd8fba84c9fb723a961a01a5b115f7cab7fe8f2c7e44"),
                hex!("53edbbf98d3fa50a85fd2d46c42502aafad3fea30bc25ba4f16ec8bf4a475c4d"),
                &[
                    hex!("87da8ad3e5c90aae0b10a559a77a0985608eaa3cc3dd338239be52572c3bdf4b"),
                    hex!("a403d27466991997b3cf4e8d238d002a1451ccc9c4790269d0f0085d9382d60f"),
                    hex!("ef37717f59726e4cc8787d5d2d75238ba9adb9627a8f4aeeec8d80465ed3f5fb"),
                ],
            ),
            (
                hex!("e678fb87749ec082a9f92537716de8e19d8bd5bc4c4d832bd3fcfd42498dac83"),
                hex!("051a082e670c688e6a0fc2c8fd5b66b7a23cd380c7c49bd0cfffb0e80fb8c233"),
                &[
                    hex!("4bb717c5e90db0ac353dfc0750c8b43a07edae0be99d6e820acc6da9f113123a"),
                    hex!("e084c38ccdbf9c6730e228b5d98e7beb9843cfb523747cc32f09f2b16def67f7"),
                    hex!("6765cee044883827b9af31c179d3135b16c30f04453943d9676a59b907a64396"),
                    hex!("58f6c98159b8fa1b152f1bcf748740754ca31c918501dbd577faf602c641df59"),
                ],
            ),
            (
                hex!("7db3258ea536fef652eaaa9ccb158045770900b3c301d727bcb7e60f9831ae2c"),
                hex!("4231b54cddc617d06e0e311536fa400e5be0a35aab5fec9ec8d98f6c6dad3916"),
                &[
                    hex!("fe6cdb1f63be231f95cdc83bb15b0d99d32d9922331b738c423625471fad7f40"),
                    hex!("8e60c0773fe78938b054e28b86ac06a194d141c1bde5f3c6f2b11468b43702cb"),
                    hex!("3121b40ccbcb5461fa9321c35c9342e21efd7c1c22f523d78b9d4de28112b6cc"),
                    hex!("51552642ffc126c66f25038f9d3b0cf485cc252215c144d51a139c8ea9a0ecc1"),
                    hex!("6e81d8d92dd3660d885deca60070d3d00069d89db1a85acb9c1f18d0c90736a7"),
                ],
            ),
            (
                hex!("ad56b3e027d78a372adebe839e154668aec5236f7d40296cfdb562fca1dc73c2"),
                hex!("68e09573a758b75ea8e7d925fe81e3155afecddc4c8aeb3fe70d87411ee53ace"),
                &[
                    hex!("ac63c0233d172cd49b2708350fd64e2cf4dccb13352e3a159c06647c60942934"),
                    hex!("9197163eca2c2dae0c8643fdfe5d346b2ffd45a2d46f38599efbfa587c3ac0c3"),
                    hex!("119e19508e009556fe53e4f78ef30eed649cdc1e090c8cb662eae1863fdc683b"),
                    hex!("babea966764f550a142dd68e5b8eb1930ff0c7333c9f2555712489a8cf6a5d18"),
                    hex!("8a70841510fca540b8c0425123efca47d5a698cf392e3bdbb7226053459fae01"),
                    hex!("fd19ddb9d16d5f5499525feb49ffca9411e7ac48de15256559f3f65f899b80af"),
                ],
            ),
            (
                hex!("090a95612ed9df6eeb854ae320355889a302498b4f5164a79d8e384a3a0d9748"),
                hex!("42e7f4058ca80d513c140837dd661acde3fb914779079baccfe188cbce275aed"),
                &[
                    hex!("4b515094bb49ab9a825bcc2ac13f84b14a9defeb1b62fc68124b088272a35626"),
                    hex!("96d62ccdfb5d896b2d2b410a2a79f9b1e7849feebc17617ba12a08d4e80affe9"),
                    hex!("70ff2fb79917ac13708f79be215bb6484d298b2fe22b4818536e74894db5e035"),
                    hex!("0e1505ca2681da7b7d7171e3d10c89348cab160ff5b2e739d3591443d2af60db"),
                    hex!("5eb36c50a2dfdb79b8ab83b0792161ac4756d9b831f1863188e10c81af5077d0"),
                    hex!("fdb123f66e51670f03a203ff2287dea6827dcd5afd4904736ec4fe9f3b52f7e2"),
                    hex!("bed7beaa1543bd8bfbfff6a8ae8bf1791dc34efa92c6342532fa33a3b72b6c9f"),
                ],
            ),
            (
                hex!("997ac1178ab7414bab823fbca45b5630df8d1d8263063e6c57da463b85d68a74"),
                hex!("947fbbc55ad237fc5dbd7d52dddd44bf3f2a09005c78873422f7ef282d8e6fcc"),
                &[
                    hex!("554e35c9566febf91cbbcb1d57a7ebd119abb0ad33a006d01623b7b379e966e0"),
                    hex!("0be000ae2fe8a45940e99c953d22014bae4932d8493ad4a551a97d437db2939d"),
                    hex!("d53abedc11a63417f76257a5587f382a57d46d63c372182600c7920bcaf74e9e"),
                    hex!("65289e8c45123ac8a54a45a6104dce5b8c065065ff3a3b6f8bf4d86bf96cb561"),
                    hex!("16df4e01eb3153223d5f3a8c0d7de9eb348158e5ca0c363568674215f68b6ff8"),
                    hex!("e54aeb4a2661f1144cb4f1bde7f9e6371d8a5568d4b3ff3382c65e143ae5d3a5"),
                    hex!("834c890559be95b8b80b82c83d70df85c934bf9dd4b0f2b5f60b8553bd1c1e53"),
                    hex!("7b7a1f78a89a17a335a06f5d7143dfecff0c10a2e0a524c91ce913ae04501b65"),
                ],
            ),
            (
                hex!("d7647e967e4f1ad3d5a0b2d231f62c4fe8fea85b845a72aaf57aeea96f2388f2"),
                hex!("5b0bf1b5c843cc5ea8e907c0d6ea901f1d4259cd61e68895fa1a9df76973ac6c"),
                &[
                    hex!("87ee22343802565be146e4fcd768cde3cdd1b1996b8626e53b62648a9fd7f5ae"),
                    hex!("e2ce5b4aacb090d1beeaf42d47e7f0e90174af6554e8bd4aea3df45e90537eb7"),
                    hex!("572b9583b3fcedf56ff69c412c4576a1353458292b7a6b10536887da47fb95c9"),
                    hex!("99ff1a074dfb52db43cf423e81e02aacb267b5f3b48761de9c3a73efe199d710"),
                    hex!("e09043e4701792d04112d18e33d5f78efe4fbda461b4e0f2f55f07ca04eed047"),
                    hex!("62d956b396ff0471c28f48462bf9b6b47caac50be8dd822198a39366071b18f4"),
                    hex!("d4e8188bd11421b606108e9bbcfb1377e122c36083beca6a2306e48bfdbc64c9"),
                    hex!("e6435ed838eba78e0af101abf79ff9600f6cc1b2b776783491161ae2d1d8df2d"),
                    hex!("436a20c053c9237a7d224016878906352eba550d778e91ba830906b8d0be4e6e"),
                ],
            ),
            (
                hex!("bc4b8c89368a254ccd0fb8ad2e9bcf95e06e1189b9a87774a3f70c51809967ef"),
                hex!("0bea27a480254ca07321850f25294478628ce83a025af4624902644f9dec23e8"),
                &[
                    hex!("fb2c2313332449ae662e59b0bf99c30263a573f152cdcfd731402fe4bc10a758"),
                    hex!("fbc005a236a1fb4c06f25c0564726bace64ae59c9051fc4e6171b5fb1466623f"),
                    hex!("5c6a33ed05f196a6eb43852aa0735f1004245a58f68d3f8848ee916dcdfea2d7"),
                    hex!("c63159daff81f0a9d10261d416ba290752f8333afbb7e22ca1b9c7f55b902338"),
                    hex!("6b759fa69caa43c5caa7c339a0ddcfd95d9c12bea4c2cb450838080b54e270c4"),
                    hex!("aa6580cdbb3431acb13dad236d1999d8b1ec1ed78f3e14061a890c6720947d18"),
                    hex!("ee2dfa62ae4ad5e5ad6d8234ce99a1b2a21ba096325d8acf951380eacac55142"),
                    hex!("3d108b090ede16d479483ca0f9acc6cf1db8b8e4597b1c64738675f13665f840"),
                    hex!("43ace791a58acf22d31e6298e7687c24276252f10396c203d38a79b232b200d1"),
                    hex!("c53abb01b9678296797b9e08e4bf0251d8acfe3f42127db1295e3c90241a594d"),
                ],
            ),
            (
                hex!("d765c015e0d30f911278d3b011faba39e8707962d90dabafb37081805dfbe121"),
                hex!("dbbd17543ddcc85cd6e3d96d08ae74f1eb5bb69b5d04ed538622423e0f78add6"),
                &[
                    hex!("152cf461b569d733167cf18c94c5c09061aced2c59cbd75529c3e5d857528d6b"),
                    hex!("e15dab61315fa2e18ad41fc7e7c99cd274e1f7e4e6005e48015118153fd78b19"),
                    hex!("0a4960c135213f187da7675369611ad66b546cb5b041ab1743deae82edad9c4e"),
                    hex!("62dabbff022a54c1f1cbd65614fad0d33f894ace380426618330339f238e703e"),
                    hex!("40df8ef6a73ec8de5e35a2c41904552be0d029cfafe3629662dafd39069d25a1"),
                    hex!("982e021ca076aff80f75ccc92ce29219ea273874a29a9c5357dc630a244a0025"),
                    hex!("a7bccd0b6489f38b9603027a032b048cdaa5c88bafb1e72f4a69e0040c0c7b45"),
                    hex!("32b1a91e7b92ed2cd5533b8a4f119ab15c76943204ecbe61b15dd2610c49ed38"),
                    hex!("b771e6ba16c7beb09c70c0550afac81f3580d12491c4470c4773424796a85753"),
                    hex!("9616f29cd2df4e187363d24c22bb6cc91530705d7057b9a4380767d9fd8be096"),
                    hex!("3ba503132cac79c870fa4c42fc32ee39a7a3c2ded84cd4b6e302d132f3d8e2ea"),
                ],
            ),
            (
                hex!("3828d41d973d48f171a901cd67f99d073cfbc4dc954fe9c58a48f31a2b0c8927"),
                hex!("ac68da2f276c44fcddf6018bfad995e66a50ef120dbcd734834f2473542179f0"),
                &[
                    hex!("754c132933fffa46b3c61b01231b5a30cdca82b16afdb5f5183a4f733345dade"),
                    hex!("7ddb2a26b4adf0c23520a8e2d7bf979a7aeca3022153da6a65091172c34ec3a2"),
                    hex!("b8bd5bc6e2dd971cf9b6582b0cdc24f84c48ee23a47c078ecfe306a3791eabe9"),
                    hex!("3fc38d28e6a82bb3f80448b7fa3b3f687e59447e6b41074217cf336e4ba50b58"),
                    hex!("0f8724b18f95908a13517f5215b67b1b9d0f7129c4e91efa23df763142be2e28"),
                    hex!("f4d394cd6493ea6185aefa0ce8d73b5c0c11f5e8ada75a7c29438ce162749deb"),
                    hex!("113cba0d436005742d35e7397d4fec8419b24320a21dcb18089e5c7644abe3d5"),
                    hex!("7b2554c19c0eb55ebfe943ac13beafcd9bad66a967fcc1e747c778bf452c6ccf"),
                    hex!("c9b96772caf052bd768d50977cda7255f479510af8628d5e24125b9482b0e786"),
                    hex!("a65e99bdfb73e6c6e57f01458a7735d0e16b30546d1856683002aa1d0980b54a"),
                    hex!("fc8086b75eff6b7a0b448e31e2bf741b24e7399dded0321f745ef034d4c80fc1"),
                    hex!("5719b81a797b751c27110480e48c7e98e27aa9397b7c58917147200fd4770d55"),
                ],
            ),
            (
                hex!("834e5f13dd06f541753f60fe2b5854eff15e54c4141cc0836c4688769a0db0a4"),
                hex!("ec58450fe3887a480b39cc493599bf4107d276f57453257bbd1446ccec960ce8"),
                &[
                    hex!("aad0e7623c1ac4fe07c2255376dd1aaf4b78a079e8f701a74560805d295d466a"),
                    hex!("6987e81e2ed74b4ccc6a0f121eb6f173f4efeb74f801e1b80e1ee97bf4216376"),
                    hex!("c00a92962c5234d276bea8975e49718c546c3027d57131333a4e4c5756899ba7"),
                    hex!("c9643ff8335553325d4706cd72930b09d632c561072b39b49106c2d424fa6773"),
                    hex!("bbb0bb01fed84effb8ed7471b14581213e49b8fd8dacd1c3f9c50f2a915bfcd7"),
                    hex!("7d07abb95cd0aa13df084adc54a04e3214c639cef5cc22fd0a1477a1a196a919"),
                    hex!("d37dff128318900dce936b5cf3a3154fb05f9b2841481554805b681c2943eead"),
                    hex!("e2b21fcc72c6380dc70d4f404dcfe0c0686f94f979989e663f4028189ae5839f"),
                    hex!("0ff8d2c58b4ea09797ece5f5554fccb824c24293b7b7bf8af4da3536548ee5eb"),
                    hex!("bf80c8ea56f88bfa8174df124f5acdecb9e919041ec664e384a8eaeb8e20be27"),
                    hex!("0350a2f1cb65f691c0cb1392226a928a3a3aac3f69fe5eab76d125fdeb5ea4c4"),
                    hex!("b2dd59993e7df68221c0da90a1ee89885b217bb6b67ab2d64feb33b66b310877"),
                    hex!("95ddeeb52d40c9a260da14b383caad730ddc8f1e6b59baf7bf110a452a05e8bb"),
                ],
            ),
            (
                hex!("bca11932a196feb98e7779662b8c0f3754a6438311209a858bb891de6bf09581"),
                hex!("23c2a65a1917cb82949e89ca65585f4d0b09a5d90a912aed4d8aff9af2a2ce65"),
                &[
                    hex!("94305a47ad8e6b744a5fd79cb27e5f4a3b28a3893c655efe3f61105c85183c82"),
                    hex!("2d293c74b60d4cc0c7ee002616a97411a3b1d3d8c1be1079a1b300e8e17c9556"),
                    hex!("8defd202af2d290cbf1e678e881430d05419c2c543b8e476b424232bc7396e14"),
                    hex!("928e459597e6a8cf9cc6c95051b16d0bcc0e4034ffbcd4ee321b9e94bbc0a172"),
                    hex!("9ee8ab4cd43158c4e8e571ee64c2102f181402238cd53a57693dbfdd5e6be3bf"),
                    hex!("23103e73c40248ce7afb8dad6dd2c2107aab20569f740197d64efbe6159a553c"),
                    hex!("013c04c5c54aa9a4dbe41f2910554bba612e16fe3c682d493c7a1b35c0b34763"),
                    hex!("37badb053bae123c6306442812f5f2df8995c29d7e9c218d4d9e86699cca19d0"),
                    hex!("6be9688bf8150d487ede28911089ea86d0be0986b51adc270317c438b6227483"),
                    hex!("21d2d9c9f93400b73d7fdbe3e1f6ff36f16be9416b568a80e2764a258b6789d5"),
                    hex!("70d80bf91e832baa1ab92289759eb2504ab4b0d3b826e944f5f4beb5d6a3764d"),
                    hex!("d9225a0a1e78a7d0485ffc6808651ef1a26bda9c7e436ab48587e91cfdab4a7c"),
                    hex!("1dbb13a78025ac77baa1e389f9b82994c6cb725c30708a266b5e1a9d0b52128b"),
                    hex!("a340a4a609095e70cc7b30cf6d3a2156b4a35c1bba574f240c37f94718616e48"),
                ],
            ),
            (
                hex!("2d0ad2566627b50cd45125e89e963433b212b368cd2d91662c44813ba9ec90c2"),
                hex!("21f750d5d938dd4ed1fa4daa4d260beb5b73509de9a9b145624d3f1afb671461"),
                &[
                    hex!("b07d768cf1f5f8266b89ecdc150a2ad55ccd76d4c12d3a380b21862809a85af6"),
                    hex!("23269a23ee1b4694b26aa317b5cd4f259925f6b3288a8f60fb871b1ad3ac00cb"),
                    hex!("1e6c55eddfc438e1f3e7b638ea6026cc01495010bafdfd789c47dff282c1af4c"),
                    hex!("6a8f83e5f2fca6940a756ef4faa15c7137082a7c31dffe0b2f5112d126ad4af1"),
                    hex!("d536c0e626cc9d2fe1b72256f5285728558f22a3dbb36e0918bcfc01d4ae7284"),
                    hex!("d0bfb8e90647cdb01c292a53a31ff3fe6f350882f1dae2b09374db45f4d54c67"),
                    hex!("d3b4e0829c4f9f63ad235d8ef838d8fb39546d90d99bbd831aff55dbbb642e2b"),
                    hex!("f529ceccd0479b9f194475c2a15143f0edac762e9bbce810436e765550c69e23"),
                    hex!("4c22276c41d7d7e28c10afc5e144a9ce32aa9c0f28bb4fcf171af7d7404fa5e2"),
                    hex!("8b79dc97bd4147f4df6d38b935bd83fb634414bae9d64a32ab45384fba5b8da5"),
                    hex!("c147d51cd2a8f7f2a9c07b1bddc5b28b74bf0c0f0632ac2fc43d0d306dd1ac14"),
                    hex!("81cabe60a358d6043d4733202d489664a929d6bf76a39828954846beb47a3baa"),
                    hex!("cb35d2065cbe3ad34cf78bf895f6323a6d76fc1256306f58e4baecabd7a77938"),
                    hex!("8c6bf2734897c193d39c343fce49a456f0ef84cf963593c5401a14621cc6ec1b"),
                    hex!("ef01b53735ccb02bc96c5fd454105053e3b016174437ed83b25d2a79a88268f2"),
                ],
            ),
        ] {
            let expected_root = Hash(expected_root);
            let root_hash = Hash(root_hash);
            let extra_hashes = extra_hashes.iter().copied().map(Hash).collect::<Vec<_>>();

            assert_eq!(expected_root, tree_hash(root_hash, &extra_hashes))
        }
    }
}

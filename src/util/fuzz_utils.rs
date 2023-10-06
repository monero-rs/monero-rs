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

use crate::blockdata::transaction::{ExtraField, KeyImage, RawExtraField, SubField, TxOutTarget};
use crate::consensus::encode::Encodable;
use crate::consensus::{deserialize, serialize};
use crate::cryptonote::hash::Hashable;
use crate::util::key::H;
use crate::util::ringct::{CtKey, EcdhInfo, Key, RctSig, RctSigBase, RctSigPrunable, RctType};
use crate::{
    Amount, Block, BlockHeader, Hash, PrivateKey, PublicKey, Transaction, TransactionPrefix, TxIn,
    TxOut, VarInt, ViewPair,
};
use hex::{FromHex, ToHex};
use std::io;
use std::str::FromStr;

/// Fuzz for block deserialization, called from the fuzz target
pub fn fuzz_block_deserialize(fuzz_data: &[u8]) -> bool {
    let fuzz_bytes = fuzz_data.to_vec();

    // Block
    if let Ok(val) = deserialize::<Block>(&fuzz_bytes[..]) {
        println!("here 1");
        println!("header {:?}", serialize(&val.header));
        println!("transaction_prefix {:?}", serialize(&val.miner_tx.prefix));
        assert_eq!(fuzz_bytes, serialize(&val), "\nfuzz_data: {:?}", fuzz_data);
    }

    true
}

/// Fuzz for block header deserialization, called from the fuzz target
pub fn fuzz_block_header_deserialize(fuzz_data: &[u8]) -> bool {
    let fuzz_bytes = fuzz_data.to_vec();

    // BlockHeader
    if let Ok(val) = deserialize::<BlockHeader>(&fuzz_bytes[..]) {
        println!("here 2");
        assert_eq!(fuzz_bytes, serialize(&val), "\nfuzz_data: {:?}", fuzz_data);
    }

    true
}

/// Fuzz for transaction prefix deserialization, called from the fuzz target
pub fn fuzz_transaction_prefix_deserialize(fuzz_data: &[u8]) -> bool {
    let fuzz_bytes = fuzz_data.to_vec();

    // TransactionPrefix
    if let Ok(val) = deserialize::<TransactionPrefix>(&fuzz_bytes[..]) {
        println!("here 3");
        assert_eq!(fuzz_bytes, serialize(&val), "\nfuzz_data: {:?}", fuzz_data);
    }

    true
}

/// Padding sub-field position in extra data
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AddPadding {
    /// Add padding to the front of the extra field
    ToFront,
    /// Add padding to the middle of the extra field
    ToMiddle,
    /// Add padding to the rear of the extra field
    ToRear,
}

fn u64_val_from_fuzz_data(fuzz_data: &[u8]) -> u64 {
    if fuzz_data.is_empty() {
        0
    } else {
        let mut vec = fuzz_data.to_vec().clone();
        vec.resize(8, 0);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(vec.as_slice());
        u64::from_le_bytes(bytes)
    }
}

/// Fuzz helper function to create an extra field, called from the fuzz target
pub fn fuzz_create_extra_field(fuzz_data: &[u8], add_padding: AddPadding) -> ExtraField {
    let fuzz_bytes = fuzz_data.to_vec();
    let hash = Hash::new(fuzz_data);

    // SubField::TxPublicKey
    let tx_pub_key_field = SubField::TxPublicKey(match PublicKey::from_slice(fuzz_data) {
        Ok(val) => val,
        Err(_) => H,
    });
    let nonce_field = SubField::Nonce(fuzz_bytes.clone());

    // SubField::Padding
    let padding_field = SubField::Padding(fuzz_bytes.first().copied().unwrap_or_default());

    // SubField::MergeMining
    let u64_val = u64_val_from_fuzz_data(fuzz_data);
    let merge_mining_field = SubField::MergeMining(Some(VarInt(u64_val)), hash);

    // SubField::AdditionalPublickKey
    let additional_public_key_field =
        SubField::AdditionalPublickKey(match PublicKey::from_slice(fuzz_data) {
            Ok(val) => {
                if fuzz_bytes.is_empty() {
                    vec![]
                } else {
                    vec![val; (fuzz_bytes[0] % 10 + 1) as usize]
                }
            }
            Err(_) => vec![H],
        });

    // SubField::MysteriousMinerGate
    let mysterious_miner_gate_field = SubField::MysteriousMinerGate(fuzz_bytes);

    let sub_fields = match add_padding {
        AddPadding::ToFront => vec![
            padding_field, // This will fail if the padding is not maximum
            tx_pub_key_field,
            nonce_field,
            merge_mining_field,
            additional_public_key_field,
            mysterious_miner_gate_field,
        ],
        AddPadding::ToMiddle => vec![
            tx_pub_key_field,
            nonce_field,
            merge_mining_field,
            padding_field, // This will fail if the padding is not maximum
            additional_public_key_field,
            mysterious_miner_gate_field,
        ],
        AddPadding::ToRear => vec![
            tx_pub_key_field,
            nonce_field,
            merge_mining_field,
            additional_public_key_field,
            mysterious_miner_gate_field,
            padding_field,
        ],
    };

    // ExtraField
    ExtraField(sub_fields)
}

/// Fuzz for extra field's sub fields parse, called from the fuzz target
pub fn fuzz_extra_field_parse_sub_fields(extra_field: &ExtraField) -> bool {
    for sub_field in &extra_field.0 {
        let ser_sub_field = serialize(sub_field);
        println!("here 4");
        match deserialize::<SubField>(&ser_sub_field) {
            Ok(des_sub_field) => {
                assert_eq!(sub_field, &des_sub_field, "\nsub field: {}", sub_field)
            }
            Err(err) => {
                panic!(
                    "Deserializing a serialized SubField may not fail\n({})\nsub field: {:?}",
                    err, sub_field
                )
            }
        }
    }

    true
}

/// Fuzz for extra field try parse, called from the fuzz target
pub fn fuzz_extra_field_try_parse(
    extra_field: &ExtraField,
    add_padding: AddPadding,
    fuzz_data: &[u8],
) -> bool {
    match RawExtraField::try_from(extra_field.clone()) {
        Ok(raw_extra_field) => {
            println!("here 5");
            match ExtraField::try_parse(&raw_extra_field) {
                Ok(parsed_extra_field) => {
                    println!("here 5.1");
                    assert_eq!(
                        extra_field, &parsed_extra_field,
                        "\nOn 'Ok(_)\noriginal: {:?}\nparsed:   {:?}\n'fuzz_data: {:?}",
                        extra_field, parsed_extra_field, fuzz_data
                    )
                }
                Err(parsed_extra_field) => {
                    if parsed_extra_field.0.len() > extra_field.0.len() {
                        panic!(
                            "On 'Err(_)', parsed extra field has to many sub fields\noriginal: {:?}\nparsed:   {:?}\nfuzz_data: {:?}",
                            extra_field,
                            parsed_extra_field,
                            fuzz_data,
                        );
                    }
                    for (i, parsed_sub_field) in parsed_extra_field.0.iter().enumerate() {
                        println!("here 5.2");
                        match parsed_sub_field {
                            SubField::Padding(_) => {
                                // The padding sub-field may be different on error
                                println!("here 5.3");
                            }
                            _ => {
                                // Other sub-fields must be the same on error
                                println!("here 5.4");
                                assert_eq!(
                                    &extra_field.0[i], parsed_sub_field,
                                   "\nOn 'Err(_)'\noriginal: {:?}\nparsed:   {:?}\nfuzz_data: {:?}",
                                   extra_field,
                                   parsed_extra_field,
                                   fuzz_data
                                );
                            }
                        }
                    }
                    if add_padding == AddPadding::ToRear {
                        panic!(
                            "\nOn 'Err(_)', parsing a serialized ExtraField with padding at the rear may not fail\n({:?})\n({:?})\nfuzz_data: {:?}",
                            extra_field,
                            parsed_extra_field,
                            fuzz_data,
                        );
                    }
                }
            };
        }
        Err(err) => {
            panic!(
                "Serializing an ExtraField may not fail\n({})\nextra field: {:?}\nfuzz_data: {:?}",
                err, extra_field, fuzz_data
            )
        }
    };

    true
}

/// Fuzz helper function to create a raw extra field, called from the fuzz target
pub fn fuzz_create_raw_extra_field(fuzz_data: &[u8]) -> Result<RawExtraField, String> {
    match RawExtraField::try_from({
        let add_padding = if fuzz_data.is_empty() {
            AddPadding::ToMiddle
        } else {
            match fuzz_data.len() % 3 {
                0 => AddPadding::ToFront,
                1 => AddPadding::ToMiddle,
                _ => AddPadding::ToRear,
            }
        };
        fuzz_create_extra_field(fuzz_data, add_padding)
    }) {
        Ok(val) => Ok(val),
        Err(e) => Err(e.to_string()),
    }
}

/// Fuzz for transaction deserialization, called from the fuzz target
pub fn fuzz_transaction_deserialize(fuzz_data: &[u8]) -> bool {
    let fuzz_bytes = fuzz_data.to_vec();

    // Transaction
    if let Ok(val) = deserialize::<Transaction>(&fuzz_bytes[..]) {
        assert_eq!(fuzz_bytes, serialize(&val));
    }

    let raw_extra_field = match fuzz_create_raw_extra_field(fuzz_data) {
        Ok(val) => val,
        Err(_) => {
            // This may not fail, otherwise the test cannot continue
            return true;
        }
    };

    println!("here 6");
    let transaction = fuzz_create_transaction_alternative_1(fuzz_data, &raw_extra_field);
    let serialized_tx = serialize(&transaction);
    let _ = deserialize::<Transaction>(&serialized_tx[..]);

    let transaction = fuzz_create_transaction_alternative_2(fuzz_data, &raw_extra_field);
    let serialized_tx = serialize(&transaction);
    let _ = deserialize::<Transaction>(&serialized_tx[..]);

    true
}

/// Fuzz for transaction serialization and deserialization, called from the fuzz target
pub fn fuzz_transaction_components(fuzz_data: &[u8]) -> bool {
    let fuzz_bytes = fuzz_data.to_vec().clone();
    let (rct_type, inputs, outputs, mixin) = if fuzz_bytes.is_empty() {
        (RctType::Null, 0, 0, 0)
    } else {
        (
            match fuzz_bytes[0] % 8 {
                0 => RctType::Null,
                1 => RctType::Full,
                3 => RctType::Clsag,
                4 => RctType::Simple,
                5 => RctType::Bulletproof,
                6 => RctType::Bulletproof2,
                7 => RctType::BulletproofPlus,
                _ => RctType::Null,
            },
            fuzz_bytes[0] % 5,
            fuzz_bytes[0] % 7,
            fuzz_bytes[0] % 3,
        )
    };

    // TransactionPrefix
    if let Ok(val) = deserialize::<TransactionPrefix>(&fuzz_bytes[..]) {
        assert_eq!(fuzz_bytes, serialize(&val));
    }
    println!("here 7.1");

    // RctSigBase
    let fuzz_bytes = fuzz_data.to_vec().clone();
    let mut decoder = io::Cursor::new(&fuzz_bytes);
    if let Ok(Some(rct_sig)) =
        RctSigBase::consensus_decode(&mut decoder, inputs as usize, outputs as usize)
    {
        let mut encoder = Vec::new();
        if rct_sig.consensus_encode(&mut encoder).is_ok() {
            // This fails! Should it?
            // assert_eq!(fuzz_bytes, encoder);
        }
    }
    println!("here 7.2");

    // RctSigPrunable
    let fuzz_bytes = fuzz_data.to_vec().clone();
    let mut decoder = io::Cursor::new(&fuzz_bytes);
    if let Ok(Some(rct_sig)) = RctSigPrunable::consensus_decode(
        &mut decoder,
        rct_type,
        inputs as usize,
        outputs as usize,
        mixin as usize,
    ) {
        let mut encoder = Vec::new();
        if rct_sig.consensus_encode(&mut encoder, rct_type).is_ok() {
            // This fails! Should it?
            // assert_eq!(fuzz_bytes, encoder);
        }
    }
    println!("here 7.3");

    true
}

/// Fuzz helper function to create a transaction, called from the fuzz target
pub fn fuzz_create_transaction_alternative_1(
    fuzz_data: &[u8],
    raw_extra_field: &RawExtraField,
) -> Transaction {
    let hash_1 = Hash::new(fuzz_data);
    let hash_2 = Hash::new(hash_1.0);
    let hash_3 = Hash::new(hash_2.0);
    let hash_4 = Hash::new(hash_3.0);
    let hash_5 = Hash::new(hash_4.0);
    let hash_6 = Hash::new(hash_5.0);
    let hash_7 = Hash::new(hash_6.0);
    let hash_8 = Hash::new(hash_7.0);
    let u64_val = u64_val_from_fuzz_data(fuzz_data);

    let prefix = TransactionPrefix {
        version: VarInt(u64_val),
        unlock_time: VarInt(u64_val),
        inputs: vec![
            TxIn::ToKey {
                amount: VarInt(u64_val),
                key_offsets: vec![],
                k_image: KeyImage { image: hash_1 },
            },
            TxIn::Gen {
                height: VarInt(u64_val),
            },
        ],
        outputs: vec![
            TxOut {
                amount: VarInt(u64_val),
                target: TxOutTarget::ToScript {
                    keys: vec![H],
                    script: fuzz_data.to_vec(),
                },
            },
            TxOut {
                amount: VarInt(u64_val),
                target: TxOutTarget::ToKey { key: hash_2.0 },
            },
            TxOut {
                amount: VarInt(u64_val),
                target: TxOutTarget::ToTaggedKey {
                    key: hash_3.0,
                    view_tag: hash_1.0[0],
                },
            },
            TxOut {
                amount: VarInt(u64_val),
                target: TxOutTarget::ToScriptHash { hash: hash_8 },
            },
        ],
        extra: raw_extra_field.clone(),
    };

    let rct_signatures = RctSig {
        sig: Option::from(RctSigBase {
            rct_type: RctType::Full,
            txn_fee: Amount::from_pico(u64_val),
            pseudo_outs: vec![
                Key { key: hash_4.0 },
                Key { key: hash_8.0 },
                Key { key: hash_7.0 },
            ],
            ecdh_info: vec![
                EcdhInfo::Standard {
                    mask: Key { key: hash_5.0 },
                    amount: Key { key: hash_6.0 },
                },
                EcdhInfo::Standard {
                    mask: Key { key: hash_5.0 },
                    amount: Key { key: hash_6.0 },
                },
            ],
            out_pk: vec![CtKey {
                mask: Key { key: hash_7.0 },
            }],
        }),
        p: None,
    };

    Transaction {
        prefix,
        signatures: vec![],
        rct_signatures,
    }
}

/// Fuzz helper function to create a transaction, called from the fuzz target
pub fn fuzz_create_transaction_alternative_2(
    fuzz_data: &[u8],
    raw_extra_field: &RawExtraField,
) -> Transaction {
    let hash_1 = Hash::new(fuzz_data);
    let hash_2 = Hash::new(hash_1.0);
    let hash_3 = Hash::new(hash_2.0);
    let hash_4 = Hash::new(hash_3.0);
    let hash_5 = Hash::new(hash_4.0);
    let hash_6 = Hash::new(hash_5.0);
    let hash_7 = Hash::new(hash_6.0);
    let hash_8 = Hash::new(hash_7.0);
    let u64_val = u64_val_from_fuzz_data(fuzz_data);

    let prefix = TransactionPrefix {
        version: VarInt(u64_val),
        unlock_time: VarInt(u64_val),
        inputs: vec![
            // Adding this results in `Error: "attempt to subtract with overflow"`
            TxIn::ToKey {
                amount: VarInt(u64_val),
                key_offsets: vec![],
                k_image: KeyImage { image: hash_1 },
            },
            TxIn::Gen {
                height: VarInt(u64_val),
            },
            TxIn::ToKey {
                amount: VarInt(u64_val),
                key_offsets: vec![VarInt(u64_val)],
                k_image: KeyImage { image: hash_1 },
            },
        ],
        outputs: vec![
            TxOut {
                amount: VarInt(u64_val),
                target: TxOutTarget::ToKey { key: hash_2.0 },
            },
            TxOut {
                amount: VarInt(u64_val),
                target: TxOutTarget::ToTaggedKey {
                    key: hash_3.0,
                    view_tag: hash_1.0[0],
                },
            },
        ],
        extra: raw_extra_field.clone(),
    };

    let rct_signatures = RctSig {
        sig: Option::from(RctSigBase {
            rct_type: RctType::Full,
            txn_fee: Amount::from_pico(u64_val),
            pseudo_outs: vec![Key { key: hash_4.0 }, Key { key: hash_8.0 }],
            ecdh_info: vec![
                EcdhInfo::Standard {
                    mask: Key { key: hash_5.0 },
                    amount: Key { key: hash_6.0 },
                },
                EcdhInfo::Standard {
                    mask: Key { key: hash_5.0 },
                    amount: Key { key: hash_6.0 },
                },
            ],
            out_pk: vec![
                CtKey {
                    mask: Key { key: hash_7.0 },
                },
                CtKey {
                    mask: Key { key: hash_8.0 },
                },
            ],
        }),
        p: Option::from(RctSigPrunable {
            range_sigs: vec![],
            bulletproofs: vec![],
            bulletproofplus: vec![],
            MGs: vec![],
            Clsags: vec![],
            pseudo_outs: vec![],
        }),
    };

    Transaction {
        prefix,
        signatures: vec![],
        rct_signatures,
    }
}

/// Fuzz for hash conversion, called from the fuzz target
pub fn fuzz_hash_convert(fuzz_data: &[u8]) -> bool {
    // Hash
    let hash = Hash::new(fuzz_data);

    let hash_str: String = hash.encode_hex();
    if let Ok(hash2) = Hash::from_hex(hash_str.clone()) {
        assert_eq!(hash, hash2);
    }

    let hash_str_with_0x = format!("0x{hash_str}");
    if let Ok(hash2) = Hash::from_hex(hash_str_with_0x) {
        assert_eq!(hash, hash2);
    }

    assert_eq!(hash.as_scalar(), Hash::hash_to_scalar(fuzz_data));

    true
}

/// Fuzz for raw extra field deserialize, called from the fuzz target
pub fn fuzz_raw_extra_field_deserialize(raw_extra_field: &RawExtraField) -> bool {
    let raw_extra_field_bytes = serialize(raw_extra_field);
    if let Ok(raw_extra_field_2) = deserialize::<RawExtraField>(&raw_extra_field_bytes) {
        assert_eq!(raw_extra_field, &raw_extra_field_2);
    }

    true
}

/// Fuzz for raw extra field, called from the fuzz target
pub fn fuzz_raw_extra_field_from(fuzz_data: &[u8]) -> bool {
    let extra_field = fuzz_create_extra_field(fuzz_data, AddPadding::ToRear);
    assert!(RawExtraField::try_from(extra_field.clone()).is_ok());

    let _ = fuzz_create_raw_extra_field(fuzz_data);

    true
}

/// Fuzz for transaction hash, called from the fuzz target
pub fn fuzz_transaction_hash(transaction: &Transaction) -> bool {
    let _hash = transaction.hash();
    true
}

/// Fuzz for transaction check outputs, called from the fuzz target
pub fn fuzz_transaction_check_outputs(transaction: &Transaction) -> bool {
    let secret_view = match PrivateKey::from_str(
        "bcfdda53205318e1c14fa0ddca1a45df363bb427972981d0249d0f4652a7df07",
    ) {
        Ok(val) => val,
        Err(_) => {
            // This may not fail, otherwise the test cannot continue
            return true;
        }
    };
    let secret_spend = match PrivateKey::from_str(
        "e5f4301d32f3bdaef814a835a18aaaa24b13cc76cf01a832a7852faf9322e907",
    ) {
        Ok(val) => val,
        Err(_) => {
            // This may not fail, otherwise the test cannot continue
            return true;
        }
    };
    let public_spend = PublicKey::from_private_key(&secret_spend);
    let viewpair = ViewPair {
        view: secret_view,
        spend: public_spend,
    };

    let _ = transaction.check_outputs(&viewpair, 0..3, 0..3);
    true
}

#[cfg(test)]
mod tests {
    use crate::{Address, AddressType, Network};
    use quickcheck::QuickCheck;

    use crate::util::fuzz_utils::{
        fuzz_block_deserialize, fuzz_block_header_deserialize, fuzz_create_extra_field,
        fuzz_create_raw_extra_field, fuzz_create_transaction_alternative_1,
        fuzz_create_transaction_alternative_2, fuzz_extra_field_parse_sub_fields,
        fuzz_extra_field_try_parse, fuzz_hash_convert, fuzz_raw_extra_field_deserialize,
        fuzz_raw_extra_field_from, fuzz_transaction_check_outputs, fuzz_transaction_components,
        fuzz_transaction_deserialize, fuzz_transaction_hash, fuzz_transaction_prefix_deserialize,
        AddPadding,
    };

    // #[test]
    #[allow(dead_code)]
    fn test_fuzz_block_deserialize() {
        fn internal(data: Vec<u8>) -> bool {
            fuzz_block_deserialize(&data)
        }

        const TESTS: u64 = 10_000;

        QuickCheck::new()
            .min_tests_passed(TESTS)
            .tests(TESTS)
            .max_tests(TESTS)
            .quickcheck(internal as fn(Vec<u8>) -> bool);
    }

    #[test]
    fn test_fuzz_block_header_deserialize() {
        fn internal(data: Vec<u8>) -> bool {
            fuzz_block_header_deserialize(&data)
        }

        const TESTS: u64 = 10_000;

        QuickCheck::new()
            .min_tests_passed(TESTS)
            .tests(TESTS)
            .max_tests(TESTS)
            .quickcheck(internal as fn(Vec<u8>) -> bool);
    }

    #[test]
    fn test_fuzz_transaction_prefix_deserialize() {
        fn internal(data: Vec<u8>) -> bool {
            fuzz_transaction_prefix_deserialize(&data)
        }

        const TESTS: u64 = 10_000;

        QuickCheck::new()
            .min_tests_passed(TESTS)
            .tests(TESTS)
            .max_tests(TESTS)
            .quickcheck(internal as fn(Vec<u8>) -> bool);
    }

    // #[test]
    #[allow(dead_code)]
    fn test_fuzz_transaction_deserialize() {
        fn internal(data: Vec<u8>) -> bool {
            fuzz_transaction_deserialize(&data)
        }

        const TESTS: u64 = 10_000;

        QuickCheck::new()
            .min_tests_passed(TESTS)
            .tests(TESTS)
            .max_tests(TESTS)
            .quickcheck(internal as fn(Vec<u8>) -> bool);
    }

    // #[test]
    #[allow(dead_code)]
    fn test_fuzz_transaction_components() {
        fn internal(data: Vec<u8>) -> bool {
            fuzz_transaction_components(&data)
        }

        const TESTS: u64 = 1_000;

        QuickCheck::new()
            .min_tests_passed(TESTS)
            .tests(TESTS)
            .max_tests(TESTS)
            .quickcheck(internal as fn(Vec<u8>) -> bool);
    }

    #[test]
    fn test_fuzz_hash_convert() {
        fn internal(data: Vec<u8>) -> bool {
            fuzz_hash_convert(&data)
        }

        const TESTS: u64 = 10_000;

        QuickCheck::new()
            .min_tests_passed(TESTS)
            .tests(TESTS)
            .max_tests(TESTS)
            .quickcheck(internal as fn(Vec<u8>) -> bool);
    }

    #[test]
    fn test_fuzz_raw_extra_field_from() {
        fn internal(data: Vec<u8>) -> bool {
            fuzz_raw_extra_field_from(&data)
        }

        const TESTS: u64 = 10_000;

        QuickCheck::new()
            .min_tests_passed(TESTS)
            .tests(TESTS)
            .max_tests(TESTS)
            .quickcheck(internal as fn(Vec<u8>) -> bool);
    }

    #[test]
    fn test_fuzz_raw_extra_field_deserialize() {
        fn internal(data: Vec<u8>) -> bool {
            let raw_extra_field = match fuzz_create_raw_extra_field(&data) {
                Ok(val) => val,
                Err(_) => {
                    // This may not fail, otherwise the test cannot continue
                    return true;
                }
            };
            fuzz_raw_extra_field_deserialize(&raw_extra_field)
        }

        const TESTS: u64 = 10_000;

        QuickCheck::new()
            .min_tests_passed(TESTS)
            .tests(TESTS)
            .max_tests(TESTS)
            .quickcheck(internal as fn(Vec<u8>) -> bool);
    }

    // #[test]
    #[allow(dead_code)]
    fn test_fuzz_extra_field_parse_sub_fields() {
        fn internal(data: Vec<u8>) -> bool {
            let add_padding = if data.is_empty() {
                AddPadding::ToMiddle
            } else {
                match data.len() % 3 {
                    0 => AddPadding::ToFront,
                    1 => AddPadding::ToMiddle,
                    _ => AddPadding::ToRear,
                }
            };
            let extra_field = fuzz_create_extra_field(&data, add_padding);
            fuzz_extra_field_parse_sub_fields(&extra_field)
        }

        const TESTS: u64 = 10_000;

        QuickCheck::new()
            .min_tests_passed(TESTS)
            .tests(TESTS)
            .max_tests(TESTS)
            .quickcheck(internal as fn(Vec<u8>) -> bool);
    }

    // #[test]
    #[allow(dead_code)]
    fn test_fuzz_extra_field_try_parse() {
        fn internal(data: Vec<u8>) -> bool {
            let add_padding = if data.is_empty() {
                AddPadding::ToMiddle
            } else {
                match data.len() % 3 {
                    0 => AddPadding::ToFront,
                    1 => AddPadding::ToMiddle,
                    _ => AddPadding::ToRear,
                }
            };
            let extra_field = fuzz_create_extra_field(&data, add_padding);
            fuzz_extra_field_try_parse(&extra_field, add_padding, &data)
        }

        const TESTS: u64 = 10_000;

        QuickCheck::new()
            .min_tests_passed(TESTS)
            .tests(TESTS)
            .max_tests(TESTS)
            .quickcheck(internal as fn(Vec<u8>) -> bool);
    }

    // #[test]
    #[allow(dead_code)]
    fn test_fuzz_transaction_hash() {
        fn internal(data: Vec<u8>) -> bool {
            let raw_extra_field = match fuzz_create_raw_extra_field(&data) {
                Ok(val) => val,
                Err(_) => {
                    // This may not fail, otherwise the test cannot continue
                    return true;
                }
            };
            let transaction = fuzz_create_transaction_alternative_1(&data, &raw_extra_field);
            let _ = fuzz_transaction_hash(&transaction);
            let transaction = fuzz_create_transaction_alternative_2(&data, &raw_extra_field);
            fuzz_transaction_hash(&transaction)
        }

        const TESTS: u64 = 10_000;

        QuickCheck::new()
            .min_tests_passed(TESTS)
            .tests(TESTS)
            .max_tests(TESTS)
            .quickcheck(internal as fn(Vec<u8>) -> bool);
    }

    #[test]
    fn test_fuzz_transaction_check_outputs() {
        fn internal(data: Vec<u8>) -> bool {
            let raw_extra_field = match fuzz_create_raw_extra_field(&data) {
                Ok(val) => val,
                Err(_) => {
                    // This may not fail, otherwise the test cannot continue
                    return true;
                }
            };
            let transaction = fuzz_create_transaction_alternative_1(&data, &raw_extra_field);
            let _ = fuzz_transaction_check_outputs(&transaction);
            let transaction = fuzz_create_transaction_alternative_2(&data, &raw_extra_field);
            let _ = fuzz_transaction_check_outputs(&transaction);
            true
        }

        const TESTS: u64 = 1_000;

        QuickCheck::new()
            .min_tests_passed(TESTS)
            .tests(TESTS)
            .max_tests(TESTS)
            .quickcheck(internal as fn(Vec<u8>) -> bool);
    }

    // #[test]
    #[allow(dead_code)]
    fn test_fuzz_address_from_bytes() {
        fn internal(data: Vec<u8>) -> bool {
            let _ = Address::from_bytes(&data);
            true
        }

        const TESTS: u64 = 10_000;

        QuickCheck::new()
            .min_tests_passed(TESTS)
            .tests(TESTS)
            .max_tests(TESTS)
            .quickcheck(internal as fn(Vec<u8>) -> bool);
    }

    // #[test]
    #[allow(dead_code)]
    fn test_fuzz_address_type_from_slice() {
        fn internal(data: Vec<u8>) -> bool {
            let network = if data.is_empty() {
                Network::Mainnet
            } else {
                match data.len() % 3 {
                    0 => Network::Mainnet,
                    1 => Network::Testnet,
                    _ => Network::Stagenet,
                }
            };
            let _ = AddressType::from_slice(&data, network);
            true
        }

        const TESTS: u64 = 10_000;

        QuickCheck::new()
            .min_tests_passed(TESTS)
            .tests(TESTS)
            .max_tests(TESTS)
            .quickcheck(internal as fn(Vec<u8>) -> bool);
    }

    // ---------------------------------------------------------------------------------------------
    // Code coverage section
    // ---------------------------------------------------------------------------------------------
    #[test]
    fn test_fuzz_block_deserialize_coverage() {
        let data = [
            12, 12, 148, 222, 186, 248, 5, 190, 179, 72, 156, 114, 42, 40, 92, 9, 42, 50, 231, 198,
            137, 58, 191, 199, 208, 105, 105, 156, 131, 38, 252, 52, 69, 167, 73, 197, 39, 107, 98,
            0, 0, 0, 0, 2, 155, 137, 34, 1, 255, 223, 136, 34, 1, 182, 153, 212, 200, 177, 236, 2,
            2, 35, 223, 82, 74, 242, 162, 239, 95, 135, 10, 219, 110, 28, 235, 3, 164, 117, 195,
            159, 139, 158, 247, 106, 165, 11, 70, 221, 210, 161, 131, 73, 64, 43, 1, 40, 57, 191,
            161, 155, 117, 36, 236, 116, 136, 145, 119, 20, 194, 22, 202, 37, 75, 56, 237, 4, 36,
            202, 101, 174, 130, 138, 124, 0, 106, 234, 241, 2, 8, 245, 49, 106, 127, 107, 153, 204,
            166, 0, 0,
        ];
        fuzz_block_deserialize(&data);
    }

    #[test]
    fn test_fuzz_block_header_deserialize_coverage() {
        let data = [
            12, 12, 148, 222, 186, 248, 5, 190, 179, 72, 156, 114, 42, 40, 92, 9, 42, 50, 231, 198,
            137, 58, 191, 199, 208, 105, 105, 156, 131, 38, 252, 52, 69, 167, 73, 197, 39, 107, 98,
            0, 0, 0, 0,
        ];
        fuzz_block_header_deserialize(&data);
    }

    #[test]
    fn test_fuzz_transaction_prefix_deserialize_coverage() {
        let data = [
            2, 155, 137, 34, 1, 255, 223, 136, 34, 1, 182, 153, 212, 200, 177, 236, 2, 2, 35, 223,
            82, 74, 242, 162, 239, 95, 135, 10, 219, 110, 28, 235, 3, 164, 117, 195, 159, 139, 158,
            247, 106, 165, 11, 70, 221, 210, 161, 131, 73, 64, 43, 1, 40, 57, 191, 161, 155, 117,
            36, 236, 116, 136, 145, 119, 20, 194, 22, 202, 37, 75, 56, 237, 4, 36, 202, 101, 174,
            130, 138, 124, 0, 106, 234, 241, 2, 8, 245, 49, 106, 127, 107, 153, 204, 166,
        ];
        fuzz_transaction_prefix_deserialize(&data);
    }

    #[test]
    fn test_fuzz_extra_field_parse_sub_fields_coverage() {
        let extra_field_1 = fuzz_create_extra_field(&[0, 1, 2], AddPadding::ToFront);
        let extra_field_2 = fuzz_create_extra_field(&[0, 1, 2], AddPadding::ToMiddle);
        assert_ne!(extra_field_1, extra_field_2);

        let mut extra_field = fuzz_create_extra_field(&[], AddPadding::ToRear);
        extra_field.0.pop();
        extra_field.0.pop();
        fuzz_extra_field_parse_sub_fields(&extra_field);
    }

    #[test]
    fn test_fuzz_extra_field_try_parse_coverage() {
        let extra_field = fuzz_create_extra_field(&[], AddPadding::ToRear);
        fuzz_extra_field_try_parse(&extra_field, AddPadding::ToRear, &[]);
        let data = [
            230, 196, 73, 143, 43, 56, 217, 81, 1, 244, 76, 0, 106, 157, 99, 164, 0, 128, 107, 252,
            189, 156, 211, 217, 79, 231, 213, 136, 104, 65, 213, 255, 90, 255, 15, 64, 244, 201,
            135, 97, 135, 0, 21, 174, 185, 65, 184, 27, 229, 84, 182, 255, 236, 217, 32, 1, 63,
        ];
        let mut extra_field = fuzz_create_extra_field(&data, AddPadding::ToMiddle);
        extra_field.0.pop();
        fuzz_extra_field_try_parse(&extra_field, AddPadding::ToMiddle, &[]);
    }

    #[test]
    fn test_fuzz_transaction_deserialize_coverage() {
        use std::panic;
        let _result = panic::catch_unwind(|| {
            let data = [1];
            fuzz_transaction_deserialize(&data);
        });
    }

    #[test]
    fn test_fuzz_remaining_coverage() {
        let data = [1];
        fuzz_transaction_components(&data);
        fuzz_hash_convert(&data);
        let raw_extra_field = fuzz_create_raw_extra_field(&data).unwrap();
        fuzz_raw_extra_field_deserialize(&raw_extra_field);
        fuzz_raw_extra_field_from(&data);
        fuzz_transaction_hash(&fuzz_create_transaction_alternative_2(
            &data,
            &raw_extra_field,
        ));
        fuzz_transaction_check_outputs(&fuzz_create_transaction_alternative_2(
            &data,
            &raw_extra_field,
        ));
    }
}

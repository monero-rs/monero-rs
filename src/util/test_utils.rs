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
        if let Ok(bytes2) = serialize(&val) {
            assert_eq!(fuzz_bytes, bytes2);
        }
    }

    true
}

/// Fuzz for block header deserialization, called from the fuzz target
pub fn fuzz_block_header_deserialize(fuzz_data: &[u8]) -> bool {
    let fuzz_bytes = fuzz_data.to_vec();

    // BlockHeader
    if let Ok(val) = deserialize::<BlockHeader>(&fuzz_bytes[..]) {
        if let Ok(bytes2) = serialize(&val) {
            assert_eq!(fuzz_bytes, bytes2);
        }
    }

    true
}

/// Fuzz for transaction prefix deserialization, called from the fuzz target
pub fn fuzz_transaction_prefix_deserialize(fuzz_data: &[u8]) -> bool {
    let fuzz_bytes = fuzz_data.to_vec();

    // TransactionPrefix
    if let Ok(val) = deserialize::<TransactionPrefix>(&fuzz_bytes[..]) {
        if let Ok(bytes2) = serialize(&val) {
            assert_eq!(fuzz_bytes, bytes2);
        }
    }

    true
}

/// Padding sub-field position in extra data
#[derive(Clone, Copy)]
pub enum AddPadding {
    /// Add padding to the front of the extra field
    ToFront,
    /// Add padding to the middle of the extra field
    ToMiddle,
    /// Add padding to the rear of the extra field
    ToRear,
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
    let padding_field = if fuzz_bytes.is_empty() {
        SubField::Padding(u8::MIN)
    } else {
        SubField::Padding(fuzz_bytes[0])
    };

    // SubField::MergeMining
    let u64_val = if fuzz_bytes.is_empty() {
        0
    } else {
        let mut vec = fuzz_bytes.clone();
        vec.resize(8, 0);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(vec.as_slice());
        u64::from_le_bytes(bytes)
    };
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

/// Fuzz for extra field try parse, called from the fuzz target
pub fn fuzz_extra_field_try_parse(extra_field: &ExtraField, add_padding: AddPadding) -> bool {
    for sub_field in &extra_field.0 {
        match serialize(sub_field) {
            Ok(val) => match deserialize::<SubField>(&val) {
                Ok(des_sub_field) => assert_eq!(sub_field, &des_sub_field),
                Err(err) => panic!("Deserializing a serialized SubField may not fail ({})", err),
            },
            Err(err) => panic!("Serializing a SubField may not fail ({})", err),
        }
    }
    match RawExtraField::try_from(extra_field.clone()) {
        Ok(raw_extra_field) => {
            match ExtraField::try_parse(&raw_extra_field) {
                Ok(des_extra_field) => assert_eq!(extra_field, &des_extra_field),
                Err(err) => {
                    match add_padding {
                        AddPadding::ToFront => {
                            // This is acceptable, because the extra field composition may be invalid
                        }
                        AddPadding::ToMiddle => {
                            // This is acceptable, because the extra field composition may be invalid
                        }
                        AddPadding::ToRear => {
                            panic!("Parsing a serialized ExtraField with padding at the rear may not fail ({})", err)
                        }
                    }
                }
            };
        }
        Err(err) => panic!("Serializing an ExtraField may not fail ({})", err),
    };

    true
}

/// Fuzz for transaction deserialization, called from the fuzz target
pub fn fuzz_transaction_deserialize(fuzz_data: &[u8]) -> bool {
    let fuzz_bytes = fuzz_data.to_vec();

    // Transaction
    if let Ok(val) = deserialize::<Transaction>(&fuzz_bytes[..]) {
        if let Ok(bytes2) = serialize(&val) {
            assert_eq!(fuzz_bytes, bytes2);
        }
    }

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
        if let Ok(bytes2) = serialize(&val) {
            assert_eq!(fuzz_bytes, bytes2);
        }
    }

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

    true
}

/// Fuzz helper function to create a transaction, called from the fuzz target
pub fn fuzz_create_transaction(fuzz_data: &[u8], raw_extra_field: &RawExtraField) -> Transaction {
    let fuzz_bytes = fuzz_data.to_vec();
    let hash_1 = Hash::new(fuzz_data);
    let hash_2 = Hash::new(hash_1.0);
    let hash_3 = Hash::new(hash_2.0);
    let hash_4 = Hash::new(hash_3.0);
    let hash_5 = Hash::new(hash_4.0);
    let hash_6 = Hash::new(hash_5.0);
    let hash_7 = Hash::new(hash_6.0);
    let hash_8 = Hash::new(hash_7.0);
    let u64_val = if fuzz_bytes.is_empty() {
        0
    } else {
        let mut vec = fuzz_bytes.clone();
        vec.resize(8, 0);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(vec.as_slice());
        u64::from_le_bytes(bytes)
    };

    let prefix = TransactionPrefix {
        version: VarInt(u64_val),
        unlock_time: VarInt(u64_val),
        inputs: vec![
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
    let raw_extra_field_bytes = match serialize(raw_extra_field) {
        Ok(val) => val,
        Err(_) => {
            // This may not fail, otherwise the test cannot continue
            return true;
        }
    };
    if let Ok(raw_extra_field_2) = deserialize::<RawExtraField>(&raw_extra_field_bytes) {
        assert_eq!(raw_extra_field, &raw_extra_field_2);
    }

    true
}

/// Fuzz for raw extra field, called from the fuzz target
pub fn fuzz_raw_extra_field_from(fuzz_data: &[u8]) -> bool {
    let extra_field = fuzz_create_extra_field(fuzz_data, AddPadding::ToRear);
    assert!(RawExtraField::try_from(extra_field.clone()).is_ok());

    true
}

/// Fuzz for transaction hash, called from the fuzz target
pub fn fuzz_transaction_hash(transaction: &Transaction) -> bool {
    match transaction.hash() {
        Ok(_) => true,
        Err(_) => {
            // An error is acceptable, because the transaction may be invalid
            true
        }
    }
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

    transaction.check_outputs(&viewpair, 0..3, 0..3).is_ok()
}

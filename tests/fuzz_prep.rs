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

use monero::blockdata::transaction::RawExtraField;
use monero::{Address, AddressType};
use quickcheck::QuickCheck;

use monero::util::test_utils::{
    fuzz_block_deserialize, fuzz_block_header_deserialize, fuzz_create_extra_field,
    fuzz_create_transaction, fuzz_extra_field_try_parse, fuzz_hash_convert,
    fuzz_raw_extra_field_deserialize, fuzz_raw_extra_field_from, fuzz_transaction_check_outputs,
    fuzz_transaction_components, fuzz_transaction_deserialize, fuzz_transaction_hash,
    fuzz_transaction_prefix_deserialize, AddPadding,
};

#[test]
fn test_fuzz_block_deserialize2() {
    fn internal(data: Vec<u8>) -> bool {
        fuzz_block_deserialize(&data)
    }

    const TESTS: u64 = 25_000;

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

    const TESTS: u64 = 25_000;

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

    const TESTS: u64 = 25_000;

    QuickCheck::new()
        .min_tests_passed(TESTS)
        .tests(TESTS)
        .max_tests(TESTS)
        .quickcheck(internal as fn(Vec<u8>) -> bool);
}

#[test]
fn test_fuzz_transaction_deserialize() {
    fn internal(data: Vec<u8>) -> bool {
        fuzz_transaction_deserialize(&data)
    }

    const TESTS: u64 = 25_000;

    QuickCheck::new()
        .min_tests_passed(TESTS)
        .tests(TESTS)
        .max_tests(TESTS)
        .quickcheck(internal as fn(Vec<u8>) -> bool);
}

#[test]
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
    println!("\nfinished");
}

#[test]
fn test_fuzz_hash_convert() {
    fn internal(data: Vec<u8>) -> bool {
        fuzz_hash_convert(&data)
    }

    const TESTS: u64 = 25_000;

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

    const TESTS: u64 = 25_000;

    QuickCheck::new()
        .min_tests_passed(TESTS)
        .tests(TESTS)
        .max_tests(TESTS)
        .quickcheck(internal as fn(Vec<u8>) -> bool);
}

#[test]
fn test_fuzz_raw_extra_field_deserialize() {
    fn internal(data: Vec<u8>) -> bool {
        let extra_field = fuzz_create_extra_field(&data, AddPadding::ToRear);
        let raw_extra_field = match RawExtraField::try_from(extra_field) {
            Ok(val) => val,
            Err(_) => {
                // This may not fail, otherwise the test cannot continue
                return true;
            }
        };
        fuzz_raw_extra_field_deserialize(&raw_extra_field)
    }

    const TESTS: u64 = 25_000;

    QuickCheck::new()
        .min_tests_passed(TESTS)
        .tests(TESTS)
        .max_tests(TESTS)
        .quickcheck(internal as fn(Vec<u8>) -> bool);
}

#[test]
fn test_fuzz_extra_field_try_parse() {
    fn internal(data: Vec<u8>) -> bool {
        let add_padding = if data.is_empty() {
            AddPadding::ToMiddle
        } else {
            match data.len() % 3 {
                0 => AddPadding::ToFront,
                1 => AddPadding::ToMiddle,
                2 => AddPadding::ToRear,
                _ => unreachable!(),
            }
        };
        let extra_field = fuzz_create_extra_field(&data, add_padding);
        fuzz_extra_field_try_parse(&extra_field, add_padding)
    }

    const TESTS: u64 = 25000;

    QuickCheck::new()
        .min_tests_passed(TESTS)
        .tests(TESTS)
        .max_tests(TESTS)
        .quickcheck(internal as fn(Vec<u8>) -> bool);
}

#[test]
fn test_fuzz_transaction_hash() {
    fn internal(data: Vec<u8>) -> bool {
        let extra_field = fuzz_create_extra_field(&data, AddPadding::ToRear);
        let raw_extra_field = match RawExtraField::try_from(extra_field) {
            Ok(val) => val,
            Err(_) => {
                // This may not fail, otherwise the test cannot continue
                return true;
            }
        };
        let transaction = fuzz_create_transaction(&data, &raw_extra_field);
        fuzz_transaction_hash(&transaction)
    }

    const TESTS: u64 = 25_000;

    QuickCheck::new()
        .min_tests_passed(TESTS)
        .tests(TESTS)
        .max_tests(TESTS)
        .quickcheck(internal as fn(Vec<u8>) -> bool);
}

#[test]
fn test_fuzz_transaction_check_outputs() {
    fn internal(data: Vec<u8>) -> bool {
        let extra_field = fuzz_create_extra_field(&data, AddPadding::ToRear);
        let raw_extra_field = match RawExtraField::try_from(extra_field) {
            Ok(val) => val,
            Err(_) => {
                // This may not fail, otherwise the test cannot continue
                return true;
            }
        };
        let transaction = fuzz_create_transaction(&data, &raw_extra_field);
        fuzz_transaction_check_outputs(&transaction)
    }

    const TESTS: u64 = 25_000;

    QuickCheck::new()
        .min_tests_passed(TESTS)
        .tests(TESTS)
        .max_tests(TESTS)
        .quickcheck(internal as fn(Vec<u8>) -> bool);
}

#[test]
fn test_fuzz_address_from_bytes() {
    fn internal(data: Vec<u8>) -> bool {
        let _ = Address::from_bytes(&data);
        true
    }

    const TESTS: u64 = 25_000;

    QuickCheck::new()
        .min_tests_passed(TESTS)
        .tests(TESTS)
        .max_tests(TESTS)
        .quickcheck(internal as fn(Vec<u8>) -> bool);
}

#[test]
fn test_fuzz_address_type_from_slice() {
    fn internal(data: Vec<u8>) -> bool {
        let network = if data.is_empty() {
            monero::Network::Mainnet
        } else {
            match data.len() % 3 {
                0 => monero::Network::Mainnet,
                1 => monero::Network::Testnet,
                2 => monero::Network::Stagenet,
                _ => unreachable!(),
            }
        };
        let _ = AddressType::from_slice(&data, network);
        true
    }

    const TESTS: u64 = 25_000;

    QuickCheck::new()
        .min_tests_passed(TESTS)
        .tests(TESTS)
        .max_tests(TESTS)
        .quickcheck(internal as fn(Vec<u8>) -> bool);
}

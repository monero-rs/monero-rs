#![no_main]

use libfuzzer_sys::fuzz_target;
use monero::util::test_utils::{
    fuzz_create_extra_field,
    fuzz_create_transaction_1,
    fuzz_create_transaction_2,
    fuzz_transaction_hash,
    AddPadding,
};
use monero::blockdata::transaction::RawExtraField;

fuzz_target!(|data: &[u8]| {
    let transaction = fuzz_create_transaction_1(&data);
    let _ = fuzz_transaction_hash(&transaction);
    let extra_field = fuzz_create_extra_field(data, AddPadding::ToRear);
    let raw_extra_field = match RawExtraField::try_from(extra_field) {
        Ok(val) => val,
        Err(_) => {
            // This may not fail, otherwise the test cannot continue
            return;
        },
    };
    let transaction = fuzz_create_transaction_2(&data, &raw_extra_field);
    let _ = fuzz_transaction_hash(&transaction);
});

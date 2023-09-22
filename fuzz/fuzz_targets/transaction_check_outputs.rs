#![no_main]

use libfuzzer_sys::fuzz_target;
use monero::util::test_utils::{
    fuzz_create_extra_field,
    fuzz_create_transaction,
    fuzz_transaction_hash,
    AddPadding,
};
use monero::blockdata::transaction::RawExtraField;

fuzz_target!(|data: &[u8]| {
    let extra_field = fuzz_create_extra_field(&data, AddPadding::ToRear);
    let raw_extra_field = match RawExtraField::try_from(extra_field) {
        Ok(val) => val,
        Err(_) => {
            // This may not fail, otherwise the test cannot continue
            return;
        },
    };
    let transaction = fuzz_create_transaction(&data, &raw_extra_field);
    fuzz_transaction_hash(&transaction);
});

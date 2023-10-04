#![no_main]

use libfuzzer_sys::fuzz_target;
use monero::util::test_utils::{
    fuzz_create_raw_extra_field,
    fuzz_create_transaction_alternative_1,
    fuzz_create_transaction_alternative_2,
    fuzz_transaction_hash,
    AddPadding,
};
use monero::blockdata::transaction::RawExtraField;

fuzz_target!(|data: &[u8]| {
    let raw_extra_field = match fuzz_create_raw_extra_field(fuzz_data) {
        Ok(val) => val,
        Err(_) => {
            // This may not fail, otherwise the test cannot continue
            return true;
        }
    };

    let transaction = fuzz_create_transaction_alternative_1(fuzz_data, &raw_extra_field);
    let serialized_tx = serialize(&transaction);
    let _ = deserialize::<Transaction>(&serialized_tx[..]);

    let transaction = fuzz_create_transaction_alternative_2(fuzz_data, &raw_extra_field);
    let serialized_tx = serialize(&transaction);
    let _ = deserialize::<Transaction>(&serialized_tx[..]);
});

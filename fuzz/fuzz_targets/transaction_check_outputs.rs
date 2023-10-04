#![no_main]

use libfuzzer_sys::fuzz_target;
use monero::util::test_utils::{
    fuzz_create_transaction_alternative_1,
    fuzz_create_transaction_alternative_2,
    fuzz_transaction_check_outputs,
};

fuzz_target!(|data: &[u8]| {
    let transaction = fuzz_create_transaction_alternative_1(&data);
    fuzz_transaction_check_outputs(&transaction);

    let transaction = fuzz_create_transaction_alternative_2(&data);
    fuzz_transaction_check_outputs(&transaction);
});

#![no_main]

use libfuzzer_sys::fuzz_target;
use monero::util::test_utils::{
    fuzz_create_transaction_1,
    fuzz_transaction_check_outputs,
};

fuzz_target!(|data: &[u8]| {
    let transaction = fuzz_create_transaction_1(&data);
    fuzz_transaction_check_outputs(&transaction);
});

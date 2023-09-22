#![no_main]

use libfuzzer_sys::fuzz_target;
use monero::util::test_utils::{
    fuzz_transaction_components,
};

fuzz_target!(|data: &[u8]| {
    fuzz_transaction_components(data);
});

#![no_main]

use libfuzzer_sys::fuzz_target;
use monero::util::test_utils::{
    fuzz_create_extra_field,
};
use monero::blockdata::transaction::RawExtraField;

// Note: This fuzz did not panic

fuzz_target!(|data: &[u8]| {
    fuzz_raw_extra_field_from(&data);
});

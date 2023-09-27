#![no_main]

use libfuzzer_sys::fuzz_target;
use monero::util::test_utils::{
    fuzz_raw_extra_field_from,
};

fuzz_target!(|data: &[u8]| {
    fuzz_raw_extra_field_from(&data);
});

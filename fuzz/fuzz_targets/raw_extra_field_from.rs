#![no_main]

use libfuzzer_sys::fuzz_target;
use monero::util::fuzz_utils::{
    fuzz_raw_extra_field_from,
};

fuzz_target!(|data: &[u8]| {
    let _unused = fuzz_raw_extra_field_from(&data);
});

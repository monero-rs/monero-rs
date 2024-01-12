#![no_main]

use libfuzzer_sys::fuzz_target;
use monero::util::fuzz_utils::{
    fuzz_create_raw_extra_field,
    fuzz_raw_extra_field_deserialize,
};

fuzz_target!(|data: &[u8]| {
    let raw_extra_field = fuzz_create_raw_extra_field(data);
    let _unused = fuzz_raw_extra_field_deserialize(&raw_extra_field);
});

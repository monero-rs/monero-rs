#![no_main]

use libfuzzer_sys::fuzz_target;
use monero::util::fuzz_utils::{
    fuzz_create_raw_extra_field,
    fuzz_raw_extra_field_deserialize,
};

fuzz_target!(|data: &[u8]| {
    let raw_extra_field = match fuzz_create_raw_extra_field(data) {
        Ok(val) => val,
        Err(_) => {
            // This may not fail, otherwise the test cannot continue
            return;
        }
    };
    let _unused = fuzz_raw_extra_field_deserialize(&raw_extra_field);
});

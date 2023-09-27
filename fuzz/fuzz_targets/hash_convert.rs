#![no_main]

use libfuzzer_sys::fuzz_target;
use monero::util::test_utils::fuzz_hash_convert;

fuzz_target!(|data: &[u8]| {
    fuzz_hash_convert(data);
});

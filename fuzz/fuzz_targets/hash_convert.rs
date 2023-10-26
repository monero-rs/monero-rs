#![no_main]

use libfuzzer_sys::fuzz_target;
use monero::util::fuzz_utils::fuzz_hash_convert;

fuzz_target!(|data: &[u8]| {
    let _unused = fuzz_hash_convert(data);
});

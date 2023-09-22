#![no_main]

use libfuzzer_sys::fuzz_target;
use monero::util::test_utils::fuzz_block_header_deserialize;

fuzz_target!(|data: &[u8]| {
    fuzz_block_header_deserialize(data);
});

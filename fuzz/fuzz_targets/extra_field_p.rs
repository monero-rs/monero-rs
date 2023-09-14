#![no_main]

use libfuzzer_sys::fuzz_target;
use monero::util::test_utils::{
    fuzz_create_extra_field,
    fuzz_extra_field_try_parse,
    AddPadding,
};

// Note: Panicked
//
// thread '<unnamed>' panicked at 'assertion failed: `(left == right)`
//   left: `ExtraField([Nonce([]), Padding(0), MergeMining(Some(0), 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470), MysteriousMinerGate([])])`,
//  right: `ExtraField([Nonce([]), Padding(37)])`',
//         /mnt/c/Users/pluto/.tari/Code/fuzzing-tari-core/src/monero_fuzz.rs:167:13


fuzz_target!(|data: &[u8]| {
    let add_padding = if data.is_empty() {
        AddPadding::ToMiddle
    } else {
        match data.len() % 3 {
            0 => AddPadding::ToFront,
            1 => AddPadding::ToMiddle,
            2 => AddPadding::ToRear,
            _ => unreachable!(),
        }
    };
    let extra_field = fuzz_create_extra_field(&data, add_padding);
    fuzz_extra_field_try_parse(&extra_field, add_padding);
});

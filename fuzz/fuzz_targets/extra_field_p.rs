#![no_main]

use libfuzzer_sys::fuzz_target;
use monero::util::test_utils::{
    fuzz_create_extra_field,
    fuzz_extra_field_try_parse,
    AddPadding,
};

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
    let extra_field = fuzz_create_extra_field(data, add_padding);
    fuzz_extra_field_try_parse(&extra_field, add_padding, &data);
});

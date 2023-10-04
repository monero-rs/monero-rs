#![no_main]

use libfuzzer_sys::fuzz_target;
use monero::util::test_utils::{
    fuzz_create_extra_field,
    fuzz_extra_field_parse_sub_fields,
    AddPadding,
};

fuzz_target!(|data: &[u8]| {
    let add_padding = if data.is_empty() {
        AddPadding::ToMiddle
    } else {
        match data.len() % 3 {
            0 => AddPadding::ToFront,
            1 => AddPadding::ToMiddle,
            _ => AddPadding::ToRear,
        }
    };
    let extra_field = fuzz_create_extra_field(data, add_padding);
    fuzz_extra_field_parse_sub_fields(&extra_field, &data)
});

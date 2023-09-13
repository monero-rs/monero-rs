#![no_main]

use libfuzzer_sys::fuzz_target;
use monero::BlockHeader;
use monero::consensus::Decodable;
use monero::consensus::Encodable;

fuzz_target!(|data: &[u8]| {

    let mut data2 = Vec::from(data);
    match BlockHeader::consensus_decode(&mut data2.as_slice()){
       Ok(header) => {
            let mut v = vec![];
            header.consensus_encode(&mut v).unwrap();
            // dbg!(&header);
            // Data might have some extra bytes that are not read
            assert_eq!(&v, &data[0..v.len()]);
       },
         Err(_) => {
            // This is fine as long as it doesn't panic
        }
    }
});

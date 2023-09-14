// Rust Monero Library
// Written in 2019-2023 by
//   Monero Rust Contributors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//

use monero::blockdata::block::Block;
use monero::blockdata::transaction::Transaction;
use monero::consensus::encode::deserialize;
use monero::util::key::{KeyPair, PrivateKey, PublicKey, ViewPair};
use std::str::FromStr;

const TRANSACTION: &str = "02000102000bb2e38c0189ea01a9bc02a533fe02a90705fd0540745f59f49374365304f8b4d5da63b444b2d74a40f8007ea44940c15cbbc80c9d106802000267f0f669ead579c1067cbffdf67c4af80b0287c549a10463122b4860fe215f490002b6a2e2f35a93d637ff7d25e20da326cee8e92005d3b18b3c425dabe8336568992c01d6c75cf8c76ac458123f2a498512eb65bb3cecba346c8fcfc516dc0c88518bb90209016f82359eb1fe71d604f0dce9470ed5fd4624bb9fce349a0e8317eabf4172f78a8b27dec6ea1a46da10ed8620fa8367c6391eaa8aabf4ebf660d9fe0eb7e9dfa08365a089ad2df7bce7ef776467898d5ca8947152923c54a1c5030e0c2f01035c555ff4285dcc44dfadd6bc37ec8b9354c045c6590446a81c7f53d8f199cace3faa7f17b3b8302a7cbb3881e8fdc23cca0275c9245fdc2a394b8d3ae73911e3541b10e7725cdeef5e0307bc218caefaafe97c102f39c8ce78f62cccf23c69baf0af55933c9d384ceaf07488f2f1ac7343a593449afd54d1065f6a1a4658845817e4b0e810afc4ca249096e463f9f368625fa37d5bbcbe87af68ce3c4d630f93a66defa4205b178f4e9fa04107bd535c7a4b2251df2dad255e470b611ffe00078c2916fc1eb2af1273e0df30dd1c74b6987b9885e7916b6ca711cbd4b7b50576e51af1439e9ed9e33eb97d8faba4e3bd46066a5026a1940b852d965c1db455d1401687ccaccc524e000b05966763564b7deb8fd64c7fb3d649897c94583dca1558893b071f5e6700dad139f3c6f973c7a43b207ee3e67dc7f7f18b52df442258200c7fe6d16685127da1df9b0d93d764c2659599bc6d300ae33bf8b7c2a504317da90ea2f0bb2af09bd531feae57cb4a0273d8add62fadfc6d43402372e5caf854e112b88417936f1a9c4045d48b5b0b7703d96801b35ff66c716cddbee1b92407aa069a162c163071710e28ccddf6fb560feea32485f2c54a477ae23fd8210427eabe4288cbe0ecbef4ed19ca049ceded424d9f839da957f56ffeb73060ea15498fcbc2d73606e85e963a667dafdb2641fb91862c07b98c1fdae8fadf514600225036dd63c22cdadb57d2125ebf30bc77f7ea0bc0dafb484bf01434954c5053b9c8a143f06972f80fa66788ea1e3425dc0104a9e3674729967b9819552ebb172418da0e4b3778ad4b3d6acd8f354ba09e54bbc8604540010e1e1e4d3066515aed457bd3399c0ce787236dbcd3923de4fb8faded10199b33c1251191612ab5526c1cf0cd55a0aeaed3f7a955ceced16dabdbeb0a2a19a9fdb5aa8c4fc8767cf70e4ad1838518bc6b9de7c420c1f57636579a14a5a8bdacd24e61a68adede8a2e07416c25409dd91ab78905bc99bab4ab4fb9e4ea628e09a271837769c4e67e580dcd5485e12e4e308cb4509686a7484a71f7dfe334499808c7122f07d45d89230b1f19ed86f675b7fec44ef5f3b178ae0af92ff114bd96baa264604fea5a762307bdce6cb483b7bc780d32ed5343fcc3aa306997f211dc075f6dfd66035c1db10bef8656fefbb45645264d401682e42fe3e05906f79d65481b87508f1a4c434e0d1dfc247d4276306f801a6b57e4e4a525177bae24e0bd88a216597d9db44f2604c29d8a5f74e7b934f55048690b5dcefd6489a81aa64c1edb49b320faab94130e603d99e455cfd828bca782176192ece95e9b967fe3dd698574cf0c0b6926970b156e1134658de657de42c4930e72b49c0d94da66c330ab188c10f0d2f578590f31bcac6fcff7e21f9ff67ae1a40d5a03b19301dcbbadc1aa9392795cf81f1401ec16d986a7f96fbb9e8e12ce04a2226e26b78117a4dfb757c6a44481ff68bb0909e7010988cd37146fb45d4cca4ba490aae323bb51a12b6864f88ea6897aa700ee9142eaf0880844083026f044a5e3dba4aae08578cb057976001beb27b5110c41fe336bf7879733739ce22fb31a1a6ac2c900d6d6c6facdbc60085e5c93d502542cfea90dbc62d4e061b7106f09f9c4f6c1b5506dd0550eb8b2bf17678b140de33a10ba676829092e6a13445d1857d06c715eea4492ff864f0b34d178a75a0f1353078f83cfee1440b0a20e64abbd0cab5c6e7083486002970a4904f8371805d1a0ee4aea8524168f0f39d2dfc55f545a98a031841a740e8422a62e123c8303021fb81afbb76d1120c0fbc4d3d97ba69f4e2fe086822ece2047c9ccea507008654c199238a5d17f009aa2dd081f7901d0688aa15311865a319ccba8de4023027235b5725353561c5f1185f6a063fb32fc65ef6e90339d406a6884d66be49d03daaf116ee4b65ef80dd3052a13157b929f98640c0bbe99c8323ce3419a136403dc3f7a95178c3966d2d7bdecf516a28eb2cf8cddb3a0463dc7a6248883f7be0a10aae1bb50728ec9b8880d6011b366a850798f6d7fe07103695dded3f371ca097c1d3596967320071d7f548938afe287cb9b8fae761fa592425623dcbf653028";

#[test]
fn recover_output_and_amount() {
    let raw_tx = hex::decode(TRANSACTION).unwrap();
    let tx = deserialize::<Transaction>(&raw_tx).expect("Raw tx deserialization failed");

    let secret_view_bytes =
        hex::decode("bcfdda53205318e1c14fa0ddca1a45df363bb427972981d0249d0f4652a7df07").unwrap();
    let secret_view = PrivateKey::from_slice(&secret_view_bytes).unwrap();

    let secret_spend_bytes =
        hex::decode("e5f4301d32f3bdaef814a835a18aaaa24b13cc76cf01a832a7852faf9322e907").unwrap();
    let secret_spend = PrivateKey::from_slice(&secret_spend_bytes).unwrap();
    let public_spend = PublicKey::from_private_key(&secret_spend);

    // Keypair used to recover the ephemeral spend key of an output
    let keypair = KeyPair {
        view: secret_view,
        spend: secret_spend,
    };

    let spend = public_spend;

    // Viewpair used to scan a transaction to retreive owned outputs
    let view_pair = ViewPair {
        view: secret_view,
        spend,
    };

    // Get all owned output for sub-addresses in range of 0-1 major index and 0-2 minor index
    let owned_outputs = tx.check_outputs(&view_pair, 0..2, 0..3).unwrap();

    assert_eq!(owned_outputs.len(), 1);
    let out = owned_outputs.get(0).unwrap();

    // Recover the ephemeral private spend key
    let private_key = out.recover_key(&keypair).unwrap();
    assert_eq!(
        "9650bef0bff89132c91f2244d909e0d65acd13415a46efcb933e6c10b7af4c01",
        format!("{}", private_key)
    );
    assert_eq!(
        "b6a2e2f35a93d637ff7d25e20da326cee8e92005d3b18b3c425dabe833656899",
        format!("{}", PublicKey::from_private_key(&private_key))
    );

    let amount = out.amount();
    assert!(amount.is_some());
    assert_eq!(amount.unwrap().as_pico(), 7000000000);
}

#[test]
fn check_output_on_miner_tx() {
    // Generated new wallet: 49cttiQ3JH4ewwyVotG84TdCe367rziTsbkpsguMSmuMBf2igZMcBZDMs7TecAvKmMg4pnrz5WmiiXQgGLSVGVWzSdv21dw
    //
    // spendkey:
    // secret: 57cabb831c03159455ef561e7ce7daf841c5921b264f837d970115b9ef24c100
    // public: d30282faa44fa7e2df5ec621bf030cd86dfc6f3d4ddcd2cfca4bca51ce1b743f
    //
    // viewkey:
    // secret: b526321e8a138afba32063ac87d21f3deb05cb40a46410f8fe861f5ab95ac606
    // public: b4c76e76ad3eac7cbcd60983966d8ce98f582a8b288acbb5cc841d69c6d2b3e3
    //
    // swiftly september faked having annoyed ourselves pedantic cunning
    // fetches major potato peeled answers against building soprano
    // eternal school lipstick wickets python puzzled large lava building
    //
    //   1  block unlocked       2022-06-29 07:33:29      35.184338534400 50ad877c2f126c9278dc4b043774bceb995c80bc2fa11de10a0f8379a856422e 0000000000000000 0.000000000000 49cttiQ3JH4ewwyVotG84TdCe367rziTsbkpsguMSmuMBf2igZMcBZDMs7TecAvKmMg4pnrz5WmiiXQgGLSVGVWzSdv21dw:35.184338534400 0 -
    //
    let block = hex::decode("0e0ec980f09506418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e38475c625023d01ff0101808080f0ffff0702e928dfd0a413a4eac0b541fcc434c56da56cb34c95d8d6916146c3a4f7071ae82101b0f38ad895b9a7bc053e9be31ddd16139ad7006396ae7a29eb6365306ae6f4b70000").unwrap();
    let block = deserialize::<Block>(&block).expect("Block deserialization failed");
    println!("{:#?}", block);

    let secret_view =
        PrivateKey::from_str("b526321e8a138afba32063ac87d21f3deb05cb40a46410f8fe861f5ab95ac606")
            .unwrap();

    let secret_spend =
        PrivateKey::from_str("57cabb831c03159455ef561e7ce7daf841c5921b264f837d970115b9ef24c100")
            .unwrap();
    let public_spend = PublicKey::from_private_key(&secret_spend);

    let keypair = KeyPair {
        view: secret_view,
        spend: secret_spend,
    };

    let spend = public_spend;
    let view_pair = ViewPair {
        view: secret_view,
        spend,
    };

    let owned_outputs = block
        .miner_tx
        .check_outputs(&view_pair, 0..1, 0..1)
        .unwrap();

    assert_eq!(owned_outputs.len(), 1);
    let out = owned_outputs.get(0).unwrap();

    let private_key = out.recover_key(&keypair).unwrap();
    assert_eq!(
        "f984b89e6c4f18ff1d6e2bd9eb5571097dbc48d5d7b4cc51ac1a548cb9d3b809",
        format!("{}", private_key)
    );
    assert_eq!(
        "e928dfd0a413a4eac0b541fcc434c56da56cb34c95d8d6916146c3a4f7071ae8",
        format!("{}", PublicKey::from_private_key(&private_key))
    );

    let amount = out.amount();
    assert!(amount.is_some());
    assert_eq!(amount.unwrap().as_pico(), 35184338534400);
}

#[test]
fn recover_output_and_amount_view_tagged() {
    // Transaction with a false positve view tag
    let raw_tx = hex::decode("020001020010f9b7b61a8a968a0288d201fafd08ee8401a4cb019efd01971eb0578604e207e403b201cb018c0fa70a0cb4bc29479087e2ae43915b3a28c6e8250edbd199779df1b3d948aa11e4e3000200037ab37a0735606650c1949d4bc4e56fada3417bb549f0400d99aa3f5e5f76e2bb5e0003d3707534b0c53156c26873f00a8d3c6e6480c599d9d4d2a3a96ee4f8002aab0f2d2c01a0e85d863a9a82dc82905310af78fa36ff6fd475ff5ef6c5c6611eb3ec629e8b0209017094944e5c8da5ba06e0f2cc0e72953d44df724bfcae12eafe54c55a413672c675f9cf407340473f77d63503f9dd3c44fcbb96d7f1e02ca7f972fb1681c5a630c2a924590ae7b485f39a8b531709c35ceae02e117ff06381e5b95a82be01ccc7d04f1cd6d3aefa10f9a400818e2f55d57edd99882d4cab5a9b3665f6efa905c330fd9d3998b8b7358b01392fac7d5d036e13e6d82013e26bfe0a5ffc04d4b0f0b7bad0e465b5a78deee3bab25d1560fcc3ce21ebdb40fc9d00025eda76c59136e0e4bbf1d18f56225e197db401a86a99709ad6f9adedc064f500df471d0bc19908911a3f8227a12dca286543d44f5f7843e2fb261d2092eeda3541706a0dd9779d7a0d762da7973ba39da0e700edb014ed68a874745b1a0e9bd758992e03076000cf3694adcd4cb8525606987e0d344f34fca2999bafaf92e5cb5716d9a1a64facef01d6adcc1d07a6d4c53a2959e6d3768f860e202c56dbe1c988d6f40278b37f07231f19d20388c1ea812596f2228dcbdbbdaaf156c15e993d2a78f2bb5d35fe34c76b72e34788ad1d08a8f24e40525583baf1deff4b6cf0e9e113eaa099a5a347a1dce8004d578209dce92759aa685071cc7ea9a50313effa55c2d64e2da7aa0c9a0d73d0147685e02f5733c25b35967331e04351d742de3092366cc1f1df7d49e8e2b13cf7ef396150c700c391ed046f7a6b0def1f1314124132ec4c0507af2fbd1804fbed13010f21da2b35c83e50a4b6382acbca1fffba7601850719dc909dff632a02216df7418fe6e87b6da323b4700f012f1b382ac27fa7e74b69384478c75af0fa1afd183b52c7174141a67ad2ce5369ce7719c46c725d42834f4a75340ce1d2b56f6d3497142a818541d18372c221b57632c7e26e006512398394a5d76c9dccec9342fca7d549061e2cf664ddbd39526290ea03e291cba522d58e7af6cec11a4183b8e59421df44dacd3a7e4eed19f2f4c743ea49c9595e82b27d5ac00401f39900ad0c406ddd69526bb8f9cd525299180863a6c5bc69c21352d0a6a571c6681a202cb2f9c561cd1b3a3a20314ec2497feda8d35a7fd48345980cc357565711d05605432ad9629dbf1ae770ccb0238a8f7565407b75571e38dd051882f553641400a95b95140fc8a932bd8393ec55f78ddb57df35d941540610026ccaec2273dbf5824578dce9736cbcbfe20715e73994a7297908388eb522e4054469448971db778bcefcbaa45a41c58ae28f82c4da60872360cbb51a2148e000b2286fee5019619e5f4a86def4ae13d8083bf23d2d93a4b634705d63012a8a08f9e353c8d9a5fa5f7c2218b8772ede25ddf072949c10c9c31e9d0024a4f1c20132595bf735601bfaa3101d2adb9cd4eef2dc60f2f450fdba5fb9988f1beb7f0724574ecc697342c22df2a28e75d264a74284d1f0e49040b1ea8604a9780ff003b02a801a615f2dc20a09c076368a9263a0cfc79b052e45df4e99fa9c1e629e0b7959c552edaff71b2b349ae34109510c401e456db5e7d2178dc643b12fc72a0a7ac9387e68aba392c988135237ac9f578c01ce5f1c9b1027665cc5be657dd70c9614cf7e0f71f37c437868e2d007f61f027f4d9238b8718423315034f0c9d1046967acd0da77b7f92cc2ca2f9358da608ae1b12a5acfb2d00b672409301df3068860621285d18f217ef5a5324a858bb7978c6cdd7358821fd30baba41c3fa50c268b57114db9c17851c6a49e5b221335c59b030d7ee7687c645d96d18e1be3051f2f6d96417a8e40ccdba572b02af5443aa9a8e8089a8e5e6cdb8821ac3f710c923256d7059514d3de3a775b80f7446b2ad7d7afdb6619eadb1514d97d26ce2d1f3dcf717cbab30ffa1d75c52e1fb65e4a1c0b612d911ab2d98d4c6e7369dc8f").unwrap();
    let tx = deserialize::<Transaction>(&raw_tx).expect("Raw tx deserialization failed");

    let secret_view_bytes =
        hex::decode("ea14e88ba27fd2b1f0d115f4e37e3058508a71539b5cad985c9bfb39592b9c05").unwrap();
    let secret_view = PrivateKey::from_slice(&secret_view_bytes).unwrap();

    let secret_spend_bytes =
        hex::decode("a336c3ad46b255925f854f2abaf5a054d5d76194bc0baa8213e251a95a6c3309").unwrap();
    let secret_spend = PrivateKey::from_slice(&secret_spend_bytes).unwrap();
    let public_spend = PublicKey::from_private_key(&secret_spend);

    // Keypair used to recover the ephemeral spend key of an output
    let keypair = KeyPair {
        view: secret_view,
        spend: secret_spend,
    };

    let spend = public_spend;

    // Viewpair used to scan a transaction to retreive owned outputs
    let view_pair = ViewPair {
        view: secret_view,
        spend,
    };

    // Get all owned output for sub-addresses in range of 0-1 major index and 0-2 minor index
    let owned_outputs = tx.check_outputs(&view_pair, 0..2, 0..3).unwrap();

    assert_eq!(owned_outputs.len(), 1);
    let out = owned_outputs.get(0).unwrap();

    // Recover the ephemeral private spend key
    let private_key = out.recover_key(&keypair).unwrap();
    assert_eq!(
        "d243f31cd076d0863d95aea770d40cc3b08549ea4de62ec3b58fed8170392303",
        format!("{}", private_key)
    );
    assert_eq!(
        "d3707534b0c53156c26873f00a8d3c6e6480c599d9d4d2a3a96ee4f8002aab0f",
        format!("{}", PublicKey::from_private_key(&private_key))
    );

    let amount = out.amount();
    assert!(amount.is_some());
    assert_eq!(amount.unwrap().as_pico(), 23985700000);

    // Transaction with view tag where the view tag is NOT a false positive
    let raw_tx = hex::decode("020001020010c0ecca15f68bf303efb38f02fbc620a2f5369208fd960ecdc00bc6a50587c503d8c002d13195de0185289a1dee80011f572209f934abadd42bc54fa308ad08c6b0d1217aa9729e8ad082d150459f94020003890c76c92a32f54410d06faa8d2d9c424babf8f5b6a6bfbaafd8c7b8ac74cea6b2000329b316989a1e3a27058d3aa237e55e8ab69b2b8d7c16f751779f42dfa7278860342c015bc6868b4286c45e5158121e77749b2246dbc9e7733c142f8c2386b03e271676020901e6b365fbbff45b0d06a09cd40e9a54f86a96ad5f7df807a67b0e9b3a1e7cefebd2f6a661ed65e98d502bd97bec2f13bb13f85d48599abe43f991e0737c7cb5b14e94c63867ef11381249bc339aa275e713fd9baf67c2377c442b586b49015858f08f80f0627d2ff608f91bece3047e2b40ecff00962a5aad4af612011d0c6d1fa314680755da8de0e5fef307f9006ad1a4daf17ae4b3c395a22048b44ffbb629a20c019e9d8053883b2446fabc4af77cd75533963b1d6ffc69725a6e4d2954ee02129bce1da729b435b0ade7be2b641b2e059b9939bdcf43b021ee333b02c71bf848c79ef8a10f9e5d2ce17eb797b067d51d5c7ee16cd3b540eecee12608965f0f4d0f1df0a3a609314ee06ae3f7af066a6eda54451006640a11f1bcc90007cd733c4328541a8d674b92bd2a6de42e84252a86489b4d42732c29cdefa125df410bd17220cfebcd298a565139dabd2e6be04b80b0b23d585d83a0f169d48a620883189ed0870904eff0f4c1a619c461773f339e71241d8837f99fc50d6a4c37896ac9709e058311a1d8d1e40d129a3fca4aeba3ddda6c53027285de41488d658e6f644ea330cc33ca9d9391fce7514b48457e7c631a48245bf30791ea4e4639ac4077fa69ece1578ba043bd6221511f85351b0644ceb3736763785f5cc21e5a317115085e08b7d4dc4a731ab9072f9b7b9cbf90f870adea47c936813106771d07e15a8cbc177f3ef11373a62bc2ff9891c956ad92472e6dd511484e15c38a136ae925645c11bbdb230c4ef455fc852ffabc60a6f67cd46dc06ad626055cf83a8fd1cc24b57eb235e67f3cbdf94f92066fa9eda924b60123e97298d6433440ebc80b835086487359f3015511b0c6b07a7aa461a285ff4d1e8d119768bb5eb27d321c5f5c5e4ed45dba9e4f6e2a721ab5fd25da90b3177050a7077b3dfc70cf4636eeff1f246c0cdf168225463f8e0e7f2c06856e31c4e2007e2f17125dbc14cfb1724cbfaaedb5a2d6ca50d8a57d9b971721f3a5ae553edec0d25922f56f1d120953e28d5d92592113079559bb6572109d59ead3c912ff92ad13c43fd50c4e570369df7a7d459118dc45349c97ef2890dd288ee6a14d2c785aab52ae1ee886b00cca75d6f1ec0fe1616d08f40dd1025f016f41f09ded960d7bc73ab1000b906908c2b2483501bd35a78cbe3905432c655fee2be28a8772af2033d926b5b2a1840bcb0ff1d37bd8539b0705d9ca1e305abd834aae2ef34fe684d18ed895afc945066287c52ee5d4613871d7cf582325751df96faf921e701779fa9bda8d24acac068eb7131eab9229248a33220d1bc20dfa3518e58f30efe6627c8f7e8b8c5ba10b4f8837b4049cfa63a50a811b18c7dd6edeaaedd6dfb614a67773e517f1575306b2c069652718d07bcc52df36fdc50e24fedf87faaeef1b9ad920d98761ab1506f5304782bc3f3fa958465cf0a0f54a97a4e7ab5abc93160c05a92ecb58333605bf2273e4f0d185d190f8f0d69cdc01dd8694fed49c31489f353ceaf40100970bf81c8f97bc1ca0d81eda8cc86061f02fbef3ff15870dd6824aa3afe40e71880cd4ff24a1f1241e5482de4143f79d85930f3d240929d7b2dd1d7f283ddb5689019e17543053bb1b46be4851dfa48d5fb8c37ff20759c8c7abfae4e2c9b6715e0b5f0dae6ea4b9d23f07c04609f96d9c3a860c3f626e37fe9d48bc590930ac270625b0f1514ce4593c0db0d51ed5d9a63bb6edaee069c41b1569827f3491f18001e10004522f4ec6851f643a505de7857ae749a0c83f8868d5f085dd81961f70068052733fc3ebd379c6717ee61ea01fd40e8a7f0b8f32bf2d6d49e5d687751d35fd94d7442e9d385b6b466172f1be1231fea5a3c1eb20f8e2d841b0a6badd36e4").unwrap();
    let tx = deserialize::<Transaction>(&raw_tx).expect("Raw tx deserialization failed");

    // Get all owned output for sub-addresses in range of 0-1 major index and 0-2 minor index
    let owned_outputs = tx.check_outputs(&view_pair, 0..2, 0..3).unwrap();

    assert_eq!(owned_outputs.len(), 1);
    let out = owned_outputs.get(0).unwrap();

    // Recover the ephemeral private spend key
    let private_key = out.recover_key(&keypair).unwrap();
    assert_eq!(
        "487275dec957e852a0092fe093cd0c0e440ab4393981e7d96fbe62ce2697ce0d",
        format!("{}", private_key)
    );
    assert_eq!(
        "890c76c92a32f54410d06faa8d2d9c424babf8f5b6a6bfbaafd8c7b8ac74cea6",
        format!("{}", PublicKey::from_private_key(&private_key))
    );

    let amount = out.amount();
    assert!(amount.is_some());
    assert_eq!(amount.unwrap().as_pico(), 24047000000);
}

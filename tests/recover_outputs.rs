use monero::blockdata::transaction::Transaction;
use monero::consensus::encode::deserialize;
use monero::util::key::{KeyPair, PrivateKey, PublicKey, ViewPair};

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
    let private_key = out.recover_key(&keypair);
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
    assert_eq!(amount.unwrap(), 7000000000);
}

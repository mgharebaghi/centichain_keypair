use bip39::Mnemonic;
use sp_core::{
    ed25519::{self, Public, Signature},
    Pair,
};

 pub struct CentichainKey;

impl CentichainKey {
    ///Generating Centichain network key pairs randomly
    ///
    ///The output is a tuple that contains seed phrase and public key
    ///
    /// ````
    pub fn generate() -> (String, Public) {
        let entropy = rand::random::<[u8; 16]>();
        let mnemonic = Mnemonic::from_entropy_in(bip39::Language::English, &entropy)
            .expect("Valid entropy should generate valid mnemonic");
        let keypair = ed25519::Pair::from_phrase(&mnemonic.to_string(), None)
            .expect("Valid mnemonic should generate valid keypair");
        (mnemonic.to_string(), keypair.0.public())
    }

    ///Returning the public key by getting the seed phrase
    /// ````
    pub fn check_phrase<'a>(seed_phrase: &String) -> Result<Public, &'a str> {
        let keypair = ed25519::Pair::from_phrase(seed_phrase, None);
        match keypair {
            Ok(pair) => Ok(pair.0.public()),
            Err(_) => Err("Your seed phrase is wrong!"),
        }
    }

    ///Taking input and returning a signature accepted by the Centichain network
    /// ````
    pub fn signing<'a>(seed_phrase: &String, message: &String) -> Result<Signature, &'a str> {
        let keypair = ed25519::Pair::from_phrase(&seed_phrase, None);
        match keypair {
            Ok(pair) => Ok(pair.0.sign(message.as_bytes())),
            Err(_) => Err("Your seed phrase is wrong!"),
        }
    }
}

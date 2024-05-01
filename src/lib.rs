use bip39::Mnemonic;
use sp_core::{ecdsa::{Public, self, Signature}, Pair};

///Generating Centichain network key pairs randomly
/// 
///The output is a tuple that contains seed phrase and public key
/// 
/// ````
pub fn generate() -> (String, Public) {
    let seed = seed15::random_seed();
    let mnemonic = Mnemonic::from_entropy(&seed).unwrap();
    let seed_phrase = mnemonic.to_string();
    let keypair = ecdsa::Pair::from_phrase(&seed_phrase, None).unwrap();
    (seed_phrase, keypair.0.public())
}

///Returning the public key by getting the seed phrase
/// ````
pub fn check_phrase_key<'a>(seed_phrase: String) -> Result<Public, &'a str> {
    let keypair = ecdsa::Pair::from_phrase(&seed_phrase, None);
    match keypair {
        Ok(pair) => {
            Ok(pair.0.public())
        },
        Err(_) => {
            Err("Your seed phrase is wrong!")
        }
    }
}

///Taking input and returning a signature accepted by the Centichain network
/// ````
pub fn sign_message(seed_phrase: String, message: &String) -> Result<Signature, &str> {
    let keypair = ecdsa::Pair::from_phrase(&seed_phrase, None);
    match keypair {
        Ok(pair) => {
            Ok(pair.0.sign(message.as_bytes()))
        },
        Err(_) => {
            Err("Your seed phrase is wrong!")
        }
    }
}

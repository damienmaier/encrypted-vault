use std::collections::HashMap;
use std::iter::zip;

use dryoc::{dryocbox, rng};
use dryoc::dryocsecretbox;
use dryoc::pwhash;
use dryoc::pwhash::VecPwHash;
use sharks;

use crate::data::UserShare;
use crate::symmetric_encryption_helper::SymEncryptedData;
use crate::symmetric_encryption_helper::SYMMETRIC_KEY_LENGHT_BYTES;


const NB_USERS_REQUIRED_TO_RETRIEVE_PRIVATE_KEY: u8 = 2;
const SALT_LENGTH_BYTES: usize = 16;



pub fn argon_config() -> pwhash::Config {

    pwhash::Config::sensitive().with_salt_length(SYMMETRIC_KEY_LENGHT_BYTES)
}


// This config makes Argon hashing fast
// This is totally unsafe and must not be used in production
// This config is used when testing, because otherwise tests would take far too much time
pub fn argon_unsafe_config() -> pwhash::Config {
    argon_config().with_memlimit(10000).with_opslimit(1)
}

pub fn create_protected_key_pair(user_credentials: &HashMap<String, String>,
                                 argon_config: &pwhash::Config)
                                 -> (HashMap<String, UserShare>, dryocbox::PublicKey) {
    let key_pair = dryocbox::KeyPair::gen();

    let shares = sharks::Sharks(NB_USERS_REQUIRED_TO_RETRIEVE_PRIVATE_KEY)
        .dealer(&key_pair.secret_key);

    let mut user_shares = HashMap::new();
    for ((name, password), share) in zip(user_credentials, shares) {
        let salt = rng::randombytes_buf(SALT_LENGTH_BYTES);

        let user_key = get_key_from_password(password, &salt, argon_config);
        let encrypted_private_key_share = SymEncryptedData::encrypt(&Vec::from(&share), &user_key);

        user_shares.insert(name.clone(), UserShare { salt, encrypted_private_key_share });
    }

    (user_shares, key_pair.public_key)
}

pub fn retrieve_private_key(
    password1: &str, user_share1: &UserShare, password2: &str, user_share2: &UserShare,
    argon_config: &pwhash::Config)
    -> dryocbox::SecretKey {
    let share1 = decrypt_share_with_password(user_share1, password1, argon_config);
    let share2 = decrypt_share_with_password(user_share2, password2, argon_config);

    let recovered_secret = sharks::Sharks(NB_USERS_REQUIRED_TO_RETRIEVE_PRIVATE_KEY).recover([&share1, &share2]).unwrap();

    <[u8; SYMMETRIC_KEY_LENGHT_BYTES]>::try_from(recovered_secret).unwrap().into()
}

fn get_key_from_password(password: &str, salt: &pwhash::Salt, argon_config: &pwhash::Config) -> dryocsecretbox::Key {
    let (hash, ..) = VecPwHash::hash_with_salt(&password.as_bytes(), salt.clone(), argon_config.clone())
        .unwrap()
        .into_parts();

    <[u8; SYMMETRIC_KEY_LENGHT_BYTES]>::try_from(hash).unwrap().into()
}

fn decrypt_share_with_password(share: &UserShare, password: &str, argon_config: &pwhash::Config) -> sharks::Share {
    let user_key = get_key_from_password(&password, &share.salt, argon_config);
    let decrypted = share.encrypted_private_key_share.decrypt(&user_key);

    sharks::Share::try_from(decrypted.as_slice()).unwrap()
}




#[cfg(test)]
mod tests {
    use dryoc::dryocbox::DryocBox;

    use super::*;

    #[test]
    fn create_then_retrieve() {
        let mut user_credentials: HashMap<String, String> = HashMap::new();

        user_credentials.insert(String::from("GLaDos"), String::from("pa89fjqp3f"));
        user_credentials.insert(String::from("Chell"), String::from("japo288asfd"));
        user_credentials.insert(String::from("Wheatley"), String::from("q27jafa;fkds"));
        user_credentials.insert(String::from("Cave"), String::from("783fjasdf"));


        let (user_shares, public_key) = create_protected_key_pair(&user_credentials, &argon_unsafe_config());

        let message = b"The cake is a lie !";
        let encrypted_token = DryocBox::seal_to_vecbox(&message, &public_key).unwrap();

        let secret_key = retrieve_private_key(
            user_credentials.get("Chell").unwrap(),
            user_shares.get("Chell").unwrap(),
            user_credentials.get("Cave").unwrap(),
            user_shares.get("Cave").unwrap(),
            &argon_unsafe_config()
        );

        assert_eq!(
            message.to_vec(),
            DryocBox::unseal_to_vec(
                &encrypted_token, &dryocbox::KeyPair { public_key, secret_key }).unwrap()
        )
    }
}
use std::collections::HashMap;
use std::iter::zip;

use dryoc::{dryocbox, rng};
use dryoc::dryocsecretbox;
use dryoc::pwhash;
use dryoc::pwhash::VecPwHash;
use sharks;
use crate::client::AuthenticatedClient;

use crate::data::{Token, UserShare};
use crate::symmetric_encryption_helper::SymEncryptedData;
use crate::symmetric_encryption_helper::SYMMETRIC_KEY_LENGHT_BYTES;

pub struct PrivateKeyProtection {
    argon2_config: pwhash::Config,
}

const NB_USERS_REQUIRED_TO_RETRIEVE_PRIVATE_KEY: u8 = 2;
const SALT_LENGTH_BYTES: usize = 16;

impl PrivateKeyProtection {
    pub fn new() -> Self {
        PrivateKeyProtection { argon2_config: pwhash::Config::sensitive().with_salt_length(SYMMETRIC_KEY_LENGHT_BYTES) }
    }

    pub fn new_unsafe() -> Self{
        let mut instance = Self::new();
        instance.argon2_config = instance.argon2_config.with_memlimit(10000).with_opslimit(1);
        instance
    }

    pub(crate) fn create_protected_key_pair(&self, user_credentials: &HashMap<String, String>)
                                 -> (HashMap<String, UserShare>, dryocbox::PublicKey) {
        let key_pair = dryocbox::KeyPair::gen();

        let shares = sharks::Sharks(NB_USERS_REQUIRED_TO_RETRIEVE_PRIVATE_KEY)
            .dealer(&key_pair.secret_key);

        let mut user_shares = HashMap::new();
        for ((name, password), share) in zip(user_credentials, shares) {
            let salt = rng::randombytes_buf(SALT_LENGTH_BYTES);

            let user_key = self.get_key_from_password(password, &salt);
            let encrypted_private_key_share = SymEncryptedData::encrypt(&Vec::from(&share), &user_key);

            user_shares.insert(name.clone(), UserShare { salt, encrypted_private_key_share });
        }

        (user_shares, key_pair.public_key)
    }

    pub(crate) fn get_vault_access(
        &self, encrypted_token: &dryocbox::VecBox, public_key: &dryocbox::PublicKey,
        password1: &str, user_share1: &UserShare,
        password2: &str, user_share2: &UserShare,
    )
        -> AuthenticatedClient {
        let share1 = self.decrypt_share_with_password(user_share1, password1);
        let share2 = self.decrypt_share_with_password(user_share2, password2);

        let recovered_secret = sharks::Sharks(NB_USERS_REQUIRED_TO_RETRIEVE_PRIVATE_KEY).recover([&share1, &share2]).unwrap();
        let private_key: dryocbox::SecretKey = <[u8; SYMMETRIC_KEY_LENGHT_BYTES]>::try_from(recovered_secret).unwrap().into();

        let key_pair = dryocbox::KeyPair { public_key: public_key.clone(), secret_key: private_key};
        let token = encrypted_token.unseal_to_vec(&key_pair).unwrap();
        AuthenticatedClient {key_pair, token}
    }

    fn get_key_from_password(&self, password: &str, salt: &pwhash::Salt) -> dryocsecretbox::Key {
        let (hash, ..) = VecPwHash::hash_with_salt(&password.as_bytes(), salt.clone(), self.argon2_config.clone())
            .unwrap()
            .into_parts();

        <[u8; SYMMETRIC_KEY_LENGHT_BYTES]>::try_from(hash).unwrap().into()
    }

    fn decrypt_share_with_password(&self, share: &UserShare, password: &str) -> sharks::Share {
        let user_key = self.get_key_from_password(&password, &share.salt);
        let decrypted = share.encrypted_private_key_share.decrypt(&user_key);

        sharks::Share::try_from(decrypted.as_slice()).unwrap()
    }
}


#[cfg(test)]
mod tests {
    use dryoc::dryocbox;
    use dryoc::dryocbox::DryocBox;

    use super::*;

    #[test]
    fn create_then_retrieve() {
        let mut user_credentials: HashMap<String, String> = HashMap::new();

        user_credentials.insert(String::from("GLaDos"), String::from("pa89fjqp3f"));
        user_credentials.insert(String::from("Chell"), String::from("japo288asfd"));
        user_credentials.insert(String::from("Wheatley"), String::from("q27jafa;fkds"));
        user_credentials.insert(String::from("Cave"), String::from("783fjasdf"));

        let mut instance = PrivateKeyProtection::new_unsafe();

        let (user_shares, public_key) = instance.create_protected_key_pair(&user_credentials);

        let token = b"The cake is a lie !";
        let encrypted_token = DryocBox::seal_to_vecbox(&token, &public_key).unwrap();

        let vault_acess = instance.get_vault_access(
            &encrypted_token, &public_key,
            user_credentials.get("Chell").unwrap(),
            user_shares.get("Chell").unwrap(),
            user_credentials.get("Cave").unwrap(),
            user_shares.get("Cave").unwrap(),
        );

        assert_eq!(
            token.to_vec(),
            DryocBox::unseal_to_vec(&encrypted_token, &vault_acess.key_pair).unwrap()
        )
    }
}
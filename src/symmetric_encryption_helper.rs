use dryoc::dryocsecretbox;
use dryoc::dryocsecretbox::NewByteArray;
use serde::Deserialize;
use serde::Serialize;

pub const SYMMETRIC_KEY_LENGHT_BYTES: usize = 32;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct SymEncryptedData {
    secret_box: dryocsecretbox::VecBox,
    nonce: dryocsecretbox::Nonce,
}

impl SymEncryptedData {
    pub fn encrypt(message: &[u8], key: &dryocsecretbox::Key) -> Self {
        let nonce = dryocsecretbox::Nonce::gen();

        Self {
            secret_box: dryocsecretbox::DryocSecretBox::encrypt_to_vecbox(message, &nonce, key),
            nonce,
        }
    }

    pub fn decrypt(&self, key: &dryocsecretbox::Key) -> Vec<u8> {
        self.secret_box.decrypt_to_vec(&self.nonce, key).unwrap()
    }
}
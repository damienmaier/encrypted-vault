use dryoc::dryocsecretbox;
use dryoc::dryocsecretbox::NewByteArray;

pub struct SymEncryptedData {
    secret_box: dryocsecretbox::VecBox,
    nonce: dryocsecretbox::Nonce,
}

impl SymEncryptedData {
    pub(crate) fn encrypt(message: &[u8], key: &dryocsecretbox::Key) -> Self {
        let nonce = dryocsecretbox::Nonce::gen();

        Self {
            secret_box: dryocsecretbox::DryocSecretBox::encrypt_to_vecbox(message, &nonce, key),
            nonce,
        }
    }

    pub(crate) fn decrypt(&self, key: &dryocsecretbox::Key) -> Vec<u8> {
        self.secret_box.decrypt_to_vec(&self.nonce, key).unwrap()
    }
}
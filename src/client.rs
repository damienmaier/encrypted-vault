use dryoc::{dryocbox, dryocsecretbox};
use dryoc::dryocbox::DryocBox;
use dryoc::dryocsecretbox::NewByteArray;

use crate::data::Document;
use crate::data::EncryptedDocument;
use crate::symmetric_encryption_helper::SymEncryptedData;
use crate::symmetric_encryption_helper::SYMMETRIC_KEY_LENGHT_BYTES;

struct UnlockedVault {
    key_pair: dryocbox::KeyPair,
}

impl UnlockedVault {
    fn new(key_pair: dryocbox::KeyPair) -> Self {
        Self { key_pair }
    }

    fn decrypt_document_key(&self, encrypted_key: &dryocbox::VecBox) -> dryocsecretbox::Key {
        let symmetric_key_vec = encrypted_key.unseal_to_vec(&self.key_pair).unwrap();

        <[u8; SYMMETRIC_KEY_LENGHT_BYTES]>::try_from(symmetric_key_vec).unwrap().into()
    }


    fn new_document(&self, document: &Document)
                    -> (EncryptedDocument, dryocbox::VecBox) {
        let document_key = dryocsecretbox::Key::gen();
        let encrypted_document_key = DryocBox::seal_to_vecbox(&document_key, &self.key_pair.public_key).unwrap();

        (document.encrypt(&document_key), encrypted_document_key)
    }

    fn get_document_name(&self, encrypted_name: &SymEncryptedData, encrypted_document_key: &dryocbox::VecBox)
                         -> String {
        let document_key = self.decrypt_document_key(encrypted_document_key);
        String::from_utf8(encrypted_name.decrypt(&document_key)).unwrap()
    }

    fn get_document(&self, encrypted_document: &EncryptedDocument, encrypted_document_key: &dryocbox::VecBox)
                    -> Document {
        let document_key = self.decrypt_document_key(encrypted_document_key);

        encrypted_document.decrypt(&document_key)
    }

    fn update_document(&self, document: &Document, encrypted_document_key: &dryocbox::VecBox)
                       -> EncryptedDocument {
        let document_key = self.decrypt_document_key(encrypted_document_key);
        document.encrypt(&document_key)
    }

    fn add_owner(&self, encrypted_document_key: &dryocbox::VecBox,
                 other_organization_public_key: &dryocbox::PublicKey)
                 -> dryocbox::VecBox {
        let document_key = self.decrypt_document_key(encrypted_document_key);
        DryocBox::seal_to_vecbox(&document_key, other_organization_public_key).unwrap()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn test_document1() -> Document {
        Document {
            name: String::from("test document name"),
            content: String::from("test document content"),
        }
    }

    fn mock_unlocked_vault() -> UnlockedVault {
        UnlockedVault::new(dryocbox::KeyPair::gen())
    }

    #[test]
    fn encryption_then_decryption() {
        let vault = mock_unlocked_vault();

        let (encrypted_document, encrypted_key) =
            vault.new_document(&test_document1());

        let decrypted_document =
            vault.get_document(&encrypted_document, &encrypted_key);

        assert_eq!(decrypted_document, test_document1());
    }

    #[test]
    fn encryption_then_name_decryption() {
        let vault = mock_unlocked_vault();

        let (encrypted_document, encrypted_key) =
            vault.new_document(&test_document1());

        let decrypted_name =
            vault.get_document_name(&encrypted_document.name, &encrypted_key);

        assert_eq!(decrypted_name, test_document1().name);
    }

    #[test]
    fn encryption_then_update_then_decryption() {
        let vault = mock_unlocked_vault();

        let (.., encrypted_key) = vault.new_document(&test_document1());
        let encrypted_document = vault.update_document(&test_document1(), &encrypted_key);
        let decrypted_document = vault.get_document(&encrypted_document, &encrypted_key);

        assert_eq!(decrypted_document, test_document1())
    }

    #[test]
    fn encryption_then_add_owner_then_decryption() {
        let vault1 = mock_unlocked_vault();
        let vault2 = mock_unlocked_vault();

        let (encrypted_document, encrypted_key) = vault1.new_document(&test_document1());
        let other_encrypted_key = vault1.add_owner(&encrypted_key, &vault2.key_pair.public_key);
        let decrypted_document = vault2.get_document(&encrypted_document, &other_encrypted_key);

        assert_eq!(decrypted_document, test_document1())
    }
}
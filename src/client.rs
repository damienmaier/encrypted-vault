use dryoc::dryocbox::NewByteArray;

struct SymEncryptedData {
    secret_box: dryoc::dryocsecretbox::VecBox,
    nonce: dryoc::dryocsecretbox::Nonce,
}

impl SymEncryptedData {
    fn encrypt(text: &[u8], key: &dryoc::dryocsecretbox::Key) -> Self {
        let nonce = dryoc::dryocsecretbox::Nonce::gen();

        Self {
            secret_box: dryoc::dryocsecretbox::DryocSecretBox::encrypt_to_vecbox(text, &nonce, key),
            nonce,
        }
    }

    fn decrypt(&self, key: &dryoc::dryocsecretbox::Key) -> Vec<u8> {
        self.secret_box.decrypt_to_vec(&self.nonce, key).unwrap()
    }
}

type EncryptedSymmetricKey = dryoc::dryocbox::VecBox;

fn encrypt_symmetric_key_with_asymmetric_key(
    symmetric_key: &dryoc::dryocsecretbox::Key,
    public_key: &dryoc::dryocbox::PublicKey,
) -> EncryptedSymmetricKey {
    dryoc::dryocbox::DryocBox::seal_to_vecbox(symmetric_key, public_key).unwrap()
}

fn decrypt_symmetric_key_with_asymmetric_key(
    encrypted_symmetric_key: &EncryptedSymmetricKey,
    asymmetric_key_pair: &dryoc::dryocbox::KeyPair,
) -> dryoc::dryocsecretbox::Key {
    let symmetric_key_vec = encrypted_symmetric_key.unseal_to_vec(&asymmetric_key_pair).unwrap();

    let symmetric_key_array: [u8; 32] = symmetric_key_vec.try_into().unwrap();
    symmetric_key_array.into()
}

#[derive(PartialEq, Debug)]
struct Document {
    name: Vec<u8>,
    content: Vec<u8>,
}

impl Document {
    fn encrypt(&self, key: &dryoc::dryocsecretbox::Key) -> EncryptedDocument {
        EncryptedDocument {
            name: SymEncryptedData::encrypt(&self.name, &key),
            content: SymEncryptedData::encrypt(&self.content, &key),
        }
    }
}

struct EncryptedDocument {
    name: SymEncryptedData,
    content: SymEncryptedData,
}

impl EncryptedDocument {
    fn decrypt(&self, key: &dryoc::dryocsecretbox::Key) -> Document {
        Document {
            name: self.name.decrypt(key),
            content: self.content.decrypt(key),
        }
    }
}

struct UnlockedVault {
    key_pair: dryoc::dryocbox::KeyPair,
}

impl UnlockedVault {
    fn new(key_pair: dryoc::dryocbox::KeyPair) -> Self {
        Self { key_pair }
    }


    fn new_document(&self, document: &Document)
                    -> (EncryptedDocument, EncryptedSymmetricKey) {
        let document_key = dryoc::dryocsecretbox::Key::gen();
        let encrypted_document_key = encrypt_symmetric_key_with_asymmetric_key(&document_key, &self.key_pair.public_key);

        (document.encrypt(&document_key), encrypted_document_key)
    }

    fn get_document_name(&self, encrypted_name: &SymEncryptedData, encrypted_document_key: &EncryptedSymmetricKey)
                         -> Vec<u8> {
        let document_key = decrypt_symmetric_key_with_asymmetric_key(encrypted_document_key, &self.key_pair);
        encrypted_name.decrypt(&document_key)
    }

    fn get_document(&self, encrypted_document: &EncryptedDocument, encrypted_document_key: &EncryptedSymmetricKey)
                    -> Document {
        let document_key = decrypt_symmetric_key_with_asymmetric_key(encrypted_document_key, &self.key_pair);

        encrypted_document.decrypt(&document_key)
    }

    fn update_document(&self, document: &Document, encrypted_document_key: &EncryptedSymmetricKey)
                       -> EncryptedDocument {
        let document_key = decrypt_symmetric_key_with_asymmetric_key(encrypted_document_key, &self.key_pair);
        document.encrypt(&document_key)
    }

    fn add_owner(&self, encrypted_document_key: &EncryptedSymmetricKey,
                 other_organization_public_key: &dryoc::dryocbox::PublicKey)
                 -> EncryptedSymmetricKey {
        let document_key = decrypt_symmetric_key_with_asymmetric_key(encrypted_document_key, &self.key_pair);
        encrypt_symmetric_key_with_asymmetric_key(&document_key, other_organization_public_key)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn test_document1() -> Document {
        Document {
            name: String::from("test document name").into_bytes(),
            content: String::from("test document content").into_bytes(),
        }
    }

    fn mock_unlocked_vault() -> UnlockedVault {
        UnlockedVault::new(dryoc::dryocbox::KeyPair::gen())
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
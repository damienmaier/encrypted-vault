struct EncryptedData {
    secret_box: dryoc::dryocsecretbox::VecBox,
    nonce: dryoc::dryocsecretbox::Nonce,
}

#[derive(PartialEq, Debug)]
struct Document {
    name: String,
    content: String,
}

struct EncryptedDocument {
    name: EncryptedData,
    content: EncryptedData,
}

struct UnlockedVault {
    key_pair: dryoc::dryocbox::KeyPair,
}

impl UnlockedVault {
    fn new(key_pair: dryoc::dryocbox::KeyPair) -> Self {
        Self { key_pair }
    }

    fn new_document(&self, document: &Document)
                    -> (EncryptedDocument, dryoc::dryocbox::VecBox) {
        unimplemented!()
    }

    fn get_document_name(&self, encrypted_name: &EncryptedData, encrypted_document_key: &dryoc::dryocbox::VecBox)
                         -> String {
        unimplemented!()
    }

    fn get_document(&self, encrypted_document: &EncryptedDocument,
                    encrypted_document_key: &dryoc::dryocbox::VecBox)
                    -> Document {
        unimplemented!()
    }

    fn update_document(&self, document: &Document, encrypted_document_key: &dryoc::dryocbox::VecBox)
                       -> EncryptedDocument {
        unimplemented!()
    }

    fn add_owner(&self, encrypted_document_key: &dryoc::dryocbox::VecBox,
                 other_organization_public_key: &dryoc::dryocbox::PublicKey)
                 -> dryoc::dryocbox::VecBox {
        unimplemented!()
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
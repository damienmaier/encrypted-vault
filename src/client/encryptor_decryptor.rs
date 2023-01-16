//! Provides functions that are used once the client has recovered its private key, to access and manipulate the documents

use dryoc::{dryocbox, dryocsecretbox};
use dryoc::dryocbox::DryocBox;
use dryoc::dryocsecretbox::NewByteArray;

use crate::data::{Document, DocumentID, EncryptedDocumentKey, EncryptedDocumentNameAndKey, EncryptedToken, Token};
use crate::data::EncryptedDocument;
use crate::error::VaultError;
use crate::error::VaultError::CryptographyError;
use crate::symmetric_encryption_helper::SymEncryptedData;

/// Owns the organization key pair. Performs encryption / decryption of the data coming from / going to the server.
#[derive(PartialEq, Debug)]
pub struct OrganizationEncryptorDecryptor {
    key_pair: dryocbox::KeyPair,
}

impl OrganizationEncryptorDecryptor {
    pub fn new(key_pair: dryocbox::KeyPair) -> OrganizationEncryptorDecryptor {
        OrganizationEncryptorDecryptor { key_pair }
    }

    /// Using a list of document ids and corresponding encrypted document names coming from the server,
    /// searches for the document id of the document named `document_name`
    pub fn find_document_id_from_name(&self, encrypted_document_names: &Vec<(DocumentID, EncryptedDocumentNameAndKey)>, document_name: &str) -> Option<DocumentID> {
        encrypted_document_names
            .iter()
            .filter(|(.., name_and_key)|
                self.decrypt_document_name(&name_and_key.data, &name_and_key.key) == Ok(document_name.to_string()))
            .map(|(id, ..)| id)
            .cloned()
            .next()
    }

    /// Chooses a random document key, encrypts the document with the document key and encrypts the document key with the organization public key
    pub fn generate_document_key_and_encrypt_document(&self, document: &Document)
                                                      -> Result<(EncryptedDocument, EncryptedDocumentKey), VaultError> {
        let document_key = dryocsecretbox::Key::gen();
        let encrypted_document_key = DryocBox::seal_to_vecbox(&document_key, &self.key_pair.public_key)
            .map_err(|_| CryptographyError)?;

        Ok((document.encrypt(&document_key), encrypted_document_key))
    }

    pub fn decrypt_document_name(&self, encrypted_name: &SymEncryptedData, encrypted_document_key: &EncryptedDocumentKey)
                                 -> Result<String, VaultError> {
        let document_key = self.decrypt_document_key(encrypted_document_key)?;
        String::from_utf8(encrypted_name.decrypt(&document_key)?).map_err(|_| CryptographyError)
    }

    pub fn decrypt_document(&self, encrypted_document: &EncryptedDocument, encrypted_document_key: &EncryptedDocumentKey)
                            -> Result<Document, VaultError> {
        let document_key = self.decrypt_document_key(encrypted_document_key)?;

        encrypted_document.decrypt(&document_key)
    }

    pub fn encrypt_document_with_key(&self, document: &Document, encrypted_document_key: &EncryptedDocumentKey)
                                     -> Result<EncryptedDocument, VaultError> {
        let document_key = self.decrypt_document_key(encrypted_document_key)?;
        Ok(document.encrypt(&document_key))
    }

    /// Decrypts a document key and encrypts it with the public key of an other organization
    pub fn encrypt_document_key_for_other_organization(&self, encrypted_document_key: &EncryptedDocumentKey,
                                                       other_organization_public_key: &dryocbox::PublicKey)
                                                       -> Result<EncryptedDocumentKey, VaultError> {
        let document_key = self.decrypt_document_key(encrypted_document_key)?;
        DryocBox::seal_to_vecbox(&document_key, other_organization_public_key).map_err(|_| CryptographyError)
    }

    pub fn decrypt_token(&self, encrypted_token: &EncryptedToken) -> Result<Token, VaultError> {
        encrypted_token.unseal_to_vec(&self.key_pair).map_err(|_| CryptographyError)
    }

    fn decrypt_document_key(&self, encrypted_key: &EncryptedDocumentKey) -> Result<dryocsecretbox::Key, VaultError> {
        let symmetric_key_vec = encrypted_key.unseal_to_vec(&self.key_pair).map_err(|_| CryptographyError)?;

        Ok(
            <[u8; dryoc::constants::CRYPTO_SECRETBOX_KEYBYTES]>::try_from(symmetric_key_vec).map_err(|_| CryptographyError)?.into()
        )
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn test_document() -> Document {
        Document {
            name: String::from("test document name"),
            content: String::from("test document content"),
        }
    }

    fn mock_encryptor_decryptor() -> OrganizationEncryptorDecryptor {
        OrganizationEncryptorDecryptor { key_pair: dryocbox::KeyPair::gen() }
    }

    #[test]
    fn encryption_then_decryption() {
        let encryptor_decryptor = mock_encryptor_decryptor();

        let (encrypted_document, encrypted_key) =
            encryptor_decryptor.generate_document_key_and_encrypt_document(&test_document()).unwrap();

        let decrypted_document =
            encryptor_decryptor.decrypt_document(&encrypted_document, &encrypted_key).unwrap();

        assert_eq!(decrypted_document, test_document());
    }

    #[test]
    fn encryption_then_name_decryption() {
        let encryptor_decryptor = mock_encryptor_decryptor();

        let (encrypted_document, encrypted_key) =
            encryptor_decryptor.generate_document_key_and_encrypt_document(&test_document()).unwrap();

        let decrypted_name =
            encryptor_decryptor.decrypt_document_name(&encrypted_document.name, &encrypted_key).unwrap();

        assert_eq!(decrypted_name, test_document().name);
    }

    #[test]
    fn encryption_then_update_then_decryption() {
        let encryptor_decryptor = mock_encryptor_decryptor();

        let (.., encrypted_key) = encryptor_decryptor.generate_document_key_and_encrypt_document(&test_document())
            .unwrap();
        let encrypted_document =
            encryptor_decryptor.encrypt_document_with_key(&test_document(), &encrypted_key)
                .unwrap();
        let decrypted_document =
            encryptor_decryptor.decrypt_document(&encrypted_document, &encrypted_key)
                .unwrap();

        assert_eq!(decrypted_document, test_document())
    }

    #[test]
    fn encryption_then_add_owner_then_decryption() {
        let encryptor_decryptor1 = mock_encryptor_decryptor();
        let encryptor_decryptor2 = mock_encryptor_decryptor();

        let (encrypted_document, encrypted_key) =
            encryptor_decryptor1.generate_document_key_and_encrypt_document(&test_document())
                .unwrap();
        let other_encrypted_key =
            encryptor_decryptor1.encrypt_document_key_for_other_organization(&encrypted_key, &encryptor_decryptor2.key_pair.public_key)
                .unwrap();
        let decrypted_document = encryptor_decryptor2.decrypt_document(&encrypted_document, &other_encrypted_key)
            .unwrap();

        assert_eq!(decrypted_document, test_document())
    }

    #[test]
    fn decrypt_token() {
        let encryptor_decryptor = mock_encryptor_decryptor();

        let token: Token = "my token".into();
        let encrypted_token =
            DryocBox::seal_to_vecbox(&token, &encryptor_decryptor.key_pair.public_key).unwrap();

        assert_eq!(token, encryptor_decryptor.decrypt_token(&encrypted_token).unwrap())
    }
}
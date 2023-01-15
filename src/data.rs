use dryoc::{dryocbox, pwhash};
use dryoc::dryocbox::DryocBox;
use serde::Deserialize;
use serde::Serialize;
use crate::error::VaultError;
use crate::error::VaultError::CryptographyError;

use crate::symmetric_encryption_helper::SymEncryptedData;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Document {
    pub name: String,
    pub content: String,
}

impl Document {
    pub fn encrypt(&self, key: &dryoc::dryocsecretbox::Key) -> EncryptedDocument {
        EncryptedDocument {
            name: SymEncryptedData::encrypt(&self.name.as_bytes(), &key),
            content: SymEncryptedData::encrypt(&self.content.as_bytes(), &key),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct EncryptedDocument {
    pub name: SymEncryptedData,
    pub content: SymEncryptedData,
}

impl EncryptedDocument {
    pub fn decrypt(&self, key: &dryoc::dryocsecretbox::Key) -> Result<Document, VaultError> {
        Ok(
            Document {
                name: String::from_utf8(self.name.decrypt(key)?).map_err(|_| CryptographyError)?,
                content: String::from_utf8(self.content.decrypt(key)?).map_err(|_| CryptographyError)?,
            }
        )
    }

    /// Creates a mock EncryptedDocument.
    /// Useful for testing.
    pub fn create_random() -> Self {
        Self {
            name: SymEncryptedData::create_random(),
            content: SymEncryptedData::create_random(),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct EncryptedDocumentNameAndKey {
    pub data: SymEncryptedData,
    pub key: EncryptedDocumentKey,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct UserShare {
    pub salt: pwhash::Salt,
    pub encrypted_private_key_share: SymEncryptedData,
}

impl UserShare {
    /// Creates a mock UserShare.
    /// Useful for testing.
    pub fn create_random() -> Self {
        Self {
            salt: pwhash::Salt::new(),
            encrypted_private_key_share: SymEncryptedData::create_random(),
        }
    }
}


pub type DocumentID = Vec<u8>;

pub const DOCUMENT_ID_LENGTH_BYTES: usize = 32;

pub type Token = Vec<u8>;

pub const TOKEN_LENGTH_BYTES: usize = 32;

pub type EncryptedToken = dryocbox::VecBox;
pub type EncryptedDocumentKey = dryocbox::VecBox;

pub fn random_encrypted_document_key() -> EncryptedDocumentKey {
    DryocBox::seal_to_vecbox("a".as_bytes(), &dryocbox::KeyPair::gen().public_key)
        .expect("Could not encrypt mock document key")
}
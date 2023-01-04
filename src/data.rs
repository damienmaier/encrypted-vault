use std::collections::HashMap;
use dryoc::{dryocbox, pwhash};
use serde::Deserialize;
use serde::Serialize;

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
    pub fn decrypt(&self, key: &dryoc::dryocsecretbox::Key) -> Document {
        Document {
            name: String::from_utf8(self.name.decrypt(key)).unwrap(),
            content: String::from_utf8(self.content.decrypt(key)).unwrap(),
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


pub type DocumentID = String;
pub const DOCUMENT_ID_LENGTH_BYTES: usize = 32;

pub type Token = Vec<u8>;
pub const TOKEN_LENGTH_BYTES: usize = 32;

pub type EncryptedToken = dryocbox::VecBox;
pub type EncryptedDocumentKey = dryocbox::VecBox;
use std::collections::HashMap;
use dryoc::{dryocbox, pwhash};
use serde::Deserialize;
use serde::Serialize;

use crate::symmetric_encryption_helper::SymEncryptedData;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub(crate) struct Document {
    pub(crate) name: String,
    pub(crate) content: String,
}

impl Document {
    pub(crate) fn encrypt(&self, key: &dryoc::dryocsecretbox::Key) -> EncryptedDocument {
        EncryptedDocument {
            name: SymEncryptedData::encrypt(&self.name.as_bytes(), &key),
            content: SymEncryptedData::encrypt(&self.content.as_bytes(), &key),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub(crate) struct EncryptedDocument {
    pub(crate) name: SymEncryptedData,
    pub(crate) content: SymEncryptedData,
}

impl EncryptedDocument {
    pub(crate) fn decrypt(&self, key: &dryoc::dryocsecretbox::Key) -> Document {
        Document {
            name: String::from_utf8(self.name.decrypt(key)).unwrap(),
            content: String::from_utf8(self.content.decrypt(key)).unwrap(),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub(crate) struct EncryptedDataEncryptedKey {
    pub(crate) data: SymEncryptedData,
    pub(crate) key: dryocbox::VecBox,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub(crate) struct UserShare {
    pub(crate) salt: pwhash::Salt,
    pub(crate) encrypted_private_key_share: SymEncryptedData,
}


pub type DocumentID = [u8; 32];

pub type Token = Vec<u8>;
pub const TOKEN_LENGTH_BYTES: usize = 32;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub(crate) struct Organization {
    pub(crate) users_data: HashMap<String, UserShare>,
    pub(crate) public_key: dryocbox::PublicKey
}
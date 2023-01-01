use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};

use dryoc::dryocbox;

use crate::data::{DocumentID, EncryptedDataEncryptedKey, Token, UserShare};
use crate::EncryptedDocument;

pub(crate) struct Server {
    data_path: PathBuf,
}

impl Server {
    pub fn new(data_path: &PathBuf) -> Server {
        Server { data_path: data_path.clone() }
    }

    pub fn create_organization(&self, organization_name: &str, users_data: &HashMap<String, UserShare>, public_key: &dryocbox::PublicKey)
                           -> Option<()>
    {
        unimplemented!();
    }

    pub fn unlock_vault(&self, organization_name: &str, user_name1: &str, user_name2: &str)
                    -> Option<(UserShare, UserShare, dryocbox::PublicKey, dryocbox::VecBox)> {
        unimplemented!()
    }

    pub fn revoke_user(&self, token: &Token, user_name: &str) -> Option<()> {
        unimplemented!()
    }

    pub fn new_document(&self, token: &Token, encrypted_document: &EncryptedDocument, encrypted_key: &dryocbox::VecBox)
                    -> Option<()> {
        unimplemented!()
    }

    pub fn list_documents(&self, token: &Token) -> Option<HashMap<DocumentID, EncryptedDataEncryptedKey>> {
        unimplemented!()
    }

    pub fn get_document_key(&self, token: &Token, document_id: &DocumentID) -> Option<dryocbox::VecBox> {
        unimplemented!()
    }

    pub fn download_document(&self, token: &Token, document_id: &DocumentID) -> Option<EncryptedDocument> {
        unimplemented!()
    }

    pub fn update_document(&self, token: &Token, document_id: &DocumentID, encrypted_document: &EncryptedDocument)
                    -> Option<()> {
        unimplemented!()
    }

    pub fn delete_document(&self, token: &Token, document_id: &DocumentID) -> Option<()> {
        unimplemented!()
    }

    pub fn get_public_key_of_organization(&self, organization_name: &str) -> Option<dryocbox::PublicKey> {
        unimplemented!()
    }

    pub fn add_owner(&self, token: &Token, document_id: &DocumentID, other_organization_name: &str, encrypted_document_key: &dryocbox::VecBox)
                 -> Option<()> {
        unimplemented!()
    }
}
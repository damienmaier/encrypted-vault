use std::collections::HashMap;
use dryoc::dryocbox;
use crate::data::{DocumentID, EncryptedDocumentKey, EncryptedDocumentNameAndKey, EncryptedToken, Token, UserShare, EncryptedDocument};

pub trait ServerConnection {
    fn create_organization(&self, organization_name: &str, users_data: &HashMap<String, UserShare>, public_key: &dryocbox::PublicKey)
                           -> Option<()>;

    fn unlock_vault(&mut self, organization_name: &str, user_name1: &str, user_name2: &str)
                    -> Option<(UserShare, UserShare, dryocbox::PublicKey, EncryptedToken)>;

    fn revoke_user(&self, token: &Token, user_name: &str) -> Option<()>;

    fn new_document(&self, token: &Token, encrypted_document: &EncryptedDocument, encrypted_key: &EncryptedDocumentKey)
                    -> Option<()>;

    fn list_documents(&self, token: &Token) -> Option<HashMap<DocumentID, EncryptedDocumentNameAndKey>>;

    fn get_document_key(&self, token: &Token, document_id: &DocumentID) -> Option<EncryptedDocumentKey>;

    fn get_document(&self, token: &Token, document_id: &DocumentID) -> Option<EncryptedDocument>;

    fn update_document(&self, token: &Token, document_id: &DocumentID, encrypted_document: &EncryptedDocument)
                       -> Option<()>;

    fn delete_document(&self, token: &Token, document_id: &DocumentID) -> Option<()>;

    fn get_public_key_of_organization(&self, organization_name: &str) -> Option<dryocbox::PublicKey>;

    fn add_owner(&self, token: &Token, document_id: &DocumentID, other_organization_name: &str, encrypted_document_key: &EncryptedDocumentKey)
                 -> Option<()>;
}
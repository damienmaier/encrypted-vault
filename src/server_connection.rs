use std::collections::HashMap;
use dryoc::{dryocbox, pwhash};
use crate::data::{DocumentID, EncryptedDocumentKey, EncryptedDocumentNameAndKey, EncryptedToken, Token, UserShare, EncryptedDocument};

pub trait ServerConnection {
    fn create_organization(&mut self, organization_name: &str, users_data: &HashMap<String, UserShare>, public_key: &dryocbox::PublicKey, argon2_config: &pwhash::Config)
                           -> Option<()>;

    fn unlock_vault(&mut self, organization_name: &str, user_name1: &str, user_name2: &str)
                    -> Option<(UserShare, UserShare, pwhash::Config, dryocbox::PublicKey, EncryptedToken)>;

    fn revoke_user(&mut self, token: &Token, user_name: &str) -> Option<()>;
    
    fn revoke_token(&mut self, token: &Token) -> Option<()>;
    
    fn new_document(&mut self, token: &Token, encrypted_document: &EncryptedDocument, encrypted_key: &EncryptedDocumentKey)
                    -> Option<()>;

    fn list_documents(&mut self, token: &Token) -> Option<HashMap<DocumentID, EncryptedDocumentNameAndKey>>;

    fn get_document_key(&mut self, token: &Token, document_id: &DocumentID) -> Option<EncryptedDocumentKey>;

    fn get_document(&mut self, token: &Token, document_id: &DocumentID) -> Option<EncryptedDocument>;

    fn update_document(&mut self, token: &Token, document_id: &DocumentID, encrypted_document: &EncryptedDocument)
                       -> Option<()>;

    fn delete_document(&mut self, token: &Token, document_id: &DocumentID) -> Option<()>;

    fn get_public_key_of_organization(&mut self, organization_name: &str) -> Option<dryocbox::PublicKey>;

    fn add_owner(&mut self, token: &Token, document_id: &DocumentID, other_organization_name: &str, encrypted_document_key: &EncryptedDocumentKey)
                 -> Option<()>;
    
}
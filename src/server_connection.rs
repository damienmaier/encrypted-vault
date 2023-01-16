//! API that the server provides to the client

use std::collections::HashMap;
use dryoc::{dryocbox, pwhash};
use crate::data::{DocumentID, EncryptedDocumentKey, EncryptedDocumentNameAndKey, EncryptedToken, Token, UserShare, EncryptedDocument};
use crate::error::VaultError;

pub trait ServerConnection {
    fn create_organization(&mut self, organization_name: &str, users_data: &HashMap<String, UserShare>, public_key: &dryocbox::PublicKey, argon2_config: &pwhash::Config)
                           -> Result<(), VaultError>;

    fn unlock_vault(&mut self, organization_name: &str, user_name1: &str, user_name2: &str)
                    -> Result<(UserShare, UserShare, pwhash::Config, dryocbox::PublicKey, EncryptedToken), VaultError>;

    fn revoke_user(&mut self, token: &Token, user_name: &str) -> Result<(), VaultError>;
    
    fn revoke_token(&mut self, token: &Token) -> Result<(), VaultError>;
    
    fn new_document(&mut self, token: &Token, encrypted_document: &EncryptedDocument, encrypted_key: &EncryptedDocumentKey)
                    -> Result<(), VaultError>;

    fn list_documents(&mut self, token: &Token) -> Result<Vec<(DocumentID, EncryptedDocumentNameAndKey)>, VaultError>;

    fn get_document_key(&mut self, token: &Token, document_id: &DocumentID) -> Result<EncryptedDocumentKey, VaultError>;

    fn get_document(&mut self, token: &Token, document_id: &DocumentID) -> Result<EncryptedDocument, VaultError>;

    fn update_document(&mut self, token: &Token, document_id: &DocumentID, encrypted_document: &EncryptedDocument)
                       -> Result<(), VaultError>;

    fn delete_document(&mut self, token: &Token, document_id: &DocumentID) -> Result<(), VaultError>;

    fn get_public_key_of_organization(&mut self, organization_name: &str) -> Result<dryocbox::PublicKey, VaultError>;

    fn add_owner(&mut self, token: &Token, document_id: &DocumentID, other_organization_name: &str, encrypted_document_key: &EncryptedDocumentKey)
                 -> Result<(), VaultError>;
    
}
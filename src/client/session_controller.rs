use dryoc::dryocbox;

use crate::client::encryptor_decryptor::OrganizationEncryptorDecryptor;
use crate::client::key_pair::retrieve_private_key;
use crate::data::{Document, DocumentID, EncryptedDocumentNameAndKey, Token};
use crate::error::VaultError;
use crate::error::VaultError::{DocumentNotFound};
use crate::server_connection::ServerConnection;
use crate::validation::validate_and_standardize_name;


#[derive(Debug, PartialEq)]
pub struct Controller<A: ServerConnection + Clone> {
    server: A,
    encryptor_decryptor: OrganizationEncryptorDecryptor,
    token: Token,
}

impl<A: ServerConnection + Clone> Controller<A> {
    pub fn unlock_vault_for_organization(server: &mut A, organization_name: &str,
                                         username1: &str, password1: &str,
                                         username2: &str, password2: &str)
                                         -> Result<Self, VaultError> {
        let organization_name = validate_and_standardize_name(organization_name)?;
        let username1 = validate_and_standardize_name(username1)?;
        let username2 = validate_and_standardize_name(username2)?;

        let (user_share1, user_share2, argon_config, public_key, encrypted_token) =
            server.unlock_vault(&organization_name, &username1, &username2)?;
        let private_key = retrieve_private_key(password1, &user_share1, password2, &user_share2, &argon_config)?;

        let encryptor_decryptor =
            OrganizationEncryptorDecryptor::new(dryocbox::KeyPair { public_key, secret_key: private_key });
        let token = encryptor_decryptor.decrypt_token(&encrypted_token)?;

        Ok(Controller { server: server.clone(), encryptor_decryptor, token })
    }

    pub fn revoke_user(&mut self, username: &str) -> Result<(), VaultError> {
        self.server.revoke_user(&self.token, username)
    }

    pub fn revoke_token(&mut self) -> Result<(), VaultError> {
        self.server.revoke_token(&self.token)
    }


    pub fn upload(&mut self, document: &Document) -> Result<(), VaultError> {
        let (encrypted_document, encrypted_key) =
            self.encryptor_decryptor.generate_document_key_and_encrypt_document(document)?;
        self.server.new_document(&self.token, &encrypted_document, &encrypted_key)
    }

    pub fn list_document_names(&mut self) -> Result<Vec<String>, VaultError> {
        let encrypted_document_names = self.server.list_documents(&self.token)?;
        encrypted_document_names
            .iter()
            .map(|(.., EncryptedDocumentNameAndKey { data, key })|
                self.encryptor_decryptor.decrypt_document_name(data, key))
            .collect()
    }


    fn get_id_of_document_by_name(&mut self, document_name: &str) -> Result<DocumentID, VaultError> {
        let document_list = self.server.list_documents(&self.token)?;
        self.encryptor_decryptor.find_document_id_from_name(&document_list, document_name).ok_or(DocumentNotFound)
    }

    pub fn download(&mut self, document_name: &str) -> Result<Document, VaultError> {
        let document_id = self.get_id_of_document_by_name(document_name)?;

        let encrypted_document = self.server.get_document(&self.token, &document_id)?;
        let document_key = self.server.get_document_key(&self.token, &document_id)?;

        self.encryptor_decryptor.decrypt_document(&encrypted_document, &document_key)
    }

    pub fn update(&mut self, document_name: &str, new_document: &Document) -> Result<(), VaultError> {
        let document_id = self.get_id_of_document_by_name(document_name)?;

        let document_key = self.server.get_document_key(&self.token, &document_id)?;
        let new_document_encrypted = self.encryptor_decryptor.encrypt_document_with_key(new_document, &document_key)?;
        self.server.update_document(&self.token, &document_id, &new_document_encrypted)
    }

    pub fn share(&mut self, document_name: &str, other_organization_name: &str) -> Result<(), VaultError> {
        let document_id = self.get_id_of_document_by_name(document_name)?;

        let encrypted_document_key = self.server.get_document_key(&self.token, &document_id)?;
        let other_organization_public_key = self.server.get_public_key_of_organization(other_organization_name)?;
        let new_encrypted_document_key =
            self.encryptor_decryptor.encrypt_document_key_for_other_organization(&encrypted_document_key, &other_organization_public_key)?;
        self.server.add_owner(&self.token, &document_id, other_organization_name, &new_encrypted_document_key)
    }

    pub fn delete(&mut self, document_name: &str) -> Result<(), VaultError> {
        let document_id = self.get_id_of_document_by_name(document_name)?;
        self.server.delete_document(&self.token, &document_id)
    }
}

impl<A: ServerConnection + Clone> Drop for Controller<A> {
    fn drop(&mut self) {
        if let Err(_) = self.revoke_token(){
            eprintln!("Error: could not revoke sessions token, the server responded with an error")
        }
    }
}

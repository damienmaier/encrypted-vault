use std::collections::HashMap;
use dryoc::{dryocbox, pwhash};
use crate::client::encryptor_decryptor::OrganizationEncryptorDecryptor;
use crate::client::key_pair::{create_protected_key_pair, retrieve_private_key};
use crate::data::{Document, DocumentID, EncryptedDocumentNameAndKey, Token};
use crate::server_connection::ServerConnection;


pub fn create_organization<A: ServerConnection>(server: &A, organization_name: &str, user_credentials: &HashMap<String, String>, argon_config: &pwhash::Config)
                                                -> Option<()> {
    let (user_encrypted_shares, public_key) =
        create_protected_key_pair(&user_credentials, &argon_config);

    server.create_organization(organization_name, &user_encrypted_shares, &public_key)
}

pub struct Controller<A: ServerConnection + Clone> {
    server: A,
    encryptor_decryptor: OrganizationEncryptorDecryptor,
    token: Token,
}

impl<A: ServerConnection + Clone> Controller<A> {
    pub fn unlock_vault_for_organization(server: &mut A, organization_name: &str,
                                         username1: &str, password1: &str,
                                         username2: &str, password2: &str,
                                         argon_config: &pwhash::Config)
                                         -> Option<Self> {
        let (user_share1, user_share2, public_key, encrypted_token) =
            server.unlock_vault(organization_name, username1, username2)?;
        let private_key = retrieve_private_key(password1, &user_share1, password2, &user_share2, argon_config);

        let encryptor_decryptor =
            OrganizationEncryptorDecryptor::new(dryocbox::KeyPair { public_key, secret_key: private_key });
        let token = encryptor_decryptor.decrypt_token(&encrypted_token);

        Some(Controller { server: server.clone(), encryptor_decryptor, token })
    }

    pub fn revoke_user(&self, username: &str) -> Option<()> {
        self.server.revoke_user(&self.token, username)
    }

    pub fn revoke_token(&mut self) -> Option<()> {
        self.server.revoke_token(&self.token)
    }


    pub fn upload(&self, document: &Document) -> Option<()> {
        let (encrypted_document, encrypted_key) =
            self.encryptor_decryptor.generate_document_key_and_encrypt_document(document);
        self.server.new_document(&self.token, &encrypted_document, &encrypted_key)
    }

    pub fn list_document_names(&self) -> Option<Vec<String>> {
        let encrypted_document_names = self.server.list_documents(&self.token)?;
        let document_names = encrypted_document_names
            .iter()
            .map(|(.., EncryptedDocumentNameAndKey{data, key})|
            self.encryptor_decryptor.decrypt_document_name(data, key))
            .collect();
        Some(document_names)
    }


    pub fn get_id_of_document_by_name(&self, document_name: &str) -> Option<DocumentID> {
        let document_list = self.server.list_documents(&self.token)?;
        self.encryptor_decryptor.find_document_id_from_name(&document_list, document_name)
    }

    pub fn download(&self, document_name: &str) -> Option<Document> {
        let document_id = self.get_id_of_document_by_name(document_name)?;

        let encrypted_document = self.server.get_document(&self.token, &document_id)?;
        let document_key = self.server.get_document_key(&self.token, &document_id)?;
        let document = self.encryptor_decryptor.decrypt_document(&encrypted_document, &document_key);

        Some(document)
    }

    pub fn update(&self, document_name: &str, new_document: &Document) -> Option<()> {
        let document_id = self.get_id_of_document_by_name(document_name)?;

        let document_key = self.server.get_document_key(&self.token, &document_id)?;
        let new_document_encrypted = self.encryptor_decryptor.encrypt_document_with_key(new_document, &document_key);
        self.server.update_document(&self.token, &document_id, &new_document_encrypted)
    }

    pub fn share(&self, document_name: &str, other_organization_name: &str) -> Option<()> {
        let document_id = self.get_id_of_document_by_name(document_name)?;

        let encrypted_document_key = self.server.get_document_key(&self.token, &document_id)?;
        let other_organization_public_key = self.server.get_public_key_of_organization(other_organization_name)?;
        let new_encrypted_document_key =
            self.encryptor_decryptor.encrypt_document_key_for_other_organization(&encrypted_document_key, &other_organization_public_key);
        self.server.add_owner(&self.token, &document_id, other_organization_name, &new_encrypted_document_key)
    }

    pub fn delete(&self, document_name: &str) -> Option<()> {
        let document_id = self.get_id_of_document_by_name(document_name)?;
        self.server.delete_document(&self.token, &document_id)
    }
}

impl<A: ServerConnection + Clone> Drop for Controller<A>{
    fn drop(&mut self) {
        self.revoke_token();
    }
}

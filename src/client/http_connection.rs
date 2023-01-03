use std::collections::HashMap;

use dryoc::dryocbox::PublicKey;
use reqwest;
use crate::config;
use crate::config::{ADD_OWNER_ENDPOINT, CREATE_ORGANIZATION_ENDPOINT, DELETE_DOCUMENT_ENDPOINT, GET_DOCUMENT_ENDPOINT, GET_DOCUMENT_KEY_ENDPOINT, GET_PUBLIC_KEY_ENDPOINT, LIST_DOCUMENTS_ENDPOINT, NEW_DOCUMENT_ENDPOINT, REVOKE_USER_ENDPOINT, UNLOCK_VAULT_ENDPOINT, UPDATE_DOCUMENT_ENDPOINT};

use crate::data::{DocumentID, EncryptedDocument, EncryptedDocumentKey, EncryptedDocumentNameAndKey, EncryptedToken, Token, UserShare};
use crate::server_connection::ServerConnection;

pub struct HttpConnection{
    server_url: reqwest::Url,
    http_client: reqwest::blocking::Client
}

impl HttpConnection{
    pub fn new(server_port: u16) -> HttpConnection {
        let mut server_url = reqwest::Url::parse(&("http://".to_string() + config::SERVER_HOSTNAME)).unwrap();
        server_url.set_port(Some(server_port)).unwrap();
        HttpConnection{server_url, http_client: reqwest::blocking::Client::new() }
    }
}


impl ServerConnection for HttpConnection{
    fn create_organization(&self, organization_name: &str, users_data: &HashMap<String, UserShare>, public_key: &PublicKey) -> Option<()> {
        let mut url = self.server_url.clone();
        url.set_path(CREATE_ORGANIZATION_ENDPOINT);
        let response = self.http_client.post(url).json(&(organization_name, users_data, public_key)).send().ok()?;
        if response.status().is_success() {
            Some(())
        } else {
            None
        }
    }

    fn unlock_vault(&mut self, organization_name: &str, user_name1: &str, user_name2: &str) -> Option<(UserShare, UserShare, PublicKey, EncryptedToken)> {
        let mut url = self.server_url.clone();
        url.set_path(UNLOCK_VAULT_ENDPOINT);
        let response = self.http_client.post(url).json(&(organization_name, user_name1, user_name2)).send().ok()?;
        if response.status().is_success() {
            response.json().ok()
        } else {
            None
        }
    }

    fn revoke_user(&self, token: &Token, user_name: &str) -> Option<()> {
        let mut url = self.server_url.clone();
        url.set_path(REVOKE_USER_ENDPOINT);
        let response = self.http_client.post(url).json(&(token, user_name)).send().ok()?;
        if response.status().is_success() {
            Some(())
        } else {
            None
        }
    }

    fn new_document(&self, token: &Token, encrypted_document: &EncryptedDocument, encrypted_key: &EncryptedDocumentKey) -> Option<()> {
        let mut url = self.server_url.clone();
        url.set_path(NEW_DOCUMENT_ENDPOINT);
        let response = self.http_client.post(url).json(&(token, encrypted_document, encrypted_key)).send().ok()?;
        if response.status().is_success() {
            Some(())
        } else {
            None
        }
    }

    fn list_documents(&self, token: &Token) -> Option<HashMap<DocumentID, EncryptedDocumentNameAndKey>> {
        let mut url = self.server_url.clone();
        url.set_path(LIST_DOCUMENTS_ENDPOINT);
        let response = self.http_client.post(url).json(&token).send().ok()?;
        if response.status().is_success() {
            response.json().ok()
        } else {
            None
        }
    }

    fn get_document_key(&self, token: &Token, document_id: &DocumentID) -> Option<EncryptedDocumentKey> {
        let mut url = self.server_url.clone();
        url.set_path(GET_DOCUMENT_KEY_ENDPOINT);
        let response = self.http_client.post(url).json(&(token, document_id)).send().ok()?;
        if response.status().is_success() {
            response.json().ok()
        } else {
            None
        }
    }

    fn get_document(&self, token: &Token, document_id: &DocumentID) -> Option<EncryptedDocument> {
        let mut url = self.server_url.clone();
        url.set_path(GET_DOCUMENT_ENDPOINT);
        let response = self.http_client.post(url).json(&(token, document_id)).send().ok()?;
        if response.status().is_success() {
            response.json().ok()
        } else {
            None
        }
    }

    fn update_document(&self, token: &Token, document_id: &DocumentID, encrypted_document: &EncryptedDocument) -> Option<()> {
        let mut url = self.server_url.clone();
        url.set_path(UPDATE_DOCUMENT_ENDPOINT);
        let response = self.http_client.post(url).json(&(token, document_id, encrypted_document)).send().ok()?;
        if response.status().is_success() {
            Some(())
        } else {
            None
        }
    }

    fn delete_document(&self, token: &Token, document_id: &DocumentID) -> Option<()> {
        let mut url = self.server_url.clone();
        url.set_path(DELETE_DOCUMENT_ENDPOINT);
        let response = self.http_client.post(url).json(&(token, document_id)).send().ok()?;
        if response.status().is_success() {
            Some(())
        } else {
            None
        }
    }

    fn get_public_key_of_organization(&self, organization_name: &str) -> Option<PublicKey> {
        let mut url = self.server_url.clone();
        url.set_path(GET_PUBLIC_KEY_ENDPOINT);
        let response = self.http_client.post(url).json(&organization_name).send().ok()?;
        if response.status().is_success() {
            response.json().ok()
        } else {
            None
        }
    }

    fn add_owner(&self, token: &Token, document_id: &DocumentID, other_organization_name: &str, encrypted_document_key: &EncryptedDocumentKey) -> Option<()> {
        let mut url = self.server_url.clone();
        url.set_path(ADD_OWNER_ENDPOINT);
        let response = self.http_client.post(url).json(&(token, document_id, other_organization_name, encrypted_document_key)).send().ok()?;
        if response.status().is_success() {
            Some(())
        } else {
            None
        }
    }
}

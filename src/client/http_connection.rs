use std::collections::HashMap;
use std::path::PathBuf;

use dryoc::dryocbox::PublicKey;
use dryoc::pwhash;
use reqwest;
use reqwest::blocking::{Client, Response};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::client::client_config::{CLIENT_FILES_LOCATION, ClientConfig};
use crate::data::{DocumentID, EncryptedDocument, EncryptedDocumentKey, EncryptedDocumentNameAndKey, EncryptedToken, Token, UserShare};
use crate::error::VaultError;
use crate::error::VaultError::ServerError;
use crate::server::http_server::{ADD_OWNER_ENDPOINT, CREATE_ORGANIZATION_ENDPOINT, DELETE_DOCUMENT_ENDPOINT, GET_DOCUMENT_ENDPOINT, GET_DOCUMENT_KEY_ENDPOINT, GET_PUBLIC_KEY_ENDPOINT, LIST_DOCUMENTS_ENDPOINT, NEW_DOCUMENT_ENDPOINT, REVOKE_TOKEN_ENDPOINT, REVOKE_USER_ENDPOINT, UNLOCK_VAULT_ENDPOINT, UPDATE_DOCUMENT_ENDPOINT};
use crate::server_connection::ServerConnection;
use crate::utils;

pub const ROOT_CERTIFICATE_FILE_NAME: &str = "root_certificate.pem";

fn http_client_configured_for_tls() -> Client {
    let root_certificate_path = PathBuf::from(CLIENT_FILES_LOCATION).join(ROOT_CERTIFICATE_FILE_NAME);
    let der_certificate = utils::get_certificate_der_from_pem_file(&root_certificate_path)
        .expect("Could not read client certificate");
    let certificate = reqwest::Certificate::from_der(&der_certificate)
        .expect("Could not read client certificate");
    Client::builder()
        .add_root_certificate(certificate)
        .tls_built_in_root_certs(false)// As we use our own CA, it is useless to trust built in CAs
        .build().expect("Could not create http client")
}

#[derive(Debug)]
pub struct HttpConnection {
    server_url: reqwest::Url,
    http_client: Client,
}

impl HttpConnection {
    pub fn new(server_port: u16) -> HttpConnection {
        let server_hostname = ClientConfig::get().server_hostname;
        let mut server_url = reqwest::Url::parse(&format!("https://{server_hostname}")).expect("Could not parse server hostname");
        server_url.set_port(Some(server_port)).expect("Could not set server port");

        HttpConnection {
            server_url,
            http_client: http_client_configured_for_tls(),
        }
    }

    fn send_payload_and_get_response<A: Serialize>(&self, payload: A, endpoint: &str) -> Result<Response, VaultError> {
        let mut url = self.server_url.clone();
        url.set_path(endpoint);
        let response = self.http_client.post(url).json(&payload).send().map_err(|_| ServerError)?;
        if response.status().is_success() {
            Ok(response)
        } else {
            Err(ServerError)
        }
    }

    fn send_payload<A: Serialize>(&self, payload: A, endpoint: &str) -> Result<(), VaultError> {
        self.send_payload_and_get_response(payload, endpoint)?;
        Ok(())
    }

    fn send_payload_and_deserialize_json_response<A: Serialize, B: DeserializeOwned>(&self, payload: A, endpoint: &str) -> Result<B, VaultError> {
        self.send_payload_and_get_response(payload, endpoint)?.json().map_err(|_| ServerError)
    }
}


impl ServerConnection for HttpConnection {
    fn create_organization(&mut self, organization_name: &str, users_data: &HashMap<String, UserShare>, public_key: &PublicKey, argon2_config: &pwhash::Config)
                           -> Result<(), VaultError> {
        self.send_payload((organization_name, users_data, public_key, argon2_config), CREATE_ORGANIZATION_ENDPOINT)
    }

    fn unlock_vault(&mut self, organization_name: &str, user_name1: &str, user_name2: &str)
                    -> Result<(UserShare, UserShare, pwhash::Config, PublicKey, EncryptedToken), VaultError> {
        self.send_payload_and_deserialize_json_response((organization_name, user_name1, user_name2), UNLOCK_VAULT_ENDPOINT)
    }

    fn revoke_user(&mut self, token: &Token, user_name: &str) -> Result<(), VaultError> {
        self.send_payload((token, user_name), REVOKE_USER_ENDPOINT)
    }

    fn revoke_token(&mut self, token: &Token) -> Result<(), VaultError> {
        self.send_payload(token, REVOKE_TOKEN_ENDPOINT)
    }

    fn new_document(&mut self, token: &Token, encrypted_document: &EncryptedDocument, encrypted_key: &EncryptedDocumentKey) -> Result<(), VaultError> {
        self.send_payload((token, encrypted_document, encrypted_key), NEW_DOCUMENT_ENDPOINT)
    }

    fn list_documents(&mut self, token: &Token) -> Result<Vec<(DocumentID, EncryptedDocumentNameAndKey)>, VaultError> {
        self.send_payload_and_deserialize_json_response(token, LIST_DOCUMENTS_ENDPOINT)
    }

    fn get_document_key(&mut self, token: &Token, document_id: &DocumentID) -> Result<EncryptedDocumentKey, VaultError> {
        self.send_payload_and_deserialize_json_response((token, document_id), GET_DOCUMENT_KEY_ENDPOINT)
    }

    fn get_document(&mut self, token: &Token, document_id: &DocumentID) -> Result<EncryptedDocument, VaultError> {
        self.send_payload_and_deserialize_json_response((token, document_id), GET_DOCUMENT_ENDPOINT)
    }

    fn update_document(&mut self, token: &Token, document_id: &DocumentID, encrypted_document: &EncryptedDocument) -> Result<(), VaultError> {
        self.send_payload((token, document_id, encrypted_document), UPDATE_DOCUMENT_ENDPOINT)
    }

    fn delete_document(&mut self, token: &Token, document_id: &DocumentID) -> Result<(), VaultError> {
        self.send_payload((token, document_id), DELETE_DOCUMENT_ENDPOINT)
    }

    fn get_public_key_of_organization(&mut self, organization_name: &str) -> Result<PublicKey, VaultError> {
        self.send_payload_and_deserialize_json_response(organization_name, GET_PUBLIC_KEY_ENDPOINT)
    }

    fn add_owner(&mut self,
                 token: &Token,
                 document_id: &DocumentID,
                 other_organization_name: &str,
                 encrypted_document_key: &EncryptedDocumentKey,
    ) -> Result<(), VaultError> {
        self.send_payload((token, document_id, other_organization_name, encrypted_document_key), ADD_OWNER_ENDPOINT)
    }
}

impl Clone for HttpConnection {
    fn clone(&self) -> Self {
        HttpConnection { server_url: self.server_url.clone(), http_client: self.http_client.clone() }
    }
}
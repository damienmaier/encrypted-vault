use std::collections::HashMap;
use dryoc::{dryocbox, pwhash};
use crate::client::encryptor_decryptor::ClientEncryptorDecryptor;
use crate::client::key_pair::{argon_config, argon_unsafe_config, create_protected_key_pair, retrieve_private_key};
use crate::data::{Document, DocumentID, Token};
use crate::server_connection::ServerConnection;

pub fn create_organization<A: ServerConnection>(server: &A, organization_name: &str, user_credentials: &HashMap<String, String>) {
    create_organization_with_argon_config(server, organization_name, user_credentials, &argon_config())
}

// This config makes Argon hashing fast
// This is totally unsafe and must not be used in production
// This config is used when testing, because otherwise tests would take far too much time
pub fn create_organization_unsafe<A: ServerConnection>(server: &A, organization_name: &str, user_credentials: &HashMap<String, String>) {
    create_organization_with_argon_config(server, organization_name, user_credentials, &argon_unsafe_config())
}

fn create_organization_with_argon_config<A: ServerConnection>(server: &A, organization_name: &str, user_credentials: &HashMap<String, String>,
                                                              argon_config: &pwhash::Config) {
    let (user_encrypted_shares, public_key) =
        create_protected_key_pair(&user_credentials, &argon_config);

    server.create_organization(organization_name, &user_encrypted_shares, &public_key).unwrap();
}

pub fn unlock_vault_for_organization(server: &mut dyn ServerConnection, organization_name: &str,
                                     username1: &str, password1: &str,
                                     username2: &str, password2: &str)
                                     -> (ClientEncryptorDecryptor, Token) {
    unlock_vault_for_organization_with_argon_config(server, organization_name, username1, password1, username2, password2, &argon_config())
}

// This config makes Argon hashing fast
// This is totally unsafe and must not be used in production
// This config is used when testing, because otherwise tests would take far too much time
pub fn unlock_vault_for_organization_unsafe(server: &mut dyn ServerConnection, organization_name: &str,
                                     username1: &str, password1: &str,
                                     username2: &str, password2: &str)
                                     -> (ClientEncryptorDecryptor, Token) {
    unlock_vault_for_organization_with_argon_config(server, organization_name, username1, password1, username2, password2, &argon_unsafe_config())
}


fn unlock_vault_for_organization_with_argon_config(server: &mut dyn ServerConnection, organization_name: &str,
                                                       username1: &str, password1: &str,
                                                       username2: &str, password2: &str,
                                                       argon_config: &pwhash::Config)
                                                       -> (ClientEncryptorDecryptor, Token) {
    let (user_share1, user_share2, public_key, encrypted_token) =
        server.unlock_vault(organization_name, username1, username2).unwrap();
    let private_key = retrieve_private_key(password1, &user_share1, password2, &user_share2, argon_config);

    let key_pair = dryocbox::KeyPair { public_key, secret_key: private_key };
    let token = encrypted_token.unseal_to_vec(&key_pair).unwrap();

    (ClientEncryptorDecryptor { key_pair }, token)
}

pub fn upload<A: ServerConnection>(document: &Document, token: &Token, client: &ClientEncryptorDecryptor, server: &A) -> Option<()> {
    let (encrypted_document, encrypted_key) = client.generate_document_key_and_encrypt_document(document);
    server.new_document(token, &encrypted_document, &encrypted_key)
}

pub fn share<A: ServerConnection>(document_id: &DocumentID, other_organization_name: &str,
                                  token: &Token, client: &ClientEncryptorDecryptor, server: &A) -> Option<()> {
    let encrypted_document_key = server.get_document_key(token, document_id).unwrap();
    let other_organization_public_key = server.get_public_key_of_organization(other_organization_name).unwrap();
    let new_encrypted_document_key = client.encrypt_document_key_for_other_organization(&encrypted_document_key, &other_organization_public_key);
    server.add_owner(token, &document_id, other_organization_name, &new_encrypted_document_key)
}

pub fn download_from_document_id<A: ServerConnection>(document_id: &DocumentID, token: &Token, client: &ClientEncryptorDecryptor, server: &A) -> Document {
    let encrypted_document = server.get_document(token, &document_id).unwrap();
    let document_key = server.get_document_key(token, &document_id).unwrap();
    let document = client.decrypt_document(&encrypted_document, &document_key);

    document
}

pub fn download_from_document_name<A: ServerConnection>(document_name: &str, token: &Token, client: &ClientEncryptorDecryptor, server: &A) -> Document {
    let document_list = server.list_documents(token).unwrap();
    let document_id = client.find_document_id_from_name(&document_list, document_name).unwrap();

    download_from_document_id(&document_id, token, &client, server)
}

pub fn update<A: ServerConnection>(document_id: &DocumentID, new_document: &Document, token: &Token, client: &ClientEncryptorDecryptor, server: &A)
                                   -> Option<()> {
    let document_key = server.get_document_key(token, &document_id)?;
    let new_document_encrypted = client.encrypt_document_with_key(new_document, &document_key);
    server.update_document(token, &document_id, &new_document_encrypted)
}

pub fn get_id_of_document_by_name<A: ServerConnection>(document_name: &str, token: &Token, client: &ClientEncryptorDecryptor, server: &A) -> Option<DocumentID> {
    let document_list = server.list_documents(token).unwrap();
    client.find_document_id_from_name(&document_list, document_name)
}